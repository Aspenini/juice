#include "macos/process/mac_process.hpp"

#include <algorithm>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>

#include "macos/loader/host_memory.hpp"

namespace juice::mac {

namespace {

constexpr size_t kBuiltinCapacity = size_t{1} << 14;
constexpr uint64_t kBuiltinStride = 16;
constexpr uint64_t kDefaultStackSize = uint64_t{8} << 20;
constexpr uint64_t kRedZone = 256;          // left alone below a guest SP when calling into the guest
constexpr uint64_t kMaxArgumentArea = 8192;  // stack arguments of a native call into the guest

MacProcess* g_process = nullptr;
thread_local MacThread* t_thread = nullptr;

std::string directory_of(const std::string& path) {
  const size_t slash = path.find_last_of('/');
  return slash == std::string::npos ? "." : path.substr(0, slash);
}

std::string join(const std::string& dir, std::string_view rest) {
  if (dir.empty()) return std::string(rest);
  return dir.back() == '/' ? dir + std::string(rest) : dir + "/" + std::string(rest);
}

// A file reader over an open stream.
struct StreamReader {
  std::shared_ptr<std::ifstream> in;
  uint64_t size = 0;
  bool operator()(uint64_t offset, void* out, size_t n) const {
    if (offset > size || n > size - offset) return false;
    in->clear();
    in->seekg(static_cast<std::streamoff>(offset));
    in->read(static_cast<char*>(out), static_cast<std::streamsize>(n));
    return static_cast<size_t>(in->gcount()) == n;
  }
};

std::optional<StreamReader> open_file(const std::string& path) {
  std::error_code ec;
  const uint64_t size = std::filesystem::file_size(path, ec);
  if (ec) return std::nullopt;
  auto in = std::make_shared<std::ifstream>(path, std::ios::binary);
  if (!*in) return std::nullopt;
  return StreamReader{std::move(in), size};
}

// Does the file at `path` have code for ARM64?
bool has_arm64(const std::string& path) {
  auto reader = open_file(path);
  if (!reader) return false;
  auto slices = macho_slices(*reader, reader->size);
  if (!slices) return false;
  for (const FatArch& a : *slices)
    if (a.cputype == kCpuTypeArm64) return true;
  return false;
}

void entry_handler(EntryFrame& frame) { g_process->call_from_native(frame); }

}  // namespace

bool NativeSystem::file_exists(const std::string& path) {
  std::error_code ec;
  return std::filesystem::is_regular_file(path, ec);
}

MacProcess::MacProcess(MacOptions options, NativeSystem& native) : options_(std::move(options)), native_(native) {
  g_process = this;
  builtins_base_ = reserve_memory(kBuiltinCapacity * kBuiltinStride);
  if (!builtins_base_) throw std::bad_alloc();
  protect_memory(builtins_base_, kBuiltinCapacity * kBuiltinStride, kProtNone);
  builtins_end_ = builtins_base_ + kBuiltinCapacity * kBuiltinStride;
  builtins_.resize(kBuiltinCapacity);
  builtins_[0].name = "<return>";
  builtin_count_.store(1, std::memory_order_release);
  engine_ = std::make_unique<runtime::Engine>(*this, options_.engine);
  entry_ = native_entry(&entry_handler);
  register_builtins();
}

MacProcess::~MacProcess() {
  if (g_process == this) g_process = nullptr;
}

MacProcess* MacProcess::instance() { return g_process; }

// --- Loading ------------------------------------------------------------------------------

std::expected<GuestImage*, std::string> MacProcess::load_image(const std::string& path, bool main) {
  auto reader = open_file(path);
  if (!reader) return std::unexpected(std::format("can't open {}", path));
  auto image = map_image(path, *reader, reader->size);
  if (!image) return std::unexpected(std::format("{}: {}", path, image.error()));
  if (main && (*image)->file.filetype != kMhExecute) return std::unexpected(path + " is not a program");
  (*image)->main = main;
  GuestImage* raw = image->get();
  std::unique_lock lock(images_mutex_);
  images_.push_back(std::move(*image));
  return raw;
}

std::optional<std::string> MacProcess::find_library(const std::string& name, const GuestImage& loader) const {
  const std::string exe_dir = directory_of(images_.empty() ? std::string() : images_.front()->path);
  auto expand = [&](const std::string& path, const GuestImage& from) -> std::string {
    if (path == "@executable_path") return exe_dir;
    if (path == "@loader_path") return directory_of(from.path);
    if (path.starts_with("@executable_path/")) return join(exe_dir, std::string_view(path).substr(17));
    if (path.starts_with("@loader_path/")) return join(directory_of(from.path), std::string_view(path).substr(13));
    return path;
  };
  std::vector<std::string> candidates;
  const std::string leaf = name.substr(name.find_last_of('/') + 1);
  for (const std::string& dir : options_.library_paths) candidates.push_back(join(dir, leaf));
  if (name.starts_with("@rpath/")) {
    // The run paths of the loading image, then of the program.
    const std::string_view rest = std::string_view(name).substr(7);
    const GuestImage* program = images_.empty() ? nullptr : images_.front().get();
    for (const GuestImage* from : {&loader, program}) {
      if (!from) continue;
      for (const std::string& rpath : from->file.rpaths) candidates.push_back(join(expand(rpath, *from), rest));
    }
  } else {
    candidates.push_back(expand(name, loader));
  }
  for (const std::string& c : candidates)
    if (native_.file_exists(c) && has_arm64(c)) return std::filesystem::path(c).lexically_normal().generic_string();
  return std::nullopt;
}

std::expected<void, std::string> MacProcess::load_dependencies(GuestImage& image) {
  for (size_t k = 0; k < image.dependencies.size(); ++k) {
    Dependency& d = image.dependencies[k];
    const DylibRef& ref = image.file.dylibs[k];
    if (auto path = find_library(ref.name, image)) {
      GuestImage* found = nullptr;
      {
        std::shared_lock lock(images_mutex_);
        for (const auto& i : images_)
          if (i->path == *path) found = i.get();
      }
      if (!found) {
        auto loaded = load_image(*path, false);
        if (!loaded) return std::unexpected(loaded.error());
        found = *loaded;
        if (auto r = load_dependencies(*found); !r) return r;
      }
      d.kind = Dependency::Kind::Guest;
      d.image = found;
      continue;
    }
    if (void* handle = native_.open_library(ref.name)) {
      d.kind = Dependency::Kind::Native;
      d.native = handle;
      continue;
    }
    d.kind = Dependency::Kind::Missing;
    if (ref.kind != DylibRef::Kind::Weak)
      return std::unexpected(std::format("library not found: {} (needed by {})", ref.name, image.path));
  }
  return {};
}

uint64_t MacProcess::native_symbol(void* library, std::string_view name) {
  // C symbols carry a leading underscore in Mach-O, not in dlsym.
  if (!name.starts_with('_')) return 0;
  return reinterpret_cast<uint64_t>(native_.find_symbol(library, std::string(name.substr(1))));
}

uint64_t MacProcess::export_address(const GuestImage& image, std::string_view name, unsigned depth) {
  if (depth > 16) return 0;
  if (auto e = image.find_export(name)) {
    if (e->reexport()) {
      if (e->ordinal < 1 || static_cast<size_t>(e->ordinal) > image.dependencies.size()) return 0;
      const Dependency& d = image.dependencies[e->ordinal - 1];
      const std::string_view target = e->import_name.empty() ? name : std::string_view(e->import_name);
      if (d.kind == Dependency::Kind::Guest) return export_address(*d.image, target, depth + 1);
      if (d.kind == Dependency::Kind::Native) return native_symbol(d.native, target);
      return 0;
    }
    const uint64_t kind = e->flags & kExportKindMask;
    if (kind == kExportKindAbsolute) return e->address;
    if (e->flags & kExportStubAndResolver) return call_guest(image.header() + e->resolver, {});
    return image.header() + e->address;
  }
  // Libraries this one re-exports whole (umbrella frameworks).
  for (size_t k = 0; k < image.dependencies.size(); ++k) {
    if (image.file.dylibs[k].kind != DylibRef::Kind::Reexport) continue;
    const Dependency& d = image.dependencies[k];
    uint64_t v = 0;
    if (d.kind == Dependency::Kind::Guest) v = export_address(*d.image, name, depth + 1);
    else if (d.kind == Dependency::Kind::Native) v = native_symbol(d.native, name);
    if (v) return v;
  }
  return 0;
}

uint64_t MacProcess::global_symbol(std::string_view name) {
  if (const uint64_t b = builtin_address(name)) return b;
  for (GuestImage* i : images())
    if (const uint64_t v = export_address(*i, name)) return v;
  return native_symbol(nullptr, name);
}

uint64_t MacProcess::missing_symbol(const GuestImage& image, const Import& import) {
  (void)image;
  const std::string key = "<missing>" + import.name;
  if (const uint64_t a = builtin_address(key)) return a;
  Builtin b;
  b.name = key;
  b.missing = true;
  const uint64_t a = add_builtin_slot(std::move(b));
  std::lock_guard lock(builtins_mutex_);
  builtin_by_name_[key] = a;
  return a;
}

uint64_t MacProcess::resolve(GuestImage& image, const Import& import) {
  if (const uint64_t b = builtin_address(import.name)) return b;
  uint64_t v = 0;
  switch (import.ordinal) {
    case kOrdinalSelf: v = export_address(image, import.name); break;
    case kOrdinalMainExecutable: v = export_address(main_image(), import.name); break;
    case kOrdinalFlatLookup:
    case kOrdinalWeakLookup: v = global_symbol(import.name); break;
    default:
      if (import.ordinal > 0 && static_cast<size_t>(import.ordinal) <= image.dependencies.size()) {
        const Dependency& d = image.dependencies[import.ordinal - 1];
        if (d.kind == Dependency::Kind::Guest) v = export_address(*d.image, import.name);
        else if (d.kind == Dependency::Kind::Native) v = native_symbol(d.native, import.name);
        // Two-level namespace misses happen (symbols that moved between
        // libraries over macOS versions): fall back to any library.
        if (!v && d.kind != Dependency::Kind::Missing) v = global_symbol(import.name);
      }
      break;
  }
  if (options_.trace_binds) {
    std::fprintf(stderr, "[juice] bind %s from %s: 0x%" PRIx64 "%s\n", import.name.c_str(),
                 ordinal_name(image.file, import.ordinal).c_str(), v, v ? "" : (import.weak ? " (weak)" : " MISSING"));
  }
  if (!v && !import.weak) v = missing_symbol(image, import);
  if (v && !image_at(v) && !(v >= builtins_base_ && v < builtins_end_)) note_native_import(import.name, v);
  return v;
}

// Native functions whose variadic arguments are all integers or pointers:
// passed as such, from the guest's 8-byte slots.
void MacProcess::note_native_import(std::string_view name, uint64_t address) {
  struct IntVariadic {
    const char* name;
    const char* encoding;
    unsigned words;
  };
  static constexpr IntVariadic kIntVariadic[] = {
      {"_open", "i*i.", 1},   {"_openat", "ii*i.", 1}, {"_fcntl", "iii.", 1},
      {"_ioctl", "iiQ.", 1},  {"_sem_open", "^v*i.", 2}, {"_shm_open", "i*i.", 1},
  };
  for (const IntVariadic& v : kIntVariadic)
    if (name == v.name) set_native_signature(address, v.encoding, v.words);
}

std::expected<void, std::string> MacProcess::bind(GuestImage& image) {
  const Fixups& f = image.fixups;
  std::vector<uint64_t> resolved(f.imports.size(), 0);
  std::vector<bool> done(f.imports.size(), false);
  auto value_of = [&](uint32_t index) {
    if (!done[index]) {
      resolved[index] = resolve(image, f.imports[index]);
      done[index] = true;
    }
    return resolved[index];
  };
  for (const Bind& b : f.binds) {
    const uint64_t v = value_of(b.import);
    write_pointer(image.address(b.address), v ? v + b.addend : 0);
  }
  // Weak definitions: the first image defining the symbol wins.
  for (const Bind& b : f.weak_binds) {
    const uint64_t v = global_symbol(f.imports[b.import].name);
    if (v) write_pointer(image.address(b.address), v + b.addend);
  }
  return {};
}

std::expected<void, std::string> MacProcess::load(const std::string& path, const std::vector<std::string>& args,
                                                  const std::vector<std::string>& environment) {
  std::error_code ec;
  exe_path_ = std::filesystem::absolute(path, ec).lexically_normal().generic_string();
  if (ec) exe_path_ = path;
  auto main = load_image(exe_path_, true);
  if (!main) return std::unexpected(main.error());
  if (auto r = load_dependencies(**main); !r) return r;

  // Bind dependencies before the images that use them (resolvers run guest code).
  std::vector<GuestImage*> order;
  std::vector<GuestImage*> seen;
  std::function<void(GuestImage*)> visit = [&](GuestImage* i) {
    if (std::find(seen.begin(), seen.end(), i) != seen.end()) return;
    seen.push_back(i);
    for (const Dependency& d : i->dependencies)
      if (d.kind == Dependency::Kind::Guest) visit(d.image);
    order.push_back(i);
  };
  visit(*main);
  for (GuestImage* i : order) {
    if (auto r = bind(*i); !r) return r;
    register_tlv(*i);
    protect_image(*i);
  }
  for (GuestImage* i : order)
    for (const ImageHook& hook : bound_hooks_) hook(*i);

  arg_strings_.clear();
  arg_strings_.push_back(options_.argv0.empty() ? path : options_.argv0);
  for (const std::string& a : args) arg_strings_.push_back(a);
  env_strings_ = environment;
  apple_strings_ = {"executable_path=" + exe_path_};
  auto pointers = [](std::vector<std::string>& strings, std::vector<char*>& out) {
    out.clear();
    for (std::string& s : strings) out.push_back(s.data());
    out.push_back(nullptr);
  };
  pointers(arg_strings_, argv_);
  pointers(env_strings_, envp_);
  pointers(apple_strings_, apple_);
  return {};
}

GuestImage* MacProcess::open_guest_library(const std::string& path, const GuestImage* loader, std::string& error) {
  const GuestImage& from = loader ? *loader : main_image();
  const auto found = find_library(path, from);
  if (!found) return nullptr;
  {
    std::shared_lock lock(images_mutex_);
    for (const auto& i : images_)
      if (i->path == *found || i->install_name == path) return i.get();
  }
  auto image = load_image(*found, false);
  if (!image) {
    error = image.error();
    return nullptr;
  }
  if (auto r = load_dependencies(**image); !r) {
    error = r.error();
    return nullptr;
  }
  if (auto r = bind(**image); !r) {
    error = r.error();
    return nullptr;
  }
  register_tlv(**image);
  protect_image(**image);
  for (const ImageHook& hook : bound_hooks_) hook(**image);
  run_initializers(**image);
  return *image;
}

GuestImage* MacProcess::image_at(uint64_t addr) const {
  std::shared_lock lock(images_mutex_);
  for (const auto& i : images_)
    if (i->contains(addr)) return i.get();
  return nullptr;
}

bool MacProcess::is_guest_code(uint64_t addr) const {
  const GuestImage* i = image_at(addr);
  return i && i->is_code(addr);
}

std::vector<GuestImage*> MacProcess::images() const {
  std::shared_lock lock(images_mutex_);
  std::vector<GuestImage*> out;
  for (const auto& i : images_) out.push_back(i.get());
  return out;
}

// --- Thread-local variables ----------------------------------------------------------------

void MacProcess::register_tlv(GuestImage& image) {
  const auto vars = image.section_data<uint64_t>("__DATA", "__thread_vars");
  if (vars.empty()) return;
  uint64_t begin = ~0ull, data_end = 0, end = 0;
  for (const Segment& seg : image.file.segments) {
    for (const Section& s : seg.sections) {
      if (s.type() == kSThreadLocalRegular || s.type() == kSThreadLocalZerofill) {
        begin = std::min(begin, s.addr);
        end = std::max(end, s.addr + s.size);
        if (s.type() == kSThreadLocalRegular) data_end = std::max(data_end, s.addr + s.size);
      }
    }
  }
  if (begin == ~0ull) begin = data_end = end = 0;
  uint32_t key;
  {
    std::lock_guard lock(tlv_mutex_);
    key = static_cast<uint32_t>(tlv_templates_.size());
    TlvTemplate t;
    t.data = begin ? image.address(begin) : 0;
    t.data_size = data_end > begin ? data_end - begin : 0;
    t.total_size = end - begin;
    tlv_templates_.push_back(t);
    tlv_key_by_image_[image.header()] = key;
  }
  // Each descriptor: {thunk, key, offset}.
  for (size_t k = 0; k + 2 < vars.size(); k += 3) vars[k + 1] = key;
}

uint64_t MacProcess::tlv_address(uint64_t descriptor) {
  const auto* d = reinterpret_cast<const uint64_t*>(descriptor);
  const uint64_t key = d[1], offset = d[2];
  MacThread& t = thread();
  if (key >= t.tlv_blocks.size()) t.tlv_blocks.resize(key + 1, 0);
  if (!t.tlv_blocks[key]) {
    TlvTemplate tmpl;
    {
      std::lock_guard lock(tlv_mutex_);
      if (key >= tlv_templates_.size()) fatal(std::format("thread-local variable with unknown key {}", key));
      tmpl = tlv_templates_[key];
    }
    auto* block = static_cast<uint8_t*>(::operator new(tmpl.total_size + 16, std::align_val_t{16}));
    std::memset(block, 0, tmpl.total_size + 16);
    if (tmpl.data_size) std::memcpy(block, reinterpret_cast<const void*>(tmpl.data), tmpl.data_size);
    t.tlv_blocks[key] = reinterpret_cast<uint64_t>(block);
  }
  return t.tlv_blocks[key] + offset;
}

// --- Running --------------------------------------------------------------------------------

MacThread& MacProcess::thread() {
  if (!t_thread) {
    auto* t = new MacThread();
    uint64_t size = kDefaultStackSize;
    // The first thread is the main thread: the program may ask for a larger stack.
    if (!main_thread_created_ && !images_.empty()) size = std::max(size, images_.front()->file.stack_size);
    main_thread_created_ = true;
    t->stack_base = reserve_memory(size);
    if (!t->stack_base) fatal("can't allocate a guest stack");
    t->stack_size = size;
    t->state.sp = (t->stack_base + size) & ~uint64_t{15};
    t_thread = t;
  }
  return *t_thread;
}

void MacProcess::call_guest(uint64_t fn, arm64::CpuState& s) {
  MacThread& t = thread();
  if (!s.sp) {
    const uint64_t below = t.active ? t.active->sp : t.state.sp;
    s.sp = (below - kRedZone) & ~uint64_t{15};
  }
  s.x[30] = builtins_base_;  // the return sentinel
  s.pc = fn;
  arm64::CpuState* outer = t.active;
  t.active = &s;
  ++t.depth;
  struct Restore {
    MacThread& t;
    arm64::CpuState* outer;
    ~Restore() {
      t.active = outer;
      --t.depth;
    }
  } restore{t, outer};
  engine_->run(s, builtins_base_);
}

uint64_t MacProcess::call_guest(uint64_t fn, std::initializer_list<uint64_t> args) {
  MacThread& t = thread();
  arm64::CpuState s = t.active ? *t.active : t.state;
  s.sp = 0;
  size_t k = 0;
  for (uint64_t a : args)
    if (k < 8) s.x[k++] = a;
  call_guest(fn, s);
  return s.x[0];
}

void MacProcess::call_from_native(EntryFrame& frame) {
  MacThread& t = thread();
  const uint64_t target = frame.target;
  if (options_.trace_calls) {
    std::fprintf(stderr, "[juice] callback 0x%" PRIx64 "(0x%" PRIx64 ", 0x%" PRIx64 ", 0x%" PRIx64 ") from native code\n",
                 target, frame.args.gpr[0], frame.args.gpr[1], frame.args.gpr[2]);
  }
  arm64::CpuState s = t.active ? *t.active : t.state;
  const uint64_t below = ((t.active ? t.active->sp : t.state.sp) - kRedZone) & ~uint64_t{15};

  // A builtin's address handed to native code (a function pointer taken by the guest).
  if (target >= builtins_base_ && target < builtins_end_) {
    const size_t index = (target - builtins_base_) / kBuiltinStride;
    if (index == 0 || index >= builtin_count_.load(std::memory_order_acquire) || !builtins_[index].fn)
      fatal(std::format("native code called JUICE's address 0x{:x}", target));
    generic_args_to_guest(frame.args, s);
    s.sp = below;
    builtins_[index].fn(*this, s);
    generic_result_to_host(s, frame.result);
    return;
  }

  const FunctionType* type = nullptr;
  {
    std::shared_lock lock(types_mutex_);
    if (auto it = guest_types_.find(target); it != guest_types_.end()) type = &it->second;
  }
  if (!type && signature_lookup_) {
    if (const char* encoding = signature_lookup_(target, frame.args.gpr[0])) {
      set_guest_signature(target, encoding);
      std::shared_lock lock(types_mutex_);
      if (auto it = guest_types_.find(target); it != guest_types_.end()) type = &it->second;
    }
  }
  if (type) {
    GuestStackArea area;
    area.base = (below - kMaxArgumentArea) & ~uint64_t{15};
    if (auto r = host_args_to_guest(*type, frame.args, s, area); !r)
      fatal(std::format("callback 0x{:x}: {}", target, r.error()));
    if (area.bytes.size() > kMaxArgumentArea) fatal(std::format("callback 0x{:x}: too many stack arguments", target));
    std::memcpy(reinterpret_cast<void*>(area.base), area.bytes.data(), area.bytes.size());
    s.sp = area.base;
    call_guest(target, s);
    guest_result_to_host(*type, frame.args, s, frame.result);
    frame.x87_result = type->ret.kind == CType::Kind::LongDouble;
  } else {
    generic_args_to_guest(frame.args, s);
    s.sp = below;
    call_guest(target, s);
    generic_result_to_host(s, frame.result);
  }
}

void MacProcess::add_image_hooks(ImageHook bound, ImageHook before_initializers) {
  if (bound) bound_hooks_.push_back(std::move(bound));
  if (before_initializers) init_hooks_.push_back(std::move(before_initializers));
}

void MacProcess::set_guest_signature(uint64_t fn, std::string_view encoding) {
  auto type = parse_function(encoding);
  if (!type) return;
  std::unique_lock lock(types_mutex_);
  guest_types_.insert_or_assign(fn, std::move(*type));
}

void MacProcess::set_native_signature(uint64_t fn, std::string_view encoding, unsigned variadic_words) {
  auto type = parse_function(encoding);
  if (!type) return;
  std::unique_lock lock(types_mutex_);
  NativeType& t = native_types_[fn];
  t.type = std::move(*type);
  t.variadic_words = variadic_words;
}

void MacProcess::call_native_function(uint64_t fn, arm64::CpuState& s, const FunctionType* type,
                                      unsigned variadic_words) {
  if (!type) {
    std::shared_lock lock(types_mutex_);
    if (auto it = native_types_.find(fn); it != native_types_.end() && it->second.type) {
      type = &*it->second.type;
      variadic_words = it->second.variadic_words;
    }
  }
  if (options_.trace_calls) {
    std::string name = native_.describe(fn);
    std::fprintf(stderr, "[juice] native %s(0x%" PRIx64 ", 0x%" PRIx64 ", 0x%" PRIx64 ")\n",
                 name.empty() ? std::format("0x{:x}", fn).c_str() : name.c_str(), s.x[0], s.x[1], s.x[2]);
  }
  HostCall call;
  HostResult result;
  if (type) {
    if (auto r = guest_args_to_host(*type, s, call, variadic_words); !r)
      fatal(std::format("call of native 0x{:x}: {}", fn, r.error()), &s);
  } else {
    generic_args_to_host(s, call);
  }
  call_native(reinterpret_cast<void*>(fn), call, result, type && type->ret.kind == CType::Kind::LongDouble);
  if (type) host_result_to_guest(*type, call, result, s);
  else generic_result_to_guest(result, s);
}

void MacProcess::run_initializers(GuestImage& image) {
  if (image.initialized) return;
  image.initialized = true;
  for (const Dependency& d : image.dependencies)
    if (d.kind == Dependency::Kind::Guest && d.image != &image) run_initializers(*d.image);
  for (const ImageHook& hook : init_hooks_) hook(image);
  const uint64_t argc_value = static_cast<uint64_t>(argc());
  const auto argv_value = reinterpret_cast<uint64_t>(argv_.data());
  const auto envp_value = reinterpret_cast<uint64_t>(envp_.data());
  const auto apple_value = reinterpret_cast<uint64_t>(apple_.data());
  for (const Segment& seg : image.file.segments) {
    for (const Section& s : seg.sections) {
      if (s.type() == kSModInitFuncPointers) {
        for (uint64_t k = 0; k + 8 <= s.size; k += 8) {
          uint64_t fn;
          std::memcpy(&fn, reinterpret_cast<const void*>(image.address(s.addr) + k), 8);
          if (fn) call_guest(fn, {argc_value, argv_value, envp_value, apple_value});
        }
      } else if (s.type() == kSInitFuncOffsets) {
        for (uint64_t k = 0; k + 4 <= s.size; k += 4) {
          uint32_t offset;
          std::memcpy(&offset, reinterpret_cast<const void*>(image.address(s.addr) + k), 4);
          call_guest(image.header() + offset, {argc_value, argv_value, envp_value, apple_value});
        }
      }
    }
  }
}

int MacProcess::run() {
  GuestImage& program = main_image();
  const uint64_t entry = program.file.entry_address();
  if (!program.file.has_main) fatal("the program has no LC_MAIN entry point (an old-style executable)");
  thread();  // the main thread's stack, with the program's requested size
  run_initializers(program);
  arm64::CpuState s = thread().state;
  s.x[0] = static_cast<uint64_t>(argc());
  s.x[1] = reinterpret_cast<uint64_t>(argv_.data());
  s.x[2] = reinterpret_cast<uint64_t>(envp_.data());
  s.x[3] = reinterpret_cast<uint64_t>(apple_.data());
  call_guest(program.address(entry), s);
  return static_cast<int>(s.x[0]);
}

// --- runtime::Environment ---------------------------------------------------------------------

bool MacProcess::read_code(uint64_t addr, uint32_t& word) {
  const GuestImage* i = image_at(addr);
  if (!i || !i->is_code(addr) || !i->is_code(addr + 3)) return false;
  std::memcpy(&word, reinterpret_cast<const void*>(addr), 4);
  return true;
}

bool MacProcess::is_host_code(uint64_t pc) { return !image_at(pc) && native_.is_native_code(pc); }

runtime::Action MacProcess::on_host_address(arm64::CpuState& s) {
  const uint64_t pc = s.pc;
  if (pc >= builtins_base_ && pc < builtins_end_) {
    const size_t index = (pc - builtins_base_) / kBuiltinStride;
    if (index == 0) return runtime::Action::Stop;  // the return sentinel
    if ((pc - builtins_base_) % kBuiltinStride || index >= builtin_count_.load(std::memory_order_acquire))
      fatal(std::format("jump into JUICE's address range at 0x{:x}", pc), &s);
    const Builtin& b = builtins_[index];
    if (b.missing) fatal(std::format("call of a missing function: {}", b.name.substr(9)), &s);
    s.pc = s.x[30];
    if (b.native) call_va_builtin(b, s);
    else b.fn(*this, s);
    return runtime::Action::Continue;
  }
  // Native code: call it, then return to the guest's link register.
  call_native_function(pc, s);
  s.pc = s.x[30];
  return runtime::Action::Continue;
}

runtime::Action MacProcess::on_exit(arm64::CpuState& s) {
  const auto reason = static_cast<arm64::ExitReason>(s.exit_reason);
  switch (reason) {
    case arm64::ExitReason::Brk:
      fatal(std::format("breakpoint (BRK #{}) at 0x{:x}", s.exit_info, s.pc), &s);
    case arm64::ExitReason::FetchFault: {
      const std::string where = native_.describe(s.pc);
      fatal(std::format("jump to 0x{:x}, which is neither guest code nor a native function{}", s.pc,
                        where.empty() ? "" : " (" + where + ")"),
            &s);
    }
    case arm64::ExitReason::MemoryFault:
      fatal(std::format("memory fault at 0x{:x} accessing 0x{:x}", s.pc, s.fault_address), &s);
    default:
      fatal(std::format("{} at 0x{:x} (0x{:08x})", arm64::to_string(reason), s.pc, s.exit_info), &s);
  }
}

// --- Builtins --------------------------------------------------------------------------------

uint64_t MacProcess::add_builtin_slot(Builtin b) {
  std::lock_guard lock(builtins_mutex_);
  const size_t index = builtin_count_.load(std::memory_order_relaxed);
  if (index >= kBuiltinCapacity) fatal("too many builtins");
  builtins_[index] = std::move(b);
  builtin_count_.store(index + 1, std::memory_order_release);
  return builtins_base_ + index * kBuiltinStride;
}

void MacProcess::add_builtin(std::string name, BuiltinFn fn) {
  Builtin b;
  b.name = name;
  b.fn = fn;
  const uint64_t a = add_builtin_slot(std::move(b));
  std::lock_guard lock(builtins_mutex_);
  builtin_by_name_[std::move(name)] = a;
}

uint64_t MacProcess::builtin_address(std::string_view name) const {
  std::lock_guard lock(builtins_mutex_);
  auto it = builtin_by_name_.find(std::string(name));
  return it == builtin_by_name_.end() ? 0 : it->second;
}

// --- Diagnostics -----------------------------------------------------------------------------

void MacProcess::dump_state(const arm64::CpuState& s) const {
  for (int k = 0; k < 31; k += 2) {
    std::fprintf(stderr, "  x%-2d %016" PRIx64, k, s.x[k]);
    if (k + 1 < 31) std::fprintf(stderr, "   x%-2d %016" PRIx64, k + 1, s.x[k + 1]);
    std::fputc('\n', stderr);
  }
  std::fprintf(stderr, "  sp  %016" PRIx64 "   pc  %016" PRIx64 "\n", s.sp, s.pc);
  if (const GuestImage* i = image_at(s.pc))
    std::fprintf(stderr, "  pc is %s+0x%" PRIx64 "\n", i->path.c_str(), s.pc - i->header());
}

void MacProcess::fatal(const std::string& message, const arm64::CpuState* s) {
  std::fprintf(stderr, "juice: %s\n", message.c_str());
  if (s) dump_state(*s);
  std::fflush(stderr);
  std::_Exit(134);
}

}  // namespace juice::mac
