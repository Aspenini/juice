#pragma once

// A macOS ARM64 program running under JUICE on x86-64 macOS.
//
// The program and the libraries it brings (its frameworks and dylibs) are
// guest images, translated; the system's libraries (libSystem, Foundation,
// AppKit, ...) are the host's own x86-64 ones, called natively. Guest and
// host share the address space:
//
//   - Guest code calling native code: the guest's pointers to native
//     functions are their real addresses (binds resolve to them), so native
//     code given one back can call it. When guest execution reaches native
//     code (is_host_code), the call is made natively with its arguments
//     converted from the ARM64 to the x86-64 convention (call_convert.hpp):
//     by the function's type when JUICE knows it, generically otherwise.
//   - Native code calling guest code (callbacks, Objective-C methods, block
//     invocations): guest code is never executable for the host, so the
//     call faults; the platform's fault handler sends it to entry(), which
//     runs the guest function with converted arguments.
//   - Some functions are JUICE's own (builtins): those that need the guest's
//     state or its images (dlopen, dlsym, the dyld image APIs, thread-local
//     variables, objc_msgSend's dispatch, setjmp, variadic functions).
//
// Platform specifics (dlopen, the fault handler) come through NativeSystem,
// so this core is portable: the tests run it on Windows with fake libraries.

#include <atomic>
#include <cstdint>
#include <expected>
#include <functional>
#include <initializer_list>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "core/arm64/state/cpu_state.hpp"
#include "macos/abi/call_convert.hpp"
#include "macos/abi/ctype.hpp"
#include "macos/abi/trampolines.hpp"
#include "macos/eh/guest_exceptions.hpp"
#include "macos/loader/guest_image.hpp"
#include "runtime/engine.hpp"

namespace juice::mac {

// What the host provides.
class NativeSystem {
 public:
  virtual ~NativeSystem() = default;
  // The host's library with this install name (dlopen), nullptr if none.
  virtual void* open_library(const std::string& install_name) = 0;
  // A symbol (without the Mach-O leading underscore) of `library`, or of any
  // library when `library` is nullptr (dlsym); nullptr if none.
  virtual void* find_symbol(void* library, const std::string& name) = 0;
  // Is `addr` native code (a function the guest may call)?
  virtual bool is_native_code(uint64_t addr) = 0;
  // "library`symbol+offset" for an address in native code (diagnostics).
  virtual std::string describe(uint64_t addr) {
    (void)addr;
    return {};
  }
  // Does a file exist at `path`?
  virtual bool file_exists(const std::string& path);
  // Copies `size` bytes at `addr` if they're readable (without faulting).
  virtual bool read_memory(uint64_t addr, void* out, size_t size) {
    (void)addr, (void)out, (void)size;
    return false;
  }
  // Raises an exception (an _Unwind_Exception) natively from here, for the
  // native code that called the guest; returns if nothing handles it.
  virtual void raise_exception(uint64_t exception) { (void)exception; }
};

struct MacOptions {
  runtime::EngineOptions engine;
  bool trace_calls = false;  // log native calls and callbacks
  bool trace_binds = false;  // log how imports resolve
  bool stats = false;
  std::vector<std::string> library_paths;  // searched for libraries (as DYLD_LIBRARY_PATH)
  std::string argv0;                       // argv[0] for the program (default: its path)
};

// The guest context of one host thread.
struct MacThread {
  arm64::CpuState state{};       // the outermost guest call's state
  arm64::CpuState* active = nullptr;  // the innermost running guest call's state
  uint64_t stack_base = 0, stack_size = 0;
  std::vector<uint64_t> tlv_blocks;  // thread-local variable blocks, by image key
  unsigned depth = 0;
};

class MacProcess;
// JUICE's implementation of a function the guest imports: reads the
// arguments from `s`, sets the results there. `s.pc` is the return address
// on entry and where execution continues afterwards (a builtin may change it).
using BuiltinFn = void (*)(MacProcess& p, arm64::CpuState& s);

class MacProcess final : public runtime::Environment {
 public:
  MacProcess(MacOptions options, NativeSystem& native);
  ~MacProcess() override;
  MacProcess(const MacProcess&) = delete;
  MacProcess& operator=(const MacProcess&) = delete;

  // The process (one per host process).
  static MacProcess* instance();

  // Loads the program and its libraries, and binds them.
  std::expected<void, std::string> load(const std::string& path, const std::vector<std::string>& args,
                                        const std::vector<std::string>& environment);
  // Runs the initializers and main(); returns main's result.
  int run();

  // --- runtime::Environment -------------------------------------------------------
  bool read_code(uint64_t addr, uint32_t& word) override;
  std::pair<uint64_t, uint64_t> host_range() const override { return {builtins_base_, builtins_end_}; }
  runtime::Action on_host_address(arm64::CpuState& s) override;
  bool is_host_code(uint64_t pc) override;
  runtime::Action on_exit(arm64::CpuState& s) override;

  // --- Images -----------------------------------------------------------------------
  GuestImage* image_at(uint64_t addr) const;
  bool is_guest_code(uint64_t addr) const;
  GuestImage& main_image() const { return *images_.front(); }
  std::vector<GuestImage*> images() const;
  // dlopen of a guest library (nullptr: not a guest library; `error` says why if it's an error).
  GuestImage* open_guest_library(const std::string& path, const GuestImage* loader, std::string& error);
  // An image's exported symbol (Mach-O name), following re-exports: a guest
  // address, a native address, or 0.
  uint64_t export_address(const GuestImage& image, std::string_view name, unsigned depth = 0);
  // Any image's (dlsym(RTLD_DEFAULT)): guest images first, then native libraries.
  uint64_t global_symbol(std::string_view name);

  // --- Calls --------------------------------------------------------------------------
  MacThread& thread();
  // Runs guest function `fn` on this thread with `s` as its state (arguments
  // set by the caller; SP chosen below the current guest frames if 0) until it
  // returns. `s` holds the results afterwards.
  void call_guest(uint64_t fn, arm64::CpuState& s);
  // With integer arguments; returns X0.
  uint64_t call_guest(uint64_t fn, std::initializer_list<uint64_t> args);
  // Native code called guest code (the System V entry; target in frame.target).
  void call_from_native(EntryFrame& frame);
  // The System V entry point for native calls into guest code: the platform's
  // fault handler continues a native call of guest address `target` there with R11 = target.
  void* entry() const { return entry_; }

  // The type of a guest function native code may call (Objective-C method
  // implementations, block invocations), as a type encoding.
  void set_guest_signature(uint64_t fn, std::string_view encoding);
  // The type of a native function, by address; for a variadic one, how many
  // 8-byte argument slots to pass after the fixed arguments (as integers).
  void set_native_signature(uint64_t fn, std::string_view encoding, unsigned variadic_words = 0);

  // Calls native function `fn` with the guest's arguments in `s` (by its type
  // if known) and sets the results; `s.pc` is unchanged.
  void call_native_function(uint64_t fn, arm64::CpuState& s, const FunctionType* type = nullptr,
                            unsigned variadic_words = 0);

  // --- Builtins -----------------------------------------------------------------------
  // Registers a builtin for imports named `name` (a Mach-O name: "_dlsym").
  void add_builtin(std::string name, BuiltinFn fn);
  // Registers variadic function `name` (taking `fixed` arguments before the
  // variadic ones) to be called as native function `va_name` with a va_list;
  // `from_va_list`: `name` itself takes a va_list (vprintf).
  void add_va_builtin(std::string name, const char* va_name, unsigned fixed, bool from_va_list);
  // The address guest code calls for a builtin registered under `name` (0 if none).
  uint64_t builtin_address(std::string_view name) const;

  // Hooks for each guest image: after it's bound (dependencies first), and
  // just before its initializers run. (The Objective-C bridge registers
  // the image's classes, then calls their +load methods.)
  using ImageHook = std::function<void(GuestImage&)>;
  void add_image_hooks(ImageHook bound, ImageHook before_initializers);
  // A guest function native code may call when it's not known by address:
  // asked for the type of `fn` called with first argument `first` (blocks).
  using SignatureLookup = std::function<const char*(uint64_t fn, uint64_t first)>;
  void set_signature_lookup(SignatureLookup lookup) { signature_lookup_ = std::move(lookup); }

  const MacOptions& options() const { return options_; }
  NativeSystem& native() { return native_; }
  GuestExceptions& exceptions() { return *exceptions_; }
  runtime::Engine& engine() { return *engine_; }

  // Program information
  int argc() const { return static_cast<int>(argv_.size()) - 1; }
  char** argv() { return argv_.data(); }
  char** envp() { return envp_.data(); }
  char** apple() { return apple_.data(); }
  const std::string& executable_path() const { return exe_path_; }

  // Thread-local variables (__thread_vars): the address of variable `descriptor` for this thread.
  uint64_t tlv_address(uint64_t descriptor);

  [[noreturn]] void fatal(const std::string& message, const arm64::CpuState* s = nullptr);

 private:
  struct Builtin {
    std::string name;
    BuiltinFn fn = nullptr;
    bool missing = false;  // a missing symbol's stub (calling it is an error)
    // A variadic function, called through its va_list form `native`: the first
    // `fixed` arguments are passed on, then a host va_list over the guest's
    // variadic arguments (on its stack, or its va_list if `from_va_list`).
    uint64_t native = 0;
    unsigned fixed = 0;
    bool from_va_list = false;
  };
  struct NativeType {
    std::optional<FunctionType> type;
    unsigned variadic_words = 0;
  };

  std::expected<GuestImage*, std::string> load_image(const std::string& path, bool main);
  std::expected<void, std::string> load_dependencies(GuestImage& image);
  std::optional<std::string> find_library(const std::string& install_name, const GuestImage& loader) const;
  std::expected<void, std::string> bind(GuestImage& image);
  uint64_t resolve(GuestImage& image, const Import& import);
  uint64_t native_symbol(void* library, std::string_view name);
  uint64_t missing_symbol(const GuestImage& image, const Import& import);
  void note_native_import(std::string_view name, uint64_t address);
  void run_initializers(GuestImage& image);
  void register_tlv(GuestImage& image);
  void register_builtins();
  uint64_t add_builtin_slot(Builtin b);
  void call_va_builtin(const Builtin& b, arm64::CpuState& s);
  void dump_state(const arm64::CpuState& s) const;

  MacOptions options_;
  NativeSystem& native_;
  std::unique_ptr<runtime::Engine> engine_;
  std::unique_ptr<GuestExceptions> exceptions_;
  void* entry_ = nullptr;

  mutable std::shared_mutex images_mutex_;
  std::vector<std::unique_ptr<GuestImage>> images_;  // the program first

  uint64_t builtins_base_ = 0, builtins_end_ = 0;  // inaccessible: builtin k at base + 16 k
  std::vector<Builtin> builtins_;                  // [0] is the return sentinel
  std::atomic<size_t> builtin_count_{0};
  std::unordered_map<std::string, uint64_t> builtin_by_name_;
  mutable std::mutex builtins_mutex_;
  bool main_thread_created_ = false;

  std::shared_mutex types_mutex_;
  std::unordered_map<uint64_t, NativeType> native_types_;
  std::unordered_map<uint64_t, FunctionType> guest_types_;

  // Thread-local variables: per image with __thread_vars, a key; per thread, blocks.
  struct TlvTemplate {
    uint64_t data = 0, data_size = 0, total_size = 0;  // the initial contents, then zeros
  };
  std::mutex tlv_mutex_;
  std::vector<TlvTemplate> tlv_templates_;
  std::unordered_map<uint64_t, uint32_t> tlv_key_by_image_;  // image header -> key

  std::vector<ImageHook> bound_hooks_, init_hooks_;
  SignatureLookup signature_lookup_;

  std::string exe_path_;
  std::vector<std::string> arg_strings_, env_strings_, apple_strings_;
  std::vector<char*> argv_, envp_, apple_;
};

}  // namespace juice::mac
