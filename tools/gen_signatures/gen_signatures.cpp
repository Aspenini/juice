// gen_signatures: generates JUICE's tables of native function and COM method
// signatures from the Windows SDK headers (tools/gen_signatures/sdk_headers.h).
//
// Windows ARM64 and Windows x64 agree on where integer and pointer arguments
// go, so JUICE's generic call bridge passes argument k as both the k-th integer
// and the k-th floating point argument. That is wrong for functions that mix
// integer and floating point arguments, pass small structures or structures
// of floats (HFAs) by value, or return structures other than 1, 2, 4 or 8
// bytes. This tool finds those functions and methods and writes their argument
// kinds (see src/windows/thunk/native_call.cpp for the notation). It also marks
// arguments that hand native code something it will call back with arguments
// of that kind: function pointers (C<n>: callback_signatures_generated.inc) and
// interface pointers (I<n>: com_interfaces_generated.inc), so that JUICE can
// convert those calls from x64 back to ARM64.
//
//   gen_signatures <output dir>   ->  signatures_generated.inc, com_signatures_generated.inc
//
// Build: xmake build juice-gen-signatures (needs LLVM's libclang).

#include <clang-c/Index.h>

#include <algorithm>
#include <cstdlib>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace {

std::string str(CXString s) {
  const char* c = clang_getCString(s);
  std::string out = c ? c : "";
  clang_disposeString(s);
  return out;
}

// Homogeneous floating point aggregate: up to four floats or four doubles.
struct Hfa {
  char elem = 0;  // 'f' or 'd'
  int count = 0;
};

bool collect_hfa(CXType t, Hfa& h, int depth = 0) {
  t = clang_getCanonicalType(t);
  if (depth > 8) return false;
  switch (t.kind) {
    case CXType_Float:
    case CXType_Double:
    case CXType_LongDouble: {
      const char e = t.kind == CXType_Float ? 'f' : 'd';
      if (h.elem && h.elem != e) return false;
      h.elem = e;
      return ++h.count <= 4;
    }
    case CXType_ConstantArray: {
      const long long n = clang_getNumElements(t);
      for (long long k = 0; k < n; ++k)
        if (!collect_hfa(clang_getArrayElementType(t), h, depth + 1)) return false;
      return true;
    }
    case CXType_Record: {
      CXCursor decl = clang_getTypeDeclaration(t);
      if (clang_getCursorKind(decl) == CXCursor_UnionDecl) return false;
      struct State {
        Hfa* h;
        int depth;
        bool ok = true;
        int fields = 0;
      } st{&h, depth};
      clang_Type_visitFields(
          t,
          [](CXCursor field, CXClientData data) {
            auto* s = static_cast<State*>(data);
            ++s->fields;
            if (clang_Cursor_isBitField(field) || !collect_hfa(clang_getCursorType(field), *s->h, s->depth + 1)) {
              s->ok = false;
              return CXVisit_Break;
            }
            return CXVisit_Continue;
          },
          &st);
      return st.ok && st.fields > 0;
    }
    default:
      return false;
  }
}

struct TypeContext;
std::string pointer_token(CXType pointee, TypeContext* ctx);

// Argument kind tokens: i (integer, pointer, or a structure passed the same way),
// f (float or double), S<n> (a structure of n bytes, n not 1, 2, 4 or 8, at
// most 16: in registers on ARM64, a pointer to a copy on x64), H<count><f|d> (HFA),
// and with a context, C<n> / I<n> for callback / interface pointers.
std::optional<std::string> classify_arg(CXType t, TypeContext* ctx = nullptr) {
  t = clang_getCanonicalType(t);
  switch (t.kind) {
    case CXType_Pointer:
      return ctx ? pointer_token(clang_getCanonicalType(clang_getPointeeType(t)), ctx) : std::string("i");
    case CXType_Float:
    case CXType_Double:
    case CXType_LongDouble:
      return "f";
    case CXType_Vector:
    case CXType_Int128:
    case CXType_UInt128:
    case CXType_Complex:
      return std::nullopt;
    case CXType_Record: {
      const long long size = clang_Type_getSizeOf(t);
      const long long align = clang_Type_getAlignOf(t);
      if (size <= 0 || align > 8) return std::nullopt;
      Hfa h;
      if (collect_hfa(t, h) && h.count >= 1 && h.count <= 4) return "H" + std::to_string(h.count) + h.elem;
      if (size > 16 || size == 1 || size == 2 || size == 4 || size == 8) return "i";
      return "S" + std::to_string(size);
    }
    default:
      return "i";
  }
}

// Return kind prefix (with ':'), empty when X0/D0 <- RAX/XMM0 is right.
std::optional<std::string> classify_return(CXType t) {
  t = clang_getCanonicalType(t);
  switch (t.kind) {
    case CXType_Vector:
    case CXType_Int128:
    case CXType_UInt128:
    case CXType_Complex:
      return std::nullopt;
    case CXType_Record: {
      const long long size = clang_Type_getSizeOf(t);
      if (size <= 0 || clang_Type_getAlignOf(t) > 8) return std::nullopt;
      Hfa h;
      if (collect_hfa(t, h) && h.count >= 1 && h.count <= 4) return "H" + std::to_string(h.count) + h.elem + ":";
      if (size == 1 || size == 2 || size == 4 || size == 8) return "";
      if (size <= 16) return "S" + std::to_string(size) + ":";
      return "L:";
    }
    default:
      return "";
  }
}

// The signature of a function type (no context: plain argument kinds), "" if
// the generic bridge handles it, nullopt if unsupported.
std::optional<std::string> type_signature(CXType type, bool method, TypeContext* ctx);

// True if the generic bridge already passes these arguments correctly.
bool generic_ok(const std::string& ret, const std::vector<std::string>& args) {
  if (!ret.empty()) return false;
  bool all_int = true, all_fp = true;
  for (const std::string& a : args) {
    all_int &= a == "i";
    all_fp &= a == "f";
  }
  return all_int || (all_fp && args.size() <= 4);
}

std::string join(const std::string& ret, const std::vector<std::string>& args) {
  std::string s = ret;
  for (const std::string& a : args) s += a;
  return s;
}

struct ComInterface {
  std::string name;
  std::string base;
  std::string uuid;  // empty if the declaration has none
  std::vector<std::pair<std::string, CXCursor>> virtuals;  // own methods in vtable order
  std::vector<std::pair<std::string, std::string>> methods;  // (name, signature or "" if generic), own methods in slot order
  bool relevant = false;  // a method (own or inherited) needs a signature
  int index = -1;         // in com_interfaces_generated.inc
};

// What argument tokens may refer to: interfaces whose methods need signatures,
// and callback signatures.
struct TypeContext {
  std::map<std::string, ComInterface>* interfaces;
  std::vector<std::string>* interface_table;  // index -> name
  std::vector<std::string> callbacks;         // index -> signature
};

int interface_index(TypeContext* ctx, const std::string& name) {
  auto it = ctx->interfaces->find(name);
  if (it == ctx->interfaces->end() || !it->second.relevant || it->second.uuid.empty()) return -1;
  if (it->second.index < 0) {
    it->second.index = static_cast<int>(ctx->interface_table->size());
    ctx->interface_table->push_back(name);
  }
  return it->second.index;
}

std::string pointer_token(CXType pointee, TypeContext* ctx) {
  if (pointee.kind == CXType_FunctionProto) {
    const std::optional<std::string> sig = type_signature(pointee, false, nullptr);
    if (!sig || sig->empty()) return "i";
    auto it = std::find(ctx->callbacks.begin(), ctx->callbacks.end(), *sig);
    const size_t index = static_cast<size_t>(it - ctx->callbacks.begin());
    if (it == ctx->callbacks.end()) ctx->callbacks.push_back(*sig);
    return "C" + std::to_string(index);
  }
  if (pointee.kind == CXType_Record) {
    const std::string name = str(clang_getCursorSpelling(clang_getTypeDeclaration(pointee)));
    const int index = interface_index(ctx, name);
    if (index >= 0) return "I" + std::to_string(index);
  }
  return "i";
}

std::optional<std::string> type_signature(CXType type, bool method, TypeContext* ctx) {
  std::vector<std::string> args;
  if (method) args.push_back("i");  // this
  std::optional<std::string> ret = classify_return(clang_getResultType(type));
  if (!ret) return std::nullopt;
  if (method && !ret->empty()) {
    // Member functions return structures through a hidden pointer after
    // `this` on both ARM64 (X1) and x64 (RDX).
    args.push_back("i");
    ret = "";
  }
  const int n = clang_getNumArgTypes(type);
  if (n < 0) return std::nullopt;
  for (int k = 0; k < n; ++k) {
    std::optional<std::string> a = classify_arg(clang_getArgType(type, static_cast<unsigned>(k)), ctx);
    if (!a) return std::nullopt;
    args.push_back(*a);
  }
  if (generic_ok(*ret, args)) return std::string();
  return join(*ret, args);
}

struct Generator {
  std::map<std::string, std::string> functions;  // name -> signature
  std::set<std::string> conflicts;
  std::map<std::string, ComInterface> interfaces;
  std::vector<std::string> interface_order;
  std::vector<std::string> interface_table;
  std::vector<CXCursor> function_cursors;
  TypeContext ctx{&interfaces, &interface_table, {}};
  bool second_pass = false;

  void add_function(const std::string& name, const std::string& sig) {
    if (conflicts.count(name)) return;
    auto [it, inserted] = functions.emplace(name, sig);
    if (!inserted && it->second != sig) {
      std::fprintf(stderr, "gen_signatures: conflicting declarations of %s: %s / %s (dropped)\n", name.c_str(),
                   it->second.c_str(), sig.c_str());
      functions.erase(it);
      conflicts.insert(name);
    }
  }

  // nullopt: unsupported argument types; "" : no signature needed.
  std::optional<std::string> function_signature(CXCursor c, bool method) {
    return type_signature(clang_getCursorType(c), method, second_pass ? &ctx : nullptr);
  }

  void visit_function(CXCursor c) {
    // Inline helpers are compiled into the program (with skipped function
    // bodies, their definitions do not count as such: check inline too).
    if (clang_isCursorDefinition(c) || clang_Cursor_isFunctionInlined(c)) return;
    if (clang_Cursor_getStorageClass(c) == CX_SC_Static) return;
    const std::string name = str(clang_getCursorSpelling(c));
    if (name.empty() || name.starts_with("operator")) return;
    if (!second_pass) {
      function_cursors.push_back(c);
      return;
    }
    std::optional<std::string> sig = function_signature(c, false);
    if (!sig) {
      if (!name.starts_with("_mm") && !name.starts_with("__")) {
        std::fprintf(stderr, "gen_signatures: %s: unsupported argument types (skipped)\n", name.c_str());
      }
      return;
    }
    if (!sig->empty()) add_function(name, *sig);
  }

  // The interface ID from __declspec(uuid("...")), as libclang prints the declaration.
  static std::string uuid_of(CXCursor c) {
    CXPrintingPolicy policy = clang_getCursorPrintingPolicy(c);
    clang_PrintingPolicy_setProperty(policy, CXPrintingPolicy_TerseOutput, 1);
    const std::string text = str(clang_getCursorPrettyPrinted(c, policy));
    clang_PrintingPolicy_dispose(policy);
    const size_t at = text.find("uuid(\"");
    if (at == std::string::npos || at + 6 + 36 > text.size()) return {};
    return text.substr(at + 6, 36);
  }

  void visit_class(CXCursor c) {
    if (!clang_isCursorDefinition(c)) return;
    const std::string name = str(clang_getCursorSpelling(c));
    if (name.empty() || interfaces.count(name)) return;
    ComInterface iface;
    iface.name = name;
    int bases = 0;
    bool any_virtual = false;
    std::vector<CXCursor> virtuals;
    struct Ctx {
      ComInterface* iface;
      int* bases;
      bool* any_virtual;
      std::vector<CXCursor>* virtuals;
    } ctx{&iface, &bases, &any_virtual, &virtuals};
    clang_visitChildren(
        c,
        [](CXCursor child, CXCursor, CXClientData data) {
          auto* x = static_cast<Ctx*>(data);
          switch (clang_getCursorKind(child)) {
            case CXCursor_CXXBaseSpecifier: {
              ++*x->bases;
              CXCursor base = clang_getTypeDeclaration(clang_getCanonicalType(clang_getCursorType(child)));
              x->iface->base = str(clang_getCursorSpelling(base));
              break;
            }
            case CXCursor_CXXMethod:
              if (clang_CXXMethod_isVirtual(child)) {
                *x->any_virtual = true;
                x->virtuals->push_back(child);
              }
              break;
            default:
              break;
          }
          return CXChildVisit_Continue;
        },
        &ctx);
    if (!any_virtual || bases > 1) return;
    if (name != "IUnknown" && (iface.base.empty() || !interfaces.count(iface.base))) return;  // COM interfaces only
    iface.uuid = uuid_of(c);
    // MSVC vtable order: declaration order, except that overloads are grouped
    // at the first one's position in reverse declaration order.
    std::vector<std::string> order;
    std::map<std::string, std::vector<CXCursor>> groups;
    for (CXCursor m : virtuals) {
      const std::string mname = str(clang_getCursorSpelling(m));
      if (!groups.count(mname)) order.push_back(mname);
      groups[mname].push_back(m);
    }
    for (const std::string& mname : order) {
      auto& g = groups[mname];
      for (auto it = g.rbegin(); it != g.rend(); ++it) {
        std::optional<std::string> sig = function_signature(*it, true);  // plain kinds: does it need one at all?
        if (sig && !sig->empty()) iface.relevant = true;
        iface.virtuals.emplace_back(mname, *it);
      }
    }
    if (!iface.base.empty() && interfaces.at(iface.base).relevant) iface.relevant = true;
    interfaces.emplace(name, std::move(iface));
    interface_order.push_back(name);
  }

  // With every interface known: the signatures, including callback and
  // interface arguments.
  void second(CXCursor root) {
    second_pass = true;
    for (CXCursor c : function_cursors) visit_function(c);
    for (const std::string& name : interface_order) {
      ComInterface& iface = interfaces.at(name);
      for (auto& [mname, cursor] : iface.virtuals) {
        std::optional<std::string> sig = function_signature(cursor, true);
        if (!sig) {
          std::fprintf(stderr, "gen_signatures: %s::%s: unsupported argument types (skipped)\n", name.c_str(),
                       mname.c_str());
          sig = "?";
        }
        iface.methods.emplace_back(mname, *sig);
      }
    }
    (void)root;
  }

  int slot_count(const std::string& name) const {
    auto it = interfaces.find(name);
    if (it == interfaces.end()) return 0;
    return static_cast<int>(it->second.virtuals.size()) + (it->second.base.empty() ? 0 : slot_count(it->second.base));
  }

  static CXChildVisitResult visit(CXCursor c, CXCursor, CXClientData data) {
    auto* g = static_cast<Generator*>(data);
    switch (clang_getCursorKind(c)) {
      case CXCursor_FunctionDecl:
        g->visit_function(c);
        return CXChildVisit_Continue;
      case CXCursor_StructDecl:
      case CXCursor_ClassDecl:
        g->visit_class(c);
        return CXChildVisit_Continue;
      case CXCursor_Namespace:
      case CXCursor_LinkageSpec:
      case CXCursor_UnexposedDecl:
        return CXChildVisit_Recurse;
      default:
        return CXChildVisit_Continue;
    }
  }
};

}  // namespace

int main(int argc, char** argv) {
  if (argc < 3) {
    std::fprintf(stderr, "usage: gen_signatures <repository root> <output dir>\n");
    return 2;
  }
  const std::filesystem::path root = argv[1], out = argv[2];
  const std::string header = (root / "tools" / "gen_signatures" / "sdk_headers.h").string();
  const char* args[] = {"-x", "c++", "-std=c++20", "--target=x86_64-pc-windows-msvc", "-fms-extensions",
                        "-fms-compatibility", "-fms-compatibility-version=19.40", "-DNOMINMAX", "-D_CRT_SECURE_NO_WARNINGS"};
  CXIndex index = clang_createIndex(0, 1);
  CXTranslationUnit tu = nullptr;
  const CXErrorCode err = clang_parseTranslationUnit2(index, header.c_str(), args, static_cast<int>(std::size(args)),
                                                      nullptr, 0, CXTranslationUnit_SkipFunctionBodies, &tu);
  if (err != CXError_Success || !tu) {
    std::fprintf(stderr, "gen_signatures: cannot parse %s (%d)\n", header.c_str(), static_cast<int>(err));
    return 1;
  }
  unsigned errors = 0;
  for (unsigned i = 0; i < clang_getNumDiagnostics(tu); ++i) {
    CXDiagnostic d = clang_getDiagnostic(tu, i);
    if (clang_getDiagnosticSeverity(d) >= CXDiagnostic_Error) {
      if (++errors <= 10) std::fprintf(stderr, "%s\n", str(clang_formatDiagnostic(d, clang_defaultDiagnosticDisplayOptions())).c_str());
    }
    clang_disposeDiagnostic(d);
  }
  if (errors) {
    std::fprintf(stderr, "gen_signatures: %u errors parsing the headers\n", errors);
    return 1;
  }

  Generator g;
  clang_visitChildren(clang_getTranslationUnitCursor(tu), &Generator::visit, &g);
  g.second(clang_getTranslationUnitCursor(tu));
  // Interfaces in the table need their bases there too (for inherited methods).
  for (size_t k = 0; k < g.interface_table.size(); ++k) {
    const std::string base = g.interfaces.at(g.interface_table[k]).base;
    if (!base.empty()) interface_index(&g.ctx, base);
  }

  std::filesystem::create_directories(out);
  auto guid_literal = [](const std::string& u) {
    std::string guid = "{0x" + u.substr(0, 8) + ", 0x" + u.substr(9, 4) + ", 0x" + u.substr(14, 4) + ", {0x" +
                       u.substr(19, 2) + ", 0x" + u.substr(21, 2);
    for (size_t b = 0; b < 6; ++b) guid += ", 0x" + u.substr(24 + 2 * b, 2);
    return guid + "}}";
  };
  {
    std::ofstream f(out / "signatures_generated.inc");
    f << "// Generated by tools/gen_signatures from the Windows SDK headers. Do not edit.\n"
      << "// Exported functions the generic ARM64 -> x64 call bridge would get wrong, by name.\n";
    for (const auto& [name, sig] : g.functions) f << "{\"" << name << "\", \"" << sig << "\"},\n";
  }
  size_t methods = 0;
  {
    std::ofstream f(out / "com_signatures_generated.inc");
    f << "// Generated by tools/gen_signatures from the Windows SDK headers. Do not edit.\n"
      << "// COM methods the generic ARM64 -> x64 call bridge would get wrong: interface, vtable slot,\n"
      << "// argument kinds (including `this`).\n";
    for (const std::string& name : g.interface_order) {
      const ComInterface& iface = g.interfaces.at(name);
      if (iface.uuid.empty()) continue;
      const int first = g.slot_count(iface.base);
      for (size_t k = 0; k < iface.methods.size(); ++k) {
        const std::string& sig = iface.methods[k].second;
        if (sig.empty() || sig == "?") continue;
        const std::string guid = guid_literal(iface.uuid);
        f << "{" << guid << ", \"" << name << "::" << iface.methods[k].first << "\", " << first + k << ", \"" << sig
          << "\"},\n";
        ++methods;
      }
    }
  }

  {
    std::ofstream f(out / "com_interfaces_generated.inc");
    f << "// Generated by tools/gen_signatures from the Windows SDK headers. Do not edit.\n"
      << "// COM interfaces with methods the generic bridge gets wrong (I<n> arguments): IID, name, base (-1: none).\n";
    for (const std::string& name : g.interface_table) {
      const ComInterface& iface = g.interfaces.at(name);
      int base = -1;
      if (!iface.base.empty()) base = g.interfaces.at(iface.base).index;
      f << "{" << guid_literal(iface.uuid) << ", \"" << name << "\", " << base << "},\n";
    }
  }
  {
    std::ofstream f(out / "callback_signatures_generated.inc");
    f << "// Generated by tools/gen_signatures from the Windows SDK headers. Do not edit.\n"
      << "// Signatures of function pointer arguments (C<n> arguments).\n";
    for (const std::string& sig : g.ctx.callbacks) f << "\"" << sig << "\",\n";
  }
  std::fprintf(stderr, "gen_signatures: %zu functions, %zu COM methods, %zu interfaces, %zu callbacks\n",
               g.functions.size(), methods, g.interface_table.size(), g.ctx.callbacks.size());
  clang_disposeTranslationUnit(tu);
  clang_disposeIndex(index);
  return 0;
}
