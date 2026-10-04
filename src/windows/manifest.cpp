#include "windows/manifest.hpp"

#include <cwctype>
#include <filesystem>
#include <format>
#include <string_view>

namespace juice::win {

namespace {

constexpr wchar_t kSettings2005[] = L"http://schemas.microsoft.com/SMI/2005/WindowsSettings";
constexpr wchar_t kSettings2016[] = L"http://schemas.microsoft.com/SMI/2016/WindowsSettings";
constexpr wchar_t kSettings2017[] = L"http://schemas.microsoft.com/SMI/2017/WindowsSettings";

std::wstring query_setting(HANDLE context, const wchar_t* ns, const wchar_t* name) {
  wchar_t buffer[256] = {};
  SIZE_T written = 0;
  if (!QueryActCtxSettingsW(0, context, ns, name, buffer, std::size(buffer) - 1, &written)) return {};
  std::wstring value;
  for (const wchar_t* p = buffer; *p; ++p)
    if (!std::iswspace(*p)) value.push_back(static_cast<wchar_t>(std::towlower(*p)));
  return value;
}

struct DpiChoice {
  DPI_AWARENESS_CONTEXT context = nullptr;
  const char* name = nullptr;
};

// The DPI awareness the manifest declares, with the precedence Windows uses:
// <dpiAwareness> (the first value in its list that is recognized) over
// <dpiAware>, and <gdiScaling> for unaware programs.
DpiChoice declared_dpi_awareness(HANDLE context) {
  DpiChoice choice;
  const std::wstring awareness = query_setting(context, kSettings2016, L"dpiAwareness");
  for (size_t pos = 0; pos < awareness.size() && !choice.context;) {
    size_t comma = awareness.find(L',', pos);
    if (comma == std::wstring::npos) comma = awareness.size();
    const std::wstring_view value = std::wstring_view(awareness).substr(pos, comma - pos);
    if (value == L"permonitorv2") choice = {DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, "per-monitor v2"};
    else if (value == L"permonitor") choice = {DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE, "per-monitor"};
    else if (value == L"system") choice = {DPI_AWARENESS_CONTEXT_SYSTEM_AWARE, "system"};
    else if (value == L"unaware") choice = {DPI_AWARENESS_CONTEXT_UNAWARE, "unaware"};
    pos = comma + 1;
  }
  if (!choice.context) {
    const std::wstring aware = query_setting(context, kSettings2005, L"dpiAware");
    if (aware == L"true") choice = {DPI_AWARENESS_CONTEXT_SYSTEM_AWARE, "system"};
    else if (aware == L"true/pm" || aware == L"permonitor") choice = {DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE, "per-monitor"};
    else if (aware == L"false") choice = {DPI_AWARENESS_CONTEXT_UNAWARE, "unaware"};
  }
  if ((!choice.context || choice.context == DPI_AWARENESS_CONTEXT_UNAWARE) &&
      query_setting(context, kSettings2017, L"gdiScaling") == L"true") {
    choice = {DPI_AWARENESS_CONTEXT_UNAWARE_GDISCALED, "unaware (GDI scaled)"};
  }
  return choice;
}

}  // namespace

std::expected<ManifestState, std::string> apply_manifest(const std::wstring& exe_path, uint64_t image_base,
                                                         std::FILE* log) {
  ManifestState state;
  // The guest image is mapped like a loaded module, so the resource APIs work on it.
  if (!FindResourceW(reinterpret_cast<HMODULE>(image_base), MAKEINTRESOURCEW(1), MAKEINTRESOURCEW(24) /* RT_MANIFEST */)) {
    if (log) std::fprintf(log, "[juice] manifest: none\n");
    return state;
  }

  const std::wstring directory = std::filesystem::path(exe_path).parent_path().wstring() + L"\\";
  ACTCTXW actctx{};
  actctx.cbSize = sizeof(actctx);
  actctx.dwFlags = ACTCTX_FLAG_RESOURCE_NAME_VALID | ACTCTX_FLAG_APPLICATION_NAME_VALID |
                   ACTCTX_FLAG_SET_PROCESS_DEFAULT;
  actctx.lpSource = exe_path.c_str();
  actctx.lpResourceName = MAKEINTRESOURCEW(1);
  actctx.lpAssemblyDirectory = nullptr;
  actctx.lpApplicationName = directory.c_str();
  state.context = CreateActCtxW(&actctx);
  if (state.context != INVALID_HANDLE_VALUE) {
    state.process_default = true;
  } else {
    // Some other component already set a process default: activate the
    // guest's context on this thread instead (threads it creates inherit it).
    actctx.dwFlags &= ~ACTCTX_FLAG_SET_PROCESS_DEFAULT;
    state.context = CreateActCtxW(&actctx);
    if (state.context == INVALID_HANDLE_VALUE) {
      return std::unexpected(std::format(
          "the program's side-by-side configuration is incorrect (CreateActCtx failed with error {})",
          GetLastError()));
    }
    ActivateActCtx(state.context, &state.cookie);
  }

  const DpiChoice dpi = declared_dpi_awareness(state.context);
  if (dpi.context) {
    state.dpi_awareness = dpi.name;
    using SetContextFn = BOOL(WINAPI*)(DPI_AWARENESS_CONTEXT);
    HMODULE user32 = LoadLibraryW(L"user32.dll");
    auto set_context = reinterpret_cast<SetContextFn>(GetProcAddress(user32, "SetProcessDpiAwarenessContext"));
    if (set_context && !set_context(dpi.context) && GetLastError() != ERROR_ACCESS_DENIED && log) {
      std::fprintf(log, "[juice] manifest: could not set DPI awareness (error %lu)\n", GetLastError());
    }
  }

  if (log) {
    std::fprintf(log, "[juice] manifest: activation context %s, DPI awareness: %s\n",
                 state.process_default ? "installed as process default" : "activated on the main thread",
                 dpi.name ? dpi.name : "not declared");
  }
  return state;
}

void activate_manifest_on_thread(const ManifestState& manifest) {
  if (manifest.context == INVALID_HANDLE_VALUE || manifest.process_default) return;
  // Left active for the rest of the thread's life, like a process default.
  ULONG_PTR cookie = 0;
  ActivateActCtx(manifest.context, &cookie);
}

}  // namespace juice::win
