/* COM in both directions: the program calls methods of objects created by
 * system DLLs through their (native x64) vtables, and system DLLs call
 * methods of an object implemented by the program through its (ARM64)
 * vtable. */
#define COBJMACROS
#include "juice_test.h"

#include <objbase.h>
#include <shlobj.h>
#include <shlwapi.h>

/* Methods are called through lpVtbl explicitly: shlwapi.h has IStream_Read()
 * and IStream_Write() helper functions that hide the COBJMACROS. */

static u64 hash_bytes(const void* data, size_t n) {
  const unsigned char* p = (const unsigned char*)data;
  u64 h = 0xcbf29ce484222325ull;
  for (size_t i = 0; i < n; ++i) h = (h ^ p[i]) * 0x100000001b3ull;
  return h;
}

static int wide_equal(const wchar_t* a, const wchar_t* b) {
  while (*a && *a == *b) ++a, ++b;
  return *a == *b;
}

/* --- A write-only IStream implemented by the program ------------------------- */

typedef struct {
  IStream iface;
  LONG refs;
  unsigned char data[4096];
  ULONG size;
  int writes, query_interfaces, other_calls;
} GuestStream;

static GuestStream* impl(IStream* s) { return (GuestStream*)s; }

static HRESULT STDMETHODCALLTYPE gs_query_interface(IStream* s, REFIID riid, void** out) {
  ++impl(s)->query_interfaces;
  if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IStream) || IsEqualIID(riid, &IID_ISequentialStream)) {
    *out = s;
    s->lpVtbl->AddRef(s);
    return S_OK;
  }
  *out = NULL;
  return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE gs_add_ref(IStream* s) { return (ULONG)++impl(s)->refs; }
static ULONG STDMETHODCALLTYPE gs_release(IStream* s) { return (ULONG)--impl(s)->refs; }
static HRESULT STDMETHODCALLTYPE gs_read(IStream* s, void* buf, ULONG n, ULONG* read) {
  (void)buf, (void)n, (void)read;
  ++impl(s)->other_calls;
  return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE gs_write(IStream* s, const void* buf, ULONG n, ULONG* written) {
  GuestStream* g = impl(s);
  ++g->writes;
  if (g->size + n > sizeof(g->data)) return STG_E_MEDIUMFULL;
  memcpy(g->data + g->size, buf, n);
  g->size += n;
  if (written) *written = n;
  return S_OK;
}
static HRESULT STDMETHODCALLTYPE gs_seek(IStream* s, LARGE_INTEGER move, DWORD origin, ULARGE_INTEGER* pos) {
  (void)move, (void)origin, (void)pos;
  ++impl(s)->other_calls;
  return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE gs_set_size(IStream* s, ULARGE_INTEGER size) {
  (void)size;
  ++impl(s)->other_calls;
  return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE gs_copy_to(IStream* s, IStream* to, ULARGE_INTEGER n, ULARGE_INTEGER* r,
                                            ULARGE_INTEGER* w) {
  (void)to, (void)n, (void)r, (void)w;
  ++impl(s)->other_calls;
  return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE gs_commit(IStream* s, DWORD flags) {
  (void)flags;
  ++impl(s)->other_calls;
  return S_OK;
}
static HRESULT STDMETHODCALLTYPE gs_revert(IStream* s) {
  ++impl(s)->other_calls;
  return E_NOTIMPL;
}
static HRESULT STDMETHODCALLTYPE gs_lock_region(IStream* s, ULARGE_INTEGER off, ULARGE_INTEGER n, DWORD type) {
  (void)off, (void)n, (void)type;
  ++impl(s)->other_calls;
  return STG_E_INVALIDFUNCTION;
}
static HRESULT STDMETHODCALLTYPE gs_stat(IStream* s, STATSTG* stat, DWORD flags) {
  (void)flags;
  ++impl(s)->other_calls;
  memset(stat, 0, sizeof(*stat));
  stat->type = STGTY_STREAM;
  stat->cbSize.QuadPart = impl(s)->size;
  return S_OK;
}
static HRESULT STDMETHODCALLTYPE gs_clone(IStream* s, IStream** out) {
  ++impl(s)->other_calls;
  *out = NULL;
  return E_NOTIMPL;
}

static IStreamVtbl guest_stream_vtbl = {
    gs_query_interface, gs_add_ref, gs_release, gs_read,         gs_write, gs_seek,  gs_set_size,
    gs_copy_to,         gs_commit,  gs_revert,  gs_lock_region, gs_lock_region, gs_stat, gs_clone,
};

static GuestStream guest_stream = {{&guest_stream_vtbl}, 1};

/* --- Tests ---------------------------------------------------------------------- */

static void malloc_test(void) {
  IMalloc* m = NULL;
  line_i("CoGetMalloc", CoGetMalloc(1, &m) == S_OK);
  void* p = IMalloc_Alloc(m, 64);
  line_i("IMalloc::Alloc", p != NULL);
  memset(p, 0x5a, 64);
  line_i("IMalloc::GetSize >= 64", IMalloc_GetSize(m, p) >= 64);
  line_i("IMalloc::DidAlloc", IMalloc_DidAlloc(m, p));
  p = IMalloc_Realloc(m, p, 256);
  line_i("IMalloc::Realloc keeps data", ((unsigned char*)p)[63] == 0x5a);
  IMalloc_Free(m, p);
  IMalloc_Release(m);
}

static void stream_test(void) {
  static const char text[] = "JUICE Uses Instruction Conversion Efficiently";
  IStream* s = SHCreateMemStream(NULL, 0);
  line_i("SHCreateMemStream", s != NULL);
  ULONG done = 0;
  line_i("IStream::Write", s->lpVtbl->Write(s, text, sizeof(text), &done) == S_OK && done == sizeof(text));
  LARGE_INTEGER zero = {0};
  ULARGE_INTEGER pos;
  pos.QuadPart = 99;
  line_i("IStream::Seek", s->lpVtbl->Seek(s, zero, STREAM_SEEK_SET, &pos) == S_OK);
  line_i("position after seek", (i64)pos.QuadPart);
  char back[64] = {0};
  s->lpVtbl->Read(s, back, sizeof(back), &done);
  line_i("IStream::Read bytes", done);
  line_i("read back matches", memcmp(back, text, sizeof(text)) == 0);
  STATSTG stat;
  s->lpVtbl->Stat(s, &stat, STATFLAG_NONAME);
  line_i("IStream::Stat size", (i64)stat.cbSize.QuadPart);
  line_i("IStream::Release", s->lpVtbl->Release(s));
}

static void shell_link_test(void) {
  IShellLinkW* link = NULL;
  HRESULT hr = CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, &IID_IShellLinkW, (void**)&link);
  line_i("CoCreateInstance(ShellLink)", hr == S_OK);
  if (hr != S_OK) return;
  wchar_t buf[128];
  IShellLinkW_SetDescription(link, L"Hello from ARM64");
  IShellLinkW_GetDescription(link, buf, 128);
  line_i("description round trip", wide_equal(buf, L"Hello from ARM64"));
  IShellLinkW_SetArguments(link, L"--juice 42");
  IShellLinkW_GetArguments(link, buf, 128);
  line_i("arguments round trip", wide_equal(buf, L"--juice 42"));
  IShellLinkW_SetShowCmd(link, SW_SHOWMINNOACTIVE);
  int show = 0;
  IShellLinkW_GetShowCmd(link, &show);
  line_i("show command", show);

  IPersistStream* persist = NULL;
  line_i("QueryInterface(IPersistStream)",
         IShellLinkW_QueryInterface(link, &IID_IPersistStream, (void**)&persist) == S_OK);
  CLSID clsid;
  IPersistStream_GetClassID(persist, &clsid);
  line("class id", clsid.Data1);

  /* Save into a native memory stream and into the program's own stream: the
   * shell calls our IStream methods from native code. */
  IStream* mem = SHCreateMemStream(NULL, 0);
  line_i("save to memory stream", IPersistStream_Save(persist, mem, FALSE) == S_OK);
  STATSTG stat;
  mem->lpVtbl->Stat(mem, &stat, STATFLAG_NONAME);
  static unsigned char saved[4096];
  ULONG n = 0;
  LARGE_INTEGER zero = {0};
  mem->lpVtbl->Seek(mem, zero, STREAM_SEEK_SET, NULL);
  mem->lpVtbl->Read(mem, saved, sizeof(saved), &n);
  mem->lpVtbl->Release(mem);

  line_i("save to program stream", IPersistStream_Save(persist, &guest_stream.iface, FALSE) == S_OK);
  line_i("program stream writes > 0", guest_stream.writes > 0);
  line_i("saved sizes equal", guest_stream.size == n && n == stat.cbSize.QuadPart);
  line_i("saved bytes equal", hash_bytes(guest_stream.data, guest_stream.size) == hash_bytes(saved, n));
  line_i("program stream references balanced", guest_stream.refs);

  IPersistStream_Release(persist);
  IShellLinkW_Release(link);
}

/* System helpers that call IUnknown methods of the program's object. */
static void callback_test(void) {
  guest_stream.query_interfaces = 0;
  IUnknown* holder = NULL;
  IUnknown_Set(&holder, (IUnknown*)&guest_stream.iface);
  line_i("refs after IUnknown_Set", guest_stream.refs);
  IUnknown_AtomicRelease((void**)&holder);
  line_i("refs after IUnknown_AtomicRelease", guest_stream.refs);
  line_i("holder cleared", holder == NULL);
  /* IUnknown_SetSite asks the object for IObjectWithSite, which it lacks. */
  line_i("IUnknown_SetSite", IUnknown_SetSite((IUnknown*)&guest_stream.iface, NULL) == E_NOINTERFACE);
  line_i("QueryInterface calls from native", guest_stream.query_interfaces > 0);
}

void mainCRTStartup(void) {
  line_i("CoInitializeEx", CoInitializeEx(NULL, COINIT_APARTMENTTHREADED) == S_OK);
  malloc_test();
  stream_test();
  shell_link_test();
  callback_test();
  CoUninitialize();
  finish(0);
}
