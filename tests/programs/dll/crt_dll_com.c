/* An in-process COM server: one class (any CLSID the program registers for
 * it) implementing IJuiceAdder, and its class factory. */
#define COBJMACROS
#include <windows.h>

#include <objbase.h>

#include "crt_dll_com.h"

typedef struct {
  IJuiceAdder iface;
  LONG refs;
} Adder;

static HRESULT STDMETHODCALLTYPE adder_qi(IJuiceAdder* self, REFIID iid, void** out) {
  if (IsEqualIID(iid, &IID_IUnknown) || IsEqualIID(iid, &IID_IJuiceAdder)) {
    *out = self;
    self->lpVtbl->AddRef(self);
    return S_OK;
  }
  *out = NULL;
  return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE adder_add_ref(IJuiceAdder* self) { return InterlockedIncrement(&((Adder*)self)->refs); }

static ULONG STDMETHODCALLTYPE adder_release(IJuiceAdder* self) {
  const LONG refs = InterlockedDecrement(&((Adder*)self)->refs);
  if (refs == 0) HeapFree(GetProcessHeap(), 0, self);
  return refs;
}

static HRESULT STDMETHODCALLTYPE adder_add(IJuiceAdder* self, int a, int b, int* sum) {
  (void)self;
  *sum = a + b;
  return S_OK;
}

static IJuiceAdderVtbl adder_vtbl = {adder_qi, adder_add_ref, adder_release, adder_add};

static HRESULT STDMETHODCALLTYPE factory_qi(IClassFactory* self, REFIID iid, void** out) {
  if (IsEqualIID(iid, &IID_IUnknown) || IsEqualIID(iid, &IID_IClassFactory)) {
    *out = self;
    return S_OK;
  }
  *out = NULL;
  return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE factory_add_ref(IClassFactory* self) {
  (void)self;
  return 2;
}

static ULONG STDMETHODCALLTYPE factory_release(IClassFactory* self) {
  (void)self;
  return 1;
}

static HRESULT STDMETHODCALLTYPE factory_create(IClassFactory* self, IUnknown* outer, REFIID iid, void** out) {
  (void)self;
  *out = NULL;
  if (outer) return CLASS_E_NOAGGREGATION;
  Adder* adder = HeapAlloc(GetProcessHeap(), 0, sizeof(Adder));
  if (!adder) return E_OUTOFMEMORY;
  adder->iface.lpVtbl = &adder_vtbl;
  adder->refs = 1;
  const HRESULT hr = adder_qi(&adder->iface, iid, out);
  adder_release(&adder->iface);
  return hr;
}

static HRESULT STDMETHODCALLTYPE factory_lock(IClassFactory* self, BOOL lock) {
  (void)self;
  (void)lock;
  return S_OK;
}

static IClassFactoryVtbl factory_vtbl = {factory_qi, factory_add_ref, factory_release, factory_create, factory_lock};
static IClassFactory factory = {&factory_vtbl};

__declspec(dllexport) HRESULT STDAPICALLTYPE DllGetClassObject(REFCLSID clsid, REFIID iid, void** out) {
  (void)clsid;
  return factory_qi(&factory, iid, out);
}

__declspec(dllexport) HRESULT STDAPICALLTYPE DllCanUnloadNow(void) { return S_FALSE; }
