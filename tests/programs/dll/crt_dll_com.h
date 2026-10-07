/* The interface of crt_dll_com.dll's class. */
#pragma once

#include <objbase.h>

typedef struct IJuiceAdder IJuiceAdder;

typedef struct IJuiceAdderVtbl {
  HRESULT(STDMETHODCALLTYPE* QueryInterface)(IJuiceAdder* self, REFIID iid, void** out);
  ULONG(STDMETHODCALLTYPE* AddRef)(IJuiceAdder* self);
  ULONG(STDMETHODCALLTYPE* Release)(IJuiceAdder* self);
  HRESULT(STDMETHODCALLTYPE* Add)(IJuiceAdder* self, int a, int b, int* sum);
} IJuiceAdderVtbl;

struct IJuiceAdder {
  const IJuiceAdderVtbl* lpVtbl;
};

/* {6A1E0F3C-2B7D-4C59-9E21-5D3B8A4F7C10} */
static const IID IID_IJuiceAdder = {0x6a1e0f3c, 0x2b7d, 0x4c59, {0x9e, 0x21, 0x5d, 0x3b, 0x8a, 0x4f, 0x7c, 0x10}};
