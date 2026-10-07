// Native API calls the generic ARM64 -> x64 bridge would get wrong without
// signatures: mixed integer / floating point arguments (GDI+, OLE Automation,
// the C runtime), structures of floats by value and returned (Direct2D
// helpers), and COM methods taking floats and float pairs (Direct2D,
// DirectWrite, WIC). Run under JUICE and natively, the output must match.

#include <windows.h>
#include <d2d1_1.h>
#include <dwrite.h>
#include <oleauto.h>
#include <wincodec.h>

#include <algorithm>
using std::max;
using std::min;
#include <gdiplus.h>

#include <cstdio>
#include <cstdlib>
#include <cmath>

using namespace Gdiplus;

static void gdiplus() {
  GdiplusStartupInput input;
  ULONG_PTR token = 0;
  if (GdiplusStartup(&token, &input, nullptr) != Ok) {
    std::printf("gdiplus: startup failed\n");
    return;
  }
  GpPen* pen = nullptr;
  REAL width = 0;
  DllExports::GdipCreatePen1(0xFF336699, 3.25f, UnitPixel, &pen);
  DllExports::GdipGetPenWidth(pen, &width);
  DllExports::GdipSetPenWidth(pen, width * 2);
  DllExports::GdipGetPenWidth(pen, &width);
  ARGB color = 0;
  DllExports::GdipGetPenColor(pen, &color);
  std::printf("gdiplus pen width %g color %08lx\n", width, color);
  DllExports::GdipDeletePen(pen);

  GpMatrix* m = nullptr;
  DllExports::GdipCreateMatrix2(1.5f, 0.25f, -0.5f, 2.0f, 10.0f, -20.0f, &m);
  DllExports::GdipTranslateMatrix(m, 3.0f, 4.0f, MatrixOrderAppend);
  DllExports::GdipScaleMatrix(m, 2.0f, 0.5f, MatrixOrderPrepend);
  REAL e[6] = {};
  DllExports::GdipGetMatrixElements(m, e);
  std::printf("gdiplus matrix %g %g %g %g %g %g\n", e[0], e[1], e[2], e[3], e[4], e[5]);
  GpPointF pts[2] = {{1.0f, 2.0f}, {-3.0f, 0.5f}};
  DllExports::GdipTransformMatrixPoints(m, pts, 2);
  std::printf("gdiplus points %g %g %g %g\n", pts[0].X, pts[0].Y, pts[1].X, pts[1].Y);
  DllExports::GdipDeleteMatrix(m);

  // A bitmap, drawn into with float coordinates, read back
  GpBitmap* bmp = nullptr;
  DllExports::GdipCreateBitmapFromScan0(32, 32, 0, PixelFormat32bppARGB, nullptr, &bmp);
  GpGraphics* g = nullptr;
  DllExports::GdipGetImageGraphicsContext(bmp, &g);
  DllExports::GdipSetSmoothingMode(g, SmoothingModeNone);
  GpPen* p2 = nullptr;
  DllExports::GdipCreatePen1(0xFFFF0000, 2.0f, UnitPixel, &p2);
  DllExports::GdipDrawLine(g, p2, 1.5f, 2.5f, 28.0f, 30.0f);
  DllExports::GdipDrawRectangle(g, p2, 4.0f, 5.0f, 20.5f, 10.0f);
  GpSolidFill* brush = nullptr;
  DllExports::GdipCreateSolidFill(0xFF00FF00, &brush);
  DllExports::GdipFillEllipse(g, reinterpret_cast<GpBrush*>(brush), 8.0f, 8.0f, 12.0f, 9.5f);
  DllExports::GdipFlush(g, FlushIntentionSync);
  unsigned sum = 0;
  for (UINT y = 0; y < 32; ++y)
    for (UINT x = 0; x < 32; ++x) {
      ARGB c = 0;
      DllExports::GdipBitmapGetPixel(bmp, static_cast<INT>(x), static_cast<INT>(y), &c);
      sum = sum * 31 + c;
    }
  std::printf("gdiplus pixels %08x\n", sum);
  DllExports::GdipDeleteBrush(reinterpret_cast<GpBrush*>(brush));
  DllExports::GdipDeletePen(p2);
  DllExports::GdipDeleteGraphics(g);
  DllExports::GdipDisposeImage(reinterpret_cast<GpImage*>(bmp));
  GdiplusShutdown(token);
}

static void automation_and_crt() {
  LONG l = 0;
  VarI4FromR8(-1234.75, &l);
  DATE d = 0;
  VarDateFromR8(45000.25, &d);
  SYSTEMTIME st = {};
  VariantTimeToSystemTime(d, &st);
  double r8 = 0;
  VarR8FromI4(77, &r8);
  std::printf("oleaut %ld %g %04u-%02u-%02u %02u:%02u %g\n", l, d, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, r8);

  volatile long long a = 1000000000007LL, b = -37;
  const lldiv_t q = lldiv(a, b);
  volatile double x = 0.71875;
  int exp = 0;
  const double mant = std::frexp(x * 1024, &exp);
  std::printf("crt lldiv %lld %lld ldexp %g frexp %g %d\n", q.quot, q.rem, std::ldexp(x, 7), mant, exp);
}

template <typename T>
static void release(T*& p) {
  if (p) p->Release();
  p = nullptr;
}

static void direct2d() {
  D2D1_MATRIX_3X2_F rot{};
  D2D1MakeRotateMatrix(30.0f, D2D1::Point2F(5.0f, -2.0f), &rot);
  std::printf("d2d rotate %.4f %.4f %.4f %.4f %.4f %.4f\n", rot._11, rot._12, rot._21, rot._22, rot._31, rot._32);
  const D2D1_COLOR_F srgb = D2D1::ColorF(0.5f, 0.25f, 1.0f, 0.75f);
  const D2D1_COLOR_F scrgb = D2D1ConvertColorSpace(D2D1_COLOR_SPACE_SRGB, D2D1_COLOR_SPACE_SCRGB, &srgb);
  std::printf("d2d color %.4f %.4f %.4f %.4f\n", scrgb.r, scrgb.g, scrgb.b, scrgb.a);

  IWICImagingFactory* wic = nullptr;
  ID2D1Factory* factory = nullptr;
  IWICBitmap* bitmap = nullptr;
  ID2D1RenderTarget* target = nullptr;
  ID2D1SolidColorBrush* brush = nullptr;
  IDWriteFactory* dwrite = nullptr;
  IDWriteTextFormat* format = nullptr;
  if (FAILED(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&wic))) ||
      FAILED(D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, &factory)) ||
      FAILED(wic->CreateBitmap(64, 48, GUID_WICPixelFormat32bppPBGRA, WICBitmapCacheOnDemand, &bitmap))) {
    std::printf("d2d: setup failed\n");
    return;
  }
  bitmap->SetResolution(144.0, 72.5);
  double rx = 0, ry = 0;
  bitmap->GetResolution(&rx, &ry);
  std::printf("wic resolution %g %g\n", rx, ry);

  const D2D1_RENDER_TARGET_PROPERTIES props = D2D1::RenderTargetProperties(
      D2D1_RENDER_TARGET_TYPE_SOFTWARE, D2D1::PixelFormat(DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_PREMULTIPLIED));
  if (FAILED(factory->CreateWicBitmapRenderTarget(bitmap, props, &target))) {
    std::printf("d2d: no render target\n");
    return;
  }
  target->SetDpi(96.0f, 96.0f);
  float dx = 0, dy = 0;
  target->GetDpi(&dx, &dy);
  const D2D1_SIZE_F size = target->GetSize();
  std::printf("d2d target %g x %g dpi %g %g\n", size.width, size.height, dx, dy);
  target->SetAntialiasMode(D2D1_ANTIALIAS_MODE_ALIASED);
  target->CreateSolidColorBrush(D2D1::ColorF(1.0f, 0.5f, 0.0f, 1.0f), &brush);
  target->BeginDraw();
  target->Clear(D2D1::ColorF(0.0f, 0.0f, 0.25f, 1.0f));
  target->DrawLine(D2D1::Point2F(2.0f, 3.0f), D2D1::Point2F(60.0f, 40.0f), brush, 3.0f);
  target->DrawRectangle(D2D1::RectF(5.0f, 6.0f, 30.5f, 20.0f), brush, 2.0f);
  brush->SetColor(D2D1::ColorF(0.0f, 1.0f, 0.5f, 0.5f));
  brush->SetOpacity(0.75f);
  target->FillEllipse(D2D1::Ellipse(D2D1::Point2F(40.0f, 24.0f), 10.0f, 7.5f), brush);
  target->SetTransform(D2D1::Matrix3x2F::Rotation(15.0f, D2D1::Point2F(32.0f, 24.0f)));
  target->DrawRoundedRectangle(D2D1::RoundedRect(D2D1::RectF(20.0f, 10.0f, 50.0f, 35.0f), 4.0f, 3.0f), brush, 1.5f);
  const HRESULT end = target->EndDraw();
  std::printf("d2d brush opacity %g end %08lx\n", brush->GetOpacity(), static_cast<unsigned long>(end));

  IWICBitmapLock* lock = nullptr;
  WICRect all = {0, 0, 64, 48};
  if (SUCCEEDED(bitmap->Lock(&all, WICBitmapLockRead, &lock))) {
    UINT bytes = 0;
    BYTE* data = nullptr;
    lock->GetDataPointer(&bytes, &data);
    unsigned sum = 0;
    for (UINT k = 0; k < bytes; ++k) sum = sum * 31 + data[k];
    std::printf("d2d pixels %u bytes %08x\n", bytes, sum);
    lock->Release();
  }

  if (SUCCEEDED(DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, __uuidof(IDWriteFactory),
                                    reinterpret_cast<IUnknown**>(&dwrite))) &&
      SUCCEEDED(dwrite->CreateTextFormat(L"Arial", nullptr, DWRITE_FONT_WEIGHT_BOLD, DWRITE_FONT_STYLE_NORMAL,
                                         DWRITE_FONT_STRETCH_NORMAL, 13.5f, L"en-us", &format))) {
    format->SetLineSpacing(DWRITE_LINE_SPACING_METHOD_UNIFORM, 20.0f, 16.0f);
    DWRITE_LINE_SPACING_METHOD method{};
    float spacing = 0, baseline = 0;
    format->GetLineSpacing(&method, &spacing, &baseline);
    std::printf("dwrite size %g weight %d spacing %g %g\n", format->GetFontSize(), format->GetFontWeight(), spacing,
                baseline);
  }
  release(format);
  release(dwrite);
  release(brush);
  release(target);
  release(bitmap);
  release(factory);
  release(wic);
}

// Objects of the program that native code calls with floats.
class Renderer : public IDWriteTextRenderer {
 public:
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** out) override {
    if (iid == __uuidof(IUnknown) || iid == __uuidof(IDWritePixelSnapping) || iid == __uuidof(IDWriteTextRenderer)) {
      *out = this;
      AddRef();
      return S_OK;
    }
    *out = nullptr;
    return E_NOINTERFACE;
  }
  ULONG STDMETHODCALLTYPE AddRef() override { return ++refs_; }
  ULONG STDMETHODCALLTYPE Release() override { return --refs_; }
  HRESULT STDMETHODCALLTYPE IsPixelSnappingDisabled(void*, BOOL* disabled) override {
    *disabled = FALSE;
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE GetCurrentTransform(void*, DWRITE_MATRIX* m) override {
    *m = {1, 0, 0, 1, 0, 0};
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE GetPixelsPerDip(void*, FLOAT* ppd) override {
    *ppd = 1.0f;
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE DrawGlyphRun(void* ctx, FLOAT x, FLOAT y, DWRITE_MEASURING_MODE mode,
                                         const DWRITE_GLYPH_RUN* run, const DWRITE_GLYPH_RUN_DESCRIPTION* desc,
                                         IUnknown* effect) override {
    std::printf("  glyph run ctx %d at %.2f %.2f mode %d glyphs %u size %g text %u effect %d\n",
                ctx == reinterpret_cast<void*>(0x1234), x, y, mode, run->glyphCount, run->fontEmSize,
                desc->stringLength, effect == nullptr);
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE DrawUnderline(void*, FLOAT x, FLOAT y, const DWRITE_UNDERLINE* u, IUnknown*) override {
    std::printf("  underline at %.2f %.2f width %.2f\n", x, y, u->width);
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE DrawStrikethrough(void*, FLOAT, FLOAT, const DWRITE_STRIKETHROUGH*, IUnknown*) override {
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE DrawInlineObject(void*, FLOAT, FLOAT, IDWriteInlineObject*, BOOL, BOOL, IUnknown*) override {
    return S_OK;
  }

 private:
  ULONG refs_ = 1;
};

class Sink : public ID2D1SimplifiedGeometrySink {
 public:
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** out) override {
    if (iid == __uuidof(IUnknown) || iid == __uuidof(ID2D1SimplifiedGeometrySink)) {
      *out = this;
      return S_OK;
    }
    *out = nullptr;
    return E_NOINTERFACE;
  }
  ULONG STDMETHODCALLTYPE AddRef() override { return 1; }
  ULONG STDMETHODCALLTYPE Release() override { return 1; }
  void STDMETHODCALLTYPE SetFillMode(D2D1_FILL_MODE mode) override { std::printf("  sink fill mode %d\n", mode); }
  void STDMETHODCALLTYPE SetSegmentFlags(D2D1_PATH_SEGMENT) override {}
  void STDMETHODCALLTYPE BeginFigure(D2D1_POINT_2F start, D2D1_FIGURE_BEGIN begin) override {
    std::printf("  sink figure at %.2f %.2f %d\n", start.x, start.y, begin);
  }
  void STDMETHODCALLTYPE AddLines(const D2D1_POINT_2F* points, UINT32 count) override {
    std::printf("  sink %u lines, last %.2f %.2f\n", count, points[count - 1].x, points[count - 1].y);
  }
  void STDMETHODCALLTYPE AddBeziers(const D2D1_BEZIER_SEGMENT*, UINT32 count) override {
    std::printf("  sink %u beziers\n", count);
  }
  void STDMETHODCALLTYPE EndFigure(D2D1_FIGURE_END end) override { std::printf("  sink end figure %d\n", end); }
  HRESULT STDMETHODCALLTYPE Close() override { return S_OK; }
};

static void callbacks() {
  IDWriteFactory* dwrite = nullptr;
  IDWriteTextFormat* format = nullptr;
  IDWriteTextLayout* layout = nullptr;
  if (SUCCEEDED(DWriteCreateFactory(DWRITE_FACTORY_TYPE_ISOLATED, __uuidof(IDWriteFactory),
                                    reinterpret_cast<IUnknown**>(&dwrite))) &&
      SUCCEEDED(dwrite->CreateTextFormat(L"Arial", nullptr, DWRITE_FONT_WEIGHT_NORMAL, DWRITE_FONT_STYLE_NORMAL,
                                         DWRITE_FONT_STRETCH_NORMAL, 16.0f, L"en-us", &format)) &&
      SUCCEEDED(dwrite->CreateTextLayout(L"Hello, guest", 12, format, 300.0f, 50.0f, &layout))) {
    layout->SetUnderline(TRUE, DWRITE_TEXT_RANGE{0, 5});
    Renderer renderer;
    std::printf("dwrite renderer\n");
    const HRESULT hr = layout->Draw(reinterpret_cast<void*>(0x1234), &renderer, 10.5f, 20.25f);
    std::printf("  draw %08lx\n", static_cast<unsigned long>(hr));
  }
  release(layout);
  release(format);
  release(dwrite);

  ID2D1Factory* factory = nullptr;
  ID2D1EllipseGeometry* ellipse = nullptr;
  if (SUCCEEDED(D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, &factory)) &&
      SUCCEEDED(factory->CreateEllipseGeometry(D2D1::Ellipse(D2D1::Point2F(50.0f, 40.0f), 20.0f, 10.0f), &ellipse))) {
    Sink sink;
    std::printf("d2d sink\n");
    const HRESULT hr = ellipse->Simplify(D2D1_GEOMETRY_SIMPLIFICATION_OPTION_LINES, nullptr, 2.0f, &sink);
    std::printf("  simplify %08lx\n", static_cast<unsigned long>(hr));
  }
  release(ellipse);
  release(factory);
}

int main() {
  CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  gdiplus();
  automation_and_crt();
  direct2d();
  callbacks();
  CoUninitialize();
  return 0;
}
