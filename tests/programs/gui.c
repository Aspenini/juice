/* A small Win32 GUI program: window class and window procedure, child
 * controls, timers, notifications, subclassing, a dialog from an in-memory
 * template, enumeration callbacks, GDI drawing and the message loop.
 *
 * Windows are hidden so the program can run unattended; pass "show" on the
 * command line to see them. The program ends by itself. */
#include "juice_test.h"

#define ID_BUTTON 101
#define ID_EDIT 102
#define WM_APP_DONE (WM_APP + 1)

static BOOL show;
static HWND main_window, button, edit;
static WNDPROC edit_original;
static int timer_ticks, subclass_settext, dialog_ticks;
static BOOL dialog_closed;

static void log_line(const char* text) {
  put_str(text);
  put_char('\n');
}

static LRESULT CALLBACK edit_subclass(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
  if (msg == WM_SETTEXT) ++subclass_settext;
  return CallWindowProcW(edit_original, hwnd, msg, wparam, lparam);
}

static BOOL CALLBACK count_children(HWND hwnd, LPARAM lparam) {
  wchar_t cls[32];
  GetClassNameW(hwnd, cls, 32);
  ++*(int*)lparam;
  return TRUE;
}

static u64 hash_bits(const unsigned char* p, size_t n) {
  u64 h = 0xcbf29ce484222325ull;
  for (size_t i = 0; i < n; ++i) h = (h ^ p[i]) * 0x100000001b3ull;
  return h;
}

/* Draw into an off-screen DIB with GDI and hash the pixels. */
static void gdi_test(void) {
  BITMAPINFO bi = {0};
  bi.bmiHeader.biSize = sizeof(bi.bmiHeader);
  bi.bmiHeader.biWidth = 96;
  bi.bmiHeader.biHeight = -48;
  bi.bmiHeader.biPlanes = 1;
  bi.bmiHeader.biBitCount = 32;
  bi.bmiHeader.biCompression = BI_RGB;
  void* bits = NULL;
  HDC dc = CreateCompatibleDC(NULL);
  HBITMAP bmp = CreateDIBSection(dc, &bi, DIB_RGB_COLORS, &bits, NULL, 0);
  HGDIOBJ old = SelectObject(dc, bmp);
  RECT r = {0, 0, 96, 48};
  HBRUSH brush = CreateSolidBrush(RGB(255, 200, 0));
  FillRect(dc, &r, brush);
  SelectObject(dc, GetStockObject(BLACK_PEN));
  Ellipse(dc, 4, 4, 44, 44);
  MoveToEx(dc, 50, 4, NULL);
  LineTo(dc, 92, 44);
  SetBkMode(dc, TRANSPARENT);
  SetTextColor(dc, RGB(128, 0, 64));
  SelectObject(dc, GetStockObject(SYSTEM_FIXED_FONT));
  TextOutW(dc, 48, 16, L"JUICE", 5);
  GdiFlush();
  line("gdi pixels", hash_bits((const unsigned char*)bits, 96 * 48 * 4));
  SIZE extent;
  GetTextExtentPoint32W(dc, L"JUICE", 5, &extent);
  line_i("text width > 0", extent.cx > 0);
  SelectObject(dc, old);
  DeleteObject(brush);
  DeleteObject(bmp);
  DeleteDC(dc);
}

/* "show" mode: render the window with PrintWindow (which makes the window
 * procedure paint into our DC) and save it as juice-gui.bmp. */
static void save_screenshot(HWND hwnd) {
  RECT r;
  GetWindowRect(hwnd, &r);
  const int w = r.right - r.left, h = r.bottom - r.top;
  BITMAPINFO bi = {0};
  bi.bmiHeader.biSize = sizeof(bi.bmiHeader);
  bi.bmiHeader.biWidth = w;
  bi.bmiHeader.biHeight = -h;
  bi.bmiHeader.biPlanes = 1;
  bi.bmiHeader.biBitCount = 32;
  bi.bmiHeader.biCompression = BI_RGB;
  void* bits = NULL;
  HDC dc = CreateCompatibleDC(NULL);
  HBITMAP bmp = CreateDIBSection(dc, &bi, DIB_RGB_COLORS, &bits, NULL, 0);
  HGDIOBJ old = SelectObject(dc, bmp);
  PrintWindow(hwnd, dc, 2 /* PW_RENDERFULLCONTENT */);
  BITMAPFILEHEADER fh = {0};
  fh.bfType = 0x4D42;
  fh.bfOffBits = sizeof(fh) + sizeof(bi.bmiHeader);
  fh.bfSize = fh.bfOffBits + (DWORD)(w * h * 4);
  HANDLE f = CreateFileA("juice-gui.bmp", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  DWORD written;
  WriteFile(f, &fh, sizeof(fh), &written, NULL);
  WriteFile(f, &bi.bmiHeader, sizeof(bi.bmiHeader), &written, NULL);
  WriteFile(f, bits, (DWORD)(w * h * 4), &written, NULL);
  CloseHandle(f);
  SelectObject(dc, old);
  DeleteObject(bmp);
  DeleteDC(dc);
}

static LRESULT CALLBACK window_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
  switch (msg) {
    case WM_CREATE: {
      const CREATESTRUCTW* cs = (const CREATESTRUCTW*)lparam;
      log_line(cs->lpCreateParams == (LPVOID)0x1234 ? "WM_CREATE with create params" : "WM_CREATE");
      DWORD visible = show ? WS_VISIBLE : 0;
      button = CreateWindowExW(0, L"BUTTON", L"Squeeze", WS_CHILD | visible | BS_PUSHBUTTON, 10, 10, 120, 30, hwnd,
                               (HMENU)ID_BUTTON, NULL, NULL);
      edit = CreateWindowExW(0, L"EDIT", L"juice", WS_CHILD | visible | WS_BORDER, 10, 50, 220, 24, hwnd,
                             (HMENU)ID_EDIT, NULL, NULL);
      edit_original = (WNDPROC)SetWindowLongPtrW(edit, GWLP_WNDPROC, (LONG_PTR)edit_subclass);
      SetTimer(hwnd, 1, show ? 500 : 10, NULL);  /* slow enough to watch when shown */
      return 0;
    }
    case WM_COMMAND:
      if (LOWORD(wparam) == ID_BUTTON && HIWORD(wparam) == BN_CLICKED) {
        log_line("button clicked");
        SetWindowTextW(edit, L"Instruction Conversion");
      }
      return 0;
    case WM_TIMER:
      if (wparam != 1) break;
      ++timer_ticks;
      if (timer_ticks == 3) SendMessageW(button, BM_CLICK, 0, 0);
      if (timer_ticks == 4 && show) save_screenshot(hwnd);
      if (timer_ticks == 6) {
        KillTimer(hwnd, 1);
        PostMessageW(hwnd, WM_CLOSE, 0, 0);
      }
      return 0;
    case WM_PAINT: {
      PAINTSTRUCT ps;
      HDC dc = BeginPaint(hwnd, &ps);
      TextOutW(dc, 10, 90, L"Hello from ARM64 under JUICE", 28);
      EndPaint(hwnd, &ps);
      return 0;
    }
    case WM_CLOSE:
      log_line("WM_CLOSE");
      DestroyWindow(hwnd);
      return 0;
    case WM_DESTROY:
      log_line("WM_DESTROY");
      PostQuitMessage(7);
      return 0;
  }
  return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static INT_PTR CALLBACK dialog_proc(HWND dlg, UINT msg, WPARAM wparam, LPARAM lparam) {
  switch (msg) {
    case WM_INITDIALOG:
      log_line(lparam == 99 ? "WM_INITDIALOG with init param" : "WM_INITDIALOG");
      SetTimer(dlg, 2, 10, NULL);
      return TRUE;
    case WM_TIMER:
      if (++dialog_ticks == 2) {
        KillTimer(dlg, 2);
        DestroyWindow(dlg);
        dialog_closed = TRUE;
      }
      return TRUE;
  }
  (void)wparam;
  return FALSE;
}

/* Modeless dialog from a template built in memory (DWORD aligned). */
static void dialog_test(void) {
  static DWORD storage[64];
  DLGTEMPLATE* t = (DLGTEMPLATE*)storage;
  t->style = DS_MODALFRAME | WS_CAPTION | WS_SYSMENU | (show ? WS_VISIBLE : 0);
  t->cdit = 0;
  t->cx = 120;
  t->cy = 40;
  WORD* p = (WORD*)(t + 1);
  *p++ = 0;  /* no menu */
  *p++ = 0;  /* default class */
  const wchar_t* title = L"JUICE dialog";
  while ((*p++ = *title++) != 0) {
  }
  HWND dlg = CreateDialogIndirectParamW(NULL, t, NULL, dialog_proc, 99);
  line_i("dialog created", dlg != NULL);
  MSG msg;
  while (!dialog_closed && GetMessageW(&msg, NULL, 0, 0) > 0) {
    if (!IsDialogMessageW(dlg, &msg)) {
      TranslateMessage(&msg);
      DispatchMessageW(&msg);
    }
  }
  line_i("dialog timer ticks", dialog_ticks);
}

static int arg_is_show(void) {
  const char* cmd = GetCommandLineA();
  for (; *cmd; ++cmd)
    if (cmd[0] == 's' && cmd[1] == 'h' && cmd[2] == 'o' && cmd[3] == 'w') return 1;
  return 0;
}

void mainCRTStartup(void) {
  show = arg_is_show();

  WNDCLASSEXW wc = {0};
  wc.cbSize = sizeof(wc);
  wc.lpfnWndProc = window_proc;
  wc.hInstance = GetModuleHandleW(NULL);
  wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
  wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
  wc.lpszClassName = L"JuiceTestWindow";
  line_i("RegisterClassExW", RegisterClassExW(&wc) != 0);
  {
    WNDCLASSEXW info = {0};
    info.cbSize = sizeof(info);
    line_i("GetClassInfoExW", GetClassInfoExW(wc.hInstance, L"JuiceTestWindow", &info) != 0);
  }

  main_window = CreateWindowExW(0, L"JuiceTestWindow", L"JUICE GUI test", WS_OVERLAPPEDWINDOW | (show ? WS_VISIBLE : 0),
                                CW_USEDEFAULT, CW_USEDEFAULT, 320, 200, NULL, NULL, wc.hInstance, (LPVOID)0x1234);
  line_i("window created", main_window != NULL);
  {
    wchar_t title[64];
    int n = GetWindowTextW(main_window, title, 64);
    line_i("title length", n);
    int children = 0;
    EnumChildWindows(main_window, count_children, (LPARAM)&children);
    line_i("child windows", children);
    line_i("SendMessage WM_GETTEXTLENGTH", (i64)SendMessageW(main_window, WM_GETTEXTLENGTH, 0, 0));
  }

  MSG msg;
  int result;
  while ((result = GetMessageW(&msg, NULL, 0, 0)) > 0) {
    TranslateMessage(&msg);
    DispatchMessageW(&msg);
  }
  line_i("quit code", (i64)msg.wParam);
  line_i("timer ticks", timer_ticks);
  {
    wchar_t text[64];
    int n = GetWindowTextW(edit, text, 64);  /* the window is destroyed: 0 */
    line_i("edit text after destroy", n);
  }
  line_i("subclassed WM_SETTEXT calls", subclass_settext);
  line_i("IsWindow after destroy", IsWindow(main_window));

  dialog_test();
  gdi_test();
  finish(0);
}
