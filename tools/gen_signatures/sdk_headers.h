// The Windows SDK headers whose functions and COM interfaces gen_signatures
// scans. Also included by the generated COM signature table, which resolves
// interface IDs with __uuidof.
#pragma once

#undef WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <commctrl.h>
#include <commdlg.h>
#include <dwmapi.h>
#include <mmsystem.h>
#include <ole2.h>
#include <oleauto.h>
#include <olectl.h>
#include <propvarutil.h>
#include <psapi.h>
#include <shellapi.h>
#include <shellscalingapi.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <uxtheme.h>
#include <wincodec.h>
#include <wininet.h>
#include <winspool.h>
#include <xinput.h>

// GDI+: the C++ wrapper classes are inline, the flat API is what programs import.
#include <algorithm>
using std::max;
using std::min;
#include <gdiplus.h>

#include <d2d1_3.h>
#include <d2d1effects_2.h>
#include <dwrite_3.h>
#include <d3d9.h>
#include <d3d10_1.h>
#include <d3d11_4.h>
#include <d3d12.h>
#include <d3dcompiler.h>
#include <dxgi1_6.h>
#include <dcomp.h>
#include <dsound.h>
#include <xaudio2.h>
#include <xaudio2fx.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mfreadwrite.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <audiopolicy.h>
#include <endpointvolume.h>

// The C runtime
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wchar.h>
