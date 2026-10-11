#pragma once

// Native DLLs' view of the guest's modules (see native_hooks.cpp).

namespace juice::win {

class GuestProcess;

// Redirect the loader queries (GetModuleFileName, GetModuleHandle(Ex),
// GetProcAddress) that native modules import, now and as more load, so that
// they answer for the guest's modules.
void install_native_hooks(GuestProcess& process);

}  // namespace juice::win
