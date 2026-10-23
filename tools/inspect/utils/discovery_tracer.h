#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace inspect::discovery {

bool Start(HMODULE module_handle);
void Stop();

} // namespace inspect::discovery

