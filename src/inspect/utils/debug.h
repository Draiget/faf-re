#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

template<class... Args>
void DebugPrintf(std::format_string<Args...> fmt, Args&&... args) {
    const auto s = std::format(fmt, std::forward<Args>(args)...);
#ifdef _WIN32
    OutputDebugStringA(s.c_str());
#else
    std::fputs(s.c_str(), stdout);
#endif
}
