#pragma once

// Force-included into every Windows engine translation unit (src/CMakeLists.txt)
// and into the Linux x86_64 simulation (cmake/FafLinux.cmake), and by nothing
// else.
//
// The recovered tree pins the Win32 layout of the 2007 binary with thousands of
// `static_assert(sizeof(T) == 0xNN)` / `static_assert(offsetof(T, m) == 0xNN)`.
// Those numbers are facts about the x86 image with its exact container layout:
// on x64 every pointer, vtable pointer and size_t is 8 bytes, and the game's x86
// build drops the containers' unused words (legacy/containers/Layout.h), so
// every assert on a type that holds a pointer or a container fails there. Only
// the x86 build with FAF_RETAIL_LAYOUT on (preset clang-x86-retail-layout) keeps
// all of them. Elsewhere they are switched off wholesale rather than gated one
// by one across ~1,100 files: a static_assert has no effect on code generation,
// so this changes diagnostics only.
//
// Code that must be checked everywhere (wire formats, file headers) cannot rely
// on static_assert in this configuration; the retail-layout build still checks
// it, and its layout carries no pointers or containers, so it is the same on all.
#if defined(__cplusplus) && (defined(_M_X64) || defined(__x86_64__) || (defined(FAF_RETAIL_LAYOUT) && FAF_RETAIL_LAYOUT == 0))
#define _ALLOW_KEYWORD_MACROS
#define static_assert(...) static_assert(true, "x86 layout assert, not checked in this build")
#endif
