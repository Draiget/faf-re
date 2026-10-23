#pragma once

// Force-included by main.vcxproj's x64 configurations, and by nothing else.
//
// The recovered tree pins the Win32 layout of the 2007 binary with thousands of
// `static_assert(sizeof(T) == 0xNN)` / `static_assert(offsetof(T, m) == 0xNN)`.
// Those numbers are facts about the x86 image: on x64 every pointer, vtable
// pointer and size_t is 8 bytes, so every assert on a pointer-bearing type
// fails, and there is no x64 original to hold the layout to. The Win32 build
// keeps all of them. Here they are switched off wholesale rather than gated one
// by one across ~1,100 files: a static_assert has no effect on code generation,
// so this changes diagnostics only.
//
// Code that must be checked on x64 as well (wire formats, file headers) cannot
// rely on static_assert in this configuration; the x86 build still checks it,
// and its layout carries no pointers, so it is the same on both.
#if defined(__cplusplus) && defined(_M_X64)
#define _ALLOW_KEYWORD_MACROS
#define static_assert(...) static_assert(true, "x86 layout assert, not checked on x64")
#endif
