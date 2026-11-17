#pragma once

/**
 * Engine addition: the platform the engine is compiled for, as macros that are always defined, to
 * 0 or 1. Use them in place of the compilers' own (_WIN32, __linux__, __APPLE__):
 *
 *   #if FAFRE_PLATFORM_WINDOWS        Windows (x86 and x64)
 *   #if FAFRE_PLATFORM_LINUX          Linux
 *   #if FAFRE_PLATFORM_MACOS          macOS
 *   #if FAFRE_PLATFORM_POSIX          Linux or macOS: what POSIX gives both (pthreads, dlopen, kill, fork)
 *
 * Code only one POSIX platform has (/proc, prctl, Mach) asks for that platform, not for POSIX.
 *
 * Every build force-includes this header (src/CMakeLists.txt, cmake/FafPosix.cmake and
 * cmake/FafPosixClient.cmake), and compiles with -Werror=undef-prefix for FAFRE_PLATFORM_ and
 * FAFRE_ARCH_, so a file that reaches a `#if FAFRE_PLATFORM_...` or `#if FAFRE_ARCH_...` without
 * it fails to build instead of reading 0.
 */

#if defined(_WIN32)
#define FAFRE_PLATFORM_WINDOWS 1
#else
#define FAFRE_PLATFORM_WINDOWS 0
#endif

#if defined(__linux__)
#define FAFRE_PLATFORM_LINUX 1
#else
#define FAFRE_PLATFORM_LINUX 0
#endif

#if defined(__APPLE__) && defined(__MACH__)
#define FAFRE_PLATFORM_MACOS 1
#else
#define FAFRE_PLATFORM_MACOS 0
#endif

#define FAFRE_PLATFORM_POSIX (FAFRE_PLATFORM_LINUX || FAFRE_PLATFORM_MACOS)

#if (FAFRE_PLATFORM_WINDOWS + FAFRE_PLATFORM_LINUX + FAFRE_PLATFORM_MACOS) != 1
#error "platform/PlatformDefines.h: exactly one of Windows, Linux and macOS must be the target"
#endif

/**
 * The processor the engine is compiled for, the same way: always defined, to 0 or 1, in place of
 * the compilers' own (_M_IX86, __i386__, _M_X64, __x86_64__, _M_ARM64, __aarch64__).
 *
 *   #if FAFRE_ARCH_X86                32-bit x86: the retail binary's layout and calling conventions
 *   #if FAFRE_ARCH_X64                x86-64
 *   #if FAFRE_ARCH_ARM64              64-bit ARM (Apple silicon)
 *   #if FAFRE_ARCH_64BIT              x86-64 or ARM64: 8-byte pointers, the 64-bit containers, the
 *                                     sim block list - what the two 64-bit targets share
 *   #if FAFRE_ARCH_X87                an x87 unit runs legacy/math's x87 routines (x86 and x86-64);
 *                                     elsewhere they are software (legacy/math/X87Soft.cpp)
 *
 * Most code that names a 64-bit target means the layout, not the instruction set: test
 * FAFRE_ARCH_64BIT there, and FAFRE_ARCH_X64 only for x86-64 instructions (MMX, a CONTEXT's
 * x87/SSE state).
 */
#if defined(_M_IX86) || defined(__i386__)
#define FAFRE_ARCH_X86 1
#else
#define FAFRE_ARCH_X86 0
#endif

#if (defined(_M_X64) && !defined(_M_ARM64EC)) || defined(__x86_64__)
#define FAFRE_ARCH_X64 1
#else
#define FAFRE_ARCH_X64 0
#endif

#if defined(_M_ARM64) || defined(__aarch64__)
#define FAFRE_ARCH_ARM64 1
#else
#define FAFRE_ARCH_ARM64 0
#endif

#if (FAFRE_ARCH_X86 + FAFRE_ARCH_X64 + FAFRE_ARCH_ARM64) != 1
#error "platform/PlatformDefines.h: exactly one of x86, x86-64 and ARM64 must be the target"
#endif

#define FAFRE_ARCH_64BIT (FAFRE_ARCH_X64 || FAFRE_ARCH_ARM64)
#define FAFRE_ARCH_X87 (FAFRE_ARCH_X86 || FAFRE_ARCH_X64)

/**
 * macOS on Apple silicon, the one platform-and-processor pair with code of its own (the software
 * x87, the arm64 floating-point environment checks, the app bundle).
 */
#define FAFRE_PLATFORM_MACOS_ARM64 (FAFRE_PLATFORM_MACOS && FAFRE_ARCH_ARM64)

/**
 * The Windows calling conventions the recovered code spells (`static void __stdcall AddBase_CTask(...)`, the
 * binary's): only Windows has them (x86 uses them, x64 ignores them). Elsewhere clang ignored each one with a
 * warning ("calling convention is not supported for this target"), so they are defined to nothing there.
 */
#if !FAFRE_PLATFORM_WINDOWS
#ifndef __stdcall
#define __stdcall
#endif
#ifndef __fastcall
#define __fastcall
#endif
#ifndef __thiscall
#define __thiscall
#endif
#ifndef __cdecl
#define __cdecl
#endif
#endif

/**
 * The Microsoft keyword spellings the recovered code uses, as standard C++, for builds compiled as
 * plain native C++ without clang's Microsoft extensions (FAF_NATIVE_DIALECT: the macOS build,
 * cmake/FafPosix.cmake). The sized integers are MSVC's: __int8 is char, __int64 is long long.
 */
#if !FAFRE_PLATFORM_WINDOWS && defined(FAF_NATIVE_DIALECT)
#define __int8 char
#define __int16 short
#define __int32 int
#define __int64 long long
#define __forceinline inline __attribute__((always_inline))
#define __debugbreak() __builtin_debugtrap()
#endif
