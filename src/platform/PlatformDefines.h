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
 * Every build force-includes this header (src/CMakeLists.txt, cmake/FafLinux.cmake and
 * cmake/FafLinuxClient.cmake), and compiles with -Werror=undef-prefix for FAFRE_PLATFORM_, so a
 * file that reaches a `#if FAFRE_PLATFORM_...` without it fails to build instead of reading 0.
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
