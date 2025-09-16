#pragma once

#if defined(_MSC_VER)
#define FA_FASTCALL __fastcall
#define FORCE_EBO __declspec(empty_bases)
#define class_EBO class FORCE_EBO
#else
#define FA_FASTCALL
#endif

#if defined(_WIN32)
#  define NOMINMAX
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#else
#  include <pthread.h>
#  include <errno.h>
#  include <time.h>
#endif

#if defined(_MSC_VER)
#include <intrin.h>
#define MOHO_FORCEINLINE __forceinline
#define MOHO_RESTRICT __restrict
#else
#include <immintrin.h>
#define MOHO_FORCEINLINE inline __attribute__((always_inline))
#define MOHO_RESTRICT __restrict__
#endif
