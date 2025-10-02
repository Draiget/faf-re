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
	#include <winsock2.h>
	#include <ws2tcpip.h>
	#include <windows.h>
#ifdef _MSC_VER
#pragma comment(lib, "Ws2_32.lib")
#endif
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

#if defined(_WINSOCKAPI_) && !defined(_WINSOCK2API_)
#  error "winsock.h (v1) was included instead of winsock2.h. Fix your include order."
#endif

#define LODWORD(x) (*reinterpret_cast<unsigned long*>(& (x)))
#define HIDWORD(x) (*reinterpret_cast<unsigned long*>(& (x) + 1))

#ifdef CreateEvent
#undef CreateEvent
#endif

#if defined(MOHO_CUSTOM_BUILD_IGNORE_EBO_PADDING)
#include <array>
#endif

/** Internal: token pasting helper */
#define MOHO_EBO__CAT_IMPL(a,b) a##b
#define MOHO_EBO__CAT(a,b)      MOHO_EBO__CAT_IMPL(a,b)

/** Internal: counter fallback */
#ifndef __COUNTER__
#define __COUNTER__ __LINE__
#endif

/**
 * Declare a unique padding member sized in 4-byte units.
 * Usage: MOHO_EBO_PADDING_FIELD(3); // reserves 12 bytes (unless ignored)
 */
#if !defined(MOHO_CUSTOM_BUILD_IGNORE_EBO_PADDING)

#define MOHO_EBO_PADDING_FIELD(N)                                                     \
    static_assert((N) >= 0, "padding units must be non-negative");                      \
    [[maybe_unused]] std::uint8_t MOHO_EBO__CAT(eboPadding_, __COUNTER__)[(N) * 4]{}

#else
 /* No actual storage, but keep a member for debug/inspection:
    - GCC/Clang: zero-sized array (extension).
    - MSVC/others: zero-size via [[no_unique_address]] empty std::array. */
#if defined(__clang__) || defined(__GNUC__)
#define MOHO_EBO_PADDING_FIELD(N)                                                   \
      [[maybe_unused]] std::uint8_t MOHO_EBO__CAT(eboPadding_, __COUNTER__)[0]{}
#else
#define MOHO_EBO_PADDING_FIELD(N)                                                   \
      [[maybe_unused]] [[no_unique_address]]                                            \
      std::array<std::uint8_t, 0> MOHO_EBO__CAT(eboPadding_, __COUNTER__){}
#endif
#endif

#if defined(_MSC_VER)
#if defined(MOHO_ABI_MSVC8_COMPAT)
#define MOHO_EMPTY_BASES
#else
#define MOHO_EMPTY_BASES __declspec(empty_bases)
#endif
#else
#define MOHO_EMPTY_BASES
#endif
