#pragma once

// libpng 1.2.x common runtime helpers recovered from ForgedAlliance.exe.
// Source origin: embedded wxWindows 2.4.2 libpng (dependencies/wxWindows-2.4.2/src/png/png.c).
//
// This header declares the small shared helpers used by both read and write paths
// (signature comparison and CRC accumulation).

#include <cstddef>
#include <cstdint>

#include "libpng/PngWriteRuntime.h"  // png_structp forward declaration

// ---------------------------------------------------------------------------
// png_struct partial layout for CRC/chunk helpers
// ---------------------------------------------------------------------------
// Binary evidence (png_calculate_crc @ 0x009E0526):
//   +0x6C:  flags        (uint32_t)  tested for 0x300 and 0x800
//   +0x110: crc          (uint32_t)
//   +0x11C: chunk_name   (uint8_t[4]); byte 0 ancillary bit test (& 0x20)
//
// libpng flags used here (from libpng 1.2.x pngconf.h/png.h):
constexpr std::uint32_t kPngFlagMallocNullMemOk       = 0x00100000;
constexpr std::uint32_t kPngFlagCrcAncillaryUse       = 0x00000100;
constexpr std::uint32_t kPngFlagCrcAncillaryNowarn    = 0x00000200;
constexpr std::uint32_t kPngFlagCrcAncillaryMask      = 0x00000300;
constexpr std::uint32_t kPngFlagCrcCriticalIgnore     = 0x00000800;

// Ancillary-bit mask on chunk_name[0] (libpng PNG_CHUNK_ANCILLARY).
constexpr std::uint8_t  kPngChunkAncillaryBit         = 0x20;

using png_bytep  = std::uint8_t*;
using png_size_t = std::uint32_t;
using png_uint_32 = std::uint32_t;

// zlib CRC primitive used by libpng.
extern "C" unsigned long crc32(unsigned long crc, const unsigned char* buf, unsigned int len);
// libpng memory compare wrapper (maps to memcmp).
extern "C" int png_memcmp(const void* s1, const void* s2, std::size_t n);

/**
 * Address: 0x009E0401 (FUN_009E0401)
 * Mangled: png_sig_cmp
 *
 * IDA signature:
 * int __cdecl png_sig_cmp(int sig, unsigned int start, unsigned int num_to_check);
 *
 * What it does:
 * Compares the supplied byte buffer against the canonical 8-byte PNG signature
 * (\x89 P N G \r \n \x1a \n). Clamps start/num_to_check into the 8-byte window
 * and returns 0 when start is past the signature or the slice matches.
 */
extern "C" int png_sig_cmp(
  const std::uint8_t* sig,
  std::uint32_t       start,
  std::uint32_t       num_to_check
);

/**
 * Address: 0x009E050E (FUN_009E050E)
 * Mangled: png_reset_crc
 *
 * IDA signature:
 * png_uint_32 __cdecl png_reset_crc(png_struct *png_ptr);
 *
 * What it does:
 * Resets the rolling CRC on the png_struct to the zlib crc32 initial state
 * (crc32(0, NULL, 0)) and returns the new value.
 */
extern "C" png_uint_32 png_reset_crc(png_structp png_ptr);

/**
 * Address: 0x009E0526 (FUN_009E0526)
 * Mangled: png_calculate_crc
 *
 * IDA signature:
 * void __cdecl png_calculate_crc(png_structp png_ptr, png_bytep ptr, png_size_t length);
 *
 * What it does:
 * Accumulates the supplied byte range into png_ptr->crc via zlib crc32, but
 * only when the chunk's CRC policy permits it. For ancillary chunks, skips
 * when PNG_FLAG_CRC_ANCILLARY_USE+NOWARN are both set. For critical chunks,
 * skips when PNG_FLAG_CRC_CRITICAL_IGNORE is set.
 */
extern "C" void png_calculate_crc(
  png_structp png_ptr,
  png_bytep   ptr,
  png_size_t  length
);
