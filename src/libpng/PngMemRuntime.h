#pragma once

// libpng 1.2.x memory / zlib allocator runtime helpers recovered from
// ForgedAlliance.exe. Source origin: embedded wxWindows 2.4.2 libpng
// (dependencies/wxWindows-2.4.2/src/png/pngmem.c).
//
// These are the glue callbacks libpng hands to zlib as (alloc_func, free_func)
// via deflateInit/inflateInit. zlib calls them back with a voidpf opaque
// (the libpng png_structp).

#include <cstddef>
#include <cstdint>

#include "libpng/PngWriteRuntime.h"  // png_structp, png_malloc

// libpng free entry point; thin wrapper around the free allocator.
extern "C" void png_free(png_structp png_ptr, void* ptr);

/**
 * Address: 0x009E0494 (FUN_009E0494)
 * Mangled: png_zalloc
 *
 * IDA signature:
 * void* __cdecl png_zalloc(png_structp png_ptr, png_uint_32 items, png_uint_32 size);
 *
 * What it does:
 * zlib allocator callback used by libpng when creating deflate/inflate streams.
 * Computes items*size, temporarily sets PNG_FLAG_MALLOC_NULL_MEM_OK so a NULL
 * return is tolerated, calls png_malloc, then restores the flag. On success
 * zero-fills the buffer in up to two memset chunks (split at 0x8000 bytes to
 * accommodate the 16-bit memset limit of the legacy libpng port).
 */
extern "C" void* png_zalloc(
  png_structp   png_ptr,
  std::uint32_t items,
  std::uint32_t size
);

/**
 * Address: 0x009E0509 (FUN_009E0509)
 * Mangled: png_zfree
 *
 * IDA signature:
 * void __cdecl png_zfree(png_structp png_ptr, void* ptr);
 *
 * What it does:
 * zlib free callback used by libpng. Thin thunk forwarding to png_free.
 */
extern "C" void png_zfree(png_structp png_ptr, void* ptr);
