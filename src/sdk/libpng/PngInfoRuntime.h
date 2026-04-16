#pragma once

#include <cstddef>
#include <cstdint>

#include "libpng/PngCommonRuntime.h"  // png_size_t
#include "libpng/PngMemRuntime.h"     // png_free
#include "libpng/PngWriteRuntime.h"

// ============================================================================
// Minimal partial view of libpng 1.2.x png_info_struct used by the info
// lifecycle helpers (init / destroy).
// ============================================================================
//
// The full png_info_struct in libpng 1.2.x is 0x120 bytes long (corroborated
// by png_info_init_3 at 0x009E0567, which passes 0x120 to memset and rejects
// any smaller caller-supplied size).
//
// Only the information lifecycle helpers zero the entire struct, so the view
// here is intentionally opaque — a fixed-size byte buffer. Field-level views
// live in PngSetRuntime.h.

constexpr std::size_t kPngInfoStructSize = 0x120;

// Forward declaration of the struct already defined in PngSetRuntime.h.
struct png_info_struct;
using png_infop  = png_info_struct*;
using png_infopp = png_info_struct**;

// libpng allocator selector: PNG_STRUCT_INFO creates a png_info.
constexpr int kPngStructInfo = 2;

using png_voidp = void*;

// Libpng internal allocator helpers (resolved at link time against png.lib).
// png_free is declared in PngMemRuntime.h.
extern "C" void* png_create_struct(int type);
extern "C" void  png_destroy_struct(void* struct_ptr);
extern "C" void  png_free_data(png_structp png_ptr, png_infop info_ptr,
                               std::uint32_t free_me, int num);

/**
 * Address: 0x009E0567 (FUN_009E0567)
 *
 * IDA signature:
 * void __cdecl png_info_init_3(png_infopp ptr_ptr, png_size_t png_info_struct_size);
 *
 * What it does:
 * Reinitialises a png_info pointer in place. If the caller-supplied struct
 * size is smaller than the real 0x120-byte png_info layout (version skew
 * guard), frees the existing struct and allocates a fresh one via the libpng
 * allocator before zeroing. Otherwise zeroes the existing struct in place.
 */
extern "C" void png_info_init_3(png_infopp ptr_ptr, png_size_t png_info_struct_size);

/**
 * Address: 0x009E0959 (FUN_009E0959)
 *
 * IDA signature:
 * void __cdecl png_info_destroy(png_structp png_ptr, png_infop info_ptr);
 *
 * What it does:
 * Releases all dynamically-allocated sub-resources owned by a png_info struct
 * via png_free_data(..., PNG_FREE_ALL, -1), releases the png_ptr-owned
 * unknown-chunk-keep list when present, and finally reinitialises the info
 * struct in place through png_info_init_3.
 */
extern "C" void png_info_destroy(png_structp png_ptr, png_infop info_ptr);

/**
 * Address: 0x009E25E3 (FUN_009E25E3)
 *
 * IDA signature:
 * png_uint_32 __cdecl png_get_valid(png_structp png_ptr, png_infop info_ptr, png_uint_32 flag);
 *
 * What it does:
 * Returns the bits of `flag` that are set in info_ptr->valid (bitmask of which
 * optional PNG chunks have been read or supplied). Returns 0 if either pointer
 * is null.
 */
extern "C" std::uint32_t png_get_valid(png_structp png_ptr, png_infop info_ptr, std::uint32_t flag);

/**
 * Address: 0x009E25C1 (FUN_009E25C1)
 *
 * IDA signature:
 * int __cdecl sub_9E25C1(int a1, int a2, char a3, char a4);
 *
 * What it does:
 * Writes row layout lanes on one png_info payload:
 * - `rowbytes` at `+0x60`
 * - `channels` at `+0x64`
 * - `pixel_depth` at `+0x65`
 */
extern "C" void png_info_set_row_layout_runtime(
  png_infop      info_ptr,
  std::uint32_t  rowbytes,
  std::uint8_t   channels,
  std::uint8_t   pixel_depth
);

/**
 * Address: 0x009E25DB (FUN_009E25DB)
 *
 * IDA signature:
 * int __cdecl sub_9E25DB(int a1);
 *
 * What it does:
 * Returns `png_info::rowbytes` from lane `+0x60`.
 */
extern "C" std::uint32_t png_info_get_rowbytes_runtime(png_infop info_ptr);
