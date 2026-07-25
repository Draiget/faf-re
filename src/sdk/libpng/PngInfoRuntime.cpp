// libpng info-struct lifecycle runtime recovery.
// Source: embedded wxWindows 2.4.2 libpng (dependencies/wxWindows-2.4.2/src/png/png.c).
// The ForgedAlliance.exe binary links libpng statically as png.lib; these
// recovered functions match the binary at their given addresses.

#include <cstring>

#include "libpng/PngInfoRuntime.h"
#include "libpng/PngMemRuntime.h"   // png_free / png_zfree
#include "libpng/PngSetRuntime.h"   // png_info_struct field layout
#include "libpng/PngStructRuntime.h"

namespace {

struct PngInfoRowLayoutRuntimeView
{
  std::uint8_t pad00_5F[0x60]{};
  std::uint32_t rowbytes = 0;  // +0x60
  std::uint8_t channels = 0;   // +0x64
  std::uint8_t pixelDepth = 0; // +0x65
};

static_assert(offsetof(PngInfoRowLayoutRuntimeView, rowbytes) == 0x60,
              "PngInfoRowLayoutRuntimeView::rowbytes offset must be 0x60");
static_assert(offsetof(PngInfoRowLayoutRuntimeView, channels) == 0x64,
              "PngInfoRowLayoutRuntimeView::channels offset must be 0x64");
static_assert(offsetof(PngInfoRowLayoutRuntimeView, pixelDepth) == 0x65,
              "PngInfoRowLayoutRuntimeView::pixelDepth offset must be 0x65");

} // namespace

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
extern "C" void png_info_init_3(png_infopp ptr_ptr, png_size_t png_info_struct_size)
{
  auto* info_ptr = reinterpret_cast<void*>(*ptr_ptr);

  if (png_info_struct_size < kPngInfoStructSize) {
    // Version-skew path: caller's png_info_struct is smaller than this
    // libpng build expects. Replace it with a fresh one.
    png_destroy_struct(info_ptr);
    info_ptr = png_create_struct(kPngStructInfo);
    *ptr_ptr = reinterpret_cast<png_info_struct*>(info_ptr);
  }

  std::memset(info_ptr, 0, kPngInfoStructSize);
}

/**
 * Address: 0x009E05DF (FUN_009E05DF)
 * Mangled: png_free_data
 *
 * IDA signature:
 * void __cdecl png_free_data(png_structp png_ptr, png_infop info_ptr,
 *                            png_uint_32 mask, int num);
 *
 * What it does:
 * Frees each info-owned optional-chunk buffer selected by `mask`, gated by the
 * matching info_ptr->free_me ownership bit. num == -1 frees a whole array
 * (recursing per element for the multi-record types text/sPLT/unknown); num >= 0
 * frees a single element. After a buffer is freed its pointer is zeroed and the
 * matching info_ptr->valid bit cleared. Finally the freed bits are removed from
 * free_me — all of `mask` for a whole-array free, otherwise `mask & ~PNG_FREE_MUL`
 * so the still-owned sibling records of a multi-record type keep their bit.
 * Branch order follows the compiled binary (not the canonical png.c source).
 */
extern "C" void png_free_data(png_structp png_ptr, png_infop info_ptr,
                              std::uint32_t mask, int num)
{
  if (png_ptr == nullptr || info_ptr == nullptr) {
    return;
  }

  const std::uint32_t owned = mask & info_ptr->free_me;

  // PNG_FREE_TEXT (0x4000) — tEXt/zTXt records (free each .key, then the array).
  if ((owned & 0x4000u) != 0) {
    if (num != -1) {
      if (info_ptr->text != nullptr && info_ptr->text[num].key != nullptr) {
        png_free(png_ptr, info_ptr->text[num].key);
        info_ptr->text[num].key = nullptr;
      }
    } else {
      for (int i = 0; i < info_ptr->num_text; ++i) {
        png_free_data(png_ptr, info_ptr, 0x4000u, i);
      }
      png_free(png_ptr, info_ptr->text);
      info_ptr->text = nullptr;
      info_ptr->num_text = 0;
    }
  }

  // PNG_FREE_TRNS (0x2000) — tRNS alpha array.
  if ((owned & 0x2000u) != 0) {
    png_free(png_ptr, info_ptr->trans);
    info_ptr->valid &= ~0x0010u;  // PNG_INFO_tRNS
    info_ptr->trans = nullptr;
  }

  // PNG_FREE_SCAL (0x100) — floating-point build frees no string, only clears valid.
  if ((owned & 0x0100u) != 0) {
    info_ptr->valid &= ~0x4000u;  // PNG_INFO_sCAL
  }

  // PNG_FREE_PCAL (0x80) — pCAL purpose/units strings + params array.
  if ((owned & 0x0080u) != 0) {
    png_free(png_ptr, info_ptr->pcal_purpose);
    png_free(png_ptr, info_ptr->pcal_units);
    info_ptr->pcal_purpose = nullptr;
    info_ptr->pcal_units = nullptr;
    if (info_ptr->pcal_params != nullptr) {
      for (int i = 0; i < info_ptr->pcal_nparams; ++i) {
        png_free(png_ptr, info_ptr->pcal_params[i]);
        info_ptr->pcal_params[i] = nullptr;
      }
      png_free(png_ptr, info_ptr->pcal_params);
      info_ptr->pcal_params = nullptr;
    }
    info_ptr->valid &= ~0x0400u;  // PNG_INFO_pCAL
  }

  // PNG_FREE_ICCP (0x10) — iCCP name + profile.
  if ((owned & 0x0010u) != 0) {
    png_free(png_ptr, info_ptr->iccp_name);
    png_free(png_ptr, info_ptr->iccp_profile);
    info_ptr->valid &= ~0x1000u;  // PNG_INFO_iCCP
    info_ptr->iccp_name = nullptr;
    info_ptr->iccp_profile = nullptr;
  }

  // PNG_FREE_SPLT (0x20) — sPLT records (free each .name + .entries, then the array).
  if ((owned & 0x0020u) != 0) {
    if (num != -1) {
      if (info_ptr->splt_palettes != nullptr) {
        png_free(png_ptr, info_ptr->splt_palettes[num].name);
        png_free(png_ptr, info_ptr->splt_palettes[num].entries);
        info_ptr->splt_palettes[num].name = nullptr;
        info_ptr->splt_palettes[num].entries = nullptr;
      }
    } else {
      if (info_ptr->splt_palettes_num != 0) {
        for (int i = 0; i < info_ptr->splt_palettes_num; ++i) {
          png_free_data(png_ptr, info_ptr, 0x0020u, i);
        }
        png_free(png_ptr, info_ptr->splt_palettes);
        info_ptr->splt_palettes = nullptr;
        info_ptr->splt_palettes_num = 0;
      }
      info_ptr->valid &= ~0x2000u;  // PNG_INFO_sPLT
    }
  }

  // PNG_FREE_UNKN (0x200) — unknown-chunk records (free each .data, then the array).
  if ((owned & 0x0200u) != 0) {
    if (num != -1) {
      if (info_ptr->unknown_chunks != nullptr) {
        png_free(png_ptr, info_ptr->unknown_chunks[num].data);
        info_ptr->unknown_chunks[num].data = nullptr;
      }
    } else {
      if (info_ptr->unknown_chunks_num != 0) {
        for (int i = 0; i < static_cast<int>(info_ptr->unknown_chunks_num); ++i) {
          png_free_data(png_ptr, info_ptr, 0x0200u, i);
        }
        png_free(png_ptr, info_ptr->unknown_chunks);
        info_ptr->unknown_chunks = nullptr;
        info_ptr->unknown_chunks_num = 0;
      }
    }
  }

  // PNG_FREE_HIST (0x08) — hIST array.
  if ((owned & 0x0008u) != 0) {
    png_free(png_ptr, info_ptr->hist);
    info_ptr->valid &= ~0x0040u;  // PNG_INFO_hIST
    info_ptr->hist = nullptr;
  }

  // PNG_FREE_PLTE (0x1000) — internally-allocated palette (freed via png_zfree).
  if ((owned & 0x1000u) != 0) {
    png_zfree(png_ptr, info_ptr->palette);
    info_ptr->valid &= ~0x0008u;  // PNG_INFO_PLTE
    info_ptr->palette = nullptr;
    info_ptr->num_palette = 0;
  }

  // PNG_FREE_ROWS (0x40) — attached image rows.
  if ((owned & 0x0040u) != 0) {
    if (info_ptr->row_pointers != nullptr) {
      for (int j = 0; j < static_cast<int>(info_ptr->height); ++j) {
        png_free(png_ptr, info_ptr->row_pointers[j]);
        info_ptr->row_pointers[j] = nullptr;
      }
      png_free(png_ptr, info_ptr->row_pointers);
      info_ptr->row_pointers = nullptr;
    }
    info_ptr->valid &= ~0x8000u;  // PNG_INFO_IDAT
  }

  // Drop the freed ownership bits. A single-element free (num != -1) must keep
  // the multi-record types' bit (PNG_FREE_MUL = 0x4220) since siblings remain.
  std::uint32_t clear = mask;
  if (num != -1) {
    clear &= 0xFFFFBDDFu;  // ~PNG_FREE_MUL
  }
  info_ptr->free_me &= ~clear;
}

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
extern "C" void png_info_destroy(png_structp png_ptr, png_infop info_ptr)
{
  constexpr std::uint32_t kPngFreeAll = 0x7FFF;

  png_free_data(png_ptr, info_ptr, kPngFreeAll, -1);

  auto chunk_list = libpng_detail::GetChunkList(png_ptr);
  if (chunk_list.num != 0) {
    png_free(png_ptr, chunk_list.entries);
    chunk_list.entries = nullptr;
    chunk_list.num     = 0;
  }

  png_info_init_3(&info_ptr, kPngInfoStructSize);
}

/**
 * Address: 0x009E25E3 (FUN_009E25E3)
 *
 * IDA signature:
 * png_uint_32 __cdecl png_get_valid(png_structp png_ptr, png_infop info_ptr, png_uint_32 flag);
 *
 * What it does:
 * Returns the bits of `flag` that are set in info_ptr->valid (bitmask of which
 * optional PNG chunks have been read or supplied). Returns 0 if either pointer
 * is null. The png_struct argument is required by the libpng API but not
 * dereferenced — only its presence acts as a guard.
 */
extern "C" std::uint32_t png_get_valid(png_structp png_ptr, png_infop info_ptr, std::uint32_t flag)
{
  if (png_ptr == nullptr || info_ptr == nullptr) {
    return 0;
  }
  // info_ptr->valid is a uint32_t at +0x08 (see PngSetRuntime.h layout view).
  return flag & info_ptr->valid;
}

/**
 * Address: 0x009E25C1 (FUN_009E25C1)
 *
 * IDA signature:
 * int __cdecl sub_9E25C1(int a1, int a2, char a3, char a4);
 *
 * What it does:
 * Stores rowbytes/channels/pixel-depth lanes in one png_info payload.
 */
extern "C" void png_info_set_row_layout_runtime(
  png_infop const info_ptr,
  const std::uint32_t rowbytes,
  const std::uint8_t channels,
  const std::uint8_t pixel_depth)
{
  auto* const info = reinterpret_cast<PngInfoRowLayoutRuntimeView*>(info_ptr);
  info->rowbytes = rowbytes;
  info->channels = channels;
  info->pixelDepth = pixel_depth;
}

/**
 * Address: 0x009E25DB (FUN_009E25DB)
 *
 * IDA signature:
 * int __cdecl sub_9E25DB(int a1);
 *
 * What it does:
 * Returns one png_info rowbytes lane (`+0x60`).
 */
extern "C" std::uint32_t png_info_get_rowbytes_runtime(png_infop info_ptr)
{
  const auto* const info = reinterpret_cast<const PngInfoRowLayoutRuntimeView*>(info_ptr);
  return info->rowbytes;
}
