#pragma once

#include <cstddef>
#include <cstdint>

#include "libpng/PngWriteRuntime.h"  // png_structp / png_voidp / fwd decls

// ============================================================================
// libpng row-transform runtime helpers recovered from ForgedAlliance.exe.
//
// All transforms operate on a single decoded scanline. The first argument is
// always a png_row_info* (libpng 1.2.x layout):
//
//   +0x00  png_uint_32 width        // pixels in row
//   +0x04  png_uint_32 rowbytes     // bytes in row
//   +0x08  png_byte    color_type   // PNG_COLOR_TYPE_*
//   +0x09  png_byte    bit_depth    // 1/2/4/8/16
//   +0x0A  png_byte    channels     // 1..4
//   +0x0B  png_byte    pixel_depth  // bit_depth * channels
//
// The transform is applied to the row buffer in-place; rowbytes / pixel_depth /
// color_type / channels may be updated when the transform changes the
// pixel format. Field offsets are taken directly from the binary evidence
// (e.g. mov [eax+0Ah], etc) and from the wxWindows 2.4.2 libpng headers.
// ============================================================================

namespace libpng_detail {

// Field offsets inside png_row_info (libpng 1.2.x).
constexpr std::size_t kRowInfoWidthOffset       = 0x00;
constexpr std::size_t kRowInfoRowbytesOffset    = 0x04;
constexpr std::size_t kRowInfoColorTypeOffset   = 0x08;
constexpr std::size_t kRowInfoBitDepthOffset    = 0x09;
constexpr std::size_t kRowInfoChannelsOffset    = 0x0A;
constexpr std::size_t kRowInfoPixelDepthOffset  = 0x0B;

// PNG color type bit flags (libpng 1.2.x).
constexpr std::uint8_t kPngColorMaskPalette    = 0x01;
constexpr std::uint8_t kPngColorMaskColor      = 0x02;
constexpr std::uint8_t kPngColorMaskAlpha      = 0x04;

constexpr std::uint8_t kPngColorTypeGray        = 0;
constexpr std::uint8_t kPngColorTypePalette     = 3;  // palette | (color in 2|alpha=>3)
constexpr std::uint8_t kPngColorTypeRgb         = 2;  // color
constexpr std::uint8_t kPngColorTypeGrayAlpha   = 4;  // alpha
constexpr std::uint8_t kPngColorTypeRgbAlpha    = 6;  // color | alpha

// Typed view onto a png_row_info* without pulling in the full libpng header.
struct PngRowInfoView
{
  std::uint32_t& width;
  std::uint32_t& rowbytes;
  std::uint8_t&  color_type;
  std::uint8_t&  bit_depth;
  std::uint8_t&  channels;
  std::uint8_t&  pixel_depth;
};

[[nodiscard]] inline PngRowInfoView GetRowInfo(void* row_info) noexcept
{
  auto* base = reinterpret_cast<std::uint8_t*>(row_info);
  return PngRowInfoView{
    *reinterpret_cast<std::uint32_t*>(base + kRowInfoWidthOffset),
    *reinterpret_cast<std::uint32_t*>(base + kRowInfoRowbytesOffset),
    *(base + kRowInfoColorTypeOffset),
    *(base + kRowInfoBitDepthOffset),
    *(base + kRowInfoChannelsOffset),
    *(base + kRowInfoPixelDepthOffset),
  };
}

// libpng 1.2.x ships these as hand-rolled lookup tables (pngrtran.c). The
// recovered functions reference them by name; the actual storage lives in
// the linked png.lib.
extern "C" const std::uint8_t onebppswaptable[256];
extern "C" const std::uint8_t twobppswaptable[256];
extern "C" const std::uint8_t fourbppswaptable[256];

} // namespace libpng_detail

// Forward declaration; full layout lives in libpng's bundled png.h, and the
// recovered helpers only ever access fields through libpng_detail::PngRowInfoView.
struct png_row_info;
#ifndef FA_LIBPNG_PNG_ROW_INFOP_DEFINED
#define FA_LIBPNG_PNG_ROW_INFOP_DEFINED
using png_row_infop = png_row_info*;
#endif

/**
 * Address: 0x009E22FF (FUN_009E22FF)
 *
 * IDA signature:
 * void __cdecl png_do_swap(png_row_infop row_info, png_bytep row);
 *
 * What it does:
 * Byte-swaps each 16-bit sample in the row in place. No-op for any bit depth
 * other than 16. Used to convert between big-endian and little-endian 16-bit
 * PNG samples on read and write.
 */
extern "C" void png_do_swap(png_row_infop row_info, std::uint8_t* row);

/**
 * Address: 0x009E232C (FUN_009E232C)
 *
 * IDA signature:
 * void __cdecl png_do_packswap(png_row_infop row_info, png_bytep row);
 *
 * What it does:
 * Reverses the bit order within each byte for sub-byte (1/2/4 bpp) rows by
 * looking up each byte in a precomputed swap table. No-op for 8/16-bit rows
 * or unknown sub-byte depths.
 */
extern "C" void png_do_packswap(png_row_infop row_info, std::uint8_t* row);

/**
 * Address: 0x009E2377 (FUN_009E2377)
 *
 * IDA signature:
 * void __cdecl png_do_strip_filler(png_row_infop row_info, png_bytep row, png_uint_32 flags);
 *
 * What it does:
 * Removes a filler channel from RGBA/GA rows in place, leaving RGB / G. The
 * sign of `flags` selects whether the filler byte is at the high or low end
 * of each pixel. Handles 8-bit and 16-bit RGBA->RGB and GA->G; updates
 * channels, pixel_depth and rowbytes and clears the alpha bit on color_type.
 */
extern "C" void png_do_strip_filler(png_row_infop row_info, std::uint8_t* row, std::uint32_t flags);

/**
 * Address: 0x009E2502 (FUN_009E2502)
 *
 * IDA signature:
 * void __cdecl png_do_bgr(png_row_infop row_info, png_bytep row);
 *
 * What it does:
 * Swaps the R and B components of every pixel in an RGB or RGBA row in place.
 * Supports 8-bit and 16-bit color depths. No-op for non-color rows.
 */
extern "C" void png_do_bgr(png_row_infop row_info, std::uint8_t* row);

/**
 * Address: 0x009E3A7E (FUN_009E3A7E)
 *
 * IDA signature:
 * void __cdecl png_do_unpack(png_row_infop row_info, png_bytep row);
 *
 * What it does:
 * Expands a 1/2/4-bpp packed row into one byte per pixel in place, walking the
 * source from the end so the unpacked samples can overwrite the packed row in
 * a single pass. Updates bit_depth to 8 and refreshes pixel_depth / rowbytes.
 */
extern "C" void png_do_unpack(png_row_infop row_info, std::uint8_t* row);

/**
 * Address: 0x009E3B8E (FUN_009E3B8E)
 *
 * IDA signature:
 * char __cdecl png_do_unshift(png_row_infop row_info, png_bytep row, png_color_8p sig_bits);
 *
 * What it does:
 * Right-shifts each channel sample so that the significant bits described by
 * the sBIT chunk land in the LSBs. Computes a per-channel shift, then dispatches
 * by bit_depth (2/4/8/16). No-op for palette rows or zero shifts.
 */
extern "C" char png_do_unshift(png_row_infop row_info, std::uint8_t* row, const std::uint8_t* sig_bits);

/**
 * Address: 0x009E3D06 (FUN_009E3D06)
 *
 * IDA signature:
 * void __cdecl png_do_chop(png_row_infop row_info, png_bytep row);
 *
 * What it does:
 * Strips the low byte of every 16-bit sample in place, downconverting a row
 * from 16 bpp to 8 bpp. Updates bit_depth, pixel_depth and rowbytes.
 */
extern "C" void png_do_chop(png_row_infop row_info, std::uint8_t* row);

/**
 * Address: 0x009E3D4A (FUN_009E3D4A)
 *
 * IDA signature:
 * void __cdecl png_do_read_swap_alpha(png_row_infop row_info, png_bytep row);
 *
 * What it does:
 * Rearranges RGBA/GA rows in place so the alpha channel comes first (ARGB / AG).
 * Walks the row in reverse for 8-bit and 16-bit color depths. No-op for any
 * row that does not carry an alpha channel.
 */
extern "C" void png_do_read_swap_alpha(png_row_infop row_info, std::uint8_t* row);

/**
 * Address: 0x009E3E3C (FUN_009E3E3C)
 *
 * IDA signature:
 * void __cdecl png_do_read_invert_alpha(png_row_infop row_info, png_bytep row);
 *
 * What it does:
 * Inverts the alpha byte(s) of every pixel in an RGBA or grayscale-alpha row
 * in place (a' = 0xFF - a, or 0xFFFF - a for 16-bit). Walks the row in
 * reverse so the writes never collide with reads.
 */
extern "C" void png_do_read_invert_alpha(png_row_infop row_info, std::uint8_t* row);

/**
 * Address: 0x009E3EE6 (FUN_009E3EE6)
 *
 * IDA signature:
 * png_uint_32 __cdecl png_do_read_filler(png_row_infop row_info, png_bytep row,
 *                                        png_uint_32 filler, png_uint_32 flags);
 *
 * What it does:
 * Inserts a filler byte/word into a grayscale or RGB row to produce GA or RGBA,
 * walking the row in reverse so the expansion writes never overrun their reads.
 * The sign of `flags` chooses leading vs. trailing filler placement. Updates
 * channels, pixel_depth and rowbytes for 8-bit and 16-bit rows.
 */
extern "C" std::uint32_t png_do_read_filler(png_row_infop row_info, std::uint8_t* row,
                                            std::uint32_t filler, std::uint32_t flags);

/**
 * Address: 0x009E411B (FUN_009E411B)
 *
 * IDA signature:
 * void __cdecl png_do_gray_to_rgb(png_row_infop row_info, png_bytep row);
 *
 * What it does:
 * Replicates a grayscale (or grayscale+alpha) row into RGB / RGBA in place,
 * walking the source in reverse. Supports 8 and 16-bit depths. Increments the
 * channel count, sets PNG_COLOR_MASK_COLOR, refreshes pixel_depth and rowbytes.
 */
extern "C" void png_do_gray_to_rgb(png_row_infop row_info, std::uint8_t* row);

/**
 * Address: 0x009E424D (FUN_009E424D)
 *
 * IDA signature:
 * int __cdecl png_do_rgb_to_gray(png_structp png_ptr, png_row_infop row_info, png_bytep row);
 *
 * What it does:
 * Collapses an RGB or RGBA row to grayscale (+alpha) in place using the
 * weighted-sum coefficients held in png_struct (rgb_to_gray_red_coeff at
 * +0x22A, _green_coeff at +0x22C, _blue_coeff at +0x22E). When the optional
 * gamma correction tables are present, the per-channel samples are gamma-
 * corrected before averaging and gamma-encoded after. Returns a flag bit set
 * to 1 whenever any pixel had unequal R/G/B components.
 */
extern "C" int png_do_rgb_to_gray(png_structp png_ptr, png_row_infop row_info, std::uint8_t* row);

/**
 * Address: 0x009E4862 (FUN_009E4862)
 *
 * IDA signature:
 * void __cdecl png_do_background(png_row_infop row_info, png_bytep row,
 *                                png_color_16p trans_values, png_color_16p background,
 *                                png_color_16p background_1,
 *                                png_bytep gamma_table, png_bytep gamma_from_1,
 *                                png_bytep gamma_to_1,
 *                                png_uint_16pp gamma_16, png_uint_16pp gamma_16_from_1,
 *                                png_uint_16pp gamma_16_to_1, int gamma_shift);
 *
 * What it does:
 * Composites the row over a solid background using the provided gamma tables.
 * Dispatches by color_type and bit_depth, handling palette/grayscale/RGB rows
 * with and without alpha at 1/2/4/8/16 bpp. After alpha-bearing rows finish
 * compositing, the alpha channel is dropped and channels / pixel_depth /
 * rowbytes are refreshed.
 */
extern "C" void png_do_background(png_row_infop row_info, std::uint8_t* row,
                                  const std::uint16_t* trans_values,
                                  const std::uint8_t* background,
                                  const std::uint16_t* background_1,
                                  const std::uint8_t* gamma_table,
                                  const std::uint8_t* gamma_from_1,
                                  const std::uint8_t* gamma_to_1,
                                  const std::uint16_t* const* gamma_16,
                                  const std::uint16_t* const* gamma_16_from_1,
                                  const std::uint16_t* const* gamma_16_to_1,
                                  std::int16_t gamma_shift);

/**
 * Address: 0x009E5686 (FUN_009E5686)
 *
 * IDA signature:
 * png_bytep __cdecl png_do_gamma(png_row_infop row_info, png_bytep row,
 *                                png_bytep gamma_table, png_uint_16pp gamma_16_table,
 *                                int gamma_shift);
 *
 * What it does:
 * Applies a per-channel gamma correction to a row. For 8-bit (and sub-byte)
 * rows the correction is a single byte->byte LUT; for 16-bit rows it is a
 * two-level table indexed by the high byte and an offset built from the low
 * byte (the standard libpng 16-bit gamma representation). Dispatches by
 * color_type and bit_depth.
 */
extern "C" std::uint8_t* png_do_gamma(png_row_infop row_info, std::uint8_t* row,
                                      const std::uint8_t* gamma_table,
                                      const std::uint16_t* const* gamma_16_table,
                                      int gamma_shift);

/**
 * Address: 0x009E59D4 (FUN_009E59D4)
 *
 * IDA signature:
 * png_uint_32 __cdecl png_do_expand_palette(png_row_infop row_info, png_bytep row,
 *                                           png_colorp palette, png_bytep trans, int num_trans);
 *
 * What it does:
 * Expands an indexed/palette row to RGB or RGBA in place, walking from the end.
 * For sub-byte palette rows the indices are first unpacked to bytes; then each
 * index is replaced with the corresponding palette entry, optionally with the
 * tRNS alpha when `trans` is non-null. Updates color_type / channels /
 * pixel_depth / rowbytes accordingly.
 */
extern "C" std::uint32_t png_do_expand_palette(png_row_infop row_info, std::uint8_t* row,
                                               const std::uint8_t* palette,
                                               const std::uint8_t* trans, int num_trans);

/**
 * Address: 0x009E5BD9 (FUN_009E5BD9)
 *
 * IDA signature:
 * png_uint_32 __cdecl png_do_expand(png_row_infop row_info, png_bytep row,
 *                                   png_color_16p trans_value);
 *
 * What it does:
 * Expands grayscale or RGB rows that carry a single transparent colour into
 * grayscale-alpha or RGBA rows in place. For sub-byte grayscale rows the row
 * is first promoted to 8 bpp (replicating the bit pattern), then alpha bytes
 * are inserted from the right, replacing the transparent colour with zero.
 */
extern "C" std::uint32_t png_do_expand(png_row_infop row_info, std::uint8_t* row,
                                       const std::uint16_t* trans_value);

/**
 * Address: 0x009E5F32 (FUN_009E5F32)
 *
 * IDA signature:
 * png_uint_32 __cdecl png_do_dither(png_row_infop row_info, png_bytep row,
 *                                   png_bytep palette_lookup, png_bytep dither_lookup);
 *
 * What it does:
 * Applies the libpng quantisation transform to a row. RGB/RGBA rows at 8 bpp
 * are reduced to a palette index by looking up a packed RRRRRGGGGGBBBBB key
 * in `palette_lookup`; palette rows at 8 bpp are remapped through
 * `dither_lookup`. Updates color_type to palette and refreshes pixel_depth /
 * rowbytes when a colour row is dithered.
 */
extern "C" std::uint32_t png_do_dither(png_row_infop row_info, std::uint8_t* row,
                                       const std::uint8_t* palette_lookup,
                                       const std::uint8_t* dither_lookup);
