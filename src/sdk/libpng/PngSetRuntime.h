#pragma once

#include <cstddef>
#include <cstdint>

#include "libpng/PngStructLayout.h"
#include "libpng/PngWriteRuntime.h"

// ============================================================================
// libpng row_info partial layout (used by png_do_invert and other transforms)
// ============================================================================
//
// Evidence: FUN_009E2298.asm (png_do_invert) reads:
//   +0x04 = rowbytes  (png_uint_32)
//   +0x08 = color_type (png_byte)
//   +0x09 = bit_depth  (png_byte)
struct png_row_info
{
  std::uint32_t width;       // +0x00
  std::uint32_t rowbytes;    // +0x04
  std::uint8_t  color_type;  // +0x08
  std::uint8_t  bit_depth;   // +0x09
  std::uint8_t  channels;    // +0x0A
  std::uint8_t  pixel_depth; // +0x0B
};
static_assert(offsetof(png_row_info, width)       == 0x00, "png_row_info::width must be at +0x00");
static_assert(offsetof(png_row_info, rowbytes)    == 0x04, "png_row_info::rowbytes must be at +0x04");
static_assert(offsetof(png_row_info, color_type)  == 0x08, "png_row_info::color_type must be at +0x08");
static_assert(offsetof(png_row_info, bit_depth)   == 0x09, "png_row_info::bit_depth must be at +0x09");

#ifndef FA_LIBPNG_PNG_ROW_INFOP_DEFINED
#define FA_LIBPNG_PNG_ROW_INFOP_DEFINED
using png_row_infop = png_row_info*;
#endif

// ============================================================================
// png_info partial layout
// ============================================================================
// Minimal partial layout of the libpng 1.2.x png_info_struct, covering fields
// accessed by the recovered set-functions below.
//
// Binary evidence from png_set_sRGB, png_set_gAMA, png_set_gAMA_fixed,
// png_set_cHRM, png_set_cHRM_fixed:
//   +0x08: valid             (uint32_t, bitmask)
//   +0x28: gamma             (float)
//   +0x2C: srgb_intent       (uint8_t)
//   +0x80: x_white           (float)
//   +0x84: y_white           (float)
//   +0x88: x_red             (float)
//   +0x8C: y_red             (float)
//   +0x90: x_green           (float)
//   +0x94: y_green           (float)
//   +0x98: x_blue            (float)
//   +0x9C: y_blue            (float)
//   +0xFC: int_gamma         (int32_t)
//   +0x100: int_x_white      (int32_t)
//   +0x104: int_y_white      (int32_t)
//   +0x108: int_x_red        (int32_t)
//   +0x10C: int_y_red        (int32_t)
//   +0x110: int_x_green      (int32_t)
//   +0x114: int_y_green      (int32_t)
//   +0x118: int_x_blue       (int32_t)
//   +0x11C: int_y_blue       (int32_t)

struct png_info_struct
{
  std::uint8_t  pad_00_to_08[0x08];         // +0x00
  std::uint32_t valid;                       // +0x08
  std::uint8_t  pad_0C_to_28[0x1C];         // +0x0C
  float         gamma;                       // +0x28
  std::uint8_t  srgb_intent;                 // +0x2C
  std::uint8_t  pad_2D_to_80[0x53];         // +0x2D
  float         x_white;                     // +0x80
  float         y_white;                     // +0x84
  float         x_red;                       // +0x88
  float         y_red;                       // +0x8C
  float         x_green;                     // +0x90
  float         y_green;                     // +0x94
  float         x_blue;                      // +0x98
  float         y_blue;                      // +0x9C
  std::uint8_t  pad_A0_to_FC[0x5C];         // +0xA0
  std::int32_t  int_gamma;                   // +0xFC
  std::int32_t  int_x_white;                 // +0x100
  std::int32_t  int_y_white;                 // +0x104
  std::int32_t  int_x_red;                   // +0x108
  std::int32_t  int_y_red;                   // +0x10C
  std::int32_t  int_x_green;                 // +0x110
  std::int32_t  int_y_green;                 // +0x114
  std::int32_t  int_x_blue;                  // +0x118
  std::int32_t  int_y_blue;                  // +0x11C
};

using png_infop       = png_info_struct*;
using png_fixed_point = std::int32_t;

static_assert(offsetof(png_info_struct, valid)       == 0x08);
static_assert(offsetof(png_info_struct, gamma)       == 0x28);
static_assert(offsetof(png_info_struct, srgb_intent) == 0x2C);
static_assert(offsetof(png_info_struct, x_white)     == 0x80);
static_assert(offsetof(png_info_struct, y_white)     == 0x84);
static_assert(offsetof(png_info_struct, x_red)       == 0x88);
static_assert(offsetof(png_info_struct, y_red)       == 0x8C);
static_assert(offsetof(png_info_struct, x_green)     == 0x90);
static_assert(offsetof(png_info_struct, y_green)     == 0x94);
static_assert(offsetof(png_info_struct, x_blue)      == 0x98);
static_assert(offsetof(png_info_struct, y_blue)      == 0x9C);
static_assert(offsetof(png_info_struct, int_gamma)   == 0xFC);
static_assert(offsetof(png_info_struct, int_x_white) == 0x100);
static_assert(offsetof(png_info_struct, int_y_white) == 0x104);
static_assert(offsetof(png_info_struct, int_x_red)   == 0x108);
static_assert(offsetof(png_info_struct, int_y_red)   == 0x10C);
static_assert(offsetof(png_info_struct, int_x_green) == 0x110);
static_assert(offsetof(png_info_struct, int_y_green) == 0x114);
static_assert(offsetof(png_info_struct, int_x_blue)  == 0x118);
static_assert(offsetof(png_info_struct, int_y_blue)  == 0x11C);

// Validity bitmask flags used by png_info.valid:
constexpr std::uint32_t kPngInfoGamma = 0x0001;
constexpr std::uint32_t kPngInfoChrm  = 0x0004;
constexpr std::uint32_t kPngInfoSrgb  = 0x0800;

// Maximum gamma value (libpng 1.2.x: 21474.83).
constexpr double kPngGammaMaxValue = 21474.83;

// Fixed-point scale for gamma (100000).
constexpr double kPngGammaFixedScale = 100000.0;

// Fixed-point rounding offset.
constexpr double kPngFixedRound = 0.5;

// Maximum fixed-point chromaticity value (corresponds to 21474.83 * 100000 ~ INT_MAX).
constexpr double kPngChrmMaxFixed = 2147483647.0;

/**
 * Address: 0x009E966F (FUN_009E966F)
 *
 * IDA signature:
 * void __cdecl png_set_sRGB(int a1, int a2, char a3);
 *
 * What it does:
 * Sets the sRGB rendering intent on the info struct. Marks the sRGB
 * validity bit in info_ptr->valid.
 */
extern "C" void png_set_sRGB(png_structp png_ptr, png_infop info_ptr, int srgb_intent);

/**
 * Address: 0x009E9074 (FUN_009E9074)
 *
 * IDA signature:
 * void __cdecl png_set_gAMA(struct png_struct *a1, int a2, double a3);
 *
 * What it does:
 * Sets the image gamma on the info struct from a floating-point value.
 * Clamps to 21474.83 maximum. Stores both float and fixed-point (100000x)
 * representations. Warns if gamma is exactly zero.
 */
extern "C" void png_set_gAMA(png_structp png_ptr, png_infop info_ptr, double file_gamma);

/**
 * Address: 0x009E90EC (FUN_009E90EC)
 *
 * IDA signature:
 * void __cdecl png_set_gAMA_fixed(png_structp a1, int a2, int a3);
 *
 * What it does:
 * Sets the image gamma on the info struct from a fixed-point integer
 * (scaled by 100000). Clamps negative values to zero with a warning.
 * Stores both fixed-point and float (1/100000) representations.
 * Warns if gamma is zero.
 */
extern "C" void png_set_gAMA_fixed(png_structp png_ptr, png_infop info_ptr, png_fixed_point int_gamma);

/**
 * Address: 0x009E8C9D (FUN_009E8C9D)
 *
 * IDA signature:
 * void __cdecl png_set_cHRM(
 *   png_structp, png_infop, double, double, double, double,
 *   double, double, double, double);
 *
 * What it does:
 * Sets the cHRM (primary chromaticities and white point) on the info struct
 * from floating-point values. Validates that all values are non-negative and
 * within the 21474.83 maximum. Stores both float and fixed-point (100000x)
 * representations.
 */
extern "C" void png_set_cHRM(
  png_structp png_ptr, png_infop info_ptr,
  double white_x, double white_y,
  double red_x,   double red_y,
  double green_x, double green_y,
  double blue_x,  double blue_y
);

/**
 * Address: 0x009E8EC0 (FUN_009E8EC0)
 *
 * IDA signature:
 * void __cdecl png_set_cHRM_fixed(
 *   png_structp, png_infop, png_fixed_point, png_fixed_point,
 *   png_fixed_point, png_fixed_point, png_fixed_point, png_fixed_point,
 *   png_fixed_point, png_fixed_point);
 *
 * What it does:
 * Sets the cHRM on the info struct from fixed-point integer values
 * (scaled by 100000). Validates all are non-negative and within INT_MAX.
 * Stores both fixed-point and float (1/100000) representations.
 */
extern "C" void png_set_cHRM_fixed(
  png_structp png_ptr, png_infop info_ptr,
  png_fixed_point white_x, png_fixed_point white_y,
  png_fixed_point red_x,   png_fixed_point red_y,
  png_fixed_point green_x, png_fixed_point green_y,
  png_fixed_point blue_x,  png_fixed_point blue_y
);

/**
 * Address: 0x009E968D (FUN_009E968D)
 *
 * IDA signature:
 * void __cdecl png_set_sRGB_gAMA_and_cHRM(png_structp, png_infop, char);
 *
 * What it does:
 * Convenience function that sets sRGB intent and then applies the standard
 * sRGB gamma (0.45455) and cHRM chromaticity values (D65 white point,
 * sRGB primaries) in both floating-point and fixed-point forms.
 */
extern "C" void png_set_sRGB_gAMA_and_cHRM(
  png_structp png_ptr, png_infop info_ptr, int srgb_intent
);

// ============================================================================
// Leaf transformation set/do helpers (recovered from the libpng public API)
// ============================================================================

/**
 * Address: 0x009E21A6 (FUN_009E21A6)
 * Mangled: png_set_bgr
 *
 * IDA signature:
 * void __cdecl png_set_bgr(png_structp png_ptr);
 *
 * What it does:
 * Sets the PNG_BGR transformation flag on the read/write struct, so that
 * subsequent row processing swaps R and B during transfer.
 */
extern "C" void png_set_bgr(png_structp png_ptr);

/**
 * Address: 0x009E21AF (FUN_009E21AF)
 * Mangled: png_set_swap
 *
 * IDA signature:
 * void __cdecl png_set_swap(png_structp png_ptr);
 *
 * What it does:
 * Enables 16-bit byte swap on row data. No-op when bit_depth != 16.
 */
extern "C" void png_set_swap(png_structp png_ptr);

/**
 * Address: 0x009E21C1 (FUN_009E21C1)
 * Mangled: png_set_packing
 *
 * IDA signature:
 * void __cdecl png_set_packing(png_structp png_ptr);
 *
 * What it does:
 * Enables expansion of sub-byte packed pixels (1/2/4 bit) into separate
 * bytes during read. No-op when bit_depth >= 8. Updates usr_bit_depth to 8.
 */
extern "C" void png_set_packing(png_structp png_ptr);

/**
 * Address: 0x009E21DA (FUN_009E21DA)
 * Mangled: png_set_packswap
 *
 * IDA signature:
 * void __cdecl png_set_packswap(png_structp png_ptr);
 *
 * What it does:
 * Enables sub-byte pack-swap on read (reverse bit order within bytes).
 * No-op when bit_depth >= 8.
 */
extern "C" void png_set_packswap(png_structp png_ptr);

/**
 * Address: 0x009E21EF (FUN_009E21EF)
 * Mangled: png_set_shift
 *
 * IDA signature:
 * void __cdecl png_set_shift(png_structp png_ptr, const png_color_8 *true_bits);
 *
 * What it does:
 * Enables the PNG_SHIFT transformation and copies the user-supplied
 * 5-byte png_color_8 sBIT structure into png_struct.shift.
 */
extern "C" void png_set_shift(png_structp png_ptr, const std::uint8_t* true_bits);

/**
 * Address: 0x009E2208 (FUN_009E2208)
 * Mangled: png_set_interlace_handling
 *
 * IDA signature:
 * int __cdecl png_set_interlace_handling(png_structp png_ptr);
 *
 * What it does:
 * Enables Adam7 interlace handling on read. Returns 1 for non-interlaced
 * images (no extra passes), or the number of passes (7) for interlaced
 * images, after enabling PNG_INTERLACE on the transformations field.
 */
extern "C" int png_set_interlace_handling(png_structp png_ptr);

/**
 * Address: 0x009E2221 (FUN_009E2221)
 * Mangled: png_set_filler
 *
 * IDA signature:
 * void __cdecl png_set_filler(png_structp png_ptr, png_uint_32 filler, int filler_loc);
 *
 * What it does:
 * Enables RGB to RGBA / G to GA filler insertion at read time. Stores the
 * filler byte at +0x12E and orients the filler bit in the flags field. For
 * RGB sources at >= 8 bit depth, sets usr_channels = 4; for grayscale-with-
 * alpha-removed sources, sets usr_channels = 2.
 */
extern "C" void png_set_filler(png_structp png_ptr, std::uint32_t filler, int filler_loc);

/**
 * Address: 0x009E2277 (FUN_009E2277)
 * Mangled: png_set_swap_alpha
 *
 * IDA signature:
 * void __cdecl png_set_swap_alpha(png_structp png_ptr);
 *
 * What it does:
 * Enables alpha channel swapping (RGBA <-> ARGB) on read.
 */
extern "C" void png_set_swap_alpha(png_structp png_ptr);

/**
 * Address: 0x009E2283 (FUN_009E2283)
 * Mangled: png_set_invert_alpha
 *
 * IDA signature:
 * void __cdecl png_set_invert_alpha(png_structp png_ptr);
 *
 * What it does:
 * Enables alpha channel inversion on read.
 */
extern "C" void png_set_invert_alpha(png_structp png_ptr);

/**
 * Address: 0x009E228F (FUN_009E228F)
 * Mangled: png_set_invert_mono
 *
 * IDA signature:
 * void __cdecl png_set_invert_mono(png_structp png_ptr);
 *
 * What it does:
 * Enables monochrome inversion on read (1 -> 0, 0 -> 1).
 */
extern "C" void png_set_invert_mono(png_structp png_ptr);

/**
 * Address: 0x009E2298 (FUN_009E2298)
 * Mangled: png_do_invert
 *
 * IDA signature:
 * void __cdecl png_do_invert(png_row_infop row_info, png_bytep row);
 *
 * What it does:
 * Inverts the active luminance/alpha bytes of a single row in place. For
 * grayscale rows (color_type == 0) every byte is bitwise-NOT'd. For 8-bit
 * gray+alpha rows (color_type == 4, bit_depth == 8) every other byte (the
 * gray sample) is inverted, leaving the alpha bytes alone. For 16-bit
 * gray+alpha rows the two-byte sample pair is inverted, again preserving
 * the alpha bytes.
 */
extern "C" void png_do_invert(png_row_infop row_info, std::uint8_t* row);

// PNG transformation flag bits set by the png_set_* helpers below.
constexpr std::uint32_t kPngTransform16To8  = 0x00000400;  // PNG_16_TO_8
constexpr std::uint32_t kPngTransformExpand = 0x00001000;  // PNG_EXPAND

// png_struct::transformations field offset (libpng 1.2.x).
// Evidence: png_set_strip_16 (0x009E3078) and png_set_expand (0x009E381A):
//   or dword ptr [a1+70h], imm
constexpr std::size_t kPngStructTransformationsOffset = 0x70;

/**
 * Address: 0x009E3078 (FUN_009E3078)
 *
 * IDA signature:
 * png_structp __cdecl png_set_strip_16(png_structp png_ptr);
 *
 * What it does:
 * Sets the PNG_16_TO_8 transformation bit on the png_struct so that the read
 * pipeline calls png_do_chop on every row, downconverting 16-bit samples to
 * 8-bit. Returns the unmodified png_ptr (libpng 1.2.x signature requires it).
 */
extern "C" png_structp png_set_strip_16(png_structp png_ptr);

/**
 * Address: 0x009E381A (FUN_009E381A)
 *
 * IDA signature:
 * png_structp __cdecl png_set_expand(png_structp png_ptr);
 *
 * What it does:
 * Sets the PNG_EXPAND transformation bit on the png_struct so that the read
 * pipeline expands palette/sub-byte rows to 8-bit RGB or RGBA via
 * png_do_expand_palette / png_do_expand. Returns the unmodified png_ptr.
 */
extern "C" png_structp png_set_expand(png_structp png_ptr);
