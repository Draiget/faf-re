// libpng set-function runtime recovery.
// Source: embedded wxWindows 2.4.2 libpng (dependencies/wxWindows-2.4.2/src/png/pngset.c).
// The ForgedAlliance.exe binary links libpng statically as png.lib; these recovered
// functions match the binary at their given addresses.

#include "libpng/PngSetRuntime.h"

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
extern "C" void png_set_sRGB(png_structp png_ptr, png_infop info_ptr, int srgb_intent)
{
  if (!png_ptr) return;
  if (!info_ptr) return;

  info_ptr->valid |= kPngInfoSrgb;
  info_ptr->srgb_intent = static_cast<std::uint8_t>(srgb_intent);
}

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
extern "C" void png_set_gAMA(png_structp png_ptr, png_infop info_ptr, double file_gamma)
{
  if (!png_ptr) return;
  if (!info_ptr) return;

  double gamma_val;
  if (file_gamma > kPngGammaMaxValue) {
    png_warning(png_ptr, "Limiting gamma to 21474.83");
    gamma_val = kPngGammaMaxValue;
  } else {
    gamma_val = file_gamma;
  }

  info_ptr->gamma = static_cast<float>(gamma_val);
  info_ptr->valid |= kPngInfoGamma;
  info_ptr->int_gamma = static_cast<std::int32_t>(kPngGammaFixedScale * gamma_val + kPngFixedRound);

  if (gamma_val == 0.0) {
    png_warning(png_ptr, "Setting gamma=0");
  }
}

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
extern "C" void png_set_gAMA_fixed(png_structp png_ptr, png_infop info_ptr, png_fixed_point int_gamma)
{
  if (!png_ptr) return;
  if (!info_ptr) return;

  png_fixed_point gamma_val;
  if (int_gamma < 0) {
    png_warning(png_ptr, "Setting negative gamma to zero");
    gamma_val = 0;
  } else {
    gamma_val = int_gamma;
  }

  info_ptr->valid |= kPngInfoGamma;
  info_ptr->int_gamma = gamma_val;
  info_ptr->gamma = static_cast<float>(static_cast<double>(gamma_val) / kPngGammaFixedScale);

  if (gamma_val == 0) {
    png_warning(png_ptr, "Setting gamma=0");
  }
}

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
  double blue_x,  double blue_y)
{
  if (!png_ptr) return;
  if (!info_ptr) return;

  if (white_x < 0.0 || white_y < 0.0 ||
      red_x   < 0.0 || red_y   < 0.0 ||
      green_x < 0.0 || green_y < 0.0 ||
      blue_x  < 0.0 || blue_y  < 0.0)
  {
    png_warning(png_ptr, "Ignoring attempt to set negative chromaticity value");
    return;
  }

  if (white_x > kPngGammaMaxValue || white_y > kPngGammaMaxValue ||
      red_x   > kPngGammaMaxValue || red_y   > kPngGammaMaxValue ||
      green_x > kPngGammaMaxValue || green_y > kPngGammaMaxValue ||
      blue_x  > kPngGammaMaxValue || blue_y  > kPngGammaMaxValue)
  {
    png_warning(png_ptr, "Ignoring attempt to set chromaticity value exceeding 21474.83");
    return;
  }

  info_ptr->x_white = static_cast<float>(white_x);
  info_ptr->y_white = static_cast<float>(white_y);
  info_ptr->x_red   = static_cast<float>(red_x);
  info_ptr->y_red   = static_cast<float>(red_y);
  info_ptr->x_green = static_cast<float>(green_x);
  info_ptr->y_green = static_cast<float>(green_y);
  info_ptr->x_blue  = static_cast<float>(blue_x);
  info_ptr->y_blue  = static_cast<float>(blue_y);

  info_ptr->int_x_white = static_cast<std::int32_t>(white_x * kPngGammaFixedScale + kPngFixedRound);
  info_ptr->int_y_white = static_cast<std::int32_t>(white_y * kPngGammaFixedScale + kPngFixedRound);
  info_ptr->int_x_red   = static_cast<std::int32_t>(red_x   * kPngGammaFixedScale + kPngFixedRound);
  info_ptr->int_y_red   = static_cast<std::int32_t>(red_y   * kPngGammaFixedScale + kPngFixedRound);
  info_ptr->int_x_green = static_cast<std::int32_t>(green_x * kPngGammaFixedScale + kPngFixedRound);
  info_ptr->int_y_green = static_cast<std::int32_t>(green_y * kPngGammaFixedScale + kPngFixedRound);
  info_ptr->int_x_blue  = static_cast<std::int32_t>(blue_x  * kPngGammaFixedScale + kPngFixedRound);
  info_ptr->valid |= kPngInfoChrm;
  info_ptr->int_y_blue  = static_cast<std::int32_t>(blue_y  * kPngGammaFixedScale + kPngFixedRound);
}

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
  png_fixed_point blue_x,  png_fixed_point blue_y)
{
  if (!png_ptr) return;
  if (!info_ptr) return;

  if (white_x < 0 || white_y < 0 ||
      red_x   < 0 || red_y   < 0 ||
      green_x < 0 || green_y < 0 ||
      blue_x  < 0 || blue_y  < 0)
  {
    png_warning(png_ptr, "Ignoring attempt to set negative chromaticity value");
    return;
  }

  auto dwhite_x = static_cast<double>(white_x);
  auto dwhite_y = static_cast<double>(white_y);
  auto dred_x   = static_cast<double>(red_x);
  auto dred_y   = static_cast<double>(red_y);
  auto dgreen_x = static_cast<double>(green_x);
  auto dgreen_y = static_cast<double>(green_y);
  auto dblue_x  = static_cast<double>(blue_x);
  auto dblue_y  = static_cast<double>(blue_y);

  if (dwhite_x > kPngChrmMaxFixed || dwhite_y > kPngChrmMaxFixed ||
      dred_x   > kPngChrmMaxFixed || dred_y   > kPngChrmMaxFixed ||
      dgreen_x > kPngChrmMaxFixed || dgreen_y > kPngChrmMaxFixed ||
      dblue_x  > kPngChrmMaxFixed || dblue_y  > kPngChrmMaxFixed)
  {
    png_warning(png_ptr, "Ignoring attempt to set chromaticity value exceeding 21474.83");
    return;
  }

  info_ptr->valid |= kPngInfoChrm;
  info_ptr->int_x_white = white_x;
  info_ptr->int_y_white = white_y;
  info_ptr->int_x_red   = red_x;
  info_ptr->int_y_red   = red_y;
  info_ptr->int_x_green = green_x;
  info_ptr->int_y_green = green_y;
  info_ptr->int_x_blue  = blue_x;
  info_ptr->int_y_blue  = blue_y;

  info_ptr->x_white = static_cast<float>(dwhite_x / kPngGammaFixedScale);
  info_ptr->y_white = static_cast<float>(dwhite_y / kPngGammaFixedScale);
  info_ptr->x_red   = static_cast<float>(dred_x   / kPngGammaFixedScale);
  info_ptr->y_red   = static_cast<float>(dred_y   / kPngGammaFixedScale);
  info_ptr->x_green = static_cast<float>(dgreen_x / kPngGammaFixedScale);
  info_ptr->y_green = static_cast<float>(dgreen_y / kPngGammaFixedScale);
  info_ptr->x_blue  = static_cast<float>(dblue_x  / kPngGammaFixedScale);
  info_ptr->y_blue  = static_cast<float>(dblue_y  / kPngGammaFixedScale);
}

// ============================================================================
// Standard sRGB chromaticity constants (IEC 61966-2-1)
// ============================================================================
static constexpr double kSrgbGamma = 0.45455;

static constexpr png_fixed_point kSrgbGammaFixed = 45455;

static constexpr png_fixed_point kSrgbWhiteX = 31270;
static constexpr png_fixed_point kSrgbWhiteY = 32900;
static constexpr png_fixed_point kSrgbRedX   = 64000;
static constexpr png_fixed_point kSrgbRedY   = 33000;
static constexpr png_fixed_point kSrgbGreenX = 30000;
static constexpr png_fixed_point kSrgbGreenY = 60000;
static constexpr png_fixed_point kSrgbBlueX  = 15000;
static constexpr png_fixed_point kSrgbBlueY  =  6000;

static constexpr double kSrgbWhiteXf = 0.3127;
static constexpr double kSrgbWhiteYf = 0.329;
static constexpr double kSrgbRedXf   = 0.64;
static constexpr double kSrgbRedYf   = 0.33;
static constexpr double kSrgbGreenXf = 0.30;
static constexpr double kSrgbGreenYf = 0.60;
static constexpr double kSrgbBlueXf  = 0.15;
static constexpr double kSrgbBlueYf  = 0.06;

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
  png_structp png_ptr, png_infop info_ptr, int srgb_intent)
{
  if (!png_ptr) return;
  if (!info_ptr) return;

  png_set_sRGB(png_ptr, info_ptr, srgb_intent);
  png_set_gAMA(png_ptr, info_ptr, kSrgbGamma);
  png_set_gAMA_fixed(png_ptr, info_ptr, kSrgbGammaFixed);
  png_set_cHRM_fixed(png_ptr, info_ptr,
    kSrgbWhiteX, kSrgbWhiteY,
    kSrgbRedX,   kSrgbRedY,
    kSrgbGreenX, kSrgbGreenY,
    kSrgbBlueX,  kSrgbBlueY);
  png_set_cHRM(png_ptr, info_ptr,
    kSrgbWhiteXf, kSrgbWhiteYf,
    kSrgbRedXf,   kSrgbRedYf,
    kSrgbGreenXf, kSrgbGreenYf,
    kSrgbBlueXf,  kSrgbBlueYf);
}

// ============================================================================
// Leaf transformation set/do helpers
// ============================================================================

/**
 * Address: 0x009E21A6 (FUN_009E21A6)
 * Mangled: png_set_bgr
 */
extern "C" void png_set_bgr(png_structp png_ptr)
{
  using namespace libpng_layout;
  Transformations(png_ptr) |= kPngBgr;
}

/**
 * Address: 0x009E21AF (FUN_009E21AF)
 * Mangled: png_set_swap
 */
extern "C" void png_set_swap(png_structp png_ptr)
{
  using namespace libpng_layout;
  if (BitDepth(png_ptr) == 16) {
    Transformations(png_ptr) |= kPngSwapBytes;
  }
}

/**
 * Address: 0x009E21C1 (FUN_009E21C1)
 * Mangled: png_set_packing
 */
extern "C" void png_set_packing(png_structp png_ptr)
{
  using namespace libpng_layout;
  if (BitDepth(png_ptr) < 8) {
    Transformations(png_ptr) |= kPngPack;
    UsrBitDepth(png_ptr) = 8;
  }
}

/**
 * Address: 0x009E21DA (FUN_009E21DA)
 * Mangled: png_set_packswap
 */
extern "C" void png_set_packswap(png_structp png_ptr)
{
  using namespace libpng_layout;
  if (BitDepth(png_ptr) < 8) {
    Transformations(png_ptr) |= kPngPackSwap;
  }
}

/**
 * Address: 0x009E21EF (FUN_009E21EF)
 * Mangled: png_set_shift
 *
 * Copies a 5-byte png_color_8 (red, green, blue, gray, alpha) into the
 * libpng struct's shift field at offset 0x181 in two writes (a dword and
 * a trailing byte) — matching the binary's 4-byte + 1-byte transfer shape.
 */
extern "C" void png_set_shift(png_structp png_ptr, const std::uint8_t* true_bits)
{
  using namespace libpng_layout;
  Transformations(png_ptr) |= kPngShift;

  auto* const shift_dst = RawBase(png_ptr) + kOffShift;
  // Binary moves 4 bytes (rgb_g) then 1 byte (alpha).
  *reinterpret_cast<std::uint32_t*>(shift_dst) =
    *reinterpret_cast<const std::uint32_t*>(true_bits);
  shift_dst[4] = true_bits[4];
}

/**
 * Address: 0x009E2208 (FUN_009E2208)
 * Mangled: png_set_interlace_handling
 */
extern "C" int png_set_interlace_handling(png_structp png_ptr)
{
  using namespace libpng_layout;
  if (Interlaced(png_ptr) == 0) {
    return 1;
  }
  Transformations(png_ptr) |= kPngInterlace;
  return 7;
}

/**
 * Address: 0x009E2221 (FUN_009E2221)
 * Mangled: png_set_filler
 *
 * Note: the binary stores the filler value as a 16-bit write at +0x12E and
 * uses bit 0x80 in the libpng flags-equivalent field at +0x6C+0x40 (offset
 * +0x6C is flags, but the FILLER_BEFORE bit observed here is in the dword
 * at offset 108 = +0x6C, masked with 0x80). Evidence: FUN_009E2221.asm.
 */
extern "C" void png_set_filler(png_structp png_ptr, std::uint32_t filler, int filler_loc)
{
  using namespace libpng_layout;
  Transformations(png_ptr) |= kPngFiller;
  Filler(png_ptr) = static_cast<std::uint16_t>(filler);

  if (filler_loc == kPngFillerBefore) {
    Flags(png_ptr) |= kPngFlagFillerBefore;
  } else {
    Flags(png_ptr) &= ~kPngFlagFillerBefore;
  }

  const std::uint8_t color_type = ColorType(png_ptr);
  if (color_type == kColorTypeRgb) {
    UsrChannels(png_ptr) = 4;
  }
  if (color_type == kColorTypeGray && BitDepth(png_ptr) >= 8) {
    UsrChannels(png_ptr) = 2;
  }
}

/**
 * Address: 0x009E2277 (FUN_009E2277)
 * Mangled: png_set_swap_alpha
 */
extern "C" void png_set_swap_alpha(png_structp png_ptr)
{
  using namespace libpng_layout;
  Transformations(png_ptr) |= kPngSwapAlpha;
}

/**
 * Address: 0x009E2283 (FUN_009E2283)
 * Mangled: png_set_invert_alpha
 */
extern "C" void png_set_invert_alpha(png_structp png_ptr)
{
  using namespace libpng_layout;
  Transformations(png_ptr) |= kPngInvertAlpha;
}

/**
 * Address: 0x009E228F (FUN_009E228F)
 * Mangled: png_set_invert_mono
 */
extern "C" void png_set_invert_mono(png_structp png_ptr)
{
  using namespace libpng_layout;
  Transformations(png_ptr) |= kPngInvertMono;
}

/**
 * Address: 0x009E2298 (FUN_009E2298)
 * Mangled: png_do_invert
 */
extern "C" void png_do_invert(png_row_infop row_info, std::uint8_t* row)
{
  const std::uint8_t color_type = row_info->color_type;
  if (color_type == 0) {
    // Grayscale: invert every byte across the row.
    std::uint32_t remaining = row_info->rowbytes;
    auto* cursor = row;
    while (remaining != 0) {
      *cursor = static_cast<std::uint8_t>(~*cursor);
      ++cursor;
      --remaining;
    }
    return;
  }

  if (color_type != 4) {
    // Anything other than gray-with-alpha is left untouched.
    return;
  }

  if (row_info->bit_depth == 8) {
    // 8-bit gray+alpha: invert every other byte (the gray sample).
    const std::uint32_t rowbytes = row_info->rowbytes;
    if (rowbytes == 0) {
      return;
    }
    std::uint32_t pairs = ((rowbytes - 1) >> 1) + 1;
    auto* cursor = row;
    while (pairs != 0) {
      *cursor = static_cast<std::uint8_t>(~*cursor);
      cursor += 2;
      --pairs;
    }
    return;
  }

  if (row_info->bit_depth == 16) {
    // 16-bit gray+alpha: invert the two-byte sample pair, leaving alpha alone.
    const std::uint32_t rowbytes = row_info->rowbytes;
    if (rowbytes == 0) {
      return;
    }
    std::uint32_t quads = ((rowbytes - 1) >> 2) + 1;
    auto* cursor = row + 1;
    while (quads != 0) {
      *(cursor - 1) = static_cast<std::uint8_t>(~*(cursor - 1));
      *cursor       = static_cast<std::uint8_t>(~*cursor);
      cursor += 4;
      --quads;
    }
  }
}

namespace {

// Typed accessor for png_struct::transformations (uint32_t at +0x70).
inline std::uint32_t& Transformations(png_structp png_ptr) noexcept
{
  auto* base = reinterpret_cast<std::uint8_t*>(png_ptr);
  return *reinterpret_cast<std::uint32_t*>(base + kPngStructTransformationsOffset);
}

} // namespace

/**
 * Address: 0x009E3078 (FUN_009E3078)
 *
 * IDA signature:
 * png_structp __cdecl png_set_strip_16(png_structp png_ptr);
 *
 * What it does:
 * Sets the PNG_16_TO_8 transformation bit on the png_struct so that the read
 * pipeline calls png_do_chop on every row, downconverting 16-bit samples to
 * 8-bit. Returns the unmodified png_ptr.
 */
extern "C" png_structp png_set_strip_16(png_structp png_ptr)
{
  Transformations(png_ptr) |= kPngTransform16To8;
  return png_ptr;
}

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
extern "C" png_structp png_set_expand(png_structp png_ptr)
{
  Transformations(png_ptr) |= kPngTransformExpand;
  return png_ptr;
}
