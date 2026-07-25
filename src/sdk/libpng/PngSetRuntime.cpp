// libpng set-function runtime recovery.
// Source: embedded wxWindows 2.4.2 libpng (dependencies/wxWindows-2.4.2/src/png/pngset.c).
// The ForgedAlliance.exe binary links libpng statically as png.lib; these recovered
// functions match the binary at their given addresses.

#include "libpng/PngSetRuntime.h"

#include <cstring>

extern "C" {
void  png_free_data(png_structp png_ptr, png_infop info_ptr, std::uint32_t mask, int num);
void* png_zalloc(png_structp png_ptr, std::uint32_t items, std::uint32_t size);
void* png_malloc(png_structp png_ptr, std::uint32_t size);
void* png_malloc_warn(png_structp png_ptr, std::uint32_t size);
}

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
 * Address: 0x009E9647 (FUN_009E9647)
 * Mangled: png_set_sBIT
 *
 * IDA signature:
 * void __cdecl png_set_sBIT(png_structp png_ptr, png_infop info_ptr, png_color_8p sig_bit);
 *
 * Stores the significant-bit depths: copies the 5-byte png_color_8 (red, green,
 * blue, gray, alpha) into info_ptr->sig_bit (0x44) and marks PNG_INFO_sBIT valid.
 */
extern "C" void png_set_sBIT(png_structp png_ptr, png_infop info_ptr, const std::uint8_t* sig_bit)
{
  if (png_ptr == nullptr || info_ptr == nullptr) {
    return;
  }
  std::memcpy(info_ptr->sig_bit, sig_bit, 5);
  info_ptr->valid |= kPngInfoSbit;
}

/**
 * Address: 0x009E9594 (FUN_009E9594)
 * Mangled: png_set_pHYs
 *
 * Stores the physical pixel dimensions (resolution) into the info struct and
 * marks PNG_INFO_pHYs valid.
 */
extern "C" void png_set_pHYs(png_structp png_ptr, png_infop info_ptr,
                             std::uint32_t res_x, std::uint32_t res_y, int unit_type)
{
  if (png_ptr == nullptr || info_ptr == nullptr) {
    return;
  }
  info_ptr->x_pixels_per_unit = res_x;
  info_ptr->y_pixels_per_unit = res_y;
  info_ptr->phys_unit_type    = static_cast<std::uint8_t>(unit_type);
  info_ptr->valid |= kPngInfoPhys;
}

/**
 * Address: 0x009E93D7 (FUN_009E93D7)
 * Mangled: png_set_oFFs
 *
 * Stores the image offset (position) into the info struct and marks
 * PNG_INFO_oFFs valid.
 */
extern "C" void png_set_oFFs(png_structp png_ptr, png_infop info_ptr,
                             std::int32_t offset_x, std::int32_t offset_y, int unit_type)
{
  if (png_ptr == nullptr || info_ptr == nullptr) {
    return;
  }
  info_ptr->x_offset          = offset_x;
  info_ptr->y_offset          = offset_y;
  info_ptr->offset_unit_type  = static_cast<std::uint8_t>(unit_type);
  info_ptr->valid |= kPngInfoOffs;
}

/**
 * Address: 0x009E99B7 (FUN_009E99B7)
 * Mangled: png_set_tIME
 *
 * Stores the image modification time into info_ptr->mod_time and marks
 * PNG_INFO_tIME valid — but only when tIME has not already been written
 * (png_ptr->mode & PNG_WROTE_tIME).
 */
extern "C" void png_set_tIME(png_structp png_ptr, png_infop info_ptr, const std::uint8_t* mod_time)
{
  using namespace libpng_layout;
  if (png_ptr == nullptr || info_ptr == nullptr || (Mode(png_ptr) & kPngWroteTime) != 0) {
    return;
  }
  std::memcpy(info_ptr->mod_time, mod_time, sizeof(info_ptr->mod_time));
  info_ptr->valid |= kPngInfoTime;
}

/**
 * Address: 0x009E8C75 (FUN_009E8C75)
 * Mangled: png_set_bKGD
 *
 * Copies the 10-byte png_color_16 background colour into info_ptr->background
 * (0x5A) and marks PNG_INFO_bKGD valid.
 */
extern "C" void png_set_bKGD(png_structp png_ptr, png_infop info_ptr, const std::uint8_t* background)
{
  if (png_ptr == nullptr || info_ptr == nullptr) {
    return;
  }
  std::memcpy(info_ptr->background, background, sizeof(info_ptr->background));
  info_ptr->valid |= kPngInfoBkgd;
}

/**
 * Address: 0x009E91F2 (FUN_009E91F2)
 * Mangled: png_set_IHDR
 *
 * Validates the IHDR fields (raising png_error on any invalid combination) and
 * records the image geometry into the info struct, computing channels,
 * pixel_depth and rowbytes. The MNG filter-method extension (filter 64 on RGB)
 * is permitted only when mng_features_permitted allows it; otherwise a non-zero
 * filter method is rejected.
 */
extern "C" void png_set_IHDR(png_structp png_ptr, png_infop info_ptr,
                             std::uint32_t width, std::uint32_t height,
                             int bit_depth, int color_type, int interlace_type,
                             int compression_type, int filter_type)
{
  using namespace libpng_layout;
  if (png_ptr == nullptr || info_ptr == nullptr) {
    return;
  }

  if (width == 0 || height == 0) {
    png_error(png_ptr, "Image width or height is zero in IHDR");
  }
  if (width > 0x7FFFFFFFu || height > 0x7FFFFFFFu) {
    png_error(png_ptr, "Invalid image size in IHDR");
  }
  if (bit_depth != 1 && bit_depth != 2 && bit_depth != 4 && bit_depth != 8 && bit_depth != 16) {
    png_error(png_ptr, "Invalid bit depth in IHDR");
  }
  if (color_type < 0 || color_type == 1 || color_type == 5 || color_type > 6) {
    png_error(png_ptr, "Invalid color type in IHDR");
  }
  if ((color_type == 3 && bit_depth > 8) ||
      ((color_type == 2 || color_type == 4 || color_type == 6) && bit_depth < 8)) {
    png_error(png_ptr, "Invalid color type/bit depth combination in IHDR");
  }
  if (interlace_type >= 2) {
    png_error(png_ptr, "Unknown interlace method in IHDR");
  }
  if (compression_type != 0) {
    png_error(png_ptr, "Unknown compression method in IHDR");
  }

  const std::uint32_t mng = Field<std::uint32_t>(png_ptr, kOffMngFeaturesPermitted);
  if ((Mode(png_ptr) & 0x1000u) != 0 && mng != 0) {
    png_warning(png_ptr, "MNG features are not allowed in a PNG datastream\n");
  }
  if (filter_type != 0) {
    if ((mng & 4u) == 0 || filter_type != 64 || (Mode(png_ptr) & 0x1000u) != 0 ||
        (color_type != 2 && color_type != 6)) {
      png_error(png_ptr, "Unknown filter method in IHDR");
    }
    if ((Mode(png_ptr) & 0x1000u) != 0) {
      png_warning(png_ptr, "Invalid filter method in IHDR");
    }
  }

  info_ptr->height           = height;
  info_ptr->compression_type = static_cast<std::uint8_t>(compression_type);
  info_ptr->filter_type      = static_cast<std::uint8_t>(filter_type);
  info_ptr->width            = width;
  info_ptr->bit_depth        = static_cast<std::uint8_t>(bit_depth);
  info_ptr->color_type       = static_cast<std::uint8_t>(color_type);
  info_ptr->interlace_type   = static_cast<std::uint8_t>(interlace_type);

  if (color_type == 3 || (color_type & 2) == 0) {
    info_ptr->channels = 1;
  } else {
    info_ptr->channels = 3;
  }
  if ((color_type & 4) != 0) {
    ++info_ptr->channels;
  }
  info_ptr->pixel_depth = static_cast<std::uint8_t>(bit_depth * info_ptr->channels);

  if (width <= 0x7FFFFFFFu / ((info_ptr->pixel_depth + 7u) >> 3) - 64u) {
    info_ptr->rowbytes = (width * info_ptr->pixel_depth + 7u) >> 3;
  } else {
    png_warning(png_ptr, "Width too large to process image data; rowbytes will overflow.");
    info_ptr->rowbytes = 0;
  }
}

/**
 * Address: 0x009E95BF (FUN_009E95BF)
 * Mangled: png_set_PLTE
 *
 * Installs the palette: frees any previously-owned palette, allocates a fresh
 * 256-entry (768-byte) buffer via png_zalloc, copies the supplied entries in,
 * points both png_ptr->palette and info_ptr->palette at it, records the count,
 * and marks PNG_INFO_PLTE valid + PNG_FREE_PLTE owned.
 */
extern "C" void png_set_PLTE(png_structp png_ptr, png_infop info_ptr,
                             const std::uint8_t* palette, int num_palette)
{
  using namespace libpng_layout;
  if (png_ptr == nullptr || info_ptr == nullptr) {
    return;
  }

  png_free_data(png_ptr, info_ptr, 0x1000u, 0);  // PNG_FREE_PLTE

  auto* const pal = static_cast<std::uint8_t*>(png_zalloc(png_ptr, 256u, 3u));
  Field<std::uint8_t*>(png_ptr, kOffPalette) = pal;
  if (pal == nullptr) {
    png_error(png_ptr, "Unable to malloc palette");
  }
  std::memcpy(pal, palette, 3u * static_cast<std::uint32_t>(num_palette));

  info_ptr->palette = pal;
  Field<std::uint16_t>(png_ptr, kOffNumPalette) = static_cast<std::uint16_t>(num_palette);
  info_ptr->free_me |= 0x1000u;   // PNG_FREE_PLTE
  info_ptr->valid   |= 0x0008u;   // PNG_INFO_PLTE
  info_ptr->num_palette = static_cast<std::uint16_t>(num_palette);
}

/**
 * Address: 0x009E99EB (FUN_009E99EB)
 * Mangled: png_set_tRNS
 *
 * Installs transparency: for a palette image, frees any prior tRNS array,
 * allocates a fresh 256-byte alpha buffer, copies the entries in, and points
 * png_ptr->trans + info->trans at it (marking PNG_FREE_TRNS). A non-palette
 * transparency value (png_color_16) is copied into info->trans_values. Marks
 * PNG_INFO_tRNS valid and records the count.
 */
extern "C" void png_set_tRNS(png_structp png_ptr, png_infop info_ptr,
                             const std::uint8_t* trans, int num_trans,
                             const std::uint8_t* trans_values)
{
  using namespace libpng_layout;
  if (png_ptr == nullptr || info_ptr == nullptr) {
    return;
  }

  if (trans != nullptr) {
    png_free_data(png_ptr, info_ptr, 0x2000u, 0);  // PNG_FREE_TRNS
    auto* const t = static_cast<std::uint8_t*>(png_malloc(png_ptr, 0x100u));
    info_ptr->trans = t;
    Field<std::uint8_t*>(png_ptr, kOffTrans) = t;
    std::memcpy(info_ptr->trans, trans, static_cast<std::uint32_t>(num_trans));
    info_ptr->free_me |= 0x2000u;  // PNG_FREE_TRNS
  }

  if (trans_values != nullptr) {
    std::memcpy(info_ptr->trans_values, trans_values, sizeof(info_ptr->trans_values));
    if (num_trans == 0) {
      num_trans = 1;
    }
  }

  info_ptr->valid |= 0x0010u;  // PNG_INFO_tRNS
  info_ptr->num_trans = static_cast<std::uint16_t>(num_trans);
}

/**
 * Address: 0x009E9162 (FUN_009E9162)
 * Mangled: png_set_hIST
 *
 * Installs the palette histogram: frees any prior hIST, allocates a fresh
 * 512-byte (256-entry) buffer, copies num_palette entries in, and points
 * png_ptr->hist + info->hist at it (marking PNG_INFO_hIST valid + PNG_FREE_HIST
 * owned). No-ops with a warning when the palette is empty or the allocation
 * fails.
 */
extern "C" void png_set_hIST(png_structp png_ptr, png_infop info_ptr, const std::uint16_t* hist)
{
  using namespace libpng_layout;
  if (png_ptr == nullptr || info_ptr == nullptr) {
    return;
  }
  if (info_ptr->num_palette == 0) {
    png_warning(png_ptr, "Palette size 0, hIST allocation skipped.");
    return;
  }

  png_free_data(png_ptr, info_ptr, 8u, 0);  // PNG_FREE_HIST
  auto* const h = static_cast<std::uint16_t*>(png_malloc_warn(png_ptr, 0x200u));
  Field<std::uint16_t*>(png_ptr, kOffHist) = h;
  if (h == nullptr) {
    png_warning(png_ptr, "Insufficient memory for hIST chunk data.");
    return;
  }

  for (int i = 0; i < info_ptr->num_palette; ++i) {
    h[i] = hist[i];
  }
  info_ptr->valid |= 0x0040u;   // PNG_INFO_hIST
  info_ptr->free_me |= 0x0008u; // PNG_FREE_HIST
  info_ptr->hist = h;
}

/**
 * Address: 0x009E97FB (FUN_009E97FB)
 * Mangled: png_set_text_2
 *
 * Appends num_text text records to info_ptr->text, growing the array (by the
 * needed count + 8 slack) when it can't fit. Each record's key and text are
 * copied into a single freshly-allocated "key\0text\0" buffer. iTXt records
 * (compression > 0) are not supported and are skipped with a warning; a record
 * with no key is skipped. Returns 1 on an allocation failure, else 0.
 */
extern "C" int png_set_text_2(png_structp png_ptr, png_infop info_ptr,
                              const png_text* text_ptr, int num_text)
{
  if (png_ptr == nullptr || info_ptr == nullptr || num_text == 0) {
    return 0;
  }

  const int needed = num_text + info_ptr->num_text;
  if (needed > info_ptr->max_text) {
    if (info_ptr->text != nullptr) {
      const int old_max = info_ptr->max_text;
      info_ptr->max_text = needed + 8;
      auto* const grown = static_cast<png_text*>(
          png_malloc_warn(png_ptr, 16u * static_cast<std::uint32_t>(info_ptr->max_text)));
      png_text* const old = info_ptr->text;
      info_ptr->text = grown;
      if (grown == nullptr) {
        png_free(png_ptr, old);
        return 1;
      }
      std::memcpy(grown, old, 16u * static_cast<std::uint32_t>(old_max));
      png_free(png_ptr, old);
    } else {
      info_ptr->num_text = 0;
      info_ptr->max_text = num_text + 8;
      info_ptr->text = static_cast<png_text*>(
          png_malloc_warn(png_ptr, 16u * static_cast<std::uint32_t>(info_ptr->max_text)));
      if (info_ptr->text == nullptr) {
        return 1;
      }
      info_ptr->free_me |= 0x4000u;  // PNG_FREE_TEXT
    }
  }

  for (int i = 0; i < num_text; ++i) {
    const png_text& src = text_ptr[i];
    if (src.key == nullptr) {
      continue;
    }
    if (src.compression > 0) {
      png_warning(png_ptr, "iTXt chunk not supported.");
      continue;
    }

    png_text* const dest = &info_ptr->text[info_ptr->num_text];
    const std::size_t key_len = std::strlen(src.key);
    std::size_t text_len;
    if (src.text != nullptr && src.text[0] != '\0') {
      text_len = std::strlen(src.text);
      dest->compression = src.compression;
    } else {
      text_len = 0;
      dest->compression = -1;
    }

    auto* const buf = static_cast<char*>(
        png_malloc_warn(png_ptr, static_cast<std::uint32_t>(text_len + key_len + 4)));
    dest->key = buf;
    if (buf == nullptr) {
      return 1;
    }
    std::memcpy(buf, src.key, key_len);
    buf[key_len] = '\0';
    dest->text = buf + key_len + 1;
    if (text_len != 0) {
      std::memcpy(dest->text, src.text, text_len);
    }
    dest->text[text_len] = '\0';
    dest->text_length = static_cast<std::uint32_t>(text_len);
    ++info_ptr->num_text;
  }
  return 0;
}

/**
 * Address: 0x009E9560 (FUN_009E9560)
 * Mangled: png_set_sCAL
 *
 * Stores the physical scale (unit + width + height as doubles) into the info
 * struct and marks PNG_INFO_sCAL valid.
 */
extern "C" void png_set_sCAL(png_structp png_ptr, png_infop info_ptr,
                             int unit, double width, double height)
{
  if (png_ptr == nullptr || info_ptr == nullptr) {
    return;
  }
  info_ptr->valid |= 0x4000u;  // PNG_INFO_sCAL
  info_ptr->scal_width  = width;
  info_ptr->scal_unit   = static_cast<std::uint8_t>(unit);
  info_ptr->scal_height = height;
}

/**
 * Address: 0x009E9402 (FUN_009E9402)
 * Mangled: png_set_pCAL
 *
 * Stores the pCAL pixel-calibration data into the info struct: the purpose
 * string, X0/X1 endpoints, equation type, units string, and nparams parameter
 * strings — each duplicated into an info-owned allocation. Marks PNG_INFO_pCAL
 * valid and PNG_FREE_PCAL owned. On any allocation failure it warns and returns
 * with the info fields partially filled, matching the binary exactly.
 */
extern "C" void png_set_pCAL(png_structp png_ptr, png_infop info_ptr,
                             char* purpose, std::int32_t X0, std::int32_t X1,
                             int type, int nparams, char* units, char** params)
{
  if (png_ptr == nullptr || info_ptr == nullptr) {
    return;
  }

  std::uint32_t length = static_cast<std::uint32_t>(std::strlen(purpose)) + 1;
  info_ptr->pcal_purpose = static_cast<char*>(png_malloc_warn(png_ptr, length));
  if (info_ptr->pcal_purpose == nullptr) {
    png_warning(png_ptr, "Insufficient memory for pCAL purpose.");
    return;
  }
  std::memcpy(info_ptr->pcal_purpose, purpose, length);

  info_ptr->pcal_X0      = X0;
  info_ptr->pcal_X1      = X1;
  info_ptr->pcal_type    = static_cast<std::uint8_t>(type);
  info_ptr->pcal_nparams = static_cast<std::uint8_t>(nparams);

  length = static_cast<std::uint32_t>(std::strlen(units)) + 1;
  info_ptr->pcal_units = static_cast<char*>(png_malloc_warn(png_ptr, length));
  if (info_ptr->pcal_units == nullptr) {
    png_warning(png_ptr, "Insufficient memory for pCAL units.");
    return;
  }
  std::memcpy(info_ptr->pcal_units, units, length);

  info_ptr->pcal_params = static_cast<char**>(
      png_malloc_warn(png_ptr, 4u * static_cast<std::uint32_t>(nparams) + 4u));
  if (info_ptr->pcal_params == nullptr) {
    png_warning(png_ptr, "Insufficient memory for pCAL params.");
    return;
  }

  info_ptr->pcal_params[nparams] = nullptr;

  for (int i = 0; i < nparams; ++i) {
    length = static_cast<std::uint32_t>(std::strlen(params[i])) + 1;
    info_ptr->pcal_params[i] = static_cast<char*>(png_malloc_warn(png_ptr, length));
    if (info_ptr->pcal_params[i] == nullptr) {
      png_warning(png_ptr, "Insufficient memory for pCAL parameter.");
      return;
    }
    std::memcpy(info_ptr->pcal_params[i], params[i], length);
  }

  info_ptr->valid   |= 0x400u;  // PNG_INFO_pCAL
  info_ptr->free_me |= 0x80u;   // PNG_FREE_PCAL
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
