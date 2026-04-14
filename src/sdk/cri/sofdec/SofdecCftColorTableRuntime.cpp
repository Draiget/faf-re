#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

#include "moho/audio/SofdecRuntime.h"

namespace
{
  /**
   * CRI Sofdec CFT (Color Format Transfer) inverse conversion tables.
   *
   * These 256-byte lookup tables implement a custom non-linear inverse mapping
   * from quantized YCbCr sample values back to linear component levels for
   * video frame color reconstruction.
   *
   * Binary data layout (all in .data segment):
   *   cft_conv_u_itbl: 0x01001408 (256 bytes)
   *   cft_conv_v_itbl: 0x01001558 (256 bytes)
   *   cft_conv_y_itbl: 0x010016A0 (256 bytes)
   *   cft_ptr_cr_rgb:  0x010017A0 (sentinel address, end of cft_conv_y_itbl)
   */

  std::array<std::uint8_t, 256> cft_conv_y_itbl{};
  std::array<std::uint8_t, 256> cft_conv_u_itbl{};
  std::array<std::uint8_t, 256> cft_conv_v_itbl{};

  struct CftArgb8888AlphaLane
  {
    std::int16_t r = 0;
    std::int16_t g = 0;
    std::int16_t b = 0;
    std::int16_t a = 0;
  };

  static_assert(sizeof(CftArgb8888AlphaLane) == 0x8, "CftArgb8888AlphaLane size must be 0x8");

  struct CftArgb8888AlphaTablePack
  {
    std::array<CftArgb8888AlphaLane, 256> base{};
    std::array<CftArgb8888AlphaLane, 256> lane1{};
    std::array<CftArgb8888AlphaLane, 256> lane2{};
  };

  static_assert(sizeof(CftArgb8888AlphaTablePack) == 0x1800, "CftArgb8888AlphaTablePack size must be 0x1800");

  struct CftYcc422PrimaryEntry
  {
    std::int32_t lane0 = 0;
    std::int32_t lane1 = 0;
    std::int32_t lane2 = 0;
    std::int32_t lane3 = 0;
  };

  static_assert(sizeof(CftYcc422PrimaryEntry) == 0x10, "CftYcc422PrimaryEntry size must be 0x10");

  struct CftYcc422SecondaryEntry
  {
    std::int32_t lane0 = 0;
    std::int32_t lane1 = 0;
  };

  static_assert(sizeof(CftYcc422SecondaryEntry) == 0x8, "CftYcc422SecondaryEntry size must be 0x8");

  struct CftYcc422ColAdjTablePack
  {
    std::array<CftYcc422PrimaryEntry, 256> primary{};
    std::array<CftYcc422SecondaryEntry, 256> secondaryU{};
    std::array<CftYcc422SecondaryEntry, 256> secondaryV{};
  };

  static_assert(sizeof(CftYcc422ColAdjTablePack) == 0x2000, "CftYcc422ColAdjTablePack size must be 0x2000");

  std::array<double, 9> cft_rgb_yuv_ccir601{
    0.257, 0.504, 0.098,
    -0.148, -0.291, 0.439,
    0.439, -0.368, -0.071,
  };
  std::array<double, 9> cft_yuv_rgb_coeff{};
  std::array<double, 9> cft_basic_ccir601{};

  CftArgb8888AlphaLane* cft_ptr_y_rgb = nullptr;
  CftArgb8888AlphaLane* cft_ptr_cb_rgb = nullptr;
  CftArgb8888AlphaLane* cft_ptr_cr_rgb = nullptr;

  template <typename T>
  [[nodiscard]] T* ResolveAddress(const std::int32_t address32)
  {
    const auto addressAsU32 = static_cast<std::uint32_t>(address32);
    const auto address = static_cast<std::uintptr_t>(addressAsU32);
    return reinterpret_cast<T*>(address);
  }

  [[nodiscard]] double ClampToByteRange(const double value)
  {
    if (value < 0.0) {
      return 0.0;
    }
    if (value > 255.0) {
      return 255.0;
    }
    return value;
  }

  [[nodiscard]] CftArgb8888AlphaTablePack* ResolveAlphaPack(const std::int32_t tableAddress)
  {
    return ResolveAddress<CftArgb8888AlphaTablePack>(tableAddress);
  }

  /**
   * Address: 0x00AEE0C0 (FUN_00AEE0C0)
   *
   * IDA signature:
   * char cftfx_makeInvConvTableCustom(void);
   *
   * What it does:
   * Populates the three inverse color conversion lookup tables
   * (Y, U, V) with a custom non-linear quantization curve.
   * The Y table uses a piecewise mapping with four regions:
   *   [0..15]:   alternating 1:1 and skip (every other input gets +2)
   *   [16..175]: 2:1 downsampling (two inputs per output value)
   *   [176..191]: 1:1 linear region
   *   [192..255]: 2:1 upsampling, clamped to 255
   * The U and V tables use symmetric 3:1 mapping around center (128)
   * with linear interpolation at the tails.
   *
   * Called from CFT_MakeYcc422ColAdjTbl and CFT_MakeArgb8888ColAdjTbl
   * during video decoder initialization.
   */
  void cftfx_makeInvConvTableCustom()
  {
    // ---- Y inverse table ----

    // Region 1: indices [0..15], alternating stride pattern.
    // Every pair of indices maps with stride: input advances by 2 each pair,
    // output advances by 3 each pair (one +1, then +2).
    int idx = 0;
    int val = 0;
    while (idx < 16) {
      cft_conv_y_itbl[idx] = static_cast<std::uint8_t>(val);
      cft_conv_y_itbl[idx + 1] = static_cast<std::uint8_t>(val + 1);
      idx += 2;
      val += 3;
    }

    // Region 2: indices [16..175], 2:1 downsampling.
    // Two consecutive table entries share the same output value.
    while (idx < 176) {
      cft_conv_y_itbl[idx] = static_cast<std::uint8_t>(val);
      cft_conv_y_itbl[idx + 1] = static_cast<std::uint8_t>(val);
      idx += 2;
      ++val;
    }

    // Region 3: indices [176..191], 1:1 linear.
    while (idx < 192) {
      cft_conv_y_itbl[idx] = static_cast<std::uint8_t>(val);
      ++val;
      ++idx;
    }

    // Region 4: indices [192..255], 2:1 upsampling clamped to 255.
    while (idx < 256) {
      const auto clamped = static_cast<std::uint8_t>(std::min(val, 255));
      cft_conv_y_itbl[idx] = clamped;
      val += 2;
      ++idx;
    }

    // ---- U and V inverse tables: symmetric from center (128) ----

    // Center region: 3:1 mapping outward from index 128, value 128.
    // Each group of 3 consecutive indices gets the same output value.
    // Covers indices [105..127] and [128..151] (center band).
    {
      int centerIdx = 128;
      int centerVal = 128;

      // Expand outward from center: 3 entries per value step, going down.
      while (centerIdx > 104) {
        cft_conv_u_itbl[centerIdx] = static_cast<std::uint8_t>(centerVal);
        cft_conv_v_itbl[centerIdx] = static_cast<std::uint8_t>(centerVal);
        cft_conv_u_itbl[centerIdx - 1] = static_cast<std::uint8_t>(centerVal);
        cft_conv_v_itbl[centerIdx - 1] = static_cast<std::uint8_t>(centerVal);
        cft_conv_u_itbl[centerIdx - 2] = static_cast<std::uint8_t>(centerVal);
        cft_conv_v_itbl[centerIdx - 2] = static_cast<std::uint8_t>(centerVal);
        centerIdx -= 3;
        --centerVal;
      }

      // Lower tail: indices [0..centerIdx], linear interpolation.
      // Uses integer division to distribute remaining range evenly.
      const int tailCount = centerIdx;
      if (centerIdx >= 0) {
        int accumulator = centerIdx * centerVal;
        const int negVal = -centerVal;
        while (centerIdx >= 0) {
          const int divided = accumulator / tailCount;
          accumulator += negVal;
          cft_conv_u_itbl[centerIdx] = static_cast<std::uint8_t>(divided);
          cft_conv_v_itbl[centerIdx] = static_cast<std::uint8_t>(divided);
          --centerIdx;
        }
      }
    }

    // Upper center: 3:1 mapping from index 128 upward.
    {
      int upperIdx = 128;
      int upperVal = 128;
      while (upperIdx < 152) {
        cft_conv_u_itbl[upperIdx] = static_cast<std::uint8_t>(upperVal);
        cft_conv_v_itbl[upperIdx] = static_cast<std::uint8_t>(upperVal);
        cft_conv_u_itbl[upperIdx + 1] = static_cast<std::uint8_t>(upperVal);
        cft_conv_v_itbl[upperIdx + 1] = static_cast<std::uint8_t>(upperVal);
        cft_conv_u_itbl[upperIdx + 2] = static_cast<std::uint8_t>(upperVal);
        cft_conv_v_itbl[upperIdx + 2] = static_cast<std::uint8_t>(upperVal);
        upperIdx += 3;
        ++upperVal;
      }

      // Upper tail: indices [152..255], linear interpolation.
      if (upperIdx <= 255) {
        const int remaining = 255 - upperIdx;
        const int rangeLeft = 255 - upperVal;
        int accumulator = 0;
        while (upperIdx <= 255) {
          const auto interpolated = static_cast<std::uint8_t>(
            upperVal + accumulator / remaining
          );
          cft_conv_u_itbl[upperIdx] = interpolated;
          cft_conv_v_itbl[upperIdx] = interpolated;
          accumulator += rangeLeft;
          ++upperIdx;
        }
      }
    }
  }

  /**
   * Address: 0x00AEE440 (FUN_00AEE440, _cftfx_makeMtx3D)
   *
   * What it does:
   * Multiplies two 3x3 matrices and scales the result by 1/64.
   */
  void cftfx_makeMtx3D(
    const std::array<double, 9>& lhs,
    const std::array<double, 9>& rhs,
    std::array<double, 9>& out
  )
  {
    for (std::int32_t row = 0; row < 3; ++row) {
      for (std::int32_t column = 0; column < 3; ++column) {
        const std::size_t index = static_cast<std::size_t>(row * 3 + column);
        const double value =
          lhs[static_cast<std::size_t>(row * 3)] * rhs[static_cast<std::size_t>(column)] +
          lhs[static_cast<std::size_t>(row * 3 + 1)] * rhs[static_cast<std::size_t>(column + 3)] +
          lhs[static_cast<std::size_t>(row * 3 + 2)] * rhs[static_cast<std::size_t>(column + 6)];
        out[index] = value * (1.0 / 64.0);
      }
    }
  }

  /**
   * Address: 0x00AEE5A0 (FUN_00AEE5A0, _cftfx_makeInverseMtx3D)
   *
   * What it does:
   * Builds one scaled (x64) inverse matrix for the provided 3x3 source matrix.
   */
  void cftfx_makeInverseMtx3D(const std::array<double, 9>& input, std::array<double, 9>& out)
  {
    const double m0 = input[0];
    const double m1 = input[1];
    const double m2 = input[2];
    const double m3 = input[3];
    const double m4 = input[4];
    const double m5 = input[5];
    const double m6 = input[6];
    const double m7 = input[7];
    const double m8 = input[8];

    const double term17 = m7 * m3;
    const double term14 = m6 * m5;
    const double term11 = m8 * m4;
    const double term18 = m6 * m4;
    const double term13 = m8 * m3;
    const double term12 = m7 * m5;

    const double inverseDeterminant =
      1.0 / (term11 * m0 + term14 * m1 + term17 * m2 - (term12 * m0 + term13 * m1 + term18 * m2));

    out[0] = (term11 - term12) * inverseDeterminant * 64.0;
    out[1] = (m8 * m1 - m7 * m2) * inverseDeterminant * -64.0;
    out[2] = (m5 * m1 - m4 * m2) * inverseDeterminant * 64.0;
    out[3] = (term13 - term14) * inverseDeterminant * -64.0;
    out[4] = (m8 * m0 - m6 * m2) * inverseDeterminant * 64.0;
    out[5] = (m5 * m0 - m3 * m2) * inverseDeterminant * -64.0;
    out[6] = (term17 - term18) * inverseDeterminant * 64.0;
    out[7] = (m7 * m0 - m6 * m1) * inverseDeterminant * -64.0;
    out[8] = (m4 * m0 - m3 * m1) * inverseDeterminant * 64.0;
  }

  /**
   * Address: 0x00AEE240 (FUN_00AEE240, _cftfx_makeConvYccRgbTable)
   *
   * What it does:
   * Rebuilds Y/Cb/Cr conversion coefficient tables for ARGB8888 conversion
   * lanes using the inverse conversion matrix.
   */
  std::int32_t cftfx_makeConvYccRgbTable()
  {
    cftfx_makeInverseMtx3D(cft_rgb_yuv_ccir601, cft_yuv_rgb_coeff);

    std::int32_t result = 0;
    for (std::size_t index = 0; index < 256; ++index) {
      const double yLane = static_cast<double>(cft_conv_y_itbl[index]);
      const double uLane = static_cast<double>(cft_conv_u_itbl[index]) - 128.0;
      const double vLane = static_cast<double>(cft_conv_v_itbl[index]) - 128.0;

      auto& yEntry = cft_ptr_y_rgb[index];
      yEntry.b = static_cast<std::int16_t>(static_cast<std::int32_t>(yLane * cft_yuv_rgb_coeff[0] + 0.5));
      yEntry.g = static_cast<std::int16_t>(static_cast<std::int32_t>(yLane * cft_yuv_rgb_coeff[3] + 0.5));
      yEntry.r = static_cast<std::int16_t>(static_cast<std::int32_t>(yLane * cft_yuv_rgb_coeff[6] + 0.5));
      yEntry.a = 16320;

      auto& cbEntry = cft_ptr_cb_rgb[index];
      cbEntry.b = static_cast<std::int16_t>(static_cast<std::int32_t>(uLane * cft_yuv_rgb_coeff[1] + 0.5));
      cbEntry.g = static_cast<std::int16_t>(static_cast<std::int32_t>(uLane * cft_yuv_rgb_coeff[4] + 0.5));
      cbEntry.r = static_cast<std::int16_t>(static_cast<std::int32_t>(uLane * cft_yuv_rgb_coeff[7] + 0.5));
      cbEntry.a = 0;

      auto& crEntry = cft_ptr_cr_rgb[index];
      crEntry.b = static_cast<std::int16_t>(static_cast<std::int32_t>(vLane * cft_yuv_rgb_coeff[2] + 0.5));
      crEntry.g = static_cast<std::int16_t>(static_cast<std::int32_t>(vLane * cft_yuv_rgb_coeff[5] + 0.5));
      result = static_cast<std::int32_t>(vLane * cft_yuv_rgb_coeff[8] + 0.5);
      crEntry.r = static_cast<std::int16_t>(result);
      crEntry.a = 0;
    }

    return result;
  }
} // namespace

/**
 * Address: 0x00AEDF40 (FUN_00AEDF40, _CFT_MakeYcc422ColAdjTbl)
 *
 * What it does:
 * Builds one YCC422 color-adjust table pack for Sofdec conversion lanes.
 */
std::int32_t CFT_MakeYcc422ColAdjTbl(const std::int32_t tableAddress)
{
  auto* const tablePack = ResolveAddress<CftYcc422ColAdjTablePack>(tableAddress);

  cftfx_makeInvConvTableCustom();
  cftfx_makeInverseMtx3D(cft_rgb_yuv_ccir601, cft_yuv_rgb_coeff);
  cftfx_makeMtx3D(cft_rgb_yuv_ccir601, cft_yuv_rgb_coeff, cft_basic_ccir601);

  const double yScale = cft_basic_ccir601[0];
  const double uScale = cft_basic_ccir601[4];
  const double vScale = cft_basic_ccir601[8];
  const double uBias = uScale * 128.0;
  const double vBias = vScale * 128.0;

  std::int32_t result = 0;
  for (std::size_t index = 0; index < 256; ++index) {
    const double yLane = static_cast<double>(cft_conv_y_itbl[index]);
    const double uLane = static_cast<double>(cft_conv_u_itbl[index]);
    const double vLane = static_cast<double>(cft_conv_v_itbl[index]);

    const std::int32_t yValue = static_cast<std::int32_t>(yLane * yScale + 0.5);
    const std::int32_t uValue = static_cast<std::int32_t>(uLane * uScale - uBias + 0.5);
    const std::int32_t vValue = static_cast<std::int32_t>(vLane * vScale - vBias + 0.5);

    auto& primary = tablePack->primary[index];
    primary.lane0 = 0;
    primary.lane1 = yValue << 16;
    primary.lane2 = 0;
    primary.lane3 = yValue;

    auto& secondaryU = tablePack->secondaryU[index];
    secondaryU.lane0 = 0;
    secondaryU.lane1 = uValue << 8;

    auto& secondaryV = tablePack->secondaryV[index];
    secondaryV.lane0 = 0;
    result = vValue << 24;
    secondaryV.lane1 = result;
  }

  return result;
}

/**
 * Address: 0x00AEE090 (FUN_00AEE090, _CFT_MakeArgb8888ColAdjTbl)
 *
 * What it does:
 * Initializes ARGB8888 Y/Cb/Cr conversion table lane pointers and rebuilds
 * conversion tables.
 */
std::int32_t CFT_MakeArgb8888ColAdjTbl(const std::int32_t tableAddress)
{
  auto* const tablePack = ResolveAlphaPack(tableAddress);
  cft_ptr_y_rgb = tablePack->base.data();
  cft_ptr_cb_rgb = tablePack->lane1.data();
  cft_ptr_cr_rgb = tablePack->lane2.data();

  cftfx_makeInvConvTableCustom();
  return cftfx_makeConvYccRgbTable();
}

/**
 * Address: 0x00AEDB70 (FUN_00AEDB70, _CFT_MakeArgb8888Alp3110Tbl)
 *
 * What it does:
 * Builds one ARGB8888 alpha table pack for 3110 blend mode.
 */
std::int32_t CFT_MakeArgb8888Alp3110Tbl(
  const std::int32_t tableAddress,
  const std::int32_t alpha0,
  const std::int32_t alpha1,
  const std::int32_t alpha2
)
{
  constexpr double kLane1RScale = 129.088;
  constexpr double kLane1GScale = 25.088;
  constexpr double kLane2GScale = 52.032;
  constexpr double kLane2BScale = 102.144;
  constexpr double kBaseMidScale = 148.3636363636364;
  constexpr std::int32_t kAlphaShift = 6;

  auto* const tables = ResolveAlphaPack(tableAddress);

  for (std::int32_t chroma = -128; chroma < 128; ++chroma) {
    const std::size_t laneIndex = static_cast<std::size_t>(chroma + 128);

    auto& lane1 = tables->lane1[laneIndex];
    lane1.r = static_cast<std::int16_t>(static_cast<std::int32_t>(kLane1RScale * static_cast<double>(chroma) + 0.5));
    lane1.g = static_cast<std::int16_t>(static_cast<std::int32_t>(0.5 - kLane1GScale * static_cast<double>(chroma)));
    lane1.b = 0;
    lane1.a = 0;

    auto& lane2 = tables->lane2[laneIndex];
    lane2.r = 0;
    lane2.g = static_cast<std::int16_t>(static_cast<std::int32_t>(0.5 - kLane2GScale * static_cast<double>(chroma)));
    lane2.b = static_cast<std::int16_t>(static_cast<std::int32_t>(kLane2BScale * static_cast<double>(chroma) + 0.5));
    lane2.a = 0;
  }

  const auto alpha0Lane = static_cast<std::int16_t>(static_cast<std::uint8_t>(alpha0));
  const auto alpha1Lane = static_cast<std::int16_t>(static_cast<std::uint8_t>(alpha1) << kAlphaShift);
  const auto alpha2Lane = static_cast<std::int16_t>(static_cast<std::uint8_t>(alpha2) << kAlphaShift);

  for (std::int32_t index = 0; index < 9; ++index) {
    auto& lane = tables->base[static_cast<std::size_t>(index)];
    lane.r = 0;
    lane.g = 0;
    lane.b = 0;
    lane.a = alpha0Lane;
  }

  for (std::int32_t index = 9; index < 134; ++index) {
    const double clamped = ClampToByteRange(static_cast<double>(index) - 16.0);
    const auto value = static_cast<std::int16_t>(static_cast<std::int32_t>(clamped * kBaseMidScale + 0.5));

    auto& lane = tables->base[static_cast<std::size_t>(index)];
    lane.r = value;
    lane.g = value;
    lane.b = value;
    lane.a = alpha1Lane;
  }

  std::int32_t result = 0;
  for (std::int32_t index = 134; index < 256; ++index) {
    const double clamped = ClampToByteRange(251.0 - static_cast<double>(index));
    result = static_cast<std::int32_t>(clamped * kBaseMidScale + 0.5);

    auto& lane = tables->base[static_cast<std::size_t>(index)];
    const auto value = static_cast<std::int16_t>(result);
    lane.r = value;
    lane.g = value;
    lane.b = value;
    lane.a = alpha2Lane;
  }

  return result;
}

/**
 * Address: 0x00AEDD50 (FUN_00AEDD50, _CFT_MakeArgb8888Alp3211Tbl)
 *
 * What it does:
 * Builds one ARGB8888 alpha table pack for 3211 blend mode.
 */
std::int32_t CFT_MakeArgb8888Alp3211Tbl(
  const std::int32_t tableAddress,
  const std::int32_t alpha0,
  const std::int32_t alpha1,
  const std::int32_t alpha2
)
{
  constexpr double kLane1RScale = 129.088;
  constexpr double kLane1GScale = 25.088;
  constexpr double kLane2GScale = 52.032;
  constexpr double kLane2BScale = 102.144;
  constexpr double kBaseMidScale = 296.7272727272727;
  constexpr double kBaseTailScale = 147.027027027027;
  constexpr std::int32_t kAlphaShift = 6;

  auto* const tables = ResolveAlphaPack(tableAddress);

  for (std::int32_t chroma = -128; chroma < 128; ++chroma) {
    const std::size_t laneIndex = static_cast<std::size_t>(chroma + 128);

    auto& lane1 = tables->lane1[laneIndex];
    lane1.r = static_cast<std::int16_t>(static_cast<std::int32_t>(kLane1RScale * static_cast<double>(chroma) + 0.5));
    lane1.g = static_cast<std::int16_t>(static_cast<std::int32_t>(0.5 - kLane1GScale * static_cast<double>(chroma)));
    lane1.b = 0;
    lane1.a = 0;

    auto& lane2 = tables->lane2[laneIndex];
    lane2.r = 0;
    lane2.g = static_cast<std::int16_t>(static_cast<std::int32_t>(0.5 - kLane2GScale * static_cast<double>(chroma)));
    lane2.b = static_cast<std::int16_t>(static_cast<std::int32_t>(kLane2BScale * static_cast<double>(chroma) + 0.5));
    lane2.a = 0;
  }

  const auto alpha0Lane = static_cast<std::int16_t>(static_cast<std::uint8_t>(alpha0));
  const auto alpha1Lane = static_cast<std::int16_t>(static_cast<std::uint8_t>(alpha1) << kAlphaShift);
  const auto alpha2Lane = static_cast<std::int16_t>(static_cast<std::uint8_t>(alpha2) << kAlphaShift);

  for (std::int32_t index = 0; index < 48; ++index) {
    auto& lane = tables->base[static_cast<std::size_t>(index)];
    lane.r = -1160;
    lane.g = -1160;
    lane.b = -1160;
    lane.a = alpha0Lane;
  }

  for (std::int32_t index = 48; index < 130; ++index) {
    const double clamped = ClampToByteRange(static_cast<double>(index) - 68.0);
    const auto value = static_cast<std::int16_t>(static_cast<std::int32_t>(clamped * kBaseMidScale + 0.5));

    auto& lane = tables->base[static_cast<std::size_t>(index)];
    lane.r = value;
    lane.g = value;
    lane.b = value;
    lane.a = alpha1Lane;
  }

  std::int32_t result = 0;
  for (std::int32_t index = 130; index < 256; ++index) {
    const double clamped = ClampToByteRange(247.0 - static_cast<double>(index));
    result = static_cast<std::int32_t>(clamped * kBaseTailScale + 0.5);

    auto& lane = tables->base[static_cast<std::size_t>(index)];
    const auto value = static_cast<std::int16_t>(result);
    lane.r = value;
    lane.g = value;
    lane.b = value;
    lane.a = alpha2Lane;
  }

  return result;
}
