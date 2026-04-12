#include <algorithm>
#include <array>
#include <cstdint>

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
} // namespace
