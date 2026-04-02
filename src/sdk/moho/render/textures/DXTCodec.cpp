#include "moho/render/textures/DXTCodec.h"

#include <array>
#include <cstring>

namespace moho
{
  namespace
  {
    constexpr std::uint8_t kDxt5AlphaCodeTable[6] = {0, 2, 3, 4, 5, 1}; // byte_DFFFF4
    constexpr std::uint8_t kDxtColorCodeTable[5] = {1, 3, 2, 0, 0x0A};  // byte_DFFFFC

    [[nodiscard]] std::uint32_t ExpandRgb565ToArgb8888(const std::uint16_t packed)
    {
      const std::uint32_t b5 = (packed & 0x001Fu);
      const std::uint32_t g6 = (packed >> 5u) & 0x003Fu;
      const std::uint32_t r5 = (packed >> 11u) & 0x001Fu;

      const std::uint32_t b8 = (b5 << 3u) | (b5 >> 2u);
      const std::uint32_t g8 = (g6 << 2u) | (g6 >> 4u);
      const std::uint32_t r8 = (r5 << 3u) | (r5 >> 2u);

      return 0xFF000000u | (r8 << 16u) | (g8 << 8u) | b8;
    }

    [[nodiscard]] std::uint32_t ReadU32(const std::uint8_t* const bytes)
    {
      std::uint32_t value = 0;
      std::memcpy(&value, bytes, sizeof(value));
      return value;
    }
  } // namespace

  /**
   * Address: 0x004047D0 (FUN_004047D0, Moho::DXT_EncodeAlphaBlock)
   */
  std::uint64_t DXT_EncodeAlphaBlock(
    const std::uint8_t* const source, const int horizontalStride, const int verticalStride
  )
  {
    std::uint32_t minAlpha = 0xFFu;
    std::uint32_t maxAlpha = 0u;

    const std::uint8_t* row = source;
    for (int y = 0; y < 4; ++y) {
      const std::uint8_t samples[4] = {
        row[0],
        row[horizontalStride],
        row[2 * horizontalStride],
        row[3 * horizontalStride],
      };
      for (std::uint8_t sample : samples) {
        if (sample == 0 || sample == 0xFFu) {
          continue;
        }
        if (sample < minAlpha) {
          minAlpha = sample;
        }
        if (sample > maxAlpha) {
          maxAlpha = sample;
        }
      }
      row += verticalStride;
    }

    std::uint32_t delta = 0u;
    std::uint32_t packedLow = 0u;
    if (minAlpha > maxAlpha) {
      packedLow = 0x0000FF00u;
    } else {
      if (minAlpha == maxAlpha) {
        ++maxAlpha;
      }
      packedLow = minAlpha | (maxAlpha << 8u);
      delta = maxAlpha - minAlpha;
    }

    std::uint64_t packed = packedLow;
    std::uint32_t bitPos = 16u;
    const std::uint8_t* blockRow = source;
    for (int y = 0; y < 4; ++y) {
      const std::uint8_t* pixel = blockRow;
      for (int x = 0; x < 4; ++x) {
        const std::uint32_t sample = *pixel;
        std::uint32_t code = 0u;
        if (sample == 0u) {
          code = 6u;
        } else if (sample == 0xFFu) {
          code = 7u;
        } else {
          const std::uint32_t lutIndex = (delta + 10u * (sample - minAlpha)) / (2u * delta);
          code = kDxt5AlphaCodeTable[lutIndex];
        }
        packed |= (static_cast<std::uint64_t>(code) << bitPos);
        bitPos += 3u;
        pixel += horizontalStride;
      }
      blockRow += verticalStride;
    }

    return packed;
  }

  /**
   * Address: 0x00404960 (FUN_00404960, Moho::DXT_EncodeGreenBlock)
   */
  std::uint64_t DXT_EncodeGreenBlock(const std::uint8_t* const source)
  {
    std::int32_t minValue = 0xFF;
    std::int32_t maxValue = 0;
    for (int i = 0; i < 16; ++i) {
      const std::int32_t sample = source[i];
      if (sample < minValue) {
        minValue = sample;
      }
      if (sample > maxValue) {
        maxValue = sample;
      }
    }

    std::int32_t maxEndpoint = (maxValue & 0xFC) | (maxValue >> 6);
    std::int32_t minEndpoint = (minValue & 0xFC) | (minValue >> 6);
    if (maxEndpoint == minEndpoint) {
      if (minEndpoint != 0) {
        minEndpoint = 0;
      } else {
        maxEndpoint = 0xFF;
      }
    }

    const std::int32_t delta = maxEndpoint - minEndpoint;
    std::uint32_t indexBits = 0u;
    std::uint32_t shift = 0u;
    for (int i = 0; i < 16; ++i) {
      std::int32_t quantized = (delta + 6 * (static_cast<std::int32_t>(source[i]) - minEndpoint)) / (2 * delta);
      if (quantized > 4) {
        quantized = 4;
      } else if (quantized < 0) {
        quantized = 0;
      }

      indexBits |= (static_cast<std::uint32_t>(kDxtColorCodeTable[quantized]) << shift);
      shift += 2u;
    }

    const std::uint32_t endpointBits =
      8u * ((static_cast<std::uint32_t>(maxEndpoint) & 0xFCu) | ((static_cast<std::uint32_t>(minEndpoint) & 0xFCu) << 16u));
    return (static_cast<std::uint64_t>(indexBits) << 32u) | endpointBits;
  }

  /**
   * Address: 0x00404B10 (FUN_00404B10, Moho::DXT_DecodeAlphaBlock)
   */
  void DXT_DecodeAlphaBlock(
    const std::uint64_t alphaBlock, const DXTFormat format, std::uint8_t* const outAlpha16
  )
  {
    if (outAlpha16 == nullptr) {
      return;
    }

    const std::uint8_t formatIndex = static_cast<std::uint8_t>(format);
    switch (formatIndex) {
      case 1: {
        const std::uint16_t alpha0 = static_cast<std::uint16_t>(alphaBlock & 0xFFFFu);
        const std::uint16_t alpha1 = static_cast<std::uint16_t>((alphaBlock >> 16u) & 0xFFFFu);
        if (alpha0 > alpha1) {
          for (int i = 0; i < 16; ++i) {
            outAlpha16[i] = 0xFFu;
          }
          return;
        }

        std::uint32_t bits = static_cast<std::uint32_t>((alphaBlock >> 32u) & 0xFFFFFFFFu);
        for (int i = 0; i < 16; ++i) {
          const std::uint8_t code = static_cast<std::uint8_t>(bits & 0x3u);
          bits >>= 2u;
          outAlpha16[i] = (code == 3u) ? 0u : 0xFFu;
        }
        return;
      }

      case 2:
      case 3: {
        std::uint64_t bits = alphaBlock >> 16u;
        for (int i = 0; i < 16; ++i) {
          const std::uint8_t nibble = static_cast<std::uint8_t>(bits & 0xFu);
          bits >>= 4u;
          outAlpha16[i] = static_cast<std::uint8_t>((nibble << 4u) | nibble);
        }
        return;
      }

      case 4:
      case 5: {
        const std::uint8_t alpha0 = static_cast<std::uint8_t>(alphaBlock & 0xFFu);
        const std::uint8_t alpha1 = static_cast<std::uint8_t>((alphaBlock >> 8u) & 0xFFu);

        std::array<std::uint8_t, 8> palette{};
        palette[0] = alpha0;
        palette[1] = alpha1;
        if (alpha0 <= alpha1) {
          palette[2] = static_cast<std::uint8_t>((alpha1 + 4 * alpha0 + 2) / 5);
          palette[3] = static_cast<std::uint8_t>((3 * alpha0 + 2 * alpha1 + 2) / 5);
          palette[4] = static_cast<std::uint8_t>((2 * alpha0 + 3 * alpha1 + 2) / 5);
          palette[5] = static_cast<std::uint8_t>((alpha0 + 4 * alpha1 + 2) / 5);
          palette[6] = 0;
          palette[7] = 0xFFu;
        } else {
          palette[2] = static_cast<std::uint8_t>((alpha1 + 6 * alpha0 + 3) / 7);
          palette[3] = static_cast<std::uint8_t>((5 * alpha0 + 2 * alpha1 + 3) / 7);
          palette[4] = static_cast<std::uint8_t>((4 * alpha0 + 3 * alpha1 + 3) / 7);
          palette[5] = static_cast<std::uint8_t>((3 * alpha0 + 4 * alpha1 + 3) / 7);
          palette[6] = static_cast<std::uint8_t>((2 * alpha0 + 5 * alpha1 + 3) / 7);
          palette[7] = static_cast<std::uint8_t>((alpha0 + 6 * alpha1 + 3) / 7);
        }

        std::uint64_t bits = alphaBlock >> 16u;
        for (int i = 0; i < 16; ++i) {
          outAlpha16[i] = palette[static_cast<std::uint8_t>(bits & 0x7u)];
          bits >>= 3u;
        }
        return;
      }

      default:
        return;
    }
  }

  /**
   * Address: 0x00404D60 (FUN_00404D60, Moho::DXT_DecodeColorBlock)
   */
  void DXT_DecodeColorBlock(
    const std::uint64_t colorBlock, const DXTFormat format, std::uint32_t* const outArgb16
  )
  {
    if (outArgb16 == nullptr) {
      return;
    }

    const std::uint16_t c0 = static_cast<std::uint16_t>(colorBlock & 0xFFFFu);
    const std::uint16_t c1 = static_cast<std::uint16_t>((colorBlock >> 16u) & 0xFFFFu);

    std::uint32_t palette[4]{};
    palette[0] = ExpandRgb565ToArgb8888(c0);
    palette[1] = ExpandRgb565ToArgb8888(c1);

    const auto c0b = static_cast<std::uint8_t>(palette[0] & 0xFFu);
    const auto c0g = static_cast<std::uint8_t>((palette[0] >> 8u) & 0xFFu);
    const auto c0r = static_cast<std::uint8_t>((palette[0] >> 16u) & 0xFFu);
    const auto c0a = static_cast<std::uint8_t>((palette[0] >> 24u) & 0xFFu);

    const auto c1b = static_cast<std::uint8_t>(palette[1] & 0xFFu);
    const auto c1g = static_cast<std::uint8_t>((palette[1] >> 8u) & 0xFFu);
    const auto c1r = static_cast<std::uint8_t>((palette[1] >> 16u) & 0xFFu);
    const auto c1a = static_cast<std::uint8_t>((palette[1] >> 24u) & 0xFFu);

    if (palette[0] <= palette[1] && format == DXTFormat_DXT1) {
      const std::uint8_t b = static_cast<std::uint8_t>((c0b + c1b + 1) / 2);
      const std::uint8_t g = static_cast<std::uint8_t>((c0g + c1g + 1) / 2);
      const std::uint8_t r = static_cast<std::uint8_t>((c0r + c1r + 1) / 2);
      const std::uint8_t a = static_cast<std::uint8_t>((c0a + c1a + 1) / 2);
      palette[2] = static_cast<std::uint32_t>(b) | (static_cast<std::uint32_t>(g) << 8u) |
                   (static_cast<std::uint32_t>(r) << 16u) | (static_cast<std::uint32_t>(a) << 24u);
      palette[3] = 0u;
    } else {
      const std::uint8_t b2 = static_cast<std::uint8_t>((c1b + 2 * c0b + 1) / 3);
      const std::uint8_t g2 = static_cast<std::uint8_t>((c1g + 2 * c0g + 1) / 3);
      const std::uint8_t r2 = static_cast<std::uint8_t>((c1r + 2 * c0r + 1) / 3);
      const std::uint8_t a2 = static_cast<std::uint8_t>((c1a + 2 * c0a + 1) / 3);
      const std::uint8_t b3 = static_cast<std::uint8_t>((c0b + 2 * c1b + 1) / 3);
      const std::uint8_t g3 = static_cast<std::uint8_t>((c0g + 2 * c1g + 1) / 3);
      const std::uint8_t r3 = static_cast<std::uint8_t>((c0r + 2 * c1r + 1) / 3);
      const std::uint8_t a3 = static_cast<std::uint8_t>((c0a + 2 * c1a + 1) / 3);

      palette[2] = static_cast<std::uint32_t>(b2) | (static_cast<std::uint32_t>(g2) << 8u) |
                   (static_cast<std::uint32_t>(r2) << 16u) | (static_cast<std::uint32_t>(a2) << 24u);
      palette[3] = static_cast<std::uint32_t>(b3) | (static_cast<std::uint32_t>(g3) << 8u) |
                   (static_cast<std::uint32_t>(r3) << 16u) | (static_cast<std::uint32_t>(a3) << 24u);
    }

    std::uint32_t codes = static_cast<std::uint32_t>(colorBlock >> 32u);
    for (int i = 0; i < 16; ++i) {
      outArgb16[i] = palette[codes & 0x3u];
      codes >>= 2u;
    }
  }

  /**
   * Address: 0x00404F80 (FUN_00404F80, Moho::DXT_DecodeBlocksToRGBA)
   */
  void DXT_DecodeBlocksToRGBA(
    const std::uint64_t alphaBlock,
    const std::uint64_t colorBlock,
    const DXTFormat format,
    std::uint32_t* const outArgb16
  )
  {
    if (outArgb16 == nullptr) {
      return;
    }

    DXT_DecodeColorBlock(colorBlock, format, outArgb16);
    if (format == DXTFormat_DXT1) {
      return;
    }

    std::uint8_t alpha[16]{};
    DXT_DecodeAlphaBlock(alphaBlock, format, alpha);
    for (int i = 0; i < 16; ++i) {
      outArgb16[i] &= 0x00FFFFFFu;
      outArgb16[i] |= (static_cast<std::uint32_t>(alpha[i]) << 24u);
    }
  }

  /**
   * Address: 0x00404FE0 (FUN_00404FE0, Moho::DXT_GetTexelAlpha)
   */
  std::uint8_t DXT_GetTexelAlpha(
    const std::uint32_t coordA,
    const std::uint8_t* const blocks,
    const std::uint32_t coordB,
    const std::uint32_t blockStrideBytes
  )
  {
    if (blocks == nullptr) {
      return 0u;
    }

    const std::uint32_t blockOffset = (coordA >> 2u) * blockStrideBytes + ((coordB >> 2u) << 4u);
    const std::uint8_t* const blockPtr = blocks + blockOffset;

    const std::uint64_t alphaBlock =
      static_cast<std::uint64_t>(ReadU32(blockPtr)) | (static_cast<std::uint64_t>(ReadU32(blockPtr + 4)) << 32u);

    std::uint8_t decoded[16]{};
    DXT_DecodeAlphaBlock(alphaBlock, DXTFormat_DXT5, decoded);

    return decoded[((coordA & 3u) << 2u) | (coordB & 3u)];
  }
} // namespace moho
