#pragma once

#include <cstdint>

namespace moho
{
  enum DXTFormat : std::uint32_t
  {
    DXTFormat_DXT1 = 1,
    DXTFormat_DXT2 = 2,
    DXTFormat_DXT3 = 3,
    DXTFormat_DXT4 = 4,
    DXTFormat_DXT5 = 5,
  };
  static_assert(sizeof(DXTFormat) == 0x4, "DXTFormat size must be 0x4");

  /**
   * Address: 0x004047D0 (FUN_004047D0, Moho::DXT_EncodeAlphaBlock)
   *
   * uchar const *,int,int
   *
   * What it does:
   * Encodes a 4x4 alpha block into DXT5 alpha payload using caller-provided
   * horizontal and vertical byte strides.
   */
  [[nodiscard]] std::uint64_t DXT_EncodeAlphaBlock(
    const std::uint8_t* source, int horizontalStride, int verticalStride
  );

  /**
   * Address: 0x00404960 (FUN_00404960, Moho::DXT_EncodeGreenBlock)
   *
   * uchar const *
   *
   * What it does:
   * Encodes a contiguous 4x4 green-channel block into DXT1-style color payload.
   */
  [[nodiscard]] std::uint64_t DXT_EncodeGreenBlock(const std::uint8_t* source);

  /**
   * Address: 0x00404B10 (FUN_00404B10, Moho::DXT_DecodeAlphaBlock)
   *
   * unsigned __int64,Moho::DXTFormat,uchar *
   *
   * What it does:
   * Decodes a 4x4 alpha payload into 16 output alpha bytes.
   */
  void DXT_DecodeAlphaBlock(std::uint64_t alphaBlock, DXTFormat format, std::uint8_t* outAlpha16);

  /**
   * Address: 0x00404D60 (FUN_00404D60, Moho::DXT_DecodeColorBlock)
   *
   * unsigned __int64,Moho::DXTFormat,uint *
   *
   * What it does:
   * Decodes a 4x4 DXT color payload into 16 ARGB pixels.
   */
  void DXT_DecodeColorBlock(std::uint64_t colorBlock, DXTFormat format, std::uint32_t* outArgb16);

  /**
   * Address: 0x00404F80 (FUN_00404F80, Moho::DXT_DecodeBlocksToRGBA)
   *
   * unsigned __int64,unsigned __int64,Moho::DXTFormat,uint *
   *
   * What it does:
   * Decodes one DXT block pair (alpha+color) into 16 ARGB pixels.
   */
  void DXT_DecodeBlocksToRGBA(
    std::uint64_t alphaBlock, std::uint64_t colorBlock, DXTFormat format, std::uint32_t* outArgb16
  );

  /**
   * Address: 0x00404FE0 (FUN_00404FE0, Moho::DXT_GetTexelAlpha)
   *
   * unsigned int,uchar const *,unsigned int,unsigned int
   *
   * What it does:
   * Fetches one decoded alpha texel from a DXT5 alpha plane using the original
   * register-based coordinate ordering recovered from the binary.
   */
  [[nodiscard]] std::uint8_t DXT_GetTexelAlpha(
    std::uint32_t coordA, const std::uint8_t* blocks, std::uint32_t coordB, std::uint32_t blockStrideBytes
  );
} // namespace moho
