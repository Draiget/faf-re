#pragma once

#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "gpg/core/streams/MemBufferStream.h"
#include "legacy/containers/Vector.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  template <typename TUnsigned>
  [[nodiscard]] constexpr TUnsigned DXT_BlockCount(const TUnsigned texelCount)
  {
    static_assert(std::is_unsigned_v<TUnsigned>, "DXT_BlockCount requires an unsigned integer type");
    return (texelCount + static_cast<TUnsigned>(3)) >> static_cast<TUnsigned>(2);
  }

  struct SBatchTextureData
  {
    static gpg::RType* sType;

    std::uint32_t mWidth = 0;                       // +0x00
    std::uint32_t mHeight = 0;                      // +0x04
    msvc8::vector<std::uint8_t> mDxt5Blocks = {};  // +0x08
  };

  /**
   * Address: 0x00447D00 (FUN_00447D00)
   *
   * What it does:
   * Builds one `SBatchTextureData` payload from DXT block rows, handling both
   * tightly-packed and caller-pitched sources.
   */
  [[nodiscard]] bool BuildBatchTextureDataFromRows(
    SBatchTextureData& outData,
    std::uint32_t width,
    std::uint32_t height,
    const void* sourceBlocks,
    std::uint32_t sourcePitchBytes
  );

  /**
   * Address: 0x00447D90 (FUN_00447D90)
   *
   * What it does:
   * Copies one decoded block byte-range from a temporary mem-buffer into
   * `SBatchTextureData` owned storage.
   */
  [[nodiscard]] bool CopyBatchTextureDataFromMemBuffer(
    SBatchTextureData& outData,
    const gpg::MemBuffer<char>& sourceBuffer
  );

  static_assert(offsetof(SBatchTextureData, mWidth) == 0x00, "SBatchTextureData::mWidth offset must be 0x00");
  static_assert(offsetof(SBatchTextureData, mHeight) == 0x04, "SBatchTextureData::mHeight offset must be 0x04");
  static_assert(offsetof(SBatchTextureData, mDxt5Blocks) == 0x08, "SBatchTextureData::mDxt5Blocks offset must be 0x08");
  static_assert(sizeof(SBatchTextureData) == 0x18, "SBatchTextureData size must be 0x18");
} // namespace moho
