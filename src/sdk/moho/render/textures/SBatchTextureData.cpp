#include "moho/render/textures/SBatchTextureData.h"

#include <cstring>

namespace moho
{
  gpg::RType* SBatchTextureData::sType = nullptr;

  /**
   * Address: 0x00447D00 (FUN_00447D00)
   */
  bool BuildBatchTextureDataFromRows(
    SBatchTextureData& outData,
    const std::uint32_t width,
    const std::uint32_t height,
    const void* const sourceBlocks,
    const std::uint32_t sourcePitchBytes
  )
  {
    if (width == 0 || height == 0 || sourceBlocks == nullptr) {
      return false;
    }

    outData.mWidth = width;
    outData.mHeight = height;

    const std::size_t encodedRowBytes = static_cast<std::size_t>(16u * DXT_BlockCount(width));
    const std::size_t encodedRows = static_cast<std::size_t>(DXT_BlockCount(height));
    const std::size_t totalEncodedBytes = encodedRows * encodedRowBytes;

    outData.mDxt5Blocks.resize(totalEncodedBytes);
    std::uint8_t* const destination = outData.mDxt5Blocks.begin();
    const std::uint8_t* sourceRow = static_cast<const std::uint8_t*>(sourceBlocks);

    if (sourcePitchBytes == encodedRowBytes) {
      std::memcpy(destination, sourceRow, totalEncodedBytes);
      return true;
    }

    std::uint8_t* destinationRow = destination;
    for (std::size_t row = 0; row < encodedRows; ++row) {
      std::memcpy(destinationRow, sourceRow, encodedRowBytes);
      destinationRow += encodedRowBytes;
      sourceRow += sourcePitchBytes;
    }
    return true;
  }

  /**
   * Address: 0x00447D90 (FUN_00447D90)
   */
  bool CopyBatchTextureDataFromMemBuffer(SBatchTextureData& outData, const gpg::MemBuffer<char>& sourceBuffer)
  {
    if (sourceBuffer.mBegin == nullptr) {
      return false;
    }

    const std::size_t sourceBytes = sourceBuffer.Size();
    outData.mDxt5Blocks.resize(sourceBytes);
    std::memcpy(outData.mDxt5Blocks.begin(), sourceBuffer.mBegin, sourceBytes);
    return true;
  }
}
