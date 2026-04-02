#include "moho/render/textures/CD3DRawBatchTexture.h"

#include <cstring>

#include "moho/render/textures/DXTCodec.h"
#include "moho/render/textures/SBatchTextureData.h"

namespace moho
{
  /**
   * Address: 0x00448120 (FUN_00448120, Moho::CD3DRawBatchTexture::CD3DRawBatchTexture)
   */
  CD3DRawBatchTexture::CD3DRawBatchTexture(const DataHandle& data, const std::uint32_t border)
    : CD3DBatchTexture(data->mWidth - (2u * border), data->mHeight - (2u * border), border)
    , mData(data)
  {
  }

  /**
   * Address: 0x004481D0 (FUN_004481D0, Moho::CD3DRawBatchTexture::dtr)
   * Address: 0x004481F0 (FUN_004481F0, helper lane)
   */
  CD3DRawBatchTexture::~CD3DRawBatchTexture()
  {
    mData.reset();
  }

  /**
   * Address: 0x00448180 (FUN_00448180, Moho::CD3DRawBatchTexture::Func1)
   */
  void CD3DRawBatchTexture::BuildTextureData(void* const destination, const std::uint32_t destinationPitchBytes)
  {
    if (destination == nullptr || !mData) {
      return;
    }

    const std::size_t encodedRowBytes = static_cast<std::size_t>(16u * DXT_BlockCount(mData->mWidth));
    const std::size_t encodedRows = static_cast<std::size_t>(DXT_BlockCount(mData->mHeight));

    const std::uint8_t* sourceRow = mData->mDxt5Blocks.begin();
    std::uint8_t* destinationRow = static_cast<std::uint8_t*>(destination);

    for (std::size_t row = 0; row < encodedRows; ++row) {
      std::memcpy(destinationRow, sourceRow, encodedRowBytes);
      destinationRow += destinationPitchBytes;
      sourceRow += encodedRowBytes;
    }
  }

  /**
   * Address: 0x00448190 (FUN_00448190, Moho::CD3DRawBatchTexture::GetAlphaAt)
   */
  std::uint8_t CD3DRawBatchTexture::GetAlphaAt(const std::uint32_t x, const std::uint32_t y) const
  {
    if (!mData) {
      return 0;
    }

    return DXT_GetTexelAlpha(
      mBorder + y,
      mData->mDxt5Blocks.begin(),
      mBorder + x,
      static_cast<std::uint32_t>(16u * DXT_BlockCount(mData->mWidth))
    );
  }
} // namespace moho

