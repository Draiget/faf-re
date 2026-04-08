#include "moho/render/textures/CD3DBatchTexture.h"

#include <bit>
#include <cstdint>
#include <new>
#include <type_traits>

#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/ID3DTextureSheet.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/textures/CD3DRawBatchTexture.h"
#include "moho/render/textures/CD3DDynamicTextureSheet.h"
#include "moho/render/textures/DeviceExitListener.h"
#include "moho/render/textures/SBatchTextureData.h"

namespace
{
  template <typename TUnsigned>
  [[nodiscard]] TUnsigned AlignToPowerOfTwo(const TUnsigned value)
  {
    static_assert(std::is_unsigned_v<TUnsigned>, "AlignToPowerOfTwo requires an unsigned integer type");
    return std::bit_ceil(value == 0 ? static_cast<TUnsigned>(1) : value);
  }
} // namespace

namespace moho
{
  boost::mutex sResourceLock{};

  /**
   * Address: 0x00BC4340 (FUN_00BC4340, register_sResourceLock)
   */
  void register_sResourceLock()
  {
    (void)sResourceLock;
  }

  /**
   * Address: 0x004470F0 (FUN_004470F0)
   */
  CD3DBatchTexture::CD3DBatchTexture(const std::uint32_t width, const std::uint32_t height, const std::uint32_t border)
    : mListLink()
    , mWidth(width)
    , mHeight(height)
    , mBorder(border)
    , mTextureSheet()
  {
    mListLink.ListResetLinks();
  }

  /**
   * Address: 0x00447170 (FUN_00447170, deleting-thunk lane)
   * Address: 0x00447490 (FUN_00447490, non-deleting body)
   */
  CD3DBatchTexture::~CD3DBatchTexture()
  {
    ResetTextureSheet();
    mListLink.ListUnlink();
  }

  /**
   * Address: 0x00447120 (FUN_00447120)
   */
  void CD3DBatchTexture::ResetTextureSheet()
  {
    mTextureSheet.reset();
  }

  /**
   * Address: 0x00447160 (FUN_00447160)
   */
  std::uint32_t CD3DBatchTexture::GetBorder() const
  {
    return mBorder;
  }

  /**
   * Address: 0x00447520 (FUN_00447520, Moho::CD3DBatchTexture::GetTextureSheet)
   */
  CD3DBatchTexture::TextureSheetHandle& CD3DBatchTexture::GetTextureSheet(
    TextureSheetHandle& outTextureSheet, Wm3::Vector2f& outUvScale, Wm3::Vector2f& outUvBorder
  )
  {
    const std::uint32_t paddedWidth = mWidth + (mBorder * 2u);
    const std::uint32_t paddedHeight = mHeight + (mBorder * 2u);
    const std::uint32_t sheetWidth = AlignToPowerOfTwo(paddedWidth);
    const std::uint32_t sheetHeight = AlignToPowerOfTwo(paddedHeight);

    if (!mTextureSheet) {
      if (CD3DDevice* const device = D3D_GetDevice(); device != nullptr) {
        if (ID3DDeviceResources* const resources = device->GetResources(); resources != nullptr) {
          (void)resources->NewDynamicTextureSheet(
            mTextureSheet,
            static_cast<int>(sheetWidth),
            static_cast<int>(sheetHeight),
            12
          );
        }
      }

      if (mTextureSheet) {
        D3DLOCKED_RECT lockedRect{};
        if (mTextureSheet->Lock(reinterpret_cast<std::uint32_t*>(&lockedRect.Pitch), &lockedRect.pBits)) {
          BuildTextureData(lockedRect.pBits, static_cast<std::uint32_t>(lockedRect.Pitch));
          (void)mTextureSheet->Unlock();
        }

        AddExitListener();
      }
    }

    const float border = static_cast<float>(mBorder);
    outUvBorder.x = border / static_cast<float>(sheetWidth);
    outUvBorder.y = border / static_cast<float>(sheetHeight);

    outUvScale.x = static_cast<float>(mWidth) / static_cast<float>(sheetWidth);
    outUvScale.y = static_cast<float>(mHeight) / static_cast<float>(sheetHeight);

    outTextureSheet = mTextureSheet;
    return outTextureSheet;
  }

  /**
   * Address: 0x004473C0 (FUN_004473C0, Moho::CD3DBatchTexture::AddExitListener)
   */
  void CD3DBatchTexture::AddExitListener()
  {
    if (sDeviceExitListener == nullptr) {
      void* const listenerStorage = ::operator new(sizeof(DeviceExitListener), std::nothrow);
      DeviceExitListener* const created = listenerStorage != nullptr ? new (listenerStorage) DeviceExitListener() : nullptr;

      DeviceExitListener* const previous = sDeviceExitListener;
      sDeviceExitListener = created;
      if (previous != nullptr) {
        previous->~DeviceExitListener();
      }
    }

    if (sDeviceExitListener != nullptr) {
      mListLink.ListLinkBefore(&sDeviceExitListener->mTrackedTextures);
    }
  }

  /**
   * Address: 0x00448270 (FUN_00448270, ?FromDXT5@CD3DBatchTexture@Moho@@...)
   * Address: 0x0044DED0 (FUN_0044DED0, shared_ptr<SBatchTextureData> ctor lane)
   * Address: 0x0044DEF0 (FUN_0044DEF0, shared_ptr<CD3DRawBatchTexture> ctor lane)
   * Address: 0x0044EAF0 (FUN_0044EAF0, shared_count<SBatchTextureData> ctor lane)
   * Address: 0x0044EB70 (FUN_0044EB70, shared_count<CD3DRawBatchTexture> ctor lane)
   */
  boost::shared_ptr<CD3DBatchTexture> CD3DBatchTexture::FromDXT5(
    const std::uint32_t width,
    const std::uint32_t height,
    const void* const dxt5Blocks,
    const std::uint32_t sourcePitchBytes
  )
  {
    boost::shared_ptr<CD3DBatchTexture> outTexture;

    boost::shared_ptr<SBatchTextureData> data(new (std::nothrow) SBatchTextureData());
    if (!data) {
      return outTexture;
    }

    if (!BuildBatchTextureDataFromRows(*data, width, height, dxt5Blocks, sourcePitchBytes)) {
      return outTexture;
    }

    boost::shared_ptr<CD3DRawBatchTexture> rawTexture(new (std::nothrow) CD3DRawBatchTexture(data, 0u));
    outTexture = rawTexture;
    return outTexture;
  }
} // namespace moho

namespace
{
  struct BatchTextureResourceLockBootstrap
  {
    BatchTextureResourceLockBootstrap()
    {
      moho::register_sResourceLock();
    }
  };

  BatchTextureResourceLockBootstrap gBatchTextureResourceLockBootstrap;
} // namespace
