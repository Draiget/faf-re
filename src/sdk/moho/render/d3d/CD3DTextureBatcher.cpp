#include "moho/render/d3d/CD3DTextureBatcher.h"

#include <cstring>

#include "gpg/core/utils/BoostWrappers.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/ID3DTextureSheet.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "moho/render/textures/CD3DDynamicTextureSheet.h"

namespace moho
{
  namespace
  {
    using BatchTextureHandle = boost::shared_ptr<CD3DBatchTexture>;

    constexpr std::int32_t kCompositeWidth = 1024;
    constexpr std::int32_t kCompositeHeight = 1024;
    constexpr std::uint32_t kCompositeBytes = 0x00100000u;
    constexpr std::int32_t kDynamicTextureFormat = 12;

    /**
     * Address: 0x00448A30 (FUN_00448A30)
     *
     * What it does:
     * Copies one batch-texture shared handle into destination scratch storage.
     */
    [[nodiscard]] BatchTextureHandle* AssignBatchTextureHandle(
      BatchTextureHandle* const destination,
      const BatchTextureHandle& source
    )
    {
      *destination = source;
      return destination;
    }

    /**
     * Address: 0x00448B30 (FUN_00448B30)
     *
     * What it does:
     * Clears one atlas tree storage lane before destructor teardown.
     */
    void DestroyTextureAtlasStorage(CD3DTextureBatcher::TextureAtlasSet* const atlasStorage)
    {
      if (atlasStorage != nullptr) {
        atlasStorage->clear();
      }
    }

    /**
     * Address: 0x00448E10 (FUN_00448E10)
     *
     * What it does:
     * Releases one batch-texture shared handle scratch lane.
     */
    void ReleaseBatchTextureHandle(BatchTextureHandle* const scratchHandle)
    {
      if (scratchHandle != nullptr) {
        scratchHandle->reset();
      }
    }

    /**
     * Address: 0x004492D0 (FUN_004492D0, sub_4492D0)
     *
     * What it does:
     * Returns whether one 32-bit value lane is zero.
     */
    [[nodiscard]] bool IsZero(const std::uint32_t* const valueLane)
    {
      return valueLane != nullptr && *valueLane == 0u;
    }

    /**
     * Address: 0x007FC170 (FUN_007FC170)
     *
     * What it does:
     * Disposes one `sp_counted_impl_p<CD3DTextureBatcher>` payload by running
     * non-deleting `CD3DTextureBatcher` teardown and releasing owned storage.
     */
    void DisposeCountedTextureBatcherStorage(
      boost::SpCountedImplStorage<CD3DTextureBatcher>* const countedStorage
    )
    {
      CD3DTextureBatcher* const ownedBatcher = countedStorage->px;
      if (ownedBatcher != nullptr) {
        ownedBatcher->~CD3DTextureBatcher();
        ::operator delete(static_cast<void*>(ownedBatcher));
      }
    }
  } // namespace

  /**
   * Address: 0x00448FC0 (FUN_00448FC0)
   *
   * What it does:
   * Orders atlas entries by shared-owner control block, then raw pointee.
   */
  bool CD3DTextureBatcher::TextureAtlasEntryLess::operator()(
    const TextureAtlasEntry& lhs,
    const TextureAtlasEntry& rhs
  ) const noexcept
  {
    const boost::SharedPtrRaw<CD3DBatchTexture> lhsRaw = boost::SharedPtrRawFromSharedBorrow(lhs.mTexture);
    const boost::SharedPtrRaw<CD3DBatchTexture> rhsRaw = boost::SharedPtrRawFromSharedBorrow(rhs.mTexture);

    if (lhsRaw.pi == rhsRaw.pi) {
      return lhsRaw.px < rhsRaw.px;
    }
    return lhsRaw.pi < rhsRaw.pi;
  }

  /**
   * Address: 0x00448A60 (FUN_00448A60)
   *
   * What it does:
   * Initializes the 1024x1024 composite atlas, allocates one byte-packed
   * backing store, and creates one dynamic texture sheet.
   */
  CD3DTextureBatcher::CD3DTextureBatcher()
    : mWidth(kCompositeWidth)
    , mHeight(kCompositeHeight)
    , mRects()
    , mDynTexSheet()
    , mMap()
    , mDirty(0)
    , mPad2D{0, 0, 0}
    , mPixels()
  {
    if (CD3DDevice* const device = D3D_GetDevice(); device != nullptr) {
      if (ID3DDeviceResources* const resources = device->GetResources(); resources != nullptr) {
        (void)resources->NewDynamicTextureSheet(
          mDynTexSheet,
          kCompositeWidth,
          kCompositeHeight,
          kDynamicTextureFormat
        );
      }
    }

    mPixels.resize(kCompositeBytes);
    Reset();
  }

  /**
   * Address: 0x00448B60 (FUN_00448B60)
   *
   * What it does:
   * Releases atlas buffers, tree nodes, and retained dynamic-sheet ownership.
   */
  CD3DTextureBatcher::~CD3DTextureBatcher()
  {
    DestroyTextureAtlasStorage(&mMap);
  }

  /**
   * Address: 0x00448C30 (FUN_00448C30)
   *
   * What it does:
   * Returns cached UVs for one batch texture or allocates new atlas space,
   * uploads the texture payload, and stores one new UV mapping.
   */
  const gpg::Rect2f* CD3DTextureBatcher::AddTexture(const boost::shared_ptr<CD3DBatchTexture>& texture)
  {
    if (!texture) {
      return nullptr;
    }

    TextureAtlasEntry lookupEntry{};
    (void)AssignBatchTextureHandle(&lookupEntry.mTexture, texture);

    TextureAtlasSet::iterator found = mMap.find(lookupEntry);
    if (found == mMap.end()) {
      gpg::Rect2i allocatedRect{};
      const int border = static_cast<int>(texture->mBorder);
      const int requiredWidth = (static_cast<int>(texture->mWidth) + (2 * border) + 3) & ~3;
      const int requiredHeight = (static_cast<int>(texture->mHeight) + (2 * border) + 3) & ~3;

      if (!FindRect(allocatedRect, requiredWidth, requiredHeight)) {
        return nullptr;
      }

      AllocateRect(allocatedRect);

      TextureAtlasEntry insertedEntry{};
      BatchTextureHandle insertionScratch;
      (void)AssignBatchTextureHandle(&insertionScratch, texture);
      (void)AssignBatchTextureHandle(&insertedEntry.mTexture, insertionScratch);
      insertedEntry.mUvRect.x0 = static_cast<float>(border + allocatedRect.x0) / static_cast<float>(mWidth);
      insertedEntry.mUvRect.z0 = static_cast<float>(border + allocatedRect.z0) / static_cast<float>(mHeight);
      insertedEntry.mUvRect.x1 = static_cast<float>(allocatedRect.x1 - border) / static_cast<float>(mWidth);
      insertedEntry.mUvRect.z1 = static_cast<float>(allocatedRect.z1 - border) / static_cast<float>(mHeight);

      found = mMap.insert(insertedEntry).first;
      ReleaseBatchTextureHandle(&insertionScratch);

      const std::size_t destinationOffset =
        (static_cast<std::size_t>(mWidth) * static_cast<std::size_t>(allocatedRect.z0)) +
        (static_cast<std::size_t>(allocatedRect.x0) * 4u);
      texture->BuildTextureData(mPixels.begin() + destinationOffset, static_cast<std::uint32_t>(4 * mWidth));
      mDirty = 1;
    }

    return &found->mUvRect;
  }

  /**
   * Address: 0x00448E50 (FUN_00448E50)
   *
   * What it does:
   * Clears atlas mappings/free-rect lanes, restores one full free rectangle,
   * and zeroes the byte buffer.
   */
  void CD3DTextureBatcher::Reset()
  {
    mMap.clear();
    mRects.clear();

    const gpg::Rect2i fullRect{0, 0, mWidth, mHeight};
    AddAvailableRect(fullRect);

    if (mPixels.begin() != nullptr) {
      std::memset(mPixels.begin(), 0, static_cast<std::size_t>(mPixels.end() - mPixels.begin()));
    }

    mDirty = 1;
  }

  /**
   * Address: 0x00448EF0 (FUN_00448EF0)
   *
   * What it does:
   * Uploads dirty atlas bytes to the dynamic texture and returns the retained
   * sheet handle as `ID3DTextureSheet`.
   */
  boost::shared_ptr<ID3DTextureSheet> CD3DTextureBatcher::GetCompositeTexture()
  {
    const std::uint32_t dirtyLane = static_cast<std::uint32_t>(mDirty);
    if (!IsZero(&dirtyLane)) {
      std::uint32_t pitch = 0;
      void* lockedBits = nullptr;

      if (mDynTexSheet && mDynTexSheet->Lock(&pitch, &lockedBits)) {
        if (pitch == static_cast<std::uint32_t>(4 * mWidth)) {
          std::memcpy(
            lockedBits,
            mPixels.begin(),
            static_cast<std::size_t>(mWidth) * static_cast<std::size_t>(mHeight)
          );
        } else {
          const std::uint32_t rowCount = static_cast<std::uint32_t>(mHeight) >> 2;
          for (std::uint32_t row = 0; row < rowCount; ++row) {
            std::memcpy(
              static_cast<std::uint8_t*>(lockedBits) + (static_cast<std::size_t>(pitch) * row),
              mPixels.begin() + (static_cast<std::size_t>(row) * static_cast<std::size_t>(mWidth)),
              static_cast<std::size_t>(4 * mWidth)
            );
          }
        }
        (void)mDynTexSheet->Unlock();
      }

      mDirty = 0;
    }

    boost::shared_ptr<ID3DTextureSheet> outTexture = mDynTexSheet;
    return outTexture;
  }

  /**
   * Address: 0x00448FE0 (FUN_00448FE0)
   *
   * What it does:
   * Selects the best-fit free rectangle (top-most, then left-most) that can
   * fit the requested dimensions.
   */
  bool CD3DTextureBatcher::FindRect(gpg::Rect2i& outRect, const int width, const int height) const
  {
    bool found = false;
    for (gpg::Rect2i* it = mRects.begin(); it != mRects.end(); ++it) {
      const gpg::Rect2i& candidate = *it;
      if (width > (candidate.x1 - candidate.x0)) {
        continue;
      }
      if (height > (candidate.z1 - candidate.z0)) {
        continue;
      }

      if (!found ||
          candidate.z0 < outRect.z0 ||
          (candidate.z0 == outRect.z0 && candidate.x0 < outRect.x0)) {
        outRect.x0 = candidate.x0;
        outRect.z0 = candidate.z0;
        outRect.x1 = candidate.x0 + width;
        outRect.z1 = candidate.z0 + height;
        found = true;
      }
    }

    return found;
  }

  /**
   * Address: 0x00449060 (FUN_00449060, sub_449060)
   *
   * What it does:
   * Removes one allocated rectangle from the free list and re-inserts
   * remaining split fragments.
   */
  void CD3DTextureBatcher::AllocateRect(const gpg::Rect2i& allocatedRect)
  {
    AvailableRectVector currentRects(mRects);
    mRects.clear();

    for (gpg::Rect2i* it = currentRects.begin(); it != currentRects.end(); ++it) {
      const gpg::Rect2i freeRect = *it;

      const bool noStrictOverlap =
        allocatedRect.x0 >= freeRect.x1 ||
        freeRect.x0 >= allocatedRect.x1 ||
        allocatedRect.z0 >= freeRect.z1 ||
        freeRect.z0 >= allocatedRect.z1 ||
        allocatedRect.x0 >= allocatedRect.x1 ||
        allocatedRect.z0 >= allocatedRect.z1 ||
        freeRect.x0 >= freeRect.x1 ||
        freeRect.z0 >= freeRect.z1;

      if (noStrictOverlap) {
        AddAvailableRect(freeRect);
        continue;
      }

      if (freeRect.x0 < allocatedRect.x0) {
        AddAvailableRect({freeRect.x0, freeRect.z0, allocatedRect.x0, freeRect.z1});
      }
      if (freeRect.z0 < allocatedRect.z0) {
        AddAvailableRect({freeRect.x0, freeRect.z0, freeRect.x1, allocatedRect.z0});
      }
      if (freeRect.x1 > allocatedRect.x1) {
        AddAvailableRect({allocatedRect.x1, freeRect.z0, freeRect.x1, freeRect.z1});
      }
      if (freeRect.z1 > allocatedRect.z1) {
        AddAvailableRect({freeRect.x0, allocatedRect.z1, freeRect.x1, freeRect.z1});
      }
    }
  }

  /**
   * Address: 0x004491F0 (FUN_004491F0, Moho::CD3DTextureBatcher::AddAvailableRect)
   *
   * What it does:
   * Inserts one free rectangle while removing dominated fragments and skipping
   * insertion when fully covered by an existing entry.
   */
  void CD3DTextureBatcher::AddAvailableRect(const gpg::Rect2i& rect)
  {
    gpg::Rect2i* writeIt = mRects.begin();

    for (gpg::Rect2i* readIt = mRects.begin(); readIt != mRects.end(); ++readIt) {
      const gpg::Rect2i& current = *readIt;

      if (current.x0 <= rect.x0) {
        if (current.x1 >= rect.x1 &&
            rect.z0 >= current.z0 &&
            current.z1 >= rect.z1) {
          return;
        }
        if (current.x0 < rect.x0) {
          if (writeIt != readIt) {
            *writeIt = current;
          }
          ++writeIt;
          continue;
        }
      }

      if (rect.x1 < current.x1 || current.z0 < rect.z0 || rect.z1 < current.z1) {
        if (writeIt != readIt) {
          *writeIt = current;
        }
        ++writeIt;
      }
    }

    if (writeIt != mRects.end()) {
      mRects.erase(writeIt, mRects.end());
    }

    mRects.push_back(rect);
  }
} // namespace moho
