#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "gpg/core/containers/Rect2.h"
#include "legacy/containers/Set.h"
#include "legacy/containers/Vector.h"

namespace moho
{
  class CD3DBatchTexture;
  class CD3DDynamicTextureSheet;
  class ID3DTextureSheet;

  /**
   * VFTABLE: none (plain helper owner)
   *
   * What it does:
   * Packs multiple `CD3DBatchTexture` payloads into one dynamic texture sheet
   * and returns cached UV rectangles keyed by source texture handle.
   */
  class CD3DTextureBatcher final
  {
  public:
    struct TextureAtlasEntry
    {
      boost::shared_ptr<CD3DBatchTexture> mTexture; // +0x00
      gpg::Rect2f mUvRect;                          // +0x08
    };

    struct TextureAtlasEntryLess
    {
      /**
       * Address: 0x00448FC0 (FUN_00448FC0)
       *
       * What it does:
       * Orders atlas entries by shared-owner control block, then raw pointee.
       */
      [[nodiscard]] bool operator()(const TextureAtlasEntry& lhs, const TextureAtlasEntry& rhs) const noexcept;
    };

    using AvailableRectVector = msvc8::vector<gpg::Rect2i>;
    using DynamicTextureSheetHandle = boost::shared_ptr<CD3DDynamicTextureSheet>;
    using TextureAtlasSet = msvc8::set<TextureAtlasEntry, TextureAtlasEntryLess>;
    using PixelByteVector = msvc8::vector<std::uint8_t>;

    /**
     * Address: 0x00448A60 (FUN_00448A60)
     *
     * What it does:
     * Initializes the 1024x1024 composite atlas, allocates one byte-packed
     * backing store, and creates one dynamic texture sheet.
     */
    CD3DTextureBatcher();

    /**
     * Address: 0x00448B60 (FUN_00448B60)
     *
     * What it does:
     * Releases atlas buffers, tree nodes, and retained dynamic-sheet ownership.
     */
    ~CD3DTextureBatcher();

    /**
     * Address: 0x00448C30 (FUN_00448C30)
     *
     * What it does:
     * Returns cached UVs for one batch texture or allocates new atlas space,
     * uploads the texture payload, and stores one new UV mapping.
     */
    [[nodiscard]] const gpg::Rect2f* AddTexture(const boost::shared_ptr<CD3DBatchTexture>& texture);

    /**
     * Address: 0x00448E50 (FUN_00448E50)
     *
     * What it does:
     * Clears atlas mappings/free-rect lanes, restores one full free rectangle,
     * and zeroes the byte buffer.
     */
    void Reset();

    /**
     * Address: 0x00448EF0 (FUN_00448EF0)
     *
     * What it does:
     * Uploads dirty atlas bytes to the dynamic texture and returns the retained
     * sheet handle as `ID3DTextureSheet`.
     */
    [[nodiscard]] boost::shared_ptr<ID3DTextureSheet> GetCompositeTexture();

  private:
    /**
     * Address: 0x00448FE0 (FUN_00448FE0)
     *
     * What it does:
     * Selects the best-fit free rectangle (top-most, then left-most) that can
     * fit the requested dimensions.
     */
    [[nodiscard]] bool FindRect(gpg::Rect2i& outRect, int width, int height) const;

    /**
     * Address: 0x00449060 (FUN_00449060, sub_449060)
     *
     * What it does:
     * Removes one allocated rectangle from the free list and re-inserts
     * remaining split fragments.
     */
    void AllocateRect(const gpg::Rect2i& allocatedRect);

    /**
     * Address: 0x004491F0 (FUN_004491F0, Moho::CD3DTextureBatcher::AddAvailableRect)
     *
     * What it does:
     * Inserts one free rectangle while removing dominated fragments and skipping
     * insertion when fully covered by an existing entry.
     */
    void AddAvailableRect(const gpg::Rect2i& rect);

  public:
    std::int32_t mWidth;                    // +0x00
    std::int32_t mHeight;                   // +0x04
    AvailableRectVector mRects;             // +0x08
    DynamicTextureSheetHandle mDynTexSheet; // +0x18
    TextureAtlasSet mMap;                   // +0x20
    std::uint8_t mDirty;                    // +0x2C
    std::uint8_t mPad2D[0x03];              // +0x2D
    PixelByteVector mPixels;                // +0x30
  };

  static_assert(sizeof(CD3DTextureBatcher::TextureAtlasEntry) == 0x18, "CD3DTextureBatcher::TextureAtlasEntry size must be 0x18");
  static_assert(offsetof(CD3DTextureBatcher, mWidth) == 0x00, "CD3DTextureBatcher::mWidth offset must be 0x00");
  static_assert(offsetof(CD3DTextureBatcher, mHeight) == 0x04, "CD3DTextureBatcher::mHeight offset must be 0x04");
  static_assert(offsetof(CD3DTextureBatcher, mRects) == 0x08, "CD3DTextureBatcher::mRects offset must be 0x08");
  static_assert(offsetof(CD3DTextureBatcher, mDynTexSheet) == 0x18, "CD3DTextureBatcher::mDynTexSheet offset must be 0x18");
  static_assert(offsetof(CD3DTextureBatcher, mMap) == 0x20, "CD3DTextureBatcher::mMap offset must be 0x20");
  static_assert(offsetof(CD3DTextureBatcher, mDirty) == 0x2C, "CD3DTextureBatcher::mDirty offset must be 0x2C");
  static_assert(offsetof(CD3DTextureBatcher, mPixels) == 0x30, "CD3DTextureBatcher::mPixels offset must be 0x30");
  static_assert(sizeof(CD3DTextureBatcher) == 0x40, "CD3DTextureBatcher size must be 0x40");
} // namespace moho
