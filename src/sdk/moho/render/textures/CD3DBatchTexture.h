#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/mutex.h"
#include "boost/shared_ptr.h"
#include "gpg/core/containers/String.h"
#include "moho/containers/TDatList.h"
#include "wm3/Vector2.h"

namespace moho
{
  class CD3DRawBatchTexture;
  class CD3DDynamicTextureSheet;
  class DeviceExitListener;
  class ID3DTextureSheet;

  /**
   * VFTABLE: 0x00E02A84
   * COL: 0x00E5FBF0
   */
  class CD3DBatchTexture
  {
    friend class DeviceExitListener;
    friend class CD3DTextureBatcher;

  public:
    using BatchTextureLink = TDatListItem<CD3DBatchTexture, void>;
    using TextureSheetHandle = boost::shared_ptr<ID3DTextureSheet>;
    using DynamicTextureSheetHandle = boost::shared_ptr<CD3DDynamicTextureSheet>;

    /**
     * Address: 0x00447170 (FUN_00447170, deleting-thunk lane)
     * Address: 0x00447490 (FUN_00447490, non-deleting body)
     *
     * What it does:
     * Releases retained dynamic-texture ownership and unlinks this texture from
     * the listener-tracked intrusive list.
     */
    virtual ~CD3DBatchTexture();

    /**
     * Address: 0x00447520 (FUN_00447520, Moho::CD3DBatchTexture::GetTextureSheet)
     *
     * boost::shared_ptr<moho::ID3DTextureSheet> &,Wm3::Vector2f &,Wm3::Vector2f &
     *
     * What it does:
     * Lazily creates one dynamic texture sheet for this batch texture, uploads
     * pixels through `BuildTextureData`, and returns UV scale/border factors.
     */
    TextureSheetHandle&
      GetTextureSheet(TextureSheetHandle& outTextureSheet, Wm3::Vector2f& outUvScale, Wm3::Vector2f& outUvBorder);

    /**
     * Address: 0x00447120 (FUN_00447120)
     *
     * What it does:
     * Releases retained dynamic texture-sheet ownership.
     */
    void ResetTextureSheet();

    /**
     * Address: 0x00447160 (FUN_00447160)
     *
     * What it does:
     * Returns the configured border texel count.
     */
    [[nodiscard]] std::uint32_t GetBorder() const;

    /**
     * Address: 0x004478C0 (?FromSolidColor@CD3DBatchTexture@Moho@@SA?AV?$shared_ptr@VCD3DBatchTexture@Moho@@@boost@@I@Z)
     *
     * What it does:
     * Returns one cached solid-color batch texture, creating it on first use.
     */
    [[nodiscard]] static boost::shared_ptr<CD3DBatchTexture> FromSolidColor(std::uint32_t rgba);

    /**
     * Address: 0x004486F0 (FUN_004486F0, Moho::CD3DBatchTexture::FromFile)
     *
     * gpg::StrArg,unsigned int
     *
     * What it does:
     * Loads one file-backed batch texture by cache key `(filename,border)`,
     * reusing retained file-texture instances when available.
     */
    [[nodiscard]] static boost::shared_ptr<CD3DBatchTexture> FromFile(gpg::StrArg filename, std::uint32_t border);

    /**
     * Address: 0x00448270 (FUN_00448270, Moho::CD3DBatchTexture::FromDXT5)
     *
     * unsigned int,unsigned int,void const *,unsigned int
     *
     * What it does:
     * Wraps caller-provided DXT5 block bytes into one `CD3DRawBatchTexture`
     * instance with zero border.
     */
    [[nodiscard]] static boost::shared_ptr<CD3DBatchTexture>
      FromDXT5(std::uint32_t width, std::uint32_t height, const void* dxt5Blocks, std::uint32_t sourcePitchBytes);

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * void *,unsigned int
     *
     * What it does:
     * Writes one texture payload into a locked dynamic-texture sheet surface.
     */
    virtual void BuildTextureData(void* destination, std::uint32_t destinationPitchBytes) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * unsigned int,unsigned int
     *
     * What it does:
     * Returns one alpha sample for the requested texel coordinate.
     */
    [[nodiscard]] virtual std::uint8_t GetAlphaAt(std::uint32_t x, std::uint32_t y) const = 0;

  protected:
    /**
     * Address: 0x004470F0 (FUN_004470F0)
     *
     * unsigned int,unsigned int,unsigned int
     *
     * What it does:
     * Initializes intrusive-list links, dimensions, border width, and clears the
     * retained dynamic-texture sheet handle.
     */
    CD3DBatchTexture(std::uint32_t width, std::uint32_t height, std::uint32_t border);

    /**
     * Address: 0x004473C0 (FUN_004473C0, Moho::CD3DBatchTexture::AddExitListener)
     *
     * What it does:
     * Ensures the process-wide device-exit listener exists and links this texture
     * into its tracked texture ring.
     */
    void AddExitListener();

  public:
    BatchTextureLink mListLink;              // +0x04
    std::uint32_t mWidth;                    // +0x0C
    std::uint32_t mHeight;                   // +0x10
    std::uint32_t mBorder;                   // +0x14
    DynamicTextureSheetHandle mTextureSheet; // +0x18
  };

  /**
   * Address: 0x00BC4340 (FUN_00BC4340, register_sResourceLock)
   *
   * What it does:
   * Startup thunk that ensures the shared batch-texture cache mutex is
   * materialized before texture-cache startup lanes run.
   */
  void register_sResourceLock();

  extern boost::mutex sResourceLock;

  static_assert(offsetof(CD3DBatchTexture, mListLink) == 0x04, "CD3DBatchTexture::mListLink offset must be 0x04");
  static_assert(offsetof(CD3DBatchTexture, mWidth) == 0x0C, "CD3DBatchTexture::mWidth offset must be 0x0C");
  static_assert(offsetof(CD3DBatchTexture, mHeight) == 0x10, "CD3DBatchTexture::mHeight offset must be 0x10");
  static_assert(offsetof(CD3DBatchTexture, mBorder) == 0x14, "CD3DBatchTexture::mBorder offset must be 0x14");
  static_assert(offsetof(CD3DBatchTexture, mTextureSheet) == 0x18, "CD3DBatchTexture::mTextureSheet offset must be 0x18");
  static_assert(sizeof(CD3DBatchTexture) == 0x20, "CD3DBatchTexture size must be 0x20");
} // namespace moho
