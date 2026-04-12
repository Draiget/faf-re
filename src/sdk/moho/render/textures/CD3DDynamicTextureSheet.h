#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/gal/TextureContext.hpp"
#include "moho/containers/TDatList.h"
#include "moho/render/ID3DTextureSheet.h"
#include "Wm3Vector2.h"
#include "Wm3Vector3.h"

namespace moho
{
  class CD3DDevice;

  class CD3DDynamicTextureSheet : public ID3DTextureSheet
  {
  public:
    using TextureHandle = ID3DTextureSheet::TextureHandle;

    /**
     * Address: 0x0043CE40 (FUN_0043CE40, Moho::CD3DDynamicTextureSheet::CD3DDynamicTextureSheet)
     *
     * CD3DDevice *,bool,std::uint32_t,std::uint32_t,std::uint32_t,bool
     *
     * What it does:
     * Initializes intrusive-list linkage and texture context metadata for one
     * dynamic texture sheet instance.
     */
    explicit CD3DDynamicTextureSheet(
      CD3DDevice* device = nullptr,
      bool archiveTextureMode = false,
      std::uint32_t width = 0,
      std::uint32_t height = 0,
      std::uint32_t format = 0,
      bool dynamicUsage = false
    );

    /**
     * Address: 0x0043CF90 (FUN_0043CF90, deleting thunk)
     * Address: 0x0043CED0 (FUN_0043CED0, non-deleting body)
     *
     * What it does:
     * Releases retained texture/context ownership and unlinks this sheet from
     * its intrusive list.
     */
    ~CD3DDynamicTextureSheet() override;

    /**
     * Address: 0x0043E630 (FUN_0043E630)
     *
     * Wm3::Vector3f *
     *
     * What it does:
     * Copies retained texture width/height into caller output.
     */
    Wm3::Vector3f* GetDimensions(Wm3::Vector3f* outDimensions) override;

    /**
     * Address: 0x0043CF70 (FUN_0043CF70)
     *
     * Wm3::Vector2i *
     *
     * What it does:
     * Writes zeroed original-dimensions payload into caller output lane.
     */
    Wm3::Vector2i* GetOriginalDimensions(Wm3::Vector2i* outDimensions) override;

    /**
     * Address: 0x0043E680 (FUN_0043E680)
     *
     * What it does:
     * Returns retained texture byte-size metadata from wrapped texture context.
     */
    int GetTextureSizeInBytes() override;

    /**
     * Address: 0x0043E690 (FUN_0043E690)
     *
     * boost::shared_ptr<gpg::gal::TextureD3D9> &
     *
     * What it does:
     * Copies retained texture ownership into caller storage.
     */
    TextureHandle& GetTexture(TextureHandle& outTexture) override;

    /**
     * Address: 0x0043E6C0 (FUN_0043E6C0)
     *
     * std::uint32_t *,void **
     *
     * What it does:
     * Locks the full texture level and returns mapped pitch + byte pointer.
     */
    bool Lock(std::uint32_t* outPitch, void** outBits) override;

    /**
     * Address: 0x0043E7A0 (FUN_0043E7A0)
     *
     * RECT const *,std::uint32_t *,void **
     *
     * What it does:
     * Locks one caller-provided texture rectangle and returns pitch + byte pointer.
     */
    bool LockRect(const RECT* rect, std::uint32_t* outPitch, void** outBits) override;

    /**
     * Address: 0x0043E870 (FUN_0043E870)
     *
     * What it does:
     * Unlocks retained texture level 0.
     */
    bool Unlock() override;

    /**
     * Address: 0x0043E8E0 (FUN_0043E8E0)
     *
     * gpg::BinaryReader *
     *
     * What it does:
     * Reads raw texture bytes from archive and recreates the wrapped texture.
     */
    bool ReadFromArchive(gpg::BinaryReader* reader) override;

    /**
     * Address: 0x0043EAA0 (FUN_0043EAA0)
     *
     * gpg::Stream *,bool
     *
     * What it does:
     * Saves retained texture bytes to stream, with optional byte-count prefix.
     */
    bool SaveToArchive(gpg::Stream* stream, bool writeSizeHeader) override;

    /**
     * Address: 0x00442940 (FUN_00442940)
     *
     * What it does:
     * Recreates retained texture ownership from the current texture context.
     */
    bool CreateTexture();

  public:
    TDatListItem<CD3DDynamicTextureSheet, void> mLink; // +0x04
    CD3DDevice* mDevice;                               // +0x0C
    TextureHandle mTexture;                            // +0x10
    gpg::gal::TextureContext mContext;                 // +0x18
    bool mArchiveTextureMode;                          // +0x6C
    std::uint8_t mPad6D[0x03];                         // +0x6D
  };

  static_assert(sizeof(CD3DDynamicTextureSheet::TextureHandle) == 0x08, "CD3DDynamicTextureSheet::TextureHandle size must be 0x08");
  static_assert(offsetof(CD3DDynamicTextureSheet, mLink) == 0x04, "CD3DDynamicTextureSheet::mLink offset must be 0x04");
  static_assert(offsetof(CD3DDynamicTextureSheet, mDevice) == 0x0C, "CD3DDynamicTextureSheet::mDevice offset must be 0x0C");
  static_assert(offsetof(CD3DDynamicTextureSheet, mTexture) == 0x10, "CD3DDynamicTextureSheet::mTexture offset must be 0x10");
  static_assert(offsetof(CD3DDynamicTextureSheet, mContext) == 0x18, "CD3DDynamicTextureSheet::mContext offset must be 0x18");
  static_assert(
    offsetof(CD3DDynamicTextureSheet, mArchiveTextureMode) == 0x6C,
    "CD3DDynamicTextureSheet::mArchiveTextureMode offset must be 0x6C"
  );
  static_assert(sizeof(CD3DDynamicTextureSheet) == 0x70, "CD3DDynamicTextureSheet size must be 0x70");
} // namespace moho
