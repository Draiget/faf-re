#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/gal/TextureContext.hpp"
#include "moho/containers/TDatList.h"
#include "moho/render/ID3DTextureSheet.h"
#include "wm3/Vector2.h"
#include "wm3/Vector3.h"

namespace moho
{
  class RD3DTextureResource : public ID3DTextureSheet
  {
  public:
    using TextureHandle = ID3DTextureSheet::TextureHandle;
    static gpg::RType* sType;

    /**
     * Address: 0x0043D710 (FUN_0043D710)
     *
     * const char *
     *
     * What it does:
     * Initializes intrusive resource links and seeds texture context from location.
     */
    explicit RD3DTextureResource(const char* location);

    /**
     * Address: 0x0043D7A0 (FUN_0043D7A0)
     *
     * const char *,void *,std::size_t
     *
     * What it does:
     * Initializes one archive-backed texture context from in-memory bytes.
     */
    RD3DTextureResource(const char* location, void* data, std::size_t size);

    /**
     * Address: 0x0043D780 (FUN_0043D780, deleting thunk)
     * Address: 0x0043D980 (FUN_0043D980, non-deleting body)
     *
     * What it does:
     * Releases retained base texture ownership, destroys context state, and unlinks
     * this resource from intrusive tracking list.
     */
    ~RD3DTextureResource() override;

    /**
     * Address: 0x0043DA20 (FUN_0043DA20)
     *
     * gpg::MemBuffer<const char>
     *
     * What it does:
     * Copies caller-provided texture-bytes payload into retained context data lane.
     */
    bool Init(gpg::MemBuffer<const char> data);

    /**
     * Address: 0x0043DBC0 (FUN_0043DBC0, Moho::RD3DTextureResource::ReloadTexture)
     *
     * What it does:
     * Re-maps texture source bytes from disk and rebuilds base texture data.
     */
    void ReloadTexture();

    /**
     * Address: 0x0043DD20 (FUN_0043DD20)
     *
     * Wm3::Vector3f *
     *
     * What it does:
     * Loads base texture on demand and returns current width/height as float vector.
     */
    Wm3::Vector3f* GetDimensions(Wm3::Vector3f* outDimensions) override;

    /**
     * Address: 0x0043DD70 (FUN_0043DD70)
     *
     * Wm3::Vector2i *
     *
     * What it does:
     * Loads base texture on demand and returns original integer width/height.
     */
    Wm3::Vector2i* GetOriginalDimensions(Wm3::Vector2i* outDimensions) override;

    /**
     * Address: 0x0043DDB0 (FUN_0043DDB0)
     *
     * What it does:
     * Loads base texture on demand and returns retained byte-size metadata.
     */
    int GetTextureSizeInBytes() override;

    /**
     * Address: 0x0043DDD0 (FUN_0043DDD0)
     *
     * boost::shared_ptr<gpg::gal::TextureD3D9> &
     *
     * What it does:
     * Loads base texture on demand and copies retained texture ownership.
     */
    TextureHandle& GetTexture(TextureHandle& outTexture) override;

    /**
     * Address: 0x0043DE10 (FUN_0043DE10)
     *
     * std::uint32_t *,void **
     *
     * What it does:
     * Preserves unreachable lock lane after forcing lazy texture load.
     */
    bool Lock(std::uint32_t* outPitch, void** outBits) override;

    /**
     * Address: 0x0043DE30 (FUN_0043DE30)
     *
     * RECT const *,std::uint32_t *,void **
     *
     * What it does:
     * Preserves unreachable rect-lock lane after forcing lazy texture load.
     */
    bool LockRect(const RECT* rect, std::uint32_t* outPitch, void** outBits) override;

    /**
     * Address: 0x0043DE50 (FUN_0043DE50)
     *
     * What it does:
     * Preserves unreachable unlock lane after forcing lazy texture load.
     */
    bool Unlock() override;

    /**
     * Address: 0x0043DE70 (FUN_0043DE70)
     *
     * gpg::BinaryReader *
     *
     * What it does:
     * Preserves unreachable archive-load lane after forcing lazy texture load.
     */
    bool ReadFromArchive(gpg::BinaryReader* reader) override;

    /**
     * Address: 0x0043DE90 (FUN_0043DE90)
     *
     * gpg::Stream *,bool
     *
     * What it does:
     * Preserves unreachable archive-save lane after forcing lazy texture load.
     */
    bool SaveToArchive(gpg::Stream* stream, bool writeSizeHeader) override;

  private:
    /**
     * Address: 0x0043DAA0 (FUN_0043DAA0)
     *
     * What it does:
     * Builds retained base texture from context data on first use and clears source bytes.
     */
    bool LoadTexture();

  public:
    TDatListItem<RD3DTextureResource, void> mResources; // +0x04
    gpg::gal::TextureContext mContext;                  // +0x0C
    TextureHandle mBaseTex;                             // +0x60
  };

  static_assert(sizeof(RD3DTextureResource::TextureHandle) == 0x08, "RD3DTextureResource::TextureHandle size must be 0x08");
  static_assert(offsetof(RD3DTextureResource, mResources) == 0x04, "RD3DTextureResource::mResources offset must be 0x04");
  static_assert(offsetof(RD3DTextureResource, mContext) == 0x0C, "RD3DTextureResource::mContext offset must be 0x0C");
  static_assert(offsetof(RD3DTextureResource, mBaseTex) == 0x60, "RD3DTextureResource::mBaseTex offset must be 0x60");
  static_assert(sizeof(RD3DTextureResource) == 0x68, "RD3DTextureResource size must be 0x68");
} // namespace moho
