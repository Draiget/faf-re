#pragma once

#include "boost/shared_ptr.h"
#include "gpg/core/streams/MemBufferStream.h"

namespace moho
{
  class RD3DTextureResource;

  class CD3DTextureResourceFactory
  {
  public:
    using TextureResourceHandle = boost::shared_ptr<RD3DTextureResource>;
    using PrefetchData = gpg::MemBuffer<const char>;
    using PrefetchDataHandle = boost::shared_ptr<PrefetchData>;

    /**
     * Address: 0x004434E0 (FUN_004434E0)
     *
     * What it does:
     * Preserves base init lane for preload-capable texture resource factory.
     */
    virtual void Init();

    /**
     * Address: 0x00443530 (FUN_00443530)
     *
     * boost::shared_ptr<RD3DTextureResource> &,const char *
     *
     * What it does:
     * Forwards texture load requests into implementation lane.
     */
    virtual TextureResourceHandle& Load(TextureResourceHandle& outTexture, const char* path);

    /**
     * Address: 0x004435E0 (FUN_004435E0)
     *
     * boost::shared_ptr<gpg::MemBuffer<const char>> &,const char *
     *
     * What it does:
     * Forwards texture prefetch requests into implementation lane.
     */
    virtual PrefetchDataHandle& Preload(PrefetchDataHandle& outPrefetchData, const char* path);

    /**
     * Address: 0x00443690 (FUN_00443690)
     *
     * boost::shared_ptr<RD3DTextureResource> &,const char *,boost::shared_ptr<gpg::MemBuffer<const char>>
     *
     * What it does:
     * Forwards load-from-prefetched-data requests into implementation lane.
     */
    virtual TextureResourceHandle&
      LoadFrom(TextureResourceHandle& outTexture, const char* path, PrefetchDataHandle prefetchData);

    /**
     * Address: 0x0043DED0 (FUN_0043DED0)
     *
     * boost::shared_ptr<RD3DTextureResource> &,const char *
     *
     * What it does:
     * Loads one texture file payload and initializes one RD3DTextureResource instance.
     */
    virtual TextureResourceHandle& LoadImpl(TextureResourceHandle& outTexture, const char* path);

    /**
     * Address: 0x0043E0C0 (FUN_0043E0C0)
     *
     * boost::shared_ptr<gpg::MemBuffer<const char>> &,const char *
     *
     * What it does:
     * Loads one texture file payload into prefetch shared buffer wrapper.
     */
    virtual PrefetchDataHandle& PreloadImpl(PrefetchDataHandle& outPrefetchData, const char* path);

    /**
     * Address: 0x0043E200 (FUN_0043E200)
     *
     * boost::shared_ptr<RD3DTextureResource> &,const char *,boost::shared_ptr<gpg::MemBuffer<const char>>
     *
     * What it does:
     * Builds one RD3DTextureResource from already-prefetched bytes.
     */
    virtual TextureResourceHandle&
      LoadFromImpl(TextureResourceHandle& outTexture, const char* path, PrefetchDataHandle prefetchData);
  };

  static_assert(sizeof(CD3DTextureResourceFactory) == 0x04, "CD3DTextureResourceFactory size must be 0x04");
} // namespace moho
