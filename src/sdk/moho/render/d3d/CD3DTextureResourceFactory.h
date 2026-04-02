#pragma once

#include "boost/shared_ptr.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "moho/resource/ResourceFactory.h"

namespace moho
{
  class RD3DTextureResource;

  class CD3DTextureResourceFactory : public ResourceFactoryBase
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
    void Init() override;

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
     * Address: 0x004AA9DE / 0x004AAA09 call lane in FUN_004AA690
     *
     * What it does:
     * Type-erased load dispatch adapter used by ResourceManager.
     */
    boost::SharedCountPair* LoadResourcePair(
      boost::SharedCountPair* outResourcePair,
      const char* path,
      gpg::RType* resourceType
    ) override;

    /**
     * Address: 0x004AB371 call lane in FUN_004AB180
     *
     * What it does:
     * Type-erased preload dispatch adapter used by prefetch-thread lanes.
     */
    boost::SharedCountPair* PreloadResourcePair(
      boost::SharedCountPair* outPrefetchPair,
      const char* path,
      gpg::RType* resourceType
    ) override;

    /**
     * Address: 0x004AA845 call lane in FUN_004AA690
     *
     * What it does:
     * Type-erased load-from-prefetch adapter used by ResourceManager.
     */
    boost::SharedCountPair* LoadResourceFromPrefetchPair(
      boost::SharedCountPair* outResourcePair,
      const char* path,
      gpg::RType* resourceType,
      const boost::SharedCountPair* prefetchPair,
      gpg::RType* prefetchType
    ) override;

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

  /**
   * Address: 0x0043E410 (FUN_0043E410, func_CreateTextureResourceFactory)
   *
   * What it does:
   * Returns the texture-factory singleton after its constructor lane has run.
   */
  [[nodiscard]] CD3DTextureResourceFactory* func_CreateTextureResourceFactory();

  /**
   * Address: 0x0043E430 (FUN_0043E430, unregister_TextureResourceFactoryPrimary)
   *
   * What it does:
   * Runs one texture-factory registration lane against the resource-manager singleton.
   */
  void unregister_TextureResourceFactoryPrimary();

  /**
   * Address: 0x0043E470 (FUN_0043E470, ??0ResourceFactoryPreload@Moho@@QAE@@Z)
   *
   * What it does:
   * Runs the preload-constructor registration lane for the texture-factory singleton.
   */
  [[nodiscard]] CD3DTextureResourceFactory* construct_TextureResourceFactoryPreload();

  /**
   * Address: 0x00BC4210 (FUN_00BC4210, register_CD3DTextureResourceFactory)
   *
   * What it does:
   * Runs texture-factory preload construction and registers process-exit
   * cleanup for the startup factory slot.
   */
  void register_CD3DTextureResourceFactory();

  /**
   * Address: 0x00BEF310 (FUN_00BEF310, cleanup_CD3DTextureResourceFactory)
   *
   * What it does:
   * Detaches the startup texture-factory registration lane from the resource
   * manager during process-exit teardown.
   */
  void cleanup_CD3DTextureResourceFactory();

  /**
   * Address: 0x00BC4230 (FUN_00BC4230, register_PrefetchType_d3d_textures)
   *
   * What it does:
   * Resolves `RD3DTextureResource` type metadata and registers the
   * `"d3d_textures"` prefetch lane.
   */
  void register_PrefetchType_d3d_textures();

  /**
   * Address: 0x0043E4C0 (FUN_0043E4C0, unregister_TextureResourceFactorySecondary)
   *
   * What it does:
   * Runs the second texture-factory registration lane against the resource-manager singleton.
   */
  void unregister_TextureResourceFactorySecondary();

  static_assert(sizeof(CD3DTextureResourceFactory) == 0x04, "CD3DTextureResourceFactory size must be 0x04");
} // namespace moho
