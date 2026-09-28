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
     * Address: 0x0043E410 (FUN_0043E410, Moho::CD3DTextureResourceFactory::CD3DTextureResourceFactory)
     * Address: 0x0043E470 (FUN_0043E470, ??0ResourceFactoryPreload@Moho@@QAE@@Z)
     *
     * What it does:
     * Out-of-line copies of the constructor chain (`this` folded to the
     * static factory): the binary's intermediate `ResourceFactoryPreload`
     * constructor (base vftable, attach, vftable 0x00E02958), then this
     * vftable (0x00E02938). The intermediate layer is folded into this class
     * here.
     */
    CD3DTextureResourceFactory() = default;

    /**
     * Address: 0x0043E430 (FUN_0043E430, Moho::CD3DTextureResourceFactory::~CD3DTextureResourceFactory)
     * Address: 0x0043E4C0 (FUN_0043E4C0, Moho::ResourceFactoryPreload::~ResourceFactoryPreload)
     *
     * What it does:
     * Out-of-line copies of the destructor chain: restore the base vftable
     * and detach from the resource manager.
     */
    ~CD3DTextureResourceFactory() = default;

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
    // NOT virtual, despite forwarding to a virtual `*Impl`. The binary's factory
    // vtable is seven slots -- Init, Load, Preload, LoadFrom, LoadImpl,
    // PreloadImpl, LoadFromImpl -- read straight off
    // ??_7?$ResourceFactory@VRScmResource@Moho@@@Moho@@6B@ (0x00E163D0) and
    // ??_7CScmResourceFactory@Moho@@6B@ (0x00E163B0), which agree slot for slot.
    // Slots 1..3 are already declared on ResourceFactoryBase (as the
    // type-erased `*ResourcePair` forms ResourceManager dispatches through --
    // slot 3 is the `mov edx, [eax+0Ch]` / `call edx` at 0x004AA83B-0x004AA845).
    // Declaring these typed forms `virtual` as well gave each of them a fresh
    // slot of its own after the base's four, pushing LoadImpl/PreloadImpl/
    // LoadFromImpl from slots 4/5/6 down to 7/8/9 -- so every dispatch through
    // this hierarchy landed on the wrong function.
    TextureResourceHandle& Load(TextureResourceHandle& outTexture, const char* path);

    /**
     * Address: 0x004435E0 (FUN_004435E0)
     *
     * boost::shared_ptr<gpg::MemBuffer<const char>> &,const char *
     *
     * What it does:
     * Forwards texture prefetch requests into implementation lane.
     */
    PrefetchDataHandle& Preload(PrefetchDataHandle& outPrefetchData, const char* path);

    /**
     * Address: 0x00443690 (FUN_00443690)
     *
     * boost::shared_ptr<RD3DTextureResource> &,const char *,boost::shared_ptr<gpg::MemBuffer<const char>>
     *
     * What it does:
     * Forwards load-from-prefetched-data requests into implementation lane.
     */
    TextureResourceHandle&
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

  private:
    /** Reflected type of the produced resource (`RD3DTextureResource`). */
    gpg::RType* mResourceType = nullptr; // +0x04
    /** Reflected type of the prefetch payload (`gpg::MemBuffer<const char>`). */
    gpg::RType* mPrefetchType = nullptr; // +0x08
  };

  /**
   * Address: 0x00BC4230 (FUN_00BC4230, register_PrefetchType_d3d_textures)
   *
   * What it does:
   * Resolves `RD3DTextureResource` type metadata and registers the
   * `"d3d_textures"` prefetch lane.
   */
  void register_PrefetchType_d3d_textures();

  static_assert(sizeof(CD3DTextureResourceFactory) == 0x0C, "CD3DTextureResourceFactory size must be 0x0C");

  /**
   * Address: 0x00BC4210 (FUN_00BC4210, dynamic initializer for `gTextureResourceFactory`)
   * Address: 0x00BEF310 (FUN_00BEF310, dynamic atexit destructor for `gTextureResourceFactory`)
   *
   * What it does:
   * The process-lifetime D3D texture factory (0x010A7A10); constructing it
   * attaches it to the resource manager.
   */
  extern CD3DTextureResourceFactory gTextureResourceFactory;
} // namespace moho
