#pragma once

#include "boost/shared_ptr.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "moho/resource/ResourceFactory.h"

namespace moho
{
  class RD3DTextureResource;

  /**
   * VFTABLE: 0x00E02938
   *
   * Loads textures. Its prefetch step only maps the file; `LoadFromImpl` makes
   * the texture from those bytes on the loading thread.
   */
  class CD3DTextureResourceFactory : public ResourceFactoryPreload<RD3DTextureResource, gpg::MemBuffer<const char>>
  {
  public:
    /**
     * Address: 0x0043E410 (FUN_0043E410, Moho::CD3DTextureResourceFactory::CD3DTextureResourceFactory)
     *
     * What it does:
     * Out-of-line copy of the constructor (`this` folded to the static
     * factory): the template's constructor (0x0043E470), then this vftable.
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
     * Address: 0x0043DED0 (FUN_0043DED0)
     *
     * What it does:
     * Maps the file and builds an `RD3DTextureResource` from it; nothing when
     * the path is empty, the file cannot be mapped, or the texture rejects it.
     */
    boost::shared_ptr<RD3DTextureResource> LoadImpl(gpg::StrArg path) override;

    /**
     * Address: 0x0043E0C0 (FUN_0043E0C0)
     *
     * What it does:
     * Maps the file and hands back a shared copy of the mapping.
     */
    boost::shared_ptr<gpg::MemBuffer<const char>> PreloadImpl(gpg::StrArg path) override;

    /**
     * Address: 0x0043E200 (FUN_0043E200)
     *
     * What it does:
     * Builds an `RD3DTextureResource` from bytes the prefetch step mapped.
     */
    boost::shared_ptr<RD3DTextureResource>
      LoadFromImpl(gpg::StrArg path, boost::shared_ptr<gpg::MemBuffer<const char>> prefetchData) override;
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
