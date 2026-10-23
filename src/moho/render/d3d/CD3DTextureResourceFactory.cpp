#include "moho/render/d3d/CD3DTextureResourceFactory.h"

#include <cstdlib>
#include <string.h>
#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/resource/ResourceManager.h"
#include "moho/resource/ResourceReflectionHelpers.h"
#include "moho/serialization/PrefetchHandleBase.h"
#include "moho/render/d3d/RD3DTextureResource.h"

namespace moho
{
  namespace
  {
    /**
     * Address: 0x0043DEB0 (FUN_0043DEB0, gpg::MemBuffer::MapFromFile)
     *
     * What it does:
     * Memory-maps a DDS file; an out-of-line wrapper over `DISK_MemoryMapFile`.
     */
    [[nodiscard]] gpg::MemBuffer<const char> MapFromFile(const gpg::StrArg path)
    {
      return DISK_MemoryMapFile(path);
    }

    /**
     * What it does:
     * The texture file's bytes; both texture loaders inline this.
     */
    [[nodiscard]] gpg::MemBuffer<const char> MapTextureFile(const gpg::StrArg path)
    {
      gpg::MemBuffer<const char> data;
      data = _stricmp(FILE_Ext(path), "dds") == 0 ? MapFromFile(path) : DISK_MemoryMapFile(path);
      return data;
    }
  } // namespace

  /**
   * Address: 0x00BC4230 (FUN_00BC4230, register_PrefetchType_d3d_textures)
   *
   * What it does:
   * Resolves `RD3DTextureResource` type metadata and registers the
   * `"d3d_textures"` prefetch lane.
   */
  void register_PrefetchType_d3d_textures()
  {
    gpg::RType* const textureType = resource_reflection::ResolveRD3DTextureResourceType();
    RES_RegisterPrefetchType("d3d_textures", textureType);
  }

  /**
   * Address: 0x0043DED0 (FUN_0043DED0)
   */
  boost::shared_ptr<RD3DTextureResource> CD3DTextureResourceFactory::LoadImpl(const gpg::StrArg path)
  {
    if (path != nullptr && path[0] != '\0') {
      const gpg::MemBuffer<const char> data = MapTextureFile(path);
      if (data.mBegin != nullptr) {
        boost::shared_ptr<RD3DTextureResource> resource(new RD3DTextureResource(path));
        if (resource->Init(data)) {
          return resource;
        }
      }
    }
    return boost::shared_ptr<RD3DTextureResource>();
  }

  /**
   * Address: 0x0043E0C0 (FUN_0043E0C0)
   */
  boost::shared_ptr<gpg::MemBuffer<const char>> CD3DTextureResourceFactory::PreloadImpl(const gpg::StrArg path)
  {
    if (path != nullptr && path[0] != '\0') {
      const gpg::MemBuffer<const char> data = MapTextureFile(path);
      if (data.mBegin != nullptr) {
        return boost::shared_ptr<gpg::MemBuffer<const char>>(new gpg::MemBuffer<const char>(data));
      }
    }
    return boost::shared_ptr<gpg::MemBuffer<const char>>();
  }

  /**
   * Address: 0x0043E200 (FUN_0043E200)
   */
  boost::shared_ptr<RD3DTextureResource> CD3DTextureResourceFactory::LoadFromImpl(
    const gpg::StrArg path, const boost::shared_ptr<gpg::MemBuffer<const char>> prefetchData
  )
  {
    boost::shared_ptr<RD3DTextureResource> resource(new RD3DTextureResource(path));
    if (!resource->Init(*prefetchData)) {
      return boost::shared_ptr<RD3DTextureResource>();
    }
    return resource;
  }
} // namespace moho

moho::CD3DTextureResourceFactory moho::gTextureResourceFactory;

namespace
{
  struct TextureResourceFactoryStartupRegistrations
  {
    TextureResourceFactoryStartupRegistrations()
    {
      moho::register_PrefetchType_d3d_textures();
    }
  };

  [[maybe_unused]] TextureResourceFactoryStartupRegistrations gTextureResourceFactoryStartupRegistrations;
} // namespace
