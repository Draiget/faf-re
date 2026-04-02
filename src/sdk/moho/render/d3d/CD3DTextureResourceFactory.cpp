#include "moho/render/d3d/CD3DTextureResourceFactory.h"

#include <cstdlib>
#include <string.h>
#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/resource/ResourceManager.h"
#include "moho/serialization/PrefetchHandleBase.h"
#include "moho/render/d3d/RD3DTextureResource.h"

namespace moho
{
  namespace
  {
    [[nodiscard]] bool IsDdsTexturePath(const char* const path)
    {
      if (path == nullptr || path[0] == '\0') {
        return false;
      }

      const char* const extension = FILE_Ext(path);
      return extension != nullptr && _stricmp(extension, "dds") == 0;
    }

    /**
     * Address: 0x0043DEB0 (FUN_0043DEB0, gpg::MemBuffer::MapFromFile)
     *
     * const char *
     *
     * What it does:
     * Compatibility wrapper for `gpg::MemBuffer::MapFromFile` used by DDS texture loads.
     */
    [[nodiscard]] gpg::MemBuffer<const char> MapFromFile(const char* const path)
    {
      return DISK_MemoryMapFile(path);
    }

    CD3DTextureResourceFactory& TextureFactorySingleton()
    {
      static CD3DTextureResourceFactory sTextureFactory;
      return sTextureFactory;
    }

    [[nodiscard]] gpg::MemBuffer<const char> LoadTextureFileBytes(const char* const path)
    {
      if (path == nullptr || path[0] == '\0') {
        return {};
      }

      if (IsDdsTexturePath(path)) {
        return MapFromFile(path);
      }

      return DISK_MemoryMapFile(path);
    }

    template <class HandleT>
    [[nodiscard]] boost::SharedCountPair SharedPairFromHandleRetained(const HandleT& handle) noexcept
    {
      const boost::SharedPtrRaw<typename HandleT::element_type> raw =
        boost::SharedPtrRawFromSharedBorrow(handle);
      boost::SharedCountPair pair{};
      pair.px = raw.px;
      pair.pi = raw.pi;
      if (pair.pi != nullptr) {
        pair.pi->add_ref_copy();
      }
      return pair;
    }

    template <class HandleT>
    [[nodiscard]] HandleT HandleFromSharedPairRetained(const boost::SharedCountPair* const pair) noexcept
    {
      HandleT handle{};
      if (pair == nullptr) {
        return handle;
      }

      auto* const layout = reinterpret_cast<boost::SharedPtrLayoutView<typename HandleT::element_type>*>(&handle);
      layout->px = static_cast<typename HandleT::element_type*>(pair->px);
      layout->pi = pair->pi;
      if (layout->pi != nullptr) {
        layout->pi->add_ref_copy();
      }
      return handle;
    }

    [[nodiscard]] CD3DTextureResourceFactory* AttachTextureFactory()
    {
      RES_EnsureResourceManager();
      ResourceManager* const manager = RES_GetResourceManager();
      CD3DTextureResourceFactory& factory = TextureFactorySingleton();
      if (manager != nullptr) {
        manager->AttachFactory(&factory);
      }
      return &factory;
    }

    void DetachTextureFactory()
    {
      RES_EnsureResourceManager();
      ResourceManager* const manager = RES_GetResourceManager();
      CD3DTextureResourceFactory& factory = TextureFactorySingleton();
      if (manager != nullptr) {
        manager->DetachFactory(&factory);
      }
    }

    template <void (*Cleanup)()>
    void RegisterExitCleanup() noexcept
    {
      (void)std::atexit(Cleanup);
    }
  } // namespace

  /**
   * Address: 0x0043E470 (FUN_0043E470, ??0ResourceFactoryPreload@Moho@@QAE@@Z)
   *
   * What it does:
   * Runs the preload-constructor registration lane for the texture-factory singleton.
   */
  CD3DTextureResourceFactory* construct_TextureResourceFactoryPreload()
  {
    return AttachTextureFactory();
  }

  /**
   * Address: 0x00BEF310 (FUN_00BEF310, cleanup_CD3DTextureResourceFactory)
   *
   * What it does:
   * Detaches the startup texture-factory registration lane from the resource
   * manager during process-exit teardown.
   */
  void cleanup_CD3DTextureResourceFactory()
  {
    DetachTextureFactory();
  }

  /**
   * Address: 0x00BC4210 (FUN_00BC4210, register_CD3DTextureResourceFactory)
   *
   * What it does:
   * Runs texture-factory preload construction and registers process-exit
   * cleanup for the startup factory slot.
   */
  void register_CD3DTextureResourceFactory()
  {
    (void)construct_TextureResourceFactoryPreload();
    RegisterExitCleanup<&cleanup_CD3DTextureResourceFactory>();
  }

  /**
   * Address: 0x00BC4230 (FUN_00BC4230, register_PrefetchType_d3d_textures)
   *
   * What it does:
   * Resolves `RD3DTextureResource` type metadata and registers the
   * `"d3d_textures"` prefetch lane.
   */
  void register_PrefetchType_d3d_textures()
  {
    gpg::RType* textureType = RD3DTextureResource::sType;
    if (textureType == nullptr) {
      textureType = gpg::LookupRType(typeid(RD3DTextureResource));
      RD3DTextureResource::sType = textureType;
    }
    RES_RegisterPrefetchType("d3d_textures", textureType);
  }

  /**
   * Address: 0x0043E410 (FUN_0043E410, func_CreateTextureResourceFactory)
   *
   * What it does:
   * Runs the texture-factory constructor lane and returns the singleton object.
   */
  CD3DTextureResourceFactory* func_CreateTextureResourceFactory()
  {
    return construct_TextureResourceFactoryPreload();
  }

  /**
   * Address: 0x0043E430 (FUN_0043E430, unregister_TextureResourceFactoryPrimary)
   *
   * What it does:
   * Preserves one texture-factory registration lane.
   */
  void unregister_TextureResourceFactoryPrimary()
  {
    DetachTextureFactory();
  }

  /**
   * Address: 0x0043E4C0 (FUN_0043E4C0, unregister_TextureResourceFactorySecondary)
   *
   * What it does:
   * Preserves the second texture-factory registration lane.
   */
  void unregister_TextureResourceFactorySecondary()
  {
    DetachTextureFactory();
  }

  /**
   * Address: 0x004434E0 (FUN_004434E0)
   *
   * What it does:
   * Preserves base init lane for preload-capable texture resource factory.
   */
  void CD3DTextureResourceFactory::Init() {}

  /**
   * Address: 0x00443530 (FUN_00443530)
   *
   * boost::shared_ptr<RD3DTextureResource> &,const char *
   *
   * What it does:
   * Forwards texture load requests into implementation lane.
   */
  CD3DTextureResourceFactory::TextureResourceHandle&
  CD3DTextureResourceFactory::Load(TextureResourceHandle& outTexture, const char* const path)
  {
    return LoadImpl(outTexture, path);
  }

  /**
   * Address: 0x004435E0 (FUN_004435E0)
   *
   * boost::shared_ptr<gpg::MemBuffer<const char>> &,const char *
   *
   * What it does:
   * Forwards texture prefetch requests into implementation lane.
   */
  CD3DTextureResourceFactory::PrefetchDataHandle&
  CD3DTextureResourceFactory::Preload(PrefetchDataHandle& outPrefetchData, const char* const path)
  {
    return PreloadImpl(outPrefetchData, path);
  }

  /**
   * Address: 0x00443690 (FUN_00443690)
   *
   * boost::shared_ptr<RD3DTextureResource> &,const char *,boost::shared_ptr<gpg::MemBuffer<const char>>
   *
   * What it does:
   * Forwards load-from-prefetched-data requests into implementation lane.
   */
  CD3DTextureResourceFactory::TextureResourceHandle&
  CD3DTextureResourceFactory::LoadFrom(
    TextureResourceHandle& outTexture,
    const char* const path,
    PrefetchDataHandle prefetchData
  )
  {
    return LoadFromImpl(outTexture, path, prefetchData);
  }

  /**
   * Address: 0x004AA9DE / 0x004AAA09 call lane in FUN_004AA690
   */
  boost::SharedCountPair* CD3DTextureResourceFactory::LoadResourcePair(
    boost::SharedCountPair* const outResourcePair,
    const char* const path,
    gpg::RType* const resourceType
  )
  {
    (void)resourceType;
    if (outResourcePair == nullptr) {
      return nullptr;
    }

    TextureResourceHandle loadedTexture{};
    (void)Load(loadedTexture, path);
    *outResourcePair = SharedPairFromHandleRetained(loadedTexture);
    return outResourcePair;
  }

  /**
   * Address: 0x004AB371 call lane in FUN_004AB180
   */
  boost::SharedCountPair* CD3DTextureResourceFactory::PreloadResourcePair(
    boost::SharedCountPair* const outPrefetchPair,
    const char* const path,
    gpg::RType* const resourceType
  )
  {
    (void)resourceType;
    if (outPrefetchPair == nullptr) {
      return nullptr;
    }

    PrefetchDataHandle prefetchedTexture{};
    (void)Preload(prefetchedTexture, path);
    *outPrefetchPair = SharedPairFromHandleRetained(prefetchedTexture);
    return outPrefetchPair;
  }

  /**
   * Address: 0x004AA845 call lane in FUN_004AA690
   */
  boost::SharedCountPair* CD3DTextureResourceFactory::LoadResourceFromPrefetchPair(
    boost::SharedCountPair* const outResourcePair,
    const char* const path,
    gpg::RType* const resourceType,
    const boost::SharedCountPair* const prefetchPair,
    gpg::RType* const prefetchType
  )
  {
    (void)resourceType;
    (void)prefetchType;
    if (outResourcePair == nullptr) {
      return nullptr;
    }

    const PrefetchDataHandle prefetchData = HandleFromSharedPairRetained<PrefetchDataHandle>(prefetchPair);
    TextureResourceHandle loadedTexture{};
    (void)LoadFrom(loadedTexture, path, prefetchData);
    *outResourcePair = SharedPairFromHandleRetained(loadedTexture);
    return outResourcePair;
  }

  /**
   * Address: 0x0043DED0 (FUN_0043DED0)
   *
   * boost::shared_ptr<RD3DTextureResource> &,const char *
   *
   * What it does:
   * Loads one texture file payload and initializes one RD3DTextureResource instance.
   */
  CD3DTextureResourceFactory::TextureResourceHandle&
  CD3DTextureResourceFactory::LoadImpl(TextureResourceHandle& outTexture, const char* const path)
  {
    outTexture.reset();

    gpg::MemBuffer<const char> textureBytes = LoadTextureFileBytes(path);
    if (textureBytes.mBegin == nullptr) {
      return outTexture;
    }

    TextureResourceHandle resource(new RD3DTextureResource(path));
    if (!resource || !resource->Init(textureBytes)) {
      outTexture.reset();
      return outTexture;
    }

    outTexture = resource;
    return outTexture;
  }

  /**
   * Address: 0x0043E0C0 (FUN_0043E0C0)
   *
   * boost::shared_ptr<gpg::MemBuffer<const char>> &,const char *
   *
   * What it does:
   * Loads one texture file payload into prefetch shared buffer wrapper.
   */
  CD3DTextureResourceFactory::PrefetchDataHandle&
  CD3DTextureResourceFactory::PreloadImpl(PrefetchDataHandle& outPrefetchData, const char* const path)
  {
    outPrefetchData.reset();

    gpg::MemBuffer<const char> textureBytes = LoadTextureFileBytes(path);
    if (textureBytes.mBegin == nullptr) {
      return outPrefetchData;
    }

    outPrefetchData.reset(new PrefetchData(textureBytes));
    return outPrefetchData;
  }

  /**
   * Address: 0x0043E200 (FUN_0043E200)
   *
   * boost::shared_ptr<RD3DTextureResource> &,const char *,boost::shared_ptr<gpg::MemBuffer<const char>>
   *
   * What it does:
   * Builds one RD3DTextureResource from already-prefetched bytes.
   */
  CD3DTextureResourceFactory::TextureResourceHandle& CD3DTextureResourceFactory::LoadFromImpl(
    TextureResourceHandle& outTexture,
    const char* const path,
    PrefetchDataHandle prefetchData
  )
  {
    outTexture.reset();
    if (!prefetchData || prefetchData->mBegin == nullptr) {
      return outTexture;
    }

    TextureResourceHandle resource(new RD3DTextureResource(path));
    if (!resource || !resource->Init(*prefetchData)) {
      outTexture.reset();
      return outTexture;
    }

    outTexture = resource;
    return outTexture;
  }
} // namespace moho

namespace
{
  struct TextureResourceFactoryStartupRegistrations
  {
    TextureResourceFactoryStartupRegistrations()
    {
      moho::register_CD3DTextureResourceFactory();
      moho::register_PrefetchType_d3d_textures();
    }
  };

  [[maybe_unused]] TextureResourceFactoryStartupRegistrations gTextureResourceFactoryStartupRegistrations;
} // namespace
