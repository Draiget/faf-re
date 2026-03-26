#include "moho/resource/CD3DTextureResourceFactory.h"

#include "gpg/core/containers/String.h"
#include "moho/resource/RD3DTextureResource.h"

namespace moho
{
  namespace
  {
    [[nodiscard]] bool HasDdsExtension(const char* const path)
    {
      return path != nullptr && path[0] != '\0' && gpg::STR_EndsWithNoCase(path, ".dds");
    }

    [[nodiscard]] gpg::MemBuffer<const char> LoadTextureFileBytes(const char* const path)
    {
      if (path == nullptr || path[0] == '\0') {
        return {};
      }

      // Binary uses two different map helpers for DDS/non-DDS lanes.
      // Current lifted source keeps both lanes routed through one shared loader.
      (void)HasDdsExtension(path);
      return gpg::LoadFileToMemBuffer(path);
    }
  } // namespace

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
