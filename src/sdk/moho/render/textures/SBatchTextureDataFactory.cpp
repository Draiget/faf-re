#include "moho/render/textures/SBatchTextureDataFactory.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/backends/d3d9/DeviceD3D9.hpp"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/resource/ResourceManager.h"
#include "moho/serialization/PrefetchHandleBase.h"

namespace
{
  [[nodiscard]] moho::SBatchTextureDataFactory& BatchTextureDataFactorySingleton()
  {
    static moho::SBatchTextureDataFactory sFactory;
    return sFactory;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00448090 (FUN_00448090, Moho::SBatchTextureDataFactory::SBatchTextureDataFactory)
   */
  SBatchTextureDataFactory::SBatchTextureDataFactory()
  {
    RES_EnsureResourceManager();
    if (ResourceManager* const manager = RES_GetResourceManager(); manager != nullptr) {
      manager->AttachFactory(this);
    }
  }

  /**
   * Address: 0x00BEF4E0 (FUN_00BEF4E0, Moho::SBatchTextureDataFactory::~SBatchTextureDataFactory)
   * Address: 0x00448050 (FUN_00448050, detach lane 1)
   * Address: 0x004480E0 (FUN_004480E0, detach lane 2)
   */
  SBatchTextureDataFactory::~SBatchTextureDataFactory()
  {
    RES_EnsureResourceManager();
    if (ResourceManager* const manager = RES_GetResourceManager(); manager != nullptr) {
      manager->DetachFactory(this);
    }
  }

  /**
   * Address: 0x00447DD0 (FUN_00447DD0, Moho::SBatchTextureDataFactory::LoadImpl)
   */
  SBatchTextureDataFactory::ResourceHandle&
  SBatchTextureDataFactory::LoadImpl(ResourceHandle& outResource, const char* const path)
  {
    outResource.reset();

    if (path == nullptr || !gpg::gal::Device::IsReady()) {
      return outResource;
    }

    const gpg::MemBuffer<const char> mappedFile = DISK_MemoryMapFile(path);
    ResourceHandle decodedData(new SBatchTextureData());
    if (!decodedData) {
      return outResource;
    }

    gpg::MemBuffer<char> decodedBlocks;
    gpg::gal::DeviceD3D9* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    if (device == nullptr) {
      return outResource;
    }

    const auto mappedBytes = static_cast<std::uint32_t>(mappedFile.mEnd - mappedFile.mBegin);
    device->GetTexture2D(
      mappedFile.mBegin,
      mappedBytes,
      &decodedBlocks,
      &decodedData->mWidth,
      reinterpret_cast<int*>(&decodedData->mHeight)
    );

    if (!CopyBatchTextureDataFromMemBuffer(*decodedData, decodedBlocks)) {
      return outResource;
    }

    outResource = decodedData;
    return outResource;
  }

  /**
   * Address: 0x00448030 (FUN_00448030, ctor bootstrap lane)
   */
  SBatchTextureDataFactory* construct_SBatchTextureDataFactory()
  {
    return &BatchTextureDataFactorySingleton();
  }

  /**
   * Address: 0x00BC4420 (FUN_00BC4420, register_SBatchTextureDataFactory)
   */
  void register_SBatchTextureDataFactory()
  {
    (void)construct_SBatchTextureDataFactory();
  }

  /**
   * Address: 0x0044A6C0 (FUN_0044A6C0)
   */
  void register_SBatchTextureDataPrefetchType()
  {
    gpg::RType* resourceType = SBatchTextureData::sType;
    if (resourceType == nullptr) {
      resourceType = gpg::LookupRType(typeid(SBatchTextureData));
      SBatchTextureData::sType = resourceType;
    }

    RES_RegisterPrefetchType("batch_textures", resourceType);
  }
} // namespace moho

namespace
{
  struct SBatchTextureDataFactoryBootstrap
  {
    SBatchTextureDataFactoryBootstrap()
    {
      moho::register_SBatchTextureDataFactory();
      moho::register_SBatchTextureDataPrefetchType();
    }
  };

  SBatchTextureDataFactoryBootstrap gSBatchTextureDataFactoryBootstrap;
} // namespace
