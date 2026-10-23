#include "moho/render/textures/SBatchTextureDataFactory.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/resource/ResourceManager.h"
#include "moho/serialization/PrefetchHandleBase.h"

namespace moho
{
  /**
   * Address: 0x00447DD0 (FUN_00447DD0, Moho::SBatchTextureDataFactory::LoadImpl)
   */
  boost::shared_ptr<SBatchTextureData> SBatchTextureDataFactory::LoadImpl(const gpg::StrArg path)
  {
    if (path == nullptr || !gpg::gal::Device::IsReady()) {
      return {};
    }

    const gpg::MemBuffer<const char> mappedFile = DISK_MemoryMapFile(path);
    boost::shared_ptr<SBatchTextureData> decodedData(new SBatchTextureData());

    gpg::MemBuffer<char> decodedBlocks;
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    if (device == nullptr) {
      return {};
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
      return {};
    }
    return decodedData;
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

  /**
   * Address: 0x00BC4440 (FUN_00BC4440, register_PrefetchType_batch_textures)
   */
  void register_PrefetchType_batch_textures()
  {
    register_SBatchTextureDataPrefetchType();
  }
} // namespace moho

namespace
{
  /**
   * Address: 0x00BC4420 (FUN_00BC4420, dynamic initializer for `sBatchTextureDataFactory`)
   * Address: 0x00BEF4E0 (FUN_00BEF4E0, dynamic atexit destructor for `sBatchTextureDataFactory`)
   *
   * What it does:
   * The process-lifetime batch-texture factory; constructing it attaches it
   * to the resource manager. Defined ahead of the bootstrap below, as
   * 0x00BC4420 precedes the prefetch key's initializer 0x00BC4440.
   */
  moho::SBatchTextureDataFactory sBatchTextureDataFactory;

  struct SBatchTextureDataFactoryBootstrap
  {
    SBatchTextureDataFactoryBootstrap()
    {
      moho::register_PrefetchType_batch_textures();
    }
  };

  SBatchTextureDataFactoryBootstrap gSBatchTextureDataFactoryBootstrap;
} // namespace
