#pragma once

#include "moho/render/textures/SBatchTextureData.h"
#include "moho/resource/ResourceFactory.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E02AF4
   * COL: 0x00E5FA60
   */
  class SBatchTextureDataFactory final : public ResourceFactory<SBatchTextureData>
  {
  public:
    using PrefetchDataHandle = ResourceHandle;

    /**
     * Address: 0x00448090 (FUN_00448090, Moho::SBatchTextureDataFactory::SBatchTextureDataFactory)
     *
     * What it does:
     * Attaches the batch-texture data factory singleton to the resource manager.
     */
    SBatchTextureDataFactory();

    /**
     * Address: 0x00BEF4E0 (FUN_00BEF4E0, Moho::SBatchTextureDataFactory::~SBatchTextureDataFactory)
     * Address: 0x00448050 (FUN_00448050, detach lane 1)
     * Address: 0x004480E0 (FUN_004480E0, detach lane 2)
     *
     * What it does:
     * Detaches this factory registration from the resource manager.
     */
    ~SBatchTextureDataFactory();

    /**
     * Address: 0x00447DD0 (FUN_00447DD0, Moho::SBatchTextureDataFactory::LoadImpl)
     *
     * boost::shared_ptr<moho::SBatchTextureData> &,const char *
     *
     * What it does:
     * Decodes one mapped texture payload through the active D3D9 device and
     * stores DXT blocks into `SBatchTextureData`.
     */
    ResourceHandle& LoadImpl(ResourceHandle& outResource, const char* path) override;
  };

  static_assert(sizeof(ResourceFactory<SBatchTextureData>) == 0x0C, "ResourceFactory<SBatchTextureData> size must be 0x0C");
  static_assert(sizeof(SBatchTextureDataFactory) == 0x0C, "SBatchTextureDataFactory size must be 0x0C");

  /**
   * Address: 0x00448030 (FUN_00448030, ctor bootstrap lane)
   */
  [[nodiscard]] SBatchTextureDataFactory* construct_SBatchTextureDataFactory();

  /**
   * Address: 0x00BC4420 (FUN_00BC4420, register_SBatchTextureDataFactory)
   */
  void register_SBatchTextureDataFactory();

  /**
   * Address: 0x0044A6C0 (FUN_0044A6C0)
   *
   * What it does:
   * Registers the `batch_textures` prefetch key against `SBatchTextureData`
   * runtime type metadata.
   */
  void register_SBatchTextureDataPrefetchType();
} // namespace moho
