#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "moho/render/textures/CD3DBatchTexture.h"

namespace moho
{
  struct SBatchTextureData;

  /**
   * VFTABLE: 0x00E02B34
   * COL: 0x00E5FA80
   */
  class CD3DRawBatchTexture : public CD3DBatchTexture
  {
  public:
    using DataHandle = boost::shared_ptr<SBatchTextureData>;

    /**
     * Address: 0x00448120 (FUN_00448120, Moho::CD3DRawBatchTexture::CD3DRawBatchTexture)
     *
     * boost::shared_ptr<moho::SBatchTextureData>,unsigned int
     *
     * What it does:
     * Initializes one raw DXT-backed batch texture from decoded block payload
     * dimensions and stores shared ownership of the source data.
     */
    CD3DRawBatchTexture(const DataHandle& data, std::uint32_t border);

    /**
     * Address: 0x004481D0 (FUN_004481D0, Moho::CD3DRawBatchTexture::dtr)
     *
     * What it does:
     * Releases retained source block ownership before base batch-texture
     * teardown.
     */
    ~CD3DRawBatchTexture() override;

    /**
     * Address: 0x00448180 (FUN_00448180, Moho::CD3DRawBatchTexture::Func1)
     *
     * void *,unsigned int
     *
     * What it does:
     * Copies DXT block rows into one locked dynamic-texture sheet destination.
     */
    void BuildTextureData(void* destination, std::uint32_t destinationPitchBytes) override;

    /**
     * Address: 0x00448190 (FUN_00448190, Moho::CD3DRawBatchTexture::GetAlphaAt)
     *
     * unsigned int,unsigned int
     *
     * What it does:
     * Decodes one alpha texel from the retained DXT block payload.
     */
    [[nodiscard]] std::uint8_t GetAlphaAt(std::uint32_t x, std::uint32_t y) const override;

  public:
    DataHandle mData; // +0x20
  };

  static_assert(offsetof(CD3DRawBatchTexture, mData) == 0x20, "CD3DRawBatchTexture::mData offset must be 0x20");
  static_assert(sizeof(CD3DRawBatchTexture) == 0x28, "CD3DRawBatchTexture size must be 0x28");
} // namespace moho
