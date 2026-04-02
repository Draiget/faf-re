#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/render/textures/CD3DBatchTexture.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E02A9C
   * COL: 0x00E5FAF8
   */
  class CD3DSolidBatchTexture final : public CD3DBatchTexture
  {
  public:
    /**
     * Address: 0x00447720 (FUN_00447720)
     *
     * unsigned int
     *
     * What it does:
     * Initializes one 2x2 solid-color batch texture payload and clears retained
     * dynamic-sheet ownership.
     */
    explicit CD3DSolidBatchTexture(std::uint32_t rgba);

    /**
     * Address: 0x004478A0 (FUN_004478A0, deleting-thunk lane)
     * Address: 0x00447760 (FUN_00447760, non-deleting body)
     *
     * What it does:
     * Removes this solid texture from the global color cache and releases base
     * batch-texture ownership.
     */
    ~CD3DSolidBatchTexture() override;

    /**
     * Address: 0x00447820 (FUN_00447820, Moho::CD3DSolidBatchTexture::Func1)
     *
     * void *,unsigned int
     *
     * What it does:
     * Emits a fixed 2x2 DXT payload for one solid RGBA color into a locked
     * dynamic-sheet destination.
     */
    void BuildTextureData(void* destination, std::uint32_t destinationPitchBytes) override;

    /**
     * Address: 0x00447890 (FUN_00447890, Moho::CD3DSolidBatchTexture::GetAlphaAt)
     *
     * unsigned int,unsigned int
     *
     * What it does:
     * Returns the solid color's alpha component.
     */
    [[nodiscard]] std::uint8_t GetAlphaAt(std::uint32_t x, std::uint32_t y) const override;

  public:
    std::uint32_t mColor; // +0x20
  };

  static_assert(offsetof(CD3DSolidBatchTexture, mColor) == 0x20, "CD3DSolidBatchTexture::mColor offset must be 0x20");
  static_assert(sizeof(CD3DSolidBatchTexture) == 0x24, "CD3DSolidBatchTexture size must be 0x24");
} // namespace moho
