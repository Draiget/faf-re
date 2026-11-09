#pragma once

// FAF addition, not in the shipped binary.
//
// Engine addition (`ren_TextureAnisotropy`): the game's effects sample their tiled textures (terrain layers, unit
// albedo, normal and specular maps) trilinearly, so ground and hulls seen at a slant blur into their smallest mips.
// On Direct3D 12 and Vulkan those samplers can take anisotropic filtering instead. Only a sampler that is trilinear
// and wraps in both directions changes: screen targets, shadow maps, lookups with point or no mips and clamped
// textures keep what their effect asks for.

#include <algorithm>
#include <cstdint>

#include "EffectDescription.h"

namespace gpg::gal::effects
{
  /** Anisotropy for tiled trilinear textures, 2 to 16; 0 or 1 leaves every sampler as its effect wrote it. */
  extern int gTextureAnisotropy;

  [[nodiscard]] inline SamplerDesc WithTextureAnisotropy(SamplerDesc desc) noexcept
  {
    constexpr std::uint32_t kMinMagMipLinear = 0x15U;
    constexpr std::uint32_t kAnisotropic = 0x55U;
    constexpr std::uint8_t kWrap = 1U;
    if (gTextureAnisotropy > 1 && desc.filter == kMinMagMipLinear && desc.addressU == kWrap && desc.addressV == kWrap) {
      desc.filter = kAnisotropic;
      desc.maxAnisotropy = static_cast<std::uint32_t>(std::min(gTextureAnisotropy, 16));
    }
    return desc;
  }
} // namespace gpg::gal::effects
