#pragma once

// FAF addition, not in the shipped binary.
//
// Engine addition (`ren_TextureAnisotropy`): the game's effects sample their tiled textures (terrain layers, unit
// albedo, normal and specular maps) trilinearly, so ground and hulls seen at a slant blur into their smallest mips.
// On Direct3D 11, 12 and Vulkan those samplers can take anisotropic filtering instead. Only a sampler that is trilinear
// and wraps in both directions changes: screen targets, shadow maps, lookups with point or no mips and clamped
// textures keep what their effect asks for, and so do lookup tables read by computed coordinates (a texture named
// *lookup*, such as mesh.fx's lookupTexture for shields and scrolling). Direct3D 11 takes the same rule
// (TakesTextureAnisotropy) on the sampler states of its Effects 11 samplers.

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <string>

#include "EffectDescription.h"

namespace gpg::gal::effects
{
  /** Anisotropy for tiled trilinear textures, 2 to 16; 0 or 1 leaves every sampler as its effect wrote it. */
  extern int gTextureAnisotropy;

  /**
   * The rule, on a sampler's description alone: trilinear (`filter` 0x15, D3D11_FILTER_MIN_MAG_MIP_LINEAR), wrapping in
   * both directions (`addressU` / `addressV` 1, D3D11_TEXTURE_ADDRESS_WRAP) and not a lookup table (`texture` names no
   * *lookup*). Every backend asks it, so the same samplers turn anisotropic on Direct3D 11, 12 and Vulkan.
   */
  [[nodiscard]] inline bool TakesTextureAnisotropy(
    const std::uint32_t filter,
    const std::uint32_t addressU,
    const std::uint32_t addressV,
    std::string texture
  )
  {
    constexpr std::uint32_t kMinMagMipLinear = 0x15U;
    constexpr std::uint32_t kWrap = 1U;
    std::transform(texture.begin(), texture.end(), texture.begin(), [](const unsigned char c) {
      return static_cast<char>(std::tolower(c));
    });
    return filter == kMinMagMipLinear && addressU == kWrap && addressV == kWrap &&
      texture.find("lookup") == std::string::npos;
  }

  [[nodiscard]] inline SamplerDesc WithTextureAnisotropy(
    SamplerDesc desc
  )
  {
    constexpr std::uint32_t kAnisotropic = 0x55U;
    if (gTextureAnisotropy > 1 && TakesTextureAnisotropy(desc.filter, desc.addressU, desc.addressV, desc.texture)) {
      desc.filter = kAnisotropic;
      desc.maxAnisotropy = static_cast<std::uint32_t>(std::min(gTextureAnisotropy, 16));
    }
    return desc;
  }
} // namespace gpg::gal::effects
