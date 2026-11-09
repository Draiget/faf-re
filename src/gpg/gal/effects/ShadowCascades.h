#pragma once

// FAF addition, not in the shipped binary.
//
// Engine addition (`ren_ShadowCascades`): the sun's shadow map as an atlas of tiles on Direct3D 12 and
// Vulkan. One tile holds the map the original fits over the whole shadowed view; the others hold the same
// light space over smaller boxes near the camera, at more texels per world unit.
//
// The game's mesh.fx and terrain.fx compute the shadow coordinate of the whole-view map in the vertex
// shader and read it in the pixel shader. The light projection is orthographic, so a finer tile's
// coordinate is a scale and offset of that one: the effect layer gives the samplers that read the shadow
// map for lighting a type of their own (`faf_shadow_sampler`) whose tex2D picks the finest tile that holds
// the point and moves the coordinate into it. The game's shader text stays as it is.
//
// The tiles and their mapping reach every such effect through one injected parameter,
// `faf_ShadowCascades`, which the backends fill before each pass from `gShadowCascades`. All zeros (the
// value before the shadow renderer writes it) reads as one map at the original coordinates.

#include <atomic>
#include <cstdint>
#include <string_view>

namespace gpg::gal::effects
{
  struct SamplerDesc;

  /** Tiles the atlas holds at most: the whole-view map and three finer ones. */
  inline constexpr std::uint32_t kShadowCascadeCount = 4U;

  /**
   * float4s in `faf_ShadowCascades`:
   * [0] (tiles in use, 0 for none; unused; the atlas coordinate of a texel that stays lit),
   * then per tile, finest first: [1 + 2k] the part of the whole-view map's coordinates the tile answers
   * for (min u, min v, max u, max v), and [2 + 2k] the move into the atlas (scale u, scale v, offset u,
   * offset v). A point no tile holds lies past the shadowed volume and reads the lit texel, as the
   * original's cleared border did.
   */
  inline constexpr std::uint32_t kShadowCascadeVectors = 1U + (2U * kShadowCascadeCount);

  inline constexpr std::string_view kShadowCascadeParameter = "faf_ShadowCascades";

  struct ShadowCascadeConstants
  {
    float vectors[kShadowCascadeVectors][4]{};
    /** Bumped on every change, so a pass rewrites the parameter only when it moved. */
    std::uint64_t version = 0U;
  };

  /** Written by the shadow renderer once per frame before the lit passes; read by the backends' BindPass. */
  extern ShadowCascadeConstants gShadowCascades;

  /**
   * Set when an effect uses a lighting shadow sampler other than as the first argument of a tex2D-family
   * call (passed to a function, say). That effect keeps the plain sampler, so it can't read an atlas, and
   * the shadow renderer goes back to the single map.
   */
  extern std::atomic<bool> gShadowCascadesBlocked;

  /**
   * A sampler that reads the shadow map for lighting: its texture is the effect's shadow texture
   * (`shadowTexture` in mesh.fx, `ShadowTexture` in terrain.fx). terrain.fx's blur samplers read the same
   * texture in atlas texels and are left alone.
   */
  [[nodiscard]] bool IsShadowLookupSampler(const SamplerDesc& sampler);

  /** The declaration the effect layer adds in front of an effect with a lighting shadow sampler. */
  [[nodiscard]] std::string_view ShadowCascadeDeclaration() noexcept;
} // namespace gpg::gal::effects
