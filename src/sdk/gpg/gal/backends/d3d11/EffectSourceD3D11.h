#pragma once

// FAF addition, not in the shipped binary.
//
// The engine-side override layer between the game's .fx files and the
// Direct3D 11 effect compiler. The effects carry a D3D10 dialect (the
// d3d10states.compat preamble, `#ifdef DIRECT3D10` sections), but GPG never
// shipped the D3D10 renderer and FAF's effects have since grown D3D9-only
// constructs outside those sections. Instead of touching gamedata, the
// backend rewrites the preprocessed source before compiling it:
//
//   - D3D9 render states in pass blocks (ZEnable, CullMode, SrcBlend,
//     ColorWriteEnable, Stencil*, DepthBias, FillMode, ...) become generated
//     BlendState / DepthStencilState / RasterizerState objects, merged with
//     the state object the pass already binds for that category;
//   - `sampler1D` / `tex1D` become a 2D sampler read at v = 0.5 (the ramps are
//     2D textures one texel high, which D3D9 let a 1D sampler read);
//   - a pixel shader whose inputs do not line up with the vertex shader's
//     output struct is called through a generated wrapper that takes that
//     struct and forwards each input by semantic (shader model 4 links
//     stages by register, D3D9 by semantic);
//   - a struct named like a technique is renamed (fx_5_0 rejects the clash);
//   - vs_4_0/ps_4_0 become 4.1 on feature level 10.1+ (32 vertex inputs);
//   - techniques that use a D3D9 fixed-function vertex shader the effect
//     never defines (FIXED_FUNC_VS) are dropped;
//   - D3D9 behaviour the D3D10 dialect loses is restored: depth clipping
//     and D3D9-scaled depth biases, alpha blended with the colour factors,
//     sqrt/rsqrt/pow on |x|, and each pass's alpha test (applied in its
//     pixel shader).

#include <string>
#include <string_view>
#include <vector>

namespace gpg::gal::d3d11
{
  struct TranslatedEffectSource
  {
    std::string source;
    std::vector<std::string> notes; // one line per rewrite worth logging
  };

  /**
   * Rewrites preprocessed effect source (no `#` directives besides `#line`)
   * as described above. Text the layer does not understand passes through.
   * The shaderModel41 flag raises the compat preamble's vs_4_0/ps_4_0 to 4.1
   * (feature level 10.1 and up). `original` is the source before
   * preprocessing, read for the D3D9 pass states the D3D10 dialect
   * preprocesses away (the alpha test).
   */
  [[nodiscard]] TranslatedEffectSource TranslateEffectSource(
    std::string_view preprocessed, bool shaderModel41, std::string_view original
  );
} // namespace gpg::gal::d3d11
