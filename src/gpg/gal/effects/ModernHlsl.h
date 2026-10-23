#pragma once

// FAF addition, not in the shipped binary.
//
// The shader half of the universal effect layer: turns one effect (D3D10
// dialect, as d3d11::TranslateEffectSource leaves it) into plain HLSL that
// DXC compiles to DXIL (Direct3D 12) and SPIR-V (Vulkan). The effect framework
// parts are already in the EffectDescription; what is left is the code:
//
//   - techniques, state objects and string globals are removed;
//   - the FX9 texture/sampler model becomes Texture2D/TextureCube/Texture3D
//     views and SamplerStates on fixed registers, joined in a `faf_sampler`
//     struct so tex2D/texCUBE/... and sampler-typed function parameters keep
//     working (FXC's backwards-compatibility mode did this for Effects 11);
//   - numeric parameters stay globals (DXC packs them into $Globals at b0,
//     row-major with -Zpr, the layout ComputeConstantLayout predicts);
//   - a function that assigns a parameter gets a local copy (FXC allowed the
//     write; DXC does not);
//   - stage-boundary semantics become SV_Position / SV_Target / SV_Depth;
//   - one wrapper entry point per (stage, function, compile-time arguments),
//     named in the pass's ShaderReference::entry.
//
// The game's .fx files are user data and never stored in the repository;
// this runs on them at load time.

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "EffectDescription.h"

namespace gpg::gal::effects
{
  enum class ShaderStage : std::uint8_t
  {
    Vertex,
    Pixel,
  };

  enum class TextureDimension : std::uint8_t
  {
    Texture2D,
    TextureCube,
    Texture3D,
  };

  /** A texture parameter's view in one dimension, on register t<slot>. */
  struct TextureSlot
  {
    std::string parameter;
    TextureDimension dimension = TextureDimension::Texture2D;
    std::uint32_t slot = 0;
  };

  /** One compiled entry point. */
  struct ShaderEntry
  {
    ShaderStage stage = ShaderStage::Vertex;
    std::string function;
    std::string arguments;
    std::string name;
  };

  /** One member of a struct parameter, relative to the start of its element. */
  struct ConstantMember
  {
    std::uint32_t offset = 0;
    std::uint32_t size = 0;
    std::uint32_t elementStride = 0;
    std::uint32_t rows = 1;
    std::uint32_t columns = 1;
    std::uint32_t elements = 1;
    ParameterClass parameterClass = ParameterClass::Scalar;
    ScalarType scalarType = ScalarType::Float;
  };

  /** Where one parameter lives in $Globals (row-major packing, -Zpr). */
  struct ConstantSlot
  {
    std::uint32_t parameter = 0;     // index into EffectDescription::parameters
    std::uint32_t offset = 0;        // bytes from the start of $Globals
    std::uint32_t size = 0;          // bytes the shader reads
    std::uint32_t elementStride = 0; // bytes between array elements
    std::vector<ConstantMember> members; // struct parameters only
  };

  struct ConstantLayout
  {
    std::vector<ConstantSlot> slots;
    std::uint32_t size = 0; // bytes of $Globals the shaders read (unaligned)

    [[nodiscard]] const ConstantSlot* Find(std::uint32_t parameter) const noexcept;
  };

  struct ModernEffect
  {
    std::string hlsl;
    std::vector<TextureSlot> textures; // register t<slot>
    // Samplers sit on register s<i> for EffectDescription::samplers[i].
    std::vector<ShaderEntry> entries;
    ConstantLayout constants;
    std::vector<std::string> notes;
  };

  /** Registers the generated views and samplers stay below. */
  inline constexpr std::uint32_t kMaxTextureSlots = 64;
  inline constexpr std::uint32_t kMaxSamplerSlots = 64;

  /**
   * Generates the HLSL for `source` (the text `description` was parsed from)
   * and names each pass's entry points in `description`.
   */
  [[nodiscard]] ModernEffect GenerateModernHlsl(std::string_view source, EffectDescription& description);

  /** HLSL packing of the numeric parameters, in declaration order. */
  [[nodiscard]] ConstantLayout ComputeConstantLayout(const EffectDescription& description);
} // namespace gpg::gal::effects
