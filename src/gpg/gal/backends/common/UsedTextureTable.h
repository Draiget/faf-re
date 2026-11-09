#pragma once

// FAF addition, not in the shipped binary: `ren_UsedTextureTable` (gpg::gal::gUsedTextureTable). Shared by the
// Direct3D 12 and Vulkan BindPass.

#include <cstddef>
#include <cstdint>
#include <vector>

#include "gpg/gal/effects/EffectParameters.h"
#include "gpg/gal/effects/EffectRuntime.h"

namespace gpg::gal
{
  /// The texture registers a bound pass's shaders read; all of them when a stage is missing or unknown. A
  /// tessellated pass's hull and domain shaders count too: the terrain's domain shader samples albedo layers its
  /// pixel shader doesn't, and leaving them out kept a table with old bindings for them.
  [[nodiscard]] inline std::uint64_t PassTextureSlots(
    const effects::CompiledEntry* const vertex,
    const effects::CompiledEntry* const pixel,
    const effects::CompiledEntry* const hull = nullptr,
    const effects::CompiledEntry* const domain = nullptr
  )
  {
    if (vertex == nullptr) {
      return ~std::uint64_t{0};
    }
    std::uint64_t slots = vertex->textureSlots | ((pixel != nullptr) ? pixel->textureSlots : 0U);
    if (hull != nullptr) {
      slots |= hull->textureSlots;
    }
    if (domain != nullptr) {
      slots |= domain->textureSlots;
    }
    return slots;
  }

  /**
   * Whether the effect's texture table still holds every binding the pass reads: for each register in `used`, the
   * binding the effect has now is the one `kept` recorded when the table was built. A slot the table recorded as
   * empty while the effect binds something (a view of the wrong kind, a pass sampling its own target) counts as
   * changed, which only rebuilds the table as before.
   */
  [[nodiscard]] inline bool UsedTextureBindingsKept(
    const effects::EffectProgram& program,
    const effects::ParameterStore& parameters,
    const std::vector<effects::TextureBinding>& kept,
    const std::uint64_t used
  )
  {
    const std::vector<std::int32_t>& slotParameters = program.TextureSlotParameters();
    for (std::size_t index = 0U; index < slotParameters.size() && index < 64U; ++index) {
      if ((used & (std::uint64_t{1} << index)) == 0U) {
        continue;
      }
      if (index >= kept.size()) {
        return false;
      }
      const std::int32_t parameter = slotParameters[index];
      const Texture* texture = nullptr;
      const RenderTarget* renderTarget = nullptr;
      if (parameter >= 0) {
        const effects::TextureBinding& binding = parameters.Binding(static_cast<std::uint32_t>(parameter));
        texture = binding.texture.get();
        renderTarget = binding.renderTarget.get();
      }
      if (texture != kept[index].texture.get() || renderTarget != kept[index].renderTarget.get()) {
        return false;
      }
    }
    return true;
  }
} // namespace gpg::gal
