#pragma once

// FAF addition, not in the shipped binary.
//
// The little SPIR-V reading the Vulkan backend needs: the stage interface of
// a DXC-compiled shader (each input or output variable's Location, the HLSL
// semantic DXC records with -fspv-reflect, and its component type), and a
// way to move pixel-shader input locations onto the vertex shader's outputs.
// Direct3D links stages by semantic; Vulkan links them by location, and DXC
// numbers each shader's interface in its own declaration order.

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace gpg::gal::effects
{
  struct SpirvInterfaceVariable
  {
    enum class Component : std::uint8_t
    {
      Float,
      Uint,
      Sint,
    };

    std::uint32_t id = 0;
    std::uint32_t location = 0;
    std::uint32_t locations = 1;     // arrays take one location per element
    std::uint32_t components = 4;
    Component component = Component::Float;
    std::string semantic;            // upper case, without the index ("TEXCOORD")
    std::uint32_t semanticIndex = 0; // index of the first location
    bool builtIn = false;            // SV_Position and other system values
  };

  struct SpirvInterface
  {
    std::vector<SpirvInterfaceVariable> inputs;
    std::vector<SpirvInterfaceVariable> outputs;
  };

  /** Reads the interface variables of a single-entry-point module; empty on malformed code. */
  [[nodiscard]] SpirvInterface ReflectSpirvInterface(const std::vector<std::uint8_t>& code);

  /**
   * Returns `code` without the reflection decorations -fspv-reflect adds
   * (UserSemantic / UserTypeGOOGLE and their SPV_GOOGLE extensions), so the
   * module needs no VK_GOOGLE_* device extension.
   */
  [[nodiscard]] std::vector<std::uint8_t> StripSpirvReflection(const std::vector<std::uint8_t>& code);

  /** Returns `code` with each input variable's Location replaced by `locations[id]` where present. */
  [[nodiscard]] std::vector<std::uint8_t> PatchSpirvInputLocations(
    const std::vector<std::uint8_t>& code, const std::map<std::uint32_t, std::uint32_t>& locations
  );
} // namespace gpg::gal::effects
