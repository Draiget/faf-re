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
    std::uint32_t locations = 1; // arrays take one location per element
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

  /**
   * Engine addition (ren_UsedTextureTable): bit b for every image variable of descriptor set 0 at binding b (0..63) the
   * module declares - DXC removes the resources a shader doesn't read - so with -fvk-t-shift 0 the texture registers it
   * reads; all bits when the code can't be read.
   */
  [[nodiscard]] std::uint64_t ReflectSpirvTextureSlots(const std::vector<std::uint8_t>& code);

  /** Returns `code` with each input variable's Location replaced by `locations[id]` where present. */
  [[nodiscard]] std::vector<std::uint8_t> PatchSpirvInputLocations(
    const std::vector<std::uint8_t>& code,
    const std::map<std::uint32_t, std::uint32_t>& locations
  );

  /**
   * The locations for PatchSpirvInputLocations that link a pixel shader to a vertex shader, by input id:
   * each input takes the location of the vertex output with its semantic, as Direct3D links stages. An
   * input no output writes, which Direct3D reads as an undefined value, is invalid in Vulkan wherever it
   * lands (VUID-RuntimeSpirv-OpEntryPoint-08743); it takes locations of its own, so that they at least are
   * the device's: in the pixel shader's order, the highest that are free for all it takes (an array or a
   * matrix takes one per element or column), at most `lastLocation`, the device's last fragment input
   * location (VkPhysicalDeviceLimits::maxFragmentInputComponents, four components each). One that finds no
   * such locations (more inputs than the device has locations) is left out and keeps its own.
   */
  [[nodiscard]] std::map<std::uint32_t, std::uint32_t>
  LinkPixelInputLocations(const SpirvInterface& vertex, const SpirvInterface& pixel, std::uint32_t lastLocation);

  /** The work group size a compute module declares (OpExecutionMode LocalSize); false without one or on bad code. */
  [[nodiscard]] bool ReflectSpirvComputeGroupSize(const std::vector<std::uint8_t>& code, std::uint32_t (&size)[3]);
} // namespace gpg::gal::effects
