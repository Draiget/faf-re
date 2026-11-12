#pragma once

// FAF addition, not in the shipped binary.
//
// The screen passes that rebuild positions from the scene depth (ren_Ao, ren_DynamicLights, ren_Atmosphere, ren_Taa,
// ren_RayBounce) read it through `GpuBindings::readBoundDepth`, which only Direct3D 12 and Vulkan provide (their
// head depth targets are created readable; anywhere else t6 reads 0).

#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"

namespace moho
{
  /** The device's backend gives dispatches the bound depth target to read (Direct3D 12 and Vulkan). */
  [[nodiscard]] inline bool BackendReadsBoundDepth(
    gpg::gal::Device& device
  )
  {
    const gpg::gal::DeviceContext* const context = device.GetDeviceContext();
    return context != nullptr &&
      (context->mDeviceType == gpg::gal::DeviceApi::Direct3D12 || context->mDeviceType == gpg::gal::DeviceApi::Vulkan);
  }
} // namespace moho
