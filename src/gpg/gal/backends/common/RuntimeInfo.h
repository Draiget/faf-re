// FAF addition, not in the shipped binary: helpers for Device::GetRuntimeInfo.
#pragma once

#include <cstdint>
#include <string>

#include "gpg/gal/Device.hpp"

namespace gpg::gal::common
{
  /** "1.2.3.4" from a Windows driver version (the four 16-bit fields of a LARGE_INTEGER). */
  [[nodiscard]] std::string FormatWindowsDriverVersion(std::uint64_t version);

  /**
   * Logs every field of `info` on two lines, prefixed with `prefix`
   * ("D3D12", "Vulkan"). Called once when the device is ready.
   */
  void LogRuntimeInfo(const char* prefix, const DeviceRuntimeInfo& info);
} // namespace gpg::gal::common
