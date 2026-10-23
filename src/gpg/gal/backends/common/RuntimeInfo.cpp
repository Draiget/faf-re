// FAF addition, not in the shipped binary: see RuntimeInfo.h.

#include "RuntimeInfo.h"

#include <cstdio>

#include "gpg/core/utils/Logging.h"

namespace gpg::gal::common
{
  std::string FormatWindowsDriverVersion(const std::uint64_t version)
  {
    char text[48]{};
    std::snprintf(
      text, sizeof(text), "%u.%u.%u.%u", static_cast<unsigned>((version >> 48U) & 0xFFFFU),
      static_cast<unsigned>((version >> 32U) & 0xFFFFU), static_cast<unsigned>((version >> 16U) & 0xFFFFU),
      static_cast<unsigned>(version & 0xFFFFU)
    );
    return text;
  }

  void LogRuntimeInfo(const char* const prefix, const DeviceRuntimeInfo& info)
  {
    constexpr double kMiB = 1024.0 * 1024.0;
    gpg::Logf(
      "%s: runtime info: api %s, adapter '%s' (vendor 0x%04X device 0x%04X), driver %s, feature level %s, "
      "swap chain %s, vsync %s, gpu-driven features 0x%X",
      prefix, info.api.c_str(), info.adapter.c_str(), info.vendorId, info.deviceId, info.driverVersion.c_str(),
      info.featureLevel.c_str(), info.swapChain.c_str(), info.vsync ? "on" : "off", info.gpuDrivenFeatures
    );
    gpg::Logf(
      "%s: runtime info: dedicated %.0f MiB, shared %.0f MiB, local %.0f / %.0f MiB, non-local %.0f / %.0f MiB "
      "(usage / budget), available texture memory %.0f MiB",
      prefix, static_cast<double>(info.dedicatedVideoMemory) / kMiB, static_cast<double>(info.sharedSystemMemory) / kMiB,
      static_cast<double>(info.localUsage) / kMiB, static_cast<double>(info.localBudget) / kMiB,
      static_cast<double>(info.nonLocalUsage) / kMiB, static_cast<double>(info.nonLocalBudget) / kMiB,
      static_cast<double>(info.availableTextureMemory) / kMiB
    );
  }
} // namespace gpg::gal::common
