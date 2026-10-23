// Engine addition, not in the shipped binary (see GpuPathSettings.h).

#include "moho/render/GpuPathSettings.h"

#include "gpg/gal/Device.hpp"
#include "gpg/gal/GpuDriven.h"

namespace moho
{
  extern int ren_GpuIcons;
  extern int ren_GpuIconClassify;
  extern int ren_GpuFog;
  extern int ren_GpuSelectBrackets;
  extern int ren_ParticleBatch;
  extern int ren_GpuProjectileIcons;

  namespace
  {
    struct GpuPathEntry
    {
      const char* name;
      const int* setting;
      std::uint32_t path;
      std::uint32_t features;
    };

    const GpuPathEntry kGpuPaths[] = {
      {"ren_GpuIcons", &ren_GpuIcons, gpg::gal::kGpuPathStrategicIcons, gpg::gal::kGpuFeatureVertexPulling},
      {"ren_GpuIconClassify", &ren_GpuIconClassify, gpg::gal::kGpuPathIconClassify,
       gpg::gal::kGpuFeatureVertexPulling | gpg::gal::kGpuFeatureCompute | gpg::gal::kGpuFeatureIndirectDraw},
      {"ren_GpuFog", &ren_GpuFog, gpg::gal::kGpuPathFogOfWar, gpg::gal::kGpuFeatureVertexPulling},
      {"ren_GpuSelectBrackets", &ren_GpuSelectBrackets, gpg::gal::kGpuPathSelectBrackets, gpg::gal::kGpuFeatureVertexPulling},
      {"ren_ParticleBatch", &ren_ParticleBatch, gpg::gal::kGpuPathParticleBatch, gpg::gal::kGpuFeatureBufferCopy},
      {"ren_GpuProjectileIcons", &ren_GpuProjectileIcons, gpg::gal::kGpuPathProjectileIcons,
       gpg::gal::kGpuFeatureVertexPulling},
    };
  } // namespace

  bool GpuPathEnabled(const int setting, const std::uint32_t path, const std::uint32_t requiredFeatures)
  {
    if (setting == 0) {
      return false;
    }
    const gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    if (device == nullptr || (device->GetGpuDrivenFeatures() & requiredFeatures) != requiredFeatures) {
      return false;
    }
    return setting > 0 || (device->GetGpuDrivenVerified() & path) != 0U;
  }

  std::string DescribeGpuPaths()
  {
    std::string text;
    for (const GpuPathEntry& entry : kGpuPaths) {
      const int setting = *entry.setting;
      const bool enabled = GpuPathEnabled(setting, entry.path, entry.features);
      text += text.empty() ? "" : ", ";
      text += entry.name;
      text += setting < 0 ? "=auto:" : setting == 0 ? "=0:" : "=1:";
      text += enabled ? "on" : "off";
    }
    return text;
  }
} // namespace moho
