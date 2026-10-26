// Engine addition, not in the shipped binary (see GpuPathSettings.h).

#include "moho/render/GpuPathSettings.h"

#include "gpg/gal/Device.hpp"
#include "gpg/gal/GpuDriven.h"
#include "gpg/gal/PipelineDiskCache.h"
#include "gpg/gal/backends/common/ImageCodec.h"
#include "gpg/gal/effects/EffectRuntime.h"
#include "moho/console/CConCommand.h"

namespace moho
{
  namespace
  {
    /**
     * Engine addition: `d3d_PipelineCache` switches the on-disk pipeline cache (see
     * gpg/gal/PipelineDiskCache.h). Off, pipelines are neither loaded from nor added to it;
     * `/nopipelinecache` also keeps the file from being opened at device creation.
     */
    TConVar<bool> gTConVar_d3d_PipelineCache(
      "d3d_PipelineCache",
      "Keep Direct3D 12 pipeline states on disk across sessions, so they are not compiled again in the frame that "
      "first draws them (1, the default) or create every one in that frame (0). /nopipelinecache turns it off at startup.",
      &gpg::gal::gPipelineDiskCache
    );

    /** Engine addition: `ren_DdsDirectLoad` (see gpg/gal/backends/common/ImageCodec.h). */
    TConVar<bool> gTConVar_ren_DdsDirectLoad(
      "ren_DdsDirectLoad",
      "Direct3D 12 / Vulkan: read DXT1/3/5 DDS textures straight from the file (1, the default) instead of decoding "
      "every texture through D3DX11 on a software device (0), which takes 25-45 ms per 1024x1024 texture.",
      &gpg::gal::imaging::gDdsDirectLoad
    );

    /** Engine addition: `ren_BackgroundShaders` (see EffectProgram::PrepareInBackground). */
    TConVar<bool> gTConVar_ren_BackgroundShaders(
      "ren_BackgroundShaders",
      "Direct3D 12 / Vulkan: prepare every shader of an effect on low-priority background threads when the effect is "
      "created, reading the cached ones and compiling the rest into the cache (1, the default), instead of opening the "
      "cache file or compiling in the frame that first draws with a shader (0). Read when an effect is created.",
      &gpg::gal::effects::gBackgroundShaders
    );

    /** Engine addition: `ren_TextureDecodeCache` (see gpg/gal/backends/common/ImageCodec.h). */
    TConVar<bool> gTConVar_ren_TextureDecodeCache(
      "ren_TextureDecodeCache",
      "Direct3D 12 / Vulkan: keep textures that took D3DX11 more than 8 ms to decode (the original game's textures "
      "without mip levels) in the shader cache directory and read them back in later sessions (1, the default), or "
      "decode every time (0).",
      &gpg::gal::imaging::gTextureDecodeCache
    );
  } // namespace

  extern int ren_GpuIcons;
  extern int ren_GpuIconClassify;
  extern int ren_GpuFog;
  extern int ren_GpuSelectBrackets;
  extern int ren_ParticleBatch;
  extern int ren_GpuProjectileIcons;
  extern int ren_GpuShapes;

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
      {"ren_GpuShapes", &ren_GpuShapes, gpg::gal::kGpuPathWorldShapes, gpg::gal::kGpuFeatureVertexPulling},
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
