// Engine addition, not in the shipped binary (see GpuPathSettings.h).

#include "moho/render/GpuPathSettings.h"

#include "gpg/gal/Device.hpp"
#include "gpg/gal/GpuDriven.h"
#include "gpg/gal/PipelineDiskCache.h"
#include "gpg/gal/PlacedResources.h"
#include "gpg/gal/backends/common/ImageCodec.h"
#include "gpg/gal/backends/common/PipelineMemo.h"
#include "gpg/gal/backends/d3d11/EffectSourceD3D11.h"
#include "gpg/gal/effects/EffectRuntime.h"
#include "gpg/gal/effects/TextureFiltering.h"
#include "moho/console/CConCommand.h"
#include "moho/render/ProjectileIconRenderer.h"
#include "moho/render/RangeGpuRenderer.h"
#include "moho/render/SelectionBracketGpuRenderer.h"
#include "moho/render/StrategicIconRenderer.h"
#include "moho/render/WorldShapeGpuRenderer.h"

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

    /** Engine addition: `d3d_PlacedResources` (see gpg/gal/PlacedResources.h). */
    TConVar<bool> gTConVar_d3d_PlacedResources(
      "d3d_PlacedResources",
      "Direct3D 12: place file textures and static buffers in large heaps created ahead of time (1, the default), "
      "or give each its own committed resource, which costs a driver allocation and a fence wait each (0). Read at "
      "each creation.",
      &gpg::gal::gPlacedResources
    );

    /** Engine addition: `d3d_SharedBuffers` (see gpg/gal/PlacedResources.h). */
    TConVar<bool> gTConVar_d3d_SharedBuffers(
      "d3d_SharedBuffers",
      "Direct3D 12: small static buffers sit at offsets inside large buffers (1, the default), or each takes at "
      "least 64 KB of a heap (0). Needs d3d_PlacedResources. Read at each creation.",
      &gpg::gal::gSharedBuffers
    );

    /** Engine addition: `ren_PipelineMemo` (see gpg/gal/backends/common/PipelineMemo.h). */
    TConVar<bool> gTConVar_ren_PipelineMemo(
      "ren_PipelineMemo",
      "Direct3D 12 / Vulkan: a draw finds its pipeline in a small table of recent ones (1, the default), or always builds "
      "the full key (0). Read at each draw.",
      &gpg::gal::gPipelineMemo
    );

    /** Engine addition: `ren_UsedTextureTable` (see gpg/gal/backends/common/PipelineMemo.h). */
    TConVar<bool> gTConVar_ren_UsedTextureTable(
      "ren_UsedTextureTable",
      "Direct3D 12 / Vulkan: an effect pass keeps its texture table when only bindings its shaders don't read changed (1, "
      "the default), or rebuilds it on any change (0). Read at each pass.",
      &gpg::gal::gUsedTextureTable
    );

    /** Engine addition: `ren_VulkanDynamicConstants` (see gpg/gal/backends/common/PipelineMemo.h). */
    TConVar<bool> gTConVar_ren_VulkanDynamicConstants(
      "ren_VulkanDynamicConstants",
      "Vulkan: a draw whose shader constants changed binds one set per upload buffer with its constants' offset (1, the "
      "default), or allocates and writes a new set (0). Read between frames.",
      &gpg::gal::gVulkanDynamicConstants
    );

    /** Engine addition: `ren_LockedRangeOnly` (see gpg/gal/PlacedResources.h). */
    TConVar<bool> gTConVar_ren_LockedRangeOnly(
      "ren_LockedRangeOnly",
      "Direct3D 12 / Vulkan: a dynamic buffer whose owner reads only what it just wrote copies only those bytes when "
      "it is renamed (1, the default), or copies all of it (0). Read at each unlock.",
      &gpg::gal::gLockedRangeOnly
    );

    /** Engine addition: `ren_ReleaseBufferCopies` (see gpg/gal/PlacedResources.h). */
    TConVar<bool> gTConVar_ren_ReleaseBufferCopies(
      "ren_ReleaseBufferCopies",
      "Direct3D 12 / Vulkan: free the CPU copy of a static buffer its owner won't lock again, such as a mesh's (1, the "
      "default), or keep every copy (0). Read when the owner releases it.",
      &gpg::gal::gReleaseBufferCopies
    );

    /** Engine addition: `ren_VulkanScaledPresent` (see gpg/gal/PlacedResources.h). */
    TConVar<bool> gTConVar_ren_VulkanScaledPresent(
      "ren_VulkanScaledPresent",
      "Vulkan: each head draws into an image of its own that is copied into the window's image at present, so a "
      "resized window keeps showing the game (1, the default), or draws straight into the window's images (0), "
      "which stop presenting after a resize. Read when the device makes its head targets.",
      &gpg::gal::gVulkanScaledPresent
    );

    /** Engine addition: `ren_VulkanPreciseBarriers` (see gpg/gal/PlacedResources.h). */
    TConVar<bool> gTConVar_ren_VulkanPreciseBarriers(
      "ren_VulkanPreciseBarriers",
      "Vulkan: a target switching between being drawn into, sampled and copied waits only for the work that used it "
      "(1, the default), or for all earlier work on the GPU (0). Read at each switch.",
      &gpg::gal::gVulkanPreciseBarriers
    );

    /** Engine addition: `ren_TextureAnisotropy` (see gpg/gal/effects/TextureFiltering.h). */
    TConVar<int> gTConVar_ren_TextureAnisotropy(
      "ren_TextureAnisotropy",
      "Direct3D 12 and Vulkan: anisotropic filtering (2-16) for the tiled textures the effects sample trilinearly - "
      "terrain layers, unit albedo, normal and specular maps - so ground and hulls seen at a slant stay sharp; 0 keeps "
      "the effects' own filtering. 8 by default. Applies at the next draw of each effect.",
      &gpg::gal::effects::gTextureAnisotropy
    );

    /** Engine addition: `d3d_UploadIdleMB` (see gpg/gal/PlacedResources.h). */
    TConVar<int> gTConVar_d3d_UploadIdleMB(
      "d3d_UploadIdleMB",
      "Direct3D 12: megabytes of idle upload pages kept for reuse; past it they are given back. Each page is 8 MB of "
      "committed process memory. Read at each retire.",
      &gpg::gal::gUploadIdleMB
    );

    /** Engine addition: `ren_DdsDirectLoad` (see gpg/gal/backends/common/ImageCodec.h). */
    TConVar<bool> gTConVar_ren_DdsDirectLoad(
      "ren_DdsDirectLoad",
      "Direct3D 12 / Vulkan: read DXT1/3/5 DDS textures straight from the file (1, the default) instead of decoding "
      "every texture through D3DX11 on a software device (0), which takes 25-45 ms per 1024x1024 texture.",
      &gpg::gal::imaging::gDdsDirectLoad
    );

    /** Engine addition: `ren_PrepareDuringLoading` (see REN_PrepareGpuPaths). */
    TConVar<bool> gTConVar_ren_PrepareDuringLoading(
      "ren_PrepareDuringLoading",
      "Build the GPU-driven render paths and the map's sky dome while the loading screen waits for the sim (1, the "
      "default) instead of in the first frame of play that draws them (0), where they took some 120 ms.",
      &moho::ren_PrepareDuringLoading
    );

    /** Engine addition: `ren_EffectFastScan` (see gpg/gal/backends/d3d11/EffectSourceD3D11.h). */
    TConVar<bool> gTConVar_ren_EffectFastScan(
      "ren_EffectFastScan",
      "Read effect source with plain scans (1, the default) or with the std::regex searches they replaced (0), which "
      "took about half of the time from process start to the lobby; same result. /fxregex turns it off at startup. "
      "Read when an effect is created.",
      &gpg::gal::d3d11::gEffectFastScan
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
  extern int ren_GpuRanges;
  extern int ren_GpuText;
  extern int ren_GpuFontCook;

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
      {"ren_GpuRanges", &ren_GpuRanges, gpg::gal::kGpuPathRanges, gpg::gal::kGpuFeatureVertexPulling},
      {"ren_GpuText", &ren_GpuText, gpg::gal::kGpuPathMsdfText, gpg::gal::kGpuFeatureVertexPulling},
      {"ren_GpuFontCook", &ren_GpuFontCook, gpg::gal::kGpuPathMsdfCook,
       gpg::gal::kGpuFeatureVertexPulling | gpg::gal::kGpuFeatureCompute},
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

bool moho::ren_PrepareDuringLoading = true;

int moho::REN_PrepareGpuPaths()
{
  // `IsActive` builds a path's program on its first call, as the first frame that draws it would.
  int active = 0;
  active += StrategicIconRenderer::Get().IsActive() ? 1 : 0;
  active += StrategicIconRenderer::Get().IsClassifyActive() ? 1 : 0;
  active += ProjectileIconRenderer::Get().IsActive() ? 1 : 0;
  active += SelectionBracketGpuRenderer::Get().IsActive() ? 1 : 0;
  active += WorldShapeGpuRenderer::Get().IsActive() ? 1 : 0;
  active += RangeGpuRenderer::Get().IsActive() ? 1 : 0;
  active += REN_PrepareGpuVisionCaster() ? 1 : 0;
  return active;
}
