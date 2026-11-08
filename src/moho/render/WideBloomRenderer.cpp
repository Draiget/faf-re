#include "moho/render/WideBloomRenderer.h"

#include <algorithm>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/GpuDriven.h"
#include "moho/console/CConCommand.h"
#include "moho/render/ID3DRenderTarget.h"
#include "moho/render/WideBloomShader.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "Wm3IVector2.h"

namespace moho
{
  float ren_BloomWide = 0.0f;

  TConVar<float> gTConVar_ren_BloomWide(
    "ren_BloomWide",
    "Wide, soft glow added after the bloom on Direct3D 12 and Vulkan, around lights, explosions and shields: its "
    "strength, 0 (off) by default, 1 normal, up to 2. Needs ren_Bloom.",
    &ren_BloomWide
  );

  float ren_BloomWideThreshold = 0.2f;

  TConVar<float> gTConVar_ren_BloomWideThreshold(
    "ren_BloomWideThreshold",
    "Glow level, on the weakest colour channel, below which ren_BloomWide spreads nothing (0.2 by default), ramped "
    "in up to twice that: the bloom's glow holds a faint copy of the whole scene, which would otherwise haze "
    "everything, and strongly coloured glow such as green build ghosts keeps only the original bloom.",
    &ren_BloomWideThreshold
  );

  namespace
  {
    // The bloom targets' format (CBloomRenderer::Init).
    constexpr int kGlowTargetFormat = 2;
  } // namespace

  WideBloomRenderer& WideBloomRenderer::Get(const int head)
  {
    static WideBloomRenderer sRenderers[2];
    return sRenderers[head == 1 ? 1 : 0];
  }

  bool WideBloomRenderer::IsActive()
  {
    if (!(ren_BloomWide > 0.0f)) {
      return false;
    }
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    if (device == nullptr) {
      return false;
    }
    if (device != mDevice) {
      *this = WideBloomRenderer();
      mDevice = device;
      gpg::gal::DeviceContext* const context = device->GetDeviceContext();
      const bool modern = context != nullptr
        && (context->mDeviceType == gpg::gal::DeviceApi::Direct3D12 || context->mDeviceType == gpg::gal::DeviceApi::Vulkan);
      if (modern && (device->GetGpuDrivenFeatures() & gpg::gal::kGpuFeatureVertexPulling) != 0U) {
        gpg::gal::GpuProgramDesc desc{};
        desc.source = kWideBloomShaderSource;
        desc.sourceBytes = sizeof(kWideBloomShaderSource) - 1U;
        desc.vertexEntry = "WideVS";
        desc.depthTest = false;
        desc.depthWrite = false;
        desc.cullBackFaces = false;
        desc.sampler = gpg::gal::GpuSampler::LinearClamp;
        desc.name = "BloomWideDown";
        desc.pixelEntry = "DownPS";
        desc.blend = gpg::gal::GpuBlend::Opaque;
        desc.colorWriteMask = 0x0FU;
        mDown = device->CreateGpuProgram(desc);
        desc.name = "BloomWideUp";
        desc.pixelEntry = "UpPS";
        desc.blend = gpg::gal::GpuBlend::Additive; // src * weight + dst
        desc.colorWriteMask = 0x07U;               // the head's alpha is the glow amount and the water mask
        mUp = device->CreateGpuProgram(desc);
      }
      mSupported = mDown != nullptr && mUp != nullptr;
      if (mSupported) {
        gpg::Logf("Bloom: wide glow available on this renderer (ren_BloomWide %.2f)", ren_BloomWide);
      }
    }
    return mSupported;
  }

  bool WideBloomRenderer::EnsureLevels(const int glowWidth, const int glowHeight)
  {
    if (glowWidth == mGlowWidth && glowHeight == mGlowHeight && mLevels[kLevels - 1].target) {
      return true;
    }
    mGlowWidth = glowWidth;
    mGlowHeight = glowHeight;
    ID3DDeviceResources* const resources = D3D_GetDevice()->GetResources();
    int width = glowWidth;
    int height = glowHeight;
    for (Level& level : mLevels) {
      width = std::max(width / 2, 1);
      height = std::max(height / 2, 1);
      level.width = width;
      level.height = height;
      level.target.reset();
      ID3DDeviceResources::RenderTargetHandle created{};
      resources->CreateRenderTarget(created, width, height, kGlowTargetFormat);
      level.target = created;
      if (!level.target) {
        gpg::Logf("Bloom: wide glow target %dx%d could not be created; ren_BloomWide off for this device", width, height);
        mSupported = false;
        return false;
      }
    }
    return true;
  }

  void WideBloomRenderer::Render(
    const int head, const boost::shared_ptr<ID3DRenderTarget>& glow, const int glowWidth, const int glowHeight
  )
  {
    if (!mSupported || !glow || glowWidth <= 1 || glowHeight <= 1 || !EnsureLevels(glowWidth, glowHeight)) {
      return;
    }
    CD3DDevice* const device = D3D_GetDevice();

    Wm3::Vector2i savedPos{};
    Wm3::Vector2i savedSize{};
    float savedMinZ = 0.0f;
    float savedMaxZ = 1.0f;
    device->GetView(&savedPos, &savedSize, &savedMinZ, &savedMaxZ);

    boost::shared_ptr<CD3DDepthStencil> activeDepthStencil;
    ID3DDepthStencil* const depthStencil = device->GetDepthStencil(activeDepthStencil).get();

    // One full-target triangle from `source` (`sourceWidth` by `sourceHeight`) into the bound
    // target (`width` by `height`) with `program`.
    const auto pass = [&](gpg::gal::GpuProgram* const program, const boost::shared_ptr<ID3DRenderTarget>& source,
                          const int sourceWidth, const int sourceHeight, const int width, const int height,
                          const float weight, const float threshold) {
      ID3DRenderTarget::SurfaceHandle surface{};
      (void)source->GetSurface(surface);
      if (!surface) {
        return;
      }
      Wm3::Vector2i pos{0, 0};
      Wm3::Vector2i size{width, height};
      device->SetViewport(&pos, &size, 0.0f, 1.0f);
      const float constants[12] = {
        1.0f / static_cast<float>(sourceWidth), 1.0f / static_cast<float>(sourceHeight),
        static_cast<float>(sourceWidth), static_cast<float>(sourceHeight),
        1.0f / static_cast<float>(width), 1.0f / static_cast<float>(height),
        static_cast<float>(width), static_cast<float>(height),
        weight, threshold, 0.0f, 0.0f,
      };
      gpg::gal::GpuDrawCall draw{};
      draw.program = program;
      draw.bindings.constants = constants;
      draw.bindings.constantBytes = sizeof(constants);
      draw.bindings.targets[0] = surface.get();
      draw.vertexCountPerInstance = 3U;
      draw.instanceCount = 1U;
      mDevice->DrawGpuProgram(draw);
    };

    // Down: glow -> level 0 -> ... -> level 3, the threshold on the first step only.
    const boost::shared_ptr<ID3DRenderTarget>* source = &glow;
    int sourceWidth = glowWidth;
    int sourceHeight = glowHeight;
    float threshold = std::clamp(ren_BloomWideThreshold, 0.0f, 0.5f);
    for (Level& level : mLevels) {
      device->SetRenderTarget1(level.target.get(), depthStencil, false, 0, 1.0f, 0);
      pass(mDown.get(), *source, sourceWidth, sourceHeight, level.width, level.height, 1.0f, threshold);
      threshold = 0.0f;
      source = &level.target;
      sourceWidth = level.width;
      sourceHeight = level.height;
    }

    // Up: level 3 is added into level 2, ..., level 1 into level 0, so level 0 holds the sum.
    for (int index = kLevels - 1; index > 0; --index) {
      Level& smaller = mLevels[index];
      Level& larger = mLevels[index - 1];
      device->SetRenderTarget1(larger.target.get(), depthStencil, false, 0, 1.0f, 0);
      pass(mUp.get(), smaller.target, smaller.width, smaller.height, larger.width, larger.height, 1.0f, 0.0f);
    }

    // Onto the head: the average of the four levels, times the strength.
    device->SetRenderTarget2(head, false, 0, 1.0f, 0);
    const int headWidth = device->GetHeadWidth(static_cast<unsigned int>(head));
    const int headHeight = device->GetHeadHeight(static_cast<unsigned int>(head));
    pass(mUp.get(), mLevels[0].target, mLevels[0].width, mLevels[0].height, headWidth, headHeight,
         std::min(ren_BloomWide, 2.0f) / static_cast<float>(kLevels), 0.0f);

    device->SetViewport(&savedPos, &savedSize, savedMinZ, savedMaxZ);
  }
} // namespace moho
