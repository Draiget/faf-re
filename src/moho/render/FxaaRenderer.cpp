#include "moho/render/FxaaRenderer.h"

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/GpuDriven.h"
#include "gpg/gal/Head.hpp"
#include "moho/console/CConCommand.h"
#include "moho/render/FxaaShader.h"

namespace moho
{
  int ren_Fxaa = 1;

  TConVar<int> gTConVar_ren_Fxaa(
    "ren_Fxaa",
    "FXAA on the world views (Direct3D 12 and Vulkan, which have no multisampled back buffer): 1 (the default) on, "
    "0 off. -1, the old automatic setting a saved option may still hold, means on.",
    &ren_Fxaa
  );

  FxaaRenderer& FxaaRenderer::Get()
  {
    static FxaaRenderer sRenderer;
    return sRenderer;
  }

  bool FxaaRenderer::IsActive()
  {
    if (ren_Fxaa == 0) {
      return false;
    }
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    if (device == nullptr) {
      return false;
    }
    if (device != mDevice) {
      *this = FxaaRenderer();
      mDevice = device;
      gpg::gal::DeviceContext* const context = device->GetDeviceContext();
      const bool modern = context != nullptr
        && (context->mDeviceType == gpg::gal::DeviceApi::Direct3D12 || context->mDeviceType == gpg::gal::DeviceApi::Vulkan);
      if (modern && (device->GetGpuDrivenFeatures() & gpg::gal::kGpuFeatureVertexPulling) != 0U) {
        gpg::gal::GpuProgramDesc desc{};
        desc.name = "Fxaa";
        desc.source = kFxaaShaderSource;
        desc.sourceBytes = sizeof(kFxaaShaderSource) - 1U;
        desc.vertexEntry = "FxaaVS";
        desc.pixelEntry = "FxaaPS";
        desc.blend = gpg::gal::GpuBlend::Opaque;
        desc.colorWriteMask = 0x07U; // alpha is the glow amount the bloom pass reads
        desc.depthTest = false;
        desc.depthWrite = false;
        desc.cullBackFaces = false;
        desc.sampler = gpg::gal::GpuSampler::LinearClamp;
        mProgram = device->CreateGpuProgram(desc);
      }
      mSupported = mProgram != nullptr;
      if (mSupported) {
        gpg::Logf("FXAA: available on this renderer (ren_Fxaa %d)", ren_Fxaa);
      }
    }
    return mSupported;
  }

  void FxaaRenderer::Render(gpg::gal::RenderTarget& copy, const int width, const int height)
  {
    if (!mSupported || width <= 0 || height <= 0) {
      return;
    }
    const float constants[4] = {
      1.0f / static_cast<float>(width), 1.0f / static_cast<float>(height), static_cast<float>(width), static_cast<float>(height),
    };
    gpg::gal::GpuDrawCall draw{};
    draw.program = mProgram.get();
    draw.bindings.constants = constants;
    draw.bindings.constantBytes = sizeof(constants);
    draw.bindings.targets[0] = &copy;
    draw.vertexCountPerInstance = 3U;
    draw.instanceCount = 1U;
    mDevice->DrawGpuProgram(draw);
  }
} // namespace moho
