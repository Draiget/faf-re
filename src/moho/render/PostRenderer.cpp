#include "moho/render/PostRenderer.h"

#include <algorithm>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/GpuDriven.h"
#include "gpg/gal/Head.hpp"
#include "moho/console/CConCommand.h"
#include "moho/render/PostShader.h"

namespace moho
{
  float ren_Sharpen = 0.5f;
  int ren_Grade = 1;
  float ren_GradeVibrance = 0.25f;
  float ren_GradeContrast = 0.15f;

  TConVar<float> gTConVar_ren_Sharpen(
    "ren_Sharpen",
    "Contrast-adaptive sharpening of the world views on Direct3D 12 and Vulkan, 0 to 1 (0.5 by default); 0 off.",
    &ren_Sharpen
  );

  TConVar<int> gTConVar_ren_Grade(
    "ren_Grade",
    "Colour grade of the world views on Direct3D 12 and Vulkan (vibrance and a gentle contrast curve): 1 (the "
    "default) on, 0 off.",
    &ren_Grade
  );

  TConVar<float> gTConVar_ren_GradeVibrance(
    "ren_GradeVibrance",
    "Saturation added to dull colours by ren_Grade (0.25 by default); strong colours such as team colours change little.",
    &ren_GradeVibrance
  );

  TConVar<float> gTConVar_ren_GradeContrast(
    "ren_GradeContrast",
    "Share of an S-curve mixed in by ren_Grade, 0 to 1 (0.15 by default): darker shadows, brighter highlights.",
    &ren_GradeContrast
  );

  PostRenderer& PostRenderer::Get()
  {
    static PostRenderer sRenderer;
    return sRenderer;
  }

  bool PostRenderer::IsActive()
  {
    if (ren_Sharpen <= 0.0f && ren_Grade == 0) {
      return false;
    }
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    if (device == nullptr) {
      return false;
    }
    if (device != mDevice) {
      *this = PostRenderer();
      mDevice = device;
      gpg::gal::DeviceContext* const context = device->GetDeviceContext();
      const bool modern = context != nullptr
        && (context->mDeviceType == gpg::gal::DeviceApi::Direct3D12 || context->mDeviceType == gpg::gal::DeviceApi::Vulkan);
      if (modern && (device->GetGpuDrivenFeatures() & gpg::gal::kGpuFeatureVertexPulling) != 0U) {
        gpg::gal::GpuProgramDesc desc{};
        desc.name = "Post";
        desc.source = kPostShaderSource;
        desc.sourceBytes = sizeof(kPostShaderSource) - 1U;
        desc.vertexEntry = "PostVS";
        desc.pixelEntry = "PostPS";
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
        gpg::Logf("Post: sharpening and grading available on this renderer (ren_Sharpen %.2f, ren_Grade %d)", ren_Sharpen, ren_Grade);
      }
    }
    return mSupported;
  }

  void PostRenderer::Render(gpg::gal::RenderTarget& copy, const int width, const int height)
  {
    if (!mSupported || width <= 0 || height <= 0) {
      return;
    }
    const bool grade = ren_Grade != 0;
    const float constants[8] = {
      1.0f / static_cast<float>(width),
      1.0f / static_cast<float>(height),
      static_cast<float>(width),
      static_cast<float>(height),
      ren_Sharpen > 0.0f ? std::min(ren_Sharpen, 1.0f) : -1.0f,
      grade ? std::clamp(ren_GradeVibrance, -1.0f, 1.0f) : 0.0f,
      grade ? std::clamp(ren_GradeContrast, 0.0f, 1.0f) : 0.0f,
      0.0f,
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
