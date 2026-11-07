#include "moho/render/AmbientOcclusionRenderer.h"

#include <algorithm>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/GpuDriven.h"
#include "moho/console/CConCommand.h"
#include "moho/math/VMatrix4.h"
#include "moho/render/AmbientOcclusionShader.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/sim/CWldMap.h"

namespace moho
{
  int ren_Ao = -1;
  float ren_AoRadius = 2.0f;
  float ren_AoIntensity = 1.0f;
  float ren_AoBias = 0.25f;
  float ren_AoFadeStart = 120.0f;
  float ren_AoFadeEnd = 260.0f;

  TConVar<int> gTConVar_ren_Ao(
    "ren_Ao",
    "Ambient occlusion from scene depth: 1 on, 0 off, -1 (the default) on Direct3D 12 and Vulkan. "
    "Direct3D 9 and 11 can't read the depth target and keep the original look.",
    &ren_Ao
  );
  TConVar<float> gTConVar_ren_AoRadius("ren_AoRadius", "Ambient occlusion reach in world units.", &ren_AoRadius);
  TConVar<float> gTConVar_ren_AoIntensity("ren_AoIntensity", "Ambient occlusion strength.", &ren_AoIntensity);
  TConVar<float> gTConVar_ren_AoBias(
    "ren_AoBias",
    "How steeply (as a cosine, 0..1) a neighbour must rise above a surface before it occludes it; "
    "keeps the creases between terrain triangles clean.",
    &ren_AoBias
  );
  TConVar<float> gTConVar_ren_AoFadeStart(
    "ren_AoFadeStart", "Camera distance where ambient occlusion starts to fade out.", &ren_AoFadeStart
  );
  TConVar<float> gTConVar_ren_AoFadeEnd("ren_AoFadeEnd", "Camera distance where ambient occlusion is gone.", &ren_AoFadeEnd);

  float ren_AoContact = 0.35f;
  float ren_AoContactLength = 1.5f;
  TConVar<float> gTConVar_ren_AoContact(
    "ren_AoContact",
    "Contact shadow strength, 0 to 1: how much a short ray towards the sun that hits nearby depth darkens "
    "(part of ren_Ao; 0 turns contact shadows off).",
    &ren_AoContact
  );
  TConVar<float> gTConVar_ren_AoContactLength(
    "ren_AoContactLength", "Contact shadow ray length in world units.", &ren_AoContactLength
  );

  // Defined in moho/app/WxRuntimeTypes.cpp (0x007FA170).
  [[nodiscard]] IWldTerrainRes* REN_GetTerrainRes();

  namespace
  {
    struct AoConstants
    {
      VMatrix4 inverseViewProjection;
      float viewRect[4];
      float bufferSize[4];
      float eye[4];
      float radius;
      float intensity;
      float projScale;
      float bias;
      float fadeStart;
      float fadeEnd;
      float unused[2];
      VMatrix4 viewProjection;
      float sun[4];
      float contact[4];
    };
    static_assert(sizeof(AoConstants) == 240, "AoConstants matches the shader's cbuffer");

    [[nodiscard]] bool BackendReadsBoundDepth(gpg::gal::Device& device)
    {
      const gpg::gal::DeviceContext* const context = device.GetDeviceContext();
      return context != nullptr
        && (context->mDeviceType == gpg::gal::DeviceApi::Direct3D12 || context->mDeviceType == gpg::gal::DeviceApi::Vulkan);
    }
  } // namespace

  AmbientOcclusionRenderer& AmbientOcclusionRenderer::Get()
  {
    static AmbientOcclusionRenderer sRenderer;
    return sRenderer;
  }

  bool AmbientOcclusionRenderer::IsActive()
  {
    if (ren_Ao == 0) {
      return false;
    }
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    if (device == nullptr) {
      return false;
    }
    if (device != mDevice) {
      *this = AmbientOcclusionRenderer();
      mDevice = device;
      constexpr std::uint32_t kNeeded = gpg::gal::kGpuFeatureVertexPulling | gpg::gal::kGpuFeatureCompute;
      if (BackendReadsBoundDepth(*device) && (device->GetGpuDrivenFeatures() & kNeeded) == kNeeded) {
        gpg::gal::GpuProgramDesc compute{};
        compute.name = "AmbientOcclusion";
        compute.source = kAmbientOcclusionShaderSource;
        compute.sourceBytes = sizeof(kAmbientOcclusionShaderSource) - 1U;
        compute.computeEntry = "AoCS";
        mCompute = device->CreateGpuProgram(compute);

        gpg::gal::GpuProgramDesc composite{};
        composite.name = "AmbientOcclusionComposite";
        composite.source = kAmbientOcclusionShaderSource;
        composite.sourceBytes = sizeof(kAmbientOcclusionShaderSource) - 1U;
        composite.vertexEntry = "AoCompositeVS";
        composite.pixelEntry = "AoCompositePS";
        composite.blend = gpg::gal::GpuBlend::Multiply;
        composite.colorWriteMask = 0x07U; // alpha is the glow amount and the water mask
        composite.depthTest = false;
        composite.depthWrite = false;
        composite.cullBackFaces = false;
        mComposite = device->CreateGpuProgram(composite);
      }
      mSupported = mCompute != nullptr && mComposite != nullptr;
      if (mSupported) {
        gpg::Logf("Ambient occlusion: on this renderer (ren_Ao)");
      }
    }
    return mSupported;
  }

  void AmbientOcclusionRenderer::Render(const GeomCamera3& camera, const int x, const int y, const int width, const int height)
  {
    if (!mSupported || width < 8 || height < 8 || ren_AoRadius <= 0.0f || ren_AoIntensity <= 0.0f) {
      return;
    }
    const auto samplesAcross = static_cast<std::uint32_t>(width + 1) / 2U;
    const auto samplesDown = static_cast<std::uint32_t>(height + 1) / 2U;
    const std::uint32_t needed = samplesAcross * samplesDown;
    if (mTerms == nullptr || needed > mTermCapacity) {
      gpg::gal::GpuBufferDesc desc{};
      desc.name = "AmbientOcclusionTerms";
      desc.stride = 2U * sizeof(float);
      desc.capacity = needed;
      desc.shaderWrite = true;
      mTerms = mDevice->CreateGpuBuffer(desc);
      mTermCapacity = (mTerms != nullptr) ? needed : 0U;
      if (mTerms == nullptr) {
        return;
      }
    }

    AoConstants constants{};
    constants.inverseViewProjection = camera.inverseViewProjection;
    constants.viewRect[0] = static_cast<float>(x);
    constants.viewRect[1] = static_cast<float>(y);
    constants.viewRect[2] = static_cast<float>(width);
    constants.viewRect[3] = static_cast<float>(height);
    constants.bufferSize[0] = static_cast<float>(samplesAcross);
    constants.bufferSize[1] = static_cast<float>(samplesDown);
    constants.bufferSize[2] = 1.0f / static_cast<float>(samplesAcross);
    constants.bufferSize[3] = 1.0f / static_cast<float>(samplesDown);
    constants.eye[0] = camera.inverseView.r[3].x;
    constants.eye[1] = camera.inverseView.r[3].y;
    constants.eye[2] = camera.inverseView.r[3].z;
    constants.radius = ren_AoRadius;
    constants.intensity = ren_AoIntensity;
    // Half the view's height spans one unit of the projection's y scale; samples are every second pixel.
    constants.projScale = camera.projection.r[1].y * static_cast<float>(height) * 0.25f;
    constants.bias = ren_AoBias;
    constants.fadeStart = ren_AoFadeStart;
    constants.fadeEnd = std::max(ren_AoFadeEnd, ren_AoFadeStart + 1.0f);
    constants.viewProjection = camera.viewProjection;
    if (IWldTerrainRes* const terrain = REN_GetTerrainRes(); terrain != nullptr && ren_AoContact > 0.0f) {
      Wm3::Vector3f sun = terrain->GetSunDirection();
      sun.Normalize();
      constants.sun[0] = sun.X();
      constants.sun[1] = sun.Y();
      constants.sun[2] = sun.Z();
      constants.sun[3] = std::min(ren_AoContact, 1.0f);
      constants.contact[0] = std::max(ren_AoContactLength, 0.1f);
      constants.contact[1] = std::max(ren_AoContactLength, 0.1f);
    }

    gpg::gal::GpuDispatch dispatch{};
    dispatch.program = mCompute.get();
    dispatch.bindings.constants = &constants;
    dispatch.bindings.constantBytes = sizeof(constants);
    dispatch.bindings.writeBuffers[0] = mTerms.get();
    dispatch.bindings.readBoundDepth = true;
    dispatch.groupsX = (samplesAcross + 7U) / 8U;
    dispatch.groupsY = (samplesDown + 7U) / 8U;
    mDevice->DispatchGpuProgram(dispatch);

    gpg::gal::GpuDrawCall draw{};
    draw.program = mComposite.get();
    draw.bindings.constants = &constants;
    draw.bindings.constantBytes = sizeof(constants);
    draw.bindings.readBuffers[0] = mTerms.get();
    draw.vertexCountPerInstance = 3U;
    draw.instanceCount = 1U;
    mDevice->DrawGpuProgram(draw);
  }
} // namespace moho
