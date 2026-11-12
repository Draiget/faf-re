#include "moho/render/BounceLight.h"

#include "moho/render/BoundDepthSupport.h"
#include <algorithm>
#include <cstdint>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/GpuDriven.h"
#include "gpg/gal/effects/RayTracedShadows.h"
#include "moho/console/CConCommand.h"
#include "moho/math/VMatrix4.h"
#include "moho/render/BounceLightShader.h"
#include "moho/render/camera/GeomCamera3.h"

namespace moho
{
  // Engine addition (ren_RayBounce): see BounceLight.h.
  int ren_RayBounce = 0;
  int ren_RayBounceRays = 4;
  float ren_RayBounceRadius = 10.0f;
  float ren_RayBounceStrength = 1.0f;
  float ren_RayBounceReach = 500.0f;
  extern float ren_RayAoLift; // AmbientOcclusionRenderer.cpp: the rays' lift per unit of camera distance

  namespace
  {
    TConVar<int> gTConVar_ren_RayBounce(
      "ren_RayBounce",
      "With ren_RayTracedShadows: one bounce of diffuse light by ray - grass, sunlit cliffs and buildings light what "
      "stands next to them in their own colour. 1 on, 0 off (default).",
      &ren_RayBounce
    );
    TConVar<int> gTConVar_ren_RayBounceRays(
      "ren_RayBounceRays",
      "ren_RayBounce: rays per point (1-16, 4 the default).",
      &ren_RayBounceRays
    );
    TConVar<float> gTConVar_ren_RayBounceRadius(
      "ren_RayBounceRadius",
      "ren_RayBounce: how far, in world units, a point gathers bounced light (10 the default).",
      &ren_RayBounceRadius
    );
    TConVar<float> gTConVar_ren_RayBounceStrength(
      "ren_RayBounceStrength",
      "ren_RayBounce: how strong the bounced light is (1 the default).",
      &ren_RayBounceStrength
    );
    TConVar<float> gTConVar_ren_RayBounceReach(
      "ren_RayBounceReach",
      "ren_RayBounce: points further than this from the camera get none (500 the default).",
      &ren_RayBounceReach
    );

    struct BounceConstants
    {
      VMatrix4 inverseViewProjection;
      VMatrix4 viewProjection;
      float viewRect[4];
      float bufferSize[4];
      float eye[4];
      float params[4];
      float params2[4];
    };
    static_assert(sizeof(BounceConstants) == 208, "BounceConstants matches the shader's cbuffer");

  } // namespace

  BounceLight& BounceLight::Get()
  {
    static BounceLight sBounceLight;
    return sBounceLight;
  }

  bool BounceLight::IsActive()
  {
    if (ren_RayBounce <= 0) {
      return false;
    }
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    if (device == nullptr) {
      return false;
    }
    if (device != mDevice) {
      *this = BounceLight();
      mDevice = device;
      constexpr std::uint32_t kNeeded =
        gpg::gal::kGpuFeatureVertexPulling | gpg::gal::kGpuFeatureCompute | gpg::gal::kGpuFeatureRayQuery;
      if (BackendReadsBoundDepth(*device) && (device->GetGpuDrivenFeatures() & kNeeded) == kNeeded) {
        gpg::gal::GpuProgramDesc compute{};
        compute.name = "BounceLight";
        compute.source = kBounceLightShaderSource;
        compute.sourceBytes = sizeof(kBounceLightShaderSource) - 1U;
        compute.computeEntry = "BounceCS";
        mCompute = device->CreateGpuProgram(compute);

        gpg::gal::GpuProgramDesc composite{};
        composite.name = "BounceLightComposite";
        composite.source = kBounceLightShaderSource;
        composite.sourceBytes = sizeof(kBounceLightShaderSource) - 1U;
        composite.vertexEntry = "BounceCompositeVS";
        composite.pixelEntry = "BounceCompositePS";
        composite.blend = gpg::gal::GpuBlend::Brighten; // colour * (1 + light): lit ground keeps its hue
        composite.colorWriteMask = 0x07U;               // alpha is the glow amount and the water mask
        composite.depthTest = false;
        composite.depthWrite = false;
        composite.cullBackFaces = false;
        mComposite = device->CreateGpuProgram(composite);
      }
      mSupported = mCompute != nullptr && mComposite != nullptr;
      if (mSupported) {
        gpg::Logf("Bounce light: on this renderer (ren_RayBounce)");
      }
    }
    // The ray-traced scene must be this frame's (RayScene published it: ren_RayTracedShadows traced).
    return mSupported && gpg::gal::effects::gRayShadows.vectors[4][0] > 0.0f;
  }

  void BounceLight::Render(
    const GeomCamera3& camera,
    gpg::gal::RenderTarget& frame,
    const float waterLevel,
    const int x,
    const int y,
    const int width,
    const int height
  )
  {
    if (!mSupported || width < 8 || height < 8 || ren_RayBounceRadius <= 0.0f || ren_RayBounceStrength <= 0.0f) {
      return;
    }
    const auto samplesAcross = static_cast<std::uint32_t>(width + 1) / 2U;
    const auto samplesDown = static_cast<std::uint32_t>(height + 1) / 2U;
    const std::uint32_t needed = samplesAcross * samplesDown;
    if (mTerms == nullptr || needed > mTermCapacity) {
      gpg::gal::GpuBufferDesc desc{};
      desc.name = "BounceLightTerms";
      desc.stride = 4U * sizeof(float);
      desc.capacity = needed;
      desc.shaderWrite = true;
      mTerms = mDevice->CreateGpuBuffer(desc);
      mTermCapacity = (mTerms != nullptr) ? needed : 0U;
      if (mTerms == nullptr) {
        return;
      }
    }

    BounceConstants constants{};
    constants.inverseViewProjection = camera.inverseViewProjection;
    constants.viewProjection = camera.viewProjection;
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
    constants.eye[3] = std::max(ren_RayBounceReach, 1.0f);
    constants.params[0] = ren_RayBounceRadius;
    constants.params[1] = ren_RayBounceStrength;
    constants.params[2] = static_cast<float>(std::clamp(ren_RayBounceRays, 1, 16));
    constants.params[3] = std::max(ren_RayAoLift, 0.0f);
    constants.params2[0] = gpg::gal::effects::gRayShadows.vectors[7][1];
    constants.params2[1] = waterLevel;

    gpg::gal::GpuDispatch dispatch{};
    dispatch.program = mCompute.get();
    dispatch.bindings.constants = &constants;
    dispatch.bindings.constantBytes = sizeof(constants);
    dispatch.bindings.writeBuffers[0] = mTerms.get();
    dispatch.bindings.targets[0] = &frame;
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
