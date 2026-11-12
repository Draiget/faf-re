#include "moho/render/TemporalAA.h"

#include "moho/render/BoundDepthSupport.h"
#include <algorithm>
#include <cmath>
#include <cstdint>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/GpuDriven.h"
#include "moho/console/CConCommand.h"
#include "moho/math/VMatrix4.h"
#include "moho/render/TemporalAAShader.h"

namespace moho
{
  class IWldTerrainRes;
  // Defined in moho/app/WxRuntimeTypes.cpp and WRenViewport.cpp.
  [[nodiscard]] IWldTerrainRes* REN_GetTerrainRes();
  [[nodiscard]] int REN_GetGameTick();

  // Engine addition (ren_Taa): see TemporalAA.h.
  int ren_Taa = 0;
  float ren_TaaHistory = 0.9f;
  float ren_RenderScale = 1.0f;

  namespace
  {
    TConVar<int> gTConVar_ren_Taa(
      "ren_Taa",
      "Direct3D 12 and Vulkan: temporal anti-aliasing - each frame the world is drawn a fraction of a pixel apart and "
      "blended with the last frames, so edges, thin lines and far detail stop crawling. Replaces FXAA while on. 1 on, "
      "0 "
      "off (default).",
      &ren_Taa
    );
    TConVar<float> gTConVar_ren_TaaHistory(
      "ren_TaaHistory",
      "ren_Taa: how much of the last frames a pixel keeps, 0 to 0.97 (0.9 the default); more is smoother and softer.",
      &ren_TaaHistory
    );

    TConVar<float> gTConVar_ren_RenderScale(
      "ren_RenderScale",
      "With ren_Taa: the world is drawn at this share of the view's width and height (0.5 to 1; 1, the default, is "
      "full size) and the TAA pass rebuilds the full view from it and the last frames (temporal upscaling). Lower is "
      "faster on a slow graphics card and softer. The interface and strategic icons stay full size.",
      &ren_RenderScale
    );

    struct TaaConstants
    {
      gpg::gal::Matrix inverseViewProjection;
      gpg::gal::Matrix prevViewProjection;
      float viewRect[4];
      float params[4];
      float lowRect[4];
      float jitter[4];
    };
    static_assert(sizeof(TaaConstants) == 192, "TaaConstants matches the shader's cbuffer");

    /** The radical inverse of `index` in `base`: the Halton sequence, 0 to 1. */
    [[nodiscard]] float Halton(
      std::uint32_t index,
      const std::uint32_t base
    )
    {
      float fraction = 1.0f;
      float result = 0.0f;
      while (index > 0U) {
        fraction /= static_cast<float>(base);
        result += fraction * static_cast<float>(index % base);
        index /= base;
      }
      return result;
    }

  } // namespace

  TemporalAA& TemporalAA::Get()
  {
    static TemporalAA sTemporalAA;
    return sTemporalAA;
  }

  bool TemporalAA::IsActive()
  {
    if (ren_Taa <= 0) {
      mHistoryValid = false;
      mPending = false;
      return false;
    }
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    if (device == nullptr) {
      return false;
    }
    if (device != mDevice) {
      mDevice = device;
      mSupported = false;
      mCompute.reset();
      mComposite.reset();
      mCompositeAlpha.reset();
      mHistory[0].reset();
      mHistory[1].reset();
      mHistoryCapacity = 0U;
      mHistoryValid = false;
      constexpr std::uint32_t kNeeded = gpg::gal::kGpuFeatureVertexPulling | gpg::gal::kGpuFeatureCompute;
      if (BackendReadsBoundDepth(*device) && (device->GetGpuDrivenFeatures() & kNeeded) == kNeeded) {
        gpg::gal::GpuProgramDesc compute{};
        compute.name = "TemporalAA";
        compute.source = kTemporalAAShaderSource;
        compute.sourceBytes = sizeof(kTemporalAAShaderSource) - 1U;
        compute.computeEntry = "TaaCS";
        mCompute = device->CreateGpuProgram(compute);

        gpg::gal::GpuProgramDesc composite{};
        composite.name = "TemporalAAComposite";
        composite.source = kTemporalAAShaderSource;
        composite.sourceBytes = sizeof(kTemporalAAShaderSource) - 1U;
        composite.vertexEntry = "TaaCompositeVS";
        composite.pixelEntry = "TaaCompositePS";
        composite.blend = gpg::gal::GpuBlend::Opaque;
        composite.colorWriteMask = 0x07U; // alpha is the glow amount and the water mask
        composite.depthTest = false;
        composite.depthWrite = false;
        composite.cullBackFaces = false;
        mComposite = device->CreateGpuProgram(composite);
        composite.name = "TemporalAACompositeAlpha";
        composite.colorWriteMask = 0x0FU; // upscaled: the glow amount and water mask come from the drawn samples
        mCompositeAlpha = device->CreateGpuProgram(composite);
      }
      mSupported = mCompute != nullptr && mComposite != nullptr && mCompositeAlpha != nullptr;
      if (mSupported) {
        gpg::Logf("TAA: on this renderer (ren_Taa)");
      }
    }
    return mSupported;
  }

  GeomCamera3* TemporalAA::Jitter(
    const GeomCamera3& camera,
    const bool allowScale
  )
  {
    // The history is another picture after a map change, a replay going back, another camera, or a camera jump
    // (the eye moved more than a tenth of its height in one frame: a minimap click, a jump to a unit).
    const void* const map = REN_GetTerrainRes();
    const int tick = REN_GetGameTick();
    const float eye[3] = {camera.inverseView.r[3].x, camera.inverseView.r[3].y, camera.inverseView.r[3].z};
    const float dx = eye[0] - mHistoryEye[0];
    const float dy = eye[1] - mHistoryEye[1];
    const float dz = eye[2] - mHistoryEye[2];
    const float jump = 0.1f * std::max(std::abs(eye[1]), 10.0f);
    if (
      &camera != mHistoryCamera || map != mHistoryMap || tick < mHistoryTick ||
      dx * dx + dy * dy + dz * dz > jump * jump
    ) {
      mHistoryValid = false;
    }
    mHistoryCamera = &camera;
    mHistoryMap = map;
    mHistoryTick = tick;
    std::copy(eye, eye + 3, mHistoryEye);

    mJittered = camera;
    const float fullWidth = std::max(camera.viewport.r[3].z, 1.0f);
    const float fullHeight = std::max(camera.viewport.r[3].w, 1.0f);
    // Without the post passes or the history buffers the resolve can't run: an offset nothing takes back would
    // shake the picture by a fraction of a pixel every frame, so the world is drawn as it is.
    if (!allowScale || !EnsureHistory(static_cast<int>(fullWidth), static_cast<int>(fullHeight))) {
      mPending = false;
      mHistoryValid = false;
      return &mJittered;
    }
    // ren_RenderScale: the world is drawn into the top-left share of the view; the resolve rebuilds the rest (only
    // with the history for the full view, so a resolve that couldn't run never leaves the world in a corner).
    mScale = std::clamp(ren_RenderScale, 0.5f, 1.0f);
    const float width = std::max(std::floor(fullWidth * mScale), 1.0f);
    const float height = std::max(std::floor(fullHeight * mScale), 1.0f);
    // 8 offsets of the Halton (2, 3) sequence, within the pixel; in clip space x grows right and y up.
    const std::uint32_t step = (mFrame++ % 8U) + 1U;
    mJitterPixels[0] = Halton(step, 2U) - 0.5f;
    mJitterPixels[1] = Halton(step, 3U) - 0.5f;
    const float jitterX = mJitterPixels[0] * 2.0f / width;
    const float jitterY = -mJitterPixels[1] * 2.0f / height;
    // Row vectors: clip.x += jitter * clip.w, for perspective (w from z, row 2) and orthographic (w = 1, row 3).
    gpg::gal::Matrix projection = camera.projection;
    projection.r[2].x += jitterX * projection.r[2].w;
    projection.r[3].x += jitterX * projection.r[3].w;
    projection.r[2].y += jitterY * projection.r[2].w;
    projection.r[3].y += jitterY * projection.r[3].w;
    mJittered.SetProjection(projection);
    // SetProjection rebuilds the viewport rows without the LOD scale; the rest of the camera stays the view's.
    mJittered.viewport = camera.viewport;
    mJittered.lodScale = camera.lodScale;
    if (width < fullWidth || height < fullHeight) {
      // A smaller viewport, as a split view has: the passes size themselves from it (WRenViewport's local screen,
      // the terrain's water mapping). The per-pixel rows (r[0..2]) stay the full view's, so markers sized in pixels
      // (selection brackets, footprints) come out their size on screen once the picture is scaled up.
      mJittered.viewport.r[3].z = width;
      mJittered.viewport.r[3].w = height;
    }
    mLowWidth = static_cast<int>(width);
    mLowHeight = static_cast<int>(height);
    mFullRect[0] = static_cast<int>(camera.viewport.r[3].x);
    mFullRect[1] = static_cast<int>(camera.viewport.r[3].y);
    mFullRect[2] = static_cast<int>(fullWidth);
    mFullRect[3] = static_cast<int>(fullHeight);
    mViewProjection = camera.viewProjection;
    mInverseViewProjection = camera.inverseViewProjection;
    mPending = true;
    return &mJittered;
  }

  bool TemporalAA::EnsureHistory(
    const int width,
    const int height
  )
  {
    if (!mSupported || width < 8 || height < 8) {
      return false;
    }
    const std::uint32_t needed = static_cast<std::uint32_t>(width) * static_cast<std::uint32_t>(height);
    if (mHistory[0] != nullptr && mHistory[1] != nullptr && needed <= mHistoryCapacity) {
      return true;
    }
    for (boost::shared_ptr<gpg::gal::GpuBuffer>& history : mHistory) {
      gpg::gal::GpuBufferDesc desc{};
      desc.name = "TemporalAAHistory";
      desc.stride = 4U * sizeof(float);
      desc.capacity = needed;
      desc.shaderWrite = true;
      history = mDevice->CreateGpuBuffer(desc);
    }
    mHistoryCapacity = (mHistory[0] != nullptr && mHistory[1] != nullptr) ? needed : 0U;
    mHistoryValid = false;
    return mHistoryCapacity != 0U;
  }

  bool TemporalAA::Resolve(
    gpg::gal::RenderTarget& copy,
    const int x,
    const int y,
    const int width,
    const int height
  )
  {
    if (!mPending) {
      return false;
    }
    mPending = false;
    if (!mSupported || width < 8 || height < 8) {
      mHistoryValid = false;
      return false;
    }
    if (!EnsureHistory(width, height)) {
      return false;
    }
    if (width != mHistoryWidth || height != mHistoryHeight) {
      mHistoryWidth = width;
      mHistoryHeight = height;
      mHistoryValid = false;
    }

    TaaConstants constants{};
    // The unmoved camera: a still point lands on the same pixel centre as last frame, so the history isn't
    // resampled (and blurred) every frame by the offset.
    constants.inverseViewProjection = mInverseViewProjection;
    constants.prevViewProjection = mPrevViewProjection;
    constants.viewRect[0] = static_cast<float>(x);
    constants.viewRect[1] = static_cast<float>(y);
    constants.viewRect[2] = static_cast<float>(width);
    constants.viewRect[3] = static_cast<float>(height);
    constants.params[0] = std::clamp(ren_TaaHistory, 0.0f, 0.97f);
    constants.params[1] = mHistoryValid ? 1.0f : 0.0f;
    const bool upscaled = mLowWidth < width || mLowHeight < height;
    constants.params[2] = upscaled ? 1.0f : 0.0f;
    constants.lowRect[0] = static_cast<float>(x);
    constants.lowRect[1] = static_cast<float>(y);
    constants.lowRect[2] = static_cast<float>(std::min(mLowWidth, width));
    constants.lowRect[3] = static_cast<float>(std::min(mLowHeight, height));
    constants.jitter[0] = mJitterPixels[0];
    constants.jitter[1] = mJitterPixels[1];

    const int read = mCurrent;
    const int write = 1 - mCurrent;
    gpg::gal::GpuDispatch dispatch{};
    dispatch.program = mCompute.get();
    dispatch.bindings.constants = &constants;
    dispatch.bindings.constantBytes = sizeof(constants);
    dispatch.bindings.readBuffers[0] = mHistory[read].get();
    dispatch.bindings.writeBuffers[0] = mHistory[write].get();
    dispatch.bindings.targets[0] = &copy;
    dispatch.bindings.readBoundDepth = true;
    dispatch.groupsX = (static_cast<std::uint32_t>(width) + 7U) / 8U;
    dispatch.groupsY = (static_cast<std::uint32_t>(height) + 7U) / 8U;
    mDevice->DispatchGpuProgram(dispatch);

    gpg::gal::GpuDrawCall draw{};
    draw.program = upscaled ? mCompositeAlpha.get() : mComposite.get();
    draw.bindings.constants = &constants;
    draw.bindings.constantBytes = sizeof(constants);
    draw.bindings.readBuffers[0] = mHistory[write].get();
    draw.vertexCountPerInstance = 3U;
    draw.instanceCount = 1U;
    mDevice->DrawGpuProgram(draw);

    mCurrent = write;
    mHistoryValid = true;
    mPrevViewProjection = mViewProjection;
    return true;
  }
} // namespace moho
