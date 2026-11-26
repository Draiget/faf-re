#include "gpg/gal/RenderScalePass.h"

#include <algorithm>
#include <string>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/DepthStencilTargetContext.hpp"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/RenderTargetContext.hpp"

namespace gpg::gal
{
  namespace
  {
    // gal render target format 2: B8G8R8A8, the back buffer's format (CD3DDevice's head targets use it too). Depth:
    // format 3 (D24S8).
    constexpr std::uint32_t kColorFormat = 2U;
    constexpr std::uint32_t kDepthFormat = 3U;

    D3DVIEWPORT9 MakeViewport(
      const RenderScaleRect& rect
    )
    {
      D3DVIEWPORT9 viewport{};
      viewport.X = static_cast<DWORD>(std::max(rect.x, 0));
      viewport.Y = static_cast<DWORD>(std::max(rect.y, 0));
      viewport.Width = static_cast<DWORD>(std::max(rect.width, 1));
      viewport.Height = static_cast<DWORD>(std::max(rect.height, 1));
      viewport.MinZ = 0.0f;
      viewport.MaxZ = 1.0f;
      return viewport;
    }
  } // namespace

  RenderScalePass& RenderScalePass::Instance()
  {
    static RenderScalePass instance;
    return instance;
  }

  void RenderScalePass::ReleaseTargets()
  {
    mColor.reset();
    mDepth.reset();
    mMiddle.reset();
    mWidth = mHeight = 0U;
    mWindowWidth = mWindowHeight = 0U;
    mMiddleWidth = mMiddleHeight = 0U;
  }

  void RenderScalePass::Release()
  {
    ReleaseTargets();
    mUpscale.reset();
    mSharpen.reset();
    mDevice = nullptr;
    mFailed = false;
    mLoggedRefusal = false;
  }

  bool RenderScalePass::EnsureProgram(
    Device& device
  )
  {
    if (mDevice != &device) {
      Release();
      mDevice = &device;
    }
    if (mUpscale != nullptr && mSharpen != nullptr) {
      return true;
    }
    const std::string source = RenderScaleSource();
    const auto make = [&](const char* const name, const char* const pixelEntry) {
      GpuProgramDesc desc;
      desc.name = name;
      desc.source = source.c_str();
      desc.sourceBytes = source.size();
      desc.vertexEntry = "ScaleVS";
      desc.pixelEntry = pixelEntry;
      desc.sampler = GpuSampler::PointClamp;
      desc.blend = GpuBlend::Opaque;
      desc.colorWriteMask = 0x07U; // the alpha channel of the back buffer is left alone
      return device.CreateGpuProgram(desc);
    };
    mUpscale = make("RenderScaleUpscale", "UpscalePS");
    mSharpen = make("RenderScaleSharpen", "SharpenPS");
    if (mUpscale == nullptr || mSharpen == nullptr) {
      mUpscale.reset();
      mSharpen.reset();
      mFailed = true;
      gpg::Warnf("Render scale disabled: its GPU programs did not compile");
      return false;
    }
    return true;
  }

  bool RenderScalePass::Prepare(
    Device& device,
    const std::uint32_t windowWidth,
    const std::uint32_t windowHeight,
    const float factor
  )
  {
    if (mFailed && mDevice == &device) {
      return false;
    }
    if ((device.GetGpuDrivenFeatures() & kGpuFeatureVertexPulling) == 0U) {
      if (!mLoggedRefusal) {
        mLoggedRefusal = true;
        gpg::Warnf(
          "Render scale is not available: this render API has no GPU programs; the world is drawn at full size"
        );
      }
      return false;
    }
    if (!EnsureProgram(device)) {
      return false;
    }
    if (
      mColor != nullptr && mDepth != nullptr && mWindowWidth == windowWidth && mWindowHeight == windowHeight &&
      mWidth == RenderScaleExtent(windowWidth, factor) && mHeight == RenderScaleExtent(windowHeight, factor)
    ) {
      return true;
    }

    const std::uint32_t width = RenderScaleExtent(windowWidth, factor);
    const std::uint32_t height = RenderScaleExtent(windowHeight, factor);
    // Creating a target resets the device's viewport on some backends; the caller sets its own afterwards.
    D3DVIEWPORT9 savedViewport{};
    device.GetViewport(&savedViewport);
    mColor.reset();
    mDepth.reset();
    const RenderTargetContext colorContext(width, height, kColorFormat);
    mColor = device.CreateRenderTarget(&colorContext);
    // Created sampled (field 0x10), like the head's: the passes that read the bound depth (ren_Ao, the lights) still
    // can.
    const DepthStencilTargetContext depthContext(width, height, kDepthFormat, true);
    mDepth = device.CreateDepthStencilTarget(&depthContext);
    device.SetViewport(&savedViewport);
    if (mColor == nullptr || mDepth == nullptr) {
      mColor.reset();
      mDepth.reset();
      mFailed = true;
      gpg::Warnf("Render scale disabled: no %ux%u render target", width, height);
      return false;
    }
    mWidth = width;
    mHeight = height;
    mWindowWidth = windowWidth;
    mWindowHeight = windowHeight;
    gpg::Logf(
      "Render scale: world drawn at %ux%u for a %ux%u window (%.0f%%)",
      width,
      height,
      windowWidth,
      windowHeight,
      factor * 100.0f
    );
    return true;
  }

  bool RenderScalePass::Resolve(
    Device& device,
    const std::uint32_t head,
    const RenderScaleRect& source,
    const RenderScaleRect& dest,
    const float sharpness
  )
  {
    if (
      mFailed || mColor == nullptr || mUpscale == nullptr || source.width < 1 || source.height < 1 || dest.width < 1 ||
      dest.height < 1
    ) {
      return false;
    }
    const OutputContext* const headContext = device.GetHeadOutputContext(head);
    if (headContext == nullptr || headContext->surface == nullptr) {
      return false;
    }
    const std::shared_ptr<RenderTarget> back = headContext->surface;
    const bool sharpen = sharpness > 0.001f;

    OutputContext saved;
    device.GetContext(&saved);
    D3DVIEWPORT9 savedViewport{};
    device.GetViewport(&savedViewport);

    if (sharpen) {
      const std::uint32_t backWidth = back->GetContext()->width_;
      const std::uint32_t backHeight = back->GetContext()->height_;
      if (mMiddle == nullptr || mMiddleWidth != backWidth || mMiddleHeight != backHeight) {
        mMiddle.reset();
        const RenderTargetContext context(backWidth, backHeight, kColorFormat);
        mMiddle = device.CreateRenderTarget(&context);
        mMiddleWidth = backWidth;
        mMiddleHeight = backHeight;
        if (mMiddle == nullptr) {
          gpg::Warnf(
            "Render scale: no %ux%u target for the sharpening pass; drawing without it", backWidth, backHeight
          );
        }
      }
    }

    const std::shared_ptr<DepthStencilTarget> noDepth;
    const RenderScaleConstants constants = BuildRenderScaleConstants(source, dest, sharpness);
    const bool twoPasses = sharpen && mMiddle != nullptr;

    const auto draw =
      [&](GpuProgram* const program, const std::shared_ptr<RenderTarget>& output, RenderTarget* const input) {
      const OutputContext target(output, noDepth);
      device.ClearTarget(&target);
      const D3DVIEWPORT9 viewport = MakeViewport(dest);
      device.SetViewport(&viewport);
      GpuDrawCall call;
      call.program = program;
      call.bindings.constants = &constants;
      call.bindings.constantBytes = sizeof(constants);
      call.bindings.targets[0] = input;
      call.vertexCountPerInstance = 3U;
      call.instanceCount = 1U;
      device.DrawGpuProgram(call);
    };

    draw(mUpscale.get(), twoPasses ? mMiddle : back, mColor.get());
    if (twoPasses) {
      draw(mSharpen.get(), back, mMiddle.get());
    }

    device.ClearTarget(&saved);
    device.SetViewport(&savedViewport);
    ++mResolves;
    return true;
  }
} // namespace gpg::gal
