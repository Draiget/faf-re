#include "gpg/gal/AmbientOcclusionPass.h"

#include <algorithm>
#include <string>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/OutputContext.hpp"
#include "gpg/gal/RenderTargetContext.hpp"
#include "gpg/gal/DepthStencilTargetContext.hpp"

namespace gpg::gal
{
  namespace
  {
    // gal render target format 7: two 16-bit unorm channels (occlusion, view depth / far).
    constexpr std::uint32_t kOcclusionFormat = 7U;

    D3DVIEWPORT9 MakeViewport(
      const float x,
      const float y,
      const float width,
      const float height
    )
    {
      D3DVIEWPORT9 viewport{};
      viewport.X = static_cast<DWORD>(std::max(x, 0.0f));
      viewport.Y = static_cast<DWORD>(std::max(y, 0.0f));
      viewport.Width = static_cast<DWORD>(std::max(width, 1.0f));
      viewport.Height = static_cast<DWORD>(std::max(height, 1.0f));
      viewport.MinZ = 0.0f;
      viewport.MaxZ = 1.0f;
      return viewport;
    }
  } // namespace

  AmbientOcclusionPass& AmbientOcclusionPass::Instance()
  {
    static AmbientOcclusionPass instance;
    return instance;
  }

  void AmbientOcclusionPass::Release()
  {
    mCompute.reset();
    mBlur.reset();
    mWide.reset();
    mComposite.reset();
    mTargetA.reset();
    mTargetB.reset();
    mTargetWidth = 0U;
    mTargetHeight = 0U;
    mDevice = nullptr;
    mFailed = false;
    mLoggedRefusal = false;
  }

  bool AmbientOcclusionPass::EnsureResources(
    Device& device,
    const std::uint32_t width,
    const std::uint32_t height,
    const bool halfRes
  )
  {
    if (mDevice != &device) {
      Release();
      mDevice = &device;
    }
    if (mCompute == nullptr) {
      const std::string source = backend::AmbientOcclusionSource();
      const auto make = [&](const char* const name, const char* const pixelEntry, const bool composite) {
        GpuProgramDesc desc;
        desc.name = name;
        desc.source = source.c_str();
        desc.sourceBytes = source.size();
        desc.vertexEntry = "AoVS";
        desc.pixelEntry = pixelEntry;
        desc.sampler = GpuSampler::PointClamp;
        if (composite) {
          // Black with alpha = 1 - occlusion over the colour: colour * occlusion. The alpha channel of the back buffer
          // is left alone.
          desc.blend = GpuBlend::AlphaBlend;
          desc.colorWriteMask = 0x07U;
        } else {
          desc.blend = GpuBlend::Opaque;
          desc.colorWriteMask = 0x03U;
        }
        return device.CreateGpuProgram(desc);
      };
      mCompute = make("AmbientOcclusionCompute", "AoComputePS", false);
      mBlur = make("AmbientOcclusionBlur", "AoBlurPS", false);
      mWide = make("AmbientOcclusionWide", "AoWidePS", false);
      mComposite = make("AmbientOcclusionComposite", "AoCompositePS", true);
      if (mCompute == nullptr || mBlur == nullptr || mWide == nullptr || mComposite == nullptr) {
        gpg::Warnf("Ambient occlusion disabled: its GPU programs did not compile");
        mFailed = true;
        return false;
      }
    }

    const std::uint32_t targetWidth = AmbientOcclusionTargetExtent(width, halfRes);
    const std::uint32_t targetHeight = AmbientOcclusionTargetExtent(height, halfRes);
    if (mTargetA == nullptr || mTargetB == nullptr || mTargetWidth != targetWidth || mTargetHeight != targetHeight) {
      mTargetA.reset();
      mTargetB.reset();
      // Creating a render target resets the device's viewport on some backends; the caller restores its own.
      const RenderTargetContext context(targetWidth, targetHeight, kOcclusionFormat);
      mTargetA = device.CreateRenderTarget(&context);
      mTargetB = device.CreateRenderTarget(&context);
      if (mTargetA == nullptr || mTargetB == nullptr) {
        gpg::Warnf("Ambient occlusion disabled: no %ux%u render target", targetWidth, targetHeight);
        mTargetA.reset();
        mTargetB.reset();
        mFailed = true;
        return false;
      }
      mTargetWidth = targetWidth;
      mTargetHeight = targetHeight;
      gpg::Logf(
        "Ambient occlusion: %ux%u occlusion targets for a %ux%u view", targetWidth, targetHeight, width, height
      );
    }
    return true;
  }

  bool AmbientOcclusionPass::Apply(
    Device& device,
    const AmbientOcclusionParams& params
  )
  {
    const auto refuse = [&](const char* const reason) {
      if (!mLoggedRefusal) {
        mLoggedRefusal = true;
        gpg::Warnf("Ambient occlusion is not available: %s; nothing is drawn", reason);
      }
      return false;
    };
    if (params.level <= 0 || params.rectWidth < 1.0f || params.rectHeight < 1.0f || mFailed) {
      return false;
    }
    if ((device.GetGpuDrivenFeatures() & kGpuFeatureVertexPulling) == 0U) {
      return refuse("this render API has no GPU programs");
    }
    // The targets the world view is drawn into now: the head's back buffer and depth buffer, or whatever the frame
    // draws the world into.
    OutputContext saved;
    device.GetContext(&saved);
    const OutputContext* const headContext = &saved;
    if (headContext->surface == nullptr || headContext->depthStencil == nullptr) {
      return refuse("no colour or depth target is bound");
    }
    if (!headContext->depthStencil->GetContext()->field0x10_) {
      return refuse("the bound depth buffer was not created sampled");
    }
    const RenderTargetContext* const backContext = headContext->surface->GetContext();
    const bool halfRes = AmbientOcclusionHalfRes(params);

    D3DVIEWPORT9 savedViewport{};
    device.GetViewport(&savedViewport);
    if (!EnsureResources(device, backContext->width_, backContext->height_, halfRes)) {
      device.SetViewport(&savedViewport);
      return false;
    }

    AmbientOcclusionConstants constants = BuildAmbientOcclusionConstants(params);
    const D3DVIEWPORT9 aoViewport = MakeViewport(
      constants.aoRect[0],
      constants.aoRect[1],
      constants.aoRect[2] - constants.aoRect[0] + 1.0f,
      constants.aoRect[3] - constants.aoRect[1] + 1.0f
    );
    const std::shared_ptr<RenderTarget> back = headContext->surface;
    const std::shared_ptr<DepthStencilTarget> depth = headContext->depthStencil;
    const std::shared_ptr<DepthStencilTarget> noDepth;

    const auto draw = [&](
                        GpuProgram* const program,
                        const std::shared_ptr<RenderTarget>& output,
                        const D3DVIEWPORT9& viewport,
                        RenderTarget* const input
                      ) {
      const OutputContext target(output, noDepth);
      device.ClearTarget(&target);
      device.SetViewport(&viewport);
      GpuDrawCall call;
      call.program = program;
      call.bindings.constants = &constants;
      call.bindings.constantBytes = sizeof(constants);
      call.bindings.depthTarget = depth.get();
      call.bindings.targets[0] = input;
      call.vertexCountPerInstance = 3U;
      call.instanceCount = 1U;
      device.DrawGpuProgram(call);
    };

    // Occlusion into A, blurred along x into B; with the smoothing pass (smoothReach) B is then blurred along y back
    // into A and smoothed along x into B, so the last draw's own vertical blur takes over a clean input.
    const bool smooth = constants.shape[2] > 0.0f;
    constants.blur[0] = 0.0f;
    constants.blur[1] = 0.0f;
    draw(mCompute.get(), mTargetA, aoViewport, nullptr);
    constants.blur[0] = 1.0f;
    constants.blur[1] = 0.0f;
    draw(mBlur.get(), mTargetB, aoViewport, mTargetA.get());
    if (smooth) {
      constants.blur[0] = 0.0f;
      constants.blur[1] = 1.0f;
      draw(mBlur.get(), mTargetA, aoViewport, mTargetB.get());
      constants.blur[0] = 1.0f;
      constants.blur[1] = 0.0f;
      draw(mWide.get(), mTargetB, aoViewport, mTargetA.get());
    }
    constants.blur[0] = 0.0f;
    constants.blur[1] = 1.0f;
    constants.blur[3] = smooth ? 1.0f : 0.0f;
    draw(
      mComposite.get(),
      back,
      MakeViewport(params.rectX, params.rectY, params.rectWidth, params.rectHeight),
      mTargetB.get()
    );

    device.ClearTarget(&saved);
    device.SetViewport(&savedViewport);
    ++mFrames;
    return true;
  }
} // namespace gpg::gal
