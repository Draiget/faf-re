#include "moho/render/SmaaRenderer.h"

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/GpuDriven.h"
#include "gpg/gal/OutputContext.hpp"
#include "gpg/gal/RenderTargetContext.hpp"
#include "moho/render/FxaaRenderer.h"
#include "moho/render/SmaaShader.h"

namespace moho
{
  namespace
  {
    // gal render target format 2: four 8-bit unorm channels (B8G8R8A8 or R8G8B8A8; the channels are addressed as r, g,
    // b, a either way).
    constexpr std::uint32_t kEightBitFormat = 2U;
  } // namespace

  SmaaRenderer& SmaaRenderer::Get()
  {
    static SmaaRenderer sRenderer;
    return sRenderer;
  }

  void SmaaRenderer::Release()
  {
    *this = SmaaRenderer();
  }

  bool SmaaRenderer::IsActive()
  {
    if (ren_Fxaa != 2) {
      return false;
    }
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    if (device == nullptr) {
      return false;
    }
    if (device != mDevice) {
      *this = SmaaRenderer();
      mDevice = device;
      gpg::gal::DeviceContext* const context = device->GetDeviceContext();
      const bool modern = context != nullptr &&
        (context->mDeviceType == gpg::gal::DeviceApi::Direct3D11 ||
         context->mDeviceType == gpg::gal::DeviceApi::Direct3D12 ||
         context->mDeviceType == gpg::gal::DeviceApi::Vulkan);
      if (modern && (device->GetGpuDrivenFeatures() & gpg::gal::kGpuFeatureVertexPulling) != 0U) {
        const auto make = [&](const char* const name, const char* const pixelEntry, const std::uint8_t mask) {
          gpg::gal::GpuProgramDesc desc{};
          desc.name = name;
          desc.source = kSmaaShaderSource;
          desc.sourceBytes = sizeof(kSmaaShaderSource) - 1U;
          desc.vertexEntry = "SmaaVS";
          desc.pixelEntry = pixelEntry;
          desc.blend = gpg::gal::GpuBlend::Opaque;
          desc.colorWriteMask = mask;
          desc.depthTest = false;
          desc.depthWrite = false;
          desc.cullBackFaces = false;
          desc.sampler = gpg::gal::GpuSampler::LinearClamp;
          return device->CreateGpuProgram(desc);
        };
        mEdges = make("SmaaEdges", "SmaaEdgePS", 0x0FU);
        mWeights = make("SmaaWeights", "SmaaWeightsPS", 0x0FU);
        mBlend = make("SmaaBlend", "SmaaBlendPS", 0x07U); // alpha is the glow amount the bloom pass reads
      }
      mSupported = mEdges != nullptr && mWeights != nullptr && mBlend != nullptr;
      if (mSupported) {
        gpg::Logf("SMAA: available on this renderer (ren_Fxaa %d)", ren_Fxaa);
      }
    }
    return mSupported && !mFailed;
  }

  bool SmaaRenderer::EnsureTargets(
    const int width,
    const int height
  )
  {
    if (mEdgeTarget != nullptr && mWeightTarget != nullptr && mWidth == width && mHeight == height) {
      return true;
    }
    mEdgeTarget.reset();
    mWeightTarget.reset();
    // Creating a render target resets the device's viewport on some backends; the caller puts its own back.
    D3DVIEWPORT9 saved{};
    mDevice->GetViewport(&saved);
    const gpg::gal::RenderTargetContext context(
      static_cast<std::uint32_t>(width), static_cast<std::uint32_t>(height), kEightBitFormat
    );
    mEdgeTarget = mDevice->CreateRenderTarget(&context);
    mWeightTarget = mDevice->CreateRenderTarget(&context);
    mDevice->SetViewport(&saved);
    if (mEdgeTarget == nullptr || mWeightTarget == nullptr) {
      mEdgeTarget.reset();
      mWeightTarget.reset();
      mFailed = true;
      gpg::Warnf("SMAA is off: no %dx%d edge and blend weight targets", width, height);
      return false;
    }
    mWidth = width;
    mHeight = height;
    gpg::Logf("SMAA: %dx%d edge and blend weight targets", width, height);
    return true;
  }

  void SmaaRenderer::Render(
    gpg::gal::RenderTarget& copy,
    const int width,
    const int height
  )
  {
    if (!mSupported || mFailed || width <= 0 || height <= 0 || !EnsureTargets(width, height)) {
      return;
    }
    gpg::gal::OutputContext savedContext;
    mDevice->GetContext(&savedContext);
    D3DVIEWPORT9 view{};
    mDevice->GetViewport(&view);
    const bool wholeTarget = view.X == 0U && view.Y == 0U && view.Width >= static_cast<DWORD>(width) &&
      view.Height >= static_cast<DWORD>(height);

    // One pass into a working target over the view's rectangle. A working target keeps what an earlier view or frame
    // left outside that rectangle, and the weight search reads some pixels past it, so a view smaller than the head
    // clears the target first.
    const auto intoTarget = [&](
                              gpg::gal::GpuProgram* const program,
                              const std::shared_ptr<gpg::gal::RenderTarget>& output,
                              gpg::gal::RenderTarget* const first
                            ) {
      const std::shared_ptr<gpg::gal::DepthStencilTarget> noDepth;
      const gpg::gal::OutputContext target(output, noDepth);
      mDevice->ClearTarget(&target);
      if (!wholeTarget) {
        D3DVIEWPORT9 all = view;
        all.X = 0U;
        all.Y = 0U;
        all.Width = static_cast<DWORD>(width);
        all.Height = static_cast<DWORD>(height);
        mDevice->SetViewport(&all);
        mDevice->Clear(true, false, false, 0U, 1.0f, 0);
      }
      mDevice->SetViewport(&view);
      gpg::gal::GpuDrawCall draw{};
      draw.program = program;
      draw.bindings.targets[0] = first;
      draw.vertexCountPerInstance = 3U;
      draw.instanceCount = 1U;
      mDevice->DrawGpuProgram(draw);
    };
    intoTarget(mEdges.get(), mEdgeTarget, &copy);
    intoTarget(mWeights.get(), mWeightTarget, mEdgeTarget.get());

    mDevice->ClearTarget(&savedContext);
    mDevice->SetViewport(&view);
    gpg::gal::GpuDrawCall draw{};
    draw.program = mBlend.get();
    draw.bindings.targets[0] = &copy;
    draw.bindings.targets[1] = mWeightTarget.get();
    draw.vertexCountPerInstance = 3U;
    draw.instanceCount = 1U;
    mDevice->DrawGpuProgram(draw);
  }
} // namespace moho
