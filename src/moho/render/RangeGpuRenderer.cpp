#include "moho/render/RangeGpuRenderer.h"

#include "gpg/gal/Device.hpp"
#include "gpg/gal/GpuDriven.h"
#include "gpg/gal/IndexBuffer.hpp"
#include "gpg/gal/VertexBuffer.hpp"
#include "moho/console/CConCommand.h"
#include "moho/render/GpuPathSettings.h"
#include "moho/render/RangeGpuShader.h"
#include "moho/render/RangeRenderer.h"
#include "moho/render/camera/GeomCamera3.h"

namespace moho
{
  int ren_GpuRanges = -1;

  TConVar<int> gTConVar_ren_GpuRanges(
    "ren_GpuRanges",
    "Stencil range rings with one instanced draw per batch from a GPU buffer instead of the range effect. "
    "-1 (auto, the default) turns it on where the backend has verified this path, 1 wherever it can, 0 never.",
    &ren_GpuRanges
  );

  namespace
  {
    struct RangeConstants
    {
      gpg::gal::Matrix view;
      gpg::gal::Matrix projection;
      std::uint32_t firstPayload;
      std::uint32_t unused[3];
    };
    static_assert(sizeof(RangeConstants) == 144, "RangeConstants");
    static_assert(sizeof(SRangeExtractionPayload) == 16, "payloads are uploaded as RangePayload");

    /** Floats per ring-template vertex: position, then the inner/outer radius coefficients. */
    constexpr std::uint32_t kCylinderVertexFloats = 5U;
  } // namespace

  RangeGpuRenderer& RangeGpuRenderer::Get()
  {
    static RangeGpuRenderer sRenderer;
    return sRenderer;
  }

  bool RangeGpuRenderer::IsActive()
  {
    if (!GpuPathEnabled(ren_GpuRanges, gpg::gal::kGpuPathRanges, gpg::gal::kGpuFeatureVertexPulling)) {
      return false;
    }
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    if (device == nullptr) {
      return false;
    }
    if (device != mDevice) {
      mDevice = device;
      mProgram.reset();
      mCylinder.reset();
      mCylinderSource = nullptr;
      mPayloadStream.Reset();
      mPayloadBuffer = nullptr;
      mSupported = false;
      if ((device->GetGpuDrivenFeatures() & gpg::gal::kGpuFeatureVertexPulling) != 0U) {
        gpg::gal::GpuProgramDesc desc{};
        desc.name = "CastRange";
        desc.source = kRangeGpuShaderSource;
        desc.sourceBytes = sizeof(kRangeGpuShaderSource) - 1U;
        desc.vertexEntry = "CastRangeVS";
        desc.pixelEntry = "CastRangePS";
        // range.fx "Cast": no colour writes, cull none, depth test less without writes, two-sided
        // stencil counting z-failures (+1 clockwise, -1 counter-clockwise, wrapping) into the low
        // seven bits, skipping pixels whose bit 7 is set (ref 0xFF, mask 0x80, notequal); a skipped
        // clockwise face zeroes the low bits.
        desc.blend = gpg::gal::GpuBlend::Opaque;
        desc.colorWriteMask = 0x00U;
        desc.depthTest = true;
        desc.depthWrite = false;
        desc.depthFunc = gpg::gal::GpuCompare::Less;
        desc.depthClip = true;
        desc.cullBackFaces = false;
        desc.stencil.enable = true;
        desc.stencil.readMask = 0x80U;
        desc.stencil.writeMask = 0x7FU;
        desc.stencil.reference = 0xFFU;
        desc.stencil.front = {
          gpg::gal::GpuStencilOp::Zero, gpg::gal::GpuStencilOp::Increment, gpg::gal::GpuStencilOp::Keep,
          gpg::gal::GpuCompare::NotEqual
        };
        desc.stencil.back = {
          gpg::gal::GpuStencilOp::Keep, gpg::gal::GpuStencilOp::Decrement, gpg::gal::GpuStencilOp::Keep,
          gpg::gal::GpuCompare::NotEqual
        };
        mProgram = device->CreateGpuProgram(desc);
        mSupported = mProgram != nullptr;
      }
    }
    return mSupported;
  }

  bool RangeGpuRenderer::RefreshCylinder(RangeRenderer& renderer)
  {
    gpg::gal::VertexBuffer* const source = renderer.mGeometry.mVertexBuffer.get();
    if (source == nullptr) {
      return false;
    }
    if (source == mCylinderSource && mCylinder != nullptr) {
      return true;
    }
    // The ring template exactly as `RangeRenderer::Init` wrote it: read back from the buffer the
    // effect path draws, so it carries the same map heights.
    const auto vertexCount = static_cast<std::uint32_t>(renderer.mVertexCount);
    const void* const vertices = source->Lock(0U, 0U, gpg::gal::MohoD3DLockFlags::ReadOnly);
    if (vertices == nullptr) {
      return false;
    }
    gpg::gal::GpuBufferDesc desc{};
    desc.name = "RangeCylinder";
    desc.stride = sizeof(float);
    desc.capacity = vertexCount * kCylinderVertexFloats;
    mCylinder = mDevice->CreateGpuBuffer(desc);
    if (mCylinder != nullptr) {
      mDevice->UpdateGpuBuffer(*mCylinder, 0U, desc.capacity, vertices);
    }
    source->Unlock();
    mCylinderSource = source;
    return mCylinder != nullptr;
  }

  bool RangeGpuRenderer::Upload(RangeRenderer& renderer, const std::span<const SRangeExtractionPayload> payloads)
  {
    if (!mSupported || mDevice == nullptr || renderer.mGeometry.mIndexBuffer == nullptr || !RefreshCylinder(renderer)) {
      return false;
    }
    if (payloads.empty()) {
      return true;
    }
    mPayloadBuffer = mPayloadStream.Update(payloads.data(), payloads.size());
    return mPayloadBuffer != nullptr;
  }

  void RangeGpuRenderer::Cast(
    const RangeRenderer& renderer, const GeomCamera3& camera, const std::uint32_t first, const std::uint32_t count
  )
  {
    if (count == 0U || mPayloadBuffer == nullptr) {
      return;
    }
    RangeConstants constants{};
    constants.view = camera.view;
    constants.projection = camera.projection;
    constants.firstPayload = first;

    gpg::gal::GpuDrawCall call{};
    call.program = mProgram.get();
    call.bindings.constants = &constants;
    call.bindings.constantBytes = sizeof(constants);
    call.bindings.readBuffers[0] = mCylinder.get();
    call.bindings.readBuffers[1] = mPayloadBuffer;
    call.indexBuffer = renderer.mGeometry.mIndexBuffer.get();
    call.vertexCountPerInstance = static_cast<std::uint32_t>(renderer.mIndexCount);
    call.instanceCount = count;
    mDevice->DrawGpuProgram(call);
  }
} // namespace moho
