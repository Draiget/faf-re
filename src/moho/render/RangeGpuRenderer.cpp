#include "moho/render/RangeGpuRenderer.h"

#include "gpg/core/utils/Logging.h"
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
  int ren_MergeRanges = 1;

  TConVar<int> gTConVar_ren_GpuRanges(
    "ren_GpuRanges",
    "Draw range rings with GPU-instanced shaders. -1 auto, 1 on, 0 legacy D3D9 stencil passes.",
    &ren_GpuRanges
  );

  TConVar<int> gTConVar_ren_MergeRanges(
    "ren_MergeRanges",
    "Merge range rings into outer boundary envelope (1 on, 0 individual overlapping rings).",
    &ren_MergeRanges
  );

  namespace
  {
    struct RangeConstants
    {
      VMatrix4 view;
      VMatrix4 projection;
    };
    static_assert(sizeof(RangeConstants) % 16 == 0, "constant blocks are whole float4s");
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
      mEnvelopeStream.Reset();
      mSupported = false;
      if ((device->GetGpuDrivenFeatures() & gpg::gal::kGpuFeatureVertexPulling) != 0U) {
        gpg::gal::GpuProgramDesc desc{};
        desc.name = "CastRange";
        desc.source = kRangeGpuShaderSource;
        desc.sourceBytes = sizeof(kRangeGpuShaderSource) - 1U;
        desc.vertexEntry = "CastRangeVS";
        desc.pixelEntry = "CastRangePS";
        desc.blend = gpg::gal::GpuBlend::Opaque;
        desc.colorWriteMask = 0x00U;
        desc.depthTest = true;
        desc.depthWrite = false;
        desc.depthFunc = gpg::gal::GpuCompare::Less;
        desc.depthClip = true;
        desc.cullBackFaces = false;
        desc.stencil.enable = true;
        desc.stencil.readMask = 0xFFU;
        desc.stencil.writeMask = 0xFFU;
        desc.stencil.reference = 0U;
        desc.stencil.front = {
          gpg::gal::GpuStencilOp::Keep, gpg::gal::GpuStencilOp::Increment, gpg::gal::GpuStencilOp::Keep,
          gpg::gal::GpuCompare::Always
        };
        desc.stencil.back = {
          gpg::gal::GpuStencilOp::Keep, gpg::gal::GpuStencilOp::Decrement, gpg::gal::GpuStencilOp::Keep,
          gpg::gal::GpuCompare::Always
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
    const auto vertexCount = static_cast<std::uint32_t>(renderer.mVertexCount);
    const void* const vertices = source->Lock(0U, 0U, gpg::gal::MohoD3DLockFlags::ReadOnly);
    if (vertices == nullptr) {
      return false;
    }
    gpg::gal::GpuBufferDesc desc{};
    desc.name = "RangeCylinder";
    desc.stride = sizeof(float);
    desc.capacity = vertexCount * 5U;
    mCylinder = mDevice->CreateGpuBuffer(desc);
    if (mCylinder != nullptr) {
      mDevice->UpdateGpuBuffer(*mCylinder, 0U, vertexCount * 5U, vertices);
    }
    source->Unlock();
    mCylinderSource = source;
    return mCylinder != nullptr;
  }

  bool RangeGpuRenderer::CastEnvelopes(
    RangeRenderer& renderer,
    const GeomCamera3& cameraView,
    const std::span<const RangeEnvelopeInstance> instances
  )
  {
    if (instances.empty()) {
      return true;
    }
    if (!mSupported || mDevice == nullptr) {
      return false;
    }
    if (!RefreshCylinder(renderer) || renderer.mGeometry.mIndexBuffer == nullptr) {
      return false;
    }

    gpg::gal::GpuBuffer* const envelopeBuffer = mEnvelopeStream.Update(instances.data(), instances.size());
    if (envelopeBuffer == nullptr) {
      return false;
    }

    RangeConstants constants{};
    constants.view = cameraView.view;
    constants.projection = cameraView.projection;

    gpg::gal::GpuDrawCall call{};
    call.program = mProgram.get();
    call.bindings.constants = &constants;
    call.bindings.constantBytes = sizeof(constants);
    call.bindings.readBuffers[0] = mCylinder.get();
    call.bindings.readBuffers[1] = envelopeBuffer;
    call.indexBuffer = renderer.mGeometry.mIndexBuffer.get();
    call.vertexCountPerInstance = static_cast<std::uint32_t>(renderer.mIndexCount);
    call.instanceCount = static_cast<std::uint32_t>(instances.size());

    mDevice->DrawGpuProgram(call);
    return true;
  }
} // namespace moho
