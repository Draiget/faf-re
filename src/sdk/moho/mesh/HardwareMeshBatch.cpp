#include "MeshBatch.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>

#include "Mesh.h"

#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/DrawIndexedContext.hpp"
#include "gpg/gal/IndexBufferContext.hpp"
#include "gpg/gal/VertexBufferContext.hpp"
#include "gpg/gal/backends/d3d9/DeviceD3D9.hpp"
#include "gpg/gal/backends/d3d9/EffectTechniqueD3D9.hpp"
#include "gpg/gal/backends/d3d9/Float16HardwareVertexFormatterD3D9.hpp"
#include "gpg/gal/backends/d3d9/IndexBufferD3D9.hpp"
#include "gpg/gal/backends/d3d9/VertexBufferD3D9.hpp"
#include "gpg/gal/backends/d3d9/VertexFormatD3D9.hpp"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DEffectTechnique.h"
#include "moho/resource/RScmResource.h"
#include "moho/resource/SScmFile.h"

namespace gpg::gal
{
  // Returns the process-wide hardware vertex formatter (float16 or plain,
  // selected once by device type). Defined in the D3D9 backend TU near
  // func_AllowMeshInstancing (0x008E7550, func_GetHardwareVertexFormatter).
  Float16HardwareVertexFormatterD3D9* GetHardwareVertexFormatter();
} // namespace gpg::gal

namespace moho
{
  namespace
  {
    /**
     * Staging layout the hardware vertex formatter reads as its source vertex
     * (`WriteFormattedVertex`, stream class 0). This mirrors the backend's
     * private `SourceMeshVertexRuntime` (0xB8 bytes); the batch-fill path only
     * populates the fields the stream-0 packer consumes. Kept file-local as a
     * transient staging record — it is not a binary-owned object.
     *
     * Field offsets byte-verified against the vertex-scatter loop in
     * FUN_007E7540 (0x007E797D..0x007E7AD6) and the stream-0 reads in
     * gpg::gal::Float16HardwareVertexFormatterD3D9::WriteFormattedVertex.
     */
    struct MeshBatchSourceVertex final
    {
      std::uint8_t pad00_50[0x51]{};
      std::uint8_t boneIndex0 = 0; // +0x51
      std::uint8_t boneIndex1 = 0; // +0x52
      std::uint8_t boneIndex2 = 0; // +0x53
      std::uint8_t boneIndex3 = 0; // +0x54
      std::uint8_t pad55_57[3]{};
      float position[3]{}; // +0x58
      std::uint8_t pad64_6F[0x0C]{};
      float vec70[3]{}; // +0x70
      float vec7C[3]{}; // +0x7C
      float vec88[3]{}; // +0x88
      float texCoord0[2]{}; // +0x94 (streamScalar94/98)
      float texCoord1[2]{}; // +0x9C (streamScalar9C/A0)
      std::uint8_t padA4_B7[0x14]{};
    };

    static_assert(offsetof(MeshBatchSourceVertex, boneIndex0) == 0x51, "MeshBatchSourceVertex::boneIndex0 offset must be 0x51");
    static_assert(offsetof(MeshBatchSourceVertex, position) == 0x58, "MeshBatchSourceVertex::position offset must be 0x58");
    static_assert(offsetof(MeshBatchSourceVertex, vec70) == 0x70, "MeshBatchSourceVertex::vec70 offset must be 0x70");
    static_assert(offsetof(MeshBatchSourceVertex, vec7C) == 0x7C, "MeshBatchSourceVertex::vec7C offset must be 0x7C");
    static_assert(offsetof(MeshBatchSourceVertex, vec88) == 0x88, "MeshBatchSourceVertex::vec88 offset must be 0x88");
    static_assert(offsetof(MeshBatchSourceVertex, texCoord0) == 0x94, "MeshBatchSourceVertex::texCoord0 offset must be 0x94");
    static_assert(offsetof(MeshBatchSourceVertex, texCoord1) == 0x9C, "MeshBatchSourceVertex::texCoord1 offset must be 0x9C");
    static_assert(sizeof(MeshBatchSourceVertex) == 0xB8, "MeshBatchSourceVertex size must be 0xB8");
  } // namespace

  /**
   * Address: 0x007E7540 (FUN_007E7540, slot 1 override; IDA: HardwareMeshBatch::Func1)
   * Mangled slot: ??_7HardwareMeshBatch@Moho@@6B@ +0x04
   *
   * IDA signature:
   * int __thiscall Moho::HardwareMeshBatch::Func1(HardwareMeshBatch* this,
   *   int lod, int remap, boost::shared_ptr<RScmResource> referenceResource,
   *   boost::shared_ptr<RScmResource> currentResource);
   *
   * What it does:
   * Seeds the base batch counters, then builds the static GPU buffers for the
   * mesh: derives the max instances-per-draw budget from the device's primitive
   * cap (non-remap batches only), copies the SCM 16-bit index data verbatim into
   * a GPU index buffer, selects the GPU vertex declaration through the active
   * hardware vertex formatter, and streams every SCM vertex into the static GPU
   * vertex buffer one record at a time via the formatter.
   */
  void HardwareMeshBatch::Initialize(
    const MeshLOD* const lod,
    const bool remapToReferenceResource,
    const boost::shared_ptr<RScmResource> referenceResource,
    const boost::shared_ptr<RScmResource> currentResource
  )
  {
    // Base initialization seeds mUseBoneRemap / mCurrentResource / counters
    // (vertex/index/triangle/bone counts) from the mesh resource.
    MeshBatch::Initialize(lod, remapToReferenceResource, referenceResource, currentResource);

    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    const gpg::gal::DeviceContext* const deviceContext = device->GetDeviceContext();

    // Instanced (non-remap) batches split the device's primitive budget across
    // as many instances as fit; remapped batches keep the base default.
    if (mUseBoneRemap == 0) {
      mMaxInstancesPerDraw =
        static_cast<std::int32_t>(deviceContext->mMaxPrimitiveCount / static_cast<std::uint32_t>(mTriangleCount));
    }

    const SScmFile* const mesh = currentResource->mFile.get();

    // --- Static index buffer: verbatim copy of the SCM 16-bit index data. ---
    {
      gpg::gal::IndexBufferContext indexContext;
      indexContext.size_ = static_cast<std::uint32_t>(mIndexCount);
      indexContext.format_ = 1U;
      indexContext.type_ = 1U;

      boost::shared_ptr<gpg::gal::IndexBufferD3D9> indexBuffer;
      indexBuffer = *device->CreateIndexBuffer(&indexBuffer, &indexContext);
      IndexBufferHandle() = indexBuffer;

      const std::size_t indexBytes = static_cast<std::size_t>(mIndexCount) * sizeof(std::uint16_t);
      std::int16_t* const mappedIndices =
        IndexBufferHandle()->Lock(0U, 0U, gpg::gal::MohoD3DLockFlags::None);
      std::memcpy(mappedIndices, scm_file::GetIndices(*mesh), indexBytes);
      IndexBufferHandle()->Unlock();
    }

    // --- Vertex declaration + static vertex buffer. ---
    gpg::gal::Float16HardwareVertexFormatterD3D9* const formatter = gpg::gal::GetHardwareVertexFormatter();

    // The formatter fills the passed shared_ptr slot with the GPU vertex
    // declaration for stream class 0.
    boost::shared_ptr<gpg::gal::VertexFormatD3D9> vertexFormat;
    formatter->SelectVertexFormatToken(reinterpret_cast<std::uintptr_t>(&vertexFormat), 0);
    VertexFormatHandle() = vertexFormat;

    const std::uint32_t vertexStride = formatter->GetVertexStride(0, 0);

    gpg::gal::VertexBufferContext vertexContext;
    vertexContext.width_ = static_cast<std::uint32_t>(mVertexCount);
    vertexContext.height_ = vertexStride;
    vertexContext.type_ = 2U;
    vertexContext.usage_ = 1U;

    boost::shared_ptr<gpg::gal::VertexBufferD3D9> vertexBuffer;
    vertexBuffer = *device->CreateVertexBuffer(&vertexBuffer, &vertexContext);
    mStaticVertexBuffer = vertexBuffer;

    auto* mappedVertices =
      static_cast<std::uint8_t*>(mStaticVertexBuffer->Lock(0U, 0U, gpg::gal::MohoD3DLockFlags::None));

    const SScmVertex* const sourceVertices = scm_file::GetVertices(*mesh);
    for (std::int32_t vertexIndex = 0; vertexIndex < mVertexCount; ++vertexIndex) {
      const SScmVertex& source = sourceVertices[vertexIndex];

      MeshBatchSourceVertex staging{};
      staging.position[0] = source.mLocalPositionX;
      staging.position[1] = source.mLocalPositionY;
      staging.position[2] = source.mLocalPositionZ;
      staging.vec7C[0] = source.mVec0C[0];
      staging.vec7C[1] = source.mVec0C[1];
      staging.vec7C[2] = source.mVec0C[2];
      staging.vec88[0] = source.mVec18[0];
      staging.vec88[1] = source.mVec18[1];
      staging.vec88[2] = source.mVec18[2];
      staging.vec70[0] = source.mVec24[0];
      staging.vec70[1] = source.mVec24[1];
      staging.vec70[2] = source.mVec24[2];
      staging.texCoord0[0] = source.mTexCoord0[0];
      staging.texCoord0[1] = source.mTexCoord0[1];
      staging.texCoord1[0] = source.mTexCoord1[0];
      staging.texCoord1[1] = source.mTexCoord1[1];
      staging.boneIndex0 = source.mBoneIndex;
      staging.boneIndex1 = source.mBoneIndex1;
      staging.boneIndex2 = source.mBoneIndex2;
      staging.boneIndex3 = source.mBoneIndex3;

      formatter->WriteFormattedVertex(0, mappedVertices, &staging, 0);
      mappedVertices += vertexStride;
    }

    mStaticVertexBuffer->Unlock();
  }

  /**
   * Address: 0x007E7D00 (FUN_007E7D00, slot 5 override; IDA: sub_7E7D00)
   *
   * What it does:
   * Grows the dynamic per-instance vertex buffer (and its CPU scratch mirror)
   * so it can hold `instanceCount` instances, clamped to the batch's
   * max-instances-per-draw budget. No-op when the current budget already covers
   * the request or is already at the cap.
   */
  void HardwareMeshBatch::PrepareBatch(const std::int32_t instanceCount)
  {
    if (instanceCount <= mActiveInstanceBudget || mActiveInstanceBudget >= mMaxInstancesPerDraw) {
      return;
    }

    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());

    // New budget = min(requested, cap).
    mActiveInstanceBudget = (instanceCount < mMaxInstancesPerDraw) ? instanceCount : mMaxInstancesPerDraw;

    gpg::gal::Float16HardwareVertexFormatterD3D9* const formatter = gpg::gal::GetHardwareVertexFormatter();

    gpg::gal::VertexBufferContext vertexContext;
    vertexContext.width_ = static_cast<std::uint32_t>(mActiveInstanceBudget);
    vertexContext.type_ = 3U;
    vertexContext.usage_ = 2U;
    const std::uint32_t perInstanceStride = formatter->GetVertexStride(1, 0);
    vertexContext.height_ = perInstanceStride;

    boost::shared_ptr<gpg::gal::VertexBufferD3D9> instanceBuffer;
    instanceBuffer = *device->CreateVertexBuffer(&instanceBuffer, &vertexContext);
    mDynamicVertexBuffer = instanceBuffer;

    // Reallocate the CPU staging mirror to match the new instance budget.
    if (mScratchVertexData != nullptr) {
      ::operator delete[](mScratchVertexData);
    }
    mScratchVertexData =
      ::operator new(static_cast<std::size_t>(perInstanceStride) * static_cast<std::size_t>(mActiveInstanceBudget));
  }

  /**
   * Address: 0x007E7E30 (FUN_007E7E30, slot 6 override; IDA: sub_7E7E30)
   *
   * What it does:
   * Binds this batch's GPU vertex declaration and static index buffer on the
   * active device before drawing.
   */
  void HardwareMeshBatch::BindBuffers()
  {
    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    device->SetVertexDeclaration(VertexFormatHandle());
    device->SetBufferIndices(IndexBufferHandle());
  }

  /**
   * Address: 0x007E89E0 (FUN_007E89E0, slot 8 override; IDA: HardwareMeshBatch::Func8)
   *
   * IDA signature:
   * void __thiscall Moho::HardwareMeshBatch::Func8(HardwareMeshBatch* this, int a2);
   *
   * What it does:
   * Hardware-instanced draw of one packed slice. Binds the static mesh geometry
   * on stream 0 with an instance-frequency divider of `packedCount` (draw the
   * geometry once per that many instances) and the per-instance dynamic data on
   * stream 1 (advance once per instance), builds the indexed-draw context from
   * the batch's vertex/index counts, then walks every pass of the current effect
   * technique, issuing one DrawIndexedPrimitive per pass between BeginPass/EndPass
   * and wrapped by BeginTechnique/EndTechnique.
   */
  void HardwareMeshBatch::DrawBatch(const std::int32_t packedCount)
  {
    if (packedCount == 0) {
      return;
    }

    CD3DDevice* const d3dDevice = D3D_GetDevice();
    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());

    // Ensure the process-wide hardware vertex formatter singleton is realized
    // before the draw (the binary discards the returned pointer here — the call
    // is kept only for its lazy-init side effect).
    (void)gpg::gal::GetHardwareVertexFormatter();

    CD3DEffect* const effect = d3dDevice->GetCurEffect();
    if (effect == nullptr) {
      return;
    }

    // Stream 0: static geometry, drawn once per `packedCount` instances.
    device->SetVertexBuffer(0, mStaticVertexBuffer, packedCount, 0);
    // Stream 1: per-instance dynamic data, one advance per instance.
    device->SetVertexBuffer(1, mDynamicVertexBuffer, 1, 0);

    gpg::gal::DrawIndexedContext drawContext;
    drawContext.topologyToken_ = 4;                 // triangle-list topology token
    drawContext.vertexCount_ = mVertexCount;        // (.c mNumVertices)
    drawContext.primitiveCountInput_ = mIndexCount; // (.c mPrimCount)

    gpg::gal::EffectTechniqueD3D9* const technique = effect->mCurrentTechnique.px;

    const int passCount = technique->BeginTechnique();
    for (int pass = 0; pass < passCount; ++pass) {
      technique->BeginPass(pass);
      device->DrawIndexedPrimitive(&drawContext);
      technique->EndPass();
    }
    technique->EndTechnique();
    // drawContext destructor runs automatically (RAII), matching the binary's
    // ~DrawIndexedContext(&v14) at function exit.
  }

  /**
   * Address: 0x007E8B60 (FUN_007E8B60, slot 7 override; IDA: HardwareMeshBatch::Func7)
   *
   * What it does:
   * End-of-batch hook. The hardware batch has no per-batch teardown work; the
   * binary body is empty.
   */
  void HardwareMeshBatch::EndBatch()
  {
  }

  /**
   * Address: 0x007E7350 (FUN_007E7350, Moho::HardwareMeshBatchInit)
   *
   * IDA signature:
   * Moho::HardwareMeshBatch* __userpurge Moho::HardwareMeshBatchInit@<eax>(
   *   HardwareMeshBatch* batch, int lod, int remap,
   *   boost::shared_ptr<RScmResource> referenceResource,
   *   boost::shared_ptr<RScmResource> currentResource);
   *
   * What it does:
   * Placement-constructs one `HardwareMeshBatch` over the caller-allocated
   * storage: runs the base `MeshBatch` constructor, installs the
   * `HardwareMeshBatch` vtable, zero-clears the derived buffer/scratch lanes,
   * then drives `HardwareMeshBatch::Initialize` to build the GPU buffers.
   * Returns `batch`.
   */
  HardwareMeshBatch* HardwareMeshBatchInit(
    HardwareMeshBatch* const batch,
    const MeshLOD* const lod,
    const bool remapToReferenceResource,
    boost::shared_ptr<RScmResource> referenceResource,
    boost::shared_ptr<RScmResource> currentResource
  )
  {
    // Construct the concrete object in place: the compiler-generated ctor runs
    // the base MeshBatch ctor, installs the HardwareMeshBatch vtable, and
    // default-initializes the derived buffer/scratch lanes (all null) — the
    // exact effect of the binary's inlined field zeroing at 0x007E7384.
    HardwareMeshBatch* const constructed = ::new (static_cast<void*>(batch)) HardwareMeshBatch();
    constructed->Initialize(lod, remapToReferenceResource ? 1 : 0, referenceResource, currentResource);
    return constructed;
  }
} // namespace moho
