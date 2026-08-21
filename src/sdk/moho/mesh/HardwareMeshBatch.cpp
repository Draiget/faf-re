#include "MeshBatch.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>

#include "Mesh.h"

#include "moho/animation/CAniPose.h"
#include "moho/animation/CAniSkel.h"
#include "moho/math/QuaternionMath.h"
#include "moho/math/VMatrix4.h"
#include "gpg/gal/backends/d3d9/EffectVariableD3D9.hpp"
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
      // --- Stream class 1 lanes (per-instance), written by FillBatch. --------
      std::uint8_t instanceIndex = 0; // +0x00
      std::uint8_t pad01_03[3]{};
      float meshColor = 0.0f;         // +0x04
      std::int32_t color = 0;         // +0x08
      float shaderTime = 0.0f;        // +0x0C
      VMatrix4 transform{};           // +0x10 (0x40 bytes)
      std::uint8_t bonePaletteBase = 0; // +0x50
      // --- Stream class 0 lanes (per-vertex), written by Initialize. --------
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
      // --- Stream class 1 tail lanes (per-instance), written by FillBatch. ---
      std::uint8_t useSecondaryData = 0; // +0xA4
      std::uint8_t padA5_A7[3]{};
      float scroll[2]{};                 // +0xA8, +0xAC
      std::uint8_t dissolve = 0;         // +0xB0
      std::uint8_t padB1_B3[3]{};
      float parameter = 0.0f;            // +0xB4
    };

    static_assert(offsetof(MeshBatchSourceVertex, meshColor) == 0x04, "MeshBatchSourceVertex::meshColor offset must be 0x04");
    static_assert(offsetof(MeshBatchSourceVertex, color) == 0x08, "MeshBatchSourceVertex::color offset must be 0x08");
    static_assert(offsetof(MeshBatchSourceVertex, shaderTime) == 0x0C, "MeshBatchSourceVertex::shaderTime offset must be 0x0C");
    static_assert(offsetof(MeshBatchSourceVertex, transform) == 0x10, "MeshBatchSourceVertex::transform offset must be 0x10");
    static_assert(offsetof(MeshBatchSourceVertex, bonePaletteBase) == 0x50, "MeshBatchSourceVertex::bonePaletteBase offset must be 0x50");
    static_assert(offsetof(MeshBatchSourceVertex, useSecondaryData) == 0xA4, "MeshBatchSourceVertex::useSecondaryData offset must be 0xA4");
    static_assert(offsetof(MeshBatchSourceVertex, scroll) == 0xA8, "MeshBatchSourceVertex::scroll offset must be 0xA8");
    static_assert(offsetof(MeshBatchSourceVertex, dissolve) == 0xB0, "MeshBatchSourceVertex::dissolve offset must be 0xB0");
    static_assert(offsetof(MeshBatchSourceVertex, parameter) == 0xB4, "MeshBatchSourceVertex::parameter offset must be 0xB4");
    static_assert(offsetof(MeshBatchSourceVertex, boneIndex0) == 0x51, "MeshBatchSourceVertex::boneIndex0 offset must be 0x51");
    static_assert(offsetof(MeshBatchSourceVertex, position) == 0x58, "MeshBatchSourceVertex::position offset must be 0x58");
    static_assert(offsetof(MeshBatchSourceVertex, vec70) == 0x70, "MeshBatchSourceVertex::vec70 offset must be 0x70");
    static_assert(offsetof(MeshBatchSourceVertex, vec7C) == 0x7C, "MeshBatchSourceVertex::vec7C offset must be 0x7C");
    static_assert(offsetof(MeshBatchSourceVertex, vec88) == 0x88, "MeshBatchSourceVertex::vec88 offset must be 0x88");
    static_assert(offsetof(MeshBatchSourceVertex, texCoord0) == 0x94, "MeshBatchSourceVertex::texCoord0 offset must be 0x94");
    static_assert(offsetof(MeshBatchSourceVertex, texCoord1) == 0x9C, "MeshBatchSourceVertex::texCoord1 offset must be 0x9C");
    static_assert(sizeof(MeshBatchSourceVertex) == 0xB8, "MeshBatchSourceVertex size must be 0xB8");

    /// Wrap period the mesh shader's animated-time lane is reduced modulo
    /// (flt_F57F08); shared with the frame/effect shader-time lanes in Mesh.cpp.
    constexpr float kMeshShaderTimeWrapSeconds = 36000.0f;

    /// Normalized dissolve is handed to the shader as a byte (dword_E4F7B8).
    constexpr float kDissolveToByteScale = 255.0f;

    /// Y a bone is parked at when the pose hides it or its remap index is out of
    /// range; combined with a zero scale it collapses the bone's geometry.
    constexpr float kHiddenBoneDepth = -1000.0f;

    /**
     * Scales the three basis rows of a row-major transform in place, leaving the
     * translation row untouched. Inlined into `HardwareMeshBatch::FillBatch` in
     * the binary (the twelve `mulss` at 0x007E8730..0x007E884F).
     */
    void ScaleTransformRows(VMatrix4& transform, const Wm3::Vec3f& scale)
    {
      const float axisScale[3] = {scale.x, scale.y, scale.z};

      for (std::size_t row = 0; row < 3; ++row) {
        transform.r[row].x *= axisScale[row];
        transform.r[row].y *= axisScale[row];
        transform.r[row].z *= axisScale[row];
        transform.r[row].w *= axisScale[row];
      }
    }

    /**
     * Writes one instance's slice of the two global GPU skinning palettes.
     *
     * Each bone's world placement is the pose's composite transform applied to
     * the skeleton's rest offset (scaled by the instance), and its rotation is
     * the composite rotation composed with the rest rotation. Bones the pose
     * hides - and bones whose remap index falls outside the pose - are parked
     * below the world with a zero scale instead.
     *
     * Inlined into `HardwareMeshBatch::FillBatch` in the binary
     * (0x007E8312..0x007E86AC).
     */
    void FillInstanceBonePalettes(
      const MeshInstance& meshInstance,
      const CAniPose& pose,
      const CAniSkel& skeleton,
      const msvc8::vector<std::int32_t>& boneRemapIndices,
      const std::int32_t boneCount,
      const std::uint8_t paletteBase
    )
    {
      SkinPaletteEntry* const transPalette = GetMeshShaderVarTransPalette().mPalette.mBegin;
      SkinPaletteEntry* const rotPalette = GetMeshShaderVarRotPalette().mPalette.mBegin;

      const auto poseBoneCount = static_cast<std::uint32_t>(pose.mBones.end() - pose.mBones.begin());
      const float instanceScale = meshInstance.scale.x;

      for (std::int32_t boneIndex = 0; boneIndex < boneCount; ++boneIndex) {
        const auto slot = static_cast<std::size_t>(paletteBase) + static_cast<std::size_t>(boneIndex);
        const auto remapIndex = static_cast<std::uint32_t>(boneRemapIndices[static_cast<std::size_t>(boneIndex)]);

        const CAniPoseBone* const poseBone =
          remapIndex < poseBoneCount ? &pose.mBones.begin()[remapIndex] : nullptr;

        if (poseBone == nullptr || poseBone->mVisible == 0) {
          transPalette[slot] = SkinPaletteEntry{0.0f, kHiddenBoneDepth, 0.0f, 0.0f};
          rotPalette[slot] = SkinPaletteEntry{0.0f, 0.0f, 0.0f, 1.0f};
          continue;
        }

        // The binary reads the skeleton bone unconditionally once the pose bone
        // is visible: pose and skeleton always carry the same bone count, so the
        // bounds test inlined from CAniSkel::GetBone never fails here.
        const SAniSkelBone* const restBone = skeleton.GetBone(remapIndex);
        const Wm3::Quatf restRotation = restBone->mBoneTransform.orient_;
        const Wm3::Vec3f restOffset = restBone->mBoneTransform.pos_;

        const VTransform composite = poseBone->GetCompositeTransform();

        Wm3::Vec3f scaledOffset{
          restOffset.x * instanceScale,
          restOffset.y * instanceScale,
          restOffset.z * instanceScale,
        };

        Wm3::Vec3f rotatedOffset{};
        MultQuadVec(&rotatedOffset, &scaledOffset, &composite.orient_);

        transPalette[slot] = SkinPaletteEntry{
          composite.pos_.x + rotatedOffset.x,
          rotatedOffset.y + composite.pos_.y,
          rotatedOffset.z + composite.pos_.z,
          instanceScale,
        };

        // Hamilton product `composite.orient_ * restRotation`, written in the
        // binary's exact grouping - float addition does not associate, so the
        // parenthesisation is part of the behaviour.
        const Wm3::Quatf& c = composite.orient_;
        const Wm3::Quatf& b = restRotation;
        Wm3::Quatf composed{
          ((c.w * b.w - c.x * b.x) - c.y * b.y) - c.z * b.z,
          ((b.x * c.w + c.y * b.z) + c.x * b.w) - c.z * b.y,
          ((b.y * c.w + c.z * b.x) + c.y * b.w) - c.x * b.z,
          ((c.x * b.y + b.z * c.w) + c.z * b.w) - c.y * b.x,
        };
        NormalizeQuatInPlace(&composed);

        // The palette hands the shader xyzw; the engine stores wxyz.
        rotPalette[slot] = SkinPaletteEntry{composed.x, composed.y, composed.z, composed.w};
      }
    }
  } // namespace

  /**
   * Address: 0x007E8B70 (FUN_007E8B70, deleting destructor lane; slot 0 of
   * `??_7HardwareMeshBatch@Moho@@6B@`, VTABLE_CONFIRMED via the vtable's data
   * xref to this address)
   * Address: 0x007E7480 (FUN_007E7480, non-deleting destructor body)
   *
   * IDA signature:
   * int __thiscall sub_7E7480(HardwareMeshBatch* this);
   *
   * What it does:
   * Destroys one `HardwareMeshBatch`: releases this batch's own GPU
   * resources through `ReleaseGpuResources`, then falls through to the
   * implicit per-member destruction of the two remaining `boost::shared_ptr`
   * members (`mDynamicVertexBuffer`, `mStaticVertexBuffer` - both already
   * null by this point, so those are no-ops in the binary too) and the base
   * `MeshBatch::~MeshBatch()` teardown of `mCurrentResource` and
   * `mBoneRemapIndices`.
   */
  HardwareMeshBatch::~HardwareMeshBatch()
  {
    ReleaseGpuResources();
  }

  /**
   * Address: 0x007E7BE0 (FUN_007E7BE0)
   *
   * IDA signature:
   * void __usercall sub_7E7BE0(HardwareMeshBatch* this@<esi>);
   *
   * What it does:
   * Releases every GPU-resource handle this batch owns and resets the base
   * batch counters this instance derived during `Initialize`. Release order,
   * exactly as compiled: index buffer, static vertex buffer, dynamic vertex
   * buffer, vertex declaration, then the CPU scratch mirror (`operator
   * delete[]`). The base `MeshBatch` counters `mVertexCount`, `mIndexCount`,
   * `mBoneCount`, `mAttachCount`, `mMaxInstancesPerDraw` and
   * `mActiveInstanceBudget` are zeroed alongside the handle releases;
   * `mTriangleCount` is deliberately left untouched (the binary never writes
   * it here). This is the only caller of this helper - it exists as a
   * separate compiled function in the binary but is exercised solely from
   * the destructor.
   */
  void HardwareMeshBatch::ReleaseGpuResources() noexcept
  {
    mVertexCount = 0;
    mIndexCount = 0;
    mBoneCount = 0;
    mAttachCount = 0;
    mMaxInstancesPerDraw = 0;
    mActiveInstanceBudget = 0;

    IndexBufferHandle().reset();
    mStaticVertexBuffer.reset();
    mDynamicVertexBuffer.reset();
    VertexFormatHandle().reset();

    if (mScratchVertexData != nullptr) {
      ::operator delete[](mScratchVertexData);
      mScratchVertexData = nullptr;
    }
  }

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
   * Address: 0x007E7EA0 (FUN_007E7EA0, slot 9 override; IDA: HardwareMeshBatch::Func9)
   * Mangled slot: ??_7HardwareMeshBatch@Moho@@6B@ +0x24
   *
   * IDA signature:
   * int __thiscall Moho::HardwareMeshBatch::Func9(HardwareMeshBatch* this,
   *   int** current, int* end, char reflectedOnly);
   *
   * What it does:
   * Packs one draw call's worth of per-instance vertex records. It walks
   * `[*current, end)` - advancing `*current` as it goes, so the caller's loop
   * resumes where this one stopped - and for every instance that still has a
   * live pose it stages one instance vertex into the CPU scratch buffer through
   * the hardware vertex formatter's stream-class-1 packer, then uploads the
   * whole run into the dynamic per-instance vertex buffer in one lock.
   *
   * Skinned batches (`mUseBoneRemap`) additionally fill this instance's slice of
   * the two global GPU skinning palettes: `transPalette` takes the bone's world
   * position with the instance's scale in `w`, `rotPalette` takes the composite
   * bone rotation as `xyzw`. A bone the pose hides - or one whose remap index
   * falls outside either the pose or the skeleton - is pushed to y = -1000 with
   * zero scale, which is how the shipped shader makes it disappear. Unskinned
   * batches instead carry the instance transform itself in the vertex record and
   * leave the palettes at the identity this function seeds them to on entry.
   *
   * Both palettes are uploaded to the mesh effect once, after the run.
   *
   * Returns the number of instances actually packed, which is what
   * `MeshBatch::Render` hands to `DrawBatch`.
   */
  std::int32_t HardwareMeshBatch::FillBatch(
    MeshInstance**& current,
    MeshInstance** const end,
    const bool reflectedOnly
  )
  {
    MeshShaderPaletteVar& transPaletteVar = GetMeshShaderVarTransPalette();
    MeshShaderPaletteVar& rotPaletteVar = GetMeshShaderVarRotPalette();
    SkinPaletteEntry* const transPalette = transPaletteVar.mPalette.mBegin;
    SkinPaletteEntry* const rotPalette = rotPaletteVar.mPalette.mBegin;

    gpg::gal::Float16HardwareVertexFormatterD3D9* const formatter = gpg::gal::GetHardwareVertexFormatter();

    // Seed every bone slot this batch owns with an identity transform, so a
    // batch that packs fewer instances than the palette holds leaves no stale
    // bones behind.
    for (std::int32_t boneIndex = 0; boneIndex < mBoneCount; ++boneIndex) {
      transPalette[boneIndex] = SkinPaletteEntry{0.0f, 0.0f, 0.0f, 1.0f};
      rotPalette[boneIndex] = SkinPaletteEntry{0.0f, 0.0f, 0.0f, 1.0f};
    }

    // One draw is capped by the dynamic buffer's instance budget; the caller
    // re-enters for whatever is left over.
    const std::int32_t remaining = static_cast<std::int32_t>(end - current);
    const std::int32_t instanceBudget = (remaining < mActiveInstanceBudget) ? remaining : mActiveInstanceBudget;
    if (instanceBudget == 0) {
      return 0;
    }

    // The binary zeroes the staging record once, ahead of the run, and only
    // rewrites the lanes that vary per instance.
    MeshBatchSourceVertex staging{};

    const std::uint32_t instanceStride = formatter->GetVertexStride(1, 0);

    std::int32_t packedCount = 0;
    std::uint32_t scratchOffset = 0;

    while (current != end) {
      MeshInstance* const meshInstance = *current;

      // The reflection pass only draws instances that are flagged reflectable.
      if (!reflectedOnly || meshInstance->isReflected != 0) {
        boost::shared_ptr<CAniPose> pose;
        CaptureMeshInstanceCurrentPose(&pose, meshInstance);

        // An instance whose pose (or whose pose's skeleton) has gone away is
        // skipped without consuming a slot in the draw.
        const boost::shared_ptr<const CAniSkel> skeleton =
          pose.get() != nullptr ? pose->GetSkeleton() : boost::shared_ptr<const CAniSkel>{};

        if (pose.get() != nullptr && skeleton.get() != nullptr) {
          staging.instanceIndex = static_cast<std::uint8_t>(packedCount);
          staging.color = meshInstance->color;
          staging.meshColor = meshInstance->meshColor;
          staging.shaderTime =
            std::fmod(static_cast<float>(meshInstance->gameTick), kMeshShaderTimeWrapSeconds);
          staging.useSecondaryData = mUseSecondaryData;
          staging.parameter = (&meshInstance->parameters)[mParameterAnnotation];
          staging.scroll[0] = meshInstance->scroll1.x
            + ((meshInstance->scroll2.x - meshInstance->scroll1.x) * MeshInstance::sCurrentInterpolant);
          staging.scroll[1] = meshInstance->scroll1.y
            + ((meshInstance->scroll2.y - meshInstance->scroll1.y) * MeshInstance::sCurrentInterpolant);
          staging.dissolve = static_cast<std::uint8_t>(
            static_cast<std::int32_t>(meshInstance->dissolve * kDissolveToByteScale)
          );

          if (mUseBoneRemap != 0) {
            // Skinned: the vertex record carries no transform of its own - every
            // vertex is placed by the bone palette entries filled below.
            staging.bonePaletteBase =
              static_cast<std::uint8_t>(static_cast<std::int8_t>(packedCount) * static_cast<std::int8_t>(mBoneCount));
            CopyTransform4x4(&staging.transform, VMatrix4::sIdentity);

            FillInstanceBonePalettes(
              *meshInstance, *pose, *skeleton, mBoneRemapIndices, mBoneCount, staging.bonePaletteBase
            );
          } else {
            // Unskinned: one instance transform, scaled per axis, in the record.
            staging.bonePaletteBase = 0;

            meshInstance->UpdateInterpolatedFields();

            VMatrix4 instanceTransform;
            instanceTransform.Set(meshInstance->curOrientation, meshInstance->interpolatedPosition);
            ScaleTransformRows(instanceTransform, meshInstance->scale);

            CopyTransform4x4(&staging.transform, instanceTransform);
          }

          formatter->WriteFormattedVertex(
            1,
            static_cast<std::uint8_t*>(mScratchVertexData) + scratchOffset,
            &staging,
            0
          );

          scratchOffset += instanceStride;
          ++packedCount;
        }
      }

      ++current;
      if (packedCount >= instanceBudget) {
        break;
      }
    }

    // Upload the packed run in one discard lock, then publish both palettes to
    // the mesh effect.
    const std::uint32_t packedBytes = static_cast<std::uint32_t>(packedCount) * instanceStride;
    void* const mapped = mDynamicVertexBuffer->Lock(0U, packedBytes, gpg::gal::MohoD3DLockFlags::Discard);
    std::memcpy(mapped, mScratchVertexData, packedBytes);
    mDynamicVertexBuffer->Unlock();

    if (transPaletteVar.Exists()) {
      transPaletteVar.mEffectVariable->SetPtr(
        transPaletteVar.mPalette.mBegin,
        transPaletteVar.mPalette.Count() * static_cast<std::uint32_t>(sizeof(SkinPaletteEntry))
      );
    }
    if (rotPaletteVar.Exists()) {
      rotPaletteVar.mEffectVariable->SetPtr(
        rotPaletteVar.mPalette.mBegin,
        rotPaletteVar.mPalette.Count() * static_cast<std::uint32_t>(sizeof(SkinPaletteEntry))
      );
    }

    return packedCount;
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
