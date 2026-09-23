#include <cstdio>
#include <cstdlib>
#include "MeshBatch.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>

#include "Mesh.h"
#include "gpg/core/utils/Logging.h"   // TEMPORARY PROBE (do not commit)

#include "moho/animation/CAniPose.h"
#include "moho/animation/CAniSkel.h"
#include "moho/math/QuaternionMath.h"
#include "moho/math/VMatrix4.h"
#include "gpg/gal/backends/d3d9/EffectVariableD3D9.hpp"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/DrawIndexedContext.hpp"
#include "gpg/gal/IndexBufferContext.hpp"
#include "gpg/gal/MeshVertex.h"
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

namespace
{
  // TEMPORARY -- runtime toggle files for the exploded-mesh triage. A toggle is
  // on while "<FAF_TOGGLE_DIR>/<name>" exists; delete when resolved.
  bool RuntimeToggleFileExists(const char* const name)
  {
    static char sDir[512] = {};
    static bool sDirResolved = false;
    if (!sDirResolved) {
      sDirResolved = true;
      std::size_t length = 0;
      if (::getenv_s(&length, sDir, sizeof(sDir), "FAF_TOGGLE_DIR") != 0 || length == 0u) {
        sDir[0] = 0;
      }
    }
    if (sDir[0] == 0) {
      return false;
    }
    char path[640];
    (void)std::snprintf(path, sizeof(path), "%s\\%s", sDir, name);
    return ::GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
  }
}

namespace moho
{
  namespace
  {
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
      SkinPaletteEntry* const transPalette = GetMeshShaderVarTransPalette().mPalette.begin();
      SkinPaletteEntry* const rotPalette = GetMeshShaderVarRotPalette().mPalette.begin();

      const auto poseBoneCount = static_cast<std::uint32_t>(pose.mBones.end() - pose.mBones.begin());
      const float instanceScale = meshInstance.scale.x;

      for (std::int32_t boneIndex = 0; boneIndex < boneCount; ++boneIndex) {
        const auto slot = static_cast<std::size_t>(paletteBase) + static_cast<std::size_t>(boneIndex);
        const auto remapIndex = static_cast<std::uint32_t>(boneRemapIndices[static_cast<std::size_t>(boneIndex)]);

        const CAniPoseBone* const poseBone =
          remapIndex < poseBoneCount ? &pose.mBones.begin()[remapIndex] : nullptr;

        // TEMPORARY SWITCH -- FAF_NO_HIDEBONE=1 treats every remapped bone as
        // visible so hidden-bone parking can be ruled in/out for the wedges.
        static int sIgnoreHiddenBones = 0;
        static unsigned sToggleCalls = 0;
        if ((sToggleCalls++ % 500u) == 0u) {
          sIgnoreHiddenBones = RuntimeToggleFileExists("nohide.on") ? 1 : 0;
        }

        if (poseBone == nullptr || (poseBone->mVisible == 0 && sIgnoreHiddenBones == 0)) {
          // TEMPORARY PROBE -- invisible-commander triage, delete when resolved.
          {
            static int sHiddenBudget = 0;
            static unsigned sHiddenCalls = 0;
            ++sHiddenCalls;
            if (sHiddenBudget < 40 || (sHiddenCalls % 4000u) == 0u) {
              ++sHiddenBudget;
              int visibleCount = 0;
              for (const CAniPoseBone& bone : pose.mBones) {
                visibleCount += bone.mVisible != 0u ? 1 : 0;
              }
              const SAniSkelBone* const hiddenSkelBone = skeleton.GetBone(remapIndex);
              const char* const hiddenName =
                hiddenSkelBone != nullptr && hiddenSkelBone->mBoneName != nullptr ? hiddenSkelBone->mBoneName : "?";
              char probe[300];
              (void)std::snprintf(probe, sizeof(probe),
                                  "[BONEHIDE] call=%u inst=%p pose=%p bone=%d/%d remap=%u name=%s poseBones=%u poseVisible=%d poseBone=%p visible=%d\n",
                                  sHiddenCalls, static_cast<const void*>(&meshInstance), static_cast<const void*>(&pose),
                                  boneIndex, boneCount, remapIndex, hiddenName, poseBoneCount, visibleCount,
                                  static_cast<const void*>(poseBone),
                                  poseBone != nullptr ? static_cast<int>(poseBone->mVisible) : -1);
              ::OutputDebugStringA(probe);
            }
          }
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

        // Hamilton product `composite.orient_ * restRotation`, transcribed from
        // the four inlined SSE blocks in `HardwareMeshBatch::Func9`/`FillBatch`
        // (0x007E7EA0). Both operands are ordinary `(w,x,y,z)`-storage
        // quaternions - `Wm3::Quaternion` keeps `m_afTuple[0]=w,[1]=x,[2]=y,
        // [3]=z`, and the binary loads `composite.orient_` from the transform's
        // `+0x00..+0x0C` and `restRotation` from `SAniSkelBone::mBoneTransform.
        // orient_`'s `+0x24..+0x30` as four raw floats in that same order - so
        // this is the plain textbook product, with no scalar-lane reinterpret.
        // Naming the loaded slots `c0..c3` / `r0..r3` by memory index, the
        // binary computes:
        //   0x007E84D4..0x007E8510  w = c0*r0 - c1*r1 - c2*r2 - c3*r3
        //   0x007E8516..0x007E8543  x = c0*r1 + c2*r3 + c1*r0 - c3*r2
        //   0x007E8549..0x007E8591  y = c0*r2 + c3*r1 + c2*r0 - c1*r3
        //   0x007E8571..0x007E8595  z = c1*r2 + c0*r3 + c3*r0 - c2*r1
        // Float addition does not associate, so the parenthesisation below
        // mirrors the binary's exact accumulation order.
        const Wm3::Quatf& c = composite.orient_;
        const Wm3::Quatf& b = restRotation;
        Wm3::Quatf composed{
          ((c.w * b.w - c.x * b.x) - c.y * b.y) - c.z * b.z,
          ((c.w * b.x + c.y * b.z) + c.x * b.w) - c.z * b.y,
          ((c.w * b.y + c.z * b.x) + c.y * b.w) - c.x * b.z,
          ((c.x * b.y + c.w * b.z) + c.z * b.w) - c.y * b.x,
        };
        NormalizeQuatInPlace(&composed);

        // The palette hands the shader xyzw; the engine stores wxyz.
        rotPalette[slot] = SkinPaletteEntry{composed.x, composed.y, composed.z, composed.w};

        // TEMPORARY PROBE -- invisible-commander triage, delete when resolved.
        {
          static int sBoneBudget = 0;
          if (sBoneBudget < 12 && boneCount > 4) {
            ++sBoneBudget;
            char probe[320];
            (void)std::snprintf(
              probe, sizeof(probe),
              "[BONEDIAG] inst=%p bone=%d/%d remap=%u pos=(%.2f,%.2f,%.2f) s=%.3f "
              "comp.pos=(%.2f,%.2f,%.2f) comp.q=(%.3f,%.3f,%.3f,%.3f) rest.pos=(%.2f,%.2f,%.2f) "
              "rest.q=(%.3f,%.3f,%.3f,%.3f) out.q=(%.3f,%.3f,%.3f,%.3f)\n",
              static_cast<const void*>(&meshInstance), boneIndex, boneCount, remapIndex,
              meshInstance.interpolatedPosition.x, meshInstance.interpolatedPosition.y, meshInstance.interpolatedPosition.z,
              instanceScale,
              composite.pos_.x, composite.pos_.y, composite.pos_.z,
              c.w, c.x, c.y, c.z,
              restOffset.x, restOffset.y, restOffset.z,
              b.w, b.x, b.y, b.z,
              composed.w, composed.x, composed.y, composed.z);
            ::OutputDebugStringA(probe);
          }
        }
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

    mIndexBuffer.reset();
    mStaticVertexBuffer.reset();
    mDynamicVertexBuffer.reset();
    mVertexFormat.reset();

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

    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
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

      mIndexBuffer = device->CreateIndexBuffer(&indexContext);

      const std::size_t indexBytes = static_cast<std::size_t>(mIndexCount) * sizeof(std::uint16_t);
      std::int16_t* const mappedIndices = mIndexBuffer->Lock(0U, 0U, gpg::gal::MohoD3DLockFlags::None);
      std::memcpy(mappedIndices, scm_file::GetIndices(*mesh), indexBytes);
      mIndexBuffer->Unlock();
    }

    // --- Vertex declaration + static vertex buffer. ---
    gpg::gal::MeshFormatter* const formatter = gpg::gal::GetHardwareVertexFormatter();
    mVertexFormat = formatter->CreateVertexFormat(0);

    const std::uint32_t vertexStride = formatter->GetVertexStride(0, 0);

    gpg::gal::VertexBufferContext vertexContext;
    vertexContext.vertexCount_ = static_cast<std::uint32_t>(mVertexCount);
    vertexContext.stride_ = vertexStride;
    vertexContext.type_ = 2U;
    vertexContext.usage_ = 1U;

    mStaticVertexBuffer = device->CreateVertexBuffer(&vertexContext);

    auto* mappedVertices =
      static_cast<std::uint8_t*>(mStaticVertexBuffer->Lock(0U, 0U, gpg::gal::MohoD3DLockFlags::None));

    const SScmVertex* const sourceVertices = scm_file::GetVertices(*mesh);
    for (std::int32_t vertexIndex = 0; vertexIndex < mVertexCount; ++vertexIndex) {
      const SScmVertex& source = sourceVertices[vertexIndex];

      gpg::gal::MeshVertex staging{};
      staging.position[0] = source.mLocalPositionX;
      staging.position[1] = source.mLocalPositionY;
      staging.position[2] = source.mLocalPositionZ;
      // 0x007E79B2..0x007E7A43, staging record at [esp+0x4C].
      staging.normal[0] = source.mNormal[0];
      staging.normal[1] = source.mNormal[1];
      staging.normal[2] = source.mNormal[2];
      staging.tangent[0] = source.mTangent[0];
      staging.tangent[1] = source.mTangent[1];
      staging.tangent[2] = source.mTangent[2];
      staging.binormal[0] = source.mBinormal[0];
      staging.binormal[1] = source.mBinormal[1];
      staging.binormal[2] = source.mBinormal[2];
      staging.texCoord0[0] = source.mTexCoord0[0];
      staging.texCoord0[1] = source.mTexCoord0[1];
      staging.texCoord1[0] = source.mTexCoord1[0];
      staging.texCoord1[1] = source.mTexCoord1[1];
      staging.boneIndices[0] = source.mBoneIndex;
      staging.boneIndices[1] = source.mBoneIndex1;
      staging.boneIndices[2] = source.mBoneIndex2;
      staging.boneIndices[3] = source.mBoneIndex3;

      formatter->WriteFormattedVertex(0, mappedVertices, staging, 0);
      mappedVertices += vertexStride;
    }

    mStaticVertexBuffer->Unlock();

    // TEMPORARY PROBE -- exploded-mesh triage, delete when resolved. Which
    // bones do this mesh's vertices reference, by name, and does any index
    // fall outside the skinned bone range?
    if (mBoneCount > 4) {
      static int sHistBudget = 0;
      const boost::shared_ptr<const CAniSkel> gateSkeleton = currentResource->GetSkeleton();
      const SAniSkelBone* const gateBone = gateSkeleton ? gateSkeleton->GetBone(0u) : nullptr;
      const char* const gateName = gateBone != nullptr && gateBone->mBoneName != nullptr ? gateBone->mBoneName : "";
      const bool looksLikeUnit = std::strlen(gateName) == 7 && (gateName[0] == 'U' || gateName[0] == 'X');
      if (sHistBudget < 12 && looksLikeUnit) {
        ++sHistBudget;
        {
          char remapLine[700];
          int rw = std::snprintf(remapLine, sizeof(remapLine), "[REMAP] batch=%p unit=%s useRemap=%u ref=%p cur=%p bones=%d:",
                                 static_cast<const void*>(this), gateName, static_cast<unsigned>(mUseBoneRemap),
                                 static_cast<const void*>(referenceResource.get()), static_cast<const void*>(currentResource.get()),
                                 mBoneCount);
          for (std::int32_t i = 0; i < mBoneCount && rw < static_cast<int>(sizeof(remapLine)) - 12; ++i) {
            rw += std::snprintf(remapLine + rw, sizeof(remapLine) - static_cast<std::size_t>(rw), " %d", mBoneRemapIndices[static_cast<std::size_t>(i)]);
          }
          (void)std::snprintf(remapLine + rw, sizeof(remapLine) - static_cast<std::size_t>(rw), "\n");
          ::OutputDebugStringA(remapLine);
        }
        // Triangles whose three vertices sit on different bones, computed on
        // the CPU-side SCM data this batch was built from. The shipped files
        // have zero of these, so any non-zero count here means the in-memory
        // mesh is already corrupt before it reaches the GPU.
        {
          const std::uint16_t* const indices = scm_file::GetIndices(*mesh);
          unsigned mixed = 0;
          unsigned badIndex = 0;
          for (std::int32_t tri = 0; tri < mTriangleCount; ++tri) {
            const std::uint16_t a = indices[3 * tri];
            const std::uint16_t b = indices[3 * tri + 1];
            const std::uint16_t c = indices[3 * tri + 2];
            if (a >= mVertexCount || b >= mVertexCount || c >= mVertexCount) {
              ++badIndex;
              continue;
            }
            const unsigned ba = sourceVertices[a].mBoneIndex;
            const unsigned bb = sourceVertices[b].mBoneIndex;
            const unsigned bc = sourceVertices[c].mBoneIndex;
            if (ba != bb || bb != bc) {
              ++mixed;
            }
          }
          char mixedLine[300];
          (void)std::snprintf(mixedLine, sizeof(mixedLine),
                              "[MIXTRI] batch=%p unit=%s tris=%d mixed=%u badIndex=%u idx0..5=%u,%u,%u,%u,%u,%u hdr: vOff=%u vCnt=%u iOff=%u iCnt=%u skin=%u total=%u\n",
                              static_cast<const void*>(this), gateName, mTriangleCount, mixed, badIndex,
                              indices[0], indices[1], indices[2], indices[3], indices[4], indices[5],
                              mesh->mVertexOffset, mesh->mVertexCount, mesh->mIndexDataOffset,
                              mesh->mIndexCount, mesh->mSkinBoneCount, mesh->mBoneTotalCount);
          ::OutputDebugStringA(mixedLine);
        }
        // GPU-side read-back: decode the first three packed vertices straight
        // out of the static vertex buffer and the first six indices out of the
        // index buffer, next to the source values they were packed from.
        {
          auto halfToFloat = [](const std::uint16_t h) -> float {
            const std::uint32_t sign = (h & 0x8000u) ? 0x80000000u : 0u;
            std::uint32_t exponent = (h >> 10) & 0x1Fu;
            std::uint32_t mantissa = h & 0x3FFu;
            std::uint32_t bits;
            if (exponent == 0u) {
              if (mantissa == 0u) {
                bits = sign;
              } else {
                exponent = 127u - 15u + 1u;
                while ((mantissa & 0x400u) == 0u) { mantissa <<= 1; --exponent; }
                mantissa &= 0x3FFu;
                bits = sign | (exponent << 23) | (mantissa << 13);
              }
            } else if (exponent == 31u) {
              bits = sign | 0x7F800000u | (mantissa << 13);
            } else {
              bits = sign | ((exponent + 127u - 15u) << 23) | (mantissa << 13);
            }
            float out;
            std::memcpy(&out, &bits, sizeof(out));
            return out;
          };
          const std::uint32_t stride = formatter->GetVertexStride(0, 0);
          const auto* const packed = static_cast<const std::uint8_t*>(
            mStaticVertexBuffer->Lock(0U, 0U, gpg::gal::MohoD3DLockFlags::ReadOnly));
          char rb[900];
          int w = std::snprintf(rb, sizeof(rb), "[VBREAD] batch=%p fmt=%u stride=%u decl=%p",
                                static_cast<const void*>(this),
                                mVertexFormat ? mVertexFormat->formatCode_ : 0u, stride,
                                mVertexFormat ? static_cast<gpg::gal::VertexFormatD3D9*>(mVertexFormat.get())->vertexDeclaration_ : nullptr);
          for (int v = 0; v < 3 && packed != nullptr; ++v) {
            const std::uint8_t* const rec = packed + static_cast<std::size_t>(v) * stride;
            std::uint16_t h[4];
            std::memcpy(h, rec, sizeof(h));
            const SScmVertex& src = sourceVertices[v];
            w += std::snprintf(rb + w, sizeof(rb) - static_cast<std::size_t>(w),
                               " | v%d src=(%.3f,%.3f,%.3f) b=%u gpu=(%.3f,%.3f,%.3f) b=%u,%u,%u,%u",
                               v, src.mLocalPositionX, src.mLocalPositionY, src.mLocalPositionZ, src.mBoneIndex,
                               halfToFloat(h[0]), halfToFloat(h[1]), halfToFloat(h[2]),
                               rec[0x28], rec[0x29], rec[0x2A], rec[0x2B]);
          }
          if (packed != nullptr) {
            // Full-buffer verification: every vertex's position and bone byte
            // against the source records, plus a sanity bound on the source.
            unsigned posMismatch = 0;
            unsigned boneMismatch = 0;
            unsigned sourceOutOfBounds = 0;
            int worstVertex = -1;
            float worstError = 0.0f;
            for (std::int32_t v = 0; v < mVertexCount; ++v) {
              const std::uint8_t* const rec = packed + static_cast<std::size_t>(v) * stride;
              std::uint16_t h[3];
              std::memcpy(h, rec, sizeof(h));
              const SScmVertex& src = sourceVertices[v];
              const float srcPos[3] = {src.mLocalPositionX, src.mLocalPositionY, src.mLocalPositionZ};
              float err = 0.0f;
              for (int k = 0; k < 3; ++k) {
                const float d = std::fabs(halfToFloat(h[k]) - srcPos[k]);
                if (d > err) {
                  err = d;
                }
                if (std::fabs(srcPos[k]) > 1000.0f) {
                  ++sourceOutOfBounds;
                }
              }
              if (err > 0.05f + 0.01f * std::fabs(srcPos[0]) + 0.01f * std::fabs(srcPos[1]) + 0.01f * std::fabs(srcPos[2])) {
                ++posMismatch;
              }
              if (err > worstError) {
                worstError = err;
                worstVertex = v;
              }
              if (rec[0x28] != src.mBoneIndex) {
                ++boneMismatch;
              }
            }
            w += std::snprintf(rb + w, sizeof(rb) - static_cast<std::size_t>(w),
                               " | FULL posMismatch=%u boneMismatch=%u srcOOB=%u worst=v%d err=%.4f",
                               posMismatch, boneMismatch, sourceOutOfBounds, worstVertex, worstError);
            mStaticVertexBuffer->Unlock();
          }
          const std::int16_t* const gpuIndices = mIndexBuffer->Lock(0U, 0U, gpg::gal::MohoD3DLockFlags::ReadOnly);
          if (gpuIndices != nullptr) {
            w += std::snprintf(rb + w, sizeof(rb) - static_cast<std::size_t>(w), " | gpuIdx=%d,%d,%d,%d,%d,%d",
                               gpuIndices[0], gpuIndices[1], gpuIndices[2], gpuIndices[3], gpuIndices[4], gpuIndices[5]);
            mIndexBuffer->Unlock();
          }
          (void)std::snprintf(rb + w, sizeof(rb) - static_cast<std::size_t>(w), "\n");
          ::OutputDebugStringA(rb);
        }
        unsigned counts[256] = {};
        unsigned outOfRange = 0;
        unsigned maxIndex = 0;
        for (std::int32_t vertexIndex = 0; vertexIndex < mVertexCount; ++vertexIndex) {
          const unsigned boneIndex = sourceVertices[vertexIndex].mBoneIndex;
          ++counts[boneIndex];
          if (boneIndex > maxIndex) {
            maxIndex = boneIndex;
          }
          if (static_cast<std::int32_t>(boneIndex) >= mBoneCount) {
            ++outOfRange;
          }
        }
        const boost::shared_ptr<const CAniSkel> skeleton = currentResource->GetSkeleton();
        char line[1600];
        int written = std::snprintf(line, sizeof(line), "[VERTHIST] batch=%p verts=%d bones=%d/%u maxIdx=%u outOfRange=%u:",
                                    static_cast<const void*>(this), mVertexCount, mBoneCount,
                                    skeleton ? static_cast<unsigned>(skeleton->mBones.size()) : 0u, maxIndex, outOfRange);
        for (std::int32_t boneIndex = 0; boneIndex < mBoneCount && written < static_cast<int>(sizeof(line)) - 80; ++boneIndex) {
          const SAniSkelBone* const bone = skeleton ? skeleton->GetBone(static_cast<std::uint32_t>(boneIndex)) : nullptr;
          const char* const name = bone != nullptr && bone->mBoneName != nullptr ? bone->mBoneName : "?";
          const int parent = bone != nullptr ? bone->mParentBoneIndex : -9;
          written += std::snprintf(line + written, sizeof(line) - static_cast<std::size_t>(written),
                                   " %d:%s(p%d)=%u", boneIndex, name, parent, counts[boneIndex]);
        }
        (void)std::snprintf(line + written, sizeof(line) - static_cast<std::size_t>(written), "\n");
        ::OutputDebugStringA(line);
      }
    }
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

    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();

    // New budget = min(requested, cap).
    mActiveInstanceBudget = (instanceCount < mMaxInstancesPerDraw) ? instanceCount : mMaxInstancesPerDraw;

    gpg::gal::MeshFormatter* const formatter = gpg::gal::GetHardwareVertexFormatter();

    gpg::gal::VertexBufferContext vertexContext;
    vertexContext.vertexCount_ = static_cast<std::uint32_t>(mActiveInstanceBudget);
    vertexContext.type_ = 3U;
    vertexContext.usage_ = 2U;
    const std::uint32_t perInstanceStride = formatter->GetVertexStride(1, 0);
    vertexContext.stride_ = perInstanceStride;

    mDynamicVertexBuffer = device->CreateVertexBuffer(&vertexContext);

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
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    device->SetVertexDeclaration(mVertexFormat);
    device->SetBufferIndices(mIndexBuffer);
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
    // TEMPORARY PROBE (do not commit): "nostatic.on" skips every non-bone-remap batch.
    {
      static int sSkipStatic = 0;
      static unsigned sStaticToggleCalls = 0;
      if ((sStaticToggleCalls++ % 100u) == 0u) {
        sSkipStatic = RuntimeToggleFileExists("nostatic.on") ? 1 : 0;
      }
      if (sSkipStatic != 0 && mUseBoneRemap == 0) {
        return;
      }
    }

    // TEMPORARY PROBE / SWITCH -- exploded-mesh triage, delete when resolved.
    // FAF_NO_SKINNED=1 skips every skinned (bone-remapped) draw so the black
    // wedges can be attributed; the probe dumps the first few skinned draws.
    {
      static int sSkinnedDrawMode = 0;
      static unsigned sDrawToggleCalls = 0;
      if ((sDrawToggleCalls++ % 100u) == 0u) {
        sSkinnedDrawMode = RuntimeToggleFileExists("noskin.on") ? 1 : 0;
      }
      if (mUseBoneRemap != 0) {
        static int sDrawBudget = 0;
        if (sDrawBudget < 6 && mBoneCount > 4) {
          ++sDrawBudget;
          const SkinPaletteEntry* const trans = GetMeshShaderVarTransPalette().mPalette.begin();
          const SkinPaletteEntry* const rot = GetMeshShaderVarRotPalette().mPalette.begin();
          const auto* const record = static_cast<const std::uint8_t*>(mScratchVertexData);
          const float* const rows = reinterpret_cast<const float*>(record);
          char probe[512];
          (void)std::snprintf(
            probe, sizeof(probe),
            "[DRAWDIAG] batch=%p packed=%d verts=%d idx=%d bones=%d maxInst=%d budget=%d paletteSize=%u "
            "trans0=(%.2f,%.2f,%.2f,%.3f) rot0=(%.3f,%.3f,%.3f,%.3f) trans1=(%.2f,%.2f,%.2f,%.3f) "
            "anim=(%u,%u,%u,%u) row0=(%.2f,%.2f,%.2f) row3=(%.2f,%.2f,%.2f) skip=%d\n",
            static_cast<const void*>(this), packedCount, mVertexCount, mIndexCount, mBoneCount,
            mMaxInstancesPerDraw, mActiveInstanceBudget,
            static_cast<unsigned>(GetMeshShaderVarTransPalette().mPalette.size()),
            trans[0].x, trans[0].y, trans[0].z, trans[0].w, rot[0].x, rot[0].y, rot[0].z, rot[0].w,
            trans[1].x, trans[1].y, trans[1].z, trans[1].w,
            record[0x30], record[0x31], record[0x32], record[0x33],
            rows[0], rows[1], rows[2], rows[9], rows[10], rows[11], sSkinnedDrawMode);
          ::OutputDebugStringA(probe);
        }
        if (sSkinnedDrawMode == 1) {
          return;
        }
        // Per-family toggles: skip ACUs, the Salem destroyers, or everything
        // that is not a unit (tree clusters and other props).
        static unsigned sFamilyToggleCalls = 0;
        static int sSkipAcu = 0;
        static int sSkipDest = 0;
        static int sSkipNonUnit = 0;
        if ((sFamilyToggleCalls++ % 100u) == 0u) {
          sSkipAcu = RuntimeToggleFileExists("noacu.on") ? 1 : 0;
          sSkipDest = RuntimeToggleFileExists("nodest.on") ? 1 : 0;
          sSkipNonUnit = RuntimeToggleFileExists("notrees.on") ? 1 : 0;
        }
        if (sSkipAcu != 0 || sSkipDest != 0 || sSkipNonUnit != 0) {
          boost::shared_ptr<const CAniSkel> skeleton;
          if (mCurrentResource) {
            skeleton = mCurrentResource->GetSkeleton();
          }
          const SAniSkelBone* const root = skeleton ? skeleton->GetBone(0u) : nullptr;
          const char* const rootName = root != nullptr && root->mBoneName != nullptr ? root->mBoneName : "";
          const bool isUnit = std::strlen(rootName) == 7 && (rootName[0] == 'U' || rootName[0] == 'X');
          const bool isAcu = isUnit && std::strcmp(rootName + 2, "L0001") == 0;
          const bool isDest = std::strcmp(rootName, "URS0201") == 0;
          if ((sSkipAcu != 0 && isAcu) || (sSkipDest != 0 && isDest) || (sSkipNonUnit != 0 && !isUnit)) {
            return;
          }
        }
      }
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
    SkinPaletteEntry* const transPalette = transPaletteVar.mPalette.begin();
    SkinPaletteEntry* const rotPalette = rotPaletteVar.mPalette.begin();

    gpg::gal::MeshFormatter* const formatter = gpg::gal::GetHardwareVertexFormatter();

    // Seed every bone slot this batch owns with an identity transform, so a
    // batch that packs fewer instances than the palette holds leaves no stale
    // bones behind.
    { static int sSeed = 0; if (sSeed < 12) { ++sSeed; gpg::Warnf("[SEEDDIAG] batch=%p boneCount=%d remap=%d paletteSize=%u", static_cast<const void*>(this), mBoneCount, static_cast<int>(mUseBoneRemap), static_cast<unsigned>(transPaletteVar.mPalette.size())); } } // TEMPORARY PROBE (do not commit)
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
    gpg::gal::MeshVertex staging{};

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

        // TEMPORARY PROBE -- invisible-props triage, delete when resolved.
        if (pose.get() == nullptr || skeleton.get() == nullptr) {
          static unsigned sSkipCalls = 0;
          if ((sSkipCalls++ % 300u) == 0u) {
            char skipLine[200];
            (void)std::snprintf(skipLine, sizeof(skipLine), "[FILLSKIP] batch=%p bones=%d inst=%p pose=%p skel=%p staticPose=%u\n",
                                static_cast<const void*>(this), mBoneCount, static_cast<const void*>(meshInstance),
                                static_cast<const void*>(pose.get()), static_cast<const void*>(skeleton.get()),
                                static_cast<unsigned>(meshInstance->isStaticPose));
            ::OutputDebugStringA(skipLine);
          }
        }

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
            { static int sI = 0; if (sI < 10) { ++sI; gpg::Warnf("[INSTDIAG] inst=%p pos=(%.2f,%.2f,%.2f) q=(%.3f,%.3f,%.3f,%.3f) scale=(%.3f,%.3f,%.3f) r0=(%.3f,%.3f,%.3f) r3=(%.2f,%.2f,%.2f)", static_cast<const void*>(meshInstance), meshInstance->interpolatedPosition.x, meshInstance->interpolatedPosition.y, meshInstance->interpolatedPosition.z, meshInstance->curOrientation.w, meshInstance->curOrientation.x, meshInstance->curOrientation.y, meshInstance->curOrientation.z, meshInstance->scale.x, meshInstance->scale.y, meshInstance->scale.z, instanceTransform.r[0].x, instanceTransform.r[0].y, instanceTransform.r[0].z, instanceTransform.r[3].x, instanceTransform.r[3].y, instanceTransform.r[3].z); } } // TEMPORARY PROBE (do not commit)
          }

          formatter->WriteFormattedVertex(
            1,
            static_cast<std::uint8_t*>(mScratchVertexData) + scratchOffset,
            staging,
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
        transPaletteVar.mPalette.begin(),
        static_cast<std::uint32_t>(transPaletteVar.mPalette.size()) * static_cast<std::uint32_t>(sizeof(SkinPaletteEntry))
      );
    }
    if (rotPaletteVar.Exists()) {
      rotPaletteVar.mEffectVariable->SetPtr(
        rotPaletteVar.mPalette.begin(),
        static_cast<std::uint32_t>(rotPaletteVar.mPalette.size()) * static_cast<std::uint32_t>(sizeof(SkinPaletteEntry))
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
