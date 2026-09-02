#include "MeshBatch.h"

#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/backends/d3d9/DeviceD3D9.hpp"
#include "moho/mesh/Mesh.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/d3d/CD3DEffectTechnique.h"
#include "moho/resource/RScmResource.h"
#include "moho/resource/SScmFile.h"

#include <cstring>

namespace
{
  /**
   * Address: 0x007E8F70 (FUN_007E8F70)
   *
   * What it does:
   * Scans one C-string pointer range and stores the first cursor whose text
   * exactly matches the probe string; otherwise stores `end`.
   */
  const char*** MeshBatchFindMatchingNameCursor(
    const msvc8::string* const probeName,
    const char*** const outCursor,
    const char** begin,
    const char** const end
  ) noexcept
  {
    if (probeName == nullptr || outCursor == nullptr) {
      return nullptr;
    }

    const char** cursor = begin;
    while (cursor != end) {
      const char* const candidateText = *cursor;
      const std::size_t candidateLength = (candidateText != nullptr) ? std::strlen(candidateText) : 0u;

      const int compareResult =
        probeName->compare(0u, probeName->size(), candidateText != nullptr ? candidateText : "", candidateLength);
      if (compareResult == 0) {
        break;
      }

      ++cursor;
    }

    *outCursor = cursor;
    return outCursor;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x007E6DA0 (FUN_007E6DA0, Moho::MeshBatchInit)
   *
   * What it does:
   * Initializes base batch state, counters, remap storage and resource handles.
   */
  MeshBatch::MeshBatch()
    : mUseBoneRemap(1)
    , pad_05_07{}
    , mCurrentResource()
    , mVertexCount(0)
    , mIndexCount(0)
    , mTriangleCount(0)
    , mBoneCount(0)
    , mAttachCount(0)
    , mMaxInstancesPerDraw(0)
    , mActiveInstanceBudget(0)
    , mBoneRemapIndices()
    , mUseSecondaryData(0)
    , pad_3D_3F{}
    , mParameterAnnotation(0)
    , mVertexDeclarationHandle()
    , mIndexBindingHandle()
  {}

  /**
   * Address: 0x007E6E10 (FUN_007E6E10, deleting destructor thunk)
   * Address: 0x007E6E30 (FUN_007E6E30, complete dtor)
   *
   * What it does:
   * Releases batch handles/remap buffers and base resource ownership.
   */
  MeshBatch::~MeshBatch() = default;

  /**
   * Address: 0x007E6F60 (FUN_007E6F60, Moho::MeshBatch::Initialize)
   *
   * What it does:
   * Seeds every per-batch counter from the current mesh resource's SCM file,
   * sizes the bone-remap table, derives the instance budget, and resolves the
   * LOD material's `parameter` integer annotation off the "mesh" effect.
   *
   * The remap table is what maps this batch's bone slots onto the pose's bones.
   * When the batch is not remapped, or the reference resource is absent or is
   * the current resource, it is the identity (0x007E7010). Otherwise both SCM
   * files' bone-name blocks are walked and each of this mesh's bones is matched
   * by name into the reference mesh, with unmatched bones mapping to 0
   * (0x007E7050..0x007E7180).
   */
  void MeshBatch::Initialize(
    const MeshLOD* const lod,
    const bool remapToReferenceResource,
    const boost::shared_ptr<RScmResource> referenceResource,
    const boost::shared_ptr<RScmResource> currentResource
  )
  {
    mUseBoneRemap = static_cast<std::uint8_t>(remapToReferenceResource ? 1u : 0u);
    mCurrentResource = currentResource;

    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    ID3DDeviceResources* const resources = D3D_GetDevice()->GetResources();
    const gpg::gal::DeviceContext* const deviceContext = device->GetDeviceContext();

    const SScmFile& mesh = *currentResource->mFile;

    // 0x007E6FB9..0x007E6FE3. The triangle count is the index count divided by
    // three (the binary's `imul 55555556h` signed magic divide), and the attach
    // count is the bone-table remainder past the skinned bones.
    mVertexCount = static_cast<std::int32_t>(mesh.mBoneBoundsSampleCount);
    mIndexCount = static_cast<std::int32_t>(mesh.mIndexCount);
    mTriangleCount = mIndexCount / 3;
    mBoneCount = static_cast<std::int32_t>(mesh.mSkinBoneCount);
    mAttachCount = static_cast<std::int32_t>(mesh.mBoneTotalCount) - mBoneCount;

    mBoneRemapIndices.resize(static_cast<std::size_t>(mBoneCount));

    if (mUseBoneRemap != 0u) {
      // Remapped batches share one 80-slot skinning palette between instances,
      // so the budget is however many whole skeletons fit in it (0x007E6FFC).
      mMaxInstancesPerDraw = 80 / mBoneCount;

      const RScmResource* const reference = referenceResource.get();
      if (reference == nullptr || reference == currentResource.get()) {
        for (std::int32_t boneIndex = 0; boneIndex < mBoneCount; ++boneIndex) {
          mBoneRemapIndices.begin()[static_cast<std::size_t>(boneIndex)] = boneIndex;
        }
      } else {
        msvc8::vector<const char*> meshBoneNames;
        msvc8::vector<const char*> referenceBoneNames;
        scm_file::FillBoneNamePointers(mesh, meshBoneNames);
        scm_file::FillBoneNamePointers(*reference->mFile, referenceBoneNames);

        const char** const referenceBegin = referenceBoneNames.begin();
        const char** const referenceEnd = referenceBoneNames.end();

        for (std::int32_t boneIndex = 0; boneIndex < mBoneCount; ++boneIndex) {
          const char* const boneName = meshBoneNames.begin()[static_cast<std::size_t>(boneIndex)];
          const msvc8::string probeName(boneName, std::strlen(boneName));

          const char** match = referenceEnd;
          MeshBatchFindMatchingNameCursor(&probeName, &match, referenceBegin, referenceEnd);

          // A bone with no counterpart in the reference skeleton maps to slot 0.
          mBoneRemapIndices.begin()[static_cast<std::size_t>(boneIndex)] =
            (match == referenceEnd) ? 0 : static_cast<std::int32_t>(match - referenceBegin);
        }
      }
    } else {
      // Non-remapped batches are hardware-instanced: the budget is whichever of
      // the 16-bit vertex-index ceiling and the device's primitive cap binds
      // first (0x007E72A3 onward).
      std::int32_t budget = 0xFFFF / mVertexCount;
      const auto primitiveBudget =
        static_cast<std::int32_t>(deviceContext->mMaxPrimitiveCount / static_cast<std::uint32_t>(mTriangleCount));
      if (budget >= primitiveBudget) {
        budget = primitiveBudget;
      }
      mMaxInstancesPerDraw = budget;
    }

    mUseSecondaryData = lod->scrolling;

    // 0x007E7130..0x007E7181: look up the "mesh" effect and read the LOD
    // material technique's "parameter" integer annotation into +0x40. IDA
    // resolves the technique argument as `lod + 0x10`, which is
    // `MeshLOD::mat` (+0x0C) plus `MeshMaterial::mShaderAnnotation` (+0x04).
    // The call site pushes the effect and the two strings but no visible
    // default literal, so the default is taken as 0 - the same value the
    // sibling "renderStage" lookup in Mesh.cpp passes.
    CD3DEffect* const meshEffect = resources->FindEffect("mesh");
    mParameterAnnotation =
      meshEffect->GetIntegerAnnotation(lod->mat.mShaderAnnotation, msvc8::string("parameter"), 0);
  }

  /**
   * Address: 0x007E6F40 (FUN_007E6F40, ?GetBoneCount@MeshBatch@Moho@@UBEHXZ)
   */
  std::int32_t MeshBatch::GetBoneCount() const
  {
    return mBoneCount;
  }

  /**
   * Address: 0x007E6F50 (FUN_007E6F50, ?GetAttachCount@MeshBatch@Moho@@UBEHXZ)
   */
  std::int32_t MeshBatch::GetAttachCount() const
  {
    return mAttachCount;
  }

  /**
   * Address: 0x007E72D0 (FUN_007E72D0,
   * ?Render@MeshBatch@Moho@@UAEXABV?$vector@PAVMeshInstance@Moho@@V?$allocator@PAVMeshInstance@Moho@@@std@@@std@@_N@Z)
   *
   * What it does:
   * Dispatches instance rendering in derived-defined batch slices.
   */
  void MeshBatch::Render(const msvc8::vector<MeshInstance*>& meshInstances, const bool reflectedOnly)
  {
    MeshInstance** const begin = meshInstances.begin();
    MeshInstance** const end = meshInstances.end();
    const std::int32_t instanceCount = begin ? static_cast<std::int32_t>(end - begin) : 0;

    PrepareBatch(instanceCount);
    BindBuffers();

    MeshInstance** current = begin;
    while (current != end) {
      const std::int32_t packedCount = FillBatch(current, end, reflectedOnly);
      DrawBatch(packedCount);
    }

    EndBatch();
  }
} // namespace moho
