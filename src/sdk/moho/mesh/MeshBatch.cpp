#include "MeshBatch.h"

#include "moho/resource/RScmResource.h"

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
   * Seeds per-batch metadata from mesh/resource input and prepares remap state.
   */
  void MeshBatch::Initialize(
    const MeshLOD* const /*lod*/,
    const bool remapToReferenceResource,
    const boost::shared_ptr<RScmResource> /*referenceResource*/,
    const boost::shared_ptr<RScmResource> currentResource
  )
  {
    mUseBoneRemap = static_cast<std::uint8_t>(remapToReferenceResource ? 1u : 0u);
    mCurrentResource = currentResource;

    // Common counters are always reset before concrete backend setup in binary.
    mVertexCount = 0;
    mIndexCount = 0;
    mTriangleCount = 0;
    mBoneCount = 0;
    mAttachCount = 0;
    mMaxInstancesPerDraw = 0;
    mActiveInstanceBudget = 0;
    mUseSecondaryData = 0;
    mParameterAnnotation = 0;
    mBoneRemapIndices.clear();

    // Full scm-file and D3D effect binding is recovered in follow-up meshbatch passes.
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
  void MeshBatch::Render(const msvc8::vector<MeshInstance*>& meshInstances, const bool includeHidden)
  {
    MeshInstance** const begin = meshInstances.begin();
    MeshInstance** const end = meshInstances.end();
    const std::int32_t instanceCount = begin ? static_cast<std::int32_t>(end - begin) : 0;

    PrepareBatch(instanceCount);
    BindBuffers();

    MeshInstance** current = begin;
    while (current != end) {
      const std::int32_t packedCount = FillBatch(current, end, includeHidden);
      DrawBatch(packedCount);
    }

    EndBatch();
  }
} // namespace moho
