#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "legacy/containers/Vector.h"

namespace moho
{
  class MeshInstance;
  class MeshLOD;
  class MeshBatchRenderBinding;
  class RScmResource;

  /**
   * Base mesh batch interface/state shared by software/hardware batch implementations.
   *
   * Address evidence:
   * - 0x007E6DA0 (FUN_007E6DA0, Moho::MeshBatchInit)
   * - 0x007E6E30 (FUN_007E6E30, complete destructor body)
   * - 0x007E6E10 (FUN_007E6E10, deleting destructor thunk)
   */
  class MeshBatch
  {
  public:
    /**
     * Address: 0x007E6DA0 (FUN_007E6DA0, Moho::MeshBatchInit)
     *
     * What it does:
     * Initializes base batch state, counters, remap storage and resource handles.
     */
    MeshBatch();

    /**
     * Address: 0x007E6E10 (FUN_007E6E10, deleting destructor thunk)
     * Address: 0x007E6E30 (FUN_007E6E30, complete dtor)
     *
     * What it does:
     * Releases batch handles/remap buffers and base resource ownership.
     */
    virtual ~MeshBatch();

    /**
     * Address: 0x007E6F60 (FUN_007E6F60, Moho::MeshBatch::Initialize)
     *
     * What it does:
     * Seeds per-batch metadata from mesh/resource input and prepares remap state.
     */
    virtual void Initialize(
      const MeshLOD* lod,
      bool remapToReferenceResource,
      boost::shared_ptr<RScmResource> referenceResource,
      boost::shared_ptr<RScmResource> currentResource
    );

    /**
     * Address: 0x007E6F40 (FUN_007E6F40, ?GetBoneCount@MeshBatch@Moho@@UBEHXZ)
     */
    [[nodiscard]] virtual std::int32_t GetBoneCount() const;

    /**
     * Address: 0x007E6F50 (FUN_007E6F50, ?GetAttachCount@MeshBatch@Moho@@UBEHXZ)
     */
    [[nodiscard]] virtual std::int32_t GetAttachCount() const;

    /**
     * Address: 0x007E72D0 (FUN_007E72D0,
     * ?Render@MeshBatch@Moho@@UAEXABV?$vector@PAVMeshInstance@Moho@@V?$allocator@PAVMeshInstance@Moho@@@std@@@std@@_N@Z)
     *
     * What it does:
     * Dispatches instance rendering in derived-defined batch slices.
     */
    virtual void Render(const msvc8::vector<MeshInstance*>& meshInstances, bool includeHidden);

  protected:
    // Slots 5-9 in MeshBatch vtable (implemented by concrete batchers).
    virtual void PrepareBatch(std::int32_t instanceCount) = 0;
    virtual void BindBuffers() = 0;
    virtual void EndBatch() = 0;
    virtual void DrawBatch(std::int32_t packedCount) = 0;
    virtual std::int32_t FillBatch(MeshInstance**& current, MeshInstance** end, bool includeHidden) = 0;

  public:
    std::uint8_t mUseBoneRemap; // +0x04
    std::uint8_t pad_05_07[0x03]{};
    boost::shared_ptr<RScmResource> mCurrentResource; // +0x08
    std::int32_t mVertexCount;                        // +0x10
    std::int32_t mIndexCount;                         // +0x14
    std::int32_t mTriangleCount;                      // +0x18
    std::int32_t mBoneCount;                          // +0x1C
    std::int32_t mAttachCount;                        // +0x20
    std::int32_t mMaxInstancesPerDraw;                // +0x24
    std::int32_t mActiveInstanceBudget;               // +0x28
    msvc8::vector<std::int32_t> mBoneRemapIndices;    // +0x2C
    std::uint8_t mUseSecondaryData;                   // +0x3C
    std::uint8_t pad_3D_3F[0x03]{};
    std::int32_t mParameterAnnotation;                                  // +0x40
    boost::shared_ptr<MeshBatchRenderBinding> mVertexDeclarationHandle; // +0x44
    boost::shared_ptr<MeshBatchRenderBinding> mIndexBindingHandle;      // +0x4C
  };

  static_assert(offsetof(MeshBatch, mUseBoneRemap) == 0x04, "MeshBatch::mUseBoneRemap offset must be 0x04");
  static_assert(offsetof(MeshBatch, mCurrentResource) == 0x08, "MeshBatch::mCurrentResource offset must be 0x08");
  static_assert(offsetof(MeshBatch, mVertexCount) == 0x10, "MeshBatch::mVertexCount offset must be 0x10");
  static_assert(offsetof(MeshBatch, mBoneCount) == 0x1C, "MeshBatch::mBoneCount offset must be 0x1C");
  static_assert(offsetof(MeshBatch, mAttachCount) == 0x20, "MeshBatch::mAttachCount offset must be 0x20");
  static_assert(offsetof(MeshBatch, mBoneRemapIndices) == 0x2C, "MeshBatch::mBoneRemapIndices offset must be 0x2C");
  static_assert(
    offsetof(MeshBatch, mParameterAnnotation) == 0x40, "MeshBatch::mParameterAnnotation offset must be 0x40"
  );
  static_assert(
    offsetof(MeshBatch, mVertexDeclarationHandle) == 0x44, "MeshBatch::mVertexDeclarationHandle offset must be 0x44"
  );
  static_assert(offsetof(MeshBatch, mIndexBindingHandle) == 0x4C, "MeshBatch::mIndexBindingHandle offset must be 0x4C");
  static_assert(sizeof(MeshBatch) == 0x54, "MeshBatch size must be 0x54");
} // namespace moho
