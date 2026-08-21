#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "legacy/containers/Vector.h"

namespace gpg::gal
{
  class VertexBufferD3D9;
  class VertexFormatD3D9;
  class IndexBufferD3D9;
} // namespace gpg::gal

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
     *
     * `reflectedOnly` is the reflection pass: when set, `FillBatch` packs only
     * instances whose `MeshInstance::isReflected` flag is still on.
     */
    virtual void Render(const msvc8::vector<MeshInstance*>& meshInstances, bool reflectedOnly);

  protected:
    // Slots 5-9 in MeshBatch vtable (implemented by concrete batchers).
    virtual void PrepareBatch(std::int32_t instanceCount) = 0;
    virtual void BindBuffers() = 0;
    virtual void EndBatch() = 0;
    virtual void DrawBatch(std::int32_t packedCount) = 0;
    virtual std::int32_t FillBatch(MeshInstance**& current, MeshInstance** end, bool reflectedOnly) = 0;

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

  /**
   * Hardware (GPU-instanced) mesh batch backend.
   *
   * VTABLE: 0x00E3F558 (`??_7HardwareMeshBatch@Moho@@6B@`), byte-verified from
   * bin/2025.7.1/ForgedAlliance.exe. 10 slots; overrides slot 0 (dtor,
   * 0x007E8B70), slot 1 (`Initialize`, 0x007E7540), slot 5 (`PrepareBatch`,
   * 0x007E7D00), slot 6 (`BindBuffers`, 0x007E7E30), slot 7 (`EndBatch`,
   * 0x007E8B60), slot 8 (`DrawBatch`, 0x007E89E0) and slot 9 (`FillBatch`,
   * 0x007E7EA0); inherits slots 2/3/4 (`GetBoneCount`/`GetAttachCount`/
   * `Render`) from `MeshBatch`.
   *
   * Layout (complete-object size 0x68 = base 0x54 + 0x14):
   *   - `+0x44` (base `mVertexDeclarationHandle` slot, reused) holds the
   *     `boost::shared_ptr<gpg::gal::VertexFormatD3D9>` for this batch's
   *     GPU vertex declaration.
   *   - `+0x4C` (base `mIndexBindingHandle` slot, reused) holds the
   *     `boost::shared_ptr<gpg::gal::IndexBufferD3D9>` for the static index
   *     buffer.
   *   - `+0x54` static (all-instances) vertex buffer.
   *   - `+0x5C` dynamic (per-instance) vertex buffer.
   *   - `+0x64` CPU scratch buffer for per-instance vertex staging.
   *
   * Field offsets/types byte-verified from the construction path (`FUN_007E7350`
   * / `FUN_007E7540`) and the batch-draw path (`FUN_007E7D00`).
   */
  class HardwareMeshBatch : public MeshBatch
  {
  public:
    /**
     * Address: 0x007E8B70 (FUN_007E8B70, deleting destructor lane; slot 0 of
     * `??_7HardwareMeshBatch@Moho@@6B@`, VTABLE_CONFIRMED via the vtable's data
     * xref to this address)
     * Address: 0x007E7480 (FUN_007E7480, non-deleting destructor body)
     *
     * What it does:
     * Destroys one `HardwareMeshBatch`: releases this batch's own GPU
     * resources through `ReleaseGpuResources`, then - implicitly, via the
     * per-member and base-class teardown the compiler inserts after this
     * body - the base `MeshBatch` resources (`mCurrentResource`,
     * `mBoneRemapIndices`).
     */
    ~HardwareMeshBatch() override;

    /**
     * Address: 0x007E7540 (FUN_007E7540, slot 1 override,
     * ?Initialize@HardwareMeshBatch@Moho@@ (IDA: Func1))
     *
     * IDA signature:
     * int __thiscall Moho::HardwareMeshBatch::Func1(HardwareMeshBatch* this,
     *   int lod, int remap, boost::shared_ptr<RScmResource> referenceResource,
     *   boost::shared_ptr<RScmResource> currentResource);
     *
     * What it does:
     * Runs base `MeshBatch::Initialize` to seed counters from the mesh
     * resource, then builds the GPU static index buffer (verbatim copy of the
     * SCM 16-bit index data), the GPU vertex declaration, and the static
     * vertex buffer whose contents are streamed one vertex at a time through
     * the active hardware vertex formatter.
     */
    void Initialize(
      const MeshLOD* lod,
      bool remapToReferenceResource,
      boost::shared_ptr<RScmResource> referenceResource,
      boost::shared_ptr<RScmResource> currentResource
    ) override;

    // --- Concrete backend slot overrides (bodies out of this pass's scope) ---
    /** Address: 0x007E7D00 (FUN_007E7D00, slot 5). */
    void PrepareBatch(std::int32_t instanceCount) override;
    /** Address: 0x007E7E30 (FUN_007E7E30, slot 6). */
    void BindBuffers() override;
    /** Address: 0x007E8B60 (FUN_007E8B60, slot 7). */
    void EndBatch() override;
    /** Address: 0x007E89E0 (FUN_007E89E0, slot 8). */
    void DrawBatch(std::int32_t packedCount) override;
    /**
     * Address: 0x007E7EA0 (FUN_007E7EA0, slot 9).
     *
     * Packs one draw call's worth of per-instance vertex records out of
     * `[current, end)`, fills the global GPU skinning palettes for skinned
     * batches, uploads the run into the dynamic vertex buffer and returns how
     * many instances it packed. See the definition for the full behaviour.
     */
    std::int32_t FillBatch(MeshInstance**& current, MeshInstance** end, bool reflectedOnly) override;

    /**
     * Typed view of the base `mVertexDeclarationHandle` slot (+0x44).
     *
     * The binary reuses the base batch-render-binding handle slot to store this
     * batch's `boost::shared_ptr<VertexFormatD3D9>`. `boost::shared_ptr<T>` has a
     * T-independent layout, so this is a typed reinterpretation of the same
     * slot, not raw offset arithmetic.
     */
    [[nodiscard]] boost::shared_ptr<gpg::gal::VertexFormatD3D9>& VertexFormatHandle() noexcept
    {
      return reinterpret_cast<boost::shared_ptr<gpg::gal::VertexFormatD3D9>&>(mVertexDeclarationHandle);
    }

    /**
     * Typed view of the base `mIndexBindingHandle` slot (+0x4C): the batch's
     * `boost::shared_ptr<IndexBufferD3D9>` static index buffer.
     */
    [[nodiscard]] boost::shared_ptr<gpg::gal::IndexBufferD3D9>& IndexBufferHandle() noexcept
    {
      return reinterpret_cast<boost::shared_ptr<gpg::gal::IndexBufferD3D9>&>(mIndexBindingHandle);
    }

  private:
    /**
     * Address: 0x007E7BE0 (FUN_007E7BE0)
     *
     * IDA signature:
     * void __usercall sub_7E7BE0(HardwareMeshBatch* this@<esi>);
     *
     * What it does:
     * Releases every GPU-resource handle this batch owns - the base batch's
     * index buffer and vertex declaration handles, and this batch's own
     * static and dynamic vertex buffers - then frees the CPU scratch mirror
     * used to stage per-instance vertex data. Also resets the base
     * `MeshBatch` counters this batch derives during `Initialize`
     * (`mVertexCount`, `mIndexCount`, `mBoneCount`, `mAttachCount`,
     * `mMaxInstancesPerDraw`, `mActiveInstanceBudget`) back to zero;
     * `mTriangleCount` is left untouched, matching the binary exactly. Called
     * once, from the destructor.
     */
    void ReleaseGpuResources() noexcept;

  public:
    // +0x54 static (all-instances) GPU vertex buffer built in Initialize.
    boost::shared_ptr<gpg::gal::VertexBufferD3D9> mStaticVertexBuffer;
    // +0x5C dynamic (per-instance) GPU vertex buffer grown by PrepareBatch.
    boost::shared_ptr<gpg::gal::VertexBufferD3D9> mDynamicVertexBuffer;
    // +0x64 CPU scratch buffer for per-instance vertex staging.
    void* mScratchVertexData = nullptr;
  };

  static_assert(offsetof(HardwareMeshBatch, mStaticVertexBuffer) == 0x54, "HardwareMeshBatch::mStaticVertexBuffer offset must be 0x54");
  static_assert(offsetof(HardwareMeshBatch, mDynamicVertexBuffer) == 0x5C, "HardwareMeshBatch::mDynamicVertexBuffer offset must be 0x5C");
  static_assert(offsetof(HardwareMeshBatch, mScratchVertexData) == 0x64, "HardwareMeshBatch::mScratchVertexData offset must be 0x64");
  static_assert(sizeof(HardwareMeshBatch) == 0x68, "HardwareMeshBatch size must be 0x68");

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
   * Placement-initializes one freshly allocated `HardwareMeshBatch`: runs the
   * base `MeshBatch` constructor, installs the `HardwareMeshBatch` vtable,
   * zero-clears the derived buffer/scratch lanes, then drives
   * `HardwareMeshBatch::Initialize` to build the GPU buffers. Returns `batch`.
   */
  HardwareMeshBatch* HardwareMeshBatchInit(
    HardwareMeshBatch* batch,
    const MeshLOD* lod,
    bool remapToReferenceResource,
    boost::shared_ptr<RScmResource> referenceResource,
    boost::shared_ptr<RScmResource> currentResource
  );
} // namespace moho
