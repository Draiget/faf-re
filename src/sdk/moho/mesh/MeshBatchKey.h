#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/Map.h"
#include "legacy/containers/RbTree.h"
#include "legacy/containers/Vector.h"

namespace moho
{
  class MeshInstance;
  class MeshLOD;

  class MeshBatchKey
  {
  public:
    /**
     * Address: 0x007DB060 (FUN_007DB060)
     *
     * IDA signature:
     * void __thiscall MeshBatchKey(MeshBatchKey *this@<ecx>);
     *
     * What it does:
     * Publishes the RTTI/vtable identity for one mesh-batch key object and
     * leaves the three payload lanes uninitialised, exactly as the shipped
     * body does (`mov [ecx], offset ??_7MeshBatchKey@Moho@@6B@ / retn`).
     */
    MeshBatchKey();

    MeshBatchKey(const MeshBatchKey&) = default;
    MeshBatchKey& operator=(const MeshBatchKey&) = default;

    /**
     * Address: 0x007DB0B0 (FUN_007DB0B0)
     *
     * What it does:
     * Releases one mesh-batch key object when called as deleting destructor.
     */
    virtual ~MeshBatchKey();

  public:
    std::uint8_t mIsStaticPose; // +0x04
    std::uint8_t pad_05_07[0x03];

    /**
     * The LOD this bucket batches (`MeshBatchKey` +0x08).
     *
     * `MeshRenderer::Batch` writes the `Mesh::ComputeLOD` result here
     * (0x007DFBED `mov [esp+20h], eax` into the slot the key load at
     * 0x007DFCDC reads back), and every render pass dereferences it for the
     * bucket's material and hardware batch. IDA's frame-base tracking drifts
     * across this function - it applies the demangled `ABEXXZ` (`retn 0`)
     * signature to `MeshInstance::UpdateInterpolatedFields`, which actually
     * ends `retn 4` (0x007DEF5C), so IDA counts the two `push edi` argument
     * slots as never reclaimed and splits this one slot into `var_1D0` and
     * `var_1D4`. The loop is esp-balanced (epilogue `add esp, 1E0h` after
     * three pops returns to the E-0x1EC the loop starts at), so both
     * `[esp+20h]` references name the same slot.
     */
    MeshLOD* mLod;  // +0x08
    float mSortKey; // +0x0C
  };

  /**
   * Address: 0x007E35B0 (FUN_007E35B0)
   *
   * IDA signature:
   * char __usercall less@<al>(const MeshBatchKey *lhs@<esi>, const MeshBatchKey *rhs@<edx>);
   *
   * What it does:
   * `std::less<MeshBatchKey>` - the key comparator the batch-bucket map is
   * instantiated with. Orders by `mSortKey`, then by the static-pose flag
   * (unset before set), then by the LOD-key lane.
   *
   * Two details are read straight off the shipped body and are load bearing:
   *   - the operand order is `lhs < rhs` with `lhs` in `esi` and `rhs` in
   *     `edx` (0x007E35B0 `movss xmm0,[esi+0Ch]` / `movss xmm1,[edx+0Ch]`,
   *     then `comiss xmm1,xmm0 / jbe -> false` at 0x007E35E2);
   *   - the LOD-key lane is compared **unsigned** (`setb` at 0x007E35D3, and
   *     again in the two inlined copies at 0x007E40F2 and 0x007E2CB7). That
   *     lane carries a pointer value, so the unsigned form is the correct one.
   *
   * The comparator is stateless, which is what keeps the owning map at the
   * shipped 12-byte `{proxy, _Myhead, _Mysize}` footprint through the
   * empty-base optimisation in `msvc8::detail::rb_compare_carrier`.
   */
  struct MeshBatchKeyLess
  {
    [[nodiscard]] bool operator()(const MeshBatchKey& lhs, const MeshBatchKey& rhs) const noexcept;
  };

  /**
   * `std::vector<Moho::MeshInstance*>` - the batch map's mapped type.
   *
   * Confirmed from the demangled `MeshRenderer::RenderCartographic` /
   * `RenderDepth` signatures (Mesh.h), whose map parameter spells the mapped
   * type `std::vector<Moho::MeshInstance*, std::allocator<...>>`, and from the
   * shipped `{proxy, _Myfirst, _Mylast, _Myend}` 0x10-byte footprint that
   * `msvc8::vector` already models. `MeshBatch::Render` consumes exactly this
   * type, so the render loops hand a bucket's mapped value straight to it with
   * no cast.
   */
  using MeshBatchInstanceVector = msvc8::vector<MeshInstance*>;

  /**
   * `std::map<Moho::MeshBatchKey, std::vector<Moho::MeshInstance*>>`.
   *
   * All red-black mechanics - `_Lbound` (0x007E40C0), `_Buynode` (0x007E4BC0),
   * `_Insert` (0x007E3F10), `_Lrotate` (0x007E4AC0), `_Rrotate` (0x007E4B30),
   * `_Inc` (0x007E42F0), `_Dec` (0x007E4FA0), `insert` (0x007E3CF0),
   * hinted `insert` (0x007E3340) and `operator[]` (0x007E2C60) - live in
   * `msvc8::detail::rb_tree` / `msvc8::map`, which is the single owner of
   * those addresses. This header no longer re-implements any of them.
   */
  using MeshBatchBucketTree = msvc8::map<MeshBatchKey, MeshBatchInstanceVector, MeshBatchKeyLess>;

  /**
   * One stored element: `std::pair<const MeshBatchKey, std::vector<MeshInstance*>>`.
   *
   * Address: 0x007E36C0 (FUN_007E36C0, pair(const MeshBatchKey&, const mapped_type&))
   * Address: 0x007E5070 (FUN_007E5070, pair(const pair&))
   *
   * Both are compiler-generated `std::pair` constructors, so they have no
   * hand-written body; they are emitted from the two call sites that build a
   * `value_type`:
   *   - 0x007E36C0 (`retn 0Ch`, three stack args: dest, key, mapped) is the
   *     `value_type(k, mapped_type())` temporary inside `map::operator[]` -
   *     `push &temp_vector / push key / push &dest / call sub_7E36C0` at
   *     0x007E2CCE..0x007E2CD9;
   *   - 0x007E5070 (`retn 8`, two stack args: dest, source pair) is the
   *     placement copy `_Buynode` performs into the fresh node's payload -
   *     `lea ecx,[esi+0Ch] / push ecx / call sub_7E5070` at
   *     0x007E4C15..0x007E4C1C.
   * Both copy the key inline (vptr + the three lanes) and then call the
   * `std::vector<MeshInstance*>` copy constructor at 0x007E41A0 on the
   * payload at +0x10, which is what pins `first` at +0x00 and `second` at
   * +0x10 in the 0x20-byte value type.
   */
  using MeshBatchBucket = MeshBatchBucketTree::value_type;

  /**
   * One MSVC8 `_Tree::_Node` for the batch-bucket map.
   *
   * Confirmed field-for-field against `_Buynode` at 0x007E4BC0:
   * `[esi] = arg_0` (left), `[esi+4] = arg_4` (parent), `[esi+8] = arg_8`
   * (right), `lea ecx,[esi+0Ch]` for the payload copy, `[esi+2Ch] = 0`
   * (`_Color` = red) and `[esi+2Dh] = 0` (`_Isnil`); the node allocator at
   * 0x007E5740 sizes each node `ecx * 0x30` (`lea edx,[ecx+ecx*2] / shl edx,4`)
   * and rejects counts at or above `0xFFFFFFFF / 0x30`.
   *
   * Retained as a named alias so those size/offset guarantees stay asserted
   * here; recovered behaviour code reaches elements through the container's
   * iterators, never through this type.
   */
  using MeshBatchBucketNode = msvc8::detail::rb_node<MeshBatchBucket>;

  /**
   * Address: 0x007E2C60 (FUN_007E2C60, `std::map<MeshBatchKey, vector<MeshInstance*>>::operator[]`)
   *
   * What it does:
   * Returns the instance vector bucketed under `key`, default-constructing an
   * empty one at the located gap when the key is absent. The body is
   * `msvc8::map::operator[]` (Map.h), which owns the address: it takes the
   * `lower_bound` cursor (`call sub_7E40C0` at 0x007E2C84) and feeds it back
   * as the insert hint (`push edi` at 0x007E2CDE, then
   * `call sub_7E3340`), so the located gap is filled without a second descent.
   *
   * This wrapper exists only to keep the call shape the binary uses - key in
   * `ecx`, tree on the stack - readable at the one engine call site in
   * `MeshRenderer::CollectVisibleInstances`.
   */
  [[nodiscard]] MeshBatchInstanceVector*
  MeshBatchBucketTreeFindOrCreateInstances(const MeshBatchKey& key, MeshBatchBucketTree& tree);

  static_assert(offsetof(MeshBatchKey, mIsStaticPose) == 0x04, "MeshBatchKey::mIsStaticPose offset must be 0x04");
  static_assert(offsetof(MeshBatchKey, mLod) == 0x08, "MeshBatchKey::mLod offset must be 0x08");
  static_assert(offsetof(MeshBatchKey, mSortKey) == 0x0C, "MeshBatchKey::mSortKey offset must be 0x0C");
  static_assert(sizeof(MeshBatchKey) == 0x10, "MeshBatchKey size must be 0x10");

  static_assert(sizeof(MeshBatchInstanceVector) == 0x10, "MeshBatchInstanceVector size must be 0x10");

  // Payload +0x00/+0x10 and total 0x20: 0x007E36C0/0x007E5070 copy the key
  // lanes at +0x00..+0x0F and call the vector copy ctor on +0x10.
  static_assert(offsetof(MeshBatchBucket, first) == 0x00, "MeshBatchBucket::first offset must be 0x00");
  static_assert(offsetof(MeshBatchBucket, second) == 0x10, "MeshBatchBucket::second offset must be 0x10");
  static_assert(sizeof(MeshBatchBucket) == 0x20, "MeshBatchBucket size must be 0x20");

  // Node lanes, all read directly off _Buynode (0x007E4BC0) and _Lbound
  // (0x007E40C0, which tests `[ecx+2Dh]` for the nil byte).
  static_assert(offsetof(MeshBatchBucketNode, left) == 0x00, "MeshBatchBucketNode::left offset must be 0x00");
  static_assert(offsetof(MeshBatchBucketNode, parent) == 0x04, "MeshBatchBucketNode::parent offset must be 0x04");
  static_assert(offsetof(MeshBatchBucketNode, right) == 0x08, "MeshBatchBucketNode::right offset must be 0x08");
  static_assert(offsetof(MeshBatchBucketNode, value) == 0x0C, "MeshBatchBucketNode::value offset must be 0x0C");
  static_assert(offsetof(MeshBatchBucketNode, color) == 0x2C, "MeshBatchBucketNode::color offset must be 0x2C");
  static_assert(offsetof(MeshBatchBucketNode, isNil) == 0x2D, "MeshBatchBucketNode::isNil offset must be 0x2D");
  static_assert(sizeof(MeshBatchBucketNode) == 0x30, "MeshBatchBucketNode size must be 0x30");

  static_assert(sizeof(MeshBatchBucketTree) == 0x0C, "MeshBatchBucketTree size must be 0x0C");
} // namespace moho
