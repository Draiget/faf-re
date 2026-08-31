#include "MeshBatchKey.h"

namespace moho
{
  /**
   * Address: 0x007DB060 (FUN_007DB060)
   *
   * What it does:
   * Publishes the mesh-batch key vtable pointer and leaves the payload lanes
   * untouched - the shipped body is a two-instruction
   * `mov dword ptr [ecx], offset ??_7MeshBatchKey@Moho@@6B@ / retn`.
   */
  MeshBatchKey::MeshBatchKey() = default;

  /**
   * Address: 0x007DB0B0 (FUN_007DB0B0)
   *
   * What it does:
   * Releases one mesh-batch key object when called as deleting destructor.
   *
   * The trivial destructor body is ICF-folded onto the constructor at
   * 0x007DB060: the unwind funclets of both `std::pair` constructors
   * (0x00B9DDF3 and 0x00BA35D3) reach the key destructor through
   * `jmp sub_7DB060`, because a vptr store followed by `retn` is byte-identical
   * for the two.
   */
  MeshBatchKey::~MeshBatchKey() = default;

  /**
   * Address: 0x007E35B0 (FUN_007E35B0)
   *
   * IDA signature:
   * char __usercall less@<al>(const MeshBatchKey *lhs@<esi>, const MeshBatchKey *rhs@<edx>);
   *
   * What it does:
   * Strict weak order over mesh-batch keys: sort key first, then the
   * static-pose flag (unset orders before set), then the LOD-key lane as an
   * unsigned 32-bit value.
   *
   * Branch-for-branch against the shipped body:
   *   0x007E35BA  `ucomiss xmm0,xmm1` + `test ah,44h` / `jp 0x007E35E2`
   *               - unequal (or unordered) sort keys leave through
   *                 `comiss xmm1,xmm0 / jbe -> false`, i.e. `lhs < rhs`;
   *   0x007E35C9  `cmp al,cl` on the static-pose bytes; when they differ,
   *               0x007E35D7 returns false for a set `lhs` byte and true for a
   *               set `rhs` byte - which is exactly `lhs.mIsStaticPose == 0`;
   *   0x007E35D3  `setb` on the LOD-key lanes - an **unsigned** compare. That
   *               lane carries a collection-buffer address, so values above
   *               0x7FFFFFFF are reachable and the unsigned form matters. The
   *               two inlined copies of this comparator agree (`setb` at
   *               0x007E40F2 in `_Lbound` and at 0x007E2CB7 in `operator[]`).
   *
   * Called from the hinted insert at 0x007E3340 (six code xrefs, one per
   * comparison branch); `_Lbound` and `operator[]` inline it instead.
   */
  bool MeshBatchKeyLess::operator()(const MeshBatchKey& lhs, const MeshBatchKey& rhs) const noexcept
  {
    if (lhs.mSortKey != rhs.mSortKey) {
      return lhs.mSortKey < rhs.mSortKey;
    }

    if (lhs.mIsStaticPose != rhs.mIsStaticPose) {
      return lhs.mIsStaticPose == 0U;
    }

    return static_cast<std::uint32_t>(lhs.mLodIndexKey) < static_cast<std::uint32_t>(rhs.mLodIndexKey);
  }

  /**
   * Address: 0x007E2C60 (FUN_007E2C60, `std::map<MeshBatchKey, vector<MeshInstance*>>::operator[]`)
   *
   * IDA signature:
   * mapped_type *__thiscall operator[](const key_type *key@<ecx>, _Tree *this);
   *
   * What it does:
   * Returns the instance vector bucketed under `key`, inserting an empty one at
   * the located gap when the key is absent.
   *
   * The body lives on `msvc8::map::operator[]` (Map.h), which is the single
   * owner of this address; this is the named call shape for the one engine call
   * site (`MeshRenderer::CollectVisibleInstances`). Routing through
   * `operator[]` is what restores the shipped insert hint: 0x007E2C84 calls
   * `_Lbound` and 0x007E2CDE pushes that same cursor back as the hint argument
   * of the hinted insert at 0x007E3340, so the gap the descent already found is
   * filled without a second descent. The previous hand-rolled body here
   * computed the lower bound and then discarded it, taking the unhinted
   * `insert` path instead.
   */
  MeshBatchInstanceVector* MeshBatchBucketTreeFindOrCreateInstances(const MeshBatchKey& key, MeshBatchBucketTree& tree)
  {
    return &tree[key];
  }
} // namespace moho
