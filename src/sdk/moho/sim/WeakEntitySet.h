#pragma once

#include <cstddef>
#include <cstdint>
#include <new>

namespace moho
{
  class UserEntity;

  /**
   * One intrusive weak reference to a `UserEntity`, as stored inside a
   * weak-set tree node.
   *
   * Layout evidence: the weak-node teardown helper (FUN_008B38C0) walks
   * 8-byte records, follows `+0x04` to the next node in the owner's chain and
   * splices the record out of the slot that points at it.
   */
  struct SSelectionWeakRefUserEntity
  {
    void* mOwnerLinkSlot;                    // +0x00
    SSelectionWeakRefUserEntity* mNextOwner; // +0x04
  };

  static_assert(sizeof(SSelectionWeakRefUserEntity) == 0x08, "SSelectionWeakRefUserEntity size must be 0x08");
  static_assert(
    offsetof(SSelectionWeakRefUserEntity, mOwnerLinkSlot) == 0x00,
    "SSelectionWeakRefUserEntity::mOwnerLinkSlot offset must be 0x00"
  );
  static_assert(
    offsetof(SSelectionWeakRefUserEntity, mNextOwner) == 0x04,
    "SSelectionWeakRefUserEntity::mNextOwner offset must be 0x04"
  );

  /**
   * One red-black tree node of a weak-entity set.
   *
   * Layout evidence: the shared node allocator (FUN_007B4640 -> FUN_007B4FA0)
   * hands out 28-byte nodes, and every weak-set head initializer writes
   * `_Isnil` at `+0x19`. The 12-byte payload at `+0x0C` is the
   * `{entity-pointer key, weak reference}` pair.
   */
  struct SSelectionNodeUserEntity
  {
    SSelectionNodeUserEntity* mLeft;   // +0x00
    SSelectionNodeUserEntity* mParent; // +0x04
    SSelectionNodeUserEntity* mRight;  // +0x08
    std::uint32_t mKey;                // +0x0C
    SSelectionWeakRefUserEntity mEnt;  // +0x10
    std::uint8_t mColor;               // +0x18
    std::uint8_t mIsSentinel;          // +0x19
    std::uint8_t pad_1A[2];
  };

  static_assert(sizeof(SSelectionNodeUserEntity) == 0x1C, "SSelectionNodeUserEntity size must be 0x1C");
  static_assert(
    offsetof(SSelectionNodeUserEntity, mEnt) == 0x10, "SSelectionNodeUserEntity::mEnt offset must be 0x10"
  );
  static_assert(
    offsetof(SSelectionNodeUserEntity, mIsSentinel) == 0x19,
    "SSelectionNodeUserEntity::mIsSentinel offset must be 0x19"
  );

  /**
   * `WeakSet<UserEntity>` — the shipped 12-byte MSVC8 tree header
   * `{proxy, _Myhead, _Mysize}`.
   *
   * This is the bare set as embedded in `UserArmy` (the idle-engineer and
   * idle-factory registries at +0x1F8 and +0x204, which are 12 bytes apart).
   * `SSelectionSetUserEntity` extends it with the extra selection lane the
   * session's selection sets carry.
   */
  struct WeakEntitySetUserEntity
  {
    void* mAllocProxy;               // +0x00
    SSelectionNodeUserEntity* mHead; // +0x04
    std::uint32_t mSize;             // +0x08
  };

  static_assert(sizeof(WeakEntitySetUserEntity) == 0x0C, "WeakEntitySetUserEntity size must be 0x0C");
  static_assert(
    offsetof(WeakEntitySetUserEntity, mHead) == 0x04, "WeakEntitySetUserEntity::mHead offset must be 0x04"
  );
  static_assert(
    offsetof(WeakEntitySetUserEntity, mSize) == 0x08, "WeakEntitySetUserEntity::mSize offset must be 0x08"
  );

  /**
   * Builds one weak-set head sentinel through the shared 28-byte node
   * allocator (FUN_007B4640), marking it as the sentinel and self-linking all
   * three child pointers, exactly as every weak-set initializer in the binary
   * does.
   *
   * This is the single head-builder for every weak-entity set in the engine —
   * the session selection, the per-army idle registries and every transient
   * local set alike. Do not open-code a second copy of it.
   */
  [[nodiscard]] inline SSelectionNodeUserEntity* AllocateWeakEntitySetHead()
  {
    auto* const head = static_cast<SSelectionNodeUserEntity*>(::operator new(sizeof(SSelectionNodeUserEntity)));
    head->mLeft = head;
    head->mParent = head;
    head->mRight = head;
    head->mKey = 0u;
    head->mEnt.mOwnerLinkSlot = nullptr;
    head->mEnt.mNextOwner = nullptr;
    head->mColor = 1u;
    head->mIsSentinel = 1u;
    head->pad_1A[0] = 0u;
    head->pad_1A[1] = 0u;
    return head;
  }

  /** Brings one weak-entity set up empty, head sentinel included. */
  inline void InitWeakEntitySetHead(WeakEntitySetUserEntity& set)
  {
    set.mAllocProxy = nullptr;
    set.mHead = AllocateWeakEntitySetHead();
    set.mSize = 0u;
  }

  class UserUnit;

  /**
   * `WeakSet<UserUnit>` — the engine's second weak-set instantiation.
   *
   * It is the set type the unit-facing session API hands around:
   * `?GetSelectionUnits@CWldSession@Moho@@QBEXAAV?$WeakSet@VUserUnit@Moho@@@2@@Z`
   * (0x00896000) and `?GetValidAttackingUnits@…` (0x00896090) both take one by
   * reference, `CFormation` embeds one at its own `+0x00` as the drag-formation
   * participant tree, and the command-issue "select unit" ring events carry one
   * at `event+0x08`.
   *
   * Layout evidence, read off the `WeakSet<UserUnit>` emission itself
   * (0x00822270 `Add`, 0x00822420 find-or-insert, 0x00822670 insert,
   * 0x008229E0 node alloc, 0x00822AB0 node init):
   *   - the header is the same 12-byte MSVC8 tree header: `sub_822420` loads
   *     the head from `[set+4]` (0x0082242A) and `sub_822670` compares the
   *     live-node count at `[set+8]` against `0x15555554` (0x00822688);
   *   - the nodes are the same 0x1C shape: `sub_822420` descends `mLeft` at
   *     `[n]` (0x00822450) / `mRight` at `[n+8]` (0x00822454), compares keys at
   *     `[n+0xC]` (0x00822440) and tests the sentinel flag at `[n+0x19]`
   *     (0x00822430), while `sub_822AB0` seeds the weak-owner pair at `+0x10`
   *     (0x00822ACA) and clears `mColor`/`mIsSentinel` at `+0x18`/`+0x19`
   *     (0x00822ADA / 0x00822ADE);
   *   - the nodes come out of the very same shared 28-byte node allocator
   *     `sub_7B4FA0` (called at 0x008229E6) that the `WeakSet<UserEntity>`
   *     emission uses;
   *   - the key is the raw element pointer stored verbatim (0x00822294), and
   *     the weak-owner chain is reached through the identical `+ 8`
   *     `WeakObject` sub-object adjust (0x0082229A) that
   *     `WeakSet<UserEntity>::Add` uses at 0x007AE1DA.
   *
   * The two instantiations are therefore byte-identical, as they must be:
   * `UserUnit` reaches `UserEntity` through a single non-virtual base at
   * offset zero, so the stored pointer, its key encoding and its `WeakObject`
   * sub-object are all the same bytes at the same address. This is modelled as
   * a distinct C++ type layered over the shared header and node definitions
   * rather than as a second copy of the layout, so the two emissions cannot
   * drift apart.
   */
  struct WeakUnitSetUserUnit : WeakEntitySetUserEntity
  {
    /** One `{owning set, tree node}` iterator pair. */
    struct Index
    {
      WeakUnitSetUserUnit* mOwnerSet;  // +0x00
      SSelectionNodeUserEntity* mNode; // +0x04
    };

    /**
     * The `std::pair<iterator, bool>` `Add` returns through its hidden sret
     * pointer: `{set, node}` at `+0x00`/`+0x04` and the inserted flag at
     * `+0x08` (0x00822306..0x0082230C).
     */
    struct AddResult : Index
    {
      std::uint8_t mWasInserted;        // +0x08
      std::uint8_t mReserved09_0B[3]{}; // +0x09
    };

    /**
     * Address: 0x00822270 (FUN_00822270, sub_822270)
     *
     * IDA signature:
     * Moho::WeakSet_UserUnit_FindResBool *__userpurge sub_822270@<eax>(
     *     Moho::WeakSet_UserUnit_FindResBool *result@<esi>,
     *     Moho::WeakSet_UserUnit *set,
     *     Moho::UserUnit *unit);
     *
     * What it does:
     * Inserts one unit key into the weak set and returns `{iterator, inserted}`.
     * The map insert is bracketed by an intrusive weak guard: a stack
     * `WeakPtr<UserUnit>` is linked into the unit's weak-owner use-list before
     * the insert (0x008222A9-0x008222B3) and spliced back out afterwards by
     * walking the chain until the slot pointing at it is found
     * (0x008222DF-0x008222F8), so a unit destroyed while the tree is being
     * rebalanced tombstones this reference instead of leaving it dangling. The
     * splice also runs on the throwing path, through the EH funclet at
     * 0x00B94260.
     *
     * Defined in CWldSession.cpp, next to the rest of this instantiation's
     * red-black tree lanes.
     */
    [[nodiscard]] static AddResult* Add(AddResult* outResult, WeakUnitSetUserUnit* set, UserUnit* unit);
  };

  static_assert(sizeof(WeakUnitSetUserUnit) == 0x0C, "WeakUnitSetUserUnit size must be 0x0C");
  static_assert(offsetof(WeakUnitSetUserUnit, mHead) == 0x04, "WeakUnitSetUserUnit::mHead offset must be 0x04");
  static_assert(offsetof(WeakUnitSetUserUnit, mSize) == 0x08, "WeakUnitSetUserUnit::mSize offset must be 0x08");
  static_assert(sizeof(WeakUnitSetUserUnit::Index) == 0x08, "WeakUnitSetUserUnit::Index size must be 0x08");
  static_assert(
    offsetof(WeakUnitSetUserUnit::AddResult, mWasInserted) == 0x08,
    "WeakUnitSetUserUnit::AddResult::mWasInserted offset must be 0x08"
  );
  static_assert(sizeof(WeakUnitSetUserUnit::AddResult) == 0x0C, "WeakUnitSetUserUnit::AddResult size must be 0x0C");
} // namespace moho
