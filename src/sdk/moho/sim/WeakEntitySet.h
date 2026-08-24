#pragma once

#include <cstddef>
#include <cstdint>
#include <new>

#include "legacy/containers/Vector.h"

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

    /**
     * Trivial/zero-initializing by design: every existing embedding of this
     * type (`CWldSession::mSelection`, `UserArmy::mEngineers/mFactories`,
     * `CFormation::mParticipants`, the transient `ScopedLocalSelectionSet`
     * guards) constructs a blank `{nullptr,nullptr,0}` header and brings it up
     * through the explicit `InitWeakEntitySetHead`/`InitializeLocalSelectionSet`
     * family rather than through the constructor. Do not change this to an
     * allocating default constructor - `CWldSession`'s own constructor
     * (CWldSession.cpp) writes `mSelection.mHead = nullptr` immediately after
     * default-constructing it, so an allocating default ctor would leak the
     * head this ctor built on every session construction.
     */
    WeakEntitySetUserEntity() = default;

    /**
     * Address: 0x00868DB0 (FUN_00868DB0, `msvc8::vector<WeakSet<UserEntity>>::
     * uninit_fill_n`'s per-element copy) + 0x00822210 (FUN_00822210,
     * `CopySelectionSetFromOther`'s underlying single-element clone step)
     *
     * What it does:
     * Deep-clones one weak-entity-set tree into a fresh head/sentinel, walking
     * the source's live (tombstone-pruned) entries through `find`/`Iterator_inc`
     * and re-inserting each one via `InsertSelectionEntity` - the same
     * range-clone shape `CopySelectionSetFromOther` already uses for
     * `SSelectionSetUserEntity`, generalized to the bare 12-byte header so the
     * vector-of-sets growth lane below can copy-construct it. Defined in
     * CWldSession.cpp alongside the rest of this header's out-of-line members.
     */
    WeakEntitySetUserEntity(const WeakEntitySetUserEntity& other);

    /**
     * Address: 0x00868E50 (FUN_00868E50, `sub_868E50`) - same body as
     * `ReleaseSelectionWeakSetStorageCompat`'s null-head-checked branch,
     * generalized onto the owning type itself: erases every node and frees the
     * head sentinel through `ReleaseStorage()`.
     */
    ~WeakEntitySetUserEntity();

    /**
     * One `{owning set, current node}` iteration cursor - the shape every
     * weak-set walk in the engine keeps on the stack while it scans.
     *
     * It lives on the shared header rather than on either instantiation
     * because the tree body is the same body for both: `First` and `Next`
     * below are single addresses that the linker folded across the
     * `WeakSet<UserEntity>` and `WeakSet<UserUnit>` emissions, so a cursor
     * built by one is consumed by the other.
     */
    struct FindResult
    {
      WeakEntitySetUserEntity* mSet;  // +0x00
      SSelectionNodeUserEntity* mRes; // +0x04
    };

    /**
     * Address: 0x0066A060 (FUN_0066A060, Moho::WeakSet_UserEntity::First)
     * Address: 0x007B25F0 (FUN_007B25F0, sub_7B25F0)
     *
     * IDA signature:
     * Moho::WeakSet_UserEntity_FindRes *__usercall sub_7B25F0@<eax>(
     *     Moho::WeakSet_UserEntity_FindRes *result@<ebx>,
     *     Moho::WeakSet_UserEntity *set@<eax>);
     *
     * What it does:
     * Starts weak-set iteration at the left-most tree node and returns one
     * `{set,node}` cursor pair after tombstone filtering through `find`.
     *
     * 0x007B25F0 is the `WeakSet<UserUnit>` emission of this same body -
     * byte-identical to 0x0066A060 (`mHead` at `[set+4]`, `mLeft` at `[head]`,
     * the same `PruneTombstonesAndFindLive` tail, the same `{set,node}` store).
     * `CUIWorldView::HandleEvent` reaches it at 0x0087069F over the transient
     * selection-unit set and at 0x00871065 over a command helper's
     * under-cursor set.
     */
    [[nodiscard]] FindResult* First(FindResult* outResult);

    /**
     * Address: 0x007F0490 (FUN_007F0490, sub_7F0490)
     *
     * IDA signature:
     * Moho::WeakSet_UserEntity_FindRes *__stdcall sub_7F0490(
     *     Moho::WeakSet_UserEntity_FindRes *cursor);
     *
     * What it does:
     * Advances one weak-set iteration cursor by a single *live* node: runs the
     * red-black successor step (`Iterator_inc`) on `cursor->mRes`, then filters
     * tombstoned entries out of the way with `find` against the cursor's own
     * set, writing the resulting node back into `cursor->mRes` and returning
     * the cursor.
     *
     * The body never touches `this` - the cursor carries its own set pointer -
     * which is why it is `static` here and `__stdcall` in the image.
     * `CUIWorldView::HandleEvent` calls it at 0x008706D8 (selection scan for a
     * command-graph hover hint) and at 0x0087108C (the shift+ctrl right-release
     * "remove this command from every unit under the cursor" loop).
     */
    [[nodiscard]] static FindResult* Next(FindResult* cursor);

    /**
     * Address: 0x007AF740 (FUN_007AF740, sub_7AF740)
     *
     * What it does:
     * Erases one half-open weak-set node range `[first,last)`. When the range
     * is the full tree, it tears down the entire subtree in one pass and resets
     * head links/size to the empty-state sentinel shape.
     *
     * Declared on the bare 12-byte header rather than on
     * `SSelectionSetUserEntity`, because that is the object the binary hands
     * these lanes: the body reads only `mHead` and writes only `mSize`, and the
     * erase paths are reached with the per-army idle registries -- which are
     * bare sets embedded in `UserArmy` at +0x1F8 and +0x204 -- exactly as often
     * as with the session selection.
     */
    [[nodiscard]] SSelectionNodeUserEntity**
      EraseRange(SSelectionNodeUserEntity** outNode, SSelectionNodeUserEntity* first, SSelectionNodeUserEntity* last);

    /**
     * Address: 0x007B0870 (FUN_007B0870, sub_7B0870)
     *
     * What it does:
     * Recursively destroys one weak-set subtree and unlinks each node from its
     * user-entity weak-owner intrusive lane before delete.
     *
     * Sits on the bare header for the same reason `EraseRange` does -- it is
     * reached from the erase paths of every weak-entity set, and it reads no
     * member state at all, only the nodes it is handed.
     */
    void DestroySubtree(SSelectionNodeUserEntity* node);

    /** One `{owning set, tree node}` iterator pair, mirroring `WeakUnitSetUserUnit::Index`. */
    struct Index
    {
      WeakEntitySetUserEntity* mOwnerSet; // +0x00
      SSelectionNodeUserEntity* mNode;    // +0x04
    };

    /** `std::pair<iterator, bool>` shape `Add` returns, mirroring `WeakUnitSetUserUnit::AddResult`. */
    struct AddResult : Index
    {
      std::uint8_t mWasInserted;        // +0x08
      std::uint8_t mReserved09_0B[3]{}; // +0x09
    };

    /**
     * Address: 0x00867890/0x00867B90/0x00868040/0x00868580/0x00868DB0 wire this
     * class into the `msvc8::vector<WeakSet<UserEntity>>::resize` growth lane
     * below via the copy constructor; this `Add` is the bare-header sibling of
     * `SSelectionSetUserEntity::Add` (0x007AE1B0-family), generalized the same
     * way `find`/`Iterator_inc`/`EraseRange` already are on this header because
     * `InsertSelectionEntity`'s body only ever touches `mHead`/`mSize`.
     *
     * What it does:
     * Inserts one user-entity pointer key into the weak-set tree and returns
     * `{ownerSet,node,inserted}` in `outResult`.
     */
    [[nodiscard]] static AddResult* Add(AddResult* outResult, WeakEntitySetUserEntity* set, UserEntity* entity);

    /**
     * Address: 0x0066A090-family (`IsEmptyAfterPrune`, generalized onto the
     * bare header the same way `EraseRange`/`ReleaseStorage` are, since the
     * body only reads `mHead`).
     *
     * What it does:
     * Returns true when tombstone pruning from the left-most node reaches the
     * head sentinel immediately (no live weak-set entries remain).
     */
    [[nodiscard]] bool IsEmptyAfterPrune();

    /**
     * Address: 0x007ABDE0 (FUN_007ABDE0, sub_7ABDE0)
     * Address: 0x007ABE10 (FUN_007ABE10, sub_7ABE10)
     *
     * What it does:
     * Clears all weak-set nodes, destroys the tree head sentinel, and resets
     * storage links/counters for this set. Bare-header sibling of
     * `SSelectionSetUserEntity::ReleaseStorage`; the destructor above forwards
     * to this.
     */
    std::int32_t ReleaseStorage();

    /**
     * Address: 0x007B4640 (FUN_007B4640, `_Tree::_Buynode()`)
     *
     * What it does:
     * Buys one raw tree node through the shared checked 28-byte allocator
     * (0x007B4FA0) and brings it up in VC8's neutral state: all three links
     * null, colour black, not a sentinel. The null tests the binary emits
     * after each `lea` are compiler artifacts on a pointer it has just
     * derived, and can never fire.
     *
     * Callers finish the node. `_Init` self-links it and flips `mIsSentinel`
     * to make a head; the insert paths seat the links on the head and colour
     * it red instead.
     */
    [[nodiscard]] static SSelectionNodeUserEntity* BuyNode();
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
    // VC8's `_Tree::_Init`: buy a neutral node, then self-link it and mark it
    // the sentinel. The buy half is out-of-line in the binary at 0x007B4640,
    // which already leaves the colour black and the pad bytes zeroed.
    SSelectionNodeUserEntity* const head = WeakEntitySetUserEntity::BuyNode();
    head->mLeft = head;
    head->mParent = head;
    head->mRight = head;
    head->mKey = 0u;
    head->mEnt.mOwnerLinkSlot = nullptr;
    head->mEnt.mNextOwner = nullptr;
    head->mIsSentinel = 1u;
    return head;
  }

  /**
   * Address: 0x007B3C60 (FUN_007B3C60, sub_7B3C60) -- a second, per-call-site
   * binary emission of this function fused with the assignment into the
   * owning container: `head = BuyNode(); this->mHead = head; head->
   * mIsSentinel = 1; head->mParent = head; head->mLeft = head; head->mRight
   * = head; this->mSize = 0;`. It does not touch `this->mAllocProxy` (left
   * to whatever the caller already set, e.g. a zero-initialized object) and
   * does not zero `head->mKey`/`head->mEnt` the way `InitWeakEntitySetHead`
   * below does -- this call site's node payload is left exactly as
   * `WeakEntitySetUserEntity::BuyNode` returned it (garbage key/owner-link
   * bytes on the header node, which real Dinkumware `_Tree::_Init` never
   * reads back since the header's value slot is never a live element).
   * DB-integrity fix: this token was marked `recovered` with
   * `source_paths=null` and a boilerplate "batch 0x007B**** pass" note
   * that cited nothing; a full `src/sdk` sweep found zero real citations
   * anywhere. The callee (`0x007B4640`) and the shape (buy + flip
   * sentinel + self-link + zero container size) are an unambiguous match
   * for this function's fused `AllocateWeakEntitySetHead` +
   * `set.mHead`/`set.mSize` assignment below; cited here rather than
   * adding a bespoke duplicate free function, matching every other
   * per-call-site-emission citation in this file.
   */

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
