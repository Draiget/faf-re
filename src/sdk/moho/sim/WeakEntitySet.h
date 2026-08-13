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
} // namespace moho
