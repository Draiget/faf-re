#pragma once

#include <cstddef>
#include <cstdint>
#include <new>

#include "legacy/containers/Vector.h"

// Windows GDI headers define `GetObject` as an ANSI/Unicode macro alias.
// Undefine it so intrusive weak-pointer accessors keep their intended name.
#ifdef GetObject
#undef GetObject
#endif

namespace gpg
{
  class RType;
}

namespace moho
{
  class Unit;
  class IUnit;
  class UnitWeapon;
  class UserEntity;
  class UserUnit;

  template <class T>
  struct WeakPtrOwnerLinkOffset
  {
    static constexpr std::uintptr_t value = sizeof(void*);
  };

#ifndef MOHO_WEAKPTR_OWNER_LINK_OFFSET_UNITWEAPON_DEFINED
#define MOHO_WEAKPTR_OWNER_LINK_OFFSET_UNITWEAPON_DEFINED
  template <>
  struct WeakPtrOwnerLinkOffset<UnitWeapon>
  {
    static constexpr std::uintptr_t value = 0x14;
  };
#endif

  /**
   * `UserEntity`'s weak-link head is its `WeakObject` base's `weakLinkHead_`,
   * which sits at +0x08 because the class carries a vtable at +0x00 and the
   * IUnit-chain head at +0x04. Every avatar/creator lane in the binary decodes
   * these nodes with a literal `lea reg, [slot-8]` (0x008B2340 in the army
   * avatar scan, 0x008C0870 in `UserUnit::UpdateUnitData`).
   *
   * `UserUnit` derives from `UserEntity` at offset zero, so it shares the
   * offset.
   */
  template <>
  struct WeakPtrOwnerLinkOffset<UserEntity>
  {
    static constexpr std::uintptr_t value = 0x08;
  };

  template <>
  struct WeakPtrOwnerLinkOffset<UserUnit>
  {
    static constexpr std::uintptr_t value = 0x08;
  };

  /**
   * Recovered intrusive weak-pointer node layout used by Moho reflection helpers.
   *
   * Binary evidence:
   * - Weak-pointer set path (`sub_1012F320` / FA `sub_541320`) updates two dwords:
   *   [0] owner link slot pointer, [1] next node pointer in owner chain.
   */
  template <class T>
  struct WeakPtr
  {
    /**
     * Address: 0x006EC5B0 (FUN_006EC5B0, the `WeakPtr<CUnitCommand>`-typed
     * sibling emission of this same body -- `msvc8::vector<WeakPtr<CUnitCommand>>`'s
     * `_Ufill`, reached from its `_Insert_n` 0x006EA440 and `push_back`
     * 0x006E9680, both cited on Vector.h)
     * Address: 0x007A5FE0 (FUN_007A5FE0, ICF twin, identical `function_sha256`
     * to FUN_006EC5B0. Reached from `GrowAndInsertInputCaptureWeakRef`
     * (`FUN_007A5A70`, UiRuntimeTypes.cpp): the reallocation branch fill-
     * constructs the staged insert value into the freshly copied buffer's
     * gap, and the in-place append-at-end branch fill-constructs it directly
     * at the old `_Mylast`.)
     * Address: 0x008B39A0 (FUN_008B39A0, `WeakPtr<UserUnit>`-typed sibling
     * emission -- `.c` decompile matches this body exactly, re-reading the
     * fixed `source.ownerLinkSlot` storage fresh every iteration and never
     * advancing the source pointer. Moved off the anonymous-namespace
     * `CopyIntrusiveLinkRangeFromOwnerSlotLane` free function in
     * `moho/containers/LegacyContainerFillLanes.cpp`, a RULE ONE reach-in
     * duplicate over an `IntrusiveLinkRuntimeView***` triple pointer that
     * modeled this exact same shape without naming `moho::WeakPtr<T>`.
     * Reached from `msvc8::vector<WeakPtr<UserUnit>>::insert`'s in-place
     * tail-shift branch -- `InsertWeakPtrVectorObjectAt` (`FUN_008B2770`)
     * and `EnsureWeakPtrVectorCapacity` (`FUN_008B2B70`) above both already
     * cite this address in their own evidence chains -- via the
     * source-first adapter below.)
     *
     * IDA signature:
     * void *__fastcall sub_7A5FE0(WeakPtr<T> *destination@<eax>,
     *                              int count@<edx>, WeakPtr<T> *source@<edi>);
     *
     * What it does:
     * Fill-constructs `count` lanes starting at `destination`, all copying
     * the same `source` node's owner-link slot and relinking each filled
     * lane at the owner-chain head. Unlike `AssignFillRange` below, this
     * assumes the destination lanes are uninitialized (no prior chain
     * membership to detach) -- the construct-into-fresh-storage half of the
     * canonical VC8 `_Insert_n`/fill-lane pair.
     */
    static WeakPtr<T>* FillConstructRange(
      WeakPtr<T>* destination, std::int32_t count, const WeakPtr<T>& source
    ) noexcept
    {
      for (; count > 0; --count, ++destination) {
        if (destination == nullptr) {
          continue;
        }

        void* const ownerLinkSlot = source.ownerLinkSlot;
        destination->ownerLinkSlot = ownerLinkSlot;
        if (ownerLinkSlot == nullptr) {
          destination->nextInOwner = nullptr;
        } else {
          auto** const ownerHead = reinterpret_cast<WeakPtr<T>**>(ownerLinkSlot);
          destination->nextInOwner = *ownerHead;
          *ownerHead = destination;
        }
      }
      return destination;
    }

    /**
     * Address: 0x008B2E20 (FUN_008B2E20)
     *
     * IDA signature:
     * void *__usercall sub_8B2E20@<eax>(void *destination@<ebx>,
     *                                    WeakPtr<T> **ownerSlotLane@<edi>,
     *                                    int count@<esi>);
     *
     * What it does:
     * Source-first register-shape adapter: forwards to `FillConstructRange`
     * above with `count` and `source` swapped back into canonical order,
     * then returns the advanced destination cursor `destination + count`
     * (the binary computes this as `&destination[2 * count]`, i.e. `count`
     * `WeakPtr<T>` elements). Moved off the anonymous-namespace
     * `CopyIntrusiveLinkRangeFromOwnerSlotLaneSourceFirstAdapterA` free
     * function in `moho/containers/LegacyContainerFillLanes.cpp`.
     */
    static WeakPtr<T>* FillConstructSourceFirstAdapterA(
      WeakPtr<T>* const destination, const WeakPtr<T>& source, const std::int32_t count
    ) noexcept
    {
      (void)FillConstructRange(destination, count, source);
      return destination + count;
    }

    /**
     * Address: 0x007A6030 (FUN_007A6030, moved off `AssignWeakPtrRangeForward`
     * in this file -- that citation was wrong. `FUN_007A6030`'s own
     * disassembly (`cmp eax,esi` / `jz done`; the loop body re-reads `[edx]`
     * for the source lane every iteration without ever advancing `edx`;
     * `eax` advances by 8 and is compared against the fixed `esi` bound) is
     * a single-source *fill*, not a two-range copy -- the source never
     * moves, only the destination does. Reached from
     * `GrowAndInsertInputCaptureWeakRef` (`FUN_007A5A70`, UiRuntimeTypes.cpp)
     * to assign the staged insert value into the single-slot gap opened by
     * that function's in-place tail-shift branch; the reallocation branch
     * and the append-at-end branch both pass an empty
     * `[destination,destinationEnd)` range here, making the call a
     * documented no-op in those two paths.
     *
     * What it does:
     * Assign-fills every lane in `[destination, destinationEnd)` from the
     * same single `source` lane via `ResetFromOwnerLinkSlot`, which detaches
     * each destination lane's previous chain membership first when it
     * differs from source's -- the assign-into-live-storage counterpart to
     * `FillConstructRange` above.
     */
    static WeakPtr<T>* AssignFillRange(
      WeakPtr<T>* destination, WeakPtr<T>* const destinationEnd, const WeakPtr<T>& source
    ) noexcept
    {
      for (; destination != destinationEnd; ++destination) {
        destination->ResetFromOwnerLinkSlot(source.ownerLinkSlot);
      }
      return destination;
    }

    inline static gpg::RType* sType = nullptr;

    // Owner link points at the owner's intrusive weak-link head slot.
    // Most owners use +sizeof(void*), but some recovered types have different
    // owner-link slot offsets (specialized via WeakPtrOwnerLinkOffset<T>).
    static constexpr std::uintptr_t kOwnerLinkOffset = WeakPtrOwnerLinkOffset<T>::value;

    void* ownerLinkSlot;     // points to owner weak-link slot (owner + kOwnerLinkOffset) or nullptr/sentinel
    WeakPtr<T>* nextInOwner; // intrusive next node in owner chain

    WeakPtr() noexcept
      : ownerLinkSlot(nullptr)
      , nextInOwner(nullptr)
    {}

    /**
     * Address: 0x0056AA00 (FUN_0056AA00, Moho::WeakPtr_IUnit::WeakPtr_IUnit)
     * Address: 0x005A6DB0 (FUN_005A6DB0)
     * Address: 0x0057D560 (FUN_0057D560)
     * Address: 0x00686080 (FUN_00686080 -- this constructor emitted out of line
     * with the node in EAX and the object in ECX: `slot = object ? object + 4 : 0`,
     * push-front on that slot. Zero callers, no pointer or jump to it anywhere
     * in the image. Formerly `LinkBackLinkNodeFromOwnerLane` in
     * moho/entity/EntityDb.cpp (RULE THREE), removed 2026-09-22.)
     *
     * What it does:
     * Initializes one weak-pointer node from an owner object pointer and links
     * it at the head of the owner's intrusive weak-link chain.
     */
    explicit WeakPtr(T* object) noexcept
      : ownerLinkSlot(nullptr)
      , nextInOwner(nullptr)
    {
      BindObjectUnlinked(object);
      (void)LinkIntoOwnerChainHeadUnlinked();
    }

    // Recovered aggregate-like initialization lane used by serializer/runtime
    // wrappers that materialize weak nodes from raw intrusive fields.
    WeakPtr(void* encodedOwnerLinkSlot, WeakPtr<T>* nextNode) noexcept
      : ownerLinkSlot(encodedOwnerLinkSlot)
      , nextInOwner(nextNode)
    {}

    /**
     * Address: 0x00736C8F (inlined into `CDamage::CDamage(const CDamage&)`,
     * FUN_00736C40, once per weak lane -- `mInstigator` at `+0x38` and
     * `mTarget` at `+0x40`):
     *
     *     mov  eax, [edi+38h]        ; other.ownerLinkSlot
     *     lea  ecx, [esi+38h]        ; this
     *     mov  [ecx], eax            ; ownerLinkSlot = other.ownerLinkSlot
     *     jz   short zero_next       ; slot == 0 ?
     *     mov  edx, [eax]            ; *slot -- current chain head
     *     mov  [ecx+4], edx          ; nextInOwner = head
     *     mov  [eax], ecx            ; *slot = this
     *
     * What it does:
     * Copy-constructs one weak node onto the *same* owner as `other` and
     * inserts it at the head of that owner's intrusive chain. It never
     * detaches first -- the destination storage is fresh, so it holds no
     * prior chain membership. This is the construct-into-fresh-storage
     * counterpart to `operator=` below, and the shape every relinking
     * copy lane in this header (`FillConstructRange`,
     * `CopyWeakPtrPayloadRangeCore`, ...) is a vectorised emission of.
     *
     * Address: 0x00686D50 (FUN_00686D50 -- this constructor emitted out of line,
     * node in EAX, source in ECX; zero callers, no pointer or jump to it anywhere
     * in the image. Formerly `LinkBackLinkNodeFromBackRefOwner` in
     * moho/entity/EntityDb.cpp (RULE THREE), removed 2026-09-22.)
     */
    WeakPtr(const WeakPtr<T>& other) noexcept
      : ownerLinkSlot(other.ownerLinkSlot)
      , nextInOwner(nullptr)
    {
      if (ownerLinkSlot != nullptr && !IsSentinel()) {
        auto** const head = reinterpret_cast<WeakPtr<T>**>(ownerLinkSlot);
        nextInOwner = *head;
        *head = this;
      }
    }

    /**
     * Address: 0x00737D52 (inlined into `func_DoDamageRing`, FUN_00737B30,
     * for the `pointDamage.mInstigator = damage.mInstigator` lane): compares
     * the incoming slot against the current one, unlinks this node from its
     * present chain when they differ, then relinks at the new owner's head --
     * i.e. exactly `ResetFromOwnerLinkSlot(other.ownerLinkSlot)`, which is
     * why the two share one body in the binary.
     * Address: 0x00836B90 (FUN_00836B90 -- `WeakPtr<T>::operator=` (unlink from the old owner chain, relink at `other.ownerLinkSlot`), 48-byte element; `RebuildFactoryQueueDisplaySnapshot` 0x00835DF0; callers 0x00835DF0; formerly `RelinkIntrusiveNodeViaIndirectOwner` in moho/containers/LegacyContainerRuntime.cpp (RULE ONE), file removed 2026-09-10.)
     * Address: 0x006886D0 (FUN_006886D0 -- `operator=`, node in EAX, source in
     * EDX; zero callers, no pointer or jump to it anywhere in the image. Formerly
     * `RebindBackLinkNode` in moho/entity/EntityDb.cpp (RULE THREE), removed
     * 2026-09-22.)
     */
    WeakPtr<T>& operator=(const WeakPtr<T>& other) noexcept
    {
      if (this != &other) {
        ResetFromOwnerLinkSlot(other.ownerLinkSlot);
      }
      return *this;
    }

    ~WeakPtr() noexcept;

    [[nodiscard]] static bool IsSentinelSlot(void* slot) noexcept
    {
      return reinterpret_cast<std::uintptr_t>(slot) == kOwnerLinkOffset;
    }

    [[nodiscard]] static void* EncodeOwnerLinkSlot(T* object) noexcept
    {
      if (!object) {
        return nullptr;
      }
      return reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) + kOwnerLinkOffset);
    }

    /**
     * Address: 0x0057D540 (FUN_0057D540)
     *
     * What it does:
     * Decodes one weak owner-link slot back to the owning object pointer
     * (`slot - kOwnerLinkOffset`), returning null for empty/sentinel lanes.
     * Address: 0x006860D0 (FUN_006860D0 -- this accessor emitted out of line,
     * node in EAX: `slot ? slot - 4 : 0`; zero callers, no pointer or jump to it
     * anywhere in the image. Formerly `ResolveBackLinkNodeOwner` in
     * moho/entity/EntityDb.cpp (RULE THREE), removed 2026-09-22.)
     */
    [[nodiscard]] static T* DecodeOwnerObject(void* slot) noexcept
    {
      if (!slot || IsSentinelSlot(slot)) {
        return nullptr;
      }
      const auto raw = reinterpret_cast<std::uintptr_t>(slot);
      return reinterpret_cast<T*>(raw - kOwnerLinkOffset);
    }

    [[nodiscard]] bool IsSentinel() const noexcept
    {
      return IsSentinelSlot(ownerLinkSlot);
    }

    [[nodiscard]] bool HasValue() const noexcept
    {
      return ownerLinkSlot != nullptr && !IsSentinel();
    }

    [[nodiscard]] T* GetObjectPtr() const noexcept
    {
      return DecodeOwnerObject(ownerLinkSlot);
    }

    [[nodiscard]] bool IsLinkedInOwnerChain() const noexcept
    {
      return ownerLinkSlot != nullptr && !IsSentinel();
    }

    // There used to be a `GetObject()` alias for `GetObjectPtr()` here, behind
    // `#if !defined(GetObject)`. That guard protects the *declaration* and
    // nothing else: a translation unit that reaches this header before
    // <windows.h> gets the method declared, and then every later call site
    // expands through the GDI macro to `GetObjectW`/`GetObjectA` and fails to
    // compile. `CollisionBeamEntityLuaFunctionThunks.cpp` broke exactly that
    // way. `GetObjectPtr()` is the real accessor and has no such exposure, so
    // the alias is gone rather than re-guarded.

    /**
     * @warning This faults today once projectile impact scripts actually run.
     * `ownerLinkSlot` is `owner + kOwnerLinkOffset`, so a node whose owner was
     * freed without being drained dereferences into released memory here --
     * observed reading 0xF2B8458D from
     * `Projectile::~Projectile` -> `CAiTarget::~CAiTarget` ->
     * `CAiTarget::UnlinkEntityTargetRef` -> `UnlinkFromOwnerChain` -> here.
     * See [[project_onimpact_shape_and_weakptr_crash]] for the trigger.
     *
     * What is already ruled out: the drain itself is correct, and it does run.
     * `CScriptObject::~CScriptObject` calls `ClearWeakObjectChain`, whose body
     * walks the chain nulling each node's `ownerLinkSlot`/`nextInOwner` exactly
     * as `WeakObject::DetachAllWeakReferences` does. A node that had been
     * drained would leave `IsLinkedInOwnerChain()` false and return above.
     *
     * Also ruled out, so do not "fix" either: `ResetFromOwnerLinkSlot` below is
     * correct, and so is `CAiTarget::CopyFromLinkedTarget`, which is its only
     * interesting caller. Both match `CAiTarget`'s copy helper in the binary
     * (0x005D5670) step for step -- it walks the old owner's chain and splices
     * the node out (0x005D5684..0x005D5694), then sets the new slot and pushes
     * the node onto that owner's head, `nextInOwner = *ownerHead;
     * *ownerHead = this` (0x005D569F..0x005D56A4). The `BindOwnerLinkSlotUnlinked`
     * doc a few lines below *does* say "without inserting into the owner's
     * chain", but that is a different method and not the one on this path.
     *
     * The open lead is **which** `WeakObject` subobject was drained. Entity
     * carries one at RTTI mdisp=4 inside `CScriptObject`, and `Unit.cpp:13838`
     * calls a second, duplicate `ClearWeakObjectChain` on a *different* one --
     * `static_cast<WeakObject&>(static_cast<IUnit&>(*this))`. A `WeakPtr` bound
     * to one subobject's head is not drained by the destructor that drains the
     * other, which would leave exactly this dangling slot.
     *
     * The offset half of that question is now answered, and it is *not* the
     * bug: `WeakPtr<Entity>` takes the default `WeakPtrOwnerLinkOffset` of
     * `sizeof(void*)`, and RTTI puts Entity's `WeakObject` at mdisp=4, so the
     * slot `EncodeOwnerLinkSlot` produces is the same one
     * `ClearWeakObjectChain` walks. (`UserEntity`/`UserUnit` need their 0x08
     * specialisations because of their vtable; plain `Entity` does not.)
     *
     * **The owner is not a freed object at all.** Instrumenting
     * `CAiTarget::UnlinkEntityTargetRef` with the OnImpact fix applied caught
     * the faulting node: `slot=00C466A1 owner=00C4669D linked=1`, against 848
     * unlinks that were all clean (`slot=0`). Two things rule out the lifetime
     * story that the rest of this comment was chasing:
     *
     *  - `0x00C4669D` is **odd**, and every `Entity` is at least 4-byte
     *    aligned, so it was never an object pointer;
     *  - it lies inside the **module image** (base 0x00400000, ~12 MB), not the
     *    heap -- live entities in the same run sat at 0x4F84231C, 0x55745000.
     *    It reads like a vtable or constant-pool address.
     *
     * So `ownerLinkSlot` is holding a non-pointer rather than a stale one, and
     * the drain machinery is exonerated: there is nothing for
     * `ClearWeakObjectChain` to have missed. Look instead at how this
     * `CAiTarget` got that value -- a layout or aliasing problem, e.g.
     * `Projectile::mTargetPosData` at +0x2EC reading the wrong bytes, or a
     * `CAiTarget` copied out of storage that was never constructed. `CAiTarget`
     * itself is `= default` and `WeakPtr`'s default ctor does zero both fields,
     * so plain default construction is not the source.
     *
     * The corruption is rare -- one node in 848 -- so reproduce it with the
     * OnImpact fix from [[project_onimpact_shape_and_weakptr_crash]] applied
     * and that same probe, rather than expecting it on demand.
     */
    [[nodiscard]] bool ReplaceInOwnerChain(WeakPtr<T>* replacement) noexcept
    {
      if (!IsLinkedInOwnerChain()) {
        return false;
      }

      auto** slot = reinterpret_cast<WeakPtr<T>**>(ownerLinkSlot);
      while (*slot && *slot != this) {
        slot = &(*slot)->nextInOwner;
      }

      if (*slot != this) {
        return false;
      }

      *slot = replacement;
      return true;
    }

    void UnlinkFromOwnerChain() noexcept
    {
      if (!IsLinkedInOwnerChain()) {
        return;
      }

      if (ReplaceInOwnerChain(nextInOwner)) {
        ownerLinkSlot = nullptr;
        nextInOwner = nullptr;
      }
    }

    void ClearLinkState() noexcept
    {
      ownerLinkSlot = nullptr;
      nextInOwner = nullptr;
    }

    /**
     * Binds an encoded owner-link slot without inserting into the owner's chain.
     *
     * Use this when a node payload is copied/staged first and linked later by
     * explicit insertion logic.
     */
    void BindOwnerLinkSlotUnlinked(void* encodedOwnerLinkSlot) noexcept
    {
      ownerLinkSlot = encodedOwnerLinkSlot;
      nextInOwner = nullptr;
    }

    /**
     * Binds this weak node to an object owner slot without linking into the chain.
     */
    void BindObjectUnlinked(T* object) noexcept
    {
      BindOwnerLinkSlotUnlinked(EncodeOwnerLinkSlot(object));
    }

    /**
     * Inserts one weak node at the current owner-chain head without first
     * scanning for/removing an existing link.
     *
     * Precondition: node is currently unlinked from the owner chain.
     */
    [[nodiscard]] bool LinkIntoOwnerChainHeadUnlinked() noexcept
    {
      if (!HasValue()) {
        nextInOwner = nullptr;
        return false;
      }

      auto** const head = reinterpret_cast<WeakPtr<T>**>(ownerLinkSlot);
      nextInOwner = *head;
      *head = this;
      return true;
    }

    /**
     * Address: 0x0057D610 (FUN_0057D610)
     * Address: 0x005419A0 (FUN_005419A0)
     * Address: 0x005DB430 (FUN_005DB430)
     * Address: 0x0057D4B0 (FUN_0057D4B0)
     * Address: 0x005A6E00 (FUN_005A6E00, Moho::WeakPtr_Entity::Set)
     *
     * The compiler emits this body once per instantiation and the linker
     * leaves the copies distinct; all of the addresses above are byte-identical
     * emissions of this one function, so they resolve here rather than to
     * separate recoveries.
     *
     * What it does:
     * Rebinds this weak-pointer node to a new owner-link slot, detaches the
     * node from its previous intrusive owner chain when needed, and inserts it
     * at the head of the new owner chain.
     * Address: 0x007A5610 (FUN_007A5610 -- `WeakPtr<T>::ResetFromOwnerLinkSlot` (unlink from the old chain, relink at the requested owner head); callers 0x007A4970; formerly `RebindIntrusiveOwnerSlotNodeRuntime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-10.)
     * Address: 0x0084E330 (FUN_0084E330 -- `WeakPtr<T>::ResetFromOwnerLinkSlot` with the owner head at `owner + 0x08`; callers 0x0084D000; formerly `RebindIntrusiveOwnerSlotNodeRuntimeB` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-10.)
     * Address: 0x00873810 (FUN_00873810 -- `WeakPtr<T>::ResetFromOwnerLinkSlot` with the owner head at `owner + 0x08`; callers 0x008704B0; formerly `RebindIntrusiveOwnerSlotNodeRuntimeC` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-10.)
     */
    void ResetFromOwnerLinkSlot(void* newOwnerLinkSlot) noexcept
    {
      if (newOwnerLinkSlot == ownerLinkSlot) {
        return;
      }

      // Detach from current owner chain.
      if (ownerLinkSlot && !IsSentinel()) {
        auto** cursor = reinterpret_cast<WeakPtr<T>**>(ownerLinkSlot);
        while (*cursor && *cursor != this) {
          cursor = reinterpret_cast<WeakPtr<T>**>(
            reinterpret_cast<std::uintptr_t>(*cursor) + offsetof(WeakPtr<T>, nextInOwner)
          );
        }
        if (*cursor == this) {
          *cursor = nextInOwner;
        }
      }

      ownerLinkSlot = newOwnerLinkSlot;
      if (newOwnerLinkSlot && !IsSentinelSlot(newOwnerLinkSlot)) {
        auto** const head = reinterpret_cast<WeakPtr<T>**>(newOwnerLinkSlot);
        nextInOwner = *head;
        *head = this;
      } else {
        nextInOwner = nullptr;
      }
    }

    /**
     * Address: 0x00836BD0 (FUN_00836BD0 -- `WeakPtr<T>::ResetFromObject` (the owner's weak-link head at +0x08); `UserUnit::UpdateUnitData` 0x008C0750; callers 0x008C0750; formerly `RelinkIntrusiveNodeViaOwnerOffset08` in moho/containers/LegacyContainerRuntime.cpp (RULE ONE), file removed 2026-09-10.)
     * Address: 0x00632CA0 (FUN_00632CA0 -- the `WeakPtr<UnitWeapon>` emission,
     *   identified by its owner-link offset: the body's `add ecx, 0x14` is
     *   `EncodeOwnerLinkSlot`'s `kOwnerLinkOffset`, and
     *   `WeakPtrOwnerLinkOffset<UnitWeapon>::value` is the only 0x14
     *   specialization. The rest matches `ResetFromOwnerLinkSlot` instruction
     *   for instruction, including the null-slot branch that writes
     *   `nextInOwner = nullptr`. Zero callers, unreachable; formerly
     *   `AttachNodeToOwnerHead` over an `IntrusiveOwnerHeadRuntimeView` in
     *   moho/animation/IAniManipulator.cpp (RULE ONE), removed 2026-09-22.)
     * Address: 0x0066A2A0 (FUN_0066A2A0 -- the `WeakPtr<WWinManagedFrame>` emission
     *   (`lea edx, [ecx+178h]` is WeakPtrOwnerLinkOffset<WWinManagedFrame>);
     *   caller EFX_CreateEmitterWindow 0x0066A007; formerly
     *   `RebindManagedWindowSlotToFrame` in moho/console/CConCommand.cpp, removed
     *   with the wx conversion.)
     * Address: 0x004F7230 (FUN_004F7230 -- the `WeakPtr<WWinManagedDialog>`
     *   emission (`lea edx, [ecx+170h]`), the slot in EAX and the dialog in
     *   ECX; zero callers, a linker-retained copy.)
     * Address: 0x004F72F0 (FUN_004F72F0 -- a second
     *   `WeakPtr<WWinManagedFrame>` emission (`lea edx, [ecx+178h]`) in the
     *   managed-window TU; zero callers.)
     */
    void ResetFromObject(T* object) noexcept
    {
      ResetFromOwnerLinkSlot(EncodeOwnerLinkSlot(object));
    }

    void Set(T* object) noexcept
    {
      ResetFromObject(object);
    }
  };

  static_assert(sizeof(WeakPtr<void>) == 0x08, "WeakPtr<T> must be 8 bytes");
  static_assert(WeakPtr<void>::kOwnerLinkOffset == 0x4, "WeakPtr ABI expects owner-link offset 0x4");
  static_assert(offsetof(WeakPtr<void>, ownerLinkSlot) == 0x00, "WeakPtr<T>::ownerLinkSlot offset must be 0x00");
  static_assert(offsetof(WeakPtr<void>, nextInOwner) == 0x04, "WeakPtr<T>::nextInOwner offset must be 0x04");

  template <class PayloadT>
  struct WeakPtrPayloadLane
  {
    WeakPtr<void> weak;
    PayloadT payload;
  };

  static_assert(sizeof(WeakPtrPayloadLane<std::uint32_t>) == 0x0C, "WeakPtrPayloadLane<uint32_t> size must be 0x0C");
  static_assert(sizeof(WeakPtrPayloadLane<float>) == 0x0C, "WeakPtrPayloadLane<float> size must be 0x0C");

  template <class PayloadT>
  [[nodiscard]] inline WeakPtrPayloadLane<PayloadT>* CopyWeakPtrPayloadRangeCore(
    WeakPtrPayloadLane<PayloadT>* destination,
    const WeakPtrPayloadLane<PayloadT>* sourceEnd,
    const WeakPtrPayloadLane<PayloadT>* sourceBegin
  ) noexcept
  {
    for (const WeakPtrPayloadLane<PayloadT>* source = sourceBegin; source != sourceEnd; ++source, ++destination) {
      if (destination == nullptr) {
        continue;
      }

      destination->weak.ownerLinkSlot = source->weak.ownerLinkSlot;
      if (source->weak.ownerLinkSlot == nullptr) {
        destination->weak.nextInOwner = nullptr;
      } else {
        auto** const ownerHead = reinterpret_cast<WeakPtr<void>**>(source->weak.ownerLinkSlot);
        destination->weak.nextInOwner = *ownerHead;
        *ownerHead = &destination->weak;
      }
      destination->payload = source->payload;
    }
    return destination;
  }

  /**
   * Address: 0x00628FD0 (FUN_00628FD0)
   *
   * What it does:
   * Copy-assigns one weak-link + float payload lane while preserving
   * intrusive owner-chain links for the embedded weak node.
   */
  [[nodiscard]] inline WeakPtrPayloadLane<float>* AssignWeakPtrFloatPayloadLaneWithRelink(
    WeakPtrPayloadLane<float>* const destination,
    const WeakPtrPayloadLane<float>* const source
  ) noexcept
  {
    destination->weak = source->weak;
    destination->payload = source->payload;
    return destination;
  }

  struct PrefixedWeakPtrDwordPayloadLane
  {
    std::uint32_t prefix0;
    std::uint32_t prefix1;
    WeakPtr<void> weak;
    std::uint32_t payload;
  };

  static_assert(sizeof(PrefixedWeakPtrDwordPayloadLane) == 0x14, "PrefixedWeakPtrDwordPayloadLane size must be 0x14");

  /**
   * Address: 0x00687A70 (FUN_00687A70)
   *
   * What it does:
   * Copy-assigns one 20-byte payload lane with two leading dwords, one
   * embedded weak-link node, and one trailing dword while preserving intrusive
   * weak-owner chain semantics.
   */
  [[nodiscard]] inline PrefixedWeakPtrDwordPayloadLane* CopyPrefixedWeakPtrDwordPayloadLane(
    PrefixedWeakPtrDwordPayloadLane* const destination,
    const PrefixedWeakPtrDwordPayloadLane* const source
  ) noexcept
  {
    if (destination == nullptr || source == nullptr) {
      return destination;
    }

    destination->prefix0 = source->prefix0;
    destination->prefix1 = source->prefix1;

    if (source->weak.ownerLinkSlot != destination->weak.ownerLinkSlot) {
      if (destination->weak.ownerLinkSlot != nullptr) {
        auto** cursor = reinterpret_cast<WeakPtr<void>**>(destination->weak.ownerLinkSlot);
        while (*cursor != &destination->weak) {
          cursor = &(*cursor)->nextInOwner;
        }
        *cursor = destination->weak.nextInOwner;
      }

      destination->weak.ownerLinkSlot = source->weak.ownerLinkSlot;
      if (source->weak.ownerLinkSlot != nullptr) {
        auto** const ownerHead = reinterpret_cast<WeakPtr<void>**>(source->weak.ownerLinkSlot);
        destination->weak.nextInOwner = *ownerHead;
        *ownerHead = &destination->weak;
      } else {
        destination->weak.nextInOwner = nullptr;
      }
    }

    destination->payload = source->payload;
    return destination;
  }

  /**
   * Address: 0x00689310 (FUN_00689310)
   *
   * What it does:
   * Constructs `count` prefixed weak-payload records from one repeated
   * source record, relinking each written record's embedded weak pointer
   * into the source's owner chain via `CopyPrefixedWeakPtrDwordPayloadLane`.
   * Count-based sibling of `FillPrefixedWeakPtrDwordPayloadRangeFromSingleLane`
   * (0x00689520 below), which takes an end-pointer instead of a count.
   */
  [[nodiscard]] inline PrefixedWeakPtrDwordPayloadLane* ConstructPrefixedWeakPtrDwordPayloadRepeated(
    PrefixedWeakPtrDwordPayloadLane* destination,
    std::uint32_t count,
    const PrefixedWeakPtrDwordPayloadLane* const source
  ) noexcept
  {
    for (; count != 0u; --count, ++destination) {
      if (destination == nullptr) {
        continue;
      }
      (void)CopyPrefixedWeakPtrDwordPayloadLane(destination, source);
    }
    return destination;
  }

  /**
   * Address: 0x00689520 (FUN_00689520)
   *
   * What it does:
   * Copies one fixed prefixed weak-payload lane into every destination lane in
   * `[destinationBegin, destinationEnd)` and returns the last written lane
   * pointer (or `sourceLane` when destination range is empty).
   */
  [[maybe_unused]] [[nodiscard]] inline PrefixedWeakPtrDwordPayloadLane* FillPrefixedWeakPtrDwordPayloadRangeFromSingleLane(
    PrefixedWeakPtrDwordPayloadLane* sourceLane,
    PrefixedWeakPtrDwordPayloadLane* destinationBegin,
    PrefixedWeakPtrDwordPayloadLane* destinationEnd
  ) noexcept
  {
    PrefixedWeakPtrDwordPayloadLane* result = sourceLane;
    for (PrefixedWeakPtrDwordPayloadLane* destination = destinationBegin; destination != destinationEnd; ++destination) {
      result = CopyPrefixedWeakPtrDwordPayloadLane(destination, sourceLane);
    }
    return result;
  }

  [[nodiscard]] inline PrefixedWeakPtrDwordPayloadLane* CopyPrefixedWeakPtrDwordPayloadRangeBackwardCore(
    PrefixedWeakPtrDwordPayloadLane* destinationEnd,
    const PrefixedWeakPtrDwordPayloadLane* sourceEnd,
    const PrefixedWeakPtrDwordPayloadLane* sourceBegin
  ) noexcept
  {
    auto* destination = destinationEnd;
    const PrefixedWeakPtrDwordPayloadLane* source = sourceEnd;
    while (source != sourceBegin) {
      --destination;
      --source;
      (void)CopyPrefixedWeakPtrDwordPayloadLane(destination, source);
    }
    return destination;
  }

  /**
   * Address: 0x00689D70 (FUN_00689D70)
   *
   * IDA signature:
   * void *__usercall sub_689D70@<eax>(void *result@<eax>, const void *sourceBegin@<ecx>, const void *sourceEnd@<edi>);
   *
   * What it does:
   * Forward counterpart of `CopyPrefixedWeakPtrDwordPayloadRangeBackwardCore`
   * above: walks `[sourceBegin, sourceEnd)` in ascending order, copying each
   * lane into the matching destination slot via
   * `CopyPrefixedWeakPtrDwordPayloadLane` and preserving intrusive
   * weak-owner chain semantics per element exactly like that member.
   * `.asm`-confirmed field-for-field: prefix0/prefix1 direct copy, the
   * owner-chain splice (relink into the owner's weak-observer chain when
   * non-null, else clear), then the trailing payload dword -- the same
   * per-element shape `CopyPrefixedWeakPtrDwordPayloadLane` already
   * expresses, just looped. The binary carries a `destination != nullptr`
   * guard around the whole per-element body (absent from the
   * already-recovered backward core above -- different call site,
   * different codegen, not a contradiction); preserved here for binary
   * fidelity.
   *
   * Real instantiation: this exact 20-byte shape (4-byte prefix0/prefix1,
   * an embedded `WeakPtr<T>`, 4-byte trailing payload) is, field-for-field,
   * `moho::CEntityDbBoundedPropQueueNode` in `moho/entity/EntityDb.cpp`
   * (`mPriority`/`mBoundedTick`/`mOwnerLink`(`WeakPtr<Prop>`)/`mHandleId` at
   * the same four offsets as `prefix0`/`prefix1`/`weak`/`payload`) -- see
   * `Vector.h`'s `insert(const_iterator, const T&)` citation for
   * `FUN_006882E0` (`msvc8::vector<CEntityDbBoundedPropQueueNode>::insert`,
   * this function's real caller) for the full evidence chain. This file's
   * generic, less-specifically-typed `PrefixedWeakPtrDwordPayloadLane` and
   * `EntityDb.cpp`'s properly-typed `CEntityDbBoundedPropQueueNode` are two
   * independently-recovered names for the same binary object -- a
   * `Duplicate layout contract` violation predating this citation, flagged
   * here rather than silently carried forward; a dedicated pass should
   * either retype this whole `PrefixedWeakPtrDwordPayloadLane` family onto
   * `CEntityDbBoundedPropQueueNode` directly or confirm a second, distinct
   * owner actually needs the generic name kept.
   */
  [[nodiscard]] inline PrefixedWeakPtrDwordPayloadLane* CopyPrefixedWeakPtrDwordPayloadRangeForwardCore(
    PrefixedWeakPtrDwordPayloadLane* destinationBegin,
    const PrefixedWeakPtrDwordPayloadLane* sourceBegin,
    const PrefixedWeakPtrDwordPayloadLane* sourceEnd
  ) noexcept
  {
    auto* destination = destinationBegin;
    for (const PrefixedWeakPtrDwordPayloadLane* source = sourceBegin; source != sourceEnd; ++source, ++destination) {
      if (destination != nullptr) {
        (void)CopyPrefixedWeakPtrDwordPayloadLane(destination, source);
      }
    }
    return destination;
  }

  /**
   * Address: 0x00689570 (FUN_00689570)
   *
   * What it does:
   * Register-shape adapter lane for backward prefixed weak-payload range copy
   * into destination tail storage.
   */
  [[maybe_unused]] [[nodiscard]] inline PrefixedWeakPtrDwordPayloadLane* CopyPrefixedWeakPtrDwordPayloadRangeBackwardAdapterA(
    const PrefixedWeakPtrDwordPayloadLane* sourceEnd,
    PrefixedWeakPtrDwordPayloadLane* destinationEnd,
    const PrefixedWeakPtrDwordPayloadLane* sourceBegin
  ) noexcept
  {
    return CopyPrefixedWeakPtrDwordPayloadRangeBackwardCore(destinationEnd, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x006898B0 (FUN_006898B0)
   *
   * What it does:
   * Mirrored register-shape adapter lane for backward prefixed weak-payload
   * range copy into destination tail storage.
   */
  [[maybe_unused]] [[nodiscard]] inline PrefixedWeakPtrDwordPayloadLane* CopyPrefixedWeakPtrDwordPayloadRangeBackwardAdapterB(
    PrefixedWeakPtrDwordPayloadLane* destinationEnd,
    const PrefixedWeakPtrDwordPayloadLane* sourceEnd,
    const PrefixedWeakPtrDwordPayloadLane* sourceBegin
  ) noexcept
  {
    return CopyPrefixedWeakPtrDwordPayloadRangeBackwardCore(destinationEnd, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x007A5FB0 (FUN_007A5FB0)
   *
   * What it does:
   * Unlinks every weak node in `[begin, end)` from its owner chain without
   * mutating the unlinked nodes' local storage lanes.
   */
  inline void UnlinkWeakPtrRangeWithoutClearing(WeakPtr<void>* begin, WeakPtr<void>* end) noexcept
  {
    for (; begin != end; ++begin) {
      if (begin->ownerLinkSlot == nullptr) {
        continue;
      }

      auto** cursor = reinterpret_cast<WeakPtr<void>**>(begin->ownerLinkSlot);
      while (*cursor != begin) {
        cursor = &(*cursor)->nextInOwner;
      }
      *cursor = begin->nextInOwner;
    }
  }

  /**
   * Address: 0x005A6DE0 (FUN_005A6DE0, `WeakPtr<Entity>`'s emission -- the
   * `CDamage` copy-ctor unwind funclets at 0x00BAC2EF / 0x00BAC2FA reach it
   * as `mov ecx,[ebp+4]; add ecx,38h/40h; jmp sub_5A6DE0`, i.e. as the
   * member destructor of the two weak lanes)
   * Address: 0x0056AA50 (FUN_0056AA50, Moho::WeakPtr_IUnit::~WeakPtr_IUnit --
   * the `WeakPtr<IUnit>` emission of this same body)
   * Address: 0x004F7210 (FUN_004F7210 -- the `WeakPtr<WWinManagedDialog>`
   * emission; zero callers, the registry's destroy range 0x004FADE0 inlines
   * it. Formerly anchored in moho/app/WxRuntimeTypes.cpp.)
   * Address: 0x004F72D0 (FUN_004F72D0 -- the `WeakPtr<WWinManagedFrame>`
   * emission; zero callers, 0x004FAED0 inlines it.)
   *
   * IDA signature:
   * void __fastcall sub_5A6DE0(WeakPtr<T> *this@<ecx>);
   *
   * What it does:
   * Unlinks this node from its owner's intrusive weak-link chain. The node's
   * own storage is left untouched -- it is about to die, and the binary
   * likewise never clears it:
   *
   *     mov  eax, [ecx]        ; ownerLinkSlot
   *     test eax, eax
   *     jz   ret               ; not linked
   *     cmp  [eax], ecx        ; head == this ?
   *     jz   unlink            ;   eax still holds the head slot
   *  loop:
   *     mov  eax, [eax]        ; node = *cursor
   *     add  eax, 4            ; cursor = &node->nextInOwner
   *     cmp  [eax], ecx
   *     jnz  loop
   *  unlink:
   *     mov  ecx, [ecx+4]      ; this->nextInOwner
   *     mov  [eax], ecx        ; *cursor = nextInOwner
   *
   * This body is why the chain stays consistent when a weak holder dies while
   * still aimed at a live owner. Leaving it defaulted -- as this template did
   * until the `CDamage` ring-damage crash -- silently strands the dead node in
   * the owner's chain, and the next walk of that chain (a `Set`, another
   * destructor, or `ClearWeakObjectChain`) dereferences whatever has since
   * reused the storage. That is the `0xF2B8458D` / `0x00C4669D` "corrupt
   * ownerLinkSlot" class of fault documented on `ReplaceInOwnerChain` above:
   * the drain was always correct, the *departures* were not.
   *
   * The `while` here additionally stops on a null cursor. The binary runs off
   * the end instead, which cannot happen there because every live node really
   * is in the chain it names; keeping the guard costs nothing and contains the
   * damage if a node is ever staged with a slot it was never linked into (see
   * `BindOwnerLinkSlotUnlinked`).
   */
  template <class T>
  inline WeakPtr<T>::~WeakPtr() noexcept
  {
    if (ownerLinkSlot == nullptr || IsSentinel()) {
      return;
    }

    auto** cursor = reinterpret_cast<WeakPtr<T>**>(ownerLinkSlot);
    while (*cursor != nullptr && *cursor != this) {
      cursor = &(*cursor)->nextInOwner;
    }
    if (*cursor == this) {
      *cursor = nextInOwner;
    }
  }

  /**
   * Address: 0x0057D4F0 (FUN_0057D4F0, Moho::WeakPtr_Unit::Set)
   *
   * What it does:
   * Rebinds one weak-unit node by unlinking from its current owner chain and
   * inserting at the head of the new owner's weak-link list.
   */
  template <>
  inline void WeakPtr<Unit>::Set(Unit* object) noexcept
  {
    void* const targetOwnerLinkSlot = EncodeOwnerLinkSlot(object);
    if (ownerLinkSlot == targetOwnerLinkSlot) {
      return;
    }

    if (ownerLinkSlot != nullptr) {
      auto** existing = reinterpret_cast<WeakPtr<Unit>**>(ownerLinkSlot);
      while (*existing != this) {
        existing = &(*existing)->nextInOwner;
      }
      *existing = nextInOwner;
    }

    ownerLinkSlot = targetOwnerLinkSlot;
    if (targetOwnerLinkSlot != nullptr) {
      auto** const ownerHead = reinterpret_cast<WeakPtr<Unit>**>(targetOwnerLinkSlot);
      nextInOwner = *ownerHead;
      *ownerHead = this;
    } else {
      nextInOwner = nullptr;
    }
  }

  template <class T>
  struct WeakPtrVectorStorage
  {
    WeakPtr<T>* begin;
    WeakPtr<T>* end;
    WeakPtr<T>* capacityEnd;
  };
  static_assert(sizeof(WeakPtrVectorStorage<void>) == 0x0C, "WeakPtrVectorStorage<T> must be 12 bytes");

  template <class T>
  struct WeakPtrVectorRuntimeView
  {
    void* proxy;
    WeakPtr<T>* begin;
    WeakPtr<T>* end;
    WeakPtr<T>* capacityEnd;
  };
  static_assert(sizeof(WeakPtrVectorRuntimeView<void>) == 0x10, "WeakPtrVectorRuntimeView<T> must be 16 bytes");
  static_assert(
    offsetof(WeakPtrVectorRuntimeView<void>, begin) == 0x04,
    "WeakPtrVectorRuntimeView<T>::begin offset must be 0x04"
  );
  static_assert(
    offsetof(WeakPtrVectorRuntimeView<void>, end) == 0x08,
    "WeakPtrVectorRuntimeView<T>::end offset must be 0x08"
  );
  static_assert(
    offsetof(WeakPtrVectorRuntimeView<void>, capacityEnd) == 0x0C,
    "WeakPtrVectorRuntimeView<T>::capacityEnd offset must be 0x0C"
  );

  /**
   * Address: 0x0056D3C0 (FUN_0056D3C0, sub_56D3C0)
   * Address: 0x0061CA70 (FUN_0061CA70)
   *
   * What it does:
   * Unlinks each `WeakPtr<Unit>` in [`begin`, `end`) from its owner chain by
   * replacing owner-chain references to each node with that node's `nextInOwner`.
   */
  inline void UnlinkWeakPtrUnitRange(WeakPtr<Unit>* begin, WeakPtr<Unit>* end) noexcept
  {
    while (begin != end) {
      begin->UnlinkFromOwnerChain();
      ++begin;
    }
  }

  template <class T>
  [[nodiscard]] WeakPtrVectorRuntimeView<T>& AsWeakPtrVectorRuntimeView(msvc8::vector<WeakPtr<T>>& weakVector) noexcept
  {
    return *reinterpret_cast<WeakPtrVectorRuntimeView<T>*>(&weakVector);
  }

  template <class T>
  [[nodiscard]] const WeakPtrVectorRuntimeView<T>&
  AsWeakPtrVectorRuntimeView(const msvc8::vector<WeakPtr<T>>& weakVector) noexcept
  {
    return *reinterpret_cast<const WeakPtrVectorRuntimeView<T>*>(&weakVector);
  }

  /**
   * Address: 0x008B2B70 (FUN_008B2B70, msvc8::vector<Moho::WeakPtr<UserUnit>>
   * ::insert(pos, 1, value) for the 8-byte `WeakPtr<T>` element -- the real
   * `_Insert_n` shape: max_size guard (`0x1FFFFFFF`), in-place tail-shift
   * when capacity allows (`sub_8B39A0`), else VC8's real 1.5x growth
   * (`(cap>>1)+cap`, floored to `size+1` when that's not enough --
   * `msvc8::vector<T>::recommended_capacity()`'s own formula, reused below
   * rather than re-derived, since this element's move-with-relink semantics
   * don't go through `Vector.h`'s generic `reallocate_to`) followed by an
   * allocate (`sub_8B3700`), head/gap/tail relocate
   * (`sub_8B39A0`/`sub_8B3D30`), and old-block release. The capacity-growth
   * divergence this citation caught (this function was doubling from a
   * capacity-4 floor; the binary grows 1.5x from an exact-fit-at-1 floor,
   * matching every other `_Insert_n` in this codebase) is fixed below by
   * calling `recommended_capacity()` directly instead of re-deriving the
   * formula. Reached from `Moho::AddArmyAvatar` (FUN_008B2300,
   * UserUnit.cpp) via `InsertWeakPtrVectorObjectAt`.
   */
  template <class T>
  void EnsureWeakPtrVectorCapacity(msvc8::vector<WeakPtr<T>>& weakVector, const std::size_t requiredCount)
  {
    auto& view = AsWeakPtrVectorRuntimeView(weakVector);

    const std::size_t size = view.begin ? static_cast<std::size_t>(view.end - view.begin) : 0u;
    const std::size_t capacity = view.begin ? static_cast<std::size_t>(view.capacityEnd - view.begin) : 0u;
    if (requiredCount <= capacity) {
      return;
    }

    const std::size_t newCapacity = weakVector.recommended_capacity(requiredCount);

    auto* const newBegin = static_cast<WeakPtr<T>*>(::operator new(sizeof(WeakPtr<T>) * newCapacity));
    for (std::size_t i = 0; i < newCapacity; ++i) {
      newBegin[i].ownerLinkSlot = nullptr;
      newBegin[i].nextInOwner = nullptr;
    }

    for (std::size_t i = 0; i < size; ++i) {
      newBegin[i].ResetFromOwnerLinkSlot(view.begin[i].ownerLinkSlot);
      view.begin[i].ResetFromObject(nullptr);
    }

    ::operator delete(view.begin);
    view.begin = newBegin;
    view.end = newBegin + size;
    view.capacityEnd = newBegin + newCapacity;
  }

  /**
   * Address: 0x00599530 (FUN_00599530, msvc8::vector<WeakPtr<CUnitCommand>>::size)
   *
   * What it does:
   * `(view.end - view.begin) / sizeof(WeakPtr<T>)` - the binary emits this
   * out of line for `WeakPtr<CUnitCommand>` and calls it from
   * `CUnitCommand::AddUnit` by way of this helper; the same
   * `view.end - view.begin` computation is inlined at each of this file's
   * other `WeakPtrVectorRuntimeView` accessors (`EnsureWeakPtrVectorCapacity`,
   * `InsertWeakPtrVectorObjectAt`, `RemoveWeakPtrVectorObject`) rather than
   * calling a shared helper.
   */
  template <class T>
  [[nodiscard]] std::size_t
  NormalizeWeakPtrVectorInsertIndex(const msvc8::vector<WeakPtr<T>>& weakVector, int index) noexcept
  {
    const auto& view = AsWeakPtrVectorRuntimeView(weakVector);
    const std::size_t size = view.begin ? static_cast<std::size_t>(view.end - view.begin) : 0u;

    int normalized = index;
    if (normalized < 0) {
      normalized += static_cast<int>(size) + 1;
    }
    if (normalized < 0) {
      normalized = 0;
    }

    std::size_t result = static_cast<std::size_t>(normalized);
    if (result > size) {
      result = size;
    }
    return result;
  }

  /**
   * Address: 0x008B2770 (FUN_008B2770, msvc8::vector<Moho::WeakPtr<UserUnit>>
   * ::push_back's fast-path append -- the sibling emission of the grow lane
   * described above (FUN_008B2B70); AddArmyAvatar's InsertWeakPtrVectorObjectAt
   * call below covers this address's index==size() behavior byte-for-byte.
   *
   * Re-verified directly from FUN_008B2770.asm and FUN_008B2B70.asm (its
   * general insert(pos,1,value), in-place/capacity-sufficient branch at
   * loc_8B2D40) to resolve a divergence a prior pass flagged but did not fix:
   *   - append (pos==end): both FUN_008B2770's fast path and FUN_008B2B70's
   *     own tailCount==0 fallback construct the slot via FUN_008B39A0 -- an
   *     unconditional 2-word write, no read of the slot's prior contents.
   *   - mid-insert (pos!=end, tailCount>=1): FUN_008B3630 -> FUN_008B3D30
   *     fill-*constructs* the freshly-grown tail slot begin[size] from
   *     begin[size-1] (same no-read-before-write shape as FUN_008B39A0;
   *     confirmed from FUN_008B3D30.asm -- `mov ecx,[edx]; mov [eax],ecx`
   *     writes the destination unconditionally and never reads
   *     [eax]/[eax+4] first). FUN_008B3660 -> FUN_008B3B90 then
   *     back-shift-*assigns* [pos,size-1) into [pos+1,size) --
   *     FUN_008B3B90.asm DOES read [eax-8] before decrementing/overwriting,
   *     matching `AssignWeakPtrRangeBackward`'s detach-before-relink shape,
   *     correctly, since those destinations are live elements, not raw
   *     storage. FUN_008B3910 finally assigns the new value into the
   *     vacated gap at pos, matching `AssignFillRange`'s single-element
   *     read-before-write shape.
   *
   * The manual shift loop below used to run the read-before-write
   * `ResetFromOwnerLinkSlot` on the newly-grown tail slot too (loop
   * iteration i==size), and the final assign-into-clampedIndex line ran
   * unconditionally even for the append case, where clampedIndex names that
   * same uninitialized tail slot. Both are now split out as
   * `FillConstructRange` calls to match FUN_008B39A0/FUN_008B3D30; the
   * middle-shift loop and the mid-insert gap-assign already matched
   * FUN_008B3B90/FUN_008B3910's read-before-write shape and are unchanged.
   */
  template <class T>
  void InsertWeakPtrVectorObjectAt(
    msvc8::vector<WeakPtr<T>>& weakVector, T* object, const std::size_t index
  )
  {
    auto& view = AsWeakPtrVectorRuntimeView(weakVector);
    const std::size_t size = view.begin ? static_cast<std::size_t>(view.end - view.begin) : 0u;
    const std::size_t clampedIndex = index <= size ? index : size;

    EnsureWeakPtrVectorCapacity(weakVector, size + 1u);

    if (clampedIndex < size) {
      // begin[size] is freshly-grown capacity, not a live element yet:
      // fill-construct it from the current last element first (FUN_008B3D30
      // shape), then back-shift-assign the rest into place (FUN_008B3B90
      // shape, unchanged).
      (void)WeakPtr<T>::FillConstructRange(view.begin + size, 1, view.begin[size - 1]);

      for (std::size_t i = size - 1; i > clampedIndex; --i) {
        view.begin[i].ResetFromOwnerLinkSlot(view.begin[i - 1].ownerLinkSlot);
        view.begin[i - 1].ResetFromObject(nullptr);
      }

      // The vacated gap at clampedIndex is still a live (if logically
      // superseded) element, so the new value is assigned into it,
      // detaching whatever it was previously holding (FUN_008B3910 shape).
      view.begin[clampedIndex].ResetFromObject(object);
    } else {
      // Appending at the end: begin[clampedIndex] (== begin[size]) is
      // uninitialized capacity, so the new value is constructed directly,
      // matching FUN_008B2770's fast path and FUN_008B2B70's own
      // tailCount==0 fallback (both call FUN_008B39A0).
      // Constructed in place rather than staged through a local node: a local
      // would name `object`'s chain without ever being linked into it, and
      // `~WeakPtr` (which unlinks) would then walk that chain for a node that
      // is not there. The one-arg constructor is the same bind-then-link-at-head
      // sequence `FillConstructRange` performs for a single lane.
      ::new (static_cast<void*>(view.begin + clampedIndex)) WeakPtr<T>(object);
    }

    view.end = view.begin + size + 1u;
  }

  template <class T>
  /**
   * Address: 0x006EC170 (FUN_006EC170)
   *
   * What it does:
   * Finds one weak-pointer lane in `[begin, end)` whose bound object pointer
   * equals `object`, returning `end` when no match is present.
   */
  [[nodiscard]] WeakPtr<T>* FindWeakPtrObjectRange(
    WeakPtr<T>* begin,
    WeakPtr<T>* end,
    const T* object
  ) noexcept
  {
    for (WeakPtr<T>* cursor = begin; cursor != end; ++cursor) {
      if (cursor->GetObjectPtr() == object) {
        return cursor;
      }
    }
    return end;
  }

  template <class T>
  [[nodiscard]] bool RemoveWeakPtrVectorObject(msvc8::vector<WeakPtr<T>>& weakVector, const T* object)
  {
    if (!object) {
      return false;
    }

    auto& view = AsWeakPtrVectorRuntimeView(weakVector);
    const std::size_t size = view.begin ? static_cast<std::size_t>(view.end - view.begin) : 0u;
    if (!view.begin || size == 0u) {
      return false;
    }

    WeakPtr<T>* const match = FindWeakPtrObjectRange(view.begin, view.begin + size, object);
    if (match == view.begin + size) {
      return false;
    }

    const std::size_t index = static_cast<std::size_t>(match - view.begin);
    view.begin[index].ResetFromObject(nullptr);
    for (std::size_t j = index + 1; j < size; ++j) {
        view.begin[j - 1].ResetFromOwnerLinkSlot(view.begin[j].ownerLinkSlot);
        view.begin[j].ResetFromObject(nullptr);
    }

    view.end = view.begin + size - 1u;
    return true;
  }

  /**
   * Removes one intrusive weak-pointer entry from a contiguous weak-pointer container.
   *
   * The container is expected to expose `size()`, `operator[]`, and `pop_back()`
   * with elements matching `WeakPtr<T>` semantics.
   */
  template <class TWeakVector>
  void EraseWeakVectorEntry(TWeakVector& weakVector, const std::size_t index) noexcept
  {
    const std::size_t count = weakVector.size();
    if (index >= count) {
      return;
    }

    weakVector[index].ResetFromObject(nullptr);
    for (std::size_t i = index + 1; i < count; ++i) {
      weakVector[i - 1].ResetFromOwnerLinkSlot(weakVector[i].ownerLinkSlot);
      weakVector[i].ResetFromObject(nullptr);
    }
    weakVector.pop_back();
  }
} // namespace moho
