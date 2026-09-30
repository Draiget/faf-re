#pragma once

#include <cstddef>
#include <cstdint>
#include <new>

#include "legacy/containers/Vector.h"
#include "moho/misc/WeakObject.h"
#include "moho/sim/SimThreadRole.h"

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


  /**
   * Moho's intrusive weak pointer: an 8-byte node on a singly linked chain that
   * its owner keeps in a `WeakObject`.
   *
   * `ownerLinkSlot` is the address of that chain's head (the owner's
   * `WeakObject`, or null), and `nextInOwner` threads the chain. The owner never
   * learns who points at it: every node links itself onto the head as it gets a
   * target, splices itself back out as it drops it, and the owner blanks
   * whatever is still on the chain when it dies
   * (`WeakObject::DetachAllWeakReferences`).
   *
   * Everything below is built on two moves, which is also how the binary reads:
   * `LinkAtOwnerHead` (push-front) and `UnlinkFromOwner` (walk to the node and
   * splice it out). The walk has no null test: a node with a slot is always on
   * the chain that slot heads, so the binary never looks for the end.
   */
  template <class T>
  struct WeakPtr
  {
    inline static gpg::RType* sType = nullptr;

    void* ownerLinkSlot;     // the owner's weak-chain head (`EncodeOwnerLinkSlot`), or null
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
     * Points at `object` and links onto the front of its weak chain. A member
     * built this way in a constructor's initialiser list is the "bind, then
     * push-front with no prior unlink" every recovered constructor used to spell
     * out by hand.
     */
    explicit WeakPtr(T* const object) noexcept
      : ownerLinkSlot(EncodeOwnerLinkSlot(object))
    {
      LinkAtOwnerHead();
    }

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
     * counterpart to `operator=` below. Every relinking copy an
     * `msvc8::vector` of weak pointers (or of a struct holding one) emits --
     * `uninit_fill_n`, `uninit_copy_n` -- is this constructor in a loop.
     *
     * Address: 0x00686D50 (FUN_00686D50 -- this constructor emitted out of line,
     * node in EAX, source in ECX; zero callers, no pointer or jump to it anywhere
     * in the image. Formerly `LinkBackLinkNodeFromBackRefOwner` in
     * moho/entity/EntityDb.cpp (RULE THREE), removed 2026-09-22.)
     */
    WeakPtr(const WeakPtr<T>& other) noexcept
      : ownerLinkSlot(other.ownerLinkSlot)
    {
      LinkAtOwnerHead();
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
     *
     * There is no self-assignment test (0x00836B90 opens with
     * `cmp [edx], ecx; jz ret`): assigning a node to itself compares equal
     * slots and does nothing.
     */
    WeakPtr<T>& operator=(const WeakPtr<T>& other) noexcept
    {
      ResetFromOwnerLinkSlot(other.ownerLinkSlot);
      return *this;
    }

    ~WeakPtr() noexcept;

    /**
     * The weak-chain head `object` is referenced through, null for a null
     * object.
     *
     * An owner keeps that chain in its `WeakObject` base, and this is the cast
     * to it: the compiler supplies the base offset and the null guard, which is
     * the `obj ? obj + N : 0` the binary emits at every encode -- `+0x04` for
     * `CMauiControl` (0x0079DB80), `+0x14` for `UnitWeapon`, whose
     * `CScriptObject` sits behind its `CTaskEvent` (0x00632CA0), `+0x170` and
     * `+0x178` for the managed wx dialog and frame. An owner with several
     * `WeakObject`s, or none, says where its chain is with a static
     * `WeakLinkHeadOf` of its own.
     */
    [[nodiscard]] static void* EncodeOwnerLinkSlot(T* const object) noexcept
    {
      if constexpr (requires { T::WeakLinkHeadOf(object); }) {
        return T::WeakLinkHeadOf(object);
      } else {
        WeakObject* const weak = object;
        return weak;
      }
    }

    /**
     * Address: 0x0057D540 (FUN_0057D540)
     *
     * What it does:
     * Decodes one weak owner-link slot back to the owning object pointer:
     * `slot ? slot - N : 0`, the downcast from the owner's `WeakObject`.
     * Address: 0x006860D0 (FUN_006860D0 -- this accessor emitted out of line,
     * node in EAX: `slot ? slot - 4 : 0`; zero callers, no pointer or jump to it
     * anywhere in the image. Formerly `ResolveBackLinkNodeOwner` in
     * moho/entity/EntityDb.cpp (RULE THREE), removed 2026-09-22.)
     */
    [[nodiscard]] static T* DecodeOwnerObject(void* const slot) noexcept
    {
      if constexpr (requires { T::FromWeakLinkHead(slot); }) {
        return T::FromWeakLinkHead(slot);
      } else {
        return static_cast<T*>(static_cast<WeakObject*>(slot));
      }
    }

    /** True while this node is on an owner's chain, i.e. points at something. */
    [[nodiscard]] bool HasValue() const noexcept
    {
      return ownerLinkSlot != nullptr;
    }

    /**
     * Address: 0x00485830 (FUN_00485830 -- the `WeakPtr<CNetTCPConnector>`
     *   emission, node in EAX: `slot ? slot - 4 : 0`. Called from
     *   `CNetTCPConnector::Pull` (0x0048534B) after each connection's `Pull`;
     *   ICF twin of 0x0057D540 above. Formerly `HasLinkedOwner` over an
     *   `STcpConnWorkFrame` overlay in moho/net/CNetTCPConnector.cpp,
     *   removed 2026-09-28.)
     *
     * What it does:
     * Returns the object this node refers to, or null once the owner has
     * detached its weak references.
     */
    [[nodiscard]] T* GetObjectPtr() const noexcept
    {
      return DecodeOwnerObject(ownerLinkSlot);
    }

    /**
     * True when this node refers to `object`. This is the comparison
     * `std::find` makes when a `vector<WeakPtr<T>>` is searched for a raw
     * `T*`: `CUnitCommand::RemoveUnit` finds its own queue entry that way.
     */
    [[nodiscard]] friend bool operator==(const WeakPtr<T>& weak, const T* const object) noexcept
    {
      return weak.GetObjectPtr() == object;
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
     * Drops the target: off the owner's chain, both words null. The same as
     * `Set(nullptr)`.
     */
    void UnlinkFromOwnerChain() noexcept
    {
      ResetFromOwnerLinkSlot(nullptr);
    }

    /**
     * Blanks both words without touching any chain.
     *
     * Only correct on a node that is on no chain. The binary does this where a
     * node is being built in place: `CAiTarget`'s decode from an `SSTITarget`
     * (0x005E2650) and ground-target paths write `[this+4] = [this+8] = 0` over
     * fresh storage.
     */
    void ClearLinkState() noexcept
    {
      ownerLinkSlot = nullptr;
      nextInOwner = nullptr;
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
     * Moves this node to the chain `newOwnerLinkSlot` heads: nothing when that
     * is already its chain, otherwise off the old one and onto the front of the
     * new one (or `nextInOwner = 0` for a null slot).
     * Address: 0x007A5610 (FUN_007A5610 -- `WeakPtr<T>::ResetFromOwnerLinkSlot` (unlink from the old chain, relink at the requested owner head); callers 0x007A4970; formerly `RebindIntrusiveOwnerSlotNodeRuntime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-10.)
     */
    void ResetFromOwnerLinkSlot(void* const newOwnerLinkSlot) noexcept
    {
      if (newOwnerLinkSlot == ownerLinkSlot) {
        return;
      }

      UnlinkFromOwner();
      ownerLinkSlot = newOwnerLinkSlot;
      LinkAtOwnerHead();
    }

    /**
     * Address: 0x00836BD0 (FUN_00836BD0 -- `WeakPtr<T>::ResetFromObject` (the owner's weak-link head at +0x08); `UserUnit::UpdateUnitData` 0x008C0750; callers 0x008C0750; formerly `RelinkIntrusiveNodeViaOwnerOffset08` in moho/containers/LegacyContainerRuntime.cpp (RULE ONE), file removed 2026-09-10.)
     * Address: 0x00632CA0 (FUN_00632CA0 -- the `WeakPtr<UnitWeapon>` emission,
     *   identified by its owner-link offset: the body's `add ecx, 0x14` is
     *   the `UnitWeapon` -> `WeakObject` base cast, and `UnitWeapon` is the
     *   only owner whose `WeakObject` sits at 0x14. The rest matches `ResetFromOwnerLinkSlot` instruction
     *   for instruction, including the null-slot branch that writes
     *   `nextInOwner = nullptr`. Zero callers, unreachable; formerly
     *   `AttachNodeToOwnerHead` over an `IntrusiveOwnerHeadRuntimeView` in
     *   moho/animation/IAniManipulator.cpp (RULE ONE), removed 2026-09-22.)
     * Address: 0x0066A2A0 (FUN_0066A2A0 -- the `WeakPtr<WWinManagedFrame>` emission
     *   (`lea edx, [ecx+178h]` is its `WeakObject` base, after the wxFrame);
     *   caller EFX_CreateEmitterWindow 0x0066A007; formerly
     *   `RebindManagedWindowSlotToFrame` in moho/console/CConCommand.cpp, removed
     *   with the wx conversion.)
     * Address: 0x004F7230 (FUN_004F7230 -- the `WeakPtr<WWinManagedDialog>`
     *   emission (`lea edx, [ecx+170h]`), the slot in EAX and the dialog in
     *   ECX; zero callers, a linker-retained copy.)
     * Address: 0x004F72F0 (FUN_004F72F0 -- a second
     *   `WeakPtr<WWinManagedFrame>` emission (`lea edx, [ecx+178h]`) in the
     *   managed-window TU; zero callers.)
     * Address: 0x0079DB80 (FUN_0079DB80 -- the `WeakPtr<CMauiControl>`
     *   emission: node in EAX, control in ECX, `lea edx, [ecx+4]`. Callers
     *   `MAUI_SetKeyboardFocus` 0x0079CC10 (`Maui_CurrentFocusControl`),
     *   `cfunc_CMauiScrollbarSetScrollableL` 0x007A1820
     *   (`CMauiScrollbar::mScrollable`) and `func_OnMouseMove` 0x007A4970
     *   (the stack hit-control link and the mouse-over global). Formerly
     *   `RebindIntrusiveOwnerLink`/`SetCurrentFocusControlLink` in
     *   moho/ui/UiRuntimeTypes.cpp, removed 2026-09-25.)
     * Address: 0x0084E330 (FUN_0084E330 -- the `WeakPtr<CMauiCursor>`
     *   emission, `lea edx, [ecx+4]`; caller `CUIManager::SetCursor`
     *   0x0084D000 (`CUIManager::mCursor`). Formerly
     *   `CMauiCursorLink::AssignCursor`, removed 2026-09-25.)
     * Address: 0x00873810 (FUN_00873810 -- the `WeakPtr<ISelectionDragger>`
     *   emission, `lea edx, [ecx+4]`; caller `CUIWorldView::HandleEvent`
     *   0x00870E35 (`CUIWorldView::mSelectionDragger`, right after
     *   `NewSelectionDragger`). Formerly `BindWorldViewOverlayDragger` in
     *   moho/ui/UiRuntimeTypes.cpp, removed 2026-09-25.)
     * Address: 0x008AEC20 (FUN_008AEC20 -- the `WeakPtr<UserArmy>` emission
     *   (the army's chain head at +0x1E0); caller
     *   `CUserSoundManager::SetListenerArmy` (`mListenerArmy`). Formerly
     *   `RelinkArmyHook` over a `ListenerArmyHook` look-alike in
     *   moho/audio/CUserSoundManager.cpp, removed 2026-09-30.)
     *
     * All three share `function_sha256` 5c93862d...: one 70-byte body,
     * emitted once per owner type.
     */
    void ResetFromObject(T* const object) noexcept
    {
      ResetFromOwnerLinkSlot(EncodeOwnerLinkSlot(object));
    }

    /**
     * Address: 0x0057D4F0 (FUN_0057D4F0, Moho::WeakPtr_Unit::Set -- the
     *   `WeakPtr<Unit>` emission: `slot = unit ? unit + 4 : 0`, unlink from the
     *   old chain, link at the new head, with no other test. It used to be a
     *   separate specialization here because the generic body carried sentinel
     *   checks the binary does not have.)
     */
    void Set(T* const object) noexcept
    {
      ResetFromObject(object);
    }

  private:
    /** The chain `ownerLinkSlot` heads: the owner's `WeakObject`, read as a node pointer. */
    [[nodiscard]] WeakPtr<T>** OwnerChainHead() const noexcept
    {
      return static_cast<WeakPtr<T>**>(ownerLinkSlot);
    }

    /**
     * Pushes this node onto the front of the chain `ownerLinkSlot` heads, or
     * sets `nextInOwner` to null when there is none (0x0057D640..0x0057D64E):
     *
     *     test edx, edx / mov [eax], edx / jz null
     *     mov  ecx, [edx]      ; head
     *     mov  [eax+4], ecx    ; nextInOwner = head
     *     mov  [edx], eax      ; head = this
     * Address: 0x007AE140 (FUN_007AE140 -- the `WeakPtr<UserEntity>` emission: `slot = entity ? entity + 8 : 0`, pushed onto the chain; no caller, a retained copy. Formerly `LinkSelectionWeakOwnerRef` in moho/sim/CWldSession.cpp, removed 2026-09-30.)
     */
    void LinkAtOwnerHead() noexcept
    {
      if (ownerLinkSlot == nullptr) {
        nextInOwner = nullptr;
        return;
      }

      MOHO_ASSERT_NOT_SIM_WORKER("WeakPtr owner-chain link");
      WeakPtr<T>** const head = OwnerChainHead();
      nextInOwner = *head;
      *head = this;
    }

    /**
     * Splices this node out of the chain it is on and leaves its own two words
     * alone (0x0057D621..0x0057D63F, and all of `~WeakPtr`). The walk stops at
     * this node and nowhere else: there is no null test, because a node with a
     * slot is on that slot's chain.
     * Address: 0x0066AF90 (FUN_0066AF90 -- the `WeakPtr<UserEntity>` emission of the splice-out walk, returning the slot it stopped on; callers the camera's target-list node teardown 0x007A71B0, 0x007A75A0, `TargetEntities` 0x007A8640, `TargetNoseCam` 0x007A8A20 and 0x00842920. Formerly `UnlinkSelectionWeakOwnerRefNoReset` in moho/sim/CWldSession.cpp, removed 2026-09-30.)
     * Address: 0x0082BA90 (FUN_0082BA90 -- the `WeakPtr<UserCommandIssueHelper>` emission, the destructor of the rebuild's inserted stack link (0x008B7211 in 0x008B6F60). Formerly `UnlinkCommandQueueOwnerEntry` in moho/unit/core/UserUnit.cpp, removed 2026-09-30.)
     */
    void UnlinkFromOwner() noexcept
    {
      if (ownerLinkSlot == nullptr) {
        return;
      }

      MOHO_ASSERT_NOT_SIM_WORKER("WeakPtr owner-chain link");
      WeakPtr<T>** cursor = OwnerChainHead();
      while (*cursor != this) {
        cursor = &(*cursor)->nextInOwner;
      }
      *cursor = nextInOwner;
    }
  };

  static_assert(sizeof(WeakPtr<void>) == 0x08, "WeakPtr<T> must be 8 bytes");
  static_assert(offsetof(WeakPtr<void>, ownerLinkSlot) == 0x00, "WeakPtr<T>::ownerLinkSlot offset must be 0x00");
  static_assert(offsetof(WeakPtr<void>, nextInOwner) == 0x04, "WeakPtr<T>::nextInOwner offset must be 0x04");

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
   * Address: 0x0079DB60 (FUN_0079DB60 -- the `WeakPtr<CMauiControl>`
   * emission, same `function_sha256` as 0x005A6DE0; the MAUI dispatch paths
   * reach it by tail-jump, e.g. the out-of-line chunk of
   * `MAUI_SetKeyboardFocus` at 0x00B78323. Formerly the unlink half of
   * `RebindIntrusiveOwnerLink` in moho/ui/UiRuntimeTypes.cpp.)
   * Address: 0x00485810 (FUN_00485810 -- the `WeakPtr<CNetTCPConnector>`
   * emission, reached only by `jmp` from the unwind funclets of
   * `CNetTCPConnection::Pull` (0x00BAEFF6) and `CNetTCPConnector::Pull`
   * (0x00BB3486), whose normal paths inline it. Formerly `LinkWorkFrame` /
   * `UnlinkWorkFrame` over an `STcpConnWorkFrame` overlay in
   * moho/net/CNetTCPConnector.cpp, removed 2026-09-28.)
   * Address: 0x005C2360 (FUN_005C2360 -- the `WeakPtr<Unit>` emission, `this`
   * in ECX: `SReconKey`'s destructor, which is nothing but its weak pointer's.
   * Callers `CAiReconDBImpl::GenerateNewBlips` 0x005C0A70 (the key temporary
   * built for each `mBlipMap.insert`), `ReconTick` 0x005C0C40,
   * `ReconGetJamingBlips` 0x005C20C0 and 0x005C6210. Formerly
   * `UnlinkKeyFromSourceChain` in moho/ai/CAiReconDBImpl.cpp, which nothing
   * called, removed 2026-09-30.)
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
   * destructor, or `DetachAllWeakReferences`) dereferences whatever has since
   * reused the storage. That was the `0xF2B8458D` / `0x00C4669D` "corrupt
   * `ownerLinkSlot`" class of fault: the owners' drains were always correct,
   * the departures were not.
   *
   * The walk runs until it finds this node, exactly as the binary does. It
   * used to stop on a null cursor as well, to survive nodes that had been given
   * a slot without being linked onto it; the constructors that did that
   * (`BindObjectUnlinked` followed later, or never, by a link) now construct
   * the pointer instead.
   */
  template <class T>
  inline WeakPtr<T>::~WeakPtr() noexcept
  {
    UnlinkFromOwner();
  }

  inline void WeakObject::DetachAllWeakReferences() noexcept
  {
    while (weakLinkHead_ != nullptr) {
      WeakPtr<void>* const node = weakLinkHead_;
      weakLinkHead_ = node->nextInOwner;
      node->ownerLinkSlot = nullptr;
      node->nextInOwner = nullptr;
    }
  }

} // namespace moho
