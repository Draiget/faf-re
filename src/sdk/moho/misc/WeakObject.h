#pragma once
#include <cstddef>
#include <cstdint>

namespace moho
{
  template <class T>
  struct WeakPtr;

  /**
   * The head of the chain of `WeakPtr`s aimed at an object. A class that can be
   * weakly referenced derives from this; `WeakPtr<T>` casts to it to find the
   * chain, and each node's `ownerLinkSlot` holds the address of this head.
   */
  class WeakObject
  {
  public:
    /**
     * Drops every weak reference still aimed at this object, blanking each
     * node's owner slot and forward link as it leaves the chain.
     *
     * The destructor runs this, so that a weak holder outliving the owner
     * observes a detached node rather than a dangling owner slot. The walk is
     * destructive and leaves the head slot empty.
     *
     * The compiler inlines it into every owner destructor rather than emitting
     * a callable body, which is why it has no address of its own.
     * `~CScriptObject` (0x004C7340) carries the canonical emission, and it
     * fixes the layout too -- the head is read at `[esi+4]`, i.e. `WeakObject`
     * sits immediately after `CScriptObject`'s vptr:
     *
     *     0x004C73BF  8B 46 04           mov  eax, [esi+4]     ; head
     *     0x004C73C2  85 C0 / 74 24      test eax,eax / jz end
     *   loop:
     *     0x004C73D0  8B 50 04           mov  edx, [eax+4]     ; node->nextInOwner
     *     0x004C73D3  89 56 04           mov  [esi+4], edx     ; head = next
     *     0x004C73D6  C7 00 00 00 00 00  mov  dword [eax], 0   ; ownerLinkSlot = 0
     *     0x004C73DC  C7 40 04 00 ...    mov  dword [eax+4], 0 ; nextInOwner  = 0
     *     0x004C73E3  8B 46 04           mov  eax, [esi+4]     ; reload head
     *     0x004C73E6  85 C0 / 75 E6      test eax,eax / jnz loop
     *
     * Note it re-reads the head each iteration instead of following `edx`, so
     * a node that relinks itself while being blanked is still handled. Three
     * hand-written `ClearWeakObjectChain` copies of this loop (in
     * CScriptObject.cpp, Unit.cpp and CAcquireTargetTask.cpp) were folded back
     * into this member on 2026-09-16; the programmer wrote one method and the
     * compiler inlined it, which is what the single `[esi+4]` shape above says.
     *
     * Defined in WeakPtr.h, where the node type is complete.
     */
    void DetachAllWeakReferences() noexcept;

    /**
     * Drops every weak reference still aimed at the object
     * (`DetachAllWeakReferences`).
     *
     * The binary has this destructor. Every owner runs the drain where the
     * compiler destroys a base or a member, after the owner's own body and
     * after every member declared later, never as a statement of the owner's
     * body:
     * - last base: `~CScriptObject` 0x004C73BF, `~IMauiDragger` 0x0078DB30,
     *   `~CNetTCPConnector` 0x00484BD5, `~CWldTerrainDecal` 0x0089CC5C,
     *   `~UserCommandIssueHelper` 0x008B4049, `IUnit` at the end of `~Unit`
     *   0x006A736E, `UserEntity`'s +0x08 base 0x008B8892;
     * - before the first base: `~CTaskThread` 0x00409149 (then the
     *   `TDatListItem` unlink), `~STaskEventLinkage` 0x00406D59, the wx
     *   windows 0x004F40AE / 0x004F423E (then `~wxDialog`/`~wxFrame`),
     *   `~CAcquireTargetTask`'s two listener bases 0x005D89B9 / 0x005D89E2
     *   (then `~CTask`);
     * - member order: `UserEntity::mAmbientLoop` 0x008B87E2 (between
     *   `mVariableData` and the pose pointers), `UserArmy::mWeakRefs`
     *   0x008B1784 (after `mAvatars`, before `IArmy`'s teardown);
     * - a global: `gDefaultSharedAmbientLoop`'s static destructor
     *   0x004DF190, in reverse declaration order between the mutex after it
     *   and the map before it.
     *
     * Defined in WeakPtr.h, with `DetachAllWeakReferences`.
     */
    ~WeakObject() noexcept;

    // The first `WeakPtr` aimed at this object, or null. Every node on the
    // chain holds this member's address in its `ownerLinkSlot`.
    WeakPtr<void>* weakLinkHead_;
  };

  static_assert(sizeof(WeakObject) == sizeof(void*), "WeakObject must be one pointer");
  // `WeakPtr` uses the object's address as its chain-head slot.
  static_assert(offsetof(WeakObject, weakLinkHead_) == 0, "WeakObject::weakLinkHead_ must lead the object");
} // namespace moho

// The chain's nodes are `WeakPtr`s, and `DetachAllWeakReferences` is defined
// with them.
#include "moho/misc/WeakPtr.h"
