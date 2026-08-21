#include "moho/sim/IdleUnitSelector.h"

#include <cstddef>
#include <cstdint>

#include "moho/sim/CWldSession.h"
#include "moho/unit/Broadcaster.h"

namespace moho
{
  static_assert(sizeof(IdleUnitSelector) == 0x20, "IdleUnitSelector complete-object size must be 0x20");

  /**
   * Address: 0x00865490 (FUN_00865490, IdleUnitSelector process-global constructor)
   *
   * What it does:
   * Initializes `mIdleSet` as an empty weak-entity set: buys the self-linked
   * sentinel head through `InitWeakEntitySetHead` and clears the trailing
   * `mSizeMirrorOrUnused` lane. Matches the binary's explicit field-by-field
   * setup - `WeakEntitySetUserEntity`/`SSelectionSetUserEntity` are bare
   * structs with no member default constructors of their own.
   */
  IdleUnitSelector::IdleUnitSelector()
  {
    InitWeakEntitySetHead(mIdleSet);
    mIdleSet.mSizeMirrorOrUnused = 0u;
  }

  /**
   * Address: 0x008656A0 (FUN_008656A0)
   *
   * What it does:
   * Detaches this idle-selector listener node from its current lane and
   * reinserts it immediately before the provided lane anchor. Operates on
   * `Listener<SSelectionEvent>::mListenerLink`, inherited at complete-object
   * +0x08 - confirmed by reading/writing that exact offset from the
   * unadjusted (primary-vtable) `this` in the binary.
   */
  void IdleUnitSelector::AttachToSessionListenerLane(void* const laneContext)
  {
    auto* const laneAnchor = static_cast<Broadcaster*>(laneContext);
    this->mListenerLink.ListLinkBefore(laneAnchor);
  }

  /**
   * Address: 0x008656E0 (FUN_008656E0)
   *
   * What it does:
   * Detaches this idle-selector listener node from its current lane and
   * leaves it self-linked.
   */
  void IdleUnitSelector::DetachFromSessionListenerLane(void* const laneContext)
  {
    (void)laneContext;
    this->mListenerLink.ListUnlink();
  }

  /**
   * Address: 0x00865540 (FUN_00865540)
   *
   * What it does:
   * Compares `mIdleSet`'s live entity keys against `event.mCurrentSelection`
   * via `HasSameLiveEntitySet`; when they differ, destroys every tracked
   * idle-set node and resets the red-black tree head back to its empty
   * self-linked sentinel state, including the `mSizeMirrorOrUnused` lane.
   *
   * The binary inlines the reset as a direct
   * `DestroySubtree(mHead->mParent)` call plus three head self-loop stores
   * (it does not go through `EraseRange`'s generic range-erase dispatch).
   * `DestroySubtree` is a private `SSelectionSetUserEntity` member, so this
   * reuses the public `EraseRange` full-range fast path instead - for a
   * `first == mHead->mLeft, last == mHead` call, `EraseRange` performs the
   * identical `DestroySubtree(head->mParent)` + head self-loop + `mSize = 0`
   * sequence internally. `mSizeMirrorOrUnused` is reset explicitly afterward
   * to match the binary's final store, since `EraseRange` does not touch
   * that lane.
   */
  void IdleUnitSelector::OnEvent(const SSelectionEvent event)
  {
    if (mIdleSet.HasSameLiveEntitySet(*event.mCurrentSelection)) {
      return;
    }

    SSelectionNodeUserEntity* cursor = mIdleSet.mHead->mLeft;
    (void)mIdleSet.EraseRange(&cursor, mIdleSet.mHead->mLeft, mIdleSet.mHead);
    mIdleSet.mSizeMirrorOrUnused = 0u;
  }

  namespace
  {
    /**
     * Address: 0x010C4408 (.data, IdleUnitSelector singleton instance).
     *
     * The engine constructs exactly one `IdleUnitSelector` for the process
     * lifetime, matching the sibling `SelectionListener`/`PauseListener`
     * singletons.
     */
    IdleUnitSelector& GlobalIdleUnitSelector() noexcept
    {
      static IdleUnitSelector sSelector;
      return sSelector;
    }

    /**
     * Address: 0x00BE6160 (FUN_00BE6160, IdleUnitSelector static-init thunk).
     *
     * What it does:
     * Constructs the process-global `IdleUnitSelector` instance (0x00865490)
     * and registers it with the world-session loader's teardown/attach
     * callback vector, exactly matching `SelectionListener`'s
     * `kSelectionListenerStaticInit` shape. The binary registers the raw
     * object address before either vtable is written; the callback vector is
     * never read before real process teardown, so registering after full
     * construction here is behaviorally identical.
     */
    [[maybe_unused]] const bool kIdleUnitSelectorStaticInit = []() noexcept {
      IdleUnitSelector& selector = GlobalIdleUnitSelector();
      (void)WLD_AddOnTeardownCallback(reinterpret_cast<IWldTeardownCallback*>(&selector));
      return true;
    }();
  } // namespace
} // namespace moho
