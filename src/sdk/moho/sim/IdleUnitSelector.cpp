#include "moho/sim/IdleUnitSelector.h"

#include <cstddef>
#include <cstdint>

#include "moho/collision/CColPrimitiveBox3f.h"
#include "moho/entity/UserEntity.h"
#include "moho/mesh/Mesh.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/sim/CWldSession.h"
#include "moho/unit/Broadcaster.h"
#include "Wm3AxisAlignedBox3.h"
#include "Wm3Box3.h"

namespace moho
{
  static_assert(sizeof(IdleUnitSelector) == 0x20, "IdleUnitSelector complete-object size must be 0x20");

  namespace
  {
    /**
     * Address: 0x00868690 (FUN_00868690)
     *
     * What it does:
     * The test `OnEvent` uses to decide the selection changed. Both empty is
     * the same, one empty is different; otherwise every entry of `lhs` is
     * compared with every entry of `rhs` and any mismatch is a difference. So
     * two non-empty sets only count as the same when each holds one unit and
     * it is the same unit. Each `begin()` prunes, as every walk does.
     */
    [[nodiscard]] bool HoldTheSameUnit(const WeakSet<UserEntity>& lhs, const WeakSet<UserEntity>& rhs)
    {
      const bool lhsEmpty = lhs.begin() == lhs.end();
      if (lhsEmpty && rhs.begin() == rhs.end()) {
        return true;
      }
      if ((lhs.begin() == lhs.end()) != (rhs.begin() == rhs.end())) {
        return false;
      }

      for (UserEntity* const left : lhs) {
        for (UserEntity* const right : rhs) {
          if (left != right) {
            return false;
          }
        }
      }
      return true;
    }

    IdleUnitSelector& GlobalIdleUnitSelector() noexcept;
  } // namespace

  /**
   * Address: 0x00865490 (FUN_00865490, IdleUnitSelector process-global constructor)
   *
   * What it does:
   * `mIdleSet` comes up empty and the focus cycle at step 0.
   */
  IdleUnitSelector::IdleUnitSelector()
    : mIdleSet()
    , mFocusStep(0)
  {}

  /**
   * Address: 0x00865780 (FUN_00865780, IdleUnitSelector process-global
   * destructor)
   *
   * What it does:
   * `mIdleSet`'s destructor (full-range erase, free the head), then the
   * `Listener` base's unlink; the body itself is empty.
   *
   * The binary reaches this destructor through a compiler-generated,
   * argument-less thunk (`FUN_00C07510`, `void sub_C07510() { sub_865780();
   * }`) registered with `atexit()` by the static-init thunk at
   * `FUN_00BE6160` (`sub_865490(); return atexit(sub_C07510);`) - the
   * standard MSVC "destroy this one function-local static" pattern, the
   * same shape already established for `SelectionListener`'s
   * `FUN_00C075D0`/`FUN_00BE62E0` pair. `GlobalIdleUnitSelector()`'s
   * `static IdleUnitSelector sSelector;` magic static reproduces that
   * atexit registration automatically, so `FUN_00C07510`/the explicit
   * `atexit()` call have no separate source-level counterpart here.
   */
  IdleUnitSelector::~IdleUnitSelector() = default;

  /**
   * Address: 0x008656A0 (FUN_008656A0)
   *
   * What it does:
   * Subscribes this listener to the session's selection broadcaster
   * (`session + 0x00`); the node is at complete-object +0x08.
   */
  void IdleUnitSelector::AttachToSessionListenerLane(CWldSession* const session)
  {
    session->mSelectionBroadcaster.AddListener(this);
  }

  /**
   * Address: 0x008656E0 (FUN_008656E0)
   *
   * What it does:
   * Detaches this idle-selector listener node from its current lane and
   * leaves it self-linked.
   */
  void IdleUnitSelector::DetachFromSessionListenerLane(CWldSession* const)
  {
    ListUnlink();
  }

  /**
   * Address: 0x00865540 (FUN_00865540)
   *
   * What it does:
   * `this` is the `Listener` sub-object (+0x04). Unless the new selection
   * holds the same unit as the cycle's copy (0x00868690), the copy is cleared
   * (the set's whole-tree erase, `_Erase` 0x007B0870) and the cycle restarts.
   */
  void IdleUnitSelector::OnEvent(const SSelectionEvent event)
  {
    if (HoldTheSameUnit(mIdleSet, *event.mCurrentSelection)) {
      return;
    }

    mIdleSet.Clear();
    mFocusStep = 0;
  }

  void IdleUnitSelector::CycleCameraFocus(const WeakSet<UserEntity>& selection, CameraImpl* const camera)
  {
    IdleUnitSelector& selector = GlobalIdleUnitSelector();
    switch (selector.mFocusStep) {
      case 0:
        selector.mFocusStep = 1;
        selector.mIdleSet = selection;
        return;

      case 1:
        camera->TargetEntities(selection, false, camera->CameraGetTargetZoom(), 0.0f);
        selector.mFocusStep = 2;
        return;

      case 2: {
        UserEntity* const first = *selection.begin();
        MeshInstance* const meshInstance = first->mMeshInstance;
        const Wm3::Box3f* meshBox = &Invalid<Wm3::Box3f>();
        if (meshInstance != nullptr) {
          meshInstance->UpdateInterpolatedFields();
          meshBox = &meshInstance->box;
        }
        const Wm3::Box3f orientedBox(*meshBox);
        Wm3::AxisAlignedBox3f frameBox{};
        orientedBox.ComputeAABB(frameBox.Min, frameBox.Max);

        camera->TargetBox(frameBox, 0.0f);
        camera->TargetNothing();
        selector.mFocusStep = 1;
        return;
      }

      default:
        return;
    }
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
      (void)WLD_AddOnTeardownCallback(static_cast<ISessionListener*>(&selector));
      return true;
    }();
  } // namespace
} // namespace moho
