#include "moho/ui/SelectionDragger.h"

#include <algorithm>
#include <limits>
#include <new>

#include "gpg/core/containers/FastVector.h"
#include "moho/collision/CGeomSolid3.h"
#include "moho/entity/UserEntity.h"
#include "moho/mesh/Mesh.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/CWldSession.h"
#include "moho/unit/core/UserUnit.h"

namespace
{
  class ISelectionDraggerRuntimeLane
  {
  public:
    ISelectionDraggerRuntimeLane() noexcept
      : mSelectionListHead(nullptr)
    {}

    virtual ~ISelectionDraggerRuntimeLane() = default;

  public:
    moho::SelectionDraggerLink* mSelectionListHead; // +0x04
  };
  static_assert(sizeof(ISelectionDraggerRuntimeLane) == 0x08, "ISelectionDraggerRuntimeLane size must be 0x08");
  static_assert(
    offsetof(ISelectionDraggerRuntimeLane, mSelectionListHead) == 0x04,
    "ISelectionDraggerRuntimeLane::mSelectionListHead offset must be 0x04"
  );

  /**
   * Address: 0x00864040 (FUN_00864040)
   *
   * What it does:
   * Constructs one selection-dragger interface base lane by clearing the
   * intrusive list-head pointer and installing the interface vtable.
   */
  [[maybe_unused]] ISelectionDraggerRuntimeLane* InitializeISelectionDraggerRuntimeLane(
    ISelectionDraggerRuntimeLane* const outLane
  ) noexcept
  {
    return ::new (outLane) ISelectionDraggerRuntimeLane();
  }

  [[nodiscard]] float InvalidSelectionScreenCoord() noexcept
  {
    static bool initialized = false;
    static float invalidCoord = 0.0f;
    if (!initialized) {
      initialized = true;
      invalidCoord = std::numeric_limits<float>::quiet_NaN();
    }
    return invalidCoord;
  }

  [[nodiscard]] moho::UserEntity* DecodeSelectionEntity(
    const moho::SSelectionWeakRefUserEntity& weakRef
  ) noexcept
  {
    if (weakRef.mOwnerLinkSlot == nullptr) {
      return nullptr;
    }

    constexpr std::uintptr_t kSelectionOwnerLinkOffset = offsetof(moho::UserEntity, mIUnitChainHead);
#if defined(MOHO_ABI_MSVC8_COMPAT)
    static_assert(kSelectionOwnerLinkOffset == 0x08, "UserEntity selection weak-link offset must stay 0x08");
#endif

    const std::uintptr_t raw = reinterpret_cast<std::uintptr_t>(weakRef.mOwnerLinkSlot);
    if (raw < kSelectionOwnerLinkOffset) {
      return nullptr;
    }

    return reinterpret_cast<moho::UserEntity*>(raw - kSelectionOwnerLinkOffset);
  }

  /**
   * Address: 0x00868AF0 (FUN_00868AF0)
   *
   * What it does:
   * Imports one collected `UserEntity*` range into a selection weak-set,
   * preserving the original weak-owner guard semantics through
   * `SSelectionSetUserEntity::Add`.
   */
  void AddCollectedEntitiesToSelection(
    moho::SSelectionSetUserEntity& selection,
    const gpg::fastvector<moho::UserEntity*>& entities
  )
  {
    for (moho::UserEntity* const entity : entities) {
      moho::SSelectionSetUserEntity::AddResult addResult{};
      (void)moho::SSelectionSetUserEntity::Add(&addResult, &selection, entity);
    }
  }

  /**
   * Address: 0x00863E20 (FUN_00863E20)
   *
   * What it does:
   * Removes dragged weak-set entries that the owning world session cannot
   * select, while preserving the cheat override path handled by
   * `CWldSession::CanSelectUnit`.
   */
  void PruneDraggedSelectionToSelectableUnits(
    moho::SSelectionSetUserEntity& selection,
    moho::CWldSession& session
  )
  {
    if (selection.mHead == nullptr) {
      return;
    }

    moho::SSelectionNodeUserEntity* node = selection.mHead->mLeft;
    node = moho::SSelectionSetUserEntity::find(&selection, node, &node);
    while (node != selection.mHead) {
      moho::UserEntity* const entity = DecodeSelectionEntity(node->mEnt);
      if (session.CanSelectUnit(reinterpret_cast<moho::UserUnit*>(entity))) {
        moho::SSelectionSetUserEntity::Iterator_inc(&node);
        node = moho::SSelectionSetUserEntity::find(&selection, node, &node);
        continue;
      }

      moho::SSelectionNodeUserEntity* next = node;
      moho::SSelectionSetUserEntity::Iterator_inc(&next);
      next = moho::SSelectionSetUserEntity::find(&selection, next, &next);
      (void)selection.EraseRange(&node, node, next);
      node = next;
    }
  }

  /**
   * Address: 0x00868A00 (FUN_00868A00)
   *
   * What it does:
   * Adds every live entity from one weak-set iterator range into another
   * selection weak-set.
   */
  [[maybe_unused]] moho::SSelectionNodeUserEntity* AddSelectionRange(
    moho::SSelectionSetUserEntity& destination,
    moho::SSelectionSetUserEntity& source,
    moho::SSelectionNodeUserEntity* first,
    moho::SSelectionNodeUserEntity* const last
  )
  {
    moho::SSelectionNodeUserEntity* node = first;
    while (node != last) {
      moho::UserEntity* const entity = DecodeSelectionEntity(node->mEnt);
      moho::SSelectionSetUserEntity::AddResult addResult{};
      (void)moho::SSelectionSetUserEntity::Add(&addResult, &destination, entity);

      moho::SSelectionSetUserEntity::Iterator_inc(&node);
      node = moho::SSelectionSetUserEntity::find(&source, node, &node);
    }

    return node;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x008637F0 (FUN_008637F0, ??0SelectionDragger@Moho@@...)
   *
   * What it does:
   * Initializes list/session/camera lanes, captures drag-start screen
   * coordinates from `CWldSession::CursorScreenPos`, and seeds the world
   * position from `CWldSession::CursorWorldPos` when available (otherwise
   * from the process-wide invalid vector singleton).
   */
  SelectionDragger::SelectionDragger(CameraImpl* const camera, CWldSession* const session)
    : mSelectionListHead(nullptr)
    , mSess(session)
    , mCam(camera)
    , mX0(0.0f)
    , mY0(0.0f)
    , mPos(Invalid<Wm3::Vector3f>())
  {
    if (session == nullptr) {
      return;
    }

    if (session->mCursorWorldState[0] != 0u) {
      mPos = session->CursorWorldPos;
    }

    mX0 = session->CursorScreenPos.x;
    mY0 = session->CursorScreenPos.y;
  }

  SelectionDragger::~SelectionDragger()
  {
    while (mSelectionListHead != nullptr) {
      SelectionDraggerLink* const next = mSelectionListHead->mNext;
      mSelectionListHead->mOwnerHead = nullptr;
      mSelectionListHead->mNext = nullptr;
      mSelectionListHead = next;
    }
  }

  /**
   * Address: 0x00864000 (FUN_00864000, Moho::SelectionDragger::dtr)
   *
   * What it does:
   * Runs dragger cleanup and conditionally frees this object when bit 0 of
   * `deleteFlags` is set.
   */
  SelectionDragger* SelectionDragger::DeleteWithFlag(const std::uint8_t deleteFlags) noexcept
  {
    this->~SelectionDragger();
    if ((deleteFlags & 1u) != 0u) {
      ::operator delete(this);
    }
    return this;
  }

  /**
   * Address: 0x00864CB0 (FUN_00864CB0, ??0SelectionDragger2D@Moho@@QAE@@Z)
   *
   * What it does:
   * Initializes 2D dragger endpoint lanes from the shared invalid-screen
   * sentinel and clears stretch activity state.
   */
  SelectionDragger2D::SelectionDragger2D(CameraImpl* const camera, CWldSession* const session)
    : SelectionDragger(camera, session)
    , mStretch(0)
    , pad_0025{0, 0, 0}
    , mX1(InvalidSelectionScreenCoord())
    , mY1(InvalidSelectionScreenCoord())
  {}

  /**
   * Address: 0x00864FC0 (FUN_00864FC0, Moho::SelectionDragger2D::Func5)
   *
   * What it does:
   * Canonicalizes drag endpoints into a min/max screen rectangle and
   * unprojects that rectangle into a world-space solid through the active
   * camera.
   */
  CGeomSolid3 SelectionDragger2D::BuildSelectionSolid() const
  {
    gpg::Rect2f screenRect{};
    screenRect.x0 = std::min(mX0, mX1);
    screenRect.x1 = std::max(mX0, mX1);
    screenRect.z0 = std::min(mY0, mY1);
    screenRect.z1 = std::max(mY0, mY1);
    return mCam->CameraGetView().Unproject(screenRect);
  }

  /**
   * Address: 0x00864DA0 (FUN_00864DA0, Moho::SelectionDragger2D::Func6)
   *
   * What it does:
   * Returns whether the dragger has stretched beyond the click threshold and
   * should produce a selection volume.
   */
  bool SelectionDragger2D::HasActiveSelectionDrag() const
  {
    return mStretch != 0u;
  }

  /**
   * Address: 0x00863F10 (FUN_00863F10)
   *
   * What it does:
   * Builds a temporary drag volume, gathers unit entities from the session
   * spatial DB, imports them into `outSelection`, and prunes anything the
   * session is not allowed to select.
   */
  void CollectSelectionDraggerEntities(SSelectionSetUserEntity& outSelection, SelectionDragger& dragger)
  {
    if (!dragger.HasActiveSelectionDrag()) {
      return;
    }

    CGeomSolid3 selectionSolid = dragger.BuildSelectionSolid();
    gpg::fastvector_n<UserEntity*, 20> collectedEntities;

    auto* const spatialDb = reinterpret_cast<SpatialDB_MeshInstance*>(dragger.mSess->GetEntitySpatialDbStorage());
    (void)spatialDb->CollectInVolume(collectedEntities, ENTITYTYPE_Unit, &selectionSolid);

    AddCollectedEntitiesToSelection(outSelection, collectedEntities);
    PruneDraggedSelectionToSelectableUnits(outSelection, *dragger.mSess);
  }
} // namespace moho
