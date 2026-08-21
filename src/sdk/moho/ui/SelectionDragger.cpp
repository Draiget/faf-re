#include "moho/ui/SelectionDragger.h"

#include <algorithm>
#include <cmath>
#include <limits>

#include "gpg/core/containers/FastVector.h"
#include "moho/collision/CGeomSolid3.h"
#include "moho/entity/UserEntity.h"
#include "moho/mesh/Mesh.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/CWldTerrainDecal.h"
#include "moho/render/CWldTerrainDecalTYPETypeInfo.h"
#include "moho/render/SelectionBracketRenderer.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "moho/math/QuaternionMath.h"
#include "moho/entity/Entity.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/CWldSession.h"
#include "moho/terrain/splat/CWldSplat.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/UserUnit.h"

namespace
{
  /**
   * Screen-space distance (in pixels) the cursor has to travel before a press
   * stops being a click and latches into a rubber-band selection.
   *
   * Binary: `ds:0x00DFE5AC` = 4.0f, compared at 0x00864E1A-0x00864E29.
   */
  constexpr float kSelectionDragStretchThresholdPixels = 4.0f;

  /**
   * Half-thickness (in pixels) of each of the four rubber-band border bars, so
   * the drawn frame is two pixels wide.
   *
   * Binary: `ds:0x00DFEC20` = 1.0f, added/subtracted at 0x00865214 onwards.
   */
  constexpr float kSelectionRectBorderHalfWidthPixels = 1.0f;

  /** Translucent black fill of the rubber-band rectangle (0x00865050+0x92). */
  constexpr std::uint32_t kSelectionRectFillColor = 0x30000000u;

  /** Near-opaque white frame around the rubber-band rectangle (0x008651BD). */
  constexpr std::uint32_t kSelectionRectBorderColor = 0xA0FFFFFFu;

  /**
   * Per-vertex modulator for every rubber-band quad: the batcher takes the
   * bound solid-colour texture unmodified (`or eax, 0FFFFFFFFh` before each
   * `DrawQuad` in 0x00865050).
   */
  constexpr std::uint32_t kSelectionRectVertexColor = 0xFFFFFFFFu;

  /**
   * Emits one axis-aligned screen-space rectangle as a single prim-batcher
   * quad.
   *
   * Every `DrawQuad` inside `SelectionDragger2D::Render` builds its four
   * corners in the same order - `(x0,y0) -> (x1,y0) -> (x1,y1) -> (x0,y1)` -
   * so the corner mechanics are lifted here instead of being open-coded five
   * times.
   */
  void DrawSelectionRectQuad(
    moho::CD3DPrimBatcher& batcher,
    const float x0,
    const float y0,
    const float x1,
    const float y1
  )
  {
    batcher.DrawQuad(
      moho::Vector3f(x0, y0, 0.0f),
      moho::Vector3f(x1, y0, 0.0f),
      moho::Vector3f(x1, y1, 0.0f),
      moho::Vector3f(x0, y1, 0.0f),
      kSelectionRectVertexColor
    );
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
   *
   * Invocation: `SelectionDragger::DragRelease` (0x00863870) calls this three
   * times - once per shift-modifier sub-branch to merge the current session
   * selection into a fresh scratch set, once to merge the dragged set into
   * the current selection on the "genuinely new entities" path, and once to
   * pull the winning priority bucket's entries into the final result set.
   */
  moho::SSelectionNodeUserEntity* AddSelectionRange(
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

  /**
   * Texture shared by the 3D dragger's two highlight decals, and also the
   * name bound into each decal's slot-0 name lane.
   *
   * Binary: `aTexturesUiComm_4` at `ds:0x00E47560`, referenced four times
   * inside `SelectionDragger3D::SetTextures` (0x00864950) - twice as the
   * `GetTexture` path and twice as the `SetName` payload.
   */
  constexpr const char* kSelectionHighlightDecalTexturePath =
    "/textures/ui/common/game/selection/selection.dds";

  /**
   * Address: 0x00864A19-0x00864B1F and 0x00864B1F-0x00864C2D
   *          (inlined twice into `Moho::SelectionDragger3D::SetTextures`,
   *          0x00864950)
   *
   * What it does:
   * Creates one terrain highlight decal of the requested type through the
   * decal manager, binds it into `decalSlot`, and forces it into the
   * always-visible state the dragger needs: unrestricted fidelity, the shared
   * selection texture in name slot 0, no near cutoff, and both the LOD cutoff
   * and the spatial-db dissolve cutoff pushed to `FLT_MAX` so the highlight
   * never fades out with camera distance. Flatness optimization is turned off
   * last, because the highlight has to follow terrain relief under the drag
   * box rather than be flattened to a single plane.
   *
   * The binary re-reads the weak slot and re-applies its `-4` downcast before
   * nearly every field write rather than caching one decal pointer, which is
   * what a body that dereferences the weak lane each time compiles to - hence
   * this takes the slot itself, not an already-resolved reference.
   */
  void CreateHighlightDecal(
    moho::CDecalManager& decalManager,
    moho::WeakPtr<moho::CWldTerrainDecal>& decalSlot,
    const moho::EWldTerrainDecalType decalType
  )
  {
    decalSlot.Set(decalManager.LoadDecal(nullptr));

    decalSlot.GetObjectPtr()->mFidelity = 0;
    decalSlot.GetObjectPtr()->mType = decalType;
    decalSlot.GetObjectPtr()->SetName(kSelectionHighlightDecalTexturePath, 0);
    decalSlot.GetObjectPtr()->mNearCutoff = 0.0f;
    decalSlot.GetObjectPtr()->mCutoffLOD = std::numeric_limits<float>::max();
    decalSlot.GetObjectPtr()->mEntry.UpdateDissolveCutoff(std::numeric_limits<float>::max());
    decalSlot.GetObjectPtr()->EnableFlatOptimization(false);
  }

  /**
   * Address: 0x008644B5-0x00864519 and 0x00864519-0x0086457B
   *          (inlined twice into `Moho::SelectionDragger3D::DragMove`,
   *          0x00864340)
   *
   * What it does:
   * Points one highlight decal at the current drag box: horizontal scale from
   * the heading-aligned drag delta (vertical scale pinned to 1.0), origin at
   * the drag anchor, and a pure yaw rotation matching the camera. `Update()`
   * republishes the decal's transform and spatial-db bounds.
   *
   * Both decals receive byte-identical values - only their `mType` differs -
   * so this is one helper called twice rather than two transforms.
   */
  void ApplyHighlightDecalTransform(
    moho::WeakPtr<moho::CWldTerrainDecal>& decalSlot,
    const Wm3::Vector3f& alignedDragExtent,
    const Wm3::Vector3f& anchorPosition,
    const float headingRotation
  )
  {
    moho::CWldTerrainDecal* const decal = decalSlot.GetObjectPtr();

    decal->mScale.x = alignedDragExtent.x;
    decal->mScale.y = 1.0f;
    decal->mScale.z = alignedDragExtent.z;

    decal->mPosition.x = anchorPosition.x;
    decal->mPosition.y = anchorPosition.y;
    decal->mPosition.z = anchorPosition.z;

    decal->mOrientation.x = 0.0f;
    decal->mOrientation.y = headingRotation;
    decal->mOrientation.z = 0.0f;

    decal->Update();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x008637F0 (FUN_008637F0, ??0SelectionDragger@Moho@@...)
   *
   * What it does:
   * Initializes session/camera lanes, captures drag-start screen coordinates
   * from `CWldSession::CursorScreenPos`, and seeds the world position from
   * `CWldSession::CursorWorldPos` when available (otherwise from the
   * process-wide invalid vector singleton). The `mov dword ptr [eax+4], 0` the
   * body opens with (0x008637F0) is the inlined `IMauiDragger` base
   * constructor clearing its own `WeakObject` head, not a member of this
   * class - the compiler emits it from the base initializer.
   */
  SelectionDragger::SelectionDragger(CameraImpl* const camera, CWldSession* const session)
    : mSess(session)
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

  /**
   * Address: 0x00864080 (non-deleting destructor body)
   *
   * What it does:
   * Nothing of its own. The whole body is the inlined base teardown: the vptr
   * restore to `??_7IMauiDragger@Moho@@6B@` at 0x00864080 and the drain loop
   * over `[ecx+4]` at 0x00864090 are `~IMauiDragger` (0x0078DB20), which the
   * compiler emits as base destruction. Kept out-of-line so the address
   * annotation has a definition to sit on.
   */
  SelectionDragger::~SelectionDragger() = default;

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
   * Address: 0x00863870 (FUN_00863870)
   *
   * IDA signature:
   * void __thiscall Moho::SelectionDragger::DragRelease(
   *     Moho::SelectionDragger *this, Moho::SMauiEventData *a2);
   *
   * What it does:
   * Forwards the release event through this dragger's own `DragMove`. If the
   * dragger never produced an active drag, releases the plain click-selection
   * path instead. Otherwise collects the entities the drag volume currently
   * covers and resolves a new session selection:
   *   - Shift held: builds a scratch copy of the current session selection.
   *     If none of the dragged entities were already selected, the result is
   *     "current minus dragged" (a deselect). Otherwise the current selection
   *     is merged into the dragged set and that becomes the new selection.
   *   - Shift not held: every dragged `UserUnit` whose mesh bounds intersect
   *     the dragger's world solid (skipping stationary units mid-upgrade) is
   *     filed into a priority bucket keyed by its blueprint's
   *     `General.SelectionPriority` (forced to 6 for not-yet-built entities in
   *     the `LOWSELECTPRIO` category), scaled per-axis by the blueprint's
   *     `mSelectionMeshScale{X,Y,Z}` lanes. The first non-empty bucket becomes
   *     the new selection.
   *
   * This body does not call the three CWldSession.cpp-local helpers the
   * binary uses internally (`CopySelectionSetFromOther`,
   * `FindSelectionNodeByEntityGuarded`, the vector<WeakEntitySetUserEntity>
   * growth chain rooted at 0x00867890) because those are file-private
   * (anonymous namespace) to that translation unit. The same observable
   * behavior is reached through the public `SSelectionSetUserEntity` API
   * (`Find`, `find`, `Add`, `Iterator_inc`, `IsEmptyAfterPrune`,
   * `ReleaseStorage`), this file's `AddSelectionRange`/`DecodeSelectionEntity`
   * helpers, and the already-recovered generic `msvc8::vector<T>::resize`.
   *
   * Invocation: vtable slot +0x08 of `??_7SelectionDragger@Moho@@6B@`,
   * `??_7SelectionDragger2D@Moho@@6B@` and `??_7SelectionDragger3D@Moho@@6B@`
   * (three constructor-anchored vtables all publish this exact body; neither
   * derived class overrides the slot).
   */
  void SelectionDragger::DragRelease(const SMauiEventData* const eventData)
  {
    DragMove(eventData);

    if (!HasActiveSelectionDrag()) {
      mSess->ReleaseDrag(eventData->mModifiers);
      return;
    }

    ScopedLocalSelectionSet draggedSelectionGuard{};
    SSelectionSetUserEntity& draggedSelection = draggedSelectionGuard.get();
    CollectSelectionDraggerEntities(draggedSelection, *this);

    if ((eventData->mModifiers & MEM_Shift) != 0u) {
      // The binary treats `mSess->mSelection` as mutable here (its own
      // tombstone-pruning walk mutates the tree in place); `GetSelection()`
      // only exposes a const accessor, so bridge that recovery-added
      // restriction rather than the original's actual mutability.
      auto& liveSelection = const_cast<SSelectionSetUserEntity&>(mSess->GetSelection());

      ScopedLocalSelectionSet currentSelectionGuard{};
      SSelectionSetUserEntity& currentSelection = currentSelectionGuard.get();
      if (liveSelection.mHead != nullptr) {
        SSelectionNodeUserEntity* first = liveSelection.mHead->mLeft;
        first = SSelectionSetUserEntity::find(&liveSelection, first, &first);
        (void)AddSelectionRange(currentSelection, liveSelection, first, liveSelection.mHead);
      }

      const std::int32_t missingFromCurrent = draggedSelection.CountEntitiesMissingFrom(currentSelection);
      if (missingFromCurrent >= draggedSelection.size()) {
        // None of the dragged entities were already selected: keep every
        // currently-selected entity that the drag did not cover.
        ScopedLocalSelectionSet keptSelectionGuard{};
        SSelectionSetUserEntity& keptSelection = keptSelectionGuard.get();

        SSelectionNodeUserEntity* node = currentSelection.mHead->mLeft;
        node = SSelectionSetUserEntity::find(&currentSelection, node, &node);
        while (node != currentSelection.mHead) {
          UserEntity* const entity = DecodeSelectionEntity(node->mEnt);

          SSelectionSetUserEntity::FindResult found{};
          (void)SSelectionSetUserEntity::Find(&found, &draggedSelection, entity);
          if (found.mRes == draggedSelection.mHead) {
            SSelectionSetUserEntity::AddResult addResult{};
            (void)SSelectionSetUserEntity::Add(&addResult, &keptSelection, entity);
          }

          SSelectionSetUserEntity::Iterator_inc(&node);
          node = SSelectionSetUserEntity::find(&currentSelection, node, &node);
        }

        mSess->SetSelection(keptSelection);
      } else {
        // At least one dragged entity is genuinely new: merge the current
        // selection into the dragged set and select the union.
        SSelectionNodeUserEntity* first = currentSelection.mHead->mLeft;
        first = SSelectionSetUserEntity::find(&currentSelection, first, &first);
        (void)AddSelectionRange(draggedSelection, currentSelection, first, currentSelection.mHead);

        mSess->SetSelection(draggedSelection);
      }
    } else {
      // No modifier: group intersected entities into per-priority buckets and
      // select the first non-empty one. Buckets are indexed 1-based in the
      // binary (bucket 0 is never used), so `priorityBuckets[i]` holds
      // priority `i + 1`.
      msvc8::vector<SSelectionSetUserEntity> priorityBuckets;
      const CGeomSolid3 selectionSolid = BuildSelectionSolid();

      SSelectionNodeUserEntity* node = draggedSelection.mHead->mLeft;
      node = SSelectionSetUserEntity::find(&draggedSelection, node, &node);
      while (node != draggedSelection.mHead) {
        UserEntity* const entity = DecodeSelectionEntity(node->mEnt);
        UserUnit* const unit = (entity != nullptr) ? entity->IsUserUnit() : nullptr;

        if (unit != nullptr) {
          const IUnit* const unitBridge = GetIUnitBridge(unit);
          // Skip stationary entities that are actively mid-upgrade.
          if (unitBridge->IsMobile() || !unitBridge->IsUnitState(UNITSTATE_BeingUpgraded)) {
            MeshInstance* const meshInstance = unit->mMeshInstance;
            if (meshInstance != nullptr) {
              meshInstance->UpdateInterpolatedFields();
              Wm3::Box3f scoredBox = meshInstance->box;

              const RUnitBlueprint* const blueprint = unitBridge->GetBlueprint();
              scoredBox.Extent[1] *= blueprint->mSelectionMeshScaleX;
              scoredBox.Extent[2] *= blueprint->mSelectionMeshScaleY;
              scoredBox.Extent[0] *= blueprint->mSelectionMeshScaleZ;

              if (selectionSolid.Intersects(scoredBox)) {
                const bool forceLowPriority = unit->mVariableData.mIsBeingBuilt == 1u
                  && unit->IsInCategory(msvc8::string("LOWSELECTPRIO", 13u));
                const std::int32_t priority = forceLowPriority ? 6 : blueprint->General.SelectionPriority;
                const std::uint32_t bucketIndex = (priority > 1) ? static_cast<std::uint32_t>(priority) : 1u;

                if (priorityBuckets.size() < bucketIndex) {
                  const std::size_t oldSize = priorityBuckets.size();
                  priorityBuckets.resize(bucketIndex);
                  for (std::size_t i = oldSize; i < bucketIndex; ++i) {
                    InitializeLocalSelectionSet(priorityBuckets[i]);
                  }
                }

                SSelectionSetUserEntity::AddResult addResult{};
                (void)SSelectionSetUserEntity::Add(&addResult, &priorityBuckets[bucketIndex - 1u], unit);
              }
            }
          }
        }

        SSelectionSetUserEntity::Iterator_inc(&node);
        node = SSelectionSetUserEntity::find(&draggedSelection, node, &node);
      }

      ScopedLocalSelectionSet resultSelectionGuard{};
      SSelectionSetUserEntity& resultSelection = resultSelectionGuard.get();
      for (SSelectionSetUserEntity& bucket : priorityBuckets) {
        if (!bucket.IsEmptyAfterPrune()) {
          SSelectionNodeUserEntity* first = bucket.mHead->mLeft;
          first = SSelectionSetUserEntity::find(&bucket, first, &first);
          (void)AddSelectionRange(resultSelection, bucket, first, bucket.mHead);
          break;
        }
      }

      mSess->SetSelection(resultSelection);

      for (SSelectionSetUserEntity& bucket : priorityBuckets) {
        (void)bucket.ReleaseStorage();
      }
    }
  }

  /**
   * Address: 0x00864CB0 (FUN_00864CB0, ??0SelectionDragger2D@Moho@@QAE@@Z)
   *
   * What it does:
   * Initializes 2D dragger endpoint lanes from the shared invalid-screen
   * sentinel and clears stretch activity state.
   */
  /**
   * Address: 0x00865470 (FUN_00865470, Moho::SelectionDragger2D::Func1)
   *
   * IDA signature:
   * SelectionDragger_vtbl** __thiscall sub_865470(SelectionDragger_vtbl** this, char deleteFlags);
   *
   * What it does:
   * Scalar-deleting-destructor variant — runs the implicit
   * `~SelectionDragger2D()` chain (which forwards into the base
   * `~SelectionDragger` body that releases the intrusive selection
   * link list) and conditionally frees the object's heap storage when
   * bit 0 of `deleteFlags` is set. Matches the binary's `??_G` vtable
   * slot for SelectionDragger2D.
   *
   * Invocation: vtable-slot 0 of `??_7SelectionDragger2D@Moho@@6B@`
   * — invoked indirectly through `delete dragger2D` callsites that go
   * through the SelectionDragger2D vtable.
   */
  SelectionDragger2D* SelectionDragger2D::DeleteWithFlag(const std::uint8_t deleteFlags) noexcept
  {
    this->~SelectionDragger2D();
    if ((deleteFlags & 1u) != 0u) {
      ::operator delete(this);
    }
    return this;
  }

  SelectionDragger2D::SelectionDragger2D(CameraImpl* const camera, CWldSession* const session)
    : SelectionDragger(camera, session)
    , mStretch(0)
    , pad_0025{0, 0, 0}
    , mX1(InvalidSelectionScreenCoord())
    , mY1(InvalidSelectionScreenCoord())
  {}

  /**
   * Address: 0x00864D10 (FUN_00864D10, ??1SelectionDragger2D@Moho@@UAE@XZ)
   * Mangled: ??1SelectionDragger2D@Moho@@UAE@XZ
   *
   * IDA signature:
   * SelectionDragger_vtbl* __stdcall sub_864D10(SelectionDragger_vtbl** this);
   *
   * What it does:
   * Derived-destructor body for `SelectionDragger2D`. Drops every node from the
   * process-global `sSelectionBrackets` weak-set by taking the full-range erase
   * path (identical to the binary's inlined `DestroySubtree(head->mParent)` +
   * head/size reset sequence at 0x864D37-0x864D64). The base `~SelectionDragger()`
   * chains automatically afterwards to unlink the intrusive selection-link list
   * and restore the IMauiDragger base vtable (binary 0x864D67-0x864D84).
   *
   * Invocation: reached from `SelectionDragger2D::DeleteWithFlag` (0x00865470,
   * the `??_G` scalar-deleting-dtor vtable slot), which calls this dtor before
   * conditionally freeing the object.
   */
  SelectionDragger2D::~SelectionDragger2D()
  {
    SSelectionNodeUserEntity* cursor =
      sSelectionBrackets.mHead != nullptr ? sSelectionBrackets.mHead->mLeft : nullptr;
    (void)sSelectionBrackets.EraseRange(&cursor, cursor, sSelectionBrackets.mHead);
  }

  /**
   * Address: 0x00864DB0 (FUN_00864DB0, Moho::SelectionDragger2D::Func2)
   * Mangled: vtable slot +0x04 of ??_7SelectionDragger2D@Moho@@6B@ (0x00E47A48)
   *
   * IDA signature:
   * void __thiscall Moho::SelectionDragger2D::Func2(
   *     Moho::SelectionDragger2D *this, int a2);
   *
   * What it does:
   * Stores the event's cursor position as the drag-end corner, latches
   * `mStretch` once the straight-line drag distance passes the click
   * threshold, then rebuilds the highlighted-unit bracket set: everything the
   * current drag volume covers is collected into a scratch weak-set and copied
   * into the process-global `sSelectionBrackets` (which is emptied first).
   *
   * Invocation: vtable slot +0x04 of `??_7SelectionDragger2D@Moho@@6B@`. The
   * matching dispatch site is 0x008638A3 (`call edx` with
   * `edx = [[this]+4]`) inside `SelectionDragger::DragRelease` (0x00863870),
   * which forwards the release event through the dragger's own `DragMove`
   * before resolving the selection.
   */
  void SelectionDragger2D::DragMove(const SMauiEventData* const eventData)
  {
    mX1 = eventData->mMousePos.x;
    mY1 = eventData->mMousePos.y;

    const float dragX = mX0 - mX1;
    const float dragY = mY0 - mY1;
    const bool stretchedPastClick =
      std::sqrt((dragX * dragX) + (dragY * dragY)) > kSelectionDragStretchThresholdPixels;
    // Latching `or`, not an assignment: once a drag has stretched it stays
    // stretched even if the cursor returns to the press point (0x00864E34).
    mStretch = static_cast<std::uint8_t>(mStretch | (stretchedPastClick ? 1u : 0u));

    SSelectionSetUserEntity draggedSelection{};
    InitializeLocalSelectionSet(draggedSelection);
    CollectSelectionDraggerEntities(draggedSelection, *this);

    // Drop last frame's brackets. The binary open-codes the full-range erase
    // (`DestroySubtree(head->mParent)` plus the head/size reset) at
    // 0x00864E71-0x00864EA4; `EraseRange` over `[head->mLeft, head)` is that
    // same teardown through the one owning helper.
    SSelectionNodeUserEntity* bracketCursor =
      sSelectionBrackets.mHead != nullptr ? sSelectionBrackets.mHead->mLeft : nullptr;
    (void)sSelectionBrackets.EraseRange(&bracketCursor, bracketCursor, sSelectionBrackets.mHead);

    SSelectionNodeUserEntity* node = draggedSelection.mHead->mLeft;
    node = SSelectionSetUserEntity::find(&draggedSelection, node, &node);
    while (node != draggedSelection.mHead) {
      SSelectionSetUserEntity::AddResult addResult{};
      (void)SSelectionSetUserEntity::Add(&addResult, &sSelectionBrackets, DecodeSelectionEntity(node->mEnt));

      SSelectionSetUserEntity::Iterator_inc(&node);
      node = SSelectionSetUserEntity::find(&draggedSelection, node, &node);
    }

    (void)draggedSelection.ReleaseStorage();
  }

  /**
   * Address: 0x00865050 (FUN_00865050, Moho::SelectionDragger2D::Func4)
   * Mangled: vtable slot +0x10 of ??_7SelectionDragger2D@Moho@@6B@ (0x00E47A54)
   *
   * IDA signature:
   * void __thiscall Moho::SelectionDragger2D::Func4(
   *     Moho::SelectionDragger2D *this, Moho::CD3DPrimBatcher *a3);
   *
   * What it does:
   * Draws the rubber-band rectangle. Nothing is emitted until the drag has
   * stretched past the click threshold. Otherwise the drag endpoints are
   * canonicalized into a screen rectangle, one translucent black quad fills it,
   * and four near-opaque white bars are drawn one pixel outside/inside each
   * edge to frame it.
   *
   * Invocation: vtable slot +0x10 of `??_7SelectionDragger2D@Moho@@6B@`. The
   * dispatch site is 0x0086F06D (`call edx` with `edx = [[esi-4]+0x10]`,
   * `ecx = esi-4`) inside `Moho::CUIWorldView::Draw` (0x0086EF40), which
   * recovers the `IMauiDragger*` from its current-dragger intrusive link at
   * `+0x29C` and hands the prim batcher straight through.
   */
  void SelectionDragger2D::Render(CD3DPrimBatcher* const batcher)
  {
    if (!HasActiveSelectionDrag()) {
      return;
    }

    // Screen space: y grows downward, so the smaller y is the top edge.
    const float left = std::min(mX1, mX0);
    const float right = std::max(mX1, mX0);
    const float top = std::min(mY1, mY0);
    const float bottom = std::max(mY1, mY0);

    batcher->SetTexture(CD3DBatchTexture::FromSolidColor(kSelectionRectFillColor));
    DrawSelectionRectQuad(*batcher, left, bottom, right, top);

    constexpr float kEdge = kSelectionRectBorderHalfWidthPixels;
    batcher->SetTexture(CD3DBatchTexture::FromSolidColor(kSelectionRectBorderColor));
    DrawSelectionRectQuad(*batcher, left - kEdge, top + kEdge, right + kEdge, top - kEdge);
    DrawSelectionRectQuad(*batcher, left - kEdge, bottom + kEdge, right + kEdge, bottom - kEdge);
    DrawSelectionRectQuad(*batcher, left - kEdge, bottom - kEdge, left + kEdge, top + kEdge);
    DrawSelectionRectQuad(*batcher, right - kEdge, bottom - kEdge, right + kEdge, top + kEdge);
  }

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
   * Address: 0x008640F0 (FUN_008640F0, ??0SelectionDragger3D@Moho@@...)
   *
   * What it does:
   * Chains the `SelectionDragger` base constructor, installs this class's own
   * vtable, clears the stretch/active latch and the pending drag-end world
   * position (seeded to the shared invalid-vector sentinel, matching the
   * base constructor's own `mPos` seeding), zeroes the two highlight-decal
   * weak-reference slots and the owned highlight-texture shared-pointer
   * lane, and caches this view's decal manager
   * (`session->mWldMap->mTerrainRes->GetDecalManager()`, matching
   * 0x00864193-0x008641A1's `[[session+0x1C]+4]` vtable-slot-0x130 dispatch,
   * confirmed as `IWldTerrainRes::GetDecalManager()`) for later use by
   * `DragMove`/`~SelectionDragger3D` (both not yet recovered - see the class
   * doc comment in SelectionDragger.h).
   *
   * The binary performs every one of these field writes unconditionally with
   * no null check on `session` (0x00864193 dereferences `[edi+0x1C]`
   * directly); this recovery matches that exactly rather than adding a
   * defensive guard the original does not have. The sole caller
   * (`func_NewSelectionDragger2D`/`NewSelectionDragger`, 0x00865880) always
   * supplies a live session.
   */
  SelectionDragger3D::SelectionDragger3D(CameraImpl* const camera, CWldSession* const session)
    : SelectionDragger(camera, session)
    , mStretch(0)
    , pad_0025{0, 0, 0}
    , mDragEndPos(Invalid<Wm3::Vector3f>())
    , mAlbedoDecal()
    , mWaterAlbedoDecal()
    , mHighlightTexture()
    , mDecalManager(session->mWldMap->mTerrainRes->GetDecalManager())
  {}

  /**
   * Address: 0x00864C90 (FUN_00864C90, Moho::SelectionDragger3D::Func1)
   *
   * What it does:
   * Scalar-deleting-destructor variant for `SelectionDragger3D` - delegates
   * to the destructor chain and conditionally releases the object's heap
   * storage when bit 0 of `deleteFlags` is set. See the class doc comment in
   * SelectionDragger.h: the destructor this chains into is the
   * compiler-generated implicit one (still correctly chains to the base
   * `~SelectionDragger()`), not a 1:1 port of the binary's 0x008641C0 body.
   */
  SelectionDragger3D* SelectionDragger3D::DeleteWithFlag(const std::uint8_t deleteFlags) noexcept
  {
    this->~SelectionDragger3D();
    if ((deleteFlags & 1u) != 0u) {
      ::operator delete(this);
    }
    return this;
  }

  /**
   * Address: 0x00864340 (FUN_00864340, Moho::SelectionDragger3D::Func2)
   * Mangled: vtable slot +0x04 of ??_7SelectionDragger3D@Moho@@6B@ (0x00E47A28)
   *
   * IDA signature:
   * void __thiscall Moho::SelectionDragger3D::Func2(
   *     Moho::SelectionDragger3D *this, Moho::SMauiEventData *a2);
   *
   * What it does:
   * One pointer-drag step of the volumetric dragger. Latches `mStretch` once
   * the cursor has travelled past the click threshold, then unprojects the
   * cursor onto the terrain surface. The first sample that lands on a valid
   * surface while `mPos` is still the invalid sentinel *anchors* `mPos` and
   * returns - there is no box yet. Every later sample stores the surface
   * point in `mDragEndPos`, ensures the two highlight decals exist, stretches
   * them across the camera-heading-aligned delta between anchor and cursor,
   * and rebuilds the global bracket set from everything the drag volume now
   * covers.
   *
   * Invocation: vtable slot +0x04 of `??_7SelectionDragger3D@Moho@@6B@`,
   * dispatched at 0x008638A3 (`call edx`, `edx = [[this]+4]`) inside
   * `SelectionDragger::DragRelease` (0x00863870).
   */
  void SelectionDragger3D::DragMove(const SMauiEventData* const eventData)
  {
    const float cursorX = eventData->mMousePos.x;
    const float cursorY = eventData->mMousePos.y;

    const float dragX = cursorX - mX0;
    const float dragY = cursorY - mY0;
    const bool stretchedPastClick =
      std::sqrt((dragX * dragX) + (dragY * dragY)) > kSelectionDragStretchThresholdPixels;
    // Latching `or` (0x008643BD), not an assignment: once a drag has
    // stretched it stays stretched even if the cursor comes back.
    mStretch = static_cast<std::uint8_t>(mStretch | (stretchedPastClick ? 1u : 0u));

    Wm3::Vector2f cursorPoint{};
    cursorPoint.x = cursorX;
    cursorPoint.y = cursorY;

    const Wm3::Vector3f surfacePoint = mCam->CameraScreenToSurface(cursorPoint);
    if (!IsValidVector3f(surfacePoint)) {
      return;
    }

    if (!IsValidVector3f(mPos)) {
      // First surface-valid sample of this drag: anchor it and stop. The
      // binary writes the three lanes individually here (0x008643F7) rather
      // than assigning the vector wholesale as the `mDragEndPos` path below
      // does.
      mPos.x = surfacePoint.x;
      mPos.y = surfacePoint.y;
      mPos.z = surfacePoint.z;
      return;
    }

    mDragEndPos.x = surfacePoint.x;
    mDragEndPos.y = surfacePoint.y;
    mDragEndPos.z = surfacePoint.z;

    SetTextures();

    // The decals are yaw-rotated *against* the camera, and the drag delta is
    // rotated into that same frame, so the box stays screen-aligned however
    // the camera is turned. `BuildSelectionSolid` (0x00864670) reaches the
    // same frame from the other direction - it orients by `+heading` and
    // rotates the delta by the conjugate.
    const float headingRotation = -mCam->CameraGetHeading();

    Wm3::Vector3f worldDelta{};
    worldDelta.x = mDragEndPos.x - mPos.x;
    worldDelta.y = mDragEndPos.y - mPos.y;
    worldDelta.z = mDragEndPos.z - mPos.z;

    const Wm3::Quaternionf headingOrientation = COORDS_Orient(headingRotation, 0.0f);

    Wm3::Vector3f alignedDragExtent{};
    MultQuadVec(&alignedDragExtent, &worldDelta, &headingOrientation);

    ApplyHighlightDecalTransform(mAlbedoDecal, alignedDragExtent, mPos, headingRotation);
    ApplyHighlightDecalTransform(mWaterAlbedoDecal, alignedDragExtent, mPos, headingRotation);

    ScopedLocalSelectionSet draggedSelection;
    CollectSelectionDraggerEntities(draggedSelection.get(), *this);

    ClearSelectionBrackets();

    SSelectionNodeUserEntity* node = draggedSelection.get().mHead->mLeft;
    node = SSelectionSetUserEntity::find(&draggedSelection.get(), node, &node);
    while (node != draggedSelection.get().mHead) {
      SSelectionSetUserEntity::AddResult addResult{};
      (void)SSelectionSetUserEntity::Add(&addResult, &sSelectionBrackets, DecodeSelectionEntity(node->mEnt));

      SSelectionSetUserEntity::Iterator_inc(&node);
      node = SSelectionSetUserEntity::find(&draggedSelection.get(), node, &node);
    }
  }

  /**
   * Address: 0x00864950 (FUN_00864950, Moho::SelectionDragger3D::SetTextures)
   *
   * IDA signature:
   * void __stdcall Moho::SelectionDragger3D::SetTextures(
   *     Moho::SelectionDragger3D *a1);
   *
   * What it does:
   * Lazily brings up this dragger's two terrain highlight decals. Returns
   * immediately once `mAlbedoDecal` resolves to a live decal, so the
   * per-motion `DragMove` call only ever builds them once. Otherwise it loads
   * the shared selection texture, creates an `Albedo` decal for land and a
   * `WaterAlbedo` decal for water - identical apart from `mType`, so the
   * highlight paints across both surfaces - and raises both to the front of
   * the manager's draw order so nothing else overdraws them.
   *
   * Invocation: called once from `SelectionDragger3D::DragMove` (0x00864340)
   * at 0x00864441, on the branch that has just latched a valid drag-end
   * world position.
   */
  void SelectionDragger3D::SetTextures()
  {
    // 0x0086496E-0x0086497D: load the weak slot, apply its `-4` downcast, and
    // bail when the result is non-null. `mAlbedoDecal` and `mWaterAlbedoDecal`
    // are always created together, so testing the first covers both.
    if (mAlbedoDecal.GetObjectPtr() != nullptr) {
      return;
    }

    ID3DDeviceResources::TextureResourceHandle highlightTexture;
    D3D_GetDevice()->GetResources()->GetTexture(
      highlightTexture, kSelectionHighlightDecalTexturePath, nullptr, true
    );
    mHighlightTexture = highlightTexture;

    // `mDecalManager` is the `IDecalManager*` the terrain resource handed out,
    // and the binary reaches both of the calls below through its vtable
    // (+0x1C `LoadDecal`, +0x4C `MoveDecalToFront`). Those two slots live in
    // the block `CDecalManager` has not yet promoted into its declared virtual
    // table, so - exactly as `CConCommand.cpp`'s `NewSplatAt` call site and
    // `CWldSession.cpp`'s `AddDecals`/`ProcessRemovals` call sites already do -
    // they are reached through the sole implementing class. `CDecalManager` is
    // the only class deriving from `IDecalManager` in this binary, so this is
    // behaviourally identical to the virtual dispatch it stands in for.
    CDecalManager& decalManager = *static_cast<CDecalManager*>(mDecalManager);

    CreateHighlightDecal(decalManager, mAlbedoDecal, WldTerrainDecalType_Albedo);
    CreateHighlightDecal(decalManager, mWaterAlbedoDecal, WldTerrainDecalType_WaterAlbedo);

    // Water first, then land (0x00864C2D then 0x00864C45): each call moves its
    // decal to index 0, so issuing them in this order leaves the land decal
    // frontmost.
    decalManager.MoveDecalToFront(mWaterAlbedoDecal.GetObjectPtr());
    decalManager.MoveDecalToFront(mAlbedoDecal.GetObjectPtr());
  }

  /**
   * Address: 0x00864C80 (FUN_00864C80, Moho::SelectionDragger3D::Func4)
   * Mangled: vtable slot +0x10 of ??_7SelectionDragger3D@Moho@@6B@
   *
   * What it does:
   * Empty override (`retn 4` in the binary) - the 3D dragger draws its
   * highlight through terrain decals updated by `DragMove`, not through the
   * shared prim batcher.
   */
  void SelectionDragger3D::Render(CD3DPrimBatcher*)
  {}

  /**
   * Address: 0x00864670 (FUN_00864670, Moho::SelectionDragger3D::Func5)
   *
   * What it does:
   * Builds one oriented world-space box between the inherited `mPos` (the
   * drag anchor, latched once by `DragMove`) and `mDragEndPos` (the endpoint
   * `DragMove` rewrites on every later sample): orients a 3x3 frame from the
   * active camera's heading via
   * `COORDS_Orient`/`QuatToMatrix`, sets the box center to the midpoint of
   * the two points, sets the box's horizontal extents from the two points'
   * delta rotated into that frame (via `MultQuadVec` with the conjugate
   * orientation), and leaves the vertical extent (`Extent[1]`) at `FLT_MAX`
   * so the volume is unbounded in that axis - i.e. an infinitely tall,
   * heading-aligned column between the drag start and end points.
   */
  CGeomSolid3 SelectionDragger3D::BuildSelectionSolid() const
  {
    const Wm3::Quaternionf headingOrientation = COORDS_Orient(mCam->CameraGetHeading(), 0.0f);

    Wm3::Quaternionf inverseHeadingOrientation{};
    inverseHeadingOrientation.x = headingOrientation.x;
    inverseHeadingOrientation.y = -0.0f - headingOrientation.y;
    inverseHeadingOrientation.z = -0.0f - headingOrientation.z;
    inverseHeadingOrientation.w = -0.0f - headingOrientation.w;

    Wm3::Vector3f worldDelta{};
    worldDelta.x = mDragEndPos.x - mPos.x;
    worldDelta.y = mDragEndPos.y - mPos.y;
    worldDelta.z = mDragEndPos.z - mPos.z;

    Wm3::Vector3f localDelta{};
    MultQuadVec(&localDelta, &worldDelta, &inverseHeadingOrientation);

    Wm3::Box3f box{};
    box.Center.x = (mDragEndPos.x + mPos.x) * 0.5f;
    box.Center.y = (mDragEndPos.y + mPos.y) * 0.5f;
    box.Center.z = (mDragEndPos.z + mPos.z) * 0.5f;
    QuatToMatrix(&headingOrientation, box.Axis);
    box.Extent[0] = std::fabs(localDelta.x * 0.5f);
    box.Extent[1] = std::numeric_limits<float>::max();
    box.Extent[2] = std::fabs(localDelta.z * 0.5f);

    return CGeomSolid3(box);
  }

  /**
   * Address: 0x00864320 (FUN_00864320, Moho::SelectionDragger3D::Func6)
   *
   * What it does:
   * Returns whether the drag latched active (`mStretch`) and the current
   * cursor world position is valid.
   */
  bool SelectionDragger3D::HasActiveSelectionDrag() const
  {
    return mStretch != 0u && IsValidVector3f(mPos);
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
    // Heap-backed: `CollectInVolume` takes the base `gpg::fastvector<T>&`,
    // whose grow path frees `start_` without an `originalVec_` test. See the
    // note in CWldSession::DoBeat.
    gpg::fastvector<UserEntity*> collectedEntities;

    auto* const spatialDb = reinterpret_cast<SpatialDB_MeshInstance*>(dragger.mSess->GetEntitySpatialDbStorage());
    (void)spatialDb->CollectInVolume(collectedEntities, ENTITYTYPE_Unit, &selectionSolid);

    AddCollectedEntitiesToSelection(outSelection, collectedEntities);
    PruneDraggedSelectionToSelectableUnits(outSelection, *dragger.mSess);
  }
} // namespace moho
