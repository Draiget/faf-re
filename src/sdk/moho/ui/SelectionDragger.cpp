#include "moho/ui/SelectionDragger.h"

#include <algorithm>
#include <cmath>
#include <limits>

#include "gpg/core/containers/FastVector.h"
#include "moho/collision/CGeomSolid3.h"
#include "moho/entity/UserEntity.h"
#include "moho/mesh/Mesh.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/CWldSession.h"
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
