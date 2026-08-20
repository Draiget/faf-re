#include "moho/ui/UiRuntimeTypes.h"

#include <cmath>
#include <cstdint>

#include "gpg/core/containers/Rect2.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/ui/EMauiKeyCodeTypeInfo.h"
#include "legacy/containers/List.h"
#include "moho/math/Wm3DistanceFafExtras.h"
#include "moho/mesh/Mesh.h"
#include "moho/render/ProjectileArcRenderer.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/CWldSession.h"
#include "moho/command/CommandManager.h"
#include "moho/command/CommandIssueHelper.h"
#include "moho/entity/REntityBlueprintTypeInfo.h"
#include "moho/sim/STIMap.h"
#include "moho/unit/core/UserUnit.h"

namespace moho
{

  /**
   * Address: 0x0086EE00 (FUN_0086EE00, Moho::CRenderWorldView::Render)
   * Slot: 0
   *
   * IDA signature:
   * void __thiscall Moho::CRenderWorldView::Render(CRenderWorldView* this,
   *   CD3DPrimBatcher* batcher, int renderPass, CWldMap* map, float deltaT);
   *
   * What it does:
   * Draws every world-space overlay this view owns for one frame, in the
   * binary's order: resource splats, strategic icons, projectile icons and
   * arcs, mesh previews, command splats, the economy readout, and finally the
   * command graph through slot 2.
   *
   * Resource splats and strategic icons are suppressed together whenever the
   * view hides resources or the free camera is active. `IsMiniMap` is
   * dispatched and its result dropped - the binary calls the slot and never
   * reads eax (0x0086EE4E..0x0086EE56).
   *
   * Argument note: every `fld` in this function reads `[ebp+10h]`, the `map`
   * parameter (`D9 45 10` at 0x0086EE58/EE84/EEAC/EED4/EEF2/EF16);
   * `[ebp+14h]`, `deltaSeconds`, is loaded only for `RenderProjectileIcons`
   * and the slot-2 tail. That is why `RenderProjectileArcs` and
   * `DrawEconomyOverlay` take the map as their trailing argument rather than
   * the `float interpolant` both were first recovered with.
   */
  void CRenderWorldView::Render(
    CD3DPrimBatcher* const batcher,
    const int renderPass,
    CWldMap* const map,
    const float deltaSeconds
  )
  {
    if (!mHideResources && !cam_Free) {
      if (mEnableResourceRendering) {
        GeomCamera3* const resourceView = const_cast<GeomCamera3*>(&mCamera->CameraGetView());
        if (UI_RenResources) {
          mWldSession->RenderResources(resourceView, batcher);
        }
      }

      // `IsMiniMap()`'s result is NOT dropped: 0x0086EE5B pushes the returned
      // `eax` as the last of the five stack slots this call site sets up, and
      // `RenderStrategicIcons` forwards it to its custom-name and
      // selection-set label passes so the minimap draws status bars without
      // text. (An earlier pass recorded this dispatch as side-effect-only.)
      mWldSession->RenderStrategicIcons(mCamera, batcher, map, IsMiniMap());
    }

    mWldSession->RenderProjectileIcons(mCamera, this, batcher, map, deltaSeconds);

    if (UI_RenProjectileArcs) {
      RenderProjectileArcs(
        mWldSession, const_cast<GeomCamera3*>(&mCamera->CameraGetView()), batcher, map
      );
    }

    // The binary re-fetches the camera view before each of the next two passes
    // and discards it; neither takes a camera argument.
    (void)mCamera->CameraGetView();
    mWldSession->RenderMeshPreviews();

    (void)mCamera->CameraGetView();
    mWldSession->DrawCommandSplats();

    mWldSession->DrawEconomyOverlay(mCamera, batcher, map);

    RenderCommandGraph(batcher, renderPass, map, deltaSeconds);
  }

  /**
   * Address: 0x0086ECB0 (FUN_0086ECB0, Moho::CRenderWorldView::Func1)
   * Slot: 1
   *
   * IDA signature:
   * int __thiscall sub_86ECB0(Moho::CRenderWorldView *this);
   *
   * What it does:
   * Per-frame pre-render hook: re-runs the build-drag preview so the ghost
   * meshes under the cursor track this frame's command mode and drag endpoints.
   * Minimap views have no build drag, so they skip it.
   *
   * This is the slot `WRenViewport::RenderAllHeads` dispatches once per
   * registered world view at the head of every frame.
   */
  void CRenderWorldView::Func1()
  {
    if (mIsMiniMap) {
      return;
    }

    mBuildDrag.UpdateDragPreview();
  }

  /**
   * Address: 0x0086EBF0 (FUN_0086EBF0, Moho::CRenderWorldView::GetCamera)
   * Slot: 3
   *
   * What it does:
   * Returns the camera this view renders through.
   */
  CameraImpl* CRenderWorldView::GetCamera()
  {
    return mCamera;
  }

  /**
   * Address: 0x0086EBE0 (FUN_0086EBE0, Moho::CRenderWorldView::GetCameraView)
   * Slot: 4
   *
   * What it does:
   * Forwards to the camera's view payload (a tail call through the camera's
   * own vtable in the binary).
   */
  GeomCamera3* CRenderWorldView::GetCameraView()
  {
    return const_cast<GeomCamera3*>(&mCamera->CameraGetView());
  }

  /**
   * Address: 0x0086EC00 (FUN_0086EC00, Moho::CRenderWorldView::GetCameraOffset)
   * Slot: 5
   *
   * What it does:
   * Forwards to the camera's positional offset lane.
   */
  Wm3::Vector3f* CRenderWorldView::GetCameraOffset()
  {
    return const_cast<Wm3::Vector3f*>(&mCamera->CameraGetOffset());
  }

  /**
   * Address: 0x0086EC10 (FUN_0086EC10, Moho::CRenderWorldView::CameraGetTargetZoom)
   * Slot: 6
   */
  float CRenderWorldView::CameraGetTargetZoom()
  {
    return mCamera->CameraGetTargetZoom();
  }

  /**
   * Address: 0x0086EC20 (FUN_0086EC20, Moho::CRenderWorldView::GetMaxZoom)
   * Slot: 7
   */
  float CRenderWorldView::GetMaxZoom()
  {
    return mCamera->GetMaxZoom();
  }

  /**
   * Address: 0x0086EC30 (FUN_0086EC30, Moho::CRenderWorldView::CameraGetZoom)
   * Slot: 8
   */
  float CRenderWorldView::CameraGetZoom()
  {
    return mCamera->CameraGetZoom();
  }

  /**
   * Address: 0x0086DC90 (FUN_0086DC90, Moho::CRenderWorldView::IsMiniMap)
   * Slot: 10
   */
  bool CRenderWorldView::IsMiniMap()
  {
    return mIsMiniMap;
  }

  /**
   * Address: 0x0086DC00 (FUN_0086DC00, Moho::CRenderWorldView::SetOrthographic)
   * Slot: 11
   *
   * What it does:
   * Stores the orthographic toggle and mirrors it onto the camera. Going
   * orthographic disables camera shake; leaving it re-enables shake.
   */
  void CRenderWorldView::SetOrthographic(const bool orthographicEnabled)
  {
    mOrthographic = orthographicEnabled;

    if (mCamera == nullptr) {
      return;
    }

    mCamera->CameraSetOrtho(orthographicEnabled);
    mCamera->CanShake(!orthographicEnabled);
  }

  /**
   * Address: 0x0086DC60 (FUN_0086DC60, Moho::CRenderWorldView::CanShake)
   * Slot: 12
   *
   * What it does:
   * Returns the stored orthographic toggle - the binary reuses this one byte
   * for both lanes, so an orthographic view reports "can shake".
   */
  bool CRenderWorldView::CanShake()
  {
    return mOrthographic;
  }

  /**
   * Address: 0x0082A120 (FUN_0082A120, sub_82A120)
   *
   * IDA signature:
   * void __cdecl sub_82A120(int a1, int a2, int a3, _DWORD *a4, int a5, float a6);
   *
   * What it does:
   * Ramer-Douglas-Peucker simplification of one path span. Finds the sampled
   * point lying furthest from the straight line between `first` and `last`; if
   * that distance clears `tolerance` the point is kept and the two halves are
   * simplified in turn, otherwise the whole span collapses to its endpoints.
   *
   * The kept point is inserted *before* `insertBefore`, and the left half then
   * recurses against the newly inserted node while the right half recurses
   * against the original position - which is what leaves `simplified` in path
   * order without a sort.
   */
  void SimplifyPathSpan(
    const msvc8::vector<Wm3::Vector3f>& points,
    const std::int32_t first,
    const std::int32_t last,
    msvc8::list<Wm3::Vector3f>& simplified,
    const msvc8::list<Wm3::Vector3f>::iterator insertBefore,
    const float tolerance
  )
  {
    const Wm3::Segment3f span = Wm3::MakeSegment3fFromEndpoints(points[first], points[last]);

    std::int32_t farthest = -1;
    float farthestDistance = 0.0f;
    for (std::int32_t index = first + 1; index < last; ++index) {
      const float distance = Wm3::DistVector3Segment3fGet(points[index], span);
      if (distance > farthestDistance) {
        farthestDistance = distance;
        farthest = index;
      }
    }

    if (farthestDistance <= tolerance) {
      return;
    }

    const msvc8::list<Wm3::Vector3f>::iterator inserted = simplified.insert(insertBefore, points[farthest]);
    SimplifyPathSpan(points, first, farthest, simplified, inserted, tolerance);
    SimplifyPathSpan(points, farthest, last, simplified, insertBefore, tolerance);
  }

  /**
   * Address: 0x0082A2B0 (FUN_0082A2B0, sub_82A2B0)
   *
   * IDA signature:
   * int __usercall sub_82A2B0@<eax>(Moho::WeakSet_UserEntity *ebx0@<ebx>);
   *
   * What it does:
   * Picks the unit a path preview should be drawn for: the deepest one in the
   * selection, measured by its blueprint's Z size. Units still under
   * construction and units whose blueprint has no resolved footprint are
   * skipped, since neither can be path-found for.
   *
   * The binary reaches the blueprint through the `IUnit` sub-object at
   * `UserUnit+0x148` (`sizeof(UserEntity)`), slot 7 `GetBlueprint`, and tests
   * `IsBeingBuilt` through slot 13 of the primary vtable.
   */
  UserUnit* PickPathPreviewSubject(SSelectionSetUserEntity& selection)
  {
    if (selection.mHead == nullptr) {
      return nullptr;
    }

    UserUnit* subject = nullptr;
    float deepest = 0.0f;

    SSelectionNodeUserEntity* node = nullptr;
    (void)selection.PruneTombstonesAndFindLive(&node, selection.mHead->mLeft);

    while (node != selection.mHead) {
      if (UserEntity* const entity = ResolveWeakEntitySetNodeEntity(*node); entity != nullptr) {
        if (UserUnit* const unit = entity->IsUserUnit(); unit != nullptr) {
          const RUnitBlueprint* const blueprint = unit->GetBlueprint();
          if (blueprint != nullptr && blueprint->Physics.ResolvedFootprint != nullptr && !unit->IsBeingBuilt()
              && blueprint->mSizeZ > deepest) {
            deepest = blueprint->mSizeZ;
            subject = unit;
          }
        }
      }

      SSelectionSetUserEntity::Iterator_inc(&node);
      (void)selection.PruneTombstonesAndFindLive(&node, node);
    }

    return subject;
  }

  /**
   * Address: 0x00854A30 (FUN_00854A30, sub_854A30)
   *
   * IDA signature:
   * char __usercall sub_854A30@<al>(float *a1@<edi>, float *a2@<esi>);
   *
   * What it does:
   * Structure-skirt adjacency test used by the build-drag adjacency-bonus
   * highlighter: true when rectangle `a`'s footprint touches or overlaps
   * rectangle `b`'s along either axis. First checks edge-to-edge contact
   * along X (within 1 world unit) with a containing/overlapping Z span;
   * then, symmetrically, edge-to-edge contact along Z with an overlapping X
   * span. The `>= 0.0f` guards on the `fabs` results are NaN guards, not
   * dead code - both are kept.
   */
  [[nodiscard]] bool AreSkirtsAdjacent(const gpg::Rect2f& a, const gpg::Rect2f& b) noexcept
  {
    if (std::fabs(a.x0 - b.x1) < 1.0f || std::fabs(a.x1 - b.x0) < 1.0f) {
      return (a.z0 >= b.z0 && b.z1 >= a.z1) || (b.z0 >= a.z0 && a.z1 >= b.z1);
    }

    const float zFront = std::fabs(a.z0 - b.z1);
    const float zBack = std::fabs(a.z1 - b.z0);
    return ((zFront >= 0.0f && zFront < 1.0f) || (zBack >= 0.0f && zBack < 1.0f))
        && ((a.x0 >= b.x0 && b.x1 >= a.x1) || (b.x0 >= a.x0 && a.x1 >= b.x1));
  }

  /**
   * Address: 0x00854B70 (FUN_00854B70, sub_854B70)
   *
   * IDA signature:
   * void __stdcall sub_854B70(CUIWorldViewBuildDragRuntimeView *buildDrag,
   *   CD3DPrimBatcher *batcher, CameraImpl *camera);
   *
   * What it does:
   * Draws every mobile unit in the camera frustum with a translucent skirt
   * outline (0xD800D800), brightening it to opaque green (0xFF00FF00) the
   * first time its footprint is adjacent to an unclaimed build-preview mesh
   * that also grants that unit an adjacency bonus for the preview's
   * blueprint - the same preview slot is never checked twice, matching the
   * binary's "first unclaimed candidate wins" scan. Skips dead/queued-for-
   * destruction/mobile units and anything beyond the active preview mesh's
   * fade-in LOD distance. A second pass then draws every build-preview mesh
   * itself at its current (possibly just-brightened) color.
   *
   * The IDA decompile of this function is flagged "local variable
   * allocation has failed" and mis-structures the adjacency miss case as a
   * `break` out of the per-unit loop with a dangling `goto` back into an
   * already-exited inner loop - both artifacts of failed control-flow
   * recovery. The real control flow (confirmed against the raw x86: the
   * `jz`/`jnz` at 0x00854E05/0x00854E25 both land on the *same* per-preview
   * loop back-edge at 0x00854E32, never on the outer per-unit loop's exit)
   * is the ordinary "for each candidate, continue on miss, break on hit"
   * shape recovered below.
   *
   * `buildDrag->mMeshes`/`mBlueprints` are guarded parallel arrays; a
   * length mismatch returns immediately without drawing or flushing
   * (0x00854C7C, `jnz` straight to the epilogue) - preserved as an early
   * return rather than folded into the loop guards below.
   */
  void DrawBuildDragAdjacencyHighlights(
    CUIWorldViewBuildDragRuntimeView& buildDrag, CD3DPrimBatcher* const batcher, CameraImpl* const camera
  )
  {
    constexpr std::uint32_t kDefaultSkirtColor = 0xD800D800u;
    constexpr std::uint32_t kAdjacentSkirtColor = 0xFF00FF00u;

    (void)batcher->Setup("TAlphaBlendLinearSampleNoDepth");
    batcher->SetViewProjMatrix(camera->CameraGetView());
    batcher->SetTexture(CD3DBatchTexture::FromSolidColor(0xFFFFFFFFu));

    if (buildDrag.mMeshes.size() != buildDrag.mBlueprints.size()) {
      return;
    }

    CHeightField* const heightField = buildDrag.mSession->mWldMap->mTerrainRes->GetHeightField();
    const std::size_t previewCount = buildDrag.mMeshes.size();

    CameraFrustumUserEntityList* const frustumUnits = camera->GetArmyUnitsInFrustum();
    for (CameraUserEntityWeakRef* weakRef = frustumUnits->mStart; weakRef != frustumUnits->mFinish; ++weakRef) {
      UserEntity* const entity = DecodeCameraFrustumWeakRef(*weakRef);
      if (entity == nullptr) {
        continue;
      }

      UserUnit* const unit = entity->IsUserUnit();
      if (unit == nullptr) {
        continue;
      }

      IUnit* const iunit = GetIUnitBridge(unit);
      if (iunit->IsDead() || iunit->DestroyQueued()) {
        continue;
      }

      const RUnitBlueprint* const unitBlueprint = iunit->GetBlueprint();
      if (unitBlueprint->IsMobile()) {
        continue;
      }

      const Wm3::Vec3f& unitPosition = iunit->GetPosition();
      if (camera->CameraGetView().viewport.ProjectViewportDepthRow1(unitPosition)
          >= buildDrag.mActiveBuildMesh->mIconFadeInZoom) {
        continue;
      }

      std::uint32_t color = kDefaultSkirtColor;
      for (std::size_t i = 0; i < previewCount; ++i) {
        MeshInstance* const previewMesh = buildDrag.mMeshes[i].get();
        if (previewMesh->color != static_cast<std::int32_t>(kDefaultSkirtColor)) {
          continue;
        }

        const Wm3::Vec3f previewPos = previewMesh->GetInterpolatedPos();
        const gpg::Rect2f previewSkirt =
          buildDrag.mBlueprints[i]->GetSkirtRect(SCoordsVec2{previewPos.x, previewPos.z});
        gpg::Rect2f unitSkirt{};
        (void)unit->GetSkirt(&unitSkirt);

        if (AreSkirtsAdjacent(previewSkirt, unitSkirt) && unit->DoOnDetectAdjacencyBonusFor(buildDrag.mBlueprints[i])) {
          color = kAdjacentSkirtColor;
          previewMesh->color = static_cast<std::int32_t>(kAdjacentSkirtColor);
          break;
        }
      }

      DrawUnitSkirt(heightField, iunit->GetBlueprint(), camera->CameraGetView(), iunit->GetPosition(),
        buildDrag.mSession, batcher, color);
    }

    for (std::size_t i = 0; i < buildDrag.mMeshes.size(); ++i) {
      MeshInstance* const previewMesh = buildDrag.mMeshes[i].get();
      previewMesh->UpdateInterpolatedFields();
      DrawUnitSkirt(heightField, buildDrag.mBlueprints[i], camera->CameraGetView(),
        previewMesh->interpolatedPosition, buildDrag.mSession, batcher, static_cast<std::uint32_t>(previewMesh->color));
    }

    batcher->Flush();
  }

  /**
   * Address: 0x00853DC0 (FUN_00853DC0, Moho::DrawCommandGraph)
   *
   * IDA signature:
   * void __fastcall Moho::DrawCommandGraph(CameraImpl *camera@<ecx>,
   *   CUIWorldViewBuildDragRuntimeView *buildDrag@<edx>, CD3DPrimBatcher *batcher);
   *
   * What it does:
   * The build-drag overlay pass, called once per frame from
   * `CRenderWorldView::RenderCommandGraph` regardless of whether the command
   * graph itself is showing.
   *
   * Latches every queued-order ghost mesh's hidden flag to whether a command
   * graph is currently active whenever that state changes, so ghosts hide
   * while the full graph view is up. Then, while the cursor is over the
   * world and the build-drag preview isn't invalidated: recomputes the
   * current left-click command mode, draws every other unit's planned-build
   * skirt unless Shift is held, draws this drag's own adjacency highlights,
   * and - while placing an anchored build (`COMMOD_BuildAnchored`) - finds
   * the first selected unit with a positive build-assist radius and draws
   * that radius as a ground circle.
   *
   * The decompile is flagged "positive sp value has been detected" and its
   * pseudocode mis-names two fields it gets from the wrong stack offset
   * (`mCursorInfo.mInWorld` and `mode.mBlueprint`); both were re-derived from
   * the raw x86: `cmp byte ptr [ecx+4B0h], 0` at 0x00853E44 is
   * `CursorInfoRuntimeView::mHitValid` (`CWldSession::GetCursorInfo()`'s
   * backing field, offset confirmed against `CWldSessionCursorRuntimeView`
   * in CWldSession.cpp), and `cmp dword ptr [esp+44h], 3` at 0x00853EAA is
   * `CommandModeData::mMode == COMMOD_BuildAnchored` (there is no
   * `ERuleBPUnitCommandCaps` enumerant `3`, while `COMMOD_BuildAnchored`
   * is a real, semantically exact match for "draw the build-assist radius").
   */
  void DrawCommandGraph(CameraImpl* const camera, CUIWorldViewBuildDragRuntimeView& buildDrag, CD3DPrimBatcher* const batcher)
  {
    const boost::SharedPtrRaw<UICommandGraph> graph = buildDrag.mSession->GetCommandGraph(false);
    const bool graphActive = (graph.px != nullptr);

    if (buildDrag.mUnknown5D != graphActive) {
      buildDrag.mUnknown5D = graphActive;
      for (auto& [cmdId, mesh] : buildDrag.mPreviewPositions) {
        mesh->isHidden = buildDrag.mUnknown5D;
      }
    }

    if (buildDrag.mSession->GetCursorInfo().mHitValid && !buildDrag.mPreviewInvalid) {
      CommandModeData mode{};
      (void)buildDrag.mSession->GetLeftMouseButtonAction(&mode, &buildDrag.mSession->CursorInfo(), 0);

      if (!MAUI_KeyIsDown(MKEY_SHIFT)) {
        DrawAllUnitSkirts(batcher, buildDrag.mSession, camera->CameraGetView());
      }

      DrawBuildDragAdjacencyHighlights(buildDrag, batcher, camera);

      if (mode.mMode == COMMOD_BuildAnchored) {
        msvc8::vector<UserUnit*> selection{};
        buildDrag.mSession->GetSelectionUnits(selection);

        for (UserUnit* const unit : selection) {
          const RUnitBlueprint* const blueprint = GetIUnitBridge(unit)->GetBlueprint();
          const float buildAssistRadius = blueprint->Economy.MaxBuildDistance;
          if (buildAssistRadius > 0.0f) {
            DRAW_Circle(
              batcher, 0.0f, GetIUnitBridge(unit)->GetPosition(), Wm3::Vector3f{0.0f, 1.0f, 0.0f}, 0.0f, 0u, 0u,
              nullptr, false, buildAssistRadius
            );
            batcher->Flush();
            break;
          }
        }
      }
      // `mode` going out of scope here runs CommandModeData::~CommandModeData(),
      // which unlinks mMouseDragStart/mMouseDragEnd - the binary inlines that
      // unlink by hand at this exact point (0x00853E8B..0x00853EE8).
    }
  }

  /**
   * Address: 0x0086ECD0 (FUN_0086ECD0, Moho::CRenderWorldView::RenderCommandGraph)
   * Slot: 2
   *
   * What it does:
   * With Shift held on a non-minimap view, lazily creates/caches this view's
   * command-graph handle (`mComGraph`), draws its mesh, and draws every
   * pending mobile-build order's footprint skirt; otherwise drops the cached
   * handle. Always draws the local build-drag overlay.
   *
   * Folds in `sub_85AF40` (0x0085AF40, 28 lines) - its sole caller - whose
   * entire body is "peek the session's command graph (`allowCreate=false`,
   * independent of the `mComGraph` cache above) and draw its mesh if
   * present," already-named operations here rather than a standalone
   * one-call helper. The two more register arguments its own `__userpurge`
   * signature carried (`CRenderWorldView*`, `boost::shared_ptr<UICommandGraph>&`,
   * i.e. `this` and `&mComGraph`) are dead - never dereferenced by
   * `sub_829190` either, confirmed against every callsite in its
   * disassembly.
   */
  void CRenderWorldView::RenderCommandGraph(
    CD3DPrimBatcher* const batcher, const std::int32_t renderPass, [[maybe_unused]] CWldMap* const map,
    const float deltaSeconds
  )
  {
    if (mIsMiniMap || !MAUI_KeyIsDown(MKEY_SHIFT)) {
      mComGraph = boost::SharedPtrRaw<UICommandGraph>{};
    } else {
      if (mComGraph.px == nullptr) {
        mComGraph = mWldSession->GetCommandGraph(/*allowCreate=*/true);
      }

      const boost::SharedPtrRaw<UICommandGraph> graph = mWldSession->GetCommandGraph(/*allowCreate=*/false);
      DrawCommandGraphMeshIfPresent(graph.px, mCamera->CameraGetView(), *batcher, renderPass, deltaSeconds);

      DrawAllUnitSkirts(batcher, mWldSession, mCamera->CameraGetView());
    }

    if (!mIsMiniMap) {
      DrawCommandGraph(mCamera, mBuildDrag, batcher);
    }
  }

  /**
   * Address: 0x00827A00 (FUN_00827A00, sub_827A00)
   *
   * IDA signature:
   * int __userpurge sub_827A00@<eax>(float *p1@<ebx>, float *t0@<edi>,
   *   float *t1@<esi>, CD3DPrimBatcher *batcher, float *p0, int width,
   *   unsigned int color, float uStart, float aspectRatio);
   *
   * What it does:
   * Subdivides one Hermite spline span between two command-graph anchors
   * (`p0`..`p1`, tangents `t0`/`t1`, already scaled by the caller's
   * smoothness radius) into `ui_CurveSegments+1` samples (minimum 2,
   * verified against the raw asm's Hermite basis coefficients, which match
   * the textbook h00/h01/h10/h11 polynomials exactly) and emits one ribbon
   * quad per consecutive sample pair. Each sample's half-width offset is a
   * 90-degree XZ rotation of *that sample's own* normalized tangent
   * (`{tangent.z, 0, -tangent.x} * halfWidth`) rather than a single shared
   * segment normal, so quads stay mitered along the curve and the ribbon
   * only widens in the ground plane (Y offset is always zero). The running
   * texture-U coordinate advances every iteration - including the first,
   * against a zero-initialized "previous" position - by that step's chord
   * length scaled by `1/width * aspectRatio` (the caller's sole caller,
   * `DrawCommandOrderline`, passes `CommandGraphNode::mOrderlineAspectRatio`
   * here - the time-based dash-scroll phase is already folded into
   * `uStart` before the call, via `mOrderlineAnimRate`). This is a genuine
   * binary quirk (a bogus origin-distance folded into the first real
   * segment's U), preserved rather than "fixed".
   *
   * `width` arrives as a plain 4-byte slot the caller fills with a float's
   * bit pattern (an IDA `int`-vs-`float` register-typing artifact, not a
   * real integer parameter) - declared here as `float` directly.
   */
  void EmitHermiteRibbonSegments(
    CD3DPrimBatcher& batcher, const Wm3::Vector3f& p0, const Wm3::Vector3f& p1, const Wm3::Vector3f& t0,
    const Wm3::Vector3f& t1, const float width, const std::uint32_t color, const float uStart, const float aspectRatio
  )
  {
    std::int32_t segmentCount = ui_CurveSegments + 1;
    if (segmentCount < 2) {
      segmentCount = 2;
    }

    const float halfWidth = width * 0.5f;
    const float step = 1.0f / static_cast<float>(segmentCount - 1);

    Wm3::Vector3f prevPos{0.0f, 0.0f, 0.0f};
    Wm3::Vector3f prevTangent{0.0f, 0.0f, 0.0f};
    float u = uStart;

    for (std::int32_t i = 0; i < segmentCount; ++i) {
      const float t = static_cast<float>(i) * step;
      const float t2 = t * t;
      const float t3 = t2 * t;

      const float h00 = (2.0f * t3 - 3.0f * t2) + 1.0f;
      const float h01 = 3.0f * t2 - 2.0f * t3;
      const float h10 = (t3 - 2.0f * t2) + t;
      const float h11 = t3 - t2;

      const Wm3::Vector3f pos{
        (h00 * p0.x + h01 * p1.x) + (h10 * t0.x + h11 * t1.x),
        (h00 * p0.y + h01 * p1.y) + (h10 * t0.y + h11 * t1.y),
        (h00 * p0.z + h01 * p1.z) + (h10 * t0.z + h11 * t1.z),
      };

      const float dh00 = (6.0f * t2) - (6.0f * t);
      const float dh01 = (6.0f * t) - (6.0f * t2);
      const float dh10 = (3.0f * t2) - (4.0f * t) + 1.0f;
      const float dh11 = (3.0f * t2) - (2.0f * t);

      const Wm3::Vector3f deriv{
        (dh00 * p0.x + dh01 * p1.x) + (dh10 * t0.x + dh11 * t1.x),
        (dh00 * p0.y + dh01 * p1.y) + (dh10 * t0.y + dh11 * t1.y),
        (dh00 * p0.z + dh01 * p1.z) + (dh10 * t0.z + dh11 * t1.z),
      };

      const float derivLen = std::sqrt((deriv.x * deriv.x + deriv.z * deriv.z) + deriv.y * deriv.y);
      Wm3::Vector3f tangent{0.0f, 0.0f, 0.0f};
      if (derivLen > 0.000001f) {
        const float invLen = 1.0f / derivLen;
        tangent = {deriv.x * invLen, deriv.y * invLen, deriv.z * invLen};
      }

      const float prevU = u;
      const float dx = pos.x - prevPos.x;
      const float dz = pos.z - prevPos.z;
      const float dy = pos.y - prevPos.y;
      u = std::sqrt((dx * dx + dz * dz) + dy * dy) * (1.0f / width) * aspectRatio + u;

      if (i != 0) {
        const Wm3::Vector3f offset{tangent.z * halfWidth, 0.0f, -tangent.x * halfWidth};
        const Wm3::Vector3f prevOffset{prevTangent.z * halfWidth, 0.0f, -prevTangent.x * halfWidth};

        const CD3DPrimBatcher::Vertex curPlus{pos.x + offset.x, pos.y + offset.y, pos.z + offset.z, color, u, 0.0f};
        const CD3DPrimBatcher::Vertex curMinus{pos.x - offset.x, pos.y - offset.y, pos.z - offset.z, color, u, 1.0f};
        const CD3DPrimBatcher::Vertex prevPlus{
          prevPos.x + prevOffset.x, prevPos.y + prevOffset.y, prevPos.z + prevOffset.z, color, prevU, 0.0f
        };
        const CD3DPrimBatcher::Vertex prevMinus{
          prevPos.x - prevOffset.x, prevPos.y - prevOffset.y, prevPos.z - prevOffset.z, color, prevU, 1.0f
        };

        batcher.DrawQuad(prevPlus, prevMinus, curMinus, curPlus);
      }

      prevPos = pos;
      prevTangent = tangent;
    }
  }

} // namespace moho
