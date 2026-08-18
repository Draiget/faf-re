#include "moho/ui/UiRuntimeTypes.h"

#include <cstdint>

#include "gpg/core/containers/Rect2.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/containers/SCoordsVec2.h"
#include "legacy/containers/List.h"
#include "moho/math/Wm3DistanceFafExtras.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/render/textures/CD3DBatchTexture.h"
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

} // namespace moho
