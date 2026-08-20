#include "moho/render/SelectionBracketRenderer.h"

#include <cmath>
#include <cstddef>

#include "boost/shared_ptr.h"
#include "moho/collision/CColPrimitiveBox3f.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/entity/UserEntity.h"
#include "moho/math/QuaternionMath.h"
#include "moho/mesh/Mesh.h"
#include "moho/misc/WeakPtr.h"
#include "moho/render/SelectionBracketParams.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/UserArmy.h"
#include "moho/ui/SelectionDragger.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/UserUnit.h"

#include "Wm3Box3.h"

namespace moho
{
  TDatListItem<BlinkyBox, void> sBlinkyBoxes{};

  /**
   * Address: 0x00F57DE5 (ren_SelectBoxes)
   *
   * Console toggle for the whole world-view selection pass; `func_RenUI` tests
   * it once at 0x007FD4B8 and returns immediately when it is clear. The image
   * byte at 0x00F57DE5 is 0x01, so the shipped default is on. Only two things
   * in the binary touch it: this read and the convar registration at
   * 0x00BE1E66, so its definition lives with its reader.
   */
  bool ren_SelectBoxes = true;
} // namespace moho

namespace
{
  /**
   * 0x00E4F8C4, the epsilon `func_DrawSelectionBrackets` compares
   * `|mSelectionThickness|` against before preferring the blueprint's value
   * over `ren_SelectBracketSize`.
   */
  constexpr float kSelectionThicknessEpsilon = 1.0e-5f;

  /** 0x00E3E410, the shared bracket atlas every selected entity is drawn with. */
  constexpr const char* kSelectionBracketTexturePath =
    "/textures/ui/common/game/selection/selection_brackets_player.dds";

  /** 0x00E3F370 / 0x00E02320, the prim-batcher effect + technique the pass runs under. */
  constexpr const char* kSelectionBracketTechnique = "TAlphaBlendLinearSample";
  constexpr const char* kSelectionBracketEffectFile = "primbatcher";

  /**
   * One of the four selection-bracket corners: which `Wm3::Box3f` ground-plane
   * vertex it sits on, and the top-left corner of its quarter of the 2x2
   * bracket atlas.
   *
   * `Wm3::Box3f::ComputeVertices` writes `-X-Y-Z, +X-Y-Z, +X+Y-Z, -X+Y-Z,
   * -X-Y+Z, +X-Y+Z, +X+Y+Z, -X+Y+Z`; the pass flattens the Y extent to zero
   * first, so indices 0/1/5/4 are the four ground corners in counter-clockwise
   * order. That is exactly the order the binary draws them in, one `DrawQuad`
   * each at 0x007FCF54, 0x007FD0C7, 0x007FD244 and 0x007FD3C7.
   */
  struct SelectionBracketCorner
  {
    std::size_t boxVertexIndex;
    float atlasU0;
    float atlasV0;
  };

  constexpr SelectionBracketCorner kSelectionBracketCorners[4] = {
    {0u, 0.0f, 0.0f},
    {1u, 0.5f, 0.0f},
    {5u, 0.5f, 0.5f},
    {4u, 0.0f, 0.5f},
  };

  /** Half the bracket atlas, i.e. the UV span of one corner tile. */
  constexpr float kSelectionBracketAtlasHalf = 0.5f;

  /**
   * Projects one world point through a camera's viewport row 2 - the lane the
   * renderer keeps its world-units-per-pixel denominator in, the sibling of
   * `VMatrix4::ProjectViewportDepthRow1`. `func_DrawSelectionBrackets` builds
   * it inline at 0x007FCBB5..0x007FCBFB out of `[camera+0x2A4 .. +0x2B0]`,
   * which is `GeomCamera3::viewport` (+0x284) row 2.
   */
  [[nodiscard]] float ProjectViewportPixelScaleRow(
    const moho::VMatrix4& viewport,
    const Wm3::Vector3f& point
  ) noexcept
  {
    const moho::Vector4f& row = viewport.r[2];
    return (row.x * point.x) + (row.y * point.y) + (row.z * point.z) + row.w;
  }

  /**
   * Resolves the `UserEntity` behind one selection weak-set node, the decode
   * `func_RenUI` open-codes at every one of its four draw sites
   * (`lea ecx, [eax-8]`, e.g. 0x007FD56C). The `-8` is
   * `WeakPtrOwnerLinkOffset<UserEntity>` - `UserEntity::mIUnitChainHead`.
   */
  [[nodiscard]] moho::UserEntity* DecodeSelectionEntity(
    const moho::SSelectionWeakRefUserEntity& weakRef
  ) noexcept
  {
    return moho::WeakPtr<moho::UserEntity>::DecodeOwnerObject(weakRef.mOwnerLinkSlot);
  }

  /**
   * Draws the shared player brackets over every live entry of one selection
   * weak-set. Mirrors both copies of the loop the binary emits back to back at
   * 0x007FD545..0x007FD596 (session selection) and 0x007FD5B3..0x007FD62F
   * (`sSelectionBrackets`): prune to the first live node with `find`, draw,
   * step the iterator, prune again, stop at the head sentinel.
   */
  void DrawSelectionSetBrackets(
    moho::SSelectionSetUserEntity& selection,
    moho::CD3DPrimBatcher& batcher,
    const moho::GeomCamera3& camera,
    const float interpolationAlpha
  )
  {
    moho::SSelectionNodeUserEntity* const head = selection.mHead;
    if (head == nullptr) {
      return;
    }

    moho::SSelectionNodeUserEntity* node = nullptr;
    node = moho::SSelectionSetUserEntity::find(&selection, head->mLeft, &node);
    while (node != head) {
      moho::DrawSelectionBrackets(DecodeSelectionEntity(node->mEnt), &batcher, &camera, interpolationAlpha);
      moho::SSelectionSetUserEntity::Iterator_inc(&node);
      node = moho::SSelectionSetUserEntity::find(&selection, node, &node);
    }
  }

  /**
   * Draws one entity's brackets with its own per-army bracket texture, the
   * shape shared by the hover pass (0x007FD74A..0x007FD7BC) and the blinky-box
   * pass (0x007FD91D..0x007FD95C). A blueprint without a bracket texture draws
   * nothing.
   */
  void DrawArmyColouredBrackets(
    moho::UserEntity* const entity,
    const moho::UserArmy* const viewingArmy,
    moho::CD3DPrimBatcher& batcher,
    const moho::GeomCamera3& camera,
    const float interpolationAlpha
  )
  {
    if (entity == nullptr) {
      return;
    }

    const boost::shared_ptr<moho::CD3DBatchTexture> bracketTexture =
      entity->GetSelectionBracketTexture(viewingArmy);
    if (!bracketTexture) {
      return;
    }

    batcher.SetTexture(bracketTexture);
    moho::DrawSelectionBrackets(entity, &batcher, &camera, interpolationAlpha);
  }

  /**
   * Advances one blinky box by `elapsedSeconds` and reports whether it is in
   * its visible half-cycle afterwards (0x007FD8B7..0x007FD8FE). The flag flips
   * whenever the running cycle time passes the current phase's length, and the
   * overshoot is carried into the next phase rather than discarded.
   */
  [[nodiscard]] bool AdvanceBlinkyBoxCycle(moho::BlinkyBox& box, const float elapsedSeconds) noexcept
  {
    const bool wasOff = box.mIsOn == 0u;

    box.mCurDuration += elapsedSeconds;
    const float cycleTime = box.mCurCycleTime + elapsedSeconds;
    box.mCurCycleTime = cycleTime;

    const float phaseLength = wasOff ? box.mOffTime : box.mOnTime;
    if (cycleTime > phaseLength) {
      box.mIsOn = wasOff ? 1u : 0u;
      box.mCurCycleTime = cycleTime - phaseLength;
    }

    return box.mIsOn != 0u;
  }

  /**
   * Whether the hovered entity already has a blinky box of its own
   * (0x007FD679..0x007FD6BC). When it does, the hover pass is skipped so the
   * two bracket layers do not stack.
   */
  [[nodiscard]] bool IsEntityBlinking(const moho::UserEntity* const entity) noexcept
  {
    for (const auto* node = moho::sBlinkyBoxes.mNext; node != &moho::sBlinkyBoxes; node = node->mNext) {
      const auto* const box = static_cast<const moho::BlinkyBox*>(node);
      if (DecodeSelectionEntity(box->mUnit) == entity) {
        return true;
      }
    }
    return false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x007FC820 (FUN_007FC820, func_DrawSelectionBrackets)
   *
   * IDA signature:
   * void __usercall func_DrawSelectionBrackets(
   *   Moho::UserEntity *entity@<ecx>, Moho::CD3DPrimBatcher *batcher,
   *   Moho::GeomCamera3 *camera, float interpolationAlpha);
   *
   * What it does:
   * See the declaration. The three stack arguments sit at frame `+0x04`
   * (batcher, read into `esi` at 0x007FCE15 as `DrawQuad`'s `this`), `+0x08`
   * (camera, read into `eax` at 0x007FCBAE) and `+0x0C` (the interpolation
   * alpha, read at 0x007FC998 and 0x007FCC31); the entity arrives in `ecx`
   * and the caller cleans the stack (`add esp, 0Ch`).
   */
  void DrawSelectionBrackets(
    UserEntity* const entity,
    CD3DPrimBatcher* const batcher,
    const GeomCamera3* const camera,
    const float interpolationAlpha
  )
  {
    if (entity == nullptr) {
      return;
    }

    // 0x007FC849..0x007FC899: one-shot latch. The first bracket drawn in the
    // process imports the Lua tuning table; the 1-byte token it hands back
    // becomes the "already imported" sentinel, and whatever was published
    // before (null on the first pass) is released.
    if (SelectionParamsSentinel() == nullptr) {
      void* const importedToken = LoadLuaSelectionParams(::operator new(1u));
      void* const previousToken = SelectionParamsSentinel();
      SelectionParamsSentinel() = importedToken;
      ::operator delete(previousToken);
    }

    MeshInstance* const meshInstance = entity->mMeshInstance;
    if (meshInstance != nullptr) {
      meshInstance->UpdateInterpolatedFields();
    }

    Wm3::Box3f selectionBox = meshInstance != nullptr ? meshInstance->box : Invalid<Wm3::Box3f>();

    float selectionSizeX = ren_SelectionSizeFudge * selectionBox.Extent[0];
    float selectionSizeZ = ren_SelectionSizeFudge * selectionBox.Extent[2];
    Wm3::Vector3f selectionCenterOffset{0.0f, 0.0f, 0.0f};

    // 0x007FC8CE: dispatched through vtable slot 2, the *const* `IsUserUnit`
    // overload, so the lookup goes through a const view of the entity.
    const UserEntity& constEntity = *entity;
    if (const UserUnit* const unit = constEntity.IsUserUnit(); unit != nullptr) {
      const RUnitBlueprint* const blueprint = GetIUnitBridge(unit)->GetBlueprint();

      if (blueprint->mSelectionSizeX > 0.0f) {
        selectionSizeX = blueprint->mSelectionSizeX * ren_UnitSelectionScale;
      }
      if (blueprint->mSelectionSizeZ > 0.0f) {
        selectionSizeZ = blueprint->mSelectionSizeZ * ren_UnitSelectionScale;
      }

      if (blueprint->mSelectionCenterOffsetX != 0.0f || blueprint->mSelectionCenterOffsetY != 0.0f
          || blueprint->mSelectionCenterOffsetZ != 0.0f) {
        // 0x007FC998..0x007FCB3C: the binary inlines the quaternion-to-matrix
        // expansion here instead of calling the shared helper it uses four
        // times below, but the algebra is the same `MultQuadVec` rotation of
        // the blueprint offset into the entity's interpolated orientation.
        const VTransform interpolated = constEntity.GetInterpolatedTransform(interpolationAlpha);
        const Wm3::Vector3f blueprintOffset{
          blueprint->mSelectionCenterOffsetX,
          blueprint->mSelectionCenterOffsetY,
          blueprint->mSelectionCenterOffsetZ
        };
        (void)MultQuadVec(&selectionCenterOffset, &blueprintOffset, &interpolated.orient_);
      }
    }

    const float maxSelectionSize = selectionSizeZ > selectionSizeX ? selectionSizeZ : selectionSizeX;

    // 0x007FCB5F..0x007FCBA8: `fabs` on both sides, so a negative blueprint
    // thickness is honoured - only a near-zero one falls back to the console
    // default.
    const REntityBlueprint* const entityBlueprint = entity->mParams.mBlueprint;
    float bracketThickness = ren_SelectBracketSize;
    if (std::fabs(entityBlueprint->mSelectionThickness) >= kSelectionThicknessEpsilon) {
      bracketThickness = entityBlueprint->mSelectionThickness;
    }

    // 0x007FCBB5..0x007FCC25: the on-screen size floor. The denominator is
    // built from the entity's *current* transform, not the interpolated one.
    const float viewportPixelScale =
      ProjectViewportPixelScaleRow(camera->viewport, entity->mVariableData.mCurTransform.pos_);
    if (ren_SelectBracketMinPixelSize > ((maxSelectionSize * bracketThickness) / viewportPixelScale)) {
      bracketThickness = (ren_SelectBracketMinPixelSize * viewportPixelScale) / maxSelectionSize;
    }

    // 0x007FCC2B..0x007FCCC7: flatten the box onto the ground plane at the
    // entity's interpolated height, offset by the rotated blueprint centre.
    selectionBox.Extent[0] = selectionSizeX;
    selectionBox.Extent[1] = 0.0f;
    selectionBox.Extent[2] = selectionSizeZ;
    selectionBox.Center.x = selectionBox.Center.x + selectionCenterOffset.x;
    selectionBox.Center.y = constEntity.GetInterpolatedTransform(interpolationAlpha).pos_.y
      + ren_SelectionHeightFudge + selectionCenterOffset.y;
    selectionBox.Center.z = selectionBox.Center.z + selectionCenterOffset.z;

    Wm3::Vector3f boxVertices[8]{};
    selectionBox.ComputeVertices(boxVertices);

    // 0x007FCCCC..0x007FCDE4: the four corners of one bracket tile, sized by
    // the bracket thickness and rotated into the entity's current orientation.
    // The negative lane really is spelled `-0.0f - thickness` in the binary.
    const float positiveExtent = maxSelectionSize * bracketThickness;
    const float negativeExtent = (-0.0f - bracketThickness) * maxSelectionSize;
    const float flatExtent = maxSelectionSize * 0.0f;

    const Wm3::Vector3f localTileCorners[4] = {
      {negativeExtent, flatExtent, negativeExtent},
      {positiveExtent, flatExtent, negativeExtent},
      {positiveExtent, flatExtent, positiveExtent},
      {negativeExtent, flatExtent, positiveExtent},
    };

    const Wm3::Quaternionf& orientation = entity->mVariableData.mCurTransform.orient_;
    Wm3::Vector3f tileCornerOffsets[4]{};
    for (std::size_t corner = 0; corner < 4u; ++corner) {
      (void)MultQuadVec(&tileCornerOffsets[corner], &localTileCorners[corner], &orientation);
    }

    for (const SelectionBracketCorner& bracket : kSelectionBracketCorners) {
      const Wm3::Vector3f& boxCorner = boxVertices[bracket.boxVertexIndex];

      CD3DPrimBatcher::Vertex quad[4]{};
      for (std::size_t corner = 0; corner < 4u; ++corner) {
        quad[corner].mX = boxCorner.x + tileCornerOffsets[corner].x;
        quad[corner].mY = boxCorner.y + tileCornerOffsets[corner].y;
        quad[corner].mZ = boxCorner.z + tileCornerOffsets[corner].z;
        quad[corner].mColor = ren_SelectColor;
      }

      quad[0].mU = bracket.atlasU0;
      quad[0].mV = bracket.atlasV0;
      quad[1].mU = bracket.atlasU0 + kSelectionBracketAtlasHalf;
      quad[1].mV = bracket.atlasV0;
      quad[2].mU = bracket.atlasU0 + kSelectionBracketAtlasHalf;
      quad[2].mV = bracket.atlasV0 + kSelectionBracketAtlasHalf;
      quad[3].mU = bracket.atlasU0;
      quad[3].mV = bracket.atlasV0 + kSelectionBracketAtlasHalf;

      batcher->DrawQuad(quad[0], quad[1], quad[2], quad[3]);
    }
  }

  /**
   * Address: 0x007FD490 (FUN_007FD490, func_RenUI)
   *
   * IDA signature:
   * void __cdecl func_RenUI(
   *   Moho::CWldSession *session, Moho::GeomCamera3 *camera,
   *   Moho::CD3DPrimBatcher *batcher, float interpolationAlpha,
   *   float elapsedSeconds);
   *
   * What it does:
   * See the declaration. Five stack arguments at frame `+0x04`, `+0x08`,
   * `+0x0C`, `+0x10` and `+0x14`; the fifth is the blinky-box time delta read
   * at 0x007FD88E and 0x007FD9A1, and both callers clean all five with
   * `add esp, 14h`.
   */
  void RenUI(
    CWldSession* const session,
    const GeomCamera3* const camera,
    CD3DPrimBatcher* const batcher,
    const float interpolationAlpha,
    const float elapsedSeconds
  )
  {
    if (session == nullptr || !ren_SelectBoxes) {
      return;
    }

    batcher->SetViewMatrix(camera->view);
    batcher->SetProjectionMatrix(camera->projection);

    // 0x007FD4E5..0x007FD4FC: the shared-texture pass runs whenever *either*
    // set still holds a live entry.
    if (!session->mSelection.IsEmptyFromHeadFind() || !sSelectionBrackets.IsEmptyFromHeadFind()) {
      const boost::shared_ptr<CD3DBatchTexture> playerBrackets =
        CD3DBatchTexture::FromFile(kSelectionBracketTexturePath, 1u);

      (void)batcher->Setup(kSelectionBracketTechnique);
      batcher->SetTexture(playerBrackets);

      DrawSelectionSetBrackets(session->mSelection, *batcher, *camera, interpolationAlpha);
      DrawSelectionSetBrackets(sSelectionBrackets, *batcher, *camera, interpolationAlpha);

      batcher->Flush();
    }

    // 0x007FD679..0x007FD7BC: the hovered unit gets its own army-coloured
    // brackets, but only when it is not already blinking and not already part
    // of the selection.
    UserEntity* const hoveredEntity = session->GetHoveredUserEntity();
    if (!IsEntityBlinking(hoveredEntity) && hoveredEntity != nullptr) {
      SSelectionSetUserEntity::FindResult selectionHit{};
      (void)SSelectionSetUserEntity::Find(&selectionHit, &session->mSelection, hoveredEntity);

      if (selectionHit.mRes == session->mSelection.mHead && hoveredEntity->IsUserUnit() != nullptr) {
        const boost::shared_ptr<CD3DBatchTexture> bracketTexture =
          hoveredEntity->GetSelectionBracketTexture(session->GetFocusArmy());

        if (bracketTexture) {
          // 0x007FD762..0x007FD794: the hover pass re-selects the effect and
          // technique on the device itself and clears the batcher's composite
          // rebuild flag before drawing.
          CD3DDevice* const device = D3D_GetDevice();
          (void)device->SelectFxFile(kSelectionBracketEffectFile);
          (void)device->SelectTechnique(kSelectionBracketTechnique);
          CD3DPrimBatcherRuntimeView::FromBatcher(batcher)->mRebuildComposite = 0u;

          batcher->SetTexture(bracketTexture);
          DrawSelectionBrackets(hoveredEntity, batcher, camera, interpolationAlpha);
          batcher->Flush();
        }
      }
    }

    // 0x007FD804..0x007FD9D3: tick the blinky-box ring, dropping dead or
    // expired entries and drawing the ones currently lit.
    if (sBlinkyBoxes.mNext == &sBlinkyBoxes) {
      return;
    }

    CD3DDevice* const device = D3D_GetDevice();
    (void)device->SelectFxFile(kSelectionBracketEffectFile);
    (void)device->SelectTechnique(kSelectionBracketTechnique);
    CD3DPrimBatcherRuntimeView::FromBatcher(batcher)->mRebuildComposite = 0u;

    auto* node = sBlinkyBoxes.mNext;
    while (node != &sBlinkyBoxes) {
      auto* const box = static_cast<BlinkyBox*>(node);
      UserEntity* const blinkingEntity = DecodeSelectionEntity(box->mUnit);

      if (blinkingEntity == nullptr || box->mCurDuration > box->mTotalTime) {
        // 0x007FD9AE: expired or dead entries are spliced out and reset to a
        // self-linked singleton; the binary never frees them.
        node = box->ListUnlink();
        continue;
      }

      if (AdvanceBlinkyBoxCycle(*box, elapsedSeconds)) {
        DrawArmyColouredBrackets(
          DecodeSelectionEntity(box->mUnit), session->GetFocusArmy(), *batcher, *camera, interpolationAlpha
        );
      }

      node = node->mNext;
    }

    batcher->Flush();
  }
} // namespace moho
