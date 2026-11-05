#include "moho/ui/UiPrivate.h"
#include "moho/console/CConCommand.h"
#include "moho/lua/CScrLuaObjectFactory.h"

namespace moho
{
  bool ren_BuildGhostsPerBeat = true;

  namespace
  {
    TConVar<bool> gTConVar_ren_BuildGhostsPerBeat(
      "ren_BuildGhostsPerBeat",
      "The ghosts at queued build orders are rebuilt once per sim beat (1, the default), or for each view of each "
      "frame as in the original (0). Read each frame.",
      &ren_BuildGhostsPerBeat
    );
  } // namespace
} // namespace moho

namespace
{
  // FAF community binary-patch addition (see CMauiControl::SetCustomRender).
  constexpr const char* kCUIWorldViewSetCustomRenderHelpText = "WorldView:SetCustomRender(bool)";
  constexpr const char* kCUIWorldViewGetScreenPosHelpText = "(vector2f|nil) = GetScreenPos(unit)";
  constexpr const char* kAddBlinkyBoxHelpText = "AddBlinkyBox(entityId, onTime, offTime, totalTime)";
  constexpr const char* kAddCommandFeedbackBlipHelpText = "AddCommandFeedbackBlip(meshInfoTable, duration)";
  constexpr const char* kCUIWorldViewCameraResetHelpText = "moho.UIWorldView:Reset()";
  constexpr const char* kCUIWorldViewGetsGlobalCameraCommandsHelpText =
    "moho.UIWorldView:GetsGlobalCameraCommands(bool getsCommands)";
  constexpr const char* kCUIWorldViewGetRightMouseButtonOrderHelpText =
    "string moho.UIWorldView:GetRightMouseButtonOrder()";
  constexpr const char* kCUIWorldViewSetCartographicHelpText = "SetCartographic(bool)";
  constexpr const char* kCUIWorldViewIsCartographicHelpText = "bool IsCartographic()";
  constexpr const char* kCUIWorldViewEnableResourceRenderingHelpText = "EnableResourceRendering(bool)";
  constexpr const char* kCUIWorldViewIsResourceRenderingEnabledHelpText = "bool IsResourceRenderingEnabled()";
  constexpr const char* kCUIWorldViewUnlockInputHelpText = "UnlockInput(camera)";
  constexpr const char* kCUIWorldViewLockInputHelpText = "LockInput(camera)";
  constexpr const char* kCUIWorldViewIsInputLockedHelpText = "IsInputLocked(camera)";
  constexpr const char* kCUIWorldViewSetHighlightEnabledHelpText = "SetHighlightEnabled(bool)";
  constexpr const char* kCUIWorldViewZoomScaleHelpText =
    "ZoomScale(x, y, wheelRot, wheelDelta) - cause the world to zoom based on wheel rotation event";
  constexpr const char* kUnProjectHelpText = "VECTOR3 UnProject(self,VECTOR2)";
  constexpr const char* kCUIWorldViewProjectHelpText =
    "VECTOR2 Project(self,VECTOR3) - given a point in world space, projects the point to control space";
  constexpr const char* kCUIWorldViewHasHighlightCommandHelpText = "bool moho.UIWorldView:HasHighlightCommand()";
  constexpr const char* kCUIWorldShowConvertToPatrolCursorHelpText =
    "bool moho.UIWorldView:ShowConvertToPatrolCursor()";

  /**
   * Address: 0x0085AFE0 (FUN_0085AFE0, sub_85AFE0)
   *
   * What it does:
   * Converts one normalized device coordinate point into viewport pixel space
   * and floors X/Y lanes to match Lua-facing screen position semantics.
   */
  [[nodiscard]] Wm3::Vector3f ProjectNormalizedScreenPointToViewportFloor(
    const Wm3::Vector2f& normalizedPoint,
    const float viewportWidth,
    const float viewportHeight
  ) noexcept
  {
    Wm3::Vector3f screenPoint{};
    screenPoint.x = std::floor(((normalizedPoint.x - -1.0f) * viewportWidth) * 0.5f);
    screenPoint.y = std::floor(((-viewportHeight * (normalizedPoint.y - -1.0f)) * 0.5f) + viewportHeight);
    screenPoint.z = 0.0f;
    return screenPoint;
  }
}


// --- FAF community binary-patch addition: WorldView:SetCustomRender. No
// `Address:` block -- this method never existed in the original 2007 binary;
// it ships only via FA-Binary-Patches (section/DrawFunc.cpp, registered with
// `UIRegFuncT<0x00E491E8, 0x00F8D88C>` on class "CUIWorldView"). As there: the
// argument count error names "SetCustomRender", the flag is any Lua value taken
// by truthiness (`lua_toboolean`), and nothing is returned.

int moho::cfunc_CUIWorldViewSetCustomRender(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldViewSetCustomRenderL(ResolveBindingState(luaContext));
}

moho::CScrLuaInitForm* moho::func_CUIWorldViewSetCustomRender_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetCustomRender",
    &moho::cfunc_CUIWorldViewSetCustomRender,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldViewSetCustomRenderHelpText
  );
  return &binder;
}

int moho::cfunc_CUIWorldViewSetCustomRenderL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, "SetCustomRender");

  LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);
  if (worldView == nullptr) {
    return 0;
  }

  worldView->SetCustomRender(lua_toboolean(state->m_state, 2) != 0);
  return 0;
}

// --- FAF community binary-patch addition: WorldView:ProjectMultiple. No `Address:`
// block -- it ships only via FA-Binary-Patches (section/WorldView.cpp, registered on
// class "CUIWorldView"). Each vector is read as the patch's `ToVector` does: a
// non-table is the zero vector, otherwise raw [1], [2], [3] through lua_tonumber.

int moho::cfunc_CUIWorldViewProjectMultiple(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldViewProjectMultipleL(ResolveBindingState(luaContext));
}

moho::CScrLuaInitForm* moho::func_CUIWorldViewProjectMultiple_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "ProjectMultiple",
    &moho::cfunc_CUIWorldViewProjectMultiple,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    "WorldView:ProjectMultiple(vectors)"
  );
  return &binder;
}

int moho::cfunc_CUIWorldViewProjectMultipleL(
  LuaPlus::LuaState* const state
)
{
  lua_State* const L = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, "ProjectMultiple");
  if (!lua_istable(L, 2)) {
    luaL_argerror(L, 2, "table expected.");
  }

  LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);
  if (worldView == nullptr) {
    return 0;
  }
  moho::CameraImpl* const camera = worldView->GetCamera();
  if (camera == nullptr) {
    return 0;
  }
  const GeomCamera3& view = camera->CameraGetView();

  const auto readVector = [L](const int index) {
    Wm3::Vector3f vector{0.0f, 0.0f, 0.0f};
    if (lua_istable(L, index)) {
      float* const components[3] = {&vector.x, &vector.y, &vector.z};
      for (int component = 0; component < 3; ++component) {
        lua_rawgeti(L, index, component + 1);
        *components[component] = static_cast<float>(lua_tonumber(L, -1));
        lua_pop(L, 1);
      }
    }
    return vector;
  };

  // Every key of the input keeps its key in the result, with a plain {x, y} value.
  lua_newtable(L);
  const int resultIndex = lua_gettop(L);
  lua_pushnil(L);
  while (lua_next(L, 2) != 0) {
    const Wm3::Vector2f screen = view.Project(readVector(lua_gettop(L)));
    lua_pushvalue(L, -2);
    lua_newtable(L);
    lua_pushnumber(L, screen.x);
    lua_rawseti(L, -2, 1);
    lua_pushnumber(L, screen.y);
    lua_rawseti(L, -2, 2);
    lua_rawset(L, resultIndex);
    lua_pop(L, 1);
  }
  return 1;
}

/**
 * Address: 0x00822FA0 (FUN_00822FA0, ??0UIBuildDragger@Moho@@QAE@@Z)
 *
 * What it does:
 * Captures the current world cursor position as both start/end drag points and
 * mirrors those lanes into the world-view build-drag state.
 */
moho::UIBuildDragger::UIBuildDragger(
  moho::CWldSession* const session,
  moho::CBuildDragPreview* const worldView,
  moho::CameraImpl* const camera
)
  : mWldSession(session)
  , mWldView(worldView)
  , mCam(camera)
  , mStart(0.0f, 0.0f, 0.0f)
  , mEnd(0.0f, 0.0f, 0.0f)
{
  if (mWldSession != nullptr) {
    mStart = mWldSession->CursorWorldPos;
  }

  mEnd = mStart;

  if (mWldView != nullptr) {
    mWldView->mStart = mStart;
    mWldView->mEnd = mEnd;
  }
}

/**
 * Address: 0x008230A0 (FUN_008230A0, Moho::UIBuildDragger::ReleaseDrag)
 *
 * IDA signature:
 * void __usercall Moho::UIBuildDragger::ReleaseDrag(
 *     Moho::SMauiEventData *a1@<ebx>, Moho::UIBuildDragger *a2@<edi>);
 *
 * What it does:
 * Resolves the current left-mouse command-mode payload via
 * `CWldSession::GetLeftMouseButtonAction` (using the session-bound cursor
 * MouseInfo at +0x4B0), snapshots the rules "DRAGBUILD" entity-category set
 * locally, and tests whether the resolved blueprint's ordinal bit is set in
 * the snapshot. When the blueprint participates in DRAGBUILD, projects the
 * event's screen-space cursor onto the world surface via
 * `mCam->CameraScreenToSurface()` and, if valid, snaps `mEnd` to the surface
 * point and mirrors both drag lanes (`mStart`/`mEnd`) into the bound
 * world-view build-drag state. Shared per-tick drag-tracking helper invoked
 * by both the `DragMove` and `DragRelease` virtual override lanes.
 */
void moho::UIBuildDragger::ReleaseDrag(
  const moho::SMauiEventData* const eventData
)
{
  // Re-derive the left-mouse command mode from the session's cursor MouseInfo
  // lane (the MouseInfo nests directly inside `CWldSession` at +0x4B0).
  CommandModeData commandMode{};
  const MouseInfo& cursorInfo = mWldSession->GetCursorInfo();
  (void)mWldSession->GetLeftMouseButtonAction(&commandMode, &cursorInfo, 0);

  // Take a stack snapshot of the rules' DRAGBUILD entity-category set. The
  // binary copies (mUniverse, mBits.mFirstWordIndex, mBits.mWords) into a
  // local BVSet so the per-bit lookup below operates on stable storage even
  // if the rules-owned source set mutates concurrently.
  const EntityCategorySet* const dragBuildCategory = mWldSession->mRules->GetEntityCategory("DRAGBUILD");
  EntityCategorySet dragBuildSnapshot;
  dragBuildSnapshot = *dragBuildCategory;

  if (commandMode.mBlueprint != nullptr) {
    const auto* const blueprint = static_cast<const RBlueprint*>(commandMode.mBlueprint);
    const std::uint32_t blueprintOrdinal = static_cast<std::uint32_t>(blueprint->mBlueprintOrdinal);
    if (dragBuildSnapshot.ContainsBit(blueprintOrdinal)) {
      // Blueprint participates in DRAGBUILD: refresh the drag-end to the
      // current surface intersection of the event's screen-space cursor.
      const Wm3::Vector2f mousePos(eventData->mMousePos.x, eventData->mMousePos.y);
      const Wm3::Vector3f surfacePoint = mCam->CameraScreenToSurface(mousePos);
      if (IsValidVector3f(surfacePoint)) {
        mEnd = surfacePoint;
        mWldView->mStart = mStart;
        mWldView->mEnd = mEnd;
      }
    }
  }
}

/**
 * Address: 0x00823BB0 (FUN_00823BB0, slot +0x04 of ??_7UIBuildDragger@Moho@@6B@)
 * Mangled: ?DragMove@UIBuildDragger@Moho@@UAEXPBUSMauiEventData@2@@Z
 *
 * IDA signature:
 * void __thiscall Moho::UIBuildDragger::DragMove(
 *     Moho::UIBuildDragger *this@<ecx>, Moho::SMauiEventData *eventData);
 *
 * What it does:
 * Forwards one drag-move tick to the shared `ReleaseDrag` helper, which
 * re-resolves the active build blueprint and snaps `mEnd` to the cursor's
 * current world-surface intersection when the blueprint is a DRAGBUILD.
 */
void moho::UIBuildDragger::DragMove(
  const moho::SMauiEventData* const eventData
)
{
  ReleaseDrag(eventData);
}

/**
 * Address: 0x00823CA0 (FUN_00823CA0, slot +0x0C of ??_7UIBuildDragger@Moho@@6B@)
 * Mangled: ?OnCurrentDraggerReplaced@UIBuildDragger@Moho@@UAEXXZ
 *
 * IDA signature:
 * void __thiscall Moho::UIBuildDragger::OnCurrentDraggerReplaced(
 *     Moho::UIBuildDragger *this@<ecx>);
 *
 * What it does:
 * Drops the build dragger when a different dragger takes over. `delete this`,
 * emitted as the usual null test plus a call through vtable slot +0x00 with
 * the scalar-delete flag set.
 */
void moho::UIBuildDragger::OnCurrentDraggerReplaced()
{
  delete this;
}
namespace
{
  constexpr std::int32_t kBuildPreviewMeshColor = static_cast<std::int32_t>(0xFF00FF00u);
}


/**
 * Address: 0x008529C0 (FUN_008529C0, struct_WorldView_object::struct_WorldView_object)
 *
 * What it does:
 * Initializes the world-view build-preview cache, invalid start/end vectors,
 * and empty preview mesh/material/decal state.
 */
moho::CBuildDragPreview::CBuildDragPreview()
  : mSession(moho::WLD_GetActiveSession())
  , mActiveBuildMesh(nullptr)
  , mMeshes()
  , mBlueprints()
  , mPreviewPositions()
  , mUnitPlaceMaterial()
  , mDecal(nullptr)
  , mActiveCommandMode(moho::COMMOD_None)
  , mStart(
      gpg::NaN,
      gpg::NaN,
      gpg::NaN
    )
  , mEnd(mStart)
  , mPreviewInvalid(false)
  , mQueuedGhostsHidden(false)
{}

/**
 * Address: 0x00852B20 (FUN_00852B20, struct_WorldView_object::~struct_WorldView_object)
 *
 * What it does:
 * Clears the preview caches and the terrain decal (0x00852B46); the rest is
 * member destruction in reverse order - the preview material's release
 * (0x00852B50), the positions map (0x00852B97), then the blueprint and mesh
 * vectors (0x00852BAB, 0x00852BCF).
 */
moho::CBuildDragPreview::~CBuildDragPreview()
{
  ClearBuildPreviewCache();
}

/**
 * Address: 0x008549B0 (FUN_008549B0, struct_WorldView_object::Destroy)
 *
 * What it does:
 * Clears active build-preview mesh/blueprint caches and destroys the terrain
 * decal used by the preview lane.
 */
void moho::CBuildDragPreview::ClearBuildPreviewCache()
{
  // Drain mMeshes. FUN_008555E0 is this container's own
  // `erase(first, last)` emission -- releasing each shared control block as it
  // goes -- so calling erase by name is what keeps that symbol referenced.
  (void)mMeshes.erase(mMeshes.begin(), mMeshes.end());

  // mBlueprints holds trivially-destructible raw pointers, so the binary
  // collapses the live range with a single `_Mylast = _Myfirst` store.
  mBlueprints.clear();

  if (mDecal != nullptr) {
    auto* const session = moho::WLD_GetActiveSession();
    auto* const decalManager = static_cast<moho::CDecalManager*>(session->mWldMap->mTerrainRes->GetDecalManager());
    decalManager->DestroyDecal(mDecal);
    mDecal = nullptr;
  }
}

boost::shared_ptr<moho::MeshInstance> moho::CBuildDragPreview::CreateBuildPreviewMeshInstance(
  moho::RUnitBlueprint* const blueprint
)
{
  if (!mUnitPlaceMaterial) {
    const fa::string shaderName("UnitPlace");
    const fa::string emptyTextureName;
    mUnitPlaceMaterial = moho::MeshMaterial::Create(
      shaderName, emptyTextureName, emptyTextureName, emptyTextureName, emptyTextureName, emptyTextureName, nullptr
    );
  }

  moho::RMeshBlueprint* const meshBlueprint = mSession->mRules->GetMeshBlueprint(blueprint->Display.MeshBlueprint);
  const float uniformScale = blueprint->Display.UniformScale;
  const Wm3::Vector3f previewScale(uniformScale, uniformScale, uniformScale);

  moho::MeshInstance* const meshInstance = moho::MeshRenderer::GetInstance()->CreateMeshInstance(
    moho::WLD_GetActiveSession()->mGameTick,
    kBuildPreviewMeshColor,
    meshBlueprint,
    previewScale,
    false,
    mUnitPlaceMaterial
  );
  return boost::shared_ptr<moho::MeshInstance>(meshInstance);
}

/**
 * Address: 0x00854130 (FUN_00854130, sub_854130)
 *
 * What it does:
 * Creates one `UnitPlace` build-preview mesh instance for a unit blueprint and
 * appends it to the preview mesh/blueprint caches. The shared-ptr mesh
 * push is routed through the per-T named helper
 * `PushBackMeshInstanceSharedPtrVector` (FUN_00855040) to preserve the
 * MSVC8 `vector<shared_ptr<MeshInstance>>::push_back` symbol shape.
 */
void moho::CBuildDragPreview::AppendBuildPreviewMesh(
  moho::RUnitBlueprint* const blueprint
)
{
  boost::shared_ptr<moho::MeshInstance> meshInstance = CreateBuildPreviewMeshInstance(blueprint);
  moho::PushBackMeshInstanceSharedPtrVector(mMeshes, meshInstance);
  mBlueprints.push_back(blueprint);
}

/**
 * Address: 0x008544B0 (FUN_008544B0, sub_8544B0)
 *
 * What it does:
 * Replaces one cached build-preview mesh/blueprint slot with a freshly created
 * `UnitPlace` mesh instance for the provided unit blueprint.
 */
void moho::CBuildDragPreview::ReplaceBuildPreviewMesh(
  const std::size_t index,
  moho::RUnitBlueprint* const blueprint
)
{
  boost::shared_ptr<moho::MeshInstance> meshInstance = CreateBuildPreviewMeshInstance(blueprint);
  mMeshes[index] = meshInstance;
  mBlueprints[index] = blueprint;
}
namespace
{
  /// 0x00853A38 / 0x00853B43: the translucent tint every queued-build ghost is
  /// created with and stamped with (0xAARRGGBB).
  constexpr std::int32_t kQueuedBuildGhostColor = static_cast<std::int32_t>(0xD800D800u);

  /**
   * Inlined block from FUN_008534F0 (0x00853586..0x008536EB).
   *
   * What it does:
   * Reports whether a unit under this order's own cursor is already building
   * it. Walks the helper's cached cursor-entity weak-set - pruning tombstones
   * as it goes, exactly as the binary does - and for every unit that has work
   * in progress and reports `UNITSTATE_Building`, compares the front of that
   * unit's command queue against this order.
   *
   * The binary reads the unit-only lanes (`mWorkProgress`, the `IUnit`
   * sub-object) without an `IsUserUnit` check first: a mobile-build order's
   * cursor set only ever holds units, so the static downcast below is the same
   * assumption expressed in source.
   */
  [[nodiscard]] bool IsQueuedBuildAlreadyUnderway(
    moho::UserCommandIssueHelper& helper
  )
  {
    const moho::CmdId orderId = helper.mConstantData.cmd;
    for (moho::UserUnit* const unit : *moho::ResolveCommandIssueCursorEntities(helper)) {
      if (unit->mUnitVarDat.mWorkProgress > 0.0f && unit->IsUnitState(moho::UNITSTATE_Building)) {
        const moho::UserCommandIssueHelper* const currentOrder =
          moho::ResolveUserUnitFrontCommandIssueHelper(unit->GetCommandQueue());
        if (currentOrder != nullptr && currentOrder->mConstantData.cmd == orderId) {
          return true;
        }
      }
    }

    return false;
  }
}


/**
 * Address: 0x008534F0 (FUN_008534F0, sub_8534F0)
 *
 * What it does:
 * Rebuilds the queued mobile-build ghost meshes into a fresh lane and swaps it
 * over `mPreviewPositions`; see the header for the full description.
 */
void moho::CBuildDragPreview::RefreshQueuedBuildGhosts()
{
  moho::CWldSession* const session = moho::WLD_GetActiveSession();

  // Engine change: orders reach this map from the sim, once per beat, and walking every army's orders
  // for each view of each frame was 3 % of a frame in a 12-player game.
  const std::uint16_t stamp = static_cast<std::uint16_t>(
    static_cast<std::uint32_t>(session->mGameTick) * 31U + static_cast<std::uint32_t>(session->mCommandManager->mCommands.size())
  );
  if (moho::ren_BuildGhostsPerBeat && stamp == mQueuedGhostStamp) {
    return;
  }
  mQueuedGhostStamp = stamp;

  // Built from scratch every pass. Whatever stays behind in the map this one
  // displaces belongs to orders that are gone, and dies with it below.
  fa::map<moho::CmdId, boost::shared_ptr<moho::MeshInstance>> refreshed;

  for (const auto& [commandId, helper] : session->mCommandManager->mCommands) {
    static_cast<void>(commandId);
    if (helper == nullptr) {
      continue;
    }

    if (moho::ResolveCommandIssueHelperCommandType(*helper) != moho::EUnitCommandType::UNITCOMMAND_BuildMobile) {
      continue;
    }

    const bool ghostUnderway = IsQueuedBuildAlreadyUnderway(*helper);
    if (ghostUnderway) {
      continue;
    }

    const moho::CmdId orderId = helper->mConstantData.cmd;

    boost::shared_ptr<moho::MeshInstance> ghost;
    if (const auto cached = mPreviewPositions.find(orderId); cached != mPreviewPositions.end()) {
      ghost = cached->second;
      ghost->isHidden = 0;
      refreshed[orderId] = ghost;
    } else {
      gpg::RRef blueprintRef{};
      blueprintRef = gpg::MakeRRef<moho::REntityBlueprint>(helper->mConstantData.blueprint);
      const gpg::RRef unitBlueprintRef = gpg::REF_UpcastPtr(blueprintRef, moho::RUnitBlueprint::StaticGetClass());
      if (unitBlueprintRef.mObj == nullptr) {
        continue;
      }

      auto* const unitBlueprint = static_cast<moho::RUnitBlueprint*>(unitBlueprintRef.mObj);
      moho::RMeshBlueprint* const meshBlueprint =
        session->mRules->GetMeshBlueprint(unitBlueprint->Display.MeshBlueprint);
      if (meshBlueprint == nullptr) {
        continue;
      }

      // The ghost takes the top LOD's own albedo/normals/specular sheets so it
      // reads as the unit it previews, but through the `UnitPlace` shader; the
      // lookup and secondary lanes stay empty.
      const moho::RMeshBlueprintLOD& topLod = *meshBlueprint->mLods.begin();
      const fa::string shaderName("UnitPlace");
      const fa::string emptyTextureName;
      boost::shared_ptr<moho::MeshMaterial> ghostMaterial = moho::MeshMaterial::Create(
        shaderName,
        topLod.mAlbedoName,
        topLod.mNormalsName,
        topLod.mSpecularName,
        emptyTextureName,
        emptyTextureName,
        nullptr
      );

      const float uniformScale = unitBlueprint->Display.UniformScale;
      const Wm3::Vector3f ghostScale(uniformScale, uniformScale, uniformScale);
      ghost.reset(
        moho::MeshRenderer::GetInstance()->CreateMeshInstance(
          session->mGameTick, kQueuedBuildGhostColor, meshBlueprint, ghostScale, false, ghostMaterial
        )
      );

      refreshed[orderId] = ghost;
      ghost->color = kQueuedBuildGhostColor;
    }

    // Ghosts never rotate - the stance is the identity orientation at the
    // order's own anchor, and start == end so nothing interpolates.
    moho::VTransform stance;
    stance.orient_ = Wm3::Quatf(1.0f, 0.0f, 0.0f, 0.0f);
    stance.pos_ = moho::ResolveCommandIssueHelperAnchorPosition(*helper);
    ghost->SetStance(stance, stance);
  }

  mPreviewPositions.swap(refreshed);
}

/**
 * Address: 0x0040DAD0 (FUN_0040DAD0)
 *
 * What it does:
 * Initializes one build-drag stepping lane from start/end world XZ
 * coordinates, deriving normalized per-step deltas and integer step count.
 */
[[maybe_unused]] static void InitBuildDragStepState(
  SBuildDragStep* const state,
  const float stepLength,
  const float startX,
  const float startZ,
  const float endX,
  const float endZ
) noexcept
{
  const float deltaX = endX - startX;
  const float deltaZ = endZ - startZ;

  state->mX = startX;
  state->mZ = startZ;

  const float absDeltaZ = std::fabs(deltaZ);
  const float absDeltaX = std::fabs(deltaX);
  const float maxAxisDelta = (absDeltaZ <= absDeltaX) ? absDeltaX : absDeltaZ;

  if (maxAxisDelta == 0.0f) {
    state->mXStep = 0.0f;
    state->mZStep = 0.0f;
    state->mStepCount = 1;
    return;
  }

  const float inverseMaxAxisDelta = 1.0f / maxAxisDelta;
  state->mXStep = (inverseMaxAxisDelta * deltaX) * stepLength;
  state->mZStep = (inverseMaxAxisDelta * deltaZ) * stepLength;

  const float rawStepCount = maxAxisDelta / stepLength;
  const float roundedStepCount = std::nearbyintf(rawStepCount);
  std::int32_t carryAdjust = 0;
  if (rawStepCount < roundedStepCount) {
    carryAdjust = -1;
  }

  state->mStepCount = static_cast<std::int32_t>(roundedStepCount) + carryAdjust + 1;
}
namespace
{
  /**
   * The build-drag translation unit converts float->cell with `fld`/`fistp`
   * pairs (x87 round-to-nearest-even) and then narrows through a 16-bit
   * `movsx` - see 0x00823306 / 0x0082332C / 0x0082335E / 0x00823384 for the
   * drag ends and 0x00823466 / 0x00823472 / 0x00823806 / 0x00823812 for the
   * per-step positions. A plain `static_cast<int>` truncates instead of
   * rounding, which shifts every placement on the negative half of the map, so
   * the conversion is routed through the same round-then-narrow shape.
   */
  [[nodiscard]] std::int16_t BuildDragCellCoord(
    const float value
  ) noexcept
  {
    return static_cast<std::int16_t>(std::lrintf(value));
  }

  /// The function-local `invalid_vec` sentinel `UIBuildDragger::DragRelease`
  /// publishes into both world-view preview lanes (0x00823BEF sources the same
  /// quiet NaN into x/y/z; the guard word at 0x010C7AB0 is MSVC's magic-static
  /// machinery, which C++ provides for free).
  [[nodiscard]] const Wm3::Vector3f& InvalidBuildDragVector() noexcept
  {
    static const Wm3::Vector3f sInvalid(
      std::numeric_limits<float>::quiet_NaN(),
      std::numeric_limits<float>::quiet_NaN(),
      std::numeric_limits<float>::quiet_NaN()
    );
    return sInvalid;
  }
}


/**
 * Address: 0x00823220 (FUN_00823220, sub_823220)
 *
 * IDA signature:
 * Moho::UserEntity *__userpurge sub_823220@<eax>(
 *     Moho::UIBuildDragger *this@<edi>, Moho::SMauiEventData *eventData);
 *
 * File-static in the binary as well as here: every other member of
 * `UIBuildDragger` carries a real symbol and this address carries none, it
 * takes `this` in `edi` rather than `ecx`, and its only caller
 * (`UIBuildDragger::DragRelease`, 0x00823BE3) lives in the same translation
 * unit. The `Moho::UserEntity*` return in the IDA signature is an artefact -
 * the value left in `eax` at every exit is just the cursor of the inlined
 * `~MouseInfo` weak-unlink walk (0x00823AF9-0x00823B21), and the caller
 * overwrites `eax` at 0x00823BE8 without reading it.
 *
 * What it does:
 * Turns one finished build drag into the run of build orders it stands for.
 * Re-resolves the left-mouse command mode against a local snapshot of the
 * session cursor and bails unless it is a build mode. Snaps both drag ends
 * from footprint centre to footprint origin cells, pulls the active build
 * template, then walks the drag line one template (or skirt) extent at a time,
 * issuing `UNITCOMMAND_BuildMobile` at every step - once per template entry
 * when a template is active, once for the dragged blueprint otherwise. Only
 * the very first order of the run clears the target queue, and only when SHIFT
 * is not held. Placements that fail the range/buildability tests are still
 * issued while the session is not previewing invalid placements. Ends with a
 * single `UNITCOMMAND_None` notification covering the whole run.
 */
static void IssueBuildDragOrders(
  moho::UIBuildDragger* const dragger,
  const moho::SMauiEventData* const eventData
)
{
  moho::CWldSession* const session = dragger->mWldSession;

  // 0x0082323B/0x00823241/0x0082324B: copy-construct a local cursor snapshot
  // from the session's own MouseInfo lane at +0x4B0. The copy relinks the
  // hovered-unit weak-owner chain onto the local; scope exit unlinks it (the
  // compiler inlined that destructor at 0x00823AF9-0x00823B21).
  const moho::MouseInfo cursorSnapshot(session->GetCursorInfo());

  // 0x00823262/0x00823276: only the SHIFT bit of the modifier mask survives -
  // it turns "replace the queue" into "append to it".
  const bool appendToQueue = (eventData->mModifiers & moho::MEM_Shift) != 0;

  moho::CommandModeData commandMode{};
  (void)session->GetLeftMouseButtonAction(&commandMode, &cursorSnapshot, 0);

  // 0x0082328D-0x0082329C: anything that is not a build mode drops out here.
  if (commandMode.mMode != moho::COMMOD_Build && commandMode.mMode != moho::COMMOD_BuildAnchored) {
    return;
  }

  auto* const buildBlueprint = static_cast<moho::RUnitBlueprint*>(commandMode.mBlueprint);
  const moho::SFootprint& footprint = buildBlueprint->mFootprint;

  // 0x008232D4-0x00823388: both drag ends move from footprint centre to
  // footprint origin, round to the nearest cell, and narrow to 16 bits.
  const float startX =
    static_cast<float>(BuildDragCellCoord(dragger->mStart.x - static_cast<float>(footprint.mSizeX) * 0.5f));
  const float startZ =
    static_cast<float>(BuildDragCellCoord(dragger->mStart.z - static_cast<float>(footprint.mSizeZ) * 0.5f));
  const float endX =
    static_cast<float>(BuildDragCellCoord(dragger->mEnd.x - static_cast<float>(footprint.mSizeX) * 0.5f));
  const float endZ =
    static_cast<float>(BuildDragCellCoord(dragger->mEnd.z - static_cast<float>(footprint.mSizeZ) * 0.5f));

  // 0x0082339E: only the first order of the run may clear the target queue.
  bool hasIssuedAnyOrder = false;

  // 0x008233A3: both spans are pure out-parameters - the callee writes them
  // unconditionally, so the initialisers here are dead stores that keep the
  // locals from being read uninitialised in the (impossible) failure path.
  float templateSpanZ = 0.0f;
  float templateSpanX = 0.0f;
  gpg::fastvector_n<moho::SBuildTemplateInfo, 16> templates;
  (void)session->GetActiveBuildTemplate(&templateSpanZ, &templateSpanX, &templates);

  SBuildDragStep dragStep{};
  moho::SOccupationResult occupation{};
  moho::CHeightField* const heightField = session->mWldMap->mTerrainRes->GetHeightField();

  if (!templates.Empty()) {
    // 0x008233D5-0x00823419: step along whichever axis the drag is longer on,
    // one whole template extent per step.
    const float deltaX = std::fabs(endX - startX);
    const float deltaZ = std::fabs(endZ - startZ);
    const float stepLength = (deltaX > deltaZ) ? templateSpanX : templateSpanZ;
    InitBuildDragStepState(&dragStep, stepLength, startX, startZ, endX, endZ);

    while (dragStep.mStepCount > 0) { // 0x00823444 / 0x0082376C
      // 0x00823460-0x008234B5: the step lands on a cell; the template anchors
      // at that cell's centre.
      const float anchorX = static_cast<float>(BuildDragCellCoord(dragStep.mX)) + 0.5f;
      const float anchorZ = static_cast<float>(BuildDragCellCoord(dragStep.mZ)) + 0.5f;

      // 0x0082347F-0x008234CC: the elevation probe walks the height field and
      // the result is then discarded (`fstp st` at 0x008234CC) - the placement
      // Y comes from the occupation result below.
      (void)heightField->GetElevation(anchorX, anchorZ);

      // By value: the binary copy-constructs a whole SBuildTemplateInfo per
      // iteration (0x008234E0-0x00823735, four POD dwords plus the blueprint-id
      // string) and destroys it at the bottom of the loop.
      for (const moho::SBuildTemplateInfo& entry : templates) {
        const moho::SBuildTemplateInfo templateEntry(entry);
        const float placeX = anchorX + templateEntry.mPos.x;
        const float placeZ = anchorZ + templateEntry.mPos.z;

        // 0x008235A5-0x008235CF: the entry's blueprint id is filename-normalised
        // into a scoped temporary and resolved through the rules' vtable.
        moho::RResId entryBlueprintId{};
        (void)gpg::STR_SetFilename(&entryBlueprintId.name, gpg::StrArg(templateEntry.mBlueprintId.c_str()));
        moho::RUnitBlueprint* const entryBlueprint = session->mRules->GetUnitBlueprint(entryBlueprintId);

        // 0x008235FD-0x0082364F: the payload is built before the placement test
        // runs, exactly as the binary orders it.
        moho::SSTICommandIssueData issueData(moho::EUnitCommandType::UNITCOMMAND_BuildMobile);
        issueData.mBlueprint = entryBlueprint;

        const moho::SCoordsVec2 placement{placeX, placeZ};
        const bool placeable =
          moho::USERUNIT_CanBeBuiltAt(*session, entryBlueprint, placement, false, &occupation, nullptr);

        // 0x00823664-0x00823671: an unbuildable spot is still ordered while the
        // session is not previewing invalid placements.
        if (placeable || !session->mShowInvalidBuildPlacementPreview) {
          issueData.mTarget.mPos = occupation.pos;
          issueData.mTarget.mType = moho::EAiTargetType::AITARGET_Ground;
          issueData.mTarget.mEnt = 0xF0000000u;

          // 0x00823692-0x008236CF
          moho::ISSUE_Command(session->mSelection, issueData, !hasIssuedAnyOrder && !appendToQueue);
          hasIssuedAnyOrder = true;
        }
      }

      // 0x0082373B-0x0082376C
      dragStep.mX += dragStep.mXStep;
      dragStep.mZ += dragStep.mZStep;
      --dragStep.mStepCount;
    }
  } else {
    // 0x00823777-0x00823799: without a template the stride is the blueprint's
    // larger skirt extent.
    const float stepLength = (buildBlueprint->Physics.SkirtSizeZ > buildBlueprint->Physics.SkirtSizeX)
      ? buildBlueprint->Physics.SkirtSizeZ
      : buildBlueprint->Physics.SkirtSizeX;
    InitBuildDragStepState(&dragStep, stepLength, startX, startZ, endX, endZ);

    while (dragStep.mStepCount > 0) { // 0x008237E4 / 0x00823A02
      // 0x00823800-0x00823879: back from footprint origin to footprint centre.
      const float placeX =
        static_cast<float>(BuildDragCellCoord(dragStep.mX)) + static_cast<float>(footprint.mSizeX) * 0.5f;
      const float placeZ =
        static_cast<float>(BuildDragCellCoord(dragStep.mZ)) + static_cast<float>(footprint.mSizeZ) * 0.5f;

      // 0x0082387F-0x0082389F: sampled and discarded, same as the template run.
      (void)heightField->GetElevation(placeX, placeZ);

      moho::SSTICommandIssueData issueData(moho::EUnitCommandType::UNITCOMMAND_BuildMobile);
      issueData.mBlueprint = buildBlueprint;

      // 0x008238B4-0x00823934: anchored builds must also be in range. When the
      // range test fails the buildability test is skipped entirely, so
      // `occupation` deliberately keeps whatever the previous step left in it -
      // the binary relies on that when it falls through to the
      // show-invalid path below.
      const moho::SCoordsVec2 placement{placeX, placeZ};
      bool placeable = true;
      if (commandMode.mMode == moho::COMMOD_BuildAnchored) {
        placeable = moho::USERUNIT_WithinBuildDistance(*session, buildBlueprint, placement);
      }
      if (placeable) {
        placeable = moho::USERUNIT_CanBeBuiltAt(*session, buildBlueprint, placement, false, &occupation, nullptr);
      }

      if (placeable || !session->mShowInvalidBuildPlacementPreview) {
        issueData.mTarget.mPos = occupation.pos;
        issueData.mTarget.mType = moho::EAiTargetType::AITARGET_Ground;
        issueData.mTarget.mEnt = 0xF0000000u;

        moho::ISSUE_Command(session->mSelection, issueData, !hasIssuedAnyOrder && !appendToQueue);
        hasIssuedAnyOrder = true;
      }

      // 0x008239D5-0x00823A02
      dragStep.mX += dragStep.mXStep;
      dragStep.mZ += dragStep.mZStep;
      --dragStep.mStepCount;
    }
  }

  // 0x00823A08-0x00823A4A: one terminal notification for the whole run.
  {
    const moho::SSTICommandIssueData runCompleteData(moho::EUnitCommandType::UNITCOMMAND_None);
    moho::UI_OnCommandIssued(session->mSelection, runCompleteData, !appendToQueue);
  }

  // 0x00823A4F-0x00823A93: destroy every entry's blueprint-id string and drop
  // any spilled heap storage. `templates` is a local `gpg::fastvector_n<
  // SBuildTemplateInfo, 16>`; its own destructor does this at scope exit.
}

/**
 * Address: 0x00823BD0 (FUN_00823BD0, slot +0x08 of ??_7UIBuildDragger@Moho@@6B@)
 * Mangled: ?DragRelease@UIBuildDragger@Moho@@UAEXPBUSMauiEventData@2@@Z
 *
 * IDA signature:
 * void __thiscall Moho::UIBuildDragger::DragRelease(
 *     Moho::UIBuildDragger *this@<ecx>, Moho::SMauiEventData *eventData);
 *
 * What it does:
 * Ends the build drag: one last `ReleaseDrag` snap of `mEnd` (0x00823BDD),
 * the whole run of build orders (0x00823BE3), then both bound world-view
 * preview lanes reset to the invalid-vector sentinel so the preview stops
 * drawing (`mWldView->mStart` at +0x44..+0x4C, 0x00823C48/0x00823C55/
 * 0x00823C62; `mWldView->mEnd` at +0x50..+0x58, 0x00823C6F/0x00823C7C/
 * 0x00823C89), and finally `delete this` through slot +0x00 (0x00823C8E).
 */
void moho::UIBuildDragger::DragRelease(
  const moho::SMauiEventData* const eventData
)
{
  ReleaseDrag(eventData);
  IssueBuildDragOrders(this, eventData);

  const Wm3::Vector3f& invalid = InvalidBuildDragVector();
  mWldView->mStart = invalid;
  mWldView->mEnd = invalid;

  delete this;
}

/**
 * Address: 0x00822F60 (FUN_00822F60)
 *
 * What it does:
 * Thin forwarding lane that adapts drag-step initializer arguments and
 * returns the same state pointer.
 */
[[maybe_unused]] static SBuildDragStep* InitBuildDragStepStateAndReturnState(
  SBuildDragStep* const state,
  const float stepLength,
  const float startX,
  const float startZ,
  const float endX,
  const float endZ
) noexcept
{
  InitBuildDragStepState(state, stepLength, startX, startZ, endX, endZ);
  return state;
}

/**
 * Address: 0x00852C10 (FUN_00852C10, sub_852C10)
 *
 * What it does:
 * Drives the build-drag preview for one frame; see the header for the full
 * description.
 */
void moho::CBuildDragPreview::UpdateDragPreview()
{
  moho::CommandModeData mode;
  (void)mSession->GetLeftMouseButtonAction(&mode, &mSession->CursorInfo(), 0);

  const auto* const buildBlueprint = static_cast<const moho::RUnitBlueprint*>(mode.mBlueprint);

  moho::RMeshBlueprint* activeMesh = nullptr;
  if (buildBlueprint != nullptr) {
    activeMesh = mSession->mRules->GetMeshBlueprint(buildBlueprint->Display.MeshBlueprint);
  }

  // Anything that changes what is being placed invalidates the whole cached
  // preview run, meshes and blueprints alike.
  if (mActiveBuildMesh != activeMesh || mode.mMode != mActiveCommandMode) {
    ClearBuildPreviewCache();
  }
  mActiveBuildMesh = activeMesh;
  mActiveCommandMode = mode.mMode;

  RefreshQueuedBuildGhosts();

  if (
    (mode.mMode != moho::COMMOD_Build && mode.mMode != moho::COMMOD_BuildAnchored) || mActiveBuildMesh == nullptr ||
    mActiveBuildMesh->mLods.empty()
  ) {
    mPreviewInvalid = true;
    return;
  }

  // An invalid drag start means "no drag yet" - the preview collapses onto the
  // cursor cell.
  Wm3::Vector3f dragStart = mStart;
  Wm3::Vector3f dragEnd = mEnd;
  if (!moho::IsValidVector3f(dragStart)) {
    dragStart = mode.mMouseDragStart.mMouseWorldPos;
    dragEnd = dragStart;
  }

  if (!moho::IsValidVector3f(dragStart) || !moho::IsValidVector3f(dragEnd)) {
    mPreviewInvalid = true;
    return;
  }

  mPreviewInvalid = false;

  const moho::STIMap* const map = mSession->GetSTIMap();
  const gpg::Rect2i playable = map->mPlayableRect;
  const moho::SFootprint& footprint = buildBlueprint->mFootprint;
  const moho::SOCellPos startCell = footprint.ToCellPos(dragStart);
  const moho::SOCellPos endCell = footprint.ToCellPos(dragEnd);

  std::int32_t cachedMeshCount = static_cast<std::int32_t>(mMeshes.size());
  std::int32_t placedCount = 0;

  float templateSpanZ = 0.0f;
  float templateSpanX = 0.0f;
  gpg::fastvector_n<moho::SBuildTemplateInfo, 16> buildTemplate{};
  (void)mSession->GetActiveBuildTemplate(&templateSpanZ, &templateSpanX, &buildTemplate);

  // Whichever axis the drag runs along picks the stamp pitch.
  const std::int32_t spanCellsX = std::abs(endCell.x - startCell.x);
  const std::int32_t spanCellsZ = std::abs(endCell.z - startCell.z);

  const auto placeOne =
    [this, &cachedMeshCount, &placedCount](
      moho::RUnitBlueprint* const blueprint, const moho::VTransform& stance, const std::uint32_t previewColor
    ) {
    const std::int32_t slot = placedCount;
    if (slot >= cachedMeshCount) {
      AppendBuildPreviewMesh(blueprint);
      ++cachedMeshCount;
    } else {
      ReplaceBuildPreviewMesh(static_cast<std::size_t>(slot), blueprint);
    }

    if (const boost::shared_ptr<moho::MeshInstance>& preview = mMeshes[static_cast<std::size_t>(slot)]; preview) {
      preview->color = static_cast<std::int32_t>(previewColor);
      preview->SetStance(stance, stance);
    }
    ++placedCount;
  };

  if (!buildTemplate.Empty()) {
    const float stepLength = spanCellsX > spanCellsZ ? templateSpanX : templateSpanZ;

    SBuildDragStep step{};
    (void)InitBuildDragStepStateAndReturnState(
      &step,
      stepLength,
      static_cast<float>(startCell.x),
      static_cast<float>(startCell.z),
      static_cast<float>(endCell.x),
      static_cast<float>(endCell.z)
    );

    for (; step.mStepCount > 0; --step.mStepCount) {
      const moho::SOCellPos cell{
        static_cast<std::int16_t>(static_cast<std::int32_t>(step.mX)),
        static_cast<std::int16_t>(static_cast<std::int32_t>(step.mZ))
      };
      // A template stamp is placed relative to a plain 1x1 cell origin; each
      // entry carries its own offset and its own blueprint.
      const Wm3::Vector3f stampOrigin = moho::COORDS_ToWorldPos(map, cell, moho::LAYER_None, 1, 1);

      for (const moho::SBuildTemplateInfo& entry : buildTemplate) {
        const Wm3::Vector3f entryPosition{
          stampOrigin.x + entry.mPos.x, stampOrigin.y + entry.mPos.y, stampOrigin.z + entry.mPos.z
        };

        // `RResId` is a bare `fa::string` wrapper, which is why the binary
        // hands the canonicalised path buffer straight to the rules lookup.
        moho::RResId blueprintPath;
        (void)gpg::STR_InitFilename(&blueprintPath.name, entry.mBlueprintId.c_str());
        auto* const entryBlueprint = mSession->mRules->GetUnitBlueprint(blueprintPath);

        const auto cellX = static_cast<std::int32_t>(entryPosition.x);
        const auto cellZ = static_cast<std::int32_t>(entryPosition.z);
        if (cellX < playable.x0 || cellX >= playable.x1 || cellZ < playable.z0 || cellZ >= playable.z1) {
          continue;
        }

        moho::VTransform stance;
        stance.orient_ = Wm3::Quatf(1.0f, 0.0f, 0.0f, 0.0f);
        stance.pos_ = Wm3::Vector3f(0.0f, 0.0f, 0.0f);
        const std::uint32_t previewColor =
          moho::EvaluateBuildTemplatePlacementPreview(entryPosition, entryBlueprint, *mSession, stance);

        placeOne(entryBlueprint, stance, previewColor);
      }

      step.mX += step.mXStep;
      step.mZ += step.mZStep;
    }
  } else {
    // No template: one preview per cell, stepping by the blueprint's own
    // skirt extent along the dominant drag axis.
    const float stepLength = std::max(buildBlueprint->Physics.SkirtSizeX, buildBlueprint->Physics.SkirtSizeZ);

    SBuildDragStep step{};
    (void)InitBuildDragStepStateAndReturnState(
      &step,
      stepLength,
      static_cast<float>(startCell.x),
      static_cast<float>(startCell.z),
      static_cast<float>(endCell.x),
      static_cast<float>(endCell.z)
    );

    for (; step.mStepCount > 0; --step.mStepCount) {
      const moho::SOCellPos cell{
        static_cast<std::int16_t>(static_cast<std::int32_t>(step.mX)),
        static_cast<std::int16_t>(static_cast<std::int32_t>(step.mZ))
      };
      const Wm3::Vector3f cellPosition = moho::COORDS_ToWorldPos(
        map, cell, static_cast<moho::ELayer>(footprint.mOccupancyCaps), footprint.mSizeX, footprint.mSizeZ
      );

      // Unlike the template branch this one stops at the first cell that
      // leaves the playable area rather than skipping it.
      const auto cellX = static_cast<std::int32_t>(cellPosition.x);
      const auto cellZ = static_cast<std::int32_t>(cellPosition.z);
      if (cellX < playable.x0 || cellX >= playable.x1 || cellZ < playable.z0 || cellZ >= playable.z1) {
        break;
      }

      moho::VTransform stance;
      stance.orient_ = Wm3::Quatf(1.0f, 0.0f, 0.0f, 0.0f);
      stance.pos_ = Wm3::Vector3f(0.0f, 0.0f, 0.0f);
      const std::uint32_t previewColor =
        moho::EvaluateCommandModeBuildPlacementPreview(mode, cellPosition, *mSession, stance);

      // The single-blueprint lane reuses the cached slot in place rather than
      // recreating its mesh, so it only overwrites the blueprint entry.
      const std::int32_t slot = placedCount;
      if (slot >= cachedMeshCount) {
        AppendBuildPreviewMesh(const_cast<moho::RUnitBlueprint*>(buildBlueprint));
        ++cachedMeshCount;
      } else if (mBlueprints[static_cast<std::size_t>(slot)] != nullptr) {
        mBlueprints[static_cast<std::size_t>(slot)] = const_cast<moho::RUnitBlueprint*>(buildBlueprint);
      }

      if (const boost::shared_ptr<moho::MeshInstance>& preview = mMeshes[static_cast<std::size_t>(slot)]; preview) {
        preview->color = static_cast<std::int32_t>(previewColor);
        preview->SetStance(stance, stance);
      }

      ++placedCount;
      step.mX += step.mXStep;
      step.mZ += step.mZStep;
    }
  }

  // Trim whatever a longer previous drag left behind.
  if (cachedMeshCount > placedCount) {
    mMeshes.resize(static_cast<std::size_t>(placedCount));
    mBlueprints.resize(static_cast<std::size_t>(placedCount));
  }
  // `buildTemplate` is a local `gpg::fastvector_n<SBuildTemplateInfo, 16>`;
  // its own destructor releases every entry and any spilled heap storage.
}

/**
 * Address: 0x0086DFF0 (FUN_0086DFF0, func_ProcessMouseScrubbing)
 *
 * What it does:
 * While scrub mode is active, accumulates mouse delta into scrub lanes,
 * recenters the cursor to scrub anchor, and hides cursor texture state.
 */
static void func_ProcessMouseScrubbing()
{
  if (sMouseIsScrubbing == 0) {
    return;
  }

  POINT cursorPoint{};
  ::GetCursorPos(&cursorPoint);
  // The shipped build flips these two accumulations from `add` to `sub` by
  // rewriting the instructions at 0x0086E01F / 0x0086E027; carry that choice
  // as a sign instead. See UI_SetInvertMidMouseScrub.
  const LONG scrubSign = sInvertMidMouseScrub ? -1 : 1;
  sMouseScrubDelta.x += scrubSign * (cursorPoint.x - sMouseScrubLanded.x);
  sMouseScrubDelta.y += scrubSign * (cursorPoint.y - sMouseScrubLanded.y);
  ::SetCursorPos(sMouseScrubAnchor.x, sMouseScrubAnchor.y);
  ::GetCursorPos(&sMouseScrubLanded);

  auto* const cursor = moho::g_UIManager->GetCursor();
  (void)SetCursorShowingAndMarkDirty(cursor, false);
}

/**
 * Address: 0x0086E270 (FUN_0086E270, ??0CMiniMapDragger@Moho@@QAE@@Z)
 *
 * What it does:
 * Initializes one minimap dragger and copies its camera-name lane from the
 * incoming string payload. The string arrives by value (`retn 20h` == the
 * 4-byte `this` plus the 0x1C-byte `std::string`), which is why the sole call
 * site copy-constructs a temporary before the call (0x00870DB5).
 */
CMiniMapDragger::CMiniMapDragger(
  fa::string cameraName
)
  : moho::IMauiDragger()
{
  mCameraName.assign(cameraName, 0, fa::string::npos);
}

/**
 * Address: 0x0086E2F0 (FUN_0086E2F0, Moho::CMiniMapDragger::DragMove)
 * Slot: +0x04
 *
 * What it does:
 * Updates world-session cursor screen lanes from incoming Maui event coords
 * and retargets the named minimap camera to the current cursor world point.
 */
void CMiniMapDragger::DragMove(
  const moho::SMauiEventData* const eventData
)
{
  moho::CWldSession* const activeSession = moho::WLD_GetActiveSession();
  if (activeSession == nullptr) {
    return;
  }

  moho::MouseInfo& sessionCursor = activeSession->CursorInfo();
  if (sessionCursor.mHitValid == 0u) {
    return;
  }

  moho::RCamManager* const cameraManager = moho::CAM_GetManager();
  moho::CameraImpl* const camera = cameraManager != nullptr ? cameraManager->GetCamera(mCameraName.c_str()) : nullptr;
  if (camera == nullptr) {
    return;
  }

  moho::MouseInfo cursorInfo = sessionCursor;
  cursorInfo.mMouseScreenPos.x = eventData->mMousePos.x;
  cursorInfo.mMouseScreenPos.y = eventData->mMousePos.y;
  sessionCursor = cursorInfo;

  camera->TargetLocation(cursorInfo.mMouseWorldPos, 0.0f);
}

/**
 * Address: 0x0086E3F0 (FUN_0086E3F0, Moho::CMiniMapDragger::DragRelease)
 * Slot: +0x08
 *
 * What it does:
 * Destroys this minimap dragger instance.
 */
void CMiniMapDragger::DragRelease(
  const moho::SMauiEventData* const /*eventData*/
)
{
  delete this;
}

/**
 * Address: 0x0086E3E0 (FUN_0086E3E0, Moho::CMiniMapDragger::DragCancel)
 * Slot: +0x0C
 *
 * What it does:
 * Destroys this minimap dragger instance.
 */
void CMiniMapDragger::OnCurrentDraggerReplaced()
{
  delete this;
}

/**
 * Address: 0x00823CB0 (FUN_00823CB0, func_NewUIBuildDragger)
 *
 * What it does:
 * Allocates one UIBuildDragger, runs its constructor with session/world-view/
 * camera lanes, then posts the dragger; on allocation failure it posts a null
 * dragger lane.
 */
static void func_NewUIBuildDragger(
  moho::CMauiFrame* const originFrame,
  moho::CWldSession* const session,
  const moho::SMauiEventData* const eventData,
  moho::CameraImpl* const camera,
  moho::CBuildDragPreview* const worldView
)
{
  auto* const storage = static_cast<moho::UIBuildDragger*>(::operator new(sizeof(moho::UIBuildDragger), std::nothrow));
  if (storage != nullptr) {
    auto* const dragger = new (storage) moho::UIBuildDragger(session, worldView, camera);
    func_PostDragger(originFrame, dragger, eventData);
    return;
  }

  func_PostDragger(originFrame, nullptr, eventData);
}

/**
 * Address: 0x008242B0 (FUN_008242B0, func_NewCommandDragger)
 *
 * IDA signature:
 * int __usercall func_NewCommandDragger@<eax>(
 *     Moho::CMauiFrame *a1@<edi>, Moho::CWldSession *a2,
 *     Moho::SMauiEventData *a3, Moho::CameraImpl *a4, int isDragger);
 *
 * What it does:
 * Allocates one `UICommandDragger` (`push 1Ch` at 0x008242C7 - the class's own
 * 0x1C bytes), constructs it over the session/camera/dragged-command triple and
 * posts it as the world view's active dragger. On allocation failure the
 * constructor is skipped (`xor eax, eax` at 0x008242F8) and a null dragger is
 * posted, exactly as the sibling build-drag and selection-drag factories do.
 *
 * Invocation: sole caller is `Moho::CUIWorldView::HandleEvent` (0x008704B0),
 * from the `COMMOD_Reclaim` arm of the left-button-press command-mode switch
 * (call site 0x00870EBB). That parent is recovered further down this file and
 * calls this helper by name, as it does the three siblings around it
 * (`func_NewUIBuildDragger`, `NewSelectionDragger`, `func_StartMouseScrubbing`).
 */
static void func_NewCommandDragger(
  moho::CMauiFrame* const originFrame,
  moho::CWldSession* const session,
  const moho::SMauiEventData* const eventData,
  moho::CameraImpl* const camera,
  const moho::CmdId commandId
)
{
  auto* const storage =
    static_cast<moho::UICommandDragger*>(::operator new(sizeof(moho::UICommandDragger), std::nothrow));
  if (storage != nullptr) {
    auto* const dragger = new (storage) moho::UICommandDragger(session, camera, commandId);
    func_PostDragger(originFrame, dragger, eventData);
    return;
  }

  func_PostDragger(originFrame, nullptr, eventData);
}

/**
 * Address: 0x00865880 (FUN_00865880)
 * Decompiler placeholder name: `func_NewSelectionDragger2D` - misleading.
 * Despite the name, this allocates a `SelectionDragger3D` on the
 * `Moho::ui_DragSelect2D == false` path: that branch's sole callee is
 * `Moho::SelectionDragger3D::SelectionDragger3D` (0x008640F0, see
 * `SelectionDragger.cpp`), not a second `SelectionDragger2D` construction.
 * Recovered here as a behavior-first free-function name instead.
 *
 * IDA signature:
 * Moho::SelectionDragger2D *__usercall func_NewSelectionDragger2D@<eax>(
 *     Moho::CWldSession *edx0@<edx>, Moho::CMauiFrame *a1,
 *     struct Moho::SMauiEventData *a3);
 * (The `Moho::SelectionDragger2D*` return type in that signature is the
 * decompiler's own imprecise type inference - the `ui_DragSelect2D == false`
 * path returns a `SelectionDragger3D*` through the same slot, so the real
 * common return type is `IMauiDragger*`, which is what both branches
 * construct a subclass of.)
 *
 * What it does:
 * Allocates either a `SelectionDragger2D` (screen-space rubber-band) or a
 * `SelectionDragger3D` (world-space volume, highlighted with terrain decals)
 * depending on `Moho::ui_DragSelect2D`, constructs it with the supplied
 * camera/session, then posts it as the world view's active dragger through
 * `func_PostDragger`. Posts a null dragger on allocation failure (matching
 * the binary's `xor eax, eax` fallthrough on both branches).
 *
 * Invocation: sole caller is `Moho::CUIWorldView::HandleEvent` (0x008704B0),
 * recovered further down this file, which calls it by name from the
 * `COMMOD_Move` non-minimap arm of its left-button-press command switch and
 * then binds the returned dragger into `CUIWorldView::mSelectionDragger`.
 * The disassembly at 0x00870E0C-0x00870E23 resolves the
 * call's arguments from the world view's own fields: `camera` from
 * `CUIWorldView::mCamera` (+0x120, the raw pointer
 * value the constructor chain stores verbatim into `SelectionDragger::mCam`
 * with no dereference in between), `session` from
 * `CUIWorldView::mWldSession` (+0x208), and `originFrame` from
 * `CMauiControl::mRootFrame` (+0xFC); `eventData` is `HandleEvent`'s own event
 * argument forwarded through unchanged.
 */
static moho::ISelectionDragger* NewSelectionDragger(
  moho::CameraImpl* const camera,
  moho::CWldSession* const session,
  moho::CMauiFrame* const originFrame,
  const moho::SMauiEventData* const eventData
)
{
  moho::ISelectionDragger* dragger = nullptr;

  if (moho::ui_DragSelect2D) {
    auto* const storage =
      static_cast<moho::SelectionDragger2D*>(::operator new(sizeof(moho::SelectionDragger2D), std::nothrow));
    if (storage != nullptr) {
      dragger = new (storage) moho::SelectionDragger2D(camera, session);
    }
  } else {
    auto* const storage =
      static_cast<moho::SelectionDragger3D*>(::operator new(sizeof(moho::SelectionDragger3D), std::nothrow));
    if (storage != nullptr) {
      dragger = new (storage) moho::SelectionDragger3D(camera, session);
    }
  }

  func_PostDragger(originFrame, dragger, eventData);
  return dragger;
}

/**
 * Address: 0x00873170 (FUN_00873170, cfunc_CUIWorldViewSetCartographic)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldViewSetCartographicL`.
 */
int moho::cfunc_CUIWorldViewSetCartographic(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldViewSetCartographicL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00873190 (FUN_00873190, func_CUIWorldViewSetCartographic_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIWorldView:SetCartographic(bool)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldViewSetCartographic_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetCartographic",
    &moho::cfunc_CUIWorldViewSetCartographic,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldViewSetCartographicHelpText
  );
  return &binder;
}

/**
 * Address: 0x008731F0 (FUN_008731F0, cfunc_CUIWorldViewSetCartographicL)
 *
 * What it does:
 * Updates one world-view orthographic/cartographic render mode flag.
 */
int moho::cfunc_CUIWorldViewSetCartographicL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCUIWorldViewSetCartographicHelpText);

  LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);
  LuaPlus::LuaStackObject cartographicArg(state, 2);
  worldView->SetOrthographic(cartographicArg.GetBoolean());
  return 0;
}

/**
 * Address: 0x008732C0 (FUN_008732C0, cfunc_CUIWorldViewIsCartographic)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldViewIsCartographicL`.
 */
int moho::cfunc_CUIWorldViewIsCartographic(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldViewIsCartographicL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x008732E0 (FUN_008732E0, func_CUIWorldViewIsCartographic_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIWorldView:IsCartographic()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldViewIsCartographic_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "IsCartographic",
    &moho::cfunc_CUIWorldViewIsCartographic,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldViewIsCartographicHelpText
  );
  return &binder;
}

/**
 * Address: 0x00873340 (FUN_00873340, cfunc_CUIWorldViewIsCartographicL)
 *
 * What it does:
 * Returns whether one world-view currently renders in orthographic mode.
 */
int moho::cfunc_CUIWorldViewIsCartographicL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCUIWorldViewIsCartographicHelpText);

  LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);
  lua_pushboolean(
    state->m_state, worldView->CanShake()
  );
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00873410 (FUN_00873410, cfunc_CUIWorldViewEnableResourceRendering)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldViewEnableResourceRenderingL`.
 */
int moho::cfunc_CUIWorldViewEnableResourceRendering(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldViewEnableResourceRenderingL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00873430 (FUN_00873430, func_CUIWorldViewEnableResourceRendering_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIWorldView:EnableResourceRendering(bool)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldViewEnableResourceRendering_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "EnableResourceRendering",
    &moho::cfunc_CUIWorldViewEnableResourceRendering,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldViewEnableResourceRenderingHelpText
  );
  return &binder;
}

/**
 * Address: 0x00873490 (FUN_00873490, cfunc_CUIWorldViewEnableResourceRenderingL)
 *
 * What it does:
 * Updates one world-view resource-rendering enable flag.
 */
int moho::cfunc_CUIWorldViewEnableResourceRenderingL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCUIWorldViewEnableResourceRenderingHelpText);

  LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);
  LuaPlus::LuaStackObject enabledArg(state, 2);
  worldView->mEnableResourceRendering =
    enabledArg.GetBoolean() ? static_cast<std::uint8_t>(1u) : static_cast<std::uint8_t>(0u);
  return 0;
}

/**
 * Address: 0x00873550 (FUN_00873550, cfunc_CUIWorldViewIsResourceRenderingEnabled)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldViewIsResourceRenderingEnabledL`.
 */
int moho::cfunc_CUIWorldViewIsResourceRenderingEnabled(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldViewIsResourceRenderingEnabledL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00873570 (FUN_00873570, func_CUIWorldViewIsResourceRenderingEnabled_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIWorldView:IsResourceRenderingEnabled()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldViewIsResourceRenderingEnabled_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "IsResourceRenderingEnabled",
    &moho::cfunc_CUIWorldViewIsResourceRenderingEnabled,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldViewIsResourceRenderingEnabledHelpText
  );
  return &binder;
}

/**
 * Address: 0x008735D0 (FUN_008735D0, cfunc_CUIWorldViewIsResourceRenderingEnabledL)
 *
 * What it does:
 * Returns whether one world-view has resource rendering enabled.
 */
int moho::cfunc_CUIWorldViewIsResourceRenderingEnabledL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCUIWorldViewIsResourceRenderingEnabledHelpText);

  LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);
  lua_pushboolean(state->m_state, worldView->mEnableResourceRendering != 0);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x008725B0 (FUN_008725B0, cfunc_CUIWorldViewZoomScale)
 *
 * What it does:
 * Unwraps the raw Lua callback context and forwards to
 * `cfunc_CUIWorldViewZoomScaleL`.
 */
int moho::cfunc_CUIWorldViewZoomScale(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldViewZoomScaleL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x008725D0 (FUN_008725D0, func_CUIWorldViewZoomScale_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIWorldView:ZoomScale(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldViewZoomScale_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "ZoomScale",
    &moho::cfunc_CUIWorldViewZoomScale,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldViewZoomScaleHelpText
  );
  return &binder;
}

/**
 * Address: 0x00872630 (FUN_00872630, cfunc_CUIWorldViewZoomScaleL)
 *
 * What it does:
 * Reads `CUIWorldView:ZoomScale` Lua args and forwards anchor and wheel
 * zoom lanes into the active world-view camera.
 */
int moho::cfunc_CUIWorldViewZoomScaleL(
  LuaPlus::LuaState* const state
)
{
  if (state == nullptr || state->m_state == nullptr) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 5, kCUIWorldViewZoomScaleHelpText);

  LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);
  if (moho::CameraImpl* const camera = worldView->GetCamera(); camera != nullptr) {
    LuaPlus::LuaStackObject yArg(state, 3);
    if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&yArg, "number");
    }
    const float y = static_cast<float>(lua_tonumber(state->m_state, 3));

    LuaPlus::LuaStackObject xArg(state, 2);
    if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&xArg, "number");
    }
    float zoomAnchor[2] = {static_cast<float>(lua_tonumber(state->m_state, 2)), y};
    camera->CameraSetPivot(Wm3::Vector2f(zoomAnchor[0], zoomAnchor[1]));

    moho::CameraImpl* const wheelCamera = worldView->GetCamera();
    LuaPlus::LuaStackObject wheelDeltaArg(state, 5);
    if (lua_type(state->m_state, 5) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&wheelDeltaArg, "number");
    }
    const float wheelDelta = static_cast<float>(lua_tonumber(state->m_state, 5));

    LuaPlus::LuaStackObject wheelRotArg(state, 4);
    if (lua_type(state->m_state, 4) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&wheelRotArg, "number");
    }
    const float wheelRotation = static_cast<float>(lua_tonumber(state->m_state, 4));
    wheelCamera->CameraZoom(wheelRotation / wheelDelta);
  }

  return 0;
}

/**
 * Address: 0x00872C60 (FUN_00872C60, cfunc_UnProject)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnProjectL`.
 */
int moho::cfunc_UnProject(
  lua_State* const luaContext
)
{
  return cfunc_UnProjectL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00872C80 (FUN_00872C80, func_UnProject_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `UnProject(self, screenPos)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_UnProject_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(), "UnProject", &moho::cfunc_UnProject, nullptr, "<global>", kUnProjectHelpText
  );
  return &binder;
}

/**
 * Address: 0x00872CE0 (FUN_00872CE0, cfunc_UnProjectL)
 *
 * What it does:
 * Resolves one world-view camera and converts a screen-space `Vector2` into
 * a world-space `Vector3` surface point.
 */
int moho::cfunc_UnProjectL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kUnProjectHelpText);

  const LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);
  moho::CameraImpl* const camera = worldView->GetCamera();

  const LuaPlus::LuaObject screenPointObject(LuaPlus::LuaStackObject(state, 2));
  const Wm3::Vector2f screenPoint = SCR_FromLuaCopy<Wm3::Vector2f>(screenPointObject);

  const Wm3::Vector3f worldPoint = camera->CameraScreenToSurface(screenPoint);
  LuaPlus::LuaObject worldPointObject = SCR_ToLua<Wm3::Vector3f>(state, worldPoint);
  worldPointObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x00872E20 (FUN_00872E20, cfunc_CUIWorldViewProject)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldViewProjectL`.
 */
int moho::cfunc_CUIWorldViewProject(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldViewProjectL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00872E40 (FUN_00872E40, func_CUIWorldViewProject_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIWorldView:Project(self, worldPos)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldViewProject_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "Project",
    &moho::cfunc_CUIWorldViewProject,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldViewProjectHelpText
  );
  return &binder;
}

/**
 * Address: 0x00872EA0 (FUN_00872EA0, cfunc_CUIWorldViewProjectL)
 *
 * What it does:
 * Projects one world-space `Vector3` into world-view control-space
 * coordinates and returns one `Vector2` (or nil when camera is absent).
 */
int moho::cfunc_CUIWorldViewProjectL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCUIWorldViewProjectHelpText);

  const LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);
  moho::CameraImpl* const camera = worldView->GetCamera();
  if (camera == nullptr) {
    lua_pushnil(state->m_state);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  const LuaPlus::LuaObject worldPointObject(LuaPlus::LuaStackObject(state, 2));
  const Wm3::Vector3f worldPoint = SCR_FromLuaCopy<Wm3::Vector3f>(worldPointObject);

  const float height = CScriptLazyVar_float::GetValue(&worldView->mHeightLV);
  const float width = CScriptLazyVar_float::GetValue(&worldView->mWidthLV);

  const Wm3::Vector2f projectedPoint = camera->CameraGetView().Project(worldPoint, 0.0f, width, height, 0.0f);
  LuaPlus::LuaObject projectedPointObject = SCR_ToLua<Wm3::Vector2f>(state, projectedPoint);
  projectedPointObject.PushStack(state);
  return 1;
}
namespace
{
  constexpr const char* kCUIWorldViewInitHelpText =
    "moho.UIWorldView:__init(parent_control, cameraName, depth, isMiniMap, trackCamera)";
}


/**
 * Address: 0x0086E480 (FUN_0086E480, Moho::CUIWorldView::CUIWorldView)
 *
 * What it does:
 * Constructs a world-view UI control: the CMauiControl base, the members (two
 * command-mode blocks and the build-drag preview among them), the camera,
 * optional world-camera/minimap promotion, viewport registration, then reads
 * WorldViewParams from /lua/ui/controls/worldview.lua.
 */
moho::CUIWorldView::CUIWorldView(
  LuaPlus::LuaObject* const luaObj,
  moho::CMauiControl* const parent,
  const char* const name,
  const int depth,
  const bool isMiniMap,
  const char* const cameraTrack
)
  : CMauiControl(luaObj, parent, fa::string("World View"))
  , mIsMiniMap(isMiniMap)
  , mWorldViewDepth(depth)
  , mWldSession(moho::WLD_GetActiveSession()) // 0x0086E6A8 reads the global sWldSession
  , mCameraTrack(cameraTrack)
{
  // The +0x11C vtable is written twice (0x0086E4DF the plain
  // ??_7IRenderWorldView@Moho@@6B@, then 0x0086E4EF this class's own
  // ??_7CUIWorldView@Moho@@6BIRenderWorldView@Moho@@@): the interface base,
  // then this class. Every member is constructed by then, with the values the
  // stores at 0x0086E4F9..0x0086E742 write.
  SetDebugName(fa::string(name));

  moho::STIMap* const map =
    mWldSession->mWldMap->mTerrainRes->mMap;
  LuaPlus::LuaState* const activeState = luaObj->GetActiveState();
  moho::RCamManager* const camManager = moho::CAM_GetManager();
  mCamera.reset(camManager->CreateCamera(gpg::StrArg(name), *map, activeState));

  if (_stricmp(name, "WorldCamera") == 0) {
    moho::func_SetWorldCamera(mCamera.get());
  }

  if (isMiniMap) {
    mCamera->SetLODScale(moho::cam_DefaultMiniLOD);
    mCamera->CanShake(false);
  }

  // The root frame's `mTargetHead` (+0x130) picks the viewport head.
  moho::ren_Viewport->AddWorldView(this, static_cast<moho::CMauiFrame*>(mRootFrame)->mTargetHead, mWorldViewDepth);

  mNeedsFrameUpdate = true;

  LuaPlus::LuaObject module =
    moho::SCR_Import(moho::g_UIManager->mLuaState, gpg::StrArg("/lua/ui/controls/worldview.lua"));
  if (!module.IsNil()) {
    LuaPlus::LuaObject params = module["WorldViewParams"];
    if (params.IsTable()) {
      if (!params["ui_SelectTolerance"].IsNil()) {
        moho::ui_SelectTolerance = params["ui_SelectTolerance"].GetNumber();
      }
      if (!params["ui_DisableCursorFixing"].IsNil()) {
        moho::ui_DisableCursorFixing = params["ui_DisableCursorFixing"].GetBoolean();
      }
      if (!params["ui_ExtractSnapTolerance"].IsNil()) {
        moho::ui_ExtractSnapTolerance = params["ui_ExtractSnapTolerance"].GetNumber();
      }
    }
  }
}

gpg::RType* moho::CUIWorldView::sType = nullptr;

/**
 * Address: 0x0086DB70 (FUN_0086DB70, Moho::CUIWorldView::StaticGetClass)
 *
 * What it does:
 * Returns the cached reflection type for `CUIWorldView`, resolving it through
 * RTTI on first use.
 */
gpg::RType* moho::CUIWorldView::StaticGetClass()
{
  if (sType == nullptr) {
    sType = gpg::LookupRType(typeid(CUIWorldView));
  }
  return sType;
}

/**
 * Address: 0x0086DB70 (FUN_0086DB70, Moho::CUIWorldView::GetClass)
 *
 * VFTable SLOT: 0
 */
gpg::RType* moho::CUIWorldView::GetClass() const
{
  return StaticGetClass();
}

/**
 * Address: 0x0086DB90 (FUN_0086DB90, Moho::CUIWorldView::GetDerivedObjectRef)
 *
 * VFTable SLOT: 1
 *
 * What it does:
 * Builds the reflected reference the Lua bridge upcasts from - this pointer
 * plus the type the slot above resolves.
 */
gpg::RRef moho::CUIWorldView::GetDerivedObjectRef()
{
  return gpg::MakeSelfRef(this);
}

/**
 * Address: 0x0086EA40 (FUN_0086EA40, Moho::CUIWorldView::~CUIWorldView)
 * Deleting dtor: 0x0086EA20 (FUN_0086EA20, Moho::CUIWorldView::dtr)
 *
 * What it does:
 * Cancels any dragger still held and takes this view out of the global
 * viewport. Everything after that is member destruction, in reverse
 * declaration order: the selection-dragger link (0x0086EAB8), the camera-track
 * name (0x0086EADE), the build-drag preview (0x0086EB18), the command-graph
 * reference (0x0086EB22), both command-mode blocks (0x0086EB5C/0x0086EB67) and
 * last the camera (0x0086EB71); then the interface vtable restore (0x0086EB85)
 * and `~CMauiControl` (0x0086EB94).
 */
moho::CUIWorldView::~CUIWorldView()
{
  // A dragger outlives the control that posted it, so a view destroyed mid-drag
  // leaves the global lane pointing into freed memory.
  if (IMauiDragger* const currentDragger = func_GetCurrentDragger(); currentDragger != nullptr) {
    currentDragger->OnCurrentDraggerReplaced();
    (void)func_SetCurDragger(nullptr);
    sCurrentDraggerKeycode = 0;
  }

  ren_Viewport->RemoveWorldView(this);
}

/**
 * Address: 0x00871710 (FUN_00871710, cfunc_CUIWorldView__initL)
 *
 * What it does:
 * Lua constructor worker for CUIWorldView:__init. See header.
 */
int moho::cfunc_CUIWorldView__initL(
  LuaPlus::LuaState* const state
)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount < 4 || argumentCount > 6) {
    LuaPlus::LuaState::Error(
      state, "%s\n  expected between %d and %d args, but got %d", kCUIWorldViewInitHelpText, 4, 6, argumentCount
    );
  }

  LuaPlus::LuaObject parentObject(LuaPlus::LuaStackObject(state, 2));
  CMauiControl* const parent = SCR_FromLua_CMauiControl(parentObject, state);

  fa::string trackCamera;
  bool isMiniMap = false;

  if (lua_gettop(state->m_state) == 5) {
    if (LuaPlus::LuaStackObject(state, 5).GetBoolean()) {
      LuaPlus::LuaState::Error(state, "Minimap view must have a view to track defined");
      return 0;
    }
  } else if (lua_gettop(state->m_state) == 6) {
    isMiniMap = LuaPlus::LuaStackObject(state, 5).GetBoolean();
    LuaPlus::LuaStackObject trackArg(state, 6);
    const char* const trackStr = lua_tostring(state->m_state, 6);
    if (trackStr == nullptr) {
      trackArg.TypeError("string");
    }
    trackCamera = fa::string(trackStr, std::strlen(trackStr));
  }

  void* const storage = AllocateZeroedUiObject<void>(sizeof(CUIWorldView));
  CUIWorldView* worldView = nullptr;
  if (storage != nullptr) {
    LuaPlus::LuaObject selfObject(LuaPlus::LuaStackObject(state, 1));

    LuaPlus::LuaStackObject depthArg(state, 4);
    if (lua_type(state->m_state, 4) != LUA_TNUMBER) {
      depthArg.TypeError("number");
    }
    const int depth = static_cast<int>(lua_tonumber(state->m_state, 4));

    LuaPlus::LuaStackObject nameArg(state, 3);
    const char* const cameraName = lua_tostring(state->m_state, 3);
    if (cameraName == nullptr) {
      nameArg.TypeError("string");
    }

    worldView = new (storage) CUIWorldView(&selfObject, parent, cameraName, depth, isMiniMap, trackCamera.c_str());
  }

  worldView->DoInit();
  worldView->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x00871690 (FUN_00871690, cfunc_CUIWorldView__init)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CUIWorldView__initL`.
 */
int moho::cfunc_CUIWorldView__init(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldView__initL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x008716B0 (FUN_008716B0, func_CUIWorldView__init_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIWorldView:__init(...)` Lua constructor binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldView__init_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "__init",
    &moho::cfunc_CUIWorldView__init,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldViewInitHelpText
  );
  return &binder;
}

/**
 * Address: 0x00871A20 (FUN_00871A20, cfunc_CUIWorldViewCameraReset)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldViewCameraResetL`.
 */
int moho::cfunc_CUIWorldViewCameraReset(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldViewCameraResetL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00871A40 (FUN_00871A40, func_CUIWorldViewCameraReset_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIWorldView:CameraReset()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldViewCameraReset_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "CameraReset",
    &moho::cfunc_CUIWorldViewCameraReset,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldViewCameraResetHelpText
  );
  return &binder;
}

/**
 * Address: 0x00871AA0 (FUN_00871AA0, cfunc_CUIWorldViewCameraResetL)
 *
 * What it does:
 * Resets one world-view camera and returns the world-view Lua object.
 */
int moho::cfunc_CUIWorldViewCameraResetL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCUIWorldViewCameraResetHelpText);

  LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);
  if (moho::CameraImpl* const camera = worldView->GetCamera(); camera != nullptr) {
    camera->CameraReset();
  }

  worldView->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x00871B70 (FUN_00871B70, cfunc_CUIWorldViewGetsGlobalCameraCommands)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldViewGetsGlobalCameraCommandsL`.
 */
int moho::cfunc_CUIWorldViewGetsGlobalCameraCommands(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldViewGetsGlobalCameraCommandsL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00871B90 (FUN_00871B90, func_CUIWorldViewGetsGlobalCameraCommands_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIWorldView:GetsGlobalCameraCommands(bool)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldViewGetsGlobalCameraCommands_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetsGlobalCameraCommands",
    &moho::cfunc_CUIWorldViewGetsGlobalCameraCommands,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldViewGetsGlobalCameraCommandsHelpText
  );
  return &binder;
}

/**
 * Address: 0x00871BF0 (FUN_00871BF0, cfunc_CUIWorldViewGetsGlobalCameraCommandsL)
 *
 * What it does:
 * Updates one world-view global-camera-command flag and returns the
 * world-view Lua object.
 */
int moho::cfunc_CUIWorldViewGetsGlobalCameraCommandsL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCUIWorldViewGetsGlobalCameraCommandsHelpText);

  LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);

  LuaPlus::LuaStackObject getsCommandsArg(state, 2);
  worldView->mGlobalCameraCommands =
    getsCommandsArg.GetBoolean() ? static_cast<std::uint8_t>(1u) : static_cast<std::uint8_t>(0u);

  worldView->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x00871CC0 (FUN_00871CC0, cfunc_CUIWorldViewGetRightMouseButtonOrder)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldViewGetRightMouseButtonOrderL`.
 */
int moho::cfunc_CUIWorldViewGetRightMouseButtonOrder(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldViewGetRightMouseButtonOrderL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00871CE0 (FUN_00871CE0, func_CUIWorldViewGetRightMouseButtonOrder_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIWorldView:GetRightMouseButtonOrder()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldViewGetRightMouseButtonOrder_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetRightMouseButtonOrder",
    &moho::cfunc_CUIWorldViewGetRightMouseButtonOrder,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldViewGetRightMouseButtonOrderHelpText
  );
  return &binder;
}

/**
 * Address: 0x00871D40 (FUN_00871D40, cfunc_CUIWorldViewGetRightMouseButtonOrderL)
 *
 * What it does:
 * Resolves the active right-click action from world-session cursor context
 * and returns the order lexical token string (or nil when no order applies).
 */
int moho::cfunc_CUIWorldViewGetRightMouseButtonOrderL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCUIWorldViewGetRightMouseButtonOrderHelpText);

  LuaPlus::LuaObject unused;

  CWldSession* const activeSession = WLD_GetActiveSession();
  moho::MouseInfo& sessionCursor = activeSession->CursorInfo();
  if (sessionCursor.mHitValid != 0u) {
    CommandModeData commandMode{};
    (void)func_GetRightMouseButtonAction(&commandMode, &sessionCursor, 0, activeSession);

    if (commandMode.mMode == COMMOD_Order) {
      gpg::RRef commandCapRef{};
      commandCapRef = gpg::MakeRRef<moho::ERuleBPUnitCommandCaps>(&commandMode.mCommandCaps);
      const fa::string commandLexical = commandCapRef.GetLexical();
      lua_pushstring(state->m_state, commandLexical.c_str());
      (void)lua_gettop(state->m_state);
      return 1;
    }
  }

  lua_pushnil(state->m_state);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00871EC0 (FUN_00871EC0, cfunc_CUIWorldViewHasHighlightCommand)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldViewHasHighlightCommandL`.
 */
int moho::cfunc_CUIWorldViewHasHighlightCommand(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldViewHasHighlightCommandL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00871EE0 (FUN_00871EE0, func_CUIWorldViewHasHighlightCommand_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIWorldView:HasHighlightCommand()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldViewHasHighlightCommand_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "HasHighlightCommand",
    &moho::cfunc_CUIWorldViewHasHighlightCommand,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldViewHasHighlightCommandHelpText
  );
  return &binder;
}

/**
 * Address: 0x00871F40 (FUN_00871F40, cfunc_CUIWorldViewHasHighlightCommandL)
 *
 * What it does:
 * Returns whether the active world-session cursor currently has one
 * highlight command id.
 */
int moho::cfunc_CUIWorldViewHasHighlightCommandL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCUIWorldViewHasHighlightCommandHelpText);

  CWldSession* const activeSession = WLD_GetActiveSession();
  const moho::MouseInfo& sessionCursor = activeSession->CursorInfo();
  lua_pushboolean(state->m_state, sessionCursor.mIsDragger != -1);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00871FA0 (FUN_00871FA0, cfunc_CUIWorldShowConvertToPatrolCursor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldShowConvertToPatrolCursorL`.
 */
int moho::cfunc_CUIWorldShowConvertToPatrolCursor(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldShowConvertToPatrolCursorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00871FC0 (FUN_00871FC0, func_CUIWorldShowConvertToPatrolCursor_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIWorldView:ShowConvertToPatrolCursor()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldShowConvertToPatrolCursor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "ShowConvertToPatrolCursor",
    &moho::cfunc_CUIWorldShowConvertToPatrolCursor,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldShowConvertToPatrolCursorHelpText
  );
  return &binder;
}

/**
 * Address: 0x00872020 (FUN_00872020, cfunc_CUIWorldShowConvertToPatrolCursorL)
 *
 * What it does:
 * Returns one world-view flag controlling patrol-convert cursor display.
 */
int moho::cfunc_CUIWorldShowConvertToPatrolCursorL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCUIWorldShowConvertToPatrolCursorHelpText);

  LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);
  lua_pushboolean(state->m_state, worldView->mConvertToPatrolCursor != 0);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x008720E0 (FUN_008720E0, cfunc_CUIWorldViewUnlockInput)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldViewUnlockInputL`.
 */
int moho::cfunc_CUIWorldViewUnlockInput(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldViewUnlockInputL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00872100 (FUN_00872100, func_CUIWorldViewUnlockInput_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIWorldView:UnlockInput(camera)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldViewUnlockInput_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "UnlockInput",
    &moho::cfunc_CUIWorldViewUnlockInput,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldViewUnlockInputHelpText
  );
  return &binder;
}

/**
 * Address: 0x00872160 (FUN_00872160, cfunc_CUIWorldViewUnlockInputL)
 *
 * What it does:
 * Decrements one world-view input-lock counter lane.
 */
int moho::cfunc_CUIWorldViewUnlockInputL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCUIWorldViewUnlockInputHelpText);

  LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);
  --worldView->mInputLocks;
  return 0;
}

/**
 * Address: 0x00872200 (FUN_00872200, cfunc_CUIWorldViewLockInput)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldViewLockInputL`.
 */
int moho::cfunc_CUIWorldViewLockInput(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldViewLockInputL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00872220 (FUN_00872220, func_CUIWorldViewLockInput_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIWorldView:LockInput(camera)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldViewLockInput_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "LockInput",
    &moho::cfunc_CUIWorldViewLockInput,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldViewLockInputHelpText
  );
  return &binder;
}

/**
 * Address: 0x00872280 (FUN_00872280, cfunc_CUIWorldViewLockInputL)
 *
 * What it does:
 * Increments one world-view input-lock counter lane.
 */
int moho::cfunc_CUIWorldViewLockInputL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCUIWorldViewLockInputHelpText);

  LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);
  ++worldView->mInputLocks;
  return 0;
}

/**
 * Address: 0x00872330 (FUN_00872330, cfunc_CUIWorldViewIsInputLocked)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldViewIsInputLockedL`.
 */
int moho::cfunc_CUIWorldViewIsInputLocked(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldViewIsInputLockedL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00872350 (FUN_00872350, func_CUIWorldViewIsInputLocked_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIWorldView:IsInputLocked(camera)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldViewIsInputLocked_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "IsInputLocked",
    &moho::cfunc_CUIWorldViewIsInputLocked,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldViewIsInputLockedHelpText
  );
  return &binder;
}

/**
 * Address: 0x008723B0 (FUN_008723B0, cfunc_CUIWorldViewIsInputLockedL)
 *
 * What it does:
 * Returns whether one world-view input-lock counter lane is positive.
 */
int moho::cfunc_CUIWorldViewIsInputLockedL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCUIWorldViewIsInputLockedHelpText);

  LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);
  lua_pushboolean(state->m_state, worldView->mInputLocks > 0);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00872470 (FUN_00872470, cfunc_CUIWorldViewSetHighlightEnabled)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldViewSetHighlightEnabledL`.
 */
int moho::cfunc_CUIWorldViewSetHighlightEnabled(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldViewSetHighlightEnabledL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00872490 (FUN_00872490, func_CUIWorldViewSetHighlightEnabled_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIWorldView:SetHighlightEnabled(bool)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldViewSetHighlightEnabled_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetHighlightEnabled",
    &moho::cfunc_CUIWorldViewSetHighlightEnabled,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldViewSetHighlightEnabledHelpText
  );
  return &binder;
}

/**
 * Address: 0x008724F0 (FUN_008724F0, cfunc_CUIWorldViewSetHighlightEnabledL)
 *
 * What it does:
 * Updates one world-view highlight-enabled boolean lane.
 */
int moho::cfunc_CUIWorldViewSetHighlightEnabledL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCUIWorldViewSetHighlightEnabledHelpText);

  LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);
  LuaPlus::LuaStackObject enabledArg(state, 2);
  worldView->mHighlightEnabled =
    enabledArg.GetBoolean() ? static_cast<std::uint8_t>(1u) : static_cast<std::uint8_t>(0u);
  return 0;
}

/**
 * Address: 0x0086EC40 (FUN_0086EC40, Moho::CUIWorldView::SetHidden)
 *
 * What it does:
 * Toggles the world view's participation in viewport rendering: forwards the
 * hidden state to the CMauiControl base, then removes (when hiding) or adds
 * (when showing) the render-world-view into the global viewport, using the
 * root-frame event handler and the view's render depth.
 *
 * VFTable SLOT: 7 (+0x1C)
 */
void moho::CUIWorldView::SetHidden(
  const bool hidden
)
{
  CMauiControl::SetHidden(hidden);

  auto* const renderView = static_cast<IRenderWorldView*>(this);
  if (hidden) {
    ren_Viewport->RemoveWorldView(renderView);
  } else {
    // The root frame's `mTargetHead` (+0x130) picks the viewport head.
    ren_Viewport->AddWorldView(renderView, static_cast<CMauiFrame*>(mRootFrame)->mTargetHead, mWorldViewDepth);
  }
}

/**
 * Address: 0x0086EF40 (FUN_0086EF40, Moho::CUIWorldView::Draw)
 *
 * What it does:
 * Refreshes world-view viewport lazy-var bounds when drawing world content,
 * otherwise dispatches optional overlay draw callback state.
 *
 * VFTable SLOT: 6 (+0x18)
 */
void moho::CUIWorldView::DoRender(
  CD3DPrimBatcher* const primBatcher,
  const std::int32_t drawMask
)
{
  if (drawMask == 1) {
    const float left = CScriptLazyVar_float::GetValue(&mLeftLV);
    const float top = CScriptLazyVar_float::GetValue(&mTopLV);
    const float width = CScriptLazyVar_float::GetValue(&mWidthLV);
    const float height = CScriptLazyVar_float::GetValue(&mHeightLV);

    if (
      mCachedViewLeft != left || mCachedViewTop != top ||
      mCachedViewWidth != width || mCachedViewHeight != height
    ) {
      mCachedViewLeft = left;
      mCachedViewTop = top;
      mCachedViewWidth = width;
      mCachedViewHeight = height;

      // `mCamera` (+0x120) is the world view's own camera. This is the one
      // and only place that pushes the
      // Lua-driven on-screen rect (worldview.lua resizes mLeftLV/Top/
      // Right/Bottom as part of its own layout pass) down to the camera;
      // without it the camera keeps the {0,0}/{1,1} unit placeholder its own
      // constructor seeds, so its frustum never covers real screen space and
      // nothing is ever collected to render (confirmed live via dbgrun:
      // MeshRenderer::Batch's frustum-volume query returned zero instances
      // every frame with the camera stuck at viewport width=1).
      if (moho::CameraImpl* const camera = mCamera.get(); camera != nullptr) {
        // 0x0086EF40 passes the third and fourth lazy vars STRAIGHT THROUGH as the
        // extent - it stores Left/Top into v11 and the +0x98/+0xAC values into v12
        // and calls slot 3 with (v11, v12); there is no subtraction anywhere in the
        // body. CameraSetViewport treats that second argument as a size (it derives
        // the aspect as x/y and normalises row 1 by 1/x), so those two lanes are the
        // control extent, not its right/bottom edges. The invented `right - left` /
        // `bottom - top` gave the minimap a 228x19 viewport - a sliver a few pixels
        // tall - instead of its real 253x211.
        camera->CameraSetViewport(Wm3::Vector2f(left, top), Wm3::Vector2f(width, height));
      }
    }
    return;
  }

  // Any other pass draws the selection dragger this view posted, if it is
  // still alive: `ISelectionDragger::Render`, vtable +0x10 (0x0086F06D).
  if (ISelectionDragger* const selectionDragger = mSelectionDragger.GetObjectPtr(); selectionDragger != nullptr) {
    selectionDragger->Render(primBatcher);
  }
}

/**
 * Address: 0x0086F520 (FUN_0086F520, Moho::CUIWorldView::UpdateSelection)
 *
 * IDA signature:
 * void __stdcall Moho::CUIWorldView::UpdateSelection(
 *   Moho::CUIWorldView *this, Wm3::Vector2f *mouse);
 *
 * What it does: see the declaration.
 *
 * Recovery note (documented, bounded uncertainty): the shipped body carries
 * Hex-Rays' "local variable allocation has failed" warning; the corrupted
 * mess it produces was fixed by clearing two conflicting *user-defined*
 * split-lvar overrides already saved in this project's IDB (stale artifacts
 * of an earlier failed reconstruction pass, at stack byte-offsets 0x40 and
 * 0xD8), then re-decompiling. That repair, plus direct `.asm`
 * `calc_stkvar_struc_offset` verification of every field this comment relies
 * on, resolved the overwhelming majority of the body with confidence -
 * including the selection tie-break block, the `GetActiveBuildTemplate`
 * call arity, the `UICursorInfo::Copy` direction, and every category/army/
 * mask filter. Two narrow spots remain genuine MSVC8 stack-slot-reuse
 * artifacts that cannot be reproduced byte-for-byte in new source without
 * relying on undefined cross-object stack layout: the tail cursor-info
 * persistence below (`resultCursor`) and the extractor-snap search center,
 * both flagged at their call sites.
 */
void moho::CUIWorldView::UpdateSelection(
  const Wm3::Vector2f& mouseScreenPos
)
{
  MouseInfo hit;
  hit.mIsDragger = 0;
  hit.mMouseScreenPos.y = std::numeric_limits<float>::quiet_NaN();
  hit.mMouseWorldPos = mCamera->CameraScreenToSurface(mouseScreenPos);
  const bool raycastHitWorld = IsValidVector3f(hit.mMouseWorldPos);
  hit.mHitValid = raycastHitWorld ? 1u : 0u;

  if (mCursorInside == 0u) {
    // Cursor left the view since the last update: persist the fresh raycast
    // and skip the full selection/highlight/extractor-snap pass entirely.
    mWldSession->CursorInfo() = hit;
    return;
  }

  UserEntity* bestCandidate = nullptr;

  if (raycastHitWorld) {
    const GeomCamera3& cameraView = mCamera->CameraGetView();

    gpg::Rect2f selectionRect{};
    selectionRect.x0 = mouseScreenPos.x - ui_SelectTolerance;
    selectionRect.x1 = mouseScreenPos.x + ui_SelectTolerance;
    selectionRect.z0 = mouseScreenPos.y - ui_SelectTolerance;
    selectionRect.z1 = mouseScreenPos.y + ui_SelectTolerance;
    CGeomSolid3 selectionSolid = cameraView.Unproject(selectionRect);

    const float cameraZoom = mCamera->CameraGetTargetZoom();

    gpg::fastvector<UserEntity*> collected;
    auto* const spatialDb = mWldSession->GetEntitySpatialDbStorage();
    const EEntityType volumeEntityMask =
      (cameraZoom <= 150.0f) ? static_cast<EEntityType>(ENTITYTYPE_Unit | ENTITYTYPE_Prop) : ENTITYTYPE_Unit;
    (void)spatialDb->CollectInVolume(collected, volumeEntityMask, &selectionSolid);


    float bestDistSq = std::numeric_limits<float>::max();

    for (UserEntity* const candidate : collected) {
      if (candidate->mVariableData.mIsDead) {
        continue;
      }

      // SELECTABLE, or FERRYBEACON, or (not) UNTARGETABLE - matches the
      // binary's short-circuit chain exactly (only the categories actually
      // needed to resolve inclusion get string-constructed and tested).
      bool included = candidate->IsInCategory("SELECTABLE");
      if (!included) {
        included = candidate->IsInCategory("FERRYBEACON") || !candidate->IsInCategory("UNTARGETABLE");
      }
      if (!included) {
        continue;
      }

      bool isOnCarrier = false;
      if (UserEntity* const attachmentParent = candidate->GetAttachmentParent()) {
        isOnCarrier = attachmentParent->IsInCategory("CARRIER");
      }
      if (isOnCarrier) {
        continue;
      }

      // Strategic-icon suppression bit; see CWldSession.cpp's identical
      // `kStrategicIconEntitySuppressedMask` local constant (that pass's
      // 0x0085BAC3 gate) for the byte-offset evidence this bit shares.
      constexpr std::uint32_t kStrategicIconEntitySuppressedMask = 0x20u;
      UserUnit* const candidateAsUnit = candidate->IsUserUnit();
      if (
        candidateAsUnit != nullptr && (candidateAsUnit->mIntelStateFlags & kStrategicIconEntitySuppressedMask) != 0u
      ) {
        continue;
      }

      const std::int32_t focusArmy = mWldSession->FocusArmy;
      UserArmy* const focusArmyPtr = (focusArmy < 0) ? nullptr : mWldSession->userArmies[focusArmy];
      const bool ownedByFocusArmy = candidate->mArmy == focusArmyPtr;
      const bool visibleOnPlayableMap =
        mWldSession->GetSTIMap()->IsPlayable(candidate->mVariableData.mCurTransform.pos_) &&
        (candidateAsUnit == nullptr || !candidateAsUnit->mUnitVarDat.mIsBusy);
      if (!ownedByFocusArmy && !visibleOnPlayableMap) {
        continue;
      }

      if (MeshInstance* const mesh = candidate->mMeshInstance) {
        const REntityBlueprint* const blueprint = candidate->mParams.mBlueprint;
        if (blueprint->IsMobile() && blueprint->mUseOOBTestZoom > cameraZoom) {
          // Tight zoom on a mobile unit: exact oriented-mesh pick test
          // against the camera's screen-point pick ray.
          const GeomLine3 pickRay = cameraView.Unproject(mouseScreenPos);
          const Wm3::Line3f wmPickRay(pickRay.pos, pickRay.dir);
          mesh->UpdateInterpolatedFields();
          if (!Wm3::TestLine3Box3(wmPickRay, mesh->box)) {
            continue;
          }
        } else {
          // Otherwise a cheap axis-aligned mesh-bounds test, adjusted by the
          // blueprint's selection-mesh top-weighting and X/Z rescale knobs.
          mesh->UpdateInterpolatedFields();
          float boxXMin = mesh->xMin;
          float boxXMax = mesh->xMax;
          float boxYMin = mesh->yMin;
          float boxYMax = mesh->yMax;
          float boxZMin = mesh->zMin;
          float boxZMax = mesh->zMax;

          if (blueprint->mSelectionMeshUseTopAmount <= 0.0f) {
            boxYMax = boxYMax - ((boxYMax - boxYMin) * blueprint->mSelectionYOffset);
          } else {
            boxYMin = ((1.0f - blueprint->mSelectionMeshUseTopAmount) * (boxYMax - boxYMin)) + boxYMin;
          }
          if (blueprint->mSelectionMeshScaleX != 1.0f) {
            const float centerX = (boxXMin + boxXMax) * 0.5f;
            const float halfX = (boxXMax - centerX) * blueprint->mSelectionMeshScaleX;
            boxXMax = centerX + halfX;
            boxXMin = centerX - halfX;
          }
          if (blueprint->mSelectionMeshScaleZ != 1.0f) {
            const float centerZ = (boxZMin + boxZMax) * 0.5f;
            const float halfZ = (boxZMax - centerZ) * blueprint->mSelectionMeshScaleZ;
            boxZMax = centerZ + halfZ;
            boxZMin = centerZ - halfZ;
          }

          const Wm3::AxisAlignedBox3f selectionBounds{{boxXMin, boxYMin, boxZMin}, {boxXMax, boxYMax, boxZMax}};
          if (!selectionSolid.Intersects(selectionBounds)) {
            continue;
          }
        }
      }

      // Interpolation alpha reads the still-zero (from entry) `mIsDragger`
      // scratch slot - i.e. always 0.0f (last-known/non-interpolated pose).
      const Wm3::Vec3f interpolatedPosition = candidate->GetInterpolatedPosition(0.0f);
      const Wm3::Vector2f projected = cameraView.Project(interpolatedPosition);
      const float dx = projected.x - mouseScreenPos.x;
      const float dy = projected.y - mouseScreenPos.y;
      const float distSq = (dx * dx) + (dy * dy);

      const bool preferOverCurrentBest =
        bestCandidate != nullptr && bestCandidate->IsUserUnit() == nullptr && candidateAsUnit != nullptr;
      if (bestDistSq > distSq || preferOverCurrentBest) {
        bestDistSq = distSq;
        bestCandidate = candidate;
      }
    }

    if (bestCandidate != nullptr) {
      // Redirect hover from an unfinished unit to its builder when the
      // builder is alive/not-destroy-queued and its blueprint's own name
      // matches what the unfinished unit says it upgrades from.
      const std::uint32_t attachmentParentId = bestCandidate->mVariableData.mAttachmentParentRef;
      UserEntity* const attachmentParent = mWldSession->LookupEntityId(static_cast<EntId>(attachmentParentId));
      if (attachmentParent == nullptr) {
        if (UserUnit* const bestAsUnit = bestCandidate->IsUserUnit()) {
          if (bestAsUnit->IsBeingBuilt()) {
            UserEntity* const creator = bestAsUnit->mCreator.GetObjectPtr();
            if (creator != nullptr) {
              if (UserUnit* const creatorUnit = creator->IsUserUnit()) {
                if (!creatorUnit->IsDead() && !creatorUnit->DestroyQueued()) {
                  const RUnitBlueprint* const bestBlueprint = bestAsUnit->GetBlueprint();
                  const RUnitBlueprint* const creatorBlueprint = creatorUnit->GetBlueprint();
                  if (
                    _stricmp(
                      creatorBlueprint->mBlueprintId.c_str(), bestBlueprint->General.UpgradesFrom.name.c_str()
                    ) == 0
                  ) {
                    bestCandidate = creatorUnit;
                  }
                }
              }
            }
          }
        }
      } else if (UserUnit* const attachmentParentAsUnit = attachmentParent->IsUserUnit()) {
        // A unit riding a transport, or still being built inside a factory,
        // hands the hover to its attachment parent, so clicking a factory
        // selects the factory and not the unit on its roll-off pad.
        // 0x0086FDE8 tests TRANSPORTATION and on a hit jumps straight to the
        // redirect (0x0086FDEF `jne 0x0086FE2B`); only a miss tests FACTORY
        // (0x0086FE1D), whose result is the flag. Then 0x0086FE6D re-reads
        // GetAttachmentParent() into the best candidate.
        if (
          attachmentParentAsUnit->IsInCategory("TRANSPORTATION") ||
          attachmentParentAsUnit->IsInCategory("FACTORY")
        ) {
          bestCandidate = attachmentParent;
        }
      }
    }
  }

  // The rest of the frame's cursor-state update runs unconditionally,
  // whether or not the raycast landed on the world.
  // The id of the command node the cursor is over, or -1. This is the value
  // the whole order-interaction layer keys off: `GetLeftMouseButtonAction`
  // feeds it to `DefaultModeFromDrag`, which answers COMMOD_Move for the -1
  // sentinel (top byte 0xFF) and COMMOD_Reclaim - the "grab this command
  // node" arm that builds a `UICommandDragger` - for a real CmdId. It is also
  // what `HasHoveredCommand`, the Lua `IsDragging` binding, and the
  // shift+ctrl right-release command-strip path read.
  CmdId highlightCommandId = -1;
  if (mHighlightEnabled && !mIsMiniMap) {
    highlightCommandId =
      ResolveCommandGraphCursorHighlightIfPresent(mComGraph.get(), mCamera->CameraGetView(), mouseScreenPos);
  }

  float templateSpanZ = 0.0f;
  float templateSpanX = 0.0f;
  gpg::fastvector_n<SBuildTemplateInfo, 16> activeTemplate{};
  (void)mWldSession->GetActiveBuildTemplate(&templateSpanZ, &templateSpanX, &activeTemplate);

  // FAF hot-patch (FA-Binary-Patches BuildTemplateSnap): the stock binary skipped the whole
  // extractor snap while a build template was active (`jnz 0x008701E1`, NOPed at 0x0086FFF0).
  // The mass-extractor snap now always runs; the hydrocarbon snap still needs an empty
  // template (HookHydroCondition, jumped to from 0x00870044).
  {
    CommandModeData leftMouseMode{};
    (void)mWldSession->GetLeftMouseButtonAction(&leftMouseMode, &mWldSession->CursorInfo(), 0);

    if (leftMouseMode.mMode == COMMOD_Build || leftMouseMode.mMode == COMMOD_BuildAnchored) {
      const auto* const buildBlueprint = static_cast<const RUnitBlueprint*>(leftMouseMode.mBlueprint);
      EDepositType depositType = kNone;
      if (buildBlueprint->Physics.BuildRestriction == RULEUBR_OnMassDeposit) {
        depositType = kMass;
      } else if (buildBlueprint->Physics.BuildRestriction == RULEUBR_OnHydrocarbonDeposit && activeTemplate.Empty()) {
        depositType = kHydrocarbon;
      }

      if (depositType != kNone && raycastHitWorld) {
        // Search-radius: the extractor snap tolerance projected through the
        // camera's depth-scale row, clamped to [ui_MinExtractSnapPixels,
        // ui_MaxExtractSnapPixels] on-screen pixels.
        const GeomCamera3& cameraView = mCamera->CameraGetView();
        const float depthW = cameraView.viewport.ProjectViewportWidthRow2(hit.mMouseWorldPos);
        float snapPixels = ui_ExtractSnapTolerance / depthW;
        snapPixels = std::clamp(snapPixels, ui_MinExtractSnapPixels, ui_MaxExtractSnapPixels);
        const float snapRadius = snapPixels * depthW;

        // Search center: the raycast hit position, inset by half the
        // building's footprint so the deposit search starts from the
        // building's own placement anchor rather than its cursor corner.
        Wm3::Vec3f searchCenter = hit.mMouseWorldPos;
        searchCenter.z = searchCenter.z - (static_cast<float>(buildBlueprint->mFootprint.mSizeZ) * 0.5f);
        searchCenter.x = searchCenter.x - (static_cast<float>(buildBlueprint->mFootprint.mSizeX) * 0.5f);

        GridPos searchFrom(&searchCenter, 1);
        // `{0, 0}` here selected GridPos's world-position constructor with a
        // NULL Wm3::Vec3f* (GridPos is not an aggregate), so hovering with a
        // mass-extractor build order dereferenced null in GridPos::GridPos.
        GridPos foundDeposit{};
        auto* const simResources = mWldSession->mSimResources.px;
        if (
          simResources != nullptr &&
          simResources->FindClosestDeposit(&searchFrom, &foundDeposit, snapRadius, depositType)
        ) {
          const SOCellPos snappedCell{
            static_cast<std::int16_t>(foundDeposit.x), static_cast<std::int16_t>(foundDeposit.z)
          };
          // The layer argument is the build blueprint's own occupancy caps
          // (0x008701A2, `movzx ecx, byte ptr [eax+0DAh]` - `mFootprint` at
          // +0xD8, `mOccupancyCaps` its third byte), not LAYER_None. It is
          // what decides whether the snapped cursor takes the seabed height
          // or the water plane, so a hydrocarbon/mass structure that builds
          // on the seabed was being snapped to the water surface instead of
          // the deposit it is standing on. The 1x1 extent is the binary's
          // (`push 1` twice at 0x008701A9): a deposit occupies one cell
          // regardless of what gets built over it.
          hit.mMouseWorldPos = COORDS_ToWorldPos(
            mWldSession->GetSTIMap(),
            snappedCell,
            static_cast<ELayer>(static_cast<std::uint8_t>(buildBlueprint->mFootprint.mOccupancyCaps)),
            1,
            1
          );
        }
      }
    }
  }

  // Tail cursor-info persistence. The binary rebuilds this MouseInfo value
  // from bytes belonging to locals whose real lifetime ended earlier in the
  // function (the selection loop's `bestCandidate`/scratch cluster) -
  // genuine MSVC8 stack-slot reuse across disjoint lifetimes, not a portable
  // cross-object layout new source can replicate safely. Reconstructed here
  // from the pieces with a real, traceable source instead: hit validity and
  // world position from the fresh raycast, and hover unit from the resolved
  // selection.
  MouseInfo resultCursor;
  resultCursor.mHitValid = hit.mHitValid;
  resultCursor.mMouseWorldPos = hit.mMouseWorldPos;
  resultCursor.SetHoveredEntity(bestCandidate);
  resultCursor.mIsDragger = highlightCommandId;
  resultCursor.mMouseScreenPos = mouseScreenPos;
  mWldSession->CursorInfo() = resultCursor;
}
namespace
{
  /// Both command-graph hover banners this file raises are posted with
  /// `flt_E4F6E8` as their lifetime (0x00870770 and 0x00870817). The shipped
  /// `.rdata` word at VA 0x00E4F6E8 is `00 00 80 bf` == -1.0f, i.e. "no
  /// timeout" - the banner stays until something replaces or stops it.
  ///
  /// Deliberately not shared with `kCursorBannerSeconds` (3.0f) in
  /// CWldSession.cpp: those are `SCommandModeData::HandleEvent`'s banners,
  /// which carry a real duration, a named colour and `anchorToCursor = true`.
  constexpr float kHintBannerNoTimeout = -1.0f;

  /// Both banners are posted in the default colour (`push 0FFFFFFFFh` at
  /// 0x0087077E / 0x00870825).
  constexpr std::uint32_t kHintBannerDefaultColor = 0xFFFFFFFFu;

  /**
   * The cursor banner API names the two screen-space floats `SMauiMousePos`;
   * the world view just hands `&cursorInfo.mMouseScreenPos` over in `ecx`
   * (0x00870787 / 0x0087082C).
   */
  [[nodiscard]] moho::SMauiMousePos ToHintBannerPos(
    const Wm3::Vector2f& screenPos
  ) noexcept
  {
    return moho::SMauiMousePos{screenPos.x, screenPos.y};
  }

  /**
   * A `CmdId` packs its issuing source into the high byte, and the
   * `(MouseInfo, modifiers)` command-mode constructor seeds the cursor's id
   * lane with an all-ones sentinel. "The cursor is over a live command" is
   * therefore the source-byte test the world view runs at 0x00870627 and
   * 0x0087100D - the same test `SCommandModeData::HandleEvent` spells
   * `HasDraggedCommand` on its own copy of the lane.
   */
  [[nodiscard]] bool HasHoveredCommand(
    const moho::MouseInfo& cursorInfo
  ) noexcept
  {
    constexpr std::uint32_t kCommandSourceMask = 0xFF000000u;
    return (static_cast<std::uint32_t>(cursorInfo.mIsDragger) & kCommandSourceMask) != kCommandSourceMask;
  }

  /**
   * Drops any pending drag formation.
   *
   * The binary open-codes this three-line tail at four separate points in
   * `CUIWorldView::HandleEvent` - 0x00870578 (pointer left the view),
   * 0x00870423 (the left-command helper's own tail), 0x008710D2 (the shared
   * right-button tail) - always as "build a throwaway `WeakSet<UserUnit>`,
   * clear `mReady`, `Reset()`, tear the set down again". The transient set is
   * never populated or read; it exists because the same source statement
   * scopes it, so it is kept here rather than optimised away.
   */
  void ClearPendingDragFormation(
    moho::CWldSession& session
  )
  {
    const moho::WeakSet<moho::UserUnit> formationUnits;

    moho::CFormation* const formation = session.mCurFormation;
    formation->mReady = false;
    formation->Reset();
  }
}


/**
 * Address: 0x00870310 (FUN_00870310, sub_870310)
 *
 * IDA signature:
 * void __stdcall sub_870310(
 *     Moho::CUIWorldView *view, Moho::UICursorInfo *cursorInfo,
 *     char useLastQueuedDestination);
 *
 * What it does:
 * The left-button command dispatch `CUIWorldView::HandleEvent` shares between
 * its press and double-click arms. When the pending left command is a
 * Move or Attack, it re-derives the drag formation from the current selection
 * first: an empty selection drops the formation (`mReady = false`, `Reset()`),
 * a non-empty one marks it ready and rebuilds it through
 * `ChooseFormation` + `Finalize`. It then runs the stored left command
 * (`SCommandModeData::HandleEvent`), telling it whether this was a
 * double-click by testing the view's own state lane against
 * `MET_ButtonDClick`. Finally it clears the formation again so the next drag
 * starts clean.
 *
 * The trailing clear genuinely constructs and tears down a second empty
 * participant set (0x00870423-0x0087048C) - that is `ClearPendingDragFormation`
 * being inlined a second time, not dead code.
 */
static void ApplyDragFormationAndDispatchLeftCommand(
  moho::CUIWorldView* const view,
  moho::MouseInfo* const cursorInfo,
  const bool useLastQueuedDestination
)
{
  moho::CWldSession& session = *view->mWldSession;

  const moho::ERuleBPUnitCommandCaps leftCommandCaps = view->mLeftMouseCommand.mCommandCaps;
  if (leftCommandCaps == moho::RULEUCC_Attack || leftCommandCaps == moho::RULEUCC_Move) {
    moho::WeakSet<moho::UserUnit> formationUnits;
    session.GetSelectionUnits(formationUnits);

    moho::CFormation* const formation = session.mCurFormation;

    // 0x0087037F-0x008703A9: `Empty()` inlined, `SkipDead` (0x007B29C0) from
    // the leftmost node against the head.
    if (formationUnits.Empty()) {
      formation->mReady = false;
      formation->Reset();
    } else {
      formation->mReady = true;
      formation->ChooseFormation(cursorInfo->mMouseWorldPos, formationUnits, useLastQueuedDestination);
      formation->Finalize();
    }
  }

  // 0x00870403: `mState` holds the event type of the click that opened this
  // command, so `== MET_ButtonDClick` is the "this was a double click" flag the
  // command dispatcher wants.
  view->mLeftMouseCommand.HandleEvent(session, view->mState == moho::MET_ButtonDClick);

  ClearPendingDragFormation(session);
}

/**
 * Address: 0x008704B0 (FUN_008704B0, Moho::CUIWorldView::HandleEvent)
 * Mangled: ?HandleEvent@CUIWorldView@Moho@@UAE_NABUSMauiEventData@2@@Z
 *
 * VFTable SLOT: 12 (+0x30) of `??_7CUIWorldView@Moho@@6B@` (VA 0x00E49074)
 *
 * What it does: see the declaration.
 */
bool moho::CUIWorldView::HandleEvent(
  const SMauiEventData& eventData
)
{
  // --- cursor enter / exit ------------------------------------------------
  if (eventData.mEventType == MET_MouseEnter) {
    mCursorInside = 1u;
  } else if (eventData.mEventType == MET_MouseExit) {
    // 0x008704F9: the rotation flag is read before `mCursorInside` is cleared.
    const bool wasRotating = mCameraRotationActive;
    mCursorInside = 0u;

    if (wasRotating && !cam_Free) {
      mCamera->CameraRevertRotation();
    }
    mCameraRotationActive = false;

    // 0x00870526-0x00870566: this is `func_StartMouseScrubbing(false, ...)`
    // inlined - same `ui_DisableCursorFixing`/already-stopped guard, same
    // cursor show + default-texture restore, same recentre on the scrub origin.
    func_StartMouseScrubbing(false, nullptr);

    if (mWldSession->mCurFormation->mReady) {
      ClearPendingDragFormation(*mWldSession);
    }
  }

  if (sMouseIsScrubbing == 0u) {
    UpdateSelection(Wm3::Vector2f(eventData.mMousePos.x, eventData.mMousePos.y));
  }

  MouseInfo& cursorInfo = mWldSession->CursorInfo();

  // The base control gets first refusal, and a locked view swallows everything
  // that survives it (0x008705F8 / 0x00870605).
  if (CMauiControl::HandleEvent(eventData)) {
    return true;
  }
  if (mInputLocks > 0) {
    return true;
  }

  mConvertToPatrolCursor = false;

  // --- command-graph hover banners ---------------------------------------
  bool stopCursorText = true;

  if (mComGraph && HasHoveredCommand(cursorInfo)) {
    UserCommandIssueHelper* const hoveredCommand = FindCommandIssueHelperInSession(mWldSession, cursorInfo.mIsDragger);

    if (hoveredCommand != nullptr) {
      UICommandModeData uiCommandMode{};
      UI_GetCommandMode(uiCommandMode);

      WeakSet<UserUnit> selectedUnits;
      mWldSession->GetSelectionUnits(selectedUnits);

      // Does any selected unit already participate in the hovered command?
      // (`begin` 0x007B25F0 at 0x0087069F, `++` 0x007F0490 at 0x008706D8.)
      bool selectionExcluded = false;
      for (UserUnit* const selectedUnit : selectedUnits) {
        if (IsCommandCandidateExcludedByCachedRelation(*hoveredCommand, selectedUnit)) {
          selectionExcluded = true;
          break;
        }
      }

      const bool inOrderMode = uiCommandMode.mMode == "order";

      if (selectionExcluded) {
        // Move orders the selection already owns can be restarted as patrol.
        const EUnitCommandType hoveredCommandType = ResolveCommandIssueHelperCommandType(*hoveredCommand);
        if (
          (hoveredCommandType == EUnitCommandType::UNITCOMMAND_Move ||
           hoveredCommandType == EUnitCommandType::UNITCOMMAND_FormMove) &&
          CanRestartSelectionMoveCommandAsPatrol(mWldSession->mSelection, hoveredCommand)
        ) {
          UI_StartCursorText(
            ToHintBannerPos(cursorInfo.mMouseScreenPos),
            inOrderMode ? "<LOC Engine0009>Left-click to convert moves into patrol"
                        : "<LOC Engine0010>Right-click to convert moves into patrol",
            kHintBannerDefaultColor,
            kHintBannerNoTimeout,
            false
          );
          stopCursorText = false;
          mConvertToPatrolCursor = true;
        }
      } else {
        // Attack orders nothing in the selection owns can be joined by
        // double-clicking - the "coordinated attack" gesture.
        const EUnitCommandType hoveredCommandType = ResolveCommandIssueHelperCommandType(*hoveredCommand);
        if (
          hoveredCommandType == EUnitCommandType::UNITCOMMAND_Attack ||
          hoveredCommandType == EUnitCommandType::UNITCOMMAND_FormAttack
        ) {
          CommandModeData rightMouseCommand{};
          (void)func_GetRightMouseButtonAction(&rightMouseCommand, &cursorInfo, 0, mWldSession);

          CommandModeData leftMouseCommand{};
          (void)mWldSession->GetLeftMouseButtonAction(&leftMouseCommand, &cursorInfo, 0);

          if (rightMouseCommand.mCommandCaps == RULEUCC_Attack || leftMouseCommand.mCommandCaps == RULEUCC_Attack) {
            UI_StartCursorText(
              ToHintBannerPos(cursorInfo.mMouseScreenPos),
              inOrderMode ? "<LOC Engine0007>Double left-click for coordinated attack"
                          : "<LOC Engine0008>Double right-click for coordinated attack",
              kHintBannerDefaultColor,
              kHintBannerNoTimeout,
              false
            );
            stopCursorText = false;
          }
        }
      }
    }
  }

  if (stopCursorText) {
    UI_StopCursorText();
  }

  // --- wheel rotation (0x008708B4) ---------------------------------------
  if (eventData.mEventType == MET_WheelRotation) {
    CommandModeData wheelCommand(cursorInfo, eventData.mModifiers);
    if (wheelCommand.mMode != COMMOD_None) {
      wheelCommand.HandleEvent(*mWldSession, false);
    } else {
      mCamera->CameraSetPivot(cursorInfo.mMouseScreenPos);
      mCamera->CameraZoom(static_cast<float>(eventData.mWheelRotation) / static_cast<float>(eventData.mWheelData));
    }
    return true;
  }

  // --- pointer motion (0x00870963) ---------------------------------------
  if (eventData.mEventType == MET_MouseMotion) {
    const bool spaceDragActive =
      MAUI_KeyIsDown(MKEY_SPACE) && (cam_Free || ren_BgLowerBound > mCamera->CameraGetTargetZoom());

    if (spaceDragActive) {
      if (mCursorInside != 0u) {
        if (mCameraRotationActive) {
          func_StartMouseScrubbing(true, this);

          // With cursor fixing on, the pointer is pinned to the scrub anchor
          // and the accumulated scrub delta is the motion; with it off, the
          // delta is measured against the previous sample.
          Wm3::Vector2f spinDelta;
          if (ui_DisableCursorFixing) {
            spinDelta.x = cursorInfo.mMouseScreenPos.x - mLastCursorScreenPos.x;
            spinDelta.y = cursorInfo.mMouseScreenPos.y - mLastCursorScreenPos.y;
          } else {
            spinDelta.x = static_cast<float>(sMouseScrubDelta.x);
            spinDelta.y = static_cast<float>(sMouseScrubDelta.y);
          }

          mCamera->CameraSpin(spinDelta);
          sMouseScrubDelta.x = 0;
          sMouseScrubDelta.y = 0;
        } else {
          mCameraRotationActive = true;
        }

        mLastCursorScreenPos = cursorInfo.mMouseScreenPos;
      }
    } else {
      if (mCameraRotationActive && !cam_Free) {
        mCamera->CameraRevertRotation();
      }
      mCameraRotationActive = false;
      func_StartMouseScrubbing(false, nullptr);
    }

    mCamera->CameraSetPivot(cursorInfo.mMouseScreenPos);
    return true;
  }

  // --- middle-button press (0x00870B0A) ----------------------------------
  if (eventData.mEventType == MET_ButtonPress && eventData.mKeyCode == kPostDraggerMiddleButton) {
    CommandModeData middleCommand(cursorInfo, eventData.mModifiers);
    if (middleCommand.mMode != COMMOD_None) {
      middleCommand.HandleEvent(*mWldSession, false);
    } else {
      auto* const storage = static_cast<CameraDragger*>(::operator new(sizeof(CameraDragger), std::nothrow));
      IMauiDragger* dragger = nullptr;
      if (storage != nullptr) {
        dragger = new (storage) CameraDragger(mCamera.get(), cursorInfo.mMouseScreenPos, this, &moho::CameraImpl::CameraPan);
      }
      func_PostDragger(GetRootFrame(), dragger, &eventData);
    }
    return false;
  }

  // --- left-button double click (0x00870BC9) -----------------------------
  //
  // Ordering matters: this test sits ahead of the left-press one, and a
  // double-click on any other button falls straight through into the
  // right-double-click arm at 0x00870F1B.
  if (eventData.mEventType == MET_ButtonDClick && eventData.mKeyCode == kPostDraggerLeftButton) {
    if (mWldSession->mCurFormation->mReady) {
      mWldSession->mCurFormation->LuaFinalize();
      return true;
    }

    mState = MET_ButtonDClick;

    if (mLeftMouseCommand.mMode == COMMOD_Order) {
      ApplyDragFormationAndDispatchLeftCommand(this, &cursorInfo, (eventData.mModifiers & MEM_Shift) != 0);
      return true;
    }

    if (mLeftMouseCommand.mMode != COMMOD_Move) {
      return false;
    }

    // 0x00870C2A-0x00870C34: `mUnitHover` is a weak-link slot, so "something
    // live is hovered" is the slot decoding to a real owner - neither null nor
    // the bare offset the slot is left holding when the entity dies. That is
    // exactly what `CWldSession::GetHoveredUserEntity()` resolves.
    if (mWldSession->GetHoveredUserEntity() != nullptr && !IsMiniMap()) {
      mWldSession->HandleDoubleClickSelection(mCamera.get());
    }
    return true;
  }

  // --- left-button press (0x00870CA4) ------------------------------------
  if (eventData.mEventType == MET_ButtonPress && eventData.mKeyCode == kPostDraggerLeftButton) {
    if (mWldSession->mCurFormation->mReady) {
      mWldSession->mCurFormation->LuaFinalize();
      return true;
    }

    mState = MET_ButtonPress;

    CommandModeData pressCommand{};
    (void)mWldSession->GetLeftMouseButtonAction(&pressCommand, &cursorInfo, eventData.mModifiers);
    mLeftMouseCommand = pressCommand;

    switch (mLeftMouseCommand.mMode) {
    case COMMOD_None:
      return false;

    case COMMOD_Build:
    case COMMOD_BuildAnchored:
      func_NewUIBuildDragger(GetRootFrame(), mWldSession, &eventData, mCamera.get(), &mBuildDrag);
      return true;

    case COMMOD_Move:
      if (IsMiniMap()) {
        // A minimap only drags its own tracked camera, and only when it has
        // one (0x00870D49).
        if (mCameraTrack.empty()) {
          return true;
        }

        if (CameraImpl* const trackedCamera = CAM_GetCamera(mCameraTrack.c_str()); trackedCamera != nullptr) {
          trackedCamera->TargetLocation(cursorInfo.mMouseWorldPos, 0.0f);
        }

        auto* const storage = static_cast<CMiniMapDragger*>(::operator new(sizeof(CMiniMapDragger), std::nothrow));
        IMauiDragger* miniMapDragger = nullptr;
        if (storage != nullptr) {
          miniMapDragger = new (storage) CMiniMapDragger(mCameraTrack);
        }
        func_PostDragger(GetRootFrame(), miniMapDragger, &eventData);
        return true;
      }

      {
        mSelectionDragger.ResetFromObject(NewSelectionDragger(mCamera.get(), mWldSession, GetRootFrame(), &eventData));
      }
      return true;

    case COMMOD_Reclaim:
      func_NewCommandDragger(GetRootFrame(), mWldSession, &eventData, mCamera.get(), cursorInfo.mIsDragger);
      return true;

    default:
      // COMMOD_Order, COMMOD_Ping and anything past the jump table's six
      // entries all land on the shared left-command dispatch.
      ApplyDragFormationAndDispatchLeftCommand(this, &cursorInfo, (eventData.mModifiers & MEM_Shift) != 0);
      return true;
    }
  }

  // --- right-button press / double click (0x00870F12) ----------------------
  //
  // The binary reaches this arm for both MET_ButtonPress and MET_ButtonDClick
  // on the right button (the left-press arm is `if (press) { if (key==1) ...}`
  // and everything else that is a press or a double click falls through to
  // the `mKeyCode == 3` test at 0x00870F12), storing the event type in the
  // last-right-event lane. Handling only the double click left the command
  // data unset on an ordinary right click, so the release issued nothing.
  if (
    (eventData.mEventType == MET_ButtonPress || eventData.mEventType == MET_ButtonDClick) &&
    eventData.mKeyCode == kPostDraggerRightButton
  ) {
    mLastRightButtonEvent = eventData.mEventType;

    CommandModeData rightCommand{};
    (void)func_GetRightMouseButtonAction(&rightCommand, &cursorInfo, eventData.mModifiers, mWldSession);
    mCommandData = rightCommand;


    if (mCommandData.mMode != COMMOD_Order) {
      return false;
    }
    if (mWldSession->GetSelection().Size() == 0) {
      return false;
    }

    const bool useLastQueuedDestination = (eventData.mModifiers & MEM_Shift) != 0;

    WeakSet<UserUnit> formationUnits;
    mWldSession->GetSelectionUnits(formationUnits);
    mWldSession->mCurFormation->ProcessMouse(
      &formationUnits, true, cursorInfo.mMouseWorldPos, useLastQueuedDestination
    );
    return false;
  }

  // --- right-button release (0x00870FF7) ----------------------------------
  if (eventData.mEventType == MET_ButtonRelease && eventData.mKeyCode == kPostDraggerRightButton) {
    const bool overHoveredCommand = HasHoveredCommand(cursorInfo);
    const auto modifiers = static_cast<std::uint32_t>(eventData.mModifiers);

    if (
      overHoveredCommand && (modifiers & MEM_Shift) != 0u && (modifiers & MEM_Ctrl) != 0u && !mWldSession->IsObserver()
    ) {
      // Shift+Ctrl right-release strips the hovered command from every unit
      // under the cursor instead of issuing anything.
      if (
        UserCommandIssueHelper* const hoveredCommand =
          FindCommandIssueHelperInSession(mWldSession, cursorInfo.mIsDragger);
        hoveredCommand != nullptr
      ) {
        // `begin` 0x007B25F0 at 0x00871065, `++` 0x007F0490 at 0x0087108C.
        for (UserUnit* const unit : *ResolveCommandIssueCursorEntities(*hoveredCommand)) {
          ISSUE_RemoveCommandFromUnitQueue(hoveredCommand, unit);
        }
      }
    } else {
      if (mCommandData.mMode != COMMOD_None && sMouseIsScrubbing == 0u) {
        mCommandData.HandleEvent(*mWldSession, mLastRightButtonEvent == MET_ButtonDClick);
      }
    }

    ClearPendingDragFormation(*mWldSession);
    return false;
  }

  return false;
}

/**
 * Address: 0x00871140 (FUN_00871140, Moho::CUIWorldView::Frame)
 *
 * IDA signature:
 * void __thiscall Moho::CUIWorldView::OnFrame(Moho::CUIWorldView *this, float a2);
 *
 * VFTable SLOT: 13 (+0x34)
 *
 * What it does: see the declaration.
 */
void moho::CUIWorldView::Frame(
  const float deltaSeconds
)
{
  func_ProcessMouseScrubbing();

  if (mCursorInside != 0u && sMouseIsScrubbing == 0u) {
    UpdateSelection(mWldSession->CursorInfo().mMouseScreenPos);
    RunScript("OnUpdateCursor");
  }

  if (mInputLocks <= 0) {
    float panSpeed = ui_KeyboardPanSpeed;
    float rotateSpeed = ui_KeyboardRotateSpeed;
    if (MAUI_KeyIsDown(MKEY_CONTROL)) {
      panSpeed = ui_KeyboardPanAccelerateMultiplier * panSpeed;
      rotateSpeed = ui_KeyboardRotateAccelerateMultiplier * rotateSpeed;
    }

    if (!MAUI_KeyIsDown(MKEY_SPACE)) {
      if (mCameraRotationActive && !cam_Free) {
        mCamera->CameraRevertRotation();
      }
      mCameraRotationActive = false;
    }

    if (mGlobalCameraCommands) {
      if (!MAUI_KeyIsDown(MKEY_MENU) && !mIsMiniMap) {
        if (MAUI_KeyIsDown(MKEY_INSERT)) {
          mCamera->CameraSpin({rotateSpeed, 0.0f});
        } else if (MAUI_KeyIsDown(MKEY_DELETE)) {
          mCamera->CameraSpin({-rotateSpeed, 0.0f});
        }
      }

      if (mGlobalCameraCommands) {
        float panX = 0.0f;
        float panY = 0.0f;

        if (ui_ScreenEdgeScrollView) {
          gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
          const gpg::gal::Head& head = device->GetDeviceContext()->GetHead(0u);
          if (head.mWindowed) {
            POINT cursorPoint{};
            ::GetCursorPos(&cursorPoint);
            if (cursorPoint.x == 0) {
              panX = panSpeed;
            }
            if (cursorPoint.y == 0) {
              panY = panSpeed;
            }
            if (cursorPoint.x == static_cast<LONG>(head.mWidth) - 1) {
              panX = panX - panSpeed;
            }
            if (cursorPoint.y == static_cast<LONG>(head.mHeight) - 1) {
              panY = panY - panSpeed;
            }
          }
        }

        if (ui_ArrowKeysScrollView) {
          if (MAUI_KeyIsDown(MKEY_UP)) {
            panY = panY + panSpeed;
          }
          if (MAUI_KeyIsDown(MKEY_DOWN)) {
            panY = panY - panSpeed;
          }
          if (MAUI_KeyIsDown(MKEY_LEFT)) {
            panX = panX + panSpeed;
          }
          if (MAUI_KeyIsDown(MKEY_RIGHT)) {
            panX = panX - panSpeed;
          }
        }

        if (!MAUI_KeyIsDown(MKEY_MENU) && (panX != 0.0f || panY != 0.0f)) {
          mCamera->CameraPan({panX, panY});
        }
      }
    }

    const bool iconsVisible = !mCameraRotationActive && !cam_Free;
    if (iconsVisible != mIconsVisible) {
      mIconsVisible = iconsVisible;
      RunScriptWithBool("OnIconsVisible", iconsVisible);
    }

    RunScriptNum("OnFrame", deltaSeconds);
  }
}

/**
 * Address: 0x008728B0 (FUN_008728B0, cfunc_CUIWorldViewGetScreenPosL)
 *
 * What it does:
 * Projects one `UserUnit` world position through the world-view camera and
 * returns one screen-space `Vector2` when the unit mesh intersects camera
 * frustum; otherwise pushes nil.
 */
int moho::cfunc_CUIWorldViewGetScreenPosL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCUIWorldViewGetScreenPosHelpText);

  const LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 2));
  const UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);

  moho::CameraImpl* const camera = worldView->GetCamera();

  MeshInstance* const meshInstance = userUnit->mMeshInstance;
  if (meshInstance == nullptr) {
    lua_pushnil(state->m_state);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  meshInstance->UpdateInterpolatedFields();

  const GeomCamera3& cameraView = camera->CameraGetView();
  const Wm3::AxisAlignedBox3f meshBounds{
    {meshInstance->xMin, meshInstance->yMin, meshInstance->zMin},
    {meshInstance->xMax, meshInstance->yMax, meshInstance->zMax},
  };
  if (!cameraView.solid2.Intersects(meshBounds)) {
    lua_pushnil(state->m_state);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  const Wm3::Vec3f& unitPosition = static_cast<const IUnit*>(userUnit)->GetPosition();
  const Wm3::Vector2f normalizedPoint = cameraView.Project(unitPosition, -1.0f, 1.0f, -1.0f, 1.0f);

  const float viewportWidth = cameraView.viewport.r[3].z;
  const float viewportHeight = cameraView.viewport.r[3].w;
  const Wm3::Vector3f screenPoint =
    ProjectNormalizedScreenPointToViewportFloor(normalizedPoint, viewportWidth, viewportHeight);

  if (screenPoint.x < 0.0f || screenPoint.x > viewportWidth || screenPoint.y < 0.0f || screenPoint.y > viewportHeight) {
    lua_pushnil(state->m_state);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  const Wm3::Vector2f screenPoint2{screenPoint.x, screenPoint.y};
  LuaPlus::LuaObject screenPointObject = SCR_ToLua<Wm3::Vector2f>(state, screenPoint2);
  screenPointObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x00872830 (FUN_00872830, cfunc_CUIWorldViewGetScreenPos)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldViewGetScreenPosL`.
 */
int moho::cfunc_CUIWorldViewGetScreenPos(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldViewGetScreenPosL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00872850 (FUN_00872850, func_CUIWorldViewGetScreenPos_LuaFuncDef)
 *
 * What it does:
 * Publishes the `GetScreenPos(unit)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldViewGetScreenPos_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetScreenPos",
    &moho::cfunc_CUIWorldViewGetScreenPos,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldViewGetScreenPosHelpText
  );
  return &binder;
}

/**
 * Address: 0x007FDAF0 (FUN_007FDAF0, cfunc_AddBlinkyBox)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_AddBlinkyBoxL`.
 */
int moho::cfunc_AddBlinkyBox(
  lua_State* const luaContext
)
{
  return cfunc_AddBlinkyBoxL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007FDB10 (FUN_007FDB10, func_AddBlinkyBox_LuaFuncDef)
 *
 * What it does:
 * Publishes global `AddBlinkyBox(entityId, onTime, offTime, totalTime)` Lua
 * binder metadata.
 */
moho::CScrLuaInitForm* moho::func_AddBlinkyBox_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(), "AddBlinkyBox", &moho::cfunc_AddBlinkyBox, nullptr, "<global>", kAddBlinkyBoxHelpText
  );
  return &binder;
}

/**
 * Address: 0x007FDB70 (FUN_007FDB70, cfunc_AddBlinkyBoxL)
 *
 * What it does:
 * Parses one entity-id plus three timing args and appends one blinky-box node
 * for the resolved live user-entity.
 */
int moho::cfunc_AddBlinkyBoxL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 4, kAddBlinkyBoxHelpText);

  const LuaPlus::LuaStackObject entityIdArg(state, 1);
  if (lua_type(state->m_state, 1) != LUA_TNUMBER) {
    entityIdArg.TypeError("integer");
  }

  const EntId entityId = static_cast<EntId>(static_cast<std::int32_t>(lua_tonumber(state->m_state, 1)));
  CWldSession* const session = WLD_GetActiveSession();
  UserEntity* const entity = session != nullptr ? session->LookupEntityId(entityId) : nullptr;
  if (entity == nullptr) {
    LuaPlus::LuaState::Error(state, "Invalid entity id");
    return 0;
  }

  const LuaPlus::LuaStackObject totalTimeArg(state, 4);
  if (lua_type(state->m_state, 4) != LUA_TNUMBER) {
    totalTimeArg.TypeError("number");
  }
  const float totalTime = static_cast<float>(lua_tonumber(state->m_state, 4));

  const LuaPlus::LuaStackObject offTimeArg(state, 3);
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    offTimeArg.TypeError("number");
  }
  const float offTime = static_cast<float>(lua_tonumber(state->m_state, 3));

  const LuaPlus::LuaStackObject onTimeArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    onTimeArg.TypeError("number");
  }
  const float onTime = static_cast<float>(lua_tonumber(state->m_state, 2));

  func_PushBlinkyBox(entity, onTime, offTime, totalTime);
  return 0;
}
namespace
{


  [[nodiscard]] const char* LuaStringOrEmpty(
    const LuaPlus::LuaObject& object
  ) noexcept
  {
    const char* const value = object.GetString();
    return value != nullptr ? value : "";
  }

  [[nodiscard]] boost::shared_ptr<moho::RScmResource> ResolveCommandFeedbackModelFromDescriptor(
    const LuaPlus::LuaObject& meshDescriptor,
    moho::CWldSession* const worldSession,
    float* const outUniformScale
  )
  {
    const LuaPlus::LuaObject meshNameObject = meshDescriptor.GetByName("MeshName");
    if (!meshNameObject.IsNil()) {
      if (outUniformScale != nullptr) {
        *outUniformScale = static_cast<float>(meshDescriptor.GetByName("UniformScale").GetNumber());
      }
      // 0x00857D0F: the shared `GetModel` lane.
      return moho::GetModel(LuaStringOrEmpty(meshNameObject), nullptr);
    }

    if (worldSession == nullptr || worldSession->mRules == nullptr) {
      return {};
    }

    fa::string blueprintId(LuaStringOrEmpty(meshDescriptor.GetByName("BlueprintID")));
    moho::RResId normalizedBlueprintId{};
    gpg::STR_CopyFilename(&normalizedBlueprintId.name, &blueprintId);

    moho::RUnitBlueprint* const unitBlueprint = worldSession->mRules->GetUnitBlueprint(normalizedBlueprintId);
    if (unitBlueprint == nullptr) {
      return {};
    }

    if (outUniformScale != nullptr) {
      *outUniformScale = unitBlueprint->Display.UniformScale;
    }

    moho::RMeshBlueprint* const meshBlueprint =
      worldSession->mRules->GetMeshBlueprint(unitBlueprint->Display.MeshBlueprint);
    if (meshBlueprint == nullptr) {
      return {};
    }

    const moho::RMeshBlueprintLOD* const lodBegin = meshBlueprint->mLods.begin();
    if (lodBegin == nullptr || lodBegin == meshBlueprint->mLods.end()) {
      return {};
    }

    // 0x00857E58: the second `GetModel` call in this function, on the blueprint
    // arm's front LOD.
    return moho::GetModel(lodBegin->mMeshName.c_str(), nullptr);
  }
}


/**
 * Address: 0x00857BE0 (FUN_00857BE0, cfunc_AddCommandFeedbackBlipL)
 *
 * What it does:
 * Reads one descriptor table `(MeshName|BlueprintID, Position, TextureName,
 * ShaderName[, UniformScale])` plus duration, creates one transient mesh
 * marker, and pushes it onto the command-feedback blip list.
 */
int moho::cfunc_AddCommandFeedbackBlipL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kAddCommandFeedbackBlipHelpText);

  CWldSession* const worldSession = moho::WLD_GetSession();
  if (worldSession == nullptr) {
    gpg::Warnf("AddCommandFeedbackBlip: No user session, unable to add blip");
    return 0;
  }

  if (lua_type(state->m_state, 1) != LUA_TTABLE) {
    gpg::Warnf("AddCommandFeedbackBlip: Expecting lua table as argument");
    return 0;
  }

  const LuaPlus::LuaObject meshDescriptor(LuaPlus::LuaStackObject(state, 1));

  float uniformScale = 1.0f;
  const boost::shared_ptr<RScmResource> modelResource =
    ResolveCommandFeedbackModelFromDescriptor(meshDescriptor, worldSession, &uniformScale);
  if (!modelResource) {
    return 0;
  }

  const Wm3::Vector3f worldPosition = SCR_FromLuaCopy<Wm3::Vector3f>(meshDescriptor.GetByName("Position"));

  const fa::string textureName(LuaStringOrEmpty(meshDescriptor.GetByName("TextureName")));
  const fa::string shaderName(LuaStringOrEmpty(meshDescriptor.GetByName("ShaderName")));
  const fa::string emptyTextureName{};

  const boost::shared_ptr<MeshMaterial> material = MeshMaterial::Create(
    shaderName, textureName, emptyTextureName, emptyTextureName, emptyTextureName, emptyTextureName, nullptr
  );

  MeshRenderer* const renderer = MeshRenderer::GetInstance();
  const Wm3::Vector3f meshScale{uniformScale, uniformScale, uniformScale};
  // 0x008581BB..0x008581F6: the resource/material overload (0x007DF710) with
  // a LOD cutoff of FLT_MAX (0x00E4F798 = 0x7F7FFFFF), so the blip is never
  // LOD-culled. The `CommandFeedback` vertex shader grows the mesh with
  // distance instead; with the default 1000 cutoff the blip vanished once
  // the camera zoomed out.
  MeshInstance* const meshInstance = renderer != nullptr
    ? renderer->CreateMeshInstance(
        worldSession->mGameTick,
        -1,
        modelResource,
        meshScale,
        false,
        material,
        std::numeric_limits<float>::max()
      )
    : nullptr;
  if (meshInstance == nullptr) {
    return 0;
  }

  SCommandFeedbackBlip blip{};
  blip.mMeshInstance = meshInstance;
  blip.mDuration = static_cast<float>(lua_tonumber(state->m_state, 2));
  blip.mCurTime = 0.0f;

  sCommandFeedbackBlips.push_back(blip);

  meshInstance->lifetimeParameter = blip.mDuration * 10.0f;

  VTransform transform{};
  transform.orient_.w = 1.0f;
  transform.orient_.x = 0.0f;
  transform.orient_.y = 0.0f;
  transform.orient_.z = 0.0f;
  transform.pos_.x = worldPosition.x;
  transform.pos_.y = worldPosition.y;
  transform.pos_.z = worldPosition.z;
  meshInstance->SetStance(transform, transform);

  return 0;
}

/**
 * Address: 0x00857B60 (FUN_00857B60, cfunc_AddCommandFeedbackBlip)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_AddCommandFeedbackBlipL`.
 */
int moho::cfunc_AddCommandFeedbackBlip(
  lua_State* const luaContext
)
{
  return cfunc_AddCommandFeedbackBlipL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00857B80 (FUN_00857B80, func_AddCommandFeedbackBlip_LuaFuncDef)
 *
 * What it does:
 * Publishes global `AddCommandFeedbackBlip(meshInfoTable, duration)` Lua
 * binder metadata.
 */
moho::CScrLuaInitForm* moho::func_AddCommandFeedbackBlip_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "AddCommandFeedbackBlip",
    &moho::cfunc_AddCommandFeedbackBlip,
    nullptr,
    "<global>",
    kAddCommandFeedbackBlipHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086E060 (FUN_0086E060, ??0CameraDragger@Moho@@QAE@@Z)
 *
 * What it does:
 * Initializes one camera dragger with drag target camera/lane and enables
 * mouse-scrub mode for the owning control. The `IMauiDragger` base installs the
 * vptr and clears the weak-reference head (`mov [esi+4], ecx` with ecx==0 at
 * 0x0086E080, `mov dword ptr [esi], offset ??_7CameraDragger@Moho@@6B@` at
 * 0x0086E096).
 */
CameraDragger::CameraDragger(
  moho::CameraImpl* const camera,
  const Wm3::Vector2f& mousePos,
  moho::CMauiControl* const ownerControl,
  const CameraDragDeltaFn dragDelta
)
  : moho::IMauiDragger()
  , mCamera(camera)
  , mPos(mousePos)
  , mDragDelta(dragDelta)
{
  func_StartMouseScrubbing(true, ownerControl);
}

/**
 * Address: 0x0086E0D0 (FUN_0086E0D0, Moho::CameraDragger::~CameraDragger)
 * Scalar deleting destructor: 0x0086E250 (FUN_0086E250, Moho::CameraDragger::dtr)
 *
 * What it does:
 * Disables mouse-scrub mode. The `~IMauiDragger` base tail then unlinks every
 * weak reference still aimed at this dragger - the `WeakObject` drain half of
 * the shipped body, which MSVC emits rather than the programmer writing it.
 */
CameraDragger::~CameraDragger()
{
  func_StartMouseScrubbing(false, nullptr);
}

/**
 * Address: 0x0086E140 (FUN_0086E140, Moho::CameraDragger::DragMove)
 * Slot: +0x04
 *
 * What it does:
 * Applies camera drag delta from either raw mouse motion (cursor-fixing
 * disabled) or accumulated scrub delta, then resets scrub delta lanes.
 */
void CameraDragger::DragMove(
  const moho::SMauiEventData* const eventData
)
{
  if (moho::ui_DisableCursorFixing) {
    const Wm3::Vector2f currentMousePos(eventData->mMousePos.x, eventData->mMousePos.y);
    const Wm3::Vector2f dragDelta(currentMousePos.x - mPos.x, currentMousePos.y - mPos.y);
    (mCamera->*mDragDelta)(dragDelta);
    mPos = currentMousePos;
    return;
  }

  const Wm3::Vector2f dragDelta(static_cast<float>(sMouseScrubDelta.x), static_cast<float>(sMouseScrubDelta.y));
  (mCamera->*mDragDelta)(dragDelta);
  sMouseScrubDelta.x = 0;
  sMouseScrubDelta.y = 0;
}

/**
 * Address: 0x0086E220 (FUN_0086E220, Moho::CameraDragger::DragRelease)
 * Slot: +0x08
 *
 * What it does:
 * Reverts held camera rotation when free-look is off, then destroys this
 * dragger instance.
 */
void CameraDragger::DragRelease(
  const moho::SMauiEventData* const /*eventData*/
)
{
  if (!moho::cam_Free) {
    mCamera->CameraRevertRotation();
  }
  delete this;
}

/**
 * Address: 0x0086E1F0 (FUN_0086E1F0, Moho::CameraDragger::DragCancel)
 * Slot: +0x0C
 *
 * What it does:
 * Mirrors `DragRelease`: conditionally reverts camera rotation and destroys
 * this dragger.
 */
void CameraDragger::OnCurrentDraggerReplaced()
{
  if (!moho::cam_Free) {
    mCamera->CameraRevertRotation();
  }
  delete this;
}

/**
 * Address: 0x0086E430 (FUN_0086E430, Moho::CMiniMapDragger::~CMiniMapDragger)
 * Scalar deleting destructor: 0x0086E410 (FUN_0086E410, Moho::CMiniMapDragger::dtr)
 *
 * What it does:
 * Releases the camera-name storage and drains the `IMauiDragger` base's
 * weak-reference chain. Both halves are compiler-emitted (the member string's
 * destructor and the base destructor call), so the source body is empty.
 */
CMiniMapDragger::~CMiniMapDragger() = default;
