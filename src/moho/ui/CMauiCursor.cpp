#include "moho/ui/UiPrivate.h"

namespace
{
  constexpr const char* kCreateCursorName = "_c_CreateCursor";
  constexpr const char* kCreateCursorHelpText = "_c_CreateCursor(luaobj,spec)";
  constexpr const char* kCursorSetDefaultTextureHelpText = "Cursor:SetDefaultTexture(filename, hotspotX, hotspotY)";
  constexpr const char* kCursorSetNewTextureHelpText = "Cursor:SetTexture(filename, hotspotX, hotspotY)";
  constexpr const char* kCursorResetToDefaultHelpText = "Cursor:ResetToDefault()";
  constexpr const char* kCursorShowHelpText = "Cursor:Show()";

  /**
   * Address: 0x0078C9E0 (FUN_0078C9E0)
   *
   * What it does:
   * Stores active cursor hotspot `(x,y)` lanes.
   */
  [[maybe_unused]] CMauiCursor* SetCursorHotspotXY(
    CMauiCursor* const cursor,
    const std::int32_t hotspotX,
    const std::int32_t hotspotY
  ) noexcept
  {
    cursor->mHotspotX = hotspotX;
    cursor->mHotspotY = hotspotY;
    return cursor;
  }

  /**
   * Address: 0x0078C9F0 (FUN_0078C9F0)
   *
   * What it does:
   * Stores default cursor hotspot `(x,y)` lanes.
   */
  [[maybe_unused]] CMauiCursor* SetCursorDefaultHotspotXY(
    CMauiCursor* const cursor,
    const std::int32_t hotspotX,
    const std::int32_t hotspotY
  ) noexcept
  {
    cursor->mDefaultHotspotX = hotspotX;
    cursor->mDefaultHotspotY = hotspotY;
    return cursor;
  }

  moho::StatItem* gCameraCursorPositionStat = nullptr;
  moho::StatItem* gCameraCursorElevationStat = nullptr;
  moho::StatItem* gCameraCursorOCellStat = nullptr;
  moho::StatItem* gCameraCursorLodMetricStat = nullptr;
  moho::StatItem* gCameraFocusDistanceStat = nullptr;
  moho::StatItem* gMinimapCursorLodMetricStat = nullptr;
  moho::StatItem* gMinimapFocusDistanceStat = nullptr;

  [[nodiscard]] moho::StatItem* EnsureEngineStringStat(
    moho::StatItem*& slot,
    const char* const statPath
  )
  {
    if (slot == nullptr) {
      slot = moho::GetEngineStats()->GetItem_0(statPath);
      (void)slot->Release(0);
    }
    return slot;
  }

  [[nodiscard]] moho::StatItem* EnsureEngineFloatStat(
    moho::StatItem*& slot,
    const char* const statPath
  )
  {
    if (slot == nullptr) {
      slot = moho::GetEngineStats()->GetItem3(statPath);
      (void)slot->Release(0);
    }
    return slot;
  }

  void StoreEngineFloatStat(
    moho::StatItem*& slot,
    const char* const statPath,
    const float value
  )
  {
    moho::StatItem* const item = EnsureEngineFloatStat(slot, statPath);
    item->StorePrimaryBits(std::bit_cast<std::int32_t>(value));
  }

  [[nodiscard]] float SampleCursorTerrainElevation(
    const moho::CUIWorldView& worldView,
    const Wm3::Vec3f& cursorWorldPosition
  )
  {
    const auto* const map =
      worldView.mWldSession->mWldMap->mTerrainRes->mMap;
    return map->mHeightField->GetElevation(cursorWorldPosition.x, cursorWorldPosition.z);
  }

  void StoreCursorLodAndFocusStats(
    moho::CameraImpl& camera,
    const Wm3::Vec3f& cursorWorldPosition,
    moho::StatItem*& lodStat,
    const char* const lodStatPath,
    moho::StatItem*& focusStat,
    const char* const focusStatPath
  )
  {
    StoreEngineFloatStat(lodStat, lodStatPath, camera.LODMetric(cursorWorldPosition));

    const float targetZoom = camera.CameraGetTargetZoom();
    const Wm3::Vec3f& offsetBefore = camera.CameraGetOffset();
    const float focusDistance = std::fabs((offsetBefore.y + targetZoom) - camera.CameraGetOffset().y);
    StoreEngineFloatStat(focusStat, focusStatPath, focusDistance);
  }

  [[nodiscard]] moho::CMauiCursor* ResolveCursorFromLuaObjectOrError(
    const LuaPlus::LuaObject& object,
    LuaPlus::LuaState* state
  )
  {
    constexpr const char* kExpectedGameObjectError = "Expected a game object. (Did you call with '.' instead of ':'?)";
    constexpr const char* kDestroyedGameObjectError = "Game object has been destroyed";
    constexpr const char* kIncorrectGameObjectTypeError =
      "Incorrect type of game object.  (Did you call with '.' instead of ':'?)";

    moho::CScriptObject** const scriptObjectSlot = moho::SCR_ScriptObjectSlot(object);
    if (!scriptObjectSlot) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
      return nullptr;
    }

    moho::CScriptObject* const scriptObject = *scriptObjectSlot;
    if (!scriptObject) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
      return nullptr;
    }

    const gpg::RRef sourceRef = moho::SCR_MakeScriptObjectRef(scriptObject);
    const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, gpg::RTypeOf<moho::CMauiCursor>());
    if (!upcast.mObj) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    return static_cast<moho::CMauiCursor*>(upcast.mObj);
  }

  void ApplyCursorDefaultTexture(
    moho::CMauiCursor* const cursor,
    const char* const texturePath
  )
  {
    if (!cursor) {
      return;
    }
    cursor->SetDefaultTexture(texturePath);
  }
}

gpg::RType* moho::CMauiCursor::sType = nullptr;

/**
 * Address: 0x0078CB50 (FUN_0078CB50, Moho::CMauiCursor::CMauiCursor)
 *
 * What it does:
 * Initializes cursor texture/hotspot runtime lanes and binds one Lua object
 * back-reference.
 */
moho::CMauiCursor::CMauiCursor(
  LuaPlus::LuaObject* const luaObject
)
  : CScriptObject()
  , mTexture()
  , mDefaultTexture()
  , mNeedsUpdate(true)
  , mIsShowing(true)
  , mHotspotX(0)
  , mHotspotY(0)
  , mDefaultHotspotX(0)
  , mDefaultHotspotY(0)
{
  if (luaObject != nullptr) {
    SetLuaObject(*luaObject);
  }
}

/**
 * Address: 0x0078C9A0 (FUN_0078C9A0, Moho::CMauiCursor::GetClass)
 *
 * What it does:
 * Returns the cached reflection descriptor for `CMauiCursor`, resolved via
 * RTTI on first use.
 */
gpg::RType* moho::CMauiCursor::GetClass() const
{
  if (!sType) {
    sType = gpg::LookupRType(typeid(CMauiCursor));
  }
  return sType;
}

/**
 * Address: 0x0078C9C0 (FUN_0078C9C0, Moho::CMauiCursor::GetDerivedObjectRef)
 *
 * What it does:
 * Packs `{this, GetClass()}` as a reflection reference handle.
 */
gpg::RRef moho::CMauiCursor::GetDerivedObjectRef()
{
  return gpg::MakeSelfRef(this);
}

/**
 * Address: 0x0078CFD0 (FUN_0078CFD0, cfunc__c_CreateCursor)
 *
 * What it does:
 * Unwraps raw Lua callback context (`lua_State::stateUserData`) and forwards
 * the call to `cfunc__c_CreateCursorL`.
 */
int moho::cfunc__c_CreateCursor(
  lua_State* const luaContext
)
{
  return cfunc__c_CreateCursorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0078CFF0 (FUN_0078CFF0, func__c_CreateCursor_LuaFuncDef)
 *
 * What it does:
 * Publishes global Lua binder metadata for `_c_CreateCursor(luaobj,spec)` into
 * the user-side `CScrLuaInitFormSet` so the Lua runtime can dispatch to
 * `cfunc__c_CreateCursor` at script-load time.
 */
moho::CScrLuaInitForm* moho::func__c_CreateCursor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(), kCreateCursorName, &moho::cfunc__c_CreateCursor, nullptr, "<global>", kCreateCursorHelpText
  );
  return &binder;
}

/**
 * Address: 0x0078D050 (FUN_0078D050, cfunc__c_CreateCursorL)
 *
 * IDA signature:
 * int __usercall cfunc__c_CreateCursorL@<eax>(LuaPlus::LuaState *a1@<esi>);
 *
 * What it does:
 * Validates the `(luaobj, spec)` argument shape (warns when the argument
 * count differs from 2), allocates one `CMauiCursor` bound to the first Lua
 * argument, and pushes the cursor's stored Lua object back onto the stack.
 */
int moho::cfunc__c_CreateCursorL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCreateCursorHelpText);

  CMauiCursor* cursor = nullptr;
  {
    LuaPlus::LuaObject luaObjectArgument(LuaPlus::LuaStackObject(state, 1));
    // Binary: `operator new(0x58)`.
    cursor = AllocateZeroedUiObject<CMauiCursor>(0x58u);
    new (cursor) CMauiCursor(&luaObjectArgument);
  }

  // CMauiCursor shares the CScriptObject runtime layout (cObject @+0x0C, mLuaObj @+0x20).
  cursor->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x0078CCA0 (FUN_0078CCA0, Moho::CMauiCursor::SetTexture)
 *
 * What it does:
 * Loads one cursor texture resource and applies it to the active cursor
 * texture lane.
 */
void moho::CMauiCursor::SetTexture(
  const char* const texturePath
)
{
  ID3DDeviceResources::TextureResourceHandle loadedTexture{};
  D3D_GetDevice()->GetResources()->GetTexture(loadedTexture, texturePath, 0, false);

  if (loadedTexture.get() != mTexture.get()) {
    mTexture = loadedTexture;
    mNeedsUpdate = true;
  }
}

/**
 * Address: 0x0078CD80 (FUN_0078CD80, Moho::CMauiCursor::SetDefaultTexture)
 *
 * What it does:
 * Loads one default cursor texture and updates default/active texture lanes.
 * If active texture still equals the old default, it is replaced as well.
 */
void moho::CMauiCursor::SetDefaultTexture(
  const char* const texturePath
)
{
  ID3DDeviceResources::TextureResourceHandle loadedTexture{};
  D3D_GetDevice()->GetResources()->GetTexture(loadedTexture, texturePath, 0, false);

  if (loadedTexture.get() == mDefaultTexture.get()) {
    return;
  }

  if (mTexture.get() == mDefaultTexture.get()) {
    mTexture = loadedTexture;
    mNeedsUpdate = true;
  }

  mDefaultTexture = loadedTexture;
}

/**
 * Address: 0x0078CEA0 (FUN_0078CEA0, Moho::CMauiCursor::ResetToDefault)
 *
 * What it does:
 * Restores active cursor texture/hotspot lanes from default cursor state.
 */
void moho::CMauiCursor::ResetToDefault()
{
  if (mTexture.get() != mDefaultTexture.get()) {
    mTexture = mDefaultTexture;
    mHotspotX = mDefaultHotspotX;
    mHotspotY = mDefaultHotspotY;
    mNeedsUpdate = true;
  }
}

/**
 * Address: 0x0078D390 (FUN_0078D390, cfunc_CMauiCursorSetDefaultTexture)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiCursorSetDefaultTextureL`.
 */
int moho::cfunc_CMauiCursorSetDefaultTexture(
  lua_State* const luaContext
)
{
  return cfunc_CMauiCursorSetDefaultTextureL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0078D3B0 (FUN_0078D3B0, func_CMauiCursorSetDefaultTexture_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiCursor:SetDefaultTexture(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiCursorSetDefaultTexture_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetDefaultTexture",
    &moho::cfunc_CMauiCursorSetDefaultTexture,
    &moho::CScrLuaMetatableFactory<moho::CMauiCursor>::Instance(),
    "CMauiCursor",
    kCursorSetDefaultTextureHelpText
  );
  return &binder;
}

/**
 * Address: 0x0078D410 (FUN_0078D410, cfunc_CMauiCursorSetDefaultTextureL)
 *
 * What it does:
 * Reads one cursor object plus texture/hotspot Lua args and updates cursor
 * default texture/hotspot lanes.
 */
int moho::cfunc_CMauiCursorSetDefaultTextureL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 4, kCursorSetDefaultTextureHelpText);

  LuaPlus::LuaObject cursorObject(LuaPlus::LuaStackObject(state, 1));
  CMauiCursor* const cursor = ResolveCursorFromLuaObjectOrError(cursorObject, state);

  LuaPlus::LuaStackObject textureArg(state, 2);
  const char* texturePath = lua_tostring(state->m_state, 2);
  if (texturePath == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&textureArg, "string");
    texturePath = "";
  }
  ApplyCursorDefaultTexture(cursor, texturePath);

  LuaPlus::LuaStackObject hotspotYArg(state, 4);
  if (lua_type(state->m_state, 4) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&hotspotYArg, "integer");
  }
  const int hotspotY = static_cast<int>(lua_tonumber(state->m_state, 4));

  LuaPlus::LuaStackObject hotspotXArg(state, 3);
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&hotspotXArg, "integer");
  }
  const int hotspotX = static_cast<int>(lua_tonumber(state->m_state, 3));

  (void)SetCursorDefaultHotspotXY(cursor, hotspotX, hotspotY);
  return 0;
}

/**
 * Address: 0x0078D130 (FUN_0078D130, cfunc_CMauiCursorSetNewTexture)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiCursorSetNewTextureL`.
 */
int moho::cfunc_CMauiCursorSetNewTexture(
  lua_State* const luaContext
)
{
  return cfunc_CMauiCursorSetNewTextureL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0078D150 (FUN_0078D150, func_CMauiCursorSetNewTexture_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiCursor:SetNewTexture(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiCursorSetNewTexture_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetNewTexture",
    &moho::cfunc_CMauiCursorSetNewTexture,
    &moho::CScrLuaMetatableFactory<moho::CMauiCursor>::Instance(),
    "CMauiCursor",
    kCursorSetNewTextureHelpText
  );
  return &binder;
}

/**
 * Address: 0x0078D1B0 (FUN_0078D1B0, cfunc_CMauiCursorSetNewTextureL)
 *
 * What it does:
 * Reads one cursor plus texture/hotspot Lua args and updates active cursor
 * texture/hotspot lanes.
 */
int moho::cfunc_CMauiCursorSetNewTextureL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 4, kCursorSetNewTextureHelpText);

  LuaPlus::LuaStackObject textureArg(state, 2);
  const char* texturePath = lua_tostring(state->m_state, 2);
  if (texturePath == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&textureArg, "string");
    texturePath = "";
  }

  LuaPlus::LuaObject cursorObject(LuaPlus::LuaStackObject(state, 1));
  CMauiCursor* const cursor = ResolveCursorFromLuaObjectOrError(cursorObject, state);
  cursor->SetTexture(texturePath);

  LuaPlus::LuaStackObject hotspotYArg(state, 4);
  if (lua_type(state->m_state, 4) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&hotspotYArg, "integer");
  }
  const int hotspotY = static_cast<int>(lua_tonumber(state->m_state, 4));

  LuaPlus::LuaStackObject hotspotXArg(state, 3);
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&hotspotXArg, "integer");
  }
  const int hotspotX = static_cast<int>(lua_tonumber(state->m_state, 3));

  (void)SetCursorHotspotXY(cursor, hotspotX, hotspotY);
  return 0;
}

/**
 * Address: 0x0078D5A0 (FUN_0078D5A0, cfunc_CMauiCursorResetToDefault)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiCursorResetToDefaultL`.
 */
int moho::cfunc_CMauiCursorResetToDefault(
  lua_State* const luaContext
)
{
  return cfunc_CMauiCursorResetToDefaultL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0078D5C0 (FUN_0078D5C0, func_CMauiCursorResetToDefault_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiCursor:ResetToDefault()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiCursorResetToDefault_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "ResetToDefault",
    &moho::cfunc_CMauiCursorResetToDefault,
    &moho::CScrLuaMetatableFactory<moho::CMauiCursor>::Instance(),
    "CMauiCursor",
    kCursorResetToDefaultHelpText
  );
  return &binder;
}

/**
 * Address: 0x0078D620 (FUN_0078D620, cfunc_CMauiCursorResetToDefaultL)
 *
 * What it does:
 * Resolves one cursor object and restores active texture/hotspot lanes from
 * default cursor state.
 */
int moho::cfunc_CMauiCursorResetToDefaultL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCursorResetToDefaultHelpText);

  LuaPlus::LuaObject cursorObject(LuaPlus::LuaStackObject(state, 1));
  CMauiCursor* const cursor = ResolveCursorFromLuaObjectOrError(cursorObject, state);
  cursor->ResetToDefault();
  return 0;
}

/**
 * Address: 0x0078D6C0 (FUN_0078D6C0, cfunc_CMauiCursorHide)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiCursorHideL`.
 */
int moho::cfunc_CMauiCursorHide(
  lua_State* const luaContext
)
{
  return cfunc_CMauiCursorHideL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0078D6E0 (FUN_0078D6E0, func_CMauiCursorHide_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiCursor:Hide()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiCursorHide_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "Hide",
    &moho::cfunc_CMauiCursorHide,
    &moho::CScrLuaMetatableFactory<moho::CMauiCursor>::Instance(),
    "CMauiCursor",
    kCursorShowHelpText
  );
  return &binder;
}

/**
 * Address: 0x0078D740 (FUN_0078D740, cfunc_CMauiCursorHideL)
 *
 * What it does:
 * Resolves one cursor object and marks it hidden in runtime cursor state
 * lanes.
 */
int moho::cfunc_CMauiCursorHideL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCursorShowHelpText);

  LuaPlus::LuaObject cursorObject(LuaPlus::LuaStackObject(state, 1));
  CMauiCursor* const cursor = ResolveCursorFromLuaObjectOrError(cursorObject, state);
  (void)SetCursorShowingAndMarkDirty(cursor, false);
  return 0;
}

/**
 * Address: 0x0078D7F0 (FUN_0078D7F0, cfunc_CMauiCursorShow)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiCursorShowL`.
 */
int moho::cfunc_CMauiCursorShow(
  lua_State* const luaContext
)
{
  return cfunc_CMauiCursorShowL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0078D810 (FUN_0078D810, func_CMauiCursorShow_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiCursor:Show()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiCursorShow_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "Show",
    &moho::cfunc_CMauiCursorShow,
    &moho::CScrLuaMetatableFactory<moho::CMauiCursor>::Instance(),
    "CMauiCursor",
    kCursorShowHelpText
  );
  return &binder;
}

/**
 * Address: 0x0078D870 (FUN_0078D870, cfunc_CMauiCursorShowL)
 *
 * What it does:
 * Resolves one cursor object and marks it visible in runtime cursor state
 * lanes.
 */
int moho::cfunc_CMauiCursorShowL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCursorShowHelpText);

  LuaPlus::LuaObject cursorObject(LuaPlus::LuaStackObject(state, 1));
  CMauiCursor* const cursor = ResolveCursorFromLuaObjectOrError(cursorObject, state);
  (void)SetCursorShowingAndMarkDirty(cursor, true);
  return 0;
}

/**
 * Address: 0x0086F090 (FUN_0086F090)
 *
 * What it does:
 * Publishes world-camera/minimap cursor telemetry into engine stats: cursor
 * position text, terrain elevation, occupancy-cell text, camera LOD metric,
 * and focus distance.
 */
void moho::UIWorldViewUpdateCursorEngineStats(
  CUIWorldView* const worldView,
  const Wm3::Vec3f& cursorWorldPosition
)
{
  moho::CameraImpl* const camera = worldView->mCamera.get();

  if (_stricmp(camera->CameraGetName(), "WorldCamera") == 0) {
    const fa::string positionText =
      gpg::STR_Printf("x=%.2f,y=%.2f,z=%.2f", cursorWorldPosition.x, cursorWorldPosition.y, cursorWorldPosition.z);
    EnsureEngineStringStat(gCameraCursorPositionStat, "Camera_Cursor_Position")->SetValue(positionText);

    StoreEngineFloatStat(
      gCameraCursorElevationStat,
      "Camera_Cursor_Elevation",
      SampleCursorTerrainElevation(*worldView, cursorWorldPosition)
    );

    const auto cellX = static_cast<std::int16_t>(static_cast<int>(cursorWorldPosition.x - 0.5f));
    const auto cellZ = static_cast<std::int16_t>(static_cast<int>(cursorWorldPosition.z - 0.5f));
    const fa::string cellText = gpg::STR_Printf("x=%i,z=%i", cellX, cellZ);
    EnsureEngineStringStat(gCameraCursorOCellStat, "Camera_Cursor_OCell")->SetValue(cellText);

    StoreCursorLodAndFocusStats(
      *camera,
      cursorWorldPosition,
      gCameraCursorLodMetricStat,
      "Camera_Cursor_LODMetric",
      gCameraFocusDistanceStat,
      "Camera_FocusDistance"
    );
  }

  if (_stricmp(camera->CameraGetName(), "MiniMap") == 0) {
    StoreCursorLodAndFocusStats(
      *camera,
      cursorWorldPosition,
      gMinimapCursorLodMetricStat,
      "Minimap_Cursor_LODMetric",
      gMinimapFocusDistanceStat,
      "Minimap_FocusDistance"
    );
  }
}

/**
 * Address: 0x0078CEF0 (FUN_0078CEF0, sub_78CEF0)
 *
 * What it does:
 * Commits pending cursor texture/visibility state to the active D3D device.
 */
void moho::MAUI_UpdateCursor(
  CMauiCursor* const cursor
)
{
  if (cursor == nullptr) {
    return;
  }

  if (!cursor->mNeedsUpdate) {
    return;
  }

  CD3DDevice* const device = D3D_GetDevice();
  if (device == nullptr) {
    return;
  }

  cursor->mNeedsUpdate = false;

  gpg::gal::Device* const galDevice = gpg::gal::Device::GetInstance();
  gpg::gal::DeviceContext* const deviceContext = galDevice != nullptr ? galDevice->GetDeviceContext() : nullptr;
  const gpg::gal::Head* primaryHead = nullptr;
  if (deviceContext != nullptr && deviceContext->GetHeadCount() > 0) {
    primaryHead = &deviceContext->GetHead(0u);
  }

  if (cursor->mTexture.get() != nullptr) {
    (void)device->SetCursor(cursor->mHotspotX, cursor->mHotspotY, cursor->mTexture);
  }

  const bool shouldShowCursor =
    cursor->mIsShowing || (primaryHead != nullptr && !primaryHead->mWindowed && ui_WindowedAlwaysShowsCursor);
  (void)device->ShowCursor(shouldShowCursor);
}
