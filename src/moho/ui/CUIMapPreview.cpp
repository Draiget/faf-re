#include "moho/ui/UiPrivate.h"

namespace
{
  constexpr const char* kCUIMapPreviewSetTextureHelpText = "CUIMapPreview:SetTexture(texture_name)";
  constexpr const char* kCUIMapPreviewSetTextureFromMapHelpText = "CUIMapPreview:SetTextureFromMap(map_name)";
  constexpr const char* kCUIMapPreviewClearTextureHelpText = "CUIMapPreview::ClearTexture()";
}

gpg::RType* moho::CUIMapPreview::sType = nullptr;

/**
 * Address: 0x00850770 (FUN_00850770, Moho::CUIMapPreview::CUIMapPreview)
 *
 * What it does:
 * Constructs one map-preview control from Lua object + parent lanes and
 * initializes preview texture ownership lanes.
 */
moho::CUIMapPreview::CUIMapPreview(
  LuaPlus::LuaObject* const luaObject,
  CMauiControl* const parent
)
  : CMauiControl(luaObject, parent, "mappreview")
{
  mTexture = {};
}

/**
 * Address: 0x008507F0 (FUN_008507F0, Moho::CUIMapPreview::~CUIMapPreview)
 *
 * What it does:
 * Releases the preview texture lane before the inherited control teardown
 * continues through `CMauiControl`.
 */
moho::CUIMapPreview::~CUIMapPreview()
{
  mTexture = {};
}

/**
 * Address: 0x008507D0 (FUN_008507D0, Moho::CUIMapPreview::Delete)
 *
 * What it does:
 * Mirrors the deleting-destructor thunk lane for map-preview controls and
 * optionally frees the storage block.
 */
moho::CUIMapPreview* moho::CUIMapPreview::DeleteWithFlag(
  CUIMapPreview* const object,
  const std::uint8_t deleteFlags
) noexcept
{
  object->~CUIMapPreview();
  if ((deleteFlags & 1u) != 0u) {
    operator delete(object);
  }

  return object;
}

/**
 * Address: 0x00850870 (FUN_00850870, Moho::CUIMapPreview::SetTexture)
 *
 * What it does:
 * Clears existing preview texture ownership and loads one map-preview texture
 * from D3D device resources by file path.
 */
bool moho::CUIMapPreview::SetTexture(
  const char* const texturePath
)
{
  mTexture = {};

  if (texturePath == nullptr || texturePath[0] == '\0') {
    return false;
  }

  ID3DDeviceResources::TextureResourceHandle loadedTexture{};
  if (CD3DDevice* const device = D3D_GetDevice(); device != nullptr) {
    if (ID3DDeviceResources* const resources = device->GetResources(); resources != nullptr) {
      resources->GetTexture(loadedTexture, texturePath, 0, true);
    }
  }

  mTexture = boost::static_pointer_cast<ID3DTextureSheet>(loadedTexture);
  return mTexture.get() != nullptr;
}

/**
 * Address: 0x008509A0 (FUN_008509A0, Moho::CUIMapPreview::SetTextureFromMap)
 *
 * What it does:
 * Clears existing preview texture ownership, loads one map in preview-only
 * mode through `WLD_LoadMapPreview`, and binds the resulting preview texture
 * sheet when the load produced a preview chunk.
 */
bool moho::CUIMapPreview::SetTextureFromMap(
  const char* const mapPath
)
{
  mTexture = {};

  if (mapPath == nullptr || mapPath[0] == '\0') {
    return false;
  }

  fa::auto_ptr<CWldMap> loadedMap = WLD_LoadMapPreview(mapPath);
  if (loadedMap.get() != nullptr && loadedMap->mMapPreviewChunk != nullptr) {
    mTexture = loadedMap->mMapPreviewChunk->mPreviewTexture;
  }

  return mTexture.get() != nullptr;
}

/**
 * Address: 0x00850AC0 (FUN_00850AC0, Moho::CUIMapPreview::ClearTexture)
 *
 * What it does:
 * Releases any currently bound map-preview texture ownership.
 */
void moho::CUIMapPreview::ClearTexture()
{
  mTexture = {};
}

/**
 * Address: 0x00850B10 (FUN_00850B10, Moho::CUIMapPreview::Draw)
 *
 * IDA signature:
 * void __thiscall Moho::CUIMapPreview::Draw(
 *   CUIMapPreview* this, CD3DPrimBatcher* primBatcher, int drawMask);
 *
 * What it does:
 * Renders the bound preview texture as an aspect-fit (letterbox/pillarbox)
 * white-tinted textured quad centered inside the control bounds. No-op when no
 * texture is bound. Occupies the CMauiControl::DoRender vtable slot; drawMask
 * is unused.
 */
void moho::CUIMapPreview::DoRender(
  CD3DPrimBatcher* const primBatcher,
  const std::int32_t drawMask
)
{
  (void)drawMask;

  if (!mTexture) {
    return;
  }

  float left = CScriptLazyVar_float::GetValue(&mLeftLV);
  float top = CScriptLazyVar_float::GetValue(&mTopLV);
  float right = CScriptLazyVar_float::GetValue(&mRightLV);
  float bottom = CScriptLazyVar_float::GetValue(&mBottomLV);

  Wm3::Vector3f dimensions{};
  (void)mTexture->GetDimensions(&dimensions);

  const float scaleX = (right - left) / dimensions.x;
  const float scaleY = (bottom - top) / dimensions.y;
  if (scaleY <= scaleX) {
    const float pad = ((right - left) - (dimensions.x * scaleY)) * 0.5f;
    left = left + pad;
    right = right - pad;
  } else {
    const float pad = ((bottom - top) - (dimensions.y * scaleX)) * 0.5f;
    top = top + pad;
    bottom = bottom - pad;
  }

  primBatcher->SetTexture(mTexture);

  constexpr std::uint32_t vertexColor = 0xFFFFFFFFu;
  const CD3DPrimBatcher::Vertex topLeft = MakeBorderVertex(left, top, vertexColor, 0.0f, 0.0f);
  const CD3DPrimBatcher::Vertex topRight = MakeBorderVertex(right, top, vertexColor, 1.0f, 0.0f);
  const CD3DPrimBatcher::Vertex bottomRight = MakeBorderVertex(right, bottom, vertexColor, 1.0f, 1.0f);
  const CD3DPrimBatcher::Vertex bottomLeft = MakeBorderVertex(left, bottom, vertexColor, 0.0f, 1.0f);
  primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
}

/**
 * Address: 0x00850ED0 (FUN_00850ED0, cfunc_CUIMapPreviewSetTexture)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIMapPreviewSetTextureL`.
 */
int moho::cfunc_CUIMapPreviewSetTexture(
  lua_State* const luaContext
)
{
  return cfunc_CUIMapPreviewSetTextureL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00850EF0 (FUN_00850EF0, func_CUIMapPreviewSetTexture_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIMapPreview:SetTexture(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIMapPreviewSetTexture_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetTexture",
    &moho::cfunc_CUIMapPreviewSetTexture,
    &moho::CScrLuaMetatableFactory<moho::CUIMapPreview>::Instance(),
    "CUIMapPreview",
    kCUIMapPreviewSetTextureHelpText
  );
  return &binder;
}

/**
 * Address: 0x00850F50 (FUN_00850F50, cfunc_CUIMapPreviewSetTextureL)
 *
 * What it does:
 * Reads one `CUIMapPreview` plus texture-path string and returns one success
 * boolean from `CUIMapPreview::SetTexture`.
 */
int moho::cfunc_CUIMapPreviewSetTextureL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCUIMapPreviewSetTextureHelpText);

  LuaPlus::LuaObject mapPreviewObject(LuaPlus::LuaStackObject(state, 1));
  CUIMapPreview* const mapPreview = SCR_FromLua_CUIMapPreview(mapPreviewObject, state);

  LuaPlus::LuaStackObject textureArg(state, 2);
  const char* texturePath = lua_tostring(state->m_state, 2);
  if (texturePath == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&textureArg, "string");
    texturePath = "";
  }

  const bool success = mapPreview->SetTexture(texturePath);
  lua_pushboolean(state->m_state, success);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00851040 (FUN_00851040, cfunc_CUIMapPreviewSetTextureFromMap)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIMapPreviewSetTextureFromMapL`.
 */
int moho::cfunc_CUIMapPreviewSetTextureFromMap(
  lua_State* const luaContext
)
{
  return cfunc_CUIMapPreviewSetTextureFromMapL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00851060 (FUN_00851060, func_CUIMapPreviewSetTextureFromMap_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIMapPreview:SetTextureFromMap(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIMapPreviewSetTextureFromMap_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetTextureFromMap",
    &moho::cfunc_CUIMapPreviewSetTextureFromMap,
    &moho::CScrLuaMetatableFactory<moho::CUIMapPreview>::Instance(),
    "CUIMapPreview",
    kCUIMapPreviewSetTextureFromMapHelpText
  );
  return &binder;
}

/**
 * Address: 0x008510C0 (FUN_008510C0, cfunc_CUIMapPreviewSetTextureFromMapL)
 *
 * What it does:
 * Reads one `CUIMapPreview` plus map-path string and returns one success
 * boolean from `CUIMapPreview::SetTextureFromMap`.
 */
int moho::cfunc_CUIMapPreviewSetTextureFromMapL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCUIMapPreviewSetTextureFromMapHelpText);

  LuaPlus::LuaObject mapPreviewObject(LuaPlus::LuaStackObject(state, 1));
  CUIMapPreview* const mapPreview = SCR_FromLua_CUIMapPreview(mapPreviewObject, state);

  LuaPlus::LuaStackObject mapArg(state, 2);
  const char* mapPath = lua_tostring(state->m_state, 2);
  if (mapPath == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&mapArg, "string");
    mapPath = "";
  }

  const bool success = mapPreview->SetTextureFromMap(mapPath);
  lua_pushboolean(state->m_state, success);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x008511B0 (FUN_008511B0, cfunc_CUIMapPreviewClearTexture)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIMapPreviewClearTextureL`.
 */
int moho::cfunc_CUIMapPreviewClearTexture(
  lua_State* const luaContext
)
{
  return cfunc_CUIMapPreviewClearTextureL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x008511D0 (FUN_008511D0, func_CUIMapPreviewClearTexture_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIMapPreview:ClearTexture()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIMapPreviewClearTexture_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "ClearTexture",
    &moho::cfunc_CUIMapPreviewClearTexture,
    &moho::CScrLuaMetatableFactory<moho::CUIMapPreview>::Instance(),
    "CUIMapPreview",
    kCUIMapPreviewClearTextureHelpText
  );
  return &binder;
}

/**
 * Address: 0x00851230 (FUN_00851230, cfunc_CUIMapPreviewClearTextureL)
 *
 * What it does:
 * Reads one `CUIMapPreview` and clears its currently bound preview texture.
 */
int moho::cfunc_CUIMapPreviewClearTextureL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCUIMapPreviewClearTextureHelpText);

  LuaPlus::LuaObject mapPreviewObject(LuaPlus::LuaStackObject(state, 1));
  CUIMapPreview* const mapPreview = SCR_FromLua_CUIMapPreview(mapPreviewObject, state);
  mapPreview->ClearTexture();
  return 0;
}

/**
 * Address: 0x008505E0 (FUN_008505E0, Moho::CUIMapPreview::GetClass)
 *
 * What it does:
 * Returns the cached reflection descriptor for `CUIMapPreview`, resolved via
 * RTTI on first use.
 */
gpg::RType* moho::CUIMapPreview::GetClass() const
{
  if (!sType) {
    sType = gpg::LookupRType(typeid(CUIMapPreview));
  }
  return sType;
}

/**
 * Address: 0x00850600 (FUN_00850600, Moho::CUIMapPreview::GetDerivedObjectRef)
 *
 * What it does:
 * Packs `{this, GetClass()}` as a reflection reference handle.
 */
gpg::RRef moho::CUIMapPreview::GetDerivedObjectRef()
{
  return gpg::MakeSelfRef(this);
}
