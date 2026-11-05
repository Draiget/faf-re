#include "moho/ui/UiPrivate.h"

namespace
{
  constexpr const char* kInternalCreateBorderHelpText =
    "InternalCreateBorder(luaobj,parent) -- for internal use by CreateBorder()";
  constexpr const char* kCMauiBorderSetNewTexturesHelpText =
    "SetNewTextures(vertical, horizontal, upperLeft, upperRight, lowerLeft, lowerRight)";
  constexpr const char* kCMauiBorderSetSolidColorHelpText = "SetSolidColor(color)";
}

gpg::RType* moho::CMauiBorder::sType = nullptr;

/**
 * Address: 0x00785960 (FUN_00785960, cfunc_CMauiBorderSetNewTextures)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiBorderSetNewTexturesL`.
 */
int moho::cfunc_CMauiBorderSetNewTextures(
  lua_State* const luaContext
)
{
  return cfunc_CMauiBorderSetNewTexturesL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00785980 (FUN_00785980, func_CMauiBorderSetNewTextures_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBorder:SetNewTextures(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBorderSetNewTextures_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetNewTextures",
    &moho::cfunc_CMauiBorderSetNewTextures,
    &moho::CScrLuaMetatableFactory<moho::CMauiBorder>::Instance(),
    "CMauiBorder",
    kCMauiBorderSetNewTexturesHelpText
  );
  return &binder;
}

/**
 * Address: 0x007859E0 (FUN_007859E0, cfunc_CMauiBorderSetNewTexturesL)
 *
 * What it does:
 * Reads one `CMauiBorder` plus six optional texture-path lanes and forwards
 * resolved texture handles to `CMauiBorder::SetTextures`.
 */
int moho::cfunc_CMauiBorderSetNewTexturesL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 7, kCMauiBorderSetNewTexturesHelpText);

  LuaPlus::LuaObject borderObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBorder* const border = SCR_FromLua_CMauiBorder(borderObject, state);

  const auto readOptionalTexturePath = [state](const int index) -> const char* {
    if (lua_type(state->m_state, index) == LUA_TNIL) {
      return nullptr;
    }

    LuaPlus::LuaStackObject textureArg(state, index);
    const char* texturePath = lua_tostring(state->m_state, index);
    if (texturePath == nullptr) {
      LuaPlus::LuaStackObject::TypeError(&textureArg, "string");
      texturePath = "";
    }
    return texturePath;
  };

  const char* const vertPath = readOptionalTexturePath(2);
  const char* const horzPath = readOptionalTexturePath(3);
  const char* const ulPath = readOptionalTexturePath(4);
  const char* const urPath = readOptionalTexturePath(5);
  const char* const llPath = readOptionalTexturePath(6);
  const char* const lrPath = readOptionalTexturePath(7);

  const boost::shared_ptr<CD3DBatchTexture> vertTexture =
    vertPath != nullptr ? CD3DBatchTexture::FromFile(vertPath, 1u) : boost::shared_ptr<CD3DBatchTexture>{};
  const boost::shared_ptr<CD3DBatchTexture> horzTexture =
    horzPath != nullptr ? CD3DBatchTexture::FromFile(horzPath, 1u) : boost::shared_ptr<CD3DBatchTexture>{};
  const boost::shared_ptr<CD3DBatchTexture> ulTexture =
    ulPath != nullptr ? CD3DBatchTexture::FromFile(ulPath, 1u) : boost::shared_ptr<CD3DBatchTexture>{};
  const boost::shared_ptr<CD3DBatchTexture> urTexture =
    urPath != nullptr ? CD3DBatchTexture::FromFile(urPath, 1u) : boost::shared_ptr<CD3DBatchTexture>{};
  const boost::shared_ptr<CD3DBatchTexture> llTexture =
    llPath != nullptr ? CD3DBatchTexture::FromFile(llPath, 1u) : boost::shared_ptr<CD3DBatchTexture>{};
  const boost::shared_ptr<CD3DBatchTexture> lrTexture =
    lrPath != nullptr ? CD3DBatchTexture::FromFile(lrPath, 1u) : boost::shared_ptr<CD3DBatchTexture>{};

  border->SetTextures(vertTexture, horzTexture, ulTexture, urTexture, llTexture, lrTexture);
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00785FA0 (FUN_00785FA0, cfunc_CMauiBorderSetSolidColor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiBorderSetSolidColorL`.
 */
int moho::cfunc_CMauiBorderSetSolidColor(
  lua_State* const luaContext
)
{
  return cfunc_CMauiBorderSetSolidColorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00785FC0 (FUN_00785FC0, func_CMauiBorderSetSolidColor_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBorder:SetSolidColor(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBorderSetSolidColor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetSolidColor",
    &moho::cfunc_CMauiBorderSetSolidColor,
    &moho::CScrLuaMetatableFactory<moho::CMauiBorder>::Instance(),
    "CMauiBorder",
    kCMauiBorderSetSolidColorHelpText
  );
  return &binder;
}

/**
 * Address: 0x00786020 (FUN_00786020, cfunc_CMauiBorderSetSolidColorL)
 *
 * What it does:
 * Reads one `CMauiBorder` plus one color lane and assigns one shared
 * solid-color texture to all six border texture slots.
 */
int moho::cfunc_CMauiBorderSetSolidColorL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiBorderSetSolidColorHelpText);

  LuaPlus::LuaObject borderObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBorder* const border = SCR_FromLua_CMauiBorder(borderObject, state);

  LuaPlus::LuaObject colorObject(LuaPlus::LuaStackObject(state, 2));
  const std::uint32_t rgba = SCR_DecodeColor(state, colorObject);
  const boost::shared_ptr<CD3DBatchTexture> solidTexture = CD3DBatchTexture::FromSolidColor(rgba);
  border->SetTextures(solidTexture, solidTexture, solidTexture, solidTexture, solidTexture, solidTexture);

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x007857B0 (FUN_007857B0, cfunc_InternalCreateBorder)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_InternalCreateBorderL`.
 */
int moho::cfunc_InternalCreateBorder(
  lua_State* const luaContext
)
{
  return cfunc_InternalCreateBorderL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007857D0 (FUN_007857D0, func_InternalCreateBorder_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `InternalCreateBorder(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_InternalCreateBorder_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "InternalCreateBorder",
    &moho::cfunc_InternalCreateBorder,
    nullptr,
    "<global>",
    kInternalCreateBorderHelpText
  );
  return &binder;
}

/**
 * Address: 0x00785830 (FUN_00785830, cfunc_InternalCreateBorderL)
 *
 * What it does:
 * Reads `(luaobj,parent)`, constructs one `CMauiBorder`, dispatches `OnInit`,
 * and pushes the created control object.
 */
int moho::cfunc_InternalCreateBorderL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kInternalCreateBorderHelpText);

  LuaPlus::LuaObject parentObject(LuaPlus::LuaStackObject(state, 2));
  CMauiControl* const parentControl = SCR_FromLua_CMauiControl(parentObject, state);

  LuaPlus::LuaObject luaObject(LuaPlus::LuaStackObject(state, 1));
  // Binary: `operator new(0x174)`.
  auto* const border = AllocateZeroedUiObject<CMauiBorder>(0x174u);
  new (border) CMauiBorder(&luaObject, parentControl);
  border->DoInit();
  border->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x00784A10 (FUN_00784A10, Moho::CMauiBorder::CMauiBorder)
 *
 * What it does:
 * Constructs one border control from Lua object + parent lanes and initializes
 * border texture/lazy-var runtime fields.
 */
moho::CMauiBorder::CMauiBorder(
  LuaPlus::LuaObject* const luaObject,
  CMauiControl* const parent
)
  : CMauiControl(luaObject, parent, "border")
  , mBorderWidthLV(LuaStateOf(luaObject))
  , mBorderHeightLV(LuaStateOf(luaObject))
{
  LuaPlus::LuaObject& controlLuaObject = mLuaObj;
  controlLuaObject.SetObject("BorderWidth", &mBorderWidthLV);
  controlLuaObject.SetObject("BorderHeight", &mBorderHeightLV);
}

/**
 * Address: 0x00784840 (FUN_00784840, Moho::CMauiBorder::StaticGetClass)
 *
 * What it does:
 * Returns cached reflection descriptor for `CMauiBorder`.
 */
gpg::RType* moho::CMauiBorder::StaticGetClass()
{
  if (!sType) {
    sType = gpg::LookupRType(typeid(CMauiBorder));
  }
  return sType;
}

/**
 * Address: 0x00784860 (FUN_00784860, Moho::CMauiBorder::GetClass)
 *
 * What it does:
 * Returns cached reflection descriptor for this `CMauiBorder` instance.
 */
gpg::RType* moho::CMauiBorder::GetClass() const
{
  return StaticGetClass();
}

/**
 * Address: 0x00784880 (FUN_00784880, Moho::CMauiBorder::GetDerivedObjectRef)
 *
 * What it does:
 * Packs `{this, GetClass()}` as a reflection reference handle.
 */
gpg::RRef moho::CMauiBorder::GetDerivedObjectRef()
{
  return gpg::MakeSelfRef(this);
}

/**
 * Address: 0x00784D60 (FUN_00784D60, Moho::CMauiBorder::SetTextures)
 *
 * What it does:
 * Replaces any non-null border texture lanes and updates border width/height
 * lazy-vars from the vertical and horizontal texture dimensions.
 */
void moho::CMauiBorder::SetTextures(
  const boost::shared_ptr<CD3DBatchTexture>& vert,
  const boost::shared_ptr<CD3DBatchTexture>& horz,
  const boost::shared_ptr<CD3DBatchTexture>& ul,
  const boost::shared_ptr<CD3DBatchTexture>& ur,
  const boost::shared_ptr<CD3DBatchTexture>& ll,
  const boost::shared_ptr<CD3DBatchTexture>& lr
)
{
  if (vert) {
    mTex1 = vert;
    CScriptLazyVar_float::SetValue(&mBorderWidthLV, static_cast<float>(vert->mWidth));
  }

  if (horz) {
    mTexHorz = horz;
    CScriptLazyVar_float::SetValue(&mBorderHeightLV, static_cast<float>(horz->mHeight));
  }

  if (ul) {
    mTexUL = ul;
  }

  if (ur) {
    mTexUR = ur;
  }

  if (ll) {
    mTexLL = ll;
  }

  if (lr) {
    mTexLR = lr;
  }
}

/**
 * Address: 0x00784D00 (FUN_00784D00, Moho::CMauiBorder::Dump)
 *
 * What it does:
 * Logs this border label and current border width/height lazy-var values.
 */
void moho::CMauiBorder::Dump()
{
  CMauiControl::Dump();
  gpg::Logf("CMauiBorder");

  const double borderHeight = static_cast<double>(CScriptLazyVar_float::GetValue(&mBorderHeightLV));
  const double borderWidth = static_cast<double>(CScriptLazyVar_float::GetValue(&mBorderWidthLV));
  gpg::Logf("BorderWidth = %.3f BorderHeight = %.3f", borderWidth, borderHeight);
}

/**
 * Address: 0x00784F50 (FUN_00784F50, Moho::CMauiBorder::Draw)
 *
 * What it does:
 * Draws border corner quads, then optional horizontal and vertical body strips
 * using border lazy-var geometry and retained border textures.
 */
void moho::CMauiBorder::DoRender(
  CD3DPrimBatcher* const primBatcher,
  const std::int32_t drawMask
)
{
  (void)drawMask;
  if (primBatcher == nullptr) {
    return;
  }

  if (!mTex1 || !mTexHorz || !mTexUL || !mTexUR || !mTexLL || !mTexLR) {
    return;
  }

  const float left = CScriptLazyVar_float::GetValue(&mLeftLV);
  const float top = CScriptLazyVar_float::GetValue(&mTopLV);
  const float right = CScriptLazyVar_float::GetValue(&mRightLV);
  const float bottom = CScriptLazyVar_float::GetValue(&mBottomLV);
  const float borderWidth =
    static_cast<float>(FloorFrndintAdjustDown(CScriptLazyVar_float::GetValue(&mBorderWidthLV)));
  const float borderHeight =
    static_cast<float>(FloorFrndintAdjustDown(CScriptLazyVar_float::GetValue(&mBorderHeightLV)));

  const float innerLeft = left + borderWidth;
  const float innerRight = right - borderWidth;
  const float innerTop = top + borderHeight;
  const float innerBottom = bottom - borderHeight;

  const std::uint32_t color = mVertexAlpha;

  primBatcher->SetTexture(mTexUL);
  {
    const CD3DPrimBatcher::Vertex topLeft = MakeBorderVertex(left, top, color, 0.0f, 0.0f);
    const CD3DPrimBatcher::Vertex topRight = MakeBorderVertex(innerLeft, top, color, 1.0f, 0.0f);
    const CD3DPrimBatcher::Vertex bottomRight = MakeBorderVertex(innerLeft, innerTop, color, 1.0f, 1.0f);
    const CD3DPrimBatcher::Vertex bottomLeft = MakeBorderVertex(left, innerTop, color, 0.0f, 1.0f);
    primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
  }

  primBatcher->SetTexture(mTexUR);
  {
    const CD3DPrimBatcher::Vertex topLeft = MakeBorderVertex(innerRight, top, color, 0.0f, 0.0f);
    const CD3DPrimBatcher::Vertex topRight = MakeBorderVertex(right, top, color, 1.0f, 0.0f);
    const CD3DPrimBatcher::Vertex bottomRight = MakeBorderVertex(right, innerTop, color, 1.0f, 1.0f);
    const CD3DPrimBatcher::Vertex bottomLeft = MakeBorderVertex(innerRight, innerTop, color, 0.0f, 1.0f);
    primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
  }

  primBatcher->SetTexture(mTexLL);
  {
    const CD3DPrimBatcher::Vertex topLeft = MakeBorderVertex(left, innerBottom, color, 0.0f, 0.0f);
    const CD3DPrimBatcher::Vertex topRight = MakeBorderVertex(innerLeft, innerBottom, color, 1.0f, 0.0f);
    const CD3DPrimBatcher::Vertex bottomRight = MakeBorderVertex(innerLeft, bottom, color, 1.0f, 1.0f);
    const CD3DPrimBatcher::Vertex bottomLeft = MakeBorderVertex(left, bottom, color, 0.0f, 1.0f);
    primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
  }

  primBatcher->SetTexture(mTexLR);
  {
    const CD3DPrimBatcher::Vertex topLeft = MakeBorderVertex(innerRight, innerBottom, color, 0.0f, 0.0f);
    const CD3DPrimBatcher::Vertex topRight = MakeBorderVertex(right, innerBottom, color, 1.0f, 0.0f);
    const CD3DPrimBatcher::Vertex bottomRight = MakeBorderVertex(right, bottom, color, 1.0f, 1.0f);
    const CD3DPrimBatcher::Vertex bottomLeft = MakeBorderVertex(innerRight, bottom, color, 0.0f, 1.0f);
    primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
  }

  if ((right - left) > (borderWidth * 2.0f)) {
    primBatcher->SetTexture(mTexHorz);
    {
      const CD3DPrimBatcher::Vertex topLeft = MakeBorderVertex(innerLeft, top, color, 0.0f, 0.0f);
      const CD3DPrimBatcher::Vertex topRight = MakeBorderVertex(innerRight, top, color, 1.0f, 0.0f);
      const CD3DPrimBatcher::Vertex bottomRight = MakeBorderVertex(innerRight, innerTop, color, 1.0f, 1.0f);
      const CD3DPrimBatcher::Vertex bottomLeft = MakeBorderVertex(innerLeft, innerTop, color, 0.0f, 1.0f);
      primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
    }

    {
      const CD3DPrimBatcher::Vertex topLeft = MakeBorderVertex(innerLeft, innerBottom, color, 0.0f, 1.0f);
      const CD3DPrimBatcher::Vertex topRight = MakeBorderVertex(innerRight, innerBottom, color, 1.0f, 1.0f);
      const CD3DPrimBatcher::Vertex bottomRight = MakeBorderVertex(innerRight, bottom, color, 1.0f, 0.0f);
      const CD3DPrimBatcher::Vertex bottomLeft = MakeBorderVertex(innerLeft, bottom, color, 0.0f, 0.0f);
      primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
    }
  }

  if ((bottom - top) > (borderHeight * 2.0f)) {
    primBatcher->SetTexture(mTex1);
    {
      const CD3DPrimBatcher::Vertex topLeft = MakeBorderVertex(left, innerTop, color, 0.0f, 0.0f);
      const CD3DPrimBatcher::Vertex topRight = MakeBorderVertex(innerLeft, innerTop, color, 1.0f, 0.0f);
      const CD3DPrimBatcher::Vertex bottomRight = MakeBorderVertex(innerLeft, innerBottom, color, 1.0f, 1.0f);
      const CD3DPrimBatcher::Vertex bottomLeft = MakeBorderVertex(left, innerBottom, color, 0.0f, 1.0f);
      primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
    }

    {
      const CD3DPrimBatcher::Vertex topLeft = MakeBorderVertex(innerRight, innerTop, color, 1.0f, 0.0f);
      const CD3DPrimBatcher::Vertex topRight = MakeBorderVertex(right, innerTop, color, 0.0f, 0.0f);
      const CD3DPrimBatcher::Vertex bottomRight = MakeBorderVertex(right, innerBottom, color, 0.0f, 1.0f);
      const CD3DPrimBatcher::Vertex bottomLeft = MakeBorderVertex(innerRight, innerBottom, color, 1.0f, 1.0f);
      primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
    }
  }
}
