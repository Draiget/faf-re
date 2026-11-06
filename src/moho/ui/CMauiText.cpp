#include "moho/ui/UiPrivate.h"

#include <cmath>
#include <map>
#include <string>

#include "moho/misc/FileWaitHandleSet.h"
#include "moho/render/font/MsdfFontCheck.h"
#include "moho/render/font/MsdfFontRegistry.h"

namespace
{
  constexpr const char* kInternalCreateTextHelpText = "InternalCreateText(luaobj,parent)";
  constexpr const char* kCMauiTextSetNewFontHelpText = "Text:SetNewFont(family, pointsize)";
  constexpr const char* kCMauiTextGetTextHelpText = "string Text:GetText()";
  constexpr const char* kCMauiTextSetNewColorHelpText = "Text:SetNewColor(color)";
  constexpr const char* kCMauiTextSetDropShadowHelpText = "Text:SetDropShadow(bool)";
  constexpr const char* kCMauiTextSetCenteredHorizontallyHelpText = "Text:SetCenteredHorizontally(bool)";
  constexpr const char* kCMauiTextSetCenteredVerticallyHelpText = "Text:SetCenteredVertically(bool)";
  constexpr const char* kCMauiTextSetNewClipToWidthHelpText =
    "SetNewClipToWidth(bool) - will cause the control to only render as many charachters as fit in its width";
  constexpr const char* kCMauiTextSetTextHelpText = "CMauiText:SetText(text)";
  constexpr const char* kCMauiTextGetStringAdvanceHelpText =
    "number Text:GetAdvance(string) - get the advance of a string using the same font as the text control";
  constexpr const char* kCMauiTextSetTextScaleHelpText =
    "Text:SetTextScale(scale[, pivotX, pivotY]) - draw the text larger or smaller without moving the layout. The "
    "pivots say which point of the control stays put, 0 to 1 across it; the middle by default";
  constexpr const char* kCMauiTextGetTextScaleHelpText = "number Text:GetTextScale()";
  constexpr const char* kLoadFontHelpText =
    "string LoadFont(path) - load a .ttf or .otf under /mods/<mod>/fonts/ and return the family to pass to SetFont, "
    "or nil when it is refused";

  /**
   * Engine addition: a text control's draw scale, beside it because the class's layout is the binary's. Only
   * controls with a scale are here, so the rest pay one load per draw.
   */
  struct STextScale
  {
    float mScale = 1.0f;
    float mPivotX = 0.5f;
    float mPivotY = 0.5f;
  };
  std::map<const moho::CMauiText*, STextScale> sTextScales;

  constexpr float kMaxTextScale = 64.0f;

  /**
   * Address: 0x0078EBF0 (FUN_0078EBF0)
   *
   * What it does:
   * Returns one font descent metric lane.
   */
  [[maybe_unused]] float ReadFontDescentLane(
    const CD3DFont* const font
  ) noexcept
  {
    return font->mDescent;
  }
}

gpg::RType* moho::CMauiText::sType = nullptr;

/**
 * Address: 0x007A3340 (FUN_007A3340, cfunc_InternalCreateText)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_InternalCreateTextL`.
 */
int moho::cfunc_InternalCreateText(
  lua_State* const luaContext
)
{
  return cfunc_InternalCreateTextL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A3360 (FUN_007A3360, func_InternalCreateText_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `InternalCreateText(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_InternalCreateText_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "InternalCreateText",
    &moho::cfunc_InternalCreateText,
    nullptr,
    "<global>",
    kInternalCreateTextHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A33C0 (FUN_007A33C0, cfunc_InternalCreateTextL)
 *
 * What it does:
 * Reads `(luaobj,parent)`, constructs one `CMauiText`, dispatches `OnInit`,
 * and pushes the created control object.
 */
int moho::cfunc_InternalCreateTextL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kInternalCreateTextHelpText);

  LuaPlus::LuaObject parentObject(LuaPlus::LuaStackObject(state, 2));
  CMauiControl* const parentControl = SCR_FromLua_CMauiControl(parentObject, state);

  LuaPlus::LuaObject luaObject(LuaPlus::LuaStackObject(state, 1));
  // Binary: `operator new(0x194)`.
  auto* const text = AllocateZeroedUiObject<CMauiText>(0x194u);
  new (text) CMauiText(&luaObject, parentControl);
  text->DoInit();
  text->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x007A2BE0 (FUN_007A2BE0, Moho::CMauiText::CMauiText)
 *
 * What it does:
 * Constructs one text control from Lua object + parent lanes and initializes
 * text/font/lazy-var runtime fields.
 */
moho::CMauiText::CMauiText(
  LuaPlus::LuaObject* const luaObject,
  CMauiControl* const parent
)
  : CMauiControl(luaObject, parent, "text")
  , mFont(nullptr)
  , mText()
  , mColor(0xFFFFFFFFu)
  , mDropShadow(false)
  , mClipToWidth(false)
  , mCenteredHorizontally(false)
  , mCenteredVertically(false)
  , mTextAdvanceLV(LuaStateOf(luaObject))
  , mFontAscentLV(LuaStateOf(luaObject))
  , mFontDescentLV(LuaStateOf(luaObject))
  , mFontExternalLeadingLV(LuaStateOf(luaObject))
{
  LuaPlus::LuaObject& controlLuaObject = mLuaObj;
  controlLuaObject.SetObject("TextAdvance", &mTextAdvanceLV);
  controlLuaObject.SetObject("FontAscent", &mFontAscentLV);
  controlLuaObject.SetObject("FontDescent", &mFontDescentLV);
  controlLuaObject.SetObject("FontExternalLeading", &mFontExternalLeadingLV);
}

/**
 * Address: 0x007A2D60 (FUN_007A2D60, Moho::CMauiText::~CMauiText)
 * Deleting dtor: 0x007A2D40 (FUN_007A2D40, Moho::CMauiText::dtr)
 *
 * IDA signature:
 * _DWORD *__stdcall sub_7A2D60(CMauiText *this);
 *
 * What it does:
 * Destroys the four lazy-var LuaObject lanes (external-leading, descent,
 * ascent, text-advance), tidies the cached text string, releases the
 * intrusive font reference, then falls through to the base CMauiControl
 * destructor.
 */
moho::CMauiText::~CMauiText()
{
  // The binary drops the font last, after the lazy vars and the string, which
  // is where a smart-pointer member at +0x11C would put it. `mFont` is a raw
  // pointer here, so the release runs from the body, ahead of them.
  ReleaseIntrusiveFont(mFont);
  sTextScales.erase(this);
}

/**
 * Address: 0x007A2EA0 (FUN_007A2EA0, Moho::CMauiText::SetNewFont)
 *
 * What it does:
 * Rebinds text font lane and refreshes cached text/font metric lazy-vars.
 */
void moho::CMauiText::SetNewFont(
  CD3DFont* const font
)
{
  AssignIntrusiveFont(mFont, font);

  if (mFont != nullptr) {
    const float advance = mFont->GetAdvance(mText.c_str(), 0);
    CScriptLazyVar_float::SetValue(&mTextAdvanceLV, advance);
    CScriptLazyVar_float::SetValue(&mFontAscentLV, mFont->mAscent);
    CScriptLazyVar_float::SetValue(&mFontDescentLV, ReadFontDescentLane(mFont));
    CScriptLazyVar_float::SetValue(&mFontExternalLeadingLV, mFont->mExternalLeading);
  } else {
    CScriptLazyVar_float::SetValue(&mTextAdvanceLV, 0.0f);
    CScriptLazyVar_float::SetValue(&mFontAscentLV, 0.0f);
    CScriptLazyVar_float::SetValue(&mFontDescentLV, 0.0f);
    CScriptLazyVar_float::SetValue(&mFontExternalLeadingLV, 0.0f);
  }
}

/**
 * Address: 0x007A2FA0 (FUN_007A2FA0, Moho::CMauiText::SetText)
 *
 * What it does:
 * Stores one new text lane and refreshes cached text-advance width when a
 * font is bound.
 */
void moho::CMauiText::SetText(
  const char* const text
)
{
  const char* const safeText = text != nullptr ? text : "";
  mText.assign_owned(safeText);

  if (mFont != nullptr) {
    const float advance = mFont->GetAdvance(mText.c_str(), 0);
    CScriptLazyVar_float::SetValue(&mTextAdvanceLV, advance);
  }
}

/**
 * Address: 0x007A2E40 (FUN_007A2E40, Moho::CMauiText::Dump)
 *
 * What it does:
 * Logs this text control label, color lane, and current text payload.
 */
void moho::CMauiText::Dump()
{
  CMauiControl::Dump();

  gpg::Logf("CMauiText");
  gpg::Logf("Color = %#08X", mColor);
  gpg::Logf("Text = %s", mText.c_str());
}

/**
 * Address: 0x007A3040 (FUN_007A3040, Moho::CMauiText::Draw)
 *
 * IDA signature:
 * Wm3::Vector3f* __thiscall Moho::CMauiText::Draw(
 *   CMauiText* this, CD3DPrimBatcher* primBatcher, int drawMask);
 *
 * What it does:
 * Renders this text control's string. Horizontal origin is centered (and
 * back-shifted by half the measured advance) when mCenteredHorizontally is set,
 * otherwise the left edge. Baseline Y is vertically centered when
 * mCenteredVertically is set, otherwise ascent below the top edge. An optional
 * (+1,+1) drop shadow is drawn first, then the main run whose alpha byte is
 * derived from mAlpha. maxAdvance clips to the control width when mClipToWidth
 * is set, otherwise a quiet-NaN "no clip" sentinel is passed. Occupies the
 * CMauiControl::DoRender vtable slot; drawMask is unused.
 */
void moho::CMauiText::DoRender(
  CD3DPrimBatcher* const primBatcher,
  const std::int32_t drawMask
)
{
  (void)drawMask;

  CD3DFont* const font = mFont;
  if (font == nullptr) {
    return;
  }

  const char* const text = mText.c_str();

  // Engine addition (issue #304): a mod's font gets its own metrics when its atlas arrives, after Lua laid out
  // this control with the default font's, so the values Lua reads catch up here.
  if (font->IsModFont()) {
    const float advance = font->GetAdvance(text, 0);
    if (advance != CScriptLazyVar_float::GetValue(&mTextAdvanceLV) || font->mAscent != CScriptLazyVar_float::GetValue(&mFontAscentLV)) {
      SetNewFont(font);
    }
  }

  // Horizontal origin.
  float originX;
  if (mCenteredHorizontally) {
    const float advance = font->GetAdvance(text, 0);
    const float left = CScriptLazyVar_float::GetValue(&mLeftLV);
    originX = CScriptLazyVar_float::GetValue(&mWidthLV) * 0.5f + left - 0.5f * advance;
  } else {
    originX = CScriptLazyVar_float::GetValue(&mLeftLV);
  }

  // Baseline Y.
  float baselineY;
  if (mCenteredVertically) {
    const float centeredAscent = font->mAscent - font->mInternalLeading;
    const float top = CScriptLazyVar_float::GetValue(&mTopLV);
    baselineY = CScriptLazyVar_float::GetValue(&mHeightLV) * 0.5f + 0.5f * centeredAscent + top;
  } else {
    const float top = CScriptLazyVar_float::GetValue(&mTopLV);
    baselineY = font->mAscent + top;
  }

  // Engine addition: `SetTextScale`. The text grows around its pivot in the control, without touching the layout.
  float textScale = 1.0f;
  float pivotX = 0.0f;
  float pivotY = 0.0f;
  if (!sTextScales.empty()) {
    const auto scaled = sTextScales.find(this);
    if (scaled != sTextScales.end()) {
      textScale = scaled->second.mScale;
      if (textScale <= 0.0f) {
        return;
      }
      pivotX = CScriptLazyVar_float::GetValue(&mLeftLV) + CScriptLazyVar_float::GetValue(&mWidthLV) * scaled->second.mPivotX;
      pivotY = CScriptLazyVar_float::GetValue(&mTopLV) + CScriptLazyVar_float::GetValue(&mHeightLV) * scaled->second.mPivotY;
      originX = pivotX + (originX - pivotX) * textScale;
      baselineY = pivotY + (baselineY - pivotY) * textScale;
    }
  }

  const Wm3::Vector3f xAxis{textScale, 0.0f, 0.0f};
  const Wm3::Vector3f yAxis{0.0f, -textScale, 0.0f};

  // Optional drop shadow, offset by (+1, +1).
  if (mDropShadow) {
    const std::uint32_t shadowColor = this->AdjustARGBAlpha(mColor & 0xFF000000u);
    const float shadowMaxAdvance = mClipToWidth ? CScriptLazyVar_float::GetValue(&mWidthLV)
                                                          : gpg::NaN;
    const Wm3::Vector3f shadowOrigin{originX + textScale, baselineY + textScale, 0.0f};
    (void)font->Render(text, primBatcher, shadowOrigin, xAxis, yAxis, shadowColor, 1.0f, shadowMaxAdvance);
  }

  // Main text run.
  const float maxAdvance = mClipToWidth ? CScriptLazyVar_float::GetValue(&mWidthLV)
                                                  : gpg::NaN;

  // Alpha byte derived from mAlpha exactly as the binary does: negate-scale,
  // truncate toward zero, then subtract the shifted magnitude.
  const float alphaScaled = mAlpha * -255.0f;
  const std::uint32_t alphaMagnitude = static_cast<std::uint32_t>(static_cast<std::int64_t>(alphaScaled));
  const std::uint32_t color = (mColor & 0x00FFFFFFu) - (alphaMagnitude << 24);

  const Wm3::Vector3f origin{originX, baselineY, 0.0f};
  (void)font->Render(text, primBatcher, origin, xAxis, yAxis, color, 1.0f, maxAdvance);
}

/**
 * Address: 0x007A34F0 (FUN_007A34F0, cfunc_CMauiTextSetNewFont)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiTextSetNewFontL`.
 */
int moho::cfunc_CMauiTextSetNewFont(
  lua_State* const luaContext
)
{
  return cfunc_CMauiTextSetNewFontL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A3510 (FUN_007A3510, func_CMauiTextSetNewFont_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiText:SetNewFont(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiTextSetNewFont_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetNewFont",
    &moho::cfunc_CMauiTextSetNewFont,
    &moho::CScrLuaMetatableFactory<moho::CMauiText>::Instance(),
    "CMauiText",
    kCMauiTextSetNewFontHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A3570 (FUN_007A3570, cfunc_CMauiTextSetNewFontL)
 *
 * What it does:
 * Reads one `CMauiText` plus `(family, pointsize)`, creates one font, and
 * applies it to text runtime lanes.
 */
int moho::cfunc_CMauiTextSetNewFontL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 3, kCMauiTextSetNewFontHelpText);

  LuaPlus::LuaObject textObject(LuaPlus::LuaStackObject(state, 1));
  CMauiText* const textControl = SCR_FromLua_CMauiText(textObject, state);

  LuaPlus::LuaStackObject familyArg(state, 2);
  const char* const familyName = lua_tostring(state->m_state, 2);
  if (familyName == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&familyArg, "string");
  }

  LuaPlus::LuaStackObject pointSizeArg(state, 3);
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&pointSizeArg, "integer");
  }
  const int pointSize = static_cast<int>(lua_tonumber(state->m_state, 3));

  boost::SharedPtrRaw<CD3DFont> createdFont = CD3DFont::Create(pointSize, familyName);
  if (createdFont.px != nullptr) {
    textControl->SetNewFont(createdFont.px);
    lua_settop(state->m_state, 1);
  } else {
    lua_pushnil(state->m_state);
    (void)lua_gettop(state->m_state);
  }

  createdFont.release();
  return 1;
}

/**
 * Address: 0x007A3710 (FUN_007A3710, cfunc_CMauiTextSetText)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiTextSetTextL`.
 */
int moho::cfunc_CMauiTextSetText(
  lua_State* const luaContext
)
{
  return cfunc_CMauiTextSetTextL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A3730 (FUN_007A3730, func_CMauiTextSetText_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiText:SetText(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiTextSetText_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetText",
    &moho::cfunc_CMauiTextSetText,
    &moho::CScrLuaMetatableFactory<moho::CMauiText>::Instance(),
    "CMauiText",
    kCMauiTextSetTextHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A3790 (FUN_007A3790, cfunc_CMauiTextSetTextL)
 *
 * What it does:
 * Reads one `CMauiText` plus text string and updates control text and cached
 * text advance.
 */
int moho::cfunc_CMauiTextSetTextL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiTextSetTextHelpText);

  LuaPlus::LuaObject textControlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiText* const textControl = SCR_FromLua_CMauiText(textControlObject, state);

  LuaPlus::LuaStackObject textArg(state, 2);
  const char* text = lua_tostring(state->m_state, 2);
  if (text == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&textArg, "string");
    text = "";
  }

  textControl->SetText(text);
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x007A3880 (FUN_007A3880, cfunc_CMauiTextGetText)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiTextGetTextL`.
 */
int moho::cfunc_CMauiTextGetText(
  lua_State* const luaContext
)
{
  return cfunc_CMauiTextGetTextL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A38A0 (FUN_007A38A0, func_CMauiTextGetText_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiText:GetText()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiTextGetText_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetText",
    &moho::cfunc_CMauiTextGetText,
    &moho::CScrLuaMetatableFactory<moho::CMauiText>::Instance(),
    "CMauiText",
    kCMauiTextGetTextHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A3900 (FUN_007A3900, cfunc_CMauiTextGetTextL)
 *
 * What it does:
 * Reads one `CMauiText` and returns its current text lane.
 */
int moho::cfunc_CMauiTextGetTextL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiTextGetTextHelpText);

  LuaPlus::LuaObject textObject(LuaPlus::LuaStackObject(state, 1));
  const CMauiText* const textControl = SCR_FromLua_CMauiText(textObject, state);
  lua_pushstring(state->m_state, textControl->mText.c_str());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x007A39F0 (FUN_007A39F0, cfunc_CMauiTextSetNewColor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiTextSetNewColorL`.
 */
int moho::cfunc_CMauiTextSetNewColor(
  lua_State* const luaContext
)
{
  return cfunc_CMauiTextSetNewColorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A3A10 (FUN_007A3A10, func_CMauiTextSetNewColor_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiText:SetNewColor(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiTextSetNewColor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetNewColor",
    &moho::cfunc_CMauiTextSetNewColor,
    &moho::CScrLuaMetatableFactory<moho::CMauiText>::Instance(),
    "CMauiText",
    kCMauiTextSetNewColorHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A3A70 (FUN_007A3A70, cfunc_CMauiTextSetNewColorL)
 *
 * What it does:
 * Reads one `CMauiText` plus color arg and updates text color lane.
 */
int moho::cfunc_CMauiTextSetNewColorL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiTextSetNewColorHelpText);

  LuaPlus::LuaObject textObject(LuaPlus::LuaStackObject(state, 1));
  CMauiText* const textControl = SCR_FromLua_CMauiText(textObject, state);

  LuaPlus::LuaObject colorObject(LuaPlus::LuaStackObject(state, 2));
  textControl->mColor = SCR_DecodeColor(state, colorObject);
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x007A3B60 (FUN_007A3B60, cfunc_CMauiTextSetDropShadow)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiTextSetDropShadowL`.
 */
int moho::cfunc_CMauiTextSetDropShadow(
  lua_State* const luaContext
)
{
  return cfunc_CMauiTextSetDropShadowL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A3B80 (FUN_007A3B80, func_CMauiTextSetDropShadow_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiText:SetDropShadow(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiTextSetDropShadow_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetDropShadow",
    &moho::cfunc_CMauiTextSetDropShadow,
    &moho::CScrLuaMetatableFactory<moho::CMauiText>::Instance(),
    "CMauiText",
    kCMauiTextSetDropShadowHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A3BE0 (FUN_007A3BE0, cfunc_CMauiTextSetDropShadowL)
 *
 * What it does:
 * Reads one `CMauiText` plus bool and updates drop-shadow lane.
 */
int moho::cfunc_CMauiTextSetDropShadowL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiTextSetDropShadowHelpText);

  LuaPlus::LuaObject textObject(LuaPlus::LuaStackObject(state, 1));
  CMauiText* const textControl = SCR_FromLua_CMauiText(textObject, state);

  LuaPlus::LuaStackObject dropShadowArg(state, 2);
  textControl->mDropShadow = LuaPlus::LuaStackObject::GetBoolean(&dropShadowArg);
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x007A3CB0 (FUN_007A3CB0, cfunc_CMauiTextSetCenteredHorizontally)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiTextSetCenteredHorizontallyL`.
 */
int moho::cfunc_CMauiTextSetCenteredHorizontally(
  lua_State* const luaContext
)
{
  return cfunc_CMauiTextSetCenteredHorizontallyL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A3CD0 (FUN_007A3CD0, func_CMauiTextSetCenteredHorizontally_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiText:SetCenteredHorizontally(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiTextSetCenteredHorizontally_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetCenteredHorizontally",
    &moho::cfunc_CMauiTextSetCenteredHorizontally,
    &moho::CScrLuaMetatableFactory<moho::CMauiText>::Instance(),
    "CMauiText",
    kCMauiTextSetCenteredHorizontallyHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A3D30 (FUN_007A3D30, cfunc_CMauiTextSetCenteredHorizontallyL)
 *
 * What it does:
 * Reads one `CMauiText` plus bool and updates horizontal-centering lane.
 */
int moho::cfunc_CMauiTextSetCenteredHorizontallyL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiTextSetCenteredHorizontallyHelpText);

  LuaPlus::LuaObject textObject(LuaPlus::LuaStackObject(state, 1));
  CMauiText* const textControl = SCR_FromLua_CMauiText(textObject, state);

  LuaPlus::LuaStackObject centeredArg(state, 2);
  textControl->mCenteredHorizontally =
    LuaPlus::LuaStackObject::GetBoolean(&centeredArg);
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x007A3E00 (FUN_007A3E00, cfunc_CMauiTextSetCenteredVertically)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiTextSetCenteredVerticallyL`.
 */
int moho::cfunc_CMauiTextSetCenteredVertically(
  lua_State* const luaContext
)
{
  return cfunc_CMauiTextSetCenteredVerticallyL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A3E20 (FUN_007A3E20, func_CMauiTextSetCenteredVertically_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiText:SetCenteredVertically(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiTextSetCenteredVertically_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetCenteredVertically",
    &moho::cfunc_CMauiTextSetCenteredVertically,
    &moho::CScrLuaMetatableFactory<moho::CMauiText>::Instance(),
    "CMauiText",
    kCMauiTextSetCenteredVerticallyHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A3E80 (FUN_007A3E80, cfunc_CMauiTextSetCenteredVerticallyL)
 *
 * What it does:
 * Reads one `CMauiText` plus bool and updates vertical-centering lane.
 */
int moho::cfunc_CMauiTextSetCenteredVerticallyL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiTextSetCenteredVerticallyHelpText);

  LuaPlus::LuaObject textObject(LuaPlus::LuaStackObject(state, 1));
  CMauiText* const textControl = SCR_FromLua_CMauiText(textObject, state);

  LuaPlus::LuaStackObject centeredArg(state, 2);
  textControl->mCenteredVertically = LuaPlus::LuaStackObject::GetBoolean(&centeredArg);
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x007A3F50 (FUN_007A3F50, cfunc_CMauiTextGetStringAdvance)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiTextGetStringAdvanceL`.
 */
int moho::cfunc_CMauiTextGetStringAdvance(
  lua_State* const luaContext
)
{
  return cfunc_CMauiTextGetStringAdvanceL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A3F70 (FUN_007A3F70, func_CMauiTextGetStringAdvance_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiText:GetStringAdvance(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiTextGetStringAdvance_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetStringAdvance",
    &moho::cfunc_CMauiTextGetStringAdvance,
    &moho::CScrLuaMetatableFactory<moho::CMauiText>::Instance(),
    "CMauiText",
    kCMauiTextGetStringAdvanceHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A3FD0 (FUN_007A3FD0, cfunc_CMauiTextCMauiTextL)
 *
 * What it does:
 * Reads one `CMauiText` plus string arg and returns measured text advance
 * from the text-control font lane.
 */
int moho::cfunc_CMauiTextGetStringAdvanceL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiTextGetStringAdvanceHelpText);

  LuaPlus::LuaObject textControlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiText* const textControl = SCR_FromLua_CMauiText(textControlObject, state);

  LuaPlus::LuaStackObject textArg(state, 2);
  const char* const text = lua_tostring(state->m_state, 2);
  if (text == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&textArg, "string");
  }

  CD3DFont* const font = textControl->mFont;
  const float advance = font != nullptr ? font->GetAdvance(text, 0) : 0.0f;
  lua_pushnumber(state->m_state, advance);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x007A40E0 (FUN_007A40E0, cfunc_CMauiTextSetNewClipToWidth)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiTextSetNewClipToWidthL`.
 */
int moho::cfunc_CMauiTextSetNewClipToWidth(
  lua_State* const luaContext
)
{
  return cfunc_CMauiTextSetNewClipToWidthL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A4100 (FUN_007A4100, func_CMauiTextSetNewClipToWidth_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiText:SetNewClipToWidth(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiTextSetNewClipToWidth_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetNewClipToWidth",
    &moho::cfunc_CMauiTextSetNewClipToWidth,
    &moho::CScrLuaMetatableFactory<moho::CMauiText>::Instance(),
    "CMauiText",
    kCMauiTextSetNewClipToWidthHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A4160 (FUN_007A4160, cfunc_CMauiTextSetNewClipToWidthL)
 *
 * What it does:
 * Reads one `CMauiText` plus bool and updates clip-to-width lane.
 */
int moho::cfunc_CMauiTextSetNewClipToWidthL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiTextSetNewClipToWidthHelpText);

  LuaPlus::LuaObject textObject(LuaPlus::LuaStackObject(state, 1));
  CMauiText* const textControl = SCR_FromLua_CMauiText(textObject, state);

  LuaPlus::LuaStackObject clipArg(state, 2);
  textControl->mClipToWidth = LuaPlus::LuaStackObject::GetBoolean(&clipArg);
  lua_settop(state->m_state, 1);
  return 1;
}

int moho::cfunc_CMauiTextSetTextScale(
  lua_State* const luaContext
)
{
  return cfunc_CMauiTextSetTextScaleL(ResolveBindingState(luaContext));
}

/**
 * Engine addition: `Text:SetTextScale(scale[, pivotX, pivotY])`. A mod on the shipped game checks that the method
 * exists. Costs no new font, unlike calling SetFont with each size, so it can change every frame.
 */
moho::CScrLuaInitForm* moho::func_CMauiTextSetTextScale_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetTextScale",
    &moho::cfunc_CMauiTextSetTextScale,
    &moho::CScrLuaMetatableFactory<moho::CMauiText>::Instance(),
    "CMauiText",
    kCMauiTextSetTextScaleHelpText
  );
  return &binder;
}

int moho::cfunc_CMauiTextSetTextScaleL(
  LuaPlus::LuaState* const state
)
{
  const int argumentCount = lua_gettop(state->m_state);
  moho::SCR_ExpectExactArgs(state, argumentCount == 2 ? 2 : 4, kCMauiTextSetTextScaleHelpText);

  LuaPlus::LuaObject textObject(LuaPlus::LuaStackObject(state, 1));
  const CMauiText* const textControl = SCR_FromLua_CMauiText(textObject, state);

  STextScale scale{};
  const auto readNumber = [state](const int index) {
    LuaPlus::LuaStackObject argument(state, index);
    if (lua_type(state->m_state, index) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&argument, "number");
    }
    return static_cast<float>(lua_tonumber(state->m_state, index));
  };
  scale.mScale = readNumber(2);
  if (argumentCount == 4) {
    scale.mPivotX = readNumber(3);
    scale.mPivotY = readNumber(4);
  }
  if (!std::isfinite(scale.mScale) || !std::isfinite(scale.mPivotX) || !std::isfinite(scale.mPivotY)) {
    scale = STextScale{};
  }
  scale.mScale = (std::min)((std::max)(scale.mScale, 0.0f), kMaxTextScale);

  if (scale.mScale == 1.0f) {
    sTextScales.erase(textControl);
  } else {
    sTextScales[textControl] = scale;
  }
  lua_settop(state->m_state, 1);
  return 1;
}

int moho::cfunc_CMauiTextGetTextScale(
  lua_State* const luaContext
)
{
  return cfunc_CMauiTextGetTextScaleL(ResolveBindingState(luaContext));
}

moho::CScrLuaInitForm* moho::func_CMauiTextGetTextScale_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetTextScale",
    &moho::cfunc_CMauiTextGetTextScale,
    &moho::CScrLuaMetatableFactory<moho::CMauiText>::Instance(),
    "CMauiText",
    kCMauiTextGetTextScaleHelpText
  );
  return &binder;
}

int moho::cfunc_CMauiTextGetTextScaleL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiTextGetTextScaleHelpText);
  LuaPlus::LuaObject textObject(LuaPlus::LuaStackObject(state, 1));
  const CMauiText* const textControl = SCR_FromLua_CMauiText(textObject, state);
  const auto scaled = sTextScales.find(textControl);
  lua_pushnumber(state->m_state, scaled != sTextScales.end() ? scaled->second.mScale : 1.0f);
  (void)lua_gettop(state->m_state);
  return 1;
}

int moho::cfunc_LoadFont(
  lua_State* const luaContext
)
{
  return cfunc_LoadFontL(ResolveBindingState(luaContext));
}

/**
 * Engine addition (issue #304): `LoadFont(path)`. In the user Lua state only, never the sim's. Docs for mod authors
 * are in docs/MOD_FONTS.md.
 */
moho::CScrLuaInitForm* moho::func_LoadFont_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "LoadFont",
    &moho::cfunc_LoadFont,
    nullptr,
    "<global>",
    kLoadFontHelpText
  );
  return &binder;
}

int moho::cfunc_LoadFontL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kLoadFontHelpText);
  LuaPlus::LuaStackObject pathArg(state, 1);
  const char* const path = lua_tostring(state->m_state, 1);
  if (path == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&pathArg, "string");
    return 0;
  }

  std::string reason;
  std::string family;
  if (!ren_ModFonts) {
    gpg::Warnf("MSDF: mod font %s refused: ren_ModFonts is off", path);
  } else if (!MSDF_IsAllowedModFontPath(path, reason)) {
    gpg::Warnf("MSDF: mod font %s refused: %s", path, reason.c_str());
  } else {
    FILE_EnsureWaitHandleSet();
    FWaitHandleSet* const waitHandleSet = FILE_GetWaitHandleSet();
    fa::string mountedPath{};
    SDiskFileInfo info{};
    if (waitHandleSet != nullptr && waitHandleSet->mHandle != nullptr) {
      (void)waitHandleSet->mHandle->FindFile(&mountedPath, path, &info);
    }
    if (mountedPath.empty()) {
      gpg::Warnf("MSDF: mod font %s refused: no such file", path);
    } else if (info.mFileSize > kMsdfMaxFontBytes) {
      gpg::Warnf("MSDF: mod font %s refused: the file is over the size limit", path);
    } else {
      gpg::MemBuffer<char> fontBytes = DISK_ReadFile(mountedPath.c_str());
      if (fontBytes.mBegin == nullptr) {
        gpg::Warnf("MSDF: mod font %s refused: it can't be read", path);
      } else {
        family = MSDF_RegisterModFont(path, fontBytes.mBegin, static_cast<std::size_t>(fontBytes.mEnd - fontBytes.mBegin));
      }
    }
  }

  if (family.empty()) {
    lua_pushnil(state->m_state);
  } else {
    lua_pushstring(state->m_state, family.c_str());
  }
  return 1;
}

/**
 * Address: 0x007A29D0 (FUN_007A29D0, Moho::CMauiText::GetClass)
 *
 * What it does:
 * Returns the cached reflection descriptor for `CMauiText`, resolved via
 * RTTI on first use.
 */
gpg::RType* moho::CMauiText::GetClass() const
{
  if (!sType) {
    sType = gpg::LookupRType(typeid(CMauiText));
  }
  return sType;
}

/**
 * Address: 0x007A29F0 (FUN_007A29F0, Moho::CMauiText::GetDerivedObjectRef)
 *
 * What it does:
 * Packs `{this, GetClass()}` as a reflection reference handle.
 */
gpg::RRef moho::CMauiText::GetDerivedObjectRef()
{
  return gpg::MakeSelfRef(this);
}
