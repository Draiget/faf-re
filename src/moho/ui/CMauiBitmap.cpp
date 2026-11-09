#include "moho/ui/UiPrivate.h"
#include "moho/lua/CScrLuaObjectFactory.h"

namespace
{
  constexpr const char* kInternalCreateBitmapHelpText =
    "InternalCreateBitmap(luaobj,parent) -- for internal use by CreateBitmap()";
  constexpr const char* kCMauiBitmapSetNewTextureHelpText = "Bitmap:SetNewTexture(filename(s), border=1)";
  constexpr const char* kCMauiBitmapInternalSetSolidColorHelpText = "Bitmap:InternalSetSolidColor(color)";
  constexpr const char* kCMauiBitmapSetUVHelpText = "Bitmap:SetUV(float u0, float v0, float u1, float v1)";
  constexpr const char* kCMauiBitmapUseAlphaHitTestHelpText = "UseAlphaHitTest(bool)";
  constexpr const char* kCMauiBitmapSetTiledHelpText = "SetTiled(bool)";
  constexpr const char* kCMauiBitmapLoopHelpText = "Loop(bool)";
  constexpr const char* kCMauiBitmapPlayHelpText = "Play()";
  constexpr const char* kCMauiBitmapStopHelpText = "Stop()";
  constexpr const char* kCMauiBitmapSetFrameHelpText = "SetFrame(int)";
  constexpr const char* kCMauiBitmapGetFrameHelpText = "int GetFrame()";
  constexpr const char* kCMauiBitmapSetFrameRateHelpText = "CMauiBitmap:SetFrameRate(frameRate)";
  constexpr const char* kCMauiBitmapSetForwardPatternHelpText = "SetForwardPattern()";
  constexpr const char* kCMauiBitmapSetBackwardPatternHelpText = "SetBackwardPattern()";
  constexpr const char* kCMauiBitmapSetPingPongPatternHelpText = "SetPingPongPattern()";
  constexpr const char* kCMauiBitmapSetLoopPingPongPatternHelpText = "SetLoopPingPongPattern()";
  constexpr const char* kCMauiBitmapSetFramePatternHelpText = "SetFramePattern(pattern)";
  constexpr const char* kCMauiBitmapShareTexturesHelpText =
    "ShareTextures(bitmap) - allows two bitmaps to use the same textures";

  /**
   * Address: 0x00782F80 (FUN_00782F80)
   *
   * What it does:
   * Appends one texture batch entry to the bitmap's legacy vector lane.
   */
  void AppendBitmapTextureBatch(
    fa::vector<boost::shared_ptr<moho::CD3DBatchTexture>>& textureBatches,
    const boost::shared_ptr<moho::CD3DBatchTexture>& texture
  )
  {
    textureBatches.push_back(texture);
  }
}

gpg::RType* moho::CMauiBitmap::sType = nullptr;

/**
 * Address: 0x00780ED0 (FUN_00780ED0, cfunc_CMauiBitmapSetNewTexture)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiBitmapSetNewTextureL`.
 */
int moho::cfunc_CMauiBitmapSetNewTexture(
  lua_State* const luaContext
)
{
  return cfunc_CMauiBitmapSetNewTextureL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00780EF0 (FUN_00780EF0, func_CMauiBitmapSetNewTexture_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:SetNewTexture(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapSetNewTexture_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetNewTexture",
    &moho::cfunc_CMauiBitmapSetNewTexture,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapSetNewTextureHelpText
  );
  return &binder;
}

/**
 * Address: 0x00780F50 (FUN_00780F50, cfunc_CMauiBitmapSetNewTextureL)
 *
 * What it does:
 * Rebuilds one bitmap texture-batch sequence from one filename or filename
 * table and reapplies default forward frame pattern.
 */
int moho::cfunc_CMauiBitmapSetNewTextureL(
  LuaPlus::LuaState* const state
)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount < 2 || argumentCount > 3) {
    LuaPlus::LuaState::Error(
      state, "%s\n  expected between %d and %d args, but got %d", kCMauiBitmapSetNewTextureHelpText, 2, 3, argumentCount
    );
  }

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);

  bitmap->mTextureBatches.clear();
  bitmap->SetFrame(0);

  int border = 1;
  if (argumentCount >= 3) {
    LuaPlus::LuaStackObject borderArg(state, 3);
    if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&borderArg, "integer");
    }
    border = static_cast<int>(lua_tonumber(state->m_state, 3));
  }
  const auto borderLane = static_cast<std::uint32_t>(border);

  if (lua_isstring(state->m_state, 2) != 0) {
    LuaPlus::LuaStackObject textureArg(state, 2);
    const char* texturePath = lua_tostring(state->m_state, 2);
    if (texturePath == nullptr) {
      LuaPlus::LuaStackObject::TypeError(&textureArg, "string");
      texturePath = "";
    }

    boost::shared_ptr<CD3DBatchTexture> texture = CD3DBatchTexture::FromFile(texturePath, borderLane);
    if (texture) {
      bitmap->SetTexture(texture);
    } else {
      bitmap->SetTexture(CD3DBatchTexture::FromSolidColor(0xFFAAAA00u));
    }

    bitmap->SetDebugName(gpg::STR_Printf("Bitmap file = %s", texturePath));
  } else if (lua_type(state->m_state, 2) == LUA_TTABLE) {
    LuaPlus::LuaObject frameTableObject(LuaPlus::LuaStackObject(state, 2));
    const int frameCount = frameTableObject.GetCount();
    for (int frameIndex = 1; frameIndex <= frameCount; ++frameIndex) {
      LuaPlus::LuaObject frameObject = frameTableObject[frameIndex];
      const char* texturePath = frameObject.GetString();
      const char* const pathText = texturePath != nullptr ? texturePath : "";

      boost::shared_ptr<CD3DBatchTexture> texture = CD3DBatchTexture::FromFile(pathText, borderLane);
      if (texture) {
        bitmap->SetTexture(texture);
      } else {
        bitmap->SetTexture(CD3DBatchTexture::FromSolidColor(0xFFAAAA00u));
      }

      const fa::string frameText = gpg::STR_Printf("Frame %d = %s\n", frameIndex, pathText);
      fa::string debugName = bitmap->GetDebugName();
      debugName += frameText;
      bitmap->SetDebugName(debugName);
    }
  }

  bitmap->SetForwardPattern();
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00781440 (FUN_00781440, cfunc_CMauiBitmapInternalSetSolidColor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiBitmapInternalSetSolidColorL`.
 */
int moho::cfunc_CMauiBitmapInternalSetSolidColor(
  lua_State* const luaContext
)
{
  return cfunc_CMauiBitmapInternalSetSolidColorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00781460 (FUN_00781460, func_CMauiBitmapInternalSetSolidColor_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:InternalSetSolidColor(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapInternalSetSolidColor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "InternalSetSolidColor",
    &moho::cfunc_CMauiBitmapInternalSetSolidColor,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapInternalSetSolidColorHelpText
  );
  return &binder;
}

/**
 * Address: 0x007814C0 (FUN_007814C0, cfunc_CMauiBitmapInternalSetSolidColorL)
 *
 * What it does:
 * Resolves one bitmap plus one color argument, rebuilds one solid-color
 * texture frame, and refreshes debug name text.
 */
int moho::cfunc_CMauiBitmapInternalSetSolidColorL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiBitmapInternalSetSolidColorHelpText);

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);

  bitmap->mTextureBatches.clear();
  bitmap->SetFrame(0);

  LuaPlus::LuaObject colorObject(LuaPlus::LuaStackObject(state, 2));
  const std::uint32_t rgba = SCR_DecodeColor(state, colorObject);
  const boost::shared_ptr<CD3DBatchTexture> solidTexture = CD3DBatchTexture::FromSolidColor(rgba);
  bitmap->SetTexture(solidTexture);
  bitmap->SetForwardPattern();

  LuaPlus::LuaStackObject colorTextArg(state, 2);
  const char* colorText = lua_tostring(state->m_state, 2);
  if (colorText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&colorTextArg, "string");
    colorText = "";
  }

  fa::string debugName("Bitmap is solid color ");
  debugName += colorText;
  bitmap->SetDebugName(debugName);

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00781690 (FUN_00781690, cfunc_CMauiBitmapSetUV)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiBitmapSetUVL`.
 */
int moho::cfunc_CMauiBitmapSetUV(
  lua_State* const luaContext
)
{
  return cfunc_CMauiBitmapSetUVL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007816B0 (FUN_007816B0, func_CMauiBitmapSetUV_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:SetUV(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapSetUV_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetUV",
    &moho::cfunc_CMauiBitmapSetUV,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapSetUVHelpText
  );
  return &binder;
}

/**
 * Address: 0x0077FE80 (FUN_0077FE80)
 *
 * What it does:
 * Clamps one bitmap UV quad `(u0,v0,u1,v1)` to `[0,1]` and writes the
 * runtime UV lanes.
 */
[[maybe_unused]] static moho::CMauiBitmap* func_SetBitmapUvClamped(
  moho::CMauiBitmap* const bitmap,
  const float u0,
  const float v0,
  const float u1,
  const float v1
) noexcept
{
  const auto clamp01 = [](const float value) noexcept -> float {
    if (value >= 1.0f) {
      return 1.0f;
    }
    if (value < 0.0f) {
      return 0.0f;
    }
    return value;
  };

  bitmap->mU0 = clamp01(u0);
  bitmap->mV0 = clamp01(v0);
  bitmap->mU1 = clamp01(u1);
  bitmap->mV1 = clamp01(v1);
  return bitmap;
}

/**
 * Address: 0x00781710 (FUN_00781710, cfunc_CMauiBitmapSetUVL)
 *
 * What it does:
 * Reads one bitmap plus `(u0,v0,u1,v1)` lanes, clamps each to `[0,1]`, and
 * updates UV runtime lanes.
 */
int moho::cfunc_CMauiBitmapSetUVL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 5, kCMauiBitmapSetUVHelpText);

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);

  LuaPlus::LuaStackObject v1Arg(state, 5);
  if (lua_type(state->m_state, 5) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&v1Arg, "number");
  }
  float v1 = static_cast<float>(lua_tonumber(state->m_state, 5));

  LuaPlus::LuaStackObject u1Arg(state, 4);
  if (lua_type(state->m_state, 4) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&u1Arg, "number");
  }
  float u1 = static_cast<float>(lua_tonumber(state->m_state, 4));

  LuaPlus::LuaStackObject v0Arg(state, 3);
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&v0Arg, "number");
  }
  float v0 = static_cast<float>(lua_tonumber(state->m_state, 3));

  LuaPlus::LuaStackObject u0Arg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&u0Arg, "number");
  }
  float u0 = static_cast<float>(lua_tonumber(state->m_state, 2));

  (void)func_SetBitmapUvClamped(bitmap, u0, v0, u1, v1);

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00781950 (FUN_00781950, cfunc_CMauiBitmapUseAlphaHitTest)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiBitmapUseAlphaHitTestL`.
 */
int moho::cfunc_CMauiBitmapUseAlphaHitTest(
  lua_State* const luaContext
)
{
  return cfunc_CMauiBitmapUseAlphaHitTestL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00781970 (FUN_00781970, func_CMauiBitmapUseAlphaHitTest_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:UseAlphaHitTest(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapUseAlphaHitTest_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "UseAlphaHitTest",
    &moho::cfunc_CMauiBitmapUseAlphaHitTest,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapUseAlphaHitTestHelpText
  );
  return &binder;
}

/**
 * Address: 0x007819D0 (FUN_007819D0, cfunc_CMauiBitmapUseAlphaHitTestL)
 *
 * What it does:
 * Reads one `CMauiBitmap` plus one boolean lane and updates alpha-hit-test
 * state.
 */
int moho::cfunc_CMauiBitmapUseAlphaHitTestL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiBitmapUseAlphaHitTestHelpText);

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);

  LuaPlus::LuaStackObject enabledArg(state, 2);
  (void)SetBitmapAlphaHitTestEnabled(bitmap, enabledArg.GetBoolean());

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00781AA0 (FUN_00781AA0, cfunc_CMauiBitmapSetTiled)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiBitmapSetTiledL`.
 */
int moho::cfunc_CMauiBitmapSetTiled(
  lua_State* const luaContext
)
{
  return cfunc_CMauiBitmapSetTiledL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00781AC0 (FUN_00781AC0, func_CMauiBitmapSetTiled_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:SetTiled(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapSetTiled_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetTiled",
    &moho::cfunc_CMauiBitmapSetTiled,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapSetTiledHelpText
  );
  return &binder;
}

/**
 * Address: 0x00781B20 (FUN_00781B20, cfunc_CMauiBitmapSetTiledL)
 *
 * What it does:
 * Reads one `CMauiBitmap` plus one boolean lane and updates tiled-render
 * state.
 */
int moho::cfunc_CMauiBitmapSetTiledL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiBitmapSetTiledHelpText);

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);

  LuaPlus::LuaStackObject tiledArg(state, 2);
  (void)SetBitmapTiledEnabled(bitmap, tiledArg.GetBoolean());

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00781BF0 (FUN_00781BF0, cfunc_CMauiBitmapLoop)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiBitmapLoopL`.
 */
int moho::cfunc_CMauiBitmapLoop(
  lua_State* const luaContext
)
{
  return cfunc_CMauiBitmapLoopL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00781C10 (FUN_00781C10, func_CMauiBitmapLoop_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:Loop(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapLoop_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "Loop",
    &moho::cfunc_CMauiBitmapLoop,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapLoopHelpText
  );
  return &binder;
}

/**
 * Address: 0x00781C70 (FUN_00781C70, cfunc_CMauiBitmapLoopL)
 *
 * What it does:
 * Reads one `CMauiBitmap` plus one boolean lane and updates looping state.
 */
int moho::cfunc_CMauiBitmapLoopL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiBitmapLoopHelpText);

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);

  LuaPlus::LuaStackObject loopArg(state, 2);
  (void)SetBitmapLoopEnabled(bitmap, loopArg.GetBoolean());

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00781D40 (FUN_00781D40, cfunc_CMauiBitmapPlay)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiBitmapPlayL`.
 */
int moho::cfunc_CMauiBitmapPlay(
  lua_State* const luaContext
)
{
  return cfunc_CMauiBitmapPlayL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00781D60 (FUN_00781D60, func_CMauiBitmapPlay_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:Play()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapPlay_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "Play",
    &moho::cfunc_CMauiBitmapPlay,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapPlayHelpText
  );
  return &binder;
}

/**
 * Address: 0x00781DC0 (FUN_00781DC0, cfunc_CMauiBitmapPlayL)
 *
 * What it does:
 * Starts animated playback when this bitmap has more than one texture batch.
 */
int moho::cfunc_CMauiBitmapPlayL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiBitmapPlayHelpText);

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);

  (void)EnableBitmapAnimationIfMultipleTextures(bitmap);

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00781EA0 (FUN_00781EA0, cfunc_CMauiBitmapStop)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiBitmapStopL`.
 */
int moho::cfunc_CMauiBitmapStop(
  lua_State* const luaContext
)
{
  return cfunc_CMauiBitmapStopL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00781EC0 (FUN_00781EC0, func_CMauiBitmapStop_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:Stop()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapStop_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "Stop",
    &moho::cfunc_CMauiBitmapStop,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapStopHelpText
  );
  return &binder;
}

/**
 * Address: 0x00781F20 (FUN_00781F20, cfunc_CMauiBitmapStopL)
 *
 * What it does:
 * Stops animated playback and dispatches `OnAnimationStopped` when this
 * bitmap has active multi-frame texture state.
 */
int moho::cfunc_CMauiBitmapStopL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiBitmapStopHelpText);

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);

  bitmap->StopAnimationPlayback();

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00782000 (FUN_00782000, cfunc_CMauiBitmapSetFrame)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiBitmapSetFrameL`.
 */
int moho::cfunc_CMauiBitmapSetFrame(
  lua_State* const luaContext
)
{
  return cfunc_CMauiBitmapSetFrameL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00782020 (FUN_00782020, func_CMauiBitmapSetFrame_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:SetFrame(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapSetFrame_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetFrame",
    &moho::cfunc_CMauiBitmapSetFrame,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapSetFrameHelpText
  );
  return &binder;
}

/**
 * Address: 0x00782080 (FUN_00782080, cfunc_CMauiBitmapSetFrameL)
 *
 * What it does:
 * Reads one `CMauiBitmap` plus frame index and applies clamped frame
 * selection.
 */
int moho::cfunc_CMauiBitmapSetFrameL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiBitmapSetFrameHelpText);

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);

  LuaPlus::LuaStackObject frameArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&frameArg, "integer");
  }

  const int frameIndex = static_cast<int>(lua_tonumber(state->m_state, 2));
  bitmap->SetFrame(frameIndex);

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00782180 (FUN_00782180, cfunc_CMauiBitmapGetFrame)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiBitmapGetFrameL`.
 */
int moho::cfunc_CMauiBitmapGetFrame(
  lua_State* const luaContext
)
{
  return cfunc_CMauiBitmapGetFrameL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007821A0 (FUN_007821A0, func_CMauiBitmapGetFrame_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:GetFrame()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapGetFrame_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetFrame",
    &moho::cfunc_CMauiBitmapGetFrame,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapGetFrameHelpText
  );
  return &binder;
}

/**
 * Address: 0x00782200 (FUN_00782200, cfunc_CMauiBitmapGetFrameL)
 *
 * What it does:
 * Reads one `CMauiBitmap` and pushes current frame index lane.
 */
int moho::cfunc_CMauiBitmapGetFrameL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiBitmapGetFrameHelpText);

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);
  const int frameIndex = ReadBitmapCurrentFrame(bitmap);

  lua_pushnumber(state->m_state, static_cast<float>(frameIndex));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00782420 (FUN_00782420, cfunc_CMauiBitmapSetFrameRate)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiBitmapSetFrameRateL`.
 */
int moho::cfunc_CMauiBitmapSetFrameRate(
  lua_State* const luaContext
)
{
  return cfunc_CMauiBitmapSetFrameRateL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00782440 (FUN_00782440, func_CMauiBitmapSetFrameRate_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:SetFrameRate(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapSetFrameRate_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetFrameRate",
    &moho::cfunc_CMauiBitmapSetFrameRate,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapSetFrameRateHelpText
  );
  return &binder;
}

/**
 * Address: 0x00780250 (FUN_00780250)
 *
 * What it does:
 * Updates one bitmap frame-duration lane from `frameRate` as `1.0f / fps`.
 */
[[maybe_unused]] static moho::CMauiBitmap* func_SetBitmapFrameRate(
  moho::CMauiBitmap* const bitmap,
  const float frameRate
) noexcept
{
  bitmap->mFrameDurationSeconds = 1.0f / frameRate;
  return bitmap;
}

/**
 * Address: 0x007824A0 (FUN_007824A0, cfunc_CMauiBitmapSetFrameRateL)
 *
 * What it does:
 * Reads one `CMauiBitmap` plus numeric frame-rate and updates its
 * frame-duration lane (`1.0 / fps`).
 */
int moho::cfunc_CMauiBitmapSetFrameRateL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiBitmapSetFrameRateHelpText);

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);

  LuaPlus::LuaStackObject frameRateArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&frameRateArg, "number");
  }

  const float frameRate = static_cast<float>(lua_tonumber(state->m_state, 2));
  (void)func_SetBitmapFrameRate(bitmap, frameRate);

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x007825A0 (FUN_007825A0, cfunc_CMauiBitmapSetForwardPattern)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiBitmapSetForwardPatternL`.
 */
int moho::cfunc_CMauiBitmapSetForwardPattern(
  lua_State* const luaContext
)
{
  return cfunc_CMauiBitmapSetForwardPatternL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007825C0 (FUN_007825C0, func_CMauiBitmapSetForwardPattern_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:SetForwardPattern()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapSetForwardPattern_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetForwardPattern",
    &moho::cfunc_CMauiBitmapSetForwardPattern,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapSetForwardPatternHelpText
  );
  return &binder;
}

/**
 * Address: 0x00782620 (FUN_00782620, cfunc_CMauiBitmapSetForwardPatternL)
 *
 * What it does:
 * Resolves one bitmap and rebuilds its forward frame pattern.
 */
int moho::cfunc_CMauiBitmapSetForwardPatternL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiBitmapSetForwardPatternHelpText);

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);
  bitmap->SetForwardPattern();

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x007826E0 (FUN_007826E0, cfunc_CMauiBitmapSetBackwardPattern)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiBitmapSetBackwardPatternL`.
 */
int moho::cfunc_CMauiBitmapSetBackwardPattern(
  lua_State* const luaContext
)
{
  return cfunc_CMauiBitmapSetBackwardPatternL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00782700 (FUN_00782700, func_CMauiBitmapSetBackwardPattern_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:SetBackwardPattern()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapSetBackwardPattern_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetBackwardPattern",
    &moho::cfunc_CMauiBitmapSetBackwardPattern,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapSetBackwardPatternHelpText
  );
  return &binder;
}

/**
 * Address: 0x00782760 (FUN_00782760, cfunc_CMauiBitmapSetBackwardPatternL)
 *
 * What it does:
 * Resolves one bitmap and rebuilds its backward frame pattern.
 */
int moho::cfunc_CMauiBitmapSetBackwardPatternL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiBitmapSetBackwardPatternHelpText);

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);
  bitmap->SetBackwardPattern();

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00782820 (FUN_00782820, cfunc_CMauiBitmapSetPingPongPattern)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiBitmapSetPingPongPatternL`.
 */
int moho::cfunc_CMauiBitmapSetPingPongPattern(
  lua_State* const luaContext
)
{
  return cfunc_CMauiBitmapSetPingPongPatternL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00782840 (FUN_00782840, func_CMauiBitmapSetPingPongPattern_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:SetPingPongPattern()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapSetPingPongPattern_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetPingPongPattern",
    &moho::cfunc_CMauiBitmapSetPingPongPattern,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapSetPingPongPatternHelpText
  );
  return &binder;
}

/**
 * Address: 0x007828A0 (FUN_007828A0, cfunc_CMauiBitmapSetPingPongPatternL)
 *
 * What it does:
 * Resolves one bitmap and rebuilds its ping-pong frame pattern.
 */
int moho::cfunc_CMauiBitmapSetPingPongPatternL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiBitmapSetPingPongPatternHelpText);

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);
  bitmap->SetPingPongPattern();

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00782960 (FUN_00782960, cfunc_CMauiBitmapSetLoopPingPongPattern)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiBitmapSetLoopPingPongPatternL`.
 */
int moho::cfunc_CMauiBitmapSetLoopPingPongPattern(
  lua_State* const luaContext
)
{
  return cfunc_CMauiBitmapSetLoopPingPongPatternL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00782980 (FUN_00782980, func_CMauiBitmapSetLoopPingPongPattern_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:SetLoopPingPongPattern()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapSetLoopPingPongPattern_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetLoopPingPongPattern",
    &moho::cfunc_CMauiBitmapSetLoopPingPongPattern,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapSetLoopPingPongPatternHelpText
  );
  return &binder;
}

/**
 * Address: 0x007829E0 (FUN_007829E0, cfunc_CMauiBitmapSetLoopPingPongPatternL)
 *
 * What it does:
 * Resolves one bitmap and rebuilds its loop ping-pong frame pattern.
 */
int moho::cfunc_CMauiBitmapSetLoopPingPongPatternL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiBitmapSetLoopPingPongPatternHelpText);

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);
  bitmap->SetLoopPingPongPattern();

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00782AA0 (FUN_00782AA0, cfunc_CMauiBitmapSetFramePattern)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiBitmapSetFramePatternL`.
 */
int moho::cfunc_CMauiBitmapSetFramePattern(
  lua_State* const luaContext
)
{
  return cfunc_CMauiBitmapSetFramePatternL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00782AC0 (FUN_00782AC0, func_CMauiBitmapSetFramePattern_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:SetFramePattern(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapSetFramePattern_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetFramePattern",
    &moho::cfunc_CMauiBitmapSetFramePattern,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapSetFramePatternHelpText
  );
  return &binder;
}

/**
 * Address: 0x00782B20 (FUN_00782B20, cfunc_CMauiBitmapSetFramePatternL)
 *
 * What it does:
 * Resolves one bitmap plus frame-index table and rebuilds frame-pattern lanes.
 */
int moho::cfunc_CMauiBitmapSetFramePatternL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiBitmapSetFramePatternHelpText);

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);

  if (lua_type(state->m_state, 2) == LUA_TTABLE) {
    LuaPlus::LuaObject frameTableObject(LuaPlus::LuaStackObject(state, 2));
    const int frameCount = frameTableObject.GetCount();

    fa::vector<std::int32_t> framePattern{};
    if (frameCount > 0) {
      framePattern.reserve(static_cast<std::size_t>(frameCount));
    }

    for (int frameIndex = 1; frameIndex <= frameCount; ++frameIndex) {
      LuaPlus::LuaObject frameObject = frameTableObject[frameIndex];
      framePattern.push_back(frameObject.GetInteger());
    }

    bitmap->SetFramePattern(framePattern);
  } else {
    gpg::Warnf("Bitmap:SetFramePattern requires an array of integers!");
  }

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00782CE0 (FUN_00782CE0, cfunc_CMauiBitmapShareTextures)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiBitmapShareTexturesL`.
 */
int moho::cfunc_CMauiBitmapShareTextures(
  lua_State* const luaContext
)
{
  return cfunc_CMauiBitmapShareTexturesL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00782D00 (FUN_00782D00, func_CMauiBitmapShareTextures_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:ShareTextures(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapShareTextures_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "ShareTextures",
    &moho::cfunc_CMauiBitmapShareTextures,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapShareTexturesHelpText
  );
  return &binder;
}

/**
 * Address: 0x00782D60 (FUN_00782D60, cfunc_CMauiBitmapShareTexturesL)
 *
 * What it does:
 * Reads two `CMauiBitmap` controls and shares texture-batch lanes from source
 * into destination bitmap runtime state.
 */
int moho::cfunc_CMauiBitmapShareTexturesL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiBitmapShareTexturesHelpText);

  LuaPlus::LuaObject destinationObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const destinationBitmap = SCR_FromLua_CMauiBitmap(destinationObject, state);

  LuaPlus::LuaObject sourceObject(LuaPlus::LuaStackObject(state, 2));
  CMauiBitmap* const sourceBitmap = SCR_FromLua_CMauiBitmap(sourceObject, state);

  destinationBitmap->ShareTextures(sourceBitmap);
  lua_settop(state->m_state, 1);
  return 1;
}

// --- FAF community binary-patch addition: Bitmap:SetColorMask. No `Address:`
// block -- this method never existed in the original 2007 binary; it ships only
// via FA-Binary-Patches (section/MauiBitmap.cpp, `UIRegFuncT<0x00E37C14,
// 0x00F8D7DC>` on class "CMauiBitmap").

int moho::cfunc_CMauiBitmapSetColorMask(
  lua_State* const luaContext
)
{
  return cfunc_CMauiBitmapSetColorMaskL(ResolveBindingState(luaContext));
}

moho::CScrLuaInitForm* moho::func_CMauiBitmapSetColorMask_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetColorMask",
    &moho::cfunc_CMauiBitmapSetColorMask,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    "Bitmap:SetColorMask(color)"
  );
  return &binder;
}

int moho::cfunc_CMauiBitmapSetColorMaskL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, "SetColorMask");

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);
  if (bitmap == nullptr) {
    return 0;
  }

  // The patch hands `lua_tostring` straight to TryConvertToColor (0x004B2B90); a value
  // that is not a string reports as an unknown colour here instead of reading null.
  const char* const colorText = lua_tostring(state->m_state, 2);
  std::uint32_t color = 0u;
  if (colorText == nullptr || !SCR_ParseColor(colorText, &color)) {
    luaL_error(state->m_state, "Unknown color: %s", colorText != nullptr ? colorText : "nil");
  }

  // The colour replaces the vertex colour's RGB; its alpha (SetAlpha) stays.
  bitmap->mVertexAlpha = (bitmap->mVertexAlpha & 0xFF000000u) | (color & 0x00FFFFFFu);
  return 0;
}

/**
 * Address: 0x00780D20 (FUN_00780D20, cfunc_InternalCreateBitmap)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_InternalCreateBitmapL`.
 */
int moho::cfunc_InternalCreateBitmap(
  lua_State* const luaContext
)
{
  return cfunc_InternalCreateBitmapL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00780D40 (FUN_00780D40, func_InternalCreateBitmap_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `InternalCreateBitmap(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_InternalCreateBitmap_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "InternalCreateBitmap",
    &moho::cfunc_InternalCreateBitmap,
    nullptr,
    "<global>",
    kInternalCreateBitmapHelpText
  );
  return &binder;
}

/**
 * Address: 0x00780DA0 (FUN_00780DA0, cfunc_InternalCreateBitmapL)
 *
 * What it does:
 * Reads `(luaobj,parent)`, constructs one `CMauiBitmap`, dispatches `OnInit`,
 * and pushes the created control object.
 */
int moho::cfunc_InternalCreateBitmapL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kInternalCreateBitmapHelpText);

  LuaPlus::LuaObject parentObject(LuaPlus::LuaStackObject(state, 2));
  CMauiControl* const parentControl = SCR_FromLua_CMauiControl(parentObject, state);

  LuaPlus::LuaObject luaObject(LuaPlus::LuaStackObject(state, 1));
  // Binary: `operator new(0x18C)`. See cfunc_InternalCreateFrameL for why the
  // real object size has to be spelled out here.
  auto* const bitmap = AllocateZeroedUiObject<CMauiBitmap>(0x18Cu);
  new (bitmap) CMauiBitmap(&luaObject, parentControl);
  bitmap->DoInit();
  bitmap->mLuaObj.PushStack(state);
  return 1;
}
namespace
{
  [[nodiscard]] std::int32_t GetBitmapTextureBatchCount(
    const moho::CMauiBitmap* const bitmap
  ) noexcept
  {
    const boost::shared_ptr<moho::CD3DBatchTexture>* const textureStart = bitmap->mTextureBatches.begin();
    return textureStart != nullptr ? static_cast<std::int32_t>(bitmap->mTextureBatches.end() - textureStart) : 0;
  }

  /**
   * Address: 0x0077F7F0 (FUN_0077F7F0)
   *
   * What it does:
   * Stores one alpha-hit-test boolean lane into one bitmap runtime view.
   */
  [[maybe_unused]] moho::CMauiBitmap* SetBitmapAlphaHitTestEnabled(
    moho::CMauiBitmap* const bitmap,
    const bool enabled
  ) noexcept
  {
    bitmap->mUseAlphaHitTest = enabled;
    return bitmap;
  }

  /**
   * Address: 0x0077F7E0 (FUN_0077F7E0)
   *
   * What it does:
   * Stores one tiled-render boolean lane into one bitmap runtime view.
   */
  [[maybe_unused]] moho::CMauiBitmap* SetBitmapTiledEnabled(
    moho::CMauiBitmap* const bitmap,
    const bool enabled
  ) noexcept
  {
    bitmap->mIsTiled = enabled;
    return bitmap;
  }

  /**
   * Address: 0x00780100 (FUN_00780100)
   *
   * What it does:
   * Stores one loop-enabled boolean lane into one bitmap runtime view.
   */
  [[maybe_unused]] moho::CMauiBitmap* SetBitmapLoopEnabled(
    moho::CMauiBitmap* const bitmap,
    const bool enabled
  ) noexcept
  {
    bitmap->mDoLoop = enabled;
    return bitmap;
  }

  /**
   * Address: 0x00780220 (FUN_00780220)
   *
   * What it does:
   * Reads one current-frame index lane from one bitmap runtime view.
   */
  [[maybe_unused]] std::int32_t ReadBitmapCurrentFrame(
    const moho::CMauiBitmap* const bitmap
  ) noexcept
  {
    return bitmap->mCurrentFrame;
  }

  /**
   * Address: 0x00780090 (FUN_00780090)
   *
   * What it does:
   * Enables bitmap animation/frame updates when there are at least two queued
   * textures; returns remaining texture-slot count.
   */
  [[maybe_unused]] std::uint32_t EnableBitmapAnimationIfMultipleTextures(
    moho::CMauiBitmap* const bitmap
  ) noexcept
  {
    const auto* const batchCursor = bitmap->mTextureBatches.end();
    if (batchCursor == nullptr) {
      return 0u;
    }

    const std::uint32_t remainingSlots =
      static_cast<std::uint32_t>(bitmap->mTextureBatches.capacity() - bitmap->mTextureBatches.size());
    if (remainingSlots > 1u) {
      bitmap->mIsPlaying = true;
      bitmap->mNeedsFrameUpdate = true;
    }
    return remainingSlots;
  }
}


/**
 * Address: 0x0077F950 (FUN_0077F950, Moho::CMauiBitmap::CMauiBitmap)
 *
 * What it does:
 * Constructs one bitmap control from Lua object + parent, initializes texture
 * sequence/state lanes, and binds bitmap width/height lazy-vars into Lua.
 */
moho::CMauiBitmap::CMauiBitmap(
  LuaPlus::LuaObject* const luaObject,
  CMauiControl* const parent
)
  : CMauiControl(luaObject, parent, "Bitmap")
  , mBitmapWidthLV(LuaStateOf(luaObject))
  , mBitmapHeightLV(LuaStateOf(luaObject))
{
  mU1 = 1.0f;
  mV1 = 1.0f;
  mU0 = 0.0f;
  mV0 = 0.0f;
  mHitMask = nullptr;
  mUseAlphaHitTest = false;
  mIsTiled = false;
  mFrameDurationSeconds = 1.0f / 12.0f;
  mIsPlaying = false;
  mDoLoop = false;
  mCurrentFrame = 0;
  mCurrentFrameTimeSeconds = 0.0f;

  LuaPlus::LuaObject& controlLuaObject = mLuaObj;
  controlLuaObject.SetObject("BitmapWidth", &mBitmapWidthLV);
  controlLuaObject.SetObject("BitmapHeight", &mBitmapHeightLV);
}

/**
 * Address: 0x0077FBF0 (FUN_0077FBF0, Moho::CMauiBitmap::~CMauiBitmap body)
 * Deleting thunk: 0x0077FAA0 (FUN_0077FAA0, Moho::CMauiBitmap::dtr)
 *
 * What it does:
 * Deletes the hit mask (0x0077FC1A..0x0077FC36). The rest is member
 * destruction - the frame pattern (0x0077FC3C), both lazy vars
 * (0x0077FC6C/0x0077FC7C) and the texture batches (0x0077FC85) - before
 * `~CMauiControl`.
 */
moho::CMauiBitmap::~CMauiBitmap()
{
  delete mHitMask;
  mHitMask = nullptr;
}

/**
 * Address: 0x0077FF70 (FUN_0077FF70, Moho::CMauiBitmap::HitTest)
 *
 * What it does:
 * Applies base bounds hit-testing first, then uses packed hit-mask lanes when
 * present; otherwise optionally checks texture alpha at the local pixel.
 */
bool moho::CMauiBitmap::HitTest(
  const float x,
  const float y
)
{
  const bool baseHit = CMauiControl::HitTest(x, y);
  if (!baseHit) {
    return false;
  }

  const float localX = x - CScriptLazyVar_float::GetValue(&mLeftLV);
  const float localY = y - CScriptLazyVar_float::GetValue(&mTopLV);

  const gpg::BitArray2D* const hitMask = mHitMask;
  if (hitMask != nullptr) {
    const int sampleX = static_cast<int>(localX);
    const int sampleY = static_cast<int>(localY);
    const std::uint32_t bitMask = 1u << (static_cast<std::uint32_t>(sampleY) & 0x1Fu);
    const int wordRow = static_cast<int>(static_cast<std::uint32_t>(sampleY) >> 5u);
    const int wordIndex = sampleX + (hitMask->width * wordRow);
    return (hitMask->ptr[wordIndex] & static_cast<std::int32_t>(bitMask)) != 0;
  }

  if (!mUseAlphaHitTest) {
    return baseHit;
  }

  const std::int32_t* const frameStart = mFrames.begin();
  const boost::shared_ptr<CD3DBatchTexture>* const textureStart = mTextureBatches.begin();
  const std::int32_t frameTextureIndex = frameStart[mCurrentFrame];
  const boost::shared_ptr<CD3DBatchTexture>& texture = textureStart[frameTextureIndex];
  if (!texture) {
    return baseHit;
  }

  const std::int32_t pixelX = static_cast<std::int32_t>(localX);
  const std::int32_t pixelY = static_cast<std::int32_t>(localY);
  return texture->GetAlphaAt(static_cast<std::uint32_t>(pixelX), static_cast<std::uint32_t>(pixelY)) != 0u;
}

/**
 * Address: 0x00780850 (FUN_00780850, Moho::CMauiBitmap::Draw)
 *
 * IDA signature:
 * void __thiscall Moho::CMauiBitmap::Draw(CMauiBitmap* this, CD3DPrimBatcher* primBatcher);
 *
 * What it does:
 * Renders the current animation frame's texture batch over the control bounds,
 * as a tiled quad when tiling is enabled or a UV-clipped quad otherwise. No-op
 * when no frames/textures are bound. Occupies the CMauiControl::DoRender vtable
 * slot; drawMask is unused.
 */
void moho::CMauiBitmap::DoRender(
  CD3DPrimBatcher* const primBatcher,
  const std::int32_t drawMask
)
{
  (void)drawMask;

  if (mFrames.empty() || mTextureBatches.empty()) {
    return;
  }

  const std::int32_t frameIndex = mFrames[mCurrentFrame];
  if (!mTextureBatches[frameIndex]) {
    return;
  }

  const float bottom = CScriptLazyVar_float::GetValue(&mBottomLV);
  const float right = CScriptLazyVar_float::GetValue(&mRightLV);
  const float top = CScriptLazyVar_float::GetValue(&mTopLV);
  const float left = CScriptLazyVar_float::GetValue(&mLeftLV);

  gpg::Rect2f destRect;
  destRect.x0 = left;
  destRect.z0 = top;
  destRect.x1 = right;
  destRect.z1 = bottom;

  const boost::shared_ptr<CD3DBatchTexture> texture = mTextureBatches[frameIndex];
  primBatcher->SetTexture(texture);

  const std::uint32_t vertexColor = mVertexAlpha;

  if (mIsTiled) {
    gpg::Rect2f tileRect;
    tileRect.x0 = 0.0f;
    tileRect.z0 = 0.0f;
    tileRect.x1 = (right - left) / static_cast<float>(texture->mWidth);
    tileRect.z1 = (bottom - top) / static_cast<float>(texture->mHeight);
    DRAW_TiledQuad(primBatcher, destRect, tileRect, destRect, vertexColor);
  } else {
    gpg::Rect2f uvRect;
    uvRect.x0 = mU0;
    uvRect.z0 = mV0;
    uvRect.x1 = mU1;
    uvRect.z1 = mV1;
    DRAW_ClippedQuad(primBatcher, destRect, uvRect, destRect, vertexColor);
  }
}

/**
 * Address: 0x0077FCF0 (FUN_0077FCF0, Moho::CMauiBitmap::ShareTextures)
 *
 * What it does:
 * Copies texture-batch lanes from `sourceBitmap` into this bitmap and refreshes
 * bitmap width/height lazy-vars from frame `0`.
 */
void moho::CMauiBitmap::ShareTextures(
  CMauiBitmap* const sourceBitmap
)
{

  mTextureBatches = sourceBitmap->mTextureBatches;

  const boost::shared_ptr<CD3DBatchTexture>* const textureStart = mTextureBatches.begin();
  CScriptLazyVar_float::SetValue(&mBitmapWidthLV, static_cast<float>(textureStart->get()->mWidth));
  CScriptLazyVar_float::SetValue(&mBitmapHeightLV, static_cast<float>(textureStart->get()->mHeight));
}

/**
 * Address: 0x0077FD90 (FUN_0077FD90, Moho::CMauiBitmap::SetTexture)
 *
 * What it does:
 * Appends one texture lane to this bitmap texture-batch list and updates width
 * and height lazy-vars for single-frame paths.
 */
void moho::CMauiBitmap::SetTexture(
  const boost::shared_ptr<CD3DBatchTexture>& texture
)
{
  AppendBitmapTextureBatch(mTextureBatches, texture);

  const boost::shared_ptr<CD3DBatchTexture>* const textureStart = mTextureBatches.begin();
  if (textureStart != nullptr && (mTextureBatches.end() - textureStart) == 1) {
    CScriptLazyVar_float::SetValue(&mBitmapWidthLV, static_cast<float>(texture->mWidth));
    CScriptLazyVar_float::SetValue(&mBitmapHeightLV, static_cast<float>(texture->mHeight));
    return;
  }

  const boost::shared_ptr<CD3DBatchTexture>* const parentTexture = mTextureBatches.begin();
  const CD3DBatchTexture* const addedTexture = texture.get();
  if (addedTexture->mWidth != (*parentTexture)->mWidth || addedTexture->mHeight != (*parentTexture)->mHeight) {
    gpg::Warnf(
      "CMauiBitmap:SetTexture - bitmap #%d in sequence does not have same width and height as parent.",
      GetBitmapTextureBatchCount(this)
    );
  }
}

/**
 * Address: 0x007802D0 (FUN_007802D0, Moho::CMauiBitmap::SetFramePattern)
 *
 * What it does:
 * Rebuilds frame-pattern lanes from caller-provided frame indices, warning on
 * negative or out-of-range values.
 */
void moho::CMauiBitmap::SetFramePattern(
  const fa::vector<std::int32_t>& framePattern
)
{
  mFrames.clear();

  const std::int32_t textureCount = GetBitmapTextureBatchCount(this);
  const std::int32_t* const frameStart = framePattern.begin();
  if (frameStart == nullptr) {
    return;
  }

  const std::int32_t frameCount = static_cast<std::int32_t>(framePattern.end() - frameStart);
  for (std::int32_t frameCursor = 0; frameCursor < frameCount; ++frameCursor) {
    const std::int32_t requestedFrame = frameStart[frameCursor];
    if (requestedFrame >= 0) {
      if (requestedFrame > textureCount - 1) {
        gpg::Warnf(
          "Bitmap:SetFramePattern - Frame index %d found in frame pattern which is larger than number of textures(%d).",
          requestedFrame,
          textureCount
        );
      }
    } else {
      gpg::Warnf("Bitmap:SetFramePattern - Negative frame index %d found in frame pattern.", requestedFrame);
    }

    std::int32_t clampedFrame = textureCount - 1;
    if (requestedFrame < clampedFrame) {
      clampedFrame = requestedFrame;
    }
    if (clampedFrame < 0) {
      clampedFrame = 0;
    }
    mFrames.push_back(clampedFrame);
  }
}

/**
 * Address: 0x00780420 (FUN_00780420, Moho::CMauiBitmap::SetForwardPattern)
 *
 * What it does:
 * Rebuilds frame-pattern lanes to play texture batches forward.
 */
void moho::CMauiBitmap::SetForwardPattern()
{
  mFrames.clear();

  const std::int32_t textureCount = GetBitmapTextureBatchCount(this);
  for (std::int32_t frameIndex = 0; frameIndex < textureCount; ++frameIndex) {
    mFrames.push_back(frameIndex);
  }
}

/**
 * Address: 0x007804E0 (FUN_007804E0, Moho::CMauiBitmap::SetBackwardPattern)
 *
 * What it does:
 * Rebuilds frame-pattern lanes to play texture batches backward.
 */
void moho::CMauiBitmap::SetBackwardPattern()
{
  mFrames.clear();

  const std::int32_t textureCount = GetBitmapTextureBatchCount(this);
  for (std::int32_t remaining = textureCount; remaining > 0; --remaining) {
    mFrames.push_back(remaining - 1);
  }
}

/**
 * Address: 0x007805B0 (FUN_007805B0, Moho::CMauiBitmap::SetPingPongPattern)
 *
 * What it does:
 * Rebuilds one ping-pong frame sequence that returns to frame `0`.
 */
void moho::CMauiBitmap::SetPingPongPattern()
{
  mFrames.clear();

  const std::int32_t textureCount = GetBitmapTextureBatchCount(this);
  if (textureCount <= 0) {
    return;
  }

  for (std::int32_t frameIndex = 0; frameIndex < textureCount; ++frameIndex) {
    mFrames.push_back(frameIndex);
  }

  if (textureCount == 1) {
    return;
  }

  for (std::int32_t frameIndex = textureCount - 2; frameIndex >= 0; --frameIndex) {
    mFrames.push_back(frameIndex);
  }
}

/**
 * Address: 0x00780700 (FUN_00780700, Moho::CMauiBitmap::SetLoopPingPongPattern)
 *
 * What it does:
 * Rebuilds one loop-friendly ping-pong sequence that excludes endpoint
 * duplicates.
 */
void moho::CMauiBitmap::SetLoopPingPongPattern()
{
  mFrames.clear();

  const std::int32_t textureCount = GetBitmapTextureBatchCount(this);
  for (std::int32_t frameIndex = 0; frameIndex < textureCount; ++frameIndex) {
    mFrames.push_back(frameIndex);
  }

  if (textureCount <= 2) {
    return;
  }

  for (std::int32_t frameIndex = textureCount - 2; frameIndex > 0; --frameIndex) {
    mFrames.push_back(frameIndex);
  }
}

/**
 * Address: 0x007800C0 (FUN_007800C0)
 *
 * What it does:
 * Stops animated playback and dispatches `OnAnimationStopped` when active
 * multi-frame texture state is present.
 */
void moho::CMauiBitmap::StopAnimationPlayback()
{
  const auto* const batchBegin = mTextureBatches.begin();
  if (batchBegin == nullptr) {
    return;
  }

  const std::ptrdiff_t batchCount = mTextureBatches.end() - batchBegin;
  if (batchCount <= 1) {
    return;
  }

  mIsPlaying = false;
  mNeedsFrameUpdate = false;
  RunScript("OnAnimationStopped");
}

/**
 * Address: 0x00780110 (FUN_00780110, Moho::CMauiBitmap::SetFrame)
 *
 * What it does:
 * Clamps requested frame index to available frame range and stores it.
 */
std::int32_t moho::CMauiBitmap::SetFrame(
  const std::int32_t frameIndex
)
{

  std::int32_t selectedFrame = 0;
  const std::int32_t* const frameStart = mFrames.begin();
  if (frameStart != nullptr) {
    const std::int32_t frameCount = static_cast<std::int32_t>(mFrames.end() - frameStart);
    if (frameCount > 0) {
      selectedFrame = frameCount - 1;
    }
  }

  if (frameIndex < selectedFrame) {
    selectedFrame = frameIndex;
  }
  if (selectedFrame < 0) {
    selectedFrame = 0;
  }

  mCurrentFrame = selectedFrame;
  return selectedFrame;
}

/**
 * Address: 0x00780270 (FUN_00780270, Moho::CMauiBitmap::Frame)
 *
 * What it does:
 * Dispatches the bitmap `OnFrame` script callback, advances the frame timer
 * when playback is active, and wraps back to frame-end handling once the
 * current frame duration is exceeded.
 */
void moho::CMauiBitmap::Frame(
  const float deltaSeconds
)
{
  RunScriptNum("OnFrame", deltaSeconds);

  if (!mIsPlaying) {
    return;
  }

  const float nextFrameTime = deltaSeconds + mCurrentFrameTimeSeconds;
  mCurrentFrameTimeSeconds = nextFrameTime;
  if (nextFrameTime <= mFrameDurationSeconds) {
    return;
  }

  mCurrentFrameTimeSeconds = 0.0f;
  OnPatternEnd();
}

/**
 * Address: 0x00780160 (FUN_00780160, Moho::CMauiBitmap::OnPatternEnd)
 *
 * What it does:
 * Advances frame-pattern playback, handles loop/end behavior, and emits
 * `OnAnimationFinished`/`OnAnimationFrame` callbacks.
 */
void moho::CMauiBitmap::OnPatternEnd()
{
  const std::int32_t* const frameStart = mFrames.begin();
  if (frameStart == nullptr) {
    return;
  }

  const std::int32_t frameCount = static_cast<std::int32_t>(mFrames.end() - frameStart);
  if (frameCount <= 1) {
    return;
  }

  ++mCurrentFrame;
  if (mCurrentFrame < 0) {
    mCurrentFrame = 0;
  }

  const std::int32_t* const currentFrameStart = mFrames.begin();
  const std::int32_t currentFrameCount =
    currentFrameStart != nullptr ? static_cast<std::int32_t>(mFrames.end() - currentFrameStart) : 0;
  if (mCurrentFrame >= currentFrameCount) {
    if (mDoLoop) {
      mCurrentFrame = 0;
    } else {
      const std::int32_t* const terminalFrameStart = mFrames.begin();
      const std::int32_t terminalFrameCount =
        terminalFrameStart != nullptr ? static_cast<std::int32_t>(mFrames.end() - terminalFrameStart) : 0;
      mCurrentFrame = terminalFrameCount - 1;
      mIsPlaying = false;
      mNeedsFrameUpdate = false;
    }

    RunScript("OnAnimationFinished");
  }

  CallbackInt("OnAnimationFrame", mCurrentFrame);
}

/**
 * Address: 0x0077FAD0 (FUN_0077FAD0, Moho::CMauiBitmap::Dump)
 *
 * What it does:
 * Logs base CMauiControl state, then logs CMauiBitmap-specific texture batch
 * count, current bitmap width/height (from script lazy vars), UV rectangle,
 * alpha hit-test flag, animation frame count, frame rate, playback state,
 * and current frame index.
 */
void moho::CMauiBitmap::Dump()
{
  CMauiControl::Dump();
  gpg::Logf("CMauiBitmap");


  const int textureCount = static_cast<int>(mTextureBatches.size());

  // The binary fetches height first then width on the FPU stack � preserve order.
  const float bitmapHeight = CScriptLazyVar_float::GetValue(&mBitmapHeightLV);
  const float bitmapWidth = CScriptLazyVar_float::GetValue(&mBitmapWidthLV);
  gpg::Logf("Num Textures = %d Width = %.3f Height = %.3f", textureCount, bitmapWidth, bitmapHeight);
  gpg::Logf("uv = %.3f,%.3f %.3f,%.3f", mU0, mV0, mU1, mV1);

  const char* const alphaHitTest = mUseAlphaHitTest ? "true" : "false";
  gpg::Logf("Alpha Hit Test = %s", alphaHitTest);

  const char* const playing = mIsPlaying ? "true" : "false";
  const int frameCount = static_cast<int>(mFrames.size());
  gpg::Logf(
    "Num frames = %d Frame rate = %.3f Playing = %s Current Frame = %d",
    frameCount,
    mFrameDurationSeconds,
    playing,
    mCurrentFrame
  );
}

/**
 * Address: 0x0077F7A0 (FUN_0077F7A0, Moho::CMauiBitmap::GetClass)
 *
 * What it does:
 * Returns the cached reflection descriptor for `CMauiBitmap`, resolved via
 * RTTI on first use.
 */
gpg::RType* moho::CMauiBitmap::GetClass() const
{
  if (!sType) {
    sType = gpg::LookupRType(typeid(CMauiBitmap));
  }
  return sType;
}

/**
 * Address: 0x0077F7C0 (FUN_0077F7C0, Moho::CMauiBitmap::GetDerivedObjectRef)
 *
 * What it does:
 * Packs `{this, GetClass()}` as a reflection reference handle.
 */
gpg::RRef moho::CMauiBitmap::GetDerivedObjectRef()
{
  return gpg::MakeSelfRef(this);
}
