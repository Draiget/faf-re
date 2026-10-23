#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"

#include "gpg/core/reflection/Reflection.h"
#include "moho/lua/CScrLuaBinderFwd.h"
#include "moho/misc/WeakPtr.h"
#include "moho/script/CScriptObject.h"
#include "Wm3Vector2.h"
#include "Wm3Vector3.h"

struct lua_State;

namespace LuaPlus
{
  class LuaState;
} // namespace LuaPlus

namespace moho
{
  class CameraImpl;
  class CWldSession;
  class CWldTerrainDecal;
  class IDecalManager;
  class RD3DTextureResource;

  /**
   * VFTABLE: 0x00E499BC
   * COL: 0x00E9C420
   */
  class ScriptedDecal : public CScriptObject
  {
  public:
    /**
     * Address: 0x0087EB60 (FUN_0087EB60, Moho::ScriptedDecal::ScriptedDecal)
     *
     * What it does:
     * Initializes one scripted decal from the active world session and the
     * supplied Lua object payload.
     */
    ScriptedDecal(CWldSession* session, LuaPlus::LuaObject luaObject);

    /**
     * Address: 0x0087F070 (FUN_0087F070, scalar deleting thunk)
     * Address: 0x0087EC20 (FUN_0087EC20, non-deleting body)
     *
     * VFTable SLOT: 2
     */
    ~ScriptedDecal() override;

    /**
     * Address: 0x0087F030 (FUN_0087F030, ?GetClass@ScriptedDecal@Moho@@UBEPAVRType@gpg@@XZ)
     *
     * VFTable SLOT: 0
     */
    [[nodiscard]]
    gpg::RType* GetClass() const override;

    /**
     * Address: 0x0087F050 (FUN_0087F050, ?GetDerivedObjectRef@ScriptedDecal@Moho@@UAE?AVRRef@gpg@@XZ)
     *
     * VFTable SLOT: 1
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x0087ECE0 (FUN_0087ECE0, Moho::ScriptedDecal::SetPosition)
     *
     * What it does:
     * Stores one world-space position, re-centres the decal quad on it, and
     * republishes the terrain decal's transform. Invalid (NaN) positions are
     * dropped without touching any lane.
     */
    void SetPosition(const Wm3::Vector3f& worldPosition);

    /**
     * Address: 0x0087ED70 (FUN_0087ED70, Moho::ScriptedDecal::SetPositionByScreen)
     *
     * What it does:
     * Projects one screen-space point onto the terrain through the world
     * camera and applies the resulting world-space position.
     */
    void SetPositionByScreen(const Wm3::Vector2f& screenPoint);

    /**
     * Address: 0x0087ED90 (FUN_0087ED90, Moho::ScriptedDecal::SetScale)
     *
     * What it does:
     * Resizes both this decal and the terrain decal it owns, then reapplies
     * the current position so the quad stays centred on it.
     */
    void SetScale(const Wm3::Vector3f& scale);

    /**
     * Address: 0x0087EDE0 (FUN_0087EDE0, Moho::ScriptedDecal::SetTexture)
     *
     * What it does:
     * Loads one texture by path and rebuilds this decal's terrain decal around
     * it: the previous decal is handed back to the manager, a fresh one is
     * created with the texture bound into name slot 0, distance fade disabled,
     * and it is added to the manager's splat list.
     */
    void SetTexture(const char* texturePath);

  public:
    static gpg::RType* sType;

    /**
     * The terrain decal this scripted decal drives, held weakly: the decal
     * manager owns it, and `CWldTerrainDecal`'s own teardown blanks this lane
     * through its `WeakObject` base (the weak head at `decal + 0x04` the
     * binary's `slot - 4` downcasts and `0x008679E0` relinks decode).
     */
    WeakPtr<CWldTerrainDecal> mDecal;                       // +0x34
    boost::shared_ptr<RD3DTextureResource> mDynamicTexture; // +0x3C
    IDecalManager* mDecalManager;                           // +0x44
    CameraImpl* mWorldCamera;                               // +0x48
    Wm3::Vector3f mScale;                                   // +0x4C
    Wm3::Vector3f mWorldPosition;                           // +0x58
  };

  static_assert(sizeof(ScriptedDecal) == 0x64, "ScriptedDecal size must be 0x64");
  static_assert(offsetof(ScriptedDecal, mDecal) == 0x34, "ScriptedDecal::mDecal offset must be 0x34");
  static_assert(
    offsetof(ScriptedDecal, mDynamicTexture) == 0x3C, "ScriptedDecal::mDynamicTexture offset must be 0x3C"
  );
  static_assert(offsetof(ScriptedDecal, mDecalManager) == 0x44, "ScriptedDecal::mDecalManager offset must be 0x44");
  static_assert(offsetof(ScriptedDecal, mWorldCamera) == 0x48, "ScriptedDecal::mWorldCamera offset must be 0x48");
  static_assert(offsetof(ScriptedDecal, mScale) == 0x4C, "ScriptedDecal::mScale offset must be 0x4C");
  static_assert(offsetof(ScriptedDecal, mWorldPosition) == 0x58, "ScriptedDecal::mWorldPosition offset must be 0x58");

  /**
   * Address: 0x0087F1E0 (FUN_0087F1E0, cfunc__c_CreateDecal)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc__c_CreateDecalL`.
   */
  int cfunc__c_CreateDecal(lua_State* luaContext);

  /**
   * Address: 0x0087F200 (FUN_0087F200, func__c_CreateDecal_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `_c_CreateDecal`.
   */
  CScrLuaInitForm* func__c_CreateDecal_LuaFuncDef();

  /**
   * Address: 0x0087F260 (FUN_0087F260, cfunc__c_CreateDecalL)
   *
   * What it does:
   * Creates one scripted decal from the active world session and returns its
   * Lua object, or nil when no session is active.
   */
  int cfunc__c_CreateDecalL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0087F360 (FUN_0087F360, cfunc_ScriptedDecalSetTexture)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_ScriptedDecalSetTextureL`.
   */
  int cfunc_ScriptedDecalSetTexture(lua_State* luaContext);

  /**
   * Address: 0x0087F380 (FUN_0087F380, func_ScriptedDecalSetTexture_LuaFuncDef)
   *
   * What it does:
   * Publishes the `ScriptedDecal:SetTexture(path)` Lua binder.
   */
  CScrLuaInitForm* func_ScriptedDecalSetTexture_LuaFuncDef();

  /**
   * Address: 0x0087F3E0 (FUN_0087F3E0, cfunc_ScriptedDecalSetTextureL)
   *
   * What it does:
   * Validates one scripted decal plus one texture-path string, then applies the texture.
   */
  int cfunc_ScriptedDecalSetTextureL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0087F4C0 (FUN_0087F4C0, cfunc_ScriptedDecalSetScale)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_ScriptedDecalSetScaleL`.
   */
  int cfunc_ScriptedDecalSetScale(lua_State* luaContext);

  /**
   * Address: 0x0087F4E0 (FUN_0087F4E0, func_ScriptedDecalSetScale_LuaFuncDef)
   *
   * What it does:
   * Publishes the `ScriptedDecal:SetScale(scaleVec3)` Lua binder.
   */
  CScrLuaInitForm* func_ScriptedDecalSetScale_LuaFuncDef();

  /**
   * Address: 0x0087F540 (FUN_0087F540, cfunc_ScriptedDecalSetScaleL)
   *
   * What it does:
   * Reads one scale vector, updates runtime decal scale lanes, and reapplies position.
   */
  int cfunc_ScriptedDecalSetScaleL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0087F660 (FUN_0087F660, cfunc_ScriptedDecalSetPositionByScreen)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ScriptedDecalSetPositionByScreenL`.
   */
  int cfunc_ScriptedDecalSetPositionByScreen(lua_State* luaContext);

  /**
   * Address: 0x0087F680 (FUN_0087F680, func_ScriptedDecalSetPositionByScreen_LuaFuncDef)
   *
   * What it does:
   * Publishes the `ScriptedDecal:SetPositionByScreen(screenPoint)` Lua binder.
   */
  CScrLuaInitForm* func_ScriptedDecalSetPositionByScreen_LuaFuncDef();

  /**
   * Address: 0x0087F6E0 (FUN_0087F6E0, cfunc_ScriptedDecalSetPositionByScreenL)
   *
   * What it does:
   * Converts one screen-space point via world camera projection and applies it.
   */
  int cfunc_ScriptedDecalSetPositionByScreenL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0087F7E0 (FUN_0087F7E0, cfunc_ScriptedDecalSetPosition)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_ScriptedDecalSetPositionL`.
   */
  int cfunc_ScriptedDecalSetPosition(lua_State* luaContext);

  /**
   * Address: 0x0087F800 (FUN_0087F800, func_ScriptedDecalSetPosition_LuaFuncDef)
   *
   * What it does:
   * Publishes the `ScriptedDecal:SetPosition(worldPoint)` Lua binder.
   */
  CScrLuaInitForm* func_ScriptedDecalSetPosition_LuaFuncDef();

  /**
   * Address: 0x0087F860 (FUN_0087F860, cfunc_ScriptedDecalSetPositionL)
   *
   * What it does:
   * Reads one world-space vector argument and applies it via `ScriptedDecal::SetPosition`.
   */
  int cfunc_ScriptedDecalSetPositionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0087F950 (FUN_0087F950, cfunc_ScriptedDecalDestroy)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_ScriptedDecalDestroyL`.
   */
  int cfunc_ScriptedDecalDestroy(lua_State* luaContext);

  /**
   * Address: 0x0087F970 (FUN_0087F970, func_ScriptedDecalDestroy_LuaFuncDef)
   *
   * What it does:
   * Publishes the `ScriptedDecal:Destroy()` Lua binder.
   */
  CScrLuaInitForm* func_ScriptedDecalDestroy_LuaFuncDef();

  /**
   * Address: 0x0087F9D0 (FUN_0087F9D0, cfunc_ScriptedDecalDestroyL)
   *
   * What it does:
   * Resolves one scripted decal object and destroys it through virtual delete lane.
   */
  int cfunc_ScriptedDecalDestroyL(LuaPlus::LuaState* state);
} // namespace moho
