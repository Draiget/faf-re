#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"

#include "gpg/core/reflection/Reflection.h"
#include "moho/lua/CScrLuaBinderFwd.h"
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
  class RD3DTextureResource;
  class CWldSession;

  struct ScriptedDecalRuntimeLink
  {
    ScriptedDecalRuntimeLink* mHead;
    ScriptedDecalRuntimeLink* mNext;
  };
  static_assert(sizeof(ScriptedDecalRuntimeLink) == 0x08, "ScriptedDecalRuntimeLink size must be 0x08");

  /**
   * Runtime service used by ScriptedDecal for registration/unregistration.
   *
   * `RemoveRuntimeDecal` corresponds to vtable slot offset +0x24 in recovered
   * ScriptedDecal teardown path (FUN_0087EC20).
   */
  class IDecalRuntimeService
  {
  public:
    virtual void Slot00() = 0;
    virtual void Slot01() = 0;
    virtual void Slot02() = 0;
    virtual void Slot03() = 0;
    virtual void Slot04() = 0;
    virtual void Slot05() = 0;
    virtual void Slot06() = 0;
    virtual void* Slot07(std::int32_t lane) = 0;
    virtual void Slot08() = 0;
    virtual void RemoveRuntimeDecal(void* runtimeEntry) = 0;
    virtual void Slot10() = 0;
    virtual void Slot11() = 0;
    virtual void Slot12() = 0;
    virtual void Slot13() = 0;
    virtual void Slot14() = 0;
    virtual void Slot15() = 0;
    virtual void Slot16() = 0;
    virtual void Slot17() = 0;
    virtual void Slot18_CommitRuntimeDecal(void* runtimeEntry) = 0;
    virtual void Slot19() = 0;
    virtual void Slot20() = 0;
    virtual void Slot21() = 0;
    virtual void Slot22() = 0;
    virtual void Slot23() = 0;
    virtual void Slot24() = 0;
    virtual void Slot25() = 0;
    virtual void Slot26() = 0;
    virtual void Slot27_NotifyRuntimeUpdate() = 0;
  };

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
     * Validates and stores one world-space position, then updates the linked
     * runtime decal entry.
     */
    [[nodiscard]] bool SetPosition(const Wm3::Vector3f* worldPosition);

    /**
     * Address: 0x0087ED70 (FUN_0087ED70, Moho::ScriptedDecal::SetPositionByScreen)
     *
     * What it does:
     * Projects one screen-space point through the active world camera and
     * applies the resulting world-space position.
     */
    [[nodiscard]] bool SetPositionByScreen(const Wm3::Vector2f* screenPoint);

    /**
     * Address: 0x0087ED90 (FUN_0087ED90, Moho::ScriptedDecal::SetScale)
     *
     * What it does:
     * Updates local/runtime decal scale lanes and reapplies world positioning.
     */
    [[nodiscard]] bool SetScale(const Wm3::Vector3f* scale);

    /**
     * Address: 0x0087EDE0 (FUN_0087EDE0, Moho::ScriptedDecal::SetTexture)
     *
     * What it does:
     * Loads one dynamic texture sheet by path and refreshes this decal's
     * runtime decal-entry state.
     */
    ScriptedDecal* SetTexture(const char* texturePath);

  public:
    static gpg::RType* sType;

    ScriptedDecalRuntimeLink mRuntimeLink;     // +0x34
    boost::shared_ptr<RD3DTextureResource> mDynamicTexture; // +0x3C
    IDecalRuntimeService* mDecalService;       // +0x44
    void* mWorldCamera;                        // +0x48
    float mScaleX;                             // +0x4C
    float mScaleY;                             // +0x50
    float mScaleZ;                             // +0x54
    Wm3::Vector3f mWorldPosition;              // +0x58
  };

  static_assert(sizeof(ScriptedDecal) == 0x64, "ScriptedDecal size must be 0x64");
  static_assert(offsetof(ScriptedDecal, mRuntimeLink) == 0x34, "ScriptedDecal::mRuntimeLink offset must be 0x34");
  static_assert(
    offsetof(ScriptedDecal, mDynamicTexture) == 0x3C, "ScriptedDecal::mDynamicTexture offset must be 0x3C"
  );
  static_assert(offsetof(ScriptedDecal, mDecalService) == 0x44, "ScriptedDecal::mDecalService offset must be 0x44");
  static_assert(offsetof(ScriptedDecal, mWorldCamera) == 0x48, "ScriptedDecal::mWorldCamera offset must be 0x48");
  static_assert(offsetof(ScriptedDecal, mScaleX) == 0x4C, "ScriptedDecal::mScaleX offset must be 0x4C");
  static_assert(offsetof(ScriptedDecal, mScaleY) == 0x50, "ScriptedDecal::mScaleY offset must be 0x50");
  static_assert(offsetof(ScriptedDecal, mScaleZ) == 0x54, "ScriptedDecal::mScaleZ offset must be 0x54");
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
