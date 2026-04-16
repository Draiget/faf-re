#pragma once
#include "gpg/core/containers/FastVector.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/BoostUtils.h"
#include "lua/LuaObject.h"
#include "moho/containers/TDatList.h"
#include "moho/misc/InstanceCounter.h"
#include "moho/misc/WeakObject.h"
#include "platform/Platform.h"
#include <cstddef>
#include <cstdint>
#include <string>

namespace moho
{
  template <class T>
  struct WeakPtr;

  class CScrLuaInitForm;
  class Entity;
  class Prop;
  class ReconBlip;
  class Unit;
  class UnitWeapon;

  class MOHO_EMPTY_BASES CScriptObject : public gpg::RObject,
                                         public WeakObject,
                                         public boost::noncopyable_::noncopyable,
                                         public InstanceCounter<CScriptObject>
  {
    // Legacy MSVC8 ABI places empty-base storage ahead of first data member.
    // With __declspec(empty_bases) this storage is removed, so add +4 only
    // in non-MSVC8-compat builds to keep cObject at +0x0C.
#if !defined(MOHO_ABI_MSVC8_COMPAT)
    MOHO_EBO_PADDING_FIELD(1);
#endif

  protected:
    /**
     * Address: 0x004C6F70 (??0CScriptObject@Moho@@IAE@XZ)
     *
     * What it does:
     * Initializes base CScriptObject storage without binding a Lua object yet.
     */
    CScriptObject();

    /**
     * Address: 0x004C7010 (??0CScriptObject@Moho@@IAE@ABVLuaObject@LuaPlus@@000@Z)
     *
     * What it does:
     * Initializes base storage and immediately binds script-side Lua object metadata.
     */
    CScriptObject(
      const LuaPlus::LuaObject& metaOrFactory,
      const LuaPlus::LuaObject& arg1,
      const LuaPlus::LuaObject& arg2,
      const LuaPlus::LuaObject& arg3
    );

  public:
    static gpg::RType* sType;
    static gpg::RType* sPointerType;

    [[nodiscard]]
    static gpg::RType* StaticGetClass();

    /**
     * Address: 0xA82547
     * VFTable SLOT: 0
     */
    [[nodiscard]]
    virtual gpg::RType* GetClass() const = 0;

    /**
     * Address: 0xA82547
     * VFTable SLOT: 1
     */
    virtual gpg::RRef GetDerivedObjectRef() = 0;

    /**
     * Address: 0x004C7340 (FUN_004C7340, Moho::CScriptObject::~CScriptObject)
     * Deleting destructor thunk: 0x004C6FF0 (FUN_004C6FF0, Moho::CScriptObject::dtr)
     * VFTable SLOT: 2
     */
    virtual ~CScriptObject();

    /**
     * Address: 0x4C70A0
     * VFTable SLOT: 3
     */
    virtual msvc8::string GetErrorDescription();

    /**
     * Address: 0x004C70D0
     */
    void CreateLuaObject(
      const LuaPlus::LuaObject&, const LuaPlus::LuaObject&, const LuaPlus::LuaObject&, const LuaPlus::LuaObject&
    );

    /**
     * Address: 0x004C72D0
     */
    void SetLuaObject(const LuaPlus::LuaObject& obj);

    /**
     * Address: 0x004C7410
     */
    void LogScriptWarning(CScriptObject*, const char*, const char*);

    /**
     * Address: 0x004C74B0
     */
    LuaPlus::LuaObject FindScript(LuaPlus::LuaObject* dest, const char* name);

    /**
     * Address: 0x004C7580
     */
    bool RunScriptMultiRet(
      const char* funcName,
      gpg::core::FastVector<LuaPlus::LuaObject>& out,
      LuaPlus::LuaObject arg1,
      LuaPlus::LuaObject arg2,
      LuaPlus::LuaObject arg3,
      LuaPlus::LuaObject arg4,
      LuaPlus::LuaObject arg5
    );

    /**
     * Address: 0x00623F10 (FUN_00623F10, Moho::CScriptObject::TaskTick)
     *
     * What it does:
     * Calls script callback `TaskTick(self)` and returns integer result.
     */
    [[nodiscard]]
    int TaskTick();

    /**
     * Address: 0x004C8530 (FUN_004C8530, Moho::CScriptObject::GetPointerType)
     *
     * What it does:
     * Lazily resolves and caches reflected pointer type descriptor for `CScriptObject*`.
     */
    [[nodiscard]] static gpg::RType* GetPointerType();

    /**
     * Address: 0x004C8DC0 (FUN_004C8DC0, Moho::CScriptObject::MemberDeserialize)
     *
     * What it does:
     * Loads `cObject` and `mLuaObj` lanes from archive using LuaObject reflected type.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x004C8E40 (FUN_004C8E40, Moho::CScriptObject::MemberSerialize)
     *
     * What it does:
     * Saves `cObject` and `mLuaObj` lanes into archive using LuaObject reflected type.
     */
    void MemberSerialize(gpg::WriteArchive* archive);

    /**
     * Address: 0x00581AA0
     *
     * @param callback
     */
    void CallbackStr(const char* callback);

    /**
     * Address: 0x005FCFE0
     *
     * @param callback
     * @param arg0
     */
    void CallbackStr(const char* callback, const char** arg0);

    /**
     * Address: 0x0067F450
     *
     * @param callback
     * @param arg0
     * @param arg1
     */
    void CallbackStr(const char* callback, const char** arg0, const char** arg1);

    /**
       * Address: 0x006B0940 (FUN_006B0940)
     *
     * Calls script callback with a single integer argument.
     */
    void CallbackInt(const char* callback, int value);

    template <class... Ts>
    LuaPlus::LuaObject RunScript(const char* name, Ts... args)
    {
      LuaPlus::LuaObject script;
      FindScript(&script, name);
      if (script) {
        LuaPlus::LuaFunction<LuaPlus::LuaObject> fn{script};
        return fn(args...);
      }
      return {};
    }

    /**
     * Address: 0x006753A0
     * @param scriptName
     * @param args
     * @param obj
     */
    void LuaPCall(const char* scriptName, const char* const* args, LuaPlus::LuaObject* obj);

    /**
     * Address: 0x005C9480 (FUN_005C9480, Moho::CScriptObject::RunScript_Int)
     *
     * What it does:
     * Invokes one script callback with `(self, intValue)` when present.
     */
    void RunScriptInt(const char* scriptName, int intValue);

    /**
     * Address: 0x005D0540 (FUN_005D0540, Moho::CScriptObject::RunScript_Obj_Num)
     *
     * What it does:
     * Invokes one script callback with `(self)` and returns numeric result.
     */
    [[nodiscard]] float RunScriptObjNum(const char* scriptName);

    /**
     * Address: 0x005D06B0 (FUN_005D06B0, Moho::CScriptObject::RunScript_Weap)
     *
     * What it does:
     * Invokes one script callback with `(self, weapon)` when present.
     */
    void RunScriptWeapon(const char* scriptName, UnitWeapon* weapon);

    /**
     * Address: 0x005EC1C0 (FUN_005EC1C0, Moho::CScriptObject::RunScript_Obj)
     *
     * What it does:
     * Invokes one script callback with `(self, unit)` when present.
     */
    void RunScriptUnit(const char* scriptName, Unit* unit);

    /**
     * Address: 0x005F48A0 (FUN_005F48A0, Moho::CScriptObject::RunScript_Bool)
     *
     * What it does:
     * Invokes one script callback with `(self)` and returns Lua bool result.
     */
    [[nodiscard]] bool RunScriptBool(const char* scriptName);

    /**
     * Address: 0x005FCA70 (FUN_005FCA70, Moho::CScriptObject::GetLuaValue)
     *
     * What it does:
     * Reads one numeric field from the script object table by key.
     */
    [[nodiscard]] float GetLuaValue(const char* key) const;

    /**
     * Address: 0x005FCB70 (FUN_005FCB70, Moho::CScriptObject::SetLuaValue)
     *
     * What it does:
     * Writes one numeric field into the script object table by key.
     */
    void SetLuaValue(const char* key, float value);

    /**
     * Address: 0x005FD1C0 (FUN_005FD1C0, Moho::CScriptObject::RunScript_Weakunit)
     *
     * What it does:
     * Invokes one script callback with `(self, weakUnitValue)` when present.
     */
    void RunScriptWeakUnit(const char* scriptName, const WeakPtr<Unit>& unitLink);

    /**
     * Address: 0x00605600 (FUN_00605600, Moho::CScriptObject::RunScript_Weakent)
     *
     * What it does:
     * Invokes one script callback with `(self, weakEntityValue)` when present.
     */
    void RunScriptWeakEntity(const char* scriptName, const WeakPtr<Entity>& entityLink);

    /**
     * Address: 0x00633070 (FUN_00633070, Moho::CScriptObject::Call_Str)
     *
     * What it does:
     * Invokes one script callback with `(self, stringValue)` when present.
     */
    void CallString(const char* scriptName, const std::string& stringValue);

    /**
     * Address: 0x00638970 (FUN_00638970, Moho::CScriptObject::RunScript_StrNum3)
     *
     * What it does:
     * Invokes one script callback with `(self, text, a, b, c)` when present.
     */
    void RunScriptStringNum3(const char* scriptName, const char* text, float a, float b, float c);

    /**
     * Address: 0x0067F180 (FUN_0067F180, Moho::CScriptObject::RunScript_Ent)
     *
     * What it does:
     * Invokes one script callback with `(self, entity)` when present.
     */
    void RunScriptEntity(const char* scriptName, Entity* entityArg);

    /**
     * Address: 0x0067F2E0 (FUN_0067F2E0, Moho::CScriptObject::RunScript_Num2)
     *
     * What it does:
     * Invokes one script callback with `(self, a, b)` when present.
     */
    void RunScriptNum2(const char* scriptName, float a, float b);

    /**
     * Address: 0x0069F550 (FUN_0069F550, Moho::CScriptObject::RunScriptBool)
     *
     * What it does:
     * Invokes one script callback with `(self, value)` when present.
     */
    void RunScriptWithBool(const char* scriptName, bool value);

    /**
     * Address: 0x006B07D0 (FUN_006B07D0, Moho::CScriptObject::RunScript_ObjStr)
     *
     * What it does:
     * Invokes one script callback with `(self, obj, text)` when present.
     */
    void RunScriptObjectString(const char* scriptName, const LuaPlus::LuaObject& objectArg, const char* text);

    /**
     * Address: 0x0078A870 (FUN_0078A870, Moho::CScriptObject::RunScript_Num)
     *
     * What it does:
     * Invokes one script callback with `(self, number)` when present.
     */
    void RunScriptNum(const char* scriptName, float value);

    /**
     * Address: 0x0078AB70 (FUN_0078AB70, Moho::CScriptObject::RunScript_StrNum)
     *
     * What it does:
     * Invokes one script callback with `(self, text, number)` when present.
     */
    void RunScriptStringNum(const char* scriptName, const char* text, float value);

    /**
     * Address: 0x007950D0 (FUN_007950D0, Moho::CScriptObject::RunScript_String)
     *
     * What it does:
     * Invokes one script callback with `(self, text)` and returns Lua bool result.
     */
    [[nodiscard]] bool RunScriptStringBool(const char* scriptName, const std::string& value);

    /**
     * Address: 0x00795260 (FUN_00795260, Moho::CScriptObject::RunScript_IntObject)
     *
     * What it does:
     * Invokes one script callback with `(self, intValue, objectArg)` when present.
     */
    void RunScriptIntObject(const char* scriptName, int intValue, const LuaPlus::LuaObject& objectArg);

    /**
     * Address: 0x007953D0 (FUN_007953D0, Moho::CScriptObject::RunScript_OnCharPressed)
     *
     * What it does:
     * Invokes `OnCharPressed(self, keyCode)` callback and returns Lua bool result.
     */
    [[nodiscard]] bool RunScriptOnCharPressed(int keyCode);

    /**
     * Address: 0x0057A500 (FUN_0057A500, Moho::CScriptObject::OnSpawnPreBuiltUnits)
     *
     * What it does:
     * Invokes `OnSpawnPreBuiltUnits(self)` callback when present.
     */
    void OnSpawnPreBuiltUnits();

    /**
     * Address: 0x00620760 (FUN_00620760, Moho::CScriptObject::RunScript_CreateWreckageProp)
     *
     * What it does:
     * Invokes `CreateWreckageProp(self, reclaimFraction)` and returns created Lua object.
     */
    [[nodiscard]] LuaPlus::LuaObject RunScriptCreateWreckageProp(float reclaimFraction);

    /**
     * Address: 0x006B0660 (FUN_006B0660, Moho::CScriptObject::RunScript_OnAdjacentTo)
     *
     * What it does:
     * Invokes `OnAdjacentTo(self, sourceUnit, adjacentUnit)` callback when present.
     */
    void RunScriptOnAdjacentTo(Unit* sourceUnit, Unit* adjacentUnit);

    /**
     * Address: 0x006DD430 (FUN_006DD430, Moho::CScriptObject::GetWeaponClass)
     *
     * What it does:
     * Invokes `GetWeaponClass(self, weaponBlueprintClass)` callback and returns Lua object result.
     */
    [[nodiscard]] LuaPlus::LuaObject GetWeaponClass(const LuaPlus::LuaObject& weaponBlueprintClass);

    /**
     * Address: 0x005EBED0 (FUN_005EBED0, Moho::CScriptObject::RunScript_Unit_Bool)
     *
     * What it does:
     * Executes one script callback with a `Unit*` argument and returns bool result.
     */
    [[nodiscard]]
    bool RunScriptUnitBool(const char* scriptName, Unit* unitArg);

    /**
     * Address: 0x00581930
     * @param fileName
     * @param obj
     */
    void LuaCall(const char* fileName, LuaPlus::LuaObject* obj);

    /**
     * Address: 0x005EC040 (FUN_005EC040, Moho::CScriptObject::RunScript_UnitOnDamage)
     *
     * What it does:
     * Invokes `OnDamage(unit, amount, canTakeDamage, "Damage")` on this script object.
     */
    void RunScriptUnitOnDamage(Unit* sourceUnit, int amount, bool canTakeDamageFlag);

    /**
     * Address: 0x005FC730 (FUN_005FC730, Moho::CScriptObject::OnStopBuild)
     *
     * What it does:
     * Invokes script callback `OnStopBuild(self, reason, unitObject)` when present.
     */
    void OnStopBuild(const WeakPtr<Unit>& unitLink, const std::string& reason);

    /**
     * Address: 0x005FC8E0 (FUN_005FC8E0, Moho::CScriptObject::RunScript_OnStartBuild)
     *
     * What it does:
     * Invokes script callback `OnStartBuild(self, focusUnit, buildAction)` when present.
     */
    void RunScriptOnStartBuild(Unit* focusUnit, const std::string& buildAction);

    /**
     * Address: 0x005FCBF0 (FUN_005FCBF0, Moho::CScriptObject::RunScript_OnBuildProgress)
     *
     * What it does:
     * Invokes `OnBuildProgress(self, sourceUnit, previousProgress, currentProgress)` when present.
     */
    void RunScriptOnBuildProgress(const WeakPtr<Unit>& sourceUnitLink, float previousProgress, float currentProgress);

    /**
     * Address: 0x005C92C0 (FUN_005C92C0, Moho::CScriptObject::RunScript_OnIntelChange)
     *
     * What it does:
     * Invokes script callback `OnIntelChange(self, blip, intelSenseName, gained)` when present.
     */
    void RunScriptOnIntelChange(ReconBlip* blip, const std::string& intelSenseName, bool gained);

    /**
     * Address: 0x0073A330 (FUN_0073A330, Moho::CScriptObject::RunScript_OnGetDamageAbsorption)
     *
     * What it does:
     * Invokes `OnGetDamageAbsorption(self, sourceEntity, amount, damageType)` and
     * returns the numeric absorption contribution from script.
     */
    [[nodiscard]]
    float RunScriptOnGetDamageAbsorption(const WeakPtr<Entity>& sourceLink, float amount, const std::string& damageType);

    /**
     * Address: 0x0073A4F0 (FUN_0073A4F0, Moho::CScriptObject::RunScript_EntityOnDamage)
     *
     * What it does:
     * Invokes `OnDamage(self, amount, payload, damageType, sourceEntity)` callback.
     */
    void RunScriptEntityOnDamage(
      const WeakPtr<Entity>& sourceLink,
      float amount,
      const LuaPlus::LuaObject& payload,
      const std::string& damageType
    );

    /**
     * Address: 0x00598660 (FUN_00598660, Moho::CScriptObject::RunScript_OnCollision)
     *
     * What it does:
     * Invokes `OnCollision(self, otherObject, a, b, c, d)` callback when present.
     */
    void RunScriptOnCollision(
      const LuaPlus::LuaObject& otherObject,
      float collisionParamA,
      float collisionParamB,
      float collisionParamC,
      float collisionParamD
    );

    /**
     * Address: 0x005FCD80 (FUN_005FCD80, Moho::CScriptObject::RunScript_OnBeingBuiltProgress)
     *
     * What it does:
     * Invokes `OnBeingBuiltProgress(self, sourceUnit, progress, buildRate)` callback when present.
     */
    void RunScriptOnBeingBuiltProgress(Unit* sourceUnit, float progress, float buildRate);

    /**
     * Address: 0x00602CA0 (FUN_00602CA0, Moho::CScriptObject::StartTransportBeamUp)
     *
     * What it does:
     * Invokes `OnStartTransportBeamUp(self, attachBone, sourceUnit)` callback when present.
     */
    void StartTransportBeamUp(const WeakPtr<Unit>& sourceUnitLink, int attachBone);

    /**
     * Address: 0x0060C590 (FUN_0060C590, Moho::CScriptObject::RunScript_OnTeleportUnit)
     *
     * What it does:
     * Invokes `OnTeleportUnit(self, argA, argB, argC)` callback when present.
     */
    void RunScriptOnTeleportUnit(
      const LuaPlus::LuaObject& argA,
      const LuaPlus::LuaObject& argB,
      const LuaPlus::LuaObject& argC
    );

    /**
     * Address: 0x006B0AB0 (FUN_006B0AB0, Moho::CScriptObject::RunScript_UnitOnKilled)
     *
     * What it does:
     * Invokes `OnKilled(self, sourceEntity, reason, value)` callback for unit-owned scripts.
     */
    void RunScriptUnitOnKilled(Entity* sourceEntity, const char* reason, float value);

    /**
     * Address: 0x006B0C50 (FUN_006B0C50, Moho::CScriptObject::RunScript_OnTerrainTypeChange)
     *
     * What it does:
     * Invokes `OnTerrainTypeChange(self, oldTerrain, newTerrain)` callback when present.
     */
    void RunScriptOnTerrainTypeChange(const LuaPlus::LuaObject& oldTerrain, const LuaPlus::LuaObject& newTerrain);

    /**
     * Address: 0x006B0DD0 (FUN_006B0DD0, Moho::CScriptObject::RunScript_WeakunitStr)
     *
     * What it does:
     * Invokes `OnStopBeingBuilt(self, sourceUnit, layerName)` callback when present.
     */
    void RunScriptOnStopBeingBuilt(const WeakPtr<Unit>& sourceUnitLink, const char* layerName);

    /**
     * Address: 0x006DD5D0 (FUN_006DD5D0, Moho::CScriptObject::RunScript_OnCollisionCheckWeapon)
     *
     * What it does:
     * Invokes `OnCollisionCheckWeapon(self, weapon)` and returns Lua-bool result.
     */
    [[nodiscard]] bool RunScriptOnCollisionCheckWeapon(UnitWeapon* weapon);

    /**
     * Address: 0x006FAC00 (FUN_006FAC00, Moho::CScriptObject::RunScript_PropOnKilled)
     *
     * What it does:
     * Invokes `OnKilled(self, sourceProp, reason, value)` callback for prop-owned scripts.
     */
    void RunScriptPropOnKilled(Prop* sourceProp, const char* reason, float value);

    /**
     * Address: 0x007CB940
     *
     * @param out
     * @param name
     */
    void RunScriptObj(LuaPlus::LuaObject& out, const char* name);

    /**
     * Address: 0x00675CF0
     */
    void LuaInvoke3_DiscardReturn(
      LuaPlus::LuaObject& func, LuaPlus::LuaObject& selfObj, const char* stringArg, LuaPlus::LuaObject& payloadObj
    );

  public:
    LuaPlus::LuaObject cObject; // +0x0C (size 0x14)
    LuaPlus::LuaObject mLuaObj; // +0x20 (size 0x14)
  };

  /**
   * Address: 0x004C7A90 (FUN_004C7A90, cfunc_IsDestroyed)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_IsDestroyedL`.
   */
  int cfunc_IsDestroyed(lua_State* luaContext);

  /**
   * Address: 0x004C7AB0 (FUN_004C7AB0, func_IsDestroyed_LuaFuncDef)
   *
   * What it does:
   * Publishes the global core-lane Lua binder for `IsDestroyed`.
   */
  CScrLuaInitForm* func_IsDestroyed_LuaFuncDef();

  /**
   * Address: 0x004C7B10 (FUN_004C7B10, cfunc_IsDestroyedL)
   *
   * What it does:
   * Returns whether one Lua `_c_object` payload is missing or already nulled.
   */
  int cfunc_IsDestroyedL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00BC60C0 (FUN_00BC60C0, register_IsDestroyed_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_IsDestroyed_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IsDestroyed_LuaFuncDef();

  using ScrConcatArgsSink = void(__cdecl*)(LuaPlus::LuaState* state, const char* text);

  /**
   * Address: 0x004CD740 (FUN_004CD740, Moho::SCR_ConcatArgsAndCall)
   *
   * What it does:
   * Concatenates Lua args through `tostring`, applies control-code formatting,
   * and emits split lines through a sink callback.
   */
  void SCR_ConcatArgsAndCall(LuaPlus::LuaState* state, std::uint8_t delimiterControlCode, ScrConcatArgsSink sink);

  /**
   * Address: 0x004CD8F0 (FUN_004CD8F0, cfunc_printUser)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to the global `print` sink.
   */
  int cfunc_printUser(lua_State* luaContext);

  /**
   * Address: 0x004CD910 (FUN_004CD910, func_printUser_LuaFuncDef)
   *
   * What it does:
   * Publishes the user-lane global Lua binder for `print`.
   */
  CScrLuaInitForm* func_printUser_LuaFuncDef();

  /**
   * Address: 0x004CD9A0 (FUN_004CD9A0, cfunc_LOG)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `LOG`.
   */
  int cfunc_LOG(lua_State* luaContext);

  /**
   * Address: 0x004CD9C0 (FUN_004CD9C0, func_LOG_LuaFuncDef)
   *
   * What it does:
   * Publishes the core-lane global Lua binder for `LOG`.
   */
  CScrLuaInitForm* func_LOG_LuaFuncDef();

  /**
   * Address: 0x004CDA50 (FUN_004CDA50, cfunc_WARN)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `WARN`.
   */
  int cfunc_WARN(lua_State* luaContext);

  /**
   * Address: 0x004CDA70 (FUN_004CDA70, func_WARN_LuaFuncDef)
   *
   * What it does:
   * Publishes the core-lane global Lua binder for `WARN`.
   */
  CScrLuaInitForm* func_WARN_LuaFuncDef();

  /**
   * Address: 0x004CDB00 (FUN_004CDB00, cfunc_SPEW)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `SPEW`.
   */
  int cfunc_SPEW(lua_State* luaContext);

  /**
   * Address: 0x004CDB20 (FUN_004CDB20, func_SPEW_LuaFuncDef)
   *
   * What it does:
   * Publishes the core-lane global Lua binder for `SPEW`.
   */
  CScrLuaInitForm* func_SPEW_LuaFuncDef();

  /**
   * Address: 0x004CEAF0 (FUN_004CEAF0, cfunc_doscript)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_doscriptL`.
   */
  int cfunc_doscript(lua_State* luaContext);

  /**
   * Address: 0x004CEB10 (FUN_004CEB10, func_doscript_LuaFuncDef)
   *
   * What it does:
   * Publishes the core-lane global Lua binder for `doscript`.
   */
  CScrLuaInitForm* func_doscript_LuaFuncDef();

  /**
   * Address: 0x004CEB70 (FUN_004CEB70, cfunc_doscriptL)
   *
   * What it does:
   * Validates `doscript(script, [env])` args and dispatches to `func_LuaDoScript`.
   */
  int cfunc_doscriptL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00BC6410 (FUN_00BC6410, register_printUser_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_printUser_LuaFuncDef`.
   */
  CScrLuaInitForm* register_printUser_LuaFuncDef();

  /**
   * Address: 0x00BC6420 (FUN_00BC6420, register_LOG_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_LOG_LuaFuncDef`.
   */
  CScrLuaInitForm* register_LOG_LuaFuncDef();

  /**
   * Address: 0x00BC6430 (FUN_00BC6430, register_WARN_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_WARN_LuaFuncDef`.
   */
  CScrLuaInitForm* register_WARN_LuaFuncDef();

  /**
   * Address: 0x00BC6440 (FUN_00BC6440, register_SPEW_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_SPEW_LuaFuncDef`.
   */
  CScrLuaInitForm* register_SPEW_LuaFuncDef();

  /**
   * Address: 0x00BC64A0 (FUN_00BC64A0, register_doscript_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_doscript_LuaFuncDef`.
   */
  CScrLuaInitForm* register_doscript_LuaFuncDef();

  static_assert(sizeof(CScriptObject) == 0x34, "CScriptObject must be 0x34");
  static_assert(offsetof(CScriptObject, cObject) == 0x0C, "CScriptObject::cObject must be +0x0C");
  static_assert(offsetof(CScriptObject, mLuaObj) == 0x20, "CScriptObject::mLuaObj must be +0x20");
} // namespace moho
