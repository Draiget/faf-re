#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "lua/LuaObject.h"
#include "moho/script/CScriptObject.h"
#include "moho/task/CTaskEvent.h"

namespace moho
{
  class CAiAttackerImpl;
  class CAiBrain;
  class CAiNavigatorImpl;
  class CAiPersonality;
  class CLobby;
  class CMauiBitmap;
  class CMauiControl;
  class CPlatoon;
  class CUIWorldView;
  class CameraImpl;
  class CMauiItemList;
  class Entity;
  class Projectile;
  class Unit;
  class UnitWeapon;
  class UserUnit;

  class CScriptEvent : public CTaskEvent, public CScriptObject
  {
  public:
    /**
     * Address: 0x004C9420 (FUN_004C9420, ??0CScriptEvent@Moho@@QAE@@Z)
     *
     * What it does:
     * Constructs task-event and script-object subobjects, then installs
     * CScriptEvent vtables for both base views.
     */
    CScriptEvent();

    /**
     * Address: 0x004C94A0 (scalar deleting thunk)
     * Address: 0x004C94C0 (FUN_004C94C0, ??1CScriptEvent@Moho@@UAE@XZ)
     *
     * VFTable SLOT: 0
     */
    ~CScriptEvent() override;

    /**
     * Address: 0x004C93E0 (FUN_004C93E0, ?GetClass@CScriptEvent@Moho@@UBEPAVRType@gpg@@XZ)
     *
     * VFTable SLOT: 1 (CScriptObject subobject)
     */
    [[nodiscard]]
    gpg::RType* GetClass() const override;

    /**
     * Address: 0x004C9400 (FUN_004C9400, ?GetDerivedObjectRef@CScriptEvent@Moho@@UAE?AVRRef@gpg@@XZ)
     *
     * VFTable SLOT: 2 (CScriptObject subobject)
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x004CB820 (FUN_004CB820, Moho::CScriptEvent::MemberDeserialize)
     *
     * What it does:
     * Loads `CTaskEvent` and `CScriptObject` base subobjects from archive.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x004CB8A0 (FUN_004CB8A0, Moho::CScriptEvent::MemberSerialize)
     *
     * What it does:
     * Saves `CTaskEvent` and `CScriptObject` base subobjects into archive.
     */
    void MemberSerialize(gpg::WriteArchive* archive);

  public:
    static gpg::RType* sType;
  };

  class CScriptEventSerializer
  {
  public:
    /**
     * Address: 0x004CA280 (FUN_004CA280, Moho::CScriptEventSerializer::Deserialize)
     *
     * What it does:
     * Serializer load thunk forwarding into `CScriptEvent::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x004CA290 (FUN_004CA290, Moho::CScriptEventSerializer::Serialize)
     *
     * What it does:
     * Serializer save thunk forwarding into `CScriptEvent::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x004CB0A0 (FUN_004CB0A0, sub_4CB0A0)
     * Slot: 0
     *
     * What it does:
     * Binds CScriptEvent serializer callbacks into RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

  class CScriptEventTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x004CB760 (FUN_004CB760, Moho::CScriptEventTypeInfo::AddBase_CScriptObject)
     *
     * What it does:
     * Registers `CScriptObject` reflected base at subobject offset `0x10`.
     */
    static void AddBase_CScriptObject(gpg::RType* typeInfo);

    /**
     * Address: 0x004CB7C0 (FUN_004CB7C0, Moho::CScriptEventTypeInfo::AddBase_CTaskEvent)
     *
     * What it does:
     * Registers `CTaskEvent` reflected base at subobject offset `0x00`.
     */
    static void AddBase_CTaskEvent(gpg::RType* typeInfo);

    /**
     * Address: 0x004CA1D0 (FUN_004CA1D0, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~CScriptEventTypeInfo() override;

    /**
     * Address: 0x004CA1C0 (FUN_004CA1C0, ?GetName@CScriptEventTypeInfo@Moho@@UBEPBDXZ)
     * Slot: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x004CA170 (FUN_004CA170, ?Init@CScriptEventTypeInfo@Moho@@UAEXXZ)
     * Slot: 9
     */
    void Init() override;
  };

  /**
   * Address: 0x004C8270 (FUN_004C8270, func_GetCObj_CScriptObject)
   *
   * What it does:
   * Resolves `_c_object` from Lua userdata/table payload and returns the
   * underlying CScriptObject pointer.
   */
  [[nodiscard]]
  CScriptObject* SCR_GetScriptObjectFromLuaObject(const LuaPlus::LuaObject& object);

  /**
   * Address: 0x005936C0 (FUN_005936C0, Moho::SCR_FromLua_Unit)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `Unit*` and raises Lua errors when
   * payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  Unit* SCR_FromLua_Unit(const LuaPlus::LuaObject& object);

  /**
   * Address: 0x00633220 (FUN_00633220, Moho::SCR_FromLua_UnitWeapon)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `UnitWeapon*` and raises Lua
   * errors when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  UnitWeapon* SCR_FromLua_UnitWeapon(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x00822B80 (FUN_00822B80, Moho::SCR_FromLua_UserUnit)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `UserUnit*` and raises Lua errors
   * when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  UserUnit* SCR_FromLua_UserUnit(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x005930D0 (FUN_005930D0, Moho::SCR_FromLua_CAiBrain)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CAiBrain*` and raises Lua errors
   * when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  CAiBrain* SCR_FromLua_CAiBrain(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x005DEF90 (FUN_005DEF90, Moho::SCR_FromLua_CAiAttackerImpl)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CAiAttackerImpl*` and raises Lua
   * errors when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  CAiAttackerImpl* SCR_FromLua_CAiAttackerImpl(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x005BD320 (FUN_005BD320, Moho::SCR_FromLua_CAiPersonality)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CAiPersonality*` and raises Lua
   * errors when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  CAiPersonality* SCR_FromLua_CAiPersonality(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x005A7F50 (FUN_005A7F50, Moho::SCR_FromLua_CAiNavigatorImpl)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CAiNavigatorImpl*` and raises Lua
   * errors when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  CAiNavigatorImpl* SCR_FromLua_CAiNavigatorImpl(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x00593AF0 (FUN_00593AF0, Moho::SCR_FromLua_CPlatoon)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CPlatoon*` and raises Lua errors
   * when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  CPlatoon* SCR_FromLua_CPlatoon(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x007CB7E0 (FUN_007CB7E0, Moho::SCR_FromLua_CLobby)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CLobby*` and raises Lua errors
   * when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  CLobby* SCR_FromLua_CLobby(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x007B0E90 (FUN_007B0E90, Moho::SCR_FromLua_CameraImpl)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CameraImpl*` and raises Lua
   * errors when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  CameraImpl* SCR_FromLua_CameraImpl(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x00873A70 (FUN_00873A70, Moho::SCR_FromLua_CUIWorldView)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CUIWorldView*` and raises Lua
   * errors when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  CUIWorldView* SCR_FromLua_CUIWorldView(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x0079C9C0 (FUN_0079C9C0, Moho::SCR_FromLua_CMauiItemList)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CMauiItemList*` and raises Lua
   * errors when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  CMauiItemList* SCR_FromLua_CMauiItemList(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x00783BA0 (FUN_00783BA0, Moho::SCR_FromLua_CMauiControl)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CMauiControl*` and raises Lua
   * errors when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  CMauiControl* SCR_FromLua_CMauiControl(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x00783C70 (FUN_00783C70, Moho::SCR_FromLua_CMauiBitmap)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CMauiBitmap*` and raises Lua
   * errors when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  CMauiBitmap* SCR_FromLua_CMauiBitmap(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x005A8020 (FUN_005A8020, Moho::SCR_FromLua_Entity)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `Entity*` and raises Lua errors
   * when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  Entity* SCR_FromLua_Entity(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x005E3800 (FUN_005E3800, Moho::SCR_FromLuaNoError_Entity)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `Entity*` without raising Lua
   * errors; returns nullptr for missing, destroyed, or type-mismatched values.
   */
  [[nodiscard]]
  Entity* SCR_FromLuaNoError_Entity(const LuaPlus::LuaObject& object);

  /**
   * Address: 0x006A44C0 (FUN_006A44C0, Moho::SCR_FromLua_Projectile)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `Projectile*` and raises Lua
   * errors when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  Projectile* SCR_FromLua_Projectile(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x004C9030 (FUN_004C9030, func_RRefCScriptObject)
   *
   * What it does:
   * Builds an RTTI-aware `gpg::RRef` for a CScriptObject pointer.
   */
  [[nodiscard]]
  gpg::RRef SCR_MakeScriptObjectRef(CScriptObject* object);

  /**
   * Address: 0x004CBE30 (FUN_004CBE30, func_UpCastCScriptEventUnsafe)
   *
   * What it does:
   * Upcasts an arbitrary object reference to CScriptEvent and returns null
   * when cast fails.
   */
  [[nodiscard]]
  CScriptEvent* SCR_UpCastScriptEventUnsafe(const gpg::RRef& source);

  /**
   * Address: 0x004CB980 (FUN_004CB980, sub_4CB980)
   *
   * What it does:
   * Converts Lua payload object to CScriptEvent by chaining script-object
   * extraction and RTTI upcast.
   */
  [[nodiscard]]
  CScriptEvent* SCR_GetScriptEventFromLuaObject(const LuaPlus::LuaObject& object);

  static_assert(sizeof(CScriptEvent) == 0x44, "CScriptEvent size must be 0x44");
  static_assert(sizeof(CScriptEventSerializer) == 0x14, "CScriptEventSerializer size must be 0x14");
  static_assert(sizeof(CScriptEventTypeInfo) == 0x64, "CScriptEventTypeInfo size must be 0x64");
} // namespace moho
