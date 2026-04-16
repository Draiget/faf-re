#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "lua/LuaObject.h"
#include "moho/script/CScriptObject.h"
#include "moho/task/CTaskEvent.h"

namespace moho
{
  class CollisionBeamEntity;
  class CAimManipulator;
  class CBoneEntityManipulator;
  class CBuilderArmManipulator;
  class CAnimationManipulator;
  class CRotateManipulator;
  class CAiAttackerImpl;
  class CAiBrain;
  class CAiNavigatorImpl;
  class CAiPersonality;
  class CSlaveManipulator;
  class CThrustManipulator;
  class CPathDebugger;
  class CLobby;
  class CDiscoveryService;
  class CMauiBitmap;
  class CMauiBorder;
  class CMauiControl;
  class CMauiEdit;
  class CMauiCursor;
  class CMauiFrame;
  class CMauiHistogram;
  class CMauiLuaDragger;
  class CMauiMesh;
  class CMauiMovie;
  class CPlatoon;
  class CCollisionManipulator;
  class CUnitCommand;
  class CDamage;
  class CUnitScriptTask;
  class CSlideManipulator;
  class HSound;
  class IEffect;
  class CDecalHandle;
  class IAniManipulator;
  class MotorFallDown;
  class ScriptedDecal;
  class CUIMapPreview;
  class CUIWorldMesh;
  class CUIWorldView;
  class CameraImpl;
  class CMauiItemList;
  class CMauiScrollbar;
  class CMauiText;
  class Entity;
  class UserEntity;
  class Projectile;
  class Prop;
  class ReconBlip;
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
     * Address: 0x006D30F0 (FUN_006D30F0, ??0CScriptEvent@Moho@@QAE@@Z_0)
     *
     * What it does:
     * Constructs the script-event lane using one caller-supplied Lua
     * metatable/factory object plus three default Lua argument lanes.
     */
    explicit CScriptEvent(const LuaPlus::LuaObject& scriptFactory);

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
   * Address: 0x004C8270 (helper alias of script-object extraction lane)
   *
   * What it does:
   * Returns the `_c_object` userdata payload slot (`CScriptObject**`) for one
   * Lua game-object value, or `nullptr` when the payload is missing.
   */
  [[nodiscard]]
  CScriptObject** SCR_FromLua_CScriptObject(const LuaPlus::LuaObject& object);

  /**
   * Address: 0x004CBA60 (FUN_004CBA60, Moho::SCR_FromLua_CScriptEvent)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CScriptEvent*` and raises Lua
   * errors when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  CScriptEvent* SCR_FromLua_CScriptEvent(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

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
    * Alias of FUN_00593970 (non-canonical helper lane).
   *
   * What it does:
   * Converts one Lua object to `Unit*` without throwing conversion errors:
   * returns null when the payload is missing or of a non-unit runtime type.
   */
  [[nodiscard]]
  Unit* SCR_GetUnitOptional(const LuaPlus::LuaObject& object);

  /**
   * Address: 0x00623FF0 (FUN_00623FF0, Moho::SCR_FromLua_CUnitScriptTask)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CUnitScriptTask*` and raises Lua
   * errors when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  CUnitScriptTask* SCR_FromLua_CUnitScriptTask(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

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
   * Address: 0x006DD930 (FUN_006DD930, func_GetUnitWeaponOpt)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `UnitWeapon*`; raises Lua errors
   * for missing payload or wrong runtime type, and returns nullptr for
   * destroyed game objects.
   */
  [[nodiscard]]
  UnitWeapon* SCR_FromLua_UnitWeaponOpt(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x006332F0 (FUN_006332F0, Moho::SCR_FromLua_CAimManipulator)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CAimManipulator*` and raises Lua
   * errors when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  CAimManipulator* SCR_FromLua_CAimManipulator(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x00635390 (FUN_00635390, Moho::SCR_FromLua_CBoneEntityManipulator)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CBoneEntityManipulator*` and
   * raises Lua errors when payload is missing, destroyed, or of the wrong
   * runtime type.
   */
  [[nodiscard]]
  CBoneEntityManipulator* SCR_FromLua_CBoneEntityManipulator(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x006371D0 (FUN_006371D0, Moho::SCR_FromLua_CBuilderArmManipulator)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CBuilderArmManipulator*` and
   * raises Lua errors when payload is missing, destroyed, or of the wrong
   * runtime type.
   */
  [[nodiscard]]
  CBuilderArmManipulator* SCR_FromLua_CBuilderArmManipulator(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x00638AF0 (FUN_00638AF0, Moho::SCR_FromLua_CCollisionManipulator)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CCollisionManipulator*` and
   * raises Lua errors when payload is missing, destroyed, or of the wrong
   * runtime type.
   */
  [[nodiscard]]
  CCollisionManipulator* SCR_FromLua_CCollisionManipulator(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x0063CDE0 (FUN_0063CDE0, Moho::SCR_FromLua_IAniManipulator)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `IAniManipulator*` and raises Lua
   * errors when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  IAniManipulator* SCR_FromLua_IAniManipulator(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x0063CEB0 (FUN_0063CEB0, func_GetIAniManipulatorOpt)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `IAniManipulator*`; raises Lua
   * errors for missing payload or wrong runtime type, and returns nullptr for
   * destroyed game objects.
   */
  [[nodiscard]]
  IAniManipulator* SCR_FromLua_IAniManipulatorOpt(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x006585F0 (FUN_006585F0, Moho::SCR_FromLua_IEffect)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `IEffect*` and raises Lua errors
   * when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  IEffect* SCR_FromLua_IEffect(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x00670F90 (FUN_00670F90, func_GetIEffectOpt)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `IEffect*`; raises Lua errors for
   * missing payload or wrong runtime type, and returns nullptr for destroyed
   * game objects.
   */
  [[nodiscard]]
  IEffect* SCR_FromLua_IEffectOpt(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x00671050 (FUN_00671050, func_GetCDecalHandleOpt)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CDecalHandle*`; raises Lua
   * errors for missing payload or wrong runtime type, and returns nullptr for
   * destroyed game objects.
   */
  [[nodiscard]]
  CDecalHandle* SCR_FromLua_CDecalHandleOpt(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x006423E0 (FUN_006423E0, Moho::SCR_FromLua_CAnimationManipulator)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CAnimationManipulator*` and
   * raises Lua errors when payload is missing, destroyed, or of the wrong
   * runtime type.
   */
  [[nodiscard]]
  CAnimationManipulator* SCR_FromLua_CAnimationManipulator(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x00645560 (FUN_00645560, Moho::SCR_FromLua_CRotateManipulator)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CRotateManipulator*` and raises
   * Lua errors for missing, destroyed, or type-mismatched game objects.
   */
  [[nodiscard]]
  CRotateManipulator* SCR_FromLua_CRotateManipulator(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x00646900 (FUN_00646900, Moho::SCR_FromLua_CSlaveManipulator)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CSlaveManipulator*` and raises
   * Lua errors when payload is missing, destroyed, or of the wrong runtime
   * type.
   */
  [[nodiscard]]
  CSlaveManipulator* SCR_FromLua_CSlaveManipulator(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x0064B3A0 (FUN_0064B3A0, Moho::SCR_FromLua_CThrustManipulator)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CThrustManipulator*` and raises
   * Lua errors when payload is missing, destroyed, or of the wrong runtime
   * type.
   */
  [[nodiscard]]
  CThrustManipulator* SCR_FromLua_CThrustManipulator(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x00648710 (FUN_00648710, Moho::SCR_FromLua_CSlideManipulator)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CSlideManipulator*` and raises
   * Lua errors when payload is missing, destroyed, or of the wrong runtime
   * type.
   */
  [[nodiscard]]
  CSlideManipulator* SCR_FromLua_CSlideManipulator(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x006755F0 (FUN_006755F0, Moho::SCR_FromLua_CollisionBeamEntity)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CollisionBeamEntity*` and raises
   * Lua errors when payload is missing, destroyed, or of the wrong runtime
   * type.
   */
  [[nodiscard]]
  CollisionBeamEntity* SCR_FromLua_CollisionBeamEntity(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x00695E00 (FUN_00695E00, Moho::SCR_FromLua_MotorFallDown)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `MotorFallDown*` and raises Lua
   * errors when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  MotorFallDown* SCR_FromLua_MotorFallDown(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x006F8E40 (FUN_006F8E40, Moho::SCR_FromLua_CUnitCommand)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CUnitCommand*` and raises Lua
   * errors when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  CUnitCommand* SCR_FromLua_CUnitCommand(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x008AFCE0 (FUN_008AFCE0, func_GetHSoundOpt)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `HSound*`; raises Lua errors for
   * missing payload or wrong runtime type, and returns nullptr for destroyed
   * game objects.
   */
  [[nodiscard]]
  HSound* SCR_FromLua_HSoundOpt(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x00762460 (FUN_00762460, Moho::SCR_FromLua_HSound)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `HSound*` and raises Lua errors
   * when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  HSound* SCR_FromLua_HSound(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x007B62C0 (FUN_007B62C0, Moho::SCR_FromLua_CPathDebugger)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CPathDebugger*` and raises Lua
   * errors when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  CPathDebugger* SCR_FromLua_CPathDebugger(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x0073A830 (FUN_0073A830, Moho::SCR_FromLua_CDamage)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CDamage*` and raises Lua errors
   * when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  CDamage* SCR_FromLua_CDamage(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x008C6220 (FUN_008C6220, Moho::SCR_FromLua_UserEntity)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `UserEntity*` and raises Lua
   * errors when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  UserEntity* SCR_FromLua_UserEntity(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

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
   * Address: 0x00593A30 (FUN_00593A30, func_GetCPlatoonOpt)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CPlatoon*`; raises Lua errors for
   * missing payload or wrong runtime type, and returns nullptr for destroyed
   * game objects.
   */
  [[nodiscard]]
  CPlatoon* SCR_FromLua_CPlatoonOpt(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

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
   * Address: 0x00786210 (FUN_00786210, Moho::SCR_FromLua_CMauiBorder)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CMauiBorder*` and raises Lua
   * errors for missing, destroyed, or type-mismatched game objects.
   */
  [[nodiscard]]
  CMauiBorder* SCR_FromLua_CMauiBorder(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x0079EB20 (FUN_0079EB20, Moho::SCR_FromLua_CMauiMesh)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CMauiMesh*` and raises Lua
   * errors for missing, destroyed, or type-mismatched game objects.
   */
  [[nodiscard]]
  CMauiMesh* SCR_FromLua_CMauiMesh(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x007CB4A0 (FUN_007CB4A0, Moho::SCR_FromLua_CDiscoveryService)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CDiscoveryService*` and raises
   * Lua errors for missing, destroyed, or type-mismatched game objects.
   */
  [[nodiscard]]
  CDiscoveryService* SCR_FromLua_CDiscoveryService(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x007CB570 (FUN_007CB570, func_GetCDiscoveryServiceOpt)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CDiscoveryService*`; raises Lua
   * errors for missing payload or wrong runtime type, and returns nullptr for
   * destroyed game objects.
   */
  [[nodiscard]]
  CDiscoveryService* SCR_FromLua_CDiscoveryServiceOpt(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x007CB720 (FUN_007CB720, func_GetCLobbyOpt)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CLobby*`; raises Lua errors for
   * missing payload or wrong runtime type, and returns nullptr for destroyed
   * game objects.
   */
  [[nodiscard]]
  CLobby* SCR_FromLua_CLobbyOpt(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

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
   * Address: 0x0086D900 (FUN_0086D900, Moho::SCR_FromLua_CUIWorldMesh)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CUIWorldMesh*` and raises Lua
   * errors when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  CUIWorldMesh* SCR_FromLua_CUIWorldMesh(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x007989B0 (FUN_007989B0, Moho::SCR_FromLua_CMauiHistogram)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CMauiHistogram*` and raises Lua
   * errors when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  CMauiHistogram* SCR_FromLua_CMauiHistogram(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x00851440 (FUN_00851440, Moho::SCR_FromLua_CUIMapPreview)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CUIMapPreview*` and raises Lua
   * errors when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  CUIMapPreview* SCR_FromLua_CUIMapPreview(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x0078D9D0 (FUN_0078D9D0, Moho::SCR_FromLua_CMauiCursor)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CMauiCursor*` and raises Lua
   * errors when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  CMauiCursor* SCR_FromLua_CMauiCursor(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x0087FB30 (FUN_0087FB30, Moho::SCR_FromLua_ScriptedDecal)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `ScriptedDecal*` and raises Lua
   * errors when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  ScriptedDecal* SCR_FromLua_ScriptedDecal(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

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
   * Address: 0x007A01A0 (FUN_007A01A0, Moho::SCR_FromLua_CMauiMovie)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CMauiMovie*` and raises Lua
   * errors when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  CMauiMovie* SCR_FromLua_CMauiMovie(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x007A2760 (FUN_007A2760, Moho::SCR_FromLua_CMauiScrollbar)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CMauiScrollbar*` and raises Lua
   * errors when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  CMauiScrollbar* SCR_FromLua_CMauiScrollbar(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x007A42E0 (FUN_007A42E0, Moho::SCR_FromLua_CMauiText)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CMauiText*` and raises Lua
   * errors when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  CMauiText* SCR_FromLua_CMauiText(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

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
   * Address: 0x0078F560 (FUN_0078F560, Moho::SCR_FromLua_CMauiEdit)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CMauiEdit*` and raises Lua
   * errors when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  CMauiEdit* SCR_FromLua_CMauiEdit(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

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
   * Address: 0x0078E7B0 (FUN_0078E7B0, Moho::SCR_FromLua_CMauiFrame)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CMauiFrame*` and raises Lua
   * errors when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  CMauiFrame* SCR_FromLua_CMauiFrame(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x0078EA20 (FUN_0078EA20, Moho::SCR_FromLua_CMauiLuaDragger)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `CMauiLuaDragger*` and raises Lua
   * errors when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  CMauiLuaDragger* SCR_FromLua_CMauiLuaDragger(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

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
   * Address: 0x006208D0 (FUN_006208D0, func_GetEntityOpt)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `Entity*`; raises Lua errors for
   * missing payload or wrong runtime type, and returns nullptr for destroyed
   * game objects.
   */
  [[nodiscard]]
  Entity* SCR_FromLua_EntityOpt(const LuaPlus::LuaObject& object);

  /**
   * Address: 0x005C98E0 (FUN_005C98E0, Moho::SCR_FromLua_ReconBlip)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `ReconBlip*` and raises Lua
   * errors when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  ReconBlip* SCR_FromLua_ReconBlip(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

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
   * Address: 0x006A4590 (FUN_006A4590, func_GetProjectileOpt)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `Projectile*`; raises Lua errors
   * for missing payload or wrong runtime type, and returns nullptr for
   * destroyed game objects.
   */
  [[nodiscard]]
  Projectile* SCR_FromLua_ProjectileOpt(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Address: 0x006FD1C0 (FUN_006FD1C0, Moho::SCR_FromLua_Prop)
   *
   * What it does:
   * Converts one Lua `_c_object` payload to `Prop*` and raises Lua errors
   * when payload is missing, destroyed, or of the wrong runtime type.
   */
  [[nodiscard]]
  Prop* SCR_FromLua_Prop(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
    * Alias of FUN_004C9030 (non-canonical helper lane).
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

  /**
   * Address: 0x00BC6220 (FUN_00BC6220, CScriptEvent startup type-info registration)
   *
   * What it does:
   * Pre-registers `CScriptEvent` reflected type metadata and schedules
   * type-info cleanup at process exit.
   */
  void register_CScriptEventTypeInfo();

  /**
   * Address: 0x00BC6240 (FUN_00BC6240, register_CScriptEventSerializer)
   *
   * What it does:
   * Initializes startup serializer callback lanes for `CScriptEvent` and
   * schedules intrusive helper cleanup at process exit.
   */
  void register_CScriptEventSerializer();

  /**
   * Address: 0x004CA2D0 (FUN_004CA2D0, serializer cleanup alias A)
   * Address: 0x004CA300 (FUN_004CA300, serializer cleanup alias B)
   *
   * What it does:
   * Unlinks static serializer helper node from the intrusive helper list and
   * restores self-links.
   */
  gpg::SerHelperBase* cleanup_CScriptEventSerializer();
} // namespace moho
