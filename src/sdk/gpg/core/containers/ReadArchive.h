// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a reconstruction target; keep address docs in sync with recovered bodies.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>

#include "ArchiveSerialization.h"
#include "boost/shared_ptr.h"
#include "legacy/containers/Vector.h"

namespace msvc8
{
  struct string;
}

namespace LuaPlus
{
  class LuaState;
}

struct lua_State;
struct Table;
struct TString;
struct LClosure;
struct Udata;
struct Proto;
struct UpVal;

namespace moho
{
  template <class TEvent>
  class Listener;
  template <class TEvent>
  class ManyToOneListener;

  enum EFormationdStatus : std::int32_t;
  enum EAiNavigatorEvent : std::int32_t;
  enum EAiAttackerEvent : std::int32_t;
  enum EAiTransportEvent : std::int32_t;
  enum ECommandEvent : std::int32_t;
  enum EUnitCommandQueueStatus : std::int32_t;
  enum ECollisionBeamEvent : std::int32_t;
  enum EProjectileImpactEvent : std::int32_t;
  enum EAiResult : std::int32_t;
  class HSound;
  class CSndParams;
  struct REntityBlueprint;
  struct RMeshBlueprint;
  struct RUnitBlueprint;
  class RRuleGameRules;
  class ReconBlip;
  class IUnit;
  class CAniPose;
  class CAniActor;
  class IAniManipulator;
  class PathTables;
  class IPathTraveler;
  class Shield;
  class CArmyStats;
  class CArmyStatItem;
  class CAcquireTargetTask;
  class CAiAttackerImpl;
  class CTask;
  class CTaskThread;
  struct STaskEventLinkage;
  class StatItem;
  class CEconomy;
  class CEconomyEvent;
  class CCommandDb;
  class CUnitCommand;
  class CDecalBuffer;
  class CDecalHandle;
  class CParticleTexture;
  class CEntityDb;
  class Entity;
  class COGrid;
  class CInfluenceMap;
  class STIMap;
  class PathQueue;
  class CAiBrain;
  class CAiPathFinder;
  class CAiPathNavigator;
  class CAiPathSpline;
  class CAiPersonality;
  class CUnitCommandQueue;
  class CUnitMotion;
  class CFireWeaponTask;
  class CRandomStream;
  struct RProjectileBlueprint;
  class IEffect;
  class IEffectManager;
  class IAiAttacker;
  class IAiBuilder;
  class IAiCommandDispatch;
  class IAiFormationDB;
  class IAiNavigator;
  class IAiReconDB;
  class IAiSiloBuild;
  class IAiTransport;
  class IFormationInstance;
  class ISoundManager;
  class EntityMotor;
  class EntityCollisionUpdater;
  class IAiSteering;
  using CColPrimitiveBase = EntityCollisionUpdater;
  class CCommandTask;
  class CIntel;
  class CIntelPosHandle;
  class CTaskStage;
  struct CPathPoint;
  struct CEconRequest;
  struct PositionHistory;
  struct REmitterBlueprint;
  struct RTrailBlueprint;
  struct RUnitBlueprintWeapon;
  struct SPhysConstants;
  struct SPhysBody;
  struct SNavPath;
  class Sim;
  class SimArmy;
  class CPlatoon;
  class Unit;
  class UnitWeapon;
  class EntitySetBase;
}

namespace gpg
{
  class RIndexed;
  class RRef;
  class RType;

  /**
   * VFTABLE: 0x00D48D14
   * COL:  0x00E53B84
   */
  class ReadArchive
  {
  public:
    /**
     * Address: 0x00952B60 (FUN_00952B60, ??0ReadArchive@gpg@@QAE@XZ)
     *
     * What it does:
     * Initializes tracked-type and tracked-pointer tables to empty state and
     * resets the null tracked-pointer sentinel to the reserved ownership lane.
     */
    ReadArchive();

    /**
     * Address: 0x00953700 (FUN_00953700)
     * Demangled: gpg::ReadArchive::dtr
     *
     * What it does:
     * Destroys read-archive bookkeeping state.
     */
    virtual ~ReadArchive();

    /**
     * Address: 0x00A82547
     * Slot: 1
     * Demangled: _purecall
     */
    virtual void ReadBytes(char*, size_t) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 2
     * Demangled: _purecall
     */
    virtual void ReadString(msvc8::string*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 3
     * Demangled: _purecall
     */
    virtual void ReadFloat(float*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 4
     * Demangled: _purecall
     */
    virtual void ReadUInt64(unsigned __int64*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 5
     * Demangled: _purecall
     */
    virtual void ReadInt64(__int64*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 6
     * Demangled: _purecall
     */
    virtual void ReadULong(unsigned long*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 7
     * Demangled: _purecall
     */
    virtual void ReadLong(long*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 8
     * Demangled: _purecall
     */
    virtual void ReadUInt(unsigned int*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 9
     * Demangled: _purecall
     */
    virtual void ReadInt(int*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 10
     * Demangled: _purecall
     */
    virtual void ReadUShort(unsigned short*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 11
     * Demangled: _purecall
     */
    virtual void ReadShort(short*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 12
     * Demangled: _purecall
     */
    virtual void ReadUByte(unsigned __int8*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 13
     * Demangled: _purecall
     */
    virtual void ReadByte(__int8*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 14
     * Demangled: _purecall
     */
    virtual void ReadBool(bool*) = 0;

    /**
     * Address: 0x00952BD0 (FUN_00952BD0)
     * Slot: 15
     * Demangled: public: virtual void __thiscall gpg::ReadArchive::EndSection(bool)
     *
     * What it does:
     * Releases tracked pointer/type-handle section state.
     */
    virtual void EndSection(bool);

    /**
     * Address: 0x00A82547
     * Slot: 16
     * Demangled: _purecall
     */
    virtual int NextMarker() = 0;

    /**
     * Address: 0x00953DA0 (FUN_00953DA0)
     * Demangled: public: void __thiscall gpg::ReadArchive::Read(class gpg::RType const *,void *,class gpg::RRef const
     * &)
     *
     * What it does:
     * Reads one typed object payload using reflection serializer callbacks.
     */
    void Read(const gpg::RType* type, void* object, const gpg::RRef& ownerRef);

    /**
     * Address: 0x004C1520 (FUN_004C1520, gpg::ReadArchive::ReadPointer_LuaState)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to `LuaPlus::LuaState`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_LuaState(LuaPlus::LuaState** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x004CC550 (FUN_004CC550, gpg::ReadArchive::ReadPointerOwned_LuaState)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `LuaPlus::LuaState`.
     */
    ReadArchive* ReadPointerOwned_LuaState(LuaPlus::LuaState** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x0090BA60 (FUN_0090BA60, gpg::ReadArchive::ReadPointer_lua_State)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to C Lua `lua_State`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_lua_State(lua_State** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00921950 (FUN_00921950, gpg::ReadArchive::ReadPointer_Table)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to Lua `Table`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_Table(Table** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00921830 (FUN_00921830, gpg::ReadArchive::ReadPointer_TString)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to Lua `TString`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_TString(TString** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00921A70 (FUN_00921A70, gpg::ReadArchive::ReadPointer_LClosure)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to Lua `LClosure`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_LClosure(LClosure** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00921B90 (FUN_00921B90, gpg::ReadArchive::ReadPointer_Udata)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to Lua `Udata`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_Udata(Udata** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00921CB0 (FUN_00921CB0, gpg::ReadArchive::ReadPointer_Proto)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to Lua `Proto`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_Proto(Proto** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00921DD0 (FUN_00921DD0, gpg::ReadArchive::ReadPointer_UpVal)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to Lua `UpVal`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_UpVal(UpVal** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x004E63A0 (FUN_004E63A0, gpg::ReadArchive::ReadPointer_CSndParams)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to `moho::CSndParams`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_CSndParams(moho::CSndParams** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x0055A920 (FUN_0055A920, gpg::ReadArchive::ReadPointer_CSndParams2)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to `moho::CSndParams`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_CSndParams2(moho::CSndParams** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x004E64E0 (FUN_004E64E0, gpg::ReadArchive::ReadPointer_HSound)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to `moho::HSound`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_HSound(moho::HSound** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00511790 (FUN_00511790, gpg::ReadArchive::ReadPointer_RRuleGameRules2)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::RRuleGameRules`, throwing `SerializationError` on
     * pointee-type mismatch.
     */
    ReadArchive* ReadPointer_RRuleGameRules(moho::RRuleGameRules** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00554E80 (FUN_00554E80, gpg::ReadArchive::ReadPointer_REntityBlueprint)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::REntityBlueprint`, throwing `SerializationError` on
     * pointee-type mismatch.
     */
    ReadArchive* ReadPointer_REntityBlueprint(moho::REntityBlueprint** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x0055A7E0 (FUN_0055A7E0, gpg::ReadArchive::ReadPointer_RMeshBlueprint)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::RMeshBlueprint`, throwing `SerializationError` on
     * pointee-type mismatch.
     */
    ReadArchive* ReadPointer_RMeshBlueprint(moho::RMeshBlueprint** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x0055F640 (FUN_0055F640, gpg::ReadArchive::ReadPointer_RUnitBlueprint)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::RUnitBlueprint`, throwing `SerializationError` on
     * pointee-type mismatch.
     */
    ReadArchive* ReadPointer_RUnitBlueprint(moho::RUnitBlueprint** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00527480 (FUN_00527480, gpg::ReadArchive::ReadPointer_RUnitBlueprint2)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::RUnitBlueprint`, throwing `SerializationError` on
     * pointee-type mismatch.
     */
    ReadArchive* ReadPointer_RUnitBlueprint2(moho::RUnitBlueprint** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00584D30 (FUN_00584D30, gpg::ReadArchive::ReadPointer_SimArmy)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to `moho::SimArmy`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_SimArmy(moho::SimArmy** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00584E70 (FUN_00584E70, gpg::ReadArchive::ReadPointerOwned_CAiPersonality)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::CAiPersonality`.
     */
    ReadArchive* ReadPointerOwned_CAiPersonality(moho::CAiPersonality** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x005850F0 (FUN_005850F0, gpg::ReadArchive::ReadPointerOwned_CTaskStage)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::CTaskStage`.
     */
    ReadArchive* ReadPointerOwned_CTaskStage(moho::CTaskStage** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x0040B530 (FUN_0040B530, gpg::ReadArchive::ReadPointerOwned_CTask)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::CTask`.
     */
    ReadArchive* ReadPointerOwned_CTask(moho::CTask** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x0040B640 (FUN_0040B640, gpg::ReadArchive::ReadPointer_CTask)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to `moho::CTask`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_CTask(moho::CTask** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x0040B800 (FUN_0040B800, gpg::ReadArchive::ReadPointerOwned_CTaskThread)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::CTaskThread`.
     */
    ReadArchive* ReadPointerOwned_CTaskThread(moho::CTaskThread** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x0040C4A0 (FUN_0040C4A0, gpg::ReadArchive::ReadPointer_CTaskThread)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to `moho::CTaskThread`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_CTaskThread(moho::CTaskThread** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x0040D650 (FUN_0040D650, gpg::ReadArchive::ReadPointer_CTaskStage)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to `moho::CTaskStage`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_CTaskStage(moho::CTaskStage** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x0041A3D0 (FUN_0041A3D0, gpg::ReadArchive::ReadPointerOwned_StatItem)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::StatItem`.
     */
    ReadArchive* ReadPointerOwned_StatItem(moho::StatItem** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x004081E0 (FUN_004081E0, gpg::ReadArchive::ReadPointer_STaskEventLinkage)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::STaskEventLinkage`, throwing `SerializationError` on
     * pointee-type mismatch.
     */
    ReadArchive* ReadPointer_STaskEventLinkage(moho::STaskEventLinkage** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00407A50 (FUN_00407A50, gpg::ReadArchive::ReadPointerOwned_STaskEventLinkage)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::STaskEventLinkage`.
     */
    ReadArchive* ReadPointerOwned_STaskEventLinkage(
      moho::STaskEventLinkage** outValue, const gpg::RRef* ownerRef
    );

    /**
     * Address: 0x00584FB0 (FUN_00584FB0, gpg::ReadArchive::ReadPointer_Sim)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to `moho::Sim`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_Sim(moho::Sim** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00750FD0 (FUN_00750FD0, gpg::ReadArchive::ReadPointerOwned_SimArmy)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::SimArmy`.
     */
    ReadArchive* ReadPointerOwned_SimArmy(moho::SimArmy** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x0059E810 (FUN_0059E810, gpg::ReadArchive::ReadPointer_IFormationInstance)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::IFormationInstance`, throwing `SerializationError` on
     * pointee-type mismatch.
     */
    ReadArchive* ReadPointer_IFormationInstance(moho::IFormationInstance** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00571230 (FUN_00571230, gpg::ReadArchive::ReadPointer_Listener_EFormationdStatus)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::Listener<moho::EFormationdStatus>`, throwing
     * `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_Listener_EFormationdStatus(
      moho::Listener<moho::EFormationdStatus>** outValue, const gpg::RRef* ownerRef
    );

    /**
     * Address: 0x00599ED0 (FUN_00599ED0, gpg::ReadArchive::ReadPointer_CUnitCommandQueue)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::CUnitCommandQueue`, throwing `SerializationError` on
     * pointee-type mismatch.
     */
    ReadArchive* ReadPointer_CUnitCommandQueue(moho::CUnitCommandQueue** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x005F5100 (FUN_005F5100, gpg::ReadArchive::ReadPointer_CUnitCommand)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::CUnitCommand`, throwing `SerializationError` on
     * pointee-type mismatch.
     */
    ReadArchive* ReadPointer_CUnitCommand(moho::CUnitCommand** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x005A2900 (FUN_005A2900, gpg::ReadArchive::ReadPointer_Unit)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to `moho::Unit`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_Unit(moho::Unit** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x005A8130 (FUN_005A8130, gpg::ReadArchive::ReadPointer_Listener_EAiNavigatorEvent)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::Listener<moho::EAiNavigatorEvent>`, throwing
     * `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_Listener_EAiNavigatorEvent(
      moho::Listener<moho::EAiNavigatorEvent>** outValue, const gpg::RRef* ownerRef
    );

    /**
     * Address: 0x00541E00 (FUN_00541E00, gpg::ReadArchive::ReadPointer_IUnit)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to `moho::IUnit`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_IUnit(moho::IUnit** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x005AC9A0 (FUN_005AC9A0, gpg::ReadArchive::ReadPointer_PathQueue)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to `moho::PathQueue`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_PathQueue(moho::PathQueue** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x005096E0 (FUN_005096E0, gpg::ReadArchive::ReadPointer_STIMap)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to `moho::STIMap`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_STIMap(moho::STIMap** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x005ACAE0 (FUN_005ACAE0, gpg::ReadArchive::ReadPointer_COGrid)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to `moho::COGrid`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_COGrid(moho::COGrid** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x005A98A0 (FUN_005A98A0, gpg::ReadArchive::ReadPointerOwned_CAiPathNavigator)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::CAiPathNavigator`.
     */
    ReadArchive* ReadPointerOwned_CAiPathNavigator(moho::CAiPathNavigator** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x005B1A50 (FUN_005B1A50, gpg::ReadArchive::ReadPointerOwned_CAiPathFinder)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::CAiPathFinder`.
     */
    ReadArchive* ReadPointerOwned_CAiPathFinder(moho::CAiPathFinder** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x005CC370 (FUN_005CC370, gpg::ReadArchive::ReadPointer_ReconBlip)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to `moho::ReconBlip`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_ReconBlip(moho::ReconBlip** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x005CE0E0 (FUN_005CE0E0, gpg::ReadArchive::ReadPointer_CInfluenceMap)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::CInfluenceMap`, throwing `SerializationError` on
     * pointee-type mismatch.
     */
    ReadArchive* ReadPointer_CInfluenceMap(moho::CInfluenceMap** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x005D13E0 (FUN_005D13E0, gpg::ReadArchive::ReadPointer_UnitWeapon)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to `moho::UnitWeapon`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_UnitWeapon(moho::UnitWeapon** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x005DEC30 (FUN_005DEC30, gpg::ReadArchive::ReadPointerOwned_UnitWeapon)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::UnitWeapon`.
     */
    ReadArchive* ReadPointerOwned_UnitWeapon(moho::UnitWeapon** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x005DED40 (FUN_005DED40, gpg::ReadArchive::ReadPointerOwned_CAcquireTargetTask)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::CAcquireTargetTask`.
     */
    ReadArchive* ReadPointerOwned_CAcquireTargetTask(moho::CAcquireTargetTask** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x005D4FE0 (FUN_005D4FE0, gpg::ReadArchive::ReadPointerOwned_CAiPathSpline)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::CAiPathSpline`.
     */
    ReadArchive* ReadPointerOwned_CAiPathSpline(moho::CAiPathSpline** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x005D5120 (FUN_005D5120, gpg::ReadArchive::ReadPointer_CUnitMotion)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to `moho::CUnitMotion`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_CUnitMotion(moho::CUnitMotion** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x005E10B0 (FUN_005E10B0, gpg::ReadArchive::ReadPointer_CAcquireTargetTask)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::CAcquireTargetTask`, throwing `SerializationError` on
     * pointee-type mismatch.
     */
    ReadArchive* ReadPointer_CAcquireTargetTask(moho::CAcquireTargetTask** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x005E21D0 (FUN_005E21D0, gpg::ReadArchive::ReadPointer_CAiAttackerImpl)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::CAiAttackerImpl`, throwing `SerializationError` on
     * pointee-type mismatch.
     */
    ReadArchive* ReadPointer_CAiAttackerImpl(moho::CAiAttackerImpl** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x005DF0F0 (FUN_005DF0F0, gpg::ReadArchive::ReadPointer_Listener_EAiAttackerEvent)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::Listener<moho::EAiAttackerEvent>`, throwing
     * `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_Listener_EAiAttackerEvent(
      moho::Listener<moho::EAiAttackerEvent>** outValue, const gpg::RRef* ownerRef
    );

    /**
     * Address: 0x005EC540 (FUN_005EC540, gpg::ReadArchive::ReadPointer_Listener_EAiTransportEvent)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::Listener<moho::EAiTransportEvent>`, throwing
     * `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_Listener_EAiTransportEvent(
      moho::Listener<moho::EAiTransportEvent>** outValue, const gpg::RRef* ownerRef
    );

    /**
     * Address: 0x005F2170 (FUN_005F2170, gpg::ReadArchive::ReadPointer_CCommandTask)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to `moho::CCommandTask`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_CCommandTask(moho::CCommandTask** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x0060D940 (FUN_0060D940, gpg::ReadArchive::ReadPointer_EAiResult)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to `moho::EAiResult`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_EAiResult(moho::EAiResult** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00633FB0 (FUN_00633FB0, gpg::ReadArchive::ReadPointer_RUnitBlueprintWeapon)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::RUnitBlueprintWeapon`, throwing `SerializationError` on
     * pointee-type mismatch.
     */
    ReadArchive* ReadPointer_RUnitBlueprintWeapon(
      moho::RUnitBlueprintWeapon** outValue, const gpg::RRef* ownerRef
    );

    /**
     * Address: 0x006340F0 (FUN_006340F0, gpg::ReadArchive::ReadPointer_RProjectileBlueprint)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::RProjectileBlueprint`, throwing `SerializationError` on
     * pointee-type mismatch.
     */
    ReadArchive* ReadPointer_RProjectileBlueprint(
      moho::RProjectileBlueprint** outValue, const gpg::RRef* ownerRef
    );

    /**
     * Address: 0x006607B0 (FUN_006607B0, gpg::ReadArchive::ReadPointer_REmitterBlueprint)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::REmitterBlueprint`, throwing `SerializationError` on
     * pointee-type mismatch.
     */
    ReadArchive* ReadPointer_REmitterBlueprint(moho::REmitterBlueprint** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x006729C0 (FUN_006729C0, gpg::ReadArchive::ReadPointer_RTrailBlueprint)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::RTrailBlueprint`, throwing `SerializationError` on
     * pointee-type mismatch.
     */
    ReadArchive* ReadPointer_RTrailBlueprint(moho::RTrailBlueprint** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x0063E530 (FUN_0063E530, gpg::ReadArchive::ReadPointer_CAniPose)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to `moho::CAniPose`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_CAniPose(moho::CAniPose** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x0063EC70 (FUN_0063EC70, gpg::ReadArchive::ReadPointer_CAniActor)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to `moho::CAniActor`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_CAniActor(moho::CAniActor** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x0065A810 (FUN_0065A810, gpg::ReadArchive::ReadPointer_CParticleTexture)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> SHARED` ownership
     * transition, and upcasts the pointee to `moho::CParticleTexture`.
     */
    ReadArchive* ReadPointer_CParticleTexture(moho::CParticleTexture** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x006761B0 (FUN_006761B0, gpg::ReadArchive::ReadPointer_IEffect)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to `moho::IEffect`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_IEffect(moho::IEffect** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x006756E0 (FUN_006756E0, gpg::ReadArchive::ReadPointer_ManyToOneListener_ECollisionBeamEvent)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::ManyToOneListener<moho::ECollisionBeamEvent>`, throwing
     * `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_ManyToOneListener_ECollisionBeamEvent(
      moho::ManyToOneListener<moho::ECollisionBeamEvent>** outValue, const gpg::RRef* ownerRef
    );

    /**
     * Address: 0x00698900 (FUN_00698900, gpg::ReadArchive::ReadPointer_SPhysConstants)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::SPhysConstants`, throwing `SerializationError` on
     * pointee-type mismatch.
     */
    ReadArchive* ReadPointer_SPhysConstants(moho::SPhysConstants** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x0069F920 (FUN_0069F920, gpg::ReadArchive::ReadPointer_ManyToOneListener_EProjectileImpactEvent)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::ManyToOneListener<moho::EProjectileImpactEvent>`, throwing
     * `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_ManyToOneListener_EProjectileImpactEvent(
      moho::ManyToOneListener<moho::EProjectileImpactEvent>** outValue, const gpg::RRef* ownerRef
    );

    /**
     * Address: 0x006E0500 (FUN_006E0500, gpg::ReadArchive::ReadPointer_IAiAttacker)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::IAiAttacker`, throwing `SerializationError` on
     * pointee-type mismatch.
     */
    ReadArchive* ReadPointer_IAiAttacker(moho::IAiAttacker** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x006EB870 (FUN_006EB870, gpg::ReadArchive::ReadPointer_Listener_ECommandEvent)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::Listener<moho::ECommandEvent>`, throwing `SerializationError`
     * on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_Listener_ECommandEvent(
      moho::Listener<moho::ECommandEvent>** outValue, const gpg::RRef* ownerRef
    );

    /**
     * Address: 0x006F8F60 (FUN_006F8F60, gpg::ReadArchive::ReadPointer_Listener_EUnitCommandQueueStatus)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::Listener<moho::EUnitCommandQueueStatus>`, throwing
     * `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_Listener_EUnitCommandQueueStatus(
      moho::Listener<moho::EUnitCommandQueueStatus>** outValue, const gpg::RRef* ownerRef
    );

    /**
     * Address: 0x00713F30 (FUN_00713F30, gpg::ReadArchive::ReadPointer_CAiBrain)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to `moho::CAiBrain`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_CAiBrain(moho::CAiBrain** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x007703A0 (FUN_007703A0, gpg::ReadArchive::ReadPointer_IAiReconDB)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::IAiReconDB`, throwing `SerializationError` on
     * pointee-type mismatch.
     */
    ReadArchive* ReadPointer_IAiReconDB(moho::IAiReconDB** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00763C80 (FUN_00763C80, gpg::ReadArchive::ReadPointer_Listener_NavPath)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::Listener<const moho::SNavPath&>`, throwing
     * `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_Listener_NavPath(
      moho::Listener<const moho::SNavPath&>** outValue, const gpg::RRef* ownerRef
    );

    /**
     * Address: 0x00771550 (FUN_00771550, gpg::ReadArchive::ReadPointer_IEffectManager)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::IEffectManager`, throwing `SerializationError` on
     * pointee-type mismatch.
     */
    ReadArchive* ReadPointer_IEffectManager(moho::IEffectManager** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x006895A0 (FUN_006895A0, gpg::ReadArchive::ReadPointer_EntitySetBase)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::EntitySetBase`, throwing `SerializationError` on
     * pointee-type mismatch.
     */
    ReadArchive* ReadPointer_EntitySetBase(moho::EntitySetBase** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x006BC1E0 (FUN_006BC1E0, gpg::ReadArchive::ReadPointer_CPathPoint)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to `moho::CPathPoint`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_CPathPoint(moho::CPathPoint** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x007545A0 (FUN_007545A0, gpg::ReadArchive::ReadPointer_Shield)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to `moho::Shield`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_Shield(moho::Shield** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x0076A8E0 (FUN_0076A8E0, gpg::ReadArchive::ReadPointer_IPathTraveler)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::IPathTraveler`, throwing `SerializationError` on
     * pointee-type mismatch.
     */
    ReadArchive* ReadPointer_IPathTraveler(moho::IPathTraveler** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x0076B1C0 (FUN_0076B1C0, gpg::ReadArchive::ReadPointer_PathTables)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to `moho::PathTables`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_PathTables(moho::PathTables** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x007745F0 (FUN_007745F0, gpg::ReadArchive::ReadPointer_CEconRequest)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::CEconRequest`, throwing `SerializationError` on
     * pointee-type mismatch.
     */
    ReadArchive* ReadPointer_CEconRequest(moho::CEconRequest** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x005D1AD0 (FUN_005D1AD0, gpg::ReadArchive::ReadPointerOwned_CEconRequest)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::CEconRequest`.
     */
    ReadArchive* ReadPointerOwned_CEconRequest(moho::CEconRequest** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00774BF0 (FUN_00774BF0, gpg::ReadArchive::ReadPointer_CEconomy)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to `moho::CEconomy`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_CEconomy(moho::CEconomy** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x007070A0 (FUN_007070A0, gpg::ReadArchive::ReadPointerOwned_CEconomy)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::CEconomy`.
     */
    ReadArchive* ReadPointerOwned_CEconomy(moho::CEconomy** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x007040E0 (FUN_007040E0, gpg::ReadArchive::ReadPointerOwned_CPlatoon)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::CPlatoon`.
     */
    ReadArchive* ReadPointerOwned_CPlatoon(moho::CPlatoon** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x0063CB90 (FUN_0063CB90, gpg::ReadArchive::ReadPointerOwned_IAniManipulator)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::IAniManipulator`.
     */
    ReadArchive* ReadPointerOwned_IAniManipulator(moho::IAniManipulator** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x0066C350 (FUN_0066C350, gpg::ReadArchive::ReadPointerOwned_IEffect)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::IEffect`.
     */
    ReadArchive* ReadPointerOwned_IEffect(moho::IEffect** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x006B10F0 (FUN_006B10F0, gpg::ReadArchive::ReadPointerOwned_CEconomyEvent)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::CEconomyEvent`.
     */
    ReadArchive* ReadPointerOwned_CEconomyEvent(moho::CEconomyEvent** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x006E2B60 (FUN_006E2B60, gpg::ReadArchive::ReadPointerOwned_CUnitCommand)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::CUnitCommand`.
     */
    ReadArchive* ReadPointerOwned_CUnitCommand(moho::CUnitCommand** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00682EF0 (FUN_00682EF0, gpg::ReadArchive::ReadPointerOwned_SPhysBody)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::SPhysBody`.
     */
    ReadArchive* ReadPointerOwned_SPhysBody(moho::SPhysBody** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00683030 (FUN_00683030, gpg::ReadArchive::ReadPointerOwned_Motor)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::EntityMotor`.
     */
    ReadArchive* ReadPointerOwned_Motor(moho::EntityMotor** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x006829F0 (FUN_006829F0, gpg::ReadArchive::ReadPointerOwned_PositionHistory)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::PositionHistory`.
     */
    ReadArchive* ReadPointerOwned_PositionHistory(moho::PositionHistory** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00682B30 (FUN_00682B30, gpg::ReadArchive::ReadPointerOwned_CColPrimitiveBase)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::CColPrimitiveBase`.
     */
    ReadArchive* ReadPointerOwned_CColPrimitiveBase(moho::CColPrimitiveBase** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00682C70 (FUN_00682C70, gpg::ReadArchive::ReadPointerOwned_CIntel)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::CIntel`.
     */
    ReadArchive* ReadPointerOwned_CIntel(moho::CIntel** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00680FB0 (FUN_00680FB0, gpg::ReadArchive::ReadPointer_Entity)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts the pointee to `moho::Entity`
     * without consuming ownership state.
     */
    ReadArchive* ReadPointer_Entity(moho::Entity** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00688AC0 (FUN_00688AC0, gpg::ReadArchive::ReadPointerOwned_Entity)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::Entity`.
     */
    ReadArchive* ReadPointerOwned_Entity(moho::Entity** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x006B4A70 (FUN_006B4A70, gpg::ReadArchive::ReadPointerOwned_IAiSteering)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::IAiSteering`.
     */
    ReadArchive* ReadPointerOwned_IAiSteering(moho::IAiSteering** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x006B4BB0 (FUN_006B4BB0, gpg::ReadArchive::ReadPointerOwned_CUnitMotion)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::CUnitMotion`.
     */
    ReadArchive* ReadPointerOwned_CUnitMotion(moho::CUnitMotion** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x006B4CF0 (FUN_006B4CF0, gpg::ReadArchive::ReadPointerOwned_CUnitCommandQueue)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::CUnitCommandQueue`.
     */
    ReadArchive* ReadPointerOwned_CUnitCommandQueue(moho::CUnitCommandQueue** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x006B5330 (FUN_006B5330, gpg::ReadArchive::ReadPointerOwned_IAiCommandDispatch)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::IAiCommandDispatch`.
     */
    ReadArchive* ReadPointerOwned_IAiCommandDispatch(moho::IAiCommandDispatch** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x006B5470 (FUN_006B5470, gpg::ReadArchive::ReadPointerOwned_IAiNavigator)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::IAiNavigator`.
     */
    ReadArchive* ReadPointerOwned_IAiNavigator(moho::IAiNavigator** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x006B55B0 (FUN_006B55B0, gpg::ReadArchive::ReadPointerOwned_IAiBuilder)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::IAiBuilder`.
     */
    ReadArchive* ReadPointerOwned_IAiBuilder(moho::IAiBuilder** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00706E20 (FUN_00706E20, gpg::ReadArchive::ReadPointerOwned_CAiBrain)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::CAiBrain`.
     */
    ReadArchive* ReadPointerOwned_CAiBrain(moho::CAiBrain** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00706F60 (FUN_00706F60, gpg::ReadArchive::ReadPointerOwned_IAiReconDB)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::IAiReconDB`.
     */
    ReadArchive* ReadPointerOwned_IAiReconDB(moho::IAiReconDB** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x006B4E30 (FUN_006B4E30, gpg::ReadArchive::ReadPointerOwned_IFormationInstance)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::IFormationInstance`.
     */
    ReadArchive* ReadPointerOwned_IFormationInstance(moho::IFormationInstance** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x006B50B0 (FUN_006B50B0, gpg::ReadArchive::ReadPointerOwned_CAniActor)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::CAniActor`.
     */
    ReadArchive* ReadPointerOwned_CAniActor(moho::CAniActor** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x006B51F0 (FUN_006B51F0, gpg::ReadArchive::ReadPointerOwned_IAiAttacker)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::IAiAttacker`.
     */
    ReadArchive* ReadPointerOwned_IAiAttacker(moho::IAiAttacker** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x006B56F0 (FUN_006B56F0, gpg::ReadArchive::ReadPointerOwned_IAiSiloBuild)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::IAiSiloBuild`.
     */
    ReadArchive* ReadPointerOwned_IAiSiloBuild(moho::IAiSiloBuild** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x006B5830 (FUN_006B5830, gpg::ReadArchive::ReadPointerOwned_IAiTransport)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::IAiTransport`.
     */
    ReadArchive* ReadPointerOwned_IAiTransport(moho::IAiTransport** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x006E0640 (FUN_006E0640, gpg::ReadArchive::ReadPointerOwned_CFireWeaponTask)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::CFireWeaponTask`.
     */
    ReadArchive* ReadPointerOwned_CFireWeaponTask(moho::CFireWeaponTask** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x006EB9E0 (FUN_006EB9E0, gpg::ReadArchive::ReadPointerWeak_IFormationInstance)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> SHARED` ownership
     * transition, and upcasts the pointee to `moho::IFormationInstance`.
     */
    ReadArchive* ReadPointerWeak_IFormationInstance(moho::IFormationInstance** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x007071E0 (FUN_007071E0, gpg::ReadArchive::ReadPointerOwned_CArmyStats)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::CArmyStats`.
     */
    ReadArchive* ReadPointerOwned_CArmyStats(moho::CArmyStats** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00707320 (FUN_00707320, gpg::ReadArchive::ReadPointerOwned_CInfluenceMap)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::CInfluenceMap`.
     */
    ReadArchive* ReadPointerOwned_CInfluenceMap(moho::CInfluenceMap** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00714070 (FUN_00714070, gpg::ReadArchive::ReadPointerOwned_CArmyStatItem)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::CArmyStatItem`.
     */
    ReadArchive* ReadPointerOwned_CArmyStatItem(moho::CArmyStatItem** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x007141B0 (FUN_007141B0, gpg::ReadArchive::ReadPointer_CArmyStatItem)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to `moho::CArmyStatItem`,
     * throwing `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_CArmyStatItem(moho::CArmyStatItem** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00757540 (FUN_00757540, gpg::ReadArchive::ReadPointerOwned_CRandomStream)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::CRandomStream`.
     */
    ReadArchive* ReadPointerOwned_CRandomStream(moho::CRandomStream** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00757680 (FUN_00757680, gpg::ReadArchive::ReadPointerOwned_SPhysConstants)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::SPhysConstants`.
     */
    ReadArchive* ReadPointerOwned_SPhysConstants(moho::SPhysConstants** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x007577C0 (FUN_007577C0, gpg::ReadArchive::ReadPointerOwned_IAiFormationDB)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::IAiFormationDB`.
     */
    ReadArchive* ReadPointerOwned_IAiFormationDB(moho::IAiFormationDB** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00757B10 (FUN_00757B10, gpg::ReadArchive::ReadPointerOwned_CCommandDB)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::CCommandDb`.
     */
    ReadArchive* ReadPointerOwned_CCommandDB(moho::CCommandDb** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00757C50 (FUN_00757C50, gpg::ReadArchive::ReadPointerOwned_CDecalBuffer)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::CDecalBuffer`.
     */
    ReadArchive* ReadPointerOwned_CDecalBuffer(moho::CDecalBuffer** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00757D90 (FUN_00757D90, gpg::ReadArchive::ReadPointerOwned_IEffectManager)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::IEffectManager`.
     */
    ReadArchive* ReadPointerOwned_IEffectManager(moho::IEffectManager** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00757ED0 (FUN_00757ED0, gpg::ReadArchive::ReadPointerOwned_ISoundManager)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::ISoundManager`.
     */
    ReadArchive* ReadPointerOwned_ISoundManager(moho::ISoundManager** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00758010 (FUN_00758010, gpg::ReadArchive::ReadPointerOwned_EntityDB)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::CEntityDb`.
     */
    ReadArchive* ReadPointerOwned_EntityDB(moho::CEntityDb** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x0076EC30 (FUN_0076EC30, gpg::ReadArchive::ReadPointerOwned_CIntelPosHandle)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::CIntelPosHandle`.
     */
    ReadArchive* ReadPointerOwned_CIntelPosHandle(moho::CIntelPosHandle** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x0077D7A0 (FUN_0077D7A0, gpg::ReadArchive::ReadPointerOwned_CDecalHandle)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
     * transition, and upcasts the pointee to `moho::CDecalHandle`.
     */
    ReadArchive* ReadPointerOwned_CDecalHandle(moho::CDecalHandle** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00953B30 (FUN_00953B30)
     * Demangled: public: class gpg::ReadArchive & __thiscall gpg::ReadArchive::TrackPointer(class gpg::RRef const &)
     *
     * What it does:
     * Appends one pre-tracked pointer entry for an already-constructed object.
     */
    ReadArchive& TrackPointer(const gpg::RRef& objectRef);

    /**
     * Address: 0x00952F10 (FUN_00952F10)
     * Demangled: gpg::ReadArchive::ReadTypeHandle
     *
     * What it does:
     * Reads or resolves reflected type/version handle from archive token stream.
     */
    TypeHandle ReadTypeHandle();

  protected:
    msvc8::vector<TypeHandle> mTypeHandles;
    msvc8::vector<TrackedPointerInfo> mTrackedPtrs;
    TrackedPointerInfo mNullTrackedPointer;

    friend TrackedPointerInfo& ReadRawPointer(ReadArchive* archive, const RRef& ownerRef);
    friend void
    ReadPointerShared_LaunchInfoBase(boost::SharedPtrRaw<moho::LaunchInfoBase>& outPointer, ReadArchive* archive, const RRef& ownerRef);
    friend void ReadPointerShared_SSessionSaveData(
      boost::SharedPtrRaw<moho::SSessionSaveData>& outPointer, ReadArchive* archive, const RRef& ownerRef
    );
    friend void
    ReadPointerShared_CAniPose(boost::SharedPtrRaw<moho::CAniPose>& outPointer, ReadArchive* archive, const RRef& ownerRef);
    friend void
    ReadPointerShared_CAniSkel(boost::SharedPtrRaw<moho::CAniSkel>& outPointer, ReadArchive* archive, const RRef& ownerRef);
    friend void ReadPointerShared_Stats_StatItem(
      boost::SharedPtrRaw<moho::Stats<moho::StatItem>>& outPointer, ReadArchive* archive, const RRef& ownerRef
    );
    friend void ReadPointerShared_ISimResources(
      boost::SharedPtrRaw<moho::ISimResources>& outPointer, ReadArchive* archive, const RRef& ownerRef
    );
    friend void
    ReadPointerShared_CIntelGrid(boost::SharedPtrRaw<moho::CIntelGrid>& outPointer, ReadArchive* archive, const RRef& ownerRef);
    friend void ReadPointerShared_RScaResource(
      boost::SharedPtrRaw<moho::RScaResource>& outPointer, ReadArchive* archive, const RRef& ownerRef
    );
    friend void ReadPointerShared_RScmResource(
      boost::SharedPtrRaw<moho::RScmResource>& outPointer, ReadArchive* archive, const RRef& ownerRef
    );
    friend void
    ReadPointerShared_STrigger(boost::SharedPtrRaw<moho::STrigger>& outPointer, ReadArchive* archive, const RRef& ownerRef);
  };
  static_assert(sizeof(ReadArchive) == 0x38, "ReadArchive size must be 0x38");

  /**
   * Address: 0x007638D0 (FUN_007638D0)
   *
   * What it does:
   * Repeatedly reads `Listener<const SNavPath&>` pointers from `archive` and
   * relinks each non-null listener node into the intrusive ring immediately
   * before `listHead`.
   */
  moho::Listener<const moho::SNavPath&>* ReadAndLinkNavPathListeners(
    ReadArchive* archive,
    moho::Listener<const moho::SNavPath&>* listHead,
    int version,
    const gpg::RRef* ownerRef
  );

  /**
   * Address: 0x009048B0 (FUN_009048B0)
   * Mangled: ?CreateBinaryReadArchive@gpg@@YAPAVReadArchive@1@ABV?$shared_ptr@U_iobuf@@@boost@@@Z
   *
   * What it does:
   * Creates one file-backed concrete `ReadArchive` for save/load serializers.
   */
  ReadArchive* CreateBinaryReadArchive(const boost::shared_ptr<std::FILE>& file);
} // namespace gpg
