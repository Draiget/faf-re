#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <type_traits>
#include <typeinfo>
#include <vector>

#include "gpg/core/containers/DList.h"
#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/utils/Global.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/containers/TDatList.h"

struct lua_State;
struct TString;
struct Table;
struct UpVal;
struct Proto;
struct CClosure;

namespace boost
{
  template <class T>
  class shared_ptr;
} // namespace boost

namespace Wm3
{
  template <class Real>
  class Box3;
  template <class Real>
  class Sphere3;
  template <class T>
  class Vector3;
  using Vector3f = Vector3<float>;
} // namespace Wm3

namespace moho
{
  class CAiBrain;
  class CAiAttackerImpl;
  class IAiAttacker;
  class IAiSteering;
  class IAiCommandDispatch;
  class IAiReconDB;
  class CAiBuilderImpl;
  class IAiBuilder;
  class CAiNavigatorAir;
  class CAiNavigatorLand;
  class IAiNavigator;
  class CAiPathFinder;
  class CAiPathNavigator;
  class CAiPathSpline;
  struct ArmyLaunchInfo;
  struct UnitWeaponInfo;
  struct SOffsetInfo;
  class IAiSiloBuild;
  class IAiTransport;
  struct SAiReservedTransportBone;
  struct SAssignedLocInfo;
  struct SPickUpInfo;
  struct SAttachPoint;
  struct SSTIEntityAttachInfo;
  class IAiFormationDB;
  class IPathTraveler;
  class PathTables;
  class CTaskStage;
  class CAiPersonality;
  class CAiFormationInstance;
  class CAiFormationDBImpl;
  class CAiReconDBImpl;
  class CAiSteeringImpl;
  class CAiSiloBuildImpl;
  class CAiTransportImpl;
  class LAiAttackerImpl;
  class IAiCommandDispatchImpl;
  template <class TEvent>
  class Listener;
  template <class TEvent>
  class ManyToOneListener;
  template <class T>
  class Stats;
  class CAniActor;
  class CAniPose;
  class CAniPoseBone;
  struct SAniManipBinding;
  class IAniManipulator;
  class CFootPlantManipulator;
  class CRotateManipulator;
  class CStorageManipulator;
  class CThrustManipulator;
  class IFormationInstance;
  enum EEconResource : std::int32_t;
  enum EAlliance : std::int32_t;
  enum ETriggerOperator : std::int32_t;
  enum ECompareType : std::int32_t;
  enum ELayer : std::int32_t;
  enum class ENetProtocolType : std::int32_t;
  enum EReconFlags : std::int32_t;
  enum ECommandEvent : std::int32_t;
  enum EUnitCommandQueueStatus : std::int32_t;
  enum EAiAttackerEvent : std::int32_t;
  enum EAiNavigatorEvent : std::int32_t;
  enum EAiNavigatorStatus : std::int32_t;
  enum EAiPathNavigatorState : std::int32_t;
  enum EAiTransportEvent : std::int32_t;
  enum EPathType : std::int32_t;
  enum ESearchType : std::int32_t;
  enum ESiloBuildStage : std::int32_t;
  enum ESiloType : std::int32_t;
  enum EProjectileImpactEvent : int;
  enum class EAiTargetType : std::int32_t;
  enum class ESTITargetType : std::int32_t;
  enum EAiResult : std::int32_t;
  enum class ESquadClass : std::int32_t;
  enum EVisibilityMode : std::int32_t;
  enum EUnitState : std::int32_t;
  enum EFireState : std::int32_t;
  enum EMauiScrollAxis : std::int32_t;
  enum EMauiKeyCode : std::int32_t;
  enum EMauiEventType : std::int32_t;
  enum class EUnitCommandType : std::int32_t;
  enum EGenericIconType : std::int32_t;
  enum EIntel : std::int32_t;
  enum EThreatType : std::int32_t;
  enum ERuleBPUnitCommandCaps : std::int32_t;
  enum ERuleBPUnitToggleCaps : std::int32_t;
  enum ESpecialFileType : std::int32_t;
  class CPlatoon;
  class CSquad;
  class CTaskThread;
  struct SPhysConstants;
  struct SPhysBody;
  class SimArmy;
  class CAcquireTargetTask;
  class CFactoryBuildTask;
  class CUnitCaptureTask;
  class CUnitCarrierLand;
  class CUnitCarrierLaunch;
  class CUnitCarrierRetrieve;
  class CUnitGetBuiltTask;
  class CUnitGuardTask;
  class CUnitMobileBuildTask;
  class CUnitRepairTask;
  class CUnitSacrificeTask;
  class CUnitTeleportTask;
  class CUnitUpgradeTask;
  class CArmyStats;
  class CArmyImpl;
  class CArmyStatItem;
  class CLuaConOutputHandler;
  class CLuaTask;
  class CWaitForTask;
  class CFireWeaponTask;
  class CEconomyEvent;
  class CDecalBuffer;
  class CDecalHandle;
  class CUnitUnloadUnits;
  class CIntelCounterHandle;
  class CIntelPosHandle;
  class Prop;
  class CSndVar;
  class HSound;
  class ISoundManager;
  struct SAudioRequest;
  class CParticleTexture;
  class CUnitCommand;
  class CUnitCommandQueue;
  class CCommandDB;
  class CUnitMotion;
  class IEffect;
  class IEffectManager;
  class CEffectManagerImpl;
  class CEfxBeam;
  class CEfxEmitter;
  class CEfxTrailEmitter;
  class COGrid;
  class CInfluenceMap;
  class InfluenceGrid;
  struct SThreat;
  class RDebugCollision;
  class RDebugGrid;
  class RDebugRadar;
  class RDebugNavPath;
  class RDebugNavWaypoints;
  class RDebugNavSteering;
  class RDebugWeapons;
  class CColPrimitiveBase;
  class Motor;
  class Entity;
  class CollisionBeamEntity;
  class EntityDB;
  class EntitySetBase;
  template <class T>
  class EntitySetTemplate;
  class CIntel;
  class CScriptObject;
  class CScriptEvent;
  class CSndParams;
  class ISimResources;
  class CSimResources;
  class LaunchInfoNew;
  struct CPathPoint;
  struct HPathCell;
  struct SNavPath;
  class ReconBlip;
  struct SPerArmyReconInfo;
  class CRandomStream;
  class IdPool;
  struct PositionHistory;
  struct RBlueprint;
  struct RBeamBlueprint;
  struct ResourceDeposit;
  struct EntityCategoryHelper;
  struct RMeshBlueprint;
  struct RMeshBlueprintLOD;
  class RScmResource;
  struct RPropBlueprint;
  class REmitterCurveKey;
  class REmitterBlueprintCurve;
  struct REmitterBlueprint;
  class Projectile;
  struct RProjectileBlueprint;
  struct RTrailBlueprint;
  class RRuleGameRules;
  struct SOCellPos;
  struct SPointVector;
  struct SRuleFootprintsBlueprint;
  struct RUnitBlueprint;
  struct RUnitBlueprintWeapon;
  template <class T, class U>
  struct BVSet;
  using EntityCategorySet = BVSet<const RBlueprint*, EntityCategoryHelper>;
  struct SCondition;
  struct STrigger;
  struct SSessionSaveData;
  class IUnit;
  class Unit;
  class UnitWeapon;
  struct SEfxCurve;
  class Shield;
  template <class T>
  struct CountedPtr;
  template <class T>
  struct WeakPtr;
  template <class TShape>
  class CColPrimitive;
  class MotorSinkAway;
} // namespace moho

namespace LuaPlus
{
  class LuaState;
} // namespace LuaPlus

namespace gpg
{
  class RObject;
  class RRef;
  class RType;
  class RField;
  class REnumType;
  class RIndexed;
  class ReadArchive;
  class WriteArchive;
  class SerConstructResult;
  class SerSaveConstructArgsResult;
  /**
   * VFTABLE: 0x00D48B90 (`??_7SerHelperBase@gpg@@6B@`)
   *
   * Base of every `Ser{Construct,SaveConstruct,SaveLoad}Helper_<T>` reflection
   * bootstrap singleton (`CIntelPosHandleConstruct`, `Rect2iSerializer`, the
   * per-file `...ConstructHelper`/`...Serializer` globals throughout
   * `src/sdk/**`). Each of those helpers self-registers at static-init time,
   * waits on the process-global pending list below, then gets dispatched once
   * (via `Init()`) to bind its construct/delete or load/save callback(s) onto
   * a reflected `RType`.
   *
   * RTTI: `gpg::DListItem<SerHelperBase>` at +0x04 (with its
   * `boost::noncopyable`), after the vtable. `FUN_009501D0` self-links that
   * node and appends it to `sNewHelpers`; `FUN_00950D50` pops each node and
   * recovers the helper as `node - 4`.
   */
  struct SerHelperBase : public DListItem<SerHelperBase>
  {
    /**
     * Address: 0x009501D0 (FUN_009501D0, gpg::SerHelperBase::SerHelperBase)
     *
     * What it does:
     * Lazily creates the process-global pending-helper list (`sNewHelpers`),
     * then appends this freshly self-linked node to its tail so a later
     * `InitNewHelpers` pass drains and dispatches helpers in construction
     * order.
     */
    SerHelperBase();

    /**
     * Address: 0x00950D50 vtable slot 0 dispatch target.
     *
     * What it does:
     * Binds this helper's callback(s) onto the reflected `RType` it targets.
     * Every leaf helper type overrides this with its own binding logic;
     * `InitNewHelpers` calls it once per helper when drained from the pending
     * list.
     */
    virtual void Init() = 0;

    /**
     * Address: 0x00950D50 (FUN_00950D50, gpg::SerHelperBase::InitNewHelpers)
     * Address: 0x00953BE0 caller lane (`gpg::WriteArchive::WriteArchive`)
     *
     * What it does:
     * Drains the pending serializer-helper intrusive list in FIFO order,
     * dispatching `Init()` on each helper, then releases the list root.
     */
    static void InitNewHelpers();

    // Address: 0x00F8ECB8 - process-global pending helper intrusive-list root.
    static DList<SerHelperBase>* sNewHelpers;
  };
  static_assert(sizeof(SerHelperBase) == 0xC, "SerHelperBase size must be 0xC");

  /**
   * C-string comparator for map keys.
   */
  struct CStrLess
  {
    bool operator()(const char* a, const char* b) const noexcept
    {
      if (a == b)
        return false;
      if (!a)
        return true;
      if (!b)
        return false;
      return std::strcmp(a, b) < 0;
    }
  };

  /**
   * type_info comparator used by the preregistration map.
   * Mirrors the binary's use of type_info::before.
   */
  struct TypeInfoLess
  {
    bool operator()(const std::type_info* a, const std::type_info* b) const noexcept
    {
      if (a == b)
        return false;
      if (!a)
        return b != nullptr;
      if (!b)
        return false;
      return a->before(*b) != 0;
    }
  };

  // `RRefCompare` moved to ArchiveSerialization.h: `WriteArchive::mObjRefs` is
  // keyed on `RRef` and ordered by it, and that header sits below this one.

  using TypeMap = std::map<const char*, RType*, CStrLess>;
  using TypeVec = msvc8::vector<RType*>;
  using TypeInfoMap = std::map<const std::type_info*, RType*, TypeInfoLess>;

  class RObject
  {
  public:
    /**
     * Address: 0x004012C0 (FUN_004012C0)
     * PDB name: sub_4012C0
     *
     * What it does:
     * Initializes the base vftable lane for reflected objects.
     */
    RObject() noexcept;

    /**
     * Address: 0x00A82547
     * VFTable SLOT: 0
     */
    [[nodiscard]]
    virtual RType* GetClass() const = 0;

    /**
     * Address: 0x00A82547
     * VFTable SLOT: 1
     */
    virtual RRef GetDerivedObjectRef() = 0;

    /**
     * Address: 0x008DD460 (FUN_008DD460, ?IsA@RObject@gpg@@QBE_NPAVRType@2@@Z_0)
     *
     * What it does:
     * Returns whether this object's dynamic reflected type is derived from one
     * requested target type lane.
     */
    [[nodiscard]] bool IsA(RType* type) const;

    /**
     * Address: 0x004012D0 (FUN_004012D0)
     * PDB name: sub_4012D0
     * VFTable SLOT: 2
     *
     * What it does:
     * Owns deleting-dtor lane for RObject base and conditionally frees `this`.
     */
    virtual ~RObject() noexcept;
  };
  static_assert(sizeof(RObject) == 0x04, "RObject must be 0x04");

  // template<class T>
  class RRef
  {
  public:
    void* mObj;
    RType* mType;

    /**
     * Address: 0x00401280 (FUN_00401280)
     *
     * What it does:
     * Initializes an empty reflection reference `{nullptr, nullptr}`.
     */
    RRef() noexcept;

    /**
     * Address: 0x00401290 (FUN_00401290)
     *
     * What it does:
     * Initializes a reflection reference from explicit object/type lanes.
     */
    RRef(void* ptr, gpg::RType* type) noexcept;

    /**
     * Address: 0x009204A0 (FUN_009204A0)
     *
     * What it does:
     * Initializes one reflection reference from a Lua `TString*` by routing
     * through the canonical `gpg::RRef_TString` helper lane.
     */
    explicit RRef(TString* value) noexcept;

    /**
     * Address: 0x009204D0 (FUN_009204D0)
     *
     * What it does:
     * Initializes one reflection reference from a Lua `Table*` by routing
     * through the canonical `gpg::RRef_Table` helper lane.
     */
    explicit RRef(Table* value) noexcept;

    /**
     * Address: 0x00920670 (FUN_00920670)
     *
     * What it does:
     * Initializes one reflection reference from a Lua `LClosure*` by routing
     * through the canonical `gpg::RRef_LClosure` helper lane.
     */
    explicit RRef(LClosure* value) noexcept;

    /**
     * Address: 0x009206A0 (FUN_009206A0)
     *
     * What it does:
     * Initializes one reflection reference from a Lua `UpVal*` by routing
     * through the canonical `gpg::RRef_UpVal` helper lane.
     */
    explicit RRef(UpVal* value) noexcept;

    /**
     * Address: 0x00920750 (FUN_00920750)
     *
     * What it does:
     * Initializes one reflection reference from a Lua `Proto*` by routing
     * through the canonical `gpg::RRef_Proto` helper lane.
     */
    explicit RRef(Proto* value) noexcept;

    /**
     * Address: 0x00920780 (FUN_00920780)
     *
     * What it does:
     * Initializes one reflection reference from a raw Lua `lua_State*` by
     * routing through `gpg::RRef_lua_State`.
     */
    explicit RRef(lua_State* value) noexcept;

    /**
     * Address: 0x009207B0 (FUN_009207B0)
     *
     * What it does:
     * Initializes one reflection reference from a Lua `Udata*` by routing
     * through the canonical `gpg::RRef_Udata` helper lane.
     */
    explicit RRef(Udata* value) noexcept;

    /**
     * Address: 0x00950640 (FUN_00950640)
     *
     * What it does:
     * Initializes one reflection reference from `gpg::ArchiveToken*` by
     * routing through `gpg::RRef_ArchiveToken`.
     */
    explicit RRef(ArchiveToken* value) noexcept;

    /**
     * Address: 0x008D6DA0 (FUN_008D6DA0)
     *
     * What it does:
     * Initializes one reflection reference from `moho::RUnitBlueprint*` by
     * routing through `gpg::RRef_RUnitBlueprint`.
     */
    explicit RRef(moho::RUnitBlueprint* value) noexcept;

    /**
     * Address: 0x008E1580 (FUN_008E1580)
     *
     * What it does:
     * Initializes one reflection reference from `char*` by routing through
     * `gpg::RRef_char`.
     */
    explicit RRef(char* value) noexcept;

    /**
     * Address: 0x008E1650 (FUN_008E1650)
     *
     * What it does:
     * Initializes one reflection reference from `short*` by routing through
     * `gpg::RRef_short`.
     */
    explicit RRef(short* value) noexcept;

    /**
     * Address: 0x008E17C0 (FUN_008E17C0)
     *
     * What it does:
     * Initializes one reflection reference from `long*` by routing through
     * `gpg::RRef_long`.
     */
    explicit RRef(long* value) noexcept;

    /**
     * Address: 0x008E1890 (FUN_008E1890)
     *
     * What it does:
     * Initializes one reflection reference from `signed char*` by routing
     * through `gpg::RRef_schar`.
     */
    explicit RRef(signed char* value) noexcept;

    /**
     * Address: 0x008E1A00 (FUN_008E1A00)
     *
     * What it does:
     * Initializes one reflection reference from `unsigned short*` by routing
     * through `gpg::RRef_ushort`.
     */
    explicit RRef(unsigned short* value) noexcept;

    /**
     * Address: 0x004012B0 (FUN_004012B0)
     *
     * What it does:
     * Returns the raw referenced object pointer lane.
     */
    [[nodiscard]] void* GetObject() const noexcept;

    /**
     * Address: 0x004A35D0 (FUN_004A35D0)
     *
     * What it does:
     * Reads the reference value as lexical text through the bound `RType`.
     */
    msvc8::string GetLexical() const;

    /**
     * Address: 0x004A3600 (FUN_004A3600)
     *
     * What it does:
     * Writes one lexical text value through the bound `RType`.
     */
    bool SetLexical(const char*) const;
    /**
     * Address: 0x00406690 (FUN_00406690)
     *
     * What it does:
     * Returns reflected type name for this reference, or `"null"` when untyped.
     */
    const char* GetName() const;

    const char* GetTypeName() const
    {
      return GetName();
    }
    /**
     * Address: 0x004A3610 (FUN_004A3610)
     *
     * What it does:
     * Returns the indexed child reference at `ind`.
     */
    RRef operator[](unsigned int ind) const;

    /**
     * Address: 0x004A3630 (FUN_004A3630)
     *
     * What it does:
     * Returns indexed element count for this reference, or zero when unindexed.
     */
    size_t GetCount() const;

    /**
     * Address: 0x004A3650 (FUN_004A3650)
     *
     * What it does:
     * Returns the bound runtime reflection type descriptor.
     */
    const RType* GetRType() const;

    /**
     * Address: 0x004A3660 (FUN_004A3660)
     *
     * What it does:
     * Returns indexed-view support for the bound type.
     */
    const RIndexed* IsIndexed() const;

    /**
     * Address: 0x004CC9E0 (FUN_004CC9E0, gpg::RRef::IsPointer)
     *
     * What it does:
     * Returns pointer-view support for the bound type.
     */
    const RIndexed* IsPointer() const;

    int GetNumBases() const;                 // gpgcore.dll
    RRef GetBase(int ind) const;             // gpgcore.dll

    /**
     * Address: 0x004CC9B0 (FUN_004CC9B0, gpg::RRef::GetNumFields)
     *
     * What it does:
     * Returns reflected field count for the bound type.
     */
    int GetNumFields() const;

    RRef GetField(int ind) const;            // gpgcore.dll
    const char* GetFieldName(int ind) const; // gpgcore.dll
    void Delete();                           // 0x008D8800

    /**
     * Address: 0x004C1690 (FUN_004C1690 -- `Upcast<LuaPlus::LuaState>`; formerly `RRef::CastLuaState`.)
     * Address: 0x00585270 (FUN_00585270 -- `Upcast<moho::SimArmy>`; formerly `UpcastToSimArmy` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x00585460 (FUN_00585460 -- `Upcast<moho::CAiPersonality>`; formerly `UpcastToCAiPersonality` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x005943C0 (FUN_005943C0 -- `Upcast<moho::CAiBrain>`; formerly `UpcastToCAiBrain` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x0059A030 (FUN_0059A030 -- `Upcast<moho::CUnitCommandQueue>`; formerly `UpcastCUnitCommandQueueRef` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x0059EB00 (FUN_0059EB00 -- `Upcast<moho::IFormationInstance>`; formerly `UpcastToIFormationInstance` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x005A89B0 (FUN_005A89B0 -- `Upcast<moho::Entity>`; formerly `UpcastToEntity` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x005A9A00 (FUN_005A9A00 -- `Upcast<moho::CAiPathNavigator>`; formerly `UpcastToCAiPathNavigator` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x005ACC60 (FUN_005ACC60 -- `Upcast<moho::PathQueue>`; formerly `UpcastToPathQueue` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x005B1B90 (FUN_005B1B90 -- `Upcast<moho::CAiPathFinder>`; formerly `UpcastToCAiPathFinder` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x005CE500 (FUN_005CE500 -- `Upcast<moho::CInfluenceMap>`; formerly `UpcastToCInfluenceMap` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x005D1710 (FUN_005D1710 -- `Upcast<moho::UnitWeapon>`; formerly `UpcastToUnitWeapon` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x005D1C30 (FUN_005D1C30 -- `Upcast<moho::CEconRequest>`; formerly `UpcastToCEconRequest` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x005D5280 (FUN_005D5280 -- `Upcast<moho::CAiPathSpline>`; formerly `UpcastToCAiPathSpline` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x005D52C0 (FUN_005D52C0 -- `Upcast<moho::CUnitMotion>`; formerly `UpcastToCUnitMotion` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x005E0680 (FUN_005E0680 -- `Upcast<moho::CAcquireTargetTask>`; formerly `UpcastToCAcquireTargetTask` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x005F5240 (FUN_005F5240 -- `Upcast<moho::CUnitCommand>`; formerly `UpcastToCUnitCommand` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x0063D720 (FUN_0063D720 -- `Upcast<moho::IAniManipulator>`; formerly `UpcastToIAniManipulator` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x0063EDD0 (FUN_0063EDD0 -- `Upcast<moho::CAniActor>`; formerly `UpcastToCAniActor` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x006587A0 (FUN_006587A0 -- `Upcast<moho::IEffect>`; formerly `UpcastToIEffect` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x00671140 (FUN_00671140 -- `Upcast<moho::CDecalHandle>`; formerly `UpcastToCDecalHandle` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x00680F10 (FUN_00680F10 -- `Upcast<moho::PositionHistory>`; formerly `UpcastToPositionHistory` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x006831F0 (FUN_006831F0 -- `Upcast<moho::CColPrimitiveBase>`; formerly `UpcastToCColPrimitiveBase` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x006833E0 (FUN_006833E0 -- `Upcast<moho::CIntel>`; formerly `UpcastToCIntel` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x006835C0 (FUN_006835C0 -- `Upcast<moho::CTextureScroller>`; formerly `UpcastToCTextureScroller` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x006837A0 (FUN_006837A0 -- `Upcast<moho::SPhysBody>`; formerly `UpcastToSPhysBody` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x00683980 (FUN_00683980 -- `Upcast<moho::Motor>`; formerly `UpcastToMotor` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x006B21A0 (FUN_006B21A0 -- `Upcast<moho::CEconomyEvent>`; formerly `UpcastToCEconomyEvent` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x006B5990 (FUN_006B5990 -- `Upcast<moho::IAiSteering>`; formerly `UpcastToIAiSteering` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x006B5B80 (FUN_006B5B80 -- `Upcast<moho::CEconStorage>`; formerly `UpcastToCEconStorage` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x006B5D60 (FUN_006B5D60 -- `Upcast<moho::IAiAttacker>`; formerly `UpcastToIAiAttacker` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x006B5F50 (FUN_006B5F50 -- `Upcast<moho::IAiCommandDispatch>`; formerly `UpcastToIAiCommandDispatch` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x006B6140 (FUN_006B6140 -- `Upcast<moho::IAiNavigator>`; formerly `UpcastToIAiNavigator` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x006B6330 (FUN_006B6330 -- `Upcast<moho::IAiBuilder>`; formerly `UpcastToIAiBuilder` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x006B6520 (FUN_006B6520 -- `Upcast<moho::IAiSiloBuild>`; formerly `UpcastToIAiSiloBuild` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x006B6710 (FUN_006B6710 -- `Upcast<moho::IAiTransport>`; formerly `UpcastToIAiTransport` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x006E07A0 (FUN_006E07A0 -- `Upcast<moho::CFireWeaponTask>`; formerly `UpcastToCFireWeaponTask` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x00707600 (FUN_00707600 -- `Upcast<moho::IAiReconDB>`; formerly `UpcastToIAiReconDB` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x007077F0 (FUN_007077F0 -- `Upcast<moho::CEconomy>`; formerly `UpcastToCEconomy` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x007079D0 (FUN_007079D0 -- `Upcast<moho::CArmyStats>`; formerly `UpcastToCArmyStats` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x007149D0 (FUN_007149D0 -- `Upcast<moho::CArmyStatItem>`; formerly `UpcastToCArmyStatItem` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x0072B0E0 (FUN_0072B0E0 -- `Upcast<moho::CSquad>`; formerly `UpcastToCSquad` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x00758230 (FUN_00758230 -- `Upcast<moho::CRandomStream>`; formerly `UpcastToCRandomStream` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x00758270 (FUN_00758270 -- `Upcast<moho::SPhysConstants>`; formerly `UpcastToSPhysConstants` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x007582B0 (FUN_007582B0 -- `Upcast<moho::IAiFormationDB>`; formerly `UpcastToIAiFormationDB` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x007586B0 (FUN_007586B0 -- `Upcast<moho::CCommandDB>`; formerly `UpcastToCCommandDb` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x007586F0 (FUN_007586F0 -- `Upcast<moho::CDecalBuffer>`; formerly `UpcastToCDecalBuffer` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x007588D0 (FUN_007588D0 -- `Upcast<moho::IEffectManager>`; formerly `UpcastToIEffectManager` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x00758AC0 (FUN_00758AC0 -- `Upcast<moho::ISoundManager>`; formerly `UpcastToISoundManager` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x00758CB0 (FUN_00758CB0 -- `Upcast<moho::EntityDB>`; formerly `UpcastToCEntityDb` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x0076B6E0 (FUN_0076B6E0 -- `Upcast<moho::PathQueue::Impl>`; formerly `UpcastToPathQueueImpl` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x0076ED90 (FUN_0076ED90 -- `Upcast<moho::CIntelPosHandle>`; formerly `UpcastToCIntelPosHandle` in gpg/core/containers/ReadArchive.cpp.)
     * Address: 0x0054EBC0 (FUN_0054EBC0 -- `Upcast<moho::CAniPose>`, the type check of `ReadPointerShared<moho::CAniPose>`; formerly `gpg::RRef::Upcast_CAniPose` in gpg/core/containers/ArchiveSerialization.cpp.)
     * Address: 0x005503B0 (FUN_005503B0 -- `Upcast<moho::CAniSkel>`, the type check of `ReadPointerShared<moho::CAniSkel>`; formerly `gpg::RRef::Upcast_CAniSkel` in gpg/core/containers/ArchiveSerialization.cpp.)
     * Address: 0x0055FD70 (FUN_0055FD70 -- `Upcast<moho::Stats<moho::StatItem>>`, the type check of `ReadPointerShared<moho::Stats<moho::StatItem>>`; formerly `gpg::RRef::Upcast_StatsStatItem` in gpg/core/containers/ArchiveSerialization.cpp.)
     * Address: 0x00551FA0 (FUN_00551FA0 -- `Upcast<moho::CIntelGrid>`, the type check of `ReadPointerShared<moho::CIntelGrid>`; formerly `gpg::RRef::Upcast_CIntelGrid` in gpg/core/containers/ArchiveSerialization.cpp.)
     * Address: 0x005CE6E0 (FUN_005CE6E0 -- `Upcast<moho::CIntelGrid>`, the type check of `ReadPointerShared<moho::CIntelGrid>`; formerly a second `gpg::RRef::Upcast_CIntelGrid` in gpg/core/containers/ArchiveSerialization.cpp.)
     * Address: 0x006431A0 (FUN_006431A0 -- `Upcast<moho::RScaResource>`, the type check of `ReadPointerShared<moho::RScaResource>`; formerly `gpg::RRef::Upcast_RScaResource` in gpg/core/containers/ArchiveSerialization.cpp.)
     * Address: 0x0055AB30 (FUN_0055AB30 -- `Upcast<moho::RScmResource>`, the type check of `ReadPointerShared<moho::RScmResource>`; formerly `gpg::RRef::Upcast_RScmResource` in gpg/core/containers/ArchiveSerialization.cpp.)
     * Address: 0x00714A10 (FUN_00714A10 -- `Upcast<moho::STrigger>`, the type check of `ReadPointerShared<moho::STrigger>`; formerly `gpg::RRef::Upcast_STrigger` in gpg/core/containers/ArchiveSerialization.cpp.)
     * Address: 0x008849B0 (FUN_008849B0 -- `Upcast<moho::SSessionSaveData>`, the type check of `ReadPointerShared<moho::SSessionSaveData>`; formerly `func_CastSSessionSaveData` in gpg/core/containers/ArchiveSerialization.cpp.)
     * Address: 0x007584A0 (FUN_007584A0 -- `Upcast<moho::ISimResources>`, the type check of `ReadPointerShared<moho::ISimResources>`; formerly `func_CastISimResources` in gpg/core/containers/ArchiveSerialization.cpp.)
     * Address: 0x00885110 (FUN_00885110 -- `Upcast<moho::LaunchInfoBase>`, the type check of `ReadPointerShared<moho::LaunchInfoBase>`; formerly `func_CastLaunchInfoBase` in gpg/core/containers/ArchiveSerialization.cpp.)
     *
     * What it does:
     * This reference's object as a `T*` (`REF_UpcastPtr` to `T`'s type), or
     * null when it is not a `T`.
     */
    template <class T>
    [[nodiscard]] T* Upcast() const;

    /**
     * Address: 0x00920400 (FUN_00920400, gpg::RRef::TryUpcast_lua_State)
     *
     * What it does:
     * Upcasts this reflected reference to one raw `lua_State*` lane and throws
     * `gpg::BadRefCast` when the runtime type is incompatible.
     */
    [[nodiscard]] lua_State* TryUpcastLuaThreadState() const;

    /**
     * Address: 0x008E17F0 (FUN_008E17F0, gpg::RRef::TryUpcast_long)
     *
     * What it does:
     * Upcasts this reflected reference to one `long*` lane and throws
     * `gpg::BadRefCast` when the runtime type is incompatible.
     */
    [[nodiscard]] long* TryUpcastLong() const;

    /**
     * Address: 0x008E15B0 (FUN_008E15B0, gpg::RRef::TryUpcast_char)
     *
     * What it does:
     * Upcasts this reflected reference to one plain `char*` lane and throws
     * `gpg::BadRefCast` when the runtime type is incompatible. Plain `char` is
     * a distinct reflected type from both `signed char` and `unsigned char`.
     */
    [[nodiscard]] char* TryUpcastChar() const;

    /**
     * Address: 0x008E1680 (FUN_008E1680, gpg::RRef::TryUpcast_short)
     *
     * What it does:
     * Upcasts this reflected reference to one `short*` lane and throws
     * `gpg::BadRefCast` when the runtime type is incompatible.
     */
    [[nodiscard]] short* TryUpcastShort() const;

    /**
     * Address: 0x008E1720 (FUN_008E1720, gpg::RRef::TryUpcast_int)
     *
     * What it does:
     * Upcasts this reflected reference to one `int*` lane and throws
     * `gpg::BadRefCast` when the runtime type is incompatible.
     */
    [[nodiscard]] int* TryUpcastInt() const;

    /**
     * Address: 0x008E18C0 (FUN_008E18C0, gpg::RRef::TryUpcast_schar)
     *
     * What it does:
     * Upcasts this reflected reference to one `signed char*` lane and throws
     * `gpg::BadRefCast` when the runtime type is incompatible.
     */
    [[nodiscard]] signed char* TryUpcastSignedChar() const;

    /**
     * Address: 0x008E1960 (FUN_008E1960, gpg::RRef::TryUpcast_uchar)
     *
     * What it does:
     * Upcasts this reflected reference to one `unsigned char*` lane and throws
     * `gpg::BadRefCast` when the runtime type is incompatible.
     */
    [[nodiscard]] unsigned char* TryUpcastUnsignedChar() const;

    /**
     * Address: 0x008E1A30 (FUN_008E1A30, gpg::RRef::TryUpcast_ushort)
     *
     * What it does:
     * Upcasts this reflected reference to one `unsigned short*` lane and throws
     * `gpg::BadRefCast` when the runtime type is incompatible.
     */
    [[nodiscard]] unsigned short* TryUpcastUnsignedShort() const;

    /**
     * Address: 0x008E1AD0 (FUN_008E1AD0, gpg::RRef::TryUpcast_uint)
     *
     * What it does:
     * Upcasts this reflected reference to one `unsigned int*` lane and throws
     * `gpg::BadRefCast` when the runtime type is incompatible.
     */
    [[nodiscard]] unsigned int* TryUpcastUnsignedInt() const;

    /**
     * Address: 0x008E1BA0 (FUN_008E1BA0, gpg::RRef::TryUpcast_ulong)
     *
     * What it does:
     * Upcasts this reflected reference to one `unsigned long*` lane and throws
     * `gpg::BadRefCast` when the runtime type is incompatible.
     */
    [[nodiscard]] unsigned long* TryUpcastUnsignedLong() const;

    /**
     * Address: 0x00557A90 (FUN_00557A90, gpg::RRef::TryUpcast_RBlueprint_P)
     *
     * What it does:
     * Upcasts this reflected reference to one `RBlueprint*` pointer-slot lane
     * and throws `gpg::BadRefCast` when the runtime type is incompatible.
     */
    [[nodiscard]] moho::RBlueprint** TryUpcastRBlueprintPointerSlot() const;

    /**
     * Address: 0x0059DE10 (FUN_0059DE10, gpg::RRef::TryUpcast_IFormationInstance_P)
     *
     * What it does:
     * Upcasts this reflected reference to one `IFormationInstance*`
     * pointer-slot lane and throws `gpg::BadRefCast` on type mismatch.
     */
    [[nodiscard]] moho::IFormationInstance** TryUpcastIFormationInstancePointerSlot() const;

    /**
     * Address: 0x005A1E90 (FUN_005A1E90, gpg::RRef::TryUpcast_RUnitBlueprint_P)
     *
     * What it does:
     * Upcasts this reflected reference to one `RUnitBlueprint*` pointer-slot
     * lane and throws `gpg::BadRefCast` on type mismatch.
     */
    [[nodiscard]] moho::RUnitBlueprint** TryUpcastRUnitBlueprintPointerSlot() const;

    /**
     * Address: 0x005CA2E0 (FUN_005CA2E0, gpg::RRef::TryUpcast_ReconBlip_P)
     *
     * What it does:
     * Upcasts this reflected reference to one `ReconBlip*` pointer-slot lane
     * and throws `gpg::BadRefCast` on type mismatch.
     */
    [[nodiscard]] moho::ReconBlip** TryUpcastReconBlipPointerSlot() const;

    /**
     * Address: 0x005DF630 (FUN_005DF630, gpg::RRef::TryUpcast_UnitWeapon_P)
     *
     * What it does:
     * Upcasts this reflected reference to one `UnitWeapon*` pointer-slot lane
     * and throws `gpg::BadRefCast` on type mismatch.
     */
    [[nodiscard]] moho::UnitWeapon** TryUpcastUnitWeaponPointerSlot() const;

    /**
     * Address: 0x005DF6B0 (FUN_005DF6B0, gpg::RRef::TryUpcast_CAcquireTargetTask_P)
     *
     * What it does:
     * Upcasts this reflected reference to one `CAcquireTargetTask*`
     * pointer-slot lane and throws `gpg::BadRefCast` on type mismatch.
     */
    [[nodiscard]] moho::CAcquireTargetTask** TryUpcastCAcquireTargetTaskPointerSlot() const;

    /**
     * Address: 0x0063E6E0 (FUN_0063E6E0, gpg::RRef::TryUpcast_IAniManipulator_P)
     *
     * What it does:
     * Upcasts this reflected reference to one `IAniManipulator*` pointer-slot
     * lane and throws `gpg::BadRefCast` on type mismatch.
     */
    [[nodiscard]] moho::IAniManipulator** TryUpcastIAniManipulatorPointerSlot() const;

    /**
     * Address: 0x0066D110 (FUN_0066D110, gpg::RRef::TryUpcast_IEffect_P)
     *
     * What it does:
     * Upcasts this reflected reference to one `IEffect*` pointer-slot lane and
     * throws `gpg::BadRefCast` on type mismatch.
     */
    [[nodiscard]] moho::IEffect** TryUpcastIEffectPointerSlot() const;

    /**
     * Address: 0x0067FD80 (FUN_0067FD80, gpg::RRef::TryUpcast_Entity_P)
     *
     * What it does:
     * Upcasts this reflected reference to one `Entity*` pointer-slot lane and
     * throws `gpg::BadRefCast` on type mismatch.
     */
    [[nodiscard]] moho::Entity** TryUpcastEntityPointerSlot() const;

    /**
     * Address: 0x006B3D00 (FUN_006B3D00, gpg::RRef::TryUpcast_CEconomyEvent_P)
     *
     * What it does:
     * Upcasts this reflected reference to one `CEconomyEvent*` pointer-slot
     * lane and throws `gpg::BadRefCast` on type mismatch.
     */
    [[nodiscard]] moho::CEconomyEvent** TryUpcastCEconomyEventPointerSlot() const;

    /**
     * Address: 0x006EC5E0 (FUN_006EC5E0, gpg::RRef::TryUpcast_Listener_ECommandEvent)
     *
     * What it does:
     * Upcasts this reflected reference to one `Listener<ECommandEvent>` object
     * lane and throws `gpg::BadRefCast` on type mismatch.
     */
    [[nodiscard]] moho::Listener<moho::ECommandEvent>* TryUpcastListenerECommandEvent() const;

    /**
     * Address: 0x006F93D0 (FUN_006F93D0, gpg::RRef::TryUpcast_Listener_EUnitCommandQueueStatus)
     *
     * What it does:
     * Upcasts this reflected reference to one
     * `Listener<EUnitCommandQueueStatus>` object lane and throws
     * `gpg::BadRefCast` on type mismatch.
     */
    [[nodiscard]] moho::Listener<moho::EUnitCommandQueueStatus>* TryUpcastListenerEUnitCommandQueueStatus() const;

    /**
     * Address: 0x006FD290 (FUN_006FD290, gpg::RRef::TryUpcast_Prop)
     *
     * What it does:
     * Upcasts this reflected reference to one `Prop` object lane and throws
     * `gpg::BadRefCast` on type mismatch.
     */
    [[nodiscard]] moho::Prop* TryUpcastProp() const;

    /**
     * Address: 0x0054E230 (FUN_0054E230, gpg::RRef::TryUpcast_CAniPose)
     *
     * What it does:
     * Upcasts this reflected reference to one `CAniPose` object lane and
     * throws `gpg::BadRefCast` on type mismatch.
     */
    [[nodiscard]] moho::CAniPose* TryUpcastCAniPose() const;

    /**
     * Address: 0x0067FBA0 (FUN_0067FBA0, gpg::RRef::TryUpcast_PositionHistory)
     *
     * What it does:
     * Upcasts this reflected reference to one `PositionHistory` object lane
     * and throws `gpg::BadRefCast` on type mismatch.
     */
    [[nodiscard]] moho::PositionHistory* TryUpcastPositionHistory() const;

    /**
     * Address: 0x006E3E10 (FUN_006E3E10, gpg::RRef::TryUpcast_CUnitCommand_P)
     *
     * What it does:
     * Upcasts this reflected reference to one `CUnitCommand*` pointer-slot lane
     * and throws `gpg::BadRefCast` on type mismatch.
     */
    [[nodiscard]] moho::CUnitCommand** TryUpcastCUnitCommandPointerSlot() const;

    /**
     * Address: 0x00712B20 (FUN_00712B20, gpg::RRef::TryUpcast_CArmyStatItem_P)
     *
     * What it does:
     * Upcasts this reflected reference to one `CArmyStatItem*` pointer-slot
     * lane and throws `gpg::BadRefCast` on type mismatch.
     */
    [[nodiscard]] moho::CArmyStatItem** TryUpcastCArmyStatItemPointerSlot() const;

    /**
     * Address: 0x00751F10 (FUN_00751F10, gpg::RRef::TryUpcast_SimArmy_P)
     *
     * What it does:
     * Upcasts this reflected reference to one `SimArmy*` pointer-slot lane and
     * throws `gpg::BadRefCast` on type mismatch.
     */
    [[nodiscard]] moho::SimArmy** TryUpcastSimArmyPointerSlot() const;

    /**
     * Address: 0x00751FC0 (FUN_00751FC0, gpg::RRef::TryUpcast_Shield_P)
     *
     * What it does:
     * Upcasts this reflected reference to one `Shield*` pointer-slot lane and
     * throws `gpg::BadRefCast` on type mismatch.
     */
    [[nodiscard]] moho::Shield** TryUpcastShieldPointerSlot() const;

    /**
     * Address: 0x0077F430 (FUN_0077F430, gpg::RRef::TryUpcast_CDecalHandle_P)
     *
     * What it does:
     * Upcasts this reflected reference to one `CDecalHandle*` pointer-slot lane
     * and throws `gpg::BadRefCast` on type mismatch.
     */
    [[nodiscard]] moho::CDecalHandle** TryUpcastCDecalHandlePointerSlot() const;

    /**
     * Address: 0x0084AB10 (FUN_0084AB10, gpg::RRef::CurrentUIState)
     *
     * What it does:
     * Builds one reflected reference bound to the global UI state lane.
     */
    static RRef* CurrentUIState(RRef* out);
  };
  static_assert(sizeof(RRef) == 0x08, "RRef must be 0x08");

  /**
   * Global registries (original: func_GetRTypeMap / func_GetRTypeVec).
   */
  /**
   * Address: 0x008DF880 (FUN_008DF880, gpg::GetRTypeMap)
   *
   * What it does:
   * Lazily constructs and returns the global RTTI registry map.
   */
  inline TypeMap& GetRTypeMap()
  {
    static TypeMap gMap;
    return gMap;
  }

  /**
   * Address: 0x008DD8E0 (FUN_008DD8E0, func_GetRTypeVec)
   *
   * What it does:
   * Lazily constructs and returns the global reflection type-index vector.
   */
  inline TypeVec& GetRTypeVec()
  {
    static TypeVec gVec;
    return gVec;
  }

  /**
   * Address: 0x008DF7C0 (gpg::GetPreRTypeMap)
   *
   * What it does:
   * Lazily constructs and returns the global preregistered RTTI map.
   */
  inline TypeInfoMap& GetRTypePreregisteredMap()
  {
    static TypeInfoMap gMap;
    return gMap;
  }

  /**
   * Address: 0x008E0750 (FA), 0x1001CDC0 (gpgcore.dll)
   *
   * type_info const &
   *
   * What it does:
   * Resolves a preregistered type descriptor by RTTI and lazily finalizes
   * registration (`Init` + `RegisterType`) on first lookup.
   */
  RType* LookupRType(const std::type_info& typeInfo);

  /**
   * Address: 0x008DF850 (FUN_008DF850), 0x1001BBC0 (gpgcore.dll)
   *
   * type_info const &, gpg::RType *
   *
   * What it does:
   * Adds a type descriptor to the RTTI preregistration map.
   */
  void PreRegisterRType(const std::type_info& typeInfo, RType* type);

  /**
   * The reflected type of `T`, looked up once and kept in one cache slot per
   * `T` for the whole program: `RListType<SNamedFootprint>`'s `GetName`,
   * `SerLoad` and `SerSave` all read 0x010C6DC4, `list<ESiloType>`'s read
   * 0x010C6D78, and `Rect2<int>`'s 0x010C6D98 is shared by 21 functions in
   * seven translation units. Each read is the inlined
   * `if (!slot) slot = LookupRType(typeid(T));`.
   *
   * Where `T` declares its own `static RType* sType` (`SDecalInfo`,
   * 0x010C76F8) the binary's slot is that member. The slot here is the
   * template's own: a `T::sType` test would also find a base class's member
   * through a derived `T` and hand back the base's type. Both slots hold the
   * same lookup.
   *
   * Out-of-line copies with no callers:
   *
   * Address: 0x0073AAC0 (FUN_0073AAC0 -- `RTypeOf<moho::CDamageMethod>`, slot 0x010C768C; formerly
   * `CachedDamageMethodType` in moho/sim/CDamage.cpp, which also called `preregister_CDamageEMethodTypeInfo`
   * first -- the binary does not; removed 2026-09-30.)
   * Address: 0x0073AAE0 (FUN_0073AAE0 -- `RTypeOf<moho::SMinMax<float>>`; formerly `CachedSMinMaxFloatType`
   * in moho/sim/CDamage.cpp, removed 2026-09-30.)
   * Address: 0x0054CFC0 (FUN_0054CFC0 -- `RTypeOf<moho::CAniDefaultSkel>`; formerly `CachedDefaultSkelType` in
   * moho/animation/CAniDefaultSkelConstruct.cpp, removed 2026-09-30.)
   * Address: 0x0050D390 (FUN_0050D390 -- `RTypeOf<gpg::Rect2i>`, slot 0x010C6D98; formerly `CachedRect2iType`
   * in gpg/core/reflection/Reflection.cpp, removed 2026-10-01.)
   *
   * A pointer type is the exception: its descriptor is the pointee's
   * `RPointerType` object, which `U::GetPointerType()` constructs before it
   * looks `U*` up, so the lookup goes through that function
   * (`RListType<Entity*>::GetName` 0x00685DF0 calls `Entity::GetPointerType`
   * 0x0067CFA0).
   */
  template <class T>
  [[nodiscard]] RType* RTypeOf()
  {
    if constexpr (std::is_pointer_v<T>) {
      return std::remove_pointer_t<T>::GetPointerType();
    } else {
      static RType* sType = nullptr;
      if (sType == nullptr) {
        sType = LookupRType(typeid(T));
      }
      return sType;
    }
  }

  /**
   * Address: 0x0053B1E0 (FUN_0053B1E0 -- `SetShared<moho::RScaResource>`; formerly `SetConstructResultSharedScaResource` in moho/resource/RScaResource.cpp.)
   * Address: 0x00539D80 (FUN_00539D80 -- `SetShared<moho::RScmResource>`; formerly `SetConstructResultSharedModelResource` in moho/resource/RScmResource.cpp.)
   * Address: 0x00539C80 (FUN_00539C80 -- `SetShared<const moho::CAniSkel>`; formerly `SetConstructResultSharedAniSkel` in moho/resource/CAniResourceSkelConstruct.cpp.)
   *
   * What it does:
   * Copies the pointer into a `shared_ptr<void>`, looks up `T`'s type through
   * its cache slot, and hands both to the untyped `SetShared`.
   */
  template <class T>
  void SerConstructResult::SetShared(const boost::shared_ptr<T>& object, const unsigned int flags)
  {
    using Object = std::remove_const_t<T>;
    SetShared(boost::shared_ptr<void>(boost::const_pointer_cast<Object>(object)), RTypeOf<Object>(), flags);
  }

  RRef REF_UpcastPtr(const RRef& source, const RType* targetType);

  template <class T>
  T* RRef::Upcast() const
  {
    return static_cast<T*>(REF_UpcastPtr(*this, RTypeOf<T>()).mObj);
  }

  /**
   * Address: 0x005DE010 (FUN_005DE010, preregister_CAcquireTargetTaskPointerTypeStartup)
   *
   * What it does:
   * Preregisters the startup-owned pointer reflection descriptor for
   * `moho::CAcquireTargetTask*`.
   */
  [[nodiscard]] RType* preregister_CAcquireTargetTaskPointerTypeStartup();

  /**
   * Address: 0x0074FE70 (FUN_0074FE70, preregister_SimArmyPointerTypeStartup)
   *
   * What it does:
   * Preregisters the startup-owned pointer reflection descriptor for
   * `moho::SimArmy*`.
   */
  [[nodiscard]] RType* preregister_SimArmyPointerTypeStartup();

  /**
   * Address: 0x00750280 (FUN_00750280, preregister_ShieldPointerTypeStartup)
   *
   * What it does:
   * Preregisters the startup-owned pointer reflection descriptor for
   * `moho::Shield*`.
   */
  [[nodiscard]] RType* preregister_ShieldPointerTypeStartup();

  /**
   * Address: 0x0077EBA0 (FUN_0077EBA0, preregister_CDecalHandlePointerTypeStartup)
   *
   * What it does:
   * Preregisters the startup-owned pointer reflection descriptor for
   * `moho::CDecalHandle*`.
   */
  [[nodiscard]] RType* preregister_CDecalHandlePointerTypeStartup();

  /**
   * Address: 0x007522B0 (FUN_007522B0, register/preregister of RVectorType<SimArmy*>)
   *
   * What it does:
   * Constructs the startup-owned `gpg::RVectorType<moho::SimArmy*>` descriptor
   * global (installing both vtables) and preregisters it under
   * `typeid(std::vector<moho::SimArmy*>)`.
   */
  [[nodiscard]] RType* preregister_SimArmyVectorTypeStartup();

  /**
   * Address: 0x0074E240 (FUN_0074E240, gpg::RVectorType<SimArmy*> element deserializer)
   *
   * What it does:
   * Reads the element count, then reads that many tracked `moho::SimArmy*`
   * pointers and installs them into the destination `std::vector<moho::SimArmy*>`
   * addressed by `vectorPtr`. Signature matches `RType::load_func_t`; the
   * trailing version/owner lanes are unused by this vector body.
   */
  void DeserializeSimArmyPtrVector(ReadArchive* archive, int vectorPtr, int version, RRef* ownerRef);

  /**
   * Address: 0x0074E350 (FUN_0074E350, gpg::RVectorType<SimArmy*> element serializer)
   *
   * What it does:
   * Writes the element count, then writes each `moho::SimArmy*` element as one
   * unowned tracked raw pointer. Signature matches `RType::save_func_t`; the
   * trailing version/owner lanes are unused by this vector body.
   */
  void SerializeSimArmyPtrVector(WriteArchive* archive, int vectorPtr, int version, RRef* ownerRef);

  /**
   * Address: 0x008E0810 (FUN_008E0810, gpg::REF_RegisterAllTypes)
   * Address: 0x1001CEB0 (gpgcore.dll)
   *
   * What it does:
   * Forces lazy registration for all preregistered RTTI entries.
   */
  void REF_RegisterAllTypes();

  /**
   * Address: 0x008DD940 (FUN_008DD940, gpg::REF_GetTypeIndexed)
   * Address: 0x10018CB0 (gpgcore.dll)
   *
   * int
   *
   * What it does:
   * Returns the type descriptor at an index in the global registration vector.
   */
  const RType* REF_GetTypeIndexed(int index);

  /**
   * Address: 0x008DF950 (FUN_008DF950, gpg::REF_GetTypeCount)
   *
   * What it does:
   * Returns the total reflected type count stored in the global type map.
   */
  std::size_t REF_GetTypeCount();

  /**
   * Address: 0x008DF8A0
   * Address: 0x008DF910 (FUN_008DF910, gpg::REF_FindTypeNamed `_0` overload)
   *
   * char const *
   *
   * What it does:
   * Returns registered reflection descriptor by exact type-name lookup.
   */
  RType* REF_FindTypeNamed(const char* name);

  /**
   * Address: 0x008D9590 (FUN_008D9590, gpg::REF_UpcastPtr)
   *
   * gpg::RRef const &, gpg::RType const *
   *
   * What it does:
   * Recursively walks base-type lanes and returns one upcasted reflected pointer
   * reference when a compatible base is found.
   */
  RRef REF_UpcastPtr(const RRef& source, const RType* targetType);

  /**
   * Address: 0x00582080 (FUN_00582080, gpg::RRef_int pack lane)
   *
   * What it does:
   * Builds one temporary `RRef_int` and copies its `(mObj,mType)` pair into
   * caller-owned output storage.
   */
  RRef* PackRRef_int(RRef* out, int* value);

  /**
   * Address: 0x00582050 (FUN_00582050, gpg::RRef_bool pack lane)
   *
   * What it does:
   * Builds one temporary `RRef_bool` and copies its `(mObj,mType)` pair into
   * caller-owned output storage.
   */
  RRef* PackRRef_bool(RRef* out, bool* value);

  /**
   * Address: 0x00402D30 (FUN_00402D30, sub_402D30)
   *
   * What it does:
   * Wrapper that assigns `RRef_uint` output lanes into the provided `RRef`.
   */
  RRef* AssignUIntRef(RRef* out, unsigned int* value);

  /**
   * Address: 0x008E1B70 (FUN_008E1B70)
   *
   * What it does:
   * Wrapper that assigns `RRef_ulong` output lanes into the provided `RRef`.
   */
  RRef* AssignULongRef(RRef* out, unsigned long* value);

  /**
   * Address: 0x0084A140 (FUN_0084A140, sub_84A140)
   *
   * What it does:
   * Wrapper that assigns `RRef_ESTITargetType` output lanes into provided
   * `RRef`.
   */
  RRef* AssignESTITargetTypeRef(RRef* out, moho::ESTITargetType* value);

  /**
   * Address: 0x00704040 (FUN_00704040, sub_704040)
   *
   * What it does:
   * Wrapper that assigns `RRef_ESquadClass` output lanes into provided `RRef`.
   */
  RRef* AssignESquadClassRef(RRef* out, moho::ESquadClass* value);

  /**
   * Address: 0x0078A9D0 (FUN_0078A9D0, sub_78A9D0)
   *
   * What it does:
   * Wrapper that materializes one temporary `RRef_EMauiScrollAxis` and copies
   * its object/type lanes into the destination ref.
   */
  RRef* AssignEMauiScrollAxisRef(RRef* out, moho::EMauiScrollAxis* value);

  /**
   * Address: 0x00795DD0 (FUN_00795DD0, sub_795DD0)
   *
   * What it does:
   * Wrapper that materializes one temporary `RRef_EMauiEventType` and copies
   * its object/type lanes into the destination ref.
   */
  RRef* AssignEMauiEventTypeRef(RRef* out, moho::EMauiEventType* value);

  /**
   * Address: 0x00830D40 (FUN_00830D40, sub_830D40)
   *
   * What it does:
   * Primary wrapper that materializes one temporary `RRef_EUnitCommandType`
   * and copies its object/type lanes into the destination ref.
   */
  RRef* AssignEUnitCommandTypeRefPrimary(RRef* out, moho::EUnitCommandType* value);

  /**
   * Address: 0x0084A170 (FUN_0084A170, sub_84A170)
   *
   * What it does:
   * Secondary wrapper that materializes one temporary `RRef_EUnitCommandType`
   * and copies its object/type lanes into the destination ref.
   */
  RRef* AssignEUnitCommandTypeRefSecondary(RRef* out, moho::EUnitCommandType* value);

  /**
   * Address: 0x006B0C20 (FUN_006B0C20)
   *
   * What it does:
   * Materializes one temporary `RRef_EUnitState` and copies `(mObj,mType)`
   * into caller-owned output storage.
   */
  RRef* PackRRef_EUnitState(RRef* out, moho::EUnitState* value);

  /**
   * Address: 0x008BEC10 (FUN_008BEC10)
   *
   * What it does:
   * Materializes one temporary `RRef_EFireState` and copies `(mObj,mType)`
   * into caller-owned output storage.
   */
  RRef* PackRRef_EFireState(RRef* out, moho::EFireState* value);

  /**
   * Address: 0x0084A380 (FUN_0084A380)
   * Address: 0x008CD130 (FUN_008CD130)
   *
   * What it does:
   * Materializes one temporary `RRef_ESpecialFileType` and copies
   * `(mObj,mType)` into caller-owned output storage.
   */
  RRef* AssignESpecialFileTypeRefAdapter(RRef* out, moho::ESpecialFileType* value);

  /**
   * Address: 0x0085F840 (FUN_0085F840, sub_85F840)
   *
   * What it does:
   * Wrapper that materializes one temporary `RRef_EGenericIconType` and copies
   * its object/type lanes into the destination ref.
   */
  RRef* AssignEGenericIconTypeRef(RRef* out, moho::EGenericIconType* value);

  /**
   * Address: 0x0063A2B0 (FUN_0063A2B0, gpg::RRef_CFootPlantManipulator)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CFootPlantManipulator`
   * object pointer with derived-type normalization.
   */
  RRef* RRef_CFootPlantManipulator(RRef* out, moho::CFootPlantManipulator* value);

  /**
   * Address: 0x0063A230 (FUN_0063A230)
   *
   * What it does:
   * Wrapper lane that materializes one temporary
   * `RRef_CFootPlantManipulator` and copies object/type fields into the
   * destination reference record.
   */
  RRef* AssignCFootPlantManipulatorRef(RRef* out, moho::CFootPlantManipulator* value);

  /**
   * Address: 0x006456F0 (FUN_006456F0, gpg::RRef_CRotateManipulator)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CRotateManipulator` object
   * pointer with derived-type normalization.
   */
  RRef* RRef_CRotateManipulator(RRef* out, moho::CRotateManipulator* value);

  /**
   * Address: 0x00649C00 (FUN_00649C00, gpg::RRef_CStorageManipulator)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CStorageManipulator` object
   * pointer with derived-type normalization.
   */
  RRef* RRef_CStorageManipulator(RRef* out, moho::CStorageManipulator* value);

  /**
   * Address: 0x0064B530 (FUN_0064B530, gpg::RRef_CThrustManipulator)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CThrustManipulator` object
   * pointer with derived-type normalization.
   */
  RRef* RRef_CThrustManipulator(RRef* out, moho::CThrustManipulator* value);

  /**
   * Address: 0x005DF0C0 (FUN_005DF0C0)
   *
   * What it does:
   * Packs one `RRef_CAcquireTargetTask_P` result into caller-owned output
   * storage.
   */
  RRef* PackRRef_CAcquireTargetTask_P(RRef* out, moho::CAcquireTargetTask** value);

  /**
   * Address: 0x0066C480 (FUN_0066C480, gpg::RRef_CEffectManagerImpl)
   *
   * What it does:
   * Builds a reflected reference for a `moho::CEffectManagerImpl` object
   * pointer with derived-type normalization.
   */
  RRef* RRef_CEffectManagerImpl(RRef* out, moho::CEffectManagerImpl* value);

  /**
   * Address: 0x0066C2A0 (FUN_0066C2A0, gpg::RRef_CEffectManagerImpl pack lane)
   *
   * What it does:
   * Builds one temporary `RRef_CEffectManagerImpl` and copies its
   * `(mObj,mType)` pair into caller-owned output storage.
   */
  RRef* PackRRef_CEffectManagerImpl(RRef* out, moho::CEffectManagerImpl* value);

  /**
   * Address: 0x0066D0B0 (FUN_0066D0B0, gpg::RRef_IEffect pack lane)
   *
   * What it does:
   * Builds one temporary `RRef_IEffect` and copies its `(mObj,mType)` pair
   * into caller-owned output storage.
   */
  RRef* PackRRef_IEffect(RRef* out, moho::IEffect* value);

  /**
   * Address: 0x00658750 (FUN_00658750, gpg::RRef_CEfxBeam pack lane)
   *
   * What it does:
   * Builds one temporary `RRef_CEfxBeam` and copies its `(mObj,mType)` pair
   * into caller-owned output storage.
   */
  RRef* PackRRef_CEfxBeam(RRef* out, moho::CEfxBeam* value);

  /**
   * Address: 0x0065A7E0 (FUN_0065A7E0, gpg::RRef_CountedPtr_CParticleTexture pack lane)
   *
   * What it does:
   * Builds one temporary `RRef_CountedPtr_CParticleTexture` and copies its
   * `(mObj,mType)` pair into caller-owned output storage.
   */
  RRef* PackRRef_CountedPtr_CParticleTexture(RRef* out, moho::CountedPtr<moho::CParticleTexture>* value);

  /**
   * Address: 0x0065FA20 (FUN_0065FA20, gpg::RRef_SEfxCurve pack lane)
   *
   * What it does:
   * Builds one temporary `RRef_SEfxCurve` and copies its `(mObj,mType)` pair
   * into caller-owned output storage.
   */
  RRef* PackRRef_SEfxCurve(RRef* out, moho::SEfxCurve* value);

  /**
   * Address: 0x0065FF20 (FUN_0065FF20, gpg::RRef_CEfxEmitter)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CEfxEmitter` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_CEfxEmitter(RRef* out, moho::CEfxEmitter* value);

  /**
   * Address: 0x0065FB30 (FUN_0065FB30, gpg::RRef_CEfxEmitter pack lane)
   * Address: 0x00608000 (FUN_00608000)
   *
   * What it does:
   * Builds one temporary `RRef_CEfxEmitter` and copies its `(mObj,mType)` pair
   * into caller-owned output storage.
   */
  RRef* PackRRef_CEfxEmitter(RRef* out, moho::CEfxEmitter* value);

  /**
   * Address: 0x00672560 (FUN_00672560, gpg::RRef_CEfxTrailEmitter)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CEfxTrailEmitter` object
   * pointer with derived-type normalization.
   */
  RRef* RRef_CEfxTrailEmitter(RRef* out, moho::CEfxTrailEmitter* value);

  /**
   * Address: 0x00672510 (FUN_00672510, gpg::RRef_CEfxTrailEmitter pack lane)
   *
   * What it does:
   * Builds one temporary `RRef_CEfxTrailEmitter` and copies its `(mObj,mType)`
   * pair into caller-owned output storage.
   */
  RRef* PackRRef_CEfxTrailEmitter(RRef* out, moho::CEfxTrailEmitter* value);

  /**
   * Address: 0x0066D0E0 (FUN_0066D0E0, gpg::RRef_IEffect_P pack lane)
   *
   * What it does:
   * Builds one temporary `RRef_IEffect_P` and copies its `(mObj,mType)` pair
   * into caller-owned output storage.
   */
  RRef* PackRRef_IEffect_P(RRef* out, moho::IEffect** value);

  /**
   * Address: 0x00761B70 (FUN_00761B70)
   *
   * What it does:
   * Builds one reflected reference from the `index`-th contiguous
   * `SAudioRequest` lane starting at `(*firstElementSlot)`.
   */
  RRef* RRef_SAudioRequestArraySlot(RRef* out, moho::SAudioRequest* const* firstElementSlot, int index);

  /**
   * Address: 0x006755A0 (FUN_006755A0, helper lane)
   *
   * What it does:
   * Materializes a temporary `RRef_CollisionBeamEntity` and copies its object
   * and type lanes into the destination reference.
   */
  RRef* AssignCollisionBeamEntityRef(RRef* out, moho::CollisionBeamEntity* value);

  /**
   * Address: 0x006FAE00 (FUN_006FAE00)
   *
   * What it does:
   * Packs one `RRef_Prop` result into caller-owned output storage.
   */
  RRef* PackRRef_Prop(RRef* out, moho::Prop* value);

  /**
   * Address: 0x0067F700 (FUN_0067F700, gpg::RRef_Entity_P pack lane)
   *
   * What it does:
   * Builds one temporary `RRef_Entity_P` and copies its `(mObj,mType)` pair
   * into caller-owned output storage.
   */
  RRef* PackRRef_Entity_P(RRef* out, moho::Entity** value);

  /**
   * Address: 0x006B1320 (FUN_006B1320)
   *
   * What it does:
   * Materializes one temporary `RRef_WeakPtr_Entity` and copies `(mObj,mType)`
   * into caller-owned output storage.
   */
  RRef* PackRRef_WeakPtr_Entity(RRef* out, moho::WeakPtr<moho::Entity>* value);

  /**
   * Address: 0x00688D30 (FUN_00688D30, sub_688D30)
   *
   * What it does:
   * Wrapper that materializes one temporary `RRef_EntityDB` and copies its
   * object/type lanes into the destination ref.
   */
  RRef* AssignEntityDBRef(RRef* out, moho::EntityDB* value);

  /**
   * Address: 0x00698D60 (FUN_00698D60, gpg::RRef_SPhysConstants pack lane A)
   *
   * What it does:
   * Builds one temporary `RRef_SPhysConstants` and copies its `(mObj,mType)`
   * pair into caller-owned output storage.
   */
  RRef* PackRRef_SPhysConstantsA(RRef* out, moho::SPhysConstants* value);

  /**
   * Address: 0x0069A0A0 (FUN_0069A0A0, gpg::RRef_SPhysConstants pack lane B)
   *
   * What it does:
   * Secondary pack lane that builds one temporary `RRef_SPhysConstants` and
   * copies its `(mObj,mType)` pair into caller-owned output storage.
   */
  RRef* PackRRef_SPhysConstantsB(RRef* out, moho::SPhysConstants* value);

  /**
   * Address: 0x00698850 (FUN_00698850, sub_698850)
   *
   * What it does:
   * Wrapper that materializes one temporary `RRef_SPhysBody` and copies its
   * object/type lanes into the destination ref.
   */
  RRef* AssignSPhysBodyRef(RRef* out, moho::SPhysBody* value);

  /**
   * Address: 0x006B1040 (FUN_006B1040)
   *
   * What it does:
   * Materializes one temporary `RRef_Unit` and copies `(mObj,mType)` into
   * caller-owned output storage.
   */
  RRef* PackRRef_Unit(RRef* out, moho::Unit* value);

  /**
   * Address: 0x00541A90 (FUN_00541A90, gpg::RRef_IUnit pack lane)
   *
   * What it does:
   * Builds one temporary `RRef_IUnit` and copies its `(mObj,mType)` pair into
   * caller-owned output storage.
   */
  RRef* PackRRef_IUnit(RRef* out, moho::IUnit* value);

  /**
   * Address: 0x00571030 (FUN_00571030)
   *
   * What it does:
   * Builds one temporary `RRef_WeakPtr_IUnit` and copies its `(mObj,mType)`
   * pair into caller-owned output storage.
   */
  RRef* PackRRef_WeakPtr_IUnit(RRef* out, moho::WeakPtr<moho::IUnit>* value);

  /**
   * Address: 0x00768C70 (FUN_00768C70)
   *
   * What it does:
   * Builds one temporary `RRef_PathQueue` and copies its `(mObj,mType)` pair
   * into caller-owned output storage.
   */
  RRef* PackRRef_PathQueue(RRef* out, moho::PathQueue* value);

  /**
   * Address: 0x00916E60 (FUN_00916E60, gpg::RRef_WrapFile)
   *
   * What it does:
   * Builds a reflected reference for a `WrapFile` payload (internal
   * LuaObject.cpp userdata type) using the cached RTTI lookup and 3-slot
   * TLS derived-type normalization helper. Object argument is passed as
   * `void*` because `WrapFile` is an anonymous-namespace struct in
   * `LuaObject.cpp`; callers inside that TU use the named typed overload.
   */
  RRef* RRef_WrapFile(RRef* out, void* object);

  /**
   * Address: 0x00697000 (FUN_00697000, gpg::RRef_MotorSinkAway)
   *
   * What it does:
   * Builds a reflected reference for one `moho::MotorSinkAway` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_MotorSinkAway(RRef* out, moho::MotorSinkAway* value);

  /**
   * Address: 0x0050E270 (FUN_0050E270, gpg::RRef_RBlueprint pack lane)
   *
   * What it does:
   * Builds one temporary `RRef_RBlueprint` and copies its `(mObj,mType)` pair
   * into caller-provided storage.
   */
  RRef* PackRRef_RBlueprint(RRef* out, moho::RBlueprint* value);

  /**
   * Address: 0x00537850 (FUN_00537850)
   *
   * What it does:
   * Thin adapter lane that forwards `{out,value}` into `RRef_RRuleGameRules`.
   */
  RRef* AssignRRuleGameRulesRef(RRef* out, moho::RRuleGameRules* value);

  /**
   * Address: 0x00533210 (FUN_00533210)
   *
   * What it does:
   * Materializes one temporary `RRef_SRuleFootprintsBlueprint` and copies
   * object/type lanes into `out`.
   */
  RRef* AssignSRuleFootprintsBlueprintRef(RRef* out, moho::SRuleFootprintsBlueprint* value);

  /**
   * Address: 0x00548950 (FUN_00548950, gpg::RRef_ResourceDeposit pack lane)
   * Address: 0x005FD5D0 (FUN_005FD5D0)
   *
   * What it does:
   * Builds one temporary `RRef_ResourceDeposit` and copies its `(mObj,mType)`
   * pair into caller-provided storage.
   */
  RRef* PackRRef_ResourceDeposit(RRef* out, moho::ResourceDeposit* value);

  /**
   * Address: 0x005110D0 (FUN_005110D0, gpg::RRef_REmitterBlueprint pack lane)
   *
   * What it does:
   * Builds one temporary `RRef_REmitterBlueprint` and copies its
   * `(mObj,mType)` pair into caller-provided storage.
   */
  RRef* PackRRef_REmitterBlueprint(RRef* out, moho::REmitterBlueprint* value);

  /**
   * Address: 0x00511170 (FUN_00511170, gpg::RRef_RBeamBlueprint pack lane)
   *
   * What it does:
   * Builds one temporary `RRef_RBeamBlueprint` and copies its `(mObj,mType)`
   * pair into caller-provided storage.
   */
  RRef* PackRRef_RBeamBlueprint(RRef* out, moho::RBeamBlueprint* value);

  /**
   * Address: 0x00511120 (FUN_00511120, gpg::RRef_RTrailBlueprint pack lane)
   *
   * What it does:
   * Builds one temporary `RRef_RTrailBlueprint` and copies its `(mObj,mType)`
   * pair into caller-provided storage.
   */
  RRef* PackRRef_RTrailBlueprint(RRef* out, moho::RTrailBlueprint* value);

  /**
   * Address: 0x00536B70 (FUN_00536B70)
   *
   * What it does:
   * Materializes one temporary `RRef_EntityCategory` and copies object/type
   * lanes into `out`.
   */
  RRef* AssignEntityCategoryRef(RRef* out, moho::EntityCategorySet* value);

  /**
   * Address: 0x00723A10 (FUN_00723A10, sub_723A10)
   *
   * What it does:
   * Wrapper that materializes one temporary `RRef_COGrid` and copies its
   * object/type lanes into the destination ref.
   */
  RRef* AssignCOGridRef(RRef* out, moho::COGrid* value);

  /**
   * Address: 0x007047B0 (FUN_007047B0)
   *
   * What it does:
   * Packs one `RRef_CArmyImpl` result into caller-owned output storage.
   */
  RRef* PackRRef_CArmyImpl(RRef* out, moho::CArmyImpl* value);

  /**
   * Address: 0x00751790 (FUN_00751790)
   *
   * What it does:
   * Packs one temporary `RRef_SimArmy_P` result into caller-owned output
   * storage by copying the `(mObj,mType)` lane pair.
   */
  RRef* PackRRef_SimArmy_P(RRef* out, moho::SimArmy** value);

  /**
   * Address: 0x00751E20 (FUN_00751E20)
   *
   * What it does:
   * Packs one temporary `RRef_SimArmy` result into caller-owned output storage
   * by copying the `(mObj,mType)` lane pair.
   */
  RRef* PackRRef_SimArmy(RRef* out, moho::SimArmy* value);

  // FUN_0074FD80 (GetName) and FUN_0074FF10 (GetLexical) are recovered as
  // methods of RPointerType<moho::SimArmy> (below); the earlier free-helper
  // declarations were re-homed into that specialization.

  /**
   * Address: 0x005446D0 (FUN_005446D0, gpg::RRef_LaunchInfoNew pack lane)
   *
   * What it does:
   * Builds one temporary `RRef_LaunchInfoNew` and copies its `(mObj,mType)`
   * pair into caller-owned output storage.
   */
  RRef* PackRRef_LaunchInfoNew(RRef* out, moho::LaunchInfoNew* value);

  /**
   * Address: 0x00544C80 (FUN_00544C80, gpg::RRef_ArmyLaunchInfo)
   *
   * What it does:
   * Builds a reflected reference for one `moho::ArmyLaunchInfo` value pointer.
   */
  RRef* RRef_ArmyLaunchInfo(RRef* out, moho::ArmyLaunchInfo* value);

  /**
   * Address: 0x005444E0 (FUN_005444E0, gpg::RRef_ArmyLaunchInfo pack lane)
   *
   * What it does:
   * Builds one temporary `RRef_ArmyLaunchInfo` and copies its `(mObj,mType)`
   * pair into caller-owned output storage.
   */
  RRef* PackRRef_ArmyLaunchInfo(RRef* out, moho::ArmyLaunchInfo* value);

  /**
   * Address: 0x00548BD0 (FUN_00548BD0, gpg::RRef_CSimResources pack lane)
   *
   * What it does:
   * Builds one temporary `RRef_CSimResources` and copies its `(mObj,mType)`
   * pair into caller-provided storage.
   */
  RRef* PackRRef_CSimResources(RRef* out, moho::CSimResources* value);

  /**
   * Address: 0x005818C0 (FUN_005818C0, gpg::RRef_CAiBrain pack lane)
   *
   * What it does:
   * Builds one temporary `RRef_CAiBrain` and copies its `(mObj,mType)` pair
   * into caller-owned output storage.
   */
  RRef* PackRRef_CAiBrain(RRef* out, moho::CAiBrain* value);

  /**
   * Address: 0x00572930 (FUN_00572930, gpg::RRef_SAssignedLocInfo)
   *
   * What it does:
   * Builds a reflected reference for one `moho::SAssignedLocInfo` value pointer.
   */
  RRef* RRef_SAssignedLocInfo(RRef* out, moho::SAssignedLocInfo* value);

  /**
   * Address: 0x00571090 (FUN_00571090)
   *
   * What it does:
   * Builds one temporary `RRef_SAssignedLocInfo` and copies its `(mObj,mType)`
   * pair into caller-owned output storage.
   */
  RRef* PackRRef_SAssignedLocInfo(RRef* out, moho::SAssignedLocInfo* value);

  /**
   * Address: 0x006288A0 (FUN_006288A0, gpg::RRef_SPickUpInfo)
   *
   * What it does:
   * Builds a reflected reference for one `moho::SPickUpInfo` value pointer.
   */
  RRef* RRef_SPickUpInfo(RRef* out, moho::SPickUpInfo* value);

  /**
   * Address: 0x006E3DB0 (FUN_006E3DB0)
   *
   * What it does:
   * Packs one temporary `RRef_CUnitCommand` result into caller-owned output
   * storage.
   */
  RRef* PackRRef_CUnitCommand(RRef* out, moho::CUnitCommand* value);

  /**
   * Address: 0x006E3DE0 (FUN_006E3DE0)
   *
   * What it does:
   * Packs one temporary `RRef_CUnitCommand_P` result into caller-owned output
   * storage.
   */
  RRef* PackRRef_CUnitCommand_P(RRef* out, moho::CUnitCommand** value);

  /**
   * Address: 0x006EB770 (FUN_006EB770)
   *
   * What it does:
   * Packs one `RRef_WeakPtr_CUnitCommand` result into caller-owned output
   * storage.
   */
  RRef* PackRRef_WeakPtr_CUnitCommand(RRef* out, moho::WeakPtr<moho::CUnitCommand>* value);

  /**
   * Address: 0x006F8D30 (FUN_006F8D30)
   *
   * What it does:
   * Packs one `RRef_CUnitCommandQueue` result into caller-owned output
   * storage.
   */
  RRef* PackRRef_CUnitCommandQueue(RRef* out, moho::CUnitCommandQueue* value);

  /**
   * Address: 0x005DF5E0 (FUN_005DF5E0)
   *
   * What it does:
   * Packs one `RRef_UnitWeapon` result into caller-owned output storage.
   */
  RRef* PackRRef_UnitWeapon(RRef* out, moho::UnitWeapon* value);

  /**
   * Address: 0x0055F020 (FUN_0055F020, gpg::RRef_UnitWeaponInfo)
   *
   * What it does:
   * Builds a reflected reference for one `moho::UnitWeaponInfo` value pointer.
   */
  RRef* RRef_UnitWeaponInfo(RRef* out, moho::UnitWeaponInfo* value);

  /**
   * Address: 0x005DF090 (FUN_005DF090)
   *
   * What it does:
   * Packs one `RRef_UnitWeapon_P` result into caller-owned output storage.
   */
  RRef* PackRRef_UnitWeapon_P(RRef* out, moho::UnitWeapon** value);

  /**
   * Address: 0x00404180 (FUN_00404180, sub_404180)
   *
   * What it does:
   * Wrapper that assigns `RRef_IdPool` output lanes into the provided `RRef`.
   */
  RRef* AssignIdPoolRef(RRef* out, moho::IdPool* value);

  /**
   * Address: 0x00572790 (FUN_00572790, gpg::RRef_SOffsetInfo)
   *
   * What it does:
   * Builds a reflected reference for one `moho::SOffsetInfo` value pointer.
   */
  RRef* RRef_SOffsetInfo(RRef* out, moho::SOffsetInfo* value);

  /**
   * Address: 0x00571060 (FUN_00571060)
   *
   * What it does:
   * Builds one temporary `RRef_SOffsetInfo` and copies its `(mObj,mType)`
   * pair into caller-owned output storage.
   */
  RRef* PackRRef_SOffsetInfo(RRef* out, moho::SOffsetInfo* value);

  /**
   * Address: 0x00763C20 (FUN_00763C20, sub_763C20)
   *
   * What it does:
   * Wrapper that materializes one temporary `RRef_HPathCell` and copies its
   * object/type lanes into the destination ref.
   */
  RRef* AssignHPathCellRef(RRef* out, moho::HPathCell* value);

  /**
   * Address: 0x00712AF0 (FUN_00712AF0, sub_712AF0)
   *
   * What it does:
   * Wrapper that materializes one temporary `RRef_CArmyStatItem_P` and copies
   * its object/type lanes into the destination ref.
   */
  RRef* AssignCArmyStatItemPointerRef(RRef* out, moho::CArmyStatItem** value);

  /**
   * Address: 0x006B3CD0 (FUN_006B3CD0)
   *
   * What it does:
   * Materializes one temporary `RRef_CEconomyEvent_P` and copies
   * `(mObj,mType)` into caller-owned output storage.
   */
  RRef* PackRRef_CEconomyEvent_P(RRef* out, moho::CEconomyEvent** value);

  /**
   * Address: 0x006B3CA0 (FUN_006B3CA0, sub_6B3CA0)
   *
   * What it does:
   * Wrapper that materializes one temporary `RRef_CEconomyEvent` and copies
   * its object/type lanes into the destination ref.
   */
  RRef* AssignCEconomyEventRef(RRef* out, moho::CEconomyEvent* value);

  /**
   * Address: 0x0077DAF0 (FUN_0077DAF0)
   *
   * What it does:
   * Materializes one temporary `RRef_CDecalBuffer` and copies
   * `(mObj,mType)` into caller-owned output storage.
   */
  RRef* PackRRef_CDecalBuffer(RRef* out, moho::CDecalBuffer* value);

  /**
   * Address: 0x0077F400 (FUN_0077F400)
   *
   * What it does:
   * Materializes one temporary `RRef_CDecalHandle_P` and copies
   * `(mObj,mType)` into caller-owned output storage.
   */
  RRef* PackRRef_CDecalHandle_P(RRef* out, moho::CDecalHandle** value);

  // FUN_0077EAB0 (GetName) and FUN_0077EC40 (GetLexical) are recovered as
  // methods of RPointerType<moho::CDecalHandle> (below); the earlier free-helper
  // declarations were re-homed into that specialization.

  /**
   * Address: 0x0077DB30 (FUN_0077DB30)
   *
   * What it does:
   * Materializes one temporary `RRef_CDecalHandle` and copies
   * `(mObj,mType)` into caller-owned output storage.
   */
  RRef* PackRRef_CDecalHandle(RRef* out, moho::CDecalHandle* value);

  // FUN_0077EDF0 is the SubscriptIndex vtable slot of
  // RPointerType<moho::CDecalHandle> (below); the earlier free-helper
  // declaration (RRef_CDecalHandleArraySlot) was the same address and has been
  // re-homed into that specialization.

  /**
   * Address: 0x005DEB80 (FUN_005DEB80)
   *
   * What it does:
   * Packs one `RRef_CAiAttackerImpl` result into caller-owned output storage.
   */
  RRef* PackRRef_CAiAttackerImpl(RRef* out, moho::CAiAttackerImpl* value);

  /**
   * Address: 0x005EC3B0 (FUN_005EC3B0, gpg::RRef_CAiTransportImpl pack lane)
   *
   * What it does:
   * Builds one temporary `RRef_CAiTransportImpl` and copies its `(mObj,mType)`
   * pair into caller-owned output storage.
   */
  RRef* PackRRef_CAiTransportImpl(RRef* out, moho::CAiTransportImpl* value);

  /**
   * Address: 0x005D4680 (FUN_005D4680)
   *
   * What it does:
   * Packs one `RRef_CAiSteeringImpl` result into caller-owned output storage.
   */
  RRef* PackRRef_CAiSteeringImpl(RRef* out, moho::CAiSteeringImpl* value);

  /**
   * Address: 0x005D08A0 (FUN_005D08A0)
   *
   * What it does:
   * Packs one `RRef_CAiSiloBuildImpl` result into caller-owned output storage.
   */
  RRef* PackRRef_CAiSiloBuildImpl(RRef* out, moho::CAiSiloBuildImpl* value);

  /**
   * Registers one reflected base on `typeInfo`, skipping silently when the
   * base type has not been looked up yet.
   *
   * The binary emits a distinct `AddBase_*` member per base on each type info;
   * they all reduce to this. Hoisted here because two TUs had already grown
   * their own file-private copy.
   */
  void AddBaseIfPresent(RType* typeInfo, RType* baseType, std::int32_t offset);

  /**
   * Address: 0x005EC420 (FUN_005EC420, gpg::RRef_SAiReservedTransportBone pack lane)
   *
   * What it does:
   * Builds one temporary `RRef_SAiReservedTransportBone` and copies its
   * `(mObj,mType)` pair into caller-owned output storage.
   */
  RRef* PackRRef_SAiReservedTransportBone(RRef* out, moho::SAiReservedTransportBone* value);

  /**
   * Address: 0x005EC450 (FUN_005EC450, gpg::RRef_SAttachPoint pack lane)
   *
   * What it does:
   * Builds one temporary `RRef_SAttachPoint` and copies its `(mObj,mType)`
   * pair into caller-owned output storage.
   */
  RRef* PackRRef_SAttachPoint(RRef* out, moho::SAttachPoint* value);

  /**
   * Address: 0x00581D60 (FUN_00581D60, gpg::RRef_SPointVector pack lane)
   *
   * What it does:
   * Builds one temporary `RRef_SPointVector` and copies its `(mObj,mType)`
   * pair into caller-owned output storage.
   */
  RRef* PackRRef_SPointVector(RRef* out, moho::SPointVector* value);

  /**
   * Address: 0x00651170 (FUN_00651170, gpg::RRef_RDebugNavPath pack lane)
   *
   * What it does:
   * Builds one temporary `RRef_RDebugNavPath` and copies its `(mObj,mType)`
   * pair into caller-owned output storage.
   */
  RRef* PackRRef_RDebugNavPath(RRef* out, moho::RDebugNavPath* value);

  /**
   * Address: 0x006511A0 (FUN_006511A0, gpg::RRef_RDebugNavWaypoints pack lane)
   *
   * What it does:
   * Builds one temporary `RRef_RDebugNavWaypoints` and copies its `(mObj,mType)`
   * pair into caller-owned output storage.
   */
  RRef* PackRRef_RDebugNavWaypoints(RRef* out, moho::RDebugNavWaypoints* value);

  /**
   * Address: 0x006511D0 (FUN_006511D0, gpg::RRef_RDebugNavSteering pack lane)
   *
   * What it does:
   * Builds one temporary `RRef_RDebugNavSteering` and copies its `(mObj,mType)`
   * pair into caller-owned output storage.
   */
  RRef* PackRRef_RDebugNavSteering(RRef* out, moho::RDebugNavSteering* value);

  /**
   * Address: 0x00653A50 (FUN_00653A50, gpg::RRef_RDebugWeapons pack lane)
   *
   * What it does:
   * Builds one temporary `RRef_RDebugWeapons` and copies its `(mObj,mType)`
   * pair into caller-owned output storage.
   */
  RRef* PackRRef_RDebugWeapons(RRef* out, moho::RDebugWeapons* value);

  /**
   * Address: 0x0076EA10 (FUN_0076EA10, sub_76EA10)
   *
   * What it does:
   * Wrapper that materializes one temporary `RRef_CIntel` and copies its
   * object/type lanes into the destination ref.
   */
  RRef* AssignCIntelRef(RRef* out, moho::CIntel* value);

  /**
   * Address: 0x0076FCE0 (FUN_0076FCE0, sub_76FCE0)
   *
   * What it does:
   * Wrapper that materializes one temporary `RRef_CIntelPosHandle` and copies
   * its object/type lanes into the destination ref.
   */
  RRef* AssignCIntelPosHandleRef(RRef* out, moho::CIntelPosHandle* value);

  /**
   * Address: 0x0067FB70 (FUN_0067FB70, sub_67FB70)
   *
   * What it does:
   * Wrapper that materializes one temporary `RRef_PositionHistory` and copies
   * its object/type lanes into the destination ref.
   */
  RRef* AssignPositionHistoryRef(RRef* out, moho::PositionHistory* value);

  /**
   * Address: 0x006BAC70 (FUN_006BAC70)
   *
   * What it does:
   * Materializes one temporary `RRef_CUnitMotion` and copies `(mObj,mType)`
   * into caller-owned output storage.
   */
  RRef* PackRRef_CUnitMotion(RRef* out, moho::CUnitMotion* value);

  /**
   * Address: 0x00751E60 (FUN_00751E60)
   *
   * What it does:
   * Packs one temporary `RRef_Shield` result into caller-owned output storage
   * by copying the `(mObj,mType)` lane pair.
   */
  RRef* PackRRef_Shield(RRef* out, moho::Shield* value);

  /**
   * Address: 0x00751F90 (FUN_00751F90)
   *
   * What it does:
   * Packs one temporary `RRef_Shield_P` result into caller-owned output
   * storage by copying the `(mObj,mType)` lane pair.
   */
  RRef* PackRRef_Shield_P(RRef* out, moho::Shield** value);

  // FUN_00750190 (GetName) and FUN_00750320 (GetLexical) are recovered as
  // methods of RPointerType<moho::Shield> (below); the earlier free-helper
  // declarations were re-homed into that specialization.

  /**
   * Address: 0x0040F590 (FUN_0040F590, sub_40F590)
   *
   * What it does:
   * Wrapper that assigns `RRef_CRandomStream` output lanes into provided `RRef`.
   */
  RRef* AssignCRandomStreamRef(RRef* out, moho::CRandomStream* value);

  /**
   * Address: 0x0072AC80 (FUN_0072AC80, sub_72AC80)
   *
   * What it does:
   * Wrapper that materializes one temporary `RRef_CPlatoon` and copies its
   * object/type lanes into the destination ref.
   */
  RRef* AssignCPlatoonRef(RRef* out, moho::CPlatoon* value);

  /**
   * Address: 0x00920500 (FUN_00920500, sub_920500)
   *
   * What it does:
   * Wrapper that materializes one temporary `RRef_Table` and copies its
   * object/type lanes into the destination ref.
   */
  RRef* AssignTableRef(RRef* out, Table* value);

  class RField
  {
  public:
    const char* mName;
    RType* mType;
    int mOffset;
    /// Access flags: the reference editor (`WRefEditDialog::AddChildren`
    /// 0x004A4260) lets a field be edited when `(mFlags & 3) == 3`. Blueprint
    /// ids and source paths are registered as 1, tunables as 3.
    int mFlags;
    const char* mDesc;

    RField();
    RField(const char* name, RType* type, int offset);
    RField(const char* name, RType* type, int offset, int v, const char* desc);
  };
  static_assert(sizeof(RField) == 0x14, "RField must be 0x14");

  class RType : public RObject
  {
    // Primary vftable (11 entries)
  public:
    // The two construct hooks are what let a type decide how its instances come
    // into being across an archive, instead of being default-built and then
    // filled in field by field. `CSndParams` is the clearest case: its save hook
    // writes an `SParamKey` and clears the write-members flag, and its load hook
    // reads that key back and returns the *shared* descriptor from
    // `FindOrCreateSndParamsByKey`, so both sides of a sync stream keep pointing
    // at one registered descriptor per (cue, bank, cutoff, rpc) tuple.
    //
    // The signatures are the ones the binary actually calls with, read off the
    // two dispatchers rather than guessed:
    //   0x00953720 `ReadRawPointer`  -> mSerConstructFunc(archive, version, ownerRef, result)
    //   0x00953320 `WriteRawPointer` -> mSerSaveConstructArgsFunc(archive, object, version, ownerRef, result)
    // Both are `__cdecl` free functions; the save hook's five arguments are
    // confirmed by the `CSndParams` thunk at 0x004E0C50, which takes arg_0..arg_10
    // and forwards arg_0, arg_4 and arg_10 to the body at 0x004E0CD0.
    using save_construct_args_func_t =
      void (*)(WriteArchive* archive, void* object, int version, RRef* ownerRef, SerSaveConstructArgsResult* result);
    using save_func_t = void (*)(WriteArchive*, int, int, RRef*);
    using construct_func_t =
      void (*)(ReadArchive* archive, int version, RRef* ownerRef, SerConstructResult* result);
    using load_func_t = void (*)(ReadArchive*, int, int, RRef*);
    using new_ref_func_t = RRef (*)();
    using cpy_ref_func_t = RRef (*)(RRef*);
    using delete_func_t = void (*)(void*);
    using ctor_ref_func_t = RRef (*)(void*);
    using mov_ref_func_t = RRef (*)(void*, RRef*);
    using dtr_func_t = void (*)(void*);

    static RType* sType;

    /**
     * Address: 0x00F8E540 -- dedicated `typeid(LuaPlus::TObject)` cache slot
     * hosted directly on `RType` rather than on the served type itself.
     *
     * Confirmed via a genuine linker-mangled symbol (not an IDA-guessed
     * label, unlike every sibling `T::sType` cache this session): the raw
     * asm at `TObjectSerializer`'s `Init()` (0x0091F8A0) reads/writes
     * `?TObject@RType@gpg@@3PAVRType@gpg@@A`, i.e. `gpg::RType::TObject`.
     * `LuaPlus::TObject` is a tightly `#pragma pack(push, 4)` tagged-value
     * POD reused inside `union Value`; the original engineers evidently
     * chose not to grow it with a reflection-owned static and centralized
     * this one cache on `RType` instead. Every other Lua runtime type
     * (`Table`, `Proto`, `Udata`, `LClosure`, `lua_State`) caches on its own
     * `T::sType` as usual -- this member is the sole confirmed exception.
     */
    static RType* TObject;

    /**
     * Address: 0x008DD950 (FUN_008DD950, ??0RType@gpg@@QAE@XZ_0)
     *
     * What it does:
     * Initializes base reflection descriptor lanes to empty defaults:
     * no handlers, zero size/version, and empty base/field vectors.
     */
    RType();

    /**
     * Address: 0x00401350 (FUN_00401350, gpg::RType::StaticGetClass)
     *
     * What it does:
     * Lazily resolves and caches the reflection descriptor for `gpg::RType`.
     */
    [[nodiscard]] static RType* StaticGetClass();

    /**
     * In binary: returns the family descriptor (descriptor for gpg::RType).
     *
     * Address: 0x00401370 (FUN_00401370)
     * SLOT: 0
     */
    [[nodiscard]]
    virtual RType* GetClass() const;

    /**
     * Packs { this, GetFamilyDescriptor() } into the provided handle.
     *
     * Address: 0x00401390 (FUN_00401390)
     * SLOT: 1
     */
    [[nodiscard]]
    virtual RRef GetDerivedObjectRef();

    /**
     * Address: 0x008DC130 (FUN_008DC130, gpg::RType::NewRef)
     *
     * What it does:
     * Invokes the registered default-constructor callback and returns the
     * produced reference, or throws `BadRefCast` when no constructor callback
     * is registered for this type.
     */
    [[nodiscard]] RRef NewRef() const;

    /**
     * Destructor.
     *
     * Address: 0x008DD9D0 (FUN_008DD9D0, gpg::RType::dtr)
     * Address: 0x00506F60 (FUN_00506F60, RType teardown COMDAT clone)
     * Address: 0x0050BC60 (FUN_0050BC60, RType teardown COMDAT clone)
     * Address: 0x0050BE90 (FUN_0050BE90, RType teardown COMDAT clone)
     * Address: 0x00518750 (FUN_00518750, RType teardown COMDAT clone)
     * Address: 0x0051C300 (FUN_0051C300, RType teardown COMDAT clone)
     * Address: 0x0051D6C0 (FUN_0051D6C0, RType teardown COMDAT clone)
     * Address: 0x0051D870 (FUN_0051D870, RType teardown COMDAT clone)
     * Address: 0x005218A0 (FUN_005218A0, RType teardown COMDAT clone)
     * Address: 0x005229E0 (FUN_005229E0, RType teardown COMDAT clone)
     * Address: 0x0053A360 (FUN_0053A360, RType teardown COMDAT clone)
     * Address: 0x00541490 (FUN_00541490, RType teardown COMDAT clone)
     * Address: 0x00550740 (FUN_00550740, RType teardown COMDAT clone)
     * Address: 0x005526C0 (FUN_005526C0, RType teardown COMDAT clone)
     * Address: 0x00552950 (FUN_00552950, RType teardown COMDAT clone)
     * Address: 0x00557E40 (FUN_00557E40, RType teardown COMDAT clone)
     * Address: 0x00558050 (FUN_00558050, RType teardown COMDAT clone)
     * Address: 0x00558260 (FUN_00558260, RType teardown COMDAT clone)
     * Address: 0x005584B0 (FUN_005584B0, RType teardown COMDAT clone)
     * Address: 0x0055B070 (FUN_0055B070, RType teardown COMDAT clone)
     * Address: 0x0055C0B0 (FUN_0055C0B0, RType teardown COMDAT clone)
     * Address: 0x0055C2A0 (FUN_0055C2A0, RType teardown COMDAT clone)
     * Address: 0x0055C4A0 (FUN_0055C4A0, RType teardown COMDAT clone)
     * Address: 0x0055C6B0 (FUN_0055C6B0, RType teardown COMDAT clone)
     * Address: 0x00563BA0 (FUN_00563BA0, RType teardown COMDAT clone)
     * Address: 0x00563DD0 (FUN_00563DD0, RType teardown COMDAT clone)
     * Address: 0x00566250 (FUN_00566250, RType teardown COMDAT clone)
     * Address: 0x00566640 (FUN_00566640, RType teardown COMDAT clone)
     * Address: 0x00571FC0 (FUN_00571FC0, RType teardown COMDAT clone)
     * Address: 0x00572020 (FUN_00572020, RType teardown COMDAT clone)
     * Address: 0x005777E0 (FUN_005777E0, RType teardown COMDAT clone)
     * Address: 0x005A8470 (FUN_005A8470, RType teardown COMDAT clone)
     * Address: 0x005A84D0 (FUN_005A84D0, RType teardown COMDAT clone)
     * Address: 0x005DFB90 (FUN_005DFB90, RType teardown COMDAT clone)
     * Address: 0x005DFBF0 (FUN_005DFBF0, RType teardown COMDAT clone)
     * Address: 0x005ECFB0 (FUN_005ECFB0, RType teardown COMDAT clone)
     * Address: 0x005ED010 (FUN_005ED010, RType teardown COMDAT clone)
     * Address: 0x005F4AF0 (FUN_005F4AF0, RType teardown COMDAT clone)
     * Address: 0x005FA1E0 (FUN_005FA1E0, RType teardown COMDAT clone)
     * Address: 0x00604200 (FUN_00604200, RType teardown COMDAT clone)
     * Address: 0x00607520 (FUN_00607520, RType teardown COMDAT clone)
     * Address: 0x00610F90 (FUN_00610F90, RType teardown COMDAT clone)
     * Address: 0x00618F20 (FUN_00618F20, RType teardown COMDAT clone)
     * Address: 0x0061ABB0 (FUN_0061ABB0, RType teardown COMDAT clone)
     * Address: 0x0061EE00 (FUN_0061EE00, RType teardown COMDAT clone)
     * Address: 0x006261D0 (FUN_006261D0, RType teardown COMDAT clone)
     * Address: 0x0062F6E0 (FUN_0062F6E0, RType teardown COMDAT clone)
     * Address: 0x006434C0 (FUN_006434C0, RType teardown COMDAT clone)
     * Address: 0x00645E10 (FUN_00645E10, RType teardown COMDAT clone)
     * Address: 0x00646EB0 (FUN_00646EB0, RType teardown COMDAT clone)
     * Address: 0x00694890 (FUN_00694890, RType teardown COMDAT clone)
     * Address: 0x006EBFF0 (FUN_006EBFF0, RType teardown COMDAT clone)
     * Address: 0x007668C0 (FUN_007668C0, RType teardown COMDAT clone)
     * Address: 0x00766B00 (FUN_00766B00, RType teardown COMDAT clone)
     * Address: 0x00786760 (FUN_00786760, RType teardown COMDAT clone)
     * Address: 0x0078CB00 (FUN_0078CB00, RType teardown COMDAT clone)
     * Address: 0x0078DD70 (FUN_0078DD70, RType teardown COMDAT clone)
     * Address: 0x0078EF90 (FUN_0078EF90, RType teardown COMDAT clone)
     * Address: 0x00796160 (FUN_00796160, RType teardown COMDAT clone)
     * Address: 0x00797230 (FUN_00797230, RType teardown COMDAT clone)
     * Address: 0x00797750 (FUN_00797750, RType teardown COMDAT clone)
     * Address: 0x007992F0 (FUN_007992F0, RType teardown COMDAT clone)
     * Address: 0x007A2B90 (FUN_007A2B90, RType teardown COMDAT clone)
     * Address: 0x007B5E10 (FUN_007B5E10, RType teardown COMDAT clone)
     * Address: 0x007C0920 (FUN_007C0920, RType teardown COMDAT clone)
     * Address: 0x0086A4E0 (FUN_0086A4E0, RType teardown COMDAT clone)
     * Address: 0x0087FF90 (FUN_0087FF90, RType teardown COMDAT clone)
     * Address: 0x008801B0 (FUN_008801B0, RType teardown COMDAT clone)
     * SLOT: 2
     */
    virtual ~RType();

    /**
     * Abstract: provide a label/name string for a given instance pointer.
     * In base RType default ToString uses this label with "%s at 0x%p".
     *
     * Address: 0x00A82547
     * SLOT: 3
     */
    virtual const char* GetName() const = 0;

    /**
     * Default stringification: "<label> at 0x<ptr>".
     * Returns number of bytes appended.
     *
     * Address: 0x008DB100 (FUN_008DB100)
     * SLOT: 4
     */
    virtual msvc8::string GetLexical(const RRef&) const;

    /**
     * Unknown (base: no-op/false).
     *
     * Address: 0x008D86E0 (FUN_008D86E0)
     * SLOT: 5
     */
    virtual bool SetLexical(const RRef&, const char*) const;

    /**
     * Unknown (observed as zero in base).
     *
     * Address: 0x004013B0 (FUN_004013B0)
     * SLOT: 6
     */
    [[nodiscard]]
    virtual const RIndexed* IsIndexed() const;

    /**
     * Unknown (observed as zero in base).
     *
     * Address: 0x004013C0 (FUN_004013C0)
     * SLOT: 7
     */
    [[nodiscard]]
    virtual const RIndexed* IsPointer() const;

    /**
     * Unknown (observed as zero in base).
     *
     * Address: 0x004013D0 (FUN_004013D0)
     * SLOT: 8
     */
    [[nodiscard]]
    virtual const REnumType* IsEnumType() const;

    /**
     * One-shot registration hook (called by lazy-init).
     *
     * Address: 0x008D8680
     * SLOT: 9
     */
    virtual void Init();

    /**
     * Finalization: builds indices over 20-byte member records.
     *
     * Address: 0x008DF4A0
     * SLOT: 10
     */
    virtual void Finish();

    /**
     * Address: 0x008D8640 (FUN_008D8640, ?Version@RType@gpg@@QAEXH@Z_0)
     *
     * What it does:
     * Sets RTTI version once (or verifies repeated assignments match).
     */
    void Version(int version);

    /**
     * Add a base-class reference and flatten its fields into this type.
     * - Fails if initialization is already finished (matches original assert).
     * - Appends `base` into `bases_`.
     * - For each field of `base.mType`, appends a copy into `fields_` with
     *   offset adjusted by `base.mOffset`.
     *
     * Address: 0x008DF500
     */
    void AddBase(const RField& field);

    /**
     * Register this type in global registries.
     *
     * Address: 0x008DF960
     */
    void RegisterType();

    /**
     * Address: 0x004EA0E0 (FUN_004EA0E0, gpg::RType::AddBlueprintAxisAlignedBox3f)
     *
     * What it does:
     * Appends six float fields for one axis-aligned-box payload
     * (`min0/min1/min2/max0/max1/max2`).
     */
    void AddBlueprintAxisAlignedBox3f();

    /**
     * Binary-search a field by its name.
     * Preconditions:
     *  - `initFinished_` must be true (indices built, `fields_` sorted by name).
     *  - `fields_` is sorted ascending by `RField::mName` (strcmp order).
     * Returns:
     *  - Pointer to matching RField if found;
     *  - nullptr if not found or container is empty.
     *
     * Address: 0x008D94E0
     */
    const RField* GetFieldNamed(const char* name) const;

    /**
     * Check if `this` is (transitively) derived from `baseType`.
     * If `outOffset` is provided and relation holds, accumulates byte offset
     * from `this` object start to the subobject of type `baseType`.
     * Throws std::runtime_error("Ambiguous base class") if there are >=2 distinct base paths.
     *
     * Address: 0x008DBFF0
     */
    bool IsDerivedFrom(const RType* baseType, int32_t* outOffset) const;

  public:
    bool finished_;
    bool initFinished_;
    int size_;
    int version_;
    save_construct_args_func_t serSaveConstructArgsFunc_;
    save_func_t serSaveFunc_;
    construct_func_t serConstructFunc_;
    load_func_t serLoadFunc_;
    int v8;
    int v9;
    msvc8::vector<RField> bases_;
    msvc8::vector<RField> fields_;
    new_ref_func_t newRefFunc_;
    cpy_ref_func_t cpyRefFunc_;
    delete_func_t deleteFunc_;
    ctor_ref_func_t ctorRefFunc_;
    mov_ref_func_t movRefFunc_;
    dtr_func_t dtrFunc_;
    bool v24;

  public:
    template <class T, class B>
    static int BaseSubobjectOffset()
    {
      static_assert(std::is_base_of<B, T>::value, "B must be a base of T");

      const auto* t = reinterpret_cast<const T*>(0x1000);
      const auto* b = static_cast<const B*>(t);
      return static_cast<int>(reinterpret_cast<std::uintptr_t>(b) - reinterpret_cast<std::uintptr_t>(t));
    }

    /**
     * Address: 0x0040DFA0 (FUN_0040DFA0 -- `AddField<float>`, binary name `AddField_float`.)
     * Address: 0x0040E020 (FUN_0040E020 -- `AddField<unsigned int>`, binary name `AddField_uint`.)
     * Address: 0x004EDC10 (FUN_004EDC10 -- `AddField<int>`, binary name `AddField_int`.)
     * Address: 0x00510DD0 (FUN_00510DD0 -- `AddField<bool>`, binary name `AddFieldBool`.)
     * Address: 0x0050E1F0 (FUN_0050E1F0 -- `AddField<msvc8::string>`, binary name `AddField_string`.)
     * Address: 0x004EDFD0 (FUN_004EDFD0 -- `AddField<Wm3::Vector3f>`, binary name `AddField_Vector3f`.)
     * Address: 0x00510D50 (FUN_00510D50 -- `AddField<moho::RResId>`, binary name `AddField_RResId`.)
     * Address: 0x0050D010 (FUN_0050D010 -- `AddField<unsigned char>`, binary name `AddField_uchar`.)
     * Address: 0x00510F10 (FUN_00510F10 -- `AddField<moho::REmitterBlueprintCurve>`, binary name `AddField_REmitterBlueprintCurve`.)
     * Address: 0x00510FF0 (FUN_00510FF0 -- `AddField<moho::Vector4f>`, binary name `AddField_Vector4f`.)
     * Address: 0x00513230 (FUN_00513230 -- `AddField<msvc8::vector<msvc8::string>>`, binary name `AddField_vector_string`.)
     * Address: 0x00513330 (FUN_00513330 -- `AddField<moho::SFootprint>`, binary name `AddField_SFootprint`.)
     * Address: 0x005146E0 (FUN_005146E0 -- `AddField<msvc8::list<moho::SNamedFootprint>>`, with its name
     * `"Footprints"` and offset 0 folded in: `SRuleFootprintsBlueprintTypeInfo::AddFields` 0x00513FA0 and
     * `Init` 0x00513ED0 reach it with the type in ESI.)
     * Address: 0x004F08F0 (FUN_004F08F0 -- `AddField<Wm3::Quaternionf>("r", ...)` for `VTransform::orient_`, name and offset folded in;
     * formerly `AddQuaternionRotationField in moho/render/camera/VTransform.cpp` (RULE ONE), removed 2026-09-30.)
     * Address: 0x005132B0 (FUN_005132B0 -- `AddField<moho::ECollisionShape>("CollisionShape", ...)` for `REntityBlueprint::mCollisionShape`, name and offset folded in;
     * formerly `REntityBlueprintTypeInfo::AddFieldCollisionShape` (RULE ONE), removed 2026-09-30.)
     * Address: 0x0051A330 (FUN_0051A330 -- `AddField<msvc8::vector<moho::RMeshBlueprintLOD>>("LODs", ...)` for `RMeshBlueprint::mLods`, name and offset folded in;
     * formerly `RMeshBlueprintTypeInfo::AddFieldLods` (RULE ONE), removed 2026-09-30.)
     * Address: 0x0051CDC0 (FUN_0051CDC0 -- `AddField<moho::RProjectileBlueprintDisplay>("Display", ...)` for `RProjectileBlueprint::Display`, name and offset folded in;
     * formerly `RProjectileBlueprintTypeInfo::AddFieldDisplay` (RULE ONE), removed 2026-09-30.)
     * Address: 0x0051CE40 (FUN_0051CE40 -- `AddField<moho::RProjectileBlueprintEconomy>("Economy", ...)` for `RProjectileBlueprint::Economy`, name and offset folded in;
     * formerly `RProjectileBlueprintTypeInfo::AddFieldEconomy` (RULE ONE), removed 2026-09-30.)
     * Address: 0x0051CEC0 (FUN_0051CEC0 -- `AddField<moho::RProjectileBlueprintPhysics>("Physics", ...)` for `RProjectileBlueprint::Physics`, name and offset folded in;
     * formerly `RProjectileBlueprintTypeInfo::AddFieldPhysics` (RULE ONE), removed 2026-09-30.)
     * Address: 0x0051DF00 (FUN_0051DF00 -- `AddField<moho::RPropBlueprintDisplay>("Display", ...)` for `RPropBlueprint::Display`, name and offset folded in;
     * formerly `RPropBlueprintTypeInfo::AddFieldDisplay` (RULE ONE), removed 2026-09-30.)
     * Address: 0x0051DF80 (FUN_0051DF80 -- `AddField<moho::RPropBlueprintDefense>("Defense", ...)` for `RPropBlueprint::Defense`, name and offset folded in;
     * formerly `RPropBlueprintTypeInfo::AddFieldDefense` (RULE ONE), removed 2026-09-30.)
     * Address: 0x0051E000 (FUN_0051E000 -- `AddField<moho::RPropBlueprintEconomy>("Economy", ...)` for `RPropBlueprint::Economy`, name and offset folded in;
     * formerly `RPropBlueprintTypeInfo::AddFieldEconomy` (RULE ONE), removed 2026-09-30.)
     * Address: 0x005252A0 (FUN_005252A0 -- `AddField<moho::ERuleBPUnitCommandCaps>("CommandCaps", ...)` for `RUnitBlueprintGeneral::CommandCaps`, name and offset folded in;
     * formerly `RUnitBlueprintGeneralTypeInfo::AddFieldCommandCaps` (RULE ONE), removed 2026-09-30.)
     * Address: 0x00525320 (FUN_00525320 -- `AddField<moho::ERuleBPUnitToggleCaps>("ToggleCaps", ...)` for `RUnitBlueprintGeneral::ToggleCaps`, name and offset folded in;
     * formerly `RUnitBlueprintGeneralTypeInfo::AddFieldToggleCaps` (RULE ONE), removed 2026-09-30.)
     * Address: 0x00525420 (FUN_00525420 -- `AddField<moho::ELayer>("BuildOnLayerCaps", ...)` for `RUnitBlueprintPhysics::BuildOnLayerCapsMask`, name and offset folded in;
     * formerly `RUnitBlueprintPhysicsTypeInfo::AddFieldBuildOnLayerCaps` (RULE ONE), removed 2026-09-30.)
     * Address: 0x005254A0 (FUN_005254A0 -- `AddField<moho::ERuleBPUnitBuildRestriction>("BuildRestriction", ...)` for `RUnitBlueprintPhysics::BuildRestriction`, name and offset folded in;
     * formerly `RUnitBlueprintPhysicsTypeInfo::AddFieldBuildRestriction` (RULE ONE), removed 2026-09-30.)
     * Address: 0x005255A0 (FUN_005255A0 -- `AddField<moho::RUnitBlueprintDefenseShield>("Shield", ...)` for `RUnitBlueprintDefense::Shield`, name and offset folded in;
     * formerly `RUnitBlueprintDefenseTypeInfo::AddFieldShield` (RULE ONE), removed 2026-09-30.)
     * Address: 0x005256A0 (FUN_005256A0 -- `AddField<moho::UnitWeaponRangeCategory>("RangeCategory", ...)` for `RUnitBlueprintWeapon::RangeCategory`, name and offset folded in;
     * formerly `RUnitBlueprintWeaponTypeInfo::AddFieldRangeCategory` (RULE ONE), removed 2026-09-30.)
     * Address: 0x00525720 (FUN_00525720 -- `AddField<moho::ERuleBPUnitWeaponBallisticArc>("BallisticArc", ...)` for `RUnitBlueprintWeapon::BallisticArc`, name and offset folded in;
     * formerly `RUnitBlueprintWeaponTypeInfo::AddFieldBallisticArc` (RULE ONE), removed 2026-09-30.)
     * Address: 0x005257A0 (FUN_005257A0 -- `AddField<moho::ERuleBPUnitWeaponTargetType>("TargetType", ...)` for `RUnitBlueprintWeapon::TargetType`, name and offset folded in;
     * formerly `RUnitBlueprintWeaponTypeInfo::AddFieldTargetType` (RULE ONE), removed 2026-09-30.)
     * Address: 0x00525880 (FUN_00525880 -- `AddField<moho::RUnitBlueprintGeneral>("General", ...)` for `RUnitBlueprint::General`, name and offset folded in;
     * formerly `RUnitBlueprintTypeInfo::AddFieldGeneral` (RULE ONE), removed 2026-09-30.)
     * Address: 0x00525900 (FUN_00525900 -- `AddField<moho::RUnitBlueprintDisplay>("Display", ...)` for `RUnitBlueprint::Display`, name and offset folded in;
     * formerly `RUnitBlueprintTypeInfo::AddFieldDisplaySection` (RULE ONE), removed 2026-09-30.)
     * Address: 0x00525980 (FUN_00525980 -- `AddField<moho::RUnitBlueprintPhysics>("Physics", ...)` for `RUnitBlueprint::Physics`, name and offset folded in;
     * formerly `RUnitBlueprintTypeInfo::AddFieldPhysicsSection` (RULE ONE), removed 2026-09-30.)
     * Address: 0x00525A00 (FUN_00525A00 -- `AddField<moho::RUnitBlueprintAir>("Air", ...)` for `RUnitBlueprint::Air`, name and offset folded in;
     * formerly `RUnitBlueprintTypeInfo::AddFieldAirSection` (RULE ONE), removed 2026-09-30.)
     * Address: 0x00525A80 (FUN_00525A80 -- `AddField<moho::RUnitBlueprintTransport>("Transport", ...)` for `RUnitBlueprint::Transport`, name and offset folded in;
     * formerly `RUnitBlueprintTypeInfo::AddFieldTransportSection` (RULE ONE), removed 2026-09-30.)
     * Address: 0x00525B00 (FUN_00525B00 -- `AddField<moho::RUnitBlueprintDefense>("Defense", ...)` for `RUnitBlueprint::Defense`, name and offset folded in;
     * formerly `RUnitBlueprintTypeInfo::AddFieldDefenseSection` (RULE ONE), removed 2026-09-30.)
     * Address: 0x00525B80 (FUN_00525B80 -- `AddField<moho::RUnitBlueprintAI>("AI", ...)` for `RUnitBlueprint::AI`, name and offset folded in;
     * formerly `RUnitBlueprintTypeInfo::AddFieldAiSection` (RULE ONE), removed 2026-09-30.)
     * Address: 0x00525C00 (FUN_00525C00 -- `AddField<moho::RUnitBlueprintIntel>("Intel", ...)` for `RUnitBlueprint::Intel`, name and offset folded in;
     * formerly `RUnitBlueprintTypeInfo::AddFieldIntelSection` (RULE ONE), removed 2026-09-30.)
     * Address: 0x00525C80 (FUN_00525C80 -- `AddField<msvc8::vector<moho::RUnitBlueprintWeapon>>("Weapons", ...)` for `RUnitBlueprint::Weapons`, name and offset folded in;
     * formerly `RUnitBlueprintTypeInfo::AddFieldWeaponSection` (RULE ONE), removed 2026-09-30.)
     * Address: 0x00525D00 (FUN_00525D00 -- `AddField<moho::RUnitBlueprintEconomy>("Economy", ...)` for `RUnitBlueprint::Economy`, name and offset folded in;
     * formerly `RUnitBlueprintTypeInfo::AddFieldEconomySection` (RULE ONE), removed 2026-09-30.)
     * Address: 0x0073A710 (FUN_0073A710 -- `AddField<moho::CDamageMethod>("Method", ...)` for `CDamage::mMethod`, name and offset folded in;
     * formerly `CDamageTypeInfo::AddFieldMethod` (RULE ONE), removed 2026-09-30.)
     * Address: 0x0073A790 (FUN_0073A790 -- `AddField<moho::SMinMax<float>>("MinMaxRadius", ...)` for `CDamage::mRadius`, name and offset folded in;
     * formerly `CDamageTypeInfo::AddFieldMinMaxRadius` (RULE ONE), removed 2026-09-30.)
     *
     * What it does:
     * Appends one reflected field of type `T` at `offset`: asserts the type is
     * still open (`"!mInitFinished"`, reflection.h line 734), then pushes
     * `{name, RTypeOf<T>(), offset}` and hands back the new entry.
     */
    template <class T>
    RField* AddField(const char* const name, const int offset)
    {
      GPG_ASSERT(!initFinished_);
      fields_.push_back(RField{name, RTypeOf<T>(), offset});
      return &fields_.back();
    }

    /**
     * What it does:
     * `AddField<T>(name, offset)`, then the entry's access flags and editor
     * description, stored at the call site: `RBeamBlueprintTypeInfo::AddFields`
     * 0x0050FB90 calls `AddField_float` 0x0040DFA0 and writes `[eax+0x0C] = 3`,
     * `[eax+0x10] = desc` after each field.
     */
    template <class T>
    RField* AddField(const char* const name, const int offset, const int flags, const char* const desc)
    {
      RField* const field = AddField<T>(name, offset);
      field->mFlags = flags;
      field->mDesc = desc;
      return field;
    }

    template <class T, class B>
    void AddBase()
    {
      RType* type = const_cast<RType*>(B::StaticGetClass());
      this->AddBase(RField{type->GetName(), type, BaseSubobjectOffset<T, B>()});
    }
  };
  static_assert(sizeof(RType) == 0x64, "RType must be 0x64 bytes on x86");

  /**
   * VFTABLE: 0x00D44B4C
   * COL:  0x00E5156C
   */
  class Rect2iTypeInfo final : public RType
  {
  public:
    /**
     * Address: 0x00C09760 (FUN_00C09760, gpg::Rect2iTypeInfo::dtr, atexit-thunk lane)
     * Address: 0x00906130 (FUN_00906130, gpg::Rect2iTypeInfo::dtr, vtable-slot lane)
     */
    ~Rect2iTypeInfo() override = default;

    /**
     * Address: 0x00905FD0 (FUN_00905FD0, gpg::Rect2iTypeInfo::Rect2iTypeInfo)
     *
     * What it does:
     * Constructs the Rect2<int> runtime type descriptor and preregisters it
     * with reflection registry using `typeid(Rect2i)`.
     */
    Rect2iTypeInfo();

    /**
     * Address: 0x00906020 (FUN_00906020)
     * Demangled: gpg::Rect2iTypeInfo::GetName
     *
     * What it does:
     * Returns the reflection type label string for Rect2<int>.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00906270 (FUN_00906270)
     * Demangled: gpg::Rect2iTypeInfo::Init
     *
     * What it does:
     * Registers Rect2<int> field metadata (x0/y0/x1/y1) and finalizes the descriptor.
     */
    void Init() override;
  };
  static_assert(sizeof(Rect2iTypeInfo) == 0x64, "Rect2iTypeInfo size must be 0x64");

  /**
   * VFTABLE: 0x00D44B84
   * COL:  0x00E515BC
   */
  class Rect2fTypeInfo final : public RType
  {
  public:
    /**
     * Address: 0x00C097C0 (FUN_00C097C0, gpg::Rect2fTypeInfo::dtr, atexit-thunk lane)
     * Address: 0x00906190 (FUN_00906190, gpg::Rect2fTypeInfo::dtr, vtable-slot lane)
     */
    ~Rect2fTypeInfo() override = default;

    /**
     * Address: 0x00906080 (FUN_00906080, gpg::Rect2fTypeInfo::Rect2fTypeInfo)
     *
     * What it does:
     * Constructs the Rect2<float> runtime type descriptor and preregisters it
     * with reflection registry using `typeid(Rect2f)`.
     */
    Rect2fTypeInfo();

    /**
     * Address: 0x009060D0 (FUN_009060D0)
     * Demangled: gpg::Rect2fTypeInfo::GetName
     *
     * What it does:
     * Returns the reflection type label string for Rect2<float>.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x009062D0 (FUN_009062D0)
     * Demangled: gpg::Rect2fTypeInfo::Init
     *
     * What it does:
     * Registers Rect2<float> field metadata (x0/y0/x1/y1) and finalizes the descriptor.
     */
    void Init() override;
  };
  static_assert(sizeof(Rect2fTypeInfo) == 0x64, "Rect2fTypeInfo size must be 0x64");

  namespace detail
  {
    inline constexpr char kSerializationHeaderPath[] = "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";
  } // namespace detail

  /**
   * What `SerSaveLoadHelper<T>` runs to load one object: `T`'s own
   * `MemberDeserialize`. A type that cannot have one (`std::pair`) supplies an
   * overload in its own namespace.
   */
  template <class T>
  void SerLoadMembers(ReadArchive* const archive, T& object)
  {
    object.MemberDeserialize(archive);
  }

  /**
   * What `SerSaveLoadHelper<T>` runs to save one object: `T`'s own
   * `MemberSerialize`, or an overload in `T`'s namespace.
   */
  template <class T>
  void SerSaveMembers(WriteArchive* const archive, const T& object)
  {
    object.MemberSerialize(archive);
  }

  /**
   * Demangled: gpg::SerSaveLoadHelper<T>
   *
   * Installs `T`'s load/save hooks: the archive loads and saves a `T` through
   * `T::MemberDeserialize` / `T::MemberSerialize`. Every helper in the binary
   * derives an empty named struct from this
   * (`Moho::CAniPoseSerializer : gpg::SerSaveLoadHelper<Moho::CAniPose>`), so
   * RTTI shows two vtables per `T` that share one `Init`; the per-`T`
   * addresses are cited on those structs.
   *
   * `Deserialize` / `Serialize` are out of line only where the member is, as
   * a `jmp` or a short forward; otherwise the member is inlined into them.
   * Members take `(archive)`, `(archive, version)` or
   * `(archive, version, ownerRef)`, whichever the binary's body reads. The
   * enum instantiations `vtable_writers` also lists are unreferenced copies
   * sharing a `PrimitiveSerHelper<E, int>` global's storage, not uses of
   * this template.
   */
  template <class T>
  class SerSaveLoadHelper : public SerHelperBase
  {
  public:
    SerSaveLoadHelper()
      : mLoadCallback(&SerSaveLoadHelper::Deserialize)
      , mSaveCallback(&SerSaveLoadHelper::Serialize)
    {}

    ~SerSaveLoadHelper() = default;

    /**
     * Address: 0x005B9230 (FUN_005B9230 -- `Init()` for `SValuePair`; formerly `InstallMohoSValuePairSerializerCallbacks` in gpg/core/containers/ArchiveSerialization.cpp, whose by-name lookup was disproven.)
     *
     * What it does:
     * Installs this helper's load/save callbacks on `T`'s type (vtable slot 0,
     * dispatched once by `SerHelperBase::InitNewHelpers`), asserting neither
     * was set (serialization.h lines 84 and 87). The type comes from a lazy
     * per-`T` slot, not a member of `T`: `SerSaveLoadHelper<std::pair<
     * HPathCell, float>>::Init` (0x0076D6D0) is the same code as the class
     * instantiations.
     */
    void Init() override
    {
      RType* const type = RTypeOf<T>();
      if (type->serLoadFunc_ != nullptr) {
        HandleAssertFailure("!type->mSerLoadFunc", 84, detail::kSerializationHeaderPath);
      }
      type->serLoadFunc_ = mLoadCallback;
      if (type->serSaveFunc_ != nullptr) {
        HandleAssertFailure("!type->mSerSaveFunc", 87, detail::kSerializationHeaderPath);
      }
      type->serSaveFunc_ = mSaveCallback;
    }

    /**
     * What it does:
     * Reflection load callback that forwards archive-load flow into
     * `T::MemberDeserialize`, with the archived version when `T`'s takes one
     * (`Unit`'s rejects versions below 1) and the owner reference when it
     * takes that too (the Lua objects read their payload against the
     * owning thread).
     */
    static void Deserialize(ReadArchive* const archive, const int objectPtr, const int version, RRef* const ownerRef)
    {
      T& object = *reinterpret_cast<T*>(static_cast<std::uintptr_t>(objectPtr));
      if constexpr (requires { object.MemberDeserialize(archive, version, *ownerRef); }) {
        object.MemberDeserialize(archive, version, *ownerRef);
      } else if constexpr (requires { object.MemberDeserialize(archive, version); }) {
        object.MemberDeserialize(archive, version);
      } else if constexpr (requires { object.MemberDeserialize(archive); }) {
        object.MemberDeserialize(archive);
      } else {
        SerLoadMembers(archive, object);
      }
    }

    /**
     * What it does:
     * Reflection save callback that forwards archive-save flow into
     * `T::MemberSerialize`, with the version and the owner reference when
     * `T`'s takes them.
     */
    static void Serialize(WriteArchive* const archive, const int objectPtr, const int version, RRef* const ownerRef)
    {
      T& object = *reinterpret_cast<T*>(static_cast<std::uintptr_t>(objectPtr));
      if constexpr (requires { object.MemberSerialize(archive, version, *ownerRef); }) {
        object.MemberSerialize(archive, version, *ownerRef);
      } else if constexpr (requires { object.MemberSerialize(archive, version); }) {
        object.MemberSerialize(archive, version);
      } else if constexpr (requires { object.MemberSerialize(archive); }) {
        object.MemberSerialize(archive);
      } else {
        SerSaveMembers(archive, static_cast<const T&>(object));
      }
    }

  public:
    RType::load_func_t mLoadCallback; // +0x0C
    RType::save_func_t mSaveCallback; // +0x10
  };

  /**
   * Demangled: gpg::SerConstructHelper<T>
   *
   * Installs `T`'s load-construct hook: the archive builds a `T` through
   * `T::MemberConstruct` instead of default-constructing it and loading the
   * members over it, and frees one it no longer owns with a plain `delete`.
   * Every helper in the binary derives an empty named struct from this
   * (`Moho::EntityConstruct : gpg::SerConstructHelper<Moho::Entity>`); the
   * per-`T` addresses are cited on those structs.
   *
   * `Construct` is out of line only where `MemberConstruct` is, as a 5- or
   * 8-instruction forward (whole-program optimisation drops the arguments
   * `MemberConstruct` never reads, so a 5-instruction one pushes the result
   * alone); otherwise `MemberConstruct` is inlined into it. `Delete` is
   * `delete static_cast<T*>(object)`: the deleting destructor through the
   * vtable for a polymorphic `T`, the destructor and `operator delete`
   * otherwise, and `operator delete` alone for a trivially destructible one.
   */
  template <class T>
  struct SerConstructHelper : SerHelperBase
  {
    SerConstructHelper()
      : mConstructFunc(&SerConstructHelper::Construct)
      , mDeleteFunc(&SerConstructHelper::Delete)
    {}

    /**
     * What it does:
     * Installs the construct and delete hooks on `T`'s type, asserting no
     * construct hook was installed before (serialization.h line 231). The
     * delete hook is stored unchecked.
     */
    void Init() override
    {
      RType* const type = RTypeOf<T>();
      if (type->serConstructFunc_ != nullptr) {
        HandleAssertFailure("!type->mSerConstructFunc", 231, detail::kSerializationHeaderPath);
      }
      type->serConstructFunc_ = mConstructFunc;
      type->deleteFunc_ = mDeleteFunc;
    }

    static void Construct(ReadArchive* const archive, const int version, RRef* const ownerRef, SerConstructResult* const result)
    {
      T::MemberConstruct(*archive, version, *ownerRef, *result);
    }

    static void Delete(void* const object)
    {
      delete static_cast<T*>(object);
    }

    RType::construct_func_t mConstructFunc; // +0x0C
    RType::delete_func_t mDeleteFunc;       // +0x10
  };

  /**
   * Demangled: gpg::SerSaveConstructHelper<T>
   *
   * Installs `T`'s save-construct hook: before its members, the archive
   * writes what `T::MemberConstruct` will need to rebuild the object, through
   * `T::MemberSaveConstructArgs`, which also reports how the pointer is owned.
   * Paired with a `SerConstructHelper<T>`, and like it always derived into an
   * empty named struct (`Moho::EntitySaveConstruct`) where the per-`T`
   * addresses are cited.
   */
  template <class T>
  struct SerSaveConstructHelper : SerHelperBase
  {
    SerSaveConstructHelper()
      : mSaveConstructArgsFunc(&SerSaveConstructHelper::SaveConstructArgs)
    {}

    /**
     * What it does:
     * Installs the save-construct hook on `T`'s type, asserting none was
     * installed before (serialization.h line 189).
     */
    void Init() override
    {
      RType* const type = RTypeOf<T>();
      if (type->serSaveConstructArgsFunc_ != nullptr) {
        HandleAssertFailure("!type->mSerSaveConstructArgsFunc", 189, detail::kSerializationHeaderPath);
      }
      type->serSaveConstructArgsFunc_ = mSaveConstructArgsFunc;
    }

    static void SaveConstructArgs(
      WriteArchive* const archive,
      void* const object,
      const int version,
      RRef* const ownerRef,
      SerSaveConstructArgsResult* const result
    )
    {
      static_cast<T*>(object)->MemberSaveConstructArgs(*archive, version, *ownerRef, *result);
    }

    RType::save_construct_args_func_t mSaveConstructArgsFunc; // +0x0C
  };

  /**
   * Demangled: gpg::PrimitiveSerHelper<T,IntType>
   *
   * Canonical template for a `gpg::SerHelperBase`-derived serializer that
   * reads/writes one enum (or other integral-representable) value as a
   * single `IntType` lane. Confirmed instantiated 50+ times across the
   * binary -- one per reflected enum type (`Moho::EAlliance`,
   * `Moho::EEconResource`, `Moho::ELayer`, `Moho::EUnitState`, ...) -- always
   * with `IntType=int`. Every instantiation's vtable-writer pair follows the
   * same two-address shape: a dead, zero-incoming-xref duplicate at a low
   * address (compiler/linker artifact, never reachable from `__xc_a`) and
   * the real, `__xc_a`-reachable dynamic initializer at a high address in
   * the 0x00BCxxxx-0x00BDxxxx cluster -- e.g. for `EAlliance`,
   * `FUN_0050A600` (dead) vs. `FUN_00BC7A30` (real, confirmed via
   * `incoming_xrefs` data xref from `__xc_a`).
   *
   * Each per-T real ctor's tail pushes a plain, unmangled `sub_XXXXXX`
   * cleanup thunk (not a mangled `~PrimitiveSerHelper<T,int>` destructor
   * symbol IDA could associate back to this class) as its `atexit` target;
   * every one checked decompiles to the same unlink-then-self-link shape as
   * the helper node's unlink (`gpg::DListItem::ListUnlink`). Modeled here as the compiler's own
   * implicit static-destructor registration for a global with a
   * non-trivial destructor: this template declares a real destructor and
   * relies on the compiler to emit the matching registration at each
   * instantiation site, rather than reproducing an explicit `atexit` call.
   *
   * Additional instantiations converted from hand-rolled raw-struct mimics
   * this session (real ctor address, `__xc_a`-reachable unless noted; dead
   * zero-xref duplicate ctor in parens where one exists; atexit-target
   * unlink body -> Deserialize -> Serialize addresses follow):
   *   - T=Moho::EAiAttackerEvent: ctor 0x00BCE770, atexit 0x00BF8250,
   *     Deserialize 0x005DC390, Serialize 0x005DC3B0
   *   - T=Moho::EAiNavigatorEvent: ctor 0x00BCC660, atexit 0x00BF6CD0
   *     (dead duplicates: 0x005A3130, 0x005A3160 -- formerly
   *     `gGlobalIntrusiveSentinelLaneN` in
   *     moho/containers/LegacyContainerFillLanes.cpp; removed),
   *     Deserialize 0x005A7720, Serialize 0x005A7740
   *   - T=Moho::EAiNavigatorStatus: ctor 0x00BCC600, atexit 0x00BF6C90,
   *     Deserialize 0x005A76B0, Serialize 0x005A76D0
   *   - T=Moho::CAiPathNavigator::State (recovered header still names this
   *     `EAiPathNavigatorState`, a free enum -- known divergence, see
   *     CAiPathNavigator.h): ctor 0x00BCCFE0, atexit 0x00BF7330,
   *     Deserialize 0x005B0290, Serialize 0x005B02B0
   *   - T=Moho::EAiTargetType: ctor 0x00BCEBF0, atexit 0x00BF8880,
   *     Deserialize 0x005E35B0, Serialize 0x005E35D0
   *   - T=Moho::EAiTransportEvent: ctor 0x00BCED30 (dead duplicates:
   *     0x005E8B60, 0x005E9E10 -- two, not the usual one), atexit
   *     0x00BF8970, Deserialize 0x005E9DD0, Serialize 0x005E9DF0
   *   - T=Moho::EPathType: ctor 0x00BCD290, atexit 0x00BF7420, Deserialize
   *     0x005B4E90, Serialize 0x005B4EB0
   *   - T=Moho::ESearchType: ctor 0x00BCCD10, atexit 0x00BF71B0,
   *     Deserialize 0x005AB520, Serialize 0x005AB540, Init 0x005AB120
   *   - T=Moho::ESiloBuildStage: ctor 0x00BCE050, atexit 0x00BF7E10,
   *     Deserialize 0x005CFFB0, Serialize 0x005CFFD0
   *   - T=Moho::ESiloType: ctor 0x00BC7B50 (dead duplicate 0x0050A7E0; dead
   *     sibling-writer `SerSaveLoadHelper<ESiloType>` at 0x0050AAB0, same
   *     pattern as EAlliance/ELayer/etc. above), atexit 0x00BF1FE0,
   *     Deserialize 0x0050AA70, Serialize 0x0050AA90
   *   - T=Moho::ECollisionType: ctor 0x00BCBD70 (dead sibling-writer
   *     `SerSaveLoadHelper<ECollisionType>` at 0x00598440), atexit
   *     0x00BF6520 (dead twins 0x005966D0, 0x00596700), Deserialize
   *     0x00598400, Serialize 0x00598420
   *   - T=Moho::EPathPointState: ctor 0x00BD20E0 (dead duplicate
   *     0x0062F840; dead sibling-writer `SerSaveLoadHelper<EPathPointState>`
   *     at 0x0062F9C0), atexit 0x00BFA7F0 (dead duplicates: 0x0062F5F0,
   *     0x0062F620 -- formerly `gGlobalIntrusiveSentinelLaneW` in
   *     moho/containers/LegacyContainerFillLanes.cpp; removed), Deserialize
   *     0x0062F980, Serialize 0x0062F9A0
   *   - T=Moho::ERuleBPUnitMovementType: ctor 0x00BC8930, atexit 0x00BF31E0
   *     (dead twins 0x0051FC20, 0x0051FC50), Deserialize 0x00523AB0,
   *     Serialize 0x00523AD0
   *   - T=Moho::ERuleBPUnitCommandCaps: ctor 0x00BC8990, atexit 0x00BF3220
   *     (dead twins 0x0051FFA0, 0x0051FFD0), Deserialize 0x00523B20,
   *     Serialize 0x00523B40
   *   - T=Moho::ERuleBPUnitToggleCaps: ctor 0x00BC89F0, atexit 0x00BF3260
   *     (dead twins 0x00520190, 0x005201C0), Deserialize 0x00523B90,
   *     Serialize 0x00523BB0
   *   - T=Moho::EProjectileImpactEvent: ctor 0x00BD6350, atexit 0x00BFD550,
   *     Deserialize 0x0069EEC0, Serialize 0x0069EEE0
   *   - T=Moho::EAiResult: ctor 0x00BD0530 (no dead duplicate found), atexit
   *     0x00BF9AB0, Deserialize 0x0060BCD0, Serialize 0x0060BCF0, Init
   *     0x0060B980 (found via vtable-slot xref search on
   *     `??_7?$PrimitiveSerHelper@W4EAiResult@Moho@@H@gpg@@6B@`; body matches
   *     this template's `Init()` exactly, including the shared `sCachedType`
   *     caching -- IDA's decompiler displays that global as
   *     `Moho::EAiResult::sType` but it is this template's own
   *     per-instantiation static, not a member of the enum)
   *   - T=Moho::EScrollType: ctor 0x00BDD690 (no dead duplicate found; global
   *     storage 0x010BBB6C), atexit 0x00C02650, Deserialize 0x00777FF0,
   *     Serialize 0x00778010, Init 0x00777E20 (vtable-slot-0 target shared by
   *     BOTH the real `??_7?$PrimitiveSerHelper@W4EScrollType@Moho@@H@gpg@@6B@`
   *     and the dead, zero-writer `??_7?$SerSaveLoadHelper@W4EScrollType@
   *     Moho@@@gpg@@6B@` sibling vtable -- same shared-body pattern as
   *     ESquadClass/EThreatType above. `gpg::ArchiveSerialization.cpp`'s
   *     `InstallMohoEScrollTypeSerializerCallbacks` previously modeled this
   *     same address as a generic `InstallSerSaveLoadHelperCallbacksByTypeName`
   *     by-type-name dispatch; ground-truth asm shows the standard direct-
   *     assignment `Init()` shape instead (thiscall, reads `this+0x0C`/
   *     `this+0x10`, writes `EScrollType`'s `RType::serLoadFunc_`/
   *     `serSaveFunc_` with the usual `"!type->mSerLoadFunc"`/
   *     `"!type->mSerSaveFunc"` asserts) -- same mismodeling already caught
   *     for ESTITargetType/EResourceType above. That free function itself has
   *     zero source-level callers (2026-08-26 ArchiveSerialization dead-
   *     duplicate audit) and is left as-is, out of scope for this pass.)
   *   - T=Moho::ETriggerOperator: ctor 0x00BDA000 (no dead duplicate found;
   *     global storage 0x010B8F78), atexit 0x00BFF580, Deserialize
   *     0x0070F8E0, Serialize 0x0070F900, Init 0x0070E510 (vtable-slot-0
   *     target shared by both the real `??_7?$PrimitiveSerHelper@
   *     W4ETriggerOperator@Moho@@H@gpg@@6B@` and the dead, zero-writer
   *     `??_7?$SerSaveLoadHelper@W4ETriggerOperator@Moho@@@gpg@@6B@` sibling
   *     vtable -- same shared-body pattern as EScrollType above). The prior
   *     recovery in `moho/sim/SConditionTriggerReflection.cpp` modeled the
   *     ctor address (0x00BDA000) as a fabricated eager free function --
   *     `LookupRType(typeid(ETriggerOperator))` then a direct
   *     `type->serLoadFunc_ = ...`/`serSaveFunc_ = ...` store -- called from
   *     a file-local bootstrap struct's constructor; ground-truth asm at
   *     that address has no `LookupRType` call and no direct field store at
   *     all, only the standard `SerHelperBase`-derived ctor shape. A
   *     separate 2026-08-26 ArchiveSerialization.cpp audit independently
   *     flagged 0x0070E510 as a second, seemingly-competing candidate; it is
   *     not a competitor, it is this same ctor's `Init()` method (same
   *     relationship as EScrollType's 0x00777E20 above).
   * All of the above previously used a hand-rolled `{ mHelperNext,
   * mHelperPrev, mDeserialize/mLoadCallback, mSerialize/mSaveCallback }`
   * raw-struct mimic (sometimes via a per-file or per-cluster generic
   * template of the same shape, e.g. `EnumPrimitiveSerializer<TEnum>` /
   * `PrimitiveEnumSerializer<TEnum>`), each paired with a fabricated eager
   * `Init()`-equivalent call from a bootstrap struct or register_*() free
   * function -- absent from every real ctor's disassembly checked. "Dead
   * twins" above are zero-caller/zero-xref sha256-identical ICF copies of
   * the real atexit-target unlink body, confirmed via the callgraph index.
   */
  template <class T, class IntType = int>
  class PrimitiveSerHelper : public SerHelperBase
  {
  public:
    /**
     * Per-instantiation dynamic-initializer addresses (one compiler-emitted
     * ctor per `T`; see the class-level comment above for the dead-low-vs-
     * real-high-address pattern each one follows):
     *   - T=Moho::EAlliance: 0x00BC7A30 (dead duplicate: 0x0050A600)
     *   - T=Moho::EEconResource: 0x00BCA810, atexit 0x00BF5630 (dead
     *     duplicates: 0x00563AB0, 0x00563AE0 -- formerly
     *     `gGlobalIntrusiveSentinelLaneK` in
     *     moho/containers/LegacyContainerFillLanes.cpp; removed). See
     *     moho/ai/EEconResourceTypeInfo.h.
     *   - T=Moho::EImpactType: 0x00BC7A90 (dead duplicate: 0x0050A6A0)
     *   - T=Moho::ESTITargetType: 0x00BCA2B0 (no dead duplicate found),
     *     atexit 0x00BF50E0 (dead duplicates: 0x0055AF80, 0x0055AFB0 --
     *     formerly `gGlobalIntrusiveSentinelLaneG` in
     *     moho/containers/LegacyContainerFillLanes.cpp; removed)
     *   - T=Moho::SWorldBeam::BlendMode: 0x00BC5300 (no dead duplicate found)
     *   - T=Moho::SWorldParticle::BlendMode: 0x00BC53C0 (no dead duplicate found)
     *   - T=Moho::SWorldParticle::ZMode: 0x00BC5420 (no dead duplicate found)
     *   - T=Moho::ELayer: 0x00BC7C80 (dead duplicate: 0x0050C660; a second,
     *     unrelated writer -- FUN_0050CA60, demangled
     *     `SerSaveLoadHelper<Moho::ELayer>` -- shares this global's storage
     *     address but is itself zero-xref/unreachable too)
     *   - T=Moho::EVisibilityMode: 0x00BC7AF0 (dead duplicate: 0x0050A740;
     *     same `SerSaveLoadHelper<Moho::EVisibilityMode>` sibling-writer
     *     situation at FUN_0050AA40, also zero-xref/unreachable)
     *   - T=Moho::EStatType: 0x00BC3600 (no dead duplicate found)
     *   - T=Moho::EPulseMode: 0x00BC3660 (no dead duplicate found)
     *   - T=Moho::EmitterType: 0x00BD42B0 (no dead duplicate found),
     *     atexit 0x00BFBD20 (dead duplicates: 0x0065DF80, 0x0065DFB0 --
     *     formerly `gGlobalIntrusiveSentinelLaneX` in
     *     moho/containers/LegacyContainerFillLanes.cpp; removed). See
     *     moho/render/EmitterTypeTypeInfo.h.
     *   - T=Moho::EResourceType: 0x00BC9610 (dead duplicate: 0x00547380;
     *     was wrongly tagged `external_dependency` in progress tracking
     *     before this recovery -- it is the same
     *     SerHelperBase-ctor/field-set/vtable-install/atexit shape as every
     *     other confirmed instantiation, not an OS/CRT/library import),
     *     atexit 0x00BF41A0 (dead duplicates: 0x00545B70, 0x00545BA0 --
     *     formerly modeled in moho/containers/LegacyContainerFillLanes.cpp
     *     as `gGlobalIntrusiveSentinelLaneC`/`ResetGlobalIntrusiveSentinelLane
     *     CPrimary`/`...LaneCAliasSecondary`, a raw offset-reach-in over this
     *     same global's storage with no identity of its own; removed)
     *   - T=Moho::EUnitCommandType: 0x00BC9C40 (no dead duplicate found;
     *     confirmed via `vtable_writers` class_name
     *     `?$PrimitiveSerHelper@W4EUnitCommandType@Moho@@H@gpg`) -- was
     *     previously modeled as a standalone hand-rolled
     *     `EUnitCommandTypePrimitiveSerializer` raw-struct mimic in
     *     `moho/command/EUnitCommandTypeTypeInfo.h`, wrongly guessing this
     *     instantiation belonged to `SerSaveLoadHelper<T>` instead, atexit
     *     0x00BF4960 (dead duplicates: 0x005524F0, 0x00552520 -- formerly
     *     `gGlobalIntrusiveSentinelLaneF` in
     *     moho/containers/LegacyContainerFillLanes.cpp; removed)
     *   - T=Moho::ESquadClass: 0x00BDAB80 (dead duplicate: 0x0072A4A0; a
     *     second, unrelated writer -- FUN_0072A9F0, demangled
     *     `SerSaveLoadHelper<Moho::ESquadClass>` -- shares this global's
     *     storage address but is itself zero-xref/unreachable too, same
     *     sibling-writer situation as ELayer/EVisibilityMode above)
     *   - T=Moho::EThreatType: 0x00BDA3A0 (dead duplicate: 0x007188D0; a
     *     second, unrelated writer -- FUN_00719FF0, demangled
     *     `SerSaveLoadHelper<Moho::EThreatType>` -- shares this global's
     *     storage address but is itself zero-xref/unreachable too, same
     *     sibling-writer situation as ESquadClass above. A prior fabricated
     *     mimic in moho/sim/SThreatSerializer.cpp cited the dead duplicate
     *     address as if it were this real ctor; removed.)
     *   - T=Moho::EJobType: 0x00BCA460 (no dead duplicate found), atexit
     *     0x00BF51F0 (dead duplicates: 0x0055B930, 0x0055B960 -- formerly
     *     `gGlobalIntrusiveSentinelLaneH` in
     *     moho/containers/LegacyContainerFillLanes.cpp; removed). See
     *     moho/unit/core/EJobTypeTypeInfo.h.
     *   - T=Moho::EFireState: 0x00BCA4C0 (no dead duplicate found), atexit
     *     0x00BF5230 (dead duplicates: 0x0055BAB0, 0x0055BAE0 -- formerly
     *     `gGlobalIntrusiveSentinelLaneI` in
     *     moho/containers/LegacyContainerFillLanes.cpp; removed). See
     *     moho/unit/core/EFireStateTypeInfo.h.
     *   - T=Moho::ECommandEvent: 0x00BD8EF0 (dead duplicate: 0x006E9730;
     *     a second, unrelated writer -- FUN_006EA770, demangled
     *     `SerSaveLoadHelper<Moho::ECommandEvent>` -- shares this global's
     *     storage address but is itself zero-xref/unreachable too, same
     *     sibling-writer situation as ESquadClass/EThreatType), atexit
     *     0x00BFEB50 (dead duplicates: 0x006E7E30, 0x006E7E60 -- formerly
     *     `gGlobalIntrusiveSentinelLaneAQ` in
     *     moho/containers/LegacyContainerFillLanes.cpp; removed). See
     *     moho/unit/ECommandEventTypeInfo.h.
     *   - T=Moho::EUnitState: 0x00BCA520 (no dead duplicate found), atexit
     *     0x00BF5270 (dead duplicates: 0x0055BFC0, 0x0055BFF0 -- formerly
     *     `gGlobalIntrusiveSentinelLaneJ` in
     *     moho/containers/LegacyContainerFillLanes.cpp; removed). See
     *     moho/unit/core/EUnitStateTypeInfo.h.
     */
    PrimitiveSerHelper()
      : mLoadCallback(&PrimitiveSerHelper::Deserialize)
      , mSaveCallback(&PrimitiveSerHelper::Serialize)
    {}

    ~PrimitiveSerHelper() = default;

    /**
     * Per-instantiation addresses (one compiler-emitted body per `T`):
     *   - T=Moho::EAlliance: 0x0050A920 (FUN_0050A920)
     *   - T=Moho::EEconResource: 0x00564120 (FUN_00564120)
     *   - T=Moho::EImpactType: 0x0050A990 (FUN_0050A990)
     *   - T=Moho::ESTITargetType: 0x0055B310 (FUN_0055B310)
     *   - T=Moho::SWorldBeam::BlendMode: 0x0048FDA0 (FUN_0048FDA0)
     *   - T=Moho::SWorldParticle::BlendMode: 0x0048FE10 (FUN_0048FE10)
     *   - T=Moho::SWorldParticle::ZMode: 0x0048FE80 (FUN_0048FE80)
     *   - T=Moho::ELayer: 0x0050CA20 (FUN_0050CA20)
     *   - T=Moho::EVisibilityMode: 0x0050AA00 (FUN_0050AA00)
     *   - T=Moho::EStatType: 0x00419A50 (FUN_00419A50)
     *   - T=Moho::EPulseMode: 0x00419AC0 (FUN_00419AC0)
     *   - T=Moho::EmitterType: 0x0065F3E0 (FUN_0065F3E0)
     *   - T=Moho::EResourceType: 0x005478E0 (FUN_005478E0)
     *   - T=Moho::EUnitCommandType: 0x00553540 (FUN_00553540)
     *   - T=Moho::ESquadClass: 0x0072A9B0 (FUN_0072A9B0)
     *   - T=Moho::EThreatType: 0x00719FB0 (FUN_00719FB0)
     *
     * What it does:
     * Reads one `IntType` lane from the archive and stores it into the
     * reflected object as a `T` value.
     */
    static void Deserialize(ReadArchive* const archive, const int objectPtr, const int, RRef* const)
    {
      IntType value{};
      archive->ReadInt(&value);
      *reinterpret_cast<T*>(static_cast<std::uintptr_t>(objectPtr)) = static_cast<T>(value);
    }

    /**
     * Per-instantiation addresses (one compiler-emitted body per `T`):
     *   - T=Moho::EAlliance: 0x0050A940 (FUN_0050A940)
     *   - T=Moho::EEconResource: 0x00564140 (FUN_00564140) -- this specific
     *     address was previously mis-tagged `external_dependency` as a
     *     supposed "CRT iostream/locale-facet dispatch trampoline"; it is
     *     `archive->WriteInt(*a2)`, a virtual call on our own
     *     `gpg::WriteArchive`, not CRT.
     *   - T=Moho::EImpactType: 0x0050A9B0 (FUN_0050A9B0)
     *   - T=Moho::ESTITargetType: 0x0055B330 (FUN_0055B330)
     *   - T=Moho::SWorldBeam::BlendMode: 0x0048FDC0 (FUN_0048FDC0)
     *   - T=Moho::SWorldParticle::BlendMode: 0x0048FE30 (FUN_0048FE30)
     *   - T=Moho::SWorldParticle::ZMode: 0x0048FEA0 (FUN_0048FEA0)
     *   - T=Moho::ELayer: 0x0050CA40 (FUN_0050CA40)
     *   - T=Moho::EVisibilityMode: 0x0050AA20 (FUN_0050AA20)
     *   - T=Moho::EStatType: 0x00419A70 (FUN_00419A70)
     *   - T=Moho::EPulseMode: 0x00419AE0 (FUN_00419AE0)
     *   - T=Moho::EmitterType: 0x0065F400 (FUN_0065F400)
     *   - T=Moho::EResourceType: 0x00547900 (FUN_00547900)
     *   - T=Moho::EUnitCommandType: 0x00553560 (FUN_00553560)
     *   - T=Moho::ESquadClass: 0x0072A9D0 (FUN_0072A9D0)
     *   - T=Moho::EThreatType: 0x00719FD0 (FUN_00719FD0)
     *
     * What it does:
     * Writes the reflected object's `T` value as one `IntType` lane.
     */
    static void Serialize(WriteArchive* const archive, const int objectPtr, const int, RRef* const)
    {
      const auto value = *reinterpret_cast<const T*>(static_cast<std::uintptr_t>(objectPtr));
      archive->WriteInt(static_cast<int>(value));
    }

    /**
     * Per-instantiation addresses (one compiler-emitted body per `T`):
     *   - T=Moho::EAlliance: 0x0050A630 (FUN_0050A630)
     *   - T=Moho::EEconResource: 0x00563F70 (FUN_00563F70)
     *   - T=Moho::EImpactType: 0x0050A6D0 (FUN_0050A6D0)
     *   - T=Moho::ESTITargetType: 0x0055B200 (FUN_0055B200) -- previously
     *     mis-modeled in ArchiveSerialization.cpp as a generic
     *     `InstallSerSaveLoadHelperCallbacksByTypeName(helper,
     *     "Moho::ESTITargetType")` dispatch; the real body installs two
     *     hardcoded callback pointers directly (confirmed against asm),
     *     matching this template's `Init()` exactly, not the generic
     *     by-type-name lookup.
     *   - T=Moho::SWorldBeam::BlendMode: 0x0048FAB0 (FUN_0048FAB0)
     *   - T=Moho::SWorldParticle::BlendMode: 0x0048FBF0 (FUN_0048FBF0)
     *   - T=Moho::SWorldParticle::ZMode: 0x0048FC90 (FUN_0048FC90)
     *   - T=Moho::ELayer: 0x0050C690 (FUN_0050C690)
     *   - T=Moho::EVisibilityMode: 0x0050A770 (FUN_0050A770)
     *   - T=Moho::EStatType: 0x004192B0 (FUN_004192B0)
     *   - T=Moho::EPulseMode: 0x00419350 (FUN_00419350)
     *   - T=Moho::EmitterType: 0x0065EE50 (FUN_0065EE50)
     *   - T=Moho::EResourceType: 0x005473B0 (FUN_005473B0) -- previously
     *     mis-modeled in ArchiveSerialization.cpp as a generic
     *     `InstallSerSaveLoadHelperCallbacksByTypeName(helper,
     *     "Moho::EResourceType")` dispatch (same mistake already caught for
     *     ESTITargetType above); the real body at this address is
     *     `__thiscall`, reads `this+0x0C`/`this+0x10` directly, and matches
     *     this template's `Init()` exactly (confirmed against raw asm).
     *   - T=Moho::EUnitCommandType: 0x00552D60 (FUN_00552D60) -- previously
     *     mis-labeled `gpg::SerSaveLoadHelper_EUnitCommandType::Init` in the
     *     prior recovery; raw asm matches this template's `Init()` exactly,
     *     including the identical `"!type->mSerLoadFunc"`/
     *     `"!type->mSerSaveFunc"` assert strings used by every other
     *     confirmed instantiation.
     *   - T=Moho::ESquadClass: 0x0072A4D0 -- confirmed via `incoming_xrefs`
     *     data xrefs from BOTH `??_7?$PrimitiveSerHelper@W4ESquadClass@
     *     Moho@@H@gpg@@6B@` (slot 0) and
     *     `??_7?$SerSaveLoadHelper@W4ESquadClass@Moho@@@gpg@@6B@` (slot 0) --
     *     one shared compiled body serves both vtables, same pattern as
     *     every other instantiation's `Init()`.
     *   - T=Moho::EThreatType: 0x00719370 -- same shared-body pattern,
     *     confirmed via `incoming_xrefs` from both the real
     *     `PrimitiveSerHelper<EThreatType,int>` vtable and the dead
     *     `SerSaveLoadHelper<EThreatType>` sibling vtable.
     * Address: 0x00523110 (FUN_00523110 -- `Init()` for `ERuleBPUnitMovementType`; formerly `InstallMohoERuleBPUnitMovementTypeSerializerCallbacks` in gpg/core/containers/ArchiveSerialization.cpp, whose by-name lookup was disproven.)
     * Address: 0x005231B0 (FUN_005231B0 -- `Init()` for `ERuleBPUnitCommandCaps`; formerly `InstallMohoERuleBPUnitCommandCapsSerializerCallbacks` in gpg/core/containers/ArchiveSerialization.cpp, whose by-name lookup was disproven.)
     * Address: 0x00523250 (FUN_00523250 -- `Init()` for `ERuleBPUnitToggleCaps`; formerly `InstallMohoERuleBPUnitToggleCapsSerializerCallbacks` in gpg/core/containers/ArchiveSerialization.cpp, whose by-name lookup was disproven.)
     * Address: 0x005982F0 (FUN_005982F0 -- `Init()` for `ECollisionType`; formerly `InstallMohoECollisionTypeSerializerCallbacks` in gpg/core/containers/ArchiveSerialization.cpp, whose by-name lookup was disproven.)
     * Address: 0x005A6EF0 (FUN_005A6EF0 -- `Init()` for `EAiNavigatorStatus`; formerly `InstallMohoEAiNavigatorStatusSerializerCallbacks` in gpg/core/containers/ArchiveSerialization.cpp, whose by-name lookup was disproven.)
     * Address: 0x005A6F90 (FUN_005A6F90 -- `Init()` for `EAiNavigatorEvent`; formerly `InstallMohoEAiNavigatorEventSerializerCallbacks` in gpg/core/containers/ArchiveSerialization.cpp, whose by-name lookup was disproven.)
     * Address: 0x005DB720 (FUN_005DB720 -- `Init()` for `EAiAttackerEvent`; formerly `InstallMohoEAiAttackerEventSerializerCallbacks` in gpg/core/containers/ArchiveSerialization.cpp, whose by-name lookup was disproven.)
     * Address: 0x005E34A0 (FUN_005E34A0 -- `Init()` for `EAiTargetType`; formerly `InstallMohoEAiTargetTypeSerializerCallbacks` in gpg/core/containers/ArchiveSerialization.cpp, whose by-name lookup was disproven.)
     * Address: 0x005E8B90 (FUN_005E8B90 -- `Init()` for `EAiTransportEvent`; formerly `InstallMohoEAiTransportEventSerializerCallbacks` in gpg/core/containers/ArchiveSerialization.cpp, whose by-name lookup was disproven.)
     * Address: 0x0062F870 (FUN_0062F870 -- `Init()` for `EPathPointState`; formerly `InstallMohoEPathPointStateSerializerCallbacks` in gpg/core/containers/ArchiveSerialization.cpp, whose by-name lookup was disproven.)
     * Address: 0x0069E860 (FUN_0069E860 -- `Init()` for `EProjectileImpactEvent`; formerly `InstallMohoEProjectileImpactEventSerializerCallbacks` in gpg/core/containers/ArchiveSerialization.cpp, whose by-name lookup was disproven.)
     * Address: 0x00718900 (FUN_00718900 -- `Init()` for `EThreatType`; formerly `InstallMohoEThreatTypeSerializerCallbacks` in gpg/core/containers/ArchiveSerialization.cpp, whose by-name lookup was disproven.)
     * Address: 0x0055C860 (FUN_0055C860 -- `Init()` for `PrimitiveSerHelper<moho::EJobType, int>`, vftable slot 0; formerly cited in gpg/core/containers/ArchiveSerialization.cpp as `InstallMohoEJobTypeSerializerCallbacks`.)
     * Address: 0x0055C900 (FUN_0055C900 -- `Init()` for `PrimitiveSerHelper<moho::EFireState, int>`, vftable slot 0; formerly cited in gpg/core/containers/ArchiveSerialization.cpp as `InstallMohoEFireStateSerializerCallbacks`.)
     * Address: 0x0055C9A0 (FUN_0055C9A0 -- `Init()` for `PrimitiveSerHelper<moho::EUnitState, int>`, vftable slot 0; formerly cited in gpg/core/containers/ArchiveSerialization.cpp as `InstallMohoEUnitStateSerializerCallbacks`.)
     * Address: 0x006E9760 (FUN_006E9760 -- `Init()` for `PrimitiveSerHelper<moho::ECommandEvent, int>`, vftable slot 0; formerly cited in gpg/core/containers/ArchiveSerialization.cpp as `InstallMohoECommandEventSerializerCallbacks`.)
     *
     * What it does:
     * Lazily resolves `T`'s RTTI and installs load/save callbacks from this
     * helper object into the type descriptor (vtable slot 0, dispatched by
     * `SerHelperBase::InitNewHelpers`).
     */
    void Init() override
    {
      if (sCachedType == nullptr) {
        sCachedType = LookupRType(typeid(T));
      }
      GPG_ASSERT(sCachedType->serLoadFunc_ == nullptr);
      sCachedType->serLoadFunc_ = mLoadCallback;
      GPG_ASSERT(sCachedType->serSaveFunc_ == nullptr);
      sCachedType->serSaveFunc_ = mSaveCallback;
    }

  public:
    RType::load_func_t mLoadCallback; // +0x0C
    RType::save_func_t mSaveCallback; // +0x10

  private:
    static inline RType* sCachedType = nullptr;
  };

  /**
   * VFTABLE: 0x00D48CA0
   * COL:  0x00E5DC40
   * Source hints:
   *  - c:\work\rts\main\code\src\libs\gpgcore\reflection\reflection.cpp
   */
  class REnumType : public RType
  {
  public:
    struct ROptionValue
    {
      int mValue;
      const char* mName;
    };

    /**
     * In binary:
     *
     * Address: 0x004180A0 (FUN_004180A0)
     *
     * What it does:
     * Constructs enum-type reflection state, zeroes prefix/options lanes, and
     * installs the `REnumType` virtual surface.
     */
    REnumType();

    /**
     * In binary:
     *
     * Address: 0x00418120 (FUN_00418120)
     * VFTable SLOT: 2
     *
     * What it does:
     * Releases enum option storage and tears down inherited `RType` lanes.
     */
    ~REnumType() override;

    /**
     * In binary:
     *
     * Address: 0x008E1C40
     * VFTable SLOT: 4
     */
    [[nodiscard]]
    msvc8::string GetLexical(const RRef& ref) const override;

    /**
     * In binary:
     *
     * Address: 0x008D9670
     * VFTable SLOT: 5
     */
    bool SetLexical(const RRef&, const char*) const override;

    /**
     * In binary:
     *
     * Address: 0x004180F0
     * VFTable SLOT: 8
     */
    const REnumType* IsEnumType() const override
    {
      return this;
    }

    const msvc8::vector<ROptionValue>& GetEnumOptions() const
    {
      return mEnumNames;
    }

    /**
     * In binary:
     *
     * Address: 0x008D86F0
     */
    const char* StripPrefix(const char*) const;

    /**
     * Address: 0x008D9FD0 (FUN_008D9FD0)
     *
     * What it does:
     * Scans the enum option table and returns the numeric value for a
     * case-insensitive option-name match.
     */
    bool GetEnumValue(const char*, int*) const;

    /**
     * In binary:
     *
     * Address: 0x008DF5F0
     */
    void AddEnum(char const* name, int index);

  public:
    const char* mPrefix;
    msvc8::vector<ROptionValue> mEnumNames;
  };
  static_assert(sizeof(REnumType) == 0x78, "REnumType must be 0x78 bytes on x86");

  class RIndexed
  {
  public:
    virtual RRef SubscriptIndex(void* obj, int ind) const = 0;

    virtual size_t GetCount(void* obj) const = 0;

    /**
     * Address: 0x004012F0 (FUN_004012F0)
     *
     * What it does:
     * Base implementation rejects resize/count mutation for non-resizable indexed types.
     */
    virtual void SetCount(void* obj, int count) const;

    /**
     * Address: 0x00401320 (FUN_00401320)
     *
     * What it does:
     * Base implementation rejects pointer assignment for non-pointer indexed types.
     */
    virtual void AssignPointer(void* obj, const RRef& from) const;
  };

  template <class T>
  class RPointerType;

  /**
   * Common base for pointer-reflection wrappers (`T*`).
   *
   * What it does:
   * Owns shared pointer-slot indexed semantics so per-type specializations only
   * recover the type-specific virtual surface from FA.
   */
  class RPointerTypeBase : public RType, public RIndexed
  {
  public:
    RRef SubscriptIndex(void* obj, int ind) const override;
    size_t GetCount(void* obj) const override;
    void SetCount(void* obj, int count) const override;
    void AssignPointer(void* obj, const RRef& from) const override;

    /**
     * Shared indexed-self helper used by specialization thunks.
     */
    [[nodiscard]]
    const RIndexed* AsIndexedSelf() const noexcept;

  protected:
    [[nodiscard]]
    virtual RType* GetPointeeType() const = 0;
  };
  static_assert(sizeof(RPointerTypeBase) == 0x68, "RPointerTypeBase size must be 0x68");

  /**
   * VFTABLE: 0x00E0043C
   * COL:  0x00E5CC74
   * Source hints:
   *  - c:\work\rts\main\code\src\libs\gpgcore\reflection\reflection.cpp
   */
  template <>
  class RPointerType<moho::CTaskThread> final : public RPointerTypeBase
  {
  public:
    /**
     * Address: 0x0040C8B0 (FUN_0040C8B0)
     * Demangled: sub_40C8B0
     */
    RPointerType();

    /**
     * Address: 0x0040CBD0 (FUN_0040CBD0)
     * Demangled: sub_40CBD0
     */
    ~RPointerType() override;

    /**
     * Address: 0x0040C7C0 (FUN_0040C7C0)
     * Demangled: gpg::RPointerType_CTaskThread::GetName
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0040C950 (FUN_0040C950)
     * Demangled: gpg::RPointerType_CTaskThread::GetLexical
     */
    [[nodiscard]]
    msvc8::string GetLexical(const RRef& ref) const override;

    /**
     * Address: 0x0040CAD0 (FUN_0040CAD0)
     * Demangled: gpg::RPointerType_CTaskThread::IsIndexed
     */
    [[nodiscard]]
    const RIndexed* IsIndexed() const override;

    /**
     * Address: 0x0040CAE0 (FUN_0040CAE0)
     * Demangled: gpg::RPointerType_CTaskThread::IsPointer
     */
    [[nodiscard]]
    const RIndexed* IsPointer() const override;

    /**
     * Address: 0x0040C920 (FUN_0040C920)
     * Demangled: gpg::RPointerType_CTaskThread::Init
     */
    void Init() override;

  protected:
    [[nodiscard]]
    RType* GetPointeeType() const override;
  };
  static_assert(sizeof(RPointerType<moho::CTaskThread>) == 0x68, "RPointerType<CTaskThread> size must be 0x68");

  /**
   * VFTABLE: 0x00E1E7CC
   * COL:  0x00E75ED0
   * Source hints:
   *  - c:\work\rts\main\code\src\libs\gpgcore\reflection\reflection.cpp
   */
  template <>
  class RPointerType<moho::CAcquireTargetTask> final : public RPointerTypeBase
  {
  public:
    /**
     * Address: 0x005DE390 (FUN_005DE390)
     * Demangled: gpg::RPointerType_CAcquireTargetTask::dtr
     */
    ~RPointerType() override;

    /**
     * Address: 0x005DDF20 (FUN_005DDF20)
     * Demangled: gpg::RPointerType_CAcquireTargetTask::GetName
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005DE0B0 (FUN_005DE0B0)
     * Demangled: gpg::RPointerType_CAcquireTargetTask::GetLexical
     */
    [[nodiscard]]
    msvc8::string GetLexical(const RRef& ref) const override;

    /**
     * Address: 0x005DE230 (FUN_005DE230)
     * Demangled: gpg::RPointerType_CAcquireTargetTask::IsIndexed
     */
    [[nodiscard]]
    const RIndexed* IsIndexed() const override;

    /**
     * Address: 0x005DE240 (FUN_005DE240)
     * Demangled: gpg::RPointerType_CAcquireTargetTask::IsPointer
     */
    [[nodiscard]]
    const RIndexed* IsPointer() const override;

    /**
     * Address: 0x005DE2A0 (FUN_005DE2A0)
     * Demangled: gpg::RPointerType_CAcquireTargetTask::AssignPointer
     *
     * What it does:
     * Upcasts a reflected source reference to `CAcquireTargetTask*` and stores
     * it in the destination pointer slot.
     */
    void AssignPointer(void* obj, const RRef& from) const override;

    /**
     * Address: 0x005DE080 (FUN_005DE080)
     * Demangled: gpg::RPointerType_CAcquireTargetTask::Init
     */
    void Init() override;

  protected:
    [[nodiscard]]
    RType* GetPointeeType() const override;
  };
  static_assert(
    sizeof(RPointerType<moho::CAcquireTargetTask>) == 0x68, "RPointerType<CAcquireTargetTask> size must be 0x68"
  );

  /**
   * VFTABLE: 0x00E34864 (primary) / 0x00E34894 (RIndexed subobject @ +0x64)
   * Source hints:
   *  - c:\work\rts\main\code\src\libs\gpgcore\reflection\reflection.cpp
   */
  template <>
  class RPointerType<moho::SimArmy> final : public RPointerTypeBase
  {
  public:
    /**
     * Address: 0x00750630 (FUN_00750630)
     * Demangled: gpg::RPointerType_SimArmy::dtr
     */
    ~RPointerType() override;

    /**
     * Address: 0x0074FD80 (FUN_0074FD80)
     * Demangled: gpg::RPointerType_SimArmy::GetName
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0074FF10 (FUN_0074FF10)
     * Demangled: gpg::RPointerType_SimArmy::GetLexical
     */
    [[nodiscard]]
    msvc8::string GetLexical(const RRef& ref) const override;

    /**
     * Address: 0x00750090 (FUN_00750090)
     * Demangled: gpg::RPointerType_SimArmy::IsIndexed
     */
    [[nodiscard]]
    const RIndexed* IsIndexed() const override;

    /**
     * Address: 0x007500A0 (FUN_007500A0)
     * Demangled: gpg::RPointerType_SimArmy::IsPointer
     */
    [[nodiscard]]
    const RIndexed* IsPointer() const override;

    /**
     * Address: 0x007500C0 (FUN_007500C0)
     * Demangled: gpg::RPointerType_SimArmy::SubscriptIndex
     */
    [[nodiscard]]
    RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x007500B0 (FUN_007500B0)
     * Demangled: gpg::RPointerType_SimArmy::GetCount
     */
    [[nodiscard]]
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x00750100 (FUN_00750100)
     * Demangled: gpg::RPointerType_SimArmy::AssignPointer
     *
     * What it does:
     * Upcasts a reflected source reference to `SimArmy*` and stores it in the
     * destination pointer slot.
     */
    void AssignPointer(void* obj, const RRef& from) const override;

    /**
     * Address: 0x0074FEE0 (FUN_0074FEE0)
     * Demangled: gpg::RPointerType_SimArmy::Init
     */
    void Init() override;

  protected:
    [[nodiscard]]
    RType* GetPointeeType() const override;
  };
  static_assert(sizeof(RPointerType<moho::SimArmy>) == 0x68, "RPointerType<SimArmy> size must be 0x68");

  /**
   * VFTABLE: 0x00E348A8 (primary) / 0x00E348D8 (RIndexed subobject @ +0x64)
   * Source hints:
   *  - c:\work\rts\main\code\src\libs\gpgcore\reflection\reflection.cpp
   */
  template <>
  class RPointerType<moho::Shield> final : public RPointerTypeBase
  {
  public:
    /**
     * Address: 0x00750690 (FUN_00750690)
     * Demangled: gpg::RPointerType_Shield::dtr
     */
    ~RPointerType() override;

    /**
     * Address: 0x00750190 (FUN_00750190)
     * Demangled: gpg::RPointerType_Shield::GetName
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00750320 (FUN_00750320)
     * Demangled: gpg::RPointerType_Shield::GetLexical
     */
    [[nodiscard]]
    msvc8::string GetLexical(const RRef& ref) const override;

    /**
     * Address: 0x007504A0 (FUN_007504A0)
     * Demangled: gpg::RPointerType_Shield::IsIndexed
     */
    [[nodiscard]]
    const RIndexed* IsIndexed() const override;

    /**
     * Address: 0x007504B0 (FUN_007504B0)
     * Demangled: gpg::RPointerType_Shield::IsPointer
     */
    [[nodiscard]]
    const RIndexed* IsPointer() const override;

    /**
     * Address: 0x007504D0 (FUN_007504D0)
     * Demangled: gpg::RPointerType_Shield::SubscriptIndex
     */
    [[nodiscard]]
    RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x007504C0 (FUN_007504C0)
     * Demangled: gpg::RPointerType_Shield::GetCount
     */
    [[nodiscard]]
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x00750510 (FUN_00750510)
     * Demangled: gpg::RPointerType_Shield::AssignPointer
     *
     * What it does:
     * Upcasts a reflected source reference to `Shield*` and stores it in the
     * destination pointer slot.
     */
    void AssignPointer(void* obj, const RRef& from) const override;

    /**
     * Address: 0x007502F0 (FUN_007502F0)
     * Demangled: gpg::RPointerType_Shield::Init
     */
    void Init() override;

  protected:
    [[nodiscard]]
    RType* GetPointeeType() const override;
  };
  static_assert(sizeof(RPointerType<moho::Shield>) == 0x68, "RPointerType<Shield> size must be 0x68");

  /**
   * Source hints:
   *  - c:\work\rts\main\code\src\libs\gpgcore\reflection\reflection.cpp
   */
  template <>
  class RPointerType<moho::CDecalHandle> final : public RPointerTypeBase
  {
  public:
    /**
     * Address: 0x0077EEC0 (FUN_0077EEC0)
     * Demangled: gpg::RPointerType_CDecalHandle::dtr
     */
    ~RPointerType() override;

    /**
     * Address: 0x0077EAB0 (FUN_0077EAB0)
     * Demangled: gpg::RPointerType_CDecalHandle::GetName
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0077EC40 (FUN_0077EC40)
     * Demangled: gpg::RPointerType_CDecalHandle::GetLexical
     */
    [[nodiscard]]
    msvc8::string GetLexical(const RRef& ref) const override;

    /**
     * Address: 0x0077EDC0 (FUN_0077EDC0)
     * Demangled: gpg::RPointerType_CDecalHandle::IsIndexed
     */
    [[nodiscard]]
    const RIndexed* IsIndexed() const override;

    /**
     * Address: 0x0077EDD0 (FUN_0077EDD0)
     * Demangled: gpg::RPointerType_CDecalHandle::IsPointer
     */
    [[nodiscard]]
    const RIndexed* IsPointer() const override;

    /**
     * Address: 0x0077EDF0 (FUN_0077EDF0)
     * Demangled: gpg::RPointerType_CDecalHandle::SubscriptIndex
     */
    [[nodiscard]]
    RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x0077EDE0 (FUN_0077EDE0)
     * Demangled: gpg::RPointerType_CDecalHandle::GetCount
     */
    [[nodiscard]]
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x0077EE30 (FUN_0077EE30)
     * Demangled: gpg::RPointerType_CDecalHandle::AssignPointer
     *
     * What it does:
     * Upcasts a reflected source reference to `CDecalHandle*` and stores it in
     * the destination pointer slot.
     */
    void AssignPointer(void* obj, const RRef& from) const override;

    /**
     * Address: 0x0077EC10 (FUN_0077EC10)
     * Demangled: gpg::RPointerType_CDecalHandle::Init
     */
    void Init() override;

  protected:
    [[nodiscard]]
    RType* GetPointeeType() const override;
  };
  static_assert(sizeof(RPointerType<moho::CDecalHandle>) == 0x68, "RPointerType<CDecalHandle> size must be 0x68");

  /**
   * Source hints:
   *  - c:\work\rts\main\code\src\libs\gpgcore\reflection\reflection.cpp
   */
  template <>
  class RPointerType<moho::RBlueprint> final : public RPointerTypeBase
  {
  public:
    /**
     * Address: 0x00557380 (FUN_00557380)
     * Demangled: gpg::RPointerType_RBlueprint::dtr
     */
    ~RPointerType() override;

    /**
     * Address: 0x00556F00 (FUN_00556F00)
     * Demangled: gpg::RPointerType_RBlueprint::GetName
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00557090 (FUN_00557090)
     * Demangled: gpg::RPointerType_RBlueprint::GetLexical
     */
    [[nodiscard]]
    msvc8::string GetLexical(const RRef& ref) const override;

    /**
     * Address: 0x00557210 (FUN_00557210)
     * Demangled: gpg::RPointerType_RBlueprint::IsIndexed
     */
    [[nodiscard]]
    const RIndexed* IsIndexed() const override;

    /**
     * Address: 0x00557220 (FUN_00557220)
     * Demangled: gpg::RPointerType_RBlueprint::IsPointer
     */
    [[nodiscard]]
    const RIndexed* IsPointer() const override;

    /**
     * Address: 0x00557240 (FUN_00557240)
     * Demangled: gpg::RPointerType_RBlueprint::SubscriptIndex
     *
     * What it does:
     * Builds a reflected reference to the `ind`-th `RBlueprint` in the array
     * the pointer slot addresses (stride `sizeof(RBlueprint)`).
     */
    [[nodiscard]]
    RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x00557230 (FUN_00557230)
     * Demangled: gpg::RPointerType_RBlueprint::GetCount
     *
     * What it does:
     * Returns 1 when the pointer slot is non-null, else 0 (a pointer type
     * holds at most one element).
     */
    [[nodiscard]]
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x00557280 (FUN_00557280)
     * Demangled: gpg::RPointerType_RBlueprint::AssignPointer
     *
     * What it does:
     * Upcasts a reflected source reference to `RBlueprint*` and stores it in
     * the destination pointer slot.
     */
    void AssignPointer(void* obj, const RRef& from) const override;

    /**
     * Address: 0x00557060 (FUN_00557060)
     * Demangled: gpg::RPointerType_RBlueprint::Init
     */
    void Init() override;

  protected:
    [[nodiscard]]
    RType* GetPointeeType() const override;
  };
  static_assert(sizeof(RPointerType<moho::RBlueprint>) == 0x68, "RPointerType<RBlueprint> size must be 0x68");

  /**
   * Source hints:
   *  - c:\work\rts\main\code\src\libs\gpgcore\reflection\reflection.cpp
   */
  template <>
  class RPointerType<moho::UnitWeapon> final : public RPointerTypeBase
  {
  public:
    /**
     * Address: 0x005DE330 (FUN_005DE330)
     * Demangled: gpg::RPointerType_UnitWeapon::dtr
     */
    ~RPointerType() override;

    /**
     * Address: 0x005DDB10 (FUN_005DDB10)
     * Demangled: gpg::RPointerType_UnitWeapon::GetName
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005DDCA0 (FUN_005DDCA0)
     * Demangled: gpg::RPointerType_UnitWeapon::GetLexical
     */
    [[nodiscard]]
    msvc8::string GetLexical(const RRef& ref) const override;

    /**
     * Address: 0x005DDE20 (FUN_005DDE20)
     * Demangled: gpg::RPointerType_UnitWeapon::IsIndexed
     */
    [[nodiscard]]
    const RIndexed* IsIndexed() const override;

    /**
     * Address: 0x005DDE30 (FUN_005DDE30)
     * Demangled: gpg::RPointerType_UnitWeapon::IsPointer
     */
    [[nodiscard]]
    const RIndexed* IsPointer() const override;

    /**
     * Address: 0x005DDE50 (FUN_005DDE50)
     * Demangled: gpg::RPointerType_UnitWeapon::SubscriptIndex
     *
     * What it does:
     * Builds a reflected reference to the `ind`-th `UnitWeapon` in the array
     * the pointer slot addresses (stride `sizeof(UnitWeapon)`).
     */
    [[nodiscard]]
    RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x005DDE40 (FUN_005DDE40)
     * Demangled: gpg::RPointerType_UnitWeapon::GetCount
     *
     * What it does:
     * Returns 1 when the pointer slot is non-null, else 0 (a pointer type
     * holds at most one element).
     */
    [[nodiscard]]
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x005DDE90 (FUN_005DDE90)
     * Demangled: gpg::RPointerType_UnitWeapon::AssignPointer
     *
     * What it does:
     * Upcasts a reflected source reference to `UnitWeapon*` and stores it in
     * the destination pointer slot.
     */
    void AssignPointer(void* obj, const RRef& from) const override;

    /**
     * Address: 0x005DDC70 (FUN_005DDC70)
     * Demangled: gpg::RPointerType_UnitWeapon::Init
     */
    void Init() override;

  protected:
    [[nodiscard]]
    RType* GetPointeeType() const override;
  };
  static_assert(sizeof(RPointerType<moho::UnitWeapon>) == 0x68, "RPointerType<UnitWeapon> size must be 0x68");

  /**
   * Source hints:
   *  - c:\work\rts\main\code\src\libs\gpgcore\reflection\reflection.cpp
   */
  template <>
  class RPointerType<moho::IAniManipulator> final : public RPointerTypeBase
  {
  public:
    /**
     * Address: 0x0063DF50 (FUN_0063DF50)
     * Demangled: gpg::RPointerType_IAniManipulator::dtr
     */
    ~RPointerType() override;

    /**
     * Address: 0x0063DB40 (FUN_0063DB40)
     * Demangled: gpg::RPointerType_IAniManipulator::GetName
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0063DCD0 (FUN_0063DCD0)
     * Demangled: gpg::RPointerType_IAniManipulator::GetLexical
     */
    [[nodiscard]]
    msvc8::string GetLexical(const RRef& ref) const override;

    /**
     * Address: 0x0063DE50 (FUN_0063DE50)
     * Demangled: gpg::RPointerType_IAniManipulator::IsIndexed
     */
    [[nodiscard]]
    const RIndexed* IsIndexed() const override;

    /**
     * Address: 0x0063DE60 (FUN_0063DE60)
     * Demangled: gpg::RPointerType_IAniManipulator::IsPointer
     */
    [[nodiscard]]
    const RIndexed* IsPointer() const override;

    /**
     * Address: 0x0063DEC0 (FUN_0063DEC0)
     * Demangled: gpg::RPointerType_IAniManipulator::AssignPointer
     *
     * What it does:
     * Upcasts a reflected source reference to `IAniManipulator*` and stores it
     * in the destination pointer slot.
     */
    void AssignPointer(void* obj, const RRef& from) const override;

    /**
     * Address: 0x0063DCA0 (FUN_0063DCA0)
     * Demangled: gpg::RPointerType_IAniManipulator::Init
     */
    void Init() override;

  protected:
    [[nodiscard]]
    RType* GetPointeeType() const override;
  };
  static_assert(sizeof(RPointerType<moho::IAniManipulator>) == 0x68, "RPointerType<IAniManipulator> size must be 0x68");

  /**
   * Source hints:
   *  - c:\work\rts\main\code\src\libs\gpgcore\reflection\reflection.cpp
   */
  template <>
  class RPointerType<moho::IEffect> final : public RPointerTypeBase
  {
  public:
    /**
     * Address: 0x0066CB30 (FUN_0066CB30)
     *
     * What it does:
     * Builds the descriptor and pre-registers it under `typeid(IEffect*)`.
     * The one instance is `IEffect::GetPointerType`'s function-local static,
     * and LTCG folded its address into the body: `this` is the constant
     * 0x010C8608 rather than ECX.
     */
    RPointerType();

    /**
     * Address: 0x0066CE50 (FUN_0066CE50)
     * Demangled: gpg::RPointerType_IEffect::dtr
     */
    ~RPointerType() override;

    /**
     * Address: 0x0066CA40 (FUN_0066CA40)
     * Demangled: gpg::RPointerType_IEffect::GetName
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0066CBD0 (FUN_0066CBD0)
     * Demangled: gpg::RPointerType_IEffect::GetLexical
     */
    [[nodiscard]]
    msvc8::string GetLexical(const RRef& ref) const override;

    /**
     * Address: 0x0066CD50 (FUN_0066CD50)
     * Demangled: gpg::RPointerType_IEffect::IsIndexed
     */
    [[nodiscard]]
    const RIndexed* IsIndexed() const override;

    /**
     * Address: 0x0066CD60 (FUN_0066CD60)
     * Demangled: gpg::RPointerType_IEffect::IsPointer
     */
    [[nodiscard]]
    const RIndexed* IsPointer() const override;

    /**
     * Address: 0x0066CDC0 (FUN_0066CDC0)
     * Demangled: gpg::RPointerType_IEffect::AssignPointer
     *
     * What it does:
     * Upcasts a reflected source reference to `IEffect*` and stores it in the
     * destination pointer slot.
     */
    void AssignPointer(void* obj, const RRef& from) const override;

    /**
     * Address: 0x0066CBA0 (FUN_0066CBA0)
     * Demangled: gpg::RPointerType_IEffect::Init
     */
    void Init() override;

  protected:
    [[nodiscard]]
    RType* GetPointeeType() const override;
  };
  static_assert(sizeof(RPointerType<moho::IEffect>) == 0x68, "RPointerType<IEffect> size must be 0x68");

  /**
   * Source hints:
   *  - c:\work\rts\main\code\src\libs\gpgcore\reflection\reflection.cpp
   */
  template <>
  class RPointerType<moho::CUnitCommand> final : public RPointerTypeBase
  {
  public:
    /**
     * Address: 0x006E3AC0 (FUN_006E3AC0)
     * Demangled: gpg::RPointerType_CUnitCommand::dtr
     */
    ~RPointerType() override;

    /**
     * Address: 0x006E36B0 (FUN_006E36B0)
     * Demangled: gpg::RPointerType_CUnitCommand::GetName
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x006E3840 (FUN_006E3840)
     * Demangled: gpg::RPointerType_CUnitCommand::GetLexical
     */
    [[nodiscard]]
    msvc8::string GetLexical(const RRef& ref) const override;

    /**
     * Address: 0x006E39C0 (FUN_006E39C0)
     * Demangled: gpg::RPointerType_CUnitCommand::IsIndexed
     */
    [[nodiscard]]
    const RIndexed* IsIndexed() const override;

    /**
     * Address: 0x006E39D0 (FUN_006E39D0)
     * Demangled: gpg::RPointerType_CUnitCommand::IsPointer
     */
    [[nodiscard]]
    const RIndexed* IsPointer() const override;

    /**
     * Address: 0x006E3A30 (FUN_006E3A30)
     * Demangled: gpg::RPointerType_CUnitCommand::AssignPointer
     *
     * What it does:
     * Upcasts a reflected source reference to `CUnitCommand*` and stores it in
     * the destination pointer slot.
     */
    void AssignPointer(void* obj, const RRef& from) const override;

    /**
     * Address: 0x006E3810 (FUN_006E3810)
     * Demangled: gpg::RPointerType_CUnitCommand::Init
     */
    void Init() override;

  protected:
    [[nodiscard]]
    RType* GetPointeeType() const override;
  };
  static_assert(sizeof(RPointerType<moho::CUnitCommand>) == 0x68, "RPointerType<CUnitCommand> size must be 0x68");

  /**
   * Source hints:
   *  - c:\work\rts\main\code\src\libs\gpgcore\reflection\reflection.cpp
   */
  template <>
  class RPointerType<moho::Entity> final : public RPointerTypeBase
  {
  public:
    /**
     * Address: 0x0067E750 (FUN_0067E750)
     * Demangled: gpg::RPointerType_Entity::dtr
     */
    ~RPointerType() override;

    /**
     * Address: 0x0067E320 (FUN_0067E320)
     * Demangled: gpg::RPointerType_Entity::GetName
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0067E4B0 (FUN_0067E4B0)
     * Demangled: gpg::RPointerType_Entity::GetLexical
     */
    [[nodiscard]]
    msvc8::string GetLexical(const RRef& ref) const override;

    /**
     * Address: 0x0067E630 (FUN_0067E630)
     * Demangled: gpg::RPointerType_Entity::IsIndexed
     */
    [[nodiscard]]
    const RIndexed* IsIndexed() const override;

    /**
     * Address: 0x0067E640 (FUN_0067E640)
     * Demangled: gpg::RPointerType_Entity::IsPointer
     */
    [[nodiscard]]
    const RIndexed* IsPointer() const override;

    /**
     * Address: 0x0067E6A0 (FUN_0067E6A0)
     * Demangled: gpg::RPointerType_Entity::AssignPointer
     *
     * What it does:
     * Upcasts a reflected source reference to `Entity*` and stores it in the
     * destination pointer slot.
     */
    void AssignPointer(void* obj, const RRef& from) const override;

    /**
     * Address: 0x0067E480 (FUN_0067E480)
     * Demangled: gpg::RPointerType_Entity::Init
     */
    void Init() override;

  protected:
    [[nodiscard]]
    RType* GetPointeeType() const override;
  };
  static_assert(sizeof(RPointerType<moho::Entity>) == 0x68, "RPointerType<Entity> size must be 0x68");

  /**
   * Source hints:
   *  - c:\work\rts\main\code\src\libs\gpgcore\reflection\reflection.cpp
   */
  template <>
  class RPointerType<moho::CEconomyEvent> final : public RPointerTypeBase
  {
  public:
    /**
     * Address: 0x006B2920 (FUN_006B2920)
     * Demangled: gpg::RPointerType_CEconomyEvent::dtr
     */
    ~RPointerType() override;

    /**
     * Address: 0x006B2510 (FUN_006B2510)
     * Demangled: gpg::RPointerType_CEconomyEvent::GetName
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x006B26A0 (FUN_006B26A0)
     * Demangled: gpg::RPointerType_CEconomyEvent::GetLexical
     */
    [[nodiscard]]
    msvc8::string GetLexical(const RRef& ref) const override;

    /**
     * Address: 0x006B2820 (FUN_006B2820)
     * Demangled: gpg::RPointerType_CEconomyEvent::IsIndexed
     */
    [[nodiscard]]
    const RIndexed* IsIndexed() const override;

    /**
     * Address: 0x006B2830 (FUN_006B2830)
     * Demangled: gpg::RPointerType_CEconomyEvent::IsPointer
     */
    [[nodiscard]]
    const RIndexed* IsPointer() const override;

    /**
     * Address: 0x006B2890 (FUN_006B2890)
     * Demangled: gpg::RPointerType_CEconomyEvent::AssignPointer
     *
     * What it does:
     * Upcasts a reflected source reference to `CEconomyEvent*` and stores it
     * in the destination pointer slot.
     */
    void AssignPointer(void* obj, const RRef& from) const override;

    /**
     * Address: 0x006B2670 (FUN_006B2670)
     * Demangled: gpg::RPointerType_CEconomyEvent::Init
     */
    void Init() override;

  protected:
    [[nodiscard]]
    RType* GetPointeeType() const override;
  };
  static_assert(
    sizeof(RPointerType<moho::CEconomyEvent>) == 0x68, "RPointerType<CEconomyEvent> size must be 0x68"
  );

  /**
   * VFTABLE: 0x00E017C0
   * COL:  0x00E5DD44
   * Source hints:
   *  - c:\work\rts\main\code\src\libs\gpgcore\reflection\reflection.cpp
   */
  template <>
  class RPointerType<moho::CLuaConOutputHandler> final : public RPointerTypeBase
  {
  public:
    /**
     * Address: 0x004212A0 (FUN_004212A0)
     * Demangled: gpg::RPointerType_CLuaConOutputHandler::RPointerType
     */
    RPointerType();

    /**
     * Address: 0x004215C0 (FUN_004215C0)
     * Demangled: gpg::RPointerType_CLuaConOutputHandler::dtr
     */
    ~RPointerType() override;

    /**
     * Address: 0x004211B0 (FUN_004211B0)
     * Demangled: gpg::RPointerType_CLuaConOutputHandler::GetName
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00421340 (FUN_00421340)
     * Demangled: gpg::RPointerType_CLuaConOutputHandler::GetLexical
     */
    [[nodiscard]]
    msvc8::string GetLexical(const RRef& ref) const override;

    /**
     * Address: 0x004214C0 (FUN_004214C0)
     * Demangled: gpg::RPointerType_CLuaConOutputHandler::IsIndexed
     */
    [[nodiscard]]
    const RIndexed* IsIndexed() const override;

    /**
     * Address: 0x004214D0 (FUN_004214D0)
     * Demangled: gpg::RPointerType_CLuaConOutputHandler::IsPointer
     */
    [[nodiscard]]
    const RIndexed* IsPointer() const override;

    /**
     * Address: 0x00421310 (FUN_00421310)
      * Alias of FUN_00421620 (non-canonical helper lane).
      * Alias of FUN_00421660 (non-canonical helper lane).
      * Alias of FUN_00421670 (non-canonical helper lane).
     * Demangled: gpg::RPointerType_CLuaConOutputHandler::Init
     */
    void Init() override;

  protected:
    [[nodiscard]]
    RType* GetPointeeType() const override;
  };
  static_assert(
    sizeof(RPointerType<moho::CLuaConOutputHandler>) == 0x68, "RPointerType<CLuaConOutputHandler> size must be 0x68"
  );

  /**
   * VFTABLE: 0x00E092D0
   * COL:  0x00E631BC
   * Source hints:
   *  - c:\work\rts\main\code\src\libs\gpgcore\reflection\reflection.cpp
   */
  template <>
  class RPointerType<moho::CScriptObject> final : public RPointerTypeBase
  {
  public:
    /**
     * Address: 0x004C8A00 (FUN_004C8A00)
     * Demangled: gpg::RPointerType_CScriptObject::dtr
     */
    ~RPointerType() override;

    /**
     * Address: 0x004C85F0 (FUN_004C85F0)
     * Demangled: gpg::RPointerType_CScriptObject::GetName
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x004C8780 (FUN_004C8780)
     * Demangled: gpg::RPointerType_CScriptObject::GetLexical
     */
    [[nodiscard]]
    msvc8::string GetLexical(const RRef& ref) const override;

    /**
     * Address: 0x004C8900 (FUN_004C8900)
     * Demangled: gpg::RPointerType_CScriptObject::IsIndexed
     */
    [[nodiscard]]
    const RIndexed* IsIndexed() const override;

    /**
     * Address: 0x004C8910 (FUN_004C8910)
     * Demangled: gpg::RPointerType_CScriptObject::IsPointer
     */
    [[nodiscard]]
    const RIndexed* IsPointer() const override;

    /**
     * Address: 0x004C8930 (FUN_004C8930)
     * Demangled: gpg::RPointerType_CScriptObject::SubscriptIndex
     */
    [[nodiscard]]
    RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x004C8920 (FUN_004C8920)
     * Demangled: gpg::RPointerType_CScriptObject::GetCount
     */
    [[nodiscard]]
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x004C8970 (FUN_004C8970)
     * Demangled: gpg::RPointerType_CScriptObject::AssignPointer
     *
     * What it does:
     * Upcasts a reflected source reference to `CScriptObject*` and stores it
     * in the destination pointer slot.
     */
    void AssignPointer(void* obj, const RRef& from) const override;

    /**
     * Address: 0x004C8750 (FUN_004C8750)
     * Demangled: gpg::RPointerType_CScriptObject::Init
     */
    void Init() override;

  protected:
    [[nodiscard]]
    RType* GetPointeeType() const override;
  };
  static_assert(sizeof(RPointerType<moho::CScriptObject>) == 0x68, "RPointerType<CScriptObject> size must be 0x68");

  /**
   * VFTABLE: 0x00E0BAF8
   * COL:  0x00E648D4
   * Source hints:
   *  - c:\work\rts\main\code\src\libs\gpgcore\reflection\reflection.cpp
   */
  template <>
  class RPointerType<moho::CSndParams> final : public RPointerTypeBase
  {
  public:
    /**
     * Address: 0x004E5FD0 (FUN_004E5FD0)
     * Demangled: sub_4E5FD0
     */
    ~RPointerType() override;

    /**
     * Address: 0x004E5BC0 (FUN_004E5BC0)
     * Demangled: gpg::RPointerType_CSndParams::GetName
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x004E5D50 (FUN_004E5D50)
     * Demangled: gpg::RPointerType_CSndParams::GetLexical
     */
    [[nodiscard]]
    msvc8::string GetLexical(const RRef& ref) const override;

    /**
     * Address: 0x004E5ED0 (FUN_004E5ED0)
     * Demangled: gpg::RPointerType_CSndParams::IsIndexed
     */
    [[nodiscard]]
    const RIndexed* IsIndexed() const override;

    /**
     * Address: 0x004E5EE0 (FUN_004E5EE0)
     * Demangled: gpg::RPointerType_CSndParams::IsPointer
     */
    [[nodiscard]]
    const RIndexed* IsPointer() const override;

    /**
     * Address: 0x004E5F00 (FUN_004E5F00)
     * Demangled: gpg::RPointerType_CSndParams::SubscriptIndex
     */
    [[nodiscard]]
    RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x004E5EF0 (FUN_004E5EF0)
     * Demangled: gpg::RPointerType_CSndParams::GetCount
     */
    [[nodiscard]]
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x004E5F40 (FUN_004E5F40)
     * Demangled: gpg::RPointerType_CSndParams::AssignPointer
     */
    void AssignPointer(void* obj, const RRef& from) const override;

    /**
     * Address: 0x004E5D20 (FUN_004E5D20)
     * Demangled: gpg::RPointerType_CSndParams::Init
     */
    void Init() override;

  protected:
    [[nodiscard]]
    RType* GetPointeeType() const override;
  };
  static_assert(sizeof(RPointerType<moho::CSndParams>) == 0x68, "RPointerType<CSndParams> size must be 0x68");

  /**
   * Source hints:
   *  - c:\work\rts\main\code\src\libs\gpgcore\reflection\reflection.cpp
   */
  template <>
  class RPointerType<moho::IFormationInstance> final : public RPointerTypeBase
  {
  public:
    /**
     * Address: 0x0059D8D0 (FUN_0059D8D0)
     * Demangled: gpg::RPointerType_IFormationInstance::dtr
     */
    ~RPointerType() override;

    /**
     * Address: 0x0059D4C0 (FUN_0059D4C0)
     * Demangled: gpg::RPointerType_IFormationInstance::GetName
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0059D650 (FUN_0059D650)
     * Demangled: gpg::RPointerType_IFormationInstance::GetLexical
     */
    [[nodiscard]]
    msvc8::string GetLexical(const RRef& ref) const override;

    /**
     * Address: 0x0059D7D0 (FUN_0059D7D0)
     * Demangled: gpg::RPointerType_IFormationInstance::IsIndexed
     */
    [[nodiscard]]
    const RIndexed* IsIndexed() const override;

    /**
     * Address: 0x0059D7E0 (FUN_0059D7E0)
     * Demangled: gpg::RPointerType_IFormationInstance::IsPointer
     */
    [[nodiscard]]
    const RIndexed* IsPointer() const override;

    /**
     * Address: 0x0059D840 (FUN_0059D840)
     * Demangled: gpg::RPointerType_IFormationInstance::AssignPointer
     *
     * What it does:
     * Upcasts a reflected source reference to `IFormationInstance*` and stores
     * it in the destination pointer slot.
     */
    void AssignPointer(void* obj, const RRef& from) const override;

    /**
     * Address: 0x0059D620 (FUN_0059D620)
     * Demangled: gpg::RPointerType_IFormationInstance::Init
     */
    void Init() override;

  protected:
    [[nodiscard]]
    RType* GetPointeeType() const override;
  };
  static_assert(
    sizeof(RPointerType<moho::IFormationInstance>) == 0x68, "RPointerType<IFormationInstance> size must be 0x68"
  );

  /**
   * Source hints:
   *  - c:\work\rts\main\code\src\libs\gpgcore\reflection\reflection.cpp
   */
  template <>
  class RPointerType<moho::RUnitBlueprint> final : public RPointerTypeBase
  {
  public:
    /**
     * Address: 0x005A1900 (FUN_005A1900)
     * Demangled: gpg::RPointerType_RUnitBlueprint::dtr
     */
    ~RPointerType() override;

    /**
     * Address: 0x005A14F0 (FUN_005A14F0)
     * Demangled: gpg::RPointerType_RUnitBlueprint::GetName
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005A1680 (FUN_005A1680)
     * Demangled: gpg::RPointerType_RUnitBlueprint::GetLexical
     */
    [[nodiscard]]
    msvc8::string GetLexical(const RRef& ref) const override;

    /**
     * Address: 0x005A1800 (FUN_005A1800)
     * Demangled: gpg::RPointerType_RUnitBlueprint::IsIndexed
     */
    [[nodiscard]]
    const RIndexed* IsIndexed() const override;

    /**
     * Address: 0x005A1810 (FUN_005A1810)
     * Demangled: gpg::RPointerType_RUnitBlueprint::IsPointer
     */
    [[nodiscard]]
    const RIndexed* IsPointer() const override;

    /**
     * Address: 0x005A1830 (FUN_005A1830)
     * Demangled: gpg::RPointerType_RUnitBlueprint::SubscriptIndex
     *
     * What it does:
     * Builds a reflected reference to the `ind`-th `RUnitBlueprint` in the
     * array the pointer slot addresses (stride `sizeof(RUnitBlueprint)`).
     */
    [[nodiscard]]
    RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x005A1820 (FUN_005A1820)
     * Demangled: gpg::RPointerType_RUnitBlueprint::GetCount
     *
     * What it does:
     * Returns 1 when the pointer slot is non-null, else 0 (a pointer type
     * holds at most one element).
     */
    [[nodiscard]]
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x005A1870 (FUN_005A1870)
     * Demangled: gpg::RPointerType_RUnitBlueprint::AssignPointer
     *
     * What it does:
     * Upcasts a reflected source reference to `RUnitBlueprint*` and stores it
     * in the destination pointer slot.
     */
    void AssignPointer(void* obj, const RRef& from) const override;

    /**
     * Address: 0x005A1650 (FUN_005A1650)
     * Demangled: gpg::RPointerType_RUnitBlueprint::Init
     */
    void Init() override;

  protected:
    [[nodiscard]]
    RType* GetPointeeType() const override;
  };
  static_assert(
    sizeof(RPointerType<moho::RUnitBlueprint>) == 0x68, "RPointerType<RUnitBlueprint> size must be 0x68"
  );

  /**
   * Source hints:
   *  - c:\work\rts\main\code\src\libs\gpgcore\reflection\reflection.cpp
   */
  template <>
  class RPointerType<moho::ReconBlip> final : public RPointerTypeBase
  {
  public:
    /**
     * Address: 0x005C8550 (FUN_005C8550)
     * Demangled: gpg::RPointerType_ReconBlip::dtr
     */
    ~RPointerType() override;

    /**
     * Address: 0x005C8080 (FUN_005C8080)
     * Demangled: gpg::RPointerType_ReconBlip::GetName
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005C8210 (FUN_005C8210)
     * Demangled: gpg::RPointerType_ReconBlip::GetLexical
     */
    [[nodiscard]]
    msvc8::string GetLexical(const RRef& ref) const override;

    /**
     * Address: 0x005C8390 (FUN_005C8390)
     * Demangled: gpg::RPointerType_ReconBlip::IsIndexed
     */
    [[nodiscard]]
    const RIndexed* IsIndexed() const override;

    /**
     * Address: 0x005C83A0 (FUN_005C83A0)
     * Demangled: gpg::RPointerType_ReconBlip::IsPointer
     */
    [[nodiscard]]
    const RIndexed* IsPointer() const override;

    /**
     * Address: 0x005C8400 (FUN_005C8400)
     * Demangled: gpg::RPointerType_ReconBlip::AssignPointer
     *
     * What it does:
     * Upcasts a reflected source reference to `ReconBlip*` and stores it in
     * the destination pointer slot.
     */
    void AssignPointer(void* obj, const RRef& from) const override;

    /**
     * Address: 0x005C81E0 (FUN_005C81E0)
     * Demangled: gpg::RPointerType_ReconBlip::Init
     */
    void Init() override;

  protected:
    [[nodiscard]]
    RType* GetPointeeType() const override;
  };
  static_assert(sizeof(RPointerType<moho::ReconBlip>) == 0x68, "RPointerType<ReconBlip> size must be 0x68");

  /**
   * Source hints:
   *  - c:\work\rts\main\code\src\libs\gpgcore\reflection\reflection.cpp
   */
  template <>
  class RPointerType<moho::CArmyStatItem> final : public RPointerTypeBase
  {
  public:
    /**
     * Address: 0x00711A30 (FUN_00711A30)
     * Demangled: gpg::RPointerType_CArmyStatItem::dtr
     */
    ~RPointerType() override;

    /**
     * Address: 0x007115D0 (FUN_007115D0)
     * Demangled: gpg::RPointerType_CArmyStatItem::GetName
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00711760 (FUN_00711760)
     * Demangled: gpg::RPointerType_CArmyStatItem::GetLexical
     */
    [[nodiscard]]
    msvc8::string GetLexical(const RRef& ref) const override;

    /**
     * Address: 0x007118E0 (FUN_007118E0)
     * Demangled: gpg::RPointerType_CArmyStatItem::IsIndexed
     */
    [[nodiscard]]
    const RIndexed* IsIndexed() const override;

    /**
     * Address: 0x007118F0 (FUN_007118F0)
     * Demangled: gpg::RPointerType_CArmyStatItem::IsPointer
     */
    [[nodiscard]]
    const RIndexed* IsPointer() const override;

    /**
     * Address: 0x00711950 (FUN_00711950)
     * Demangled: gpg::RPointerType_CArmyStatItem::AssignPointer
     *
     * What it does:
     * Upcasts one reflected source reference to `CArmyStatItem*` and stores
     * it in the destination pointer slot.
     */
    void AssignPointer(void* obj, const RRef& from) const override;

    /**
     * Address: 0x00711730 (FUN_00711730)
     * Demangled: gpg::RPointerType_CArmyStatItem::Init
     */
    void Init() override;

  protected:
    [[nodiscard]]
    RType* GetPointeeType() const override;
  };
  static_assert(
    sizeof(RPointerType<moho::CArmyStatItem>) == 0x68, "RPointerType<CArmyStatItem> size must be 0x68"
  );

  template <class T>
  class RVectorType;

  /**
   * Common base for vector-reflection wrappers (`std::vector<T>`).
   *
   * What it does:
   * Owns the shared indexed-container semantics for reflected
   * `std::vector<T>` descriptors so per-element specializations only recover
   * the type-specific virtual surface (name/lexical/element (de)serializers)
   * from FA.
   *
   * Layout note:
   * This is a DISTINCT binary class (own primary + RIndexed vtables and RTTI)
   * whose complete-object layout is byte-identical to `RPointerTypeBase`
   * (bases `RType`/`RObject` (via RType)/`RIndexed`; the RType base owns the two
   * `msvc8::vector<RField>` members `bases_`/`fields_` whose storage lanes at
   * +0x2C and +0x3C are freed by the scalar-deleting dtor; size 0x68). It
   * mirrors that layout intentionally — it is not a duplicate-layout of the
   * pointer base, it is the vector base with its own vtable identity.
   */
  class RVectorTypeBase : public RType, public RIndexed
  {
  public:
    /**
     * Shared indexed-self helper used by specialization thunks (returns the
     * `RIndexed` subobject at +0x64).
     */
    [[nodiscard]]
    const RIndexed* AsIndexedSelf() const noexcept;

  protected:
    [[nodiscard]]
    virtual RType* GetPointeeType() const = 0;
  };
  static_assert(sizeof(RVectorTypeBase) == 0x68, "RVectorTypeBase size must be 0x68");

  /**
   * VFTABLE: 0x00E34778 (primary, 11 slots) / 0x00E347A8 (RIndexed subobject @ +0x64, 4 slots)
   * COL:  gpg::RVectorType<moho::SimArmy*> (reflection of std::vector<moho::SimArmy*>)
   * Source hints:
   *  - c:\work\rts\main\code\src\libs\gpgcore\reflection\reflection.cpp
   *
   * Slot map (from rtti_dump_all.hpp @ 0xE34778 / 0xE347A8):
   *  primary   0 GetClass            0x401370  (RType base, inherited)
   *  primary   1 GetDerivedObjectRef 0x401390  (RType base, inherited)
   *  primary   2 dtor                0x00752420 (override)
   *  primary   3 GetName             0x0074CB70 (override)
   *  primary   4 GetLexical          0x0074CC10 (override)
   *  primary   5 SetLexical          0x8D86E0  (RType base, inherited)
   *  primary   6 IsIndexed           0x0074CCA0 (override)
   *  primary   7 IsPointer           0x4013C0  (RType base, inherited — a vector is NOT a pointer)
   *  primary   8 IsEnumType          0x4013D0  (RType base, inherited)
   *  primary   9 Init                0x0074CBF0 (override)
   *  primary  10 Finish              0x8DF4A0  (RType base, inherited)
   *  secondary 0 SubscriptIndex      0x0074CCE0 (override)
   *  secondary 1 GetCount            0x0074CCB0 (override)
   *  secondary 2 SetCount            0x0074CCD0 (override)
   *  secondary 3 AssignPointer       0x401320  (RIndexed base, inherited)
   */
  template <>
  class RVectorType<moho::SimArmy*> final : public RVectorTypeBase
  {
  public:
    /**
     * Address: 0x00752420 (FUN_00752420)
     * Demangled: gpg::RVectorType_SimArmy_P::dtr (scalar-deleting)
     *
     * What it does:
     * Frees the RType base's two `msvc8::vector<RField>` storage lanes
     * (`bases_._Myfirst` @ +0x2C, `fields_._Myfirst` @ +0x3C), restores the
     * `gpg::RObject` vftable, and conditionally deletes `this`. Defaulted in
     * source: the compiler-generated `~RType()` reproduces this behavior.
     */
    ~RVectorType() override;

    /**
     * Address: 0x0074CB70 (FUN_0074CB70)
     * Demangled: gpg::RVectorType_SimArmy_P::GetName
     *
     * What it does:
     * Builds and caches `"vector<SimArmy*>"` from the element pointer-type name
     * (`moho::SimArmy::GetPointerType()->GetName()`).
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0074CC10 (FUN_0074CC10)
     * Demangled: gpg::RVectorType_SimArmy_P::GetLexical
     *
     * What it does:
     * Renders the reflected vector as `"<base RType lexical>, size=<count>"`.
     */
    [[nodiscard]]
    msvc8::string GetLexical(const RRef& ref) const override;

    /**
     * Address: 0x0074CCA0 (FUN_0074CCA0)
     * Demangled: gpg::RVectorType_SimArmy_P::IsIndexed
     *
     * What it does:
     * Returns the `RIndexed` subobject (`this ? this+0x64 : nullptr`).
     */
    [[nodiscard]]
    const RIndexed* IsIndexed() const override;

    /**
     * Address: 0x0074CCE0 (FUN_0074CCE0)
     * Demangled: gpg::RVectorType_SimArmy_P::SubscriptIndex
     *
     * What it does:
     * Wraps `&vec._Myfirst[ind]` (a `moho::SimArmy**` slot) as one
     * `gpg::RRef_SimArmy_P` reference.
     */
    [[nodiscard]]
    RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x0074CCB0 (FUN_0074CCB0)
     * Demangled: gpg::RVectorType_SimArmy_P::GetCount
     *
     * What it does:
     * Returns the vector element count `(_Mylast - _Myfirst) / sizeof(SimArmy*)`.
     */
    [[nodiscard]]
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x0074CCD0 (FUN_0074CCD0)
     * Demangled: gpg::RVectorType_SimArmy_P::SetCount
     *
     * What it does:
     * Resizes the underlying `std::vector<SimArmy*>` storage to `count`.
     */
    void SetCount(void* obj, int count) const override;

    /**
     * Address: 0x0074CBF0 (FUN_0074CBF0)
     * Demangled: gpg::RVectorType_SimArmy_P::Init
     *
     * What it does:
     * Records the element byte-size (16 = sizeof(std::vector<SimArmy*>)),
     * version 1, and installs the element (de)serialize callbacks
     * (`serLoadFunc_ = &DeserializeSimArmyPtrVector`,
     * `serSaveFunc_ = &SerializeSimArmyPtrVector`).
     */
    void Init() override;

  protected:
    [[nodiscard]]
    RType* GetPointeeType() const override;
  };
  static_assert(sizeof(RVectorType<moho::SimArmy*>) == 0x68, "RVectorType<SimArmy*> size must be 0x68");


  /**
   * Address: 0x005F1A20 (FUN_005F1A20)
   * Address: 0x005F44A0 (FUN_005F44A0)
   * Address: 0x005FBB50 (FUN_005FBB50)
   * Address: 0x005FBC40 (FUN_005FBC40)
   * Address: 0x005FBD00 (FUN_005FBD00)
   * Address: 0x005FBDC0 (FUN_005FBDC0)
   * Address: 0x005FBE80 (FUN_005FBE80)
   * Address: 0x005FBFC0 (FUN_005FBFC0)
   * Address: 0x00602360 (FUN_00602360)
   * Address: 0x00602420 (FUN_00602420)
   * Address: 0x006024E0 (FUN_006024E0)
   * Address: 0x006025A0 (FUN_006025A0)
   * Address: 0x006052D0 (FUN_006052D0)
   * Address: 0x006076E0 (FUN_006076E0)
   * Address: 0x006077A0 (FUN_006077A0)
   * Address: 0x00607860 (FUN_00607860)
   * Address: 0x0060BA90 (FUN_0060BA90)
   * Address: 0x0060BB50 (FUN_0060BB50)
   * Address: 0x0060BC10 (FUN_0060BC10)
   * Address: 0x00610070 (FUN_00610070)
   * Address: 0x00614850 (FUN_00614850)
   * Address: 0x00617760 (FUN_00617760)
   * Address: 0x0061E4B0 (FUN_0061E4B0)
   * Address: 0x006221C0 (FUN_006221C0)
   * Address: 0x00623B30 (FUN_00623B30)
   * Address: 0x00626F40 (FUN_00626F40)
   * Address: 0x00627000 (FUN_00627000)
   * Address: 0x00632D30 (FUN_00632D30)
   * Address: 0x006350F0 (FUN_006350F0)
   * Address: 0x00638690 (FUN_00638690)
   * Address: 0x0064B100 (FUN_0064B100, Moho::CThrustManipulatorTypeInfo lane)
   * Address: 0x0064E270 (FUN_0064E270)
   * Address: 0x0064E2B0 (FUN_0064E2B0)
   * Address: 0x00650B90 (FUN_00650B90)
   * Address: 0x00650BD0 (FUN_00650BD0)
   * Address: 0x00650C10 (FUN_00650C10)
   * Address: 0x00653280 (FUN_00653280)
   * Address: 0x00657B30 (FUN_00657B30)
   * Address: 0x0065F100 (FUN_0065F100)
   * Address: 0x00699E80 (FUN_00699E80)
   * Address: 0x006498E0 (FUN_006498E0, Moho::CStorageManipulatorTypeInfo lane)
   * Address: 0x006DB800 (FUN_006DB800)
   * Address: 0x0076E7C0 (FUN_0076E7C0)
   * Address: 0x00897450 (FUN_00897450)
   *
   * What it does:
   * Writes one RType lifecycle callback lane set (`newRef`, `ctorRef`,
   * `delete`, `destruct`) into the destination type-info object.
   */
  [[nodiscard]] RType* BindRTypeLifecycleCallbacks(
    RType* typeInfo,
    RType::new_ref_func_t newRefFunc,
    RType::ctor_ref_func_t ctorRefFunc,
    RType::delete_func_t deleteFunc,
    RType::dtr_func_t dtrFunc
  ) noexcept;

  /**
   * Byte offset of the `Base` subobject inside `Derived`, for base-class
   * registrations (`RType::AddBase`). The binary registers these as
   * constants (0x34 for a unit task's command-event listener base, ...),
   * which describe the x86 layout; this is the same number on x86 and the
   * right one on x64, where every base after a pointer-bearing one moves.
   */
  template <class Derived, class Base>
  [[nodiscard]] inline int BaseSubobjectOffset() noexcept
  {
    constexpr std::uintptr_t kProbeAddress = 0x1000u;
    auto* const derived = reinterpret_cast<Derived*>(kProbeAddress);
    return static_cast<int>(reinterpret_cast<std::uintptr_t>(static_cast<Base*>(derived)) - kProbeAddress);
  }
  /**
   * Address: 0x004081E0 (FUN_004081E0 -- `ReadPointer<moho::STaskEventLinkage>`; formerly `ReadPointer_STaskEventLinkage`.)
   * Address: 0x0040B640 (FUN_0040B640 -- `ReadPointer<moho::CTask>`; formerly `ReadPointer_CTask`.)
   * Address: 0x0040C4A0 (FUN_0040C4A0 -- `ReadPointer<moho::CTaskThread>`; formerly `ReadPointer_CTaskThread`.)
   * Address: 0x0040D650 (FUN_0040D650 -- `ReadPointer<moho::CTaskStage>`; formerly `ReadPointer_CTaskStage`.)
   * Address: 0x004C1520 (FUN_004C1520 -- `ReadPointer<LuaPlus::LuaState>`; formerly `ReadPointer_LuaState`.)
   * Address: 0x004E63A0 (FUN_004E63A0 -- `ReadPointer<moho::CSndParams>`; formerly `ReadPointer_CSndParams`.)
   * Address: 0x004E64E0 (FUN_004E64E0 -- `ReadPointer<moho::HSound>`; formerly `ReadPointer_HSound`.)
   * Address: 0x005096E0 (FUN_005096E0 -- `ReadPointer<moho::STIMap>`; formerly `ReadPointer_STIMap`.)
   * Address: 0x00511790 (FUN_00511790 -- `ReadPointer<moho::RRuleGameRules>`; formerly `ReadPointer_RRuleGameRules`.)
   * Address: 0x005375C0 (FUN_005375C0 -- `ReadPointer<moho::RRuleGameRules>` (a second copy); formerly `ReadPointer_RRuleGameRules`.)
   * Address: 0x00527480 (FUN_00527480 -- `ReadPointer<moho::RUnitBlueprint>`; formerly `ReadPointer_RUnitBlueprint2`.)
   * Address: 0x00541E00 (FUN_00541E00 -- `ReadPointer<moho::IUnit>`; formerly `ReadPointer_IUnit`.)
   * Address: 0x00554E80 (FUN_00554E80 -- `ReadPointer<moho::REntityBlueprint>`; formerly `ReadPointer_REntityBlueprint`.)
   * Address: 0x0055A7E0 (FUN_0055A7E0 -- `ReadPointer<moho::RMeshBlueprint>`; formerly `ReadPointer_RMeshBlueprint`.)
   * Address: 0x0055A920 (FUN_0055A920 -- `ReadPointer<moho::CSndParams>`; formerly `ReadPointer_CSndParams2`.)
   * Address: 0x0055F640 (FUN_0055F640 -- `ReadPointer<moho::RUnitBlueprint>`; formerly `ReadPointer_RUnitBlueprint`.)
   * Address: 0x00571230 (FUN_00571230 -- `ReadPointer<moho::Listener<moho::EFormationdStatus>>`; formerly `ReadPointer_Listener_EFormationdStatus`.)
   * Address: 0x00584D30 (FUN_00584D30 -- `ReadPointer<moho::SimArmy>`; formerly `ReadPointer_SimArmy`.)
   * Address: 0x00584FB0 (FUN_00584FB0 -- `ReadPointer<moho::Sim>`; formerly `ReadPointer_Sim`.)
   * Address: 0x00599ED0 (FUN_00599ED0 -- `ReadPointer<moho::CUnitCommandQueue>`; formerly `ReadPointer_CUnitCommandQueue`.)
   * Address: 0x0059E810 (FUN_0059E810 -- `ReadPointer<moho::IFormationInstance>`; formerly `ReadPointer_IFormationInstance`.)
   * Address: 0x005A2900 (FUN_005A2900 -- `ReadPointer<moho::Unit>`; formerly `ReadPointer_Unit`.)
   * Address: 0x005A8130 (FUN_005A8130 -- `ReadPointer<moho::Listener<moho::EAiNavigatorEvent>>`; formerly `ReadPointer_Listener_EAiNavigatorEvent`.)
   * Address: 0x005AC9A0 (FUN_005AC9A0 -- `ReadPointer<moho::PathQueue>`; formerly `ReadPointer_PathQueue`.)
   * Address: 0x005ACAE0 (FUN_005ACAE0 -- `ReadPointer<moho::COGrid>`; formerly `ReadPointer_COGrid`.)
   * Address: 0x005CC370 (FUN_005CC370 -- `ReadPointer<moho::ReconBlip>`; formerly `ReadPointer_ReconBlip`.)
   * Address: 0x005CE0E0 (FUN_005CE0E0 -- `ReadPointer<moho::CInfluenceMap>`; formerly `ReadPointer_CInfluenceMap`.)
   * Address: 0x005D13E0 (FUN_005D13E0 -- `ReadPointer<moho::UnitWeapon>`; formerly `ReadPointer_UnitWeapon`.)
   * Address: 0x005D5120 (FUN_005D5120 -- `ReadPointer<moho::CUnitMotion>`; formerly `ReadPointer_CUnitMotion`.)
   * Address: 0x005DF0F0 (FUN_005DF0F0 -- `ReadPointer<moho::Listener<moho::EAiAttackerEvent>>`; formerly `ReadPointer_Listener_EAiAttackerEvent`.)
   * Address: 0x005E10B0 (FUN_005E10B0 -- `ReadPointer<moho::CAcquireTargetTask>`; formerly `ReadPointer_CAcquireTargetTask`.)
   * Address: 0x005E21D0 (FUN_005E21D0 -- `ReadPointer<moho::CAiAttackerImpl>`; formerly `ReadPointer_CAiAttackerImpl`.)
   * Address: 0x005EC540 (FUN_005EC540 -- `ReadPointer<moho::Listener<moho::EAiTransportEvent>>`; formerly `ReadPointer_Listener_EAiTransportEvent`.)
   * Address: 0x005F2170 (FUN_005F2170 -- `ReadPointer<moho::CCommandTask>`; formerly `ReadPointer_CCommandTask`.)
   * Address: 0x005F5100 (FUN_005F5100 -- `ReadPointer<moho::CUnitCommand>`; formerly `ReadPointer_CUnitCommand`.)
   * Address: 0x0060D940 (FUN_0060D940 -- `ReadPointer<moho::EAiResult>`; formerly `ReadPointer_EAiResult`.)
   * Address: 0x00633FB0 (FUN_00633FB0 -- `ReadPointer<moho::RUnitBlueprintWeapon>`; formerly `ReadPointer_RUnitBlueprintWeapon`.)
   * Address: 0x006340F0 (FUN_006340F0 -- `ReadPointer<moho::RProjectileBlueprint>`; formerly `ReadPointer_RProjectileBlueprint`.)
   * Address: 0x0063E530 (FUN_0063E530 -- `ReadPointer<moho::CAniPose>`; formerly `ReadPointer_CAniPose`.)
   * Address: 0x0063EC70 (FUN_0063EC70 -- `ReadPointer<moho::CAniActor>`; formerly `ReadPointer_CAniActor`.)
   * Address: 0x006607B0 (FUN_006607B0 -- `ReadPointer<moho::REmitterBlueprint>`; formerly `ReadPointer_REmitterBlueprint`.)
   * Address: 0x006729C0 (FUN_006729C0 -- `ReadPointer<moho::RTrailBlueprint>`; formerly `ReadPointer_RTrailBlueprint`.)
   * Address: 0x006756E0 (FUN_006756E0 -- `ReadPointer<moho::ManyToOneListener<moho::ECollisionBeamEvent>>`; formerly `ReadPointer_ManyToOneListener_ECollisionBeamEvent`.)
   * Address: 0x006761B0 (FUN_006761B0 -- `ReadPointer<moho::IEffect>`; formerly `ReadPointer_IEffect`.)
   * Address: 0x00680FB0 (FUN_00680FB0 -- `ReadPointer<moho::Entity>`; formerly `ReadPointer_Entity`.)
   * Address: 0x006895A0 (FUN_006895A0 -- `ReadPointer<moho::EntitySetBase>`; formerly `ReadPointer_EntitySetBase`.)
   * Address: 0x00698900 (FUN_00698900 -- `ReadPointer<moho::SPhysConstants>`; formerly `ReadPointer_SPhysConstants`.)
   * Address: 0x0069F920 (FUN_0069F920 -- `ReadPointer<moho::ManyToOneListener<moho::EProjectileImpactEvent>>`; formerly `ReadPointer_ManyToOneListener_EProjectileImpactEvent`.)
   * Address: 0x006BC1E0 (FUN_006BC1E0 -- `ReadPointer<moho::CPathPoint>`; formerly `ReadPointer_CPathPoint`.)
   * Address: 0x006E0500 (FUN_006E0500 -- `ReadPointer<moho::IAiAttacker>`; formerly `ReadPointer_IAiAttacker`.)
   * Address: 0x006EB870 (FUN_006EB870 -- `ReadPointer<moho::Listener<moho::ECommandEvent>>`; formerly `ReadPointer_Listener_ECommandEvent`.)
   * Address: 0x006F8F60 (FUN_006F8F60 -- `ReadPointer<moho::Listener<moho::EUnitCommandQueueStatus>>`; formerly `ReadPointer_Listener_EUnitCommandQueueStatus`.)
   * Address: 0x00713F30 (FUN_00713F30 -- `ReadPointer<moho::CAiBrain>`; formerly `ReadPointer_CAiBrain`.)
   * Address: 0x007141B0 (FUN_007141B0 -- `ReadPointer<moho::CArmyStatItem>`; formerly `ReadPointer_CArmyStatItem`.)
   * Address: 0x007545A0 (FUN_007545A0 -- `ReadPointer<moho::Shield>`; formerly `ReadPointer_Shield`.)
   * Address: 0x0076A8E0 (FUN_0076A8E0 -- `ReadPointer<moho::IPathTraveler>`; formerly `ReadPointer_IPathTraveler`.)
   * Address: 0x0076B1C0 (FUN_0076B1C0 -- `ReadPointer<moho::PathTables>`; formerly `ReadPointer_PathTables`.)
   * Address: 0x007703A0 (FUN_007703A0 -- `ReadPointer<moho::IAiReconDB>`; formerly `ReadPointer_IAiReconDB`.)
   * Address: 0x00771550 (FUN_00771550 -- `ReadPointer<moho::IEffectManager>`; formerly `ReadPointer_IEffectManager`.)
   * Address: 0x007745F0 (FUN_007745F0 -- `ReadPointer<moho::CEconRequest>`; formerly `ReadPointer_CEconRequest`.)
   * Address: 0x00774BF0 (FUN_00774BF0 -- `ReadPointer<moho::CEconomy>`; formerly `ReadPointer_CEconomy`.)
   * Address: 0x0090BA60 (FUN_0090BA60 -- `ReadPointer<lua_State>`; formerly `ReadPointer_lua_State`.)
   * Address: 0x00921830 (FUN_00921830 -- `ReadPointer<TString>`; formerly `ReadPointer_TString`.)
   * Address: 0x00921950 (FUN_00921950 -- `ReadPointer<Table>`; formerly `ReadPointer_Table`.)
   * Address: 0x00921A70 (FUN_00921A70 -- `ReadPointer<LClosure>`; formerly `ReadPointer_LClosure`.)
   * Address: 0x00921B90 (FUN_00921B90 -- `ReadPointer<Udata>`; formerly `ReadPointer_Udata`.)
   * Address: 0x00921CB0 (FUN_00921CB0 -- `ReadPointer<Proto>`; formerly `ReadPointer_Proto`.)
   * Address: 0x00921DD0 (FUN_00921DD0 -- `ReadPointer<UpVal>`; formerly `ReadPointer_UpVal`.)
   * Address: 0x006988A0 (FUN_006988A0 -- `ReadPointer<moho::SPhysConstants>` into a slot; no references in the PE; formerly `ReadRawPointerFromSPhysConstantsSlotLaneLegacyB` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00698840 (FUN_00698840 -- `ReadPointer<moho::SPhysConstants>` into a slot; no references in the PE; formerly `ReadRawPointerFromSPhysConstantsSlotLaneLegacyA` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00689150 (FUN_00689150 -- `ReadPointer<moho::EntitySetBase>` into a slot; no references in the PE; formerly `ReadRawPointerFromEntitySetBaseSlotLaneLegacyB` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00688BD0 (FUN_00688BD0 -- `ReadPointer<moho::EntitySetBase>` into a slot; no references in the PE; formerly `ReadRawPointerFromEntitySetBaseSlotLaneLegacyA` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x006E0200 (FUN_006E0200 -- `ReadPointer<moho::IAiAttacker>` into a slot; no references in the PE; formerly `ReadRawPointerFromIAiAttackerSlotLaneLegacyA` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   *
   * What it does:
   * Reads one tracked pointer (`ReadRawPointer` 0x00953720) and stores its
   * object as a `T*`: a null pointer reads as null, and an object that is not
   * a `T` throws `SerializationError`. Ownership is left as it is.
   */
  template <class T>
  ReadArchive* ReadArchive::ReadPointer(T** const outValue, const RRef* const ownerRef)
  {
    const TrackedPointerInfo& tracked = ReadRawPointer(this, *ownerRef);
    const RRef source{tracked.object, tracked.type};
    if (source.mObj == nullptr) {
      *outValue = nullptr;
      return this;
    }

    *outValue = source.Upcast<T>();
    if (*outValue == nullptr) {
      throw SerializationError(STR_Printf(
        "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
        "instead",
        RTypeOf<T>()->GetName(),
        source.GetTypeName()
      ).c_str());
    }
    return this;
  }

  /**
   * Address: 0x00407A50 (FUN_00407A50 -- `ReadPointerOwned<moho::STaskEventLinkage>`; formerly `ReadPointerOwned_STaskEventLinkage`.)
   * Address: 0x0040B530 (FUN_0040B530 -- `ReadPointerOwned<moho::CTask>`; formerly `ReadPointerOwned_CTask`.)
   * Address: 0x0040B800 (FUN_0040B800 -- `ReadPointerOwned<moho::CTaskThread>`; formerly `ReadPointerOwned_CTaskThread`.)
   * Address: 0x0041A3D0 (FUN_0041A3D0 -- `ReadPointerOwned<moho::StatItem>`; formerly `ReadPointerOwned_StatItem`.)
   * Address: 0x004CC550 (FUN_004CC550 -- `ReadPointerOwned<LuaPlus::LuaState>`; formerly `ReadPointerOwned_LuaState`.)
   * Address: 0x00584E70 (FUN_00584E70 -- `ReadPointerOwned<moho::CAiPersonality>`; formerly `ReadPointerOwned_CAiPersonality`.)
   * Address: 0x005850F0 (FUN_005850F0 -- `ReadPointerOwned<moho::CTaskStage>`; formerly `ReadPointerOwned_CTaskStage`.)
   * Address: 0x005A98A0 (FUN_005A98A0 -- `ReadPointerOwned<moho::CAiPathNavigator>`; formerly `ReadPointerOwned_CAiPathNavigator`.)
   * Address: 0x005B1A50 (FUN_005B1A50 -- `ReadPointerOwned<moho::CAiPathFinder>`; formerly `ReadPointerOwned_CAiPathFinder`.)
   * Address: 0x005D1AD0 (FUN_005D1AD0 -- `ReadPointerOwned<moho::CEconRequest>`; formerly `ReadPointerOwned_CEconRequest`.)
   * Address: 0x005D4FE0 (FUN_005D4FE0 -- `ReadPointerOwned<moho::CAiPathSpline>`; formerly `ReadPointerOwned_CAiPathSpline`.)
   * Address: 0x005DEC30 (FUN_005DEC30 -- `ReadPointerOwned<moho::UnitWeapon>`; formerly `ReadPointerOwned_UnitWeapon`.)
   * Address: 0x005DED40 (FUN_005DED40 -- `ReadPointerOwned<moho::CAcquireTargetTask>`; formerly `ReadPointerOwned_CAcquireTargetTask`.)
   * Address: 0x0063CB90 (FUN_0063CB90 -- `ReadPointerOwned<moho::IAniManipulator>`; formerly `ReadPointerOwned_IAniManipulator`.)
   * Address: 0x0066C350 (FUN_0066C350 -- `ReadPointerOwned<moho::IEffect>`; formerly `ReadPointerOwned_IEffect`.)
   * Address: 0x006829F0 (FUN_006829F0 -- `ReadPointerOwned<moho::PositionHistory>`; formerly `ReadPointerOwned_PositionHistory`.)
   * Address: 0x00682B30 (FUN_00682B30 -- `ReadPointerOwned<moho::CColPrimitiveBase>`; formerly `ReadPointerOwned_CColPrimitiveBase`.)
   * Address: 0x00682C70 (FUN_00682C70 -- `ReadPointerOwned<moho::CIntel>`; formerly `ReadPointerOwned_CIntel`.)
   * Address: 0x00682DB0 (FUN_00682DB0 -- `ReadPointerOwned<moho::CTextureScroller>`; formerly `ReadPointerOwned_CTextureScroller`.)
   * Address: 0x00682EF0 (FUN_00682EF0 -- `ReadPointerOwned<moho::SPhysBody>`; formerly `ReadPointerOwned_SPhysBody`.)
   * Address: 0x00683030 (FUN_00683030 -- `ReadPointerOwned<moho::Motor>`; formerly `ReadPointerOwned_Motor`.)
   * Address: 0x00688AC0 (FUN_00688AC0 -- `ReadPointerOwned<moho::Entity>`; formerly `ReadPointerOwned_Entity`.)
   * Address: 0x006B10F0 (FUN_006B10F0 -- `ReadPointerOwned<moho::CEconomyEvent>`; formerly `ReadPointerOwned_CEconomyEvent`.)
   * Address: 0x006B4A70 (FUN_006B4A70 -- `ReadPointerOwned<moho::IAiSteering>`; formerly `ReadPointerOwned_IAiSteering`.)
   * Address: 0x006B4BB0 (FUN_006B4BB0 -- `ReadPointerOwned<moho::CUnitMotion>`; formerly `ReadPointerOwned_CUnitMotion`.)
   * Address: 0x006B4CF0 (FUN_006B4CF0 -- `ReadPointerOwned<moho::CUnitCommandQueue>`; formerly `ReadPointerOwned_CUnitCommandQueue`.)
   * Address: 0x006B4E30 (FUN_006B4E30 -- `ReadPointerOwned<moho::IFormationInstance>`; formerly `ReadPointerOwned_IFormationInstance`.)
   * Address: 0x006B4F70 (FUN_006B4F70 -- `ReadPointerOwned<moho::CEconStorage>`; formerly `ReadPointerOwned_CEconStorage`.)
   * Address: 0x006B50B0 (FUN_006B50B0 -- `ReadPointerOwned<moho::CAniActor>`; formerly `ReadPointerOwned_CAniActor`.)
   * Address: 0x006B51F0 (FUN_006B51F0 -- `ReadPointerOwned<moho::IAiAttacker>`; formerly `ReadPointerOwned_IAiAttacker`.)
   * Address: 0x006B5330 (FUN_006B5330 -- `ReadPointerOwned<moho::IAiCommandDispatch>`; formerly `ReadPointerOwned_IAiCommandDispatch`.)
   * Address: 0x006B5470 (FUN_006B5470 -- `ReadPointerOwned<moho::IAiNavigator>`; formerly `ReadPointerOwned_IAiNavigator`.)
   * Address: 0x006B55B0 (FUN_006B55B0 -- `ReadPointerOwned<moho::IAiBuilder>`; formerly `ReadPointerOwned_IAiBuilder`.)
   * Address: 0x006B56F0 (FUN_006B56F0 -- `ReadPointerOwned<moho::IAiSiloBuild>`; formerly `ReadPointerOwned_IAiSiloBuild`.)
   * Address: 0x006B5830 (FUN_006B5830 -- `ReadPointerOwned<moho::IAiTransport>`; formerly `ReadPointerOwned_IAiTransport`.)
   * Address: 0x006E0640 (FUN_006E0640 -- `ReadPointerOwned<moho::CFireWeaponTask>`; formerly `ReadPointerOwned_CFireWeaponTask`.)
   * Address: 0x006E2B60 (FUN_006E2B60 -- `ReadPointerOwned<moho::CUnitCommand>`; formerly `ReadPointerOwned_CUnitCommand`.)
   * Address: 0x007040E0 (FUN_007040E0 -- `ReadPointerOwned<moho::CPlatoon>`; formerly `ReadPointerOwned_CPlatoon`.)
   * Address: 0x00706E20 (FUN_00706E20 -- `ReadPointerOwned<moho::CAiBrain>`; formerly `ReadPointerOwned_CAiBrain`.)
   * Address: 0x00706F60 (FUN_00706F60 -- `ReadPointerOwned<moho::IAiReconDB>`; formerly `ReadPointerOwned_IAiReconDB`.)
   * Address: 0x007070A0 (FUN_007070A0 -- `ReadPointerOwned<moho::CEconomy>`; formerly `ReadPointerOwned_CEconomy`.)
   * Address: 0x007071E0 (FUN_007071E0 -- `ReadPointerOwned<moho::CArmyStats>`; formerly `ReadPointerOwned_CArmyStats`.)
   * Address: 0x00707320 (FUN_00707320 -- `ReadPointerOwned<moho::CInfluenceMap>`; formerly `ReadPointerOwned_CInfluenceMap`.)
   * Address: 0x00707460 (FUN_00707460 -- `ReadPointerOwned<moho::PathQueue>`; formerly `ReadPointerOwned_PathQueue`.)
   * Address: 0x00714070 (FUN_00714070 -- `ReadPointerOwned<moho::CArmyStatItem>`; formerly `ReadPointerOwned_CArmyStatItem`.)
   * Address: 0x0072ACD0 (FUN_0072ACD0 -- `ReadPointerOwned<moho::CSquad>`; formerly `ReadPointerOwned_CSquad`.)
   * Address: 0x00750FD0 (FUN_00750FD0 -- `ReadPointerOwned<moho::SimArmy>`; formerly `ReadPointerOwned_SimArmy`.)
   * Address: 0x00757540 (FUN_00757540 -- `ReadPointerOwned<moho::CRandomStream>`; formerly `ReadPointerOwned_CRandomStream`.)
   * Address: 0x00757680 (FUN_00757680 -- `ReadPointerOwned<moho::SPhysConstants>`; formerly `ReadPointerOwned_SPhysConstants`.)
   * Address: 0x007577C0 (FUN_007577C0 -- `ReadPointerOwned<moho::IAiFormationDB>`; formerly `ReadPointerOwned_IAiFormationDB`.)
   * Address: 0x00757B10 (FUN_00757B10 -- `ReadPointerOwned<moho::CCommandDB>`; formerly `ReadPointerOwned_CCommandDB`.)
   * Address: 0x00757C50 (FUN_00757C50 -- `ReadPointerOwned<moho::CDecalBuffer>`; formerly `ReadPointerOwned_CDecalBuffer`.)
   * Address: 0x00757D90 (FUN_00757D90 -- `ReadPointerOwned<moho::IEffectManager>`; formerly `ReadPointerOwned_IEffectManager`.)
   * Address: 0x00757ED0 (FUN_00757ED0 -- `ReadPointerOwned<moho::ISoundManager>`; formerly `ReadPointerOwned_ISoundManager`.)
   * Address: 0x00758010 (FUN_00758010 -- `ReadPointerOwned<moho::EntityDB>`; formerly `ReadPointerOwned_EntityDB`.)
   * Address: 0x0076B570 (FUN_0076B570 -- `ReadPointerOwned<moho::PathQueue::Impl>`; formerly `ReadPointerOwned_PathQueue_Impl`.)
   * Address: 0x0076EC30 (FUN_0076EC30 -- `ReadPointerOwned<moho::CIntelPosHandle>`; formerly `ReadPointerOwned_CIntelPosHandle`.)
   * Address: 0x0077D7A0 (FUN_0077D7A0 -- `ReadPointerOwned<moho::CDecalHandle>`; formerly `ReadPointerOwned_CDecalHandle`.)
   * Address: 0x006B3E10 (FUN_006B3E10 -- `ReadPointerOwned<moho::IFormationInstance>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromIFormationInstanceSlotLaneLegacyA` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x006B3EE0 (FUN_006B3EE0 -- `ReadPointerOwned<moho::IAiCommandDispatch>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromIAiCommandDispatchSlotLaneLegacyA` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00681ED0 (FUN_00681ED0 -- `ReadPointerOwned<moho::CColPrimitiveBase>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromCColPrimitiveBaseSlotLaneLegacyA` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x005D15A0 (FUN_005D15A0 -- `ReadPointerOwned<moho::CEconRequest>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromCEconRequestNodeSlotLaneLegacyA` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00681FC0 (FUN_00681FC0 -- `ReadPointerOwned<moho::CTextureScroller>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromCTextureScrollerSlotLaneLegacyA` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x006E02A0 (FUN_006E02A0 -- `ReadPointerOwned<?>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromCFireWeaponTaskSlotLaneLegacyB` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x006DFDB0 (FUN_006DFDB0 -- `ReadPointerOwned<moho::CFireWeaponTask>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromCFireWeaponTaskSlotLaneLegacyA` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00681EA0 (FUN_00681EA0 -- `ReadPointerOwned<moho::PositionHistory>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromPositionHistorySlotLaneLegacyA` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00584630 (FUN_00584630 -- `ReadPointerOwned<moho::CAiPersonality>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromCAiPersonalitySlotLaneLegacyA` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x005D4DD0 (FUN_005D4DD0 -- `ReadPointerOwned<moho::CAiPathSpline>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromCAiPathSplineSlotLaneLegacyA` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x005D4EF0 (FUN_005D4EF0 -- `ReadPointerOwned<moho::CAiPathSpline>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `LoadOwnedRawPointerFromCAiPathSplineSlotLaneLegacyA` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x007128A0 (FUN_007128A0 -- `ReadPointerOwned<moho::CArmyStatItem>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromCArmyStatItemSlotLaneLegacyA` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x006B3FA0 (FUN_006B3FA0 -- `ReadPointerOwned<moho::IAiTransport>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromIAiTransportSlotLaneLegacyA` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x006B3F70 (FUN_006B3F70 -- `ReadPointerOwned<moho::IAiSiloBuild>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromIAiSiloBuildSlotLaneLegacyA` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x006B3F10 (FUN_006B3F10 -- `ReadPointerOwned<moho::IAiNavigator>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromIAiNavigatorSlotLaneLegacyA` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x006B3EB0 (FUN_006B3EB0 -- `ReadPointerOwned<moho::IAiAttacker>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromIAiAttackerSlotLaneLegacyA` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x006B3D80 (FUN_006B3D80 -- `ReadPointerOwned<moho::IAiSteering>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromIAiSteeringSlotLaneLegacyA` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x006B3F40 (FUN_006B3F40 -- `ReadPointerOwned<moho::IAiBuilder>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromIAiBuilderSlotLaneLegacyA` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x007064E0 (FUN_007064E0 -- `ReadPointerOwned<moho::IAiReconDB>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromIAiReconDBSlotLaneLegacyA` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x0076EB60 (FUN_0076EB60 -- `ReadPointerOwned<moho::CIntelPosHandle>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromCIntelPosHandleSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00681FF0 (FUN_00681FF0 -- `ReadPointerOwned<moho::SPhysBody>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromSPhysBodySlotLaneLegacyA` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00756280 (FUN_00756280 -- `ReadPointerOwned<moho::SPhysConstants>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromSPhysConstantsSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00756390 (FUN_00756390 -- `ReadPointerOwned<moho::IEffectManager>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromIEffectManagerSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x007562F0 (FUN_007562F0 -- `ReadPointerOwned<moho::IAiFormationDB>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromIAiFormationDBSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x007064B0 (FUN_007064B0 -- `ReadPointerOwned<moho::CAiBrain>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromCAiBrainSlotLaneLegacyA` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00756250 (FUN_00756250 -- `ReadPointerOwned<moho::CRandomStream>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromCRandomStreamSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x007563C0 (FUN_007563C0 -- `ReadPointerOwned<moho::ISoundManager>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromISoundManagerSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00706BC0 (FUN_00706BC0 -- `ReadPointerOwned<moho::CInfluenceMap>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `LoadOwnedRawPointerFromCInfluenceMapSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00706570 (FUN_00706570 -- `ReadPointerOwned<moho::CInfluenceMap>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromCInfluenceMapSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00756360 (FUN_00756360 -- `ReadPointerOwned<moho::CDecalBuffer>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromCDecalBufferSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x006B4590 (FUN_006B4590 -- `ReadPointerOwned<moho::CEconStorage>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `LoadOwnedRawPointerFromCEconStorageSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00756FF0 (FUN_00756FF0 -- `ReadPointerOwned<moho::CDecalBuffer>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `LoadOwnedRawPointerFromCDecalBufferSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00682020 (FUN_00682020 -- `ReadPointerOwned<moho::Motor>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromMotorSlotLaneLegacyA` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00706540 (FUN_00706540 -- `ReadPointerOwned<moho::CArmyStats>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromCArmyStatsSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00706B60 (FUN_00706B60 -- `ReadPointerOwned<moho::CArmyStats>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `LoadOwnedRawPointerFromCArmyStatsSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00756330 (FUN_00756330 -- `ReadPointerOwned<moho::CCommandDB>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromCCommandDbSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00756F90 (FUN_00756F90 -- `ReadPointerOwned<moho::CCommandDB>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `LoadOwnedRawPointerFromCCommandDbSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00756430 (FUN_00756430 -- `ReadPointerOwned<moho::EntityDB>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromCEntityDbSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x006B4600 (FUN_006B4600 -- `ReadPointerOwned<moho::CAniActor>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `LoadOwnedRawPointerFromCAniActorSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00757160 (FUN_00757160 -- `ReadPointerOwned<moho::EntityDB>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `LoadOwnedRawPointerFromCEntityDbSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00706C20 (FUN_00706C20 -- `ReadPointerOwned<moho::PathQueue>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `LoadOwnedRawPointerFromPathQueueSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00706510 (FUN_00706510 -- `ReadPointerOwned<moho::CEconomy>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `ReadOwnedRawPointerFromCEconomySlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00706B00 (FUN_00706B00 -- `ReadPointerOwned<moho::CEconomy>` into an owning slot, deleting the object it replaces; no references in the PE; formerly `LoadOwnedRawPointerFromCEconomySlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   *
   * What it does:
   * `ReadPointer`, for a pointer whose object the reader takes ownership of:
   * the pointer must still be unowned (`"Ownership conflict while loading
   * archive"` otherwise), and it is marked owned once the upcast succeeds.
   */
  template <class T>
  ReadArchive* ReadArchive::ReadPointerOwned(T** const outValue, const RRef* const ownerRef)
  {
    TrackedPointerInfo& tracked = ReadRawPointer(this, *ownerRef);
    if (tracked.object == nullptr) {
      *outValue = nullptr;
      return this;
    }

    if (tracked.state != TrackedPointerState::Unowned) {
      throw SerializationError("Ownership conflict while loading archive");
    }

    const RRef source{tracked.object, tracked.type};
    *outValue = source.Upcast<T>();
    if (*outValue == nullptr) {
      throw SerializationError(STR_Printf(
        "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
        "instead",
        RTypeOf<T>()->GetName(),
        source.GetTypeName()
      ).c_str());
    }

    tracked.state = TrackedPointerState::Owned;
    return this;
  }

  /**
   * Address: 0x00884C90 (FUN_00884C90 -- `ReadPointerShared<moho::LaunchInfoBase>`, for `SSavedGameHeader::mLaunchInfo` (0x008831C0); formerly `ReadPointerShared_LaunchInfoBase`.)
   * Address: 0x008843F0 (FUN_008843F0 -- `ReadPointerShared<moho::SSessionSaveData>`, for `LaunchInfoBase::mLoadSessionData` (`CSavedGame::CreateSinglePlayerSessionInfo` 0x008807F0); formerly `ReadPointerShared_SSessionSaveData`.)
   * Address: 0x0055F990 (FUN_0055F990 -- `ReadPointerShared<moho::CAniPose>`, for `CAniActor` 0x0063E200, `SPerArmyReconInfo` 0x005C8DE0, `Unit` 0x0055E030; formerly `ReadPointerShared_CAniPose`.)
   * Address: 0x0054FF20 (FUN_0054FF20 -- `ReadPointerShared<moho::CAniSkel>`, for `CAniPose::mSkeleton` (0x0054F380); formerly `ReadPointerShared_CAniSkel`.)
   * Address: 0x0055F780 (FUN_0055F780 -- `ReadPointerShared<moho::Stats<moho::StatItem>>`, for `SSTIUnitConstantData::mStatsRoot` (0x0055DF40); formerly `ReadPointerShared_Stats_StatItem`.)
   * Address: 0x00757900 (FUN_00757900 -- `ReadPointerShared<moho::ISimResources>`, for `Sim` 0x00754C60; formerly `ReadPointerShared_ISimResources`.)
   * Address: 0x00551CC0 (FUN_00551CC0 -- `ReadPointerShared<moho::CIntelGrid>`, for `SSTIArmyConstantData`'s eight grids (0x00550FC0); formerly `ReadPointerShared_CIntelGrid`.)
   * Address: 0x005CE220 (FUN_005CE220 -- `ReadPointerShared<moho::CIntelGrid>` again, a second emission for `CAiReconDBImpl`'s eight grids (0x005CCBE0), `CIntelPosHandle::mGrid` (0x00770000); formerly `ReadPointerShared_CIntelGrid2`.)
   * Address: 0x00642F60 (FUN_00642F60 -- `ReadPointerShared<moho::RScaResource>`, for `CAnimationManipulator::mAnimationRef` (0x00642A50); formerly `ReadPointerShared_RScaResource`.)
   * Address: 0x0055A5D0 (FUN_0055A5D0 -- `ReadPointerShared<moho::RScmResource>`, for `SSTIEntityVariableData::mScmResource` 0x00559B00, `SPerArmyReconInfo::mMesh` 0x005C8DE0; formerly `ReadPointerShared_RScmResource`.)
   * Address: 0x007142F0 (FUN_007142F0 -- `ReadPointerShared<moho::STrigger>`, for `list<shared_ptr<STrigger>>` 0x00710620 and the `shared_ptr<STrigger>` type's load; formerly `ReadPointerShared_STrigger`.)
   *
   * The `boost::shared_ptr<T>` members those bodies call out of line (all
   * formerly per-type helpers in gpg/core/containers/ArchiveSerialization.cpp):
   *
   * Address: 0x0054B200 (FUN_0054B200 -- `shared_ptr<moho::CAniSkel>::operator=`; callers 0x0054FF20.)
   * Address: 0x00551ED0 (FUN_00551ED0 -- `shared_ptr<moho::CIntelGrid>::operator=`; callers 0x00551CC0.)
   * Address: 0x005CE430 (FUN_005CE430 -- `shared_ptr<moho::CIntelGrid>::operator=`; callers 0x005CE220.)
   * Address: 0x00714530 (FUN_00714530 -- `shared_ptr<moho::STrigger>::operator=`; callers 0x007142F0.)
   * Address: 0x00758150 (FUN_00758150 -- `shared_ptr<moho::ISimResources>::operator=`; callers 0x00757900.)
   * Address: 0x0087FCB0 (FUN_0087FCB0 -- `shared_ptr<moho::LaunchInfoBase>::operator=`; callers 0x00884C90.)
   * Address: 0x00884670 (FUN_00884670 -- `shared_ptr<moho::SSessionSaveData>::operator=`; callers 0x008843F0.)
   * Address: 0x0055FBA0 (FUN_0055FBA0 -- `shared_ptr<moho::Stats<moho::StatItem>>::operator=`; callers 0x0055F780.)
   * Address: 0x00550130 (FUN_00550130 -- `shared_ptr<moho::CAniSkel>::reset()`; callers 0x0054FF20.)
   * Address: 0x00551F00 (FUN_00551F00 -- `shared_ptr<moho::CIntelGrid>::reset()`; callers 0x00551CC0.)
   * Address: 0x00550670 (FUN_00550670 -- `shared_ptr<moho::CIntelGrid>::reset()`, the null arm of 0x00551CC0/0x005CE220.)
   * Address: 0x00714560 (FUN_00714560 -- `shared_ptr<moho::STrigger>::reset()`; callers 0x007142F0.)
   * Address: 0x0073F5B0 (FUN_0073F5B0 -- `shared_ptr<moho::LaunchInfoBase>::reset()`; callers 0x00884C90.)
   * Address: 0x00758180 (FUN_00758180 -- `shared_ptr<moho::ISimResources>::reset()`; callers 0x00757900.)
   * Address: 0x008846E0 (FUN_008846E0 -- `shared_ptr<moho::SSessionSaveData>::reset()`; callers 0x008843F0.)
   * Address: 0x0055FC00 (FUN_0055FC00 -- `shared_ptr<moho::Stats<moho::StatItem>>::reset()`; callers 0x0055F780.)
   * Address: 0x005503F0 (FUN_005503F0 -- `static_pointer_cast<moho::CAniSkel>` of the entry's `shared_ptr<void>` (copy both words, `add_ref_copy`); callers 0x0054FF20.)
   * Address: 0x00551FE0 (FUN_00551FE0 -- the same for `moho::CIntelGrid`; callers 0x00551CC0.)
   * Address: 0x0055FDD0 (FUN_0055FDD0 -- the same for `moho::CAniPose`; callers 0x0055F990.)
   * Address: 0x005CE720 (FUN_005CE720 -- the same for `moho::CIntelGrid`; callers 0x005CE220.)
   * Address: 0x00714A50 (FUN_00714A50 -- the same for `moho::STrigger`; callers 0x007142F0.)
   * Address: 0x007584E0 (FUN_007584E0 -- the same for `moho::ISimResources`; callers 0x00757900.)
   * Address: 0x008849F0 (FUN_008849F0 -- the same for `moho::SSessionSaveData`; callers 0x008843F0.)
   * Address: 0x00885150 (FUN_00885150 -- the same for `moho::LaunchInfoBase`; callers 0x00884C90.)
   * Address: 0x0055FDB0 (FUN_0055FDB0 -- the same for `moho::Stats<moho::StatItem>`; callers 0x0055F780.)
   * Address: 0x0055B760 (FUN_0055B760 -- `~shared_ptr<moho::Stats<moho::StatItem>>`, the cast temporary's release.)
   *
   * What it does:
   * Reads one tracked pointer into `*outValue`, shared through the archive's
   * table entry (the body is `serialization.h`'s, whose assert it carries at
   * line 392):
   *   - a null pointer resets `*outValue`;
   *   - an unowned object becomes the entry's `shared_ptr<void>`, deleting it
   *     through its reflected type, and the entry turns `Shared`;
   *   - an owned one is an ownership conflict;
   *   - a shared one must have come from a `boost::shared_ptr` read.
   * An object that is not a `T` throws `SerializationError`; otherwise
   * `*outValue` takes the entry's control block, the pointer uncast.
   */
  template <class T>
  ReadArchive* ReadArchive::ReadPointerShared(boost::shared_ptr<T>* const outValue, const RRef* const ownerRef)
  {
    using Object = std::remove_cv_t<T>;

    TrackedPointerInfo& tracked = ReadRawPointer(this, *ownerRef);
    if (tracked.object == nullptr) {
      outValue->reset();
      return this;
    }

    if (tracked.state == TrackedPointerState::Unowned) {
      if (tracked.type->deleteFunc_ == nullptr) {
        HandleAssertFailure("ptrinfo.mObj.GetRType()->mDelete", 392, detail::kSerializationHeaderPath);
      }
      tracked.sharedPtr = boost::shared_ptr<void>(tracked.object, tracked.type->deleteFunc_);
      tracked.state = TrackedPointerState::Shared;
    } else if (tracked.state != TrackedPointerState::Shared) {
      throw SerializationError("Ownership conflict while loading archive");
    } else if (!tracked.sharedPtr) {
      throw SerializationError("Can't mix boost::shared_ptr with other shared pointers.");
    }

    const RRef source{tracked.object, tracked.type};
    if (source.Upcast<Object>() == nullptr) {
      throw SerializationError(STR_Printf(
        "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
        "instead",
        RTypeOf<Object>()->GetName(),
        source.GetTypeName()
      ).c_str());
    }

    *outValue = boost::static_pointer_cast<T>(tracked.sharedPtr);
    return this;
  }

  /**
   * What it does:
   * `ReadPointerShared` into a `boost::SharedPtrRaw<T>` member: the same read
   * into a `boost::shared_ptr<T>`, whose control block the member then takes.
   */
  template <class T>
  ReadArchive* ReadArchive::ReadPointerShared(boost::SharedPtrRaw<T>* const outValue, const RRef* const ownerRef)
  {
    boost::shared_ptr<T> value;
    ReadPointerShared(&value, ownerRef);
    outValue->reset_from_owner(value);
    return this;
  }
  /**
   * Per-type emissions with no references in the PE (write state and source
   * -- a value, a slot or an owner field -- folded in per copy):
   *
   * Address: 0x004E5B00 (FUN_004E5B00 -- `SaveRawPointer` of a `moho::CSndParams` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromCSndParamsSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x004E5B40 (FUN_004E5B40 -- `SaveRawPointer` of a `moho::HSound` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromHSoundSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00511220 (FUN_00511220 -- `SaveRawPointer` of a `moho::RRuleGameRules` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromRRuleGameRulesSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00526650 (FUN_00526650 -- `SaveRawPointer` of a `moho::RUnitBlueprint` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromRUnitBlueprintSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00541BC0 (FUN_00541BC0 -- `SaveRawPointer` of a `moho::IUnit` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromIUnitSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0055A3C0 (FUN_0055A3C0 -- `SaveRawPointer` of a `moho::RScmResource` slot as `Shared`; zero callers, unreachable; formerly `SaveSharedRawPointerFromRScmResourceSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0055A4A0 (FUN_0055A4A0 -- `SaveRawPointer` of a `moho::CSndParams` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromCSndParamsSlotLane2` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0055F4F0 (FUN_0055F4F0 -- `SaveRawPointer` of a `moho::CAniPose` slot as `Shared`; zero callers, unreachable; formerly `SaveSharedRawPointerFromCAniPoseSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005849F0 (FUN_005849F0 -- `SaveRawPointer` of a `moho::SimArmy` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromSimArmySlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00584A50 (FUN_00584A50 -- `SaveRawPointer` of a `moho::CAiPersonality` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromCAiPersonalitySlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00599EA0 (FUN_00599EA0 -- `SaveRawPointer` of a `moho::CUnitCommandQueue` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromCUnitCommandQueueSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005A27D0 (FUN_005A27D0 -- `SaveRawPointer` of a `moho::Unit` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromUnitSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005A9750 (FUN_005A9750 -- `SaveRawPointer` of a `moho::CAiPathNavigator` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromCAiPathNavigatorSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005AC770 (FUN_005AC770 -- `SaveRawPointer` of a `moho::PathQueue` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromPathQueueSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005AC7B0 (FUN_005AC7B0 -- `SaveRawPointer` of a `moho::COGrid` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromCOGridSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005B1930 (FUN_005B1930 -- `SaveRawPointer` of a `moho::CAiPathFinder` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromCAiPathFinderSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005CA720 (FUN_005CA720 -- `SaveRawPointer` of a `moho::ReconBlip` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromReconBlipSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005CDE00 (FUN_005CDE00 -- `SaveRawPointer` of a `moho::CInfluenceMap` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromCInfluenceMapSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005D1050 (FUN_005D1050 -- `SaveRawPointer` of a `moho::UnitWeapon` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromUnitWeaponSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005D4F10 (FUN_005D4F10 -- `SaveRawPointer` of a `moho::CAiPathSpline` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromCAiPathSplineSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005D4F50 (FUN_005D4F50 -- `SaveRawPointer` of a `moho::CUnitMotion` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromCUnitMotionSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005DFB60 (FUN_005DFB60 -- `SaveRawPointer` of a `moho::CAcquireTargetTask` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromCAcquireTargetTaskSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005E1F00 (FUN_005E1F00 -- `SaveRawPointer` of a `moho::CAiAttackerImpl` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromCAiAttackerImplSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005F50D0 (FUN_005F50D0 -- `SaveRawPointer` of a `moho::CUnitCommand` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromCUnitCommandSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0060D770 (FUN_0060D770 -- `SaveRawPointer` of a `moho::EAiResult` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromEAiResultSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005332D0 (FUN_005332D0 -- `SaveRawPointer` of a `moho::RRuleGameRules` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromRRuleGameRulesSlotLane2` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00537220 (FUN_00537220 -- `SaveRawPointer` of a `moho::RRuleGameRules` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromRRuleGameRulesSlotLane3` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0055A400 (FUN_0055A400 -- `SaveRawPointer` of a `moho::RMeshBlueprint` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromRMeshBlueprintSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0055F290 (FUN_0055F290 -- `SaveRawPointer` of a `moho::RUnitBlueprint` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromRUnitBlueprintSlotLane2` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00633F20 (FUN_00633F20 -- `SaveRawPointer` of a `moho::RUnitBlueprintWeapon` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromRUnitBlueprintWeaponSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00633F60 (FUN_00633F60 -- `SaveRawPointer` of a `moho::RProjectileBlueprint` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromRProjectileBlueprintSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0063DAD0 (FUN_0063DAD0 -- `SaveRawPointer` of a `moho::CAniPose` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromCAniPoseSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0063EA00 (FUN_0063EA00 -- `SaveRawPointer` of a `moho::CAniActor` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromCAniActorSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006606E0 (FUN_006606E0 -- `SaveRawPointer` of a `moho::REmitterBlueprint` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromREmitterBlueprintSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00672990 (FUN_00672990 -- `SaveRawPointer` of a `moho::RTrailBlueprint` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromRTrailBlueprintSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00682520 (FUN_00682520 -- `SaveRawPointer` of a `moho::PositionHistory` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromPositionHistorySlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00682570 (FUN_00682570 -- `SaveRawPointer` of a `moho::CColPrimitiveBase` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromCColPrimitiveBaseSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006826A0 (FUN_006826A0 -- `SaveRawPointer` of a `moho::CIntel` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromCIntelSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00682750 (FUN_00682750 -- `SaveRawPointer` of a `moho::SPhysBody` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromSPhysBodySlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006827B0 (FUN_006827B0 -- `SaveRawPointer` of a `moho::Motor` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromMotorSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00689160 (FUN_00689160 -- `SaveRawPointer` of a `moho::EntitySetBase` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromEntitySetBaseSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006988B0 (FUN_006988B0 -- `SaveRawPointer` of a `moho::SPhysConstants` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromSPhysConstantsSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006B4450 (FUN_006B4450 -- `SaveRawPointer` of a `moho::IAiSteering` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromIAiSteeringSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006B44B0 (FUN_006B44B0 -- `SaveRawPointer` of a `moho::CUnitMotion` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromCUnitMotionSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006B4510 (FUN_006B4510 -- `SaveRawPointer` of a `moho::CUnitCommandQueue` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromCUnitCommandQueueSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006B4630 (FUN_006B4630 -- `SaveRawPointer` of a `moho::CAniActor` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromCAniActorSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006B4680 (FUN_006B4680 -- `SaveRawPointer` of a `moho::IAiAttacker` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromIAiAttackerSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006B46D0 (FUN_006B46D0 -- `SaveRawPointer` of a `moho::IAiCommandDispatch` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromIAiCommandDispatchSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006B4720 (FUN_006B4720 -- `SaveRawPointer` of a `moho::IAiNavigator` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromIAiNavigatorSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006B4770 (FUN_006B4770 -- `SaveRawPointer` of a `moho::IAiBuilder` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromIAiBuilderSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006B47C0 (FUN_006B47C0 -- `SaveRawPointer` of a `moho::IAiSiloBuild` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromIAiSiloBuildSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006B4810 (FUN_006B4810 -- `SaveRawPointer` of a `moho::IAiTransport` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromIAiTransportSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006BBF70 (FUN_006BBF70 -- `SaveRawPointer` of a `moho::CPathPoint` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromCPathPointSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006E0210 (FUN_006E0210 -- `SaveRawPointer` of a `moho::IAiAttacker` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromIAiAttackerSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006E02C0 (FUN_006E02C0 -- `SaveRawPointer` of a `moho::CFireWeaponTask` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromCFireWeaponTaskSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00706A80 (FUN_00706A80 -- `SaveRawPointer` of a `moho::CAiBrain` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromCAiBrainSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00706AD0 (FUN_00706AD0 -- `SaveRawPointer` of a `moho::IAiReconDB` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromIAiReconDBSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00706B90 (FUN_00706B90 -- `SaveRawPointer` of a `moho::CArmyStats` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromCArmyStatsSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00706BF0 (FUN_00706BF0 -- `SaveRawPointer` of a `moho::CInfluenceMap` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromCInfluenceMapSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00712FD0 (FUN_00712FD0 -- `SaveRawPointer` of a `moho::CAiBrain` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromCAiBrainSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00713100 (FUN_00713100 -- `SaveRawPointer` of a `moho::STrigger` slot as `Shared`; zero callers, unreachable; formerly `SaveSharedRawPointerFromSTriggerSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x007523F0 (FUN_007523F0 -- `SaveRawPointer` of a `moho::Shield` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromShieldSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00756E20 (FUN_00756E20 -- `SaveRawPointer` of a `moho::CRandomStream` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromCRandomStreamSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00756E70 (FUN_00756E70 -- `SaveRawPointer` of a `moho::SPhysConstants` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromSPhysConstantsSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00756F20 (FUN_00756F20 -- `SaveRawPointer` of a `moho::IAiFormationDB` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromIAiFormationDBSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00756F60 (FUN_00756F60 -- `SaveRawPointer` of a `moho::ISimResources` slot as `Shared`; zero callers, unreachable; formerly `SaveSharedRawPointerFromISimResourcesSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00756FC0 (FUN_00756FC0 -- `SaveRawPointer` of a `moho::CCommandDB` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromCCommandDBSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00757020 (FUN_00757020 -- `SaveRawPointer` of a `moho::CDecalBuffer` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromCDecalBufferSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00757070 (FUN_00757070 -- `SaveRawPointer` of a `moho::IEffectManager` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromIEffectManagerSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x007570D0 (FUN_007570D0 -- `SaveRawPointer` of a `moho::ISoundManager` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromISoundManagerSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00757190 (FUN_00757190 -- `SaveRawPointer` of a `moho::EntityDB` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromEntityDBSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00769220 (FUN_00769220 -- `SaveRawPointer` of a `moho::IPathTraveler` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromIPathTravelerSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00769260 (FUN_00769260 -- `SaveRawPointer` of a `moho::IPathTraveler` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromIPathTravelerSlotLane2` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0076ABD0 (FUN_0076ABD0 -- `SaveRawPointer` of a `moho::PathTables` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromPathTablesSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0076EBF0 (FUN_0076EBF0 -- `SaveRawPointer` of a `moho::CIntelPosHandle` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromCIntelPosHandleSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00770310 (FUN_00770310 -- `SaveRawPointer` of a `moho::IAiReconDB` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromIAiReconDBSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00771520 (FUN_00771520 -- `SaveRawPointer` of a `moho::IEffectManager` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromIEffectManagerSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00883A40 (FUN_00883A40 -- `SaveRawPointer` of a `moho::SSessionSaveData` slot as `Shared`; zero callers, unreachable; formerly `SaveSharedRawPointerFromSSessionSaveDataSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00921210 (FUN_00921210 -- `SaveRawPointer` of a `moho::TString` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromTStringSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0054FBA0 (FUN_0054FBA0 -- `SaveRawPointer` of a `moho::CAniSkel` slot as `Shared`; zero callers, unreachable; formerly `SaveSharedRawPointerFromCAniSkelSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00551AF0 (FUN_00551AF0 -- `SaveRawPointer` of a `moho::CIntelGrid` slot as `Shared`; zero callers, unreachable; formerly `SaveSharedRawPointerFromCIntelGridSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00554C30 (FUN_00554C30 -- `SaveRawPointer` of a `moho::REntityBlueprint` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromREntityBlueprintSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0055F390 (FUN_0055F390 -- `SaveRawPointer` of a `moho::Stats_StatItem` slot as `Shared`; zero callers, unreachable; formerly `SaveSharedRawPointerFromStats_StatItemSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00584B50 (FUN_00584B50 -- `SaveRawPointer` of a `moho::Sim` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromSimSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00584BB0 (FUN_00584BB0 -- `SaveRawPointer` of a `moho::CTaskStage` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromCTaskStageSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0059DF70 (FUN_0059DF70 -- `SaveRawPointer` of a `moho::IFormationInstance` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromIFormationInstanceSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005CDE40 (FUN_005CDE40 -- `SaveRawPointer` of a `moho::CIntelGrid` slot as `Shared`; zero callers, unreachable; formerly `SaveSharedRawPointerFromCIntelGridSlotLane2` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005D1A00 (FUN_005D1A00 -- `SaveRawPointer` of a `moho::CEconRequest` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromCEconRequestSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005F2140 (FUN_005F2140 -- `SaveRawPointer` of a `moho::CCommandTask` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromCCommandTaskSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00642ED0 (FUN_00642ED0 -- `SaveRawPointer` of a `moho::RScaResource` slot as `Shared`; zero callers, unreachable; formerly `SaveSharedRawPointerFromRScaResourceSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00675B40 (FUN_00675B40 -- `SaveRawPointer` of a `moho::IEffect` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromIEffectSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00682700 (FUN_00682700 -- `SaveRawPointer` of a `moho::CTextureScroller` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromCTextureScrollerSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006B4560 (FUN_006B4560 -- `SaveRawPointer` of a `moho::IFormationInstance` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromIFormationInstanceSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006B45D0 (FUN_006B45D0 -- `SaveRawPointer` of a `moho::CEconStorage` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromCEconStorageSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00706B30 (FUN_00706B30 -- `SaveRawPointer` of a `moho::CEconomy` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromCEconomySlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00713080 (FUN_00713080 -- `SaveRawPointer` of a `moho::CArmyStatItem` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromCArmyStatItemSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x007130C0 (FUN_007130C0 -- `SaveRawPointer` of a `moho::CArmyStatItem` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromCArmyStatItemSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0072AED0 (FUN_0072AED0 -- `SaveRawPointer` of a `moho::CSquad` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromCSquadSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x007689D0 (FUN_007689D0 -- `SaveRawPointer` of a `moho::PathQueue_Impl` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromPathQueue_ImplSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0076A450 (FUN_0076A450 -- `SaveRawPointer` of a `moho::PathQueue_Impl` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromPathQueue_ImplSlotLane2` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0076ADA0 (FUN_0076ADA0 -- `SaveRawPointer` of a `moho::PathQueue_Impl` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromPathQueue_ImplSlotLane3` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0076B490 (FUN_0076B490 -- `SaveRawPointer` of a `moho::PathQueue_Impl` slot as `Owned`; zero callers, unreachable; formerly `SaveOwnedRawPointerFromPathQueue_ImplSlotLane4` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x007744E0 (FUN_007744E0 -- `SaveRawPointer` of a `moho::CEconRequest` slot as `Unowned`; zero callers, unreachable; formerly `SaveUnownedRawPointerFromCEconRequestSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x008847C0 (FUN_008847C0 -- `SaveRawPointer` of a `moho::LaunchInfoBase` slot as `Shared`; zero callers, unreachable; formerly `SaveSharedRawPointerFromLaunchInfoBaseSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x004E5920 (FUN_004E5920 -- `WriteRawPointer` of a `moho::HSound` slot as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromHSoundSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x004E65F0 (FUN_004E65F0 -- `WriteRawPointer` of a `moho::HSound` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromHSoundValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00511070 (FUN_00511070 -- `WriteRawPointer` of a `moho::RRuleGameRules` slot as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromRRuleGameRulesSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005118A0 (FUN_005118A0 -- `WriteRawPointer` of a `moho::RRuleGameRules` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromRRuleGameRulesValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00525DD0 (FUN_00525DD0 -- `WriteRawPointer` of a `moho::RUnitBlueprint` slot as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromRUnitBlueprintSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00527590 (FUN_00527590 -- `WriteRawPointer` of a `moho::RUnitBlueprint` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromRUnitBlueprintValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00541AD0 (FUN_00541AD0 -- `WriteRawPointer` of a `moho::IUnit` slot as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromIUnitSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00541F10 (FUN_00541F10 -- `WriteRawPointer` of a `moho::IUnit` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromIUnitValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0055A260 (FUN_0055A260 -- `WriteRawPointer` of a `moho::RScmResource` slot as `Shared`; zero callers, unreachable; formerly `WriteSharedRawPointerFromRScmResourceSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0055A300 (FUN_0055A300 -- `WriteRawPointer` of a `moho::CSndParams` slot as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromCSndParamsSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0055A7B0 (FUN_0055A7B0 -- `WriteRawPointer` of a `moho::RScmResource` slot as `Shared`; zero callers, unreachable; formerly `WriteSharedRawPointerFromRScmResourceSlotLane2` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0055AA30 (FUN_0055AA30 -- `WriteRawPointer` of a `moho::CSndParams` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromCSndParamsValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0055EF50 (FUN_0055EF50 -- `WriteRawPointer` of a `moho::CAniPose` slot as `Shared`; zero callers, unreachable; formerly `WriteSharedRawPointerFromCAniPoseSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0055FB70 (FUN_0055FB70 -- `WriteRawPointer` of a `moho::CAniPose` slot as `Shared`; zero callers, unreachable; formerly `WriteSharedRawPointerFromCAniPoseSlotLane2` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00584720 (FUN_00584720 -- `WriteRawPointer` of a `moho::SimArmy` slot as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromSimArmySlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00584750 (FUN_00584750 -- `WriteRawPointer` of a `moho::CAiPersonality` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCAiPersonalitySlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00584E40 (FUN_00584E40 -- `WriteRawPointer` of a `moho::SimArmy` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromSimArmyValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00584F80 (FUN_00584F80 -- `WriteRawPointer` of a `moho::CAiPersonality` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCAiPersonalityValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00599E00 (FUN_00599E00 -- `WriteRawPointer` of a `moho::CUnitCommandQueue` slot as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromCUnitCommandQueueSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00599FE0 (FUN_00599FE0 -- `WriteRawPointer` of a `moho::CUnitCommandQueue` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromCUnitCommandQueueValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005A2710 (FUN_005A2710 -- `WriteRawPointer` of a `moho::Unit` slot as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromUnitSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005A2A10 (FUN_005A2A10 -- `WriteRawPointer` of a `moho::Unit` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromUnitValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005A9550 (FUN_005A9550 -- `WriteRawPointer` of a `moho::CAiPathNavigator` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCAiPathNavigatorSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005A99B0 (FUN_005A99B0 -- `WriteRawPointer` of a `moho::CAiPathNavigator` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCAiPathNavigatorValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005AC5A0 (FUN_005AC5A0 -- `WriteRawPointer` of a `moho::PathQueue` slot as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromPathQueueSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005AC5D0 (FUN_005AC5D0 -- `WriteRawPointer` of a `moho::COGrid` slot as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromCOGridSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005ACAB0 (FUN_005ACAB0 -- `WriteRawPointer` of a `moho::PathQueue` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromPathQueueValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005ACBF0 (FUN_005ACBF0 -- `WriteRawPointer` of a `moho::COGrid` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromCOGridValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005B1820 (FUN_005B1820 -- `WriteRawPointer` of a `moho::CAiPathFinder` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCAiPathFinderSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005B1B60 (FUN_005B1B60 -- `WriteRawPointer` of a `moho::CAiPathFinder` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCAiPathFinderValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005C9C40 (FUN_005C9C40 -- `WriteRawPointer` of a `moho::ReconBlip` slot as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromReconBlipSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005CC480 (FUN_005CC480 -- `WriteRawPointer` of a `moho::ReconBlip` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromReconBlipValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005CD950 (FUN_005CD950 -- `WriteRawPointer` of a `moho::CInfluenceMap` slot as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromCInfluenceMapSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005CE1F0 (FUN_005CE1F0 -- `WriteRawPointer` of a `moho::CInfluenceMap` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromCInfluenceMapValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005D0CD0 (FUN_005D0CD0 -- `WriteRawPointer` of a `moho::UnitWeapon` slot as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromUnitWeaponSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005D14F0 (FUN_005D14F0 -- `WriteRawPointer` of a `moho::UnitWeapon` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromUnitWeaponValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005D4E50 (FUN_005D4E50 -- `WriteRawPointer` of a `moho::CAiPathSpline` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCAiPathSplineSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005D4E80 (FUN_005D4E80 -- `WriteRawPointer` of a `moho::CUnitMotion` slot as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromCUnitMotionSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005D50F0 (FUN_005D50F0 -- `WriteRawPointer` of a `moho::CAiPathSpline` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCAiPathSplineValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005D5230 (FUN_005D5230 -- `WriteRawPointer` of a `moho::CUnitMotion` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromCUnitMotionValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005DF2A0 (FUN_005DF2A0 -- `WriteRawPointer` of a `moho::CAcquireTargetTask` slot as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromCAcquireTargetTaskSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005E11C0 (FUN_005E11C0 -- `WriteRawPointer` of a `moho::CAcquireTargetTask` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromCAcquireTargetTaskValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005E1AC0 (FUN_005E1AC0 -- `WriteRawPointer` of a `moho::CAiAttackerImpl` slot as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromCAiAttackerImplSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005E22E0 (FUN_005E22E0 -- `WriteRawPointer` of a `moho::CAiAttackerImpl` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromCAiAttackerImplValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005F5090 (FUN_005F5090 -- `WriteRawPointer` of a `moho::CUnitCommand` slot as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromCUnitCommandSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005F5210 (FUN_005F5210 -- `WriteRawPointer` of a `moho::CUnitCommand` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromCUnitCommandValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0060D6D0 (FUN_0060D6D0 -- `WriteRawPointer` of a `moho::EAiResult` slot as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromEAiResultSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0060DA50 (FUN_0060DA50 -- `WriteRawPointer` of a `moho::EAiResult` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromEAiResultValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005DEBD0 (FUN_005DEBD0 -- `WriteRawPointer` of a `moho::UnitWeapon` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromUnitWeaponValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005DEC00 (FUN_005DEC00 -- `WriteRawPointer` of a `moho::CAcquireTargetTask` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCAcquireTargetTaskValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005DF200 (FUN_005DF200 -- `WriteRawPointer` of a `moho::Listener_EAiAttackerEvent` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromListener_EAiAttackerEventValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005EC650 (FUN_005EC650 -- `WriteRawPointer` of a `moho::Listener_EAiTransportEvent` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromListener_EAiTransportEventValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0063CB30 (FUN_0063CB30 -- `WriteRawPointer` of a `moho::IAniManipulator` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromIAniManipulatorValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0063D790 (FUN_0063D790 -- `WriteRawPointer` of a `moho::CAniPose` slot as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromCAniPoseSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0063E640 (FUN_0063E640 -- `WriteRawPointer` of a `moho::CAniPose` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromCAniPoseValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0063E900 (FUN_0063E900 -- `WriteRawPointer` of a `moho::CAniActor` slot as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromCAniActorSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0063ED80 (FUN_0063ED80 -- `WriteRawPointer` of a `moho::CAniActor` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromCAniActorValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006605A0 (FUN_006605A0 -- `WriteRawPointer` of a `moho::REmitterBlueprint` slot as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromREmitterBlueprintSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006608C0 (FUN_006608C0 -- `WriteRawPointer` of a `moho::REmitterBlueprint` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromREmitterBlueprintValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00672950 (FUN_00672950 -- `WriteRawPointer` of a `moho::RTrailBlueprint` slot as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromRTrailBlueprintSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00672AD0 (FUN_00672AD0 -- `WriteRawPointer` of a `moho::RTrailBlueprint` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromRTrailBlueprintValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0067F890 (FUN_0067F890 -- `WriteRawPointer` of a `moho::Entity` slot as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromEntitySlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006810C0 (FUN_006810C0 -- `WriteRawPointer` of a `moho::Entity` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromEntityValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00682110 (FUN_00682110 -- `WriteRawPointer` of a `moho::PositionHistory` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromPositionHistorySlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00682140 (FUN_00682140 -- `WriteRawPointer` of a `moho::CColPrimitiveBase` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCColPrimitiveBaseSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006821F0 (FUN_006821F0 -- `WriteRawPointer` of a `moho::CIntel` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCIntelSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00682250 (FUN_00682250 -- `WriteRawPointer` of a `moho::SPhysBody` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromSPhysBodySlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00682280 (FUN_00682280 -- `WriteRawPointer` of a `moho::Motor` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromMotorSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00682B00 (FUN_00682B00 -- `WriteRawPointer` of a `moho::PositionHistory` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromPositionHistoryValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00682C40 (FUN_00682C40 -- `WriteRawPointer` of a `moho::CColPrimitiveBase` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCColPrimitiveBaseValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00682D80 (FUN_00682D80 -- `WriteRawPointer` of a `moho::CIntel` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCIntelValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00683000 (FUN_00683000 -- `WriteRawPointer` of a `moho::SPhysBody` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromSPhysBodyValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00683140 (FUN_00683140 -- `WriteRawPointer` of a `moho::Motor` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromMotorValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00688BE0 (FUN_00688BE0 -- `WriteRawPointer` of a `moho::EntitySetBase` slot as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromEntitySetBaseSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006896B0 (FUN_006896B0 -- `WriteRawPointer` of a `moho::EntitySetBase` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromEntitySetBaseValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006B40D0 (FUN_006B40D0 -- `WriteRawPointer` of a `moho::IAiSteering` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromIAiSteeringSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006B4100 (FUN_006B4100 -- `WriteRawPointer` of a `moho::CUnitMotion` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCUnitMotionSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006B4130 (FUN_006B4130 -- `WriteRawPointer` of a `moho::CUnitCommandQueue` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCUnitCommandQueueSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006B41C0 (FUN_006B41C0 -- `WriteRawPointer` of a `moho::CAniActor` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCAniActorSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006B41F0 (FUN_006B41F0 -- `WriteRawPointer` of a `moho::IAiAttacker` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromIAiAttackerSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006B4220 (FUN_006B4220 -- `WriteRawPointer` of a `moho::IAiCommandDispatch` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromIAiCommandDispatchSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006B4250 (FUN_006B4250 -- `WriteRawPointer` of a `moho::IAiNavigator` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromIAiNavigatorSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006B4280 (FUN_006B4280 -- `WriteRawPointer` of a `moho::IAiBuilder` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromIAiBuilderSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006B42B0 (FUN_006B42B0 -- `WriteRawPointer` of a `moho::IAiSiloBuild` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromIAiSiloBuildSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006B42E0 (FUN_006B42E0 -- `WriteRawPointer` of a `moho::IAiTransport` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromIAiTransportSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006B4B80 (FUN_006B4B80 -- `WriteRawPointer` of a `moho::IAiSteering` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromIAiSteeringValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006B4CC0 (FUN_006B4CC0 -- `WriteRawPointer` of a `moho::CUnitMotion` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCUnitMotionValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006B4E00 (FUN_006B4E00 -- `WriteRawPointer` of a `moho::CUnitCommandQueue` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCUnitCommandQueueValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006B51C0 (FUN_006B51C0 -- `WriteRawPointer` of a `moho::CAniActor` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCAniActorValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006B5300 (FUN_006B5300 -- `WriteRawPointer` of a `moho::IAiAttacker` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromIAiAttackerValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006B5440 (FUN_006B5440 -- `WriteRawPointer` of a `moho::IAiCommandDispatch` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromIAiCommandDispatchValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006B5580 (FUN_006B5580 -- `WriteRawPointer` of a `moho::IAiNavigator` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromIAiNavigatorValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006B56C0 (FUN_006B56C0 -- `WriteRawPointer` of a `moho::IAiBuilder` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromIAiBuilderValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006B5800 (FUN_006B5800 -- `WriteRawPointer` of a `moho::IAiSiloBuild` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromIAiSiloBuildValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006B5940 (FUN_006B5940 -- `WriteRawPointer` of a `moho::IAiTransport` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromIAiTransportValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006DFE60 (FUN_006DFE60 -- `WriteRawPointer` of a `moho::IAiAttacker` slot as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromIAiAttackerSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006DFED0 (FUN_006DFED0 -- `WriteRawPointer` of a `moho::CFireWeaponTask` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCFireWeaponTaskSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006E0610 (FUN_006E0610 -- `WriteRawPointer` of a `moho::IAiAttacker` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromIAiAttackerValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006E0750 (FUN_006E0750 -- `WriteRawPointer` of a `moho::CFireWeaponTask` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCFireWeaponTaskValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006E2B00 (FUN_006E2B00 -- `WriteRawPointer` of a `moho::CUnitCommand` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCUnitCommandValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006EB980 (FUN_006EB980 -- `WriteRawPointer` of a `moho::Listener_ECommandEvent` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromListener_ECommandEventValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00706650 (FUN_00706650 -- `WriteRawPointer` of a `moho::CAiBrain` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCAiBrainSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00706680 (FUN_00706680 -- `WriteRawPointer` of a `moho::IAiReconDB` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromIAiReconDBSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x007066E0 (FUN_007066E0 -- `WriteRawPointer` of a `moho::CArmyStats` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCArmyStatsSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00706710 (FUN_00706710 -- `WriteRawPointer` of a `moho::CInfluenceMap` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCInfluenceMapSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00706740 (FUN_00706740 -- `WriteRawPointer` of a `moho::PathQueue` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromPathQueueSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00706F30 (FUN_00706F30 -- `WriteRawPointer` of a `moho::CAiBrain` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCAiBrainValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00707070 (FUN_00707070 -- `WriteRawPointer` of a `moho::IAiReconDB` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromIAiReconDBValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x007072F0 (FUN_007072F0 -- `WriteRawPointer` of a `moho::CArmyStats` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCArmyStatsValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00707430 (FUN_00707430 -- `WriteRawPointer` of a `moho::CInfluenceMap` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCInfluenceMapValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00707570 (FUN_00707570 -- `WriteRawPointer` of a `moho::PathQueue` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromPathQueueValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00712650 (FUN_00712650 -- `WriteRawPointer` of a `moho::CAiBrain` slot as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromCAiBrainSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00712980 (FUN_00712980 -- `WriteRawPointer` of a `moho::STrigger` slot as `Shared`; zero callers, unreachable; formerly `WriteSharedRawPointerFromSTriggerSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00714040 (FUN_00714040 -- `WriteRawPointer` of a `moho::CAiBrain` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromCAiBrainValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x007144D0 (FUN_007144D0 -- `WriteRawPointer` of a `moho::STrigger` slot as `Shared`; zero callers, unreachable; formerly `WriteSharedRawPointerFromSTriggerSlotLane2` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00750FA0 (FUN_00750FA0 -- `WriteRawPointer` of a `moho::SimArmy` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromSimArmyValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00751870 (FUN_00751870 -- `WriteRawPointer` of a `moho::Shield` slot as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromShieldSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x007546B0 (FUN_007546B0 -- `WriteRawPointer` of a `moho::Shield` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromShieldValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00756460 (FUN_00756460 -- `WriteRawPointer` of a `moho::CRandomStream` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCRandomStreamSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00756490 (FUN_00756490 -- `WriteRawPointer` of a `moho::SPhysConstants` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromSPhysConstantsSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00756500 (FUN_00756500 -- `WriteRawPointer` of a `moho::IAiFormationDB` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromIAiFormationDBSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00756530 (FUN_00756530 -- `WriteRawPointer` of a `moho::ISimResources` slot as `Shared`; zero callers, unreachable; formerly `WriteSharedRawPointerFromISimResourcesSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00756560 (FUN_00756560 -- `WriteRawPointer` of a `moho::CCommandDB` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCCommandDBSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00756590 (FUN_00756590 -- `WriteRawPointer` of a `moho::CDecalBuffer` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCDecalBufferSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x007565C0 (FUN_007565C0 -- `WriteRawPointer` of a `moho::IEffectManager` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromIEffectManagerSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x007565F0 (FUN_007565F0 -- `WriteRawPointer` of a `moho::ISoundManager` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromISoundManagerSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00756660 (FUN_00756660 -- `WriteRawPointer` of a `moho::EntityDB` slot as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromEntityDBSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00757650 (FUN_00757650 -- `WriteRawPointer` of a `moho::CRandomStream` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCRandomStreamValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00757790 (FUN_00757790 -- `WriteRawPointer` of a `moho::SPhysConstants` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromSPhysConstantsValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x007578D0 (FUN_007578D0 -- `WriteRawPointer` of a `moho::IAiFormationDB` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromIAiFormationDBValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00757AE0 (FUN_00757AE0 -- `WriteRawPointer` of a `moho::ISimResources` slot as `Shared`; zero callers, unreachable; formerly `WriteSharedRawPointerFromISimResourcesSlotLane2` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00757C20 (FUN_00757C20 -- `WriteRawPointer` of a `moho::CCommandDB` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCCommandDBValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00757D60 (FUN_00757D60 -- `WriteRawPointer` of a `moho::CDecalBuffer` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromCDecalBufferValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00757EA0 (FUN_00757EA0 -- `WriteRawPointer` of a `moho::IEffectManager` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromIEffectManagerValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00757FE0 (FUN_00757FE0 -- `WriteRawPointer` of a `moho::ISoundManager` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromISoundManagerValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00758120 (FUN_00758120 -- `WriteRawPointer` of a `moho::EntityDB` value as `Owned`; zero callers, unreachable; formerly `WriteOwnedRawPointerFromEntityDBValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00763D90 (FUN_00763D90 -- `WriteRawPointer` of a `moho::Listener_NavPath` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromListener_NavPathValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00768C10 (FUN_00768C10 -- `WriteRawPointer` of a `moho::IPathTraveler` slot as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromIPathTravelerSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0076A4E0 (FUN_0076A4E0 -- `WriteRawPointer` of a `moho::PathTables` slot as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromPathTablesSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0076A9F0 (FUN_0076A9F0 -- `WriteRawPointer` of a `moho::IPathTraveler` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromIPathTravelerValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0076B2D0 (FUN_0076B2D0 -- `WriteRawPointer` of a `moho::PathTables` value as `Unowned`; zero callers, unreachable; formerly `WriteUnownedRawPointerFromPathTablesValueLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0069FA30 (FUN_0069FA30 -- `WritePointer<moho::ManyToOneListener<moho::EProjectileImpactEvent>>` from a value, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromManyToOneListener_EProjectileImpactEventValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x006757F0 (FUN_006757F0 -- `WritePointer<moho::ManyToOneListener<moho::ECollisionBeamEvent>>` from a value, state folded to Unowned; no references in the PE; formerly `SaveUnownedRawPointerFromManyToOneListener_ECollisionBeamEventValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x006F9070 (FUN_006F9070 -- `WritePointer<moho::Listener<moho::EUnitCommandQueueStatus>>` from a value, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromListener_EUnitCommandQueueStatusValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00571340 (FUN_00571340 -- `WritePointer<moho::Listener<moho::EFormationdStatus>>` from a value, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromListener_EFormationdStatusValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x006340C0 (FUN_006340C0 -- `WritePointer<moho::RUnitBlueprintWeapon>` from a value, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromRUnitBlueprintWeaponValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00634200 (FUN_00634200 -- `WritePointer<moho::RProjectileBlueprint>` from a value, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromRProjectileBlueprintValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00633E20 (FUN_00633E20 -- `WritePointer<moho::RProjectileBlueprint>` from a slot, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromRProjectileBlueprintSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x005DEAC0 (FUN_005DEAC0 -- `WritePointer<moho::CAiAttackerImpl>` from an owner field, state folded to Unowned; no references in the PE; formerly `SaveUnownedRawPointerFromCAiAttackerImplOwnerFieldLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x005E1370 (FUN_005E1370 -- `WritePointer<moho::CAiAttackerImpl>` from an owner field, state folded to Unowned; no references in the PE; formerly `SaveUnownedRawPointerFromCAiAttackerImplOwnerFieldLane3` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00633DF0 (FUN_00633DF0 -- `WritePointer<moho::RUnitBlueprintWeapon>` from a slot, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromRUnitBlueprintWeaponSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x005E02C0 (FUN_005E02C0 -- `WritePointer<moho::CAiAttackerImpl>` from an owner field, state folded to Unowned; no references in the PE; formerly `SaveUnownedRawPointerFromCAiAttackerImplOwnerFieldLane2` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x0059E920 (FUN_0059E920 -- `WritePointer<IFormationInstance>` from a value, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromIFormationInstanceValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x0059DD30 (FUN_0059DD30 -- `WritePointer<IFormationInstance>` from a slot, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromIFormationInstanceSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x006EBB00 (FUN_006EBB00 -- `WritePointer<IFormationInstance>` from a value, state folded to Shared; no references in the PE; formerly `WriteSharedRawPointerFromIFormationInstanceValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x006B4F40 (FUN_006B4F40 -- `WritePointer<IFormationInstance>` from a value, state folded to Owned; no references in the PE; formerly `WriteOwnedRawPointerFromIFormationInstanceValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00554F90 (FUN_00554F90 -- `WritePointer<moho::REntityBlueprint>` from a value, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromREntityBlueprintValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x006B4160 (FUN_006B4160 -- `WritePointer<IFormationInstance>` from a slot, state folded to Owned; no references in the PE; formerly `WriteOwnedRawPointerFromIFormationInstanceSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x0065A930 (FUN_0065A930 -- `WritePointer<CParticleTexture>` from a value, state folded to Shared; no references in the PE; formerly `WriteSharedRawPointerFromCParticleTextureValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x005549F0 (FUN_005549F0 -- `WritePointer<moho::REntityBlueprint>` from a slot, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromREntityBlueprintSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00698A10 (FUN_00698A10 -- `WritePointer<moho::SPhysConstants>` from a value, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromSPhysConstantsValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00883630 (FUN_00883630 -- `WritePointer<moho::SSessionSaveData>` from a slot, state folded to Shared; no references in the PE; formerly `WriteSharedRawPointerFromSSessionSaveDataSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00682EC0 (FUN_00682EC0 -- `WritePointer<moho::CTextureScroller>` from a value, state folded to Owned; no references in the PE; formerly `WriteOwnedRawPointerFromCTextureScrollerValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x008845D0 (FUN_008845D0 -- `WritePointer<moho::SSessionSaveData>` from a slot, state folded to Shared; no references in the PE; formerly `WriteSharedRawPointerFromSSessionSaveDataSlotLane2` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x0055F750 (FUN_0055F750 -- `WritePointer<moho::RUnitBlueprint>` from a value, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromRUnitBlueprintValueLane2` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00771660 (FUN_00771660 -- `WritePointer<moho::IEffectManager>` from a value, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromIEffectManagerValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x0063CB60 (FUN_0063CB60 -- `WritePointer<moho::IAniManipulator*>` from a value, state folded to Owned; no references in the PE; formerly `WriteOwnedRawPointerFromIAniManipulator_PNullLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x0055A8F0 (FUN_0055A8F0 -- `WritePointer<moho::RMeshBlueprint>` from a value, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromRMeshBlueprintValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x005376D0 (FUN_005376D0 -- `WritePointer<moho::RRuleGameRules>` from a value, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromRRuleGameRulesValueLane2` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x007142C0 (FUN_007142C0 -- `WritePointer<CArmyStatItem>` from a value, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromCArmyStatItemValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x0055A290 (FUN_0055A290 -- `WritePointer<moho::RMeshBlueprint>` from a slot, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromRMeshBlueprintSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x0055EC40 (FUN_0055EC40 -- `WritePointer<moho::RUnitBlueprint>` from a slot, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromRUnitBlueprintSlotLane2` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x0076ED40 (FUN_0076ED40 -- `WritePointer<moho::CIntelPosHandle>` from a value, state folded to Owned; no references in the PE; formerly `WriteOwnedRawPointerFromCIntelPosHandleValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00536D50 (FUN_00536D50 -- `WritePointer<moho::RRuleGameRules>` from a slot, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromRRuleGameRulesSlotLane2` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x0076A8B0 (FUN_0076A8B0 -- `WritePointer<moho::IPathTraveler>` from a value, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromIPathTravelerValueLane2` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00698800 (FUN_00698800 -- `WritePointer<moho::SPhysConstants>` from a slot, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromSPhysConstantsSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00682220 (FUN_00682220 -- `WritePointer<moho::CTextureScroller>` from a slot, state folded to Owned; no references in the PE; formerly `WriteOwnedRawPointerFromCTextureScrollerSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00884E70 (FUN_00884E70 -- `WritePointer<LaunchInfoBase>` from a slot, state folded to Shared; no references in the PE; formerly `WriteSharedRawPointerFromLaunchInfoBaseSlotLane2` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x0055ED00 (FUN_0055ED00 -- `WritePointer<moho::Stats_StatItem>` from a slot, state folded to Shared; no references in the PE; formerly `WriteSharedRawPointerFromStats_StatItemSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x006B10C0 (FUN_006B10C0 -- `WritePointer<moho::CEconomyEvent*>` from a value, state folded to Owned; no references in the PE; formerly `WriteOwnedRawPointerFromCEconomyEvent_PNullLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x0070E060 (FUN_0070E060 -- `WritePointer<moho::CAiBrain>` from an owner field, state folded to Unowned; no references in the PE; formerly `SaveUnownedRawPointerFromCAiBrainOwnerFieldLane2` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x0076EB90 (FUN_0076EB90 -- `WritePointer<moho::CIntelPosHandle>` from a slot, state folded to Owned; no references in the PE; formerly `WriteOwnedRawPointerFromCIntelPosHandleSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00768BE0 (FUN_00768BE0 -- `WritePointer<moho::IPathTraveler>` from a slot, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromIPathTravelerSlotLane2` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x0076B680 (FUN_0076B680 -- `WritePointer<PathQueue_Impl>` from a value, state folded to Owned; no references in the PE; formerly `WriteOwnedRawPointerFromPathQueue_ImplValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x0055F960 (FUN_0055F960 -- `WritePointer<moho::Stats_StatItem>` from a slot, state folded to Shared; no references in the PE; formerly `WriteSharedRawPointerFromStats_StatItemSlotLane2` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00883EA0 (FUN_00883EA0 -- `WritePointer<LaunchInfoBase>` from a slot, state folded to Shared; no references in the PE; formerly `WriteSharedRawPointerFromLaunchInfoBaseSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00712940 (FUN_00712940 -- `WritePointer<CArmyStatItem>` from a slot, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromCArmyStatItemSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00712600 (FUN_00712600 -- `WritePointer<moho::CAiBrain>` from an owner field, state folded to Unowned; no references in the PE; formerly `SaveUnownedRawPointerFromCAiBrainOwnerFieldLane3` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x005F2280 (FUN_005F2280 -- `WritePointer<CCommandTask>` from a value, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromCCommandTaskValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00774700 (FUN_00774700 -- `WritePointer<moho::CEconRequest>` from a value, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromCEconRequestValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x0070E010 (FUN_0070E010 -- `WritePointer<moho::CAiBrain>` from an owner field, state folded to Unowned; no references in the PE; formerly `SaveUnownedRawPointerFromCAiBrainOwnerFieldLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x0076B330 (FUN_0076B330 -- `WritePointer<PathQueue_Impl>` from a slot, state folded to Owned; no references in the PE; formerly `WriteOwnedRawPointerFromPathQueue_ImplSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x005F2100 (FUN_005F2100 -- `WritePointer<CCommandTask>` from a slot, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromCCommandTaskSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00774320 (FUN_00774320 -- `WritePointer<moho::CEconRequest>` from a slot, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromCEconRequestSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00714180 (FUN_00714180 -- `WritePointer<CArmyStatItem>` from a value, state folded to Owned; no references in the PE; formerly `WriteOwnedRawPointerFromCArmyStatItemValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x006B1090 (FUN_006B1090 -- `WritePointer<moho::CEconomyEvent>` from a value, state folded to Owned; no references in the PE; formerly `WriteOwnedRawPointerFromCEconomyEventValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x006E2B30 (FUN_006E2B30 -- `WritePointer<moho::CUnitCommand*>` from a value, state folded to Owned; no references in the PE; formerly `WriteOwnedRawPointerFromCUnitCommand_PNullLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x0077D770 (FUN_0077D770 -- `WritePointer<moho::CDecalHandle*>` from a value, state folded to Owned; no references in the PE; formerly `WriteOwnedRawPointerFromCDecalHandle_PNullLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x006B5080 (FUN_006B5080 -- `WritePointer<moho::CEconStorage>` from a value, state folded to Owned; no references in the PE; formerly `WriteOwnedRawPointerFromCEconStorageValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00643140 (FUN_00643140 -- `WritePointer<moho::RScaResource>` from a slot, state folded to Shared; no references in the PE; formerly `WriteSharedRawPointerFromRScaResourceSlotLane2` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x005D1BE0 (FUN_005D1BE0 -- `WritePointer<moho::CEconRequest>` from a value, state folded to Owned; no references in the PE; formerly `WriteOwnedRawPointerFromCEconRequestValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x007704B0 (FUN_007704B0 -- `WritePointer<moho::IAiReconDB>` from a value, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromIAiReconDBValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00642E00 (FUN_00642E00 -- `WritePointer<moho::RScaResource>` from a slot, state folded to Shared; no references in the PE; formerly `WriteSharedRawPointerFromRScaResourceSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x007128D0 (FUN_007128D0 -- `WritePointer<CArmyStatItem>` from a slot, state folded to Owned; no references in the PE; formerly `WriteOwnedRawPointerFromCArmyStatItemSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x0077D740 (FUN_0077D740 -- `WritePointer<moho::CDecalHandle>` from a value, state folded to Owned; no references in the PE; formerly `WriteOwnedRawPointerFromCDecalHandleValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x004E64B0 (FUN_004E64B0 -- `WritePointer<moho::CSndParams>` from a value, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromCSndParamsValueLane2` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x006BC2F0 (FUN_006BC2F0 -- `WritePointer<moho::CPathPoint>` from a value, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromCPathPointValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x006B4190 (FUN_006B4190 -- `WritePointer<moho::CEconStorage>` from a slot, state folded to Owned; no references in the PE; formerly `WriteOwnedRawPointerFromCEconStorageSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x004E58F0 (FUN_004E58F0 -- `WritePointer<moho::CSndParams>` from a slot, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromCSndParamsSlotLane2` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x005D16A0 (FUN_005D16A0 -- `WritePointer<moho::CEconRequest>` from a slot, state folded to Owned; no references in the PE; formerly `WriteOwnedRawPointerFromCEconRequestSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x006E10F0 (FUN_006E10F0 -- `WritePointer<moho::Sim>` from a slot, state folded to Unowned; no references in the PE; formerly `SaveUnownedRawPointerFromSimSlotLane1Variant2` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x006BBDB0 (FUN_006BBDB0 -- `WritePointer<moho::CPathPoint>` from a slot, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromCPathPointSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00770290 (FUN_00770290 -- `WritePointer<moho::IAiReconDB>` from a slot, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromIAiReconDBSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x005CE400 (FUN_005CE400 -- `WritePointer<CIntelGrid>` from a slot, state folded to Shared; no references in the PE; formerly `WriteSharedRawPointerFromCIntelGridSlotLane4` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x006F8CB0 (FUN_006F8CB0 -- `WritePointer<moho::Unit>` from an owner field, state folded to Unowned; no references in the PE; formerly `SaveUnownedRawPointerFromUnitOwnerFieldLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00774D00 (FUN_00774D00 -- `WritePointer<moho::CEconomy>` from a value, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromCEconomyValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x005518B0 (FUN_005518B0 -- `WritePointer<CIntelGrid>` from a slot, state folded to Shared; no references in the PE; formerly `WriteSharedRawPointerFromCIntelGridSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x005CD980 (FUN_005CD980 -- `WritePointer<CIntelGrid>` from a slot, state folded to Shared; no references in the PE; formerly `WriteSharedRawPointerFromCIntelGridSlotLane3` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00585200 (FUN_00585200 -- `WritePointer<moho::CTaskStage>` from a value, state folded to Owned; no references in the PE; formerly `WriteOwnedRawPointerFromCTaskStageValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x0090B7E0 (FUN_0090B7E0 -- `WritePointer<LuaPlus::LuaState>` from a value, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromLuaStateValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00551EA0 (FUN_00551EA0 -- `WritePointer<CIntelGrid>` from a slot, state folded to Shared; no references in the PE; formerly `WriteSharedRawPointerFromCIntelGridSlotLane2` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x006762C0 (FUN_006762C0 -- `WritePointer<moho::IEffect>` from a value, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromIEffectValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00584830 (FUN_00584830 -- `WritePointer<moho::CTaskStage>` from a slot, state folded to Owned; no references in the PE; formerly `WriteOwnedRawPointerFromCTaskStageSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x0069E420 (FUN_0069E420 -- `WritePointer<moho::Sim>` from an owner field, state folded to Unowned; no references in the PE; formerly `SaveUnownedRawPointerFromSimOwnerFieldLane2` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x006FA5B0 (FUN_006FA5B0 -- `WritePointer<moho::Sim>` from an owner field, state folded to Unowned; no references in the PE; formerly `SaveUnownedRawPointerFromSimOwnerFieldLane4` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00761160 (FUN_00761160 -- `WritePointer<moho::Sim>` from an owner field, state folded to Unowned; no references in the PE; formerly `SaveUnownedRawPointerFromSimOwnerFieldLane6` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00776760 (FUN_00776760 -- `WritePointer<moho::Sim>` from an owner field, state folded to Unowned; no references in the PE; formerly `SaveUnownedRawPointerFromSimOwnerFieldLane8` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00673950 (FUN_00673950 -- `WritePointer<moho::Sim>` from an owner field, state folded to Unowned; no references in the PE; formerly `SaveUnownedRawPointerFromSimOwnerFieldLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x006AD2C0 (FUN_006AD2C0 -- `WritePointer<moho::Sim>` from an owner field, state folded to Unowned; no references in the PE; formerly `SaveUnownedRawPointerFromSimOwnerFieldLane3` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x0091EDE0 (FUN_0091EDE0 -- `WritePointer<TString>` from a value, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromTStringValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00675830 (FUN_00675830 -- `WritePointer<moho::IEffect>` from a slot, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromIEffectSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x0072B1A0 (FUN_0072B1A0 -- `WritePointer<moho::CSquad>` from a value, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromCSquadValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x007071B0 (FUN_007071B0 -- `WritePointer<moho::CEconomy>` from a value, state folded to Owned; no references in the PE; formerly `WriteOwnedRawPointerFromCEconomyValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00550100 (FUN_00550100 -- `WritePointer<moho::CAniSkel>` from a slot, state folded to Shared; no references in the PE; formerly `WriteSharedRawPointerFromCAniSkelSlotLane2` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00921420 (FUN_00921420 -- `WritePointer<TString>` from a slot, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromTStringSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x0054FAC0 (FUN_0054FAC0 -- `WritePointer<moho::CAniSkel>` from a slot, state folded to Shared; no references in the PE; formerly `WriteSharedRawPointerFromCAniSkelSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x0066C320 (FUN_0066C320 -- `WritePointer<moho::IEffect*>` from a value, state folded to Owned; no references in the PE; formerly `WriteOwnedRawPointerFromIEffect_PNullLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x009209A0 (FUN_009209A0 -- `WritePointer<UpVal>` from a value, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromUpValValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x007066B0 (FUN_007066B0 -- `WritePointer<moho::CEconomy>` from a slot, state folded to Owned; no references in the PE; formerly `WriteOwnedRawPointerFromCEconomySlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x0072AE10 (FUN_0072AE10 -- `WritePointer<moho::CSquad>` from a slot, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromCSquadSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00706C40 (FUN_00706C40 -- `WritePointer<moho::PathQueue>` from a slot, state folded to Owned; no references in the PE; formerly `SaveOwnedRawPointerFromPathQueueSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x0066C2F0 (FUN_0066C2F0 -- `WritePointer<moho::IEffect>` from a value, state folded to Owned; no references in the PE; formerly `WriteOwnedRawPointerFromIEffectValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00920970 (FUN_00920970 -- `WritePointer<Proto>` from a value, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromProtoValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x0091E8D0 (FUN_0091E8D0 -- `WritePointer<Table>` from a value, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromTableValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x0072ADE0 (FUN_0072ADE0 -- `WritePointer<moho::CSquad>` from a value, state folded to Owned; no references in the PE; formerly `WriteOwnedRawPointerFromCSquadValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x005850C0 (FUN_005850C0 -- `WritePointer<moho::Sim>` from a value, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromSimValueLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00584800 (FUN_00584800 -- `WritePointer<moho::Sim>` from a slot, state folded to Unowned; no references in the PE; formerly `WriteUnownedRawPointerFromSimSlotLane1` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x006E1140 (FUN_006E1140 -- `WritePointer<moho::Sim>` from a slot, state folded to Unowned; no references in the PE; formerly `SaveUnownedRawPointerFromSimSlotLane2` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x006E2A40 (FUN_006E2A40 -- `WritePointer<moho::Sim>` from a slot, state folded to Unowned; no references in the PE; formerly `SaveUnownedRawPointerFromSimSlotLane3` in gpg/core/containers/ArchiveSerialization.cpp, removed 2026-09-30.)
   * Address: 0x00774B80 (FUN_00774B80 -- `WritePointer<moho::CEconomy>` from a slot, state folded to Unowned; no references in the PE; formerly `SerializeUnownedCEconomyPointer` in moho/sim/CEconStorage.cpp, removed 2026-09-30.)
   * Address: 0x00774BC0 (FUN_00774BC0 -- the same, archive on the stack; no references in the PE; formerly `SerializeUnownedCEconomyPointerBinary` in moho/sim/CEconStorage.cpp, removed 2026-09-30.)
   *
   * What it does:
   * Writes `value` as a tracked pointer in `state`, owned by `ownerRef`:
   * `WriteRawPointer` 0x00953320 of `MakeRRef<T>(value)`. `RRef_RMeshBlueprint`'s
   * unowned copy 0x0055A290 is the body: the typed reference, then
   * `WriteRawPointer(archive, ref, 1, owner)`, then the archive back.
   */
  template <class T>
  WriteArchive* WriteArchive::WritePointer(T* const value, const TrackedPointerState state, const RRef& ownerRef)
  {
    WriteRawPointer(this, MakeRRef<T>(value), state, ownerRef);
    return this;
  }

  namespace detail
  {
    /**
     * The last three dynamic types one `MakeRRef<T>` resolved, most recent
     * first: a `{type_info*, RType*}` table per `T` and per thread
     * (`RRef_Entity` 0x006805E0 reaches it through the TLS slot at
     * `fs:[0x2C]`, guard bit 1 of `+0x898`).
     */
    struct RecentRuntimeTypes
    {
      struct Entry
      {
        const std::type_info* typeInfo;
        RType* type;
      };

      Entry entries[3];

      /**
       * What it does:
       * The reflected type of `info`, from the table when it is there and by
       * `LookupRType` when it is not; either way it moves to the front,
       * pushing the oldest entry out.
       */
      [[nodiscard]] RType* Find(const std::type_info& info)
      {
        int slot = 0;
        while (slot < 3 && !(entries[slot].typeInfo == &info || (entries[slot].typeInfo && *entries[slot].typeInfo == info))) {
          ++slot;
        }

        RType* type;
        if (slot == 3) {
          type = LookupRType(info);
          slot = 2;
        } else {
          type = entries[slot].type;
        }

        for (; slot > 0; --slot) {
          entries[slot] = entries[slot - 1];
        }
        entries[0] = Entry{&info, type};
        return type;
      }
    };
  } // namespace detail

  /**
   * The per-type reference builders are this template:
   *
   * Address: 0x00403020 (FUN_00403020 -- `MakeRRef<unsigned int>`; formerly `gpg::RRef_uint`.)
   * Address: 0x004041F0 (FUN_004041F0 -- `MakeRRef<moho::IdPool>`; formerly `gpg::RRef_IdPool`.)
   * Address: 0x0040C030 (FUN_0040C030 -- `MakeRRef<moho::CTaskThread>`; formerly `gpg::RRef_CTaskThread`.)
   * Address: 0x0040C300 (FUN_0040C300 -- `MakeRRef<moho::CTaskStage>`; formerly `gpg::RRef_CTaskStage`.)
   * Address: 0x0040F600 (FUN_0040F600 -- `MakeRRef<moho::CRandomStream>`; formerly `gpg::RRef_CRandomStream`.)
   * Address: 0x004220D0 (FUN_004220D0 -- `MakeRRef<moho::CLuaConOutputHandler>`; formerly `gpg::RRef_CLuaConOutputHandler`.)
   * Address: 0x004C16D0 (FUN_004C16D0 -- `MakeRRef<LuaPlus::LuaState>`; formerly `gpg::RRef_LuaState`.)
   * Address: 0x004C8C30 (FUN_004C8C30 -- `MakeRRef<moho::CScriptObject*>`; formerly `gpg::RRef_CScriptObject_P`.)
   * Address: 0x004C9030 (FUN_004C9030 -- `MakeRRef<moho::CScriptObject>`; formerly `gpg::RRef_CScriptObject`.)
   * Address: 0x004CBB60 (FUN_004CBB60 -- `MakeRRef<moho::CLuaTask>`; formerly `gpg::RRef_CLuaTask`.)
   * Address: 0x004CBE70 (FUN_004CBE70 -- `MakeRRef<moho::CWaitForTask>`; formerly `gpg::RRef_CWaitForTask`.)
   * Address: 0x004CC040 (FUN_004CC040 -- `MakeRRef<moho::CScriptEvent>`; formerly `gpg::RRef_CScriptEvent`.)
   * Address: 0x004E5590 (FUN_004E5590 -- `MakeRRef<moho::CSndVar>`; formerly `gpg::RRef_CSndVar`.)
   * Address: 0x004E5730 (FUN_004E5730 -- `MakeRRef<moho::CSndParams>`; formerly `gpg::RRef_CSndParams`.)
   * Address: 0x004E6200 (FUN_004E6200 -- `MakeRRef<moho::CSndParams*>`; formerly `gpg::RRef_CSndParams_P`.)
   * Address: 0x004E6720 (FUN_004E6720 -- `MakeRRef<moho::HSound>`; formerly `gpg::RRef_HSound`.)
   * Address: 0x00500730 (FUN_00500730 -- `MakeRRef<moho::CColPrimitive<Wm3::Sphere3f>>`; formerly `gpg::RRef_CColPrimitive_Sphere3f`.)
   * Address: 0x005008E0 (FUN_005008E0 -- `MakeRRef<moho::CColPrimitive<Wm3::Box3f>>`; formerly `gpg::RRef_CColPrimitive_Box3f`.)
   * Address: 0x0050E2A0 (FUN_0050E2A0 -- `MakeRRef<moho::RBlueprint>`; formerly `gpg::RRef_RBlueprint`.)
   * Address: 0x00511250 (FUN_00511250 -- `MakeRRef<moho::REmitterBlueprint>`; formerly `gpg::RRef_REmitterBlueprint`.)
   * Address: 0x00511400 (FUN_00511400 -- `MakeRRef<moho::RTrailBlueprint>`; formerly `gpg::RRef_RTrailBlueprint`.)
   * Address: 0x005115B0 (FUN_005115B0 -- `MakeRRef<moho::RBeamBlueprint>`; formerly `gpg::RRef_RBeamBlueprint`.)
   * Address: 0x00511940 (FUN_00511940 -- `MakeRRef<moho::RRuleGameRules>`; formerly `gpg::RRef_RRuleGameRules`.)
   * Address: 0x00513760 (FUN_00513760 -- `MakeRRef<msvc8::string>`; formerly `gpg::RRef_string`.)
   * Address: 0x00517940 (FUN_00517940 -- `MakeRRef<Wm3::Vector3f>`; formerly `gpg::RRef_Vector3f`.)
   * Address: 0x00517AE0 (FUN_00517AE0 -- `MakeRRef<moho::REmitterCurveKey>`; formerly `gpg::RRef_REmitterCurveKey`.)
   * Address: 0x00517D20 (FUN_00517D20 -- `MakeRRef<moho::REmitterBlueprintCurve>`; formerly `gpg::RRef_REmitterBlueprintCurve`.)
   * Address: 0x0051AAE0 (FUN_0051AAE0 -- `MakeRRef<moho::RMeshBlueprint>`; formerly `gpg::RRef_RMeshBlueprint`.)
   * Address: 0x0051AC90 (FUN_0051AC90 -- `MakeRRef<moho::RMeshBlueprintLOD>`; formerly `gpg::RRef_RMeshBlueprintLOD`.)
   * Address: 0x0051CFF0 (FUN_0051CFF0 -- `MakeRRef<moho::RProjectileBlueprint>`; formerly `gpg::RRef_RProjectileBlueprint`.)
   * Address: 0x0051E130 (FUN_0051E130 -- `MakeRRef<moho::RPropBlueprint>`; formerly `gpg::RRef_RPropBlueprint`.)
   * Address: 0x00526C80 (FUN_00526C80 -- `MakeRRef<moho::RUnitBlueprint>`; formerly `gpg::RRef_RUnitBlueprint`.)
   * Address: 0x00526E30 (FUN_00526E30 -- `MakeRRef<moho::RUnitBlueprintWeapon>`; formerly `gpg::RRef_RUnitBlueprintWeapon`.)
   * Address: 0x00526FD0 (FUN_00526FD0 -- `MakeRRef<float>`; formerly `gpg::RRef_float`.)
   * Address: 0x00536BA0 (FUN_00536BA0 -- `MakeRRef<moho::SRuleFootprintsBlueprint>`; formerly `gpg::RRef_SRuleFootprintsBlueprint`.)
   * Address: 0x00537250 (FUN_00537250 -- `MakeRRef<moho::EntityCategorySet>`; formerly `gpg::RRef_EntityCategory`.)
   * Address: 0x00541C50 (FUN_00541C50 -- `MakeRRef<moho::IUnit>`; formerly `gpg::RRef_IUnit`.)
   * Address: 0x00544EE0 (FUN_00544EE0 -- `MakeRRef<moho::LaunchInfoNew>`; formerly `gpg::RRef_LaunchInfoNew`.)
   * Address: 0x00549200 (FUN_00549200 -- `MakeRRef<moho::ResourceDeposit>`; formerly `gpg::RRef_ResourceDeposit`.)
   * Address: 0x00549550 (FUN_00549550 -- `MakeRRef<moho::CSimResources>`; formerly `gpg::RRef_CSimResources`.)
   * Address: 0x0054E690 (FUN_0054E690 -- `MakeRRef<moho::CAniPoseBone>`; formerly `gpg::RRef_CAniPoseBone`.)
   * Address: 0x0054EA20 (FUN_0054EA20 -- `MakeRRef<moho::CAniPose>`; formerly `gpg::RRef_CAniPose`.)
   * Address: 0x005504C0 (FUN_005504C0 -- `MakeRRef<moho::CAniSkel>`; formerly `gpg::RRef_CAniSkel`.)
   * Address: 0x005541F0 (FUN_005541F0 -- `MakeRRef<std::int32_t>`; formerly `gpg::RRef_EntId`.)
   * Address: 0x00554390 (FUN_00554390 -- `MakeRRef<moho::SOCellPos>`; formerly `gpg::RRef_SOCellPos`.)
   * Address: 0x00555040 (FUN_00555040 -- `MakeRRef<moho::REntityBlueprint>`; formerly `gpg::RRef_REntityBlueprint`.)
   * Address: 0x00557BD0 (FUN_00557BD0 -- `MakeRRef<moho::RBlueprint*>`; formerly `gpg::RRef_RBlueprint_P`.)
   * Address: 0x00559790 (FUN_00559790 -- `MakeRRef<moho::SSTIEntityAttachInfo>`; formerly `gpg::RRef_SSTIEntityAttachInfo`.)
   * Address: 0x0055AB70 (FUN_0055AB70 -- `MakeRRef<moho::RScmResource>`; formerly `gpg::RRef_RScmResource`.)
   * Address: 0x005725F0 (FUN_005725F0 -- `MakeRRef<moho::WeakPtr<moho::IUnit>>`; formerly `gpg::RRef_WeakPtr_IUnit`.)
   * Address: 0x00572C90 (FUN_00572C90 -- `MakeRRef<moho::Listener<moho::EFormationdStatus>>`; formerly `gpg::RRef_Listener_EFormationdStatus`.)
   * Address: 0x00582B50 (FUN_00582B50 -- `MakeRRef<moho::CAiBrain>`; formerly `gpg::RRef_CAiBrain`.)
   * Address: 0x00582F00 (FUN_00582F00 -- `MakeRRef<moho::SPointVector>`; formerly `gpg::RRef_SPointVector`.)
   * Address: 0x005832B0 (FUN_005832B0 -- `MakeRRef<bool>`; formerly `gpg::RRef_bool`.)
   * Address: 0x00583450 (FUN_00583450 -- `MakeRRef<int>`; formerly `gpg::RRef_int`.)
   * Address: 0x005852B0 (FUN_005852B0 -- `MakeRRef<moho::SimArmy>`; formerly `gpg::RRef_SimArmy`.)
   * Address: 0x005854A0 (FUN_005854A0 -- `MakeRRef<moho::CAiPersonality>`; formerly `gpg::RRef_CAiPersonality`.)
   * Address: 0x00593380 (FUN_00593380 -- `MakeRRef<moho::ETriggerOperator>`; formerly `gpg::RRef_ETriggerOperator`.)
   * Address: 0x00593520 (FUN_00593520 -- `MakeRRef<moho::EEconResource>`; formerly `gpg::RRef_EEconResource`.)
   * Address: 0x005937D0 (FUN_005937D0 -- `MakeRRef<moho::EAlliance>`; formerly `gpg::RRef_EAlliance`.)
   * Address: 0x00593BC0 (FUN_00593BC0 -- `MakeRRef<moho::ESquadClass>`; formerly `gpg::RRef_ESquadClass`.)
   * Address: 0x00593D60 (FUN_00593D60 -- `MakeRRef<moho::ECompareType>`; formerly `gpg::RRef_ECompareType`.)
   * Address: 0x00593F00 (FUN_00593F00 -- `MakeRRef<moho::EThreatType>`; formerly `gpg::RRef_EThreatType`.)
   * Address: 0x00599AB0 (FUN_00599AB0 -- `MakeRRef<moho::IAiCommandDispatchImpl>`; formerly `gpg::RRef_IAiCommandDispatchImpl`.)
   * Address: 0x0059A070 (FUN_0059A070 -- `MakeRRef<moho::CUnitCommandQueue>`; formerly `gpg::RRef_CUnitCommandQueue`.)
   * Address: 0x0059E080 (FUN_0059E080 -- `MakeRRef<moho::IFormationInstance*>`; formerly `gpg::RRef_IFormationInstance_P`.)
   * Address: 0x0059E2E0 (FUN_0059E2E0 -- `MakeRRef<moho::CAiFormationInstance>`; formerly `gpg::RRef_CAiFormationInstance`.)
   * Address: 0x0059E490 (FUN_0059E490 -- `MakeRRef<moho::CAiFormationDBImpl>`; formerly `gpg::RRef_CAiFormationDBImpl`.)
   * Address: 0x005A2030 (FUN_005A2030 -- `MakeRRef<moho::CAiBuilderImpl>`; formerly `gpg::RRef_CAiBuilderImpl`.)
   * Address: 0x005A22A0 (FUN_005A22A0 -- `MakeRRef<moho::RUnitBlueprint*>`; formerly `gpg::RRef_RUnitBlueprint_P`.)
   * Address: 0x005A2A40 (FUN_005A2A40 -- `MakeRRef<moho::Unit>`; formerly `gpg::RRef_Unit`.)
   * Address: 0x005A85D0 (FUN_005A85D0 -- `MakeRRef<moho::CAiNavigatorLand>`; formerly `gpg::RRef_CAiNavigatorLand`.)
   * Address: 0x005A87A0 (FUN_005A87A0 -- `MakeRRef<moho::CAiNavigatorAir>`; formerly `gpg::RRef_CAiNavigatorAir`.)
   * Address: 0x005A8A40 (FUN_005A8A40 -- `MakeRRef<moho::Listener<moho::EAiNavigatorEvent>>`; formerly `gpg::RRef_Listener_EAiNavigatorEvent`.)
   * Address: 0x005A9A40 (FUN_005A9A40 -- `MakeRRef<moho::CAiPathNavigator>`; formerly `gpg::RRef_CAiPathNavigator`.)
   * Address: 0x005ABD20 (FUN_005ABD20 -- `MakeRRef<moho::CAiPathFinder>`; formerly `gpg::RRef_CAiPathFinder`.)
   * Address: 0x005ACCA0 (FUN_005ACCA0 -- `MakeRRef<moho::PathQueue>`; formerly `gpg::RRef_PathQueue`.)
   * Address: 0x005ACE80 (FUN_005ACE80 -- `MakeRRef<moho::COGrid>`; formerly `gpg::RRef_COGrid`.)
   * Address: 0x005B5A90 (FUN_005B5A90 -- `MakeRRef<moho::CPathPoint>`; formerly `gpg::RRef_CPathPoint`.)
   * Address: 0x005B5D60 (FUN_005B5D60 -- `MakeRRef<moho::CAiPathSpline>`; formerly `gpg::RRef_CAiPathSpline`.)
   * Address: 0x005CADE0 (FUN_005CADE0 -- `MakeRRef<moho::ReconBlip>`; formerly `gpg::RRef_ReconBlip`.)
   * Address: 0x005CB020 (FUN_005CB020 -- `MakeRRef<moho::EReconFlags>`; formerly `gpg::RRef_EReconFlags`.)
   * Address: 0x005CB790 (FUN_005CB790 -- `MakeRRef<moho::SPerArmyReconInfo>`; formerly `gpg::RRef_SPerArmyReconInfo`.)
   * Address: 0x005CB930 (FUN_005CB930 -- `MakeRRef<moho::ReconBlip*>`; formerly `gpg::RRef_ReconBlip_P`.)
   * Address: 0x005CC0D0 (FUN_005CC0D0 -- `MakeRRef<moho::CAiReconDBImpl>`; formerly `gpg::RRef_CAiReconDBImpl`.)
   * Address: 0x005CE540 (FUN_005CE540 -- `MakeRRef<moho::CInfluenceMap>`; formerly `gpg::RRef_CInfluenceMap`.)
   * Address: 0x005D0E70 (FUN_005D0E70 -- `MakeRRef<moho::CAiSiloBuildImpl>`; formerly `gpg::RRef_CAiSiloBuildImpl`.)
   * Address: 0x005D1750 (FUN_005D1750 -- `MakeRRef<moho::UnitWeapon>`; formerly `gpg::RRef_UnitWeapon`.)
   * Address: 0x005D1C70 (FUN_005D1C70 -- `MakeRRef<moho::CEconRequest>`; formerly `gpg::RRef_CEconRequest`.)
   * Address: 0x005D4730 (FUN_005D4730 -- `MakeRRef<moho::CAiSteeringImpl>`; formerly `gpg::RRef_CAiSteeringImpl`.)
   * Address: 0x005D5300 (FUN_005D5300 -- `MakeRRef<moho::CUnitMotion>`; formerly `gpg::RRef_CUnitMotion`.)
   * Address: 0x005E0300 (FUN_005E0300 -- `MakeRRef<moho::CAiAttackerImpl>`; formerly `gpg::RRef_CAiAttackerImpl`.)
   * Address: 0x005E04D0 (FUN_005E04D0 -- `MakeRRef<moho::CAcquireTargetTask>`; formerly `gpg::RRef_CAcquireTargetTask`.)
   * Address: 0x005E0750 (FUN_005E0750 -- `MakeRRef<moho::UnitWeapon*>`; formerly `gpg::RRef_UnitWeapon_P`.)
   * Address: 0x005E08D0 (FUN_005E08D0 -- `MakeRRef<moho::CAcquireTargetTask*>`; formerly `gpg::RRef_CAcquireTargetTask_P`.)
   * Address: 0x005E0A90 (FUN_005E0A90 -- `MakeRRef<moho::Listener<moho::EAiAttackerEvent>>`; formerly `gpg::RRef_Listener_EAiAttackerEvent`.)
   * Address: 0x005E0E80 (FUN_005E0E80 -- `MakeRRef<moho::LAiAttackerImpl>`; formerly `gpg::RRef_LAiAttackerImpl`.)
   * Address: 0x005E3660 (FUN_005E3660 -- `MakeRRef<moho::EAiTargetType>`; formerly `gpg::RRef_EAiTargetType`.)
   * Address: 0x005EDB00 (FUN_005EDB00 -- `MakeRRef<moho::CAiTransportImpl>`; formerly `gpg::RRef_CAiTransportImpl`.)
   * Address: 0x005EDD30 (FUN_005EDD30 -- `MakeRRef<moho::SAiReservedTransportBone>`; formerly `gpg::RRef_SAiReservedTransportBone`.)
   * Address: 0x005EDED0 (FUN_005EDED0 -- `MakeRRef<moho::SAttachPoint>`; formerly `gpg::RRef_SAttachPoint`.)
   * Address: 0x005EE1B0 (FUN_005EE1B0 -- `MakeRRef<moho::Listener<moho::EAiTransportEvent>>`; formerly `gpg::RRef_Listener_EAiTransportEvent`.)
   * Address: 0x005F5280 (FUN_005F5280 -- `MakeRRef<moho::CUnitCommand>`; formerly `gpg::RRef_CUnitCommand`.)
   * Address: 0x0061CCA0 (FUN_0061CCA0 -- `MakeRRef<moho::CUnitPatrolTask>`; formerly `gpg::RRef_CUnitPatrolTask`.)
   * Address: 0x005FDCD0 (FUN_005FDCD0 -- `MakeRRef<moho::CUnitMobileBuildTask>`; formerly `gpg::RRef_CUnitMobileBuildTask`.)
   * Address: 0x005FDE80 (FUN_005FDE80 -- `MakeRRef<moho::CUnitUpgradeTask>`; formerly `gpg::RRef_CUnitUpgradeTask`.)
   * Address: 0x005FE030 (FUN_005FE030 -- `MakeRRef<moho::CUnitRepairTask>`; formerly `gpg::RRef_CUnitRepairTask`.)
   * Address: 0x005FE1E0 (FUN_005FE1E0 -- `MakeRRef<moho::CFactoryBuildTask>`; formerly `gpg::RRef_CFactoryBuildTask`.)
   * Address: 0x005FE390 (FUN_005FE390 -- `MakeRRef<moho::CUnitSacrificeTask>`; formerly `gpg::RRef_CUnitSacrificeTask`.)
   * Address: 0x006058B0 (FUN_006058B0 -- `MakeRRef<moho::CUnitCaptureTask>`; formerly `gpg::RRef_CUnitCaptureTask`.)
   * Address: 0x00608090 (FUN_00608090 -- `MakeRRef<moho::CUnitCarrierRetrieve>`; formerly `gpg::RRef_CUnitCarrierRetrieve`.)
   * Address: 0x00608240 (FUN_00608240 -- `MakeRRef<moho::CUnitCarrierLand>`; formerly `gpg::RRef_CUnitCarrierLand`.)
   * Address: 0x006083F0 (FUN_006083F0 -- `MakeRRef<moho::CUnitCarrierLaunch>`; formerly `gpg::RRef_CUnitCarrierLaunch`.)
   * Address: 0x0060CAB0 (FUN_0060CAB0 -- `MakeRRef<moho::CUnitGetBuiltTask>`; formerly `gpg::RRef_CUnitGetBuiltTask`.)
   * Address: 0x0060CC60 (FUN_0060CC60 -- `MakeRRef<moho::CUnitTeleportTask>`; formerly `gpg::RRef_CUnitTeleportTask`.)
   * Address: 0x0060D7A0 (FUN_0060D7A0 -- `MakeRRef<moho::EAiResult>`; formerly `gpg::RRef_EAiResult`.)
   * Address: 0x00614BA0 (FUN_00614BA0 -- `MakeRRef<moho::CUnitGuardTask>`; formerly `gpg::RRef_CUnitGuardTask`.)
   * Address: 0x00628DB0 (FUN_00628DB0 -- `MakeRRef<moho::CUnitUnloadUnits>`; formerly `gpg::RRef_CUnitUnloadUnits`.)
   * Address: 0x0063D230 (FUN_0063D230 -- `MakeRRef<moho::CAniActor>`; formerly `gpg::RRef_CAniActor`.)
   * Address: 0x0063D3F0 (FUN_0063D3F0 -- `MakeRRef<moho::IAniManipulator>`; formerly `gpg::RRef_IAniManipulator`.)
   * Address: 0x0063D5A0 (FUN_0063D5A0 -- `MakeRRef<moho::IAniManipulator*>`; formerly `gpg::RRef_IAniManipulator_P`.)
   * Address: 0x0063D800 (FUN_0063D800 -- `MakeRRef<moho::SAniManipBinding>`; formerly `gpg::RRef_SAniManipBinding`.)
   * Address: 0x0063EAD0 (FUN_0063EAD0 -- `MakeRRef<boost::shared_ptr<moho::CAniPose>>`; formerly `gpg::RRef_shared_ptr_CAniPose`.)
   * Address: 0x00642860 (FUN_00642860 -- `MakeRRef<std::vector<bool>::reference>`; formerly `gpg::RRef_VectorBoolReference`.)
   * Address: 0x006431E0 (FUN_006431E0 -- `MakeRRef<moho::RScaResource>`; formerly `gpg::RRef_RScaResource`.)
   * Address: 0x0064C960 (FUN_0064C960 -- `MakeRRef<moho::RDebugCollision>`; formerly `gpg::RRef_RDebugCollision`.)
   * Address: 0x0064FBC0 (FUN_0064FBC0 -- `MakeRRef<moho::RDebugGrid>`; formerly `gpg::RRef_RDebugGrid`.)
   * Address: 0x0064FD70 (FUN_0064FD70 -- `MakeRRef<moho::RDebugRadar>`; formerly `gpg::RRef_RDebugRadar`.)
   * Address: 0x00651200 (FUN_00651200 -- `MakeRRef<moho::RDebugNavPath>`; formerly `gpg::RRef_RDebugNavPath`.)
   * Address: 0x006513B0 (FUN_006513B0 -- `MakeRRef<moho::RDebugNavWaypoints>`; formerly `gpg::RRef_RDebugNavWaypoints`.)
   * Address: 0x00651560 (FUN_00651560 -- `MakeRRef<moho::RDebugNavSteering>`; formerly `gpg::RRef_RDebugNavSteering`.)
   * Address: 0x00653C50 (FUN_00653C50 -- `MakeRRef<moho::RDebugWeapons>`; formerly `gpg::RRef_RDebugWeapons`.)
   * Address: 0x00658860 (FUN_00658860 -- `MakeRRef<moho::CEfxBeam>`; formerly `gpg::RRef_CEfxBeam`.)
   * Address: 0x0065ADC0 (FUN_0065ADC0 -- `MakeRRef<moho::CountedPtr<moho::CParticleTexture>>`; formerly `gpg::RRef_CountedPtr_CParticleTexture`.)
   * Address: 0x0065FCF0 (FUN_0065FCF0 -- `MakeRRef<moho::SEfxCurve>`; formerly `gpg::RRef_SEfxCurve`.)
   * Address: 0x0066C650 (FUN_0066C650 -- `MakeRRef<moho::IEffect>`; formerly `gpg::RRef_IEffect`.)
   * Address: 0x0066C800 (FUN_0066C800 -- `MakeRRef<moho::IEffect*>`; formerly `gpg::RRef_IEffect_P`.)
   * Address: 0x00675DB0 (FUN_00675DB0 -- `MakeRRef<moho::CollisionBeamEntity>`; formerly `gpg::RRef_CollisionBeamEntity`.)
   * Address: 0x00676000 (FUN_00676000 -- `MakeRRef<moho::ManyToOneListener_ECollisionBeamEvent>`; formerly `gpg::RRef_ManyToOneListener_ECollisionBeamEvent`.)
   * Address: 0x006805E0 (FUN_006805E0 -- `MakeRRef<moho::Entity>`; formerly `gpg::RRef_Entity`.)
   * Address: 0x006807B0 (FUN_006807B0 -- `MakeRRef<moho::Entity*>`; formerly `gpg::RRef_Entity_P`.)
   * Address: 0x00680D70 (FUN_00680D70 -- `MakeRRef<moho::PositionHistory>`; formerly `gpg::RRef_PositionHistory`.)
   * Address: 0x00683230 (FUN_00683230 -- `MakeRRef<moho::CColPrimitiveBase>`; formerly `gpg::RRef_CColPrimitiveBase`.)
   * Address: 0x00683420 (FUN_00683420 -- `MakeRRef<moho::CIntel>`; formerly `gpg::RRef_CIntel`.)
   * Address: 0x00683600 (FUN_00683600 -- `MakeRRef<moho::CTextureScroller>`; formerly `gpg::RRef_CTextureScroller`.)
   * Address: 0x006837E0 (FUN_006837E0 -- `MakeRRef<moho::SPhysBody>`; formerly `gpg::RRef_SPhysBody`.)
   * Address: 0x006839C0 (FUN_006839C0 -- `MakeRRef<moho::Motor>`; formerly `gpg::RRef_Motor`.)
   * Address: 0x00689360 (FUN_00689360 -- `MakeRRef<moho::EntityDB>`; formerly `gpg::RRef_EntityDB`.)
   * Address: 0x00689920 (FUN_00689920 -- `MakeRRef<moho::EntitySetBase>`; formerly `gpg::RRef_EntitySetBase`.)
   * Address: 0x00692DB0 (FUN_00692DB0 -- `MakeRRef<moho::EVisibilityMode>`; formerly `gpg::RRef_EVisibilityMode`.)
   * Address: 0x00692F50 (FUN_00692F50 -- `MakeRRef<moho::EIntel>`; formerly `gpg::RRef_EIntel`.)
   * Address: 0x00698D80 (FUN_00698D80 -- `MakeRRef<moho::SPhysConstants>`; formerly `gpg::RRef_SPhysConstants`.)
   * Address: 0x0069FEA0 (FUN_0069FEA0 -- `MakeRRef<moho::Projectile>`; formerly `gpg::RRef_Projectile`.)
   * Address: 0x006A00F0 (FUN_006A00F0 -- `MakeRRef<moho::ManyToOneListener<moho::EProjectileImpactEvent>>`; formerly `gpg::RRef_ManyToOneListener_EProjectileImpactEvent`.)
   * Address: 0x006B1C90 (FUN_006B1C90 -- `MakeRRef<moho::EUnitState>`; formerly `gpg::RRef_EUnitState`.)
   * Address: 0x006B2020 (FUN_006B2020 -- `MakeRRef<moho::CEconomyEvent*>`; formerly `gpg::RRef_CEconomyEvent_P`.)
   * Address: 0x006B21E0 (FUN_006B21E0 -- `MakeRRef<moho::WeakPtr<moho::Entity>>`; formerly `gpg::RRef_WeakPtr_Entity`.)
   * Address: 0x006B3AD0 (FUN_006B3AD0 -- `MakeRRef<moho::CEconomyEvent>`; formerly `gpg::RRef_CEconomyEvent`.)
   * Address: 0x006B59D0 (FUN_006B59D0 -- `MakeRRef<moho::IAiSteering>`; formerly `gpg::RRef_IAiSteering`.)
   * Address: 0x006B5BC0 (FUN_006B5BC0 -- `MakeRRef<moho::CEconStorage>`; formerly `gpg::RRef_CEconStorage`.)
   * Address: 0x006B5DA0 (FUN_006B5DA0 -- `MakeRRef<moho::IAiAttacker>`; formerly `gpg::RRef_IAiAttacker`.)
   * Address: 0x006B5F90 (FUN_006B5F90 -- `MakeRRef<moho::IAiCommandDispatch>`; formerly `gpg::RRef_IAiCommandDispatch`.)
   * Address: 0x006B6180 (FUN_006B6180 -- `MakeRRef<moho::IAiNavigator>`; formerly `gpg::RRef_IAiNavigator`.)
   * Address: 0x006B6370 (FUN_006B6370 -- `MakeRRef<moho::IAiBuilder>`; formerly `gpg::RRef_IAiBuilder`.)
   * Address: 0x006B6560 (FUN_006B6560 -- `MakeRRef<moho::IAiSiloBuild>`; formerly `gpg::RRef_IAiSiloBuild`.)
   * Address: 0x006B6750 (FUN_006B6750 -- `MakeRRef<moho::IAiTransport>`; formerly `gpg::RRef_IAiTransport`.)
   * Address: 0x006D1FB0 (FUN_006D1FB0 -- `MakeRRef<moho::ERuleBPUnitToggleCaps>`; formerly `gpg::RRef_ERuleBPUnitToggleCaps`.)
   * Address: 0x006D2150 (FUN_006D2150 -- `MakeRRef<moho::EFireState>`; formerly `gpg::RRef_EFireState`.)
   * Address: 0x006D22F0 (FUN_006D22F0 -- `MakeRRef<moho::ERuleBPUnitCommandCaps>`; formerly `gpg::RRef_ERuleBPUnitCommandCaps`.)
   * Address: 0x006DD790 (FUN_006DD790 -- `MakeRRef<moho::ELayer>`; formerly `gpg::RRef_ELayer`.)
   * Address: 0x006DED40 (FUN_006DED40 -- `MakeRRef<moho::CFireWeaponTask>`; formerly `gpg::RRef_CFireWeaponTask`.)
   * Address: 0x006E3150 (FUN_006E3150 -- `MakeRRef<moho::CCommandDB>`; formerly `gpg::RRef_CCommandDB`.)
   * Address: 0x006E3310 (FUN_006E3310 -- `MakeRRef<moho::CUnitCommand*>`; formerly `gpg::RRef_CUnitCommand_P`.)
   * Address: 0x006EC1D0 (FUN_006EC1D0 -- `MakeRRef<moho::WeakPtr<moho::CUnitCommand>>`; formerly `gpg::RRef_WeakPtr_CUnitCommand`.)
   * Address: 0x006EC620 (FUN_006EC620 -- `MakeRRef<moho::Listener<moho::ECommandEvent>>`; formerly `gpg::RRef_Listener_ECommandEvent`.)
   * Address: 0x006F9410 (FUN_006F9410 -- `MakeRRef<moho::Listener<moho::EUnitCommandQueueStatus>>`; formerly `gpg::RRef_Listener_EUnitCommandQueueStatus`.)
   * Address: 0x006FAF20 (FUN_006FAF20 -- `MakeRRef<moho::Prop>`; formerly `gpg::RRef_Prop`.)
   * Address: 0x00705120 (FUN_00705120 -- `MakeRRef<moho::CPlatoon>`; formerly `gpg::RRef_CPlatoon`.)
   * Address: 0x007057D0 (FUN_007057D0 -- `MakeRRef<moho::CArmyImpl>`; formerly `gpg::RRef_CArmyImpl`.)
   * Address: 0x00707640 (FUN_00707640 -- `MakeRRef<moho::IAiReconDB>`; formerly `gpg::RRef_IAiReconDB`.)
   * Address: 0x00707830 (FUN_00707830 -- `MakeRRef<moho::CEconomy>`; formerly `gpg::RRef_CEconomy`.)
   * Address: 0x00707A10 (FUN_00707A10 -- `MakeRRef<moho::CArmyStats>`; formerly `gpg::RRef_CArmyStats`.)
   * Address: 0x00713560 (FUN_00713560 -- `MakeRRef<moho::SCondition>`; formerly `gpg::RRef_SCondition`.)
   * Address: 0x00713700 (FUN_00713700 -- `MakeRRef<moho::STrigger>`; formerly `gpg::RRef_STrigger`.)
   * Address: 0x007139C0 (FUN_007139C0 -- `MakeRRef<moho::Stats<moho::CArmyStatItem>>`; formerly `gpg::RRef_Stats_CArmyStatItem`.)
   * Address: 0x00713D90 (FUN_00713D90 -- `MakeRRef<moho::CArmyStatItem*>`; formerly `gpg::RRef_CArmyStatItem_P`.)
   * Address: 0x0071E410 (FUN_0071E410 -- `MakeRRef<moho::InfluenceGrid>`; formerly `gpg::RRef_InfluenceGrid`.)
   * Address: 0x0071E5B0 (FUN_0071E5B0 -- `MakeRRef<moho::SThreat>`; formerly `gpg::RRef_SThreat`.)
   * Address: 0x0072AF00 (FUN_0072AF00 -- `MakeRRef<moho::CSquad>`; formerly `gpg::RRef_CSquad`.)
   * Address: 0x00736A30 (FUN_00736A30 -- `MakeRRef<unsigned char>`; formerly `gpg::RRef_uchar`.)
   * Address: 0x00753910 (FUN_00753910 -- `MakeRRef<moho::SimArmy*>`; formerly `gpg::RRef_SimArmy_P`.)
   * Address: 0x00753FC0 (FUN_00753FC0 -- `MakeRRef<moho::Shield>`; formerly `gpg::RRef_Shield`.)
   * Address: 0x007542F0 (FUN_007542F0 -- `MakeRRef<moho::Shield*>`; formerly `gpg::RRef_Shield_P`.)
   * Address: 0x00756160 (FUN_00756160 -- `MakeRRef<LuaPlus::LuaState>`; formerly `gpg::RRef_LuaState`.)
   * Address: 0x00756190 (FUN_00756190 -- `MakeRRef<moho::RRuleGameRules>`; formerly `gpg::RRef_RRuleGameRules`.)
   * Address: 0x007561C0 (FUN_007561C0 -- `MakeRRef<moho::SRuleFootprintsBlueprint>`; formerly `gpg::RRef_SRuleFootprintsBlueprint`.)
   * Address: 0x00756220 (FUN_00756220 -- `MakeRRef<moho::PathTables>`; formerly `gpg::RRef_PathTables`.)
   * Address: 0x007571F0 (FUN_007571F0 -- `MakeRRef<moho::PathTables>`; formerly `gpg::RRef_PathTables`.)
   * Address: 0x007582F0 (FUN_007582F0 -- `MakeRRef<moho::IAiFormationDB>`; formerly `gpg::RRef_IAiFormationDB`.)
   * Address: 0x00758500 (FUN_00758500 -- `MakeRRef<moho::ISimResources>`; formerly `gpg::RRef_ISimResources`.)
   * Address: 0x00758730 (FUN_00758730 -- `MakeRRef<moho::CDecalBuffer>`; formerly `gpg::RRef_CDecalBuffer`.)
   * Address: 0x00758910 (FUN_00758910 -- `MakeRRef<moho::IEffectManager>`; formerly `gpg::RRef_IEffectManager`.)
   * Address: 0x00758B00 (FUN_00758B00 -- `MakeRRef<moho::ISoundManager>`; formerly `gpg::RRef_ISoundManager`.)
   * Address: 0x00762410 (FUN_00762410 -- `MakeRRef<moho::ISoundManager>`; formerly `gpg::RRef_ISoundManager`.)
   * Address: 0x00762560 (FUN_00762560 -- `MakeRRef<moho::SAudioRequest>`; formerly `gpg::RRef_SAudioRequest`.)
   * Address: 0x00762890 (FUN_00762890 -- `MakeRRef<moho::SAudioRequest>`; formerly `gpg::RRef_SAudioRequest`.)
   * Address: 0x00764280 (FUN_00764280 -- `MakeRRef<moho::HPathCell>`; formerly `gpg::RRef_HPathCell`.)
   * Address: 0x00764460 (FUN_00764460 -- `MakeRRef<moho::Listener<const moho::SNavPath&>>`; formerly `gpg::RRef_Listener_NavPath`.)
   * Address: 0x0076AE70 (FUN_0076AE70 -- `MakeRRef<moho::IPathTraveler>`; formerly `gpg::RRef_IPathTraveler`.)
   * Address: 0x0076EDD0 (FUN_0076EDD0 -- `MakeRRef<moho::CIntelPosHandle>`; formerly `gpg::RRef_CIntelPosHandle`.)
   * Address: 0x0076FE30 (FUN_0076FE30 -- `MakeRRef<moho::CIntelCounterHandle>`; formerly `gpg::RRef_CIntelCounterHandle`.)
   * Address: 0x0077E390 (FUN_0077E390 -- `MakeRRef<moho::CDecalHandle>`; formerly `gpg::RRef_CDecalHandle`.)
   * Address: 0x0077E540 (FUN_0077E540 -- `MakeRRef<moho::CDecalHandle*>`; formerly `gpg::RRef_CDecalHandle_P`.)
   * Address: 0x0078B020 (FUN_0078B020 -- `MakeRRef<moho::EMauiScrollAxis>`; formerly `gpg::RRef_EMauiScrollAxis`.)
   * Address: 0x0078E880 (FUN_0078E880 -- `MakeRRef<moho::EMauiKeyCode>`; formerly `gpg::RRef_EMauiKeyCode`.)
   * Address: 0x00795E00 (FUN_00795E00 -- `MakeRRef<moho::EMauiEventType>`; formerly `gpg::RRef_EMauiEventType`.)
   * Address: 0x007CB300 (FUN_007CB300 -- `MakeRRef<moho::ENetProtocolType>`; formerly `gpg::RRef_ENetProtocol`.)
   * Address: 0x00831EC0 (FUN_00831EC0 -- `MakeRRef<moho::EUnitCommandType>`; formerly `gpg::RRef_EUnitCommandType`.)
   * Address: 0x0084A6F0 (FUN_0084A6F0 -- `MakeRRef<moho::ESTITargetType>`; formerly `gpg::RRef_ESTITargetType`.)
   * Address: 0x0084ACA0 (FUN_0084ACA0 -- `MakeRRef<moho::ESpecialFileType>`; formerly `gpg::RRef_ESpecialFileType`.)
   * Address: 0x0085FB70 (FUN_0085FB70 -- `MakeRRef<moho::EGenericIconType>`; formerly `gpg::RRef_EGenericIconType`.)
   * Address: 0x00884A10 (FUN_00884A10 -- `MakeRRef<moho::SSessionSaveData>`; formerly `gpg::RRef_SSessionSaveData`.)
   * Address: 0x008E0A60 (FUN_008E0A60 -- `MakeRRef<char>`; formerly `gpg::RRef_char`.)
   * Address: 0x008E0C00 (FUN_008E0C00 -- `MakeRRef<short>`; formerly `gpg::RRef_short`.)
   * Address: 0x008E0DE0 (FUN_008E0DE0 -- `MakeRRef<long>`; formerly `gpg::RRef_long`.)
   * Address: 0x008E0FC0 (FUN_008E0FC0 -- `MakeRRef<signed char>`; formerly `gpg::RRef_schar`.)
   * Address: 0x008E11A0 (FUN_008E11A0 -- `MakeRRef<unsigned short>`; formerly `gpg::RRef_ushort`.)
   * Address: 0x008E1380 (FUN_008E1380 -- `MakeRRef<unsigned long>`; formerly `gpg::RRef_ulong`.)
   * Address: 0x0090B1E0 (FUN_0090B1E0 -- `MakeRRef<lua_State>`; formerly `gpg::RRef_lua_State`.)
   * Address: 0x0091E550 (FUN_0091E550 -- `MakeRRef<TString>`; formerly `gpg::RRef_TString`.)
   * Address: 0x0091E730 (FUN_0091E730 -- `MakeRRef<Table>`; formerly `gpg::RRef_Table`.)
   * Address: 0x0091E900 (FUN_0091E900 -- `MakeRRef<LClosure>`; formerly `gpg::RRef_LClosure`.)
   * Address: 0x0091EAA0 (FUN_0091EAA0 -- `MakeRRef<UpVal>`; formerly `gpg::RRef_UpVal`.)
   * Address: 0x0091EC40 (FUN_0091EC40 -- `MakeRRef<Proto>`; formerly `gpg::RRef_Proto`.)
   * Address: 0x0091EE10 (FUN_0091EE10 -- `MakeRRef<Udata>`; formerly `gpg::RRef_Udata`.)
   * Address: 0x0091F170 (FUN_0091F170 -- `MakeRRef<CClosure>`; formerly `gpg::RRef_CClosure`.)
   *
   * What it does:
   * A reference to `*value` as the object it really is. For a polymorphic
   * `T` whose dynamic type is not `T` itself, the dynamic type is looked up
   * (`detail::RecentRuntimeTypes`), asserted to derive from `T` (`"isDer"`,
   * reflection.h line 458) and the pointer moved back to the start of the
   * whole object; otherwise the reference is `{value, RTypeOf<T>()}` -- for a
   * pointer `T` that is the pointee's `RPointerType`, the reference to a
   * pointer slot.
   */
  template <class T>
  [[nodiscard]] RRef MakeRRef(T* const value)
  {
    using Object = std::remove_cv_t<T>;
    RType* const declared = RTypeOf<Object>();
    auto* const object = const_cast<Object*>(value);
    if constexpr (std::is_polymorphic_v<Object>) {
      if (object != nullptr && typeid(*object) != typeid(Object)) {
        thread_local detail::RecentRuntimeTypes sRecent{};
        RType* const runtime = sRecent.Find(typeid(*object));

        std::int32_t baseOffset = 0;
        if (!runtime->IsDerivedFrom(declared, &baseOffset)) {
          HandleAssertFailure("isDer", 458, "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\reflection.h");
        }
        return RRef{reinterpret_cast<char*>(object) - baseOffset, runtime};
      }
    }
    return RRef{object, declared};
  }

  /**
   * What it does:
   * Reads one element of a reflected container: a value through its own
   * reflected type, owned by the container's owner.
   */
  template <class T>
  void ReadElement(ReadArchive* const archive, T& value, const RRef* const ownerRef)
  {
    archive->Read(RTypeOf<T>(), &value, *ownerRef);
  }

  /**
   * What it does:
   * Reads one raw-pointer element: a tracked pointer the container does not own.
   */
  template <class T>
  void ReadElement(ReadArchive* const archive, T*& value, const RRef* const ownerRef)
  {
    archive->ReadPointer(&value, ownerRef);
  }

  /**
   * What it does:
   * Reads one `boost::shared_ptr` element: a tracked pointer shared through the archive.
   */
  template <class T>
  void ReadElement(ReadArchive* const archive, boost::shared_ptr<T>& value, const RRef* const ownerRef)
  {
    archive->ReadPointerShared(&value, ownerRef);
  }

  /**
   * What it does:
   * Writes one element of a reflected container: a value through its own
   * reflected type, owned by the container's owner.
   */
  template <class T>
  void WriteElement(WriteArchive* const archive, const T& value, const RRef* const ownerRef)
  {
    archive->Write(RTypeOf<T>(), &value, *ownerRef);
  }

  /**
   * What it does:
   * Writes one raw-pointer element as an unowned tracked pointer.
   */
  template <class T>
  void WriteElement(WriteArchive* const archive, T* const& value, const RRef* const ownerRef)
  {
    archive->WritePointer(value, TrackedPointerState::Unowned, *ownerRef);
  }

  /**
   * What it does:
   * Writes one `boost::shared_ptr` element as a shared tracked pointer.
   */
  template <class T>
  void WriteElement(WriteArchive* const archive, const boost::shared_ptr<T>& value, const RRef* const ownerRef)
  {
    archive->WritePointer(value.get(), TrackedPointerState::Shared, *ownerRef);
  }
} // namespace gpg
