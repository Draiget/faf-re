#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <type_traits>
#include <typeinfo>
#include <vector>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"

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
  template <class T>
  struct Vector3;
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
  class IAiFormationDB;
  class IPathTraveler;
  class PathTables;
  class CAiPersonality;
  class CAiFormationInstance;
  class CAiFormationDBImpl;
  class CAiReconDBImpl;
  class CAiSteeringImpl;
  class CAiSiloBuildImpl;
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
  enum EAiTransportEvent : std::int32_t;
  enum EProjectileImpactEvent : int;
  enum class EAiTargetType : std::int32_t;
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
  class CTaskThread;
  struct SPhysConstants;
  struct SPhysBody;
  class SimArmy;
  class CAcquireTargetTask;
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
  class CCommandDb;
  class CUnitMotion;
  class IEffect;
  class IEffectManager;
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
  class EntityCollisionUpdater;
  class EntityMotor;
  class Entity;
  class CollisionBeamEntity;
  class CEntityDb;
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
  using CColPrimitiveBase = EntityCollisionUpdater;
  class SphereCollisionPrimitive;
  class BoxCollisionPrimitive;
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
  struct SerHelperBase
  {
    SerHelperBase* mNext;
    SerHelperBase* mPrev;

    /**
     * Address: 0x00402400 (FUN_00402400, gpg::SerHelperBase::SerHelperBase)
     *
     * What it does:
     * Unlinks this helper node from its current intrusive list links and then
     * rewires it to a self-linked singleton.
     */
    SerHelperBase();

    /**
     * Address: 0x004027D0 (FUN_004027D0, duplicate self-link helper)
     *
     * What it does:
     * Performs the same unlink-and-self-link sequence as the constructor.
     */
    void ResetLinks();

    /**
     * Address: 0x00953BE0 caller lane (`gpg::WriteArchive::WriteArchive`)
     *
     * What it does:
     * Ensures serializer helper bootstrap lanes are initialized before
     * write-archive save paths run.
     */
    static void InitNewHelpers();
  };
  static_assert(sizeof(SerHelperBase) == 0x8, "SerHelperBase size must be 0x8");

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
    const RIndexed* IsPointer() const;       // 0x004CC9E0
    int GetNumBases() const;                 // gpgcore.dll
    RRef GetBase(int ind) const;             // gpgcore.dll
    int GetNumFields() const;                // 0x004CC9B0
    RRef GetField(int ind) const;            // gpgcore.dll
    const char* GetFieldName(int ind) const; // gpgcore.dll
    void Delete();                           // 0x008D8800

    /**
     * Address: 0x004C1690 (FUN_004C1690, gpg::RRef::CastLuaState)
     *
     * What it does:
     * Upcasts this reflected reference to `LuaPlus::LuaState` and returns null
     * when the runtime type is not LuaState-compatible.
     */
    [[nodiscard]] LuaPlus::LuaState* CastLuaState();

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

  inline TypeVec& GetRTypeVec()
  {
    static TypeVec gVec;
    return gVec;
  }

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
   * Address: 0x008E0810 (FUN_008E0810, gpg::REF_RegisterAllTypes)
   * Address: 0x1001CEB0 (gpgcore.dll)
   *
   * What it does:
   * Forces lazy registration for all preregistered RTTI entries.
   */
  void REF_RegisterAllTypes();

  /**
   * Address: 0x10018CB0 (gpgcore.dll)
   *
   * int
   *
   * What it does:
   * Returns the type descriptor at an index in the global registration vector.
   */
  const RType* REF_GetTypeIndexed(int index);

  /**
   * Address: 0x008DF8A0
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
   * Address: 0x00403020 (FUN_00403020, gpg::RRef_uint)
   *
   * What it does:
   * Builds a reflected reference for an `unsigned int` object pointer.
   */
  RRef* RRef_uint(RRef* out, unsigned int* value);

  /**
   * Address: 0x00583450 (FUN_00583450, gpg::RRef_int)
   *
   * What it does:
   * Builds a reflected reference for one `int` value pointer.
   */
  RRef* RRef_int(RRef* out, int* value);

  /**
   * Address: 0x00526FD0 (FUN_00526FD0, gpg::RRef_float)
   *
   * What it does:
   * Builds a reflected reference for one `float` value pointer.
   */
  RRef* RRef_float(RRef* out, float* value);

  /**
   * Address: 0x005832B0 (FUN_005832B0, gpg::RRef_bool)
   *
   * What it does:
   * Builds a reflected reference for one `bool` value pointer.
   */
  RRef* RRef_bool(RRef* out, bool* value);

  /**
   * Address: 0x00642860 (FUN_00642860, gpg::RRef__Vb_reference)
   *
   * What it does:
   * Builds a reflected reference for one legacy `std::vector<bool>::reference`
   * proxy value pointer.
   */
  RRef* RRef_VectorBoolReference(RRef* out, std::vector<bool>::reference* value);

  /**
   * Address: 0x00517940 (FUN_00517940, gpg::RRef_Vector3f)
   *
   * What it does:
   * Builds a reflected reference for one `Wm3::Vector3f` object pointer.
   */
  RRef* RRef_Vector3f(RRef* out, Wm3::Vector3f* value);

  /**
   * Address: 0x00513760 (FUN_00513760, gpg::RRef_string)
   *
   * What it does:
   * Builds a reflected reference for one `msvc8::string` value pointer.
   */
  RRef* RRef_string(RRef* out, msvc8::string* value);

  /**
   * Address: 0x008E0A60 (FUN_008E0A60, gpg::RRef_char)
   *
   * What it does:
   * Builds a reflected reference for one `char` value pointer.
   */
  RRef* RRef_char(RRef* out, char* value);

  /**
   * Address: 0x008E0C00 (FUN_008E0C00, gpg::RRef_short)
   *
   * What it does:
   * Builds a reflected reference for one `short` value pointer.
   */
  RRef* RRef_short(RRef* out, short* value);

  /**
   * Address: 0x008E0DE0 (FUN_008E0DE0, gpg::RRef_long)
   *
   * What it does:
   * Builds a reflected reference for one `long` value pointer.
   */
  RRef* RRef_long(RRef* out, long* value);

  /**
   * Address: 0x008E0FC0 (FUN_008E0FC0, gpg::RRef_schar)
   *
   * What it does:
   * Builds a reflected reference for one signed-byte value pointer.
   */
  RRef* RRef_schar(RRef* out, signed char* value);

  /**
   * Address: 0x00736A30 (FUN_00736A30, gpg::RRef_uchar)
   *
   * What it does:
   * Builds a reflected reference for one `unsigned char` value pointer.
   */
  RRef* RRef_uchar(RRef* out, unsigned char* value);

  /**
   * Address: 0x008E11A0 (FUN_008E11A0, gpg::RRef_ushort)
   *
   * What it does:
   * Builds a reflected reference for one `unsigned short` value pointer.
   */
  RRef* RRef_ushort(RRef* out, unsigned short* value);

  /**
   * Address: 0x008E1380 (FUN_008E1380, gpg::RRef_ulong)
   *
   * What it does:
   * Builds a reflected reference for one `unsigned long` value pointer.
   */
  RRef* RRef_ulong(RRef* out, unsigned long* value);

  /**
   * Address: 0x00402D30 (FUN_00402D30, sub_402D30)
   *
   * What it does:
   * Wrapper that assigns `RRef_uint` output lanes into the provided `RRef`.
   */
  RRef* AssignUIntRef(RRef* out, unsigned int* value);

  /**
   * Address: 0x00593520 (FUN_00593520, gpg::RRef_EEconResource)
   *
   * What it does:
   * Builds a reflected reference for one `moho::EEconResource` value pointer.
   */
  RRef* RRef_EEconResource(RRef* out, moho::EEconResource* value);

  /**
   * Address: 0x005937D0 (FUN_005937D0, gpg::RRef_EAlliance)
   *
   * What it does:
   * Builds a reflected reference for one `moho::EAlliance` value pointer.
   */
  RRef* RRef_EAlliance(RRef* out, moho::EAlliance* value);

  /**
   * Address: 0x00593BC0 (FUN_00593BC0, gpg::RRef_ESquadClass)
   *
   * What it does:
   * Builds a reflected reference for one `moho::ESquadClass` value pointer.
   */
  RRef* RRef_ESquadClass(RRef* out, moho::ESquadClass* value);

  /**
   * Address: 0x00593380 (FUN_00593380, gpg::RRef_ETriggerOperator)
   *
   * What it does:
   * Builds a reflected reference for one `moho::ETriggerOperator` value pointer.
   */
  RRef* RRef_ETriggerOperator(RRef* out, moho::ETriggerOperator* value);

  /**
   * Address: 0x00593D60 (FUN_00593D60, gpg::RRef_ECompareType)
   *
   * What it does:
   * Builds a reflected reference for one `moho::ECompareType` value pointer.
   */
  RRef* RRef_ECompareType(RRef* out, moho::ECompareType* value);

  /**
   * Address: 0x005CB020 (FUN_005CB020, gpg::RRef_EReconFlags)
   *
   * What it does:
   * Builds a reflected reference for one `moho::EReconFlags` value pointer.
   */
  RRef* RRef_EReconFlags(RRef* out, moho::EReconFlags* value);

  /**
   * Address: 0x005E3660 (FUN_005E3660, gpg::RRef_EAiTargetType)
   *
   * What it does:
   * Builds a reflected reference for one `moho::EAiTargetType` value pointer.
   */
  RRef* RRef_EAiTargetType(RRef* out, moho::EAiTargetType* value);

  /**
   * Address: 0x00704040 (FUN_00704040, sub_704040)
   *
   * What it does:
   * Wrapper that assigns `RRef_ESquadClass` output lanes into provided `RRef`.
   */
  RRef* AssignESquadClassRef(RRef* out, moho::ESquadClass* value);

  /**
   * Address: 0x0078B020 (FUN_0078B020, gpg::RRef_EMauiScrollAxis)
   *
   * What it does:
   * Builds a reflected reference for one `moho::EMauiScrollAxis` value pointer.
   */
  RRef* RRef_EMauiScrollAxis(RRef* out, moho::EMauiScrollAxis* value);

  /**
   * Address: 0x0078E880 (FUN_0078E880, gpg::RRef_EMauiKeyCode)
   *
   * What it does:
   * Builds a reflected reference for one `moho::EMauiKeyCode` value pointer.
   */
  RRef* RRef_EMauiKeyCode(RRef* out, moho::EMauiKeyCode* value);

  /**
   * Address: 0x00795E00 (FUN_00795E00, gpg::RRef_EMauiEventType)
   *
   * What it does:
   * Builds a reflected reference for one `moho::EMauiEventType` value pointer.
   */
  RRef* RRef_EMauiEventType(RRef* out, moho::EMauiEventType* value);

  /**
   * Address: 0x00831EC0 (FUN_00831EC0, gpg::RRef_EUnitCommandType)
   *
   * What it does:
   * Builds a reflected reference for one `moho::EUnitCommandType` value pointer.
   */
  RRef* RRef_EUnitCommandType(RRef* out, moho::EUnitCommandType* value);

  /**
   * Address: 0x0060D7A0 (FUN_0060D7A0, gpg::RRef_EAiResult)
   *
   * What it does:
   * Builds a reflected reference for one `moho::EAiResult` value pointer.
   */
  RRef* RRef_EAiResult(RRef* out, moho::EAiResult* value);

  /**
   * Address: 0x00692DB0 (FUN_00692DB0, gpg::RRef_EVisibilityMode)
   *
   * What it does:
   * Builds a reflected reference for one `moho::EVisibilityMode` value pointer.
   */
  RRef* RRef_EVisibilityMode(RRef* out, moho::EVisibilityMode* value);

  /**
   * Address: 0x006B1C90 (FUN_006B1C90, gpg::RRef_EUnitState)
   *
   * What it does:
   * Builds a reflected reference for one `moho::EUnitState` value pointer.
   */
  RRef* RRef_EUnitState(RRef* out, moho::EUnitState* value);

  /**
   * Address: 0x006D2150 (FUN_006D2150, gpg::RRef_EFireState)
   *
   * What it does:
   * Builds a reflected reference for one `moho::EFireState` value pointer.
   */
  RRef* RRef_EFireState(RRef* out, moho::EFireState* value);

  /**
   * Address: 0x006DD790 (FUN_006DD790, gpg::RRef_ELayer)
   *
   * What it does:
   * Builds a reflected reference for one `moho::ELayer` value pointer.
   */
  RRef* RRef_ELayer(RRef* out, moho::ELayer* value);

  /**
   * Address: 0x007CB300 (FUN_007CB300, gpg::RRef_ENetProtocol)
   *
   * What it does:
   * Builds a reflected reference for one network protocol enum lane
   * (`moho::ENetProtocolType`, binary symbol tag `ENetProtocol`).
   */
  RRef* RRef_ENetProtocol(RRef* out, moho::ENetProtocolType* value);

  /**
   * Address: 0x00692F50 (FUN_00692F50, gpg::RRef_EIntel)
   *
   * What it does:
   * Builds a reflected reference for one `moho::EIntel` value pointer.
   */
  RRef* RRef_EIntel(RRef* out, moho::EIntel* value);

  /**
   * Address: 0x00593F00 (FUN_00593F00, gpg::RRef_EThreatType)
   *
   * What it does:
   * Builds a reflected reference for one `moho::EThreatType` value pointer.
   */
  RRef* RRef_EThreatType(RRef* out, moho::EThreatType* value);

  /**
   * Address: 0x006D1FB0 (FUN_006D1FB0, gpg::RRef_ERuleBPUnitToggleCaps)
   *
   * What it does:
   * Builds a reflected reference for one `moho::ERuleBPUnitToggleCaps` value pointer.
   */
  RRef* RRef_ERuleBPUnitToggleCaps(RRef* out, moho::ERuleBPUnitToggleCaps* value);

  /**
   * Address: 0x006D22F0 (FUN_006D22F0, gpg::RRef_ERuleBPUnitCommandCaps)
   *
   * What it does:
   * Builds a reflected reference for one `moho::ERuleBPUnitCommandCaps` value pointer.
   */
  RRef* RRef_ERuleBPUnitCommandCaps(RRef* out, moho::ERuleBPUnitCommandCaps* value);

  /**
   * Address: 0x0084ACA0 (FUN_0084ACA0, gpg::RRef_ESpecialFileType)
   *
   * What it does:
   * Builds a reflected reference for one `moho::ESpecialFileType` value pointer.
   */
  RRef* RRef_ESpecialFileType(RRef* out, moho::ESpecialFileType* value);

  /**
   * Address: 0x0085FB70 (FUN_0085FB70, gpg::RRef_EGenericIconType)
   *
   * What it does:
   * Builds a reflected reference for one `moho::EGenericIconType` value pointer.
   */
  RRef* RRef_EGenericIconType(RRef* out, moho::EGenericIconType* value);

  /**
   * Address: 0x0040C030 (FUN_0040C030, gpg::RRef_CTaskThread_P)
   *
   * What it does:
   * Builds a reflected reference for a `moho::CTaskThread` object pointer.
   */
  RRef* RRef_CTaskThread(RRef* out, moho::CTaskThread* value);

  /**
   * Address: 0x0063A2B0 (FUN_0063A2B0, gpg::RRef_CFootPlantManipulator)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CFootPlantManipulator`
   * object pointer with derived-type normalization.
   */
  RRef* RRef_CFootPlantManipulator(RRef* out, moho::CFootPlantManipulator* value);

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
   * Address: 0x0063D230 (FUN_0063D230, gpg::RRef_CAniActor)
   *
   * What it does:
   * Builds a reflected reference for a `moho::CAniActor` object pointer with
   * derived-type normalization.
   */
  RRef* RRef_CAniActor(RRef* out, moho::CAniActor* value);

  /**
   * Address: 0x0063D3F0 (FUN_0063D3F0, gpg::RRef_IAniManipulator)
   *
   * What it does:
   * Builds a reflected reference for one `moho::IAniManipulator` object
   * pointer with derived-type normalization.
   */
  RRef* RRef_IAniManipulator(RRef* out, moho::IAniManipulator* value);

  /**
   * Address: 0x0063D800 (FUN_0063D800, gpg::RRef_SAniManipBinding)
   *
   * What it does:
   * Builds a reflected reference for one `moho::SAniManipBinding` value
   * pointer.
   */
  RRef* RRef_SAniManipBinding(RRef* out, moho::SAniManipBinding* value);

  /**
   * Address: 0x0063D5A0 (FUN_0063D5A0, gpg::RRef_IAniManipulator_P)
   *
   * What it does:
   * Builds a reflected reference for one `moho::IAniManipulator*` slot.
   */
  RRef* RRef_IAniManipulator_P(RRef* out, moho::IAniManipulator** value);

  /**
   * Address: 0x005E04D0 (FUN_005E04D0, gpg::RRef_CAcquireTargetTask)
   *
   * What it does:
   * Builds a reflected reference for a `moho::CAcquireTargetTask` object
   * pointer with derived-type normalization.
   */
  RRef* RRef_CAcquireTargetTask(RRef* out, moho::CAcquireTargetTask* value);

  /**
   * Address: 0x006DED40 (FUN_006DED40, gpg::RRef_CFireWeaponTask)
   *
   * What it does:
   * Builds a reflected reference for a `moho::CFireWeaponTask` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_CFireWeaponTask(RRef* out, moho::CFireWeaponTask* value);

  /**
   * Address: 0x006A00F0 (FUN_006A00F0, gpg::RRef_ManyToOneListener_EProjectileImpactEvent)
   *
   * What it does:
   * Builds a reflected reference for one `ManyToOneListener<EProjectileImpactEvent>`
   * object pointer.
   */
  RRef* RRef_ManyToOneListener_EProjectileImpactEvent(
    RRef* out,
    moho::ManyToOneListener<moho::EProjectileImpactEvent>* value
  );

  /**
   * Address: 0x005E08D0 (FUN_005E08D0, gpg::RRef_CAcquireTargetTask_P)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CAcquireTargetTask*` slot.
   */
  RRef* RRef_CAcquireTargetTask_P(RRef* out, moho::CAcquireTargetTask** value);

  /**
   * Address: 0x0059E080 (FUN_0059E080, gpg::RRef_IFormationInstance_P)
   *
   * What it does:
   * Builds a reflected reference for one `moho::IFormationInstance*` slot.
   */
  RRef* RRef_IFormationInstance_P(RRef* out, moho::IFormationInstance** value);

  /**
   * Address: 0x0066C650 (FUN_0066C650, gpg::RRef_IEffect)
   *
   * What it does:
   * Builds a reflected reference for a `moho::IEffect` object pointer with
   * derived-type normalization.
   */
  RRef* RRef_IEffect(RRef* out, moho::IEffect* value);

  /**
   * Address: 0x00658860 (FUN_00658860, gpg::RRef_CEfxBeam)
   *
   * What it does:
   * Builds a reflected reference for a `moho::CEfxBeam` object pointer with
   * derived-type normalization.
   */
  RRef* RRef_CEfxBeam(RRef* out, moho::CEfxBeam* value);

  /**
   * Address: 0x0065ADC0 (FUN_0065ADC0, gpg::RRef_CountedPtr_CParticleTexture)
   *
   * What it does:
   * Builds a reflected reference for one counted particle-texture pointer
   * wrapper.
   */
  RRef* RRef_CountedPtr_CParticleTexture(RRef* out, moho::CountedPtr<moho::CParticleTexture>* value);

  /**
   * Address: 0x0065FCF0 (FUN_0065FCF0, gpg::RRef_SEfxCurve)
   *
   * What it does:
   * Builds a reflected reference for one `moho::SEfxCurve` value pointer.
   */
  RRef* RRef_SEfxCurve(RRef* out, moho::SEfxCurve* value);

  /**
   * Address: 0x0065FF20 (FUN_0065FF20, gpg::RRef_CEfxEmitter)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CEfxEmitter` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_CEfxEmitter(RRef* out, moho::CEfxEmitter* value);

  /**
   * Address: 0x00672560 (FUN_00672560, gpg::RRef_CEfxTrailEmitter)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CEfxTrailEmitter` object
   * pointer with derived-type normalization.
   */
  RRef* RRef_CEfxTrailEmitter(RRef* out, moho::CEfxTrailEmitter* value);

  /**
   * Address: 0x0066C800 (FUN_0066C800, gpg::RRef_IEffect_P)
   *
   * What it does:
   * Builds a reflected reference for one `moho::IEffect*` slot.
   */
  RRef* RRef_IEffect_P(RRef* out, moho::IEffect** value);

  /**
   * Address: 0x0054EA20 (FUN_0054EA20, gpg::RRef_CAniPose)
   *
   * What it does:
   * Builds a reflected reference for a `moho::CAniPose` object pointer with
   * derived-type normalization.
   */
  RRef* RRef_CAniPose(RRef* out, moho::CAniPose* value);

  /**
   * Address: 0x0054E690 (FUN_0054E690, gpg::RRef_CAniPoseBone)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CAniPoseBone` value pointer.
   */
  RRef* RRef_CAniPoseBone(RRef* out, moho::CAniPoseBone* value);

  /**
   * Address: 0x0063EAD0 (FUN_0063EAD0, gpg::RRef_shared_ptr_CAniPose)
   *
   * What it does:
   * Builds a reflected reference for one `boost::shared_ptr<moho::CAniPose>`
   * value pointer.
   */
  RRef* RRef_shared_ptr_CAniPose(RRef* out, boost::shared_ptr<moho::CAniPose>* value);

  /**
   * Address: 0x004C8C30 (FUN_004C8C30, gpg::RRef_CScriptObject_P)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CScriptObject*` slot.
   */
  RRef* RRef_CScriptObject_P(RRef* out, moho::CScriptObject** value);

  /**
   * Address: 0x004CC040 (FUN_004CC040, gpg::RRef_CScriptEvent)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CScriptEvent` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_CScriptEvent(RRef* out, moho::CScriptEvent* value);

  /**
   * Address: 0x004CBB60 (FUN_004CBB60, gpg::RRef_CLuaTask)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CLuaTask` object pointer with
   * derived-type normalization.
   */
  RRef* RRef_CLuaTask(RRef* out, moho::CLuaTask* value);

  /**
   * Address: 0x004CBE70 (FUN_004CBE70, gpg::RRef_CWaitForTask)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CWaitForTask` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_CWaitForTask(RRef* out, moho::CWaitForTask* value);

  /**
   * Address: 0x004E5730 (FUN_004E5730, gpg::RRef_CSndParams)
   *
   * What it does:
   * Builds a reflected reference for a `moho::CSndParams` object pointer with
   * derived-type normalization.
   */
  RRef* RRef_CSndParams(RRef* out, moho::CSndParams* value);

  /**
   * Address: 0x004E6200 (FUN_004E6200, gpg::RRef_CSndParams_P)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CSndParams*` slot.
   */
  RRef* RRef_CSndParams_P(RRef* out, moho::CSndParams** value);

  /**
   * Address: 0x004E5590 (FUN_004E5590, gpg::RRef_CSndVar)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CSndVar` object pointer with
   * derived-type normalization.
   */
  RRef* RRef_CSndVar(RRef* out, moho::CSndVar* value);

  /**
   * Address: 0x004E6720 (FUN_004E6720, gpg::RRef_HSound)
   *
   * What it does:
   * Builds a reflected reference for one `moho::HSound` object pointer with
   * derived-type normalization.
   */
  RRef* RRef_HSound(RRef* out, moho::HSound* value);

  /**
   * Address: 0x00758B00 (FUN_00758B00, gpg::RRef_ISoundManager)
   *
   * What it does:
   * Builds a reflected reference for one `moho::ISoundManager` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_ISoundManager(RRef* out, moho::ISoundManager* value);

  /**
   * Address: 0x00762890 (FUN_00762890, gpg::RRef_SAudioRequest)
   *
   * What it does:
   * Builds a reflected reference for one `moho::SAudioRequest` object pointer.
   */
  RRef* RRef_SAudioRequest(RRef* out, moho::SAudioRequest* value);

  /**
   * Address: 0x006805E0 (FUN_006805E0, gpg::RRef_Entity)
   *
   * What it does:
   * Builds a reflected reference for a `moho::Entity` object pointer with
   * derived-type normalization.
   */
  RRef* RRef_Entity(RRef* out, moho::Entity* value);

  /**
   * Address: 0x00675DB0 (FUN_00675DB0, gpg::RRef_CollisionBeamEntity)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CollisionBeamEntity` object
   * pointer with cached derived-type normalization.
   */
  RRef* RRef_CollisionBeamEntity(RRef* out, moho::CollisionBeamEntity* value);

  /**
   * Address: 0x006755A0 (FUN_006755A0, helper lane)
   *
   * What it does:
   * Materializes a temporary `RRef_CollisionBeamEntity` and copies its object
   * and type lanes into the destination reference.
   */
  RRef* AssignCollisionBeamEntityRef(RRef* out, moho::CollisionBeamEntity* value);

  /**
   * Address: 0x006FAF20 (FUN_006FAF20, gpg::RRef_Prop)
   *
   * What it does:
   * Builds a reflected reference for one `moho::Prop` object pointer with
   * derived-type normalization.
   */
  RRef* RRef_Prop(RRef* out, moho::Prop* value);

  /**
   * Address: 0x005541F0 (FUN_005541F0, gpg::RRef_EntId)
   *
   * What it does:
   * Builds a reflected reference for one entity-id scalar lane.
   */
  RRef* RRef_EntId(RRef* out, std::int32_t* value);

  /**
   * Address: 0x006807B0 (FUN_006807B0, gpg::RRef_Entity_P)
   *
   * What it does:
   * Builds a reflected reference for one `moho::Entity*` slot.
   */
  RRef* RRef_Entity_P(RRef* out, moho::Entity** value);

  /**
   * Address: 0x006B21E0 (FUN_006B21E0, gpg::RRef_WeakPtr_Entity)
   *
   * What it does:
   * Builds a reflected reference for one `WeakPtr<Entity>` wrapper value.
   */
  RRef* RRef_WeakPtr_Entity(RRef* out, moho::WeakPtr<moho::Entity>* value);

  /**
   * Address: 0x00689360 (FUN_00689360, gpg::RRef_EntityDB)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CEntityDb` object pointer with
   * derived-type normalization.
   */
  RRef* RRef_EntityDB(RRef* out, moho::CEntityDb* value);

  /**
   * Address: 0x00689920 (FUN_00689920, gpg::RRef_EntitySetBase)
   *
   * What it does:
   * Builds a reflected reference for one `moho::EntitySetBase` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_EntitySetBase(RRef* out, moho::EntitySetBase* value);

  /**
   * Address: 0x00698D80 (FUN_00698D80, gpg::RRef_SPhysConstants)
   *
   * What it does:
   * Builds a reflected reference for one `moho::SPhysConstants` value pointer.
   */
  RRef* RRef_SPhysConstants(RRef* out, moho::SPhysConstants* value);

  /**
   * Address: 0x006837E0 (FUN_006837E0, gpg::RRef_SPhysBody)
   *
   * What it does:
   * Builds a reflected reference for one `moho::SPhysBody` value pointer.
   */
  RRef* RRef_SPhysBody(RRef* out, moho::SPhysBody* value);

  /**
   * Address: 0x005A2A40 (FUN_005A2A40, gpg::RRef_Unit)
   *
   * What it does:
   * Builds a reflected reference for a `moho::Unit` object pointer with
   * derived-type normalization.
   */
  RRef* RRef_Unit(RRef* out, moho::Unit* value);

  /**
   * Address: 0x00541C50 (FUN_00541C50, gpg::RRef_IUnit)
   *
   * What it does:
   * Builds a reflected reference for a `moho::IUnit` object pointer with
   * derived-type normalization.
   */
  RRef* RRef_IUnit(RRef* out, moho::IUnit* value);

  /**
   * Address: 0x005725F0 (FUN_005725F0, gpg::RRef_WeakPtr_IUnit)
   *
   * What it does:
   * Builds a reflected reference for one `WeakPtr<IUnit>` wrapper value.
   */
  RRef* RRef_WeakPtr_IUnit(RRef* out, moho::WeakPtr<moho::IUnit>* value);

  /**
   * Address: 0x00526C80 (FUN_00526C80, gpg::RRef_RUnitBlueprint)
   *
   * What it does:
   * Builds a reflected reference for a `moho::RUnitBlueprint` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_RUnitBlueprint(RRef* out, moho::RUnitBlueprint* value);

  /**
   * Address: 0x0050E2A0 (FUN_0050E2A0, gpg::RRef_RBlueprint)
   *
   * What it does:
   * Builds a reflected reference for one `moho::RBlueprint` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_RBlueprint(RRef* out, moho::RBlueprint* value);

  /**
   * Address: 0x00557BD0 (FUN_00557BD0, gpg::RRef_RBlueprint_P)
   *
   * What it does:
   * Builds a reflected reference for one `moho::RBlueprint*` slot.
   */
  RRef* RRef_RBlueprint_P(RRef* out, moho::RBlueprint** value);

  /**
   * Address: 0x005A22A0 (FUN_005A22A0, gpg::RRef_RUnitBlueprint_P)
   *
   * What it does:
   * Builds a reflected reference for one `moho::RUnitBlueprint*` slot.
   */
  RRef* RRef_RUnitBlueprint_P(RRef* out, moho::RUnitBlueprint** value);

  /**
   * Address: 0x00526E30 (FUN_00526E30, gpg::RRef_RUnitBlueprintWeapon)
   *
   * What it does:
   * Builds a reflected reference for one `moho::RUnitBlueprintWeapon` value
   * pointer.
   */
  RRef* RRef_RUnitBlueprintWeapon(RRef* out, moho::RUnitBlueprintWeapon* value);

  /**
   * Address: 0x00511940 (FUN_00511940, gpg::RRef_RRuleGameRules)
   *
   * What it does:
   * Builds a reflected reference for a `moho::RRuleGameRules` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_RRuleGameRules(RRef* out, moho::RRuleGameRules* value);

  /**
   * Address: 0x00536BA0 (FUN_00536BA0, gpg::RRef_SRuleFootprintsBlueprint)
   *
   * What it does:
   * Builds a reflected reference for one `moho::SRuleFootprintsBlueprint`
   * value pointer.
   */
  RRef* RRef_SRuleFootprintsBlueprint(RRef* out, moho::SRuleFootprintsBlueprint* value);

  /**
   * Address: 0x0055AB70 (FUN_0055AB70, gpg::RRef_RScmResource)
   *
   * What it does:
   * Builds a reflected reference for one `moho::RScmResource` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_RScmResource(RRef* out, moho::RScmResource* value);

  /**
   * Address: 0x00549200 (FUN_00549200, gpg::RRef_ResourceDeposit)
   *
   * What it does:
   * Builds a reflected reference for one `moho::ResourceDeposit` value
   * pointer.
   */
  RRef* RRef_ResourceDeposit(RRef* out, moho::ResourceDeposit* value);

  /**
   * Address: 0x00511250 (FUN_00511250, gpg::RRef_REmitterBlueprint)
   *
   * What it does:
   * Builds a reflected reference for one `moho::REmitterBlueprint` object
   * pointer with derived-type normalization.
   */
  RRef* RRef_REmitterBlueprint(RRef* out, moho::REmitterBlueprint* value);

  /**
   * Address: 0x00517AE0 (FUN_00517AE0, gpg::RRef_REmitterCurveKey)
   *
   * What it does:
   * Builds a reflected reference for one `moho::REmitterCurveKey` object
   * pointer with derived-type normalization.
   */
  RRef* RRef_REmitterCurveKey(RRef* out, moho::REmitterCurveKey* value);

  /**
   * Address: 0x00517D20 (FUN_00517D20, gpg::RRef_REmitterBlueprintCurve)
   *
   * What it does:
   * Builds a reflected reference for one `moho::REmitterBlueprintCurve` object
   * pointer with derived-type normalization.
   */
  RRef* RRef_REmitterBlueprintCurve(RRef* out, moho::REmitterBlueprintCurve* value);

  /**
   * Address: 0x005115B0 (FUN_005115B0, gpg::RRef_RBeamBlueprint)
   *
   * What it does:
   * Builds a reflected reference for one `moho::RBeamBlueprint` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_RBeamBlueprint(RRef* out, moho::RBeamBlueprint* value);

  /**
   * Address: 0x00511400 (FUN_00511400, gpg::RRef_RTrailBlueprint)
   *
   * What it does:
   * Builds a reflected reference for one `moho::RTrailBlueprint` object
   * pointer with derived-type normalization.
   */
  RRef* RRef_RTrailBlueprint(RRef* out, moho::RTrailBlueprint* value);

  /**
   * Address: 0x0051CFF0 (FUN_0051CFF0, gpg::RRef_RProjectileBlueprint)
   *
   * What it does:
   * Builds a reflected reference for one `moho::RProjectileBlueprint` object
   * pointer with derived-type normalization.
   */
  RRef* RRef_RProjectileBlueprint(RRef* out, moho::RProjectileBlueprint* value);

  /**
   * Address: 0x0051AAE0 (FUN_0051AAE0, gpg::RRef_RMeshBlueprint)
   *
   * What it does:
   * Builds a reflected reference for one `moho::RMeshBlueprint` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_RMeshBlueprint(RRef* out, moho::RMeshBlueprint* value);

  /**
   * Address: 0x0051AC90 (FUN_0051AC90, gpg::RRef_RMeshBlueprintLOD)
   *
   * What it does:
   * Builds a reflected reference for one `moho::RMeshBlueprintLOD` value
   * pointer.
   */
  RRef* RRef_RMeshBlueprintLOD(RRef* out, moho::RMeshBlueprintLOD* value);

  /**
   * Address: 0x0051E130 (FUN_0051E130, gpg::RRef_RPropBlueprint)
   *
   * What it does:
   * Builds a reflected reference for one `moho::RPropBlueprint` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_RPropBlueprint(RRef* out, moho::RPropBlueprint* value);

  /**
   * Address: 0x00500730 (FUN_00500730, gpg::RRef_CColPrimitive_Sphere3f)
   *
   * What it does:
   * Builds a reflected reference for one sphere collision-primitive object
   * pointer with derived-type normalization.
   */
  RRef* RRef_CColPrimitive_Sphere3f(RRef* out, moho::SphereCollisionPrimitive* value);

  /**
   * Address: 0x005008E0 (FUN_005008E0, gpg::RRef_CColPrimitive_Box3f)
   *
   * What it does:
   * Builds a reflected reference for one box collision-primitive object
   * pointer with derived-type normalization.
   */
  RRef* RRef_CColPrimitive_Box3f(RRef* out, moho::BoxCollisionPrimitive* value);

  /**
   * Address: 0x00537250 (FUN_00537250, gpg::RRef_EntityCategory)
   *
   * What it does:
   * Builds a reflected reference for one `moho::EntityCategorySet` object
   * pointer with derived-type normalization.
   */
  RRef* RRef_EntityCategory(RRef* out, moho::EntityCategorySet* value);

  /**
   * Address: 0x005ACE80 (FUN_005ACE80, gpg::RRef_COGrid)
   *
   * What it does:
   * Builds a reflected reference for a `moho::COGrid` object pointer with
   * derived-type normalization.
   */
  RRef* RRef_COGrid(RRef* out, moho::COGrid* value);

  /**
   * Address: 0x005852B0 (FUN_005852B0, gpg::RRef_SimArmy)
   *
   * What it does:
   * Builds a reflected reference for a `moho::SimArmy` object pointer with
   * derived-type normalization.
   */
  RRef* RRef_SimArmy(RRef* out, moho::SimArmy* value);

  /**
   * Address: 0x007057D0 (FUN_007057D0, gpg::RRef_CArmyImpl)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CArmyImpl` object pointer with
   * derived-type normalization.
   */
  RRef* RRef_CArmyImpl(RRef* out, moho::CArmyImpl* value);

  /**
   * Address: 0x00753910 (FUN_00753910, gpg::RRef_SimArmy_P)
   *
   * What it does:
   * Builds a reflected reference for one `moho::SimArmy*` slot.
   */
  RRef* RRef_SimArmy_P(RRef* out, moho::SimArmy** value);

  /**
   * Address: 0x00544EE0 (FUN_00544EE0, gpg::RRef_LaunchInfoNew)
   *
   * What it does:
   * Builds a reflected reference for one `moho::LaunchInfoNew` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_LaunchInfoNew(RRef* out, moho::LaunchInfoNew* value);

  /**
   * Address: 0x00544C80 (FUN_00544C80, gpg::RRef_ArmyLaunchInfo)
   *
   * What it does:
   * Builds a reflected reference for one `moho::ArmyLaunchInfo` value pointer.
   */
  RRef* RRef_ArmyLaunchInfo(RRef* out, moho::ArmyLaunchInfo* value);

  /**
   * Address: 0x00549550 (FUN_00549550, gpg::RRef_CSimResources)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CSimResources` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_CSimResources(RRef* out, moho::CSimResources* value);

  /**
   * Address: 0x00582B50 (FUN_00582B50, gpg::RRef_CAiBrain)
   *
   * What it does:
   * Builds a reflected reference for a `moho::CAiBrain` object pointer with
   * derived-type normalization.
   */
  RRef* RRef_CAiBrain(RRef* out, moho::CAiBrain* value);

  /**
   * Address: 0x005854A0 (FUN_005854A0, gpg::RRef_CAiPersonality)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CAiPersonality` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_CAiPersonality(RRef* out, moho::CAiPersonality* value);

  /**
   * Address: 0x005A2030 (FUN_005A2030, gpg::RRef_CAiBuilderImpl)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CAiBuilderImpl` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_CAiBuilderImpl(RRef* out, moho::CAiBuilderImpl* value);

  /**
   * Address: 0x0059E2E0 (FUN_0059E2E0, gpg::RRef_CAiFormationInstance)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CAiFormationInstance` object
   * pointer with derived-type normalization.
   */
  RRef* RRef_CAiFormationInstance(RRef* out, moho::CAiFormationInstance* value);

  /**
   * Address: 0x0059E490 (FUN_0059E490, gpg::RRef_CAiFormationDBImpl)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CAiFormationDBImpl` object
   * pointer with derived-type normalization.
   */
  RRef* RRef_CAiFormationDBImpl(RRef* out, moho::CAiFormationDBImpl* value);

  /**
   * Address: 0x005A85D0 (FUN_005A85D0, gpg::RRef_CAiNavigatorLand)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CAiNavigatorLand` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_CAiNavigatorLand(RRef* out, moho::CAiNavigatorLand* value);

  /**
   * Address: 0x005A87A0 (FUN_005A87A0, gpg::RRef_CAiNavigatorAir)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CAiNavigatorAir` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_CAiNavigatorAir(RRef* out, moho::CAiNavigatorAir* value);

  /**
   * Address: 0x005A9A40 (FUN_005A9A40, gpg::RRef_CAiPathNavigator)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CAiPathNavigator` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_CAiPathNavigator(RRef* out, moho::CAiPathNavigator* value);

  /**
   * Address: 0x005ABD20 (FUN_005ABD20, gpg::RRef_CAiPathFinder)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CAiPathFinder` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_CAiPathFinder(RRef* out, moho::CAiPathFinder* value);

  /**
   * Address: 0x005B5D60 (FUN_005B5D60, gpg::RRef_CAiPathSpline)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CAiPathSpline` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_CAiPathSpline(RRef* out, moho::CAiPathSpline* value);

  /**
   * Address: 0x00572930 (FUN_00572930, gpg::RRef_SAssignedLocInfo)
   *
   * What it does:
   * Builds a reflected reference for one `moho::SAssignedLocInfo` value pointer.
   */
  RRef* RRef_SAssignedLocInfo(RRef* out, moho::SAssignedLocInfo* value);

  /**
   * Address: 0x006288A0 (FUN_006288A0, gpg::RRef_SPickUpInfo)
   *
   * What it does:
   * Builds a reflected reference for one `moho::SPickUpInfo` value pointer.
   */
  RRef* RRef_SPickUpInfo(RRef* out, moho::SPickUpInfo* value);

  /**
   * Address: 0x005F5280 (FUN_005F5280, gpg::RRef_CUnitCommand)
   *
   * What it does:
   * Builds a reflected reference for a `moho::CUnitCommand` object pointer
   * with derived-type normalization.
  */
  RRef* RRef_CUnitCommand(RRef* out, moho::CUnitCommand* value);

  /**
   * Address: 0x006E3150 (FUN_006E3150, gpg::RRef_CCommandDB)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CCommandDb` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_CCommandDB(RRef* out, moho::CCommandDb* value);

  /**
   * Address: 0x006E3310 (FUN_006E3310, gpg::RRef_CUnitCommand_P)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CUnitCommand*` slot.
   */
  RRef* RRef_CUnitCommand_P(RRef* out, moho::CUnitCommand** value);

  /**
   * Address: 0x006EC1D0 (FUN_006EC1D0, gpg::RRef_WeakPtr_CUnitCommand)
   *
   * What it does:
   * Builds a reflected reference for one `WeakPtr<CUnitCommand>` wrapper
   * value.
   */
  RRef* RRef_WeakPtr_CUnitCommand(RRef* out, moho::WeakPtr<moho::CUnitCommand>* value);

  /**
   * Address: 0x0059A070 (FUN_0059A070, gpg::RRef_CUnitCommandQueue)
   *
   * What it does:
   * Builds a reflected reference for a `moho::CUnitCommandQueue` object
   * pointer with derived-type normalization.
   */
  RRef* RRef_CUnitCommandQueue(RRef* out, moho::CUnitCommandQueue* value);

  /**
   * Address: 0x005D1750 (FUN_005D1750, gpg::RRef_UnitWeapon)
   *
   * What it does:
   * Builds a reflected reference for a `moho::UnitWeapon` object pointer with
   * derived-type normalization.
   */
  RRef* RRef_UnitWeapon(RRef* out, moho::UnitWeapon* value);

  /**
   * Address: 0x0055F020 (FUN_0055F020, gpg::RRef_UnitWeaponInfo)
   *
   * What it does:
   * Builds a reflected reference for one `moho::UnitWeaponInfo` value pointer.
   */
  RRef* RRef_UnitWeaponInfo(RRef* out, moho::UnitWeaponInfo* value);

  /**
   * Address: 0x005E0750 (FUN_005E0750, gpg::RRef_UnitWeapon_P)
   *
   * What it does:
   * Builds a reflected reference for one `moho::UnitWeapon*` slot.
   */
  RRef* RRef_UnitWeapon_P(RRef* out, moho::UnitWeapon** value);

  /**
   * Address: 0x004041F0 (FUN_004041F0, gpg::RRef_IdPool)
   *
   * What it does:
   * Builds a reflected reference for a `moho::IdPool` object pointer.
   */
  RRef* RRef_IdPool(RRef* out, moho::IdPool* value);

  /**
   * Address: 0x00404180 (FUN_00404180, sub_404180)
   *
   * What it does:
   * Wrapper that assigns `RRef_IdPool` output lanes into the provided `RRef`.
   */
  RRef* AssignIdPoolRef(RRef* out, moho::IdPool* value);

  /**
   * Address: 0x0040F600 (FUN_0040F600, gpg::RRef_CRandomStream)
   *
   * What it does:
   * Builds a reflected reference for a `moho::CRandomStream` object pointer.
   */
  RRef* RRef_CRandomStream(RRef* out, moho::CRandomStream* value);

  /**
   * Address: 0x005B5A90 (FUN_005B5A90, gpg::RRef_CPathPoint)
   *
   * What it does:
   * Builds a reflected reference for a `moho::CPathPoint` object pointer with
   * cached RTTI lookup.
   */
  RRef* RRef_CPathPoint(RRef* out, moho::CPathPoint* value);

  /**
   * Address: 0x00554390 (FUN_00554390, gpg::RRef_SOCellPos)
   *
   * What it does:
   * Builds a reflected reference for one `moho::SOCellPos` value pointer.
   */
  RRef* RRef_SOCellPos(RRef* out, moho::SOCellPos* value);

  /**
   * Address: 0x00572790 (FUN_00572790, gpg::RRef_SOffsetInfo)
   *
   * What it does:
   * Builds a reflected reference for one `moho::SOffsetInfo` value pointer.
   */
  RRef* RRef_SOffsetInfo(RRef* out, moho::SOffsetInfo* value);

  /**
   * Address: 0x00764280 (FUN_00764280, gpg::RRef_HPathCell)
   *
   * What it does:
   * Builds a reflected reference for one `moho::HPathCell` object pointer.
   */
  RRef* RRef_HPathCell(RRef* out, moho::HPathCell* value);

  /**
   * Address: 0x007571F0 (FUN_007571F0, gpg::RRef_PathTables)
   *
   * What it does:
   * Builds a reflected reference for a `moho::PathTables` object pointer.
   */
  RRef* RRef_PathTables(RRef* out, moho::PathTables* value);

  /**
   * Address: 0x00707A10 (FUN_00707A10, gpg::RRef_CArmyStats)
   *
   * What it does:
   * Builds a reflected reference for a `moho::CArmyStats` object pointer with
   * derived-type normalization.
   */
  RRef* RRef_CArmyStats(RRef* out, moho::CArmyStats* value);

  /**
   * Address: 0x007139C0 (FUN_007139C0, gpg::RRef_Stats_CArmyStatItem)
   *
   * What it does:
   * Builds a reflected reference for one `moho::Stats<moho::CArmyStatItem>`
   * object pointer.
   */
  RRef* RRef_Stats_CArmyStatItem(RRef* out, moho::Stats<moho::CArmyStatItem>* value);

  /**
   * Address: 0x00713D90 (FUN_00713D90, gpg::RRef_CArmyStatItem_P)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CArmyStatItem*` slot.
   */
  RRef* RRef_CArmyStatItem_P(RRef* out, moho::CArmyStatItem** value);

  /**
   * Address: 0x005CADE0 (FUN_005CADE0, gpg::RRef_ReconBlip)
   *
   * What it does:
   * Builds a reflected reference for a `moho::ReconBlip` object pointer with
   * derived-type normalization.
   */
  RRef* RRef_ReconBlip(RRef* out, moho::ReconBlip* value);

  /**
   * Address: 0x005CB790 (FUN_005CB790, gpg::RRef_SPerArmyReconInfo)
   *
   * What it does:
   * Builds a reflected reference for one `moho::SPerArmyReconInfo` object
   * pointer.
   */
  RRef* RRef_SPerArmyReconInfo(RRef* out, moho::SPerArmyReconInfo* value);

  /**
   * Address: 0x005CB930 (FUN_005CB930, gpg::RRef_ReconBlip_P)
   *
   * What it does:
   * Builds a reflected reference for one `moho::ReconBlip*` slot.
   */
  RRef* RRef_ReconBlip_P(RRef* out, moho::ReconBlip** value);

  /**
   * Address: 0x006B2020 (FUN_006B2020, gpg::RRef_CEconomyEvent_P)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CEconomyEvent*` slot.
   */
  RRef* RRef_CEconomyEvent_P(RRef* out, moho::CEconomyEvent** value);

  /**
   * Address: 0x006B3AD0 (FUN_006B3AD0, gpg::RRef_CEconomyEvent)
   *
   * What it does:
   * Builds a reflected reference for a `moho::CEconomyEvent` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_CEconomyEvent(RRef* out, moho::CEconomyEvent* value);

  /**
   * Address: 0x00758730 (FUN_00758730, gpg::RRef_CDecalBuffer)
   *
   * What it does:
   * Builds a reflected reference for a `moho::CDecalBuffer` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_CDecalBuffer(RRef* out, moho::CDecalBuffer* value);

  /**
   * Address: 0x0077E540 (FUN_0077E540, gpg::RRef_CDecalHandle_P)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CDecalHandle*` slot.
   */
  RRef* RRef_CDecalHandle_P(RRef* out, moho::CDecalHandle** value);

  /**
   * Address: 0x0077E390 (FUN_0077E390, gpg::RRef_CDecalHandle)
   *
   * What it does:
   * Builds a reflected reference for a `moho::CDecalHandle` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_CDecalHandle(RRef* out, moho::CDecalHandle* value);

  /**
   * Address: 0x005E0300 (FUN_005E0300, gpg::RRef_CAiAttackerImpl)
   *
   * What it does:
   * Builds a reflected reference for a `moho::CAiAttackerImpl` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_CAiAttackerImpl(RRef* out, moho::CAiAttackerImpl* value);

  /**
   * Address: 0x005CC0D0 (FUN_005CC0D0, gpg::RRef_CAiReconDBImpl)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CAiReconDBImpl` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_CAiReconDBImpl(RRef* out, moho::CAiReconDBImpl* value);

  /**
   * Address: 0x005D4730 (FUN_005D4730, gpg::RRef_CAiSteeringImpl)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CAiSteeringImpl` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_CAiSteeringImpl(RRef* out, moho::CAiSteeringImpl* value);

  /**
   * Address: 0x005D0E70 (FUN_005D0E70, gpg::RRef_CAiSiloBuildImpl)
   *
   * What it does:
   * Builds a reflection reference for `moho::CAiSiloBuildImpl` using cached
   * RTTI lookup and derived-type normalization.
   */
  RRef* RRef_CAiSiloBuildImpl(RRef* out, moho::CAiSiloBuildImpl* value);

  /**
   * Address: 0x005E0E80 (FUN_005E0E80, gpg::RRef_LAiAttackerImpl)
   *
   * What it does:
   * Builds a reflected reference for one `moho::LAiAttackerImpl` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_LAiAttackerImpl(RRef* out, moho::LAiAttackerImpl* value);

  /**
   * Address: 0x006B5DA0 (FUN_006B5DA0, gpg::RRef_IAiAttacker)
   *
   * What it does:
   * Builds a reflected reference for a `moho::IAiAttacker` object pointer with
   * derived-type normalization.
   */
  RRef* RRef_IAiAttacker(RRef* out, moho::IAiAttacker* value);

  /**
   * Address: 0x006B59D0 (FUN_006B59D0, gpg::RRef_IAiSteering)
   *
   * What it does:
   * Builds a reflected reference for a `moho::IAiSteering` object pointer with
   * derived-type normalization.
   */
  RRef* RRef_IAiSteering(RRef* out, moho::IAiSteering* value);

  /**
   * Address: 0x006B5F90 (FUN_006B5F90, gpg::RRef_IAiCommandDispatch)
   *
   * What it does:
   * Builds a reflected reference for a `moho::IAiCommandDispatch` object
   * pointer with derived-type normalization.
   */
  RRef* RRef_IAiCommandDispatch(RRef* out, moho::IAiCommandDispatch* value);

  /**
   * Address: 0x00599AB0 (FUN_00599AB0, gpg::RRef_IAiCommandDispatchImpl)
   *
   * What it does:
   * Builds a reflection reference for `moho::IAiCommandDispatchImpl` using
   * cached RTTI lookup and derived-type normalization.
   */
  RRef* RRef_IAiCommandDispatchImpl(RRef* out, moho::IAiCommandDispatchImpl* value);

  /**
   * Address: 0x006B6180 (FUN_006B6180, gpg::RRef_IAiNavigator)
   *
   * What it does:
   * Builds a reflected reference for a `moho::IAiNavigator` object pointer with
   * derived-type normalization.
   */
  RRef* RRef_IAiNavigator(RRef* out, moho::IAiNavigator* value);

  /**
   * Address: 0x006B6370 (FUN_006B6370, gpg::RRef_IAiBuilder)
   *
   * What it does:
   * Builds a reflected reference for a `moho::IAiBuilder` object pointer with
   * derived-type normalization.
   */
  RRef* RRef_IAiBuilder(RRef* out, moho::IAiBuilder* value);

  /**
   * Address: 0x006B6560 (FUN_006B6560, gpg::RRef_IAiSiloBuild)
   *
   * What it does:
   * Builds a reflected reference for a `moho::IAiSiloBuild` object pointer with
   * derived-type normalization.
   */
  RRef* RRef_IAiSiloBuild(RRef* out, moho::IAiSiloBuild* value);

  /**
   * Address: 0x006B6750 (FUN_006B6750, gpg::RRef_IAiTransport)
   *
   * What it does:
   * Builds a reflected reference for a `moho::IAiTransport` object pointer with
   * derived-type normalization.
   */
  RRef* RRef_IAiTransport(RRef* out, moho::IAiTransport* value);

  /**
   * Address: 0x006EC620 (FUN_006EC620, gpg::RRef_Listener_ECommandEvent)
   *
   * What it does:
   * Builds a reflected reference for one
   * `moho::Listener<moho::ECommandEvent>` object pointer.
   */
  RRef* RRef_Listener_ECommandEvent(RRef* out, moho::Listener<moho::ECommandEvent>* value);

  /**
   * Address: 0x006F9410 (FUN_006F9410, gpg::RRef_Listener_EUnitCommandQueueStatus)
   *
   * What it does:
   * Builds a reflected reference for one
   * `moho::Listener<moho::EUnitCommandQueueStatus>` object pointer.
   */
  RRef* RRef_Listener_EUnitCommandQueueStatus(
    RRef* out, moho::Listener<moho::EUnitCommandQueueStatus>* value
  );

  /**
   * Address: 0x00764460 (FUN_00764460, gpg::RRef_Listener_NavPath)
   *
   * What it does:
   * Builds a reflected reference for one
   * `moho::Listener<const moho::SNavPath&>` object pointer.
   */
  RRef* RRef_Listener_NavPath(RRef* out, moho::Listener<const moho::SNavPath&>* value);

  /**
   * Address: 0x005A8A40 (FUN_005A8A40, gpg::RRef_Listener_EAiNavigatorEvent)
   *
   * What it does:
   * Builds a reflected reference for one `moho::Listener<moho::EAiNavigatorEvent>`
   * object pointer.
   */
  RRef* RRef_Listener_EAiNavigatorEvent(RRef* out, moho::Listener<moho::EAiNavigatorEvent>* value);

  /**
   * Address: 0x005E0A90 (FUN_005E0A90, gpg::RRef_Listener_EAiAttackerEvent)
   *
   * What it does:
   * Builds a reflected reference for one `moho::Listener<moho::EAiAttackerEvent>`
   * object pointer.
   */
  RRef* RRef_Listener_EAiAttackerEvent(RRef* out, moho::Listener<moho::EAiAttackerEvent>* value);

  /**
   * Address: 0x005EE1B0 (FUN_005EE1B0, gpg::RRef_Listener_EAiTransportEvent)
   *
   * What it does:
   * Builds a reflected reference for one `moho::Listener<moho::EAiTransportEvent>`
   * object pointer.
   */
  RRef* RRef_Listener_EAiTransportEvent(RRef* out, moho::Listener<moho::EAiTransportEvent>* value);

  /**
   * Address: 0x005EDD30 (FUN_005EDD30, gpg::RRef_SAiReservedTransportBone)
   *
   * What it does:
   * Builds a reflected reference for one `moho::SAiReservedTransportBone`
   * object pointer.
   */
  RRef* RRef_SAiReservedTransportBone(RRef* out, moho::SAiReservedTransportBone* value);

  /**
   * Address: 0x005EDED0 (FUN_005EDED0, gpg::RRef_SAttachPoint)
   *
   * What it does:
   * Builds a reflected reference for one `moho::SAttachPoint` object pointer.
   */
  RRef* RRef_SAttachPoint(RRef* out, moho::SAttachPoint* value);

  /**
   * Address: 0x00582F00 (FUN_00582F00, gpg::RRef_SPointVector)
   *
   * What it does:
   * Builds a reflected reference for one `moho::SPointVector` value pointer.
   */
  RRef* RRef_SPointVector(RRef* out, moho::SPointVector* value);

  /**
   * Address: 0x007582F0 (FUN_007582F0, gpg::RRef_IAiFormationDB)
   *
   * What it does:
   * Builds a reflected reference for a `moho::IAiFormationDB` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_IAiFormationDB(RRef* out, moho::IAiFormationDB* value);

  /**
   * Address: 0x00758500 (FUN_00758500, gpg::RRef_ISimResources)
   *
   * What it does:
   * Builds a reflected reference for a `moho::ISimResources` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_ISimResources(RRef* out, moho::ISimResources* value);

  /**
   * Address: 0x00683230 (FUN_00683230, gpg::RRef_CColPrimitiveBase)
   *
   * What it does:
   * Builds a reflected reference for a `moho::CColPrimitiveBase` object
   * pointer with derived-type normalization.
   */
  RRef* RRef_CColPrimitiveBase(RRef* out, moho::CColPrimitiveBase* value);

  /**
   * Address: 0x006839C0 (FUN_006839C0, gpg::RRef_Motor)
   *
   * What it does:
   * Builds a reflected reference for a `moho::EntityMotor` object pointer with
   * derived-type normalization.
   */
  RRef* RRef_Motor(RRef* out, moho::EntityMotor* value);

  /**
   * Address: 0x005CE540 (FUN_005CE540, gpg::RRef_CInfluenceMap)
   *
   * What it does:
   * Builds a reflected reference for a `moho::CInfluenceMap` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_CInfluenceMap(RRef* out, moho::CInfluenceMap* value);

  /**
   * Address: 0x0071E410 (FUN_0071E410, gpg::RRef_InfluenceGrid)
   *
   * What it does:
   * Builds a reflected reference for one `moho::InfluenceGrid` object pointer.
   */
  RRef* RRef_InfluenceGrid(RRef* out, moho::InfluenceGrid* value);

  /**
   * Address: 0x0071E5B0 (FUN_0071E5B0, gpg::RRef_SThreat)
   *
   * What it does:
   * Builds a reflected reference for one `moho::SThreat` object pointer.
   */
  RRef* RRef_SThreat(RRef* out, moho::SThreat* value);

  /**
   * Address: 0x0064C960 (FUN_0064C960, gpg::RRef_RDebugCollision)
   *
   * What it does:
   * Builds a reflected reference for one `moho::RDebugCollision` object
   * pointer with derived-type normalization.
   */
  RRef* RRef_RDebugCollision(RRef* out, moho::RDebugCollision* value);

  /**
   * Address: 0x0064FBC0 (FUN_0064FBC0, gpg::RRef_RDebugGrid)
   *
   * What it does:
   * Builds a reflected reference for one `moho::RDebugGrid` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_RDebugGrid(RRef* out, moho::RDebugGrid* value);

  /**
   * Address: 0x0064FD70 (FUN_0064FD70, gpg::RRef_RDebugRadar)
   *
   * What it does:
   * Builds a reflected reference for one `moho::RDebugRadar` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_RDebugRadar(RRef* out, moho::RDebugRadar* value);

  /**
   * Address: 0x00651200 (FUN_00651200, gpg::RRef_RDebugNavPath)
   *
   * What it does:
   * Builds a reflected reference for one `moho::RDebugNavPath` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_RDebugNavPath(RRef* out, moho::RDebugNavPath* value);

  /**
   * Address: 0x006513B0 (FUN_006513B0, gpg::RRef_RDebugNavWaypoints)
   *
   * What it does:
   * Builds a reflected reference for one `moho::RDebugNavWaypoints` object
   * pointer with derived-type normalization.
   */
  RRef* RRef_RDebugNavWaypoints(RRef* out, moho::RDebugNavWaypoints* value);

  /**
   * Address: 0x00651560 (FUN_00651560, gpg::RRef_RDebugNavSteering)
   *
   * What it does:
   * Builds a reflected reference for one `moho::RDebugNavSteering` object
   * pointer with derived-type normalization.
   */
  RRef* RRef_RDebugNavSteering(RRef* out, moho::RDebugNavSteering* value);

  /**
   * Address: 0x00653C50 (FUN_00653C50, gpg::RRef_RDebugWeapons)
   *
   * What it does:
   * Builds a reflected reference for one `moho::RDebugWeapons` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_RDebugWeapons(RRef* out, moho::RDebugWeapons* value);

  /**
   * Address: 0x00683420 (FUN_00683420, gpg::RRef_CIntel)
   *
   * What it does:
   * Builds a reflected reference for a `moho::CIntel` object pointer with
   * derived-type normalization.
   */
  RRef* RRef_CIntel(RRef* out, moho::CIntel* value);

  /**
   * Address: 0x0076EDD0 (FUN_0076EDD0, gpg::RRef_CIntelPosHandle)
   *
   * What it does:
   * Builds a reflected reference for a `moho::CIntelPosHandle` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_CIntelPosHandle(RRef* out, moho::CIntelPosHandle* value);

  /**
   * Address: 0x0076FE30 (FUN_0076FE30, gpg::RRef_CIntelCounterHandle)
   *
   * What it does:
   * Builds a reflected reference for one `moho::CIntelCounterHandle` object
   * pointer with derived-type normalization.
   */
  RRef* RRef_CIntelCounterHandle(RRef* out, moho::CIntelCounterHandle* value);

  /**
   * Address: 0x00707640 (FUN_00707640, gpg::RRef_IAiReconDB)
   *
   * What it does:
   * Builds a reflected reference for a `moho::IAiReconDB` object pointer with
   * derived-type normalization.
   */
  RRef* RRef_IAiReconDB(RRef* out, moho::IAiReconDB* value);

  /**
   * Address: 0x0076AE70 (FUN_0076AE70, gpg::RRef_IPathTraveler)
   *
   * What it does:
   * Builds a reflected reference for a `moho::IPathTraveler` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_IPathTraveler(RRef* out, moho::IPathTraveler* value);

  /**
   * Address: 0x00680D70 (FUN_00680D70, gpg::RRef_PositionHistory)
   *
   * What it does:
   * Builds a reflected reference for a `moho::PositionHistory` object pointer.
   */
  RRef* RRef_PositionHistory(RRef* out, moho::PositionHistory* value);

  /**
   * Address: 0x005D5300 (FUN_005D5300, gpg::RRef_CUnitMotion)
   *
   * What it does:
   * Builds a reflected reference for a `moho::CUnitMotion` object pointer with
   * derived-type normalization.
   */
  RRef* RRef_CUnitMotion(RRef* out, moho::CUnitMotion* value);

  /**
   * Address: 0x00753FC0 (FUN_00753FC0, gpg::RRef_Shield)
   *
   * What it does:
   * Builds a reflected reference for a `moho::Shield` object pointer with
   * derived-type normalization.
   */
  RRef* RRef_Shield(RRef* out, moho::Shield* value);

  /**
   * Address: 0x007542F0 (FUN_007542F0, gpg::RRef_Shield_P)
   *
   * What it does:
   * Builds a reflected reference for one `moho::Shield*` slot.
   */
  RRef* RRef_Shield_P(RRef* out, moho::Shield** value);

  /**
   * Address: 0x00758910 (FUN_00758910, gpg::RRef_IEffectManager)
   *
   * What it does:
   * Builds a reflected reference for a `moho::IEffectManager` object pointer
   * with derived-type normalization.
   */
  RRef* RRef_IEffectManager(RRef* out, moho::IEffectManager* value);

  /**
   * Address: 0x0040F590 (FUN_0040F590, sub_40F590)
   *
   * What it does:
   * Wrapper that assigns `RRef_CRandomStream` output lanes into provided `RRef`.
   */
  RRef* AssignCRandomStreamRef(RRef* out, moho::CRandomStream* value);

  /**
   * Address: 0x00705120 (FUN_00705120, gpg::RRef_CPlatoon)
   *
   * What it does:
   * Builds a reflected reference for a `moho::CPlatoon` pointer with
   * derived-type normalization.
   */
  RRef* RRef_CPlatoon(RRef* out, moho::CPlatoon* value);

  /**
   * Address: 0x00884A10 (FUN_00884A10, gpg::RRef_SSessionSaveData)
   *
   * What it does:
   * Builds a reflected reference for a `moho::SSessionSaveData` object pointer.
   */
  RRef* RRef_SSessionSaveData(RRef* out, moho::SSessionSaveData* value);

  /**
   * Address: 0x004220D0 (FUN_004220D0, gpg::RRef_CLuaConOutputHandler)
   *
   * What it does:
   * Builds a reflected reference for a `moho::CLuaConOutputHandler` object
   * pointer with derived-type normalization.
   */
  RRef* RRef_CLuaConOutputHandler(RRef* out, moho::CLuaConOutputHandler* value);

  /**
   * Address: 0x004C16D0 (FUN_004C16D0, gpg::RRef_LuaState)
   *
   * What it does:
   * Builds a reflected reference for `LuaPlus::LuaState` and preserves dynamic
   * runtime owner type when the pointed object is derived.
  */
  RRef* RRef_LuaState(RRef* out, LuaPlus::LuaState* value);

  /**
   * Address: 0x0091E550 (FUN_0091E550, gpg::RRef_TString)
   *
   * What it does:
   * Builds a reflected reference for Lua `TString` object pointers.
   */
  RRef* RRef_TString(RRef* out, TString* value);

  /**
   * Address: 0x0091E730 (FUN_0091E730, gpg::RRef_Table)
   *
   * What it does:
   * Builds a reflected reference for Lua `Table` object pointers.
   */
  RRef* RRef_Table(RRef* out, Table* value);

  /**
   * Address: 0x0091E900 (FUN_0091E900, gpg::RRef_LClosure)
   *
   * What it does:
   * Builds a reflected reference for Lua `LClosure` object pointers.
   */
  RRef* RRef_LClosure(RRef* out, LClosure* value);

  /**
   * Address: 0x0091F170 (FUN_0091F170, gpg::RRef_CClosure)
   *
   * What it does:
   * Builds a reflected reference for one Lua `CClosure` object pointer.
   */
  RRef* RRef_CClosure(RRef* out, CClosure* value);

  /**
   * Address: 0x0091EE10 (FUN_0091EE10, gpg::RRef_Udata)
   *
   * What it does:
   * Builds a reflected reference for Lua `Udata` object pointers.
   */
  RRef* RRef_Udata(RRef* out, Udata* value);

  /**
   * Address: 0x0091EAA0 (FUN_0091EAA0, gpg::RRef_UpVal)
   *
   * What it does:
   * Builds a reflected reference for Lua `UpVal` object pointers.
   */
  RRef* RRef_UpVal(RRef* out, UpVal* value);

  /**
   * Address: 0x0091EC40 (FUN_0091EC40, gpg::RRef_Proto)
   *
   * What it does:
   * Builds a reflected reference for Lua `Proto` object pointers.
   */
  RRef* RRef_Proto(RRef* out, Proto* value);

  /**
   * Address: 0x00713560 (FUN_00713560, gpg::RRef_SCondition)
   *
   * What it does:
   * Builds a reflected reference for one `moho::SCondition` object pointer.
   */
  RRef* RRef_SCondition(RRef* out, moho::SCondition* value);

  /**
   * Address: 0x00713700 (FUN_00713700, gpg::RRef_STrigger)
   *
   * What it does:
   * Builds a reflected reference for a `moho::STrigger` object pointer.
   */
  RRef* RRef_STrigger(RRef* out, moho::STrigger* value);

  /**
   * Address: 0x0090B1E0 (FUN_0090B1E0, gpg::RRef_lua_State)
   *
   * What it does:
   * Builds a reflected reference for `lua_State` object pointers.
   */
  RRef* RRef_lua_State(RRef* out, lua_State* value);

  class RField
  {
  public:
    const char* mName;
    RType* mType;
    int mOffset;
    int v4;
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
    using save_construct_args_func_t = void (*)(void*);
    using save_func_t = void (*)(WriteArchive*, int, int, RRef*);
    using construct_func_t = void (*)(void*);
    using load_func_t = void (*)(ReadArchive*, int, int, RRef*);
    using new_ref_func_t = RRef (*)();
    using cpy_ref_func_t = RRef (*)(RRef*);
    using delete_func_t = void (*)(void*);
    using ctor_ref_func_t = RRef (*)(void*);
    using mov_ref_func_t = RRef (*)(void*, RRef*);
    using dtr_func_t = void (*)(void*);

    static RType* sType;

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
     * Destructor.
     *
     * Address: 0x008DD9D0
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
     * Address: 0x0040DFA0 (FUN_0040DFA0, gpg::RType::AddField_float)
     *
     * What it does:
     * Appends one reflected `float` field descriptor.
     */
    RField* AddFieldFloat(const char* name, int offset);

    /**
     * Address: 0x0040E020 (FUN_0040E020, gpg::RType::AddField_uint)
     *
     * What it does:
     * Appends one reflected `unsigned int` field descriptor.
     */
    RField* AddFieldUInt(const char* name, int offset);

    /**
     * Address: 0x004EDC10 (FUN_004EDC10, gpg::RType::AddField_int)
     *
     * What it does:
     * Appends one reflected `int` field descriptor.
     */
    RField* AddFieldInt(const char* name, int offset);

    /**
     * Address: 0x00510DD0 (FUN_00510DD0, gpg::RType::AddFieldBool)
     *
     * What it does:
     * Appends one reflected `bool` field descriptor.
     */
    RField* AddFieldBool(const char* name, int offset);

    /**
     * Address: 0x0050E1F0 (FUN_0050E1F0, gpg::RType::AddField_string)
     *
     * What it does:
     * Appends one reflected `msvc8::string` field descriptor.
     */
    RField* AddFieldString(const char* name, int offset);

    /**
     * Address: 0x004EDFD0 (FUN_004EDFD0, gpg::RType::AddField_Vector3f)
     *
     * What it does:
     * Appends one reflected `Wm3::Vector3f` field descriptor.
     */
    RField* AddFieldVector3f(const char* name, int offset);

    /**
     * Address: 0x00510D50 (FUN_00510D50, gpg::RType::AddField_RResId)
     *
     * What it does:
     * Appends one reflected `moho::RResId` field descriptor.
     */
    RField* AddFieldRResId(const char* name, int offset);

    /**
     * Address: 0x0050D010 (FUN_0050D010, gpg::RType::AddField_uchar)
     *
     * What it does:
     * Appends one reflected `unsigned char` field descriptor.
     */
    RField* AddFieldUChar(const char* name, int offset);

    /**
     * Address: 0x00510F10 (FUN_00510F10, gpg::RType::AddField_REmitterBlueprintCurve)
     *
     * What it does:
     * Appends one reflected `moho::REmitterBlueprintCurve` field descriptor.
     */
    RField* AddFieldEmitterBlueprintCurve(const char* name, int offset);

    /**
     * Address: 0x00510FF0 (FUN_00510FF0, gpg::RType::AddField_Vector4f)
     *
     * What it does:
     * Appends one reflected `moho::Vector4f` field descriptor.
     */
    RField* AddFieldVector4f(const char* name, int offset);

    /**
     * Address: 0x00513230 (FUN_00513230, gpg::RType::AddField_vector_string)
     *
     * What it does:
     * Appends one reflected `msvc8::vector<msvc8::string>` field descriptor.
     */
    RField* AddFieldVectorString(const char* name, int offset);

    /**
     * Address: 0x00513330 (FUN_00513330, gpg::RType::AddField_SFootprint)
     *
     * What it does:
     * Appends one reflected `moho::SFootprint` field descriptor.
     */
    RField* AddFieldSFootprint(const char* name, int offset);

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

    template <class T>
    RField* AddField(const char* name, int offset)
    {
      GPG_ASSERT(!initFinished_); // if (this->mInitFinished) { gpg::HandleAssertFailure("!mInitFinished", 734,
                                  // "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/reflection.h"); }
      RField f{name, const_cast<RType*>(T::StaticGetClass()), offset};
      this->fields_.push_back(f);
      return &this->fields_.back();
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

  /**
   * VFTABLE: 0x00D44B44
   * COL:  0x00E51514
   */
  class Rect2iSerializer
  {
  public:
    /**
     * Address: 0x00905E40 (FUN_00905E40)
     * Demangled: gpg::SerSaveLoadHelper<class gpg::Rect2<int>>::Init
     *
     * What it does:
     * Binds Rect2<int> load/save callbacks onto the reflected type descriptor.
     */
    virtual void RegisterSerializeFunctions();

  public:
    SerHelperBase* mHelperNext;
    SerHelperBase* mHelperPrev;
    RType::load_func_t mLoadCallback;
    RType::save_func_t mSaveCallback;
  };
  static_assert(offsetof(Rect2iSerializer, mHelperNext) == 0x04, "Rect2iSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(Rect2iSerializer, mHelperPrev) == 0x08, "Rect2iSerializer::mHelperPrev offset must be 0x08");
  static_assert(
    offsetof(Rect2iSerializer, mLoadCallback) == 0x0C, "Rect2iSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(Rect2iSerializer, mSaveCallback) == 0x10, "Rect2iSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(Rect2iSerializer) == 0x14, "Rect2iSerializer size must be 0x14");

  /**
   * VFTABLE: 0x00D44B3C
   * COL:  0x00E514BC
   */
  class Rect2fSerializer
  {
  public:
    /**
     * Address: 0x00905EE0 (FUN_00905EE0)
     * Demangled: gpg::SerSaveLoadHelper<class gpg::Rect2<float>>::Init
     *
     * What it does:
     * Binds Rect2<float> load/save callbacks onto the reflected type descriptor.
     */
    virtual void RegisterSerializeFunctions();

  public:
    SerHelperBase* mHelperNext;
    SerHelperBase* mHelperPrev;
    RType::load_func_t mLoadCallback;
    RType::save_func_t mSaveCallback;
  };
  static_assert(offsetof(Rect2fSerializer, mHelperNext) == 0x04, "Rect2fSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(Rect2fSerializer, mHelperPrev) == 0x08, "Rect2fSerializer::mHelperPrev offset must be 0x08");
  static_assert(
    offsetof(Rect2fSerializer, mLoadCallback) == 0x0C, "Rect2fSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(Rect2fSerializer, mSaveCallback) == 0x10, "Rect2fSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(Rect2fSerializer) == 0x14, "Rect2fSerializer size must be 0x14");

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
   * Source hints:
   *  - c:\work\rts\main\code\src\libs\gpgcore\reflection\reflection.cpp
   */
  template <>
  class RPointerType<moho::RBlueprint> final : public RPointerTypeBase
  {
  public:
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

  private:
    static msvc8::string sName;
    static std::uint32_t sNameInitGuard;
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
     * Address: 0x00421620 (FUN_00421620, sub_421620 helper lane)
     * Address: 0x00421660 (FUN_00421660, sub_421660 helper lane)
     * Address: 0x00421670 (FUN_00421670, sub_421670 helper lane)
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
     * Address: 0x00711730 (FUN_00711730)
     * Demangled: gpg::RPointerType_CArmyStatItem::Init
     */
    void Init() override;

  protected:
    [[nodiscard]]
    RType* GetPointeeType() const override;

  private:
    static msvc8::string sName;
    static std::uint32_t sNameInitGuard;
  };
  static_assert(
    sizeof(RPointerType<moho::CArmyStatItem>) == 0x68, "RPointerType<CArmyStatItem> size must be 0x68"
  );
} // namespace gpg
