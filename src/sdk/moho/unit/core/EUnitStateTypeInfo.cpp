#include "moho/unit/core/EUnitStateTypeInfo.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  /**
   * Address: 0x00BCA520 (FUN_00BCA520, dynamic initializer for the global
   * `PrimitiveSerHelper<EUnitState,int>` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields (vtable slot 0 `Init()` dispatched later by
   * `gpg::SerHelperBase::InitNewHelpers`). This is an independent `__xc_a`
   * static initializer, separate from `EUnitStateTypeInfo`'s own
   * initializer below.
   *
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::EUnitState,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EUnitState@Moho@@H@gpg'`):
   * `FUN_00BCA520` (real, `__xc_a`-reachable; no dead duplicate found for
   * this instantiation). `Init()` confirmed at `FUN_0055C9A0` via the RTTI
   * vftable dump (`vftable@0xE1875C` slot 0) -- previously mis-cited in
   * `ArchiveSerialization.cpp` as a generic
   * `InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::EUnitState")`
   * dispatch; the real body does a direct `typeid`/`sType`-cache lookup and
   * hardcoded callback install, matching this template's `Init()` exactly
   * (same mis-citation family already caught this session for
   * ESTITargetType/EResourceType/EUnitCommandType/CAniPose/CAniPoseBone).
   * `Deserialize`/`Serialize` at 0x0055D450/0x0055D470 already matched this
   * template's generic bodies exactly (no fabricated null-check).
   *
   * `~PrimitiveSerHelper()`'s compiler-emitted static-destructor
   * registration for this instantiation is `FUN_00BF5270` (atexit target
   * pushed by the real ctor above); `FUN_0055BFC0`/`FUN_0055BFF0` are dead,
   * zero-xref duplicate-emission twins of that exact body
   * (function_sha256-confirmed), formerly modeled in
   * `moho/containers/LegacyContainerFillLanes.cpp` as
   * `gGlobalIntrusiveSentinelLaneJ` and its two reset thunks; removed in
   * favor of this citation.
   */
  gpg::PrimitiveSerHelper<moho::EUnitState, int> gEUnitStatePrimitiveSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x0055BB10 (FUN_0055BB10, static-init lane)
   * Address: 0x00BF5260 (FUN_00BF5260, atexit destructor of the EUnitStateTypeInfo object; registered by 0x00BCA500)
   *
   * What it does:
   * Constructs the static descriptor on first call; the constructor is what
   * performs the `PreRegisterRType`, so one construction is the whole
   * registration.
   */
  gpg::REnumType* preregister_EUnitStateTypeInfo()
  {
    static moho::EUnitStateTypeInfo sInstance;
    return &sInstance;
  }

  /**
   * Address: 0x0055BB10 (FUN_0055BB10, Moho::EUnitStateTypeInfo::EUnitStateTypeInfo)
   *
   * What it does:
   * Preregisters the enum type descriptor for `EUnitState` with the reflection registry.
   */
  EUnitStateTypeInfo::EUnitStateTypeInfo()
    : gpg::REnumType()
  {
    gpg::PreRegisterRType(typeid(EUnitState), this);
  }

  /**
   * Address: 0x0055BBA0 (FUN_0055BBA0, Moho::EUnitStateTypeInfo::dtr)
   */
  EUnitStateTypeInfo::~EUnitStateTypeInfo() = default;

  /**
   * Address: 0x0055BB90 (FUN_0055BB90, Moho::EUnitStateTypeInfo::GetName)
   */
  const char* EUnitStateTypeInfo::GetName() const
  {
    return "EUnitState";
  }

  /**
   * Address: 0x0055BB70 (FUN_0055BB70, Moho::EUnitStateTypeInfo::Init)
   */
  void EUnitStateTypeInfo::Init()
  {
    size_ = sizeof(EUnitState);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x0055BBD0 (FUN_0055BBD0, Moho::EUnitStateTypeInfo::AddEnums)
   */
  void EUnitStateTypeInfo::AddEnums()
  {
    mPrefix = "UNITSTATE_";
    AddEnum(StripPrefix("UNITSTATE_Immobile"), UNITSTATE_Immobile);
    AddEnum(StripPrefix("UNITSTATE_Moving"), UNITSTATE_Moving);
    AddEnum(StripPrefix("UNITSTATE_Attacking"), UNITSTATE_Attacking);
    AddEnum(StripPrefix("UNITSTATE_Guarding"), UNITSTATE_Guarding);
    AddEnum(StripPrefix("UNITSTATE_Building"), UNITSTATE_Building);
    AddEnum(StripPrefix("UNITSTATE_Upgrading"), UNITSTATE_Upgrading);
    AddEnum(StripPrefix("UNITSTATE_WaitingForTransport"), UNITSTATE_WaitingForTransport);
    AddEnum(StripPrefix("UNITSTATE_TransportLoading"), UNITSTATE_TransportLoading);
    AddEnum(StripPrefix("UNITSTATE_TransportUnloading"), UNITSTATE_TransportUnloading);
    AddEnum(StripPrefix("UNITSTATE_MovingDown"), UNITSTATE_MovingDown);
    AddEnum(StripPrefix("UNITSTATE_MovingUp"), UNITSTATE_MovingUp);
    AddEnum(StripPrefix("UNITSTATE_Patrolling"), UNITSTATE_Patrolling);
    AddEnum(StripPrefix("UNITSTATE_Busy"), UNITSTATE_Busy);
    AddEnum(StripPrefix("UNITSTATE_Attached"), UNITSTATE_Attached);
    AddEnum(StripPrefix("UNITSTATE_BeingReclaimed"), UNITSTATE_BeingReclaimed);
    AddEnum(StripPrefix("UNITSTATE_Repairing"), UNITSTATE_Repairing);
    AddEnum(StripPrefix("UNITSTATE_Diving"), UNITSTATE_Diving);
    AddEnum(StripPrefix("UNITSTATE_Surfacing"), UNITSTATE_Surfacing);
    AddEnum(StripPrefix("UNITSTATE_Teleporting"), UNITSTATE_Teleporting);
    AddEnum(StripPrefix("UNITSTATE_Ferrying"), UNITSTATE_Ferrying);
    AddEnum(StripPrefix("UNITSTATE_WaitForFerry"), UNITSTATE_WaitForFerry);
    AddEnum(StripPrefix("UNITSTATE_AssistMoving"), UNITSTATE_AssistMoving);
    AddEnum(StripPrefix("UNITSTATE_PathFinding"), UNITSTATE_PathFinding);
    AddEnum(StripPrefix("UNITSTATE_ProblemGettingToGoal"), UNITSTATE_ProblemGettingToGoal);
    AddEnum(StripPrefix("UNITSTATE_NeedToTerminateTask"), UNITSTATE_NeedToTerminateTask);
    AddEnum(StripPrefix("UNITSTATE_Capturing"), UNITSTATE_Capturing);
    AddEnum(StripPrefix("UNITSTATE_BeingCaptured"), UNITSTATE_BeingCaptured);
    AddEnum(StripPrefix("UNITSTATE_Reclaiming"), UNITSTATE_Reclaiming);
    AddEnum(StripPrefix("UNITSTATE_AssistingCommander"), UNITSTATE_AssistingCommander);
    AddEnum(StripPrefix("UNITSTATE_Refueling"), UNITSTATE_Refueling);
    AddEnum(StripPrefix("UNITSTATE_GuardBusy"), UNITSTATE_GuardBusy);
    AddEnum(StripPrefix("UNITSTATE_ForceSpeedThrough"), UNITSTATE_ForceSpeedThrough);
    AddEnum(StripPrefix("UNITSTATE_UnSelectable"), UNITSTATE_UnSelectable);
    AddEnum(StripPrefix("UNITSTATE_DoNotTarget"), UNITSTATE_DoNotTarget);
    AddEnum(StripPrefix("UNITSTATE_LandingOnPlatform"), UNITSTATE_LandingOnPlatform);
    AddEnum(StripPrefix("UNITSTATE_CannotFindPlaceToLand"), UNITSTATE_CannotFindPlaceToLand);
    AddEnum(StripPrefix("UNITSTATE_BeingUpgraded"), UNITSTATE_BeingUpgraded);
    AddEnum(StripPrefix("UNITSTATE_Enhancing"), UNITSTATE_Enhancing);
    AddEnum(StripPrefix("UNITSTATE_BeingBuilt"), UNITSTATE_BeingBuilt);
    AddEnum(StripPrefix("UNITSTATE_NoReclaim"), UNITSTATE_NoReclaim);
    AddEnum(StripPrefix("UNITSTATE_NoCost"), UNITSTATE_NoCost);
    AddEnum(StripPrefix("UNITSTATE_BlockCommandQueue"), UNITSTATE_BlockCommandQueue);
    AddEnum(StripPrefix("UNITSTATE_MakingAttackRun"), UNITSTATE_MakingAttackRun);
    AddEnum(StripPrefix("UNITSTATE_HoldingPattern"), UNITSTATE_HoldingPattern);
    AddEnum(StripPrefix("UNITSTATE_SiloBuildingAmmo"), UNITSTATE_SiloBuildingAmmo);
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_EUnitStateTypeInfo_4b6147, moho::preregister_EUnitStateTypeInfo)
