#include "moho/unit/core/EUnitStateTypeInfo.h"

#include <cstdint>
#include <new>
#include <typeinfo>

namespace
{
  alignas(moho::EUnitStateTypeInfo) unsigned char gEUnitStateTypeInfoStorage[sizeof(moho::EUnitStateTypeInfo)]{};
  bool gEUnitStateTypeInfoConstructed = false;
  bool gEUnitStateTypeInfoPreregistered = false;

  [[nodiscard]] moho::EUnitStateTypeInfo* AcquireEUnitStateTypeInfo()
  {
    if (!gEUnitStateTypeInfoConstructed) {
      new (gEUnitStateTypeInfoStorage) moho::EUnitStateTypeInfo();
      gEUnitStateTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::EUnitStateTypeInfo*>(gEUnitStateTypeInfoStorage);
  }

  struct EUnitStateTypeInfoBootstrap
  {
    EUnitStateTypeInfoBootstrap()
    {
      (void)moho::preregister_EUnitStateTypeInfo();
    }
  };

  [[maybe_unused]] EUnitStateTypeInfoBootstrap gEUnitStateTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x0055BB10 (FUN_0055BB10, preregister_EUnitStateTypeInfo)
   */
  gpg::REnumType* preregister_EUnitStateTypeInfo()
  {
    auto* const typeInfo = AcquireEUnitStateTypeInfo();
    if (!gEUnitStateTypeInfoPreregistered) {
      gpg::PreRegisterRType(typeid(EUnitState), typeInfo);
      gEUnitStateTypeInfoPreregistered = true;
    }

    return typeInfo;
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

  /**
   * Address: 0x0055D450 (FUN_0055D450, PrimitiveSerHelper<EUnitState>::Deserialize)
   */
  void EUnitStatePrimitiveSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    int value = 0;
    archive->ReadInt(&value);
    *reinterpret_cast<EUnitState*>(static_cast<std::uintptr_t>(objectPtr)) = static_cast<EUnitState>(value);
  }

  /**
   * Address: 0x0055D470 (FUN_0055D470, PrimitiveSerHelper<EUnitState>::Serialize)
   */
  void EUnitStatePrimitiveSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    const auto value = *reinterpret_cast<const EUnitState*>(static_cast<std::uintptr_t>(objectPtr));
    archive->WriteInt(static_cast<int>(value));
  }

  void EUnitStatePrimitiveSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = gpg::LookupRType(typeid(EUnitState));
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
    type->serLoadFunc_ = mDeserialize;
    type->serSaveFunc_ = mSerialize;
  }
} // namespace moho
