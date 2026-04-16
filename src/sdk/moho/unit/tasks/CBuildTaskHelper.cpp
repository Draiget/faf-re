#include "moho/unit/tasks/CBuildTaskHelper.h"

#include <algorithm>
#include <string>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/IAiSiloBuild.h"
#include "moho/entity/Entity.h"
#include "moho/misc/CEconomyEvent.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprintCapabilityEnums.h"
#include "moho/script/CScriptObject.h"
#include "moho/sim/Sim.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"

namespace
{
  constexpr float kFloatZero = 0.0f;
  constexpr float kFloatOne = 1.0f;
  constexpr float kTickBuildScale = 0.1f;
  constexpr float kQuarterProgress = 0.25f;
  constexpr float kHalfProgress = 0.5f;
  constexpr float kThreeQuarterProgress = 0.75f;
  constexpr const char* kOnAssignedFocusEntity = "OnAssignedFocusEntity";

  [[nodiscard]] moho::Unit* ResolveFocusUnit(const moho::WeakPtr<moho::Unit>& focusLink) noexcept
  {
    return focusLink.GetObjectPtr();
  }

  [[nodiscard]] gpg::RType* ResolveWeakPtrUnitType()
  {
    gpg::RType* type = moho::WeakPtr<moho::Unit>::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::WeakPtr<moho::Unit>));
      moho::WeakPtr<moho::Unit>::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveSimType()
  {
    static gpg::RType* cachedType = nullptr;
    if (!cachedType) {
      cachedType = gpg::LookupRType(typeid(moho::Sim));
    }
    return cachedType;
  }

  [[nodiscard]] bool DidCrossBuildProgressBand(const float previous, const float current) noexcept
  {
    return (previous < kQuarterProgress && current >= kQuarterProgress)
      || (previous < kHalfProgress && current >= kHalfProgress)
      || (previous < kThreeQuarterProgress && current >= kThreeQuarterProgress);
  }

  [[nodiscard]] float ComputeBuildProgressDelta(
    const moho::RUnitBlueprint* const blueprint,
    const moho::UnitAttributes& builderAttributes,
    const float resourceConsumed
  ) noexcept
  {
    if (blueprint == nullptr || resourceConsumed == kFloatZero) {
      return kFloatZero;
    }

    const float buildRate = builderAttributes.buildRate;
    if (buildRate <= kFloatZero) {
      return kFloatZero;
    }

    const float buildTime = blueprint->Economy.BuildTime;
    if (buildTime <= kFloatZero) {
      return kFloatZero;
    }

    const float timeToBuild = buildTime / buildRate;
    if (timeToBuild <= kFloatZero) {
      return kFloatZero;
    }

    return ((kFloatOne / timeToBuild) * resourceConsumed) * kTickBuildScale;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005F5670 (FUN_005F5670, func_CheckBuildRestriction)
   *
   * What it does:
   * Applies build-location restriction policy from unit blueprint physics:
   * mass deposit, hydrocarbon deposit, or unrestricted placement.
   */
  bool CheckBuildRestriction(
    const RUnitBlueprint* const blueprint,
    gpg::Rect2i* const buildArea,
    CBuildTaskHelper* const buildTaskHelper
  )
  {
    const ERuleBPUnitBuildRestriction restriction = blueprint->Physics.BuildRestriction;
    ISimResources* const resources = const_cast<ISimResources*>(buildTaskHelper->mSim->GetResources());

    if (restriction == RULEUBR_OnMassDeposit) {
      return resources->DepositIsInArea(kMass, buildArea);
    }

    if (restriction == RULEUBR_OnHydrocarbonDeposit) {
      return resources->DepositIsInArea(kHydrocarbon, buildArea);
    }

    return true;
  }

  CBuildTaskHelper::CBuildTaskHelper()
    : mUnit(nullptr)
    , mSim(nullptr)
    , mFocus{}
    , mBeingBuilt(false)
    , mPad11_13{0, 0, 0}
    , mUnknown14(0.0f)
    , mUnknown18(0.0f)
    , mDelta(0.0f)
    , mActionName()
    , mFractionComplete(0.0f)
    , mIsSilo(false)
    , mPad41_43{0, 0, 0}
  {}

  /**
   * Address: 0x005F56F0 (FUN_005F56F0, ??0CBuildTaskHelper@Moho@@QAE@@Z)
   */
  CBuildTaskHelper::CBuildTaskHelper(const char* const actionName, Unit* const unit)
    : CBuildTaskHelper()
  {
    mUnit = unit;
    mSim = unit ? unit->SimulationRef : nullptr;
    mActionName.assign_owned(actionName ? actionName : "");
  }

  /**
   * Address: 0x005F5660 (FUN_005F5660)
   *
   * What it does:
   * Stores the silo-mode flag lane and returns this helper for chained setup
   * flow.
   */
  CBuildTaskHelper* CBuildTaskHelper::SetSiloMode(const bool isSilo) noexcept
  {
    mIsSilo = isSilo;
    return this;
  }

  /**
   * Address: 0x005F5790 (FUN_005F5790, ??1CBuildTaskHelper@Moho@@QAE@@Z)
   */
  CBuildTaskHelper::~CBuildTaskHelper()
  {
    OnStopBuild(false);
    if (mUnit != nullptr) {
      mUnit->WorkProgress = 0.0f;
    }
    mFocus.UnlinkFromOwnerChain();
    mFocus.ClearLinkState();
  }

  /**
   * Address: 0x005F5A20 (FUN_005F5A20, Moho::CBuildTaskHelper::OnStopBuild)
   */
  void CBuildTaskHelper::OnStopBuild(const bool failed)
  {
    Unit* const ownerUnit = mUnit;
    Unit* const focusUnit = ResolveFocusUnit(mFocus);

    if (mBeingBuilt && ownerUnit != nullptr && !ownerUnit->IsDead()) {
      if (!failed) {
        ownerUnit->RunScript("OnFailedToBuild");
        if (focusUnit != nullptr) {
          focusUnit->RunScript("OnFailedToBeBuilt");
        }
      }

      const std::string actionName = mActionName.to_std();
      ownerUnit->OnStopBuild(mFocus, actionName);
    }

    if (ownerUnit != nullptr) {
      ownerUnit->FocusEntityRef.ResetObjectPtr<Entity>(nullptr);
      if (ownerUnit->FocusEntityRef.ResolveObjectPtr<Entity>() != nullptr) {
        ownerUnit->RunScript(kOnAssignedFocusEntity);
      }
      ownerUnit->NeedSyncGameData = true;
    }

    mFocus.UnlinkFromOwnerChain();
    mFocus.ClearLinkState();
    mBeingBuilt = false;
  }

  /**
   * Address: 0x005F5B00 (FUN_005F5B00, Moho::CBuildTaskHelper::SetFocus)
   */
  void CBuildTaskHelper::SetFocus(Unit* const focusUnit)
  {
    if (focusUnit == nullptr) {
      return;
    }

    if (Unit* const currentFocus = ResolveFocusUnit(mFocus); currentFocus != nullptr) {
      if (currentFocus == focusUnit) {
        return;
      }
      OnStopBuild(false);
    }

    if (mUnit != nullptr) {
      mUnit->FocusEntityRef.ResetObjectPtr<Entity>(focusUnit);
      if (mUnit->FocusEntityRef.ResolveObjectPtr<Entity>() != nullptr) {
        mUnit->RunScript(kOnAssignedFocusEntity);
      }
      mUnit->NeedSyncGameData = true;
    }

    mFocus.ResetFromObject(focusUnit);
    mBeingBuilt = true;

    if (mUnit != nullptr) {
      const std::string actionName = mActionName.to_std();
      mUnit->RunScriptOnStartBuild(focusUnit, actionName);
    }

    if (mDelta > 0.0f) {
      Unit* const creatorUnit = focusUnit->CreatorRef.ResolveObjectPtr<Unit>();
      if (creatorUnit == mUnit) {
        focusUnit->Materialize(mDelta);
      }
    }
  }

  /**
   * Address: 0x005F5BF0 (FUN_005F5BF0, Moho::CBuildTaskHelper::UpdateWorkProgress)
   */
  bool CBuildTaskHelper::UpdateWorkProgress()
  {
    Unit* const ownerUnit = mUnit;
    Unit* const focusUnit = ResolveFocusUnit(mFocus);
    if (ownerUnit == nullptr) {
      return false;
    }

    if (ownerUnit->IsPaused) {
      if (focusUnit == nullptr) {
        mFractionComplete = 0.0f;
        ownerUnit->WorkProgress = 0.0f;
        return false;
      }

      mFractionComplete = focusUnit->FractionCompleted;
      ownerUnit->WorkProgress = focusUnit->FractionCompleted;

      if (!ownerUnit->IsUnitState(UNITSTATE_Repairing) && focusUnit->FractionCompleted >= 1.0f) {
        return true;
      }

      focusUnit->Materialize(0.0f);
      return false;
    }

    const float resourceConsumed = ownerUnit->ResourceConsumed;

    if (mIsSilo) {
      if (focusUnit == nullptr) {
        return false;
      }

      const std::uint32_t commandCaps = focusUnit->GetAttributes().commandCapsMask;
      const bool supportsSiloBuild = (commandCaps & static_cast<std::uint32_t>(RULEUCC_SiloBuildNuke)) != 0u
        || (commandCaps & static_cast<std::uint32_t>(RULEUCC_SiloBuildTactical)) != 0u;
      if (!supportsSiloBuild) {
        return true;
      }

      if (!focusUnit->IsUnitState(UNITSTATE_SiloBuildingAmmo) || focusUnit->AiSiloBuild == nullptr) {
        return true;
      }

      SEconValue perSecond{};
      if (ownerUnit->mConsumptionData != nullptr) {
        perSecond = ownerUnit->mConsumptionData->mRequested;
      }
      perSecond.energy *= resourceConsumed;
      perSecond.mass *= resourceConsumed;

      focusUnit->AiSiloBuild->SiloAssistWithResource(perSecond);
      ownerUnit->WorkProgress = focusUnit->WorkProgress;
      return false;
    }

    if (focusUnit == nullptr) {
      return false;
    }

    if (focusUnit->IsUnitState(UNITSTATE_Enhancing)) {
      float workProgress = focusUnit->GetLuaValue("WorkProgress");
      if (workProgress < 1.0f) {
        if (resourceConsumed != 0.0f) {
          const float workItemBuildTime = focusUnit->GetLuaValue("WorkItemBuildTime");
          const float buildRate = ownerUnit->GetAttributes().buildRate;
          if (workItemBuildTime > 0.0f && buildRate > 0.0f) {
            const float tickDelta = ((1.0f / (workItemBuildTime / buildRate)) * resourceConsumed) * 0.1f;
            workProgress = std::min(1.0f, workProgress + tickDelta);
            focusUnit->SetLuaValue("WorkProgress", workProgress);
          }
        }

        ownerUnit->WorkProgress = workProgress;
        return false;
      }

      return true;
    }

    const RUnitBlueprint* const focusBlueprint = focusUnit->GetBlueprint();
    if (focusBlueprint == nullptr) {
      return false;
    }

    float buildProgressDelta = ComputeBuildProgressDelta(focusBlueprint, ownerUnit->GetAttributes(), resourceConsumed);
    const bool focusUnitIsDamaged = focusUnit->MaxHealth > focusUnit->Health;

    if (focusUnit->IsInCategory("SHIELD")) {
      Entity* const shieldEntity = focusUnit->GetFocusEntity();
      if (shieldEntity != nullptr) {
        if (!focusUnitIsDamaged && !focusUnit->RunScriptBool("ShieldIsOn")) {
          return true;
        }

        if (shieldEntity->MaxHealth > shieldEntity->Health) {
          const float buildRate = ownerUnit->GetAttributes().buildRate;
          const float regenRate = shieldEntity->GetLuaValue("RegenRate") * kTickBuildScale;
          float regenAssistMult = focusBlueprint->Defense.Shield.RegenAssistMult;
          if (regenAssistMult != 0.0f) {
            if (focusUnitIsDamaged) {
              regenAssistMult *= 2.0f;
              buildProgressDelta *= 0.5f;
            }
            shieldEntity->AdjustHealth(nullptr, (regenRate * buildRate) / regenAssistMult);
          }
        }
      }
    }

    if (focusBlueprint->Physics.FuelUseTime > 0.0f && focusUnit->FuelRatio < 1.0f) {
      float fuelTickDelta = (focusBlueprint->Physics.FuelRechargeRate / focusBlueprint->Physics.FuelUseTime) * kTickBuildScale;
      if (focusUnitIsDamaged) {
        fuelTickDelta *= 0.5f;
        buildProgressDelta *= 0.5f;
      }
      focusUnit->FuelRatio = std::min(1.0f, focusUnit->FuelRatio + fuelTickDelta);
    }

    focusUnit->Materialize((resourceConsumed != 0.0f) ? buildProgressDelta : 0.0f);

    const bool isRepairAction = mActionName.equals_no_case("Repair");
    if (isRepairAction && !focusUnit->IsBeingBuilt()) {
      if (focusUnit->MaxHealth > 0.0f) {
        ownerUnit->WorkProgress = focusUnit->Health / focusUnit->MaxHealth;
      } else {
        ownerUnit->WorkProgress = 1.0f;
      }

      if (ownerUnit->WorkProgress != 1.0f) {
        return false;
      }

      if (focusBlueprint->Physics.FuelUseTime > 0.0f) {
        return focusUnit->FuelRatio == 1.0f;
      }

      if (!focusUnit->IsInCategory("SHIELD")) {
        return true;
      }

      Entity* const shieldEntity = focusUnit->GetFocusEntity();
      if (shieldEntity == nullptr) {
        return true;
      }

      return shieldEntity->Health == shieldEntity->MaxHealth;
    }

    const float currentFraction = focusUnit->FractionCompleted;
    if (DidCrossBuildProgressBand(mFractionComplete, currentFraction)) {
      ownerUnit->RunScriptOnBuildProgress(mFocus, mFractionComplete, currentFraction);
      focusUnit->RunScriptOnBeingBuiltProgress(ownerUnit, mFractionComplete, currentFraction);
    }

    mFractionComplete = currentFraction;
    ownerUnit->WorkProgress = currentFraction;
    return currentFraction == 1.0f;
  }

  /**
   * Address: 0x005FE540 (FUN_005FE540, Moho::CBuildTaskHelper::MemberDeserialize)
   *
   * What it does:
   * Restores helper owner links, focus weak pointer, and runtime progress
   * lanes from one archive payload.
   */
  void CBuildTaskHelper::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    gpg::RRef ownerRef{};
    archive->ReadPointer_Unit(&mUnit, &ownerRef);

    ownerRef = gpg::RRef{};
    archive->ReadPointer_Sim(&mSim, &ownerRef);

    gpg::RType* const weakUnitType = ResolveWeakPtrUnitType();
    GPG_ASSERT(weakUnitType != nullptr);
    if (!weakUnitType) {
      return;
    }

    ownerRef = gpg::RRef{};
    archive->Read(weakUnitType, &mFocus, ownerRef);

    archive->ReadBool(&mBeingBuilt);
    archive->ReadFloat(&mUnknown14);
    archive->ReadFloat(&mUnknown18);
    archive->ReadFloat(&mDelta);
    archive->ReadString(&mActionName);
    archive->ReadFloat(&mFractionComplete);
    archive->ReadBool(&mIsSilo);
  }

  /**
   * Address: 0x005FE610 (FUN_005FE610, Moho::CBuildTaskHelper::MemberSerialize)
   *
   * What it does:
   * Stores helper owner links, focus weak pointer, and runtime progress lanes
   * into one archive payload.
   */
  void CBuildTaskHelper::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (!archive) {
      return;
    }

    const gpg::RRef ownerRef{};

    gpg::RRef unitRef{};
    gpg::RRef_Unit(&unitRef, mUnit);
    gpg::WriteRawPointer(archive, unitRef, gpg::TrackedPointerState::Unowned, ownerRef);

    gpg::RRef simRef{};
    simRef.mObj = mSim;
    simRef.mType = mSim ? ResolveSimType() : nullptr;
    gpg::WriteRawPointer(archive, simRef, gpg::TrackedPointerState::Unowned, ownerRef);

    gpg::RType* const weakUnitType = ResolveWeakPtrUnitType();
    GPG_ASSERT(weakUnitType != nullptr);
    if (!weakUnitType) {
      return;
    }

    archive->Write(weakUnitType, &mFocus, ownerRef);
    archive->WriteBool(mBeingBuilt);
    archive->WriteFloat(mUnknown14);
    archive->WriteFloat(mUnknown18);
    archive->WriteFloat(mDelta);
    archive->WriteString(const_cast<msvc8::string*>(&mActionName));
    archive->WriteFloat(mFractionComplete);
    archive->WriteBool(mIsSilo);
  }
} // namespace moho
