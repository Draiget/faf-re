#include "moho/unit/core/UnitAttributes.h"

#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprintCapabilityEnums.h"
#include "moho/sim/RRuleGameRules.h"

namespace
{
  class UnitAttributesTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "UnitAttributes";
    }

    void Init() override
    {
      size_ = sizeof(moho::UnitAttributes);
      gpg::RType::Init();
      Finish();
    }
  };

  [[nodiscard]] gpg::RType* CachedUnitAttributesType()
  {
    gpg::RType* type = moho::UnitAttributes::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::UnitAttributes));
      if (!type) {
        type = moho::preregister_UnitAttributesTypeInfo();
      }
      moho::UnitAttributes::sType = type;
    }

    return type;
  }

  [[nodiscard]] gpg::RType* CachedEntityCategorySetType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::EntityCategorySet));
    }

    return type;
  }

  [[nodiscard]] gpg::RType* CachedCommandCapsType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::ERuleBPUnitCommandCaps));
    }

    return type;
  }

  [[nodiscard]] gpg::RType* CachedToggleCapsType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::ERuleBPUnitToggleCaps));
    }

    return type;
  }

  /**
   * Address: 0x006A47F0 (FUN_006A47F0)
   *
   * What it does:
   * Restores unit spawn-elevation lane from blueprint physics elevation.
   */
  [[maybe_unused]] moho::UnitAttributes* RestoreSpawnElevationFromBlueprint(moho::UnitAttributes* const attributes) noexcept
  {
    attributes->spawnElevationOffset = attributes->blueprint->Physics.Elevation;
    return attributes;
  }

  /**
   * Address: 0x006A4830 (FUN_006A4830)
   *
   * What it does:
   * Restores unit regen-rate lane from blueprint defense data.
   */
  [[maybe_unused]] moho::UnitAttributes* RestoreRegenRateFromBlueprint(moho::UnitAttributes* const attributes) noexcept
  {
    attributes->regenRate = attributes->blueprint->Defense.RegenRate;
    return attributes;
  }

  /**
   * Address: 0x006A4840 (FUN_006A4840)
   *
   * What it does:
   * Restores unit build-rate lane from blueprint economy data.
   */
  [[maybe_unused]] moho::UnitAttributes* RestoreBuildRateFromBlueprint(moho::UnitAttributes* const attributes) noexcept
  {
    attributes->buildRate = attributes->blueprint->Economy.BuildRate;
    return attributes;
  }

  /**
   * Address: 0x006A4850 (FUN_006A4850)
   *
   * What it does:
   * Restores unit command-capability mask from blueprint general data.
   */
  [[maybe_unused]] moho::UnitAttributes* RestoreCommandCapsFromBlueprint(moho::UnitAttributes* const attributes) noexcept
  {
    attributes->commandCapsMask = static_cast<std::uint32_t>(attributes->blueprint->General.CommandCaps);
    return attributes;
  }

  /**
   * Address: 0x006A4860 (FUN_006A4860)
   *
   * What it does:
   * Restores unit toggle-capability mask from blueprint general data.
   */
  [[maybe_unused]] moho::UnitAttributes* RestoreToggleCapsFromBlueprint(moho::UnitAttributes* const attributes) noexcept
  {
    attributes->toggleCapsMask = static_cast<std::uint32_t>(attributes->blueprint->General.ToggleCaps);
    return attributes;
  }
} // namespace

namespace moho
{
  gpg::RType* UnitAttributes::sType = nullptr;

  /**
   * Address: 0x006A4760 (FUN_006A4760, Moho::UnitAttributes::UnitAttributes)
   *
   * What it does:
   * Copies rule-empty category universe lanes, clears category bit words back
   * to inline-empty storage, then restores blueprint-driven elevation/rates/caps.
   */
  UnitAttributes::UnitAttributes(const RUnitBlueprint* const unitBlueprint, const RRuleGameRulesImpl* const rules)
  {
    blueprint = unitBlueprint;

    const CategoryWordRangeView* const emptyCategory = rules->GetEntityCategory("");
    restrictionCategory.mUniverse = emptyCategory->mUniverse;
    restrictionCategory.mBits.mFirstWordIndex = emptyCategory->mBits.mFirstWordIndex;
    restrictionCategory.mBits.mWords.start_ = emptyCategory->mBits.mWords.start_;
    restrictionCategory.mBits.mWords.end_ = emptyCategory->mBits.mWords.end_;
    restrictionCategory.mBits.mWords.capacity_ = emptyCategory->mBits.mWords.capacity_;

    (void)RestoreSpawnElevationFromBlueprint(this);

    restrictionCategory.mBits.mFirstWordIndex = 0u;
    restrictionCategory.mBits.mWords.ResetStorageToInline();

    (void)RestoreRegenRateFromBlueprint(this);
    (void)RestoreBuildRateFromBlueprint(this);
    (void)RestoreCommandCapsFromBlueprint(this);
    (void)RestoreToggleCapsFromBlueprint(this);
  }

  /**
   * Address: 0x0055C210 (FUN_0055C210, preregister_UnitAttributesTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `UnitAttributes`.
   */
  gpg::RType* preregister_UnitAttributesTypeInfo()
  {
    static UnitAttributesTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(UnitAttributes), &typeInfo);
    UnitAttributes::sType = &typeInfo;
    return &typeInfo;
  }

  /**
   * Address: 0x0055C2D0 (FUN_0055C2D0, Moho::UnitAttributes::StaticGetClass)
   *
   * What it does:
   * Returns the cached reflection descriptor for `UnitAttributes`.
   */
  gpg::RType* UnitAttributes::StaticGetClass()
  {
    return CachedUnitAttributesType();
  }

  /**
   * Address: 0x0055DC00 (FUN_0055DC00, Moho::UnitAttributes::MemberDeserialize)
   *
   * What it does:
   * Deserializes pointer/category/float/caps/bool lanes into one
   * `UnitAttributes` object.
   */
  void UnitAttributes::MemberDeserialize(gpg::ReadArchive* const archive, UnitAttributes* const attributes)
  {
    const gpg::RRef ownerRef{};

    auto* blueprint = const_cast<RUnitBlueprint*>(attributes->blueprint);
    archive->ReadPointer_RUnitBlueprint(&blueprint, &ownerRef);
    attributes->blueprint = blueprint;

    archive->Read(CachedEntityCategorySetType(), &attributes->restrictionCategory, ownerRef);
    archive->ReadFloat(&attributes->spawnElevationOffset);
    archive->ReadFloat(&attributes->moveSpeedMult);
    archive->ReadFloat(&attributes->accelerationMult);
    archive->ReadFloat(&attributes->turnMult);
    archive->ReadFloat(&attributes->breakOffTriggerMult);
    archive->ReadFloat(&attributes->breakOffDistanceMult);
    archive->ReadFloat(&attributes->consumptionPerSecondEnergy);
    archive->ReadFloat(&attributes->consumptionPerSecondMass);
    archive->ReadFloat(&attributes->productionPerSecondEnergy);
    archive->ReadFloat(&attributes->productionPerSecondMass);
    archive->ReadFloat(&attributes->buildRate);
    archive->ReadFloat(&attributes->regenRate);

    auto commandCaps = static_cast<ERuleBPUnitCommandCaps>(attributes->commandCapsMask);
    archive->Read(CachedCommandCapsType(), &commandCaps, ownerRef);
    attributes->commandCapsMask = static_cast<std::uint32_t>(commandCaps);

    auto toggleCaps = static_cast<ERuleBPUnitToggleCaps>(attributes->toggleCapsMask);
    archive->Read(CachedToggleCapsType(), &toggleCaps, ownerRef);
    attributes->toggleCapsMask = static_cast<std::uint32_t>(toggleCaps);

    archive->ReadBool(&attributes->mReclaimable);
    archive->ReadBool(&attributes->mCapturable);
  }

  /**
   * Address: 0x0055DD80 (FUN_0055DD80, Moho::UnitAttributes::MemberSerialize)
   *
   * What it does:
   * Serializes pointer/category/float/caps/bool lanes from one
   * `UnitAttributes` object.
   */
  void UnitAttributes::MemberSerialize(const UnitAttributes* const attributes, gpg::WriteArchive* const archive)
  {
    const gpg::RRef ownerRef{};

    gpg::RRef blueprintRef{};
    gpg::RRef_RUnitBlueprint(&blueprintRef, const_cast<RUnitBlueprint*>(attributes->blueprint));
    gpg::WriteRawPointer(archive, blueprintRef, gpg::TrackedPointerState::Unowned, ownerRef);

    archive->Write(CachedEntityCategorySetType(), &attributes->restrictionCategory, ownerRef);
    archive->WriteFloat(attributes->spawnElevationOffset);
    archive->WriteFloat(attributes->moveSpeedMult);
    archive->WriteFloat(attributes->accelerationMult);
    archive->WriteFloat(attributes->turnMult);
    archive->WriteFloat(attributes->breakOffTriggerMult);
    archive->WriteFloat(attributes->breakOffDistanceMult);
    archive->WriteFloat(attributes->consumptionPerSecondEnergy);
    archive->WriteFloat(attributes->consumptionPerSecondMass);
    archive->WriteFloat(attributes->productionPerSecondEnergy);
    archive->WriteFloat(attributes->productionPerSecondMass);
    archive->WriteFloat(attributes->buildRate);
    archive->WriteFloat(attributes->regenRate);

    const auto commandCaps = static_cast<ERuleBPUnitCommandCaps>(attributes->commandCapsMask);
    archive->Write(CachedCommandCapsType(), &commandCaps, ownerRef);

    const auto toggleCaps = static_cast<ERuleBPUnitToggleCaps>(attributes->toggleCapsMask);
    archive->Write(CachedToggleCapsType(), &toggleCaps, ownerRef);

    archive->WriteBool(attributes->mReclaimable);
    archive->WriteBool(attributes->mCapturable);
  }
} // namespace moho

namespace
{
  struct UnitAttributesTypeInfoBootstrap
  {
    UnitAttributesTypeInfoBootstrap()
    {
      (void)moho::preregister_UnitAttributesTypeInfo();
    }
  };

  [[maybe_unused]] UnitAttributesTypeInfoBootstrap gUnitAttributesTypeInfoBootstrap;
} // namespace
