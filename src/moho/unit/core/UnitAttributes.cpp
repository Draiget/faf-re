#include "moho/unit/core/UnitAttributes.h"

#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprintCapabilityEnums.h"
#include "moho/sim/RRuleGameRules.h"
#include "gpg/core/reflection/StaticInitPhase.h"

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

    const EntityCategorySet* const emptyCategory = rules->GetEntityCategory("");
    restrictionCategory.mUniverse = emptyCategory->mUniverse;
    restrictionCategory.mBits.mFirstWordIndex = emptyCategory->mBits.mFirstWordIndex;

    // `gpg::fastvector_uint::cpy` in the binary - a real copy into our own
    // storage. Assigning the three pointer lanes instead aliased the empty
    // category's buffer while `originalVec_` still pointed at our inline one,
    // so the `ResetStorageToInline` below saw `start_ != originalVec_` and
    // `delete[]`-ed memory this vector never owned. Every unit constructed
    // handed one live block back to the allocator; the ones that landed on
    // interned Lua strings unlinked them from the string table and eventually
    // crashed the sim in the next collection.
    restrictionCategory.mBits.mWords.ResetFrom(emptyCategory->mBits.mWords);

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
  void UnitAttributes::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    const gpg::RRef ownerRef{};

    auto* loadedBlueprint = const_cast<RUnitBlueprint*>(blueprint);
    archive->ReadPointer(&loadedBlueprint, &ownerRef);
    blueprint = loadedBlueprint;

    archive->Read(CachedEntityCategorySetType(), &restrictionCategory, ownerRef);
    archive->ReadFloat(&spawnElevationOffset);
    archive->ReadFloat(&moveSpeedMult);
    archive->ReadFloat(&accelerationMult);
    archive->ReadFloat(&turnMult);
    archive->ReadFloat(&breakOffTriggerMult);
    archive->ReadFloat(&breakOffDistanceMult);
    archive->ReadFloat(&consumptionPerSecondEnergy);
    archive->ReadFloat(&consumptionPerSecondMass);
    archive->ReadFloat(&productionPerSecondEnergy);
    archive->ReadFloat(&productionPerSecondMass);
    archive->ReadFloat(&buildRate);
    archive->ReadFloat(&regenRate);

    auto commandCaps = static_cast<ERuleBPUnitCommandCaps>(commandCapsMask);
    archive->Read(CachedCommandCapsType(), &commandCaps, ownerRef);
    commandCapsMask = static_cast<std::uint32_t>(commandCaps);

    auto toggleCaps = static_cast<ERuleBPUnitToggleCaps>(toggleCapsMask);
    archive->Read(CachedToggleCapsType(), &toggleCaps, ownerRef);
    toggleCapsMask = static_cast<std::uint32_t>(toggleCaps);

    archive->ReadBool(&mReclaimable);
    archive->ReadBool(&mCapturable);
  }

  /**
   * Address: 0x0055DD80 (FUN_0055DD80, Moho::UnitAttributes::MemberSerialize)
   *
   * What it does:
   * Serializes pointer/category/float/caps/bool lanes from one
   * `UnitAttributes` object.
   */
  void UnitAttributes::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    const gpg::RRef ownerRef{};

    archive->WritePointer<moho::RUnitBlueprint>(const_cast<RUnitBlueprint*>(blueprint), gpg::TrackedPointerState::Unowned, ownerRef);

    archive->Write(CachedEntityCategorySetType(), &restrictionCategory, ownerRef);
    archive->WriteFloat(spawnElevationOffset);
    archive->WriteFloat(moveSpeedMult);
    archive->WriteFloat(accelerationMult);
    archive->WriteFloat(turnMult);
    archive->WriteFloat(breakOffTriggerMult);
    archive->WriteFloat(breakOffDistanceMult);
    archive->WriteFloat(consumptionPerSecondEnergy);
    archive->WriteFloat(consumptionPerSecondMass);
    archive->WriteFloat(productionPerSecondEnergy);
    archive->WriteFloat(productionPerSecondMass);
    archive->WriteFloat(buildRate);
    archive->WriteFloat(regenRate);

    const auto commandCaps = static_cast<ERuleBPUnitCommandCaps>(commandCapsMask);
    archive->Write(CachedCommandCapsType(), &commandCaps, ownerRef);

    const auto toggleCaps = static_cast<ERuleBPUnitToggleCaps>(toggleCapsMask);
    archive->Write(CachedToggleCapsType(), &toggleCaps, ownerRef);

    archive->WriteBool(mReclaimable);
    archive->WriteBool(mCapturable);
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

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_UnitAttributesTypeInfo_ff51a9, moho::preregister_UnitAttributesTypeInfo)

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<UnitAttributes>`, vtable 0x00E187DC.
   *
   * Address: 0x00BCA5E0 (FUN_00BCA5E0 -- constructs the global and registers its destructor.)
   * Address: 0x00BF5390 (FUN_00BF5390 -- the global's destructor.)
   * Address: 0x0055CAE0 (FUN_0055CAE0 -- `Init`.)
   * Address: 0x0055C350 (FUN_0055C350 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x0055C360 (FUN_0055C360 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct UnitAttributesSerializer : gpg::SerSaveLoadHelper<UnitAttributes>
  {};
} // namespace moho

namespace
{
  // Address: 0x010ACCF8 -- process-global `UnitAttributesSerializer` singleton.
  moho::UnitAttributesSerializer gUnitAttributesSerializer;
} // namespace
