#include "moho/unit/core/UnitAttributes.h"

#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/resource/blueprints/RUnitBlueprintCapabilityEnums.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedUnitAttributesType()
  {
    gpg::RType* type = moho::UnitAttributes::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::UnitAttributes));
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
} // namespace

namespace moho
{
  gpg::RType* UnitAttributes::sType = nullptr;

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
