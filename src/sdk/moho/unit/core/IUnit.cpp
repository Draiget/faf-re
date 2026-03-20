// Auto-generated from IDA VFTABLE/RTTI scan.
#include "moho/unit/core/IUnit.h"

#include <cstdint>

#include "moho/render/camera/VTransform.h"
#include "moho/sim/STIMap.h"

using namespace moho;

namespace
{
  constexpr float kNoWaterElevation = -10000.0f;
  constexpr std::uint32_t kLayerMaskLandOrSeabed = 0x03u;
  constexpr std::uint32_t kLayerMaskSub = 0x04u;
  constexpr std::uint32_t kLayerMaskWater = 0x08u;
  constexpr std::uint32_t kLayerMaskAirOrOrbit = 0x30u;
} // namespace

/**
 * Address: 0x006A48C0 (?IsUnit@IUnit@Moho@@UBEPBVUnit@2@XZ)
 *
 * Moho::Unit const *
 *
 * IDA signature:
 * const struct Moho::Unit *__thiscall Moho::IUnit::IsUnit(Moho::IUnit *this)
 *
 * What it does:
 * Base IUnit downcast hook for const callers; default implementation reports "not a Unit".
 */
Unit const* IUnit::IsUnit() const
{
  return nullptr;
}

/**
 * Address: 0x006A48B0 (?IsUnit@IUnit@Moho@@UAEPAVUnit@2@XZ)
 *
 * Moho::Unit *
 *
 * IDA signature:
 * struct Moho::Unit *__thiscall Moho::IUnit::IsUnit(Moho::IUnit *this)
 *
 * What it does:
 * Base IUnit downcast hook for mutable callers; default implementation reports "not a Unit".
 */
Unit* IUnit::IsUnit()
{
  return nullptr;
}

/**
 * Address: 0x006A48E0 (?IsUserUnit@IUnit@Moho@@UBEPBVUserUnit@2@XZ)
 *
 * Moho::UserUnit const *
 *
 * IDA signature:
 * const struct Moho::UserUnit *__thiscall Moho::IUnit::IsUserUnit(Moho::IUnit *this)
 *
 * What it does:
 * Base IUnit downcast hook for const user-unit checks; default implementation returns null.
 */
UserUnit const* IUnit::IsUserUnit() const
{
  return nullptr;
}

/**
 * Address: 0x006A48D0 (?IsUserUnit@IUnit@Moho@@UAEPAVUserUnit@2@XZ)
 *
 * Moho::UserUnit *
 *
 * IDA signature:
 * struct Moho::UserUnit *__thiscall Moho::IUnit::IsUserUnit(Moho::IUnit *this)
 *
 * What it does:
 * Base IUnit downcast hook for mutable user-unit checks; default implementation returns null.
 */
UserUnit* IUnit::IsUserUnit()
{
  return nullptr;
}

/**
 * Address: 0x00541540 (FUN_00541540), 0x1012EEF0 (FUN_1012EEF0)
 * Mangled: ?CalcSpawnElevation@IUnit@Moho@@SAMPBVSTIMap@2@W4ELayer@2@VVTransform@2@ABUUnitAttributes@2@@Z
 *
 * Moho::STIMap const *, Moho::ELayer, Moho::VTransform, Moho::UnitAttributes const &
 *
 * IDA signature:
 * double __cdecl Moho::IUnit::CalcSpawnElevation(...);
 *
 * What it does:
 * Computes spawn elevation using layer flags and UnitAttributes::spawnElevationOffset.
 */
float IUnit::CalcSpawnElevation(
  const STIMap* map, const ELayer layer, const VTransform transform, const UnitAttributes& attributes
)
{
  const std::uint32_t layerMask = static_cast<std::uint32_t>(layer);

  if ((layerMask & kLayerMaskLandOrSeabed) != 0u) {
    return map->GetHeightField()->GetElevation(transform.pos_.x, transform.pos_.z);
  }

  if ((layerMask & kLayerMaskWater) != 0u) {
    return map->IsWaterEnabled() ? map->GetWaterElevation() : kNoWaterElevation;
  }

  if ((layerMask & kLayerMaskSub) != 0u) {
    const float waterSurface = map->IsWaterEnabled() ? map->GetWaterElevation() : kNoWaterElevation;
    return attributes.spawnElevationOffset + waterSurface;
  }

  if ((layerMask & kLayerMaskAirOrOrbit) != 0u) {
    return map->GetSurface(transform.pos_) + attributes.spawnElevationOffset;
  }

  return 0.0f;
}
