#include "moho/misc/MiscellaneousExtractor.h"

#include "moho/entity/UserEntity.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/UserUnit.h"

namespace moho
{
  /**
   * Address: 0x007EDB10 (FUN_007EDB10)
   */
  MiscellaneousExtractor::~MiscellaneousExtractor() = default;

  /**
   * Address: 0x007ED430 (FUN_007ED430, Moho::MiscellaneousExtractor::Range)
   */
  bool MiscellaneousExtractor::Range(
    SRangeExtractionPayload* const outRange, const RUnitBlueprint* const unitBlueprint, const Wm3::Vec3f& center
  ) const
  {
    if (!outRange || !unitBlueprint) {
      return false;
    }

    const float radius = ResolvePositiveRadius(
      unitBlueprint->AI.StagingPlatformScanRadius, unitBlueprint->AI.GuardScanRadius
    );
    return StoreRangeAtCenter(outRange, center, radius);
  }

  /**
   * Address: 0x007ED370 (FUN_007ED370, Moho::MiscellaneousExtractor::Extract)
   *
   * What it does:
   * Takes the same two blueprint AI radii `Range` reads, but for a live unit:
   * `IUnit::GetBlueprint` (slot 7) then the staging-platform radius, falling
   * back to the guard radius when it is not positive, and places the ring at
   * the entity's interpolated position.
   *
   * Disassembly: `mov eax,[esi+0x148]` / `mov edx,[eax+0x1c]` /
   * `lea ecx,[esi+0x148]` / `call edx` at 0x007ED37D..0x007ED38D is the
   * `IUnit` subobject's virtual `GetBlueprint` - `sizeof(UserEntity)` is
   * 0x148, so that displacement is `UserUnit`'s `IUnit` base. The two floats
   * it then reads, `[eax+0x468]` and `[eax+0x460]`, are
   * `RUnitBlueprint::AI` (+0x460) `.StagingPlatformScanRadius` (+0x08) and
   * `.GuardScanRadius` (+0x00) - the values `blueprints-units.lua` fills in
   * for every engineer, factory and ACU to drive the Build Range overlay.
   *
   * The binary performs the upcast unchecked, relying on the caller having
   * already filtered the candidate pool by category; the `IsUserUnit` guard
   * here costs nothing and cannot change the outcome for any entity that
   * filter admits.
   */
  bool MiscellaneousExtractor::Extract(
    SRangeExtractionPayload* const outRange, const UserEntity* const userEntity, const float interpolationAlpha
  ) const
  {
    if (!outRange || !userEntity) {
      return false;
    }

    const UserUnit* const userUnit = userEntity->IsUserUnit();
    if (userUnit == nullptr) {
      return false;
    }

    const RUnitBlueprint* const unitBlueprint = static_cast<const IUnit*>(userUnit)->GetBlueprint();
    if (unitBlueprint == nullptr) {
      return false;
    }

    const float radius = ResolvePositiveRadius(
      unitBlueprint->AI.StagingPlatformScanRadius, unitBlueprint->AI.GuardScanRadius
    );
    return StoreRangeAtEntity(outRange, *userEntity, interpolationAlpha, radius);
  }
} // namespace moho
