#include "REffectBlueprint.h"

namespace moho
{
  /**
   * Address: 0x0050E650 (FUN_0050E650, scalar deleting dtor thunk)
   *
   * What it does:
   * Releases `BlueprintId` storage and tears down to `gpg::RObject`.
   */
  REffectBlueprint::~REffectBlueprint() = default;

  /**
   * Address: 0x0050E620 (FUN_0050E620)
   *
   * What it does:
   * Base effect-blueprint trail cast hook. Returns nullptr.
   */
  RTrailBlueprint* REffectBlueprint::IsTrail()
  {
    return nullptr;
  }

  /**
   * Address: 0x0050E630 (FUN_0050E630)
   *
   * What it does:
   * Base effect-blueprint beam cast hook. Returns nullptr.
   */
  RBeamBlueprint* REffectBlueprint::IsBeam()
  {
    return nullptr;
  }

  /**
   * Address: 0x0050E640 (FUN_0050E640)
   *
   * What it does:
   * Base effect-blueprint emitter cast hook. Returns nullptr.
   */
  REmitterBlueprint* REffectBlueprint::IsEmitter()
  {
    return nullptr;
  }
} // namespace moho
