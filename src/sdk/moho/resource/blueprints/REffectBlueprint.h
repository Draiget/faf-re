#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/resource/RResId.h"

namespace moho
{
  class RRuleGameRules;
  struct RBeamBlueprint;
  struct REmitterBlueprint;
  struct RTrailBlueprint;

  /**
   * Address: 0x0050F080 (FUN_0050F080)
   *
   * What it does:
   * Reflection type init for the common effect-blueprint base (`sizeof = 0x28`)
   * and fields: `BlueprintId` (+0x08), fidelity flags (+0x24..+0x26).
   */
  struct REffectBlueprint : public gpg::RObject
  {
    RRuleGameRules* mOwnerRules;  // +0x04
    RResId BlueprintId;           // +0x08
    std::uint8_t HighFidelity{1}; // +0x24
    std::uint8_t MedFidelity{1};  // +0x25
    std::uint8_t LowFidelity{1};  // +0x26
    std::uint8_t pad_0027{0};     // +0x27

    /**
     * Address: 0x0050E5F0 (FUN_0050E5F0, Moho::REffectBlueprint::REffectBlueprint)
     *
     * What it does:
     * Initializes the base effect-blueprint lane with null owner, empty
     * resource id, and all fidelity flags enabled.
     */
    REffectBlueprint();

    /**
     * Address: 0x00A82547 (`_purecall`)
     * Slot: 0
     */
    [[nodiscard]] gpg::RType* GetClass() const override = 0;

    /**
     * Address: 0x00A82547 (`_purecall`)
     * Slot: 1
     */
    gpg::RRef GetDerivedObjectRef() override = 0;

    /**
     * Address: 0x0050E650 (FUN_0050E650, scalar deleting dtor thunk)
     * Slot: 2
     *
     * What it does:
     * Releases `BlueprintId` storage and tears down to `gpg::RObject`.
     */
    ~REffectBlueprint() override;

    /**
     * Address: 0x0050E620 (FUN_0050E620)
     *
     * What it does:
     * Base effect-blueprint trail cast hook. Returns nullptr.
     */
    [[nodiscard]] virtual RTrailBlueprint* IsTrail();

    /**
     * Address: 0x0050E630 (FUN_0050E630)
     *
     * What it does:
     * Base effect-blueprint beam cast hook. Returns nullptr.
     */
    [[nodiscard]] virtual RBeamBlueprint* IsBeam();

    /**
     * Address: 0x0050E640 (FUN_0050E640)
     *
     * What it does:
     * Base effect-blueprint emitter cast hook. Returns nullptr.
     */
    [[nodiscard]] virtual REmitterBlueprint* IsEmitter();
  };

  static_assert(offsetof(REffectBlueprint, mOwnerRules) == 0x04, "REffectBlueprint::mOwnerRules offset must be 0x04");
  static_assert(offsetof(REffectBlueprint, BlueprintId) == 0x08, "REffectBlueprint::BlueprintId offset must be 0x08");
  static_assert(offsetof(REffectBlueprint, HighFidelity) == 0x24, "REffectBlueprint::HighFidelity offset must be 0x24");
  static_assert(offsetof(REffectBlueprint, MedFidelity) == 0x25, "REffectBlueprint::MedFidelity offset must be 0x25");
  static_assert(offsetof(REffectBlueprint, LowFidelity) == 0x26, "REffectBlueprint::LowFidelity offset must be 0x26");
  static_assert(sizeof(REffectBlueprint) == 0x28, "REffectBlueprint size must be 0x28");
} // namespace moho
