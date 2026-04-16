#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/resource/RResId.h"

namespace moho
{
  /**
   * Address: 0x0051D4B0 (FUN_0051D4B0)
   *
   * What it does:
   * Reflection type init for `RPropBlueprintDisplay`
   * (`MeshBlueprint` at +0x00, `UniformScale` at +0x1C, size 0x20).
   */
  struct RPropBlueprintDisplay
  {
    RResId MeshBlueprint; // +0x00
    float UniformScale;   // +0x1C
  };

  /**
   * Address: 0x0051D650 (FUN_0051D650)
   *
   * What it does:
   * Reflection type init for `RPropBlueprintDefense`
   * (`MaxHealth` +0x00, `Health` +0x04, size 0x08).
   */
  struct RPropBlueprintDefense
  {
    float MaxHealth; // +0x00
    float Health;    // +0x04
  };

  /**
   * Address: 0x0051D800 (FUN_0051D800)
   *
   * What it does:
   * Reflection type init for `RPropBlueprintEconomy`
   * (`ReclaimMassMax` +0x00, `ReclaimEnergyMax` +0x04, size 0x08).
   */
  struct RPropBlueprintEconomy
  {
    float ReclaimMassMax;   // +0x00
    float ReclaimEnergyMax; // +0x04
  };

  /**
   * Address: 0x0051D9B0 (FUN_0051D9B0)
   *
   * What it does:
   * Reflection type init sets `sizeof(RPropBlueprint) = 0x1AC` and
   * registers nested fields: `Display` (+0x17C), `Defense` (+0x19C),
   * `Economy` (+0x1A4).
   */
  struct RPropBlueprint : public REntityBlueprint
  {
    RPropBlueprintDisplay Display; // +0x017C
    RPropBlueprintDefense Defense; // +0x019C
    RPropBlueprintEconomy Economy; // +0x01A4
    static gpg::RType* sType;

    /**
     * Address: 0x0051D250 (FUN_0051D250)
     * Mangled: ??0RPropBlueprint@Moho@@QAE@PAVRRuleGameRules@1@ABVRResId@1@@Z
     *
     * What it does:
     * Runs base entity-blueprint construction with `(owner, resId)` and seeds
     * prop display/defense/economy defaults.
     */
    RPropBlueprint(RRuleGameRules* owner, const RResId& resId);

    /**
     * Local source-compat convenience constructor for scratch/default lanes.
     */
    RPropBlueprint();

    /**
     * Address: 0x0051D210 (FUN_0051D210)
     * Mangled: ?GetClass@RPropBlueprint@Moho@@UBEPAVRType@gpg@@XZ
     *
     * What it does:
     * Returns cached reflection descriptor for `RPropBlueprint`.
     */
    [[nodiscard]] gpg::RType* GetClass() const;

    /**
     * Address: 0x0051D230 (FUN_0051D230)
     * Mangled: ?GetDerivedObjectRef@RPropBlueprint@Moho@@UAE?AVRRef@gpg@@XZ
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef();

    /**
     * Address: 0x0051D370 (FUN_0051D370)
     * Mangled: ?OnInitBlueprint@RPropBlueprint@Moho@@MAEXXZ
     *
     * What it does:
     * Runs base entity-blueprint init and canonicalizes `Display.MeshBlueprint`
     * to a completed, lowercase, slash-normalized resource path.
     */
    void OnInitBlueprint();
  };

  static_assert(sizeof(RPropBlueprintDisplay) == 0x20, "RPropBlueprintDisplay size must be 0x20");
  static_assert(sizeof(RPropBlueprintDefense) == 0x08, "RPropBlueprintDefense size must be 0x08");
  static_assert(sizeof(RPropBlueprintEconomy) == 0x08, "RPropBlueprintEconomy size must be 0x08");

  static_assert(
    offsetof(RPropBlueprintDisplay, MeshBlueprint) == 0x00, "RPropBlueprintDisplay::MeshBlueprint offset must be 0x00"
  );
  static_assert(
    offsetof(RPropBlueprintDisplay, UniformScale) == 0x1C, "RPropBlueprintDisplay::UniformScale offset must be 0x1C"
  );
  static_assert(
    offsetof(RPropBlueprintDefense, MaxHealth) == 0x00, "RPropBlueprintDefense::MaxHealth offset must be 0x00"
  );
  static_assert(offsetof(RPropBlueprintDefense, Health) == 0x04, "RPropBlueprintDefense::Health offset must be 0x04");
  static_assert(
    offsetof(RPropBlueprintEconomy, ReclaimMassMax) == 0x00, "RPropBlueprintEconomy::ReclaimMassMax offset must be 0x00"
  );
  static_assert(
    offsetof(RPropBlueprintEconomy, ReclaimEnergyMax) == 0x04,
    "RPropBlueprintEconomy::ReclaimEnergyMax offset must be 0x04"
  );

  static_assert(offsetof(RPropBlueprint, Display) == 0x17C, "RPropBlueprint::Display offset must be 0x17C");
  static_assert(offsetof(RPropBlueprint, Defense) == 0x19C, "RPropBlueprint::Defense offset must be 0x19C");
  static_assert(offsetof(RPropBlueprint, Economy) == 0x1A4, "RPropBlueprint::Economy offset must be 0x1A4");
  static_assert(sizeof(RPropBlueprint) == 0x1AC, "RPropBlueprint size must be 0x1AC");
} // namespace moho
