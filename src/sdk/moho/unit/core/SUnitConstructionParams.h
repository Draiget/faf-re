#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/render/camera/VTransform.h"

namespace moho
{
  class CArmyImpl;
  struct RUnitBlueprint;
  class Unit;

  /**
   * Address context:
   * - 0x00748AA0 (cheat CreateUnit entry)
   * - 0x007489E0 (Sim::CreateUnit(const SUnitConstructionParams&, bool))
   * - 0x007468E0 (unit transfer path)
   *
   * What it does:
   * Carries unit spawn/build parameters into Sim/Unit construction routines.
   */
  struct SUnitConstructionParams
  {
    CArmyImpl* mArmy;                 // +0x00
    const RUnitBlueprint* mBlueprint; // +0x04
    VTransform mTransform;            // +0x08
    std::uint8_t mUseLayerOverride;   // +0x24
    std::uint8_t mFixElevation;       // +0x25
    std::uint8_t pad_26[2];           // +0x26
    std::int32_t mLayer;              // +0x28
    Unit* mLinkSourceUnit;            // +0x2C (used for linked construction ownership in Unit ctor path)
    std::uint8_t mComplete;           // +0x30
    std::uint8_t pad_31[3];           // +0x31
  };

  static_assert(offsetof(SUnitConstructionParams, mArmy) == 0x00, "SUnitConstructionParams::mArmy offset must be 0x00");
  static_assert(
    offsetof(SUnitConstructionParams, mBlueprint) == 0x04, "SUnitConstructionParams::mBlueprint offset must be 0x04"
  );
  static_assert(
    offsetof(SUnitConstructionParams, mTransform) == 0x08, "SUnitConstructionParams::mTransform offset must be 0x08"
  );
  static_assert(
    offsetof(SUnitConstructionParams, mUseLayerOverride) == 0x24,
    "SUnitConstructionParams::mUseLayerOverride offset must be 0x24"
  );
  static_assert(
    offsetof(SUnitConstructionParams, mFixElevation) == 0x25,
    "SUnitConstructionParams::mFixElevation offset must be 0x25"
  );
  static_assert(
    offsetof(SUnitConstructionParams, mLayer) == 0x28, "SUnitConstructionParams::mLayer offset must be 0x28"
  );
  static_assert(
    offsetof(SUnitConstructionParams, mLinkSourceUnit) == 0x2C,
    "SUnitConstructionParams::mLinkSourceUnit offset must be 0x2C"
  );
  static_assert(
    offsetof(SUnitConstructionParams, mComplete) == 0x30, "SUnitConstructionParams::mComplete offset must be 0x30"
  );
  static_assert(sizeof(SUnitConstructionParams) == 0x34, "SUnitConstructionParams size must be 0x34");
} // namespace moho
