#pragma once

#include <string>

#include "editor/doc/EdUnitFate.h"

namespace faf::editor
{
  class EdDocument;

  /** A unit blueprint's wreck as the game makes it (its costs from the kept rules, its `.bp` for the Wreckage table). */
  struct BlueprintWreck
  {
    /** False until the rules are built, or for a blueprint they don't have. */
    bool known = false;
    double buildMass = 0.0;
    double buildEnergy = 0.0;
    WreckValue wreck;
  };
  BlueprintWreck UnitBlueprintWreck(const std::string& id, bool underwater);

  /** Whether the ground at (x, z) of the open map lies below its water (a wreck there is worth 0.6 of one on land). */
  bool UnderWater(const EdDocument& document, float x, float z);

  /** The map's units that become wrecks (FateOfUnit): from the start, and only when the script creates their groups. */
  struct UnitWreckTotals
  {
    int startCount = 0;
    double startMass = 0.0;
    double startEnergy = 0.0;
    /** Every group the script may create as wrecks, all of them (the lobby's highest options). */
    int scriptCount = 0;
    double scriptMass = 0.0;
    double scriptEnergy = 0.0;
    /** Units whose blueprint the rules haven't got. */
    int unknown = 0;
  };
  UnitWreckTotals MapUnitWrecks(const EdDocument& document);
} // namespace faf::editor
