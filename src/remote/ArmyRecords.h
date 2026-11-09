#pragma once

#include "remote/wire/ArmyLane.h"

// Engine addition, server mode (plan WP5.13): an army's variable data as the army lane carries it
// (remote/wire/ArmyLane.h) and back. The path preview's cells and footprint pointer are not
// carried; `FromWire` leaves them empty.

namespace moho
{
  class RRuleGameRules;
  struct SSTIArmyVariableData;
}

namespace faf::remote
{
  [[nodiscard]] wire::SArmyRecord ArmyToWire(const moho::SSTIArmyVariableData& army);

  /** Writes `record` into `army`; categories resolve through `rules` (the client's). */
  void ArmyFromWire(const wire::SArmyRecord& record, moho::SSTIArmyVariableData& army, moho::RRuleGameRules* rules);
} // namespace faf::remote
