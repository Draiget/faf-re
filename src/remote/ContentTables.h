#pragma once

#include "remote/wire/OrdinalTable.h"

// Engine addition, server mode (plan WP7.2): the content tables of the wire format, built
// from the game rules a session loaded. Server and client build them on their own from the
// same game data and mods, and compare `Hash()` in the handshake (`SWireHello`).

namespace moho
{
  class RRuleGameRules;
}

namespace faf::remote
{
  /**
   * Blueprints: every unit, prop and projectile blueprint id (one ordinal space, as an
   * entity of any kind names one). Meshes: every mesh blueprint id. Sounds: empty for now;
   * sound parameters come from the sound banks, not the rules (WPR.9).
   */
  [[nodiscard]] wire::SContentTables BuildContentTables(moho::RRuleGameRules& rules);
} // namespace faf::remote
