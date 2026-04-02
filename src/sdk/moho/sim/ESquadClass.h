#pragma once

#include <cstdint>

namespace moho
{
  /**
   * Address evidence:
   * - 0x00723BD0: ESquadClassTypeInfo::AddEnums registers lexical options.
   *
   * What it does:
   * Encodes platoon squad-role classification used by AI platoon queries.
   */
  enum class ESquadClass : std::int32_t
  {
    Unassigned = 0,
    Attack = 1,
    Artillery = 2,
    Guard = 3,
    Support = 4,
    Scout = 5,
  };

  static_assert(sizeof(ESquadClass) == 0x4, "ESquadClass size must be 0x4");
} // namespace moho
