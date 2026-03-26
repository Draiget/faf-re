#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CArmyStatsTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0070DE80 (FUN_0070DE80, Moho::CArmyStatsTypeInfo::dtr)
     *
     * What it does:
     * Scalar deleting destructor thunk for CArmyStatsTypeInfo.
     */
    ~CArmyStatsTypeInfo() override;

    /**
     * Address: 0x0070DE70 (FUN_0070DE70, Moho::CArmyStatsTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflection type label for CArmyStats.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0070DE50 (FUN_0070DE50, Moho::CArmyStatsTypeInfo::Init)
     *
     * What it does:
     * Sets CArmyStats size metadata, adds Stats<CArmyStatItem> as reflection
     * base, and finalizes type setup.
     */
    void Init() override;

  private:
    /**
     * Address: 0x007125A0 (FUN_007125A0)
     *
     * What it does:
     * Registers Stats<CArmyStatItem> as reflection base for CArmyStats.
     */
    static void AddBase_StatsCArmyStatItem(gpg::RType* typeInfo);
  };

  static_assert(sizeof(CArmyStatsTypeInfo) == 0x64, "CArmyStatsTypeInfo size must be 0x64");
} // namespace moho
