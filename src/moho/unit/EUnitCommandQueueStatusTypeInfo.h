#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/unit/EUnitCommandQueueStatus.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E2F194
   * COL: 0x00E7F048
   */
  class EUnitCommandQueueStatusTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x006ED9D0 (FUN_006ED9D0, Moho::EUnitCommandQueueStatusTypeInfo::EUnitCommandQueueStatusTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflected enum descriptor for
     * `EUnitCommandQueueStatus`.
     */
    EUnitCommandQueueStatusTypeInfo();

    /**
     * Address: 0x00BFEEA0 (FUN_00BFEEA0, Moho::EUnitCommandQueueStatusTypeInfo::dtr)
     * Slot: 2
     */
    ~EUnitCommandQueueStatusTypeInfo() override;

    /**
     * Address: 0x006EDA50 (FUN_006EDA50, Moho::EUnitCommandQueueStatusTypeInfo::GetName)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006EDA30 (FUN_006EDA30, Moho::EUnitCommandQueueStatusTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Sets reflected enum size metadata and finalizes the descriptor.
     */
    void Init() override;
  };

  static_assert(sizeof(EUnitCommandQueueStatusTypeInfo) == 0x78, "EUnitCommandQueueStatusTypeInfo size must be 0x78");

  /**
   * Address: 0x00BD9260 (FUN_00BD9260, register_EUnitCommandQueueStatusTypeInfo)
   *
   * What it does:
   * Ensures the descriptor is constructed and schedules cleanup at process exit.
   */
  void register_EUnitCommandQueueStatusTypeInfo();
} // namespace moho

