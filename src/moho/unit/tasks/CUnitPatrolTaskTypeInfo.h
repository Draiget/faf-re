#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitPatrolTask;

  /**
   * Type-info owner for `CUnitPatrolTask`.
   */
  class CUnitPatrolTaskTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override;
    void Init() override;

    /**
     * Address: 0x0061CAA0 (FUN_0061CAA0, Moho::CUnitPatrolTaskTypeInfo::AddBase_CCommandTask)
     *
     * What it does:
     * Registers `CCommandTask` as a reflected base at offset 0x00.
     */
    static void AddBase_CCommandTask(gpg::RType* typeInfo);

    /**
     * Address: 0x0061CB00 (FUN_0061CB00, Moho::CUnitPatrolTaskTypeInfo::AddBase_Listener_ECommandEvent)
     *
     * What it does:
     * Registers `Listener<ECommandEvent>` as a reflected base at offset 0x34.
     */
    static void AddBase_Listener_ECommandEvent(gpg::RType* typeInfo);

    /**
     * Address: 0x0061CB60 (FUN_0061CB60, Moho::CUnitPatrolTaskTypeInfo::AddBase_Listener_EFormationdStatus)
     *
     * What it does:
     * Registers `Listener<EFormationdStatus>` as a reflected base at offset 0x44.
     */
    static void AddBase_Listener_EFormationdStatus(gpg::RType* typeInfo);
  };

  /**
   * Address: 0x0061AB10 (FUN_0061AB10, preregister_CUnitPatrolTaskTypeInfo)
   *
   * What it does:
   * Constructs/preregisters the startup `CUnitPatrolTaskTypeInfo` reflection
   * lane.
   */
  [[nodiscard]] gpg::RType* preregister_CUnitPatrolTaskTypeInfo();

  static_assert(sizeof(CUnitPatrolTaskTypeInfo) == 0x64, "CUnitPatrolTaskTypeInfo size must be 0x64");
} // namespace moho
