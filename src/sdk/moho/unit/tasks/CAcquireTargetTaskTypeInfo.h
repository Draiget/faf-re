#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CAcquireTargetTask;

  /**
   * VFTABLE: 0x00E1EAF4
   * COL: 0x00E75748
   */
  class CAcquireTargetTaskTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x005D86A0 (FUN_005D86A0, ??0CAcquireTargetTaskTypeInfo@Moho@@QAE@@Z)
     *
     * What it does:
     * Preregisters RTTI metadata for `CAcquireTargetTask`.
     */
    CAcquireTargetTaskTypeInfo();

    /**
     * Address: 0x005D8760 (FUN_005D8760, scalar deleting thunk)
     */
    ~CAcquireTargetTaskTypeInfo() override;

    /**
     * Address: 0x005D8750 (FUN_005D8750)
     *
     * What it does:
     * Returns the reflected type name literal for `CAcquireTargetTask`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005D8700 (FUN_005D8700)
     *
     * What it does:
     * Sets the reflected size and wires base / allocator callbacks.
     */
    void Init() override;

    /**
     * Address: 0x005DEE50 (FUN_005DEE50, AddBase_CTask)
     */
    static void AddBase_CTask(gpg::RType* typeInfo);

    /**
     * Address: 0x005DEEB0 (FUN_005DEEB0, AddBase_ManyToOneListener_EProjectileImpactEvent)
     */
    static void AddBase_ManyToOneListener_EProjectileImpactEvent(gpg::RType* typeInfo);

    /**
     * Address: 0x005DEF10 (FUN_005DEF10, AddBase_ManyToOneListener_ECollisionBeamEvent)
     */
    static void AddBase_ManyToOneListener_ECollisionBeamEvent(gpg::RType* typeInfo);

    /**
     * Address: 0x005DD990 (FUN_005DD990, NewRef)
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x005DDA20 (FUN_005DDA20, CtrRef)
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x005DDA00 (FUN_005DDA00, Delete)
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x005DDA90 (FUN_005DDA90, Destruct)
     */
    static void Destruct(void* objectStorage);
  };

  /**
   * Address: 0x00BCE910 (FUN_00BCE910, register_CAcquireTargetTaskTypeInfo)
   *
   * What it does:
   * Constructs the global type-info owner and schedules process-exit cleanup.
   */
  int register_CAcquireTargetTaskTypeInfo();

  static_assert(sizeof(CAcquireTargetTaskTypeInfo) == 0x64, "CAcquireTargetTaskTypeInfo size must be 0x64");
} // namespace moho
