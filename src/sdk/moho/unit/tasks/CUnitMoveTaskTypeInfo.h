#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitMoveTask;

  /**
   * Type-info owner for `CUnitMoveTask`.
   */
  class CUnitMoveTaskTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00618EC0 (FUN_00618EC0, Moho::CUnitMoveTaskTypeInfo::Init)
     *
     * What it does:
     * Sets move-task reflected size/callback lanes, registers reflected base
     * slices, and finalizes type-info initialization.
     */
    void Init() override;

    /**
     * Address: 0x00619DD0 (FUN_00619DD0, Moho::CUnitMoveTaskTypeInfo::NewRef)
     *
     * What it does:
     * Allocates one `CUnitMoveTask` and returns a typed reflection ref.
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x00619E70 (FUN_00619E70, Moho::CUnitMoveTaskTypeInfo::CtrRef)
     *
     * What it does:
     * Placement-constructs one `CUnitMoveTask` in caller storage and returns
     * a typed reflection ref.
     */
    static gpg::RRef CtrRef(void* objectStorage);

  private:
    /**
     * Address: 0x00619BD0 (FUN_00619BD0, callback shard)
     *
     * What it does:
     * Assigns all lifecycle callbacks (`NewRef`, `CtrRef`, delete, destruct)
     * onto one move-task type descriptor.
     */
    static void AssignAllLifecycleCallbacks(CUnitMoveTaskTypeInfo& typeInfo);

    /**
     * Address: 0x00619D50 (FUN_00619D50, callback shard)
     *
     * What it does:
     * Assigns constructor-lane callbacks (`NewRef`, `CtrRef`) to one move-task
     * type descriptor.
     */
    static void AssignCtorCallbacks(CUnitMoveTaskTypeInfo& typeInfo);

    /**
     * Address: 0x00619D60 (FUN_00619D60, callback shard)
     *
     * What it does:
     * Assigns destructor-lane callbacks (delete + in-place destruct) to one
     * move-task type descriptor.
     */
    static void AssignDtorCallbacks(CUnitMoveTaskTypeInfo& typeInfo);
  };

  /**
   * Address: 0x00618E60 (FUN_00618E60, preregister_CUnitMoveTaskTypeInfo)
   *
   * What it does:
   * Constructs/preregisters the startup `CUnitMoveTaskTypeInfo` reflection
   * lane.
   */
  [[nodiscard]] gpg::RType* preregister_CUnitMoveTaskTypeInfo();

  static_assert(sizeof(CUnitMoveTaskTypeInfo) == 0x64, "CUnitMoveTaskTypeInfo size must be 0x64");
} // namespace moho
