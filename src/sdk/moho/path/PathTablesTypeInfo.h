#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * Reflection type descriptor for the path-table registry handle `moho::PathTables`.
   */
  class PathTablesTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0076BDB0 (FUN_0076BDB0, construct-and-preregister worker)
     *
     * What it does:
     * Preregisters `PathTables` RTTI so lookup resolves to this type helper.
     */
    PathTablesTypeInfo();

    /**
     * Address: 0x0076BE40 (FUN_0076BE40, scalar deleting thunk)
     * Slot: 2
     */
    ~PathTablesTypeInfo() override;

    /**
     * Address: 0x0076BE30 (FUN_0076BE30)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type name literal for PathTables.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0076BE10 (FUN_0076BE10)
     * Slot: 9
     *
     * What it does:
     * Writes `size_` for PathTables, then performs base-init/finalization.
     */
    void Init() override;
  };

  static_assert(sizeof(PathTablesTypeInfo) == 0x64, "PathTablesTypeInfo size must be 0x64");

  /**
   * Address: 0x00BDCA50 (FUN_00BDCA50, register_PathTablesTypeInfo)
   *
   * What it does:
   * Registers the `PathTables` type-info object and installs process-exit cleanup.
   */
  int register_PathTablesTypeInfo();
} // namespace moho
