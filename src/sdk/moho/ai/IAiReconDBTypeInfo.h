#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1DAB4
   * COL:  0x00E73D38
   */
  class IAiReconDBTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005C2670 (FUN_005C2670, Moho::IAiReconDBTypeInfo::IAiReconDBTypeInfo)
     *
     * What it does:
     * Preregisters `IAiReconDB` RTTI into the reflection lookup table.
     */
    IAiReconDBTypeInfo();

    /**
     * Address: 0x005C2700 (FUN_005C2700, scalar deleting thunk)
     *
     * What it does:
     * Destroys the type-info instance through `gpg::RType` teardown and frees
     * memory when the scalar-delete flag is set.
     *
     * VFTable SLOT: 2
     */
    ~IAiReconDBTypeInfo() override;

    /**
     * Address: 0x005C26F0 (FUN_005C26F0)
     *
     * What it does:
     * Returns the reflection name string for the IAiReconDB interface.
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005C26D0 (FUN_005C26D0)
     *
     * What it does:
     * Configures IAiReconDB reflected size and finalizes RType registration.
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  static_assert(sizeof(IAiReconDBTypeInfo) == 0x64, "IAiReconDBTypeInfo size must be 0x64");

  /**
   * Address: 0x00BCDD80 (FUN_00BCDD80, register_IAiReconDBTypeInfo)
   *
   * What it does:
   * Constructs the recovered `IAiReconDBTypeInfo` helper and installs
   * process-exit cleanup.
   */
  void register_IAiReconDBTypeInfo();
} // namespace moho
