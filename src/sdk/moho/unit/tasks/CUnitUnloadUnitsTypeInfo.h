#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitUnloadUnits;

  /**
   * Type-info owner for `CUnitUnloadUnits`.
   */
  class CUnitUnloadUnitsTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override;
    void Init() override;

    /**
     * Address: 0x00627D40 (FUN_00627D40, Moho::CUnitUnloadUnitsTypeInfo::NewRef)
     *
     * What it does:
     * Allocates one `CUnitUnloadUnits` and returns a typed reflection ref.
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x00627DE0 (FUN_00627DE0, Moho::CUnitUnloadUnitsTypeInfo::CtrRef)
     *
     * What it does:
     * Constructs one `CUnitUnloadUnits` in caller-provided storage and returns
     * a typed reflection ref.
     */
    static gpg::RRef CtrRef(void* objectStorage);
  };

  /**
   * Address: 0x00626120 (FUN_00626120, preregister_CUnitUnloadUnitsTypeInfo)
   *
   * What it does:
   * Constructs/preregisters the startup `CUnitUnloadUnitsTypeInfo` reflection
   * lane.
   */
  [[nodiscard]] gpg::RType* preregister_CUnitUnloadUnitsTypeInfo();

  static_assert(sizeof(CUnitUnloadUnitsTypeInfo) == 0x64, "CUnitUnloadUnitsTypeInfo size must be 0x64");
} // namespace moho
