#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CFactoryBuildTask;

  /**
   * Type-info owner for `CFactoryBuildTask`.
   */
  class CFactoryBuildTaskTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override;
    void Init() override;

    /**
     * Address: 0x005FC480 (FUN_005FC480, Moho::CFactoryBuildTaskTypeInfo::NewRef)
     *
     * What it does:
     * Allocates one `CFactoryBuildTask` and returns a typed reflection ref.
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x005FC520 (FUN_005FC520, Moho::CFactoryBuildTaskTypeInfo::CtrRef)
     *
     * What it does:
     * Placement-constructs one `CFactoryBuildTask` in caller storage and
     * returns a typed reflection ref.
     */
    static gpg::RRef CtrRef(void* objectStorage);
  };

  /**
   * Address: 0x005FA130 (FUN_005FA130, preregister_CFactoryBuildTaskTypeInfo)
   *
   * What it does:
   * Constructs/preregisters the startup `CFactoryBuildTaskTypeInfo`
   * reflection lane.
   */
  [[nodiscard]] gpg::RType* preregister_CFactoryBuildTaskTypeInfo();

  static_assert(sizeof(CFactoryBuildTaskTypeInfo) == 0x64, "CFactoryBuildTaskTypeInfo size must be 0x64");
} // namespace moho
