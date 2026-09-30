#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  enum EJobType : std::int32_t
  {
    JOB_None = 0,
    JOB_Build = 1,
    JOB_Repair = 2,
    JOB_Reclaim = 3,
  };

  static_assert(sizeof(EJobType) == 0x4, "EJobType size must be 0x4");

  class EJobTypeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x0055B810 (FUN_0055B810, Moho::EJobTypeTypeInfo::EJobTypeTypeInfo)
     *
     * What it does:
     * Preregisters the enum type descriptor for `EJobType` with the reflection registry.
     */
    EJobTypeTypeInfo();

    /**
     * Address: 0x0055B8A0 (FUN_0055B8A0, Moho::EJobTypeTypeInfo::dtr)
     */
    ~EJobTypeTypeInfo() override;

    /**
     * Address: 0x0055B890 (FUN_0055B890, Moho::EJobTypeTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0055B870 (FUN_0055B870, Moho::EJobTypeTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x0055B8D0 (FUN_0055B8D0, Moho::EJobTypeTypeInfo::AddEnums)
     */
    void AddEnums();
  };


  static_assert(sizeof(EJobTypeTypeInfo) == 0x78, "EJobTypeTypeInfo size must be 0x78");

  /**
   * Address: 0x0055B810 (FUN_0055B810, static-init lane)
   *
   * What it does:
   * Constructs the static `EJobTypeTypeInfo` descriptor in place and returns
   * it; construction preregisters `EJobType` with the reflection registry.
   * Called from the CRT static-initializer array via FUN_00BCA440.
   */
  [[nodiscard]] gpg::REnumType* preregister_EJobTypeTypeInfo();
} // namespace moho
