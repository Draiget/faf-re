#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CCommandDBTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x006E0880 (FUN_006E0880, sub_6E0880)
     *
     * What it does:
     * Constructs/preregisters RTTI ownership for `CCommandDB`.
     */
    CCommandDBTypeInfo();

    /**
     * Address: 0x006E0910 (FUN_006E0910, Moho::CCommandDBTypeInfo::dtr)
     */
    ~CCommandDBTypeInfo() override;

    /**
     * Address: 0x006E0900 (FUN_006E0900, Moho::CCommandDBTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006E08E0 (FUN_006E08E0, Moho::CCommandDBTypeInfo::Init)
     */
    void Init() override;
  };

  static_assert(sizeof(CCommandDBTypeInfo) == 0x64, "CCommandDBTypeInfo size must be 0x64");

  /**
   * Address: 0x00BD8C40 (FUN_00BD8C40, sub_BD8C40)
   *
   * What it does:
   * Ensures `CCommandDBTypeInfo` is constructed and installs teardown.
   */
  int register_CCommandDBTypeInfo();
} // namespace moho
