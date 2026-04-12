#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CMauiControlTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00786660 (Moho::CMauiControlTypeInfo::CMauiControlTypeInfo)
     */
    CMauiControlTypeInfo();

    /**
     * Address: 0x00786700 (scalar deleting thunk)
     */
    ~CMauiControlTypeInfo() override;

    /**
     * Address: 0x007866F0 (Moho::CMauiControlTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x007866C0 (Moho::CMauiControlTypeInfo::Init)
     */
    void Init() override;
  };

  static_assert(sizeof(CMauiControlTypeInfo) == 0x64, "CMauiControlTypeInfo size must be 0x64");

  /**
   * Address: 0x00BDDD60 (register_CMauiControlTypeInfo)
   */
  void register_CMauiControlTypeInfoStartup();
} // namespace moho
