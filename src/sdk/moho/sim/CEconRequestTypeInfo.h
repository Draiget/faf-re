#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CEconRequestTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x007737B0 (Moho::CEconRequestTypeInfo::CEconRequestTypeInfo)
     */
    CEconRequestTypeInfo();

    /**
     * Address: 0x00773840 (scalar deleting thunk)
     */
    ~CEconRequestTypeInfo() override;

    /**
     * Address: 0x00773830 (Moho::CEconRequestTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00773810 (Moho::CEconRequestTypeInfo::Init)
     */
    void Init() override;
  };

  static_assert(sizeof(CEconRequestTypeInfo) == 0x64, "CEconRequestTypeInfo size must be 0x64");

  /**
   * Address: 0x00BDD1F0 (register_CEconRequestTypeInfo)
   */
  void register_CEconRequestTypeInfoStartup();
} // namespace moho
