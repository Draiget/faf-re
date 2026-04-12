#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CEconomyTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00772DE0 (Moho::CEconomyTypeInfo::CEconomyTypeInfo)
     */
    CEconomyTypeInfo();

    /**
     * Address: 0x00772E70 (scalar deleting thunk)
     */
    ~CEconomyTypeInfo() override;

    /**
     * Address: 0x00772E60 (Moho::CEconomyTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00772E40 (Moho::CEconomyTypeInfo::Init)
     */
    void Init() override;
  };

  static_assert(sizeof(CEconomyTypeInfo) == 0x64, "CEconomyTypeInfo size must be 0x64");

  /**
   * Address: 0x00BDD0B0 (register_CEconomyTypeInfo)
   */
  void register_CEconomyTypeInfoStartup();
} // namespace moho
