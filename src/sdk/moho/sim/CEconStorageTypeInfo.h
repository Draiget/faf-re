#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CEconStorageTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00773320 (Moho::CEconStorageTypeInfo::CEconStorageTypeInfo)
     */
    CEconStorageTypeInfo();

    /**
     * Address: 0x007733B0 (scalar deleting thunk)
     */
    ~CEconStorageTypeInfo() override;

    /**
     * Address: 0x007733A0 (Moho::CEconStorageTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00773380 (Moho::CEconStorageTypeInfo::Init)
     */
    void Init() override;
  };

  static_assert(sizeof(CEconStorageTypeInfo) == 0x64, "CEconStorageTypeInfo size must be 0x64");

  /**
   * Address: 0x00BDD150 (register_CEconStorageTypeInfo)
   */
  void register_CEconStorageTypeInfoStartup();
} // namespace moho
