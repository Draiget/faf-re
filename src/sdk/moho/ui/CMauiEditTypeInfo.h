#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CMauiEditTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0078EE90 (FUN_0078EE90, Moho::CMauiEditTypeInfo::CMauiEditTypeInfo)
     *
     * What it does:
     * Pre-registers the reflected `CMauiEdit` descriptor.
     */
    CMauiEditTypeInfo();

    /**
     * Address: 0x0078EF30 (FUN_0078EF30, Moho::CMauiEditTypeInfo::dtr)
     */
    ~CMauiEditTypeInfo() override;

    /**
     * Address: 0x0078EF20 (FUN_0078EF20, Moho::CMauiEditTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0078EEF0 (FUN_0078EEF0, Moho::CMauiEditTypeInfo::Init)
     */
    void Init() override;
  };

  /**
   * Address: 0x00BDE230 (FUN_00BDE230, register_CMauiEditTypeInfoStartup)
   *
   * What it does:
   * Constructs the `CMauiEdit` type-info object.
   */
  void register_CMauiEditTypeInfoStartup();
} // namespace moho
