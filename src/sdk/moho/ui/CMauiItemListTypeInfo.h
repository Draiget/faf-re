#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CMauiItemListTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x007991F0 (FUN_007991F0, Moho::CMauiItemListTypeInfo::CMauiItemListTypeInfo)
     *
     * What it does:
     * Pre-registers the reflected `CMauiItemList` descriptor.
     */
    CMauiItemListTypeInfo();

    /**
     * Address: 0x00799290 (FUN_00799290, Moho::CMauiItemListTypeInfo::dtr)
     */
    ~CMauiItemListTypeInfo() override;

    /**
     * Address: 0x00799280 (FUN_00799280, Moho::CMauiItemListTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00799250 (FUN_00799250, Moho::CMauiItemListTypeInfo::Init)
     */
    void Init() override;
  };

  /**
   * Address: 0x00BDE910 (FUN_00BDE910, register_CMauiItemListTypeInfoStartup)
   *
   * What it does:
   * Constructs the `CMauiItemList` type-info object.
   */
  void register_CMauiItemListTypeInfoStartup();
} // namespace moho
