#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E07628
   * COL: 0x00E62120
   */
  class PrefetchHandleBaseTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x004ABBF0 (FUN_004ABBF0, ??0PrefetchHandleBaseTypeInfo@Moho@@QAE@@Z)
     *
     * What it does:
     * Constructs runtime type info and preregisters `PrefetchHandleBase`.
     */
    PrefetchHandleBaseTypeInfo();

    /**
     * Address: 0x004ABC80 (FUN_004ABC80, Moho::PrefetchHandleBaseTypeInfo::dtr)
     */
    ~PrefetchHandleBaseTypeInfo() override;

    /**
     * Address: 0x004ABC70 (FUN_004ABC70, Moho::PrefetchHandleBaseTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x004ABC50 (FUN_004ABC50, Moho::PrefetchHandleBaseTypeInfo::Init)
     */
    void Init() override;
  };

  static_assert(sizeof(PrefetchHandleBaseTypeInfo) == 0x64, "PrefetchHandleBaseTypeInfo size must be 0x64");
} // namespace moho
