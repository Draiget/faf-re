#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CMauiHistogramTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00797650 (FUN_00797650, Moho::CMauiHistogramTypeInfo::CMauiHistogramTypeInfo)
     *
     * What it does:
     * Pre-registers the reflected `CMauiHistogram` descriptor.
     */
    CMauiHistogramTypeInfo();

    /**
     * Address: 0x007976F0 (FUN_007976F0, Moho::CMauiHistogramTypeInfo::dtr)
     */
    ~CMauiHistogramTypeInfo() override;

    /**
     * Address: 0x007976E0 (FUN_007976E0, Moho::CMauiHistogramTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x007976B0 (FUN_007976B0, Moho::CMauiHistogramTypeInfo::Init)
     */
    void Init() override;
  };

  void register_CMauiHistogramTypeInfoStartup();
} // namespace moho
