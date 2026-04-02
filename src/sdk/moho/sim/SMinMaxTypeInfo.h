#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class SMinMaxFloatTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0040DCA0 (FUN_0040DCA0, Moho::SMinMaxFloatTypeInfo::SMinMaxFloatTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for `SMinMax<float>`.
     */
    SMinMaxFloatTypeInfo();

    /**
     * Address: 0x0040DD50 (FUN_0040DD50, Moho::SMinMaxFloatTypeInfo::dtr)
     * Slot: 2
     */
    ~SMinMaxFloatTypeInfo() override;

    /**
     * Address: 0x0040DD40 (FUN_0040DD40, Moho::SMinMaxFloatTypeInfo::GetName)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0040DD00 (FUN_0040DD00, Moho::SMinMaxFloatTypeInfo::Init)
     * Slot: 9
     */
    void Init() override;
  };

  class SMinMaxUint32TypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0040DE10 (FUN_0040DE10, Moho::SMinMaxUint32TypeInfo::SMinMaxUint32TypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for `SMinMax<uint32_t>`.
     */
    SMinMaxUint32TypeInfo();

    /**
     * Address: 0x0040DEC0 (FUN_0040DEC0, Moho::SMinMaxUint32TypeInfo::dtr)
     * Slot: 2
     */
    ~SMinMaxUint32TypeInfo() override;

    /**
     * Address: 0x0040DEB0 (FUN_0040DEB0, Moho::SMinMaxUint32TypeInfo::GetName)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0040DE70 (FUN_0040DE70, Moho::SMinMaxUint32TypeInfo::Init)
     * Slot: 9
     */
    void Init() override;
  };

  static_assert(sizeof(SMinMaxFloatTypeInfo) == 0x64, "SMinMaxFloatTypeInfo size must be 0x64");
  static_assert(sizeof(SMinMaxUint32TypeInfo) == 0x64, "SMinMaxUint32TypeInfo size must be 0x64");
} // namespace moho
