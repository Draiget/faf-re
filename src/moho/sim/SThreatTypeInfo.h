#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class SThreatTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x007179B0 (FUN_007179B0, Moho::SThreatTypeInfo::SThreatTypeInfo)
     *
     * What it does:
     * Preregisters `SThreat` reflection metadata at startup.
     */
    SThreatTypeInfo();

    /**
     * Address: 0x00717A40 (FUN_00717A40, Moho::SThreatTypeInfo::dtr)
     *
     * What it does:
     * Scalar deleting destructor thunk for SThreatTypeInfo.
     */
    ~SThreatTypeInfo() override;

    /**
     * Address: 0x00717A30 (FUN_00717A30, Moho::SThreatTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflection type label for SThreat.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00717A10 (FUN_00717A10, Moho::SThreatTypeInfo::Init)
     *
     * What it does:
     * Sets SThreat size metadata and finalizes reflection type setup.
     */
    void Init() override;
  };

  static_assert(sizeof(SThreatTypeInfo) == 0x64, "SThreatTypeInfo size must be 0x64");

  /**
   * Address: 0x007179B0 (FUN_007179B0, static-init lane)
   *
   * IDA signature:
   * gpg::RType *sub_7179B0();
   *
   * What it does:
   * Constructs the static `SThreatTypeInfo` descriptor (`stru_10B9358` in the
   * binary) in place and returns it; construction preregisters `SThreat` with
   * the reflection registry. Called from the CRT static-initializer array via
   * FUN_00BDA760.
   */
  [[nodiscard]] gpg::RType* preregister_SThreatTypeInfo();
} // namespace moho
