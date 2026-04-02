#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class SEfxCurveTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00514C00 (FUN_00514C00, Moho::SEfxCurveTypeInfo::SEfxCurveTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for `SEfxCurve`.
     */
    SEfxCurveTypeInfo();

    /**
     * Address: 0x00514C90 (FUN_00514C90, Moho::SEfxCurveTypeInfo::dtr)
     * Slot: 2
     */
    ~SEfxCurveTypeInfo() override;

    /**
     * Address: 0x00514C80 (FUN_00514C80, Moho::SEfxCurveTypeInfo::GetName)
     * Slot: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00514C60 (FUN_00514C60, Moho::SEfxCurveTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Sets `SEfxCurve` size metadata and finalizes reflection setup.
     */
    void Init() override;
  };

  /**
   * Address: 0x00BC8420 (FUN_00BC8420, register_SEfxCurveTypeInfo)
   *
   * What it does:
   * Materializes and startup-registers `SEfxCurveTypeInfo`.
   */
  int register_SEfxCurveTypeInfo();

  static_assert(sizeof(SEfxCurveTypeInfo) == 0x64, "SEfxCurveTypeInfo size must be 0x64");
} // namespace moho
