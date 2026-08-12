#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class ETrailParamTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x00770DD0 (FUN_00770DD0)
     *
     * What it does:
     * Preregisters the reflected `ETrailParam` enum metadata.
     */
    ETrailParamTypeInfo();

    /**
     * Address: 0x00770E60 (FUN_00770E60, scalar deleting thunk)
     */
    ~ETrailParamTypeInfo() override;

    /**
     * Address: 0x00770E50 (FUN_00770E50)
     *
     * What it does:
     * Returns the reflection type name literal for ETrailParam.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00770E30 (FUN_00770E30)
     *
     * What it does:
     * Writes enum width, registers enum values, then finalizes metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00770E90 (FUN_00770E90)
     *
     * What it does:
     * Registers ETrailParam enum option names/values.
     */
    void AddEnums();
  };

  static_assert(sizeof(ETrailParamTypeInfo) == 0x78, "ETrailParamTypeInfo size must be 0x78");

  /**
   * Address: 0x00770DD0 (FUN_00770DD0, static-init lane)
   *
   * IDA signature:
   * gpg::REnumType *sub_770DD0();
   *
   * What it does:
   * Constructs the static `ETrailParamTypeInfo` descriptor (`stru_10BB670` in
   * the binary) in place and returns it; construction preregisters
   * `ETrailParam` with the reflection registry. Called from the CRT
   * static-initializer array via FUN_00BDCEA0.
   */
  [[nodiscard]] gpg::REnumType* preregister_ETrailParamTypeInfo();
} // namespace moho
