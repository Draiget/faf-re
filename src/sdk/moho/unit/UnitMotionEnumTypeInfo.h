#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "moho/unit/EUnitMotionEnums.h"

namespace moho
{
  /**
   * Address: 0x006B7100 (FUN_006B7100, EUnitMotionStateTypeInfo::GetName)
   *
   * What it does:
   * Reflection descriptor for `EUnitMotionState`.
   */
  class EUnitMotionStateTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x006B7110 (FUN_006B7110, scalar deleting thunk)
     */
    ~EUnitMotionStateTypeInfo() override;

    /**
     * Address: 0x006B7100 (FUN_006B7100)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006B70E0 (FUN_006B70E0)
     */
    void Init() override;
  };
  static_assert(sizeof(EUnitMotionStateTypeInfo) == 0x78, "EUnitMotionStateTypeInfo size must be 0x78");

  /**
   * Address: 0x006B7230 (FUN_006B7230, EUnitMotionCarrierEventTypeInfo::GetName)
   *
   * What it does:
   * Reflection descriptor for `EUnitMotionCarrierEvent`.
   */
  class EUnitMotionCarrierEventTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x006B7240 (FUN_006B7240, scalar deleting thunk)
     */
    ~EUnitMotionCarrierEventTypeInfo() override;

    /**
     * Address: 0x006B7230 (FUN_006B7230)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006B7210 (FUN_006B7210)
     */
    void Init() override;
  };
  static_assert(
    sizeof(EUnitMotionCarrierEventTypeInfo) == 0x78, "EUnitMotionCarrierEventTypeInfo size must be 0x78"
  );

  /**
   * Address: 0x006B7360 (FUN_006B7360, EUnitMotionHorzEventTypeInfo::GetName)
   *
   * What it does:
   * Reflection descriptor for `EUnitMotionHorzEvent`.
   */
  class EUnitMotionHorzEventTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x006B7370 (FUN_006B7370, scalar deleting thunk)
     */
    ~EUnitMotionHorzEventTypeInfo() override;

    /**
     * Address: 0x006B7360 (FUN_006B7360)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006B7340 (FUN_006B7340)
     */
    void Init() override;
  };
  static_assert(sizeof(EUnitMotionHorzEventTypeInfo) == 0x78, "EUnitMotionHorzEventTypeInfo size must be 0x78");

  /**
   * Address: 0x006B7490 (FUN_006B7490, EUnitMotionVertEventTypeInfo::GetName)
   *
   * What it does:
   * Reflection descriptor for `EUnitMotionVertEvent`.
   */
  class EUnitMotionVertEventTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x006B74A0 (FUN_006B74A0, scalar deleting thunk)
     */
    ~EUnitMotionVertEventTypeInfo() override;

    /**
     * Address: 0x006B7490 (FUN_006B7490)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006B7470 (FUN_006B7470)
     */
    void Init() override;
  };
  static_assert(sizeof(EUnitMotionVertEventTypeInfo) == 0x78, "EUnitMotionVertEventTypeInfo size must be 0x78");

  /**
   * Address: 0x006B75C0 (FUN_006B75C0, EUnitMotionTurnEventTypeInfo::GetName)
   *
   * What it does:
   * Reflection descriptor for `EUnitMotionTurnEvent`.
   */
  class EUnitMotionTurnEventTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x006B75D0 (FUN_006B75D0, scalar deleting thunk)
     */
    ~EUnitMotionTurnEventTypeInfo() override;

    /**
     * Address: 0x006B75C0 (FUN_006B75C0)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006B75A0 (FUN_006B75A0)
     */
    void Init() override;
  };
  static_assert(sizeof(EUnitMotionTurnEventTypeInfo) == 0x78, "EUnitMotionTurnEventTypeInfo size must be 0x78");

  /**
   * Address: 0x006B7080 (FUN_006B7080, construct_EUnitMotionStateTypeInfo)
   *
   * What it does:
   * Constructs/preregisters the reflected enum descriptor for
   * `EUnitMotionState`.
   */
  gpg::REnumType* construct_EUnitMotionStateTypeInfo();

  /**
   * Address: 0x006B71B0 (FUN_006B71B0, construct_EUnitMotionCarrierEventTypeInfo)
   *
   * What it does:
   * Constructs/preregisters the reflected enum descriptor for
   * `EUnitMotionCarrierEvent`.
   */
  gpg::REnumType* construct_EUnitMotionCarrierEventTypeInfo();

  /**
   * Address: 0x006B72E0 (FUN_006B72E0, construct_EUnitMotionHorzEventTypeInfo)
   *
   * What it does:
   * Constructs/preregisters the reflected enum descriptor for
   * `EUnitMotionHorzEvent`.
   */
  gpg::REnumType* construct_EUnitMotionHorzEventTypeInfo();

  /**
   * Address: 0x006B7410 (FUN_006B7410, construct_EUnitMotionVertEventTypeInfo)
   *
   * What it does:
   * Constructs/preregisters the reflected enum descriptor for
   * `EUnitMotionVertEvent`.
   */
  gpg::REnumType* construct_EUnitMotionVertEventTypeInfo();

  /**
   * Address: 0x006B7540 (FUN_006B7540, construct_EUnitMotionTurnEventTypeInfo)
   *
   * What it does:
   * Constructs/preregisters the reflected enum descriptor for
   * `EUnitMotionTurnEvent`.
   */
  gpg::REnumType* construct_EUnitMotionTurnEventTypeInfo();

  /**
   * Address: 0x00BD6FE0 (FUN_00BD6FE0, register_EUnitMotionStateTypeInfo)
   */
  int register_EUnitMotionStateTypeInfo();

  /**
   * Address: 0x00BD7000 (FUN_00BD7000, register_EUnitMotionStatePrimitiveSerializer)
   */
  int register_EUnitMotionStatePrimitiveSerializer();

  /**
   * Address: 0x00BD7040 (FUN_00BD7040, register_EUnitMotionCarrierEventTypeInfo)
   */
  int register_EUnitMotionCarrierEventTypeInfo();

  /**
   * Address: 0x00BD7060 (FUN_00BD7060, register_EUnitMotionCarrierEventPrimitiveSerializer)
   */
  int register_EUnitMotionCarrierEventPrimitiveSerializer();

  /**
   * Address: 0x00BD70A0 (FUN_00BD70A0, register_EUnitMotionHorzEventTypeInfo)
   */
  int register_EUnitMotionHorzEventTypeInfo();

  /**
   * Address: 0x00BD70C0 (FUN_00BD70C0, register_EUnitMotionHorzEventPrimitiveSerializer)
   */
  int register_EUnitMotionHorzEventPrimitiveSerializer();

  /**
   * Address: 0x00BD7100 (FUN_00BD7100, register_EUnitMotionVertEventTypeInfo)
   */
  int register_EUnitMotionVertEventTypeInfo();

  /**
   * Address: 0x00BD7120 (FUN_00BD7120, register_EUnitMotionVertEventPrimitiveSerializer)
   */
  int register_EUnitMotionVertEventPrimitiveSerializer();

  /**
   * Address: 0x00BD7160 (FUN_00BD7160, register_EUnitMotionTurnEventTypeInfo)
   */
  int register_EUnitMotionTurnEventTypeInfo();

  /**
   * Address: 0x00BD7180 (FUN_00BD7180, register_EUnitMotionTurnEventPrimitiveSerializer)
   */
  int register_EUnitMotionTurnEventPrimitiveSerializer();
} // namespace moho

