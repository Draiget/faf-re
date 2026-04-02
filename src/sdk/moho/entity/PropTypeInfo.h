#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E2F4A0
   * COL: 0x00E8D998
   */
  class SPropPriorityInfoTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x006F9AA0 (FUN_006F9AA0, sub_6F9AA0)
     *
     * What it does:
     * Initializes and preregisters reflection metadata for `SPropPriorityInfo`.
     */
    SPropPriorityInfoTypeInfo();

    /**
     * Address: 0x006F9B30 (FUN_006F9B30, Moho::SPropPriorityInfoTypeInfo::dtr)
     * Slot: 2
     */
    ~SPropPriorityInfoTypeInfo() override;

    /**
     * Address: 0x006F9B20 (FUN_006F9B20, Moho::SPropPriorityInfoTypeInfo::GetName)
     * Slot: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x006F9B00 (FUN_006F9B00, Moho::SPropPriorityInfoTypeInfo::Init)
     * Slot: 9
     */
    void Init() override;
  };

  /**
   * VFTABLE: 0x00E2F470
   * COL: 0x00E8D9FC
   */
  class PropTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x006FA380 (FUN_006FA380, Moho::PropTypeInfo::PropTypeInfo)
     *
     * What it does:
     * Initializes and preregisters reflection metadata for `Prop`.
     */
    PropTypeInfo();

    /**
     * Address: 0x006FA420 (FUN_006FA420, Moho::PropTypeInfo::dtr)
     * Slot: 2
     */
    ~PropTypeInfo() override;

    /**
     * Address: 0x006FA410 (FUN_006FA410, Moho::PropTypeInfo::GetName)
     * Slot: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x006FA3E0 (FUN_006FA3E0, Moho::PropTypeInfo::Init)
     * Slot: 9
     */
    void Init() override;

  private:
    /**
     * Address: 0x006FAD70 (FUN_006FAD70, Moho::PropTypeInfo::AddBase_Entity)
     *
     * What it does:
     * Adds `Entity` as the reflected base type at offset 0.
     */
    static void AddBase_Entity(gpg::RType* typeInfo);
  };

  static_assert(sizeof(SPropPriorityInfoTypeInfo) == 0x64, "SPropPriorityInfoTypeInfo size must be 0x64");
  static_assert(sizeof(PropTypeInfo) == 0x64, "PropTypeInfo size must be 0x64");

  /**
   * Address: 0x00BFF0E0 (FUN_00BFF0E0, sub_BFF0E0)
   *
   * What it does:
   * Releases `SPropPriorityInfoTypeInfo` field/base vectors and resets RObject vftable.
   */
  void cleanup_SPropPriorityInfoTypeInfo();

  /**
   * Address: 0x00BD9820 (FUN_00BD9820, sub_BD9820)
   *
   * What it does:
   * Registers `SPropPriorityInfoTypeInfo` static instance and schedules cleanup at process exit.
   */
  void register_SPropPriorityInfoTypeInfo();

  /**
   * Address: 0x00BFF170 (FUN_00BFF170, sub_BFF170)
   *
   * What it does:
   * Releases `PropTypeInfo` field/base vectors and resets RObject vftable.
   */
  void cleanup_PropTypeInfo();

  /**
   * Address: 0x00BD9880 (FUN_00BD9880, register_PropTypeInfo)
   *
   * What it does:
   * Registers `PropTypeInfo` static instance and schedules cleanup at process exit.
   */
  void register_PropTypeInfo();
} // namespace moho

