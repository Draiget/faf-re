#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/String.h"
#include "moho/containers/BVSet.h"
#include "moho/entity/EntityCategoryHelper.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class CArmyStatItem;
  struct RBlueprint;
  struct RUnitBlueprint;

  enum ETriggerOperator : std::int32_t
  {
    TRIGGER_GreaterThan = 0,
    TRIGGER_GreaterThanOrEqual = 1,
    TRIGGER_LessThan = 2,
    TRIGGER_LessThanOrEqual = 3,
  };

  struct SCondition
  {
    static gpg::RType* sType;
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x00712300 (FUN_00712300, Moho::SCondition::MemberDeserialize)
     *
     * gpg::ReadArchive *, Moho::SCondition *
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x007123B0 (FUN_007123B0, Moho::SCondition::MemberSerialize)
     *
     * Moho::SCondition *, gpg::WriteArchive *
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    CArmyStatItem* mItem;                                   // +0x00
    ETriggerOperator mOp;                                   // +0x04
    BVSet<const RBlueprint*, EntityCategoryHelper> mCat;    // +0x08
    float mVal;                                             // +0x30
    std::uint8_t mPad34[0x04];                              // +0x34
  };

  struct STrigger
  {
    static gpg::RType* sType;
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x00711030 / 0x007110F0 (FUN_00711030 / FUN_007110F0)
     *
     * What it does:
     * Initializes trigger string state and binds inline fastvector storage for two SCondition lanes.
     */
    STrigger();

    /**
       * Address: 0x00711A90 (FUN_00711A90)
     *
     * What it does:
     * Releases condition category bit-storage lanes, resets fastvector storage to inline, and clears trigger name.
     */
    ~STrigger();

    /**
     * Address: 0x00712460 (FUN_00712460, Moho::STrigger::MemberDeserialize)
     *
     * Moho::STrigger *, gpg::ReadArchive *
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x007124B0 (FUN_007124B0, Moho::STrigger::MemberSerialize)
     *
     * Moho::STrigger *, gpg::WriteArchive *
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    msvc8::string mName;                                    // +0x00
    std::uint32_t mUnk1C;                                   // +0x1C
    gpg::fastvector_runtime_view<SCondition> mConditions;   // +0x20
    std::uint8_t mPad30[0x70];                              // +0x30
  };

  static_assert(sizeof(SCondition) == 0x38, "SCondition size must be 0x38");
  static_assert(offsetof(SCondition, mItem) == 0x00, "SCondition::mItem offset must be 0x00");
  static_assert(offsetof(SCondition, mOp) == 0x04, "SCondition::mOp offset must be 0x04");
  static_assert(offsetof(SCondition, mCat) == 0x08, "SCondition::mCat offset must be 0x08");
  static_assert(offsetof(SCondition, mVal) == 0x30, "SCondition::mVal offset must be 0x30");

  static_assert(sizeof(STrigger) == 0xA0, "STrigger size must be 0xA0");
  static_assert(offsetof(STrigger, mName) == 0x00, "STrigger::mName offset must be 0x00");
  static_assert(offsetof(STrigger, mConditions) == 0x20, "STrigger::mConditions offset must be 0x20");

  /**
   * Address: 0x00BD9FE0 (FUN_00BD9FE0, register_ETriggerOperatorTypeInfo)
   */
  void register_ETriggerOperatorTypeInfo();

  /**
   * Address: 0x00BDA000 (FUN_00BDA000, sub_BDA000)
   */
  void register_ETriggerOperatorPrimitiveSerializer();

  /**
   * Address: 0x00BDA040 (FUN_00BDA040, register_SConditionTypeInfo)
   */
  void register_SConditionTypeInfo();

  /**
   * Address: 0x00BDA060 (FUN_00BDA060, register_SConditionSerializer)
   */
  void register_SConditionSerializer();

  /**
   * Address: 0x00BDA0A0 (FUN_00BDA0A0, sub_BDA0A0)
   */
  void register_STriggerTypeInfo();

  /**
   * Address: 0x00BDA0C0 (FUN_00BDA0C0, register_STriggerSerializer)
   */
  void register_STriggerSerializer();

  /**
   * Address: 0x00BDA160 (FUN_00BDA160, sub_BDA160)
   */
  void register_desktop_path_string();

  /**
   * Address: 0x00BDA250 (FUN_00BDA250, sub_BDA250)
   */
  void register_fastvector_SCondition_type();

  /**
   * Address: 0x00BDA270 (FUN_00BDA270, sub_BDA270)
   */
  void register_shared_ptr_STrigger_type();

  /**
   * Address: 0x00BDA290 (FUN_00BDA290, sub_BDA290)
   */
  void register_map_RUnitBlueprintFloat_type();

  /**
   * Address: 0x00BDA2B0 (FUN_00BDA2B0, sub_BDA2B0)
   */
  void register_stats_CArmyStatItem_type();

  /**
   * Address: 0x00BDA2D0 (FUN_00BDA2D0, sub_BDA2D0)
   */
  void register_map_StringCArmyStatItemPtr_type();
} // namespace moho
