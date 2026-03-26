#include "moho/ai/CAiPersonality.h"

#include <cstring>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/sim/Sim.h"

using namespace moho;

namespace
{
  constexpr const char* kAiPersonalityModulePath = "/lua/aipersonality.lua";
  constexpr const char* kAiPersonalityClassName = "AIPersonality";
  constexpr const char* kAiPersonalityTemplateName = "AIPersonalityTemplate";
  constexpr const char* kDefaultPersonalityName = "AverageJoe";
  constexpr std::int32_t kTemplateFieldCount = 33;
  constexpr float kDefaultAdjustDelay = 0.5f;

  [[nodiscard]] const char* SafeCString(const char* value)
  {
    return value ? value : "";
  }

  /**
   * Address: 0x005B7220 (FUN_005B7220, func_LuaAiPersonality)
   * Address: 0x005B9600 (FUN_005B9600, func_CreateCAiPersonalityLuaObject)
   *
   * What it does:
   * Loads `/lua/aipersonality.lua` and returns `AIPersonality` metatable,
   * falling back to `CScrLuaMetatableFactory<CAiPersonality>::sInstance`.
   */
  [[nodiscard]] LuaPlus::LuaObject LoadAiPersonalityMetatable(LuaPlus::LuaState* const state)
  {
    LuaPlus::LuaObject metatable;

    LuaPlus::LuaObject moduleObj = SCR_ImportLuaModule(state, kAiPersonalityModulePath);
    if (!moduleObj.IsNil()) {
      metatable = SCR_GetLuaTableField(state, moduleObj, kAiPersonalityClassName);
    }

    if (metatable.IsNil()) {
      gpg::Logf("Can't find AIPersonality, using CAiPersonality directly");
      metatable = CScrLuaMetatableFactory<CAiPersonality>::Instance().Get(state);
    }
    return metatable;
  }

  [[nodiscard]] LuaPlus::LuaObject FindTemplateRow(const LuaPlus::LuaObject& templateTable, const char* rowName)
  {
    const std::int32_t rowCount = templateTable.GetN();
    for (std::int32_t rowIndex = 1; rowIndex <= rowCount; ++rowIndex) {
      LuaPlus::LuaObject row = templateTable.GetByIndex(rowIndex);
      if (!row.IsTable() || row.GetN() != kTemplateFieldCount) {
        continue;
      }

      LuaPlus::LuaObject rowNameValue = row.GetByIndex(1);
      if (gpg::STR_EqualsNoCase(SafeCString(rowNameValue.GetString()), rowName)) {
        return row;
      }
    }
    return {};
  }

  void LoadRangeField(const LuaPlus::LuaObject& row, const std::int32_t fieldIndex, SAiPersonalityRange& outRange)
  {
    LuaPlus::LuaObject rangeObj = row.GetByIndex(fieldIndex);
    if (!rangeObj.IsTable()) {
      outRange = {};
      return;
    }

    outRange.mMinValue = static_cast<float>(rangeObj.GetByIndex(1).GetNumber());
    outRange.mMaxValue = static_cast<float>(rangeObj.GetByIndex(2).GetNumber());
  }

  void LoadStringListField(
    const LuaPlus::LuaObject& row, const std::int32_t fieldIndex, msvc8::vector<msvc8::string>& outList
  )
  {
    outList.clear();

    LuaPlus::LuaObject listObj = row.GetByIndex(fieldIndex);
    const std::int32_t count = listObj.GetN();
    if (count <= 0) {
      return;
    }

    outList.reserve(static_cast<std::size_t>(count));
    for (std::int32_t i = 1; i <= count; ++i) {
      LuaPlus::LuaObject itemObj = listObj.GetByIndex(i);
      msvc8::string value;
      value.assign_owned(SafeCString(itemObj.GetString()));
      outList.push_back(value);
    }
  }
} // namespace

gpg::RType* CAiPersonality::sType = nullptr;
CScrLuaMetatableFactory<CAiPersonality> CScrLuaMetatableFactory<CAiPersonality>::sInstance{};

CScrLuaMetatableFactory<CAiPersonality>& CScrLuaMetatableFactory<CAiPersonality>::Instance()
{
  return sInstance;
}

/**
 * Address: 0x005B9620 (FUN_005B9620, ?Create@?$CScrLuaMetatableFactory@VCAiPersonality@Moho@@@Moho@@MAE?AVLuaObject@LuaPlus@@PAVLuaState@4@@Z)
 */
LuaPlus::LuaObject CScrLuaMetatableFactory<CAiPersonality>::Create(LuaPlus::LuaState* const state)
{
  return SCR_CreateSimpleMetatable(state);
}

/**
 * Address: 0x005B6DC0 (FUN_005B6DC0, ctor body)
 */
CAiPersonality::CAiPersonality(Sim* const sim)
  : mSim(sim)
  , mPersonalityName()
  , mChatPersonality()
  , mArmySize{}
  , mPlatoonSize{}
  , mAttackFrequency{}
  , mRepeatAttackFrequency{}
  , mCounterForces{}
  , mIntelGathering{}
  , mCoordinatedAttacks{}
  , mExpansionDriven{}
  , mTechAdvancement{}
  , mUpgradesDriven{}
  , mDefenseDriven{}
  , mEconomyDriven{}
  , mFactoryTycoon{}
  , mIntelBuildingTycoon{}
  , mSuperWeaponTendency{}
  , mFavouriteStructures()
  , mAirUnitsEmphasis{}
  , mTankUnitsEmphasis{}
  , mBotUnitsEmphasis{}
  , mSeaUnitsEmphasis{}
  , mSpecialtyForcesEmphasis{}
  , mSupportUnitsEmphasis{}
  , mDirectDamageEmphasis{}
  , mIndirectDamageEmphasis{}
  , mFavouriteUnits()
  , mSurvivalEmphasis{}
  , mTeamSupport{}
  , mFormationUse{}
  , mTargetSpread{}
  , mQuittingTendency{}
  , mChatFrequency{}
  , mAdjustDelay(kDefaultAdjustDelay)
{
  if (mSim && mSim->mLuaState) {
    LuaPlus::LuaObject arg1;
    LuaPlus::LuaObject arg2;
    LuaPlus::LuaObject arg3;
    LuaPlus::LuaObject metatable = LoadAiPersonalityMetatable(mSim->mLuaState);
    CreateLuaObject(metatable, arg1, arg2, arg3);
  }

  mPersonalityName.assign_owned("None");
  mChatPersonality.assign_owned("None");
}

/**
 * Address: 0x005B6DA0 (FUN_005B6DA0, scalar deleting thunk)
 * Address: 0x005B7120 (FUN_005B7120, core dtor)
 */
CAiPersonality::~CAiPersonality() = default;

/**
 * Address: 0x005B65A0 (FUN_005B65A0, ?GetClass@CAiPersonality@Moho@@UBEPAVRType@gpg@@XZ)
 */
gpg::RType* CAiPersonality::GetClass() const
{
  gpg::RType* type = sType;
  if (!type) {
    type = gpg::LookupRType(typeid(CAiPersonality));
    sType = type;
  }
  return type;
}

/**
 * Address: 0x005B65C0 (FUN_005B65C0, ?GetDerivedObjectRef@CAiPersonality@Moho@@UAE?AVRRef@gpg@@XZ)
 */
gpg::RRef CAiPersonality::GetDerivedObjectRef()
{
  gpg::RRef ref{};
  ref.mObj = this;
  ref.mType = GetClass();
  return ref;
}

/**
 * Address: 0x005B7340 (FUN_005B7340, Moho::CAiPersonality::ReadData)
 */
void CAiPersonality::ReadData()
{
  if (!mSim || !mSim->mLuaState) {
    return;
  }

  LuaPlus::LuaObject moduleObj = SCR_ImportLuaModule(mSim->mLuaState, kAiPersonalityModulePath);
  LuaPlus::LuaObject templateTable = SCR_GetLuaTableField(mSim->mLuaState, moduleObj, kAiPersonalityTemplateName);
  if (templateTable.IsNil()) {
    gpg::Logf("Can't find AIPersonalityTemplate");
    return;
  }

  LuaPlus::LuaObject personalityTemplateRow = FindTemplateRow(templateTable, kDefaultPersonalityName);
  if (personalityTemplateRow.IsNil()) {
    gpg::Logf("Can't find the template for personality %s", kDefaultPersonalityName);
    return;
  }

  mPersonalityName.assign_owned(SafeCString(personalityTemplateRow.GetByIndex(1).GetString()));
  mChatPersonality.assign_owned(SafeCString(personalityTemplateRow.GetByIndex(2).GetString()));

  LoadRangeField(personalityTemplateRow, 3, mArmySize);
  LoadRangeField(personalityTemplateRow, 4, mPlatoonSize);
  LoadRangeField(personalityTemplateRow, 5, mAttackFrequency);
  LoadRangeField(personalityTemplateRow, 6, mRepeatAttackFrequency);
  LoadRangeField(personalityTemplateRow, 7, mCounterForces);
  LoadRangeField(personalityTemplateRow, 8, mIntelGathering);
  LoadRangeField(personalityTemplateRow, 9, mCoordinatedAttacks);
  LoadRangeField(personalityTemplateRow, 10, mExpansionDriven);
  LoadRangeField(personalityTemplateRow, 11, mTechAdvancement);
  LoadRangeField(personalityTemplateRow, 12, mUpgradesDriven);
  LoadRangeField(personalityTemplateRow, 13, mDefenseDriven);
  LoadRangeField(personalityTemplateRow, 14, mEconomyDriven);
  LoadRangeField(personalityTemplateRow, 15, mFactoryTycoon);
  LoadRangeField(personalityTemplateRow, 16, mIntelBuildingTycoon);
  LoadRangeField(personalityTemplateRow, 17, mSuperWeaponTendency);
  LoadStringListField(personalityTemplateRow, 18, mFavouriteStructures);
  LoadRangeField(personalityTemplateRow, 19, mAirUnitsEmphasis);
  LoadRangeField(personalityTemplateRow, 20, mTankUnitsEmphasis);
  LoadRangeField(personalityTemplateRow, 21, mBotUnitsEmphasis);
  LoadRangeField(personalityTemplateRow, 22, mSeaUnitsEmphasis);
  LoadRangeField(personalityTemplateRow, 23, mSpecialtyForcesEmphasis);
  LoadRangeField(personalityTemplateRow, 24, mSupportUnitsEmphasis);
  LoadRangeField(personalityTemplateRow, 25, mDirectDamageEmphasis);
  LoadRangeField(personalityTemplateRow, 26, mIndirectDamageEmphasis);
  LoadStringListField(personalityTemplateRow, 27, mFavouriteUnits);
  LoadRangeField(personalityTemplateRow, 28, mSurvivalEmphasis);
  LoadRangeField(personalityTemplateRow, 29, mTeamSupport);
  LoadRangeField(personalityTemplateRow, 30, mFormationUse);
  LoadRangeField(personalityTemplateRow, 31, mTargetSpread);
  LoadRangeField(personalityTemplateRow, 32, mQuittingTendency);
  LoadRangeField(personalityTemplateRow, 33, mChatFrequency);
}
