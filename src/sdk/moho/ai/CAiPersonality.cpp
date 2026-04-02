#include "moho/ai/CAiPersonality.h"

#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/misc/Stats.h"
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

  gpg::RType* gCScriptObjectType = nullptr;
  gpg::RType* gSimType = nullptr;
  gpg::RType* gAiPersonalityRangeType = nullptr;
  gpg::RType* gStringVectorType = nullptr;
  EngineStats* gRecoveredAiPersonalityStartupStatsSlot = nullptr;

  template <class TObject>
  [[nodiscard]] gpg::RType* CachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  [[nodiscard]] gpg::RType* CachedCScriptObjectType()
  {
    if (!CScriptObject::sType) {
      CScriptObject::sType = CachedType<CScriptObject>(gCScriptObjectType);
    }
    return CScriptObject::sType;
  }

  [[nodiscard]] gpg::RType* CachedSimType()
  {
    if (!Sim::sType) {
      Sim::sType = CachedType<Sim>(gSimType);
    }
    return Sim::sType;
  }

  [[nodiscard]] gpg::RType* CachedPersonalityRangeType()
  {
    return CachedType<SAiPersonalityRange>(gAiPersonalityRangeType);
  }

  [[nodiscard]] gpg::RType* CachedStringVectorType()
  {
    return CachedType<msvc8::vector<msvc8::string>>(gStringVectorType);
  }

  template <typename TObject>
  [[nodiscard]] TObject* ReadPointerWithType(gpg::ReadArchive* const archive, const gpg::RRef& owner, gpg::RType* expectedType)
  {
    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, owner);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
    return static_cast<TObject*>(upcast.mObj);
  }

  template <typename TObject>
  [[nodiscard]] gpg::RRef MakeTypedRef(TObject* object, gpg::RType* staticType)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = staticType;
    if (!object) {
      return out;
    }

    gpg::RType* dynamicType = staticType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = staticType;
    }

    std::int32_t baseOffset = 0;
    const bool derived = dynamicType && staticType && dynamicType->IsDerivedFrom(staticType, &baseOffset);
    if (!derived) {
      out.mObj = object;
      out.mType = dynamicType ? dynamicType : staticType;
      return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
  }

  template <typename TObject>
  void WritePointerWithType(
    gpg::WriteArchive* const archive,
    TObject* const object,
    gpg::RType* const staticType,
    const gpg::TrackedPointerState state,
    const gpg::RRef& owner
  )
  {
    const gpg::RRef objectRef = MakeTypedRef(object, staticType);
    gpg::WriteRawPointer(archive, objectRef, state, owner);
  }

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

  /**
   * Address: 0x00BF7770 (FUN_00BF7770, cleanup_CAiPersonalityStartup)
   *
   * What it does:
   * Tears down one startup-owned AI personality stats slot.
   */
  void cleanup_CAiPersonalityStartup()
  {
    if (!gRecoveredAiPersonalityStartupStatsSlot) {
      return;
    }

    delete gRecoveredAiPersonalityStartupStatsSlot;
    gRecoveredAiPersonalityStartupStatsSlot = nullptr;
  }
} // namespace

gpg::RType* CAiPersonality::sType = nullptr;
CScrLuaMetatableFactory<CAiPersonality> CScrLuaMetatableFactory<CAiPersonality>::sInstance{};

/**
 * Address: 0x00BCD6A0 (FUN_00BCD6A0)
 *
 * What it does:
 * Allocates and stores the startup Lua metatable-factory index for
 * `CAiPersonality`.
 */
int moho::register_CScrLuaMetatableFactory_CAiPersonality_Index()
{
  const int index = CScrLuaObjectFactory::AllocateFactoryObjectIndex();
  CScrLuaMetatableFactory<CAiPersonality>::Instance().SetFactoryObjectIndexForRecovery(index);
  return index;
}

/**
 * Address: 0x00BCD6C0 (FUN_00BCD6C0)
 *
 * What it does:
 * Installs process-exit cleanup for one startup-owned AI reflection slot.
 */
int moho::register_CAiPersonalityStartupCleanup()
{
  return std::atexit(&cleanup_CAiPersonalityStartup);
}

CScrLuaMetatableFactory<CAiPersonality>& CScrLuaMetatableFactory<CAiPersonality>::Instance()
{
  return sInstance;
}

namespace
{
  struct CAiPersonalityStartupBootstrap
  {
    CAiPersonalityStartupBootstrap()
    {
      (void)moho::register_CScrLuaMetatableFactory_CAiPersonality_Index();
      (void)moho::register_CAiPersonalityStartupCleanup();
    }
  };

  [[maybe_unused]] CAiPersonalityStartupBootstrap gCAiPersonalityStartupBootstrap;
} // namespace

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

/**
 * Address: 0x005B96A0 (FUN_005B96A0, Moho::CAiPersonality::MemberDeserialize)
 */
void CAiPersonality::MemberDeserialize(gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef owner{};
  archive->Read(CachedCScriptObjectType(), this, owner);
  mSim = ReadPointerWithType<Sim>(archive, owner, CachedSimType());
  archive->ReadString(&mPersonalityName);
  archive->ReadString(&mChatPersonality);

  gpg::RType* const rangeType = CachedPersonalityRangeType();
  GPG_ASSERT(rangeType != nullptr);
  gpg::RType* const stringVectorType = CachedStringVectorType();
  GPG_ASSERT(stringVectorType != nullptr);

  archive->Read(rangeType, &mArmySize, owner);
  archive->Read(rangeType, &mPlatoonSize, owner);
  archive->Read(rangeType, &mAttackFrequency, owner);
  archive->Read(rangeType, &mRepeatAttackFrequency, owner);
  archive->Read(rangeType, &mCounterForces, owner);
  archive->Read(rangeType, &mIntelGathering, owner);
  archive->Read(rangeType, &mCoordinatedAttacks, owner);
  archive->Read(rangeType, &mExpansionDriven, owner);
  archive->Read(rangeType, &mTechAdvancement, owner);
  archive->Read(rangeType, &mUpgradesDriven, owner);
  archive->Read(rangeType, &mDefenseDriven, owner);
  archive->Read(rangeType, &mEconomyDriven, owner);
  archive->Read(rangeType, &mFactoryTycoon, owner);
  archive->Read(rangeType, &mIntelBuildingTycoon, owner);
  archive->Read(rangeType, &mSuperWeaponTendency, owner);
  archive->Read(stringVectorType, &mFavouriteStructures, owner);
  archive->Read(rangeType, &mAirUnitsEmphasis, owner);
  archive->Read(rangeType, &mTankUnitsEmphasis, owner);
  archive->Read(rangeType, &mBotUnitsEmphasis, owner);
  archive->Read(rangeType, &mSeaUnitsEmphasis, owner);
  archive->Read(rangeType, &mSpecialtyForcesEmphasis, owner);
  archive->Read(rangeType, &mSupportUnitsEmphasis, owner);
  archive->Read(rangeType, &mDirectDamageEmphasis, owner);
  archive->Read(rangeType, &mIndirectDamageEmphasis, owner);
  archive->Read(stringVectorType, &mFavouriteUnits, owner);
  archive->Read(rangeType, &mSurvivalEmphasis, owner);
  archive->Read(rangeType, &mTeamSupport, owner);
  archive->Read(rangeType, &mFormationUse, owner);
  archive->Read(rangeType, &mTargetSpread, owner);
  archive->Read(rangeType, &mQuittingTendency, owner);
  archive->Read(rangeType, &mChatFrequency, owner);
  archive->ReadFloat(&mAdjustDelay);
}

/**
 * Address: 0x005B9DD0 (FUN_005B9DD0, Moho::CAiPersonality::MemberSerialize)
 */
void CAiPersonality::MemberSerialize(gpg::WriteArchive* const archive) const
{
  if (!archive) {
    return;
  }

  const gpg::RRef owner{};
  archive->Write(CachedCScriptObjectType(), const_cast<CAiPersonality*>(this), owner);
  WritePointerWithType(archive, mSim, CachedSimType(), gpg::TrackedPointerState::Unowned, owner);
  archive->WriteString(const_cast<msvc8::string*>(&mPersonalityName));
  archive->WriteString(const_cast<msvc8::string*>(&mChatPersonality));

  gpg::RType* const rangeType = CachedPersonalityRangeType();
  GPG_ASSERT(rangeType != nullptr);
  gpg::RType* const stringVectorType = CachedStringVectorType();
  GPG_ASSERT(stringVectorType != nullptr);

  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mArmySize), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mPlatoonSize), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mAttackFrequency), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mRepeatAttackFrequency), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mCounterForces), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mIntelGathering), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mCoordinatedAttacks), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mExpansionDriven), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mTechAdvancement), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mUpgradesDriven), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mDefenseDriven), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mEconomyDriven), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mFactoryTycoon), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mIntelBuildingTycoon), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mSuperWeaponTendency), owner);
  archive->Write(stringVectorType, const_cast<msvc8::vector<msvc8::string>*>(&mFavouriteStructures), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mAirUnitsEmphasis), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mTankUnitsEmphasis), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mBotUnitsEmphasis), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mSeaUnitsEmphasis), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mSpecialtyForcesEmphasis), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mSupportUnitsEmphasis), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mDirectDamageEmphasis), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mIndirectDamageEmphasis), owner);
  archive->Write(stringVectorType, const_cast<msvc8::vector<msvc8::string>*>(&mFavouriteUnits), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mSurvivalEmphasis), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mTeamSupport), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mFormationUse), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mTargetSpread), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mQuittingTendency), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mChatFrequency), owner);
  archive->WriteFloat(mAdjustDelay);
}
