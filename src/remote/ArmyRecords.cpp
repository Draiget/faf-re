#include "remote/ArmyRecords.h"

#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/sim/SSTIArmyVariableData.h"

// Engine addition, server mode: see ArmyRecords.h.

namespace faf::remote
{
  namespace
  {
    [[nodiscard]] std::vector<std::uint32_t> Members(const moho::BVIntSet& set)
    {
      std::vector<std::uint32_t> members;
      set.ForEachValue([&members](const unsigned int value) {
        if (members.size() < wire::SArmyRecord::kMaxSetMembers) {
          members.push_back(value);
        }
      });
      return members;
    }

    void AssignMembers(moho::BVIntSet& set, const std::vector<std::uint32_t>& members)
    {
      set = moho::BVIntSet{};
      for (const std::uint32_t member : members) {
        (void)set.Add(member);
      }
    }
  } // namespace

  wire::SArmyRecord ArmyToWire(const moho::SSTIArmyVariableData& army)
  {
    wire::SArmyRecord record;
    const moho::SEconTotals& economy = army.mEconomyTotals;
    record.economy = {economy.mStored.ENERGY,           economy.mStored.MASS,           economy.mIncome.ENERGY,
                      economy.mIncome.MASS,             economy.mReclaimed.ENERGY,      economy.mReclaimed.MASS,
                      economy.mLastUseRequested.ENERGY, economy.mLastUseRequested.MASS, economy.mLastUseActual.ENERGY,
                      economy.mLastUseActual.MASS};
    record.maxStorage = {economy.mMaxStorage.ENERGY, economy.mMaxStorage.MASS};
    record.resourceSharing = army.mIsResourceSharingEnabled;
    record.neutrals = Members(army.mNeutrals);
    record.allies = Members(army.mAllies);
    record.enemies = Members(army.mEnemies);
    record.isAlly = army.mIsAlly;
    record.validCommandSources = Members(army.mValidCommandSources);
    record.playerColor = army.mPlayerColorBgra;
    record.armyColor = army.mArmyColorBgra;
    record.armyType.assign(army.mArmyType.c_str());
    if (record.armyType.size() > wire::SArmyRecord::kMaxTypeLength) {
      record.armyType.resize(wire::SArmyRecord::kMaxTypeLength);
    }
    record.faction = army.mFaction;
    record.useWholeMap = army.mUseWholeMap;
    record.showScore = army.mShowScore;
    record.categoryFilter.firstWord = army.mCategoryFilterSet.mBits.mFirstWordIndex;
    record.categoryFilter.words.assign(
      army.mCategoryFilterSet.mBits.mWords.begin(), army.mCategoryFilterSet.mBits.mWords.end()
    );
    if (record.categoryFilter.words.size() > wire::SCategoryBits::kMaxWords) {
      record.categoryFilter.words.resize(wire::SCategoryBits::kMaxWords);
    }
    record.isOutOfGame = army.mIsOutOfGame;
    record.armyStart = {army.mArmyStart.x, army.mArmyStart.y};
    record.noRushTimer = army.mNoRushTimer;
    record.noRushRadius = army.mNoRushRadius;
    record.noRushOffset = {army.mNoRushOffset.x, army.mNoRushOffset.y};
    record.handicapValue = army.mHandicapValue;
    record.handicapExtra = army.mHandicapExtra;
    return record;
  }

  void ArmyFromWire(const wire::SArmyRecord& record, moho::SSTIArmyVariableData& army, moho::RRuleGameRules* const rules)
  {
    moho::SEconTotals& economy = army.mEconomyTotals;
    economy.mStored = {record.economy[0], record.economy[1]};
    economy.mIncome = {record.economy[2], record.economy[3]};
    economy.mReclaimed = {record.economy[4], record.economy[5]};
    economy.mLastUseRequested = {record.economy[6], record.economy[7]};
    economy.mLastUseActual = {record.economy[8], record.economy[9]};
    economy.mMaxStorage = {record.maxStorage[0], record.maxStorage[1]};
    army.mIsResourceSharingEnabled = record.resourceSharing;
    AssignMembers(army.mNeutrals, record.neutrals);
    AssignMembers(army.mAllies, record.allies);
    AssignMembers(army.mEnemies, record.enemies);
    army.mIsAlly = record.isAlly;
    AssignMembers(army.mValidCommandSources, record.validCommandSources);
    army.mPlayerColorBgra = record.playerColor;
    army.mArmyColorBgra = record.armyColor;
    army.mArmyType.assign(record.armyType.c_str());
    army.mFaction = record.faction;
    army.mUseWholeMap = record.useWholeMap;
    army.mWordVectorWithMeta = moho::SArmyVectorWithMeta{};
    army.mShowScore = record.showScore;
    army.mCategoryFilterSet.mUniverse.mRules = rules;
    army.mCategoryFilterSet.mBits.mFirstWordIndex = record.categoryFilter.firstWord;
    army.mCategoryFilterSet.mBits.mWords.clear();
    for (const std::uint32_t word : record.categoryFilter.words) {
      army.mCategoryFilterSet.mBits.mWords.push_back(word);
    }
    army.mIsOutOfGame = record.isOutOfGame;
    army.mArmyStart = Wm3::Vector2f{record.armyStart[0], record.armyStart[1]};
    army.mNoRushTimer = record.noRushTimer;
    army.mNoRushRadius = record.noRushRadius;
    army.mNoRushOffset = Wm3::Vector2f{record.noRushOffset[0], record.noRushOffset[1]};
    army.mHandicapValue = record.handicapValue;
    army.mHandicapExtra = record.handicapExtra;
  }
} // namespace faf::remote
