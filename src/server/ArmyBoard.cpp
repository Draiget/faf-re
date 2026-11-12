#include "server/ArmyBoard.h"

#include <algorithm>
#include <cmath>
#include <cstdio>

#include "lua/LuaObject.h"
#include "lua/LuaTableIterator.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/entity/SSTIEntityVariableData.h"
#include "moho/sim/SSTIArmyVariableData.h"
#include "moho/sim/SimDriver.h"
#include "server/ControlListener.h"

namespace faf::server
{
  namespace
  {
    constexpr std::size_t kMaxArmies = 64; // the id's source bits allow 255; a game has at most 16 armies and civilians

    [[nodiscard]] bool IsCommander(
      const moho::REntityBlueprint* const blueprint
    )
    {
      if (blueprint == nullptr) {
        return false;
      }
      for (const fa::string& category : blueprint->mCategories) {
        if (std::string_view(category.c_str()) == "COMMAND") {
          return true;
        }
      }
      return false;
    }

    [[nodiscard]] std::string Number(
      const double value
    )
    {
      if (!std::isfinite(value)) {
        return "null";
      }
      char text[32];
      std::snprintf(text, sizeof(text), "%.1f", value);
      std::string out = text;
      if (out.size() > 2 && out.ends_with(".0")) {
        out.resize(out.size() - 2);
      }
      return out == "-0" ? "0" : out;
    }

    [[nodiscard]] double NumberIn(
      LuaPlus::LuaObject table,
      const char* const key,
      const double otherwise
    )
    {
      if (!table.IsTable()) {
        return otherwise;
      }
      const LuaPlus::LuaObject value = table[key];
      return value.IsNumber() ? value.GetNumber() : otherwise;
    }
  } // namespace

  CArmyBoard::SArmy& CArmyBoard::Army(
    const std::size_t index
  )
  {
    if (index >= mArmies.size()) {
      mArmies.resize(index + 1u);
    }
    return mArmies[index];
  }

  void CArmyBoard::ReadPacket(
    const moho::SSyncData& packet
  )
  {
    std::size_t index = 0;
    for (const moho::SSTIArmyVariableData& update : packet.mArmyUpdates) {
      if (index >= kMaxArmies) {
        break;
      }
      SArmy& army = Army(index++);
      const moho::SEconTotals& economy = update.mEconomyTotals;
      army.economySeen = true;
      army.massStored = economy.mStored.MASS;
      army.energyStored = economy.mStored.ENERGY;
      army.massIncome = economy.mIncome.MASS;
      army.energyIncome = economy.mIncome.ENERGY;
      army.massStorage = economy.mMaxStorage.MASS;
      army.energyStorage = economy.mMaxStorage.ENERGY;
      army.faction = update.mFaction;
      army.outOfGame = update.mIsOutOfGame != 0u;
    }
    for (const moho::SCreateUnitParams& unit : packet.mNewUnits) {
      const std::size_t armyIndex = ArmyOfEntity(unit.mEntityId);
      if (armyIndex < kMaxArmies && IsCommander(unit.mBlueprint)) {
        SArmy& army = Army(armyIndex);
        if (!army.acuSeen || !army.acuAlive) { // the first commander; a later one (a second ACU) doesn't replace a live
                                               // one
          army.acu = unit.mEntityId;
          army.acuSeen = true;
          army.acuAlive = true;
          army.acuHealth = 0.0f;
          army.acuMaxHealth = 0.0f;
        }
      }
    }
    for (const moho::SEntityVariableUpdateEntry& entry : packet.mEntityUpdates) {
      const std::uint32_t id = static_cast<std::uint32_t>(entry.mEntityId);
      const std::size_t armyIndex = ArmyOfEntity(id);
      if (armyIndex < mArmies.size() && mArmies[armyIndex].acuSeen && mArmies[armyIndex].acu == id) {
        SArmy& army = mArmies[armyIndex];
        army.acuHealth = entry.mVariableData.mHealth;
        army.acuMaxHealth = entry.mVariableData.mMaxHealth;
        army.acuAlive = entry.mVariableData.mIsDead == 0u;
      }
    }
    for (const auto deleted : packet.mDeleteIds) {
      const std::uint32_t id = static_cast<std::uint32_t>(deleted);
      const std::size_t armyIndex = ArmyOfEntity(id);
      if (armyIndex < mArmies.size() && mArmies[armyIndex].acuSeen && mArmies[armyIndex].acu == id) {
        mArmies[armyIndex].acuAlive = false;
        mArmies[armyIndex].acuHealth = 0.0f;
      }
      mEnhancements.erase(id);
    }
  }

  void CArmyBoard::ReadSync(
    const LuaPlus::LuaObject& syncIn
  )
  {
    LuaPlus::LuaObject sync = syncIn;
    if (!sync.IsTable()) {
      return;
    }
    // `Sync.Score[army]` (1-based): FAF's ArmyScore for an observer; a defeated army in a player's view is
    // `{Defeated = true, general = {}}`.
    if (LuaPlus::LuaObject score = sync["Score"]; score.IsTable()) {
      LuaPlus::LuaTableIterator it(&score, 1);
      while (!it.m_isDone) {
        const LuaPlus::LuaObject key = it.GetKey();
        LuaPlus::LuaObject entry = it.GetValue();
        if (
          key.IsNumber() && key.GetNumber() >= 1.0 && key.GetNumber() <= static_cast<double>(kMaxArmies) &&
          entry.IsTable()
        ) {
          SArmy& army = Army(static_cast<std::size_t>(key.GetNumber()) - 1u);
          LuaPlus::LuaObject general = entry["general"];
          army.scoreSeen = true;
          army.score = NumberIn(general, "score", army.score);
          army.units = static_cast<int>(NumberIn(general, "currentunits", army.units));
          army.unitCap = static_cast<int>(NumberIn(general, "currentcap", army.unitCap));
          if (const LuaPlus::LuaObject type = entry["type"]; type.IsString()) {
            army.type = type.GetString();
          }
          const LuaPlus::LuaObject defeated = entry["Defeated"];
          army.defeated = !defeated.IsNil() && (!defeated.IsBoolean() || defeated.GetBoolean());
        }
        it.Next();
      }
    }
    // `Sync.UserUnitEnhancements`: the whole table every time one changes (SimSync.lua SyncUnitEnhancements).
    if (LuaPlus::LuaObject enhancements = sync["UserUnitEnhancements"]; enhancements.IsTable()) {
      mEnhancements.clear();
      LuaPlus::LuaTableIterator it(&enhancements, 1);
      while (!it.m_isDone) {
        const LuaPlus::LuaObject key = it.GetKey();
        LuaPlus::LuaObject slots = it.GetValue();
        if (key.IsNumber() && slots.IsTable()) {
          std::vector<std::string>& names = mEnhancements[static_cast<std::uint32_t>(key.GetNumber())];
          LuaPlus::LuaTableIterator slot(&slots, 1);
          while (!slot.m_isDone) {
            if (const LuaPlus::LuaObject name = slot.GetValue(); name.IsString()) {
              names.emplace_back(name.GetString());
            }
            slot.Next();
          }
        }
        it.Next();
      }
    }
  }

  std::string CArmyBoard::Json(
    const int beat,
    const std::vector<SPlayer>& players
  ) const
  {
    std::string out = "\"beat\":" + std::to_string(beat) + ",\"armies\":[";
    const std::size_t count = std::max(players.size(), mArmies.size());
    bool first = true;
    for (std::size_t index = 0; index < count; ++index) {
      const SArmy none{};
      const SArmy& army = index < mArmies.size() ? mArmies[index] : none;
      const SPlayer* const player = index < players.size() ? &players[index] : nullptr;
      if (player == nullptr && !army.scoreSeen) {
        continue; // civilians: no match player and no score
      }
      out += first ? "" : ",";
      first = false;
      out += "{\"army\":" + std::to_string(index + 1u);
      out += ",\"name\":" + JsonString(player != nullptr ? player->name : std::string{});
      out += ",\"team\":" + std::to_string(player != nullptr ? player->team : 0);
      out += ",\"faction\":" + (army.faction >= 0 ? std::to_string(army.faction + 1) : std::string("null"));
      out += ",\"human\":" + std::string(player != nullptr && player->human ? "true" : "false");
      out += ",\"uid\":" + (player != nullptr && player->uid != 0 ? std::to_string(player->uid) : std::string("null"));
      out += ",\"type\":" + (army.type.empty() ? std::string("null") : JsonString(army.type));
      out += ",\"score\":" + (army.scoreSeen ? Number(army.score) : std::string("null"));
      if (army.economySeen) {
        // Income is per tick in the sim (`GetEconomyIncome`); the game's UI shows it per second, ten ticks.
        out += ",\"mass\":{\"stored\":" + Number(army.massStored) + ",\"income\":" + Number(army.massIncome * 10.0) +
          ",\"storage\":" + std::to_string(army.massStorage) + "}";
        out += ",\"energy\":{\"stored\":" + Number(army.energyStored) +
          ",\"income\":" + Number(army.energyIncome * 10.0) + ",\"storage\":" + std::to_string(army.energyStorage) +
          "}";
      } else {
        out += ",\"mass\":null,\"energy\":null";
      }
      if (army.scoreSeen) {
        out += ",\"units\":{\"count\":" + std::to_string(army.units) + ",\"cap\":" + std::to_string(army.unitCap) + "}";
      } else {
        out += ",\"units\":null";
      }
      if (army.acuSeen) {
        out += ",\"acu\":{\"alive\":" + std::string(army.acuAlive ? "true" : "false") +
          ",\"health\":" + Number(army.acuHealth) + ",\"max_health\":" + Number(army.acuMaxHealth) +
          ",\"enhancements\":[";
        if (const auto found = mEnhancements.find(army.acu); found != mEnhancements.end()) {
          for (std::size_t n = 0; n < found->second.size(); ++n) {
            out += (n == 0 ? "" : ",") + JsonString(found->second[n]);
          }
        }
        out += "]}";
      } else {
        out += ",\"acu\":null";
      }
      out += ",\"defeated\":" + std::string(army.defeated || army.outOfGame ? "true" : "false");
      out += ",\"result\":" +
        (player != nullptr && !player->result.empty() ? JsonString(player->result) : std::string("null"));
      out += "}";
    }
    out += "]";
    return out;
  }
} // namespace faf::server
