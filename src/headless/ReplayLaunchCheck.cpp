#include "headless/ReplayLaunchCheck.h"
#include "headless/ReplayLuaState.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <set>
#include <stdexcept>
#include <vector>

#include "gpg/core/containers/String.h"
#include "lua/LuaObject.h"
#include "lua/LuaTableIterator.h"
#include "moho/containers/BVIntSet.h"
#include "moho/lua/SCR_String.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/misc/SessionStartup.h"
#include "moho/net/LaunchInfoBuilder.h"
#include "moho/sim/SSTICommandSource.h"
#include "moho/sim/WldSessionInfo.h"

// Engine addition, server mode: see ReplayLaunchCheck.h.

namespace faf::headless
{
  namespace
  {
    constexpr std::int32_t kObserverUidBase = 900000000; // uids for observers (the header has none)

    [[nodiscard]] LuaPlus::LuaObject FromString(const msvc8::string& text, LuaPlus::LuaState* const state)
    {
      LuaPlus::LuaObject object;
      (void)moho::SCR_FromString(&object, text, state);
      return object;
    }

    [[nodiscard]] std::vector<std::uint32_t> Sources(const moho::BVIntSet& set)
    {
      std::vector<std::uint32_t> sources;
      const unsigned int end = set.Max();
      for (unsigned int source = set.GetNext(~0u); source != end; source = set.GetNext(source)) {
        sources.push_back(source);
      }
      return sources;
    }

    /**
     * A Lua value as text with every table's keys sorted: two serialised values with the same
     * content in another key order (a table rebuilt from bytes need not iterate as the one the
     * lobby script built) give one text.
     */
    [[nodiscard]] std::string Canonical(const LuaPlus::LuaObject& value, const int depth = 0)
    {
      if (depth > 32) {
        return "<deep>";
      }
      if (value.IsTable()) {
        std::vector<std::string> entries;
        LuaPlus::LuaObject table = value;
        LuaPlus::LuaTableIterator it(&table, 1);
        while (!it.m_isDone) {
          entries.push_back(Canonical(it.GetKey(), depth + 1) + "=" + Canonical(it.GetValue(), depth + 1));
          it.Next();
        }
        std::sort(entries.begin(), entries.end());
        std::string text = "{";
        for (const std::string& entry : entries) {
          text += entry + ",";
        }
        return text + "}";
      }
      if (value.IsNumber()) {
        return gpg::STR_Printf("%.9g", value.GetNumber()).c_str();
      }
      if (value.IsString()) {
        const char* const text = value.GetString();
        return std::string("'") + (text != nullptr ? text : "") + "'";
      }
      if (value.IsBoolean()) {
        return value.GetBoolean() ? "true" : "false";
      }
      return value.IsNil() ? "nil" : "<other>";
    }

    /** As `Canonical`, but in the tables' own iteration order (what the serialiser writes). */
    [[nodiscard]] std::string Ordered(const LuaPlus::LuaObject& value, const int depth = 0)
    {
      if (depth > 32) {
        return "<deep>";
      }
      if (value.IsTable()) {
        std::string text = "{";
        LuaPlus::LuaObject table = value;
        LuaPlus::LuaTableIterator it(&table, 1);
        while (!it.m_isDone) {
          text += Ordered(it.GetKey(), depth + 1) + "=" + Ordered(it.GetValue(), depth + 1) + ",";
          it.Next();
        }
        return text + "}";
      }
      return Canonical(value, depth);
    }

    struct SParticipant
    {
      std::int32_t uid = 0;
      msvc8::string name;
    };

    /** The lobby's game config and participants, read back from a recorded launch. */
    struct SRebuiltConfig
    {
      LuaPlus::LuaObject dat;
      std::vector<SParticipant> participants; // in command-source order
      std::int32_t localUid = 0;
      bool isMultiplayer = false;
    };

    [[nodiscard]] SRebuiltConfig RebuildConfig(const moho::LaunchInfoNew& recorded, LuaPlus::LuaState* const state)
    {
      SRebuiltConfig config;
      LuaPlus::LuaObject scenario = FromString(recorded.mScenarioInfo, state);
      if (!scenario.IsTable()) {
        throw std::runtime_error("the recorded scenario info is not a table");
      }
      LuaPlus::LuaObject options = scenario["Options"];

      // The FFA team's army names give each army's slot.
      std::vector<std::string> ffaArmies;
      LuaPlus::LuaObject teams = scenario.Lookup("Configurations.standard.teams");
      if (teams.IsTable()) {
        LuaPlus::LuaTableIterator teamIt(&teams, 1);
        while (!teamIt.m_isDone) {
          LuaPlus::LuaObject team = teamIt.GetValue();
          const char* const teamName = team["name"].GetString();
          if (teamName != nullptr && _stricmp(teamName, "FFA") == 0) {
            LuaPlus::LuaObject armies = team["armies"];
            LuaPlus::LuaTableIterator armyIt(&armies, 1);
            while (!armyIt.m_isDone) {
              const char* const armyName = armyIt.GetValue().GetString();
              ffaArmies.emplace_back(armyName != nullptr ? armyName : "");
              armyIt.Next();
            }
            break;
          }
          teamIt.Next();
        }
      }

      LuaPlus::LuaObject playerOptions;
      playerOptions.AssignNewTable(state, 0, 0);
      std::map<std::uint32_t, std::int32_t> sourceOwner; // command source -> uid
      for (std::size_t army = 0; army < recorded.mStrVec.size(); ++army) {
        LuaPlus::LuaObject option = FromString(recorded.mStrVec[army], state);
        if (!option.IsTable()) {
          throw std::runtime_error("an army's recorded options are not a table");
        }
        if (option["Civilian"].GetBoolean()) {
          continue; // added by the launch itself from CivilianAlliance
        }
        const char* const armyName = option["ArmyName"].GetString();
        const auto slot = std::find(ffaArmies.begin(), ffaArmies.end(), armyName != nullptr ? armyName : "");
        if (slot == ffaArmies.end()) {
          throw std::runtime_error(std::string("army ") + (armyName ? armyName : "?") + " is not in the FFA team");
        }
        if (option["Human"].GetBoolean()) {
          const char* const ownerText = option["OwnerID"].GetString();
          const std::int32_t owner = std::atoi(ownerText != nullptr ? ownerText : "");
          for (const std::uint32_t source : Sources(recorded.mArmyLaunchInfo[army].mUnitSources)) {
            sourceOwner.emplace(source, owner);
          }
        }
        playerOptions.SetObject(static_cast<std::int32_t>(slot - ffaArmies.begin()) + 1, option);
      }

      // Every command source an army does not own is an observer's, in order.
      LuaPlus::LuaObject observers;
      observers.AssignNewTable(state, 0, 0);
      std::int32_t observerCount = 0;
      const auto& sources = recorded.mCommandSources.mSrcs;
      for (std::uint32_t source = 0; source < sources.size(); ++source) {
        SParticipant participant;
        participant.name = sources[source].mName;
        if (const auto owner = sourceOwner.find(source); owner != sourceOwner.end()) {
          participant.uid = owner->second;
        } else {
          participant.uid = kObserverUidBase + observerCount;
          LuaPlus::LuaObject observer;
          observer.AssignNewTable(state, 0, 0);
          observer.SetString("OwnerID", gpg::STR_Printf("%d", participant.uid).c_str());
          observer.SetString("PlayerName", sources[source].mName.c_str());
          observers.SetObject(++observerCount, observer);
        }
        config.participants.push_back(participant);
        if (sources[source].mTimeouts != -1) {
          config.isMultiplayer = true;
        }
      }
      if (config.participants.empty()) {
        throw std::runtime_error("the recorded launch has no command sources");
      }
      config.localUid = config.participants.front().uid;

      config.dat.AssignNewTable(state, 0, 0);
      config.dat.SetObject("GameOptions", options);
      LuaPlus::LuaObject mods = FromString(recorded.mGameMods, state);
      config.dat.SetObject("GameMods", mods);
      config.dat.SetObject("PlayerOptions", playerOptions);
      config.dat.SetObject("Observers", observers);
      return config;
    }

    void Compare(
      const char* const path, const moho::LaunchInfoNew& recorded, const msvc8::string& recordedMap,
      const moho::SLaunchBuild& build, LuaPlus::LuaState* const state, SLaunchCheckResult& result
    )
    {
      const auto differ = [&](const std::string& what) {
        ++result.differences;
        result.report += std::string(path) + ": " + what + "\n";
      };
      const moho::LaunchInfoNew& built = *build.launchInfo;
      const auto same = [](const msvc8::string& a, const msvc8::string& b) {
        return a.size() == b.size() && std::char_traits<char>::compare(a.c_str(), b.c_str(), a.size()) == 0;
      };
      // A serialised Lua value: identical bytes, or (counted apart) the same content in another
      // key order.
      const auto lua = [&](const char* name, const msvc8::string& a, const msvc8::string& b) {
        if (same(a, b)) {
          return;
        }
        if (Canonical(FromString(a, state)) == Canonical(FromString(b, state))) {
          ++result.orderOnly;
          if (std::getenv("FAF_LAUNCHCHECK_VERBOSE") != nullptr) {
            const std::string x = Ordered(FromString(a, state));
            const std::string y = Ordered(FromString(b, state));
            std::size_t at = 0;
            while (at < x.size() && at < y.size() && x[at] == y[at]) {
              ++at;
            }
            const std::size_t from = at > 80 ? at - 80 : 0;
            result.report += std::string(path) + ": " + name + " key order: recorded ..." + x.substr(from, 240)
                           + "\n    built    ..." + y.substr(from, 240) + "\n";
          }
          return;
        }
        differ(gpg::STR_Printf("%s differs in content (%zu vs %zu bytes)", name, a.size(), b.size()).c_str());
      };
      const auto bytes = [&](const char* name, const msvc8::string& a, const msvc8::string& b) {
        if (!same(a, b)) {
          std::size_t at = 0;
          while (at < a.size() && at < b.size() && a.c_str()[at] == b.c_str()[at]) {
            ++at;
          }
          differ(gpg::STR_Printf("%s differs (%zu vs %zu bytes, first difference at %zu)", name, a.size(), b.size(), at).c_str());
        }
      };
      bytes("map name", recordedMap, build.mapName);
      lua("game mods", recorded.mGameMods, built.mGameMods);
      lua("scenario info", recorded.mScenarioInfo, built.mScenarioInfo);
      if (recorded.mCheatsEnabled != built.mCheatsEnabled) {
        differ("cheats differ");
      }
      if (recorded.mInitSeed != built.mInitSeed) {
        differ("seed differs");
      }
      const auto& a = recorded.mCommandSources.mSrcs;
      const auto& b = built.mCommandSources.mSrcs;
      if (a.size() != b.size()) {
        differ(gpg::STR_Printf("command sources: %zu vs %zu", a.size(), b.size()).c_str());
      } else {
        for (std::size_t i = 0; i < a.size(); ++i) {
          if (a[i].mIndex != b[i].mIndex || a[i].mTimeouts != b[i].mTimeouts || a[i].mName.view() != b[i].mName.view()) {
            differ(gpg::STR_Printf("command source %zu differs", i).c_str());
          }
        }
      }
      if (recorded.mStrVec.size() != built.mStrVec.size() || recorded.mArmyLaunchInfo.size() != built.mArmyLaunchInfo.size()) {
        differ(gpg::STR_Printf("armies: %zu vs %zu", recorded.mStrVec.size(), built.mStrVec.size()).c_str());
        return;
      }
      for (std::size_t army = 0; army < recorded.mStrVec.size(); ++army) {
        lua(gpg::STR_Printf("army %zu options", army).c_str(), recorded.mStrVec[army], built.mStrVec[army]);
        if (Sources(recorded.mArmyLaunchInfo[army].mUnitSources) != Sources(built.mArmyLaunchInfo[army].mUnitSources)) {
          differ(gpg::STR_Printf("army %zu unit sources differ", army).c_str());
        }
      }
    }

    [[nodiscard]] moho::SLaunchBuild Build(
      const SRebuiltConfig& config, const std::vector<SParticipant>& order, const moho::LaunchInfoNew& recorded,
      LuaPlus::LuaState* const state
    )
    {
      std::vector<moho::SLaunchClient> remotes;
      msvc8::string localName;
      for (const SParticipant& participant : order) {
        if (participant.uid == config.localUid) {
          localName = participant.name;
          continue;
        }
        moho::SLaunchClient client{};
        client.uid = participant.uid;
        client.name = participant.name;
        remotes.push_back(client);
      }
      moho::CLaunchRoster roster(config.localUid, localName, std::move(remotes));
      return moho::BuildLaunchInfo(config.dat, roster, recorded.mInitSeed, config.isMultiplayer, state);
    }
  } // namespace

  SLaunchCheckResult RunLaunchCheck(const std::string& replayPath, const std::string& expectPath)
  {
    SLaunchCheckResult result;
    msvc8::auto_ptr<moho::SWldSessionInfo> sessionInfo = moho::VCR_SetupReplaySession(replayPath.c_str());
    if (sessionInfo.get() == nullptr || sessionInfo->mLaunchInfo.get() == nullptr
        || sessionInfo->mLaunchInfo->GetNew() == nullptr) {
      result.error = "cannot read the replay's header";
      return result;
    }
    const moho::LaunchInfoNew& source = *sessionInfo->mLaunchInfo->GetNew();
    // The header compared with: the same replay's, or another client's of the same game (a
    // joiner builds its launch from tables it rebuilt from the host's config bytes, which is
    // what this check does with the host's header).
    msvc8::auto_ptr<moho::SWldSessionInfo> expectInfo;
    if (!expectPath.empty()) {
      expectInfo = moho::VCR_SetupReplaySession(expectPath.c_str());
      if (expectInfo.get() == nullptr || expectInfo->mLaunchInfo.get() == nullptr
          || expectInfo->mLaunchInfo->GetNew() == nullptr) {
        result.error = "cannot read the expected replay's header";
        return result;
      }
    }
    const moho::SWldSessionInfo& expectSession = expectInfo.get() != nullptr ? *expectInfo : *sessionInfo;
    const moho::LaunchInfoNew& recorded = *expectSession.mLaunchInfo->GetNew();
    LuaPlus::LuaState* const state = ReplayLuaState();
    try {
      // The lobby's order (command-source order, the order peers were assigned), then the
      // reverse, as another roster would list them: the launch must not depend on it.
      for (const bool reversed : {false, true}) {
        const SRebuiltConfig config = RebuildConfig(source, state);
        std::vector<SParticipant> order = config.participants;
        if (reversed) {
          std::reverse(order.begin(), order.end());
        }
        const moho::SLaunchBuild build = Build(config, order, recorded, state);
        if (build.failure != nullptr) {
          result.error = std::string("launch failed: '") + build.failure + "'";
          return result;
        }
        Compare(reversed ? "server order" : "lobby order", recorded, expectSession.mMapName, build, state, result);
      }
    } catch (const std::exception& error) {
      result.error = error.what();
      return result;
    }
    result.ran = true;
    result.report += gpg::STR_Printf(
      "LAUNCHCHECK armies=%zu sources=%zu differences=%d key-order-only=%d", recorded.mStrVec.size(),
      recorded.mCommandSources.mSrcs.size(), result.differences, result.orderOnly
    ).c_str();
    return result;
  }
} // namespace faf::headless
