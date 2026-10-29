#include "moho/net/LaunchInfoBuilder.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <utility>

#include "gpg/core/containers/String.h"
#include "lua/LuaTableIterator.h"
#include "moho/containers/BVIntSet.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SSTICommandSource.h"

// Engine addition: see LaunchInfoBuilder.h. The body is the launch-info half of
// `CLobby::LaunchGame` (0x007C38C0), in the binary's order. `CLaunchRoster` repeats the lobby's
// per-peer bookkeeping (`CLobby::AssignClientIndex` 0x007C4E80, `CLobby::AssignCommandSource`
// 0x007C4F60) on a list.

namespace moho
{
  namespace
  {
    // Client indices (0..255) and command source ids (0..254; 0xFF is "none") are single bytes
    // on the wire.
    constexpr std::int32_t kMaxLaunchClients = 0x100;
    constexpr std::size_t kMaxLaunchCommandSources = 0xFF;
    constexpr std::uint32_t kInvalidCommandSourceId = 0xFFu;

    struct LaunchPlayerOptionEntry
    {
      std::int32_t mSlotIndex{-1};
      LuaPlus::LuaObject mOptions;
    };
    static_assert(sizeof(LaunchPlayerOptionEntry) == 0x18, "LaunchPlayerOptionEntry size must be 0x18");

    [[nodiscard]] std::int32_t ParseOwnerId(const LuaPlus::LuaObject& ownerIdObject)
    {
      const char* const ownerIdStr = ownerIdObject.GetString();
      return std::atoi(ownerIdStr ? ownerIdStr : "");
    }

  } // namespace

  CLaunchRoster::CLaunchRoster(
    const std::int32_t localUid, msvc8::string localName, std::vector<SLaunchClient> remotes
  )
    : mLocalUid(localUid)
    , mLocalName(std::move(localName))
    , mRemotes(std::move(remotes))
  {}

  SLaunchClient* CLaunchRoster::Find(const std::int32_t uid) noexcept
  {
    for (SLaunchClient& client : mRemotes) {
      if (client.uid == uid) {
        return &client;
      }
    }
    return nullptr;
  }

  void CLaunchRoster::AssignClientIndex(
    std::int32_t& clientIndex, const std::int32_t ownerId, const char* const name, std::int32_t& localIndex
  )
  {
    // As `CLobby::AssignClientIndex` (0x007C4E80).
    if (ownerId == mLocalUid) {
      if (localIndex == -1) {
        localIndex = clientIndex++;
      }
      return;
    }
    SLaunchClient* client = Find(ownerId);
    if (client == nullptr) {
      SLaunchClient created{};
      created.uid = ownerId;
      created.name = msvc8::string(name != nullptr ? name : "");
      mRemotes.push_back(created);
      client = &mRemotes.back();
    }
    if (client->clientIndex == -1) {
      client->clientIndex = clientIndex++;
    }
  }

  std::uint32_t CLaunchRoster::AssignCommandSource(
    const std::int32_t timeouts, const std::int32_t ownerId, msvc8::vector<SSTICommandSource>& commandSources,
    std::uint32_t& localSource
  )
  {
    // As `CLobby::AssignCommandSource` (0x007C4F60).
    if (mLocalUid == ownerId) {
      if (localSource == kInvalidCommandSourceId) {
        localSource = static_cast<std::uint32_t>(commandSources.size());
        const SSTICommandSource entry{localSource, mLocalName.c_str(), timeouts};
        AppendSSTICommandSource(commandSources, entry);
      }
      return localSource;
    }
    SLaunchClient* const client = Find(ownerId);
    if (client == nullptr) {
      return kInvalidCommandSourceId; // cannot happen: AssignClientIndex added it
    }
    if (client->commandSource == kInvalidCommandSourceId) {
      client->commandSource = static_cast<std::uint32_t>(commandSources.size());
      const SSTICommandSource entry{client->commandSource, client->name.c_str(), timeouts};
      AppendSSTICommandSource(commandSources, entry);
    }
    return client->commandSource;
  }

  SLaunchBuild BuildLaunchInfo(
    const LuaPlus::LuaObject& dat, ILaunchParticipants& participants, const std::int32_t seed, const bool isMultiplayer,
    LuaPlus::LuaState* const state
  )
  {
    SLaunchBuild build{};
    LuaPlus::LuaObject gameOptions = dat["GameOptions"];

    const LuaPlus::LuaObject scenarioFileObject = gameOptions["ScenarioFile"];
    const char* const scenarioFileText = scenarioFileObject.GetString();
    const msvc8::string scenarioFile{scenarioFileText ? scenarioFileText : ""};

    LuaPlus::LuaObject scenarioInfo = WLD_LoadScenarioInfo(scenarioFile, state);
    if (scenarioInfo.IsNil()) {
      build.failure = "";
      return build;
    }
    scenarioInfo.SetObject("Options", gameOptions);

    boost::shared_ptr<LaunchInfoNew> launchInfo(new LaunchInfoNew());
    launchInfo->mGameMods = SCR_ToString(dat["GameMods"]);
    launchInfo->mScenarioInfo = SCR_ToString(scenarioInfo);
    launchInfo->mInitSeed = seed;

    const LuaPlus::LuaObject cheatsEnabled = gameOptions["CheatsEnabled"];
    if (cheatsEnabled && cheatsEnabled.IsString()) {
      const char* const enabledStr = cheatsEnabled.GetString();
      if (enabledStr != nullptr && std::strcmp(enabledStr, "true") == 0) {
        launchInfo->mCheatsEnabled = true;
      }
    }

    LuaPlus::LuaObject teamsConfig = scenarioInfo.Lookup("Configurations.standard.teams");
    if (teamsConfig.IsNil()) {
      build.failure = "NoConfig";
      return build;
    }

    msvc8::vector<msvc8::string> ffaArmies;
    {
      LuaPlus::LuaTableIterator teamIt(&teamsConfig, 1);
      while (!teamIt.m_isDone) {
        LuaPlus::LuaObject teamObject = teamIt.GetValue();
        const LuaPlus::LuaObject teamNameObject = teamObject["name"];
        const char* const teamName = teamNameObject.GetString();
        if (teamName != nullptr && _stricmp(teamName, "FFA") == 0) {
          LuaPlus::LuaObject teamArmies = teamObject["armies"];
          LuaPlus::LuaTableIterator armyIt(&teamArmies, 1);
          while (!armyIt.m_isDone) {
            LuaPlus::LuaObject armyNameObject = armyIt.GetValue();
            const char* const armyName = armyNameObject.GetString();
            if (armyName != nullptr) {
              ffaArmies.push_back(msvc8::string(armyName));
            }
            armyIt.Next();
          }
          break;
        }
        teamIt.Next();
      }
    }

    msvc8::vector<LaunchPlayerOptionEntry> playerOptions;
    LuaPlus::LuaObject playerOptionsTable = dat["PlayerOptions"];
    if (!playerOptionsTable.IsNil()) {
      LuaPlus::LuaTableIterator optionIt(&playerOptionsTable, 1);
      while (!optionIt.m_isDone) {
        LuaPlus::LuaObject keyObject = optionIt.GetKey();
        LuaPlus::LuaObject optionObject = optionIt.GetValue();
        const std::int32_t slotIndex = keyObject.GetInteger() - 1;
        if (slotIndex >= 0 && static_cast<std::size_t>(slotIndex) < ffaArmies.size()) {
          optionObject.SetString("ArmyName", ffaArmies[static_cast<std::size_t>(slotIndex)].c_str());
        }

        LaunchPlayerOptionEntry entry{};
        entry.mSlotIndex = slotIndex;
        entry.mOptions = optionObject;
        playerOptions.push_back(entry);
        optionIt.Next();
      }
    }

    if (playerOptions.size() > ffaArmies.size()) {
      build.failure = "StartSpots";
      return build;
    }

    if (!playerOptions.empty()) {
      std::sort(
        playerOptions.begin(), playerOptions.end(),
        [](const LaunchPlayerOptionEntry& lhs, const LaunchPlayerOptionEntry& rhs) { return lhs.mSlotIndex < rhs.mSlotIndex; }
      );
    }

    std::uint32_t localSourceId = kInvalidCommandSourceId;
    launchInfo->mCommandSources.mOriginalSource = -1;

    std::int32_t timeouts = -1;
    if (isMultiplayer) {
      const LuaPlus::LuaObject timeoutObj = gameOptions["Timeouts"];
      if (timeoutObj.IsString()) {
        const char* const timeoutStr = timeoutObj.GetString();
        timeouts = std::atoi(timeoutStr ? timeoutStr : "");
      }
    }

    if (playerOptions.empty()) {
      LuaPlus::LuaObject defaultOptions = RULE_GetDefaultPlayerOptions(state);
      defaultOptions.SetString("PlayerName", "default");
      defaultOptions.SetString("ArmyName", "default");
      defaultOptions.SetBoolean("Human", false);

      LaunchPlayerOptionEntry entry{};
      entry.mSlotIndex = 0;
      entry.mOptions = defaultOptions;
      playerOptions.push_back(entry);
    }

    LuaPlus::LuaObject civilianAlliance = gameOptions["CivilianAlliance"];
    if (civilianAlliance && civilianAlliance.IsString()) {
      const char* const civilianText = civilianAlliance.GetString();
      if (civilianText != nullptr && _stricmp(civilianText, "none") != 0) {
        LuaPlus::LuaObject extraArmiesObject = scenarioInfo.Lookup("Configurations.standard.customprops.ExtraArmies");
        if (extraArmiesObject.IsString()) {
          const char* const extraArmiesText = extraArmiesObject.GetString();
          msvc8::vector<msvc8::string> extraArmies;
          gpg::STR_GetTokens(extraArmiesText ? extraArmiesText : "", " ", extraArmies);
          for (const msvc8::string& extraArmyName : extraArmies) {
            LuaPlus::LuaObject civilianOptions = RULE_GetDefaultPlayerOptions(state);
            civilianOptions.SetString("PlayerName", "civilian");
            civilianOptions.SetString("ArmyName", extraArmyName.c_str());
            civilianOptions.SetBoolean("Civilian", true);
            civilianOptions.SetBoolean("Human", false);

            LaunchPlayerOptionEntry entry{};
            entry.mSlotIndex = -1;
            entry.mOptions = civilianOptions;
            playerOptions.push_back(entry);
          }
        }
      }
    }

    const std::int32_t localUid = participants.LocalUid();
    participants.BeginAssignments();
    std::int32_t clientIndex = 0;
    std::int32_t localClientIndex = -1;
    for (std::size_t playerIndex = 0; playerIndex < playerOptions.size(); ++playerIndex) {
      const LuaPlus::LuaObject& option = playerOptions[playerIndex].mOptions;
      BVIntSet commandSourceSet{};

      const LuaPlus::LuaObject isHumanObject = option["Human"];
      if (isHumanObject.GetBoolean()) {
        const LuaPlus::LuaObject ownerIdObject = option["OwnerID"];
        const std::int32_t ownerId = ParseOwnerId(ownerIdObject);
        if (ownerId == localUid) {
          launchInfo->mCommandSources.mOriginalSource = static_cast<std::int32_t>(playerIndex);
        }

        const LuaPlus::LuaObject playerNameObject = option["PlayerName"];
        const char* const optionPlayerName = playerNameObject.GetString();
        participants.AssignClientIndex(clientIndex, ownerId, optionPlayerName ? optionPlayerName : "", localClientIndex);

        const std::uint32_t sourceId =
          participants.AssignCommandSource(timeouts, ownerId, launchInfo->mCommandSources.mSrcs, localSourceId);
        if (sourceId != kInvalidCommandSourceId) {
          (void)commandSourceSet.Add(sourceId);
        }
      }

      launchInfo->mStrVec.push_back(SCR_ToString(option));
      ArmyLaunchInfo armySourceInfo{};
      armySourceInfo.mUnitSources = commandSourceSet;
      launchInfo->mArmyLaunchInfo.push_back(armySourceInfo);
    }

    LuaPlus::LuaObject observersTable = dat["Observers"];
    LuaPlus::LuaTableIterator observerIt(&observersTable, 1);
    while (!observerIt.m_isDone) {
      LuaPlus::LuaObject observer = observerIt.GetValue();
      const std::int32_t ownerId = ParseOwnerId(observer["OwnerID"]);
      const LuaPlus::LuaObject observerNameObject = observer["PlayerName"];
      const char* const observerName = observerNameObject.GetString();
      participants.AssignClientIndex(clientIndex, ownerId, observerName ? observerName : "", localClientIndex);

      const std::int32_t observerTimeouts = isMultiplayer ? 0 : -1;
      (void)participants.AssignCommandSource(observerTimeouts, ownerId, launchInfo->mCommandSources.mSrcs, localSourceId);
      observerIt.Next();
    }

    // Engine addition (as in the lobby): without the local participant the local client index
    // stays -1, which the client manager uses as an array index; client indices and command
    // sources each travel as one byte (0xFF being "no source").
    if (localClientIndex == -1) {
      throw std::runtime_error("LaunchGame: the local player is neither a player nor an observer.");
    }
    if (clientIndex > kMaxLaunchClients || launchInfo->mCommandSources.mSrcs.size() > kMaxLaunchCommandSources) {
      throw std::runtime_error("LaunchGame: too many players and observers.");
    }

    const LuaPlus::LuaObject mapObject = scenarioInfo["map"];
    const char* const mapName = mapObject.GetString();
    build.mapName = mapName ? mapName : "";
    build.launchInfo = launchInfo;
    build.clientCount = clientIndex;
    build.localClientIndex = localClientIndex;
    build.localSourceId = localSourceId;
    return build;
  }
} // namespace moho
