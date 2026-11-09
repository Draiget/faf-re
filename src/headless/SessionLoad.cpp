#include "headless/SessionLoad.h"

#include <Windows.h>

#include <algorithm>

#include "gpg/core/streams/BinaryReader.h"
#include "lua/LuaObject.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/net/CClientManagerImpl.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/CWldSessionLoaderImpl.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/WldSessionInfo.h"

// Engine addition, server mode: see SessionLoad.h.

namespace faf::headless
{
  bool LoadSessionScenario(moho::SWldSessionInfo& sessionInfo, moho::SWldGameData& gameData, std::string& error)
  {
    moho::CWldSessionLoaderImpl* const loader = moho::GetWldSessionLoader();
    moho::LaunchInfoBase* const launchInfo = sessionInfo.mLaunchInfo.get();
    if (loader == nullptr || launchInfo == nullptr) {
      error = "no session loader or launch info";
      return false;
    }

    (void)loader->GetScenarioInfo(sessionInfo.mMapName.raw_data_unsafe(), &launchInfo->mGameMods, true);
    while (true) {
      // `WLD_DoLoading` beats the client manager every frame while the map loads.
      if (sessionInfo.mClientManager != nullptr) {
        sessionInfo.mClientManager->DoBeat();
      }
      loader->Update();
      if (loader->IsLoaded()) {
        break;
      }
      ::Sleep(5);
    }

    (void)loader->LoadGameData(&gameData);
    if (gameData.mGameRules == nullptr || gameData.mWldMap == nullptr || gameData.mState == nullptr) {
      error = "map " + std::string(sessionInfo.mMapName.c_str()) + " failed to load";
      return false;
    }
    return true;
  }

  moho::STIMap* CompleteSessionLaunchInfo(moho::SWldSessionInfo& sessionInfo, moho::RRuleGameRules& rules, moho::CWldMap& map, LuaPlus::LuaState& sessionState)
  {
    moho::LaunchInfoBase* const launchInfo = sessionInfo.mLaunchInfo.get();
    moho::STIMap* const launchMap = new moho::STIMap(map.mTerrainRes->mMap);
    launchInfo->mGameRules = &rules;
    if (launchInfo->mMap != nullptr && launchInfo->mMap != launchMap) {
      delete launchInfo->mMap;
    }
    launchInfo->mMap = launchMap;
    launchInfo->mLanguage.assign_owned(sessionState.GetGlobal("__language").ToString());
    if (moho::LaunchInfoNew* const newLaunchInfo = launchInfo->GetNew(); newLaunchInfo != nullptr) {
      newLaunchInfo->mProps = map.mProps;
    }
    return launchMap;
  }

  namespace
  {
    [[nodiscard]] std::string ReadSyncBytes(moho::SSyncData& packet)
    {
      std::string bytes;
      char buffer[4096];
      for (;;) {
        const std::size_t read = packet.mStream->Read(buffer, sizeof(buffer));
        if (read == 0u) {
          break;
        }
        bytes.append(buffer, read);
      }
      (void)packet.mStream->VirtSeek(gpg::Stream::ModeReceive, gpg::Stream::OriginBegin, 0);
      return bytes;
    }
  } // namespace

  bool SyncBytesContain(moho::SSyncData& packet, const std::string_view text)
  {
    return ReadSyncBytes(packet).find(text) != std::string::npos;
  }

  bool ReadSyncNaming(moho::SSyncData& packet, LuaPlus::LuaState* const state, const std::initializer_list<std::string_view> names, LuaPlus::LuaObject& sync)
  {
    if (packet.mStream == nullptr || state == nullptr) {
      return false;
    }
    const std::string bytes = ReadSyncBytes(packet);
    const bool named = std::any_of(names.begin(), names.end(), [&](const std::string_view name) { return bytes.find(name) != std::string::npos; });
    if (!named) {
      return false;
    }
    gpg::BinaryReader syncReader(packet.mStream);
    sync.SCR_FromByteStream(sync, state, &syncReader);
    return !sync.IsNil();
  }

  bool SyncSaysGameEnded(moho::SSyncData& packet, LuaPlus::LuaState* const state)
  {
    LuaPlus::LuaObject currentSync;
    if (!ReadSyncNaming(packet, state, {"GameEnded"}, currentSync)) {
      return false;
    }
    const LuaPlus::LuaObject gameEnded = currentSync["GameEnded"];
    return !gameEnded.IsNil() && (!gameEnded.IsBoolean() || gameEnded.GetBoolean());
  }
} // namespace faf::headless
