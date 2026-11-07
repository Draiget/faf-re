// Engine addition (dedicated-server plan WPL.4, WPR.11): VCR_SetupReplaySession,
// which reads a replay file into a replay session's launch info, moved unchanged
// out of moho/misc/SessionStartup.cpp (the front end's session launch, user side):
// headless and the game server set up replay sessions without a user side.
#include "moho/misc/SessionStartup.h"

#include <Windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <memory>
#include <stdexcept>
#include <string>
#include <typeinfo>

#include "boost/shared_ptr.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/lua/SCR_String.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/misc/StringUtils.h"
#include "moho/net/CClientManagerImpl.h"
#include "moho/net/CReplayClient.h"
#include "moho/net/CMessage.h"
#include "moho/net/CMessageStream.h"
#include "moho/net/Common.h"
#include "moho/net/ECmdStreamOp.h"
#include "moho/net/INetTCPSocket.h"
#include "moho/sim/FafGameVersion.h"
#include "moho/sim/WldSessionInfo.h"

// Engine addition: helpers shared with the file these functions came from.
namespace
{
  using moho::EGpgNetOpenMode;

  /**
   * Address: 0x00875690 (FUN_00875690, func_OpenGPGNet)
   *
   * What it does:
   * Opens one local file stream for replay/network URI fallback according to
   * recovered GPGNet mode semantics.
   */
  [[nodiscard]] std::unique_ptr<gpg::Stream> OpenGPGNet(const gpg::StrArg filename, const EGpgNetOpenMode mode)
  {
    switch (mode) {
    case EGpgNetOpenMode::Read: {
      fa::auto_ptr<gpg::Stream> openedStream = moho::DISK_OpenFileRead(filename);
      return std::unique_ptr<gpg::Stream>(openedStream.release());
    }
    case EGpgNetOpenMode::Write: {
      fa::auto_ptr<gpg::Stream> openedStream = moho::DISK_OpenFileWrite(filename);
      return std::unique_ptr<gpg::Stream>(openedStream.release());
    }
    default:
      throw std::runtime_error("unexpected mode in OpenGPGNet.");
    }
  }
  /**
   * Address: 0x008754D0 (FUN_008754D0, sub_8754D0)
   *
   * What it does:
   * Connects to GPGNet host endpoint, emits one mode byte plus replay request
   * path payload, and returns the live TCP stream lane.
   */
  [[nodiscard]]
  std::unique_ptr<gpg::Stream> OpenGPGNetSocket(
    const gpg::StrArg host, const fa::string& requestPath, const EGpgNetOpenMode mode
  )
  {
    constexpr u_short kDefaultGpgNetPort = 15000;

    u_long address = 0;
    u_short port = 0;
    if (!moho::NET_GetAddrInfo(host, kDefaultGpgNetPort, true, address, port)) {
      gpg::Logf("NET_GetAddrInfo(%s) failed: %s", host, moho::NET_GetWinsockErrorString());
      return {};
    }

    moho::INetTCPSocket* socket = moho::NET_TCPConnect(address, port);
    if (socket == nullptr) {
      const fa::string hostName = moho::NET_GetHostName(address);
      gpg::Logf("NET_TCPConnect(%s:%d) failed.", hostName.c_str(), static_cast<int>(port));
      return {};
    }

    std::unique_ptr<gpg::Stream> socketStream(socket);

    const char modeByte = [&]() -> char {
      switch (mode) {
      case EGpgNetOpenMode::Read:
        return 'G';
      case EGpgNetOpenMode::Write:
        return 'P';
      default:
        throw std::runtime_error("unexpected mode in OpenGPGNet.");
      }
    }();

    socketStream->Write(&modeByte, 1u);
    socketStream->Write(requestPath);
    socketStream->VirtFlush();
    return socketStream;
  }

  /**
   * Address: 0x00875770 (FUN_00875770, func_GPGNetOpenURI)
   *
   * What it does:
   * Resolves `gpgnet://` URI streams or falls back to local file open policy
   * for plain/drive-letter paths.
   */
  [[nodiscard]]
  std::unique_ptr<gpg::Stream> OpenGPGNetURI(const gpg::StrArg uri, const EGpgNetOpenMode mode)
  {
    fa::string scheme{};
    fa::string authority{};
    fa::string uriPath{};
    fa::string uriQuery{};
    fa::string uriFragment{};
    if (!moho::URI_Split(uri, &scheme, &authority, &uriPath, &uriQuery, &uriFragment)) {
      return OpenGPGNet(uri, mode);
    }

    if (gpg::STR_CompareNoCase(scheme.c_str(), "gpgnet:") == 0 && gpg::STR_StartsWith(authority.c_str(), "//")) {
      const fa::string requestPath = uriPath + uriQuery + uriFragment;
      return OpenGPGNetSocket(authority.c_str() + 2, requestPath, mode);
    }

    if (scheme.size() == 2u) {
      return OpenGPGNet(uri, mode);
    }

    return {};
  }

  /**
   * Address: 0x007CB8E0 (FUN_007CB8E0, func_CopyLaunchInfoBasePtr)
   *
   * What it does:
   * Copies one `shared_ptr<LaunchInfoNew>` lane into a
   * `shared_ptr<LaunchInfoBase>` output slot through swap-based temporary
   * ownership transfer.
   */
  boost::shared_ptr<moho::LaunchInfoBase>* CopyLaunchInfoBasePtr(
    boost::shared_ptr<moho::LaunchInfoBase>* const outBase,
    const boost::shared_ptr<moho::LaunchInfoNew>& source
  )
  {
    if (outBase == nullptr) {
      return nullptr;
    }

    boost::shared_ptr<moho::LaunchInfoBase> temp(source);
    temp.swap(*outBase);
    return outBase;
  }
  constexpr std::uint8_t kInvalidSourceIndex = 255u;
} // namespace

void moho::VCR_WriteReplayHeader(gpg::Stream& stream, const SWldSessionInfo& sessionInfo)
{
  constexpr char kReplayFormatBanner[] = "Replay v1.9\r\n";
  constexpr std::size_t kReplayFormatBannerBytes = sizeof(kReplayFormatBanner) - 1u;
  constexpr double kReplayEngineVersion = 1.5;
  constexpr std::uint8_t kReplayUnitSourceListEnd = 0xFFu;

  const LaunchInfoNew* const launchInfo = sessionInfo.mLaunchInfo->GetNew();
// FAF addition: the build is the game version this session runs as (`FAF_BeginSession` ran
  // before the sink was opened), so a replay always names the patches it was recorded with.
  stream.Write(gpg::STR_Printf("Supreme Commander v%1.2f.%4i", kReplayEngineVersion, FAF_GetSessionGameVersion()));
  stream.Write("\r\n");
  stream.Write(kReplayFormatBanner, kReplayFormatBannerBytes);
  stream.Write(sessionInfo.mMapName);
  stream.Write("\r\n");

  const std::int32_t gameModsBytes = static_cast<std::int32_t>(launchInfo->mGameMods.size());
  stream.Write(gameModsBytes);
  stream.Write(launchInfo->mGameMods.c_str(), static_cast<std::size_t>(gameModsBytes));

  const std::int32_t scenarioInfoBytes = static_cast<std::int32_t>(launchInfo->mScenarioInfo.size());
  stream.Write(scenarioInfoBytes);
  stream.Write(launchInfo->mScenarioInfo.c_str(), static_cast<std::size_t>(scenarioInfoBytes));

  const fa::vector<SSTICommandSource>& commandSources = launchInfo->mCommandSources.mSrcs;
  const auto commandSourceCount = static_cast<std::uint8_t>(commandSources.size());
  stream.Write(commandSourceCount);
  for (const SSTICommandSource& commandSource : commandSources) {
    // Names go out with their terminator - the reader scans for it.
    stream.Write(commandSource.mName.c_str(), commandSource.mName.size() + 1u);
    stream.Write(commandSource.mTimeouts);
  }

  stream.Write(static_cast<std::uint8_t>(launchInfo->mCheatsEnabled ? 1 : 0));

  const fa::vector<fa::string>& armyNames = launchInfo->mStrVec;
  const auto armyCount = static_cast<std::uint8_t>(armyNames.size());
  stream.Write(armyCount);
  for (std::size_t armyIndex = 0; armyIndex < armyNames.size(); ++armyIndex) {
    const fa::string& armyName = armyNames[armyIndex];
    const std::int32_t armyNameBytes = static_cast<std::int32_t>(armyName.size());
    stream.Write(armyNameBytes);
    stream.Write(armyName.c_str(), static_cast<std::size_t>(armyNameBytes));

    const BVIntSet& unitSources = launchInfo->mArmyLaunchInfo[armyIndex].mUnitSources;
    const unsigned int endOfSet = unitSources.Max();
    for (unsigned int source = unitSources.GetNext(~0u); source != endOfSet;
         source = unitSources.GetNext(source)) {
      stream.Write(static_cast<std::uint8_t>(source));
    }
    stream.Write(kReplayUnitSourceListEnd);
  }

  stream.Write(launchInfo->mInitSeed);
}

std::unique_ptr<gpg::Stream> moho::VCR_OpenGPGNetURI(const gpg::StrArg uri, const EGpgNetOpenMode mode)
{
  return OpenGPGNetURI(uri, mode);
}


namespace moho
{
  /**
   * Engine addition, not in the binary: whether the serialized Lua values a
   * replay or saved game carries (game mods, scenario, army setups) decode.
   * The session decodes them again with the same SCR_FromString when it
   * starts, on the main, loader and sim threads, where a failure is not
   * caught and ends the process. Checking them here lets the file be refused
   * while its reader can still say so.
   */
  bool LaunchInfoStringsDecode(
    const LaunchInfoBase& launchInfo, const fa::vector<fa::string>& armySetups
  )
  {
    LuaPlus::LuaState scratch(LuaPlus::LuaState::LIB_NONE);
    // Each of them is a table where it is used (Sim::Setup writes into the
    // army setups and the scenario), so anything else is refused too.
    const auto decodesTo = [&scratch](const fa::string& text, const bool nilAllowed) {
      try {
        LuaPlus::LuaObject value;
        (void)SCR_FromString(&value, text, &scratch);
        return value.IsTable() || (nilAllowed && value.IsNil());
      } catch (const std::exception&) {
        return false;
      }
    };

    // An empty mods string means no mods (RRuleGameRules skips the decode),
    // and so does an encoded nil (a launch without a mods table).
    if (!launchInfo.mGameMods.empty() && !decodesTo(launchInfo.mGameMods, true)) {
      return false;
    }
    if (!decodesTo(launchInfo.mScenarioInfo, false)) {
      return false;
    }
    for (const fa::string& armySetup : armySetups) {
      if (!decodesTo(armySetup, false)) {
        return false;
      }
    }
    return true;
  }

  ReplayLocalClientNameHook sReplayLocalClientName = nullptr;

  namespace
  {
    /// The local client's name: localised by the user side when there is one.
    [[nodiscard]] fa::string ReplayLocalClientName()
    {
      if (sReplayLocalClientName != nullptr) {
        return sReplayLocalClientName();
      }
      fa::string name;
      name.assign_owned("Local");
      return name;
    }
  } // namespace

  bool gVcrScanReplayLength = false;
  std::int32_t gVcrReplayBeats = 0;

  std::int32_t VCR_ScanReplayBeats(gpg::Stream& stream)
  {
    std::int32_t beats = 0;
    try {
      const std::uint64_t start = stream.VirtTell(gpg::Stream::ModeReceive);
      CMessage message;
      while (message.Read(&stream)) {
        if (message.GetType().raw() == static_cast<std::uint8_t>(ECmdStreamOp::CMDST_Advance)
            && message.GetMessageSize() >= static_cast<int>(sizeof(std::int32_t))) {
          CMessageStream input(message, CMessageStream::Access::kReadOnly);
          gpg::BinaryReader reader(&input);
          std::int32_t delta = 0;
          reader.ReadExact(delta);
          beats += std::max(delta, 0);
        }
        message.Clear();
      }
      (void)stream.Seek(gpg::Stream::OriginBegin, static_cast<std::int64_t>(start));
    } catch (const std::exception& error) {
      gpg::Warnf("Couldn't read the length of a replay: %s", error.what());
      return 0;
    }
    return beats;
  }

  /**
   * Address: 0x008765E0 (FUN_008765E0)
   * Mangled:
   * ?VCR_SetupReplaySession@Moho@@YA?AV?$auto_ptr@USWldSessionInfo@Moho@@@std@@VStrArg@gpg@@@Z
   *
   * What it does:
   * Loads replay file payload, reconstructs `LaunchInfoNew`, and creates
   * one replay `SWldSessionInfo` bootstrap object. A header naming a FAF game
   * version outside `kFafGameVersionOldestSupported..kFafGameVersionLatest` is
   * refused, unless `/noversioncheck` is on the command line; the recorded
   * version selects the engine patches the replay plays with.
   *
   * Engine addition: a refusal says why through `failureReason`.
   */
  fa::auto_ptr<SWldSessionInfo>
  VCR_SetupReplaySession(
    const gpg::StrArg filename,
    fa::string* const failureReason,
    std::unique_ptr<gpg::Stream>* const commandStream,
    const int skipBeats
  )
  {
    const auto refuse = [failureReason](const fa::string& reason) {
      if (failureReason != nullptr) {
        *failureReason = reason;
      }
      return fa::auto_ptr<SWldSessionInfo>();
    };

    if (filename == nullptr || filename[0] == '\0') {
      return refuse("No replay file was given.");
    }

    std::unique_ptr<gpg::Stream> replayStream{};
    try {
      replayStream = OpenGPGNetURI(filename, EGpgNetOpenMode::Read);
    } catch (...) {
      return refuse("The file could not be opened.");
    }

    if (replayStream == nullptr) {
      return refuse("The file could not be opened.");
    }

    return VCR_SetupReplaySessionFromStream(std::move(replayStream), filename, failureReason, commandStream, skipBeats);
  }

  /**
   * Engine addition (issue #275): `VCR_SetupReplaySession` from a stream already
   * open, the body of the function at 0x008765E0 from its header read on.
   */
  fa::auto_ptr<SWldSessionInfo> VCR_SetupReplaySessionFromStream(
    std::unique_ptr<gpg::Stream> replayStream,
    const gpg::StrArg filename,
    fa::string* const failureReason,
    std::unique_ptr<gpg::Stream>* const commandStream,
    const int skipBeats
  )
  {
    const auto refuse = [failureReason](const fa::string& reason) {
      if (failureReason != nullptr) {
        *failureReason = reason;
      }
      return fa::auto_ptr<SWldSessionInfo>();
    };

    // Engine addition, not in the binary: the header is read under a handler.
    // A replay is a file anyone can hand out, and the binary let a short or
    // damaged header (PrematureEOF, InvalidFormat) end the process; such a
    // replay is now refused like one of the wrong version.
    boost::shared_ptr<LaunchInfoNew> launchInfo;
    BVIntSet replayCommandSources{};
    fa::string replayMapName{};
    try {
      gpg::BinaryReader replayReader(replayStream.get());
      fa::string replayVersion{};
      replayReader.ReadString(&replayVersion);

      // The binary accepts only its own build ("Supreme Commander v1.50.3835"). This engine
      // plays every FAF game version it models, each with that version's engine patches, so a
      // replay is accepted when its build lies in that range.
      int recordedGameVersion = FAF_ParseReplayGameVersion(replayVersion.view());
      if (recordedGameVersion < kFafGameVersionOldestSupported || recordedGameVersion > kFafGameVersionLatest) {
        // FAF addition, not in the shipped binary: /noversioncheck plays a replay
        // whose header names another engine version instead of refusing it, with
        // the patches of the nearest version this engine models.
        if (!CFG_GetArgOption("/noversioncheck", 0, nullptr)) {
          return refuse(gpg::STR_Printf(
            "It was recorded by \"%s\"; this game plays replays of FAF game versions %d to %d.",
            replayVersion.c_str(),
            kFafGameVersionOldestSupported,
            kFafGameVersionLatest
          ));
        }
        const int playedGameVersion =
          (recordedGameVersion != 0 && recordedGameVersion < kFafGameVersionOldestSupported)
            ? kFafGameVersionOldestSupported
            : kFafGameVersionLatest;
        gpg::Warnf(
          "Replay %s was recorded by \"%s\", this engine plays FAF game versions %d..%d; playing it as %d anyway "
          "(/noversioncheck).",
          filename,
          replayVersion.c_str(),
          kFafGameVersionOldestSupported,
          kFafGameVersionLatest,
          playedGameVersion
        );
        recordedGameVersion = playedGameVersion;
      }
      FAF_SetReplayGameVersion(recordedGameVersion);

      fa::string ignoredString{};
      replayReader.ReadString(&ignoredString);

      std::array<char, 14> replaySignature{};
      replayReader.Read(replaySignature.data(), 13);

      replayReader.ReadString(&replayMapName);
      replayReader.ReadString(&ignoredString);

      if (std::strcmp(replaySignature.data(), "Replay v1.9\r\n") != 0) {
        return refuse("It is not a Supreme Commander: Forged Alliance replay.");
      }

      launchInfo.reset(new LaunchInfoNew());
      replayReader.ReadLengthPrefixedString(&launchInfo->mGameMods);
      replayReader.ReadLengthPrefixedString(&launchInfo->mScenarioInfo);

      std::uint8_t commandSourceCount = 0;
      replayReader.ReadExact(commandSourceCount);

      launchInfo->mCommandSources.mSrcs.clear();
      launchInfo->mCommandSources.mSrcs.reserve(commandSourceCount);

      for (std::uint32_t sourceIndex = 0; sourceIndex < commandSourceCount; ++sourceIndex) {
        SSTICommandSource source{};
        source.mIndex = sourceIndex;
        replayReader.ReadString(&source.mName);
        replayReader.ReadExact(source.mTimeouts);
        moho::AppendSSTICommandSource(launchInfo->mCommandSources.mSrcs, source);
        (void)replayCommandSources.Add(sourceIndex);
      }

      std::uint8_t cheatsEnabled = 0;
      replayReader.ReadExact(cheatsEnabled);
      launchInfo->mCheatsEnabled = cheatsEnabled != 0;

      std::uint8_t armyCount = 0;
      replayReader.ReadExact(armyCount);

      launchInfo->mArmyLaunchInfo.clear();
      launchInfo->mArmyLaunchInfo.resize(armyCount, moho::ArmyLaunchInfo{});
      launchInfo->mStrVec.clear();
      launchInfo->mStrVec.reserve(armyCount);

      for (std::uint32_t armyIndex = 0; armyIndex < armyCount; ++armyIndex) {
        fa::string armyLabel{};
        replayReader.ReadLengthPrefixedString(&armyLabel);
        launchInfo->mStrVec.push_back(armyLabel);

        while (true) {
          std::uint8_t sourceIndex = kInvalidSourceIndex;
          replayReader.ReadExact(sourceIndex);
          if (sourceIndex == kInvalidSourceIndex) {
            break;
          }
          (void)launchInfo->mArmyLaunchInfo[armyIndex].mUnitSources.Add(sourceIndex);
        }
      }

      replayReader.ReadExact(launchInfo->mInitSeed);
      launchInfo->mCommandSources.mOriginalSource = -1;

      // Engine addition: the game settings in the header are decoded again when
      // the session starts, where a malformed one is not caught.
      if (!LaunchInfoStringsDecode(*launchInfo, launchInfo->mStrVec)) {
        gpg::Warnf("Unable to read the game settings in replay %s.", filename);
        return refuse("The game settings stored in the file are damaged.");
      }
    } catch (const gpg::BinaryReader::PrematureEOF&) {
      gpg::Warnf("Unable to read the header of replay %s: it ends early.", filename);
      return refuse("The file ends early: it is incomplete or damaged.");
    } catch (const std::exception& error) {
      gpg::Warnf("Unable to read the header of replay %s: %s", filename, error.what());
      return refuse(gpg::STR_Printf("The file is damaged (%s).", error.what()));
    }

    if (gVcrScanReplayLength && replayStream != nullptr) {
      gVcrReplayBeats = VCR_ScanReplayBeats(*replayStream);
    }

    fa::auto_ptr<SWldSessionInfo> sessionInfo(new SWldSessionInfo());
    sessionInfo->mMapName = replayMapName;
    (void)CopyLaunchInfoBasePtr(&sessionInfo->mLaunchInfo, launchInfo);
    sessionInfo->mIsBeingRecorded = false;
    sessionInfo->mIsReplay = true;
    sessionInfo->mIsMultiplayer = false;
    sessionInfo->mSourceId = kInvalidSourceIndex;
    if (commandStream != nullptr) {
      *commandStream = std::move(replayStream);
      return sessionInfo;
    }
    sessionInfo->mClientManager = CLIENT_CreateClientManager(2u, nullptr, 0, true);

    if (sessionInfo->mClientManager != nullptr) {
      gpg::Stream* replayStreamOwnership = replayStream.release();
      IClient* const replayClient =
        sessionInfo->mClientManager->CreateReplayClient(&replayStreamOwnership, &replayCommandSources);
      if (skipBeats > 0) {
        static_cast<CReplayClient*>(replayClient)->SkipBeats(skipBeats); // engine addition (replay keyframes)
      }
      if (replayStreamOwnership != nullptr) {
        delete replayStreamOwnership;
      }

      const fa::string localName = ReplayLocalClientName();
      sessionInfo->mClientManager->CreateLocalClient(localName.c_str(), 1, 1, kInvalidSourceIndex);
    }

    return sessionInfo;
  }

} // namespace moho
