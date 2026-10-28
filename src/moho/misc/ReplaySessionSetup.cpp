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
#include <memory>
#include <stdexcept>
#include <string>
#include <typeinfo>

#include "boost/shared_ptr.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/utils/Logging.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/misc/StringUtils.h"
#include "moho/net/CClientManagerImpl.h"
#include "moho/net/Common.h"
#include "moho/net/INetTCPSocket.h"
#include "moho/sim/FafGameVersion.h"
#include "moho/sim/WldSessionInfo.h"

// Engine addition: helpers shared with the file these functions came from.
namespace
{
  enum class EGpgNetOpenMode : int
  {
    Read = 1,
    Write = 2,
  };

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
      msvc8::auto_ptr<gpg::Stream> openedStream = moho::DISK_OpenFileRead(filename);
      return std::unique_ptr<gpg::Stream>(openedStream.release());
    }
    case EGpgNetOpenMode::Write: {
      msvc8::auto_ptr<gpg::Stream> openedStream = moho::DISK_OpenFileWrite(filename);
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
    const gpg::StrArg host, const msvc8::string& requestPath, const EGpgNetOpenMode mode
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
      const msvc8::string hostName = moho::NET_GetHostName(address);
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
    msvc8::string scheme{};
    msvc8::string authority{};
    msvc8::string uriPath{};
    msvc8::string uriQuery{};
    msvc8::string uriFragment{};
    if (!moho::URI_Split(uri, &scheme, &authority, &uriPath, &uriQuery, &uriFragment)) {
      return OpenGPGNet(uri, mode);
    }

    if (gpg::STR_CompareNoCase(scheme.c_str(), "gpgnet:") == 0 && gpg::STR_StartsWith(authority.c_str(), "//")) {
      const msvc8::string requestPath = uriPath + uriQuery + uriFragment;
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


namespace moho
{
  ReplayLocalClientNameHook sReplayLocalClientName = nullptr;

  namespace
  {
    /// The local client's name: localised by the user side when there is one.
    [[nodiscard]] msvc8::string ReplayLocalClientName()
    {
      if (sReplayLocalClientName != nullptr) {
        return sReplayLocalClientName();
      }
      msvc8::string name;
      name.assign_owned("Local");
      return name;
    }
  } // namespace

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
  msvc8::auto_ptr<SWldSessionInfo>
  VCR_SetupReplaySession(const gpg::StrArg filename, msvc8::string* const failureReason)
  {
    const auto refuse = [failureReason](const msvc8::string& reason) {
      if (failureReason != nullptr) {
        *failureReason = reason;
      }
      return msvc8::auto_ptr<SWldSessionInfo>();
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

    // Engine addition, not in the binary: the header is read under a handler.
    // A replay is a file anyone can hand out, and the binary let a short or
    // damaged header (PrematureEOF, InvalidFormat) end the process; such a
    // replay is now refused like one of the wrong version.
    boost::shared_ptr<LaunchInfoNew> launchInfo;
    BVIntSet replayCommandSources{};
    msvc8::string replayMapName{};
    try {
      gpg::BinaryReader replayReader(replayStream.get());
      msvc8::string replayVersion{};
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

      msvc8::string ignoredString{};
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
        msvc8::string armyLabel{};
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

    msvc8::auto_ptr<SWldSessionInfo> sessionInfo(new SWldSessionInfo());
    sessionInfo->mMapName = replayMapName;
    (void)CopyLaunchInfoBasePtr(&sessionInfo->mLaunchInfo, launchInfo);
    sessionInfo->mIsBeingRecorded = false;
    sessionInfo->mIsReplay = true;
    sessionInfo->mIsMultiplayer = false;
    sessionInfo->mClientManager = CLIENT_CreateClientManager(2u, nullptr, 0, true);
    sessionInfo->mSourceId = kInvalidSourceIndex;

    if (sessionInfo->mClientManager != nullptr) {
      gpg::Stream* replayStreamOwnership = replayStream.release();
      sessionInfo->mClientManager->CreateReplayClient(&replayStreamOwnership, &replayCommandSources);
      if (replayStreamOwnership != nullptr) {
        delete replayStreamOwnership;
      }

      const msvc8::string localName = ReplayLocalClientName();
      sessionInfo->mClientManager->CreateLocalClient(localName.c_str(), 1, 1, kInvalidSourceIndex);
    }

    return sessionInfo;
  }

} // namespace moho
