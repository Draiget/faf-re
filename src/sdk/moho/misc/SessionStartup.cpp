#include "moho/misc/SessionStartup.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>

#include "boost/shared_ptr.h"
#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/utils/Logging.h"
#include "moho/client/Localization.h"
#include "moho/misc/CSaveGameRequestImpl.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/misc/StringUtils.h"
#include "moho/net/CClientManagerImpl.h"
#include "moho/net/Common.h"
#include "moho/net/INetTCPSocket.h"
#include "moho/serialization/SaveGameFileHeader.h"
#include "moho/sim/WldSessionInfo.h"
#include "moho/ui/UiRuntimeTypes.h"

namespace
{
  [[nodiscard]] const gpg::RRef& NullOwnerRef()
  {
    static const gpg::RRef kNullOwner{nullptr, nullptr};
    return kNullOwner;
  }

  [[nodiscard]] bool MatchesSavedGameIdentity(const moho::SSaveGameFileHeader& header)
  {
    return header.mGameIdPart1 == moho::APP_GetGameIdPart(0) &&
           header.mGameIdPart2 == moho::APP_GetGameIdPart(1) &&
           header.mGameIdPart3 == moho::APP_GetGameIdPart(2) &&
           header.mGameIdPart4 == moho::APP_GetGameIdPart(3);
  }

  enum class EGpgNetOpenMode : int
  {
    Read = 1,
    Write = 2,
  };

  constexpr std::uint8_t kInvalidSourceIndex = 255u;

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
} // namespace

namespace moho
{
  /**
   * Address: 0x008765E0 (FUN_008765E0)
   * Mangled:
   * ?VCR_SetupReplaySession@Moho@@YA?AV?$auto_ptr@USWldSessionInfo@Moho@@@std@@VStrArg@gpg@@@Z
   *
   * What it does:
   * Loads replay file payload, reconstructs `LaunchInfoNew`, and creates
   * one replay `SWldSessionInfo` bootstrap object.
   */
  msvc8::auto_ptr<SWldSessionInfo> VCR_SetupReplaySession(const gpg::StrArg filename)
  {
    if (filename == nullptr || filename[0] == '\0') {
      return msvc8::auto_ptr<SWldSessionInfo>();
    }

    std::unique_ptr<gpg::Stream> replayStream{};
    try {
      replayStream = OpenGPGNetURI(filename, EGpgNetOpenMode::Read);
    } catch (...) {
      return msvc8::auto_ptr<SWldSessionInfo>();
    }

    if (replayStream == nullptr) {
      return msvc8::auto_ptr<SWldSessionInfo>();
    }

    gpg::BinaryReader replayReader(replayStream.get());
    const msvc8::string expectedVersion = gpg::STR_Printf("Supreme Commander v%1.2f.%4i", 1.5, 3764);
    msvc8::string replayVersion{};
    replayReader.ReadString(&replayVersion);
    if (replayVersion.view() != expectedVersion.view()) {
      return msvc8::auto_ptr<SWldSessionInfo>();
    }

    msvc8::string ignoredString{};
    replayReader.ReadString(&ignoredString);

    std::array<char, 14> replaySignature{};
    replayReader.Read(replaySignature.data(), 13);

    msvc8::string replayMapName{};
    replayReader.ReadString(&replayMapName);
    replayReader.ReadString(&ignoredString);

    if (std::strcmp(replaySignature.data(), "Replay v1.9\r\n") != 0) {
      return msvc8::auto_ptr<SWldSessionInfo>();
    }

    boost::shared_ptr<LaunchInfoNew> launchInfo(new LaunchInfoNew());
    replayReader.ReadLengthPrefixedString(&launchInfo->mGameMods);
    replayReader.ReadLengthPrefixedString(&launchInfo->mScenarioInfo);

    std::uint8_t commandSourceCount = 0;
    replayReader.ReadExact(commandSourceCount);

    launchInfo->mCommandSources.mSrcs.clear();
    launchInfo->mCommandSources.mSrcs.reserve(commandSourceCount);

    BVIntSet replayCommandSources{};
    for (std::uint32_t sourceIndex = 0; sourceIndex < commandSourceCount; ++sourceIndex) {
      SSTICommandSource source{};
      source.mIndex = sourceIndex;
      replayReader.ReadString(&source.mName);
      replayReader.ReadExact(source.mTimeouts);
      launchInfo->mCommandSources.mSrcs.push_back(source);
      (void)replayCommandSources.Add(sourceIndex);
    }

    std::uint8_t cheatsEnabled = 0;
    replayReader.ReadExact(cheatsEnabled);
    launchInfo->mCheatsEnabled = cheatsEnabled != 0;

    std::uint8_t armyCount = 0;
    replayReader.ReadExact(armyCount);

    launchInfo->mArmyLaunchInfo.clear();
    launchInfo->mArmyLaunchInfo.resize(armyCount);
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
        (void)launchInfo->mArmyLaunchInfo[armyIndex].Add(sourceIndex);
      }
    }

    replayReader.ReadExact(launchInfo->mInitSeed);
    launchInfo->mCommandSources.mOriginalSource = -1;

    msvc8::auto_ptr<SWldSessionInfo> sessionInfo(new SWldSessionInfo());
    sessionInfo->mMapName = replayMapName;
    sessionInfo->mLaunchInfo = boost::static_pointer_cast<LaunchInfoBase>(launchInfo);
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

      const msvc8::string localName = Loc(USER_GetLuaState(), "<LOC Engine0031>Local");
      sessionInfo->mClientManager->CreateLocalClient(localName.c_str(), 1, 1, kInvalidSourceIndex);
    }

    return sessionInfo;
  }

  /**
   * Address: 0x00880330 (FUN_00880330)
   *
   * What it does:
   * Opens and validates one saved-game file and loads its header archive lane.
   */
  CSavedGame::CSavedGame(const gpg::StrArg filename)
    : mFilename(filename != nullptr ? filename : "")
    , mReader(nullptr)
    , mHeader()
  {
    const std::wstring widePath = gpg::STR_Utf8ToWide(mFilename.c_str());
    std::FILE* rawFile = nullptr;
    if (_wfopen_s(&rawFile, widePath.c_str(), L"rb") != 0) {
      rawFile = nullptr;
    }
    boost::shared_ptr<std::FILE> file(rawFile, moho::SFileStarCloser{});
    if (!file.get()) {
      throw std::runtime_error("CantOpen");
    }

    SSaveGameFileHeader fileHeader{};
    if (std::fread(&fileHeader, sizeof(fileHeader), 1, file.get()) != 1 ||
        fileHeader.mMagic != kSaveGameFileHeaderMagic || fileHeader.mVersion != kSaveGameFileHeaderVersion ||
        !MatchesSavedGameIdentity(fileHeader)) {
      throw std::runtime_error("InvalidFormat");
    }

    mReader = gpg::CreateBinaryReadArchive(file);
    mReader->Read(SSavedGameHeader::StaticGetClass(), &mHeader, NullOwnerRef());
    mReader->EndSection(false);
    if (mHeader.mVersion != 20) {
      throw std::runtime_error("WrongVersion");
    }
  }

  /**
   * Address: 0x00880770 (FUN_00880770)
   *
   * What it does:
   * Releases the loaded read-archive lane and header-owned fields.
   */
  CSavedGame::~CSavedGame()
  {
    delete mReader;
    mReader = nullptr;
  }

  /**
   * Address: 0x008807F0 (FUN_008807F0)
   *
   * What it does:
   * Builds one single-player `SWldSessionInfo` from loaded save payload.
   */
  msvc8::auto_ptr<SWldSessionInfo> CSavedGame::CreateSinglePlayerSessionInfo()
  {
    boost::shared_ptr<LaunchInfoLoad> launchInfo(new LaunchInfoLoad());
    gpg::ReadPointerShared_SSessionSaveData(launchInfo->mLoadSessionData, mReader, NullOwnerRef());
    mReader->EndSection(false);

    std::int32_t focusArmyIndex = mHeader.mFocusArmy;
    if (focusArmyIndex < 0) {
      focusArmyIndex = 0;
    }

    const msvc8::string localArmyName = mHeader.mArmyInfo[static_cast<std::size_t>(focusArmyIndex)].mPlayerName;

    launchInfo->mCommandSources.mSrcs.clear();
    SSTICommandSource source{};
    source.mIndex = 0;
    source.mName = localArmyName;
    source.mTimeouts = -1;
    launchInfo->mCommandSources.mSrcs.push_back(source);

    launchInfo->mArmyLaunchInfo.clear();
    launchInfo->mArmyLaunchInfo.reserve(mHeader.mArmyInfo.size());
    for (std::size_t armyIndex = 0; armyIndex < mHeader.mArmyInfo.size(); ++armyIndex) {
      BVIntSet armySourceSet{};
      (void)armySourceSet.Add(0);
      launchInfo->mArmyLaunchInfo.push_back(armySourceSet);
    }

    launchInfo->mCommandSources.mOriginalSource = mHeader.mFocusArmy;

    gpg::ReadArchive* const loadedArchive = mReader;
    mReader = nullptr;
    delete launchInfo->mReadArchive;
    launchInfo->mReadArchive = loadedArchive;

    launchInfo->mSharedLaunchInfo.assign_retain(mHeader.mLaunchInfo);
    launchInfo->mGameMods = launchInfo->mSharedLaunchInfo.px->mGameMods;
    launchInfo->mScenarioInfo = mHeader.mScenarioInfoText;
    launchInfo->mCheatsEnabled = USER_DebugFacilitiesEnabled();

    msvc8::auto_ptr<SWldSessionInfo> sessionInfo(new SWldSessionInfo());
    sessionInfo->mMapName = mHeader.mMapName;
    sessionInfo->mLaunchInfo = boost::static_pointer_cast<LaunchInfoBase>(launchInfo);
    sessionInfo->mIsBeingRecorded = false;
    sessionInfo->mIsReplay = false;
    sessionInfo->mIsMultiplayer = false;
    sessionInfo->mClientManager = CLIENT_CreateClientManager(1u, nullptr, 0, true);
    sessionInfo->mSourceId = kInvalidSourceIndex;

    if (sessionInfo->mClientManager != nullptr) {
      sessionInfo->mClientManager->CreateLocalClient(localArmyName.c_str(), 0, 0, 0u);
    }
    sessionInfo->mSourceId = 0u;

    return sessionInfo;
  }
} // namespace moho
