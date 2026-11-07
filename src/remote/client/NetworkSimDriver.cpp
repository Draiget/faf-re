#include "remote/client/NetworkSimDriver.h"

#include <algorithm>
#include <utility>

#include "gpg/core/streams/MemBufferStream.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/lua/SCR_String.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/resource/CSimResources.h"
#include "moho/net/CMessage.h"
#include "moho/net/CMessageStream.h"
#include "moho/net/ELobbyMsg.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SSTIArmyConstantData.h"
#include "moho/sim/SSTIArmyVariableData.h"
#include "moho/sim/SimDriver.h"
#include "remote/ArmyRecords.h"
#include "remote/client/ServerConnect.h"
#include "remote/net/Datagram.h"
#include "remote/net/GameLinks.h"
#include "remote/wire/BitStream.h"
#include "remote/wire/LuaSyncLane.h"

// Engine addition, server mode: see NetworkSimDriver.h.

namespace faf::remote::client
{
  namespace
  {
    constexpr std::uint32_t kSummaryEveryViews = 600; // one minute of game time

    /** The bytes `LuaObject::ToByteStream` writes for an empty table: a beat whose Lua lane carries nothing. */
    [[nodiscard]] std::vector<std::uint8_t> EmptyTableBytes(LuaPlus::LuaState& state)
    {
      LuaPlus::LuaObject table;
      table.AssignNewTable(&state, 0, 0u);
      // As the server writes its tables (ServerMain's MakeLaunchInfo): into a message, then its payload.
      moho::CMessage message(moho::ELobbyMsg::LOBMSG_DirectScriptData);
      {
        moho::CMessageStream stream(message, moho::CMessageStream::Access::kReadWrite);
        (void)table.ToByteStream(stream);
      }
      constexpr std::size_t kHeaderBytes = 3u;
      const auto* const bytes = reinterpret_cast<const std::uint8_t*>(message.mBuff.start_);
      const std::size_t size = message.mBuff.Size();
      return size > kHeaderBytes ? std::vector<std::uint8_t>(bytes + kHeaderBytes, bytes + size) : std::vector<std::uint8_t>{};
    }
  } // namespace

  CNetworkSimDriver::CNetworkSimDriver(
    moho::RRuleGameRules& rules, const moho::LaunchInfoBase& launch, const char* const playerName, const int clientIndex,
    const std::int32_t uid, const unsigned int sourceId, const moho::CHeightField* const heights
  )
    : mRules(rules)
    , mClientManager([this](moho::CMessage& message) { SendCommandFrame(message); }, nullptr)
    , mMarshaller(&mClientManager)
    , mEmptySyncLua(new LuaPlus::LuaState(LuaPlus::LuaState::LIB_BASE))
  {
    mEmptySync = EmptyTableBytes(*mEmptySyncLua);
    mResources.reset(new moho::CSimResources());
    mSeedHeights = heights;
    // The armies, as `CArmyImpl`'s constructor names them from each army's setup (0x006FE690: `ArmyName`,
    // `PlayerName`, `Civilian`); their intel grids stay null, which user code reads as unknown (research WP11.3).
    if (const auto* const launchNew = dynamic_cast<const moho::LaunchInfoNew*>(&launch); launchNew != nullptr) {
      for (std::size_t index = 0; index < launchNew->mStrVec.size(); ++index) {
        moho::SSTIArmyConstantData army{};
        army.mArmyIndex = static_cast<std::int32_t>(index);
        try {
          LuaPlus::LuaObject setup;
          (void)moho::SCR_FromString(&setup, launchNew->mStrVec[index], mEmptySyncLua.get());
          if (setup.IsTable()) {
            const LuaPlus::LuaObject armyName = setup["ArmyName"];
            const LuaPlus::LuaObject playerName = setup["PlayerName"];
            const LuaPlus::LuaObject civilian = setup["Civilian"];
            army.mArmyName.assign_owned(armyName.IsString() ? armyName.GetString() : "");
            army.mPlayerName.assign_owned(playerName.IsString() ? playerName.GetString() : "");
            army.mIsCivilian = static_cast<std::uint8_t>(civilian.IsBoolean() && civilian.GetBoolean() ? 1u : 0u);
          }
        } catch (const std::exception& error) {
          gpg::Warnf("server driver: army %zu's setup doesn't read: %s", index, error.what());
        }
        mArmyConstants.push_back(army);
      }
    }
    mAvailable = ::CreateEventW(nullptr, TRUE, FALSE, nullptr); // manual reset: set while packets wait
    (void)mClientManager.CreateLocalClient(playerName, clientIndex, uid, sourceId);
    mClientManager.SetLoadedHandler([] {
      const std::uint8_t loaded = static_cast<std::uint8_t>(net::ESeatMessage::Loaded);
      (void)SendServerGameMessage(std::span<const std::uint8_t>(&loaded, 1u));
      gpg::Logf("server driver: loaded; told the server");
    });
    gpg::Logf(
      "server driver: on, as client %d (uid %d, source %u), %zu armies", clientIndex, static_cast<int>(uid), sourceId, mArmyConstants.size()
    );
  }

  CNetworkSimDriver::~CNetworkSimDriver()
  {
    LogSummary("end");
    if (mAvailable != nullptr) {
      (void)::CloseHandle(mAvailable);
    }
  }

  void CNetworkSimDriver::LogSummary(const char* const when) const
  {
    const SServerViewStats noStats{};
    const SServerViewStats& views = mViews ? mViews->Stats() : noStats;
    gpg::Logf(
      "server driver %s: %llu views (%llu applied, %llu bad, %llu frame failures), beat %d, %llu commands sent, answers %llu applied / "
      "%llu refused / %llu dropped, %llu Lua lanes bad, %llu without their LuaSync; session tables: %llu records (%llu bad, %llu resets), "
      "%zu deposits, %llu terrain edits, %llu unknown ids",
      when, static_cast<unsigned long long>(mViewsTaken), static_cast<unsigned long long>(views.applied), static_cast<unsigned long long>(mViewsBad),
      static_cast<unsigned long long>(views.frameFailures), static_cast<int>(mLastBeat), static_cast<unsigned long long>(mCommandsSent),
      static_cast<unsigned long long>(mAnswers[0]), static_cast<unsigned long long>(mAnswers[1]), static_cast<unsigned long long>(mAnswers[2]),
      static_cast<unsigned long long>(mLuaLanesBad), static_cast<unsigned long long>(mLuaMissing),
      static_cast<unsigned long long>(views.tableRecords), static_cast<unsigned long long>(views.tableFailures + mTablesBad),
      static_cast<unsigned long long>(views.tableResets), mViews ? mViews->Tables().Deposits().size() : std::size_t{0},
      static_cast<unsigned long long>(mViews ? mViews->RebuildStats().terrainEdits : 0u),
      static_cast<unsigned long long>(mViews ? mViews->RebuildStats().unknownTableIds : 0u)
    );
  }

  void CNetworkSimDriver::Take(const std::vector<std::uint8_t>& message)
  {
    if (message.empty()) {
      return;
    }
    switch (static_cast<net::ESeatMessage>(message[0])) {
    case net::ESeatMessage::GameInfo: {
      SServerGameInfo info;
      if (!ReadGameInfo(message, info)) {
        gpg::Warnf("server driver: a malformed GameInfo");
        return;
      }
      // Again after a reconnect: the client keeps what it holds; the next view comes whole.
      if (!mViews) {
        mViews = std::make_unique<CServerViewClient>(mRules, info);
        if (mSeedHeights != nullptr) {
          mViews->SeedTerrain(*mSeedHeights); // no edit has reached the session's field yet: none is applied before a view
        }
        gpg::Logf(
          "server driver: map %.0f x %.0f, army %d, source %u, %llu blueprints known", info.mapSizeX, info.mapSizeZ, static_cast<int>(info.army),
          info.source, static_cast<unsigned long long>(mViews->Stats().blueprintsKnown)
        );
      }
      return;
    }
    case net::ESeatMessage::View: {
      SViewMessage view;
      if (!mViews || !ReadViewMessage(message, view)) {
        ++mViewsBad;
        return;
      }
      SPendingView pending;
      pending.message = message;
      pending.beat = view.beat;
      if (const auto early = mEarlyLua.find(view.beat); early != mEarlyLua.end()) {
        pending.lua = std::move(early->second);
        pending.haveLua = true;
        mEarlyLua.erase(early);
      }
      mPendingViews.push_back(std::move(pending));
      ReleaseViews();
      return;
    }
    case net::ESeatMessage::LuaSync: {
      // Plan WP11: the beat's Lua lane, after the server routed the beat's `Sync`.
      net::ByteReader reader(message.data() + 1, message.size() - 1u);
      const auto beat = static_cast<std::uint32_t>(reader.Varint());
      const std::uint64_t size = reader.Varint();
      const std::uint8_t* const bytes = reader.Bytes(static_cast<std::size_t>(size));
      if (!reader.Ok()) {
        ++mLuaLanesBad;
        return;
      }
      std::vector<std::uint8_t> lane(bytes, bytes + size);
      const auto pending = std::find_if(mPendingViews.begin(), mPendingViews.end(), [beat](const SPendingView& view) { return view.beat == beat; });
      if (pending != mPendingViews.end()) {
        pending->lua = std::move(lane);
        pending->haveLua = true;
        ReleaseViews();
      } else if (mEarlyLua.size() < 64u) {
        mEarlyLua[beat] = std::move(lane);
      }
      return;
    }
    case net::ESeatMessage::SessionTables: {
      // Plan WP11 step 4: before the views that name its entries (or a reset, then every record again).
      STablesMessage tables;
      if (!mViews || !ReadTablesMessage(message, tables) || !mViews->ApplyTables(tables)) {
        ++mTablesBad;
      }
      return;
    }
    case net::ESeatMessage::Beat: {
      net::ByteReader reader(message.data() + 1, message.size() - 1u);
      const std::uint64_t beat = reader.Varint();
      if (reader.Ok()) {
        mServerBeat = static_cast<std::int32_t>(beat);
      }
      return;
    }
    case net::ESeatMessage::CommandAnswer: {
      // Plan WP3.7: the beat the command went in (or refused, or dropped), for each command in the order sent.
      net::ByteReader reader(message.data() + 1, message.size() - 1u);
      (void)reader.Varint();
      const std::uint8_t answer = reader.Byte();
      if (reader.Ok() && answer <= 2u) {
        ++mAnswers[answer];
      }
      return;
    }
    default:
      return; // LaunchInfo (the session was made from it), ViewCheck (the probe compares; not yet here)
    }
  }

  void CNetworkSimDriver::ReleaseViews()
  {
    // In order: a view waits for its beat's `LuaSync`, unless the next beat's view is here (none is coming then).
    while (!mPendingViews.empty() && (mPendingViews.front().haveLua || mPendingViews.size() > 1u)) {
      SPendingView pending = std::move(mPendingViews.front());
      mPendingViews.pop_front();
      SViewMessage view;
      if (!ReadViewMessage(pending.message, view)) {
        ++mViewsBad;
        continue;
      }
      if (!pending.haveLua) {
        ++mLuaMissing;
      }
      QueueView(view, pending.haveLua ? std::span<const std::uint8_t>(pending.lua) : view.lua);
    }
  }

  void CNetworkSimDriver::QueueView(const SViewMessage& view, const std::span<const std::uint8_t> lua)
  {
    ++mViewsTaken;
    auto packet = std::make_unique<moho::SSyncData>();
    packet->mCurBeat = static_cast<std::int32_t>(view.beat);
    packet->mCurTick = static_cast<std::int32_t>(view.beat);
    packet->mAdvanced = true;
    packet->mFocusArmy = mViews->Info().army;
    if (!mArmiesGiven) {
      mArmiesGiven = true;
      for (const moho::SSTIArmyConstantData& army : mArmyConstants) {
        packet->mNewGrids.push_back(army);
      }
    }
    if (!mViews->Apply(view, *packet)) {
      ++mViewsBad;
      return;
    }
    if (packet->mSimResources.px == nullptr) {
      packet->mSimResources.reset_from_owner(mResources);
    }
    // Every army's record as this client holds it.
    const std::vector<wire::SArmyRecord>& armies = mViews->Armies();
    packet->mArmyUpdates.resize(armies.size());
    for (std::size_t index = 0; index < armies.size(); ++index) {
      ArmyFromWire(armies[index], packet->mArmyUpdates[index], &mRules);
    }
    // The beat's Lua `Sync` table (the session deserialises it every beat): the view's Lua lane, or an empty table.
    std::vector<std::uint8_t> table;
    std::vector<std::string> prints;
    if (!lua.empty()) {
      wire::BitReader reader(lua);
      if (!wire::DecodeLuaSyncLane(reader, table, prints)) {
        ++mLuaLanesBad;
        table.clear();
      }
    }
    const std::vector<std::uint8_t>& sync = table.empty() ? mEmptySync : table;
    if (mViewsTaken <= 3u || (!table.empty() && mLuaTablesLogged < 3u)) {
      // The first beats' Lua `Sync` (what the session's `OnSync` gets), for the log.
      static constexpr char kPlayableArea[] = "NewPlayableArea";
      const bool playableArea =
        std::search(table.begin(), table.end(), std::begin(kPlayableArea), std::end(kPlayableArea) - 1) != table.end();
      mLuaTablesLogged += table.empty() ? 0u : 1u;
      gpg::Logf(
        "server driver: beat %u Lua lane %zu bytes, Sync table %zu bytes%s, %zu prints", view.beat, lua.size(), table.size(),
        playableArea ? " (NewPlayableArea)" : "", prints.size()
      );
    }
    auto* const stream = new gpg::MemBufferStream(static_cast<unsigned int>(sync.size() + 16u));
    stream->Write(reinterpret_cast<const char*>(sync.data()), sync.size());
    packet->mStream = stream;
    mLastBeat = packet->mCurBeat;
    mPackets.push_back(std::move(packet));
    (void)::SetEvent(mAvailable);
    if (mViewsTaken % kSummaryEveryViews == 0u) {
      LogSummary("so far");
    }
  }

  void CNetworkSimDriver::SendCommandFrame(moho::CMessage& message)
  {
    // As the probe sends one: the kind, then the whole message (type, 16-bit size, payload).
    std::vector<std::uint8_t> frame;
    frame.reserve(1u + message.mBuff.Size());
    frame.push_back(static_cast<std::uint8_t>(net::ESeatMessage::Command));
    const auto* const bytes = reinterpret_cast<const std::uint8_t*>(message.mBuff.start_);
    frame.insert(frame.end(), bytes, bytes + message.mBuff.Size());
    if (SendServerGameMessage(frame)) {
      ++mCommandsSent;
    }
  }

  moho::CmdId CNetworkSimDriver::IssueBeat() const noexcept
  {
    return static_cast<moho::CmdId>((mLastBeat < 0 ? 0 : mLastBeat) + 1);
  }

  void CNetworkSimDriver::DisconnectClients() {}

  void CNetworkSimDriver::ShutDown()
  {
    if (!std::exchange(mShutDown, true)) {
      const std::uint8_t leaving = static_cast<std::uint8_t>(net::ESeatMessage::Leaving);
      (void)SendServerGameMessage(std::span<const std::uint8_t>(&leaving, 1u));
    }
  }

  moho::CClientManagerImpl* CNetworkSimDriver::GetClientManager()
  {
    return &mClientManager;
  }

  void CNetworkSimDriver::NoOp() {}

  void CNetworkSimDriver::Dispatch()
  {
    std::vector<std::uint8_t> message;
    while (TakeServerGameMessage(message)) {
      Take(message);
    }
  }

  void CNetworkSimDriver::IncrementOutstandingRequests() {}

  void CNetworkSimDriver::DecrementOutstandingRequestsAndSignal() {}

  bool CNetworkSimDriver::HasSyncData()
  {
    return !mPackets.empty();
  }

  void CNetworkSimDriver::GetSyncData(moho::SSyncData*& outSyncData)
  {
    // Never blocks: the session asks only after `HasSyncData`.
    outSyncData = nullptr;
    if (!mPackets.empty()) {
      outSyncData = mPackets.front().release();
      mPackets.pop_front();
    }
    if (mPackets.empty()) {
      (void)::ResetEvent(mAvailable);
    }
  }

  HANDLE CNetworkSimDriver::GetSyncDataAvailableEvent()
  {
    return mAvailable;
  }

  double CNetworkSimDriver::GetSimSpeed()
  {
    return 0.0;
  }

  // Session requests the server has no message for yet: the view's army is the server's, the cameras and filters
  // don't change what it sends (a later plan item).
  void CNetworkSimDriver::SetArmyIndex(const int) {}
  void CNetworkSimDriver::SetGeomCams(const fa::vector<moho::GeomCamera3>&) {}
  void CNetworkSimDriver::SetSyncFilterMaskA(const moho::SSyncFilterMaskBlock&) {}
  void CNetworkSimDriver::SetSyncFilterMaskB(const moho::SSyncFilterMaskBlock&) {}
  void CNetworkSimDriver::SetSyncFilterOptionFlag(const bool) {}

  void CNetworkSimDriver::RequestPause(std::int32_t* const outCommandCookie)
  {
    mMarshaller.RequestPause();
    if (outCommandCookie != nullptr) {
      *outCommandCookie = static_cast<std::int32_t>(IssueBeat());
    }
  }

  void CNetworkSimDriver::Resume(std::int32_t* const outCommandCookie)
  {
    mMarshaller.Resume();
    if (outCommandCookie != nullptr) {
      *outCommandCookie = static_cast<std::int32_t>(IssueBeat());
    }
  }

  // Commands as a lockstep client sends them; the server refuses those a player may not give (single step, creating,
  // destroying and warping entities, Lua in the sim, debug commands: remote/ServerClient.cpp).
  moho::CmdId CNetworkSimDriver::SingleStep()
  {
    mMarshaller.SingleStep();
    return IssueBeat();
  }

  moho::CmdId CNetworkSimDriver::CreateUnit(const uint32_t armyIndex, const moho::RResId& id, const moho::SCoordsVec2& pos, const float heading)
  {
    mMarshaller.CreateUnit(armyIndex, id, pos, heading);
    return IssueBeat();
  }

  moho::CmdId CNetworkSimDriver::CreateProp(const char* const id, const Wm3::Vec3f& loc)
  {
    mMarshaller.CreateProp(id, loc);
    return IssueBeat();
  }

  moho::CmdId CNetworkSimDriver::DestroyEntity(const moho::EntId entityId)
  {
    mMarshaller.DestroyEntity(entityId);
    return IssueBeat();
  }

  moho::CmdId CNetworkSimDriver::WarpEntity(const moho::EntId entityId, const moho::VTransform& transform)
  {
    mMarshaller.WarpEntity(entityId, transform);
    return IssueBeat();
  }

  moho::CmdId CNetworkSimDriver::ProcessInfoPair(const moho::EntId entityId, const gpg::StrArg key, const gpg::StrArg val)
  {
    mMarshaller.ProcessInfoPair(entityId, key, val);
    return IssueBeat();
  }

  moho::CmdId CNetworkSimDriver::IssueCommand(
    const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities, const moho::SSTICommandIssueData& data, const bool clear
  )
  {
    mMarshaller.IssueCommand(entities, data, clear);
    return IssueBeat();
  }

  moho::CmdId CNetworkSimDriver::IssueFactoryCommand(
    const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities, const moho::SSTICommandIssueData& data, const bool clear
  )
  {
    mMarshaller.IssueFactoryCommand(entities, data, clear);
    return IssueBeat();
  }

  moho::CmdId CNetworkSimDriver::IncreaseCommandCount(const moho::CmdId id, const int count)
  {
    mMarshaller.IncreaseCommandCount(id, count);
    return IssueBeat();
  }

  moho::CmdId CNetworkSimDriver::DecreaseCommandCount(const moho::CmdId id, const int count)
  {
    mMarshaller.DecreaseCommandCount(id, count);
    return IssueBeat();
  }

  moho::CmdId CNetworkSimDriver::SetCommandTarget(const moho::CmdId id, const moho::SSTITarget& target)
  {
    mMarshaller.SetCommandTarget(id, target);
    return IssueBeat();
  }

  moho::CmdId CNetworkSimDriver::SetCommandType(const moho::CmdId id, const moho::EUnitCommandType type)
  {
    mMarshaller.SetCommandType(id, type);
    return IssueBeat();
  }

  moho::CmdId CNetworkSimDriver::SetCommandCells(
    const moho::CmdId id, const gpg::core::FastVector<moho::SOCellPos>& cells, const Wm3::Vector3<float>& target
  )
  {
    mMarshaller.SetCommandCells(id, cells, target);
    return IssueBeat();
  }

  moho::CmdId CNetworkSimDriver::RemoveCommandFromUnitQueue(const moho::CmdId id, const moho::EntId unitId)
  {
    mMarshaller.RemoveCommandFromUnitQueue(id, unitId);
    return IssueBeat();
  }

  moho::CmdId CNetworkSimDriver::ExecuteLuaInSim(const char* const lua, const LuaPlus::LuaObject& args)
  {
    mMarshaller.ExecuteLuaInSim(lua, args);
    return IssueBeat();
  }

  moho::CmdId CNetworkSimDriver::LuaSimCallback(
    const char* const fnName, const LuaPlus::LuaObject& args, const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities
  )
  {
    mMarshaller.LuaSimCallback(fnName, args, entities);
    return IssueBeat();
  }

  moho::CmdId CNetworkSimDriver::ExecuteDebugCommand(
    const char* const command, const Wm3::Vector3<float>& worldPos, const uint32_t focusArmy,
    const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities
  )
  {
    mMarshaller.ExecuteDebugCommand(command, worldPos, focusArmy, entities);
    return IssueBeat();
  }

  moho::Sim* CNetworkSimDriver::ProcessEvents()
  {
    return nullptr;
  }

  void CNetworkSimDriver::ReleaseInterlockRef() {}

  void CNetworkSimDriver::RequestSaveGame(moho::ISaveRequest* const request)
  {
    // A client with no sim has nothing to save; the server keeps the game (and its replay).
    (void)request;
    gpg::Warnf("server driver: a save was asked for; a server game can't be saved by a player");
  }

  void CNetworkSimDriver::DrawNetworkStats(moho::CD3DPrimBatcher*, float, float, float, float) {}

  namespace
  {
    SServerLaunch sLaunch;
    bool sHaveLaunch = false;
  } // namespace

  void SetServerLaunch(const SServerLaunch& launch)
  {
    sLaunch = launch;
    sHaveLaunch = true;
  }

  bool HasServerLaunch() noexcept
  {
    return sHaveLaunch;
  }

  moho::ISTIDriver* CreateServerSessionDriver(
    moho::RRuleGameRules& rules, const moho::LaunchInfoBase& launch, const moho::CHeightField* const heights
  )
  {
    return new CNetworkSimDriver(rules, launch, sLaunch.playerName.c_str(), sLaunch.clientIndex, sLaunch.uid, sLaunch.source, heights);
  }
} // namespace faf::remote::client
