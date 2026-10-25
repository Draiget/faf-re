#include "remote/client/RemoteSimDriver.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <utility>

#include "gpg/core/utils/Logging.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SimDriver.h"
#include "remote/ContentTables.h"

// Engine addition, server mode: see RemoteSimDriver.h.

namespace faf::remote::client
{
  namespace
  {
    constexpr std::uint32_t kSummaryEveryBeats = 600; // one minute of game time
  } // namespace

  CRemoteSimDriver::CRemoteSimDriver(
    std::unique_ptr<moho::ISTIDriver> server, moho::RRuleGameRules& rules, const wire::SFrameCodec& codec,
    const SLoopbackOptions& options
  )
    : mServer(std::move(server))
    , mTables(BuildContentTables(rules))
    , mCodec(codec)
    , mBuilder(mTables, codec)
    , mRebuilder(codec, ResolveBlueprints(rules, mTables))
  {
    if (options.deadReckoningTolerance != 0u && mCodec.deadReckoning) {
      mReckoner.emplace(options.deadReckoningTolerance);
    }
    gpg::Logf(
      "loopback: remote driver on, %u blueprints, content hash %016llx, dead reckoning %s (%u steps)",
      mTables.blueprints.Size(), static_cast<unsigned long long>(mTables.Hash()), mReckoner ? "on" : "off",
      options.deadReckoningTolerance
    );
  }

  CRemoteSimDriver::~CRemoteSimDriver()
  {
    LogSummary("end");
  }

  void CRemoteSimDriver::LogSummary(const char* const when) const
  {
    const SRebuildStats& s = mRebuilder.Stats();
    gpg::Logf(
      "loopback %s: frames %llu, %.1f KB/s, encode failures %llu, decode failures %llu, rebuild failures %llu, "
      "created %llu, erased %llu, deleted %llu, entity updates %llu (settle %llu, packet data %llu), "
      "max position error %.5f, time per beat %.2f ms server + %.2f ms client (max %.1f ms)",
      when, static_cast<unsigned long long>(s.frames),
      s.frames != 0u ? static_cast<double>(s.frameBytes) / static_cast<double>(s.frames) * 10.0 / 1024.0 : 0.0,
      static_cast<unsigned long long>(mEncodeFailures), static_cast<unsigned long long>(s.decodeFailures),
      static_cast<unsigned long long>(mRebuildFailures), static_cast<unsigned long long>(s.created),
      static_cast<unsigned long long>(s.erased), static_cast<unsigned long long>(s.deleted),
      static_cast<unsigned long long>(s.entityUpdates), static_cast<unsigned long long>(s.settleUpdates),
      static_cast<unsigned long long>(s.entityDataBorrowed), s.maxPositionError,
      s.frames != 0u ? mServerSeconds * 1000.0 / static_cast<double>(s.frames) : 0.0,
      s.frames != 0u ? mClientSeconds * 1000.0 / static_cast<double>(s.frames) : 0.0, mMaxBeatSeconds * 1000.0
    );
    gpg::Logf(
      "loopback %s checks: created not in packet %llu, packet creations not rebuilt %llu, blueprint mismatches %llu, "
      "creations without blueprint %llu, erase mismatches %llu, delete mismatches %llu, packet updates dropped %llu, "
      "unit changes without update %llu, unit constants missing %llu",
      when, static_cast<unsigned long long>(s.createdNotInPacket),
      static_cast<unsigned long long>(s.packetCreatedNotRebuilt), static_cast<unsigned long long>(s.blueprintMismatches),
      static_cast<unsigned long long>(s.noBlueprint), static_cast<unsigned long long>(s.eraseMismatches),
      static_cast<unsigned long long>(s.deleteMismatches), static_cast<unsigned long long>(s.packetUpdatesDropped),
      static_cast<unsigned long long>(s.unitChangesWithoutUpdate), static_cast<unsigned long long>(s.unitConstantsMissing)
    );
  }

  void CRemoteSimDriver::PassThroughWire(moho::SSyncData& packet)
  {
    // Server: the frame of this beat, against the frame sent last (in loopback every frame
    // arrives, so the last one sent is always acknowledged).
    using Clock = std::chrono::steady_clock;
    const Clock::time_point start = Clock::now();
    mBuilder.Apply(packet);
    wire::SViewFrame frame = mBuilder.Build(static_cast<std::uint32_t>(packet.mCurBeat));
    if (mReckoner) {
      mReckoner->Apply(frame, mCodec);
    }
    wire::BitWriter writer;
    if (!wire::EncodeFrame(frame, mHasSent ? &mLastSent : nullptr, mCodec, writer)) {
      // Nothing usable to send: the client keeps the packet as the sim made it this beat.
      ++mEncodeFailures;
      return;
    }
    mLastSent = std::move(frame);
    mHasSent = true;
    const Clock::time_point encoded = Clock::now();

    // Client.
    if (!mRebuilder.Apply(writer.Bytes(), packet)) {
      ++mRebuildFailures;
    }
    const Clock::time_point rebuilt = Clock::now();
    mServerSeconds += std::chrono::duration<double>(encoded - start).count();
    mClientSeconds += std::chrono::duration<double>(rebuilt - encoded).count();
    mMaxBeatSeconds = std::max(mMaxBeatSeconds, std::chrono::duration<double>(rebuilt - start).count());
    if (mRebuilder.Stats().frames % kSummaryEveryBeats == 0u) {
      LogSummary("so far");
    }
  }

  void CRemoteSimDriver::DisconnectClients()
  {
    mServer->DisconnectClients();
  }

  void CRemoteSimDriver::ShutDown()
  {
    mServer->ShutDown();
  }

  moho::CClientManagerImpl* CRemoteSimDriver::GetClientManager()
  {
    return mServer->GetClientManager();
  }

  void CRemoteSimDriver::NoOp()
  {
    mServer->NoOp();
  }

  void CRemoteSimDriver::Dispatch()
  {
    mServer->Dispatch();
  }

  void CRemoteSimDriver::IncrementOutstandingRequests()
  {
    mServer->IncrementOutstandingRequests();
  }

  void CRemoteSimDriver::DecrementOutstandingRequestsAndSignal()
  {
    mServer->DecrementOutstandingRequestsAndSignal();
  }

  bool CRemoteSimDriver::HasSyncData()
  {
    return mServer->HasSyncData();
  }

  void CRemoteSimDriver::GetSyncData(moho::SSyncData*& outSyncData)
  {
    mServer->GetSyncData(outSyncData);
    if (outSyncData != nullptr) {
      PassThroughWire(*outSyncData);
    }
  }

  HANDLE CRemoteSimDriver::GetSyncDataAvailableEvent()
  {
    return mServer->GetSyncDataAvailableEvent();
  }

  double CRemoteSimDriver::GetSimSpeed()
  {
    return mServer->GetSimSpeed();
  }

  void CRemoteSimDriver::SetArmyIndex(const int armyIndex)
  {
    mServer->SetArmyIndex(armyIndex);
  }

  void CRemoteSimDriver::SetGeomCams(const msvc8::vector<moho::GeomCamera3>& geoCams)
  {
    mServer->SetGeomCams(geoCams);
  }

  void CRemoteSimDriver::SetSyncFilterMaskA(const moho::SSyncFilterMaskBlock& block)
  {
    mServer->SetSyncFilterMaskA(block);
  }

  void CRemoteSimDriver::SetSyncFilterMaskB(const moho::SSyncFilterMaskBlock& block)
  {
    mServer->SetSyncFilterMaskB(block);
  }

  void CRemoteSimDriver::SetSyncFilterOptionFlag(const bool value)
  {
    mServer->SetSyncFilterOptionFlag(value);
  }

  void CRemoteSimDriver::RequestPause(std::int32_t* const outCommandCookie)
  {
    mServer->RequestPause(outCommandCookie);
  }

  void CRemoteSimDriver::Resume(std::int32_t* const outCommandCookie)
  {
    mServer->Resume(outCommandCookie);
  }

  moho::CmdId CRemoteSimDriver::SingleStep()
  {
    return mServer->SingleStep();
  }

  moho::CmdId CRemoteSimDriver::CreateUnit(
    const uint32_t armyIndex, const moho::RResId& id, const moho::SCoordsVec2& pos, const float heading
  )
  {
    return mServer->CreateUnit(armyIndex, id, pos, heading);
  }

  moho::CmdId CRemoteSimDriver::CreateProp(const char* const id, const Wm3::Vec3f& loc)
  {
    return mServer->CreateProp(id, loc);
  }

  moho::CmdId CRemoteSimDriver::DestroyEntity(const moho::EntId entityId)
  {
    return mServer->DestroyEntity(entityId);
  }

  moho::CmdId CRemoteSimDriver::WarpEntity(const moho::EntId entityId, const moho::VTransform& transform)
  {
    return mServer->WarpEntity(entityId, transform);
  }

  moho::CmdId CRemoteSimDriver::ProcessInfoPair(const moho::EntId entityId, const gpg::StrArg key, const gpg::StrArg val)
  {
    return mServer->ProcessInfoPair(entityId, key, val);
  }

  moho::CmdId CRemoteSimDriver::IssueCommand(
    const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities, const moho::SSTICommandIssueData& data,
    const bool clear
  )
  {
    return mServer->IssueCommand(entities, data, clear);
  }

  moho::CmdId CRemoteSimDriver::IssueFactoryCommand(
    const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities, const moho::SSTICommandIssueData& data,
    const bool clear
  )
  {
    return mServer->IssueFactoryCommand(entities, data, clear);
  }

  moho::CmdId CRemoteSimDriver::IncreaseCommandCount(const moho::CmdId id, const int count)
  {
    return mServer->IncreaseCommandCount(id, count);
  }

  moho::CmdId CRemoteSimDriver::DecreaseCommandCount(const moho::CmdId id, const int count)
  {
    return mServer->DecreaseCommandCount(id, count);
  }

  moho::CmdId CRemoteSimDriver::SetCommandTarget(const moho::CmdId id, const moho::SSTITarget& target)
  {
    return mServer->SetCommandTarget(id, target);
  }

  moho::CmdId CRemoteSimDriver::SetCommandType(const moho::CmdId id, const moho::EUnitCommandType type)
  {
    return mServer->SetCommandType(id, type);
  }

  moho::CmdId CRemoteSimDriver::SetCommandCells(
    const moho::CmdId id, const gpg::core::FastVector<moho::SOCellPos>& cells, const Wm3::Vector3<float>& target
  )
  {
    return mServer->SetCommandCells(id, cells, target);
  }

  moho::CmdId CRemoteSimDriver::RemoveCommandFromUnitQueue(const moho::CmdId id, const moho::EntId unitId)
  {
    return mServer->RemoveCommandFromUnitQueue(id, unitId);
  }

  moho::CmdId CRemoteSimDriver::ExecuteLuaInSim(const char* const lua, const LuaPlus::LuaObject& args)
  {
    return mServer->ExecuteLuaInSim(lua, args);
  }

  moho::CmdId CRemoteSimDriver::LuaSimCallback(
    const char* const fnName, const LuaPlus::LuaObject& args, const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities
  )
  {
    return mServer->LuaSimCallback(fnName, args, entities);
  }

  moho::CmdId CRemoteSimDriver::ExecuteDebugCommand(
    const char* const command, const Wm3::Vector3<float>& worldPos, const uint32_t focusArmy,
    const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities
  )
  {
    return mServer->ExecuteDebugCommand(command, worldPos, focusArmy, entities);
  }

  moho::Sim* CRemoteSimDriver::ProcessEvents()
  {
    return mServer->ProcessEvents();
  }

  void CRemoteSimDriver::ReleaseInterlockRef()
  {
    mServer->ReleaseInterlockRef();
  }

  void CRemoteSimDriver::RequestSaveGame(moho::CSaveGameRequestImpl* const request)
  {
    mServer->RequestSaveGame(request);
  }

  void CRemoteSimDriver::DrawNetworkStats(
    moho::CD3DPrimBatcher* const batcher, const float anchorX, const float anchorY, const float scaleX,
    const float scaleY
  )
  {
    mServer->DrawNetworkStats(batcher, anchorX, anchorY, scaleX, scaleY);
  }

  moho::ISTIDriver* WrapForLoopback(
    moho::ISTIDriver* const driver, moho::RRuleGameRules& rules, const Wm3::AxisAlignedBox3f& mapBounds,
    const bool multiplayer
  )
  {
    if (driver == nullptr || !moho::CFG_GetArgOption("/loopback", 0, nullptr)) {
      return driver;
    }
    if (multiplayer) {
      gpg::Logf("loopback: refused, a multiplayer session runs the lockstep driver unchanged");
      return driver;
    }
    SLoopbackOptions options;
    msvc8::vector<msvc8::string> args;
    if (moho::CFG_GetArgOption("/loopbackdr", 1, &args) && !args.empty()) {
      options.deadReckoningTolerance = static_cast<std::uint32_t>(std::strtoul(args[0].c_str(), nullptr, 10));
    }
    wire::SFrameCodec codec{};
    codec.position =
      wire::SPositionQuantizer::ForMap(mapBounds.Max.x - mapBounds.Min.x, mapBounds.Max.z - mapBounds.Min.z);
    codec.maxEntities = 1u << 20;
    codec.deadReckoning = options.deadReckoningTolerance != 0u;
    return new CRemoteSimDriver(std::unique_ptr<moho::ISTIDriver>(driver), rules, codec, options);
  }
} // namespace faf::remote::client
