#include "remote/client/RemoteSimDriver.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <string>
#include <utility>

#include "gpg/core/utils/Logging.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SimDriver.h"
#include "lua/LuaObject.h"
#include "moho/net/CMessage.h"

// Engine addition, server mode: see RemoteSimDriver.h.

namespace faf::remote::client
{
  namespace
  {
    constexpr std::uint32_t kSummaryEveryBeats = 600; // one minute of game time
  } // namespace

  template <class Send>
  moho::CmdId CRemoteSimDriver::SendCommand(Send&& send)
  {
    // WP11.1: the command goes as the message a networked client sends (`CMarshaller`), and the
    // stand-in server decodes it (`CDecoder`) before the session's lockstep driver takes it.
    mIntake.BeginCommand();
    send();
    ++mCommandsSent;
    if (!mIntake.HaveCookie()) {
      ++mCommandsDropped; // the decoder refused it: the lockstep path would have sent it
      if (mCommandsDropped <= 10u) {
        gpg::Logf("loopback: a command did not survive the round trip to the server (%llu so far)",
                  static_cast<unsigned long long>(mCommandsDropped));
      }
    }
    return mIntake.Cookie();
  }

  CRemoteSimDriver::CRemoteSimDriver(
    std::unique_ptr<moho::ISTIDriver> server, moho::RRuleGameRules& rules, const wire::SFrameCodec& codec,
    const SLoopbackOptions& options
  )
    : mServer(std::move(server))
    , mLink(rules, codec, options)
    , mIntake(*mServer)
    , mCommandLua(new LuaPlus::LuaState(LuaPlus::LuaState::LIB_BASE))
    , mServerDecoder(&mIntake, mNoRecording, &rules, mCommandLua.get())
    , mClientManager(
        [this](moho::CMessage& message) { mServerDecoder.ReceiveMessage(&message, nullptr); }, mServer->GetClientManager()
      )
    , mMarshaller(&mClientManager)
  {
    gpg::Logf(
      "loopback: remote driver on, %u blueprints, content hash %016llx, dead reckoning %s (%u steps, turns %u)",
      mLink.Tables().blueprints.Size(), static_cast<unsigned long long>(mLink.Tables().Hash()),
      mLink.DeadReckoning() ? "on" : "off", options.deadReckoningTolerance, options.orientationTolerance
    );
    if (!mLink.Refusal().empty()) {
      gpg::Logf("loopback: the client refused the server's hello (%s); the session runs on the sim's packets", mLink.Refusal().c_str());
    }
  }

  CRemoteSimDriver::~CRemoteSimDriver()
  {
    LogSummary("end");
  }

  void CRemoteSimDriver::LogSummary(const char* const when) const
  {
    const std::string summary = mLink.Summary(when);
    const std::size_t split = summary.find('\n');
    gpg::Logf("%s", summary.substr(0, split).c_str());
    if (split != std::string::npos) {
      gpg::Logf("%s", summary.substr(split + 1).c_str());
    }
    gpg::Logf(
      "loopback %s commands: %llu sent through CMarshaller and CDecoder, %llu dropped, %llu unexpected messages",
      when, static_cast<unsigned long long>(mCommandsSent), static_cast<unsigned long long>(mCommandsDropped),
      static_cast<unsigned long long>(mIntake.Unexpected())
    );
  }

  void CRemoteSimDriver::PassThroughWire(moho::SSyncData& packet)
  {
    mLink.Pass(packet);
    if (mLink.Stats().frames % kSummaryEveryBeats == 0u) {
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
    // The remote client's own (WP11.4), answering as the session's lockstep one in loopback.
    return mServer->GetClientManager() != nullptr ? &mClientManager : nullptr;
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
    const moho::CmdId cookie = SendCommand([&] { mMarshaller.RequestPause(); });
    if (outCommandCookie != nullptr) {
      *outCommandCookie = cookie;
    }
  }

  void CRemoteSimDriver::Resume(std::int32_t* const outCommandCookie)
  {
    const moho::CmdId cookie = SendCommand([&] { mMarshaller.Resume(); });
    if (outCommandCookie != nullptr) {
      *outCommandCookie = cookie;
    }
  }

  moho::CmdId CRemoteSimDriver::SingleStep()
  {
    return SendCommand([&] { mMarshaller.SingleStep(); });
  }

  moho::CmdId CRemoteSimDriver::CreateUnit(
    const uint32_t armyIndex, const moho::RResId& id, const moho::SCoordsVec2& pos, const float heading
  )
  {
    return SendCommand([&] { mMarshaller.CreateUnit(armyIndex, id, pos, heading); });
  }

  moho::CmdId CRemoteSimDriver::CreateProp(const char* const id, const Wm3::Vec3f& loc)
  {
    return SendCommand([&] { mMarshaller.CreateProp(id, loc); });
  }

  moho::CmdId CRemoteSimDriver::DestroyEntity(const moho::EntId entityId)
  {
    return SendCommand([&] { mMarshaller.DestroyEntity(entityId); });
  }

  moho::CmdId CRemoteSimDriver::WarpEntity(const moho::EntId entityId, const moho::VTransform& transform)
  {
    return SendCommand([&] { mMarshaller.WarpEntity(entityId, transform); });
  }

  moho::CmdId CRemoteSimDriver::ProcessInfoPair(const moho::EntId entityId, const gpg::StrArg key, const gpg::StrArg val)
  {
    return SendCommand([&] { mMarshaller.ProcessInfoPair(entityId, key, val); });
  }

  moho::CmdId CRemoteSimDriver::IssueCommand(
    const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities, const moho::SSTICommandIssueData& data,
    const bool clear
  )
  {
    return SendCommand([&] { mMarshaller.IssueCommand(entities, data, clear); });
  }

  moho::CmdId CRemoteSimDriver::IssueFactoryCommand(
    const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities, const moho::SSTICommandIssueData& data,
    const bool clear
  )
  {
    return SendCommand([&] { mMarshaller.IssueFactoryCommand(entities, data, clear); });
  }

  moho::CmdId CRemoteSimDriver::IncreaseCommandCount(const moho::CmdId id, const int count)
  {
    return SendCommand([&] { mMarshaller.IncreaseCommandCount(id, count); });
  }

  moho::CmdId CRemoteSimDriver::DecreaseCommandCount(const moho::CmdId id, const int count)
  {
    return SendCommand([&] { mMarshaller.DecreaseCommandCount(id, count); });
  }

  moho::CmdId CRemoteSimDriver::SetCommandTarget(const moho::CmdId id, const moho::SSTITarget& target)
  {
    return SendCommand([&] { mMarshaller.SetCommandTarget(id, target); });
  }

  moho::CmdId CRemoteSimDriver::SetCommandType(const moho::CmdId id, const moho::EUnitCommandType type)
  {
    return SendCommand([&] { mMarshaller.SetCommandType(id, type); });
  }

  moho::CmdId CRemoteSimDriver::SetCommandCells(
    const moho::CmdId id, const gpg::core::FastVector<moho::SOCellPos>& cells, const Wm3::Vector3<float>& target
  )
  {
    return SendCommand([&] { mMarshaller.SetCommandCells(id, cells, target); });
  }

  moho::CmdId CRemoteSimDriver::RemoveCommandFromUnitQueue(const moho::CmdId id, const moho::EntId unitId)
  {
    return SendCommand([&] { mMarshaller.RemoveCommandFromUnitQueue(id, unitId); });
  }

  moho::CmdId CRemoteSimDriver::ExecuteLuaInSim(const char* const lua, const LuaPlus::LuaObject& args)
  {
    return SendCommand([&] { mMarshaller.ExecuteLuaInSim(lua, args); });
  }

  moho::CmdId CRemoteSimDriver::LuaSimCallback(
    const char* const fnName, const LuaPlus::LuaObject& args, const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities
  )
  {
    return SendCommand([&] { mMarshaller.LuaSimCallback(fnName, args, entities); });
  }

  moho::CmdId CRemoteSimDriver::ExecuteDebugCommand(
    const char* const command, const Wm3::Vector3<float>& worldPos, const uint32_t focusArmy,
    const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities
  )
  {
    return SendCommand([&] { mMarshaller.ExecuteDebugCommand(command, worldPos, focusArmy, entities); });
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
    args.clear();
    if (moho::CFG_GetArgOption("/loopbackturns", 1, &args) && !args.empty()) {
      options.orientationTolerance = static_cast<std::uint32_t>(std::strtoul(args[0].c_str(), nullptr, 10));
    }
    const wire::SFrameCodec codec =
      MakeLoopbackCodec(mapBounds.Max.x - mapBounds.Min.x, mapBounds.Max.z - mapBounds.Min.z, options);
    return new CRemoteSimDriver(std::unique_ptr<moho::ISTIDriver>(driver), rules, codec, options);
  }
} // namespace faf::remote::client
