#include "remote/client/LoopbackCommands.h"

#include "moho/sim/ISTIDriver.h"

// Engine addition, server mode: see LoopbackCommands.h.

namespace faf::remote::client
{
  // The client manager's own messages: a client's driver slots never marshal these.
  void CLoopbackCommandIntake::SetCommandSource(moho::CommandSourceId)
  {
    ++mUnexpected;
  }

  void CLoopbackCommandIntake::OnCommandSourceTerminated()
  {
    ++mUnexpected;
  }

  void CLoopbackCommandIntake::VerifyChecksum(const gpg::MD5Digest&, moho::CSeqNo)
  {
    ++mUnexpected;
  }

  void CLoopbackCommandIntake::AdvanceBeat(int)
  {
    ++mUnexpected;
  }

  void CLoopbackCommandIntake::EndGame()
  {
    ++mUnexpected;
  }

  // The driver slots, as the session's lockstep driver takes them.
  void CLoopbackCommandIntake::RequestPause()
  {
    std::int32_t cookie = 0;
    mServer.RequestPause(&cookie);
    Took(cookie);
  }

  void CLoopbackCommandIntake::Resume()
  {
    std::int32_t cookie = 0;
    mServer.Resume(&cookie);
    Took(cookie);
  }

  void CLoopbackCommandIntake::SingleStep()
  {
    Took(mServer.SingleStep());
  }

  void CLoopbackCommandIntake::CreateUnit(
    const uint32_t armyIndex, const moho::RResId& id, const moho::SCoordsVec2& pos, const float heading
  )
  {
    Took(mServer.CreateUnit(armyIndex, id, pos, heading));
  }

  void CLoopbackCommandIntake::CreateProp(const char* const id, const Wm3::Vec3f& loc)
  {
    Took(mServer.CreateProp(id, loc));
  }

  void CLoopbackCommandIntake::DestroyEntity(const moho::EntId entityId)
  {
    Took(mServer.DestroyEntity(entityId));
  }

  void CLoopbackCommandIntake::WarpEntity(const moho::EntId entityId, const moho::VTransform& transform)
  {
    Took(mServer.WarpEntity(entityId, transform));
  }

  void CLoopbackCommandIntake::ProcessInfoPair(const moho::EntId entityId, const gpg::StrArg key, const gpg::StrArg value)
  {
    Took(mServer.ProcessInfoPair(entityId, key, value));
  }

  void CLoopbackCommandIntake::IssueCommand(
    const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities, const moho::SSTICommandIssueData& data,
    const bool clear
  )
  {
    Took(mServer.IssueCommand(entities, data, clear));
  }

  void CLoopbackCommandIntake::IssueFactoryCommand(
    const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities, const moho::SSTICommandIssueData& data,
    const bool clear
  )
  {
    Took(mServer.IssueFactoryCommand(entities, data, clear));
  }

  void CLoopbackCommandIntake::IncreaseCommandCount(const moho::CmdId id, const int count)
  {
    Took(mServer.IncreaseCommandCount(id, count));
  }

  void CLoopbackCommandIntake::DecreaseCommandCount(const moho::CmdId id, const int count)
  {
    Took(mServer.DecreaseCommandCount(id, count));
  }

  void CLoopbackCommandIntake::SetCommandTarget(const moho::CmdId id, const moho::SSTITarget& target)
  {
    Took(mServer.SetCommandTarget(id, target));
  }

  void CLoopbackCommandIntake::SetCommandType(const moho::CmdId id, const moho::EUnitCommandType type)
  {
    Took(mServer.SetCommandType(id, type));
  }

  void CLoopbackCommandIntake::SetCommandCells(
    const moho::CmdId id, const gpg::core::FastVector<moho::SOCellPos>& cells, const Wm3::Vector3<float>& target
  )
  {
    Took(mServer.SetCommandCells(id, cells, target));
  }

  void CLoopbackCommandIntake::RemoveCommandFromUnitQueue(const moho::CmdId id, const moho::EntId unitId)
  {
    Took(mServer.RemoveCommandFromUnitQueue(id, unitId));
  }

  void CLoopbackCommandIntake::ExecuteLuaInSim(const char* const lua, const LuaPlus::LuaObject& args)
  {
    Took(mServer.ExecuteLuaInSim(lua, args));
  }

  void CLoopbackCommandIntake::LuaSimCallback(
    const char* const fnName, const LuaPlus::LuaObject& args, const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities
  )
  {
    Took(mServer.LuaSimCallback(fnName, args, entities));
  }

  void CLoopbackCommandIntake::ExecuteDebugCommand(
    const char* const command, const Wm3::Vector3<float>& worldPos, const uint32_t focusArmy,
    const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities
  )
  {
    Took(mServer.ExecuteDebugCommand(command, worldPos, focusArmy, entities));
  }
} // namespace faf::remote::client
