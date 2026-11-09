#pragma once

#include <cstdint>

#include "moho/command/ICommandSink.h"

// Engine addition, server mode (plan WP11.1): the server end of the loopback command path. The
// remote driver sends each command as the `CMarshaller` message a networked client sends; the
// engine's `CDecoder` decodes it into this sink, which hands it to the session's lockstep driver
// (the stand-in server), as the server's per-client intake will hand it to the sim (WP3).

namespace moho
{
  class ISTIDriver;
}

namespace faf::remote::client
{
  class CLoopbackCommandIntake final : public moho::ICommandSink
  {
  public:
    explicit CLoopbackCommandIntake(moho::ISTIDriver& server) noexcept
      : mServer(server)
    {}

    /** Before each command: forget the last cookie, so a dropped command shows. */
    void BeginCommand() noexcept { mHaveCookie = false; }
    /** Whether the command since `BeginCommand` reached the server, and the cookie it returned. */
    [[nodiscard]] bool HaveCookie() const noexcept { return mHaveCookie; }
    [[nodiscard]] std::int32_t Cookie() const noexcept { return mCookie; }
    /** Messages a client's driver never sends (the client manager's own), received anyway. */
    [[nodiscard]] std::uint64_t Unexpected() const noexcept { return mUnexpected; }

    void SetCommandSource(moho::CommandSourceId sourceId) override;
    void OnCommandSourceTerminated() override;
    void VerifyChecksum(const gpg::MD5Digest& digest, moho::CSeqNo seqNo) override;
    void RequestPause() override;
    void Resume() override;
    void SingleStep() override;
    void CreateUnit(uint32_t armyIndex, const moho::RResId& id, const moho::SCoordsVec2& pos, float heading) override;
    void CreateProp(const char* id, const Wm3::Vec3f& loc) override;
    void DestroyEntity(moho::EntId entityId) override;
    void WarpEntity(moho::EntId entityId, const moho::VTransform& transform) override;
    void ProcessInfoPair(moho::EntId entityId, gpg::StrArg key, gpg::StrArg value) override;
    void IssueCommand(
      const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities, const moho::SSTICommandIssueData& data, bool clear
    ) override;
    void IssueFactoryCommand(
      const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities, const moho::SSTICommandIssueData& data, bool clear
    ) override;
    void IncreaseCommandCount(moho::CmdId id, int count) override;
    void DecreaseCommandCount(moho::CmdId id, int count) override;
    void SetCommandTarget(moho::CmdId id, const moho::SSTITarget& target) override;
    void SetCommandType(moho::CmdId id, moho::EUnitCommandType type) override;
    void SetCommandCells(
      moho::CmdId id, const gpg::core::FastVector<moho::SOCellPos>& cells, const Wm3::Vector3<float>& target
    ) override;
    void RemoveCommandFromUnitQueue(moho::CmdId id, moho::EntId unitId) override;
    void ExecuteLuaInSim(const char* lua, const LuaPlus::LuaObject& args) override;
    void LuaSimCallback(
      const char* fnName, const LuaPlus::LuaObject& args, const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities
    ) override;
    void ExecuteDebugCommand(
      const char* command, const Wm3::Vector3<float>& worldPos, uint32_t focusArmy,
      const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities
    ) override;
    void AdvanceBeat(int beats) override;
    void EndGame() override;

  private:
    void Took(std::int32_t cookie) noexcept
    {
      mCookie = cookie;
      mHaveCookie = true;
    }

    moho::ISTIDriver& mServer;
    std::int32_t mCookie = 0;
    bool mHaveCookie = false;
    std::uint64_t mUnexpected = 0;
  };
} // namespace faf::remote::client
