#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <string>

#include "legacy/containers/AutoPtr.h"
#include "remote/InboundIds.h"
#include "remote/client/RemoteClientManager.h"

// Engine addition, dedicated server: headless's `--target-audit`, with `--seats-listen`. A server drops a
// command whose target its view holds no record of (remote/InboundIds.h): a real unit keeps the sim's number,
// so a modified client could otherwise name one it can't see, and watch its own unit set off towards it.
// That mustn't cost a real player an order. So every entity target a recorded player named is looked up as
// the server would, and counted by the kind of entity, with the first few that wouldn't have gone through
// named. A recording was made by a lockstep client, which holds more than a server's view does, so what
// this counts is the most that could ever be refused, not what would be.

namespace gpg
{
  class Stream;
}

namespace LuaPlus
{
  class LuaState;
}

namespace moho
{
  class CDecoder;
  class CMarshaller;
  class RRuleGameRules;
  struct CMessage;
} // namespace moho

namespace faf::remote
{
  class CViewFrames;
}

namespace faf::headless
{
  class CReplayTargetAudit
  {
  public:
    CReplayTargetAudit(moho::RRuleGameRules& rules, remote::CViewFrames& views);
    ~CReplayTargetAudit();

    void Install();
    void Uninstall();

    [[nodiscard]] std::string Summary() const;

  private:
    /** Passes every id as it is, and looks at each target. */
    class CSink final : public remote::CCommandIdRewriter
    {
    public:
      CSink(moho::ICommandSink& next, CReplayTargetAudit& owner) noexcept
        : CCommandIdRewriter(next)
        , mOwner(owner)
      {}

      void SetCommandSource(moho::CommandSourceId sourceId) override;

    protected:
      [[nodiscard]] bool RewriteEntity(std::uint32_t&) override { return true; }
      [[nodiscard]] bool RewriteCommand(std::uint32_t&) override { return true; }
      [[nodiscard]] bool AllowTarget(std::uint32_t id) override;

    private:
      CReplayTargetAudit& mOwner;
    };

    static void Observe(const moho::CMessage& message, void* context);
    void OnMessage(const moho::CMessage& message);
    void NoteTarget(std::uint32_t id);

    remote::CViewFrames& mViews;
    std::unique_ptr<LuaPlus::LuaState> mLuaState; // the decoder's own, apart from the sim's
    fa::auto_ptr<gpg::Stream> mNoRecording;
    faf::remote::client::CRemoteClientManager mCapture;
    std::unique_ptr<moho::CMarshaller> mMarshaller;
    CSink mSink;
    std::unique_ptr<moho::CDecoder> mDecoder;
    std::int32_t mArmy = -1; // the current source's army
    bool mInside = false;
    static constexpr std::size_t kFamilies = 16u; // an entity id's top 4 bits
    std::array<std::uint64_t, kFamilies> mHeld{};
    std::array<std::uint64_t, kFamilies> mNotHeld{};
    std::uint64_t mRenumbered = 0; // blips and foreign projectiles, which the id map decides
    std::string mExamples;
    std::uint32_t mExampleCount = 0;
  };
} // namespace faf::headless
