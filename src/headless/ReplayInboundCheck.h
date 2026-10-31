#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <utility>
#include <string>
#include <vector>

#include "legacy/containers/AutoPtr.h"
#include "remote/InboundIds.h"
#include "remote/ViewFrames.h"
#include "remote/client/RemoteClientManager.h"

// Engine addition, server mode (plan WP5.10): headless's `--inbound-check`, with `--view-frames
// --view-ids`. Every command of the replay is sent once more as its client would send it to a
// server that renumbers ids: decoded, its ids rewritten into the view ids of the issuing source's
// army (only ids that view was given; remote/ViewIdMap.h), translated back by the server's
// `CInboundIdTranslator` (remote/InboundIds.h) and marshalled. The bytes must equal the same
// message decoded and marshalled with no ids touched. A command naming a renumbered id its view
// was never given cannot be sent in view ids at all; it is counted, with the first few named, and
// the translator drops it as the server would.
//
// It also audits the Lua arguments of every `LuaSimCallback` (plan WPR.19): a number, or a string
// of digits, that names an entity the sim has is an id the client put into a payload. Per callback
// name and key path the summary counts such ids: the caller's own army's, blips, and foreign ones
// (another army's or nobody's). Those keys are what the Lua routing policy (WP5.11) has to mark.

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

namespace faf::headless
{
  class CReplayInboundCheck
  {
  public:
    CReplayInboundCheck(moho::RRuleGameRules& rules, const remote::CViewFrames& views);
    ~CReplayInboundCheck();

    /** Watches every message the sim's decoder receives from now on (one decoder check at a time). */
    void Install();
    void Uninstall();

    [[nodiscard]] std::string Summary() const;
    /** Commands whose round trip through view ids differs from the plain one (should stay 0). */
    [[nodiscard]] std::uint64_t Failures() const noexcept { return mDiffering; }

  private:
    /** Sim ids into the view ids of the current source's army, as its client would have sent them. */
    class CClientSide final : public remote::CCommandIdRewriter
    {
    public:
      CClientSide(moho::ICommandSink& next, CReplayInboundCheck& owner) noexcept
        : CCommandIdRewriter(next)
        , mOwner(owner)
      {}

      void SetCommandSource(moho::CommandSourceId sourceId) override;
      void LuaSimCallback(
        const char* name, const LuaPlus::LuaObject& args, const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities
      ) override;

    protected:
      [[nodiscard]] bool RewriteEntity(std::uint32_t& id) override;
      [[nodiscard]] bool RewriteCommand(std::uint32_t& id) override;

    private:
      CReplayInboundCheck& mOwner;
    };

    /** Per callback name and key path: ids found, by whose they are. */
    struct SPayloadIds
    {
      std::uint64_t own = 0;
      std::uint64_t blips = 0;
      std::uint64_t foreign = 0;
      std::uint32_t example = 0; // the first id seen there
    };
    void AuditPayload(const std::string& callback, const LuaPlus::LuaObject& value, const std::string& path, int depth);
    void AuditValue(const std::string& callback, const std::string& path, double number);

    static void Observe(const moho::CMessage& message, void* context);
    void OnMessage(const moho::CMessage& message);
    void SelectSource(moho::CommandSourceId sourceId);
    [[nodiscard]] bool IsOwnCommand(std::uint32_t commandId) const;

    const remote::CViewFrames& mViews;
    std::unique_ptr<LuaPlus::LuaState> mLuaState; // the decoders' own, apart from the sim's
    msvc8::auto_ptr<gpg::Stream> mNoRecording;
    std::vector<std::vector<char>> mCaptured; // what a marshaller sent for one message
    faf::remote::client::CRemoteClientManager mCapture;
    std::unique_ptr<moho::CMarshaller> mMarshaller;
    remote::CViewIdMap mNoMap{-1};            // the translator's map before a source is known
    remote::CInboundIdTranslator mTranslator; // the server's intake
    CClientSide mClient;                      // the client's side
    std::unique_ptr<moho::CDecoder> mPlainDecoder; // decode and marshal, ids untouched
    std::unique_ptr<moho::CDecoder> mIdDecoder;    // decode, to view ids, back, marshal
    bool mInside = false;
    std::int32_t mArmy = -1;                  // the current source's army
    std::uint32_t mLastRefused = 0;           // the last entity id the client side looked up
    std::uint64_t mMessages = 0;
    std::uint64_t mBeforeViews = 0;           // before the first beat's views (no maps yet)
    std::uint64_t mIdentical = 0;
    std::uint64_t mDiffering = 0;
    std::uint64_t mNotShown = 0;              // named a renumbered id the view never got
    std::vector<std::string> mNotShownExamples;
    std::map<std::string, std::uint64_t> mCallbacks;                         // calls by name
    std::map<std::pair<std::string, std::string>, SPayloadIds> mPayloadIds; // (callback, key path)
  };
} // namespace faf::headless
