#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "legacy/containers/AutoPtr.h"
#include "remote/client/RemoteClientManager.h"

// Engine addition, server mode (plan WP11.1): headless's `--command-check`. A remote client
// sends the server its commands as `CMarshaller` messages and the server decodes them with
// `CDecoder`; this check runs every command of a replay through that pair (decoded as the sim
// decodes it, marshalled again as a client would send it) and compares the bytes with the
// replay's. Identical bytes for every command show the two halves are each other's inverse on
// real games, Lua payloads included.

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
  class CReplayCommandCheck
  {
  public:
    explicit CReplayCommandCheck(moho::RRuleGameRules& rules);
    ~CReplayCommandCheck();

    /** Watches every message the sim's decoder receives from now on (one check at a time). */
    void Install();
    void Uninstall();

    [[nodiscard]] std::string Summary() const;
    /** Commands whose round trip differs or that did not come back (should stay 0). */
    [[nodiscard]] std::uint64_t Failures() const noexcept;

  private:
    static void Observe(const moho::CMessage& message, void* context);
    void OnMessage(const moho::CMessage& message);

    std::unique_ptr<LuaPlus::LuaState> mLuaState; // the decoder's own, apart from the sim's
    msvc8::auto_ptr<gpg::Stream> mNoRecording;
    std::vector<std::vector<char>> mCaptured;     // what the marshaller sent for one message
    faf::remote::client::CRemoteClientManager mCapture;
    std::unique_ptr<moho::CMarshaller> mMarshaller;
    std::unique_ptr<moho::CDecoder> mDecoder;
    bool mInside = false;
    std::uint64_t mMessages = 0;
    std::uint64_t mIdentical = 0;
    std::array<std::uint64_t, 256> mDiffering{};  // by opcode
    std::array<std::uint64_t, 256> mMissing{};    // decoded to no message (a dropped command)
    std::array<std::uint64_t, 256> mKeyOrderOnly{}; // a Lua table's pairs in another order only
    std::array<std::uint64_t, 256> mSeen{};
  };
} // namespace faf::headless
