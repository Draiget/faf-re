#pragma once

#include <optional>
#include <string>

#include "remote/FrameBuilder.h"
#include "remote/client/RemoteClientManager.h"
#include "remote/client/SyncRebuilder.h"
#include "remote/wire/Roster.h"
#include "remote/wire/EntityFrame.h"
#include "remote/wire/OrdinalTable.h"

// Engine addition, server mode (plan WP11): the wire between a sim and a client, in one process.
// Each sync packet goes through the server side of the entities lane (frame builder, optional
// dead reckoning, encoder against the last frame sent) and the client side (decoder,
// `CSyncRebuilder`), which rewrites the packet's entity lanes from the frames. The GUI client's
// `/loopback` (`CRemoteSimDriver`) and faf-replay's `--loopback` both run it.

namespace moho
{
  class RRuleGameRules;
  struct SSyncData;
}

namespace faf::remote::client
{
  struct SLoopbackOptions
  {
    /** Dead-reckoning tolerance in quantiser steps (1/64 unit); 0: off. */
    std::uint32_t deadReckoningTolerance = 0;
    /** With dead reckoning (WP7.8): the fitted window, the bent vertical fit and sub-steps. */
    std::uint32_t reckoningWindow = 1;          // measured (WP7.8): a longer fit sends more, saves nothing
    bool reckonVerticalAcceleration = false;    // likewise the bend
    std::uint32_t velocityFractionBits = 0;
    /** Orientation reckoning tolerance in 1/65536 turns; 0: off (every change is sent). */
    std::uint32_t orientationTolerance = 0;

    // Session requests as a server takes them (WP11.1). The defaults change nothing.
    static constexpr int kNoArmyLock = -2;
    /** The view's army as the server fixes it: a request for another is refused. */
    int lockedArmy = kNoArmyLock;
    /** Cameras go to the server at most once in this many milliseconds (0: every frame). */
    std::uint32_t geomCamsIntervalMs = 0;
  };

  /** The codec for a map of that size, with dead reckoning when the options ask for it. */
  [[nodiscard]] wire::SFrameCodec MakeLoopbackCodec(float mapSizeX, float mapSizeZ, const SLoopbackOptions& options);

  class CLoopbackLink
  {
  public:
    CLoopbackLink(moho::RRuleGameRules& rules, const wire::SFrameCodec& codec, const SLoopbackOptions& options);

    /** One beat through the wire; `packet` comes out rebuilt. */
    void Pass(moho::SSyncData& packet);

    /**
     * The roster (WP11.4): the stand-in's clients as the server reads them, sent through the
     * wire whenever they change (a ping or quiet time at most once a second) into `facade`,
     * which then answers the roster questions; chat for a client is relayed to the stand-in's.
     * Once per beat, after `Pass`.
     */
    void PassRoster(moho::IClientManager& standIn, CRemoteClientManager& facade);

    [[nodiscard]] const wire::SContentTables& Tables() const noexcept { return mTables; }
    /** Why the client refused the server's hello at connect (WP7.2), or empty: then `Pass` does nothing. */
    [[nodiscard]] const std::string& Refusal() const noexcept { return mRefusal; }
    [[nodiscard]] const SRebuildStats& Stats() const noexcept { return mRebuilder.Stats(); }
    [[nodiscard]] bool DeadReckoning() const noexcept { return mReckoner.has_value(); }

    /** Two lines (no trailing newline): traffic and timing, then the checks, which should all be 0. */
    [[nodiscard]] std::string Summary(const char* when) const;

    /** The sum of the check counters that must stay 0. */
    [[nodiscard]] std::uint64_t CheckFailures() const noexcept;

  private:
    wire::SContentTables mTables;       // the server's
    wire::SContentTables mClientContent; // the client's, built on its own from its rules
    std::string mRefusal;
    wire::SFrameCodec mCodec;
    wire::CSessionTableWriters mServerTables;
    wire::CSessionTableReaders mClientTables;
    CViewFrameBuilder mBuilder;
    std::optional<CDeadReckoner> mReckoner;
    wire::SViewFrame mLastSent;
    bool mHasSent = false;
    std::uint64_t mEncodeFailures = 0;
    std::uint64_t mRebuildFailures = 0;
    std::uint64_t mTableFailures = 0;
    std::uint64_t mTableBytes = 0; // session-table records (the reliable stream)
    // The roster (WP11.4).
    wire::SRoster mSentRoster;
    bool mHaveSentRoster = false;
    std::uint32_t mRosterBeat = 0;     // beats since the last roster sent
    std::uint64_t mRostersSent = 0;
    std::uint64_t mRosterBytes = 0;
    std::uint64_t mRosterFailures = 0;   // a roster that did not decode as sent
    std::uint64_t mRosterMismatches = 0; // the facade answering otherwise than the stand-in
    double mServerSeconds = 0.0; // building and encoding frames
    double mClientSeconds = 0.0; // decoding and rebuilding packets
    double mMaxBeatSeconds = 0.0;
    CSyncRebuilder mRebuilder;
  };
} // namespace faf::remote::client
