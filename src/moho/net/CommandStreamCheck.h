#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <vector>

#include "gpg/core/algorithms/SHA256.h"

namespace moho
{
  struct CMessage;

  /**
   * Engine addition, not in the binary: checks that every player received the
   * same command stream from each player.
   *
   * In lockstep every client runs every player's orders, so a player who sends
   * different orders to different players desyncs the game at will. Each
   * client hashes each player's stream as it arrives and puts the hash at each
   * beat boundary (an `CMDST_Advance`) into the `CLIMSG_Ack` it already
   * broadcasts for that boundary. Every client receives everyone's acks before
   * it may run a beat, so it compares each reported hash with its own first,
   * and a difference is found before any client of ours runs a beat the
   * difference touches. Nothing here enters the sim or the recorded stream.
   *
   * A difference names two players: the one whose stream differs, and the
   * one whose report showed it. When those are the same player, its own
   * acknowledgement disagrees with what reached us from it: it sent us
   * something other than it says it sent (or the bytes were changed on the
   * way). Otherwise either it sent different orders or the reporter lied.
   *
   * Lag and reordering cannot cause a difference. Each stream arrives in
   * order over its own connection, a report about a beat this client has not
   * reached waits for it, and a late report is checked against the beats
   * kept. The test suite runs games with reordered and delayed delivery.
   *
   * The digest goes after the ack's existing fields; the shipped engine reads
   * those fields only and does not look past them.
   */
  class CommandStreamCheck
  {
  public:
    /// Bytes of the stream hash a `CLIMSG_Ack` carries after its fields.
    static constexpr std::size_t kAckDigestBytes = 16;
    using AckDigest = std::array<std::uint8_t, kAckDigestBytes>;

    /// The first difference found: `sender`'s stream as `reporter` reported it
    /// at `beat` is not the stream this client received.
    struct Divergence
    {
      int sender{-1};
      int reporter{-1};
      std::uint32_t beat{0};
    };

    /**
     * `stopOnDivergence`: whether a difference stops the game here. Off by
     * default (net_CheckOrderStreams 1): no client can tell a player who sent
     * different orders from one who lies about what it received, so stopping
     * would hand anyone a way to freeze a game with one false report. The
     * difference is reported either way.
     */
    CommandStreamCheck(std::size_t clientCount, bool stopOnDivergence);

    /** One command-stream message `sender` sent, in stream order. */
    void Append(int sender, const CMessage& message);

    /**
     * `sender`'s stream reached `queuedBeat` (the message just appended was
     * its `CMDST_Advance`). Returns the hash to put in this boundary's ack, and
     * checks the reports that were waiting for this client to get here.
     */
    AckDigest NoteBoundary(int sender, std::uint32_t queuedBeat);

    /** `reporter` acknowledged `sender`'s stream at `beat` with `digest`. */
    void NoteReport(int reporter, int sender, std::uint32_t beat, const AckDigest& digest);

    [[nodiscard]] bool Diverged() const noexcept { return mDiverged; }
    [[nodiscard]] bool StopsGame() const noexcept { return mDiverged && mStopOnDivergence; }
    [[nodiscard]] bool StopsOnDivergence() const noexcept { return mStopOnDivergence; }
    [[nodiscard]] const Divergence& FirstDivergence() const noexcept { return mFirst; }

    /**
     * Whether `sender`'s own acknowledgement has disagreed with what reached
     * this client from it. Its checksum reports then say nothing about this
     * client's game. Only the sender's own acks can set this, so no other
     * player can get it set against an honest one.
     */
    [[nodiscard]] bool ProvenAltered(int sender) const noexcept;

    /** Whether there are findings `TakeFindings` has not handed out yet. */
    [[nodiscard]] bool HasFindings() const noexcept { return !mFindings.empty(); }

    /**
     * The findings to tell the user about, oldest first: each sender's first
     * difference, and the proof once its own acknowledgement shows one.
     */
    [[nodiscard]] std::vector<Divergence> TakeFindings();

  private:
    struct Boundary
    {
      std::uint32_t beat;
      AckDigest digest;
    };

    struct Report
    {
      int reporter;
      std::uint32_t beat;
      AckDigest digest;
    };

    struct Stream
    {
      gpg::SHA256 hash;
      std::deque<Boundary> boundaries; // oldest first
      std::vector<Report> pending;     // reports about boundaries not reached yet
      bool forgotOldest{false};        // boundaries before the first kept were dropped
      bool reported{false};            // a difference found from another player's report
      bool provenAltered{false};       // a difference found from the sender's own report
    };

    [[nodiscard]] bool Reached(const Stream& stream, std::uint32_t beat) const noexcept;
    void Check(int sender, const Report& report);
    void Fail(int sender, int reporter, std::uint32_t beat);

    std::vector<Stream> mStreams;
    bool mStopOnDivergence;
    bool mDiverged{false};
    Divergence mFirst{};
    std::vector<Divergence> mFindings;
  };
} // namespace moho
