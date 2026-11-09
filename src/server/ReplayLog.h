#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include "gpg/core/streams/Stream.h"

// Engine addition, dedicated server (plan WP13.1, WP15.3; design research/WP13.1-observer-stream.md): the game's replay
// as it is written, kept for observers and the live replay. The sim's driver writes the replay (`CDecoder` records each
// command message) into a `CReplayTee`, which passes every byte to the replay file and appends it to a `CReplayLog`
// with the time it was written. Whoever sends the replay on (an observer's connection, FAF's live replay service) reads
// the log from its own thread, only the bytes written long enough ago: nobody sees the game sooner than its delay.

namespace faf::server
{
  class CReplayLog
  {
  public:
    /** On the writer's thread (the sim's): `size` bytes written at `nowUs`. */
    void Append(const char* data, std::size_t size, std::uint64_t nowUs);
    /** No more bytes will come (the replay file closed). */
    void Finish() noexcept;

    /**
     * From any thread: the bytes from `offset` written at or before `untilUs`, at most `maxBytes`, appended to `out`.
     * Returns how many; 0 when none are that old yet (or `offset` is past them).
     */
    std::size_t Read(std::size_t offset, std::uint64_t untilUs, std::size_t maxBytes, std::vector<std::uint8_t>& out) const;
    [[nodiscard]] std::size_t Size() const;
    [[nodiscard]] bool Finished() const;

  private:
    mutable std::mutex mLock;
    std::vector<std::uint8_t> mBytes;
    // Each write's end offset and time, in order: times only grow, so the bytes old enough end at one of these.
    std::vector<std::pair<std::size_t, std::uint64_t>> mMarks;
    bool mFinished = false;
  };

  /** A replay stream that writes to `inner` (the replay file) and to `log`. Write and flush only, as `CDecoder` uses it. */
  class CReplayTee final : public gpg::Stream
  {
  public:
    using Clock = std::function<std::uint64_t()>; // microseconds, steady

    CReplayTee(std::unique_ptr<gpg::Stream> inner, std::shared_ptr<CReplayLog> log, Clock clock);
    ~CReplayTee() override;

    void VirtWrite(const char* data, std::size_t size) override;
    void VirtFlush() override;
    void VirtClose(Mode mode) override;

  private:
    std::unique_ptr<gpg::Stream> mInner;
    std::shared_ptr<CReplayLog> mLog;
    Clock mClock;
  };
} // namespace faf::server
