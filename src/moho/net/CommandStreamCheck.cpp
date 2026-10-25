#include "moho/net/CommandStreamCheck.h"

#include <algorithm>
#include <cstring>
#include <utility>

#include "moho/net/CMessage.h"

namespace moho
{
  namespace
  {
    // Boundaries kept per stream. Acks arrive within the game's latency, a few
    // dozen beats at most; a report older than this cannot be checked.
    constexpr std::size_t kMaxBoundaries = 4096;

    // Reports about beats this client has not reached, per stream. Honest
    // reporters are a few beats ahead; anything past this is dropped.
    constexpr std::size_t kMaxPendingReports = 1024;

    // Beat order with wrap, as the client code compares beats.
    [[nodiscard]] bool BeatBefore(const std::uint32_t lhs, const std::uint32_t rhs) noexcept
    {
      return static_cast<std::int32_t>(lhs - rhs) < 0;
    }
  } // namespace

  CommandStreamCheck::CommandStreamCheck(const std::size_t clientCount, const bool stopOnDivergence)
    : mStreams(clientCount)
    , mStopOnDivergence(stopOnDivergence)
  {}

  void CommandStreamCheck::Append(const int sender, const CMessage& message)
  {
    if (sender < 0 || static_cast<std::size_t>(sender) >= mStreams.size()) {
      return;
    }
    mStreams[static_cast<std::size_t>(sender)].hash.Update(message.mBuff.start_, message.mBuff.Size());
  }

  CommandStreamCheck::AckDigest CommandStreamCheck::NoteBoundary(const int sender, const std::uint32_t queuedBeat)
  {
    AckDigest digest{};
    if (sender < 0 || static_cast<std::size_t>(sender) >= mStreams.size()) {
      return digest;
    }

    Stream& stream = mStreams[static_cast<std::size_t>(sender)];
    const gpg::SHA256::Digest full = stream.hash.Snapshot();
    std::memcpy(digest.data(), full.data(), digest.size());

    stream.boundaries.push_back({queuedBeat, digest});
    if (stream.boundaries.size() > kMaxBoundaries) {
      stream.boundaries.pop_front();
      stream.forgotOldest = true;
    }

    // Reports this boundary settles; the rest wait for later boundaries.
    std::vector<Report> waiting;
    std::vector<Report> due;
    for (const Report& report : stream.pending) {
      (Reached(stream, report.beat) ? due : waiting).push_back(report);
    }
    stream.pending = std::move(waiting);
    for (const Report& report : due) {
      Check(sender, report);
    }
    return digest;
  }

  void CommandStreamCheck::NoteReport(
    const int reporter, const int sender, const std::uint32_t beat, const AckDigest& digest
  )
  {
    if (sender < 0 || static_cast<std::size_t>(sender) >= mStreams.size()) {
      return;
    }

    Stream& stream = mStreams[static_cast<std::size_t>(sender)];
    const Report report{reporter, beat, digest};
    if (Reached(stream, beat)) {
      Check(sender, report);
    } else if (stream.pending.size() < kMaxPendingReports) {
      stream.pending.push_back(report);
    }
  }

  bool CommandStreamCheck::Reached(const Stream& stream, const std::uint32_t beat) const noexcept
  {
    return !stream.boundaries.empty() && !BeatBefore(stream.boundaries.back().beat, beat);
  }

  bool CommandStreamCheck::ProvenAltered(const int sender) const noexcept
  {
    return sender >= 0 && static_cast<std::size_t>(sender) < mStreams.size() &&
           mStreams[static_cast<std::size_t>(sender)].provenAltered;
  }

  std::vector<CommandStreamCheck::Divergence> CommandStreamCheck::TakeFindings()
  {
    return std::exchange(mFindings, {});
  }

  void CommandStreamCheck::Check(const int sender, const Report& report)
  {
    // Checking goes on after a difference: a later report from the sender
    // itself can still prove which side it was.
    const Stream& stream = mStreams[static_cast<std::size_t>(sender)];
    if (BeatBefore(report.beat, stream.boundaries.front().beat)) {
      if (stream.forgotOldest) {
        return; // older than what is kept; cannot be checked
      }
      Fail(sender, report.reporter, report.beat); // before this stream's first boundary
      return;
    }

    // Every boundary of the stream at that beat (an advance of zero beats
    // repeats one) is a match; a beat this stream never stopped at is not.
    for (auto it = stream.boundaries.rbegin(); it != stream.boundaries.rend(); ++it) {
      if (BeatBefore(it->beat, report.beat)) {
        break;
      }
      if (it->beat == report.beat && it->digest == report.digest) {
        return;
      }
    }
    Fail(sender, report.reporter, report.beat);
  }

  void CommandStreamCheck::Fail(const int sender, const int reporter, const std::uint32_t beat)
  {
    const Divergence divergence{sender, reporter, beat};
    if (!mDiverged) {
      mDiverged = true;
      mFirst = divergence;
    }

    // One finding per sender from others' reports, and one for its own.
    Stream& stream = mStreams[static_cast<std::size_t>(sender)];
    if (sender == reporter) {
      if (!stream.provenAltered) {
        stream.provenAltered = true;
        mFindings.push_back(divergence);
      }
    } else if (!stream.reported && !stream.provenAltered) {
      stream.reported = true;
      mFindings.push_back(divergence);
    }
  }
} // namespace moho
