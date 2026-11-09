#include "server/ReplayLog.h"

#include <algorithm>

// Engine addition, dedicated server: see ReplayLog.h.

namespace faf::server
{
  void CReplayLog::Append(const char* const data, const std::size_t size, const std::uint64_t nowUs)
  {
    if (size == 0u) {
      return;
    }
    const std::scoped_lock lock(mLock);
    mBytes.insert(mBytes.end(), reinterpret_cast<const std::uint8_t*>(data), reinterpret_cast<const std::uint8_t*>(data) + size);
    // A clock that went back still keeps the times in order, so `Read`'s search holds.
    const std::uint64_t at = mMarks.empty() ? nowUs : std::max(nowUs, mMarks.back().second);
    mMarks.emplace_back(mBytes.size(), at);
  }

  void CReplayLog::Finish() noexcept
  {
    const std::scoped_lock lock(mLock);
    mFinished = true;
  }

  std::size_t CReplayLog::Read(
    const std::size_t offset, const std::uint64_t untilUs, const std::size_t maxBytes, std::vector<std::uint8_t>& out
  ) const
  {
    const std::scoped_lock lock(mLock);
    // The last write at or before `untilUs`: everything up to its end offset is old enough.
    const auto after = std::upper_bound(mMarks.begin(), mMarks.end(), untilUs, [](const std::uint64_t time, const auto& mark) { return time < mark.second; });
    if (after == mMarks.begin()) {
      return 0u;
    }
    const std::size_t end = std::prev(after)->first;
    if (offset >= end) {
      return 0u;
    }
    const std::size_t count = std::min(end - offset, maxBytes);
    out.insert(out.end(), mBytes.begin() + static_cast<std::ptrdiff_t>(offset), mBytes.begin() + static_cast<std::ptrdiff_t>(offset + count));
    return count;
  }

  std::size_t CReplayLog::Size() const
  {
    const std::scoped_lock lock(mLock);
    return mBytes.size();
  }

  bool CReplayLog::Finished() const
  {
    const std::scoped_lock lock(mLock);
    return mFinished;
  }

  CReplayTee::CReplayTee(std::unique_ptr<gpg::Stream> inner, std::shared_ptr<CReplayLog> log, Clock clock)
    : mInner(std::move(inner))
    , mLog(std::move(log))
    , mClock(std::move(clock))
  {}

  CReplayTee::~CReplayTee()
  {
    if (mLog) {
      mLog->Finish();
    }
    // `mInner` closes the replay file as it goes.
  }

  void CReplayTee::VirtWrite(const char* const data, const std::size_t size)
  {
    if (mInner) {
      mInner->Write(data, size);
    }
    if (mLog) {
      mLog->Append(data, size, mClock());
    }
  }

  void CReplayTee::VirtFlush()
  {
    if (mInner) {
      mInner->VirtFlush();
    }
  }

  void CReplayTee::VirtClose(const Mode mode)
  {
    if (mInner) {
      mInner->VirtClose(mode);
    }
    if (mLog && (mode & ModeSend) != 0) {
      mLog->Finish();
    }
  }
} // namespace faf::server
