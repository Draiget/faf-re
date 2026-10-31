#include "remote/FrameWindow.h"

#include <algorithm>

#include "remote/wire/BitStream.h"

// Engine addition, server mode: see FrameWindow.h.

namespace faf::remote
{
  const wire::SViewFrame* CServerFrameWindow::Baseline() const noexcept
  {
    if (mAcked == wire::kNoBaseline || mFrames.empty() || mFrames.front().frameId != mAcked) {
      return nullptr;
    }
    return &mFrames.front();
  }

  void CServerFrameWindow::Sent(const wire::SViewFrame& frame)
  {
    if (mSentAny && Baseline() == nullptr) {
      ++mFullFrames;
    }
    mSentAny = true;
    mFrames.push_back(frame);
    // The cap: past it the oldest frame goes, and with it, once it is the acknowledged one, the
    // baseline (the next frame then goes in full).
    while (mFrames.size() > kMaxFrames) {
      mFrames.pop_front();
    }
  }

  void CServerFrameWindow::Ack(const std::uint32_t frameId)
  {
    if (mAcked != wire::kNoBaseline && frameId <= mAcked) {
      return; // late or repeated: frame ids only grow
    }
    const auto found = std::find_if(mFrames.begin(), mFrames.end(), [frameId](const wire::SViewFrame& frame) {
      return frame.frameId == frameId;
    });
    if (found == mFrames.end()) {
      return; // no longer kept
    }
    mAcked = frameId;
    mFrames.erase(mFrames.begin(), found); // older frames are no baseline any more
  }

  bool CClientFrameWindow::Decode(
    const std::span<const std::uint8_t> bytes, const wire::SFrameCodec& codec, wire::SViewFrame& out
  )
  {
    const std::uint32_t baselineId = wire::PeekFrameBaseline(bytes);
    const wire::SViewFrame* baseline = nullptr;
    if (baselineId != wire::kNoBaseline) {
      const auto found = std::find_if(mFrames.begin(), mFrames.end(), [baselineId](const wire::SViewFrame& frame) {
        return frame.frameId == baselineId;
      });
      if (found == mFrames.end()) {
        return false;
      }
      baseline = &*found;
    }
    wire::BitReader reader(bytes);
    wire::SViewFrame decoded{};
    if (!wire::DecodeFrame(reader, baseline, codec, decoded)) {
      return false;
    }
    out = decoded;
    // Kept in id order: a frame that arrives late still goes before newer ones.
    const auto at = std::upper_bound(
      mFrames.begin(), mFrames.end(), decoded.frameId,
      [](const std::uint32_t id, const wire::SViewFrame& frame) { return id < frame.frameId; }
    );
    mFrames.insert(at, std::move(decoded));
    while (mFrames.size() > kMaxFrames) {
      mFrames.pop_front();
    }
    return true;
  }
} // namespace faf::remote
