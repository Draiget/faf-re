#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <span>

#include "remote/wire/EntityFrame.h"

// Engine addition, server mode (plan WP5.3, §7.1): which frame a view's next frame is encoded
// against. Snapshots travel unreliably, so the server encodes each frame against the newest frame
// the client acknowledged; creations and removals ride inside the delta, so a lost frame costs
// freshness, never consistency. The server keeps the frames it sent from that acknowledged one
// on, at most `kMaxFrames` of them; when the acknowledged frame falls out (or none was
// acknowledged yet) the next frame goes in full. The client keeps the frames it decoded, as many,
// and decodes each new one against the frame its header names.

namespace faf::remote
{
  inline constexpr std::size_t kMaxFrames = 32;

  class CServerFrameWindow
  {
  public:
    /** The frame the next one is encoded against: the newest acknowledged one still kept, or null. */
    [[nodiscard]] const wire::SViewFrame* Baseline() const noexcept;

    /** `frame` went out (encoded against `Baseline()`); kept as a possible baseline. */
    void Sent(const wire::SViewFrame& frame);

    /** The client acknowledged `frameId` (its newest decoded frame). Older acknowledgements are ignored. */
    void Ack(std::uint32_t frameId);

    [[nodiscard]] std::size_t Kept() const noexcept { return mFrames.size(); }
    /** Frames sent in full after the first: no acknowledged frame was left to encode against. */
    [[nodiscard]] std::uint64_t FullFrames() const noexcept { return mFullFrames; }

  private:
    std::deque<wire::SViewFrame> mFrames; // sent, oldest first; the front is the acknowledged one once there is one
    std::uint32_t mAcked = wire::kNoBaseline;
    bool mSentAny = false;
    std::uint64_t mFullFrames = 0;
  };

  class CClientFrameWindow
  {
  public:
    /**
     * Decodes one frame against the kept frame its header names (or none for a full frame) and
     * keeps it. False for a frame whose baseline is not kept, or that does not decode.
     */
    [[nodiscard]] bool Decode(std::span<const std::uint8_t> bytes, const wire::SFrameCodec& codec, wire::SViewFrame& out);

    /** The newest frame decoded (what the client acknowledges), or `kNoBaseline`. */
    [[nodiscard]] std::uint32_t Newest() const noexcept { return mFrames.empty() ? wire::kNoBaseline : mFrames.back().frameId; }

  private:
    std::deque<wire::SViewFrame> mFrames; // decoded, oldest first
  };
} // namespace faf::remote
