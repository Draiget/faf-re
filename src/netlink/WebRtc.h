#pragma once

// Issue #239: layer 2, a WebRTC data channel between two of our peers. Link
// opens one beside its ICE link once both sides proved to be ours (#234) and
// both offer WebRTC; game datagrams then go over the channel, which is
// unordered with no retransmissions, so the game's own resends stay the only
// ones. The ICE link stays up underneath as the fallback.
//
// Signalling is JSON text that Link sends through the same iceMsg path as
// its CandidatesMessage, with a "webrtc" member (IsWebRtcSignal):
//   {"srcId":1,"destId":2,"webrtc":{"description":"<sdp>","type":"offer"}}
//   {"srcId":1,"destId":2,"webrtc":{"candidate":"<sdp line>","mid":"0"}}
//
// Threading: every method may be called from any thread. libdatachannel runs
// its own threads; onData is called from them. Signals queue until
// TakeSignals. Engine addition, not recovered code.

#include "netlink/Signal.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace faf::netlink
{
  struct WebRtcOptions
  {
    std::int64_t localId = 0;
    std::int64_t remoteId = 0;
    bool offerer = false;
    std::vector<IceServer> iceServers;
    bool forceRelay = false;
    std::string bindAddress;
  };

  // True for a signal of this channel, false for a CandidatesMessage.
  bool IsWebRtcSignal(const std::string& json);

  class WebRtcChannel
  {
  public:
    WebRtcChannel(WebRtcOptions options, std::function<void(const std::uint8_t*, std::size_t)> onData,
                  std::function<void(const std::string&)> onLog);
    ~WebRtcChannel();
    WebRtcChannel(const WebRtcChannel&) = delete;
    WebRtcChannel& operator=(const WebRtcChannel&) = delete;

    // The offerer creates the channel and its offer; the answerer waits.
    void Start();
    // A signal from the peer (IsWebRtcSignal).
    void OnSignal(const std::string& json);
    // Signals for the peer since the last call.
    std::vector<std::string> TakeSignals();
    bool IsOpen() const { return mOpen.load(); }
    // Whether it gave up (closed or failed); Link then stays on ICE.
    bool HasFailed() const { return mFailed.load(); }
    // One game datagram; false when the channel is not open.
    bool Send(const void* data, std::size_t size);
    void Close();

  private:
    struct Impl;
    const std::unique_ptr<Impl> mImpl;
    std::atomic<bool> mOpen{false};
    std::atomic<bool> mFailed{false};
  };
} // namespace faf::netlink
