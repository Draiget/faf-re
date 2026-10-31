#include "netlink/WebRtc.h"

#include "netlink/Json.h"

#include <rtc/rtc.hpp>

#include <exception>
#include <mutex>
#include <optional>
#include <utility>
#include <variant>

namespace faf::netlink
{
  bool IsWebRtcSignal(const std::string& json)
  {
    const std::optional<JsonValue> v = ParseJson(json);
    return v && v->IsObject() && v->Find("webrtc") != nullptr;
  }

  struct WebRtcChannel::Impl
  {
    WebRtcOptions options;
    std::function<void(const std::uint8_t*, std::size_t)> onData;
    std::function<void(const std::string&)> onLog;

    std::mutex mutex; // the members below
    std::shared_ptr<rtc::PeerConnection> pc;
    std::shared_ptr<rtc::DataChannel> channel;
    std::vector<std::string> outbox;
    bool closed = false;

    void Log(const std::string& text) const
    {
      if (onLog) {
        onLog("webrtc: " + text);
      }
    }

    void Queue(JsonValue body)
    {
      JsonValue m = JsonValue::Object();
      m.Set("srcId", options.localId);
      m.Set("destId", options.remoteId);
      m.Set("webrtc", std::move(body));
      std::lock_guard lock(mutex);
      outbox.push_back(WriteJson(m));
    }
  };

  WebRtcChannel::WebRtcChannel(WebRtcOptions options, std::function<void(const std::uint8_t*, std::size_t)> onData,
                               std::function<void(const std::string&)> onLog)
    : mImpl(std::make_unique<Impl>())
  {
    mImpl->options = std::move(options);
    mImpl->onData = std::move(onData);
    mImpl->onLog = std::move(onLog);
  }

  WebRtcChannel::~WebRtcChannel()
  {
    Close();
  }

  void WebRtcChannel::Start()
  {
    Impl& in = *mImpl;
    rtc::Configuration config;
    for (const IceServer& s : in.options.iceServers) {
      if (s.kind == IceServer::Kind::Turn) {
        config.iceServers.emplace_back(s.host, s.port, s.username, s.credential, rtc::IceServer::RelayType::TurnUdp);
      } else {
        config.iceServers.emplace_back(s.host, s.port);
      }
    }
    if (!in.options.bindAddress.empty()) {
      config.bindAddress = in.options.bindAddress;
    }
    if (in.options.forceRelay) {
      config.iceTransportPolicy = rtc::TransportPolicy::Relay;
    }

    try {
      auto pc = std::make_shared<rtc::PeerConnection>(config);
      Impl* raw = mImpl.get();
      pc->onLocalDescription([raw](rtc::Description d) {
        JsonValue body = JsonValue::Object();
        body.Set("description", std::string(d));
        body.Set("type", d.typeString());
        raw->Queue(std::move(body));
      });
      pc->onLocalCandidate([raw](rtc::Candidate c) {
        JsonValue body = JsonValue::Object();
        body.Set("candidate", c.candidate());
        body.Set("mid", c.mid());
        raw->Queue(std::move(body));
      });
      pc->onStateChange([this, raw](rtc::PeerConnection::State s) {
        if (s == rtc::PeerConnection::State::Failed || s == rtc::PeerConnection::State::Closed) {
          if (!mFailed.exchange(true)) {
            raw->Log(s == rtc::PeerConnection::State::Failed ? "connection failed" : "connection closed");
          }
          mOpen = false;
        }
      });

      auto wire = [this, raw](const std::shared_ptr<rtc::DataChannel>& dc) {
        dc->onOpen([this, raw] {
          mOpen = true;
          raw->Log("data channel open, game datagrams move onto it");
        });
        dc->onClosed([this, raw] {
          if (mOpen.exchange(false)) {
            raw->Log("data channel closed, game datagrams back on the ICE link");
          }
          mFailed = true;
        });
        dc->onMessage([raw](rtc::message_variant m) {
          if (const auto* b = std::get_if<rtc::binary>(&m); b != nullptr && raw->onData) {
            raw->onData(reinterpret_cast<const std::uint8_t*>(b->data()), b->size());
          }
        });
      };

      if (in.options.offerer) {
        rtc::DataChannelInit init;
        init.reliability.unordered = true;
        init.reliability.maxRetransmits = 0;
        auto dc = pc->createDataChannel("game", init);
        wire(dc);
        std::lock_guard lock(in.mutex);
        in.channel = dc;
      } else {
        pc->onDataChannel([raw, wire](std::shared_ptr<rtc::DataChannel> dc) {
          wire(dc);
          std::lock_guard lock(raw->mutex);
          raw->channel = std::move(dc);
        });
      }
      std::lock_guard lock(in.mutex);
      in.pc = std::move(pc);
    } catch (const std::exception& e) {
      in.Log(std::string("could not start: ") + e.what());
      mFailed = true;
    }
  }

  void WebRtcChannel::OnSignal(const std::string& json)
  {
    Impl& in = *mImpl;
    std::shared_ptr<rtc::PeerConnection> pc;
    {
      std::lock_guard lock(in.mutex);
      pc = in.pc;
    }
    const std::optional<JsonValue> v = ParseJson(json);
    const JsonValue* body = v ? v->Find("webrtc") : nullptr;
    if (!pc || body == nullptr || !body->IsObject()) {
      return;
    }
    try {
      if (const JsonValue* d = body->Find("description"); d != nullptr && d->IsString()) {
        pc->setRemoteDescription(rtc::Description(d->AsString(), body->Get("type").AsString()));
      } else if (const JsonValue* c = body->Find("candidate"); c != nullptr && c->IsString()) {
        pc->addRemoteCandidate(rtc::Candidate(c->AsString(), body->Get("mid").AsString()));
      }
    } catch (const std::exception& e) {
      in.Log(std::string("bad signal: ") + e.what());
    }
  }

  std::vector<std::string> WebRtcChannel::TakeSignals()
  {
    std::lock_guard lock(mImpl->mutex);
    std::vector<std::string> out;
    out.swap(mImpl->outbox);
    return out;
  }

  bool WebRtcChannel::Send(const void* data, const std::size_t size)
  {
    if (!mOpen.load()) {
      return false;
    }
    std::shared_ptr<rtc::DataChannel> dc;
    {
      std::lock_guard lock(mImpl->mutex);
      dc = mImpl->channel;
    }
    if (!dc) {
      return false;
    }
    try {
      return dc->send(static_cast<const std::byte*>(data), size);
    } catch (const std::exception&) {
      return false; // closing under us; Link falls back to ICE
    }
  }

  void WebRtcChannel::Close()
  {
    std::shared_ptr<rtc::PeerConnection> pc;
    std::shared_ptr<rtc::DataChannel> dc;
    {
      std::lock_guard lock(mImpl->mutex);
      if (mImpl->closed) {
        return;
      }
      mImpl->closed = true;
      pc = std::move(mImpl->pc);
      dc = std::move(mImpl->channel);
    }
    mOpen = false;
    try {
      if (dc) {
        dc->resetCallbacks();
        dc->close();
      }
      if (pc) {
        pc->resetCallbacks();
        pc->close();
      }
    } catch (const std::exception&) {
    }
  }
} // namespace faf::netlink
