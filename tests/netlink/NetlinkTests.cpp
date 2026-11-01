// netlink tests (issue #229).
//
//   faf_netlink_tests [--bind <local address>] [--datagrams N]
//
// Unit checks of the JSON, signalling and SDP code against what the shipped
// Java adapter writes, then two links in this process (offerer and answerer,
// host candidates only) that connect and exchange N datagrams each way with
// none lost or altered. Then the layers on top: the redundant lane (#240),
// our-peer detection (#234), duplication (#235) and the WebRTC data channel
// (#239). --bind picks the local address, for hosts that drop inbound UDP to
// sockets bound to every interface.

#include "netlink/Json.h"
#include "netlink/Link.h"
#include "netlink/Signal.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace faf::netlink;

namespace
{
  int gFailures = 0;

  void Check(const bool ok, const char* what)
  {
    std::printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) {
      ++gFailures;
    }
  }

  // From docs/launcher-adapter-contract/trace-2p.jsonl: the shipped adapter's
  // onIceMsg payload (one candidate kept).
  constexpr const char* kJavaMessage =
    R"({"srcId":101,"destId":102,"password":"6cmvb8d7e03sma550p6dtta5vn","ufrag":"eb31i1k68fj1m5",)"
    R"("candidates":[{"foundation":"1","protocol":"udp","priority":2130706431,"ip":"192.168.42.77","port":6271,)"
    R"("type":"HOST_CANDIDATE","generation":0,"id":"0","relAddr":null,"relPort":0}]})";

  void UnitTests()
  {
    // JSON round trip, escapes for the Java reader.
    {
      // \x5c is a backslash: the input holds escapes, a surrogate pair among them.
      std::optional<JsonValue> v = ParseJson("{\"a\":[1,-2,3.5,true,null,\"x\x5cu00e9\x5cud83d\x5cude00{\"]}");
      Check(v && v->IsObject(), "json parses an object");
      const JsonValue& a = v->Get("a");
      Check(a.Size() == 6 && a[0].AsInt() == 1 && a[1].AsInt() == -2 && a[2].AsDouble() == 3.5, "json numbers");
      Check(a[3].AsBool() && a[4].IsNull(), "json literals");
      Check(a[5].AsString() == "x\xc3\xa9\xf0\x9f\x98\x80{", "json \\u escapes decode to UTF-8");
      const std::string out = WriteJson(*v);
      Check(out == "{\"a\":[1,-2,3.5,true,null,\"x\x5cu00e9\x5cud83d\x5cude00\x5cu007b\"]}", "json writes ASCII only, braces escaped");
      Check(!ParseJson("{\"a\":1,}").has_value(), "json rejects a trailing comma");
      Check(ParseJson("2130706431").value().AsInt() == 2130706431, "json keeps 32-bit priorities exact");
    }
    // CandidatesMessage as Jackson writes and reads it.
    {
      std::optional<CandidatesMessage> m = CandidatesMessageFromJson(kJavaMessage);
      Check(m && m->srcId == 101 && m->destId == 102 && m->candidates.size() == 1, "reads the Java adapter's message");
      Check(m && m->candidates[0].type == CandidateType::Host && !m->candidates[0].relAddr, "candidate type and null relAddr");
      Check(m && ToJson(*m) == kJavaMessage, "writes it back byte for byte");
      Check(!CandidatesMessageFromJson(R"({"srcId":1,"destId":2,"password":"p","ufrag":"u"})"), "missing candidates rejected");
      Check(!CandidatesMessageFromJson(
              R"({"srcId":1,"destId":2,"password":"p","ufrag":"u","candidates":[{"type":"host"}]})"),
            "lower-case type rejected, as Jackson does");
    }
    // SDP lines.
    {
      std::optional<Candidate> c =
        CandidateFromSdp("a=candidate:12 1 UDP 1045759 192.168.42.77 55889 typ relay raddr 0.0.0.0 rport 0");
      Check(c && c->type == CandidateType::Relayed && c->priority == 1045759 && c->port == 55889 && !c->relAddr,
            "libjuice relay line; hidden base becomes null");
      std::optional<Candidate> s =
        CandidateFromSdp("a=candidate:3 1 UDP 1678767615 1.2.3.4 50000 typ srflx raddr 10.0.0.2 rport 6112");
      Check(s && s->relAddr && *s->relAddr == "10.0.0.2" && s->relPort == 6112, "srflx related address kept");
      Check(CandidateToSdp(*s) == "a=candidate:3 1 UDP 1678767615 1.2.3.4 50000 typ srflx raddr 10.0.0.2 rport 6112",
            "candidate back to SDP");
    }
    // setIceServers.
    {
      std::optional<JsonValue> list = ParseJson(
        R"([{"urls":["turn://h1:3478?transport=udp","turn:h1:3479?transport=tcp","stun:h1:3478","turns:h1:5349"],)"
        R"("username":"u","credential":"c"},{"url":"stun:[::1]:19302"}])");
      std::vector<IceServer> s = ParseIceServers(*list);
      Check(s.size() == 3, "ice servers: tcp and turns skipped");
      Check(s.size() == 3 && s[0].kind == IceServer::Kind::Turn && s[0].host == "h1" && s[0].port == 3478 &&
              s[0].username == "u" && s[0].credential == "c",
            "turn:// url with credentials");
      Check(s.size() == 3 && s[1].kind == IceServer::Kind::Stun && s[1].port == 3478, "opaque stun: url");
      Check(s.size() == 3 && s[2].host == "::1" && s[2].port == 19302, "bracketed IPv6 and the url key");
    }
  }

  struct Side
  {
    std::unique_ptr<Link> link;
    std::mutex mutex;
    std::vector<std::uint32_t> received;
    std::atomic<int> corrupt{0};
  };

  void LoopbackTest(const std::string& bind, const int count)
  {
    Side a;
    Side b;
    auto makeCallbacks = [](Side& self, Side& other, const char* name) {
      LinkCallbacks cb;
      cb.onSignal = [&other](const CandidatesMessage& m) {
        // Through JSON, as the lobby server relays it.
        other.link->OnSignal(*CandidatesMessageFromJson(ToJson(m)));
      };
      cb.onData = [&self](const std::uint8_t* data, const std::size_t size) {
        std::uint32_t seq = 0;
        if (size != 400) {
          ++self.corrupt;
          return;
        }
        std::memcpy(&seq, data, sizeof(seq));
        for (std::size_t i = sizeof(seq); i < size; ++i) {
          if (data[i] != static_cast<std::uint8_t>(seq + i)) {
            ++self.corrupt;
            return;
          }
        }
        std::lock_guard lock(self.mutex);
        self.received.push_back(seq);
      };
      cb.onState = [name](const LinkState s) { std::printf("  %s: %s\n", name, LinkStateName(s)); };
      cb.onLog = [name](const std::string& t) { std::printf("  %s: %s\n", name, t.c_str()); };
      return cb;
    };
    LinkOptions oa;
    oa.localId = 1;
    oa.remoteId = 2;
    oa.offerer = true;
    oa.bindAddress = bind;
    LinkOptions ob = oa;
    ob.localId = 2;
    ob.remoteId = 1;
    ob.offerer = false;
    a.link = std::make_unique<Link>(oa, makeCallbacks(a, b, "offerer"));
    b.link = std::make_unique<Link>(ob, makeCallbacks(b, a, "answerer"));

    std::atomic<bool> stop{false};
    std::thread ticker([&] {
      while (!stop) {
        a.link->Tick();
        b.link->Tick();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
    });
    a.link->Start();
    b.link->Start();

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    while (!(a.link->IsConnected() && b.link->IsConnected()) && std::chrono::steady_clock::now() < deadline) {
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    Check(a.link->IsConnected() && b.link->IsConnected(), "two links connect (offerer controls)");

    // Paced like a busy game: bursts of 50, then a short pause.
    std::uint8_t buf[400];
    for (int i = 0; i < count && a.link->IsConnected(); ++i) {
      for (std::size_t k = 0; k < sizeof(buf); ++k) {
        buf[k] = static_cast<std::uint8_t>(i + k);
      }
      const auto seq = static_cast<std::uint32_t>(i);
      std::memcpy(buf, &seq, sizeof(seq));
      a.link->Send(buf, sizeof(buf));
      b.link->Send(buf, sizeof(buf));
      if (i % 50 == 49) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1500)); // let echoes run too

    stop = true;
    ticker.join();
    const LinkStats sa = a.link->GetStats();
    const LinkStats sb = b.link->GetStats();
    std::printf("  offerer: sent %llu, received %zu, echoes %llu/%llu, rtt %.3f ms\n",
                static_cast<unsigned long long>(sa.dataSent), a.received.size(),
                static_cast<unsigned long long>(sa.echoesAnswered), static_cast<unsigned long long>(sa.echoesSent),
                sa.lastRttMs);
    std::printf("  answerer: sent %llu, received %zu\n", static_cast<unsigned long long>(sb.dataSent),
                b.received.size());
    Check(a.received.size() == static_cast<std::size_t>(count) && b.received.size() == static_cast<std::size_t>(count),
          "every datagram arrived on both sides");
    Check(a.corrupt == 0 && b.corrupt == 0, "no datagram altered");
    Check(sa.echoesAnswered > 0 && sa.lastRttMs >= 0, "the offerer's echoes come back");
    Check(sa.invalidReceived == 0 && sb.invalidReceived == 0, "no invalid first byte seen");
    a.link->Close();
    b.link->Close();
  }
  // Issue #240: two of our links with the redundant lane, dropping 10 % of the
  // lane's datagrams each way. Repeats bring nearly every game datagram
  // through, each once.
  void LaneTest(const std::string& bind, const int count)
  {
    Side a;
    Side b;
    std::atomic<int> laneOn{0};
    auto makeCallbacks = [&laneOn](Side& self, Side& other, const char* name) {
      LinkCallbacks cb;
      cb.onSignal = [&other](const CandidatesMessage& m) { other.link->OnSignal(*CandidatesMessageFromJson(ToJson(m))); };
      cb.onData = [&self](const std::uint8_t* data, const std::size_t size) {
        std::uint32_t seq = 0;
        if (size != 400) {
          ++self.corrupt;
          return;
        }
        std::memcpy(&seq, data, sizeof(seq));
        for (std::size_t i = sizeof(seq); i < size; ++i) {
          if (data[i] != static_cast<std::uint8_t>(seq + i)) {
            ++self.corrupt;
            return;
          }
        }
        std::lock_guard lock(self.mutex);
        self.received.push_back(seq);
      };
      cb.onLog = [name, &laneOn](const std::string& t) {
        std::printf("  %s: %s\n", name, t.c_str());
        if (t.find("redundant lane") != std::string::npos) {
          ++laneOn;
        }
      };
      return cb;
    };
    LinkOptions oa;
    oa.localId = 1;
    oa.remoteId = 2;
    oa.offerer = true;
    oa.bindAddress = bind;
    oa.ufragPrefix = kOurUfragPrefix;
    oa.redundancy = 2;
    oa.testDropPercent = 10;
    LinkOptions ob = oa;
    ob.localId = 2;
    ob.remoteId = 1;
    ob.offerer = false;
    a.link = std::make_unique<Link>(oa, makeCallbacks(a, b, "lane offerer"));
    b.link = std::make_unique<Link>(ob, makeCallbacks(b, a, "lane answerer"));

    std::atomic<bool> stop{false};
    std::thread ticker([&] {
      while (!stop) {
        a.link->Tick();
        b.link->Tick();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
    });
    a.link->Start();
    b.link->Start();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    while (laneOn.load() < 2 && std::chrono::steady_clock::now() < deadline) {
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    Check(laneOn.load() == 2, "both links moved onto the redundant lane");

    std::uint8_t buf[400];
    for (int i = 0; i < count && a.link->IsConnected(); ++i) {
      for (std::size_t k = 0; k < sizeof(buf); ++k) {
        buf[k] = static_cast<std::uint8_t>(i + k);
      }
      const auto seq = static_cast<std::uint32_t>(i);
      std::memcpy(buf, &seq, sizeof(seq));
      a.link->Send(buf, sizeof(buf));
      b.link->Send(buf, sizeof(buf));
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    stop = true;
    ticker.join();
    const LinkStats sa = a.link->GetStats();
    const auto distinct = [](Side& s) {
      std::lock_guard lock(s.mutex);
      std::vector<std::uint32_t> v = s.received;
      std::sort(v.begin(), v.end());
      return static_cast<std::size_t>(std::unique(v.begin(), v.end()) - v.begin());
    };
    const std::size_t da = distinct(a);
    const std::size_t db = distinct(b);
    std::printf("  lane, 10%% of lane datagrams dropped each way: offerer got %zu of %d, answerer %zu of %d; "
                "repeats %llu, run out unacked %llu\n",
                da, count, db, count, static_cast<unsigned long long>(sa.laneRepeats),
                static_cast<unsigned long long>(sa.laneUnacked));
    Check(sa.onLane, "the offerer reports the lane on");
    Check(da == a.received.size() && db == b.received.size(), "no game datagram delivered twice");
    Check(da >= static_cast<std::size_t>(count) * 985 / 1000 && db >= static_cast<std::size_t>(count) * 985 / 1000,
          "at least 98.5 % arrive through 10 % loss");
    Check(a.corrupt == 0 && b.corrupt == 0, "no datagram altered");
    a.link->Close();
    b.link->Close();
  }

  // Two links with the given options: connect, wait for `ready` (or 10 s),
  // send `count` 400-byte datagrams each way, let them settle. Datagrams are
  // checked as in LoopbackTest; `invalid` counts first bytes neither side knew.
  struct PairResult
  {
    bool connected = false;
    bool ready = false;
    LinkStats a;
    LinkStats b;
    std::vector<std::uint32_t> atA;
    std::vector<std::uint32_t> atB;
    int corrupt = 0;
    bool ourA = false;
    bool ourB = false;
  };

  PairResult RunPair(LinkOptions oa, LinkOptions ob, const int count, const std::function<bool(Link&, Link&)>& ready)
  {
    Side a;
    Side b;
    auto makeCallbacks = [](Side& self, Side& other) {
      LinkCallbacks cb;
      cb.onSignal = [&other](const CandidatesMessage& m) { other.link->OnSignal(*CandidatesMessageFromJson(ToJson(m))); };
      cb.onSignalText = [&other](const std::string& json) { other.link->OnSignalText(json); };
      cb.onData = [&self](const std::uint8_t* data, const std::size_t size) {
        std::uint32_t seq = 0;
        if (size != 400) {
          ++self.corrupt;
          return;
        }
        std::memcpy(&seq, data, sizeof(seq));
        for (std::size_t i = sizeof(seq); i < size; ++i) {
          if (data[i] != static_cast<std::uint8_t>(seq + i)) {
            ++self.corrupt;
            return;
          }
        }
        std::lock_guard lock(self.mutex);
        self.received.push_back(seq);
      };
      return cb;
    };
    oa.localId = 1;
    oa.remoteId = 2;
    oa.offerer = true;
    ob.localId = 2;
    ob.remoteId = 1;
    ob.offerer = false;
    a.link = std::make_unique<Link>(oa, makeCallbacks(a, b));
    b.link = std::make_unique<Link>(ob, makeCallbacks(b, a));

    std::atomic<bool> stop{false};
    std::thread ticker([&] {
      while (!stop) {
        a.link->Tick();
        b.link->Tick();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
    });
    a.link->Start();
    b.link->Start();

    PairResult r;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    while (!(a.link->IsConnected() && b.link->IsConnected()) && std::chrono::steady_clock::now() < deadline) {
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    r.connected = a.link->IsConnected() && b.link->IsConnected();
    deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (r.connected && !ready(*a.link, *b.link) && std::chrono::steady_clock::now() < deadline) {
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    r.ready = r.connected && ready(*a.link, *b.link);

    std::uint8_t buf[400];
    for (int i = 0; r.connected && i < count; ++i) {
      for (std::size_t k = 0; k < sizeof(buf); ++k) {
        buf[k] = static_cast<std::uint8_t>(i + k);
      }
      const auto seq = static_cast<std::uint32_t>(i);
      std::memcpy(buf, &seq, sizeof(seq));
      a.link->Send(buf, sizeof(buf));
      b.link->Send(buf, sizeof(buf));
      if (i % 50 == 49) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    stop = true;
    ticker.join();
    r.a = a.link->GetStats();
    r.b = b.link->GetStats();
    r.ourA = a.link->IsOurPeer();
    r.ourB = b.link->IsOurPeer();
    {
      std::lock_guard la(a.mutex);
      r.atA = a.received;
    }
    {
      std::lock_guard lb(b.mutex);
      r.atB = b.received;
    }
    r.corrupt = a.corrupt + b.corrupt;
    a.link->Close();
    b.link->Close();
    return r;
  }

  std::size_t Distinct(std::vector<std::uint32_t> v)
  {
    std::sort(v.begin(), v.end());
    return static_cast<std::size_t>(std::unique(v.begin(), v.end()) - v.begin());
  }

  // Issue #234: two marked links find each other ours; a marked link and an
  // unmarked one (as a Java adapter peer looks) never do, and the unmarked one
  // never gets a probe.
  void OurPeerTest(const std::string& bind)
  {
    LinkOptions marked;
    marked.bindAddress = bind;
    marked.ufragPrefix = kOurUfragPrefix;
    const PairResult ours =
      RunPair(marked, marked, 200, [](Link& a, Link& b) { return a.IsOurPeer() && b.IsOurPeer(); });
    Check(ours.connected && ours.ourA && ours.ourB, "two marked links prove each other ours");
    Check(ours.atA.size() == 200 && ours.atB.size() == 200 && ours.corrupt == 0, "and carry game datagrams as before");

    LinkOptions plain;
    plain.bindAddress = bind;
    const PairResult mixed = RunPair(marked, plain, 200, [](Link&, Link&) { return false; }); // waits the full 10 s
    Check(mixed.connected && !mixed.ourA && !mixed.ourB, "a marked link and an unmarked one: neither counts as ours");
    Check(mixed.b.invalidReceived == 0, "the unmarked side never received a probe");
    Check(mixed.atA.size() == 200 && mixed.atB.size() == 200 && mixed.corrupt == 0, "and game datagrams still flow");
  }

  // Issue #235: with duplicateGapMs 0 every game datagram goes out twice; the
  // link hands both copies on (the game drops the second by its sequence).
  void DuplicateTest(const std::string& bind)
  {
    LinkOptions o;
    o.bindAddress = bind;
    o.duplicateGapMs = 0;
    const PairResult r = RunPair(o, o, 500, [](Link&, Link&) { return true; });
    std::printf("  duplicates: offerer sent %llu with %llu copies; answerer got %zu (%zu distinct)\n",
                static_cast<unsigned long long>(r.a.dataSent), static_cast<unsigned long long>(r.a.duplicatesSent),
                r.atB.size(), Distinct(r.atB));
    Check(r.connected && r.a.duplicatesSent == r.a.dataSent && r.a.dataSent == 500, "every datagram sent with a copy");
    Check(r.atB.size() == 1000 && Distinct(r.atB) == 500, "both copies arrive, each datagram twice");
    Check(r.corrupt == 0, "no copy altered");

    LinkOptions later = o;
    later.duplicateGapMs = 20;
    const PairResult d = RunPair(later, later, 500, [](Link&, Link&) { return true; });
    Check(d.connected && d.atB.size() == 1000 && Distinct(d.atB) == 500, "a copy 20 ms later arrives too");
  }

  // Issue #239: two of our links that both offer WebRTC move game datagrams
  // onto a data channel.
  void WebRtcTest(const std::string& bind)
  {
    LinkOptions o;
    o.bindAddress = bind;
    o.ufragPrefix = kOurUfragPrefix;
    o.webrtc = true;
    const PairResult r =
      RunPair(o, o, 1000, [](Link& a, Link& b) { return a.GetStats().onWebRtc && b.GetStats().onWebRtc; });
    std::printf("  webrtc: offerer sent %llu, %llu on the data channel; got %zu\n",
                static_cast<unsigned long long>(r.a.dataSent), static_cast<unsigned long long>(r.a.webRtcSent),
                r.atA.size());
    Check(r.ready, "both links open the data channel");
    Check(r.a.webRtcSent == 1000 && r.b.webRtcSent == 1000, "every game datagram goes on the data channel");
    Check(r.atA.size() == 1000 && r.atB.size() == 1000 && r.corrupt == 0, "and arrives unaltered");
  }
} // namespace

int main(int argc, char** argv)
{
  std::string bind;
  int count = 10000;
  for (int i = 1; i + 1 < argc; i += 2) {
    if (std::strcmp(argv[i], "--bind") == 0) {
      bind = argv[i + 1];
    } else if (std::strcmp(argv[i], "--datagrams") == 0) {
      count = std::atoi(argv[i + 1]);
    }
  }
  UnitTests();
  LoopbackTest(bind, count);
  LaneTest(bind, 2000);
  OurPeerTest(bind);
  DuplicateTest(bind);
  WebRtcTest(bind);
  std::printf("%s (%d failures)\n", gFailures == 0 ? "PASS" : "FAIL", gFailures);
  return gFailures == 0 ? 0 : 1;
}
