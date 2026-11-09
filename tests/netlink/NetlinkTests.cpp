// netlink tests (issue #229).
//
//   faf_netlink_tests [--bind <local address>] [--datagrams N]
//   faf_netlink_tests [--bind <local address>] --marker sealed|plain
//
// The second form only sends a readable marker over a sealed or a plain lane,
// for a packet capture (issue #289).
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
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

using namespace faf::netlink;

namespace
{
  std::string gBind;
  int gDatagrams = 10000;

  void Check(const bool ok, const char* what)
  {
    EXPECT_TRUE(ok) << what;
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

  // Link::Tick starts WebRTC holding the link's mutex and libjuice's registry
  // lock is taken inside; the poll thread holds that lock while it delivers lane
  // datagrams. Several links set up at once with traffic flowing, as in a game
  // of more than two players. A deadlock freezes every link, so a watchdog ends
  // the test: GetStats would block too.
  void LaneWebRtcSetupTest(const std::string& bind)
  {
    constexpr int kLinks = 7;
    constexpr int kRounds = 8;
    std::atomic<bool> finished{false};
    std::thread watchdog([&finished] {
      for (int i = 0; i < 1800 && !finished; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
      if (!finished) {
        std::printf("FAIL links froze while setting up WebRTC with the lane on (deadlock)\n");
        std::fflush(stdout);
        std::_Exit(1);
      }
    });
    bool allOpen = true;
    for (int round = 0; round < kRounds; ++round) {
      struct Pair
      {
        std::unique_ptr<Link> a;
        std::unique_ptr<Link> b;
      };
      std::vector<Pair> pairs(kLinks);
      for (Pair& pair : pairs) {
        LinkOptions o;
        o.bindAddress = bind;
        o.ufragPrefix = kOurUfragPrefix;
        o.webrtc = true;
        o.redundancy = 2;
        LinkOptions oa = o;
        oa.localId = 1;
        oa.remoteId = 2;
        oa.offerer = true;
        LinkOptions ob = o;
        ob.localId = 2;
        ob.remoteId = 1;
        LinkCallbacks ca;
        LinkCallbacks cb;
        Pair* raw = &pair;
        ca.onSignal = [raw](const CandidatesMessage& m) { raw->b->OnSignal(*CandidatesMessageFromJson(ToJson(m))); };
        ca.onSignalText = [raw](const std::string& json) { raw->b->OnSignalText(json); };
        cb.onSignal = [raw](const CandidatesMessage& m) { raw->a->OnSignal(*CandidatesMessageFromJson(ToJson(m))); };
        cb.onSignalText = [raw](const std::string& json) { raw->a->OnSignalText(json); };
        pair.a = std::make_unique<Link>(oa, std::move(ca));
        pair.b = std::make_unique<Link>(ob, std::move(cb));
      }
      std::atomic<bool> stop{false};
      // Each end on its own thread, as two players' processes run: one end's
      // lane datagrams must arrive while the other end is starting WebRTC.
      std::thread tickerA([&] {
        while (!stop) {
          for (Pair& pair : pairs) {
            pair.a->Tick();
          }
          std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
      });
      std::thread tickerB([&] {
        while (!stop) {
          for (Pair& pair : pairs) {
            pair.b->Tick();
          }
          std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
      });
      std::thread sender([&] {
        const std::uint8_t buf[200]{};
        while (!stop) {
          for (Pair& pair : pairs) {
            pair.a->Send(buf, sizeof(buf));
            pair.b->Send(buf, sizeof(buf));
          }
          std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
      });
      for (Pair& pair : pairs) {
        pair.a->Start();
        pair.b->Start();
      }
      const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
      bool open = false;
      while (!open && std::chrono::steady_clock::now() < deadline) {
        open = true;
        for (Pair& pair : pairs) {
          open = open && pair.a->GetStats().onWebRtc && pair.b->GetStats().onWebRtc;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
      allOpen = allOpen && open;
      stop = true;
      tickerA.join();
      tickerB.join();
      sender.join();
      for (Pair& pair : pairs) {
        pair.a->Close();
        pair.b->Close();
      }
    }
    finished = true;
    watchdog.join();
    Check(allOpen, "7 links set up WebRTC with the lane on and traffic flowing, 8 times, without freezing");
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

  // STUN and TURN servers that never answer (192.0.2.1 is reserved, RFC 5737)
  // keep libjuice gathering for 23.5 s. The links still connect by what they
  // found, in time for the offerer's wait for an answer.
  void SilentIceServerTest(const std::string& bind)
  {
    LinkOptions o;
    o.bindAddress = bind;
    IceServer stun;
    stun.host = "192.0.2.1";
    IceServer turn = stun;
    turn.kind = IceServer::Kind::Turn;
    turn.username = "u";
    turn.credential = "c";
    o.iceServers = {stun, turn};
    const PairResult r = RunPair(o, o, 200, [](Link&, Link&) { return true; });
    Check(r.connected && r.a.attempts == 1 && r.b.attempts == 1, "silent ICE servers: links connect on the first attempt");
    Check(r.atA.size() == 200 && r.atB.size() == 200 && r.corrupt == 0, "and carry game datagrams");
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

  // Issue #289: the key mark in the ufrag and the keys made from it.
  void KeyUnitTests()
  {
    LinkKeyPair a;
    LinkKeyPair b;
    Check(a.Generate() && b.Generate(), "keys: two key pairs from the system's random source");
    Check(a.Public() != b.Public(), "keys: two pairs differ");

    const std::string mark = KeyMarkFor(a.Public());
    Check(mark.size() == 2 + 64 && mark.rfind("k+", 0) == 0 && mark.find('+', 2) == std::string::npos,
          "keys: the mark is k+ and 64 hex digits, no further '+'");
    const std::string prefix = kOurUfragPrefix;
    for (const std::string marks : {std::string(""), std::string("c+"), std::string("w+c+")}) {
      const std::optional<LinkPublicKey> back = KeyFromUfrag(prefix + marks + mark, prefix);
      Check(back && *back == a.Public(), ("keys: read back after \"" + prefix + marks + "\"").c_str());
    }
    Check(!KeyFromUfrag("eb31i1k68fj1m5", prefix), "keys: a Java adapter's ufrag offers none");
    Check(!KeyFromUfrag(prefix + "c+a1b2c3d4", prefix), "keys: an older build's ufrag offers none");
    Check(!KeyFromUfrag(prefix + "c+" + mark + "0", prefix), "keys: 65 hex digits are refused");
    Check(!KeyFromUfrag(prefix + "c+" + mark.substr(0, mark.size() - 1), prefix), "keys: 63 hex digits are refused");
    std::string upper = prefix + "c+" + mark;
    for (char& c : upper) {
      c = (c >= 'a' && c <= 'f') ? static_cast<char>(c - 'a' + 'A') : c;
    }
    Check(!KeyFromUfrag(upper, prefix), "keys: upper-case hex is refused");
    Check(!KeyFromUfrag(prefix + "c+" + mark, ""), "keys: an unmarked link reads none");

    const auto ka = a.Derive(b.Public(), true);
    const auto kb = b.Derive(a.Public(), false);
    Check(ka && kb && ka->send == kb->receive && ka->receive == kb->send, "keys: offerer and answerer agree");
    Check(ka && ka->send != ka->receive, "keys: one key per direction");
    const auto swapped = b.Derive(a.Public(), true);
    Check(swapped && kb && swapped->send != kb->send, "keys: the role is part of the keys");
    LinkKeyPair c;
    Check(c.Generate(), "keys: a third pair");
    const auto kc = c.Derive(a.Public(), false);
    Check(kc && ka && kc->receive != ka->send, "keys: another peer's keys differ");
    const LinkPublicKey zero{};
    Check(!a.Derive(zero, true), "keys: a low-order public key (all zeros) gives none");
    LinkKeyPair unset;
    Check(!unset.Derive(a.Public(), true), "keys: a pair never generated gives none");
  }

  // Issue #289: two links with the lane seal it with keys from each other's
  // ufrag; one that doesn't offer keys still gets the lane, plain.
  void EncryptedLaneTest(const std::string& bind)
  {
    LinkOptions o;
    o.bindAddress = bind;
    o.ufragPrefix = kOurUfragPrefix;
    o.redundancy = 2;
    const PairResult r = RunPair(o, o, 1000, [](Link& a, Link& b) {
      return a.GetStats().laneEncrypted && b.GetStats().laneEncrypted;
    });
    std::printf("  encrypted lane: offerer got %zu, answerer %zu; unauthenticated dropped %llu / %llu\n",
                r.atA.size(), r.atB.size(), static_cast<unsigned long long>(r.a.laneUnauthenticated),
                static_cast<unsigned long long>(r.b.laneUnauthenticated));
    Check(r.ready && r.a.laneEncrypted && r.b.laneEncrypted, "both links seal the lane");
    Check(Distinct(r.atA) == 1000 && Distinct(r.atB) == 1000 && r.corrupt == 0, "every game datagram arrives unaltered");
    Check(r.a.laneUnauthenticated == 0 && r.b.laneUnauthenticated == 0, "no lane datagram refused");

    LinkOptions plain = o;
    plain.encrypt = false; // the ufrag an older build sends: fnl+c+<token>
    const PairResult m = RunPair(o, plain, 1000, [](Link& a, Link& b) { return a.GetStats().onLane && b.GetStats().onLane; });
    Check(m.ready && !m.a.laneEncrypted && !m.b.laneEncrypted, "with a peer offering no key: lane on, not sealed");
    Check(Distinct(m.atA) == 1000 && Distinct(m.atB) == 1000 && m.corrupt == 0, "and game datagrams still flow");

    LinkOptions noLane = o;
    noLane.redundancy = 0;
    const PairResult n = RunPair(o, noLane, 500, [](Link&, Link&) { return true; });
    Check(n.connected && !n.a.onLane && !n.b.onLane, "with a peer without the lane: plain 'd' frames");
    Check(n.atA.size() == 500 && n.atB.size() == 500 && n.corrupt == 0, "and game datagrams still flow");
  }

  // Issue #321: Reconnect on either end drops a sealed connection and the offerer
  // starts a new attempt; after GameEnded it does nothing. Whether the new attempt
  // connects needs a STUN or TURN server: an attempt within 2 minutes of another
  // offers no host candidates (kForceSrflxCount, as the Java adapter), and this
  // test has none. A game with a TURN server checks that part.
  void ReconnectTest(const std::string& bind, const bool onOfferer)
  {
    const char* const side = onOfferer ? "offerer" : "answerer";
    std::unique_ptr<Link> a;
    std::unique_ptr<Link> b;
    std::atomic<bool> answererDropped{false};
    // Offers the offerer has made: a new attempt. Its ICE checks may not start (attempts
    // counts those): without a STUN or TURN server, an attempt within 2 minutes of another
    // has no candidate to offer, and an empty answer ends it at once (issue #275).
    std::atomic<int> offers{0};
    auto callbacks = [&](std::unique_ptr<Link>& other, const char* name) {
      LinkCallbacks cb;
      cb.onSignal = [&other](const CandidatesMessage& m) { other->OnSignal(*CandidatesMessageFromJson(ToJson(m))); };
      cb.onLog = [name, &offers](const std::string& text) {
        std::printf("    %s: %s\n", name, text.c_str());
        if (text.rfind("initiating ICE as offerer", 0) == 0) {
          ++offers;
        }
      };
      cb.onConnected = [&answererDropped, name](const bool up) {
        if (!up && std::strcmp(name, "answerer") == 0) {
          answererDropped = true;
        }
      };
      return cb;
    };
    LinkOptions o;
    o.bindAddress = bind;
    o.ufragPrefix = kOurUfragPrefix;
    o.redundancy = 2;
    LinkOptions oa = o;
    oa.localId = 1;
    oa.remoteId = 2;
    oa.offerer = true;
    LinkOptions ob = o;
    ob.localId = 2;
    ob.remoteId = 1;
    a = std::make_unique<Link>(oa, callbacks(b, "offerer"));
    b = std::make_unique<Link>(ob, callbacks(a, "answerer"));
    std::atomic<bool> stop{false};
    std::thread ticker([&] {
      while (!stop) {
        a->Tick();
        b->Tick();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
    });
    const auto waitFor = [](const int seconds, const std::function<bool()>& done) {
      const auto t0 = std::chrono::steady_clock::now();
      while (!done() && std::chrono::steady_clock::now() < t0 + std::chrono::seconds(seconds)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
      }
      return std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    };
    const auto sealedUp = [&] {
      return a->IsConnected() && b->IsConnected() && a->GetStats().laneEncrypted && b->GetStats().laneEncrypted;
    };
    a->Start();
    b->Start();
    waitFor(20, sealedUp);
    Check(sealedUp(), (std::string("reconnect on the ") + side + ": the pair connects, lane sealed").c_str());

    Link& asked = onOfferer ? *a : *b;
    if (onOfferer) {
      // The answerer still answers new offers after its own GameEnded.
      b->SetGameEnded();
      b->Reconnect();
      std::this_thread::sleep_for(std::chrono::milliseconds(300));
      Check(sealedUp() && a->GetStats().attempts == 1, "after GameEnded, Reconnect does nothing");
    }

    const int before = offers.load();
    asked.Reconnect();
    const double seconds = waitFor(20, [&] { return answererDropped.load() && offers.load() > before; });
    std::printf("  reconnect on the %s: dropped and offer %d made after %.1f s\n", side, offers.load(), seconds);
    Check(answererDropped.load() && offers.load() > before,
          (std::string("reconnect on the ") + side + ": the connection drops and the offerer starts a new attempt").c_str());

    if (onOfferer) {
      // Issue #322: a picked path holds over the attempt policy, so "no relay" offers
      // host candidates again and the pair comes back.
      PathChoice direct;
      direct.mode = PathChoice::Mode::NoRelay;
      a->Reconnect(direct);
      const double back = waitFor(20, sealedUp);
      const LinkStats s = a->GetStats();
      std::printf("  reconnect with 'no relay': connected %d after %.1f s, path %s/%s, picked %s\n", sealedUp(), back,
                  s.localType.c_str(), s.remoteType.c_str(), PathChoiceText(s.choice).c_str());
      Check(sealedUp() && s.choice == direct && s.localType == "host",
            "reconnect with a picked path: 'no relay' connects over host candidates, lane sealed");
    }

    stop = true;
    ticker.join();
    a->Close();
    b->Close();
  }

  // Issue #275: an answer with no candidate the offerer may use (here: the offerer takes relayed
  // candidates only, and there is no relay) ends the attempt at once, not after kCheckTimeout.
  void EmptyAnswerTest(const std::string& bind)
  {
    std::unique_ptr<Link> a;
    std::unique_ptr<Link> b;
    std::mutex logMutex;
    std::vector<std::string> offererLog;
    LinkCallbacks ca;
    ca.onSignal = [&b](const CandidatesMessage& m) { b->OnSignal(*CandidatesMessageFromJson(ToJson(m))); };
    ca.onLog = [&](const std::string& text) {
      std::lock_guard lock(logMutex);
      offererLog.push_back(text);
    };
    LinkCallbacks cb;
    cb.onSignal = [&a](const CandidatesMessage& m) { a->OnSignal(*CandidatesMessageFromJson(ToJson(m))); };
    LinkOptions oa;
    oa.bindAddress = bind;
    oa.localId = 1;
    oa.remoteId = 2;
    oa.offerer = true;
    oa.forceRelay = true; // takes relayed candidates only; with no TURN server there are none
    LinkOptions ob;
    ob.bindAddress = bind;
    ob.localId = 2;
    ob.remoteId = 1;
    a = std::make_unique<Link>(oa, ca);
    b = std::make_unique<Link>(ob, cb);
    std::atomic<bool> stop{false};
    std::thread ticker([&] {
      while (!stop) {
        a->Tick();
        b->Tick();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
    });
    const auto said = [&](const char* text) {
      std::lock_guard lock(logMutex);
      return std::any_of(offererLog.begin(), offererLog.end(),
                         [&](const std::string& line) { return line.find(text) != std::string::npos; });
    };
    const auto t0 = std::chrono::steady_clock::now();
    a->Start();
    b->Start();
    while (!said("no usable candidates in the answer") && std::chrono::steady_clock::now() < t0 + std::chrono::seconds(20)) {
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    const double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    std::printf("  empty answer: attempt ended after %.1f s\n", seconds);
    Check(said("no usable candidates in the answer"), "an answer with nothing usable ends the attempt");
    Check(seconds < 8.0, "and well before the 15 s of checks");
    stop = true;
    ticker.join();
    a->Close();
    b->Close();
  }

  // Issue #289, for a packet capture: sends `count` datagrams that hold a
  // readable marker each way, on a lane that is sealed (sealed=true) or plain,
  // and prints the ufrags signalled. A capture of the sealed run must not hold
  // the marker; the plain run is the control that shows the capture sees it.
  int MarkerRun(const std::string& bind, const bool sealed, const int count)
  {
    static constexpr char kMarker[] = "FAF-PLAINTEXT-MARKER-289";
    struct End
    {
      std::unique_ptr<Link> link;
      std::atomic<int> got{0};
    };
    End a;
    End b;
    auto callbacks = [](End& self, End& other, const char* name) {
      LinkCallbacks cb;
      cb.onSignal = [&other, name](const CandidatesMessage& m) {
        const std::string json = ToJson(m);
        std::printf("  %s signals: %s\n", name, json.c_str());
        other.link->OnSignal(*CandidatesMessageFromJson(json));
      };
      cb.onData = [&self](const std::uint8_t* data, const std::size_t size) {
        if (size >= sizeof(kMarker) - 1 && std::memcmp(data, kMarker, sizeof(kMarker) - 1) == 0) {
          ++self.got;
        }
      };
      return cb;
    };
    LinkOptions o;
    o.bindAddress = bind;
    o.ufragPrefix = kOurUfragPrefix;
    o.redundancy = 2;
    o.encrypt = sealed;
    LinkOptions oa = o;
    oa.localId = 1;
    oa.remoteId = 2;
    oa.offerer = true;
    LinkOptions ob = o;
    ob.localId = 2;
    ob.remoteId = 1;
    a.link = std::make_unique<Link>(oa, callbacks(a, b, "offerer"));
    b.link = std::make_unique<Link>(ob, callbacks(b, a, "answerer"));
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
    while (!(a.link->GetStats().onLane && b.link->GetStats().onLane) && std::chrono::steady_clock::now() < deadline) {
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    char buf[200] = {};
    std::snprintf(buf, sizeof(buf), "%s game datagram text that must not be readable on the wire", kMarker);
    for (int i = 0; i < count; ++i) {
      a.link->Send(buf, sizeof(buf));
      b.link->Send(buf, sizeof(buf));
      std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    stop = true;
    ticker.join();
    const LinkStats sa = a.link->GetStats();
    const LinkStats sb = b.link->GetStats();
    std::printf("marker run %s: lane %d/%d, sealed %d/%d, received %d / %d of %d\n", sealed ? "sealed" : "plain",
                sa.onLane, sb.onLane, sa.laneEncrypted, sb.laneEncrypted, a.got.load(), b.got.load(), count);
    a.link->Close();
    b.link->Close();
    const bool ok = sa.onLane && sb.onLane && sa.laneEncrypted == sealed && sb.laneEncrypted == sealed &&
                    a.got.load() == count && b.got.load() == count;
    return ok ? 0 : 1;
  }
} // namespace

TEST(Existing_Netlink, UnitTests) { UnitTests(); }
TEST(Existing_Netlink, KeyUnitTests) { KeyUnitTests(); }
TEST(Existing_Netlink, EncryptedLane) { EncryptedLaneTest(gBind); }
TEST(Existing_Netlink, ReconnectOnOfferer) { ReconnectTest(gBind, true); }
TEST(Existing_Netlink, ReconnectOnAnswerer) { ReconnectTest(gBind, false); }
TEST(Existing_Netlink, EmptyAnswer) { EmptyAnswerTest(gBind); }
TEST(Existing_Netlink, Loopback) { LoopbackTest(gBind, gDatagrams); }
TEST(Existing_Netlink, Lane) { LaneTest(gBind, 2000); }
TEST(Existing_Netlink, OurPeer) { OurPeerTest(gBind); }
TEST(Existing_Netlink, SilentIceServer) { SilentIceServerTest(gBind); }
TEST(Existing_Netlink, Duplicate) { DuplicateTest(gBind); }
TEST(Existing_Netlink, WebRtc) { WebRtcTest(gBind); }
TEST(Existing_Netlink, LaneWebRtcSetup) { LaneWebRtcSetupTest(gBind); }

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  std::string marker;
  for (int i = 1; i + 1 < argc; i += 2) {
    if (std::strcmp(argv[i], "--bind") == 0) {
      gBind = argv[i + 1];
    } else if (std::strcmp(argv[i], "--datagrams") == 0) {
      gDatagrams = std::atoi(argv[i + 1]);
    } else if (std::strcmp(argv[i], "--marker") == 0) {
      marker = argv[i + 1]; // sealed | plain: only the capture run (#289); reconnect: only #321's tests
    }
  }
  if (marker == "reconnect") {
    GTEST_FLAG_SET(filter, "Existing_Netlink.Reconnect*");
    return RUN_ALL_TESTS();
  }
  if (!marker.empty()) {
    return MarkerRun(gBind, marker == "sealed", 500);
  }
  return RUN_ALL_TESTS();
}
