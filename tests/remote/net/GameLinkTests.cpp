// Engine addition: tests for how a player gets a channel on a game server (src/remote/net/Handshake.h,
// GameLinks.h, UdpSocket.h; plan WP10.1, WP10.5). The handshake in memory, then both ends over real
// sockets on the loopback address. Exit code = failures.
//
// Build: cmake --build --preset linux-clang-x64-release-plain --target faf_gamelink_tests
// Run:   build/linux-clang-x64-release-plain/faf_gamelink_tests

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <random>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "remote/net/Datagram.h"
#include "remote/net/GameLinks.h"
#include "remote/net/Handshake.h"
#include "remote/net/NetChannel.h"
#include "remote/net/UdpSocket.h"

using namespace faf::remote::net;

namespace
{
  void Check(const bool ok, const char* const what)
  {
    EXPECT_TRUE(ok) << what;
  }

  constexpr std::uint64_t kAddress = 0x7F00000104D2ull;
  constexpr std::uint64_t kNow = 100'000'000ull;
  constexpr std::int32_t kUid = 1001;

  struct SMemoryHandshake
  {
    SMemoryHandshake()
      : token(MakeToken("secret")), client(kUid, token)
    {
      Check(jar.Init(), "a random secret");
      const auto hello = WriteHello();
      const auto challenge = AnswerHello(hello.data(), hello.size(), jar, kAddress, kNow);
      connect = client.OnChallenge(challenge.data(), challenge.size());
    }

    Token token;
    CCookieJar jar;
    CClientHandshake client;
    std::vector<std::uint8_t> connect;
  };

  void HandshakeAgreesOnKeys()
  {
    SMemoryHandshake handshake;
    SConnectRequest request;
    Check(ReadConnect(handshake.connect.data(), handshake.connect.size(), request), "a Connect reads");
    Check(request.uid == kUid, "with its uid");
    Check(handshake.jar.Check(request.cookie, kAddress, kNow), "and a cookie that holds");

    const auto session = AnswerConnect(request, handshake.token);
    Check(session.has_value(), "the right token gets in");
    if (!session) {
      return;
    }
    const auto keys = handshake.client.OnAccept(session->accept.data(), session->accept.size());
    Check(keys.has_value(), "and the client trusts the answer");
    if (!keys) {
      return;
    }
    Check(keys->send == session->keys.receive && keys->receive == session->keys.send, "both ends hold the same keys");
    Check(keys->send != keys->receive, "one for each direction");

    NetChannel clientChannel;
    NetChannel serverChannel;
    (void)clientChannel.SetKeys(*keys);
    (void)serverChannel.SetKeys(session->keys);
    const char text[] = "hello";
    (void)clientChannel.SendReliable(text, sizeof(text));
    std::vector<std::vector<std::uint8_t>> out;
    clientChannel.Poll(1000u, out);
    Check(!out.empty(), "the channel sends");
    for (const auto& datagram : out) {
      Check(serverChannel.Receive(datagram.data(), datagram.size(), 2000u) == ReceiveResult::Accepted, "and the other end opens it");
    }
    std::vector<std::uint8_t> got;
    Check(serverChannel.TakeReliable(got) && got.size() == sizeof(text), "the message arrives");
  }

  void HandshakeRefusals()
  {
    SMemoryHandshake handshake;
    SConnectRequest request;
    (void)ReadConnect(handshake.connect.data(), handshake.connect.size(), request);

    Check(!AnswerConnect(request, MakeToken("wrong")).has_value(), "a wrong token gets nothing");
    SConnectRequest changed = request;
    changed.uid = 1002;
    Check(!AnswerConnect(changed, handshake.token).has_value(), "the proof covers the uid");
    changed = request;
    changed.clientPublic[0] ^= 1u;
    Check(!AnswerConnect(changed, handshake.token).has_value(), "and the public key");
    changed = request;
    changed.cookie[0] ^= 1u;
    Check(!AnswerConnect(changed, handshake.token).has_value(), "and the cookie");

    // A token holder sending a low-order point would make the exchange predictable.
    CCookieJar jar;
    (void)jar.Init();
    SConnectRequest degenerate = request;
    degenerate.clientPublic.fill(0u);
    Check(!AnswerConnect(degenerate, handshake.token).has_value(), "a bad proof first");

    const auto session = AnswerConnect(request, handshake.token);
    if (session) {
      std::vector<std::uint8_t> forged = session->accept;
      forged[forged.size() - 1u] ^= 1u;
      Check(!handshake.client.OnAccept(forged.data(), forged.size()).has_value(), "a forged Accept is refused");
      forged = session->accept;
      forged[2] ^= 1u;
      Check(!handshake.client.OnAccept(forged.data(), forged.size()).has_value(), "and one with another key");
    }
    CClientHandshake stranger(kUid, MakeToken("wrong"));
    const auto hello = WriteHello();
    const auto challenge = AnswerHello(hello.data(), hello.size(), handshake.jar, kAddress, kNow);
    (void)stranger.OnChallenge(challenge.data(), challenge.size());
    if (session) {
      Check(!stranger.OnAccept(session->accept.data(), session->accept.size()).has_value(), "someone in the middle without the token gets no keys");
    }
  }

  void CookiesAndHello()
  {
    CCookieJar jar;
    Check(jar.Init(), "a random secret");
    const Cookie cookie = jar.Make(kAddress, kNow);
    Check(jar.Check(cookie, kAddress, kNow), "a cookie holds at once");
    Check(jar.Check(cookie, kAddress, kNow + CCookieJar::kPeriodUs), "and through the next period");
    Check(!jar.Check(cookie, kAddress, kNow + 2u * CCookieJar::kPeriodUs), "and no longer");
    Check(!jar.Check(cookie, kAddress + 1u, kNow), "only for its address");
    CCookieJar other;
    (void)other.Init();
    Check(!other.Check(cookie, kAddress, kNow), "only from its server");

    std::vector<std::uint8_t> hello = WriteHello();
    Check(hello.size() == kHelloSize, "a Hello is padded");
    const auto answer = AnswerHello(hello.data(), hello.size(), jar, kAddress, kNow);
    Check(!answer.empty() && answer.size() < hello.size(), "and gets back less than it sent");
    Check(AnswerHello(hello.data(), hello.size() - 1u, jar, kAddress, kNow).empty(), "a short one gets nothing");
    hello[2] = 0xFFu;
    const auto version = AnswerHello(hello.data(), hello.size(), jar, kAddress, kNow);
    Check(version.size() == kRejectSize && version[2] == static_cast<std::uint8_t>(EHandshakeRefusal::Version), "another version is told so");
  }

  void Endpoints()
  {
    SEndpoint endpoint;
    Check(ParseEndpoint("192.0.2.7:7777", endpoint) && endpoint.ip == 0xC0000207u && endpoint.port == 7777u, "an address reads");
    Check(endpoint.Text() == "192.0.2.7:7777", "and writes back");
    for (const char* const bad : {"", "1.2.3", "1.2.3.4", "1.2.3.4:", "1.2.3.4:0", "1.2.3.4:70000", "1.2.3.256:80", "a.b.c.d:80", "1.2.3.4:80x"}) {
      SEndpoint ignored;
      Check(!ParseEndpoint(bad, ignored), "a bad address doesn't read");
    }
  }

  class CEvents final : public CServerLinks::IEvents
  {
  public:
    void OnJoined(const std::int32_t uid, const SEndpoint&, const bool returning) override
    {
      ++joined[uid];
      returns += returning ? 1 : 0;
    }
    void OnMessage(const std::int32_t uid, const std::vector<std::uint8_t>& message) override { messages[uid].push_back(message); }
    void OnLost(const std::int32_t uid) override { ++lost[uid]; }

    std::map<std::int32_t, int> joined;
    std::map<std::int32_t, int> lost;
    std::map<std::int32_t, std::vector<std::vector<std::uint8_t>>> messages;
    int returns = 0;
  };

  constexpr SEndpoint kLoopbackAnyPort{0x7F000001u, 0u};

  /** Runs both ends until `done` or `limitUs` of their shared clock has gone by; true when it's done. */
  template <class Done>
  [[nodiscard]] bool RunUntil(CServerLinks& server, CEvents& events, std::vector<CClientLink*> clients, std::uint64_t& nowUs, const std::uint64_t limitUs, Done done)
  {
    const std::uint64_t end = nowUs + limitUs;
    while (nowUs < end) {
      server.Pump(nowUs, events);
      for (CClientLink* const client : clients) {
        client->Pump(nowUs);
      }
      if (done()) {
        return true;
      }
      server.Wait(1);
      nowUs += 2000u;
    }
    return false;
  }

  void OverRealSockets()
  {
    CServerLinks server;
    std::string error;
    Check(server.Open(kLoopbackAnyPort, error), "the server binds");
    Check(server.Local().port != 0u, "and knows its port");
    server.AddPlayer(1, MakeToken("one"));
    server.AddPlayer(2, MakeToken("two"));
    CEvents events;
    std::uint64_t nowUs = 1000u;

    CClientLink one(1, MakeToken("one"), server.Local());
    CClientLink two(2, MakeToken("two"), server.Local());
    Check(one.Open(error) && two.Open(error), "the clients open");
    Check(RunUntil(server, events, {&one, &two}, nowUs, 2'000'000u, [&] { return one.State() == CClientLink::EState::Connected && two.State() == CClientLink::EState::Connected; }), "two players join");
    Check(events.joined[1] == 1 && events.joined[2] == 1 && events.returns == 0, "each once");

    const std::uint8_t text[] = {1, 2, 3};
    Check(one.SendReliable(text, sizeof(text)), "a player sends");
    Check(RunUntil(server, events, {&one, &two}, nowUs, 2'000'000u, [&] { return events.messages[1].size() == 1u; }), "the server gets it");
    Check(events.messages[2].empty(), "from that player only");

    server.SendUnreliableToAll(text, sizeof(text));
    std::vector<std::uint8_t> got;
    Check(RunUntil(server, events, {&one, &two}, nowUs, 2'000'000u, [&] { return two.TakeUnreliable(got); }) && got.size() == sizeof(text), "the server sends to everyone");

    // The wrong token, an unknown uid.
    CClientLink wrong(1, MakeToken("guess"), server.Local());
    CClientLink stranger(99, MakeToken("one"), server.Local());
    Check(wrong.Open(error) && stranger.Open(error), "more clients open");
    Check(RunUntil(server, events, {&one, &two, &wrong, &stranger}, nowUs, 2'000'000u, [&] { return wrong.State() == CClientLink::EState::Refused && stranger.State() == CClientLink::EState::Refused; }), "a wrong token and a stranger are refused");
    Check(wrong.Refusal() == EHandshakeRefusal::NotAdmitted, "as not admitted");
    Check(events.joined[1] == 1 && events.returns == 0, "and knock nobody out");

    // Noise, from a socket with no channel: nothing happens, and it's counted.
    CUdpSocket noise;
    Check(noise.Open(kLoopbackAnyPort, error), "a noise socket opens");
    std::minstd_rand random(1234u);
    std::array<std::uint8_t, 1400> junk{};
    const std::uint64_t strangersBefore = server.Stats().strangersDropped;
    for (int i = 0; i < 2000; ++i) {
      std::generate(junk.begin(), junk.end(), [&] { return static_cast<std::uint8_t>(random()); });
      const std::size_t size = random() % junk.size();
      if (i % 4 == 0 && size > 0u) {
        junk[0] = kDatagramTag;
      } else if (i % 4 == 1 && size > 1u) {
        junk[0] = kHandshakeTag;
        junk[1] = static_cast<std::uint8_t>(random() % 7u);
      }
      (void)noise.SendTo(junk.data(), size, server.Local());
      if (i % 64 == 0) {
        server.Pump(nowUs, events);
      }
    }
    Check(RunUntil(server, events, {&one, &two}, nowUs, 200'000u, [] { return false; }) == false, "the game goes on through it");
    Check(server.Stats().strangersDropped > strangersBefore, "noise is dropped");
    Check(one.State() == CClientLink::EState::Connected && two.State() == CClientLink::EState::Connected, "and both players stay");

    // A Connect from an earlier session, sent again, can't take the channel over.
    CUdpSocket raw;
    Check(raw.Open(kLoopbackAnyPort, error), "a raw socket opens");
    CClientHandshake earlier(1, MakeToken("one"));
    const auto hello = WriteHello();
    (void)raw.SendTo(hello.data(), hello.size(), server.Local());
    std::array<std::uint8_t, 256> buffer{};
    SEndpoint from;
    int size = -1;
    for (int i = 0; i < 200 && size < 0; ++i) {
      server.Pump(nowUs, events);
      raw.Wait(1);
      size = raw.ReceiveFrom(buffer.data(), buffer.size(), from);
    }
    Check(size == static_cast<int>(kChallengeSize), "the raw socket gets a challenge");
    const auto connect = earlier.OnChallenge(buffer.data(), static_cast<std::size_t>(size));
    (void)raw.SendTo(connect.data(), connect.size(), server.Local());
    Check(RunUntil(server, events, {&two}, nowUs, 2'000'000u, [&] { return events.returns == 1; }), "a holder of the token takes the seat back");
    Check(events.joined[1] == 2, "as a return");
    const int joinsBefore = events.joined[1];
    one.Reconnect();
    Check(RunUntil(server, events, {&one, &two}, nowUs, 2'000'000u, [&] { return one.State() == CClientLink::EState::Connected; }), "and the first client comes back with new keys");
    Check(events.joined[1] == joinsBefore + 1, "once");
    (void)raw.SendTo(connect.data(), connect.size(), server.Local());
    Check(RunUntil(server, events, {&one, &two}, nowUs, 100'000u, [] { return false; }) == false, "an old Connect goes around");
    Check(events.joined[1] == joinsBefore + 1, "and takes nothing");
    Check(one.SendReliable(text, sizeof(text)), "the live client still sends");
    const std::size_t oneMessages = events.messages[1].size();
    Check(RunUntil(server, events, {&one, &two}, nowUs, 2'000'000u, [&] { return events.messages[1].size() == oneMessages + 1u; }), "and the server still hears it");

    // Removed: no way back in.
    server.RemovePlayer(2);
    two.Reconnect();
    Check(RunUntil(server, events, {&one, &two}, nowUs, 2'000'000u, [&] { return two.State() == CClientLink::EState::Refused; }), "a removed player is refused");
  }

  void TimeoutAndRateLimit()
  {
    ChannelConfig quick;
    quick.timeoutUs = 200'000u;
    CServerLinks server(quick);
    std::string error;
    Check(server.Open(kLoopbackAnyPort, error), "the server binds");
    server.AddPlayer(1, MakeToken("one"));
    CEvents events;
    std::uint64_t nowUs = 1000u;

    CClientLink one(1, MakeToken("one"), server.Local());
    Check(one.Open(error), "a client opens");
    Check(RunUntil(server, events, {&one}, nowUs, 2'000'000u, [&] { return one.State() == CClientLink::EState::Connected; }), "joins");
    Check(RunUntil(server, events, {}, nowUs, 2'000'000u, [&] { return events.lost[1] == 1; }), "the server sees a silent player gone");
    Check(RunUntil(server, events, {}, nowUs, 400'000u, [] { return false; }) == false && events.lost[1] == 1, "and says so once");
    one.Reconnect();
    Check(RunUntil(server, events, {&one}, nowUs, 2'000'000u, [&] { return events.returns == 1; }), "the player can come back");

    // A burst of Hellos in one instant: past the budget they get nothing.
    CUdpSocket flood;
    Check(flood.Open(kLoopbackAnyPort, error), "a flood socket opens");
    const auto hello = WriteHello();
    for (int i = 0; i < 1000; ++i) {
      (void)flood.SendTo(hello.data(), hello.size(), server.Local());
    }
    server.Wait(20);
    server.Pump(nowUs, events);
    Check(server.Stats().addressLimited > 0u, "a flood of Hellos from one address hits its own limit");
    Check(server.Stats().handshakesLimited == 0u, "before the server's");
    int answers = 0;
    std::array<std::uint8_t, 256> buffer{};
    SEndpoint from;
    while (flood.ReceiveFrom(buffer.data(), buffer.size(), from) >= 0) {
      ++answers;
    }
    Check(answers <= static_cast<int>(CServerLinks::kHandshakeBurstPerAddress), "and most get no answer");
  }

  /** A raw Hello from `socket`; whether a Challenge comes back. */
  [[nodiscard]] bool GetsChallenge(CServerLinks& server, CEvents& events, CUdpSocket& socket, const std::uint64_t nowUs)
  {
    const auto hello = WriteHello();
    (void)socket.SendTo(hello.data(), hello.size(), server.Local());
    std::array<std::uint8_t, 256> buffer{};
    SEndpoint from;
    for (int i = 0; i < 100; ++i) {
      server.Pump(nowUs, events);
      socket.Wait(1);
      if (socket.ReceiveFrom(buffer.data(), buffer.size(), from) == static_cast<int>(kChallengeSize)) {
        return true;
      }
    }
    return false;
  }

  // Plan WPR.28, WPR.45, WPR.48: several loopback addresses stand for several machines.
  void AllowlistAndAddressLimits()
  {
    CServerLinks server;
    std::string error;
    Check(server.Open(kLoopbackAnyPort, error), "the server binds");
    server.AddPlayer(1, MakeToken("one"));
    server.AllowAddress(0x7F000002u); // 127.0.0.2: the match's player address
    CEvents events;
    std::uint64_t nowUs = 1000u;

    CUdpSocket listed;
    CUdpSocket flood;
    CUdpSocket other;
    Check(listed.Open(SEndpoint{0x7F000002u, 0u}, error), "a socket on the listed address opens");
    Check(flood.Open(SEndpoint{0x7F000003u, 0u}, error), "a flood socket on an unlisted address opens");
    Check(other.Open(SEndpoint{0x7F000004u, 0u}, error), "another unlisted socket opens");

    // Unlisted Hellos share a small budget: past it they get nothing, and nothing is kept for them.
    const auto hello = WriteHello();
    for (int i = 0; i < 1000; ++i) {
      (void)flood.SendTo(hello.data(), hello.size(), server.Local());
    }
    server.Wait(20);
    server.Pump(nowUs, events);
    int answers = 0;
    std::array<std::uint8_t, 256> buffer{};
    SEndpoint from;
    while (flood.ReceiveFrom(buffer.data(), buffer.size(), from) >= 0) {
      ++answers;
    }
    Check(answers <= static_cast<int>(CServerLinks::kUnlistedHandshakesPerSecond), "an unlisted flood gets at most the unlisted budget");
    Check(server.Stats().unlistedDropped > 0u, "and the rest is dropped");
    Check(server.Stats().handshakesLimited == 0u, "without touching the server's budget");
    Check(GetsChallenge(server, events, listed, nowUs), "the listed address still gets its challenge at once");

    // A player whose address the match didn't know (a VPN) gets in with the token, once the shared budget refills.
    nowUs += 2'000'000u;
    CClientLink vpn(1, MakeToken("one"), server.Local());
    Check(vpn.Open(error), "a client on 127.0.0.1, which isn't listed, opens");
    Check(RunUntil(server, events, {&vpn}, nowUs, 2'000'000u, [&] { return vpn.State() == CClientLink::EState::Connected; }), "it gets in with its token");
    // Its address is now listed: a flood from elsewhere doesn't keep it out when it comes back.
    for (int i = 0; i < 1000; ++i) {
      (void)other.SendTo(hello.data(), hello.size(), server.Local());
    }
    server.Wait(20);
    server.Pump(nowUs, events);
    vpn.Reconnect();
    Check(RunUntil(server, events, {&vpn}, nowUs, 2'000'000u, [&] { return vpn.State() == CClientLink::EState::Connected; }), "and comes back through an unlisted flood");
  }
} // namespace

TEST(Existing_GameLink, HandshakeAgreesOnKeys) { HandshakeAgreesOnKeys(); }
TEST(Existing_GameLink, HandshakeRefusals) { HandshakeRefusals(); }
TEST(Existing_GameLink, CookiesAndHello) { CookiesAndHello(); }
TEST(Existing_GameLink, Endpoints) { Endpoints(); }
TEST(Existing_GameLink, OverRealSockets) { OverRealSockets(); }
TEST(Existing_GameLink, TimeoutAndRateLimit) { TimeoutAndRateLimit(); }
TEST(Existing_GameLink, AllowlistAndAddressLimits) { AllowlistAndAddressLimits(); }
