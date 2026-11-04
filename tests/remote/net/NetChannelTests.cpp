// Engine addition: tests for the net channel (src/remote/net; plan WP10.2, WP10.3, WP10.6,
// WP10.8; issues #141, #142, #145, #147). Two channels talk over a simulated link with
// latency, jitter, loss, duplication, reordering and partitions, all from one seeded random
// stream, so every run is the same. Exit code = failures.
//
// Build: cmake --build --preset clang-x64-release --target faf_netchannel_tests
// Run:   build\clang-x64-release\tests\remote\faf_netchannel_tests.exe

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <map>
#include <random>
#include <set>
#include <string>
#include <vector>

#include "monocypher.h"
#include "remote/net/Datagram.h"
#include "remote/net/DatagramCipher.h"
#include "remote/net/NetChannel.h"
#include "remote/net/ReliableStream.h"

using namespace faf::remote::net;

namespace
{
  // --- Harness (as tests/remote/WireTests.cpp) -------------------------------------------

  int gFailures = 0;
  int gChecks = 0;

#define CHECK(cond)                                                                \
  do {                                                                             \
    ++gChecks;                                                                     \
    if (!(cond)) {                                                                 \
      ++gFailures;                                                                 \
      std::printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                \
    }                                                                              \
  } while (0)

  struct TestCase
  {
    const char* name;
    void (*body)();
  };

  void RunTest(const TestCase& test)
  {
    const int failuresBefore = gFailures;
    try {
      test.body();
    } catch (const std::exception& e) {
      ++gFailures;
      std::printf("  FAIL %s: exception escaped: %s\n", test.name, e.what());
    } catch (...) {
      ++gFailures;
      std::printf("  FAIL %s: exception escaped\n", test.name);
    }
    std::printf("%s %s\n", gFailures == failuresBefore ? "PASS" : "FAIL", test.name);
  }

  using Bytes = std::vector<std::uint8_t>;

  // The standard distributions and std::shuffle differ between standard libraries; these
  // take the engine's raw output, which does not, so every platform runs the same cases.
  double Unit(std::mt19937_64& rng)
  {
    return static_cast<double>(rng() >> 11) * (1.0 / 9007199254740992.0);
  }

  template <class T>
  void Shuffle(std::vector<T>& items, std::mt19937_64& rng)
  {
    for (std::size_t i = items.size(); i > 1; --i) {
      std::swap(items[i - 1], items[rng() % i]);
    }
  }

  Bytes RandomBytes(std::mt19937_64& rng, const std::size_t size)
  {
    Bytes bytes(size);
    for (std::uint8_t& b : bytes) {
      b = static_cast<std::uint8_t>(rng());
    }
    return bytes;
  }

  // --- Simulated link ---------------------------------------------------------------------

  struct LinkConfig
  {
    std::uint64_t latencyUs = 25'000;  // one way
    std::uint64_t jitterUs = 0;        // extra delay, uniform in [0, jitter]: reorders
    double loss = 0.0;
    double duplicate = 0.0;
    /** [begin, end) times when everything is dropped both ways. */
    std::vector<std::pair<std::uint64_t, std::uint64_t>> partitions;
  };

  /** Two channels, A and B, joined by the simulated link, stepped 1 ms at a time. */
  struct Pair
  {
    NetChannel a;
    NetChannel b;
    LinkConfig link;
    std::mt19937_64 rng;
    std::uint64_t now = 0;
    std::multimap<std::uint64_t, std::pair<bool, Bytes>> inFlight;  // time -> (to B?, datagram)
    std::uint64_t carried = 0;
    std::vector<ReceiveResult> resultsAtB;

    Pair(const ChannelConfig& config, const LinkConfig& linkConfig, const std::uint64_t seed)
      : a(config)
      , b(config)
      , link(linkConfig)
      , rng(seed)
    {}

    [[nodiscard]] bool Partitioned(const std::uint64_t t) const
    {
      return std::any_of(link.partitions.begin(), link.partitions.end(), [&](const auto& p) {
        return t >= p.first && t < p.second;
      });
    }

    void Carry(const bool toB, std::vector<Bytes>& datagrams)
    {
      for (Bytes& d : datagrams) {
        carried += d.size();
        if (Partitioned(now) || Unit(rng) < link.loss) {
          continue;
        }
        const int copies = Unit(rng) < link.duplicate ? 2 : 1;
        for (int i = 0; i < copies; ++i) {
          const std::uint64_t jitter = link.jitterUs ? rng() % (link.jitterUs + 1) : 0;
          inFlight.emplace(now + link.latencyUs + jitter, std::make_pair(toB, d));
        }
      }
      datagrams.clear();
    }

    void Step()
    {
      now += 1000;
      while (!inFlight.empty() && inFlight.begin()->first <= now) {
        auto node = inFlight.extract(inFlight.begin());
        const auto& [toB, datagram] = node.mapped();
        if (toB) {
          resultsAtB.push_back(b.Receive(datagram.data(), datagram.size(), now));
        } else {
          a.Receive(datagram.data(), datagram.size(), now);
        }
      }
      std::vector<Bytes> out;
      a.Poll(now, out);
      Carry(true, out);
      b.Poll(now, out);
      Carry(false, out);
    }
  };

  ChannelKeys KeysFor(const std::uint8_t seed, const bool swapped)
  {
    ChannelKeys keys;
    for (std::size_t i = 0; i < kKeySize; ++i) {
      keys.send[i] = static_cast<std::uint8_t>(seed + i);
      keys.receive[i] = static_cast<std::uint8_t>(seed * 3 + 7 * i + 1);
    }
    if (swapped) {
      std::swap(keys.send, keys.receive);
    }
    return keys;
  }

  // --- WP10.2: header, receive window, varints ------------------------------------------

  void TestHeaderRoundTrip()
  {
    std::mt19937_64 rng(1);
    for (int i = 0; i < 1000; ++i) {
      DatagramHeader in;
      in.flags = static_cast<std::uint8_t>(rng() & kKnownFlags);
      in.sequence = static_cast<std::uint32_t>(rng() | 1);
      in.ack = static_cast<std::uint32_t>(rng());
      in.ackBits = static_cast<std::uint32_t>(rng());
      in.ackDelay = static_cast<std::uint16_t>(rng());
      std::uint8_t bytes[kHeaderSize];
      WriteHeader(in, bytes);
      DatagramHeader out;
      CHECK(ReadHeader(bytes, sizeof bytes, out));
      CHECK(out.flags == in.flags && out.sequence == in.sequence && out.ack == in.ack &&
            out.ackBits == in.ackBits && out.ackDelay == in.ackDelay);
    }

    DatagramHeader header;
    header.sequence = 5;
    std::uint8_t bytes[kHeaderSize];
    WriteHeader(header, bytes);
    DatagramHeader out;
    CHECK(!ReadHeader(bytes, kHeaderSize - 1, out));  // short
    bytes[0] = 0x00;
    CHECK(!ReadHeader(bytes, kHeaderSize, out));  // not our tag
    bytes[0] = kDatagramTag;
    bytes[1] = 0x80;
    CHECK(!ReadHeader(bytes, kHeaderSize, out));  // unknown flag
    bytes[1] = 0;
    header.sequence = 0;
    WriteHeader(header, bytes);
    CHECK(!ReadHeader(bytes, kHeaderSize, out));  // sequence 0 is never sent
  }

  void TestVarints()
  {
    const std::uint64_t values[] = {0, 1, 127, 128, 16383, 16384, 0xFFFFFFFFull, 0x7FFFFFFFFFFFFFFFull, UINT64_MAX};
    for (const std::uint64_t v : values) {
      Bytes bytes;
      ByteWriter writer(bytes);
      writer.Varint(v);
      CHECK(bytes.size() == VarintSize(v));
      ByteReader reader(bytes.data(), bytes.size());
      CHECK(reader.Varint() == v && reader.Ok() && reader.AtEnd());
    }
    const std::uint8_t tooLong[11] = {0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01};
    ByteReader reader(tooLong, sizeof tooLong);
    (void)reader.Varint();
    CHECK(!reader.Ok());
    const std::uint8_t overflow[10] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02};
    ByteReader reader2(overflow, sizeof overflow);
    (void)reader2.Varint();
    CHECK(!reader2.Ok());
    ByteReader truncated(overflow, 3);
    (void)truncated.Varint();
    CHECK(!truncated.Ok());
  }

  // The window against a plain set of every sequence accepted.
  void TestReceiveWindowModel()
  {
    std::mt19937_64 rng(2);
    ReceiveWindow window;
    std::set<std::uint32_t> seen;
    std::uint32_t newest = 0;
    for (int i = 0; i < 200000; ++i) {
      // Mostly forward, sometimes far ahead, sometimes back inside or past the window.
      const std::uint64_t roll = rng() % 100;
      std::int64_t s;
      if (roll < 70) {
        s = static_cast<std::int64_t>(newest) + 1 + static_cast<std::int64_t>(rng() % 3);
      } else if (roll < 72) {
        s = static_cast<std::int64_t>(newest) + 1 + static_cast<std::int64_t>(rng() % 3000);
      } else {
        s = static_cast<std::int64_t>(newest) - static_cast<std::int64_t>(rng() % 1100);
      }
      if (s < 0) {
        s = 0;
      }
      const auto sequence = static_cast<std::uint32_t>(s);

      ReceiveWindow::Verdict expected;
      if (sequence == 0) {
        expected = ReceiveWindow::Verdict::TooOld;
      } else if (sequence > newest) {
        expected = ReceiveWindow::Verdict::New;
      } else if (newest - sequence >= ReceiveWindow::kSize) {
        expected = ReceiveWindow::Verdict::TooOld;
      } else {
        expected = seen.count(sequence) ? ReceiveWindow::Verdict::Duplicate : ReceiveWindow::Verdict::New;
      }
      const ReceiveWindow::Verdict got = window.Check(sequence);
      CHECK(got == expected);
      if (got != expected) {
        return;
      }
      if (got == ReceiveWindow::Verdict::New) {
        window.Accept(sequence);
        seen.insert(sequence);
        newest = std::max(newest, sequence);
      }
      std::uint32_t bits = 0;
      for (std::uint32_t k = 0; k < 32; ++k) {
        if (newest > k + 1 && seen.count(newest - 1 - k)) {
          bits |= 1u << k;
        }
      }
      CHECK(window.Newest() == newest);
      CHECK(window.AckBits() == bits);
      if (window.AckBits() != bits) {
        return;
      }
    }
  }

  // --- WP10.3: range set, reliable stream ------------------------------------------------

  void TestRangeSetModel()
  {
    std::mt19937_64 rng(3);
    RangeSet set;
    std::vector<bool> model(512, false);
    for (int i = 0; i < 20000; ++i) {
      const std::uint64_t begin = rng() % 512;
      const std::uint64_t end = std::min<std::uint64_t>(512, begin + rng() % 40);
      if (rng() % 2) {
        set.Add(begin, end);
        for (std::uint64_t k = begin; k < end; ++k) {
          model[k] = true;
        }
      } else {
        set.Remove(begin, end);
        for (std::uint64_t k = begin; k < end; ++k) {
          model[k] = false;
        }
      }
      // Missing() over the whole space must be exactly the model's holes.
      std::vector<StreamRange> missing;
      set.Missing(0, 512, missing);
      std::vector<bool> fromSet(512, true);
      std::uint64_t last = 0;
      bool ordered = true;
      for (const StreamRange& r : missing) {
        ordered = ordered && r.begin >= last && r.begin < r.end;
        last = r.end;
        for (std::uint64_t k = r.begin; k < r.end; ++k) {
          fromSet[k] = false;
        }
      }
      CHECK(ordered);
      CHECK(fromSet == model);
      std::uint64_t prefix = 0;
      while (prefix < 512 && model[prefix]) {
        ++prefix;
      }
      CHECK(set.PrefixEnd() == prefix);
      if (fromSet != model) {
        return;
      }
    }
  }

  // The receiver fed every fragment of a stream in random order with overlaps and repeats.
  void TestReceiverReassembly()
  {
    std::mt19937_64 rng(4);
    for (int round = 0; round < 50; ++round) {
      std::vector<Bytes> messages;
      Bytes stream;
      for (int m = 0; m < 40; ++m) {
        Bytes message = RandomBytes(rng, rng() % 3 == 0 ? rng() % 5000 : rng() % 50);
        ByteWriter writer(stream);
        writer.Varint(message.size());
        writer.Bytes(message.data(), message.size());
        messages.push_back(std::move(message));
      }
      std::vector<StreamRange> fragments;
      for (std::uint64_t at = 0; at < stream.size();) {
        const std::uint64_t size = std::min<std::uint64_t>(stream.size() - at, 1 + rng() % 700);
        fragments.push_back({at, at + size});
        at += size;
      }
      for (int extra = 0; extra < 30; ++extra) {  // overlapping repeats
        const std::uint64_t begin = rng() % stream.size();
        fragments.push_back({begin, std::min<std::uint64_t>(stream.size(), begin + 1 + rng() % 900)});
      }
      Shuffle(fragments, rng);

      ReliableReceiver receiver(1u << 30, 1u << 20);
      std::vector<Bytes> got;
      for (const StreamRange& f : fragments) {
        CHECK(receiver.OnFragment(f.begin, stream.data() + f.begin, static_cast<std::size_t>(f.end - f.begin)));
        Bytes message;
        while (receiver.Take(message)) {
          got.push_back(message);
        }
      }
      CHECK(got == messages);
      CHECK(receiver.Held() == 0);
      CHECK(receiver.Delivered() == stream.size());
    }

    // A length above the limit is a protocol error.
    ReliableReceiver receiver(1 << 20, 100);
    Bytes stream;
    ByteWriter writer(stream);
    writer.Varint(101);
    CHECK(!receiver.OnFragment(0, stream.data(), stream.size()));
    // Past the window: dropped, not an error, and taken later once in reach.
    ReliableReceiver small(16, 100);
    const std::uint8_t far[4] = {3, 1, 2, 3};
    CHECK(small.OnFragment(100, far, sizeof far));
    CHECK(small.Held() == 0);
  }

  struct Traffic
  {
    std::vector<Bytes> sent;
    std::size_t received = 0;
    bool inOrder = true;
  };

  void Pump(NetChannel& channel, Traffic& traffic)
  {
    Bytes message;
    while (channel.TakeReliable(message)) {
      if (traffic.received >= traffic.sent.size() || message != traffic.sent[traffic.received]) {
        traffic.inOrder = false;
      }
      ++traffic.received;
    }
  }

  /** Sends `count` messages each way and runs until both arrive or `limitMs` passes. */
  bool RunReliable(Pair& pair, const int count, const std::uint64_t limitMs, std::uint64_t* doneMs = nullptr)
  {
    Traffic toB;
    Traffic toA;
    std::mt19937_64 sizes(pair.rng());
    for (int i = 0; i < count; ++i) {
      const std::size_t size = sizes() % 10 == 0 ? sizes() % 60000 : sizes() % 300;
      toB.sent.push_back(RandomBytes(sizes, size));
      CHECK(pair.a.SendReliable(toB.sent.back().data(), toB.sent.back().size()));
      toA.sent.push_back(RandomBytes(sizes, sizes() % 200));
      CHECK(pair.b.SendReliable(toA.sent.back().data(), toA.sent.back().size()));
    }
    for (std::uint64_t ms = 0; ms < limitMs; ++ms) {
      pair.Step();
      Pump(pair.b, toB);
      Pump(pair.a, toA);
      if (toB.received == toB.sent.size() && toA.received == toA.sent.size()) {
        if (doneMs) {
          *doneMs = ms;
        }
        CHECK(toB.inOrder && toA.inOrder);
        return toB.inOrder && toA.inOrder;
      }
    }
    std::printf("    stalled: %zu/%zu to B, %zu/%zu to A\n", toB.received, toB.sent.size(), toA.received, toA.sent.size());
    return false;
  }

  void TestReliableMatrix()
  {
    struct Case
    {
      std::uint64_t latencyMs;
      std::uint64_t jitterMs;
      double loss;
      double duplicate;
    };
    const Case cases[] = {
      {0, 0, 0.0, 0.0},    {25, 0, 0.0, 0.0},    {25, 10, 0.05, 0.02}, {50, 25, 0.10, 0.05},
      {150, 50, 0.05, 0.0}, {75, 50, 0.20, 0.10}, {25, 5, 0.50, 0.0},
    };
    std::uint64_t seed = 10;
    for (const Case& c : cases) {
      LinkConfig link;
      link.latencyUs = c.latencyMs * 1000;
      link.jitterUs = c.jitterMs * 1000;
      link.loss = c.loss;
      link.duplicate = c.duplicate;
      Pair pair({}, link, ++seed);
      std::uint64_t doneMs = 0;
      const bool ok = RunReliable(pair, 300, 300'000, &doneMs);
      CHECK(ok);
      const ChannelStats& s = pair.a.Stats();
      std::printf(
        "    latency %llu ms, jitter %llu, loss %.0f%%, dup %.0f%%: done in %llu ms, %llu datagrams, %llu lost, "
        "%llu bytes resent (%llu spurious losses, reorder allowance %u datagrams, %u/8 RTT), srtt %.1f ms, "
        "B dropped %llu duplicates\n",
        static_cast<unsigned long long>(c.latencyMs),
        static_cast<unsigned long long>(c.jitterMs),
        c.loss * 100,
        c.duplicate * 100,
        static_cast<unsigned long long>(doneMs),
        static_cast<unsigned long long>(s.datagramsSent),
        static_cast<unsigned long long>(s.datagramsLost),
        static_cast<unsigned long long>(s.reliableBytesResent),
        static_cast<unsigned long long>(s.spuriousLosses),
        s.reorderThreshold,
        s.reorderTimeEighths,
        s.rttSmoothedUs / 1000.0,
        static_cast<unsigned long long>(pair.b.Stats().duplicatesDropped)
      );
      CHECK(pair.b.ReliableHeld() == 0);
      if (c.duplicate > 0) {
        CHECK(pair.b.Stats().duplicatesDropped > 0);
      }
    }
  }

  // The sender never has more than maxReliableInFlight bytes past the acked prefix.
  void TestInFlightLimit()
  {
    ChannelConfig config;
    config.maxReliableInFlight = 8 * 1024;
    LinkConfig link;
    link.latencyUs = 100'000;
    link.loss = 0.05;
    Pair pair(config, link, 77);
    const Bytes big(200'000, 0xAB);
    CHECK(pair.a.SendReliable(big.data(), big.size()));
    std::uint64_t maxCarried = 0;
    std::uint64_t carriedBefore = 0;
    Bytes got;
    bool arrived = false;
    for (int ms = 0; ms < 120'000 && !arrived; ++ms) {
      pair.Step();
      // Over any one step, A cannot put more than the window (plus headers) on the wire
      // unless resends are due, which are themselves inside the window.
      maxCarried = std::max(maxCarried, pair.carried - carriedBefore);
      carriedBefore = pair.carried;
      arrived = pair.b.TakeReliable(got);
    }
    CHECK(arrived && got == big);
    CHECK(maxCarried < 2 * config.maxReliableInFlight);
  }

  void TestMessageLimits()
  {
    ChannelConfig config;
    config.maxMessageSize = 1000;
    NetChannel channel(config);
    const Bytes ok(1000, 1);
    const Bytes tooBig(1001, 1);
    CHECK(channel.SendReliable(ok.data(), ok.size()));
    CHECK(!channel.SendReliable(tooBig.data(), tooBig.size()));
    const Bytes fits(channel.MaxUnreliableSize(), 2);
    const Bytes over(channel.MaxUnreliableSize() + 1, 2);
    CHECK(channel.SendUnreliable(fits.data(), fits.size()));
    CHECK(!channel.SendUnreliable(over.data(), over.size()));
    CHECK(channel.SendReliable(nullptr, 0));  // an empty message is a message
  }

  // Unreliable messages arrive at most once, intact, in send order where they arrive.
  void TestUnreliable()
  {
    LinkConfig link;
    link.latencyUs = 30'000;
    link.loss = 0.2;
    link.duplicate = 0.2;
    Pair pair({}, link, 5);
    std::mt19937_64 rng(6);
    std::vector<Bytes> sent;
    std::vector<Bytes> got;
    for (int ms = 0; ms < 5000; ++ms) {
      if (ms < 4000 && ms % 5 == 0) {
        Bytes message = RandomBytes(rng, 8 + rng() % 400);
        message[0] = static_cast<std::uint8_t>(sent.size());
        message[1] = static_cast<std::uint8_t>(sent.size() >> 8);
        CHECK(pair.a.SendUnreliable(message.data(), message.size()));
        sent.push_back(std::move(message));
      }
      pair.Step();
      Bytes message;
      while (pair.b.TakeUnreliable(message)) {
        got.push_back(message);
      }
    }
    std::set<std::size_t> indices;
    bool intact = true;
    for (const Bytes& m : got) {
      const std::size_t index = m[0] | (m[1] << 8);
      intact = intact && index < sent.size() && sent[index] == m;
      CHECK(indices.insert(index).second);  // never twice
    }
    CHECK(intact);
    const double share = static_cast<double>(got.size()) / static_cast<double>(sent.size());
    std::printf("    %zu of %zu unreliable messages arrived (%.1f%%) at 20%% loss\n", got.size(), sent.size(), share * 100);
    CHECK(share > 0.7 && share < 0.9);
  }

  // Issue #240: the redundant lane. Messages every 33 ms (the game's datagram
  // rate) over 20 % loss each way: with redundancy 2 nearly all arrive, each
  // once and intact; with redundancy 0 only the lucky 80 %.
  double LaneDelivery(const std::uint32_t redundancy, std::uint64_t* repeats)
  {
    ChannelConfig config;
    config.redundancy = redundancy;
    LinkConfig link;
    link.latencyUs = 50'000;
    link.loss = 0.2;
    Pair pair(config, link, 31);
    std::mt19937_64 rng(32);
    std::vector<Bytes> sent;
    std::set<std::size_t> seen;
    bool intact = true;
    for (int ms = 0; ms < 60'000; ++ms) {
      if (ms < 58'000 && ms % 33 == 0) {
        Bytes m = RandomBytes(rng, 60 + rng() % 400);
        m[0] = static_cast<std::uint8_t>(sent.size());
        m[1] = static_cast<std::uint8_t>(sent.size() >> 8);
        CHECK(pair.a.SendRedundant(m.data(), m.size()));
        sent.push_back(std::move(m));
      }
      pair.Step();
      Bytes got;
      while (pair.b.TakeUnreliable(got)) {
        const std::size_t index = got[0] | (got[1] << 8);
        intact = intact && index < sent.size() && sent[index] == got;
        CHECK(seen.insert(index).second); // never twice
      }
    }
    CHECK(intact);
    if (repeats != nullptr) {
      *repeats = pair.a.Stats().redundantRepeats;
    }
    return static_cast<double>(seen.size()) / static_cast<double>(sent.size());
  }

  void TestRedundantLane()
  {
    std::uint64_t repeats0 = 0;
    std::uint64_t repeats2 = 0;
    const double plain = LaneDelivery(0, &repeats0);
    const double redundant = LaneDelivery(2, &repeats2);
    std::printf(
      "    20%% loss each way, a message every 33 ms: %.1f%% arrive with no repeats, %.2f%% with redundancy 2 "
      "(%llu repeats)\n",
      plain * 100,
      redundant * 100,
      static_cast<unsigned long long>(repeats2)
    );
    CHECK(repeats0 == 0);
    CHECK(plain > 0.75 && plain < 0.85);
    CHECK(redundant > 0.985);
  }

  // --- WP10.6: AEAD -----------------------------------------------------------------------

  void TestSealOpen()
  {
    std::mt19937_64 rng(7);
    ChannelKey key{};
    for (std::size_t i = 0; i < kKeySize; ++i) {
      key[i] = static_cast<std::uint8_t>(rng());
    }
    for (const std::size_t payloadSize : {std::size_t{0}, std::size_t{1}, std::size_t{100}, std::size_t{1168}}) {
      const Bytes payload = RandomBytes(rng, payloadSize);
      Bytes datagram(kHeaderSize + payloadSize + kTagSize);
      DatagramHeader header;
      header.flags = kFlagEncrypted;
      header.sequence = 42;
      WriteHeader(header, datagram.data());
      std::copy(payload.begin(), payload.end(), datagram.begin() + kHeaderSize);
      SealDatagram(key, 42, datagram.data(), payloadSize);
      if (payloadSize >= 16) {
        CHECK(!std::equal(payload.begin(), payload.end(), datagram.begin() + kHeaderSize));
      }
      Bytes plain(payloadSize);
      CHECK(OpenDatagram(key, 42, datagram.data(), datagram.size(), plain.data()));
      CHECK(plain == payload);
      CHECK(!OpenDatagram(key, 43, datagram.data(), datagram.size(), plain.data()));  // other nonce
      ChannelKey other = key;
      other[5] ^= 1;
      CHECK(!OpenDatagram(other, 42, datagram.data(), datagram.size(), plain.data()));
      // Every single-bit change anywhere, header included, is refused.
      Bytes tampered = datagram;
      for (std::size_t i = 0; i < datagram.size(); ++i) {
        for (int bit = 0; bit < 8; ++bit) {
          tampered[i] ^= static_cast<std::uint8_t>(1u << bit);
          CHECK(!OpenDatagram(key, 42, tampered.data(), tampered.size(), plain.data()));
          tampered[i] ^= static_cast<std::uint8_t>(1u << bit);
        }
      }
    }
  }

  Bytes Hex(const char* text)
  {
    Bytes bytes;
    for (; text[0] != 0 && text[1] != 0; text += 2) {
      const auto nibble = [](const char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
      bytes.push_back(static_cast<std::uint8_t>(nibble(text[0]) * 16 + nibble(text[1])));
    }
    return bytes;
  }

  // Known answers from an independent implementation, so the tests do not only show the
  // code agrees with itself. (1) draft-irtf-cfrg-xchacha-03 A.3.1 through Monocypher's
  // crypto_aead_lock. (2) The channel's layout (header as associated data, sequence as
  // nonce) through SealDatagram, the expected bytes made with libsodium 1.0 via PyNaCl 1.6.2
  // crypto_aead_xchacha20poly1305_ietf_encrypt(payload, header, seq LE + 20 zeros, key).
  void TestCipherKnownAnswers()
  {
    const char* const sunscreen =
      "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would "
      "be it.";
    const Bytes plain(sunscreen, sunscreen + std::char_traits<char>::length(sunscreen));
    const Bytes aad = Hex("50515253c0c1c2c3c4c5c6c7");
    std::uint8_t key[32];
    std::uint8_t nonce[24];
    for (int i = 0; i < 32; ++i) {
      key[i] = static_cast<std::uint8_t>(0x80 + i);
    }
    for (int i = 0; i < 24; ++i) {
      nonce[i] = static_cast<std::uint8_t>(0x40 + i);
    }
    Bytes cipher(plain.size() + 16);
    crypto_aead_lock(cipher.data(), cipher.data() + plain.size(), key, nonce, aad.data(), aad.size(), plain.data(), plain.size());
    CHECK(cipher ==
          Hex("bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c670"
              "8c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da97"
              "68812f615c68b13b52ec0875924c1c7987947deafd8780acf49"));

    ChannelKey channelKey{};
    for (std::size_t i = 0; i < kKeySize; ++i) {
      channelKey[i] = static_cast<std::uint8_t>(7 * i + 3);
    }
    DatagramHeader header;
    header.flags = kFlagEncrypted;
    header.sequence = 0x01020304;
    header.ack = 5;
    header.ackBits = 0x80000001;
    header.ackDelay = 12;
    Bytes datagram(kHeaderSize + 40 + kTagSize);
    WriteHeader(header, datagram.data());
    CHECK(Bytes(datagram.begin(), datagram.begin() + kHeaderSize) == Hex("fc010403020105000000010000800c00"));
    for (std::size_t i = 0; i < 40; ++i) {
      datagram[kHeaderSize + i] = static_cast<std::uint8_t>(i);
    }
    SealDatagram(channelKey, header.sequence, datagram.data(), 40);
    CHECK(Bytes(datagram.begin() + kHeaderSize, datagram.end()) ==
          Hex("ad41c4abaa2469294f4ecff48110bdfc026fcfee7c57328f0010f4dbe246c7ca3ce94d47f292bcb0794ed6590f957a8b06ef0cd7ab"
              "6b7be7"));
  }

  // The handshake runs in plaintext, then each end calls SetKeys when it has the keys; the
  // two ends do that at different moments, with plaintext data and acks still in flight.
  // Whatever one end drops in between comes back sealed, and every message arrives once.
  void TestKeysMidSession()
  {
    LinkConfig link;
    link.latencyUs = 30'000;
    link.loss = 0.05;
    Pair pair({}, link, 21);
    Traffic toB;
    Traffic toA;
    std::mt19937_64 rng(22);
    for (int ms = 0; ms < 20'000; ++ms) {
      if (ms < 6'000 && ms % 10 == 0) {
        toB.sent.push_back(RandomBytes(rng, rng() % 3 == 0 ? 3000 : 60));
        pair.a.SendReliable(toB.sent.back().data(), toB.sent.back().size());
        toA.sent.push_back(RandomBytes(rng, 60));
        pair.b.SendReliable(toA.sent.back().data(), toA.sent.back().size());
        // 1,175 bytes: under the plaintext limit (1,181), over the sealed one (1,165).
        const Bytes ping = RandomBytes(rng, 1175);
        pair.a.SendUnreliable(ping.data(), ping.size());
      }
      if (ms == 2'000) {
        CHECK(pair.a.SetKeys(KeysFor(5, false)));
        CHECK(!pair.a.SetKeys(KeysFor(6, false)));  // once only
      }
      if (ms == 2'080) {
        CHECK(pair.b.SetKeys(KeysFor(5, true)));
      }
      pair.Step();
      Pump(pair.b, toB);
      Pump(pair.a, toA);
      Bytes drop;
      while (pair.b.TakeUnreliable(drop)) {
      }
    }
    std::printf(
      "    keys set at 2.000 s (A) and 2.080 s (B): %zu/%zu and %zu/%zu messages in order, B refused %llu "
      "unauthenticated, A dropped %llu unreliable that no longer fit\n",
      toB.received,
      toB.sent.size(),
      toA.received,
      toA.sent.size(),
      static_cast<unsigned long long>(pair.b.Stats().unauthenticatedDropped),
      static_cast<unsigned long long>(pair.a.Stats().unreliableDropped)
    );
    CHECK(toB.inOrder && toA.inOrder);
    CHECK(toB.received == toB.sent.size() && toA.received == toA.sent.size());
    CHECK(pair.b.Stats().unauthenticatedDropped > 0);
    CHECK(pair.a.Stats().unreliableDropped > 0);  // queued before the keys, too big after
    CHECK(pair.a.State() == ChannelState::Connected && pair.b.State() == ChannelState::Connected);
  }

  void TestEncryptedChannel()
  {
    LinkConfig link;
    link.latencyUs = 20'000;
    link.loss = 0.05;
    Pair pair({}, link, 8);
    pair.a.SetKeys(KeysFor(9, false));
    pair.b.SetKeys(KeysFor(9, true));
    CHECK(RunReliable(pair, 200, 120'000));
    CHECK(pair.b.Stats().unauthenticatedDropped == 0);
    CHECK(pair.a.Stats().unauthenticatedDropped == 0);

    // Capture one datagram A sends and play with it at B.
    const Bytes message = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20};
    CHECK(pair.a.SendReliable(message.data(), message.size()));
    std::vector<Bytes> out;
    pair.now += 1000;
    pair.a.Poll(pair.now, out);
    CHECK(out.size() == 1);
    if (out.size() != 1) {
      return;
    }
    const Bytes datagram = out[0];
    CHECK(std::search(datagram.begin(), datagram.end(), message.begin(), message.end()) == datagram.end());

    const ChannelStats before = pair.b.Stats();
    for (std::size_t i = 0; i < datagram.size(); i += 7) {
      Bytes tampered = datagram;
      tampered[i] ^= 0x40;
      const ReceiveResult r = pair.b.Receive(tampered.data(), tampered.size(), pair.now);
      CHECK(r == ReceiveResult::Unauthenticated || (i < 2 && r == ReceiveResult::Malformed));
    }
    CHECK(pair.b.Stats().datagramsReceived == before.datagramsReceived);
    CHECK(pair.b.Receive(datagram.data(), datagram.size(), pair.now) == ReceiveResult::Accepted);
    CHECK(pair.b.Receive(datagram.data(), datagram.size(), pair.now) == ReceiveResult::Duplicate);  // replay
    Bytes got;
    CHECK(pair.b.TakeReliable(got) && got == message);

    // A plaintext datagram is refused once keys are set.
    NetChannel plainSender;
    out.clear();
    plainSender.Poll(pair.now, out);
    CHECK(out.size() == 1);
    CHECK(pair.b.Receive(out[0].data(), out[0].size(), pair.now) == ReceiveResult::Unauthenticated);

    // Keys on one side only: nothing gets through either way.
    LinkConfig clean;
    Pair half({}, clean, 9);
    half.a.SetKeys(KeysFor(1, false));
    for (int ms = 0; ms < 1000; ++ms) {
      half.Step();
    }
    CHECK(half.a.Stats().datagramsReceived == 0 && half.b.Stats().datagramsReceived == 0);
    CHECK(half.b.Stats().unauthenticatedDropped > 0 && half.a.Stats().unauthenticatedDropped > 0);
  }

  // The last sequences: each is sent once, 2^32 - 1 never, and the channel then fails
  // instead of wrapping to a sequence (and so a nonce) used before.
  void TestSequenceEnd()
  {
    ChannelConfig config;
    config.firstSequence = UINT32_MAX - 3;
    NetChannel channel(config);
    channel.SetKeys(KeysFor(4, false));
    const Bytes message(5000, 9);  // several datagrams' worth
    CHECK(channel.SendReliable(message.data(), message.size()));
    std::vector<Bytes> out;
    channel.Poll(1000, out);
    std::vector<std::uint32_t> sequences;
    for (const Bytes& d : out) {
      DatagramHeader header;
      CHECK(ReadHeader(d.data(), d.size(), header));
      sequences.push_back(header.sequence);
    }
    CHECK((sequences == std::vector<std::uint32_t>{UINT32_MAX - 3, UINT32_MAX - 2, UINT32_MAX - 1}));
    CHECK(channel.State() == ChannelState::Failed);
    out.clear();
    channel.Poll(2000, out);
    CHECK(out.empty());
    CHECK(!channel.SendReliable(message.data(), 1));
  }

  // --- WP10.8: keepalive, RTT, loss, timeout ---------------------------------------------

  void TestKeepaliveAndRtt()
  {
    LinkConfig link;
    link.latencyUs = 40'000;  // 80 ms round trip
    link.jitterUs = 4'000;
    Pair pair({}, link, 11);
    for (int ms = 0; ms < 20'000; ++ms) {
      pair.Step();
    }
    const ChannelStats& s = pair.a.Stats();
    std::printf(
      "    idle 20 s at 80-88 ms RTT: %llu keepalives, %llu ack-only, %llu RTT samples, srtt %.1f ms, var %.1f, min %.1f\n",
      static_cast<unsigned long long>(s.keepalivesSent),
      static_cast<unsigned long long>(s.ackOnlySent),
      static_cast<unsigned long long>(s.rttSamples),
      s.rttSmoothedUs / 1000.0,
      s.rttVarUs / 1000.0,
      s.rttMinUs / 1000.0
    );
    // One keepalive per 250 ms, both ways, each answered by an ack-only datagram.
    CHECK(s.keepalivesSent >= 70 && s.keepalivesSent <= 82);
    CHECK(s.rttSamples >= 70);
    CHECK(s.rttSmoothedUs >= 78'000 && s.rttSmoothedUs <= 92'000);
    CHECK(s.datagramsLost == 0 && s.lossRecent == 0.0);
    CHECK(pair.a.State() == ChannelState::Connected && pair.b.State() == ChannelState::Connected);
  }

  void TestLossStatistics()
  {
    LinkConfig link;
    link.latencyUs = 30'000;
    link.loss = 0.10;
    Pair pair({}, link, 12);
    std::mt19937_64 rng(13);
    for (int ms = 0; ms < 60'000; ++ms) {
      if (ms % 20 == 0) {  // a steady 50 messages a second each way
        const Bytes m = RandomBytes(rng, 100);
        pair.a.SendReliable(m.data(), m.size());
        pair.b.SendReliable(m.data(), m.size());
      }
      pair.Step();
      Bytes drop;
      while (pair.a.TakeReliable(drop)) {
      }
      while (pair.b.TakeReliable(drop)) {
      }
    }
    const ChannelStats& s = pair.a.Stats();
    const double lost = static_cast<double>(s.datagramsLost) / static_cast<double>(s.datagramsLost + s.datagramsAcked);
    const double inbound = static_cast<double>(pair.b.Stats().inboundMissing) /
                           static_cast<double>(pair.b.Stats().inboundMissing + pair.b.Stats().datagramsReceived);
    std::printf(
      "    10%% loss each way, 60 s: A counted %.1f%% of its datagrams lost (recent %.1f%%), B saw %.1f%% of A's "
      "sequences missing, srtt %.1f ms\n",
      lost * 100,
      s.lossRecent * 100,
      inbound * 100,
      s.rttSmoothedUs / 1000.0
    );
    CHECK(lost > 0.07 && lost < 0.13);
    CHECK(inbound > 0.07 && inbound < 0.13);
    CHECK(s.lossRecent > 0.03 && s.lossRecent < 0.2);
  }

  void TestTimeoutAndPartition()
  {
    ChannelConfig config;
    config.timeoutUs = 10'000'000;

    // A 2 s partition: no timeout, traffic resumes, everything arrives.
    LinkConfig shortCut;
    shortCut.latencyUs = 30'000;
    shortCut.partitions.push_back({3'000'000, 5'000'000});
    Pair a({}, shortCut, 14);
    for (int ms = 0; ms < 2500; ++ms) {
      a.Step();
    }
    CHECK(RunReliable(a, 50, 60'000));
    CHECK(a.a.State() == ChannelState::Connected && a.b.State() == ChannelState::Connected);

    // A 12 s partition: both ends time out about 10 s after their last arrival.
    LinkConfig longCut;
    longCut.latencyUs = 30'000;
    longCut.partitions.push_back({1'000'000, 13'000'000});
    Pair b(config, longCut, 15);
    std::uint64_t timedOutAtA = 0;
    std::uint64_t timedOutAtB = 0;
    for (int ms = 0; ms < 15'000; ++ms) {
      b.Step();
      if (!timedOutAtA && b.a.State() == ChannelState::TimedOut) {
        timedOutAtA = b.now;
        CHECK(b.a.SinceLastReceivedUs(b.now) >= config.timeoutUs && b.a.SinceLastReceivedUs(b.now) < config.timeoutUs + 1000);
      }
      if (!timedOutAtB && b.b.State() == ChannelState::TimedOut) {
        timedOutAtB = b.now;
        CHECK(b.b.SinceLastReceivedUs(b.now) >= config.timeoutUs && b.b.SinceLastReceivedUs(b.now) < config.timeoutUs + 1000);
      }
    }
    std::printf(
      "    12 s partition from 1 s: A timed out at %.3f s, B at %.3f s\n", timedOutAtA / 1e6, timedOutAtB / 1e6
    );
    // The last arrival is the last keepalive exchange before the cut, at most 250 ms + RTT before it.
    CHECK(timedOutAtA >= 10'700'000 && timedOutAtA <= 11'031'000);
    CHECK(timedOutAtB >= 10'700'000 && timedOutAtB <= 11'031'000);
    std::vector<Bytes> out;
    b.a.Poll(b.now, out);
    CHECK(out.empty());
    const Bytes m = {1};
    CHECK(!b.a.SendReliable(m.data(), m.size()));
    CHECK(b.a.Receive(m.data(), m.size(), b.now) == ReceiveResult::Closed);
  }

  // During a partition the retransmission timer backs off instead of resending every RTO.
  void TestBackoff()
  {
    LinkConfig link;
    link.latencyUs = 20'000;
    link.partitions.push_back({500'000, 8'500'000});
    Pair pair({}, link, 16);
    const Bytes big(100'000, 7);
    pair.a.SendReliable(big.data(), big.size());
    std::uint64_t carriedAtCut = 0;
    for (int ms = 0; ms < 8'500; ++ms) {
      pair.Step();
      if (ms == 600) {
        carriedAtCut = pair.carried;
      }
    }
    const std::uint64_t duringCut = pair.carried - carriedAtCut;
    std::printf("    8 s partition: %llu bytes sent into it\n", static_cast<unsigned long long>(duringCut));
    // The whole message is in flight at most a handful of times, not once per 50 ms.
    CHECK(duringCut < 12 * big.size());
    Bytes got;
    for (int ms = 0; ms < 20'000 && !pair.b.TakeReliable(got); ++ms) {
      pair.Step();
    }
    CHECK(got == big);
  }

  // --- Hostile input ----------------------------------------------------------------------

  void TestFuzz()
  {
    std::mt19937_64 rng(17);
    for (const bool keyed : {false, true}) {
      Pair pair({}, LinkConfig{}, 18);
      if (keyed) {
        pair.a.SetKeys(KeysFor(3, false));
        pair.b.SetKeys(KeysFor(3, true));
      }
      // Real datagrams to mutate.
      std::vector<Bytes> corpus;
      const Bytes big(5000, 3);
      pair.a.SendReliable(big.data(), big.size());
      const Bytes small(40, 4);
      pair.a.SendUnreliable(small.data(), small.size());
      std::vector<Bytes> out;
      pair.a.Poll(1000, out);
      corpus = out;

      NetChannel target;
      if (keyed) {
        target.SetKeys(KeysFor(3, true));
      }
      std::uint64_t accepted = 0;
      for (int i = 0; i < 200000; ++i) {
        Bytes d;
        const std::uint64_t kind = rng() % 4;
        if (kind == 0) {
          d = RandomBytes(rng, rng() % 1300);
        } else if (kind == 1) {
          d = RandomBytes(rng, kHeaderSize + rng() % 200);
          d[0] = kDatagramTag;
          d[1] = static_cast<std::uint8_t>(rng() & kKnownFlags);
        } else {
          const Bytes& original = corpus[rng() % corpus.size()];
          d = original;
          while (d == original) {  // two flips of one bit would give the original back
            const int flips = 1 + static_cast<int>(rng() % 4);
            for (int f = 0; f < flips; ++f) {
              d[rng() % d.size()] ^= static_cast<std::uint8_t>(1u << (rng() % 8));
            }
          }
          if (kind == 3) {
            d.resize(rng() % (d.size() + 1));
          }
        }
        if (target.Receive(d.data(), d.size(), 1000 + i) == ReceiveResult::Accepted) {
          ++accepted;
        }
        target.Poll(1000 + i, out);
        out.clear();
        Bytes drop;
        while (target.TakeReliable(drop)) {
        }
        while (target.TakeUnreliable(drop)) {
        }
        CHECK(target.ReliableHeld() <= ChannelConfig{}.receiveWindow);
      }
      std::printf("    fuzz (%s): 200000 datagrams, %llu accepted, state %d\n",
                  keyed ? "keys set" : "no keys", static_cast<unsigned long long>(accepted),
                  static_cast<int>(target.State()));
      if (keyed) {
        CHECK(accepted == 0);  // nothing forged or mutated gets past the tag
      }
    }
  }

  const TestCase kTests[] = {
    {"header round trip and refusals (WP10.2)", TestHeaderRoundTrip},
    {"varints", TestVarints},
    {"receive window against a model: verdicts and ack bits (WP10.2)", TestReceiveWindowModel},
    {"range set against a model (WP10.3)", TestRangeSetModel},
    {"receiver reassembly from shuffled overlapping fragments (WP10.3)", TestReceiverReassembly},
    {"reliable messages over lossy links, both ways (WP10.3)", TestReliableMatrix},
    {"in-flight limit (WP10.3)", TestInFlightLimit},
    {"message size limits", TestMessageLimits},
    {"unreliable messages: at most once, intact", TestUnreliable},
    {"redundant lane: losses covered by repeats, each message once (#240)", TestRedundantLane},
    {"seal and open (WP10.6)", TestSealOpen},
    {"cipher known answers: XChaCha20-Poly1305 vector, the channel's layout (WP10.6)", TestCipherKnownAnswers},
    {"encrypted channel: delivery, tampering, replay, plaintext, one-sided keys (WP10.6)", TestEncryptedChannel},
    {"keys set mid-session at different moments on each end (WP10.6)", TestKeysMidSession},
    {"the sequence ends in failure, never a wrap (WP10.2, WP10.6)", TestSequenceEnd},
    {"keepalive and RTT on an idle link (WP10.8)", TestKeepaliveAndRtt},
    {"loss statistics at 10% loss (WP10.8)", TestLossStatistics},
    {"timeout after a long partition, none after a short one (WP10.8)", TestTimeoutAndPartition},
    {"retransmission backoff during a partition", TestBackoff},
    {"fuzzed datagrams", TestFuzz},
  };
} // namespace

int main()
{
  for (const TestCase& test : kTests) {
    RunTest(test);
  }
  std::printf("%d checks, %d failures\n", gChecks, gFailures);
  return gFailures;
}
