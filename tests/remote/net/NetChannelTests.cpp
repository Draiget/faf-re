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

#include <gtest/gtest.h>

#include "monocypher.h"
#include "remote/net/Datagram.h"
#include "remote/net/DatagramCipher.h"
#include "remote/net/NetChannel.h"
#include "remote/net/ReliableStream.h"
#include "remote/net/StyleProof.h"

using namespace faf::remote::net;

namespace
{
  // --- Harness (as tests/remote/WireTests.cpp) -------------------------------------------


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
      EXPECT_TRUE(ReadHeader(bytes, sizeof bytes, out));
      EXPECT_TRUE(out.flags == in.flags && out.sequence == in.sequence && out.ack == in.ack &&
            out.ackBits == in.ackBits && out.ackDelay == in.ackDelay);
    }

    DatagramHeader header;
    header.sequence = 5;
    std::uint8_t bytes[kHeaderSize];
    WriteHeader(header, bytes);
    DatagramHeader out;
    EXPECT_TRUE(!ReadHeader(bytes, kHeaderSize - 1, out));  // short
    bytes[0] = 0x00;
    EXPECT_FALSE(ReadHeader(bytes, kHeaderSize, out));  // not our tag
    bytes[0] = kDatagramTag;
    bytes[1] = 0x80;
    EXPECT_FALSE(ReadHeader(bytes, kHeaderSize, out));  // unknown flag
    bytes[1] = 0;
    header.sequence = 0;
    WriteHeader(header, bytes);
    EXPECT_FALSE(ReadHeader(bytes, kHeaderSize, out));  // sequence 0 is never sent
  }

  void TestVarints()
  {
    const std::uint64_t values[] = {0, 1, 127, 128, 16383, 16384, 0xFFFFFFFFull, 0x7FFFFFFFFFFFFFFFull, UINT64_MAX};
    for (const std::uint64_t v : values) {
      Bytes bytes;
      ByteWriter writer(bytes);
      writer.Varint(v);
      EXPECT_EQ(bytes.size(), VarintSize(v));
      ByteReader reader(bytes.data(), bytes.size());
      EXPECT_TRUE(reader.Varint() == v && reader.Ok() && reader.AtEnd());
    }
    const std::uint8_t tooLong[11] = {0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01};
    ByteReader reader(tooLong, sizeof tooLong);
    (void)reader.Varint();
    EXPECT_FALSE(reader.Ok());
    const std::uint8_t overflow[10] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02};
    ByteReader reader2(overflow, sizeof overflow);
    (void)reader2.Varint();
    EXPECT_FALSE(reader2.Ok());
    ByteReader truncated(overflow, 3);
    (void)truncated.Varint();
    EXPECT_FALSE(truncated.Ok());
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
      EXPECT_EQ(got, expected);
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
      EXPECT_EQ(window.Newest(), newest);
      EXPECT_EQ(window.AckBits(), bits);
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
      EXPECT_TRUE(ordered);
      EXPECT_EQ(fromSet, model);
      std::uint64_t prefix = 0;
      while (prefix < 512 && model[prefix]) {
        ++prefix;
      }
      EXPECT_EQ(set.PrefixEnd(), prefix);
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
        EXPECT_TRUE(receiver.OnFragment(f.begin, stream.data() + f.begin, static_cast<std::size_t>(f.end - f.begin)));
        Bytes message;
        while (receiver.Take(message)) {
          got.push_back(message);
        }
      }
      EXPECT_EQ(got, messages);
      EXPECT_EQ(receiver.Held(), 0);
      EXPECT_EQ(receiver.Delivered(), stream.size());
    }

    // A length above the limit is a protocol error.
    ReliableReceiver receiver(1 << 20, 100);
    Bytes stream;
    ByteWriter writer(stream);
    writer.Varint(101);
    EXPECT_FALSE(receiver.OnFragment(0, stream.data(), stream.size()));
    // Past the window: dropped, not an error, and taken later once in reach.
    ReliableReceiver small(16, 100);
    const std::uint8_t far[4] = {3, 1, 2, 3};
    EXPECT_TRUE(small.OnFragment(100, far, sizeof far));
    EXPECT_EQ(small.Held(), 0);
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
      EXPECT_TRUE(pair.a.SendReliable(toB.sent.back().data(), toB.sent.back().size()));
      toA.sent.push_back(RandomBytes(sizes, sizes() % 200));
      EXPECT_TRUE(pair.b.SendReliable(toA.sent.back().data(), toA.sent.back().size()));
    }
    for (std::uint64_t ms = 0; ms < limitMs; ++ms) {
      pair.Step();
      Pump(pair.b, toB);
      Pump(pair.a, toA);
      if (toB.received == toB.sent.size() && toA.received == toA.sent.size()) {
        if (doneMs) {
          *doneMs = ms;
        }
        EXPECT_TRUE(toB.inOrder && toA.inOrder);
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
      EXPECT_TRUE(ok);
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
      EXPECT_EQ(pair.b.ReliableHeld(), 0);
      if (c.duplicate > 0) {
        EXPECT_TRUE(pair.b.Stats().duplicatesDropped > 0);
      }
    }
  }

  // Plan WP10.7: the congestion window. Every case of the reliable matrix still delivers everything in order with it
  // on; on a clean link it grows from its start towards maxReliableInFlight; on a lossy one it is cut, never under its
  // floor, and the transfer still completes.
  void TestCongestionWindow()
  {
    struct Case
    {
      std::uint64_t latencyMs;
      std::uint64_t jitterMs;
      double loss;
      double duplicate;
    };
    ChannelConfig congested;
    congested.congestionControl = true;
    const Case cases[] = {
      {0, 0, 0.0, 0.0},    {25, 0, 0.0, 0.0},    {25, 10, 0.05, 0.02}, {50, 25, 0.10, 0.05},
      {150, 50, 0.05, 0.0}, {75, 50, 0.20, 0.10}, {25, 5, 0.50, 0.0},
    };
    std::uint64_t seed = 40;
    for (const Case& c : cases) {
      LinkConfig link;
      link.latencyUs = c.latencyMs * 1000;
      link.jitterUs = c.jitterMs * 1000;
      link.loss = c.loss;
      link.duplicate = c.duplicate;
      Pair pair(congested, link, ++seed);
      EXPECT_TRUE(RunReliable(pair, 300, 300'000)) << c.latencyMs << " ms, loss " << c.loss;
    }
    const std::uint64_t start = std::uint64_t{congested.initialWindowDatagrams} * congested.maxDatagramSize;
    const std::uint64_t floor = std::uint64_t{congested.minWindowDatagrams} * congested.maxDatagramSize;
    const Bytes big(2'000'000, 0x5A);
    {
      LinkConfig clean;
      clean.latencyUs = 50'000;
      Pair pair(congested, clean, 91);
      EXPECT_EQ(pair.a.Stats().congestionWindow, start);
      EXPECT_TRUE(pair.a.SendReliable(big.data(), big.size()));
      Bytes got;
      bool arrived = false;
      for (int ms = 0; ms < 60'000 && !arrived; ++ms) {
        pair.Step();
        arrived = pair.b.TakeReliable(got);
      }
      EXPECT_TRUE(arrived && got == big);
      EXPECT_TRUE(pair.a.Stats().congestionWindow > 4 * start) << pair.a.Stats().congestionWindow;
      EXPECT_EQ(pair.a.Stats().congestionCuts, 0u);
    }
    {
      LinkConfig lossy;
      lossy.latencyUs = 50'000;
      lossy.loss = 0.05;
      Pair pair(congested, lossy, 92);
      EXPECT_TRUE(pair.a.SendReliable(big.data(), big.size()));
      Bytes got;
      bool arrived = false;
      std::uint64_t smallest = ~std::uint64_t{0};
      for (int ms = 0; ms < 300'000 && !arrived; ++ms) {
        pair.Step();
        smallest = std::min(smallest, pair.a.Stats().congestionWindow);
        arrived = pair.b.TakeReliable(got);
      }
      EXPECT_TRUE(arrived && got == big);
      EXPECT_TRUE(pair.a.Stats().congestionCuts > 0u);
      EXPECT_TRUE(smallest >= floor && smallest < start) << smallest;
    }
    // Off (the default): no window kept.
    Pair plain({}, LinkConfig{}, 93);
    EXPECT_EQ(plain.a.Stats().congestionWindow, 0u);
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
    EXPECT_TRUE(pair.a.SendReliable(big.data(), big.size()));
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
    EXPECT_TRUE(arrived && got == big);
    EXPECT_TRUE(maxCarried < 2 * config.maxReliableInFlight);
  }

  void TestMessageLimits()
  {
    ChannelConfig config;
    config.maxMessageSize = 1000;
    NetChannel channel(config);
    const Bytes ok(1000, 1);
    const Bytes tooBig(1001, 1);
    EXPECT_TRUE(channel.SendReliable(ok.data(), ok.size()));
    EXPECT_FALSE(channel.SendReliable(tooBig.data(), tooBig.size()));
    const Bytes fits(channel.MaxUnreliableSize(), 2);
    const Bytes over(channel.MaxUnreliableSize() + 1, 2);
    EXPECT_TRUE(channel.SendUnreliable(fits.data(), fits.size()));
    EXPECT_FALSE(channel.SendUnreliable(over.data(), over.size()));
    EXPECT_TRUE(channel.SendReliable(nullptr, 0));  // an empty message is a message
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
        EXPECT_TRUE(pair.a.SendUnreliable(message.data(), message.size()));
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
      EXPECT_TRUE(indices.insert(index).second);  // never twice
    }
    EXPECT_TRUE(intact);
    const double share = static_cast<double>(got.size()) / static_cast<double>(sent.size());
    std::printf("    %zu of %zu unreliable messages arrived (%.1f%%) at 20%% loss\n", got.size(), sent.size(), share * 100);
    EXPECT_TRUE(share > 0.7 && share < 0.9);
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
        EXPECT_TRUE(pair.a.SendRedundant(m.data(), m.size()));
        sent.push_back(std::move(m));
      }
      pair.Step();
      Bytes got;
      while (pair.b.TakeUnreliable(got)) {
        const std::size_t index = got[0] | (got[1] << 8);
        intact = intact && index < sent.size() && sent[index] == got;
        EXPECT_TRUE(seen.insert(index).second); // never twice
      }
    }
    EXPECT_TRUE(intact);
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
    EXPECT_EQ(repeats0, 0);
    EXPECT_TRUE(plain > 0.75 && plain < 0.85);
    EXPECT_TRUE(redundant > 0.985);
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
        EXPECT_TRUE(!std::equal(payload.begin(), payload.end(), datagram.begin() + kHeaderSize));
      }
      Bytes plain(payloadSize);
      EXPECT_TRUE(OpenDatagram(key, 42, datagram.data(), datagram.size(), plain.data()));
      EXPECT_EQ(plain, payload);
      EXPECT_FALSE(OpenDatagram(key, 43, datagram.data(), datagram.size(), plain.data()));  // other nonce
      ChannelKey other = key;
      other[5] ^= 1;
      EXPECT_FALSE(OpenDatagram(other, 42, datagram.data(), datagram.size(), plain.data()));
      // Every single-bit change anywhere, header included, is refused.
      Bytes tampered = datagram;
      for (std::size_t i = 0; i < datagram.size(); ++i) {
        for (int bit = 0; bit < 8; ++bit) {
          tampered[i] ^= static_cast<std::uint8_t>(1u << bit);
          EXPECT_FALSE(OpenDatagram(key, 42, tampered.data(), tampered.size(), plain.data()));
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
    EXPECT_EQ(cipher, Hex("bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c670"
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
    EXPECT_EQ(Bytes(datagram.begin(), datagram.begin() + kHeaderSize), Hex("fc010403020105000000010000800c00"));
    for (std::size_t i = 0; i < 40; ++i) {
      datagram[kHeaderSize + i] = static_cast<std::uint8_t>(i);
    }
    SealDatagram(channelKey, header.sequence, datagram.data(), 40);
    EXPECT_EQ(Bytes(datagram.begin() + kHeaderSize, datagram.end()), Hex("ad41c4abaa2469294f4ecff48110bdfc026fcfee7c57328f0010f4dbe246c7ca3ce94d47f292bcb0794ed6590f957a8b06ef0cd7ab"
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
        EXPECT_TRUE(pair.a.SetKeys(KeysFor(5, false)));
        EXPECT_FALSE(pair.a.SetKeys(KeysFor(6, false)));  // once only
      }
      if (ms == 2'080) {
        EXPECT_TRUE(pair.b.SetKeys(KeysFor(5, true)));
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
    EXPECT_TRUE(toB.inOrder && toA.inOrder);
    EXPECT_TRUE(toB.received == toB.sent.size() && toA.received == toA.sent.size());
    EXPECT_TRUE(pair.b.Stats().unauthenticatedDropped > 0);
    EXPECT_TRUE(pair.a.Stats().unreliableDropped > 0);  // queued before the keys, too big after
    EXPECT_TRUE(pair.a.State() == ChannelState::Connected && pair.b.State() == ChannelState::Connected);
  }

  void TestEncryptedChannel()
  {
    LinkConfig link;
    link.latencyUs = 20'000;
    link.loss = 0.05;
    Pair pair({}, link, 8);
    pair.a.SetKeys(KeysFor(9, false));
    pair.b.SetKeys(KeysFor(9, true));
    EXPECT_TRUE(RunReliable(pair, 200, 120'000));
    EXPECT_EQ(pair.b.Stats().unauthenticatedDropped, 0);
    EXPECT_EQ(pair.a.Stats().unauthenticatedDropped, 0);

    // Capture one datagram A sends and play with it at B.
    const Bytes message = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20};
    EXPECT_TRUE(pair.a.SendReliable(message.data(), message.size()));
    std::vector<Bytes> out;
    pair.now += 1000;
    pair.a.Poll(pair.now, out);
    EXPECT_EQ(out.size(), 1);
    if (out.size() != 1) {
      return;
    }
    const Bytes datagram = out[0];
    EXPECT_EQ(std::search(datagram.begin(), datagram.end(), message.begin(), message.end()), datagram.end());

    const ChannelStats before = pair.b.Stats();
    for (std::size_t i = 0; i < datagram.size(); i += 7) {
      Bytes tampered = datagram;
      tampered[i] ^= 0x40;
      const ReceiveResult r = pair.b.Receive(tampered.data(), tampered.size(), pair.now);
      EXPECT_TRUE(r == ReceiveResult::Unauthenticated || (i < 2 && r == ReceiveResult::Malformed));
    }
    EXPECT_EQ(pair.b.Stats().datagramsReceived, before.datagramsReceived);
    EXPECT_EQ(pair.b.Receive(datagram.data(), datagram.size(), pair.now), ReceiveResult::Accepted);
    EXPECT_EQ(pair.b.Receive(datagram.data(), datagram.size(), pair.now), ReceiveResult::Duplicate);  // replay
    Bytes got;
    EXPECT_TRUE(pair.b.TakeReliable(got) && got == message);

    // A plaintext datagram is refused once keys are set.
    NetChannel plainSender;
    out.clear();
    plainSender.Poll(pair.now, out);
    EXPECT_EQ(out.size(), 1);
    EXPECT_EQ(pair.b.Receive(out[0].data(), out[0].size(), pair.now), ReceiveResult::Unauthenticated);

    // Keys on one side only: nothing gets through either way.
    LinkConfig clean;
    Pair half({}, clean, 9);
    half.a.SetKeys(KeysFor(1, false));
    for (int ms = 0; ms < 1000; ++ms) {
      half.Step();
    }
    EXPECT_TRUE(half.a.Stats().datagramsReceived == 0 && half.b.Stats().datagramsReceived == 0);
    EXPECT_TRUE(half.b.Stats().unauthenticatedDropped > 0 && half.a.Stats().unauthenticatedDropped > 0);
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
    EXPECT_TRUE(channel.SendReliable(message.data(), message.size()));
    std::vector<Bytes> out;
    channel.Poll(1000, out);
    std::vector<std::uint32_t> sequences;
    for (const Bytes& d : out) {
      DatagramHeader header;
      EXPECT_TRUE(ReadHeader(d.data(), d.size(), header));
      sequences.push_back(header.sequence);
    }
    EXPECT_TRUE((sequences == std::vector<std::uint32_t>{UINT32_MAX - 3, UINT32_MAX - 2, UINT32_MAX - 1}));
    EXPECT_EQ(channel.State(), ChannelState::Failed);
    out.clear();
    channel.Poll(2000, out);
    EXPECT_TRUE(out.empty());
    EXPECT_FALSE(channel.SendReliable(message.data(), 1));
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
    EXPECT_TRUE(s.keepalivesSent >= 70 && s.keepalivesSent <= 82);
    EXPECT_TRUE(s.rttSamples >= 70);
    EXPECT_TRUE(s.rttSmoothedUs >= 78'000 && s.rttSmoothedUs <= 92'000);
    EXPECT_TRUE(s.datagramsLost == 0 && s.lossRecent == 0.0);
    EXPECT_TRUE(pair.a.State() == ChannelState::Connected && pair.b.State() == ChannelState::Connected);
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
    EXPECT_TRUE(lost > 0.07 && lost < 0.13);
    EXPECT_TRUE(inbound > 0.07 && inbound < 0.13);
    EXPECT_TRUE(s.lossRecent > 0.03 && s.lossRecent < 0.2);
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
    EXPECT_TRUE(RunReliable(a, 50, 60'000));
    EXPECT_TRUE(a.a.State() == ChannelState::Connected && a.b.State() == ChannelState::Connected);

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
        EXPECT_TRUE(b.a.SinceLastReceivedUs(b.now) >= config.timeoutUs && b.a.SinceLastReceivedUs(b.now) < config.timeoutUs + 1000);
      }
      if (!timedOutAtB && b.b.State() == ChannelState::TimedOut) {
        timedOutAtB = b.now;
        EXPECT_TRUE(b.b.SinceLastReceivedUs(b.now) >= config.timeoutUs && b.b.SinceLastReceivedUs(b.now) < config.timeoutUs + 1000);
      }
    }
    std::printf(
      "    12 s partition from 1 s: A timed out at %.3f s, B at %.3f s\n", timedOutAtA / 1e6, timedOutAtB / 1e6
    );
    // The last arrival is the last keepalive exchange before the cut, at most 250 ms + RTT before it.
    EXPECT_TRUE(timedOutAtA >= 10'700'000 && timedOutAtA <= 11'031'000);
    EXPECT_TRUE(timedOutAtB >= 10'700'000 && timedOutAtB <= 11'031'000);
    std::vector<Bytes> out;
    b.a.Poll(b.now, out);
    EXPECT_TRUE(out.empty());
    const Bytes m = {1};
    EXPECT_FALSE(b.a.SendReliable(m.data(), m.size()));
    EXPECT_EQ(b.a.Receive(m.data(), m.size(), b.now), ReceiveResult::Closed);
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
    EXPECT_TRUE(duringCut < 12 * big.size());
    Bytes got;
    for (int ms = 0; ms < 20'000 && !pair.b.TakeReliable(got); ++ms) {
      pair.Step();
    }
    EXPECT_EQ(got, big);
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
        EXPECT_TRUE(target.ReliableHeld() <= ChannelConfig{}.receiveWindow);
      }
      std::printf("    fuzz (%s): 200000 datagrams, %llu accepted, state %d\n",
                  keyed ? "keys set" : "no keys", static_cast<unsigned long long>(accepted),
                  static_cast<int>(target.State()));
      if (keyed) {
        EXPECT_EQ(accepted, 0);  // nothing forged or mutated gets past the tag
      }
    }
  }

  // --- Lobby style proof ----------------------------------------------------------------

  void TestStyleProof()
  {
    StyleSeed seed{};
    seed.fill(7);
    StyleSigningKey key;
    MakeStyleSigningKey(seed, key);
    EXPECT_EQ(seed[0], 0); // wiped

    StyleSeed otherSeed{};
    otherSeed.fill(9);
    StyleSigningKey otherKey;
    MakeStyleSigningKey(otherSeed, otherKey);

    StyleChallenge challenge{};
    challenge.fill(0x11);
    const StyleColor color{0x12, 0x34, 0x56};
    const StyleSignature proof = SignStyle(key, 100, 200, challenge, color);

    EXPECT_TRUE(CheckStyle(key.publicKey, 100, 200, challenge, color, proof));

    // A key other than the one the engine knows.
    const StyleSignature forged = SignStyle(otherKey, 100, 200, challenge, color);
    EXPECT_FALSE(CheckStyle(key.publicKey, 100, 200, challenge, color, forged));

    // Replayed against a new challenge.
    StyleChallenge otherChallenge = challenge;
    otherChallenge[31] ^= 1;
    EXPECT_FALSE(CheckStyle(key.publicKey, 100, 200, otherChallenge, color, proof));

    // Passed on by a third player, who forwarded the challenge to the holder.
    EXPECT_FALSE(CheckStyle(key.publicKey, 300, 200, challenge, color, proof));
    // Shown to a player it wasn't made for.
    EXPECT_FALSE(CheckStyle(key.publicKey, 100, 300, challenge, color, proof));

    // Another colour under the same signature.
    EXPECT_FALSE(CheckStyle(key.publicKey, 100, 200, challenge, StyleColor{0x12, 0x34, 0x57}, proof));

    StyleSignature tampered = proof;
    tampered[0] ^= 1;
    EXPECT_FALSE(CheckStyle(key.publicKey, 100, 200, challenge, color, tampered));
  }

} // namespace

TEST(Existing_NetChannel, StyleProof) { TestStyleProof(); }
TEST(NetChannel, CongestionWindow) { TestCongestionWindow(); }
TEST(Existing_NetChannel, HeaderRoundTrip) { TestHeaderRoundTrip(); }
TEST(Existing_NetChannel, Varints) { TestVarints(); }
TEST(Existing_NetChannel, ReceiveWindowModel) { TestReceiveWindowModel(); }
TEST(Existing_NetChannel, RangeSetModel) { TestRangeSetModel(); }
TEST(Existing_NetChannel, ReceiverReassembly) { TestReceiverReassembly(); }
TEST(Existing_NetChannel, ReliableMatrix) { TestReliableMatrix(); }
TEST(Existing_NetChannel, InFlightLimit) { TestInFlightLimit(); }
TEST(Existing_NetChannel, MessageLimits) { TestMessageLimits(); }
TEST(Existing_NetChannel, Unreliable) { TestUnreliable(); }
TEST(Existing_NetChannel, RedundantLane) { TestRedundantLane(); }
TEST(Existing_NetChannel, SealOpen) { TestSealOpen(); }
TEST(Existing_NetChannel, CipherKnownAnswers) { TestCipherKnownAnswers(); }
TEST(Existing_NetChannel, EncryptedChannel) { TestEncryptedChannel(); }
TEST(Existing_NetChannel, KeysMidSession) { TestKeysMidSession(); }
TEST(Existing_NetChannel, SequenceEnd) { TestSequenceEnd(); }
TEST(Existing_NetChannel, KeepaliveAndRtt) { TestKeepaliveAndRtt(); }
TEST(Existing_NetChannel, LossStatistics) { TestLossStatistics(); }
TEST(Existing_NetChannel, TimeoutAndPartition) { TestTimeoutAndPartition(); }
TEST(Existing_NetChannel, Backoff) { TestBackoff(); }
TEST(Existing_NetChannel, Fuzz) { TestFuzz(); }
