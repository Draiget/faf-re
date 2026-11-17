// faf_netbench: how long the game's beat messages take between players over an impaired network, for each way the
// engine can carry them. Not a pass/fail test: it writes one JSON object of raw numbers, and
// tools/netbench/report.py turns many of them into the tables and charts of docs/NETWORK_MEASUREMENTS.md.
//
// N real CNetUDPConnectors in this process, joined pairwise by in-process links (NetPeerTransport.h) that add
// latency, jitter, loss (independent or in bursts), an uplink bandwidth and partitions. Every player sends one beat
// message every 100 ms, as the game's issue thread does, sized from an order model, plus an optional burst. The
// receiving connector's dispatch times each beat's arrival. The beat a client executes needs every other player's
// beat, so the report replays these arrival times through the game's pacing to get the pauses players would see.
//
// Carriers (carrier=):
//   plain   the game's datagrams go straight onto the link, as the shipped game and the Java adapter
//   lane    our native links (#240): each game datagram rides a net channel's redundant lane, repeated in later
//           datagrams until acked, encrypted (#289); polled on send, on receive and every 50 ms, as Link does
//   channel the game channel (net_GameChannel): the transport offers it, so each connection carries its stream on a
//           net channel after the handshake, encrypted, with net_GameChannelRepeats repeats
//
// Usage: faf_netbench key=value ...
//   seconds=60 players=2 seed=1 carrier=plain|lane redundancy=2
//   latency=25 jitter=0 loss=0 burst=1 (mean lost run length) bandwidth=0 (kbit/s uplink, 0 = unlimited) reorder=0
//   partition=<start s>:<length s> (may repeat)
//   apm=120 burstat=-1 burstbytes=0
//   flush=0 (1: the sender flushes its connections as soon as a beat is written, instead of waiting for net_SendDelay)
//   any net_* console variable the connector reads, e.g. net_MaxSendRate=65536 net_FastRetransmit=1
//   out=<file> (default stdout)

#include "moho/net/CMessage.h"
#include "moho/net/CNetUDPConnector.h"
#include "moho/net/Common.h"
#include "moho/net/IMessageReceiver.h"
#include "moho/net/INetConnection.h"
#include "moho/net/INetConnector.h"
#include "moho/net/NetConVars.h"
#include "moho/net/NetPeerTransport.h"
#include "platform/PlatformDefines.h"
#include "remote/net/DatagramCipher.h"
#include "remote/net/NetChannel.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#if FAFRE_PLATFORM_WINDOWS
#include <windows.h>
#include <timeapi.h>
#endif

using namespace moho;

namespace
{
  using Clock = std::chrono::steady_clock;

  Clock::time_point gStart;

  double NowMs()
  {
    return std::chrono::duration<double, std::milli>(Clock::now() - gStart).count();
  }

  std::uint64_t NowUs()
  {
    return static_cast<std::uint64_t>(
             std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - gStart).count()
           ) +
      1;
  }

  struct Options
  {
    double seconds = 60;
    int players = 2;
    std::uint32_t seed = 1;
    std::string carrier = "plain";
    int redundancy = 2;
    double latencyMs = 25;
    double jitterMs = 0;
    double loss = 0;
    double burst = 1;
    double bandwidthKbps = 0;
    bool reorder = false;
    std::vector<std::pair<double, double>> partitions; // start, length (s from the workload's start)
    double apm = 120;
    double burstAtS = -1;
    int burstBytes = 0;
    bool flush = false;
    std::string out;
    std::vector<std::pair<std::string, std::string>> convars;
  };

  constexpr unsigned kBeatType = 100;
  constexpr unsigned kHelloType = 101;
  constexpr unsigned kBurstType = 102;
  constexpr unsigned kOrderType = 103;
  constexpr unsigned kChecksumType = 104;
  constexpr double kBeatMs = 100.0;
  constexpr int kIpUdpBytes = 28;

  std::uint32_t AddrOf(
    const int player
  )
  {
    return 0xC6336401u + static_cast<std::uint32_t>(player); // 198.51.100.1 + player
  }

  std::uint16_t PortOf(
    const int player
  )
  {
    return static_cast<std::uint16_t>(1 + player);
  }

  // One direction of the network between two players: an uplink queue, then latency and jitter, losses and
  // partitions. Thread-safe; the network thread delivers what is due.
  class Wire
  {
  public:
    Wire(
      const Options& o,
      const std::uint32_t seed
    )
      : mOpt(o)
      , mRng(seed)
    {}

    using Sink = std::function<void(const std::vector<std::uint8_t>&)>;
    Sink sink;

    std::atomic<std::uint64_t> datagrams{0};
    std::atomic<std::uint64_t> bytes{0}; // with IP and UDP headers
    std::atomic<std::uint64_t> dropped{0};
    std::vector<std::uint64_t> bytesPerBeat; // by 100 ms slot from the workload's start (guarded by mMutex)
    double workloadStartMs = 0;

    void Send(
      const void* data,
      const std::size_t size,
      const int extraHeaderBytes
    )
    {
      std::lock_guard lock(mMutex);
      const double now = NowMs();
      const std::size_t wireSize = size + static_cast<std::size_t>(extraHeaderBytes + kIpUdpBytes);
      datagrams.fetch_add(1);
      bytes.fetch_add(wireSize);
      if (now >= workloadStartMs && workloadStartMs > 0) {
        const auto slot = static_cast<std::size_t>((now - workloadStartMs) / kBeatMs);
        if (slot < 100000) {
          if (bytesPerBeat.size() <= slot) {
            bytesPerBeat.resize(slot + 1, 0);
          }
          bytesPerBeat[slot] += wireSize;
        }
      }
      // Uplink: one datagram at a time at the given rate (a queue that never overflows: the game sends little).
      double departure = now;
      if (mOpt.bandwidthKbps > 0) {
        departure = std::max(now, mUplinkFreeAt) + static_cast<double>(wireSize) * 8.0 / mOpt.bandwidthKbps;
        mUplinkFreeAt = departure;
      }
      if (Lost(now)) {
        dropped.fetch_add(1);
        return;
      }
      double delay = mOpt.latencyMs;
      if (mOpt.jitterMs > 0) {
        delay += std::uniform_real_distribution<double>(-mOpt.jitterMs, mOpt.jitterMs)(mRng);
      }
      double at = departure + std::max(0.0, delay);
      if (!mOpt.reorder) {
        at = std::max(at, mLastAt); // jitter from queues keeps the order
      }
      mLastAt = std::max(mLastAt, at);
      const auto* p = static_cast<const std::uint8_t*>(data);
      mQueue.push_back({at, std::vector<std::uint8_t>(p, p + size)});
    }

    // Takes what is due by `now`, in arrival order.
    void TakeDue(
      const double now,
      std::vector<std::vector<std::uint8_t>>& out
    )
    {
      std::lock_guard lock(mMutex);
      std::stable_sort(mQueue.begin(), mQueue.end(), [](const Item& a, const Item& b) {
        return a.at < b.at;
      });
      while (!mQueue.empty() && mQueue.front().at <= now) {
        out.push_back(std::move(mQueue.front().bytes));
        mQueue.pop_front();
      }
    }

  private:
    struct Item
    {
      double at;
      std::vector<std::uint8_t> bytes;
    };

    // Gilbert-Elliott: losses come in runs of `burst` datagrams on average, `loss` of them in the long run.
    bool Lost(
      const double now
    )
    {
      if (workloadStartMs > 0) {
        const double s = (now - workloadStartMs) / 1000.0;
        for (const auto& [start, length] : mOpt.partitions) {
          if (s >= start && s < start + length) {
            return true;
          }
        }
      }
      if (mOpt.loss <= 0) {
        return false;
      }
      std::uniform_real_distribution<double> u(0.0, 1.0);
      if (mOpt.burst <= 1.0) {
        return u(mRng) < mOpt.loss;
      }
      const double toGood = 1.0 / mOpt.burst;
      const double toBad = mOpt.loss * toGood / (1.0 - mOpt.loss);
      mBad = mBad ? u(mRng) >= toGood : u(mRng) < toBad;
      return mBad;
    }

    const Options& mOpt;
    std::mutex mMutex;
    std::mt19937 mRng;
    std::deque<Item> mQueue;
    double mUplinkFreeAt = 0;
    double mLastAt = 0;
    bool mBad = false;
  };

  // The game's datagrams to one peer: onto the wire as they are, or into a redundant lane first.
  class Carrier final : public INetPeerTransport
  {
  public:
    Carrier(
      const Options& o,
      Wire& wire,
      const bool lane,
      const bool initiator,
      const bool channel
    )
      : mWire(wire)
      , mLaneOn(lane)
      , mChannel(channel)
      , mInitiator(initiator)
    {
      if (mLaneOn) {
        faf::remote::net::ChannelConfig config;
        config.redundancy = static_cast<std::uint32_t>(o.redundancy);
        config.timeoutUs = 24ull * 3600 * 1000 * 1000;
        config.keepaliveIntervalUs = 1'000'000;
        mLane = std::make_unique<faf::remote::net::NetChannel>(config);
        faf::remote::net::ChannelKeys keys;
        for (std::size_t i = 0; i < keys.send.size(); ++i) {
          keys.send[i] = static_cast<std::uint8_t>(initiator ? i : 0x80 + i);
          keys.receive[i] = static_cast<std::uint8_t>(initiator ? 0x80 + i : i);
        }
        (void)mLane->SetKeys(keys);
      }
    }

    // Where the peer's datagrams for this side go once unwrapped.
    CNetUDPConnector* local = nullptr;
    std::uint32_t peerAddr = 0;
    std::uint16_t peerPort = 0;

    void SendDatagram(
      const void* data,
      const std::size_t size
    ) override
    {
      if (!mLaneOn) {
        mWire.Send(data, size, 0);
        return;
      }
      std::vector<std::vector<std::uint8_t>> datagrams;
      {
        std::lock_guard lock(mLaneMutex);
        (void)mLane->SendRedundant(data, size);
        mLane->Poll(NowUs(), datagrams);
      }
      Transmit(datagrams);
    }

    // A datagram from the peer's wire.
    void Arrive(
      const std::vector<std::uint8_t>& datagram
    )
    {
      if (!mLaneOn) {
        NET_DeliverFromPeerTransport(local, peerAddr, peerPort, datagram.data(), datagram.size());
        return;
      }
      std::vector<std::vector<std::uint8_t>> messages;
      std::vector<std::vector<std::uint8_t>> datagrams;
      {
        std::lock_guard lock(mLaneMutex);
        const std::uint64_t now = NowUs();
        (void)mLane->Receive(datagram.data(), datagram.size(), now);
        std::vector<std::uint8_t> m;
        while (mLane->TakeUnreliable(m)) {
          messages.push_back(std::move(m));
        }
        mLane->Poll(now, datagrams);
      }
      Transmit(datagrams);
      for (const auto& m : messages) {
        NET_DeliverFromPeerTransport(local, peerAddr, peerPort, m.data(), m.size());
      }
    }

    [[nodiscard]] bool OffersGameChannel(
      faf::remote::net::ChannelKeys& keys,
      bool& keyed
    ) const override
    {
      keyed = false;
      if (!mChannel) {
        return false;
      }
      for (std::size_t i = 0; i < keys.send.size(); ++i) {
        keys.send[i] = static_cast<std::uint8_t>(mInitiator ? 0x40 + i : 0xC0 + i);
        keys.receive[i] = static_cast<std::uint8_t>(mInitiator ? 0xC0 + i : 0x40 + i);
      }
      keyed = true;
      return true;
    }

    // The link's 50 ms timer: acks, and repeats while the game is quiet.
    void Tick()
    {
      if (!mLaneOn) {
        return;
      }
      std::vector<std::vector<std::uint8_t>> datagrams;
      {
        std::lock_guard lock(mLaneMutex);
        mLane->Poll(NowUs(), datagrams);
      }
      Transmit(datagrams);
    }

  private:
    void Transmit(
      const std::vector<std::vector<std::uint8_t>>& datagrams
    )
    {
      for (const auto& d : datagrams) {
        mWire.Send(d.data(), d.size(), 1); // ICE carries the lane behind one 'c' byte
      }
    }

    Wire& mWire;
    bool mLaneOn;
    bool mChannel;
    bool mInitiator;
    std::mutex mLaneMutex;
    std::unique_ptr<faf::remote::net::NetChannel> mLane;
  };

  // Arrival times of one sender's beats at one receiver.
  struct Arrivals final : IMessageReceiver
  {
    std::mutex mutex;
    std::map<int, double> beatAt; // beat -> ms since start
    int hellos = 0;
    int burstMessages = 0;
    double burstDoneAt = -1;

    void ReceiveMessage(
      CMessage* message,
      CMessageDispatcher* /*dispatcher*/
    ) override
    {
      const double now = NowMs();
      std::lock_guard lock(mutex);
      const unsigned type = static_cast<unsigned>(static_cast<std::uint8_t>(message->mBuff[0]));
      if (type == kHelloType) {
        ++hellos;
        return;
      }
      if (type == kOrderType || type == kChecksumType) {
        return;
      }
      if (type == kBurstType) {
        ++burstMessages;
        burstDoneAt = now;
        return;
      }
      int beat = -1;
      if (message->GetSize() >= 3 + sizeof(beat)) {
        std::memcpy(&beat, &message->mBuff[3], sizeof(beat));
      }
      beatAt.emplace(beat, now);
    }
  };

  // One beat as a player's stream carries it (CClientManagerImpl): each order its own message, then the beat's
  // checksum, then the end of the beat, which says which beat it was. Orders hold a type byte, unit ids and a target,
  // so deflate finds in them what it finds in a game.
  std::vector<CMessage> MakeBeat(
    const int beat,
    std::mt19937& rng,
    const double apm
  )
  {
    std::vector<CMessage> out;
    std::poisson_distribution<int> count(apm / 600.0);
    const int n = count(rng);
    std::uniform_int_distribution<int> units(1, 12);
    std::uniform_int_distribution<std::uint32_t> id(0x100000, 0x100400);
    std::uniform_real_distribution<float> pos(0.0f, 1024.0f);
    for (int i = 0; i < n; ++i) {
      CMessage m(MessageType(static_cast<std::uint8_t>(kOrderType)));
      std::uint8_t header[4] = {0x0C, 0x00, static_cast<std::uint8_t>(i), 0x01};
      m.Append(reinterpret_cast<const char*>(header), sizeof(header));
      const int u = units(rng);
      m.Append(reinterpret_cast<const char*>(&u), sizeof(u));
      for (int k = 0; k < u; ++k) {
        const std::uint32_t unit = id(rng);
        m.Append(reinterpret_cast<const char*>(&unit), sizeof(unit));
      }
      const float target[3] = {pos(rng), 25.0f, pos(rng)};
      m.Append(reinterpret_cast<const char*>(target), sizeof(target));
      const char tail[12] = {};
      m.Append(tail, sizeof(tail));
      out.push_back(std::move(m));
    }
    CMessage checksum(MessageType(static_cast<std::uint8_t>(kChecksumType)));
    std::uint8_t digest[16];
    for (std::uint8_t& b : digest) {
      b = static_cast<std::uint8_t>(rng());
    }
    checksum.Append(reinterpret_cast<const char*>(digest), sizeof(digest));
    checksum.Append(reinterpret_cast<const char*>(&beat), sizeof(beat));
    out.push_back(std::move(checksum));
    CMessage advance(MessageType(static_cast<std::uint8_t>(kBeatType)));
    advance.Append(reinterpret_cast<const char*>(&beat), sizeof(beat));
    out.push_back(std::move(advance));
    return out;
  }

  bool SetConVar(
    const std::string& name,
    const std::string& value
  )
  {
    struct Int
    {
      const char* name;
      std::int32_t* var;
    };
    static const Int ints[] = {
      {"net_AckDelay", &net_AckDelay},
      {"net_SendDelay", &net_SendDelay},
      {"net_MinResendDelay", &net_MinResendDelay},
      {"net_MaxResendDelay", &net_MaxResendDelay},
      {"net_MaxSendRate", &net_MaxSendRate},
      {"net_MaxBacklog", &net_MaxBacklog},
      {"net_ResendDelayBias", &net_ResendDelayBias},
      {"net_FastRetransmit", &net_FastRetransmit},
      {"net_FastAckDelay", &net_FastAckDelay},
      {"net_CompressionMethod", &net_CompressionMethod},
      {"net_GameChannelRepeats", &net_GameChannelRepeats},
      {"net_GameChannelRepeatMs", &net_GameChannelRepeatMs},
      {"net_GameChannelRepeatHoldMs", &net_GameChannelRepeatHoldMs},
    };
    for (const Int& i : ints) {
      if (name == i.name) {
        *i.var = std::stoi(value);
        return true;
      }
    }
    if (name == "net_FastResendPings") {
      net_FastResendPings = std::stof(value);
      return true;
    }
    if (name == "net_ResendPingMultiplier") {
      net_ResendPingMultiplier = std::stof(value);
      return true;
    }
    return false;
  }

  bool Parse(
    const int argc,
    char** argv,
    Options& o
  )
  {
    for (int i = 1; i < argc; ++i) {
      const std::string arg = argv[i];
      const auto eq = arg.find('=');
      if (eq == std::string::npos) {
        std::fprintf(stderr, "not key=value: %s\n", arg.c_str());
        return false;
      }
      const std::string k = arg.substr(0, eq);
      const std::string v = arg.substr(eq + 1);
      if (k == "seconds")
        o.seconds = std::stod(v);
      else if (k == "players")
        o.players = std::stoi(v);
      else if (k == "seed")
        o.seed = static_cast<std::uint32_t>(std::stoul(v));
      else if (k == "carrier")
        o.carrier = v;
      else if (k == "redundancy")
        o.redundancy = std::stoi(v);
      else if (k == "latency")
        o.latencyMs = std::stod(v);
      else if (k == "jitter")
        o.jitterMs = std::stod(v);
      else if (k == "loss")
        o.loss = std::stod(v);
      else if (k == "burst")
        o.burst = std::stod(v);
      else if (k == "bandwidth")
        o.bandwidthKbps = std::stod(v);
      else if (k == "reorder")
        o.reorder = v != "0";
      else if (k == "partition") {
        const auto colon = v.find(':');
        o.partitions.emplace_back(std::stod(v.substr(0, colon)), std::stod(v.substr(colon + 1)));
      } else if (k == "apm")
        o.apm = std::stod(v);
      else if (k == "burstat")
        o.burstAtS = std::stod(v);
      else if (k == "burstbytes")
        o.burstBytes = std::stoi(v);
      else if (k == "flush")
        o.flush = v != "0";
      else if (k == "out")
        o.out = v;
      else if (k.rfind("net_", 0) == 0) {
        if (!SetConVar(k, v)) {
          std::fprintf(stderr, "unknown console variable %s\n", k.c_str());
          return false;
        }
        o.convars.emplace_back(k, v);
      } else {
        std::fprintf(stderr, "unknown key %s\n", k.c_str());
        return false;
      }
    }
    if (o.carrier != "plain" && o.carrier != "lane" && o.carrier != "channel") {
      std::fprintf(stderr, "carrier must be plain, lane or channel\n");
      return false;
    }
    return o.players >= 2 && o.players <= 8;
  }

  std::string JsonEscape(
    const std::string& s
  )
  {
    std::string r;
    for (const char c : s) {
      if (c == '"' || c == '\\') {
        r += '\\';
      }
      r += c;
    }
    return r;
  }
} // namespace

int main(
  int argc,
  char** argv
)
{
  Options o;
  if (!Parse(argc, argv, o)) {
    return 2;
  }
#if FAFRE_PLATFORM_WINDOWS
  // The game raises the timer resolution to 1 ms at startup (StartupClientHelpers.cpp); so does the bench.
  (void)::timeBeginPeriod(1u);
#endif
  if (!NET_Init()) {
    std::fprintf(stderr, "NET_Init failed\n");
    return 3;
  }
  gStart = Clock::now();
  const int n = o.players;
  const bool lane = o.carrier == "lane";

  std::vector<CNetUDPConnector*> connectors(static_cast<std::size_t>(n));
  for (auto& c : connectors) {
    c = static_cast<CNetUDPConnector*>(NET_MakeUDPConnector(0, {}));
    if (c == nullptr) {
      std::fprintf(stderr, "no connector\n");
      return 3;
    }
  }

  // wires[i][j]: i's datagrams to j. carriers[i][j]: i's side of the i-j link.
  std::vector<std::vector<std::unique_ptr<Wire>>> wires(static_cast<std::size_t>(n));
  std::vector<std::vector<std::shared_ptr<Carrier>>> carriers(static_cast<std::size_t>(n));
  for (int i = 0; i < n; ++i) {
    wires[i].resize(static_cast<std::size_t>(n));
    carriers[i].resize(static_cast<std::size_t>(n));
    for (int j = 0; j < n; ++j) {
      if (i != j) {
        wires[i][j] = std::make_unique<Wire>(o, o.seed * 7919u + static_cast<std::uint32_t>(i * 31 + j));
      }
    }
  }
  for (int i = 0; i < n; ++i) {
    for (int j = 0; j < n; ++j) {
      if (i == j) {
        continue;
      }
      auto c = std::make_shared<Carrier>(o, *wires[i][j], lane, i < j, o.carrier == "channel");
      c->local = connectors[i];
      c->peerAddr = AddrOf(j);
      c->peerPort = PortOf(j);
      carriers[i][j] = c;
      NET_SetPeerTransport(connectors[i], AddrOf(j), PortOf(j), c);
    }
  }
  for (int i = 0; i < n; ++i) {
    for (int j = 0; j < n; ++j) {
      if (i != j) {
        Carrier* const receiver = carriers[j][i].get();
        wires[i][j]->sink = [receiver](const std::vector<std::uint8_t>& d) {
          receiver->Arrive(d);
        };
      }
    }
  }

  // connections[i][j]: i's connection to j; arrivals[i][j]: j's beats as i received them.
  std::vector<std::vector<INetConnection*>> connections(static_cast<std::size_t>(n), std::vector<INetConnection*>(n));
  std::vector<std::vector<std::unique_ptr<Arrivals>>> arrivals(static_cast<std::size_t>(n));
  for (int i = 0; i < n; ++i) {
    arrivals[i].resize(static_cast<std::size_t>(n));
    for (int j = 0; j < n; ++j) {
      if (i == j) {
        continue;
      }
      connections[i][j] =
        i < j ? connectors[i]->Connect(AddrOf(j), PortOf(j)) : connectors[i]->Accept(AddrOf(j), PortOf(j));
      arrivals[i][j] = std::make_unique<Arrivals>();
      connections[i][j]->PushReceiver(kBeatType, kChecksumType + 1, arrivals[i][j].get());
    }
  }

  std::atomic<bool> stop{false};
  std::thread network([&] {
    std::vector<std::vector<std::uint8_t>> due;
    while (!stop.load()) {
      const double now = NowMs();
      for (int i = 0; i < n; ++i) {
        for (int j = 0; j < n; ++j) {
          if (i == j) {
            continue;
          }
          due.clear();
          wires[i][j]->TakeDue(now, due);
          for (const auto& d : due) {
            wires[i][j]->sink(d);
          }
        }
      }
      std::this_thread::sleep_for(std::chrono::microseconds(250));
    }
  });

  // As the game's issue thread (CClientManagerImpl::DoBeat): Pull only. In a running game nothing calls the
  // connector's Push, which would flush the connections at once; written data waits for net_SendDelay or a full packet.
  auto pump = [&] {
    for (CNetUDPConnector* c : connectors) {
      c->Pull();
    }
  };

  // Connect: a hello each way, until every connection has heard one.
  for (int i = 0; i < n; ++i) {
    for (int j = 0; j < n; ++j) {
      if (i != j) {
        CMessage hello(MessageType(static_cast<std::uint8_t>(kHelloType)));
        hello.Append("hi", 2);
        connections[i][j]->Write(hello);
      }
    }
  }
  const Clock::time_point connectBy = Clock::now() + std::chrono::seconds(10);
  double nextTick = NowMs();
  for (;;) {
    bool all = true;
    for (int i = 0; i < n; ++i) {
      for (int j = 0; j < n; ++j) {
        if (i != j) {
          std::lock_guard lock(arrivals[i][j]->mutex);
          all = all && arrivals[i][j]->hellos > 0;
        }
      }
    }
    if (all) {
      break;
    }
    if (Clock::now() > connectBy) {
      std::fprintf(stderr, "connections did not come up\n");
      std::_Exit(4);
    }
    pump();
    if (NowMs() >= nextTick) {
      nextTick += 50;
      for (auto& row : carriers) {
        for (auto& c : row) {
          if (c) {
            c->Tick();
          }
        }
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }

  // Workload: beat k leaves every player at start + k * 100 ms.
  const double start = NowMs() + 200;
  for (auto& row : wires) {
    for (auto& w : row) {
      if (w) {
        w->workloadStartMs = start;
      }
    }
  }
  const int beats = static_cast<int>(o.seconds * 1000.0 / kBeatMs);
  std::vector<std::vector<double>> sentAt(static_cast<std::size_t>(n), std::vector<double>(beats, -1));
  std::vector<std::mt19937> orderRng;
  for (int i = 0; i < n; ++i) {
    orderRng.emplace_back(o.seed * 104729u + static_cast<std::uint32_t>(i));
  }
  std::vector<std::uint64_t> beatBytes(static_cast<std::size_t>(n), 0);
  int next = 0;
  bool burstSent = o.burstAtS < 0 || o.burstBytes <= 0;
  double burstSentAt = -1;
  const double endAt = start + beats * kBeatMs + 10000.0; // 10 s for the last beats to arrive
  while (NowMs() < endAt) {
    const double now = NowMs();
    while (next < beats && now >= start + next * kBeatMs) {
      for (int i = 0; i < n; ++i) {
        std::vector<CMessage> beat = MakeBeat(next, orderRng[i], o.apm);
        for (CMessage& m : beat) {
          beatBytes[i] += m.GetSize();
          for (int j = 0; j < n; ++j) {
            if (i != j) {
              connections[i][j]->Write(m);
            }
          }
        }
        sentAt[i][next] = NowMs();
        if (o.flush) {
          connectors[i]->Push(); // flush=1: the beat goes out as soon as it is complete
        }
      }
      ++next;
    }
    if (!burstSent && now >= start + o.burstAtS * 1000.0) {
      // A large order (#236's modelled burst): incompressible bytes from player 0 to everyone, in 4 KB messages.
      std::mt19937 rng(o.seed);
      std::uniform_int_distribution<int> byte(0, 255);
      for (int j = 1; j < n; ++j) {
        int left = o.burstBytes;
        while (left > 0) {
          const int size = std::min(left, 4096);
          CMessage m(MessageType(static_cast<std::uint8_t>(kBurstType)));
          std::vector<char> filler(static_cast<std::size_t>(size));
          for (char& c : filler) {
            c = static_cast<char>(byte(rng));
          }
          m.Append(filler.data(), filler.size());
          connections[0][j]->Write(m);
          left -= size;
        }
      }
      burstSent = true;
      burstSentAt = NowMs();
    }
    pump();
    if (now >= nextTick) {
      nextTick += 50;
      for (auto& row : carriers) {
        for (auto& c : row) {
          if (c) {
            c->Tick();
          }
        }
      }
    }
    // Done early once every beat has arrived everywhere.
    if (next >= beats) {
      bool all = true;
      for (int i = 0; i < n && all; ++i) {
        for (int j = 0; j < n && all; ++j) {
          if (i != j) {
            std::lock_guard lock(arrivals[i][j]->mutex);
            all = static_cast<int>(arrivals[i][j]->beatAt.size()) >= beats;
          }
        }
      }
      if (all) {
        break;
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  stop = true;
  network.join();

  std::ostringstream js;
  js.setf(std::ios::fixed);
  js.precision(2);
  js << "{\"carrier\":\"" << o.carrier << "\",\"players\":" << n << ",\"seconds\":" << o.seconds
     << ",\"seed\":" << o.seed << ",\"redundancy\":" << o.redundancy << ",\"latency\":" << o.latencyMs
     << ",\"jitter\":" << o.jitterMs << ",\"loss\":" << o.loss << ",\"burst\":" << o.burst
     << ",\"bandwidth\":" << o.bandwidthKbps << ",\"reorder\":" << (o.reorder ? 1 : 0) << ",\"apm\":" << o.apm
     << ",\"burstat\":" << o.burstAtS << ",\"burstbytes\":" << o.burstBytes << ",\"flush\":" << (o.flush ? 1 : 0)
     << ",\"partitions\":[";
  for (std::size_t p = 0; p < o.partitions.size(); ++p) {
    js << (p ? "," : "") << "[" << o.partitions[p].first << "," << o.partitions[p].second << "]";
  }
  js << "],\"convars\":{";
  for (std::size_t c = 0; c < o.convars.size(); ++c) {
    js << (c ? "," : "") << "\"" << JsonEscape(o.convars[c].first) << "\":\"" << JsonEscape(o.convars[c].second)
       << "\"";
  }
  js << "},\"beats\":" << beats << ",\"payloadBytes\":[";
  for (int i = 0; i < n; ++i) {
    js << (i ? "," : "") << beatBytes[i];
  }
  js << "],\"links\":[";
  bool firstLink = true;
  for (int i = 0; i < n; ++i) {
    for (int j = 0; j < n; ++j) {
      if (i == j) {
        continue;
      }
      // Beats from i as j received them.
      Arrivals& a = *arrivals[j][i];
      Wire& w = *wires[i][j];
      std::lock_guard lock(a.mutex);
      js << (firstLink ? "" : ",") << "{\"from\":" << i << ",\"to\":" << j << ",\"datagrams\":" << w.datagrams.load()
         << ",\"bytes\":" << w.bytes.load() << ",\"dropped\":" << w.dropped.load() << ",\"delay\":[";
      firstLink = false;
      for (int b = 0; b < beats; ++b) {
        const auto it = a.beatAt.find(b);
        js << (b ? "," : "") << (it == a.beatAt.end() ? -1.0 : it->second - sentAt[i][b]);
      }
      js << "],\"bytesPerBeat\":[";
      for (std::size_t s = 0; s < w.bytesPerBeat.size(); ++s) {
        js << (s ? "," : "") << w.bytesPerBeat[s];
      }
      js << "],\"burstMs\":";
      js << (i == 0 && burstSentAt >= 0 && a.burstDoneAt >= 0 ? a.burstDoneAt - burstSentAt : -1.0);
      js << "}";
    }
  }
  js << "]}\n";

  if (o.out.empty()) {
    std::fputs(js.str().c_str(), stdout);
  } else {
    std::ofstream f(o.out, std::ios::app);
    f << js.str();
  }
  std::fflush(stdout);
  // The connectors' goodbyes take a round trip each and change nothing measured here.
  std::_Exit(0);
}
