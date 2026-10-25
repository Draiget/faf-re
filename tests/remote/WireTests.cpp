// Engine addition, server mode: tests for the server-mode wire format (src/remote/wire):
// bit stream, quantisation, content ordinals, the version handshake, and view frames.
// The frame tests are the property WPR.38 asks for: decode(encode(f, b), b) == f over
// random frame sequences and baselines, plus a decoder fed truncated, corrupted and hostile
// input, which must refuse it without crashing or allocating without bound.
//
// Build: cmake --build --preset clang-x64-release-server --target faf_remote_tests
// Run:   build\clang-x64-release-server\tests\remote\faf_remote_tests.exe   (exit code = failures)

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <limits>
#include <random>
#include <string>
#include <vector>

#include "remote/wire/BitStream.h"
#include "remote/wire/EntityFrame.h"
#include "remote/wire/OrdinalTable.h"
#include "remote/wire/Quantize.h"
#include "remote/wire/WireVersion.h"

using namespace faf::remote::wire;

namespace
{
  // --- Harness (as tests/net) ------------------------------------------------------------

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
      std::printf("  FAIL %s: non-std exception escaped\n", test.name);
    }
    std::printf("%s %s\n", gFailures == failuresBefore ? "ok  " : "FAIL", test.name);
    std::fflush(stdout);
  }

  [[nodiscard]] std::vector<std::uint8_t> Bytes(const BitWriter& writer)
  {
    const auto bytes = writer.Bytes();
    return {bytes.begin(), bytes.end()};
  }

  // --- Bit stream -------------------------------------------------------------------------

  void TestBitStreamRoundTrip()
  {
    BitWriter writer;
    for (int bits = 0; bits <= 32; ++bits) {
      const std::uint32_t value = bits == 32 ? 0xA5C3F00Fu : (0xA5C3F00Fu & ((1u << bits) - 1u));
      writer.WriteBits(value, bits);
    }
    const std::uint32_t varints[] = {0u, 1u, 127u, 128u, 16383u, 16384u, (1u << 21) - 1u, 1u << 28, 0xFFFFFFFFu};
    for (const std::uint32_t v : varints) {
      writer.WriteVarUint(v);
    }
    const float floats[] = {0.0f, -0.0f, 1.5f, -3.25e-20f, std::numeric_limits<float>::infinity(),
                            std::bit_cast<float>(0x7FC12345u)};
    for (const float f : floats) {
      writer.WriteFloatExact(f);
    }
    writer.WriteBool(true);

    const std::vector<std::uint8_t> bytes = Bytes(writer);
    CHECK(bytes.size() == (writer.BitCount() + 7u) / 8u);
    BitReader reader(bytes);
    for (int bits = 0; bits <= 32; ++bits) {
      const std::uint32_t value = bits == 32 ? 0xA5C3F00Fu : (0xA5C3F00Fu & ((1u << bits) - 1u));
      CHECK(reader.ReadBits(bits) == value);
    }
    for (const std::uint32_t v : varints) {
      CHECK(reader.ReadVarUint() == v);
    }
    for (const float f : floats) {
      CHECK(std::bit_cast<std::uint32_t>(reader.ReadFloatExact()) == std::bit_cast<std::uint32_t>(f));
    }
    CHECK(reader.ReadBool());
    CHECK(reader.Ok());
  }

  void TestBitStreamOverrun()
  {
    const std::uint8_t one[] = {0xFFu};
    BitReader reader(one);
    CHECK(reader.ReadBits(8) == 0xFFu);
    CHECK(reader.Ok());
    CHECK(reader.ReadBits(1) == 0u);
    CHECK(!reader.Ok());
    CHECK(reader.ReadBits(4) == 0u); // stays failed
    CHECK(reader.BitsLeft() == 0u);

    BitReader badWidth(one);
    CHECK(badWidth.ReadBits(33) == 0u && !badWidth.Ok());
  }

  void TestBitStreamMalformedVarUint()
  {
    const std::uint8_t sixGroups[] = {0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x00u};
    BitReader a(sixGroups);
    (void)a.ReadVarUint();
    CHECK(!a.Ok());

    const std::uint8_t wideFifth[] = {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x1Fu}; // 5th group > 4 bits
    BitReader b(wideFifth);
    (void)b.ReadVarUint();
    CHECK(!b.Ok());

    const std::uint8_t maxValue[] = {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x0Fu};
    BitReader c(maxValue);
    CHECK(c.ReadVarUint() == 0xFFFFFFFFu && c.Ok());

    const std::uint8_t truncated[] = {0x80u, 0x80u};
    BitReader d(truncated);
    (void)d.ReadVarUint();
    CHECK(!d.Ok());
  }

  // --- Quantisation -----------------------------------------------------------------------

  void TestAxisQuantizer()
  {
    const SAxisQuantizer axis{-256.0f, 1.0f / 64.0f, 17};
    for (float v = -256.0f; v < 1700.0f; v += 0.37f) {
      const float back = axis.Decode(axis.Encode(v));
      CHECK(std::fabs(back - v) <= axis.step * 0.5f + 1e-4f);
    }
    CHECK(axis.Encode(-1.0e9f) == 0u);
    CHECK(axis.Encode(1.0e9f) == axis.MaxQuantized());
    CHECK(axis.Encode(std::numeric_limits<float>::quiet_NaN()) == 0u);
    CHECK(axis.Encode(std::numeric_limits<float>::infinity()) == axis.MaxQuantized());
    CHECK(axis.Decode(0xFFFFFFFFu) == axis.Decode(axis.MaxQuantized()));
  }

  void TestPositionQuantizerForMap()
  {
    // 5 km (256), 20 km (1024) and 81 km (4096) maps plus 256 units of margin each side.
    CHECK(SPositionQuantizer::ForMap(256.0f, 256.0f).x.bits == 16);
    CHECK(SPositionQuantizer::ForMap(1024.0f, 1024.0f).x.bits == 17);
    CHECK(SPositionQuantizer::ForMap(4096.0f, 4096.0f).x.bits == 19);
    const SPositionQuantizer q = SPositionQuantizer::ForMap(4096.0f, 1024.0f);
    CHECK(q.x.bits == 19 && q.z.bits == 17 && q.y.bits == 16);
    CHECK(q.x.Decode(q.x.Encode(4096.0f + 255.0f)) > 4096.0f + 254.9f);
    CHECK(q.x.Decode(q.x.Encode(-255.0f)) < -254.9f);
  }

  void TestQuaternionPacking()
  {
    std::mt19937 rng(1234u);
    std::normal_distribution<float> normal(0.0f, 1.0f);
    float worst = 0.0f;
    for (int i = 0; i < 20000; ++i) {
      std::array<float, 4> q{normal(rng), normal(rng), normal(rng), normal(rng)};
      const float length = std::sqrt(q[0] * q[0] + q[1] * q[1] + q[2] * q[2] + q[3] * q[3]);
      for (float& c : q) {
        c /= length;
      }
      const std::array<float, 4> back = UnpackQuaternion(PackQuaternion(q));
      // q and -q are one rotation: compare against the sign that matches.
      const float dot = q[0] * back[0] + q[1] * back[1] + q[2] * back[2] + q[3] * back[3];
      const float sign = dot < 0.0f ? -1.0f : 1.0f;
      for (int c = 0; c < 4; ++c) {
        worst = std::max(worst, std::fabs(q[c] * sign - back[c]));
      }
    }
    // 10 bits over [-0.707, 0.707]: half a step is 0.00069 on the three sent components; the
    // rebuilt one can be off by a little more.
    CHECK(worst < 0.004f);
    // Yaw-only rotations: detected, quantised to 1/65536 turn, and back within half a step.
    for (int i = 0; i < 4096; ++i) {
      const double yaw = 6.283185307179586 * (i + 0.37) / 4096.0;
      const std::array<float, 4> q{0.0f, static_cast<float>(std::sin(yaw / 2)), 0.0f, static_cast<float>(std::cos(yaw / 2))};
      CHECK(IsYawOnly(q));
      const std::array<float, 4> back = YawToQuaternion(QuantizeYaw(q));
      const float dot = std::fabs(q[1] * back[1] + q[3] * back[3]);
      CHECK(dot > 0.99999f);
    }
    CHECK(!IsYawOnly({0.1f, 0.7f, 0.0f, 0.7f}));
    CHECK(QuantizeYaw({0.0f, 0.0f, 0.0f, 1.0f}) == 0u);
    CHECK(QuantizeYaw({0.0f, 0.0f, 0.0f, -1.0f}) == 0u); // -q is the same rotation (a full turn)
    const std::array<float, 4> identity{0.0f, 0.0f, 0.0f, 1.0f};
    const std::array<float, 4> back = UnpackQuaternion(PackQuaternion(identity));
    CHECK(std::fabs(back[3] - 1.0f) < 1e-3f);
  }

  // --- Content ordinals -------------------------------------------------------------------

  void TestOrdinalTable()
  {
    const std::vector<std::string> a{"uel0001", "URB0101", "xsl0402", "uel0001", "dra0202"};
    const std::vector<std::string> b{"dra0202", "xsl0402", "urb0101", "UEL0001"};
    const COrdinalTable ta = COrdinalTable::Build(a);
    const COrdinalTable tb = COrdinalTable::Build(b);
    CHECK(ta.Size() == 4u);
    CHECK(ta.Hash() == tb.Hash());
    for (std::uint32_t i = 0; i < ta.Size(); ++i) {
      CHECK(ta.Name(i) == tb.Name(i));
      CHECK(ta.Ordinal(ta.Name(i)) == i);
    }
    CHECK(ta.Ordinal("URB0101") == ta.Ordinal("urb0101"));
    CHECK(ta.Ordinal("ual0001") == COrdinalTable::kNone);
    CHECK(ta.Name(99u).empty());

    const std::vector<std::string> c{"dra0202", "xsl0402", "urb0101", "uel0002"};
    CHECK(COrdinalTable::Build(c).Hash() != ta.Hash());
    const std::vector<std::string> d{"dra0202", "xsl0402", "urb0101"};
    CHECK(COrdinalTable::Build(d).Hash() != ta.Hash());
    // A different split of the same characters must not collide.
    const std::vector<std::string> e{"ab", "c"};
    const std::vector<std::string> f{"a", "bc"};
    CHECK(COrdinalTable::Build(e).Hash() != COrdinalTable::Build(f).Hash());

    SContentTables one{ta, tb, ta};
    SContentTables two{ta, ta, tb};
    CHECK(one.Hash() == two.Hash()); // ta and tb are the same content
    SContentTables three{ta, COrdinalTable::Build(c), ta};
    CHECK(three.Hash() != one.Hash());
  }

  // --- Handshake versions -----------------------------------------------------------------

  void TestHello()
  {
    SWireHello local{};
    local.contentHash = 0x0123456789ABCDEFull;
    BitWriter writer;
    local.Encode(writer);
    const std::vector<std::uint8_t> bytes = Bytes(writer);
    BitReader reader(bytes);
    const auto decoded = SWireHello::Decode(reader);
    CHECK(decoded.has_value());
    CHECK(decoded && decoded->protocolVersion == kProtocolVersion);
    CHECK(decoded && decoded->laneVersions == kLaneVersions);
    CHECK(decoded && decoded->contentHash == local.contentHash);
    CHECK(decoded && !WireIncompatibility(local, *decoded).has_value());

    for (std::size_t length = 0; length < bytes.size(); ++length) {
      BitReader truncated(std::span<const std::uint8_t>(bytes.data(), length));
      CHECK(!SWireHello::Decode(truncated).has_value());
    }

    std::vector<std::uint8_t> badMagic = bytes;
    badMagic[0] ^= 0x01u;
    BitReader badReader(badMagic);
    CHECK(!SWireHello::Decode(badReader).has_value());

    SWireHello other = local;
    other.protocolVersion = kProtocolVersion + 1;
    CHECK(WireIncompatibility(local, other).has_value());
    other = local;
    other.laneVersions[static_cast<std::size_t>(ELane::LuaSync)] = 99;
    const auto why = WireIncompatibility(local, other);
    CHECK(why.has_value() && why->find("lua sync") != std::string::npos);
    other = local;
    other.contentHash ^= 1u;
    CHECK(WireIncompatibility(local, other).has_value());

    // A newer build with more lanes: the known lanes decode, the extra ones are dropped.
    BitWriter newer;
    newer.WriteBits(0x46414657u, 32);
    newer.WriteBits(kProtocolVersion, 16);
    newer.WriteVarUint(static_cast<std::uint32_t>(kLaneCount + 2));
    for (std::size_t lane = 0; lane < kLaneCount + 2; ++lane) {
      newer.WriteBits(lane < kLaneCount ? kLaneVersions[lane] : 7u, 16);
    }
    newer.WriteBits(0u, 32);
    newer.WriteBits(0u, 32);
    const std::vector<std::uint8_t> newerBytes = Bytes(newer);
    BitReader newerReader(newerBytes);
    const auto fromNewer = SWireHello::Decode(newerReader);
    CHECK(fromNewer.has_value() && fromNewer->laneVersions == kLaneVersions);

    // A hello claiming a huge lane count is refused before reading it.
    BitWriter hostile;
    hostile.WriteBits(0x46414657u, 32);
    hostile.WriteBits(kProtocolVersion, 16);
    hostile.WriteVarUint(0xFFFFFFFFu);
    const std::vector<std::uint8_t> hostileBytes = Bytes(hostile);
    BitReader hostileReader(hostileBytes);
    CHECK(!SWireHello::Decode(hostileReader).has_value());
  }

  // --- View frames ------------------------------------------------------------------------

  const SFrameCodec kCodec{SPositionQuantizer::ForMap(1024.0f, 1024.0f), 1u << 12};

  /** Random walk of an entity population: creations, removals, partial changes. */
  class CFrameGenerator
  {
  public:
    explicit CFrameGenerator(const std::uint32_t seed)
      : mRng(seed)
    {}

    SViewFrame Next()
    {
      SViewFrame frame{};
      frame.frameId = ++mFrameId;
      frame.beat = mFrameId * 3u;
      std::vector<SEntityRecord> next;
      for (SEntityRecord record : mLive) {
        if (Chance(0.05)) {
          continue; // removed
        }
        if (Chance(0.4)) {
          Mutate(record);
        }
        next.push_back(record);
      }
      const int creations = static_cast<int>(mRng() % 8u);
      for (int i = 0; i < creations && next.size() < kCodec.maxEntities - 8u; ++i) {
        mNextId += 1u + mRng() % 300u; // gaps of every size, never reused
        next.push_back(RandomRecord(mNextId));
      }
      frame.entities = std::move(next);
      mLive = frame.entities;
      return frame;
    }

  private:
    bool Chance(const double p) { return std::uniform_real_distribution<double>(0.0, 1.0)(mRng) < p; }

    std::uint32_t Axis(const SAxisQuantizer& axis) { return mRng() % (axis.MaxQuantized() + 1u); }

    float RandomFloat()
    {
      switch (mRng() % 6u) {
      case 0:
        return 0.0f;
      case 1:
        return -0.0f;
      case 2:
        return std::bit_cast<float>(0x7FC00001u + (mRng() & 0xFFu)); // NaN payloads survive
      default:
        return std::uniform_real_distribution<float>(-1.0e6f, 1.0e6f)(mRng);
      }
    }

    SEntityRecord RandomRecord(const std::uint32_t id)
    {
      SEntityRecord record{};
      record.id = id;
      record.blueprint = mRng() % 3u == 0u ? COrdinalTable::kNone : mRng() % 5000u;
      record.army = static_cast<std::uint8_t>(mRng() % 17u == 16u ? 0xFFu : mRng() % 16u);
      record.position = {Axis(kCodec.position.x), Axis(kCodec.position.y), Axis(kCodec.position.z)};
      record.yawOnly = (mRng() & 1u) != 0u;
      record.orientation = record.yawOnly ? (mRng() & 0xFFFFu) : static_cast<std::uint32_t>(mRng());
      record.health = RandomFloat();
      record.maxHealth = RandomFloat();
      record.fractionComplete = RandomFloat();
      record.flags = static_cast<std::uint16_t>(mRng());
      record.isUnit = (mRng() & 1u) != 0u;
      if (record.isUnit) {
        record.unit.fuelRatio = RandomFloat();
        record.unit.shieldRatio = RandomFloat();
        record.unit.workProgress = RandomFloat();
        record.unit.unitStates = (static_cast<std::uint64_t>(mRng()) << 32) | mRng();
        record.unit.scriptBits = static_cast<std::uint32_t>(mRng());
        for (std::uint16_t& count : record.unit.siloCounts) {
          count = static_cast<std::uint16_t>(mRng());
        }
        record.unit.unitFlags = static_cast<std::uint8_t>(mRng());
      }
      return record;
    }

    void Mutate(SEntityRecord& record)
    {
      const SEntityRecord fresh = RandomRecord(record.id);
      const std::uint32_t fields = mRng() & 0xFFFFu;
      if ((fields & kFieldBlueprint) != 0u) record.blueprint = fresh.blueprint;
      if ((fields & kFieldArmy) != 0u) record.army = fresh.army;
      if ((fields & kFieldPosition) != 0u) record.position = fresh.position;
      if ((fields & kFieldOrientation) != 0u) {
        record.orientation = fresh.orientation;
        record.yawOnly = fresh.yawOnly;
      }
      if ((fields & kFieldHealth) != 0u) record.health = fresh.health;
      if ((fields & kFieldMaxHealth) != 0u) record.maxHealth = fresh.maxHealth;
      if ((fields & kFieldFraction) != 0u) record.fractionComplete = fresh.fractionComplete;
      if ((fields & kFieldFlags) != 0u) record.flags = fresh.flags;
      // A kind change is rare in the sim (an entity is a unit for life); flip it now and then.
      if ((fields & kFieldKind) != 0u && mRng() % 8u == 0u) {
        record.isUnit = fresh.isUnit;
        record.unit = fresh.unit;
      }
      if (record.isUnit) {
        SUnitFields& unit = record.unit;
        const SUnitFields source = fresh.isUnit ? fresh.unit : RandomRecordUnit();
        if ((fields & kFieldUnitFuel) != 0u) unit.fuelRatio = source.fuelRatio;
        if ((fields & kFieldUnitShield) != 0u) unit.shieldRatio = source.shieldRatio;
        if ((fields & kFieldUnitWork) != 0u) unit.workProgress = source.workProgress;
        if ((fields & kFieldUnitStates) != 0u) unit.unitStates = source.unitStates;
        if ((fields & kFieldUnitScriptBits) != 0u) unit.scriptBits = source.scriptBits;
        if ((fields & kFieldUnitSilos) != 0u) unit.siloCounts = source.siloCounts;
        if ((fields & kFieldUnitFlags) != 0u) unit.unitFlags = source.unitFlags;
      }
    }

    SUnitFields RandomRecordUnit()
    {
      SEntityRecord record = RandomRecord(0);
      while (!record.isUnit) {
        record = RandomRecord(0);
      }
      return record.unit;
    }

    std::mt19937 mRng;
    std::uint32_t mFrameId = 100;
    std::uint32_t mNextId = 0;
    std::vector<SEntityRecord> mLive;
  };

  [[nodiscard]] std::vector<std::uint8_t> Encode(const SViewFrame& frame, const SViewFrame* baseline)
  {
    BitWriter writer;
    const bool encoded = EncodeFrame(frame, baseline, kCodec, writer);
    CHECK(encoded);
    return Bytes(writer);
  }

  [[nodiscard]] bool Decode(const std::vector<std::uint8_t>& bytes, const SViewFrame* baseline, SViewFrame& out)
  {
    BitReader reader(bytes);
    return DecodeFrame(reader, baseline, kCodec, out);
  }

  /** What the client does with consecutive decoded frames (WPR.38). */
  [[nodiscard]] SViewFrame ApplyDelta(const SViewFrame& before, const SFrameDelta& delta, const SViewFrame& header)
  {
    std::vector<SEntityRecord> world = before.entities;
    std::erase_if(world, [&](const SEntityRecord& r) {
      return std::binary_search(delta.removed.begin(), delta.removed.end(), r.id);
    });
    for (const SFrameDelta::SChange& change : delta.changed) {
      for (SEntityRecord& r : world) {
        if (r.id == change.record.id) {
          r = change.record;
        }
      }
    }
    world.insert(world.end(), delta.created.begin(), delta.created.end());
    std::sort(world.begin(), world.end(), [](const SEntityRecord& x, const SEntityRecord& y) { return x.id < y.id; });
    SViewFrame frame = header;
    frame.entities = std::move(world);
    return frame;
  }

  void TestFrameRoundTripProperty()
  {
    for (std::uint32_t seed = 1; seed <= 6; ++seed) {
      CFrameGenerator generator(seed);
      std::vector<SViewFrame> history;
      for (int step = 0; step < 120; ++step) {
        const SViewFrame frame = generator.Next();
        CHECK(frame.IsWellFormed());

        SViewFrame full{};
        CHECK(Decode(Encode(frame, nullptr), nullptr, full) && full == frame);

        // Against the previous frame and against older ones (an older acknowledged baseline).
        for (std::size_t back = 1; back <= 5 && back <= history.size(); back += 2) {
          const SViewFrame& baseline = history[history.size() - back];
          SViewFrame decoded{};
          CHECK(Decode(Encode(frame, &baseline), &baseline, decoded) && decoded == frame);
        }

        // The client's world follows the frame-to-frame difference.
        if (!history.empty()) {
          const SViewFrame& previous = history.back();
          CHECK(ApplyDelta(previous, ComputeFrameDelta(&previous, frame), frame) == frame);
        }
        history.push_back(frame);
      }
    }
  }

  void TestFrameUnchangedIsSmall()
  {
    CFrameGenerator generator(42u);
    SViewFrame frame{};
    for (int i = 0; i < 30; ++i) {
      frame = generator.Next();
    }
    SViewFrame same = frame;
    same.frameId += 1;
    const std::vector<std::uint8_t> bytes = Encode(same, &frame);
    CHECK(bytes.size() == 2u + 4u + 4u + 4u + 3u); // header and three empty sections
    SViewFrame decoded{};
    CHECK(Decode(bytes, &frame, decoded) && decoded == same);

    // One changed health costs gap + mask + 4 bytes.
    SViewFrame oneChange = same;
    oneChange.frameId += 1;
    oneChange.entities[oneChange.entities.size() / 2].health += 1.0f;
    const std::vector<std::uint8_t> oneBytes = Encode(oneChange, &frame);
    CHECK(oneBytes.size() <= bytes.size() + 1u + 3u + 1u + 4u);
    CHECK(Decode(oneBytes, &frame, decoded) && decoded == oneChange);
  }

  void TestFrameBaselineChecks()
  {
    CFrameGenerator generator(7u);
    const SViewFrame first = generator.Next();
    const SViewFrame second = generator.Next();
    const SViewFrame third = generator.Next();
    const std::vector<std::uint8_t> delta = Encode(third, &second);
    const std::vector<std::uint8_t> full = Encode(third, nullptr);
    CHECK(PeekFrameBaseline(delta) == second.frameId);
    CHECK(PeekFrameBaseline(full) == kNoBaseline);

    SViewFrame out{};
    CHECK(!Decode(delta, nullptr, out));  // needs its baseline
    CHECK(!Decode(delta, &first, out));   // another baseline
    CHECK(!Decode(full, &second, out));   // a full frame takes none
    CHECK(Decode(delta, &second, out) && out == third);

    // A baseline with the right id but other content is caught when the removals or changes
    // name entities it does not have.
    SViewFrame impostor = second;
    impostor.entities.clear();
    const bool mismatch = Decode(delta, &impostor, out);
    CHECK(!mismatch || out == third);
  }

  void TestEncodeRejects()
  {
    SViewFrame unsorted{};
    unsorted.entities.resize(2);
    unsorted.entities[0].id = 5;
    unsorted.entities[1].id = 5;
    BitWriter writer;
    CHECK(!EncodeFrame(unsorted, nullptr, kCodec, writer));

    SViewFrame outOfRange{};
    outOfRange.entities.resize(1);
    outOfRange.entities[0].position[1] = kCodec.position.y.MaxQuantized() + 1u;
    CHECK(!EncodeFrame(outOfRange, nullptr, kCodec, writer));

    SViewFrame tooMany{};
    tooMany.entities.resize(kCodec.maxEntities + 1u);
    for (std::uint32_t i = 0; i < tooMany.entities.size(); ++i) {
      tooMany.entities[i].id = i;
    }
    CHECK(!EncodeFrame(tooMany, nullptr, kCodec, writer));
  }

  void TestDecoderTruncation()
  {
    CFrameGenerator generator(99u);
    SViewFrame previous = generator.Next();
    for (int i = 0; i < 5; ++i) {
      previous = generator.Next();
    }
    const SViewFrame frame = generator.Next();
    const std::vector<std::uint8_t> bytes = Encode(frame, &previous);
    for (std::size_t length = 0; length < bytes.size(); ++length) {
      const std::vector<std::uint8_t> cut(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(length));
      SViewFrame out{};
      // Cutting only padding bits of the last byte cannot happen here (whole bytes are cut),
      // so every shorter buffer must be refused.
      CHECK(!Decode(cut, &previous, out));
    }
  }

  void TestDecoderCorruptionAndGarbage()
  {
    CFrameGenerator generator(2024u);
    SViewFrame previous = generator.Next();
    for (int i = 0; i < 8; ++i) {
      previous = generator.Next();
    }
    const SViewFrame frame = generator.Next();
    const std::vector<std::uint8_t> bytes = Encode(frame, &previous);

    std::mt19937 rng(5u);
    int accepted = 0;
    for (int trial = 0; trial < 4000; ++trial) {
      std::vector<std::uint8_t> corrupt = bytes;
      const int flips = 1 + static_cast<int>(rng() % 4u);
      for (int f = 0; f < flips; ++f) {
        corrupt[rng() % corrupt.size()] ^= static_cast<std::uint8_t>(1u << (rng() % 8u));
      }
      SViewFrame out{};
      if (Decode(corrupt, &previous, out)) {
        // A flip inside a field value decodes to another valid frame; it must still be well
        // formed and within the codec's limits (the frame hash, WPR.30, catches it later).
        ++accepted;
        CHECK(out.IsWellFormed() && out.entities.size() <= kCodec.maxEntities);
      }
    }
    std::printf("  corrupted deltas accepted as other valid frames: %d of 4000\n", accepted);

    for (int trial = 0; trial < 4000; ++trial) {
      std::vector<std::uint8_t> garbage(rng() % 600u);
      for (std::uint8_t& b : garbage) {
        b = static_cast<std::uint8_t>(rng());
      }
      SViewFrame out{};
      if (Decode(garbage, nullptr, out)) {
        CHECK(out.IsWellFormed() && out.entities.size() <= kCodec.maxEntities);
      }
    }
  }

  void TestDecoderHostileCounts()
  {
    // A full frame claiming 2^32-1 creations in a 20-byte buffer is refused before any
    // allocation; so is one just over the codec's entity limit.
    for (const std::uint32_t count : {0xFFFFFFFFu, kCodec.maxEntities + 1u, 1000u}) {
      BitWriter writer;
      writer.WriteBits(kLaneVersions[static_cast<std::size_t>(ELane::Entities)], 16);
      writer.WriteBits(1u, 32);
      writer.WriteBits(kNoBaseline, 32);
      writer.WriteBits(0u, 32);
      writer.WriteVarUint(0u);    // removed
      writer.WriteVarUint(count); // created
      const std::vector<std::uint8_t> bytes = Bytes(writer);
      SViewFrame out{};
      CHECK(!Decode(bytes, nullptr, out));
    }

    // Removing an id the baseline does not have.
    SViewFrame baseline{};
    baseline.frameId = 9;
    baseline.entities.resize(1);
    baseline.entities[0].id = 10;
    BitWriter writer;
    writer.WriteBits(kLaneVersions[static_cast<std::size_t>(ELane::Entities)], 16);
    writer.WriteBits(10u, 32);
    writer.WriteBits(9u, 32);
    writer.WriteBits(0u, 32);
    writer.WriteVarUint(1u);
    writer.WriteVarUint(11u); // id 11: not in the baseline
    writer.WriteVarUint(0u);
    writer.WriteVarUint(0u);
    SViewFrame out{};
    CHECK(!Decode(Bytes(writer), &baseline, out));

    // Creating an id the baseline already has.
    BitWriter dup;
    dup.WriteBits(kLaneVersions[static_cast<std::size_t>(ELane::Entities)], 16);
    dup.WriteBits(10u, 32);
    dup.WriteBits(9u, 32);
    dup.WriteBits(0u, 32);
    dup.WriteVarUint(0u);
    dup.WriteVarUint(1u);
    dup.WriteVarUint(10u);
    // every field of a non-unit, in the encoder's order: kind, position, orientation,
    // health, fraction, flags, max health, blueprint, army
    dup.WriteBool(false);
    dup.WriteBits(0u, kCodec.position.x.bits);
    dup.WriteBits(0u, kCodec.position.y.bits);
    dup.WriteBits(0u, kCodec.position.z.bits);
    dup.WriteBool(false); // smallest-three orientation
    dup.WriteBits(0u, 32);
    dup.WriteFloatExact(0.0f);
    dup.WriteFloatExact(0.0f);
    dup.WriteBits(0u, 16);
    dup.WriteFloatExact(0.0f);
    dup.WriteVarUint(COrdinalTable::kNone);
    dup.WriteBits(0xFFu, 8);
    dup.WriteVarUint(0u);
    CHECK(!Decode(Bytes(dup), &baseline, out));
    // The same bytes against a baseline without id 10 are a valid frame: the refusal above is
    // the duplicate, not the encoding.
    SViewFrame other = baseline;
    other.entities[0].id = 20;
    CHECK(Decode(Bytes(dup), &other, out) && out.entities.size() == 2u && out.entities[0].id == 10u);

    // A change with an empty field mask.
    BitWriter empty;
    empty.WriteBits(kLaneVersions[static_cast<std::size_t>(ELane::Entities)], 16);
    empty.WriteBits(10u, 32);
    empty.WriteBits(9u, 32);
    empty.WriteBits(0u, 32);
    empty.WriteVarUint(0u);
    empty.WriteVarUint(0u);
    empty.WriteVarUint(1u);
    empty.WriteVarUint(10u);
    empty.WriteBits(0u, 8);
    CHECK(!Decode(Bytes(empty), &baseline, out));
  }

  const TestCase kTests[] = {
    {"bits: round trip", &TestBitStreamRoundTrip},
    {"bits: overrun", &TestBitStreamOverrun},
    {"bits: malformed varuint", &TestBitStreamMalformedVarUint},
    {"quantize: axis", &TestAxisQuantizer},
    {"quantize: map position bits", &TestPositionQuantizerForMap},
    {"quantize: quaternion", &TestQuaternionPacking},
    {"ordinals: table and hash", &TestOrdinalTable},
    {"hello: versions", &TestHello},
    {"frame: decode(encode(f, b), b) == f", &TestFrameRoundTripProperty},
    {"frame: unchanged costs the header", &TestFrameUnchangedIsSmall},
    {"frame: baseline checks", &TestFrameBaselineChecks},
    {"frame: encoder refuses bad frames", &TestEncodeRejects},
    {"frame: truncation", &TestDecoderTruncation},
    {"frame: corruption and garbage", &TestDecoderCorruptionAndGarbage},
    {"frame: hostile counts and ids", &TestDecoderHostileCounts},
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
