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
#include "remote/wire/IntelGridDelta.h"
#include "remote/wire/OrdinalTable.h"
#include "remote/wire/NameTable.h"
#include "remote/wire/Quantize.h"
#include "remote/wire/Roster.h"
#include "remote/wire/SessionTables.h"
#include "remote/wire/SoundTable.h"
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
    explicit CFrameGenerator(const std::uint32_t seed, const bool deadReckoning = false)
      : mRng(seed)
      , mDeadReckoning(deadReckoning)
    {}

    SViewFrame Next()
    {
      SViewFrame frame{};
      frame.frameId = ++mFrameId;
      frame.beat = mFrameId * 3u;
      frame.simRate = static_cast<std::int32_t>(mRng() % 21u) - 10;
      frame.serverMs = mFrameId * 100u + mRng() % 50u;
      mBeat = frame.beat;
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
      record.tickCreated = mRng() % 4u == 0u ? 0u : mRng() % 100000u;
      record.blueprint = mRng() % 3u == 0u ? COrdinalTable::kNone : mRng() % 5000u;
      record.army = static_cast<std::uint8_t>(mRng() % 17u == 16u ? 0xFFu : mRng() % 16u);
      record.position = {Axis(kCodec.position.x), Axis(kCodec.position.y), Axis(kCodec.position.z)};
      if (mDeadReckoning) {
        // Anchored this frame, moving or still, sometimes fast (projectiles).
        for (std::int32_t& component : record.velocity) {
          component = mRng() % 3u == 0u ? 0 : static_cast<std::int32_t>(mRng() % 2001u) - 1000;
        }
        record.verticalAcceleration = mRng() % 4u == 0u ? static_cast<std::int32_t>(mRng() % 201u) - 100 : 0;
        record.followsGround = mRng() % 3u == 0u;
        record.anchorBeat = mBeat;
      }
      if (mRng() % 16u == 0u) {
        // Off the quantiser's range: exact floats, no motion.
        record.farPosition = true;
        record.farValue = {RandomFloat(), RandomFloat(), RandomFloat()};
        record.position = {};
        record.velocity = {};
        record.verticalAcceleration = 0;
        record.anchorBeat = 0;
        record.followsGround = false;
      }
      record.yawOnly = (mRng() & 1u) != 0u;
      record.orientation = record.yawOnly ? (mRng() & 0xFFFFu) : static_cast<std::uint32_t>(mRng());
      if (mDeadReckoning && record.yawOnly) {
        // Turning or not, anchored this frame or earlier.
        record.yawRate = mRng() % 2u == 0u ? 0 : static_cast<std::int32_t>(mRng() % 4001u) - 2000;
        record.orientationBeat = mBeat - std::min<std::uint32_t>(mBeat, mRng() % 50u);
      }
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
        record.unit.buildStateTag = static_cast<std::uint8_t>(mRng());
        record.unit.fake = static_cast<std::uint8_t>(mRng() & 1u);
        record.unit.stats = TSharedValue<std::vector<SUnitStat>>(RandomStats());
        if (mRng() % 2u == 0u) {
          record.unit.detail = TSharedValue<SUnitDetail>(RandomDetail());
        }
      }
      // Appearance: mostly defaults (a creation then sends none of it), sometimes anything.
      if (mRng() % 3u == 0u) {
        RandomAppearance(record.appearance, mRng());
      }
      return record;
    }

    void RandomAppearance(SAppearance& look, const std::uint32_t fields)
    {
      if ((fields & 1u) != 0u) look.mesh = mRng() % 4u == 0u ? COrdinalTable::kNone : mRng() % 3000u;
      if ((fields & 2u) != 0u) look.scale = {RandomFloat(), RandomFloat(), RandomFloat()};
      if ((fields & 4u) != 0u) {
        look.attachParent = mRng() % 2u == 0u ? SAppearance::kNoAttachParent : static_cast<std::uint32_t>(mRng());
        look.attachments.resize(mRng() % 4u == 0u ? mRng() % (SAppearance::kMaxAttachments + 1u) : 0u);
        for (std::uint32_t& id : look.attachments) {
          id = static_cast<std::uint32_t>(mRng());
        }
      }
      if ((fields & 8u) != 0u) look.visualFlags = static_cast<std::uint8_t>(mRng() & 0x1Fu);
      if ((fields & 16u) != 0u) look.impact = RandomFloat();
      if ((fields & 32u) != 0u) look.scroll = {RandomFloat(), RandomFloat(), RandomFloat(), RandomFloat()};
      if ((fields & 64u) != 0u) {
        for (std::uint32_t& radius : look.intel) {
          radius = mRng() % 2u == 0u ? 0u : static_cast<std::uint32_t>(mRng());
        }
      }
      if ((fields & 128u) != 0u) {
        look.ambientSound = mRng() % 3u == 0u ? COrdinalTable::kNone : mRng() % 500u;
        look.rumbleSound = mRng() % 3u == 0u ? COrdinalTable::kNone : mRng() % 500u;
      }
      if ((fields & 256u) != 0u) look.underlay = mRng() % 3u == 0u ? COrdinalTable::kNone : mRng() % 50u;
    }

    void Mutate(SEntityRecord& record)
    {
      const SEntityRecord fresh = RandomRecord(record.id);
      const std::uint32_t fields = mRng() & 0xFFFFu;
      if ((fields & kFieldBlueprint) != 0u) record.blueprint = fresh.blueprint;
      if ((fields & kFieldArmy) != 0u) record.army = fresh.army;
      if ((fields & kFieldPosition) != 0u) {
        record.position = fresh.position;
        record.velocity = fresh.velocity;
        record.verticalAcceleration = fresh.verticalAcceleration;
        record.followsGround = fresh.followsGround;
        record.anchorBeat = fresh.anchorBeat;
        record.farPosition = fresh.farPosition;
        record.farValue = fresh.farValue;
      }
      if ((fields & kFieldOrientation) != 0u) {
        record.orientation = fresh.orientation;
        record.yawOnly = fresh.yawOnly;
        record.yawRate = fresh.yawRate;
        record.orientationBeat = fresh.orientationBeat;
      }
      if ((fields & kFieldHealth) != 0u) record.health = fresh.health;
      if ((fields & kFieldMaxHealth) != 0u) record.maxHealth = fresh.maxHealth;
      if ((fields & kFieldFraction) != 0u) record.fractionComplete = fresh.fractionComplete;
      if ((fields & kFieldFlags) != 0u) record.flags = fresh.flags;
      if (mRng() % 4u == 0u) {
        RandomAppearance(record.appearance, mRng());
      }
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
        if (mRng() % 5u == 0u) unit.stats = source.stats;
        if (mRng() % 4u == 0u) {
          const SUnitDetail fresh = RandomDetail();
          switch (mRng() % 4u) {
          case 0: unit.detail.Edit().commands = fresh.commands; break;
          case 1: unit.detail.Edit().weapons = fresh.weapons; break;
          case 2: unit.detail.Edit().attributes = fresh.attributes; break;
          default: unit.detail.Edit().focusUnit = fresh.focusUnit; unit.detail.Edit().economy = fresh.economy; break;
          }
        }
      }
    }

    SCategoryBits RandomCategories()
    {
      SCategoryBits bits;
      bits.firstWord = mRng() % 8u;
      bits.words.resize(mRng() % 5u);
      for (std::uint32_t& word : bits.words) {
        word = static_cast<std::uint32_t>(mRng());
      }
      return bits;
    }

    SUnitDetail RandomDetail()
    {
      SUnitDetail detail;
      detail.creator = static_cast<std::uint32_t>(mRng());
      detail.creationTick = static_cast<std::int32_t>(mRng());
      detail.stunTicks = static_cast<std::int32_t>(mRng() % 50u) - 10;
      detail.jobType = static_cast<std::int32_t>(mRng() % 8u);
      detail.fireState = static_cast<std::int32_t>(mRng() % 3u);
      detail.siloMaxStorage = {static_cast<std::int32_t>(mRng() % 5u), -1};
      detail.selectionInheritor = static_cast<std::uint32_t>(mRng());
      detail.customName = mRng() % 3u == 0u ? 0xFFFFFFFFu : mRng() % 100u;
      detail.focusUnit = static_cast<std::uint32_t>(mRng());
      detail.guardedUnit = mRng() % 2u == 0u ? 0xF0000000u : static_cast<std::uint32_t>(mRng());
      detail.targetBlip = static_cast<std::uint32_t>(mRng());
      detail.didRefresh = static_cast<std::uint8_t>(mRng() & 1u);
      detail.reconFlags = static_cast<std::int32_t>(mRng());
      for (float& value : detail.economy) {
        value = RandomFloat();
      }
      detail.commands.resize(mRng() % 6u);
      for (std::int32_t& id : detail.commands) {
        id = static_cast<std::int32_t>(mRng());
      }
      detail.buildQueue.resize(mRng() % 4u);
      for (std::int32_t& id : detail.buildQueue) {
        id = static_cast<std::int32_t>(mRng() % 1000u);
      }
      detail.weapons.resize(mRng() % 3u);
      for (SUnitWeapon& weapon : detail.weapons) {
        weapon.targets = RandomCategories();
        weapon.secondary = RandomCategories();
        weapon.layer = mRng() % 128u;
        weapon.minRadius = RandomFloat();
        weapon.maxRadius = RandomFloat();
        weapon.effectiveRadius = RandomFloat();
        weapon.minRangeVisual = mRng() % 3u == 0u ? 0xFFFFFFFFu : mRng() % 50u;
        weapon.maxRangeVisual = mRng() % 50u;
      }
      SUnitAttributes& attributes = detail.attributes;
      attributes.blueprint = mRng() % 4u == 0u ? 0xFFFFFFFFu : mRng() % 5000u;
      attributes.reserved04 = mRng() % 2u;
      attributes.restriction = RandomCategories();
      for (float& value : attributes.scalars) {
        value = RandomFloat();
      }
      attributes.commandCaps = static_cast<std::uint32_t>(mRng());
      attributes.toggleCaps = static_cast<std::uint32_t>(mRng());
      attributes.flags = {static_cast<std::uint8_t>(mRng() & 1u), static_cast<std::uint8_t>(mRng() & 1u), 0, 0};
      return detail;
    }

    std::vector<SUnitStat> RandomStats()
    {
      std::vector<SUnitStat> stats;
      std::uint32_t name = mRng() % 5u;
      const int count = static_cast<int>(mRng() % 6u);
      for (int i = 0; i < count; ++i) {
        SUnitStat stat{};
        stat.name = name;
        name += 1u + mRng() % 40u;
        stat.type = static_cast<std::uint8_t>(mRng() % 4u);
        stat.realtime = (mRng() & 1u) != 0u;
        if (stat.type == SUnitStat::kString) {
          stat.text = mRng() % 4u == 0u ? 0xFFFFFFFFu : mRng() % 100u;
        } else {
          stat.bits = static_cast<std::uint32_t>(mRng());
        }
        stats.push_back(stat);
      }
      return stats;
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
    bool mDeadReckoning = false;
    std::uint32_t mBeat = 0;
    std::uint32_t mFrameId = 100;
    std::uint32_t mNextId = 0;
    std::vector<SEntityRecord> mLive;
  };

  const SFrameCodec kDeadReckoningCodec{SPositionQuantizer::ForMap(1024.0f, 1024.0f), 1u << 12, true, 0, true, true};

  [[nodiscard]] std::vector<std::uint8_t> Encode(
    const SViewFrame& frame, const SViewFrame* baseline, const SFrameCodec& codec = kCodec
  )
  {
    BitWriter writer;
    const bool encoded = EncodeFrame(frame, baseline, codec, writer);
    CHECK(encoded);
    return Bytes(writer);
  }

  [[nodiscard]] bool Decode(
    const std::vector<std::uint8_t>& bytes, const SViewFrame* baseline, SViewFrame& out,
    const SFrameCodec& codec = kCodec
  )
  {
    BitReader reader(bytes);
    return DecodeFrame(reader, baseline, codec, out);
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

  void TestFrameRoundTripDeadReckoning()
  {
    for (std::uint32_t seed = 11; seed <= 14; ++seed) {
      CFrameGenerator generator(seed, true);
      std::vector<SViewFrame> history;
      for (int step = 0; step < 120; ++step) {
        const SViewFrame frame = generator.Next();
        SViewFrame full{};
        CHECK(Decode(Encode(frame, nullptr, kDeadReckoningCodec), nullptr, full, kDeadReckoningCodec) && full == frame);
        for (std::size_t back = 1; back <= 5 && back <= history.size(); back += 2) {
          const SViewFrame& baseline = history[history.size() - back];
          SViewFrame decoded{};
          CHECK(
            Decode(Encode(frame, &baseline, kDeadReckoningCodec), &baseline, decoded, kDeadReckoningCodec)
            && decoded == frame
          );
        }
        history.push_back(frame);
      }
    }

    // Without dead reckoning a record must not carry motion; with it, an anchor must not lie
    // ahead of the frame.
    SViewFrame moving{};
    moving.beat = 50;
    moving.entities.resize(1);
    moving.entities[0].velocity = {1, 0, 0};
    BitWriter writer;
    CHECK(!EncodeFrame(moving, nullptr, kCodec, writer));
    CHECK(EncodeFrame(moving, nullptr, kDeadReckoningCodec, writer));
    SViewFrame future = moving;
    future.entities[0].anchorBeat = 51;
    BitWriter futureWriter;
    CHECK(!EncodeFrame(future, nullptr, kDeadReckoningCodec, futureWriter));
    SViewFrame falling{};
    falling.beat = 50;
    falling.entities.resize(1);
    falling.entities[0].verticalAcceleration = -3;
    BitWriter fallingWriter;
    CHECK(!EncodeFrame(falling, nullptr, kCodec, fallingWriter));
    // A turn rate needs orientation reckoning and a yaw-only record; its anchor not in the future.
    SViewFrame turning{};
    turning.beat = 50;
    turning.entities.resize(1);
    turning.entities[0].yawOnly = true;
    turning.entities[0].yawRate = 40;
    turning.entities[0].orientationBeat = 49;
    BitWriter turningWriter;
    CHECK(!EncodeFrame(turning, nullptr, kCodec, turningWriter));
    CHECK(EncodeFrame(turning, nullptr, kDeadReckoningCodec, turningWriter));
    SViewFrame tumbling = turning;
    tumbling.entities[0].yawOnly = false;
    BitWriter tumblingWriter;
    CHECK(!EncodeFrame(tumbling, nullptr, kDeadReckoningCodec, tumblingWriter));
    SViewFrame early = turning;
    early.entities[0].orientationBeat = 51;
    BitWriter earlyWriter;
    CHECK(!EncodeFrame(early, nullptr, kDeadReckoningCodec, earlyWriter));
  }

  void TestDeadReckoningRules()
  {
    const SFrameCodec& codec = kDeadReckoningCodec;
    SReckoningScheme scheme{};
    scheme.tolerance = 2;
    SEntityRecord sent{};
    sent.position = {1000, 500, 1000};
    sent.anchorBeat = 0;
    QuantizedPosition previous = sent.position;
    const auto apply = [&](SEntityRecord& record, const QuantizedPosition& last, const QuantizedPosition& now,
                           const std::uint32_t beat) {
      const QuantizedPosition pair[2] = {last, now};
      return ApplyDeadReckoning(record, pair, beat, scheme, codec);
    };

    // Starts moving at 5 steps per beat on x: one re-anchor, then the prediction holds.
    int anchors = 0;
    for (std::uint32_t beat = 1; beat <= 20; ++beat) {
      const QuantizedPosition actual{1000 + 5 * beat, 500, 1000};
      anchors += apply(sent, previous, actual, beat) ? 1 : 0;
      CHECK(PredictPosition(sent, beat, codec) == actual);
      previous = actual;
    }
    CHECK(anchors == 1);
    CHECK(sent.velocity == (std::array<std::int32_t, 3>{5, 0, 0}) && sent.anchorBeat == 1u);

    // Stops: the prediction runs ahead, the next beat re-anchors with zero velocity.
    const QuantizedPosition stopped{1100, 500, 1000};
    CHECK(apply(sent, previous, stopped, 21));
    CHECK(sent.velocity == (std::array<std::int32_t, 3>{0, 0, 0}) && sent.position == stopped);
    CHECK(!apply(sent, stopped, stopped, 22));

    // Small drift within the tolerance does not re-anchor.
    const QuantizedPosition drift{1102, 498, 1001};
    CHECK(!apply(sent, stopped, drift, 23));

    // WP7.8: a speed between whole steps (0.3 units a beat, 19.2 steps), fitted over 8 beats in
    // 1/16 steps, re-anchors far less often than the last beat's whole-step motion.
    SFrameCodec fine = codec;
    fine.velocityFractionBits = 4;
    const auto quantised = [](const double x, const double y, const double z) {
      return QuantizedPosition{
        static_cast<std::uint32_t>(std::lround(x)), static_cast<std::uint32_t>(std::lround(y)),
        static_cast<std::uint32_t>(std::lround(z))
      };
    };
    const auto anchorsOver = [&](const SReckoningScheme& use, const SFrameCodec& useCodec, const auto& path) {
      SEntityRecord record{};
      record.position = path(0);
      std::vector<QuantizedPosition> history{path(0)};
      int count = 0;
      for (std::uint32_t beat = 1; beat <= 200; ++beat) {
        history.push_back(path(beat));
        const std::size_t keep = std::min<std::size_t>(history.size(), kReckoningHistory);
        count += ApplyDeadReckoning(
                   record, std::span<const QuantizedPosition>(history.data() + history.size() - keep, keep), beat, use,
                   useCodec
                 )
                 ? 1
                 : 0;
        const QuantizedPosition shown = PredictPosition(record, beat, useCodec);
        for (int axis = 0; axis < 3; ++axis) {
          const std::int64_t error = static_cast<std::int64_t>(shown[axis]) - static_cast<std::int64_t>(history.back()[axis]);
          CHECK(error <= use.tolerance && -error <= use.tolerance);
        }
      }
      return count;
    };
    const auto cruise = [&](const std::uint32_t beat) { return quantised(1000.0 + 19.2 * beat, 500.0, 2000.0 - 7.7 * beat); };
    SReckoningScheme fitted = scheme;
    fitted.window = 8;
    const int wholeSteps = anchorsOver(scheme, codec, cruise);
    const int subSteps = anchorsOver(fitted, fine, cruise);
    CHECK(subSteps * 4 < wholeSteps);
    std::printf("  dead reckoning anchors over 200 beats: whole %d, fitted %d\n", wholeSteps, subSteps);

    // A ballistic arc (gravity on the vertical axis): the bent fit holds it, a straight one not.
    const auto arc = [quantised](const std::uint32_t beat) {
      const double t = beat;
      return quantised(1000.0 + 30.0 * t, 20000.0 + 150.0 * t - 3.1 * t * t, 3000.0);
    };
    SReckoningScheme bent = fitted;
    bent.verticalAcceleration = true;
    const int straightArc = anchorsOver(fitted, fine, [&](const std::uint32_t beat) { return arc(beat % 90u); });
    const int bentArc = anchorsOver(bent, fine, [&](const std::uint32_t beat) { return arc(beat % 90u); });
    std::printf("  ballistic arc anchors: straight %d, bent %d\n", straightArc, bentArc);
    CHECK(bentArc * 4 < straightArc);

    // Sub-step predictions round half up, the same on every axis and direction.
    SEntityRecord back{};
    back.position = {5000, 5000, 5000};
    back.velocity = {-24, 24, 0}; // 1.5 steps a beat
    CHECK(PredictPosition(back, 1, fine) == (QuantizedPosition{4999, 5002, 5000}));
    CHECK(PredictPosition(back, 2, fine) == (QuantizedPosition{4997, 5003, 5000}));
    back.verticalAcceleration = -16; // a step a beat squared: 1.5 t - t^2 / 2
    CHECK(PredictPosition(back, 4, fine) == (QuantizedPosition{4994, 4998, 5000}));

    // Predictions clamp to the axes.
    SEntityRecord edge{};
    edge.position = {3, 0, codec.position.z.MaxQuantized() - 1};
    edge.velocity = {-10, -10, 10};
    const QuantizedPosition clamped = PredictPosition(edge, 5, codec);
    CHECK(clamped[0] == 0u && clamped[1] == 0u && clamped[2] == codec.position.z.MaxQuantized());

    // Ground following: a unit crossing a hill (height sin(x / 20) * 8) at a steady speed. Its
    // height is anything but linear, so a straight fit re-anchors over and over; following the
    // terrain it re-anchors about as often as on flat ground.
    struct SHill final : IGroundHeight
    {
      [[nodiscard]] float HeightAt(const float x, const float) const noexcept override
      {
        return 20.0f + 8.0f * std::sin(x / 20.0f);
      }
    } hill;
    SFrameCodec onHill = fine;
    onHill.groundFollowing = true;
    onHill.ground = &hill;
    const auto overHill = [&](const std::uint32_t beat) {
      const float x = 100.0f + 0.3f * static_cast<float>(beat);
      const float z = 200.0f;
      return QuantizedPosition{
        onHill.position.x.Encode(x), onHill.position.y.Encode(hill.HeightAt(x, z)), onHill.position.z.Encode(z)
      };
    };
    SReckoningScheme ground = fitted;
    ground.followGround = true;
    const int straightHill = anchorsOver(fitted, onHill, overHill);
    const int groundHill = anchorsOver(ground, onHill, overHill);
    std::printf("  hill anchors over 200 beats: straight %d, following the ground %d\n", straightHill, groundHill);
    CHECK(groundHill * 3 < straightHill);

    // Orientation: a steady turn of 100.3 yaw units a beat through the wrap at a full turn, held
    // within 64 units (0.35 degrees) by a fitted rate; re-anchored far less than every beat.
    SReckoningScheme turns = fitted;
    turns.orientationTolerance = 64;
    SEntityRecord turner{};
    turner.yawOnly = true;
    turner.orientation = 65000;
    turner.orientationBeat = 0;
    std::vector<std::uint32_t> yaws{65000};
    int turnAnchors = 0;
    for (std::uint32_t beat = 1; beat <= 200; ++beat) {
      SEntityRecord actual{};
      actual.yawOnly = true;
      actual.orientation = static_cast<std::uint32_t>(std::lround(65000.0 + 100.3 * beat)) & 0xFFFFu;
      yaws.push_back(actual.orientation);
      const std::size_t keep = std::min<std::size_t>(yaws.size(), kReckoningHistory);
      turnAnchors += ApplyOrientationReckoning(
                       turner, actual, std::span<const std::uint32_t>(yaws.data() + yaws.size() - keep, keep), beat, turns,
                       fine
                     )
                     ? 1
                     : 0;
      const auto error = static_cast<std::int16_t>(static_cast<std::uint16_t>(actual.orientation - PredictYaw(turner, beat, fine)));
      CHECK(error <= 64 && error >= -64);
    }
    std::printf("  turn anchors over 200 beats: %d\n", turnAnchors);
    CHECK(turnAnchors <= 10);

    // A quaternion is held while within the tolerance and sent again past it; a change between
    // yaw-only and not is always sent.
    SEntityRecord tilted{};
    tilted.orientation = PackQuaternion({0.1f, 0.0f, 0.0f, 0.995f});
    SEntityRecord near = tilted;
    near.orientation = PackQuaternion({0.1003f, 0.0f, 0.0f, 0.99496f});
    SEntityRecord far = tilted;
    far.orientation = PackQuaternion({0.2f, 0.0f, 0.0f, 0.9798f});
    SEntityRecord held = tilted;
    CHECK(!ApplyOrientationReckoning(held, near, {}, 5, turns, fine) && held.orientation == tilted.orientation);
    CHECK(ApplyOrientationReckoning(held, far, {}, 6, turns, fine) && held.orientation == far.orientation);
    SEntityRecord flat{};
    flat.yawOnly = true;
    flat.orientation = 1000;
    const std::uint32_t flatYaw[1] = {1000};
    CHECK(ApplyOrientationReckoning(held, flat, flatYaw, 7, turns, fine) && held.yawOnly && held.yawRate == 0
          && held.orientationBeat == 7u);
  }

  void TestFrameAppearance()
  {
    // A creation with the default appearance sends none of it; each non-default field costs
    // its own bytes and comes back exactly.
    SViewFrame plain{};
    plain.frameId = 1;
    plain.entities.resize(1);
    plain.entities[0].id = 7;
    CHECK(CreationFields(plain.entities[0]) == (kEntityFields | kFieldKind));
    const std::vector<std::uint8_t> plainBytes = Encode(plain, nullptr);

    SViewFrame dressed = plain;
    SAppearance& look = dressed.entities[0].appearance;
    look.mesh = 1234;
    look.scale = {2.0f, 0.5f, -0.0f};
    look.attachParent = 0x00100005u;
    look.attachments = {0x00100006u, 0x00100009u};
    look.visualFlags = 0x15u;
    look.impact = 0.25f;
    look.scroll = {0.0f, 1.0f, 2.0f, 3.0f};
    look.intel = {20, 0, 60, 0, 0, 0, 0, 1};
    look.ambientSound = 0;
    look.rumbleSound = 7;
    look.underlay = 3;
    CHECK(CreationFields(dressed.entities[0]) == (kEntityFields | kFieldKind | kAppearanceFields));
    const std::vector<std::uint8_t> dressedBytes = Encode(dressed, nullptr);
    CHECK(dressedBytes.size() > plainBytes.size() + 40u);
    SViewFrame decoded{};
    CHECK(Decode(dressedBytes, nullptr, decoded) && decoded == dressed);

    // A change of one appearance field sends that field alone.
    SViewFrame moved = dressed;
    moved.frameId = 2;
    moved.entities[0].appearance.scale[0] = 3.0f;
    CHECK(ChangedFields(dressed.entities[0], moved.entities[0]) == kFieldScale);
    const std::vector<std::uint8_t> movedBytes = Encode(moved, &dressed);
    CHECK(Decode(movedBytes, &dressed, decoded) && decoded == moved);

    // A texture scroll that shifts (new start = old end) costs one bit and the end; any other
    // change of the scroll sends all four floats.
    SViewFrame shifted = moved;
    shifted.frameId = 3;
    shifted.entities[0].appearance.scroll = {moved.entities[0].appearance.scroll[2], moved.entities[0].appearance.scroll[3], 5.0f, 6.0f};
    SViewFrame jumped = moved;
    jumped.frameId = 3;
    jumped.entities[0].appearance.scroll = {7.0f, 8.0f, 5.0f, 6.0f};
    const std::vector<std::uint8_t> shiftedBytes = Encode(shifted, &moved);
    const std::vector<std::uint8_t> jumpedBytes = Encode(jumped, &moved);
    CHECK(shiftedBytes.size() + 8u == jumpedBytes.size());
    CHECK(Decode(shiftedBytes, &moved, decoded) && decoded == shifted);
    CHECK(Decode(jumpedBytes, &moved, decoded) && decoded == jumped);

    // A creation mask without the basic fields, or with unit fields for a non-unit, is refused.
    for (const std::uint32_t mask : {std::uint32_t{kFieldKind}, kEntityFields | kFieldKind | kFieldUnitFuel, kAllFields + 1u}) {
      BitWriter writer;
      writer.WriteBits(kLaneVersions[static_cast<std::size_t>(ELane::Entities)], 16);
      writer.WriteBits(1u, 32);
      writer.WriteBits(kNoBaseline, 32);
      writer.WriteBits(0u, 32);
      writer.WriteVarUint(0u); // sim rate
      writer.WriteBits(0u, 32); // server clock
      writer.WriteVarUint(0u);
      writer.WriteVarUint(1u);
      writer.WriteVarUint(7u);
      writer.WriteVarUint(mask);
      writer.WriteBool(false); // not a unit
      for (int i = 0; i < 40; ++i) {
        writer.WriteBits(0u, 32);
      }
      CHECK(!Decode(Bytes(writer), nullptr, decoded));
    }

    // Too many attachments are refused.
    SViewFrame crowded = plain;
    crowded.entities[0].appearance.attachments.resize(SAppearance::kMaxAttachments + 1u);
    BitWriter crowdedWriter;
    CHECK(EncodeFrame(crowded, nullptr, kCodec, crowdedWriter));
    CHECK(!Decode(Bytes(crowdedWriter), nullptr, decoded));
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
    CHECK(bytes.size() == 2u + 4u + 4u + 4u + 1u + 4u + 3u); // header (with the beat stamps) and three empty sections
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
      writer.WriteVarUint(0u); // sim rate
      writer.WriteBits(0u, 32); // server clock
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
    writer.WriteVarUint(0u); // sim rate
    writer.WriteBits(0u, 32); // server clock
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
    dup.WriteVarUint(0u); // sim rate
    dup.WriteBits(0u, 32); // server clock
    dup.WriteVarUint(0u);
    dup.WriteVarUint(1u);
    dup.WriteVarUint(10u);
    dup.WriteVarUint(kEntityFields | kFieldKind); // a creation's mask: no unit block, default appearance
    // every field of a non-unit, in the encoder's order: kind, position (far bit first), orientation,
    // health, fraction, flags, max health, blueprint, army
    dup.WriteBool(false);
    dup.WriteBool(false); // position in the quantiser's range
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
    empty.WriteVarUint(0u); // sim rate
    empty.WriteBits(0u, 32); // server clock
    empty.WriteVarUint(0u);
    empty.WriteVarUint(0u);
    empty.WriteVarUint(1u);
    empty.WriteVarUint(10u);
    empty.WriteBits(0u, 8);
    CHECK(!Decode(Bytes(empty), &baseline, out));
  }

  // --- Sound table ------------------------------------------------------------------------

  void TestSessionTables()
  {
    // Sounds (with the RPC loop variable) and names, interned once, written as one record per
    // batch, read back in order on the other side.
    CSessionTableWriters server;
    CSessionTableReaders client;
    const SSoundEntry loop{"UEL_Unit", "UEL0001_Move_Loop", "UnitMove_LodCutoff", "UEL0001_Move_Loop"};
    const SSoundEntry plain{"Explosions", "Explosion_Small", "", ""};
    CHECK(server.Sound(loop) == 0u && server.Sound(plain) == 1u && server.Sound(loop) == 0u);
    CHECK(server.Name("/textures/ui/common/game/strategicicons/icon_land_rest.dds") == 0u);
    CHECK(server.HasPending());
    BitWriter first;
    server.WritePending(first);
    CHECK(!server.HasPending());
    const std::vector<std::uint8_t> firstBytes = Bytes(first);
    BitReader firstIn(firstBytes);
    CHECK(client.Read(firstIn));
    CHECK(client.Sounds().Size() == 2u && client.Sounds().Find(0) != nullptr && *client.Sounds().Find(0) == loop);
    CHECK(client.Names().Size() == 1u && *client.Names().Find(0) == "/textures/ui/common/game/strategicicons/icon_land_rest.dds");

    // A second batch adds only what is new; an empty batch is four zero counts.
    CHECK(server.Name("/textures/ui/common/game/strategicicons/icon_land_rest.dds") == 0u);
    CHECK(server.Name("/a.dds") == 1u);
    BitWriter second;
    server.WritePending(second);
    const std::vector<std::uint8_t> secondBytes = Bytes(second);
    BitReader secondIn(secondBytes);
    CHECK(client.Read(secondIn) && client.Names().Size() == 2u && client.Sounds().Size() == 2u);
    BitWriter empty;
    server.WritePending(empty);
    CHECK(Bytes(empty).size() == 4u);

    // Resource deposits: each one once, in order, across records; negative cells survive.
    const SDeposit mass{1, 10, 12, 12, 14};
    const SDeposit hydro{2, -3, 500, 1, 504};
    CHECK(server.Deposit(mass) && server.Deposit(hydro) && server.DepositCount() == 2u && server.HasPending());
    BitWriter third;
    server.WritePending(third);
    const std::vector<std::uint8_t> thirdBytes = Bytes(third);
    BitReader thirdIn(thirdBytes);
    CHECK(client.Read(thirdIn) && client.Deposits() == (std::vector<SDeposit>{mass, hydro}));
    CHECK(server.Deposit(mass) && server.DepositCount() == 3u);
    BitWriter fourth;
    server.WritePending(fourth);
    const std::vector<std::uint8_t> fourthBytes = Bytes(fourth);
    BitReader fourthIn(fourthBytes);
    CHECK(client.Read(fourthIn) && client.Deposits().size() == 3u && client.Deposits()[2] == mass);
    for (std::size_t length = 0; length < thirdBytes.size(); ++length) {
      CSessionTableReaders cut;
      BitReader cutIn(std::span<const std::uint8_t>(thirdBytes.data(), length));
      CHECK(!cut.Read(cutIn));
    }
    // More deposits than a session may have are refused before any is read.
    BitWriter flood;
    flood.WriteVarUint(0u);
    flood.WriteVarUint(0u);
    flood.WriteVarUint(CSessionTableWriters::kMaxDeposits + 1u);
    const std::vector<std::uint8_t> floodBytes = Bytes(flood);
    CSessionTableReaders flooded;
    BitReader floodIn(floodBytes);
    CHECK(!flooded.Read(floodIn) && flooded.Deposits().empty());

    // Terrain edits: rectangles and heights come back exactly, once; a flat edit costs about a
    // byte a cell; an edit outside the field carries its rectangle alone.
    STerrainEdit flat{};
    flat.dirty = {9, 19, 13, 23};
    flat.cells = {10, 20, 13, 23};
    flat.heights.assign(16, 4321);
    flat.heights[5] = 65535;
    STerrainEdit outside{};
    outside.dirty = {2000, 2000, 2004, 2004};
    outside.cells = {0, 0, -1, -1};
    CHECK(server.TerrainEdit(flat) && server.TerrainEdit(outside));
    STerrainEdit wrong = flat;
    wrong.heights.pop_back();
    CHECK(!server.TerrainEdit(wrong));
    BitWriter fifth;
    server.WritePending(fifth);
    const std::vector<std::uint8_t> fifthBytes = Bytes(fifth);
    CHECK(fifthBytes.size() < 60u);
    BitReader fifthIn(fifthBytes);
    CHECK(client.Read(fifthIn));
    const std::vector<STerrainEdit> taken = client.TakeTerrainEdits();
    CHECK(taken.size() == 2u && taken[0] == flat && taken[1] == outside);
    CHECK(client.TakeTerrainEdits().empty());
    for (std::size_t length = 0; length < fifthBytes.size(); ++length) {
      CSessionTableReaders cut;
      BitReader cutIn(std::span<const std::uint8_t>(fifthBytes.data(), length));
      CHECK(!cut.Read(cutIn));
    }
    // A height out of range and an edit larger than allowed are refused.
    BitWriter tall;
    tall.WriteVarUint(0u);
    tall.WriteVarUint(0u);
    tall.WriteVarUint(0u);
    tall.WriteVarUint(1u);
    for (int i = 0; i < 4; ++i) {
      tall.WriteVarUint(0u);
    }
    tall.WriteBool(true);
    for (int i = 0; i < 4; ++i) {
      tall.WriteVarUint(0u);
    }
    tall.WriteVarUint(2u * 70000u); // zig-zag of 70000
    CSessionTableReaders tallReader;
    const std::vector<std::uint8_t> tallBytes = Bytes(tall);
    BitReader tallIn(tallBytes);
    CHECK(!tallReader.Read(tallIn));
    BitWriter huge;
    huge.WriteVarUint(0u);
    huge.WriteVarUint(0u);
    huge.WriteVarUint(0u);
    huge.WriteVarUint(1u);
    for (int i = 0; i < 4; ++i) {
      huge.WriteVarUint(0u);
    }
    huge.WriteBool(true);
    huge.WriteVarUint(0u);
    huge.WriteVarUint(0u);
    huge.WriteVarUint(2u * 4000u);
    huge.WriteVarUint(2u * 4000u);
    CSessionTableReaders hugeReader;
    const std::vector<std::uint8_t> hugeBytes = Bytes(huge);
    BitReader hugeIn(hugeBytes);
    CHECK(!hugeReader.Read(hugeIn));

    // The same record twice is refused (ids out of order); truncation everywhere is refused.
    CSessionTableReaders again;
    BitReader againIn(firstBytes);
    CHECK(again.Read(againIn));
    BitReader repeatIn(firstBytes);
    CHECK(!again.Read(repeatIn));
    for (std::size_t length = 0; length < firstBytes.size(); ++length) {
      CSessionTableReaders cut;
      BitReader cutIn(std::span<const std::uint8_t>(firstBytes.data(), length));
      CHECK(!cut.Read(cutIn));
    }
    // An oversized name.
    BitWriter big;
    big.WriteVarUint(0u);
    big.WriteVarUint(1u);
    big.WriteVarUint(0u);
    big.WriteVarUint(static_cast<std::uint32_t>(CNameTableReader::kMaxNameBytes + 1u));
    for (std::size_t i = 0; i <= CNameTableReader::kMaxNameBytes; ++i) {
      big.WriteBits('x', 8);
    }
    CSessionTableReaders bigReader;
    const std::vector<std::uint8_t> bigBytes = Bytes(big);
    BitReader bigIn(bigBytes);
    CHECK(!bigReader.Read(bigIn) && bigReader.Names().Size() == 0u);
  }

  void TestRoster()
  {
    // Every field comes back; truncation anywhere and hostile counts are refused.
    SRoster roster{};
    roster.localIndex = 1;
    SRosterEntry host{};
    host.index = 0;
    host.name = "Host";
    host.ownerId = 12345;
    host.sources = {0, 2};
    host.simRate = 3;
    host.ping = 41.5f;
    host.quiet = 0.25f;
    SRosterEntry joiner = host;
    joiner.index = 1;
    joiner.name = "Joiner";
    joiner.ownerId = -7;
    joiner.sources = {1};
    joiner.connected = false;
    joiner.ejectedBy = {0};
    roster.entries = {host, joiner};
    BitWriter writer;
    roster.Encode(writer);
    const std::vector<std::uint8_t> bytes = Bytes(writer);
    BitReader reader(bytes);
    const std::optional<SRoster> back = SRoster::Decode(reader);
    CHECK(back && *back == roster);
    for (std::size_t length = 0; length < bytes.size(); ++length) {
      BitReader cut(std::span<const std::uint8_t>(bytes.data(), length));
      CHECK(!SRoster::Decode(cut));
    }
    BitWriter many;
    many.WriteVarUint(0u);
    many.WriteVarUint(static_cast<std::uint32_t>(SRoster::kMaxEntries + 1u));
    const std::vector<std::uint8_t> manyBytes = Bytes(many);
    BitReader manyIn(manyBytes);
    CHECK(!SRoster::Decode(manyIn));
    SRoster other = roster;
    other.entries[0].ping = 42.0f;
    CHECK(!(other == roster));
  }

  void TestSoundTable()
  {
    CSoundTableWriter writer;
    const SSoundEntry a{"UEL_Weapon", "UEL0101_MachineGun", ""};
    const SSoundEntry b{"UEL_Weapon", "UEL0101_MachineGun", "Weapon_LodCutoff"};
    const SSoundEntry c{"Explosions", "Explosion_Large", ""};
    const auto ia = writer.Intern(a);
    const auto ib = writer.Intern(b);
    const auto ia2 = writer.Intern(a);
    const auto ic = writer.Intern(c);
    CHECK(ia.isNew && ia.id == 0u);
    CHECK(ib.isNew && ib.id == 1u); // the LOD cutoff is part of the key
    CHECK(!ia2.isNew && ia2.id == 0u);
    CHECK(ic.isNew && ic.id == 2u);
    CHECK(writer.Size() == 3u);

    BitWriter stream;
    for (std::uint32_t id = 0; id < writer.Size(); ++id) {
      writer.WriteEntry(id, stream);
    }
    const std::vector<std::uint8_t> bytes = Bytes(stream);
    CSoundTableReader reader;
    BitReader in(bytes);
    CHECK(reader.ReadEntry(in) && reader.ReadEntry(in) && reader.ReadEntry(in));
    CHECK(reader.Size() == 3u);
    CHECK(reader.Find(0) != nullptr && *reader.Find(0) == a);
    CHECK(reader.Find(1) != nullptr && *reader.Find(1) == b);
    CHECK(reader.Find(2) != nullptr && *reader.Find(2) == c);
    CHECK(reader.Find(3) == nullptr);

    // Out of order: entry 1 before entry 0, and a repeat of entry 0.
    BitWriter skipped;
    writer.WriteEntry(1, skipped);
    CSoundTableReader fresh;
    const std::vector<std::uint8_t> skippedBytes = Bytes(skipped);
    BitReader skippedIn(skippedBytes);
    CHECK(!fresh.ReadEntry(skippedIn) && fresh.Size() == 0u);
    BitWriter twice;
    writer.WriteEntry(0, twice);
    writer.WriteEntry(0, twice);
    CSoundTableReader once;
    const std::vector<std::uint8_t> twiceBytes = Bytes(twice);
    BitReader twiceIn(twiceBytes);
    CHECK(once.ReadEntry(twiceIn) && !once.ReadEntry(twiceIn) && once.Size() == 1u);

    // Truncation at every byte of one entry, and an oversized name.
    BitWriter one;
    writer.WriteEntry(0, one);
    const std::vector<std::uint8_t> oneBytes = Bytes(one);
    for (std::size_t length = 0; length < oneBytes.size(); ++length) {
      CSoundTableReader cut;
      BitReader cutIn(std::span<const std::uint8_t>(oneBytes.data(), length));
      CHECK(!cut.ReadEntry(cutIn) && cut.Size() == 0u);
    }
    BitWriter big;
    big.WriteVarUint(0u);
    big.WriteVarUint(static_cast<std::uint32_t>(CSoundTableReader::kMaxNameBytes + 1u));
    for (std::size_t i = 0; i <= CSoundTableReader::kMaxNameBytes; ++i) {
      big.WriteBits('x', 8);
    }
    big.WriteVarUint(0u);
    big.WriteVarUint(0u);
    CSoundTableReader bigReader;
    const std::vector<std::uint8_t> bigBytes = Bytes(big);
    BitReader bigIn(bigBytes);
    CHECK(!bigReader.ReadEntry(bigIn));
    // A length the remaining bytes cannot hold is refused before reading.
    BitWriter lie;
    lie.WriteVarUint(0u);
    lie.WriteVarUint(200u);
    CSoundTableReader lieReader;
    const std::vector<std::uint8_t> lieBytes = Bytes(lie);
    BitReader lieIn(lieBytes);
    CHECK(!lieReader.ReadEntry(lieIn));

    // The table's own limit.
    CSoundTableReader full;
    CSoundTableWriter many;
    BitWriter all;
    for (std::uint32_t i = 0; i <= CSoundTableReader::kMaxEntries; ++i) {
      const auto interned = many.Intern({"b", std::to_string(i), ""});
      many.WriteEntry(interned.id, all);
    }
    const std::vector<std::uint8_t> allBytes = Bytes(all);
    BitReader allIn(allBytes);
    std::uint32_t accepted = 0;
    while (full.ReadEntry(allIn)) {
      ++accepted;
    }
    CHECK(accepted == CSoundTableReader::kMaxEntries && full.Size() == CSoundTableReader::kMaxEntries);
  }

  // --- Intel grid deltas (plan WP5.4) -------------------------------------------------------

  [[nodiscard]] SGridBits RandomGrid(std::mt19937& rng, const std::uint32_t width, const std::uint32_t height, const int percent)
  {
    SGridBits grid;
    grid.width = width;
    grid.height = height;
    grid.cells.resize(static_cast<std::size_t>(width) * height);
    std::uniform_int_distribution<int> roll(0, 99);
    for (std::uint8_t& cell : grid.cells) {
      cell = roll(rng) < percent ? 1u : 0u;
    }
    return grid;
  }

  void TestGridDeltaRoundTrip()
  {
    std::mt19937 rng(20261030u);
    std::uniform_int_distribution<std::uint32_t> side(1, 64);
    for (int round = 0; round < 300; ++round) {
      const std::uint32_t width = side(rng);
      const std::uint32_t height = side(rng);
      SGridBits held = RandomGrid(rng, width, height, 40);
      // A beat sequence: each step flips a few cells, as fog moves at its edges.
      for (int beat = 0; beat < 8; ++beat) {
        SGridBits next = held;
        std::uniform_int_distribution<std::size_t> cell(0, next.cells.size() - 1);
        const int flips = static_cast<int>(rng() % 6u);
        for (int i = 0; i < flips; ++i) {
          next.cells[cell(rng)] ^= 1u;
        }
        BitWriter writer;
        CHECK(EncodeGridDelta(next, &held, writer));
        const std::vector<std::uint8_t> bytes = Bytes(writer);
        BitReader reader(bytes);
        SGridBits decoded;
        CHECK(DecodeGridDelta(reader, &held, 1u << 20, decoded));
        CHECK(decoded == next);
        held = next;
      }
      // Against no baseline, and against one of another size.
      const SGridBits fresh = RandomGrid(rng, width, height, 50);
      const SGridBits other = RandomGrid(rng, width + 1, height, 50);
      for (const SGridBits* baseline : {static_cast<const SGridBits*>(nullptr), &other}) {
        BitWriter writer;
        CHECK(EncodeGridDelta(fresh, baseline, writer));
        const std::vector<std::uint8_t> bytes = Bytes(writer);
        BitReader reader(bytes);
        SGridBits decoded;
        CHECK(DecodeGridDelta(reader, baseline, 1u << 20, decoded));
        CHECK(decoded == fresh);
      }
    }
  }

  void TestGridDeltaUnchangedIsSmall()
  {
    std::mt19937 rng(7u);
    const SGridBits grid = RandomGrid(rng, 256, 256, 50);
    BitWriter writer;
    CHECK(EncodeGridDelta(grid, &grid, writer));
    // Width and height (2 bytes each) and one run of 65536 unchanged cells (3 bytes).
    CHECK(Bytes(writer).size() <= 7u);
  }

  void TestGridDeltaHostile()
  {
    // Too many cells: refused before allocating.
    {
      BitWriter writer;
      writer.WriteVarUint(100000);
      writer.WriteVarUint(100000);
      const std::vector<std::uint8_t> bytes = Bytes(writer);
      BitReader reader(bytes);
      SGridBits decoded;
      CHECK(!DecodeGridDelta(reader, nullptr, 1u << 20, decoded));
    }
    // A run past the end.
    {
      BitWriter writer;
      writer.WriteVarUint(4);
      writer.WriteVarUint(4);
      writer.WriteVarUint(10);
      writer.WriteVarUint(10);
      const std::vector<std::uint8_t> bytes = Bytes(writer);
      BitReader reader(bytes);
      SGridBits decoded;
      CHECK(!DecodeGridDelta(reader, nullptr, 1u << 20, decoded));
    }
    // Truncated: every prefix of a valid delta is refused.
    {
      std::mt19937 rng(11u);
      const SGridBits grid = RandomGrid(rng, 20, 20, 50);
      BitWriter writer;
      CHECK(EncodeGridDelta(grid, nullptr, writer));
      const std::vector<std::uint8_t> bytes = Bytes(writer);
      for (std::size_t length = 0; length + 1 < bytes.size(); ++length) {
        const std::vector<std::uint8_t> prefix(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(length));
        BitReader reader(prefix);
        SGridBits decoded;
        CHECK(!DecodeGridDelta(reader, nullptr, 1u << 20, decoded));
      }
    }
    // The encoder refuses a grid whose cells do not match its size.
    {
      SGridBits bad;
      bad.width = 3;
      bad.height = 3;
      bad.cells.resize(8);
      BitWriter writer;
      CHECK(!EncodeGridDelta(bad, nullptr, writer));
    }
  }

  const TestCase kTests[] = {
    {"grids: delta round trip", &TestGridDeltaRoundTrip},
    {"grids: unchanged is small", &TestGridDeltaUnchangedIsSmall},
    {"grids: hostile input", &TestGridDeltaHostile},
    {"sounds: session table", &TestSoundTable},
    {"roster: round trip and refusals", &TestRoster},
    {"session tables: sounds and names", &TestSessionTables},
    {"bits: round trip", &TestBitStreamRoundTrip},
    {"bits: overrun", &TestBitStreamOverrun},
    {"bits: malformed varuint", &TestBitStreamMalformedVarUint},
    {"quantize: axis", &TestAxisQuantizer},
    {"quantize: map position bits", &TestPositionQuantizerForMap},
    {"quantize: quaternion", &TestQuaternionPacking},
    {"ordinals: table and hash", &TestOrdinalTable},
    {"hello: versions", &TestHello},
    {"frame: decode(encode(f, b), b) == f", &TestFrameRoundTripProperty},
    {"frame: dead reckoning round trip", &TestFrameRoundTripDeadReckoning},
    {"frame: dead reckoning rules", &TestDeadReckoningRules},
    {"frame: unchanged costs the header", &TestFrameUnchangedIsSmall},
    {"frame: baseline checks", &TestFrameBaselineChecks},
    {"frame: encoder refuses bad frames", &TestEncodeRejects},
    {"frame: truncation", &TestDecoderTruncation},
    {"frame: corruption and garbage", &TestDecoderCorruptionAndGarbage},
    {"frame: hostile counts and ids", &TestDecoderHostileCounts},
    {"frame: appearance block", &TestFrameAppearance},
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
