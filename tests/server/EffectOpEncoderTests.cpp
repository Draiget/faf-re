// Engine addition (dedicated-server plan WP9.1): server/EffectOpEncoder.h encodes the sim's effect operations as the
// server's effects lane sends them, and remote/wire/EffectLane.h reads the lane. These check its bytes (varints, name
// references, coalescing, the destroys a client derives, ops on effects it never saw created), the lane's framing with
// each view's own name table, and that the reader gets back every op the encoder wrote.

#include <gtest/gtest.h>

#include <cstdint>
#include <initializer_list>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "remote/wire/EffectLane.h"
#include "server/EffectOpEncoder.h"

using faf::remote::wire::CEffectLaneReader;
using faf::remote::wire::SEffectLaneOp;
using faf::server::CEffectLaneNames;
using faf::server::CEffectOpEncoder;
using faf::server::EEffectNameTable;
using faf::server::SEffectBeat;
using moho::EEffectOp;
using Bytes = std::vector<std::uint8_t>;

namespace
{
  const moho::IEffect* FakeEffect(
    const std::uintptr_t n
  )
  {
    return reinterpret_cast<const moho::IEffect*>(0x10000u + n * 0x100u);
  }

  constexpr std::uint8_t Op(
    const EEffectOp op
  )
  {
    return static_cast<std::uint8_t>(op);
  }

  Bytes Varint(
    const std::uint32_t value
  )
  {
    Bytes out;
    CEffectOpEncoder::AppendVarint(out, value);
    return out;
  }

  Bytes Lane(
    CEffectLaneNames& names,
    const SEffectBeat& beat
  )
  {
    Bytes lane;
    names.Write(beat, lane);
    return lane;
  }

  Bytes Concat(
    std::initializer_list<Bytes> parts
  )
  {
    Bytes out;
    for (const Bytes& part : parts) {
      out.insert(out.end(), part.begin(), part.end());
    }
    return out;
  }

  Bytes Text(
    const std::string& text
  )
  {
    Bytes out = Varint(static_cast<std::uint32_t>(text.size()));
    out.insert(out.end(), text.begin(), text.end());
    return out;
  }
} // namespace

TEST(
  EffectOpEncoder,
  VarintIsLeb128
)
{
  EXPECT_EQ(Varint(0u), (Bytes{0x00}));
  EXPECT_EQ(Varint(1u), (Bytes{0x01}));
  EXPECT_EQ(Varint(127u), (Bytes{0x7F}));
  EXPECT_EQ(Varint(128u), (Bytes{0x80, 0x01}));
  EXPECT_EQ(Varint(300u), (Bytes{0xAC, 0x02}));
  EXPECT_EQ(Varint(16384u), (Bytes{0x80, 0x80, 0x01}));
  EXPECT_EQ(Varint(0xFFFFFFFFu), (Bytes{0xFF, 0xFF, 0xFF, 0xFF, 0x0F}));
}

TEST(
  EffectOpEncoder,
  OpsReferToNamesByEntryAndListTheBeatsNames
)
{
  CEffectOpEncoder encoder;
  encoder.Record(
    EEffectOp::CreateEmitterOnEntity, {.effect = FakeEffect(1), .entity = 200, .army = 2, .blueprint = "/a.bp"}
  );
  encoder.Record(
    EEffectOp::CreateAttachedEmitter,
    {.effect = FakeEffect(2), .entity = 200, .bone = -1, .army = -1, .blueprint = "/a.bp"}
  );
  encoder.Record(
    EEffectOp::CreateEmitterOnEntity, {.effect = FakeEffect(3), .entity = 5, .army = 0, .blueprint = "/b.bp"}
  );
  const SEffectBeat beat = encoder.EndBeat();

  const Bytes expected{
    // id 0, entity 200 (+1 = 201: two bytes), blueprint entry 0 (reference 1), army 2 (+1)
    Op(EEffectOp::CreateEmitterOnEntity),
    0x00,
    0xC9,
    0x01,
    0x01,
    0x03,
    // id 1, entity 201, bone -1 (0), blueprint reference 1 again, army -1 (0)
    Op(EEffectOp::CreateAttachedEmitter),
    0x01,
    0xC9,
    0x01,
    0x00,
    0x01,
    0x00,
    // id 2, entity 5 (6), blueprint reference 2, army 0 (1)
    Op(EEffectOp::CreateEmitterOnEntity),
    0x02,
    0x06,
    0x02,
    0x01
  };
  EXPECT_EQ(beat.ops, expected);
  EXPECT_EQ(beat.opCount, 3u);
  ASSERT_EQ(beat.names.size(), 2u); // each name once, in first-use order
  EXPECT_EQ(beat.names[0].table, EEffectNameTable::Blueprints);
  EXPECT_EQ(beat.names[0].entry, 0u);
  EXPECT_EQ(*beat.names[0].text, "/a.bp");
  EXPECT_EQ(beat.names[1].entry, 1u);
  EXPECT_EQ(*beat.names[1].text, "/b.bp");
  EXPECT_EQ(encoder.BlueprintNames(), 2u);
  EXPECT_EQ(encoder.EncodedOps(EEffectOp::CreateEmitterOnEntity), 2u);
  EXPECT_EQ(encoder.EncodedBytes(EEffectOp::CreateAttachedEmitter), 7u);

  // A later beat names a known blueprint by the same entry, and lists it again for views that lack it.
  encoder.Record(
    EEffectOp::CreateEmitterOnEntity, {.effect = FakeEffect(4), .entity = 5, .army = 0, .blueprint = "/b.bp"}
  );
  const SEffectBeat next = encoder.EndBeat();
  EXPECT_EQ(next.ops, (Bytes{Op(EEffectOp::CreateEmitterOnEntity), 0x03, 0x06, 0x02, 0x01}));
  ASSERT_EQ(next.names.size(), 1u);
  EXPECT_EQ(next.names[0].entry, 1u);
}

TEST(
  EffectLane,
  EachViewGetsANameOnceAndALateViewGetsWhatItsOpsNeed
)
{
  CEffectOpEncoder encoder;
  CEffectLaneNames early;
  CEffectLaneNames late;

  encoder.Record(
    EEffectOp::CreateEmitterOnEntity, {.effect = FakeEffect(1), .entity = 5, .army = 0, .blueprint = "/a.bp"}
  );
  encoder.Record(
    EEffectOp::CreateEmitterOnEntity, {.effect = FakeEffect(2), .entity = 5, .army = 0, .blueprint = "/b.bp"}
  );
  const SEffectBeat first = encoder.EndBeat();
  // Two blueprint names (entry, text each), no texture name, then the ops.
  EXPECT_EQ(
    Lane(early, first), Concat({Bytes{0x02, 0x00}, Text("/a.bp"), Bytes{0x01}, Text("/b.bp"), Bytes{0x00}, first.ops})
  );
  EXPECT_EQ(early.NamesSent(), 2u);

  // A beat with no op: an empty lane, for any view.
  const SEffectBeat quiet = encoder.EndBeat();
  EXPECT_EQ(quiet.opCount, 0u);
  EXPECT_TRUE(Lane(early, quiet).empty());
  EXPECT_TRUE(Lane(late, quiet).empty());

  // Both blueprints again: the early view has them, the late one (here from now on) gets the one its ops name.
  encoder.Record(
    EEffectOp::CreateEmitterOnEntity, {.effect = FakeEffect(3), .entity = 6, .army = 1, .blueprint = "/b.bp"}
  );
  const SEffectBeat second = encoder.EndBeat();
  EXPECT_EQ(Lane(early, second), Concat({Bytes{0x00, 0x00}, second.ops}));
  EXPECT_EQ(Lane(late, second), Concat({Bytes{0x01, 0x01}, Text("/b.bp"), Bytes{0x00}, second.ops}));
  EXPECT_EQ(late.NamesSent(), 1u);

  // A client back holding nothing gets the names its ops need again.
  early.Reset();
  EXPECT_EQ(Lane(early, second), Concat({Bytes{0x01, 0x01}, Text("/b.bp"), Bytes{0x00}, second.ops}));
  EXPECT_EQ(early.NamesSent(), 3u);

  // Textures have their own table and section.
  const float light[5] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f};
  encoder.Record(
    EEffectOp::CreateLightParticle, {.army = 1, .texture = "glow", .texture2 = "ramp", .values = light, .valueCount = 5}
  );
  const SEffectBeat third = encoder.EndBeat();
  EXPECT_EQ(Lane(late, third), Concat({Bytes{0x00, 0x02, 0x00}, Text("glow"), Bytes{0x01}, Text("ramp"), third.ops}));
}

TEST(
  EffectOpEncoder,
  SetFloatKeepsTheLastValuePerParameterInABeat
)
{
  CEffectOpEncoder encoder;
  encoder.Record(EEffectOp::CreateBeam, {.effect = FakeEffect(1), .army = 0, .blueprint = "/beam.bp"});
  (void)encoder.EndBeat();

  const float one = 1.0f;
  const float two = 2.0f;
  const float three = 3.0f;
  encoder.Record(EEffectOp::SetFloat, {.effect = FakeEffect(1), .param = 6, .values = &one, .valueCount = 1});
  encoder.Record(EEffectOp::SetFloat, {.effect = FakeEffect(1), .param = 7, .values = &two, .valueCount = 1});
  encoder.Record(EEffectOp::SetFloat, {.effect = FakeEffect(1), .param = 6, .values = &three, .valueCount = 1});
  const SEffectBeat beat = encoder.EndBeat();

  EXPECT_EQ(beat.opCount, 2u);
  EXPECT_EQ(encoder.Coalesced(), 1u);
  EXPECT_TRUE(beat.names.empty());
  // Parameter 7 = 2.0, then parameter 6 = 3.0 where the last write was.
  EXPECT_EQ(
    beat.ops,
    (Bytes{
      Op(EEffectOp::SetFloat),
      0x00,
      0x08,
      0x00,
      0x00,
      0x00,
      0x40,
      Op(EEffectOp::SetFloat),
      0x00,
      0x07,
      0x00,
      0x00,
      0x40,
      0x40
    })
  );

  // Coalescing is per beat: the next beat's write is sent again.
  encoder.Record(EEffectOp::SetFloat, {.effect = FakeEffect(1), .param = 6, .values = &one, .valueCount = 1});
  EXPECT_EQ(encoder.EndBeat().opCount, 1u);
  EXPECT_EQ(encoder.Coalesced(), 1u);
}

TEST(
  EffectOpEncoder,
  DerivedDestroysAreCountedNotEncoded
)
{
  CEffectOpEncoder encoder;
  encoder.Record(
    EEffectOp::CreateEmitterOnEntity, {.effect = FakeEffect(1), .entity = 1, .army = 0, .blueprint = "/a"}
  );
  encoder.Record(
    EEffectOp::CreateEmitterOnEntity, {.effect = FakeEffect(2), .entity = 1, .army = 0, .blueprint = "/a"}
  );
  (void)encoder.EndBeat();

  // A lifetime end: the client derives it.
  encoder.Record(EEffectOp::Destroy, {.effect = FakeEffect(1)});
  // A script's destroy, then the effect manager's destroy it calls: one op on the wire, nothing derived.
  encoder.Record(EEffectOp::DestroyByScript, {.effect = FakeEffect(2)});
  encoder.Record(EEffectOp::Destroy, {.effect = FakeEffect(2)});
  const SEffectBeat beat = encoder.EndBeat();

  EXPECT_EQ(beat.ops, (Bytes{Op(EEffectOp::DestroyByScript), 0x01}));
  EXPECT_EQ(beat.opCount, 1u);
  EXPECT_EQ(encoder.DerivedDestroys(), 1u);
  EXPECT_EQ(encoder.EncodedOps(EEffectOp::Destroy), 0u);
  EXPECT_EQ(encoder.DroppedTotal(), 0u);
  EXPECT_EQ(encoder.LiveEffects(), 0u);

  // Ids are not reused: a new effect at a freed address gets the next one.
  encoder.Record(
    EEffectOp::CreateEmitterOnEntity, {.effect = FakeEffect(1), .entity = 1, .army = 0, .blueprint = "/a"}
  );
  const SEffectBeat next = encoder.EndBeat();
  ASSERT_GE(next.ops.size(), 2u);
  EXPECT_EQ(next.ops[1], 0x02);
}

TEST(
  EffectOpEncoder,
  OpsOnEffectsNeverSeenCreatedAreDropped
)
{
  CEffectOpEncoder encoder;
  const float value = 1.0f;
  const float xyz[3] = {1.0f, 2.0f, 3.0f};
  encoder.Record(EEffectOp::SetFloat, {.effect = FakeEffect(9), .param = 1, .values = &value, .valueCount = 1});
  encoder.Record(EEffectOp::SetN, {.effect = FakeEffect(9), .param = 0, .values = xyz, .valueCount = 3});
  encoder.Record(EEffectOp::SetBone, {.effect = FakeEffect(9), .entity = 3, .bone = 2});
  encoder.Record(EEffectOp::DestroyByScript, {.effect = FakeEffect(9)});
  encoder.Record(EEffectOp::Destroy, {.effect = FakeEffect(9)});

  // An effect's ops after its destroy are dropped too: the client no longer has it.
  encoder.Record(
    EEffectOp::CreateEmitterOnEntity, {.effect = FakeEffect(1), .entity = 1, .army = 0, .blueprint = "/a"}
  );
  encoder.Record(EEffectOp::Destroy, {.effect = FakeEffect(1)});
  encoder.Record(EEffectOp::SetFloat, {.effect = FakeEffect(1), .param = 1, .values = &value, .valueCount = 1});
  const SEffectBeat beat = encoder.EndBeat();

  EXPECT_EQ(beat.opCount, 1u); // the create
  EXPECT_EQ(encoder.Dropped(EEffectOp::SetFloat), 2u);
  EXPECT_EQ(encoder.Dropped(EEffectOp::SetN), 1u);
  EXPECT_EQ(encoder.Dropped(EEffectOp::SetBone), 1u);
  EXPECT_EQ(encoder.Dropped(EEffectOp::DestroyByScript), 1u);
  EXPECT_EQ(encoder.Dropped(EEffectOp::Destroy), 1u);
  EXPECT_EQ(encoder.DroppedTotal(), 6u);
  EXPECT_EQ(encoder.DerivedDestroys(), 1u);
}

TEST(
  EffectOpEncoder,
  VariableFloatsAndLightsWithoutAnEffect
)
{
  CEffectOpEncoder encoder;
  encoder.Record(
    EEffectOp::CreateEmitterOnEntity, {.effect = FakeEffect(1), .entity = 1, .army = 0, .blueprint = "/a"}
  );
  (void)encoder.EndBeat();

  // A curve: bounds and one key, 7 floats, the count first.
  const float curve[7] = {0.0f, 0.0f, 1.0f, 1.0f, 0.0f, 1.0f, 0.0f};
  encoder.Record(EEffectOp::SetCurve, {.effect = FakeEffect(1), .param = 10, .values = curve, .valueCount = 7});
  const SEffectBeat curveBeat = encoder.EndBeat();
  ASSERT_EQ(curveBeat.ops.size(), 1u + 1u + 1u + 1u + 7u * 4u);
  EXPECT_EQ(curveBeat.ops[2], 11u); // parameter 10 + 1
  EXPECT_EQ(curveBeat.ops[3], 7u);  // the float count

  // A light has no effect id; its textures go through their own name table.
  const float light[5] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f};
  encoder.Record(
    EEffectOp::CreateLightParticle, {.army = 1, .texture = "glow", .texture2 = "ramp", .values = light, .valueCount = 5}
  );
  encoder.Record(
    EEffectOp::CreateLightParticle, {.army = 1, .texture = "glow", .texture2 = "ramp", .values = light, .valueCount = 5}
  );
  const SEffectBeat beat = encoder.EndBeat();
  EXPECT_EQ(beat.opCount, 2u);
  EXPECT_EQ(beat.names.size(), 2u);
  EXPECT_EQ(encoder.TextureNames(), 2u);
  EXPECT_EQ(encoder.BlueprintNames(), 1u);
  // op, army, texture references 1 and 2, 5 floats; twice.
  EXPECT_EQ(encoder.EncodedBytes(EEffectOp::CreateLightParticle), 2u * (1u + 1u + 1u + 1u + 20u));
  EXPECT_EQ(beat.ops[0], Op(EEffectOp::CreateLightParticle));
  EXPECT_EQ(beat.ops[1], 0x02); // army 1, no id before it
}

TEST(
  EffectLane,
  TheReaderGetsBackEveryOp
)
{
  CEffectOpEncoder encoder;
  const float position[3] = {10.0f, 20.5f, -30.25f};
  const float light[5] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f};
  const float beamFloats[9] = {1, 2, 3, 4, 5, 6, 0.5f, 0.25f, 2.0f};
  const float scale = 1.5f;
  const float offset[3] = {0.0f, 1.0f, 0.0f};
  const float curve[7] = {0.0f, 0.0f, 1.0f, 2.0f, 0.5f, 1.5f, 0.0f};
  const std::uint32_t bigEntity = 0x00F00123u; // army and kind in the high bits (EntityDb.cpp)

  std::vector<std::pair<EEffectOp, moho::SEffectOpArgs>> ops = {
    {EEffectOp::CreateEmitter,
     {.effect = FakeEffect(1), .army = 3, .blueprint = "/e/a.bp", .values = position, .valueCount = 3}},
    {EEffectOp::CreateAttachedEmitter,
     {.effect = FakeEffect(2),
      .entity = static_cast<std::int32_t>(bigEntity),
      .bone = 4,
      .army = 0,
      .blueprint = "/e/b.bp"}},
    {EEffectOp::CreateEmitterAtBone,
     {.effect = FakeEffect(3), .entity = 7, .bone = 0, .army = 1, .blueprint = "/e/a.bp"}},
    {EEffectOp::CreateTrail, {.effect = FakeEffect(4), .entity = 7, .bone = 2, .army = 1, .blueprint = "/e/t.bp"}},
    {EEffectOp::CreateEmitterAtEntity, {.effect = FakeEffect(5), .entity = 8, .army = -1, .blueprint = "/e/b.bp"}},
    {EEffectOp::CreateEmitterOnEntity, {.effect = FakeEffect(6), .entity = 9, .army = 2, .blueprint = "/e/c.bp"}},
    {EEffectOp::CreateBeam, {.effect = FakeEffect(7), .army = 2, .blueprint = "/e/beam.bp"}},
    {EEffectOp::CreateBeam,
     {.effect = FakeEffect(8),
      .entity = 11,
      .bone = 1,
      .army = 0,
      .texture = "/tex/beam.dds",
      .param = 3,
      .values = beamFloats,
      .valueCount = 9}},
    {EEffectOp::CreateBeamEntityToEntity,
     {.effect = FakeEffect(9),
      .entity = 1,
      .bone = 2,
      .entity2 = 3,
      .bone2 = -1,
      .army = 0,
      .blueprint = "/e/beam.bp"}},
    {EEffectOp::AttachBeamEntityToEntity,
     {.effect = FakeEffect(10),
      .entity = 4,
      .bone = 5,
      .entity2 = 6,
      .bone2 = 7,
      .army = 1,
      .blueprint = "/e/beam.bp"}},
    {EEffectOp::CreateLightParticle,
     {.army = 1, .texture = "/tex/glow.dds", .texture2 = "/tex/ramp.dds", .values = light, .valueCount = 5}},
    {EEffectOp::SetFloat, {.effect = FakeEffect(6), .param = 18, .values = &scale, .valueCount = 1}},
    {EEffectOp::SetN, {.effect = FakeEffect(6), .param = 0, .values = offset, .valueCount = 3}},
    {EEffectOp::SetVector, {.effect = FakeEffect(6), .param = 2, .values = offset, .valueCount = 3}},
    {EEffectOp::SetCurve, {.effect = FakeEffect(6), .param = 10, .values = curve, .valueCount = 7}},
    {EEffectOp::SetEntity, {.effect = FakeEffect(7), .entity = 12}},
    {EEffectOp::SetBone, {.effect = FakeEffect(7), .entity = 12, .bone = 3}},
    {EEffectOp::DestroyByScript, {.effect = FakeEffect(6)}},
  };
  for (const auto& [op, args] : ops) {
    encoder.Record(op, args);
  }
  CEffectLaneNames names;
  const Bytes lane = Lane(names, encoder.EndBeat());

  CEffectLaneReader reader;
  std::vector<SEffectLaneOp> decoded;
  ASSERT_TRUE(reader.Read(lane, decoded));
  ASSERT_EQ(decoded.size(), ops.size());
  EXPECT_EQ(reader.UnknownNames(), 0u);
  std::uint32_t nextId = 0;
  std::uint32_t idOf[16] = {};
  for (std::size_t i = 0; i < ops.size(); ++i) {
    const auto& [op, args] = ops[i];
    const SEffectLaneOp& got = decoded[i];
    SCOPED_TRACE("op " + std::to_string(static_cast<int>(op)) + " #" + std::to_string(i));
    EXPECT_EQ(got.op, op);
    const auto effect = static_cast<std::size_t>((reinterpret_cast<std::uintptr_t>(args.effect) - 0x10000u) / 0x100u);
    if (op <= EEffectOp::CreateLightParticle) {
      if (op != EEffectOp::CreateLightParticle) {
        idOf[effect] = nextId;
        EXPECT_EQ(got.id, nextId++);
      }
    } else {
      EXPECT_EQ(got.id, idOf[effect]);
    }
    const bool hasEntity = op != EEffectOp::CreateEmitter && op != EEffectOp::CreateLightParticle &&
      op != EEffectOp::SetFloat && op != EEffectOp::SetN && op != EEffectOp::SetVector && op != EEffectOp::SetCurve &&
      op != EEffectOp::DestroyByScript && !(op == EEffectOp::CreateBeam && args.blueprint != nullptr);
    if (hasEntity) {
      EXPECT_EQ(got.entity, args.entity);
    }
    if (op == EEffectOp::CreateBeamEntityToEntity || op == EEffectOp::AttachBeamEntityToEntity) {
      EXPECT_EQ(got.bone, args.bone);
      EXPECT_EQ(got.entity2, args.entity2);
      EXPECT_EQ(got.bone2, args.bone2);
    }
    if (op <= EEffectOp::CreateLightParticle) {
      EXPECT_EQ(got.army, args.army);
    }
    if (args.blueprint != nullptr) {
      const std::string* const name = reader.Name(false, got.blueprint);
      ASSERT_NE(name, nullptr);
      EXPECT_EQ(*name, args.blueprint);
    }
    if (args.texture != nullptr) {
      const std::string* const name = reader.Name(true, got.texture);
      ASSERT_NE(name, nullptr);
      EXPECT_EQ(*name, args.texture);
    }
    if (args.texture2 != nullptr) {
      const std::string* const name = reader.Name(true, got.texture2);
      ASSERT_NE(name, nullptr);
      EXPECT_EQ(*name, args.texture2);
    }
    if (args.values != nullptr) {
      EXPECT_EQ(got.values, std::vector<float>(args.values, args.values + args.valueCount));
    }
    if (
      (op >= EEffectOp::SetFloat && op <= EEffectOp::SetCurve) ||
      (op == EEffectOp::CreateBeam && args.blueprint == nullptr)
    ) {
      EXPECT_EQ(got.param, args.param);
    }
    if (
      op == EEffectOp::CreateAttachedEmitter || op == EEffectOp::CreateEmitterAtBone || op == EEffectOp::CreateTrail ||
      op == EEffectOp::SetBone || (op == EEffectOp::CreateBeam && args.blueprint == nullptr)
    ) {
      EXPECT_EQ(got.bone, args.bone);
    }
  }
  EXPECT_EQ(reader.Name(false, 0u), nullptr);
  EXPECT_EQ(reader.NamesTaken(), 4u + 1u + 3u); // blueprints a, b, t, c, beam; textures beam, glow, ramp
}

TEST(
  EffectLane,
  TheReaderRefusesADamagedLaneAndCountsNamesItWasNeverSent
)
{
  CEffectOpEncoder encoder;
  const float xyz[3] = {1.0f, 2.0f, 3.0f};
  encoder.Record(
    EEffectOp::CreateEmitterOnEntity, {.effect = FakeEffect(1), .entity = 1, .army = 0, .blueprint = "/a.bp"}
  );
  encoder.Record(EEffectOp::SetN, {.effect = FakeEffect(1), .param = 0, .values = xyz, .valueCount = 3});
  CEffectLaneNames names;
  const Bytes lane = Lane(names, encoder.EndBeat());

  CEffectLaneReader whole;
  std::vector<SEffectLaneOp> ops;
  ASSERT_TRUE(whole.Read(lane, ops));
  ASSERT_EQ(ops.size(), 2u);

  // Cut anywhere: refused, or (cut between ops) fewer ops. Never more, and nothing read past the cut.
  for (std::size_t cut = 1; cut < lane.size(); ++cut) {
    CEffectLaneReader reader;
    const bool read = reader.Read(std::span<const std::uint8_t>(lane.data(), cut), ops);
    EXPECT_TRUE(!read || ops.size() < 2u) << "cut at " << cut;
  }

  // `Destroy` never goes on the wire, and an op byte past the last op is no op at all.
  for (const std::uint8_t bad : {Op(EEffectOp::Destroy), Op(EEffectOp::Count), std::uint8_t{0xFF}}) {
    Bytes damaged{0x00, 0x00, bad, 0x00};
    CEffectLaneReader reader;
    EXPECT_FALSE(reader.Read(damaged, ops));
  }
  // A float count past the lane's end.
  {
    Bytes damaged{0x00, 0x00, Op(EEffectOp::SetN), 0x00, 0x01, 0xFF, 0xFF, 0x03};
    CEffectLaneReader reader;
    EXPECT_FALSE(reader.Read(damaged, ops));
  }

  // A view whose client joined after the name went (here: a lane written for another client): the op decodes, and
  // the reference is counted.
  encoder.Record(
    EEffectOp::CreateEmitterOnEntity, {.effect = FakeEffect(2), .entity = 2, .army = 0, .blueprint = "/a.bp"}
  );
  const Bytes later = Lane(names, encoder.EndBeat());
  CEffectLaneReader fresh;
  ASSERT_TRUE(fresh.Read(later, ops));
  ASSERT_EQ(ops.size(), 1u);
  EXPECT_EQ(fresh.UnknownNames(), 1u);
  EXPECT_EQ(fresh.Name(false, ops[0].blueprint), nullptr);
  ASSERT_TRUE(whole.Read(later, ops));
  EXPECT_EQ(whole.UnknownNames(), 0u);
  EXPECT_EQ(*whole.Name(false, ops[0].blueprint), "/a.bp");
}
