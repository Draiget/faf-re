// Engine addition (dedicated-server plan WP9.1): headless/EffectOpEncoder.h encodes the sim's effect operations as
// the server's replication would send them. These check its bytes: varints, the name table, coalescing, the destroys
// a client derives, and ops on effects it never saw created.

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include "headless/EffectOpEncoder.h"

using faf::headless::CEffectOpEncoder;
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
  CreateSendsTheBlueprintNameOnlyOnFirstUse
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
  const CEffectOpEncoder::SBeat beat = encoder.EndBeat();

  const Bytes expected{
    // id 0, entity 200 (+1 = 201: two bytes), blueprint entry 1 with its text, army 2 (+1)
    Op(EEffectOp::CreateEmitterOnEntity),
    0x00,
    0xC9,
    0x01,
    0x01,
    0x05,
    '/',
    'a',
    '.',
    'b',
    'p',
    0x03,
    // id 1, entity 201, bone -1 (0), blueprint entry 1 again: no text, army -1 (0)
    Op(EEffectOp::CreateAttachedEmitter),
    0x01,
    0xC9,
    0x01,
    0x00,
    0x01,
    0x00,
    // id 2, entity 5 (6), blueprint entry 2 with its text, army 0 (1)
    Op(EEffectOp::CreateEmitterOnEntity),
    0x02,
    0x06,
    0x02,
    0x05,
    '/',
    'b',
    '.',
    'b',
    'p',
    0x01
  };
  EXPECT_EQ(encoder.Bytes(), expected);
  EXPECT_EQ(beat.ops, 3u);
  EXPECT_EQ(beat.bytes, expected.size());
  EXPECT_EQ(encoder.BlueprintNames(), 2u);
  EXPECT_EQ(encoder.EncodedOps(EEffectOp::CreateEmitterOnEntity), 2u);
  EXPECT_EQ(encoder.EncodedBytes(EEffectOp::CreateAttachedEmitter), 7u);

  // A later beat names a known blueprint by its entry alone.
  encoder.Record(
    EEffectOp::CreateEmitterOnEntity, {.effect = FakeEffect(4), .entity = 5, .army = 0, .blueprint = "/b.bp"}
  );
  (void)encoder.EndBeat();
  EXPECT_EQ(encoder.Bytes(), (Bytes{Op(EEffectOp::CreateEmitterOnEntity), 0x03, 0x06, 0x02, 0x01}));
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
  const CEffectOpEncoder::SBeat beat = encoder.EndBeat();

  EXPECT_EQ(beat.ops, 2u);
  EXPECT_EQ(encoder.Coalesced(), 1u);
  // Parameter 7 = 2.0, then parameter 6 = 3.0 where the last write was.
  EXPECT_EQ(
    encoder.Bytes(),
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
  EXPECT_EQ(encoder.EndBeat().ops, 1u);
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
  const CEffectOpEncoder::SBeat beat = encoder.EndBeat();

  EXPECT_EQ(encoder.Bytes(), (Bytes{Op(EEffectOp::DestroyByScript), 0x01}));
  EXPECT_EQ(beat.ops, 1u);
  EXPECT_EQ(encoder.DerivedDestroys(), 1u);
  EXPECT_EQ(encoder.EncodedOps(EEffectOp::Destroy), 0u);
  EXPECT_EQ(encoder.DroppedTotal(), 0u);
  EXPECT_EQ(encoder.LiveEffects(), 0u);

  // Ids are not reused: a new effect at a freed address gets the next one.
  encoder.Record(
    EEffectOp::CreateEmitterOnEntity, {.effect = FakeEffect(1), .entity = 1, .army = 0, .blueprint = "/a"}
  );
  (void)encoder.EndBeat();
  ASSERT_GE(encoder.Bytes().size(), 2u);
  EXPECT_EQ(encoder.Bytes()[1], 0x02);
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
  const CEffectOpEncoder::SBeat beat = encoder.EndBeat();

  EXPECT_EQ(beat.ops, 1u); // the create
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
  (void)encoder.EndBeat();
  ASSERT_EQ(encoder.Bytes().size(), 1u + 1u + 1u + 1u + 7u * 4u);
  EXPECT_EQ(encoder.Bytes()[2], 11u); // parameter 10 + 1
  EXPECT_EQ(encoder.Bytes()[3], 7u);  // the float count

  // A light has no effect id; its textures go through their own name table.
  const float light[5] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f};
  encoder.Record(
    EEffectOp::CreateLightParticle, {.army = 1, .texture = "glow", .texture2 = "ramp", .values = light, .valueCount = 5}
  );
  encoder.Record(
    EEffectOp::CreateLightParticle, {.army = 1, .texture = "glow", .texture2 = "ramp", .values = light, .valueCount = 5}
  );
  const CEffectOpEncoder::SBeat beat = encoder.EndBeat();
  EXPECT_EQ(beat.ops, 2u);
  EXPECT_EQ(encoder.TextureNames(), 2u);
  EXPECT_EQ(encoder.BlueprintNames(), 1u);
  // op, army, "glow" fresh (1 + 1 + 4), "ramp" fresh (1 + 1 + 4), 5 floats; then op, army, 1, 2, 5 floats.
  EXPECT_EQ(
    encoder.EncodedBytes(EEffectOp::CreateLightParticle), (1u + 1u + 6u + 6u + 20u) + (1u + 1u + 1u + 1u + 20u)
  );
  EXPECT_EQ(encoder.Bytes()[0], Op(EEffectOp::CreateLightParticle));
  EXPECT_EQ(encoder.Bytes()[1], 0x02); // army 1, no id before it
}
