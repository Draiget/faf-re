// Engine addition (dedicated-server plan WP9.3): remote/client/EffectLaneApplier.h, the client's end of the effects
// lane. Lanes are made as the server makes them (server/EffectOpEncoder.h and its per-view names), then applied to a
// target that records every call: each op kind reaches it with its arguments and names, under the server's effect id;
// a repeated create replaces; an effect goes with its entity; what can't be applied is skipped and counted by reason.

#include <gtest/gtest.h>

#include <cstdint>
#include <set>
#include <string>
#include <vector>

#include "remote/client/EffectLaneApplier.h"
#include "remote/wire/EffectLane.h"
#include "server/EffectOpEncoder.h"

using faf::remote::client::CEffectLaneApplier;
using faf::remote::client::EEffectSkip;
using faf::remote::client::IEffectLaneTarget;
using faf::remote::wire::SEffectLaneOp;
using faf::server::CEffectLaneNames;
using faf::server::CEffectOpEncoder;
using faf::server::SEffectBeat;
using moho::EEffectOp;
using Bytes = std::vector<std::uint8_t>;

namespace
{
  const moho::IEffect* Effect(
    const std::uintptr_t n
  )
  {
    return reinterpret_cast<const moho::IEffect*>(0x20000u + n * 0x100u);
  }

  /** One call the applier made. */
  struct SCall
  {
    std::string what; // "create", "change", "destroy", "light"
    std::uint32_t id = 0;
    SEffectLaneOp op;
    std::string blueprint;
    std::string texture;
    std::string ramp;
  };

  /** Records each call; holds the entities in `holds` (and `removed`, for `orRemoved`); refuses `missing`. */
  class CRecordingTarget final : public IEffectLaneTarget
  {
  public:
    std::set<std::int32_t> holds;
    std::set<std::int32_t> removed;
    std::set<std::string> missing;
    std::vector<SCall> calls;

    [[nodiscard]] bool HoldsEntity(
      const std::int32_t entity,
      const bool orRemoved
    ) const override
    {
      return holds.contains(entity) || (orRemoved && removed.contains(entity));
    }
    [[nodiscard]] bool Create(
      const std::uint32_t id,
      const SEffectLaneOp& op,
      const std::string* const blueprint,
      const std::string* const texture
    ) override
    {
      if (blueprint != nullptr && missing.contains(*blueprint)) {
        return false;
      }
      calls.push_back({"create", id, op, blueprint != nullptr ? *blueprint : "", texture != nullptr ? *texture : ""});
      return true;
    }
    void Change(
      const std::uint32_t id,
      const SEffectLaneOp& op
    ) override
    {
      calls.push_back({"change", id, op});
    }
    void Destroy(
      const std::uint32_t id
    ) override
    {
      calls.push_back({"destroy", id});
    }
    void Light(
      const SEffectLaneOp& op,
      const std::string* const texture,
      const std::string* const ramp
    ) override
    {
      calls.push_back({"light", 0u, op, "", texture != nullptr ? *texture : "", ramp != nullptr ? *ramp : ""});
    }
    void Unticked() override
    {
      calls.push_back({"unticked"});
    }

    [[nodiscard]] std::vector<std::string> Whats() const
    {
      std::vector<std::string> out;
      for (const SCall& call : calls) {
        out.push_back(call.what);
      }
      return out;
    }
  };

  /** A server's encoder and one view's names: each beat's lane as that view's client gets it (every op). */
  struct SServer
  {
    CEffectOpEncoder encoder;
    CEffectLaneNames names;

    Bytes Lane(
      const bool ticked = true
    )
    {
      const SEffectBeat beat = encoder.EndBeat(ticked);
      Bytes lane;
      names.Write(beat, lane);
      return lane;
    }
  };

  const float kTwo = 2.0f;
  const float kXyz[3] = {1.0f, 2.0f, 3.0f};
  const float kFive[5] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f};
} // namespace

TEST(
  EffectLaneApplier,
  EveryOpKindReachesTheTargetWithItsArguments
)
{
  SServer server;
  CRecordingTarget target;
  target.holds = {10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21};
  CEffectLaneApplier applier(target);

  server.encoder.Record(
    EEffectOp::CreateEmitter, {.effect = Effect(1), .army = 2, .blueprint = "/e.bp", .values = kXyz, .valueCount = 3}
  );
  server.encoder.Record(
    EEffectOp::CreateAttachedEmitter, {.effect = Effect(2), .entity = 10, .bone = 1, .army = 0, .blueprint = "/e.bp"}
  );
  server.encoder.Record(
    EEffectOp::CreateEmitterAtBone, {.effect = Effect(3), .entity = 11, .bone = 4, .army = 0, .blueprint = "/f.bp"}
  );
  server.encoder.Record(
    EEffectOp::CreateEmitterAtEntity, {.effect = Effect(4), .entity = 12, .army = 3, .blueprint = "/e.bp"}
  );
  server.encoder.Record(
    EEffectOp::CreateEmitterOnEntity, {.effect = Effect(5), .entity = 13, .army = 0, .blueprint = "/e.bp"}
  );
  server.encoder.Record(
    EEffectOp::CreateTrail, {.effect = Effect(6), .entity = 14, .bone = 0, .army = 0, .blueprint = "/t.bp"}
  );
  server.encoder.Record(EEffectOp::CreateBeam, {.effect = Effect(7), .army = 1, .blueprint = "/b.bp"});
  server.encoder.Record(
    EEffectOp::CreateBeam,
    {.effect = Effect(8),
     .entity = 15,
     .bone = 2,
     .army = 1,
     .texture = "/x.dds",
     .param = 3,
     .values = kFive,
     .valueCount = 5}
  );
  server.encoder.Record(
    EEffectOp::CreateBeamEntityToEntity,
    {.effect = Effect(9), .entity = 16, .bone = 1, .entity2 = 17, .bone2 = 2, .army = 1, .blueprint = "/b.bp"}
  );
  server.encoder.Record(
    EEffectOp::AttachBeamEntityToEntity,
    {.effect = Effect(10), .entity = 18, .bone = 1, .entity2 = 19, .bone2 = -1, .army = 1, .blueprint = "/c.bp"}
  );
  server.encoder.Record(
    EEffectOp::CreateLightParticle,
    {.army = 1, .texture = "/l.dds", .texture2 = "/r.dds", .values = kFive, .valueCount = 5}
  );
  server.encoder.Record(EEffectOp::SetFloat, {.effect = Effect(2), .param = 18, .values = &kTwo, .valueCount = 1});
  server.encoder.Record(EEffectOp::SetVector, {.effect = Effect(2), .param = 6, .values = kXyz, .valueCount = 3});
  server.encoder.Record(EEffectOp::SetN, {.effect = Effect(5), .param = 0, .values = kXyz, .valueCount = 3});
  server.encoder.Record(EEffectOp::SetCurve, {.effect = Effect(5), .param = 10, .values = kFive, .valueCount = 5});
  server.encoder.Record(EEffectOp::SetEntity, {.effect = Effect(7), .entity = 20});
  server.encoder.Record(EEffectOp::SetBone, {.effect = Effect(7), .entity = 21, .bone = 5});
  server.encoder.Record(EEffectOp::DestroyByScript, {.effect = Effect(3)});
  ASSERT_TRUE(applier.Apply(server.Lane(), false));

  const std::vector<std::string> expected = {
    "create",
    "create",
    "create",
    "create",
    "create",
    "create",
    "create",
    "create",
    "create",
    "create",
    "light",
    "change",
    "change",
    "change",
    "change",
    "change",
    "change",
    "destroy"
  };
  ASSERT_EQ(target.Whats(), expected);
  const std::vector<SCall>& c = target.calls;
  // Effect ids are the server's: 0 up, in create order.
  for (std::uint32_t i = 0; i < 10u; ++i) {
    EXPECT_EQ(c[i].id, i);
  }
  EXPECT_EQ(c[0].op.op, EEffectOp::CreateEmitter);
  EXPECT_EQ(c[0].blueprint, "/e.bp");
  EXPECT_EQ(c[0].op.army, 2);
  EXPECT_EQ(c[0].op.values, (std::vector<float>{1.0f, 2.0f, 3.0f}));
  EXPECT_EQ(c[1].op.op, EEffectOp::CreateAttachedEmitter);
  EXPECT_EQ(c[1].op.entity, 10);
  EXPECT_EQ(c[1].op.bone, 1);
  EXPECT_EQ(c[2].op.op, EEffectOp::CreateEmitterAtBone);
  EXPECT_EQ(c[2].blueprint, "/f.bp");
  EXPECT_EQ(c[2].op.bone, 4);
  EXPECT_EQ(c[3].op.op, EEffectOp::CreateEmitterAtEntity);
  EXPECT_EQ(c[3].op.entity, 12);
  EXPECT_EQ(c[3].op.army, 3);
  EXPECT_EQ(c[4].op.op, EEffectOp::CreateEmitterOnEntity);
  EXPECT_EQ(c[4].op.entity, 13);
  EXPECT_EQ(c[5].op.op, EEffectOp::CreateTrail);
  EXPECT_EQ(c[5].blueprint, "/t.bp");
  EXPECT_EQ(c[5].op.entity, 14);
  EXPECT_EQ(c[6].op.op, EEffectOp::CreateBeam);
  EXPECT_EQ(c[6].blueprint, "/b.bp");
  EXPECT_EQ(c[6].op.army, 1);
  EXPECT_EQ(c[6].op.entity, -1);
  EXPECT_EQ(c[7].op.op, EEffectOp::CreateBeam); // from create parameters: no blueprint, a texture and floats
  EXPECT_EQ(c[7].blueprint, "");
  EXPECT_EQ(c[7].texture, "/x.dds");
  EXPECT_EQ(c[7].op.entity, 15);
  EXPECT_EQ(c[7].op.bone, 2);
  EXPECT_EQ(c[7].op.param, 3); // the blend mode
  EXPECT_EQ(c[7].op.values.size(), 5u);
  EXPECT_EQ(c[8].op.op, EEffectOp::CreateBeamEntityToEntity);
  EXPECT_EQ(c[8].op.entity, 16);
  EXPECT_EQ(c[8].op.bone, 1);
  EXPECT_EQ(c[8].op.entity2, 17);
  EXPECT_EQ(c[8].op.bone2, 2);
  EXPECT_EQ(c[9].op.op, EEffectOp::AttachBeamEntityToEntity);
  EXPECT_EQ(c[9].blueprint, "/c.bp");
  EXPECT_EQ(c[9].op.entity2, 19);
  EXPECT_EQ(c[9].op.bone2, -1);
  EXPECT_EQ(c[10].texture, "/l.dds");
  EXPECT_EQ(c[10].ramp, "/r.dds");
  EXPECT_EQ(c[10].op.values, (std::vector<float>{1.0f, 2.0f, 3.0f, 4.0f, 5.0f}));
  EXPECT_EQ(c[11].id, 1u);
  EXPECT_EQ(c[11].op.op, EEffectOp::SetFloat);
  EXPECT_EQ(c[11].op.param, 18);
  EXPECT_EQ(c[11].op.values, (std::vector<float>{2.0f}));
  EXPECT_EQ(c[12].op.op, EEffectOp::SetVector);
  EXPECT_EQ(c[12].op.param, 6);
  EXPECT_EQ(c[13].id, 4u);
  EXPECT_EQ(c[13].op.op, EEffectOp::SetN);
  EXPECT_EQ(c[13].op.values.size(), 3u);
  EXPECT_EQ(c[14].op.op, EEffectOp::SetCurve);
  EXPECT_EQ(c[14].op.param, 10);
  EXPECT_EQ(c[14].op.values.size(), 5u);
  EXPECT_EQ(c[15].id, 6u);
  EXPECT_EQ(c[15].op.op, EEffectOp::SetEntity);
  EXPECT_EQ(c[15].op.entity, 20);
  EXPECT_EQ(c[16].op.op, EEffectOp::SetBone);
  EXPECT_EQ(c[16].op.entity, 21);
  EXPECT_EQ(c[16].op.bone, 5);
  EXPECT_EQ(c[17].id, 2u); // the script's destroy of the emitter at a bone

  const auto& counts = applier.Total();
  EXPECT_EQ(counts.ops, 18u);
  EXPECT_EQ(counts.applied, 18u);
  EXPECT_EQ(counts.created, 10u);
  EXPECT_EQ(counts.setters, 6u);
  EXPECT_EQ(counts.lights, 1u);
  EXPECT_EQ(counts.destroyedByScript, 1u);
  EXPECT_EQ(counts.Skipped(), 0u);
  EXPECT_EQ(applier.Live(), 9u);
  EXPECT_FALSE(applier.Holds(2u));
}

TEST(
  EffectLaneApplier,
  ACreateForAnIdHeldReplacesIt
)
{
  // The server sends an effect whole again with the same id (its entity came back, or after a mended frame).
  CRecordingTarget target;
  target.holds = {100};
  CEffectLaneApplier applier(target);
  SServer server;
  server.encoder.Record(
    EEffectOp::CreateEmitterOnEntity, {.effect = Effect(1), .entity = 100, .army = 0, .blueprint = "/e.bp"}
  );
  const Bytes create = server.Lane();
  ASSERT_TRUE(applier.Apply(create, false));
  ASSERT_TRUE(applier.Apply(create, false)); // the same create again (its names already held)
  EXPECT_EQ(target.Whats(), (std::vector<std::string>{"create", "destroy", "create"}));
  EXPECT_EQ(target.calls[1].id, 0u);
  EXPECT_EQ(applier.Total().replaced, 1u);
  EXPECT_EQ(applier.Total().created, 2u);
  EXPECT_EQ(applier.Live(), 1u);
}

TEST(
  EffectLaneApplier,
  AnEffectGoesWithItsEntityButAPlacedEmitterStays
)
{
  CRecordingTarget target;
  target.holds = {100, 200, 300};
  CEffectLaneApplier applier(target);
  SServer server;
  server.encoder.Record(
    EEffectOp::CreateEmitterOnEntity, {.effect = Effect(1), .entity = 100, .army = 0, .blueprint = "/e.bp"}
  );
  server.encoder.Record(
    EEffectOp::CreateEmitterAtBone, {.effect = Effect(2), .entity = 100, .bone = 1, .army = 0, .blueprint = "/e.bp"}
  );
  server.encoder.Record(
    EEffectOp::AttachBeamEntityToEntity,
    {.effect = Effect(3), .entity = 200, .bone = 0, .entity2 = 300, .bone2 = 0, .army = 0, .blueprint = "/b.bp"}
  );
  ASSERT_TRUE(applier.Apply(server.Lane(), false));
  EXPECT_EQ(applier.Live(), 3u);

  // Entity 100 goes, then the beam's far end: an empty lane each beat, and the following effects go with them.
  target.holds.erase(100);
  ASSERT_TRUE(applier.Apply({}, false));
  EXPECT_EQ(applier.Live(), 2u);
  EXPECT_FALSE(applier.Holds(0u));
  EXPECT_TRUE(applier.Holds(1u)); // placed at the bone once: stays
  target.holds.erase(300);
  ASSERT_TRUE(applier.Apply({}, false));
  EXPECT_FALSE(applier.Holds(2u));
  EXPECT_EQ(applier.Total().droppedWithEntity, 2u);
  EXPECT_EQ(target.Whats(), (std::vector<std::string>{"create", "create", "create", "destroy", "destroy"}));

  // An attach to an entity the client doesn't hold drops the effect.
  server.encoder.Record(EEffectOp::SetEntity, {.effect = Effect(2), .entity = 999});
  ASSERT_TRUE(applier.Apply(server.Lane(), false));
  EXPECT_FALSE(applier.Holds(1u));
  EXPECT_EQ(applier.Total().skipped[static_cast<std::size_t>(EEffectSkip::EntityNotHeld)], 1u);
  EXPECT_EQ(applier.Live(), 0u);
}

TEST(
  EffectLaneApplier,
  WhatCantBeAppliedIsSkippedAndCountedByReason
)
{
  CRecordingTarget target;
  target.holds = {100};
  target.removed = {500}; // a projectile the view just removed
  target.missing = {"/missing.bp"};
  CEffectLaneApplier applier(target);
  SServer server;
  // A blueprint the client's rules don't have, then a setter on that effect.
  server.encoder.Record(
    EEffectOp::CreateEmitterOnEntity, {.effect = Effect(1), .entity = 100, .army = 0, .blueprint = "/missing.bp"}
  );
  server.encoder.Record(EEffectOp::SetFloat, {.effect = Effect(1), .param = 1, .values = &kTwo, .valueCount = 1});
  // An entity the client doesn't hold (or the server held under no id: -1).
  server.encoder.Record(
    EEffectOp::CreateEmitterOnEntity, {.effect = Effect(2), .entity = 400, .army = 0, .blueprint = "/e.bp"}
  );
  server.encoder.Record(
    EEffectOp::CreateEmitterOnEntity, {.effect = Effect(3), .entity = -1, .army = 0, .blueprint = "/e.bp"}
  );
  // A beam with one end held.
  server.encoder.Record(
    EEffectOp::CreateBeamEntityToEntity,
    {.effect = Effect(4), .entity = 100, .bone = 0, .entity2 = 401, .bone2 = 0, .army = 0, .blueprint = "/b.bp"}
  );
  // An impact at the projectile the same view removed: placed from its last state, kept.
  server.encoder.Record(
    EEffectOp::CreateEmitterAtEntity, {.effect = Effect(5), .entity = 500, .army = 0, .blueprint = "/e.bp"}
  );
  // But one that follows it isn't made.
  server.encoder.Record(
    EEffectOp::CreateEmitterOnEntity, {.effect = Effect(6), .entity = 500, .army = 0, .blueprint = "/e.bp"}
  );
  ASSERT_TRUE(applier.Apply(server.Lane(), false));
  const auto skipped = [&applier](const EEffectSkip why) {
    return applier.Total().skipped[static_cast<std::size_t>(why)];
  };
  EXPECT_EQ(skipped(EEffectSkip::UnknownBlueprint), 1u);
  EXPECT_EQ(skipped(EEffectSkip::UnknownEffect), 1u);
  EXPECT_EQ(skipped(EEffectSkip::EntityNotHeld), 4u);
  EXPECT_EQ(skipped(EEffectSkip::UnknownName), 0u);
  EXPECT_EQ(applier.Total().created, 1u);
  EXPECT_TRUE(applier.Holds(4u));
  EXPECT_EQ(applier.Live(), 1u);

  // A lane naming a blueprint this client was never sent (it joined after the name went): skipped.
  CRecordingTarget late;
  late.holds = {100};
  CEffectLaneApplier lateApplier(late);
  server.encoder.Record(
    EEffectOp::CreateEmitterOnEntity, {.effect = Effect(7), .entity = 100, .army = 0, .blueprint = "/e.bp"}
  );
  ASSERT_TRUE(lateApplier.Apply(server.Lane(), false));
  EXPECT_EQ(lateApplier.Total().skipped[static_cast<std::size_t>(EEffectSkip::UnknownName)], 1u);
  EXPECT_TRUE(late.calls.empty());

  // A lane that doesn't decode: counted; the ops before the fault still apply.
  Bytes bad = {0u, 0u, static_cast<std::uint8_t>(EEffectOp::DestroyByScript), 4u, 0xFFu};
  EXPECT_FALSE(applier.Apply(bad, false));
  EXPECT_EQ(applier.Total().badLanes, 1u);
  EXPECT_EQ(applier.Total().destroyedByScript, 1u);
}

TEST(
  EffectLaneApplier,
  AWholeViewDropsEveryEffectAndEndsAndTheHorizonForgetThem
)
{
  CRecordingTarget target;
  target.holds = {100};
  CEffectLaneApplier applier(target);
  SServer server;
  server.encoder.Record(
    EEffectOp::CreateEmitterOnEntity, {.effect = Effect(1), .entity = 100, .army = 0, .blueprint = "/e.bp"}
  );
  server.encoder.Record(
    EEffectOp::CreateEmitter, {.effect = Effect(2), .army = 0, .blueprint = "/e.bp", .values = kXyz, .valueCount = 3}
  );
  ASSERT_TRUE(applier.Apply(server.Lane(), false));
  EXPECT_EQ(applier.Live(), 2u);

  // The client's own end (lifetime): forgotten, nothing destroyed through the target.
  applier.Ended(1u);
  EXPECT_EQ(applier.Live(), 1u);
  EXPECT_EQ(applier.Total().ended, 1u);
  // A whole view: everything goes.
  ASSERT_TRUE(applier.Apply({}, true));
  EXPECT_EQ(applier.Live(), 0u);
  EXPECT_EQ(applier.Total().droppedWhole, 1u);
  EXPECT_EQ(target.Whats(), (std::vector<std::string>{"create", "create", "destroy"}));

  // A count-only client forgets an effect after the horizon.
  CRecordingTarget counted;
  CEffectLaneApplier countedApplier(counted);
  countedApplier.SetHorizon(2u);
  SServer second;
  second.encoder.Record(
    EEffectOp::CreateEmitter, {.effect = Effect(1), .army = 0, .blueprint = "/e.bp", .values = kXyz, .valueCount = 3}
  );
  ASSERT_TRUE(countedApplier.Apply(second.Lane(), false));
  ASSERT_TRUE(countedApplier.Apply({}, false));
  ASSERT_TRUE(countedApplier.Apply({}, false));
  EXPECT_EQ(countedApplier.Live(), 1u);
  ASSERT_TRUE(countedApplier.Apply({}, false));
  EXPECT_EQ(countedApplier.Live(), 0u);
  EXPECT_EQ(countedApplier.Total().agedOut, 1u);
}

TEST(
  EffectLaneApplier,
  ABeatTheSimDidntTickIsTheUntickedLaneAndTheTargetHoldsItsEffects
)
{
  // Plan WP9.5: a paused beat has no op; its lane is two zero bytes (no new name, no op), which the target is told,
  // and which an older reader reads as a lane with no op. A ticked beat with no op stays an empty lane.
  SServer server;
  CRecordingTarget target;
  CEffectLaneApplier applier(target);
  const Bytes ticked = server.Lane(true);
  EXPECT_TRUE(ticked.empty());
  ASSERT_TRUE(applier.Apply(ticked, false));
  EXPECT_TRUE(target.calls.empty());

  const Bytes paused = server.Lane(false);
  EXPECT_EQ(paused, (Bytes{0x00, 0x00}));
  EXPECT_TRUE(faf::remote::wire::IsUntickedEffectLane(paused));
  ASSERT_TRUE(applier.Apply(paused, false));
  EXPECT_EQ(target.Whats(), (std::vector<std::string>{"unticked"}));
  EXPECT_EQ(applier.Total().unticked, 1u);
  faf::remote::wire::CEffectLaneReader older;
  std::vector<SEffectLaneOp> ops;
  EXPECT_TRUE(older.Read(paused, ops)) << "an older client reads it as a lane with no op";
  EXPECT_TRUE(ops.empty());

  // A paused beat with ops (a reconnect's re-sends, say) goes as any lane: the client ticks.
  target.calls.clear();
  target.holds = {5};
  server.encoder.Record(
    EEffectOp::CreateEmitterOnEntity, {.effect = Effect(1), .entity = 5, .army = 0, .blueprint = "/a.bp"}
  );
  const Bytes withOps = server.Lane(false);
  EXPECT_FALSE(faf::remote::wire::IsUntickedEffectLane(withOps));
  ASSERT_TRUE(applier.Apply(withOps, false));
  EXPECT_EQ(target.Whats(), (std::vector<std::string>{"create"}));
}
