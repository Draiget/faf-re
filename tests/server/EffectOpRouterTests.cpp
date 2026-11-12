// Engine addition (dedicated-server plan WP9.2): server/EffectOpRouter.h picks each view's effect ops: an effect goes
// to a view only while its client holds the entity it is on (or sees the point it is at), a create waits until then or
// is dropped when the effect ends first, an unattached beam goes with its first attachment, setters follow the effect,
// a light goes by the view's sight or its army's intel, and a view back from a lost connection gets every live effect
// it can place again. These check each rule on lanes as a client reads them (remote/wire/EffectLane.h), and that over
// a long random game no view gets an op for an effect its client doesn't hold.

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <iterator>
#include <map>
#include <set>
#include <unordered_map>
#include <utility>
#include <vector>

#include "remote/wire/EffectLane.h"
#include "server/EffectOpEncoder.h"
#include "server/EffectOpRouter.h"

using faf::remote::wire::CEffectLaneReader;
using faf::remote::wire::SEffectLaneOp;
using faf::server::CEffectOpEncoder;
using faf::server::CEffectRoutes;
using faf::server::CEffectViewRoute;
using faf::server::SEffectBeat;
using moho::EEffectOp;
using Bytes = std::vector<std::uint8_t>;

namespace
{
  const moho::IEffect* Effect(
    const std::uintptr_t n
  )
  {
    return reinterpret_cast<const moho::IEffect*>(0x10000u + n * 0x100u);
  }

  struct SOp
  {
    EEffectOp op;
    std::uint32_t id;
    std::int32_t entity;
    std::uint32_t floats; // count of values
  };

  /** Two views (0 and 1) on one encoder and one set of routes, each with its entities and its reader. */
  struct SGame
  {
    CEffectOpEncoder encoder;
    CEffectRoutes routes;
    CEffectViewRoute route[2];
    CEffectLaneReader reader[2];
    std::set<std::int32_t> holds[2];
    std::set<std::int32_t> left[2]; // entities the view held until this beat (cleared after each beat)
    std::uint32_t sight[2]{};       // views seeing a point, by `position[0]`: bit 0 for x 0, bit 1 for x 1
    std::uint32_t watching = 0u;
    std::map<std::int32_t, std::uint32_t> blips; // another army's unit: the views that draw its blip
    bool fresh[2]{};
    Bytes lanes[2];

    /** Ends the beat; returns each view's ops as its client reads them. */
    std::array<std::vector<SOp>, 2> Beat()
    {
      SEffectBeat beat = encoder.EndBeat();
      routes.TakeBeat(beat, 0b11u, watching, [this](const std::array<float, 3>& at) {
        return sight[at[0] > 0.5f ? 1 : 0];
      }, [this](const std::int32_t entity) {
        const auto found = blips.find(entity);
        return found != blips.end() ? found->second : 0u;
      });
      std::array<std::vector<SOp>, 2> out;
      for (std::size_t view = 0; view < 2u; ++view) {
        route[view].Write(
          beat,
          routes,
          view,
          std::exchange(fresh[view], false),
          [this, view](const std::int32_t entity, const bool orLeft) {
          return holds[view].contains(entity) || (orLeft && left[view].contains(entity));
        },
          lanes[view]
        );
        left[view].clear();
        std::vector<SEffectLaneOp> ops;
        EXPECT_TRUE(reader[view].Read(lanes[view], ops)) << "view " << view;
        for (const SEffectLaneOp& op : ops) {
          out[view].push_back(SOp{op.op, op.id, op.entity, static_cast<std::uint32_t>(op.values.size())});
        }
      }
      return out;
    }
  };

  std::vector<EEffectOp> Kinds(
    const std::vector<SOp>& ops
  )
  {
    std::vector<EEffectOp> kinds;
    for (const SOp& op : ops) {
      kinds.push_back(op.op);
    }
    return kinds;
  }

  const float kOne = 1.0f;
  const float kTwo = 2.0f;
  const float kXyz[3] = {1.0f, 2.0f, 3.0f};
} // namespace

TEST(
  EffectRoutes,
  AnEffectGoesOnlyToViewsThatHoldItsEntityAndItsSettersFollowIt
)
{
  SGame game;
  game.holds[0] = {100};
  game.encoder.Record(
    EEffectOp::CreateEmitterOnEntity, {.effect = Effect(1), .entity = 100, .army = 0, .blueprint = "/a.bp"}
  );
  game.encoder.Record(EEffectOp::SetFloat, {.effect = Effect(1), .param = 18, .values = &kTwo, .valueCount = 1});
  auto beat = game.Beat();
  EXPECT_EQ(Kinds(beat[0]), (std::vector{EEffectOp::CreateEmitterOnEntity, EEffectOp::SetFloat}));
  EXPECT_TRUE(beat[1].empty());
  EXPECT_TRUE(game.lanes[1].empty()); // no op: an empty lane, no name either
  EXPECT_EQ(game.route[1].Held(), 1u);

  // The next beat's setter and the script's destroy: to view 0 only, which holds the effect.
  game.encoder.Record(EEffectOp::SetN, {.effect = Effect(1), .param = 0, .values = kXyz, .valueCount = 3});
  game.encoder.Record(EEffectOp::DestroyByScript, {.effect = Effect(1)});
  game.encoder.Record(EEffectOp::Destroy, {.effect = Effect(1)});
  beat = game.Beat();
  EXPECT_EQ(Kinds(beat[0]), (std::vector{EEffectOp::SetN, EEffectOp::DestroyByScript}));
  EXPECT_TRUE(beat[1].empty());

  // View 1 sees entity 100 now, but the effect is gone: nothing, and it counts as dropped for view 1.
  game.holds[1] = {100};
  beat = game.Beat();
  EXPECT_TRUE(beat[0].empty());
  EXPECT_TRUE(beat[1].empty());
  (void)game.Beat();
  EXPECT_EQ(game.routes.Dropped(), 1u);
  EXPECT_EQ(game.routes.Live(), 0u);
  EXPECT_EQ(game.routes.Kept(), 0u);
  EXPECT_EQ(game.routes.KeptBytes(), 0u);
}

TEST(
  EffectRoutes,
  AHeldCreateGoesWholeWhenItsEntityEntersTheView
)
{
  SGame game;
  game.holds[0] = {100};
  game.encoder.Record(
    EEffectOp::CreateAttachedEmitter, {.effect = Effect(1), .entity = 100, .bone = 2, .army = 0, .blueprint = "/a.bp"}
  );
  (void)game.Beat();
  // Two beats of setters view 1 doesn't get: the same parameter twice (only the last is kept), and an offset.
  game.encoder.Record(EEffectOp::SetFloat, {.effect = Effect(1), .param = 18, .values = &kOne, .valueCount = 1});
  game.encoder.Record(EEffectOp::SetN, {.effect = Effect(1), .param = 0, .values = kXyz, .valueCount = 3});
  auto beat = game.Beat();
  EXPECT_EQ(beat[0].size(), 2u);
  EXPECT_TRUE(beat[1].empty());
  game.encoder.Record(EEffectOp::SetFloat, {.effect = Effect(1), .param = 18, .values = &kTwo, .valueCount = 1});
  beat = game.Beat();
  EXPECT_EQ(beat[0].size(), 1u);
  EXPECT_TRUE(beat[1].empty());

  // Entity 100 enters view 1: the create as made, then the last op per setter, in the order of their last writes.
  game.holds[1] = {100};
  beat = game.Beat();
  EXPECT_TRUE(beat[0].empty());
  ASSERT_EQ(Kinds(beat[1]), (std::vector{EEffectOp::CreateAttachedEmitter, EEffectOp::SetN, EEffectOp::SetFloat}));
  EXPECT_EQ(beat[1][0].entity, 100);
  EXPECT_EQ(beat[1][1].floats, 3u);
  EXPECT_EQ(game.route[1].Released(), 1u);
  EXPECT_EQ(game.reader[1].UnknownNames(), 0u); // the blueprint's name came with it
  ASSERT_NE(game.reader[1].Name(false, 1u), nullptr);
  EXPECT_EQ(*game.reader[1].Name(false, 1u), "/a.bp");

  // From then on it gets the setters.
  game.encoder.Record(EEffectOp::SetFloat, {.effect = Effect(1), .param = 18, .values = &kOne, .valueCount = 1});
  beat = game.Beat();
  EXPECT_EQ(Kinds(beat[1]), (std::vector{EEffectOp::SetFloat}));
}

TEST(
  EffectRoutes,
  AnEffectWhoseEntityLeavesIsDroppedThereAndGoesWholeWhenItComesBack
)
{
  SGame game;
  game.holds[0] = {100};
  game.encoder.Record(
    EEffectOp::CreateEmitterOnEntity, {.effect = Effect(1), .entity = 100, .army = 0, .blueprint = "/a.bp"}
  );
  (void)game.Beat();
  game.holds[0].clear();
  game.encoder.Record(EEffectOp::SetFloat, {.effect = Effect(1), .param = 18, .values = &kTwo, .valueCount = 1});
  auto beat = game.Beat();
  EXPECT_TRUE(beat[0].empty()); // its client dropped the effect with the entity: no setter
  EXPECT_EQ(game.route[0].Withdrawn(), 1u);
  game.holds[0] = {100};
  beat = game.Beat();
  EXPECT_EQ(Kinds(beat[0]), (std::vector{EEffectOp::CreateEmitterOnEntity, EEffectOp::SetFloat}));
}

TEST(
  EffectRoutes,
  AnUnattachedBeamGoesWithItsFirstAttachment
)
{
  SGame game;
  game.holds[0] = {100};
  game.encoder.Record(EEffectOp::CreateBeam, {.effect = Effect(1), .army = 0, .blueprint = "/beam.bp"});
  game.encoder.Record(EEffectOp::SetFloat, {.effect = Effect(1), .param = 4, .values = &kOne, .valueCount = 1});
  auto beat = game.Beat();
  EXPECT_TRUE(beat[0].empty()); // nowhere to draw it yet
  EXPECT_TRUE(beat[1].empty());

  game.encoder.Record(EEffectOp::SetBone, {.effect = Effect(1), .entity = 100, .bone = 3});
  beat = game.Beat();
  EXPECT_EQ(Kinds(beat[0]), (std::vector{EEffectOp::CreateBeam, EEffectOp::SetFloat, EEffectOp::SetBone}));
  EXPECT_EQ(beat[0][2].entity, 100);
  EXPECT_TRUE(beat[1].empty()); // view 1 doesn't hold entity 100

  // A beam between two entities needs both ends.
  game.holds[1] = {100};
  game.encoder.Record(
    EEffectOp::AttachBeamEntityToEntity,
    {.effect = Effect(2), .entity = 100, .bone = 0, .entity2 = 200, .bone2 = 0, .army = 0, .blueprint = "/beam.bp"}
  );
  beat = game.Beat();
  EXPECT_TRUE(beat[0].empty());
  EXPECT_EQ(Kinds(beat[1]), (std::vector{EEffectOp::CreateBeam, EEffectOp::SetFloat, EEffectOp::SetBone}));
  game.holds[0].insert(200);
  beat = game.Beat();
  EXPECT_EQ(Kinds(beat[0]), (std::vector{EEffectOp::AttachBeamEntityToEntity}));
  EXPECT_TRUE(beat[1].empty());
}

TEST(
  EffectRoutes,
  AnEmitterAtAPointGoesToTheViewsThatSeeItAndStays
)
{
  SGame game;
  game.sight[1] = 0b01u; // the point at x 1: view 0 sees it
  const float at[3] = {1.0f, 0.0f, 5.0f};
  game.encoder.Record(
    EEffectOp::CreateEmitter, {.effect = Effect(1), .army = 0, .blueprint = "/e.bp", .values = at, .valueCount = 3}
  );
  auto beat = game.Beat();
  EXPECT_EQ(Kinds(beat[0]), (std::vector{EEffectOp::CreateEmitter}));
  EXPECT_TRUE(beat[1].empty());

  game.sight[1] = 0b00u; // out of sight now: view 0 keeps it, and its setters
  game.encoder.Record(EEffectOp::SetFloat, {.effect = Effect(1), .param = 18, .values = &kOne, .valueCount = 1});
  beat = game.Beat();
  EXPECT_EQ(Kinds(beat[0]), (std::vector{EEffectOp::SetFloat}));
  EXPECT_TRUE(beat[1].empty());

  game.sight[1] = 0b10u; // view 1 sees the point now: the emitter goes whole
  beat = game.Beat();
  EXPECT_TRUE(beat[0].empty());
  EXPECT_EQ(Kinds(beat[1]), (std::vector{EEffectOp::CreateEmitter, EEffectOp::SetFloat}));
}

TEST(
  EffectRoutes,
  AnotherArmysUnitGoesToTheViewsThatDrawItsBlip
)
{
  // Unit 500 is view 0's own (a record of its frame); view 1 sees it only as a blip, drawn from the second beat on.
  SGame game;
  game.holds[0] = {500};
  game.encoder.Record(
    EEffectOp::CreateEmitterOnEntity, {.effect = Effect(1), .entity = 500, .army = 0, .blueprint = "/a.bp"}
  );
  auto beat = game.Beat();
  EXPECT_EQ(beat[0].size(), 1u);
  EXPECT_TRUE(beat[1].empty());

  game.blips[500] = 0b10u;
  game.encoder.Record(EEffectOp::SetFloat, {.effect = Effect(1), .param = 18, .values = &kOne, .valueCount = 1});
  beat = game.Beat();
  EXPECT_EQ(Kinds(beat[0]), (std::vector{EEffectOp::SetFloat}));
  EXPECT_EQ(Kinds(beat[1]), (std::vector{EEffectOp::CreateEmitterOnEntity, EEffectOp::SetFloat}));

  // Out of view 1's sight: its client stops drawing the blip, so it drops the effect.
  game.blips.erase(500);
  game.encoder.Record(EEffectOp::SetFloat, {.effect = Effect(1), .param = 18, .values = &kTwo, .valueCount = 1});
  beat = game.Beat();
  EXPECT_EQ(beat[0].size(), 1u);
  EXPECT_TRUE(beat[1].empty());
  EXPECT_EQ(game.route[1].Withdrawn(), 1u);
}

TEST(
  EffectRoutes,
  AnEmitterPlacedAtAnEntityGoesWhenTheEntityLeftThatBeatAndStaysWithTheView
)
{
  // A projectile's impact: made at the projectile as it goes. View 0 held it until this beat, view 1 never did.
  SGame game;
  game.left[0] = {300};
  game.encoder.Record(
    EEffectOp::CreateEmitterAtBone, {.effect = Effect(1), .entity = 300, .bone = -2, .army = 0, .blueprint = "/hit"}
  );
  auto beat = game.Beat();
  EXPECT_EQ(Kinds(beat[0]), (std::vector{EEffectOp::CreateEmitterAtBone}));
  EXPECT_TRUE(beat[1].empty());

  // It doesn't follow the entity, so it isn't dropped with it: its setters still go to view 0.
  game.encoder.Record(EEffectOp::SetFloat, {.effect = Effect(1), .param = 18, .values = &kOne, .valueCount = 1});
  beat = game.Beat();
  EXPECT_EQ(Kinds(beat[0]), (std::vector{EEffectOp::SetFloat}));
  EXPECT_EQ(game.route[0].Withdrawn(), 0u);

  // An effect that follows its entity (on-entity) doesn't go to a view whose entity left that beat.
  game.left[1] = {301};
  game.encoder.Record(
    EEffectOp::CreateEmitterOnEntity, {.effect = Effect(2), .entity = 301, .army = 0, .blueprint = "/a.bp"}
  );
  beat = game.Beat();
  EXPECT_TRUE(beat[1].empty());
}

TEST(
  EffectRoutes,
  ALightGoesByTheViewsSightOrItsArmysIntelAndToAViewThatWatchesEverything
)
{
  SGame game;
  game.sight[0] = 0b10u; // the point at x 0: view 1 sees it
  const float plain[5] = {0.0f, 0.0f, 0.0f, 1.0f, 1.0f};
  game.encoder.Record(
    EEffectOp::CreateLightParticle, {.army = 0, .texture = "t", .texture2 = "r", .values = plain, .valueCount = 5}
  );
  auto beat = game.Beat();
  EXPECT_TRUE(beat[0].empty());
  EXPECT_EQ(Kinds(beat[1]), (std::vector{EEffectOp::CreateLightParticle}));

  // From `CreateLightParticleIntel`: army 0's intel saw it, army 1's didn't; sight doesn't matter.
  game.encoder.Record(
    EEffectOp::CreateLightParticle,
    {.army = 0, .texture = "t", .texture2 = "r", .values = plain, .valueCount = 5, .armies = 0b01u}
  );
  beat = game.Beat();
  EXPECT_EQ(Kinds(beat[0]), (std::vector{EEffectOp::CreateLightParticle}));
  EXPECT_TRUE(beat[1].empty());

  // A view watching everything gets both kinds.
  game.watching = 0b10u;
  game.sight[0] = 0b00u;
  game.encoder.Record(
    EEffectOp::CreateLightParticle, {.army = 0, .texture = "t", .texture2 = "r", .values = plain, .valueCount = 5}
  );
  game.encoder.Record(
    EEffectOp::CreateLightParticle,
    {.army = 0, .texture = "t", .texture2 = "r", .values = plain, .valueCount = 5, .armies = 0b01u}
  );
  beat = game.Beat();
  EXPECT_EQ(Kinds(beat[0]), (std::vector{EEffectOp::CreateLightParticle}));
  EXPECT_EQ(beat[1].size(), 2u);
  EXPECT_EQ(game.route[1].Lights(), 3u);
}

TEST(
  EffectRoutes,
  AViewBackFromALostConnectionGetsItsLiveEffectsAndNamesAgain
)
{
  SGame game;
  game.holds[0] = {100, 101};
  game.encoder.Record(
    EEffectOp::CreateEmitterOnEntity, {.effect = Effect(1), .entity = 100, .army = 0, .blueprint = "/a.bp"}
  );
  game.encoder.Record(
    EEffectOp::CreateEmitterOnEntity, {.effect = Effect(2), .entity = 101, .army = 0, .blueprint = "/b.bp"}
  );
  game.encoder.Record(EEffectOp::SetFloat, {.effect = Effect(2), .param = 18, .values = &kTwo, .valueCount = 1});
  (void)game.Beat();
  game.encoder.Record(EEffectOp::Destroy, {.effect = Effect(1)}); // a lifetime's end: the client derives it
  (void)game.Beat();
  EXPECT_EQ(game.route[0].Names().NamesSent(), 2u);

  // Back holding nothing (a new reader too): effect 2 whole, with its name; effect 1 is gone.
  game.fresh[0] = true;
  game.reader[0] = CEffectLaneReader{};
  game.encoder.Record(EEffectOp::SetFloat, {.effect = Effect(2), .param = 6, .values = &kOne, .valueCount = 1});
  const auto beat = game.Beat();
  ASSERT_EQ(Kinds(beat[0]), (std::vector{EEffectOp::CreateEmitterOnEntity, EEffectOp::SetFloat, EEffectOp::SetFloat}));
  EXPECT_EQ(beat[0][0].id, 1u);
  EXPECT_EQ(game.reader[0].UnknownNames(), 0u);
  EXPECT_EQ(game.route[0].Names().NamesSent(), 3u); // "/b.bp" again, "/a.bp" not
}

TEST(
  EffectRoutes,
  NoViewEverGetsAnOpOnAnEffectItsClientDoesntHold
)
{
  // A long random game: 12 entities going in and out of two views, effects of every kind on them, setters, script
  // destroys, lifetimes ending, and a reconnect now and then. Each view's client keeps the effects it was sent and
  // drops those whose entity it no longer holds at a beat's end (as it drops the entity); every op it reads must be on
  // one it holds, or create one.
  SGame game;
  std::uint32_t seed = 12345u;
  const auto next = [&seed](const std::uint32_t bound) {
    seed = seed * 1664525u + 1013904223u;
    return (seed >> 8) % bound;
  };
  std::vector<std::uintptr_t> live; // fake effect numbers
  std::uintptr_t made = 0;
  std::unordered_map<std::uint32_t, std::int32_t> held[2]; // each client's effects: id -> entity (-1: none)
  std::uint64_t unknown[2]{};
  std::uint64_t got[2]{};
  for (int beatIndex = 0; beatIndex < 3000; ++beatIndex) {
    for (std::size_t view = 0; view < 2u; ++view) {
      if (next(10) == 0u) {
        const auto entity = static_cast<std::int32_t>(next(12));
        if (game.holds[view].contains(entity)) {
          game.holds[view].erase(entity);
          game.left[view].insert(entity);
        } else {
          game.holds[view].insert(entity);
        }
      }
      if (next(500) == 0u) {
        game.fresh[view] = true;
        game.reader[view] = CEffectLaneReader{};
        held[view].clear();
      }
    }
    for (std::uint32_t n = next(6); n > 0u; --n) {
      const std::uint32_t what = next(10);
      if (what < 3u || live.empty()) {
        const std::uintptr_t effect = ++made;
        const auto entity = static_cast<std::int32_t>(next(12));
        if (what == 0u && next(2) == 0u) {
          game.encoder.Record(EEffectOp::CreateBeam, {.effect = Effect(effect), .army = 0, .blueprint = "/beam.bp"});
        } else if (what == 0u) {
          game.encoder.Record(
            EEffectOp::CreateEmitterAtEntity, {.effect = Effect(effect), .entity = entity, .army = 0, .blueprint = "/b"}
          );
        } else if (what == 1u) {
          game.encoder.Record(
            EEffectOp::AttachBeamEntityToEntity,
            {.effect = Effect(effect),
             .entity = entity,
             .bone = 0,
             .entity2 = static_cast<std::int32_t>(next(12)),
             .bone2 = 0,
             .army = 0,
             .blueprint = "/beam.bp"}
          );
        } else {
          game.encoder.Record(
            EEffectOp::CreateEmitterOnEntity, {.effect = Effect(effect), .entity = entity, .army = 0, .blueprint = "/a"}
          );
        }
        live.push_back(effect);
        continue;
      }
      const std::size_t pick = next(static_cast<std::uint32_t>(live.size()));
      const std::uintptr_t effect = live[pick];
      if (what == 3u) {
        game.encoder.Record(
          EEffectOp::SetBone, {.effect = Effect(effect), .entity = static_cast<std::int32_t>(next(12))}
        );
      } else if (what < 7u) {
        game.encoder.Record(
          EEffectOp::SetFloat,
          {.effect = Effect(effect), .param = static_cast<std::int32_t>(next(3)), .values = &kOne, .valueCount = 1}
        );
      } else {
        if (what == 7u) {
          game.encoder.Record(EEffectOp::DestroyByScript, {.effect = Effect(effect)});
        }
        game.encoder.Record(EEffectOp::Destroy, {.effect = Effect(effect)});
        live[pick] = live.back();
        live.pop_back();
      }
    }
    const auto beat = game.Beat();
    for (std::size_t view = 0; view < 2u; ++view) {
      for (const SOp& op : beat[view]) {
        ++got[view];
        if (op.op == EEffectOp::CreateLightParticle) {
          continue;
        }
        if (op.op < EEffectOp::CreateLightParticle) {
          // An emitter placed at an entity doesn't follow it: the client keeps it when the entity goes.
          held[view][op.id] = op.op == EEffectOp::CreateEmitterAtEntity ? -1 : op.entity;
          continue;
        }
        const auto found = held[view].find(op.id);
        if (found == held[view].end()) {
          ++unknown[view];
          continue;
        }
        if (op.op == EEffectOp::SetEntity || op.op == EEffectOp::SetBone) {
          found->second = op.entity;
        } else if (op.op == EEffectOp::DestroyByScript) {
          held[view].erase(found);
        }
      }
      // The client drops an effect whose entity it doesn't hold. An unattached beam (-1) it keeps, though it never
      // gets one: those wait for their attachment.
      for (auto it = held[view].begin(); it != held[view].end();) {
        const bool lost = it->second >= 0 && !game.holds[view].contains(it->second);
        it = lost ? held[view].erase(it) : std::next(it);
      }
    }
  }
  EXPECT_EQ(unknown[0], 0u);
  EXPECT_EQ(unknown[1], 0u);
  EXPECT_GT(got[0], 1000u);
  EXPECT_GT(got[1], 1000u);
  EXPECT_GT(game.route[0].Released(), 10u);
  EXPECT_GT(game.route[0].Withdrawn(), 10u);
  EXPECT_GT(game.routes.Dropped(), 10u);
  EXPECT_EQ(game.reader[0].UnknownNames(), 0u);
  EXPECT_EQ(game.reader[1].UnknownNames(), 0u);
}
