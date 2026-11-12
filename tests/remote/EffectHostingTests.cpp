// Plan WP9.3 (hosting): the sim's effect classes run in a manager with no sim (moho/effects/rendering/
// CHostedEffectManager.h) over a host and follow targets (EffectHost.h), and the server-mode client's follow target
// (remote/client/EffectHosting.h). No window, no GPU: emitters without textures, beams without a camera.

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "boost/shared_ptr.h"
#include "moho/effects/rendering/CEffectImpl.h"
#include "moho/effects/rendering/CEfxBeam.h"
#include "moho/effects/rendering/CHostedEffectManager.h"
#include "moho/effects/rendering/EffectHost.h"
#include "moho/effects/rendering/EffectOps.h"
#include "moho/effects/rendering/EffectTickObserver.h"
#include "moho/effects/rendering/SEfxCurve.h"
#include "moho/particles/SParticleBuffer.h"
#include "moho/render/EBeamParam.h"
#include "moho/render/EEmitterCurve.h"
#include "moho/render/EEmitterParam.h"
#include "moho/resource/blueprints/RBeamBlueprint.h"
#include "remote/client/EffectHosting.h"
#include "remote/wire/EffectLane.h"
#include "server/EffectOpEncoder.h"
#include "server/EffectOpRecorder.h"

namespace
{
  using moho::VTransform;

  /** A host with no camera, no focus army and no map: what the effect classes read, under the test's control. */
  class CFakeHost final : public moho::IEffectHost
  {
  public:
    moho::SParticleBuffer* ParticleBuffer() override
    {
      if (!buffer) {
        buffer.reset(new moho::SParticleBuffer());
      }
      return buffer.get();
    }
    std::uint32_t CurTick() const override
    {
      return tick;
    }
    const fa::vector<moho::GeomCamera3>& Cameras() const override
    {
      return cameras;
    }
    bool HasFocusArmy() const override
    {
      return false;
    }
    bool FocusArmyDetects(
      const Wm3::Vec3f&
    ) const override
    {
      return true;
    }
    float WaterElevationAt(
      float,
      float
    ) const override
    {
      return -10000.0f;
    }
    float TerrainElevationAt(
      float,
      float
    ) const override
    {
      return 0.0f;
    }

    boost::shared_ptr<moho::SParticleBuffer> buffer;
    fa::vector<moho::GeomCamera3> cameras;
    std::uint32_t tick = 1;
  };

  /** An entity at a fixed place, whose death the test decides. */
  class CFakeTarget final : public moho::IEffectFollowTarget
  {
  public:
    explicit CFakeTarget(
      const float x,
      const float y,
      const float z
    )
    {
      current.pos_ = Wm3::Vec3f(x, y, z);
      pending = current;
    }
    bool Dying() const override
    {
      return dying;
    }
    const VTransform& Current() const override
    {
      return current;
    }
    const VTransform& Pending() const override
    {
      return pending;
    }
    float PendingVelocityScale() const override
    {
      return 1.0f;
    }
    const VTransform& History(
      int
    ) const override
    {
      return current;
    }
    VTransform BoneLocal(
      int
    ) const override
    {
      return VTransform{};
    }
    VTransform BoneWorld(
      int
    ) const override
    {
      return current;
    }
    bool UpdatesBeams() const override
    {
      return true;
    }
    void ResetHistory() const override
    {
      ++resets;
    }

    VTransform current;
    VTransform pending;
    bool dying = false;
    mutable int resets = 0;
  };

  /** An emitter without a blueprint made to emit `rate` particles a tick, for ever. */
  void MakeEmit(
    moho::IEffect& effect,
    const float rate
  )
  {
    effect.SetFloatParam(moho::EFFECT_LIFETIME, -1.0f);
    effect.SetFloatParam(moho::EFFECT_REPEATTIME, 100.0f);
    effect.SetFloatParam(moho::EFFECT_FRAMECOUNT, 1.0f);
    effect.SetFloatParam(moho::EFFECT_TEXTURE_STRIPCOUNT, 1.0f);
    moho::SEfxCurve curve;
    curve.mBoundsMin = Wm3::Vector2f(0.0f, 0.0f);
    curve.mBoundsMax = Wm3::Vector2f(100.0f, rate);
    curve.mKeys.push_back(Wm3::Vector3f(0.0f, rate, 0.0f));
    effect.SetCurveParam(moho::EMITTER_EMITRATE_CURVE, &curve);
  }
} // namespace

TEST(
  EffectHosting,
  AnEmitterOnAnEntityEmitsIntoTheHostsBufferWhereTheEntityIs
)
{
  CFakeHost host;
  moho::CHostedEffectManager manager(host);
  auto target = std::make_shared<CFakeTarget>(10.0f, 5.0f, 20.0f);

  moho::IEffect* const effect = manager.HostEmitterOnEntity(target, nullptr, 0);
  ASSERT_NE(effect, nullptr);
  EXPECT_EQ(manager.Follows(*effect, false), target.get());
  EXPECT_EQ(manager.Follows(*effect, true), nullptr);
  EXPECT_EQ(target->resets, 1) << "an attach starts the entity's history again, as Entity::InitPositionHistory";
  EXPECT_EQ(effect->GetManager(), &manager);
  MakeEmit(*effect, 3.0f);

  manager.Tick();
  ASSERT_TRUE(host.buffer);
  ASSERT_EQ(host.buffer->mParticles.size(), 3u);
  for (const moho::SWorldParticle& particle : host.buffer->mParticles) {
    EXPECT_FLOAT_EQ(particle.mPos.x, 10.0f);
    EXPECT_FLOAT_EQ(particle.mPos.y, 5.0f);
    EXPECT_FLOAT_EQ(particle.mPos.z, 20.0f);
  }
  EXPECT_EQ(manager.ActiveCount(), 1u);
}

TEST(
  EffectHosting,
  AnEmitterEndsWithItsEntityAndThePurgeReportsIt
)
{
  CFakeHost host;
  moho::CHostedEffectManager manager(host);
  std::vector<const moho::IEffect*> ended;
  manager.SetEndedHandler([&ended](const moho::IEffect& effect) {
    ended.push_back(&effect);
  });
  auto target = std::make_shared<CFakeTarget>(1.0f, 2.0f, 3.0f);
  moho::IEffect* const effect = manager.HostAttachedEmitter(target, 4, nullptr, 0);
  ASSERT_NE(effect, nullptr);
  EXPECT_EQ(static_cast<moho::CEffectImpl*>(effect)->mEntityInfo.mParentBoneIndex, 4);
  MakeEmit(*effect, 1.0f);

  manager.Tick();
  manager.PurgeDestroyedEffects();
  EXPECT_TRUE(ended.empty());

  target->dying = true; // as `DestroyQueuedFlag`: `ProcessLifetime` destroys the effect
  manager.Tick();
  EXPECT_TRUE(ended.empty()) << "nothing is deleted before the purge";
  manager.PurgeDestroyedEffects();
  ASSERT_EQ(ended.size(), 1u);
  EXPECT_EQ(ended[0], effect);
  EXPECT_EQ(manager.ActiveCount(), 0u);
  EXPECT_EQ(manager.FollowingCount(), 0u);
}

TEST(
  EffectHosting,
  AnEmitterPlacedAtAnEntityStaysWhereItWasMade
)
{
  CFakeHost host;
  moho::CHostedEffectManager manager(host);
  CFakeTarget target(7.0f, 8.0f, 9.0f);
  moho::IEffect* const effect = manager.HostEmitterAtEntity(target, nullptr, 0);
  ASSERT_NE(effect, nullptr);
  const auto& impl = static_cast<const moho::CEffectImpl&>(*effect);
  EXPECT_FLOAT_EQ(impl.mParams.start_[0], 7.0f);
  EXPECT_FLOAT_EQ(impl.mParams.start_[1], 8.0f);
  EXPECT_FLOAT_EQ(impl.mParams.start_[2], 9.0f);
  EXPECT_EQ(manager.Follows(*effect, false), nullptr);
  EXPECT_EQ(manager.FollowingCount(), 0u);
  EXPECT_EQ(impl.mNewAttachment, 0u);

  target.dying = true; // it doesn't follow, so it doesn't end with the entity
  MakeEmit(*effect, 2.0f);
  manager.Tick();
  EXPECT_EQ(manager.ActiveCount(), 1u);
  ASSERT_TRUE(host.buffer);
  EXPECT_EQ(host.buffer->mParticles.size(), 2u);
  EXPECT_FLOAT_EQ(host.buffer->mParticles[0].mPos.x, 7.0f);
}

TEST(
  EffectHosting,
  ABeamBetweenTwoEntitiesFollowsBothEnds
)
{
  CFakeHost host;
  moho::CHostedEffectManager manager(host);
  auto source = std::make_shared<CFakeTarget>(1.0f, 0.0f, 1.0f);
  auto end = std::make_shared<CFakeTarget>(9.0f, 0.0f, 9.0f);
  moho::RBeamBlueprint blueprint;
  moho::IEffect* const effect = manager.HostAttachedBeamBetween(source, 0, end, -3, &blueprint, 0);
  ASSERT_NE(effect, nullptr);
  const auto& beam = static_cast<const moho::CEfxBeam&>(*effect);
  EXPECT_EQ(manager.Follows(*effect, false), source.get());
  EXPECT_EQ(manager.Follows(*effect, true), end.get());
  EXPECT_EQ(beam.mEnd.mParentBoneIndex, 0) << "a negative end bone is clamped, as AttachEntityToEntity";

  manager.Tick(); // no camera: refreshed (`Update`), not drawn
  EXPECT_TRUE(beam.mBeam.mFromStart);
  EXPECT_FLOAT_EQ(beam.mBeam.mCurStart.pos_.x, 1.0f);
  EXPECT_FLOAT_EQ(beam.mBeam.mCurEnd.pos_.x, 9.0f);
  EXPECT_TRUE(!host.buffer || host.buffer->mBeams.empty());

  end->current.pos_ = Wm3::Vec3f(5.0f, 0.0f, 5.0f);
  manager.Tick();
  EXPECT_FLOAT_EQ(beam.mBeam.mCurEnd.pos_.x, 5.0f);

  source->dying = true;
  manager.Tick();
  manager.PurgeDestroyedEffects();
  EXPECT_EQ(manager.ActiveCount(), 0u);
}

TEST(
  EffectHosting,
  TheClientsTargetKeepsTheSimsHistoryAndTransforms
)
{
  using faf::remote::client::CClientFollowTarget;
  CClientFollowTarget target;
  CClientFollowTarget::SState state;
  state.current.pos_ = Wm3::Vec3f(1.0f, 0.0f, 0.0f);
  state.pending.pos_ = Wm3::Vec3f(2.0f, 0.0f, 0.0f);
  target.Update(state);
  EXPECT_FLOAT_EQ(target.Current().pos_.x, 1.0f);
  EXPECT_FLOAT_EQ(target.Pending().pos_.x, 2.0f);
  EXPECT_FLOAT_EQ(target.History(0).pos_.x, 1.0f);

  // It moved: as `Entity::AdvanceCoords`, the ring takes the old position and then the new one.
  state.current.pos_ = Wm3::Vec3f(2.0f, 0.0f, 0.0f);
  state.pending.pos_ = Wm3::Vec3f(3.0f, 0.0f, 0.0f);
  target.Update(state);
  EXPECT_FLOAT_EQ(target.History(0).pos_.x, 2.0f);
  EXPECT_FLOAT_EQ(target.History(1).pos_.x, 1.0f);

  // Still: the ring doesn't move.
  target.Update(state);
  EXPECT_FLOAT_EQ(target.History(0).pos_.x, 2.0f);
  EXPECT_FLOAT_EQ(target.History(1).pos_.x, 1.0f);

  // `Entity::InitPositionHistory`: every sample the default transform.
  target.ResetHistory();
  EXPECT_FLOAT_EQ(target.History(0).pos_.x, 0.0f);
  EXPECT_FLOAT_EQ(target.History(3).pos_.x, 0.0f);

  // No mesh and no blueprint: a bone is the entity itself (`Entity::GetBoneWorldTransform`).
  const VTransform bone = target.BoneWorld(2);
  EXPECT_NEAR(bone.pos_.x, 2.0f, 1e-6f);
  EXPECT_NEAR(bone.pos_.y, 0.0f, 1e-6f);
  const VTransform root = target.BoneWorld(-1);
  EXPECT_FLOAT_EQ(root.pos_.x, 2.0f);
  EXPECT_TRUE(target.UpdatesBeams()) << "with no prop blueprint a beam on it keeps updating";

  EXPECT_FALSE(target.Dying());
  target.MarkGone();
  EXPECT_TRUE(target.Dying());
  EXPECT_FLOAT_EQ(target.Current().pos_.x, 2.0f) << "a gone entity keeps its last state";
}

TEST(
  EffectHosting,
  AUnitsRootBoneIsHalfItsHeightOnThePendingTransform
)
{
  using faf::remote::client::CClientFollowTarget;
  CClientFollowTarget target;
  CClientFollowTarget::SState state;
  state.isUnit = true;
  state.current.pos_ = Wm3::Vec3f(4.0f, 1.0f, 4.0f);
  state.pending.pos_ = Wm3::Vec3f(5.0f, 1.0f, 4.0f);
  target.Update(state);
  // `Unit::GetBoneWorldTransform` without a pose: the anchor on the pending transform; no blueprint, no lift.
  const VTransform root = target.BoneWorld(-1);
  EXPECT_NEAR(root.pos_.x, 5.0f, 1e-6f);
  EXPECT_NEAR(root.pos_.y, 1.0f, 1e-6f);
  // `Unit::GetBoneLocalTransform` without a pose: identity.
  const VTransform local = target.BoneLocal(3);
  EXPECT_FLOAT_EQ(local.pos_.x, 0.0f);
  EXPECT_FLOAT_EQ(local.orient_.w, 1.0f);
}

namespace
{
  /** Plan WPR.10: what the tick observer is told, effect by effect. */
  class CRecordingObserver final : public moho::IEffectTickObserver
  {
  public:
    void OnEffectTicked(
      const moho::IEffect& effect,
      const moho::SEffectTick& tick
    ) override
    {
      ticks.push_back({&effect, tick});
    }
    void OnEffectEnding(
      const moho::IEffect& effect,
      const moho::EEffectEnd why
    ) override
    {
      endings.push_back({&effect, why});
    }
    void OnEffectDestroyed(
      const moho::IEffect& effect
    ) override
    {
      destroyed.push_back(&effect);
    }

    std::vector<std::pair<const moho::IEffect*, moho::SEffectTick>> ticks;
    std::vector<std::pair<const moho::IEffect*, moho::EEffectEnd>> endings;
    std::vector<const moho::IEffect*> destroyed;
  };

  /** Sets the observer for one test, and always takes it away again. */
  struct SObserving
  {
    explicit SObserving(
      moho::IEffectTickObserver& observer
    )
    {
      moho::gEffectTickObserver = &observer;
    }
    ~SObserving()
    {
      moho::gEffectTickObserver = nullptr;
    }
  };

  std::uint32_t sOpsSeen = 0;
  void CountOps(
    moho::EEffectOp,
    const moho::SEffectOpArgs&
  )
  {
    ++sOpsSeen;
  }
} // namespace

TEST(
  EffectHosting,
  TheTickObserverIsToldEachTicksParticlesThePlaceAndTheEnd
)
{
  CFakeHost host;
  moho::CHostedEffectManager manager(host);
  auto target = std::make_shared<CFakeTarget>(3.0f, 4.0f, 5.0f);
  moho::IEffect* const effect = manager.HostEmitterOnEntity(target, nullptr, 0);
  ASSERT_NE(effect, nullptr);
  MakeEmit(*effect, 3.0f);

  CRecordingObserver observer;
  {
    const SObserving observing(observer);
    manager.Tick();
    ASSERT_EQ(observer.ticks.size(), 1u);
    EXPECT_EQ(observer.ticks[0].first, effect);
    EXPECT_EQ(observer.ticks[0].second.particles, 3u) << "what this tick put in the host's buffer";
    EXPECT_EQ(observer.ticks[0].second.trails, 0u);
    EXPECT_FALSE(observer.ticks[0].second.hidden);
    ASSERT_TRUE(observer.ticks[0].second.positioned);
    EXPECT_FLOAT_EQ(observer.ticks[0].second.position[0], 3.0f);
    EXPECT_FLOAT_EQ(observer.ticks[0].second.position[2], 5.0f);
    ASSERT_TRUE(host.buffer);
    EXPECT_EQ(host.buffer->mParticles.size(), 3u);

    target->dying = true;
    manager.Tick();
    ASSERT_EQ(observer.endings.size(), 1u);
    EXPECT_EQ(observer.endings[0].second, moho::EEffectEnd::EntityGone);
    ASSERT_EQ(observer.destroyed.size(), 1u) << "DestroyEffect tells it, once";
    EXPECT_EQ(observer.destroyed[0], effect);
    ASSERT_EQ(observer.ticks.size(), 2u);
    EXPECT_EQ(observer.ticks[1].second.particles, 0u);
    manager.PurgeDestroyedEffects();
  }

  // Without an observer the same tick reports nothing and emits the same.
  auto again = std::make_shared<CFakeTarget>(0.0f, 0.0f, 0.0f);
  moho::IEffect* const quiet = manager.HostEmitterOnEntity(again, nullptr, 0);
  ASSERT_NE(quiet, nullptr);
  MakeEmit(*quiet, 2.0f);
  host.buffer.reset();
  manager.Tick();
  EXPECT_EQ(observer.ticks.size(), 2u);
  ASSERT_TRUE(host.buffer);
  EXPECT_EQ(host.buffer->mParticles.size(), 2u);
}

TEST(
  EffectHosting,
  AnEmitterNoCameraSeesIsReportedHidden
)
{
  CFakeHost host; // no camera
  moho::CHostedEffectManager manager(host);
  moho::IEffect* const effect = manager.HostEmitterAt(Wm3::Vector3<float>(1.0f, 2.0f, 3.0f), nullptr, 0);
  ASSERT_NE(effect, nullptr);
  MakeEmit(*effect, 1.0f);
  effect->SetFloatParam(moho::EFFECT_EMITIFVISIBLE, 1.0f);
  CRecordingObserver observer;
  const SObserving observing(observer);
  manager.Tick();
  ASSERT_EQ(observer.ticks.size(), 1u);
  EXPECT_TRUE(observer.ticks[0].second.hidden);
  EXPECT_EQ(observer.ticks[0].second.particles, 0u);
}

TEST(
  EffectHosting,
  AHostedManagersDestroysAreNotTheSimsOps
)
{
  // The sim's op hook records the sim's effect ops for the server; a client's hosted manager destroys its own effects
  // (lifetime, entity, the lane's drops), which must not reach it (a headless run hosts both in one process).
  CFakeHost host;
  moho::CHostedEffectManager manager(host);
  moho::IEffect* const effect = manager.HostEmitterAt(Wm3::Vector3<float>(0.0f, 0.0f, 0.0f), nullptr, 0);
  ASSERT_NE(effect, nullptr);
  sOpsSeen = 0;
  moho::gEffectOpHook = &CountOps;
  manager.DestroyEffect(effect);
  moho::gEffectOpHook = nullptr;
  manager.PurgeDestroyedEffects();
  EXPECT_EQ(sOpsSeen, 0u);
}

TEST(
  EffectHosting,
  ACollisionBeamsLengthPutsItsBoneOneAtTheBeamsEnd
)
{
  using faf::remote::client::CClientFollowTarget;
  auto beamEntity = std::make_shared<CClientFollowTarget>();
  CClientFollowTarget::SState state; // no mesh, no unit: what a collision beam entity is on the client
  state.current.pos_ = Wm3::Vec3f(10.0f, 2.0f, 10.0f);
  state.pending = state.current;
  beamEntity->Update(state);
  EXPECT_NEAR(beamEntity->BoneLocal(1).pos_.z, 0.0f, 1e-6f) << "no length yet: an entity's bone";

  // `CollisionBeamEntity::CheckCollision` gives the beam effect its length; the client learns it from that op.
  beamEntity->LearnBeamLength(25.0f);
  ASSERT_TRUE(beamEntity->HasBeamLength());
  const VTransform local = beamEntity->BoneLocal(1);
  EXPECT_FLOAT_EQ(local.pos_.z, 25.0f);
  EXPECT_FLOAT_EQ(local.orient_.w, 1.0f);
  EXPECT_FLOAT_EQ(beamEntity->BoneLocal(0).pos_.z, 0.0f);
  EXPECT_FLOAT_EQ(beamEntity->BoneLocal(2).pos_.z, 0.0f) << "only bone 1 is moved locally (0x006731A0)";
  // `GetBoneWorldTransform` (0x006730B0): any bone but 0 along the transform's +Z; identity orientation here.
  EXPECT_FLOAT_EQ(beamEntity->BoneWorld(1).pos_.z, 35.0f);
  EXPECT_FLOAT_EQ(beamEntity->BoneWorld(0).pos_.z, 10.0f);

  // The end splash: an emitter on bone 1 emits at the beam's end.
  CFakeHost host;
  moho::CHostedEffectManager manager(host);
  moho::IEffect* const splash = manager.HostAttachedEmitter(beamEntity, 1, nullptr, 0);
  ASSERT_NE(splash, nullptr);
  MakeEmit(*splash, 1.0f);
  manager.Tick();
  ASSERT_TRUE(host.buffer);
  ASSERT_EQ(host.buffer->mParticles.size(), 1u);
  EXPECT_NEAR(host.buffer->mParticles[0].mPos.x, 10.0f, 1e-4f);
  EXPECT_NEAR(host.buffer->mParticles[0].mPos.z, 35.0f, 1e-4f);

  // A unit, or an entity with a mesh, is no collision beam: a length on a beam that follows it changes nothing.
  CClientFollowTarget unit;
  CClientFollowTarget::SState unitState;
  unitState.isUnit = true;
  unit.Update(unitState);
  unit.LearnBeamLength(9.0f);
  EXPECT_FALSE(unit.HasBeamLength());
}

TEST(
  EffectHosting,
  ABeamFromCreateParametersTakesItsColourAndUvFromTheLane
)
{
  using faf::remote::wire::SEffectLaneOp;
  SEffectLaneOp op;
  op.op = moho::EEffectOp::CreateBeam;
  op.bone = -1;
  op.army = 2;
  op.param = 4;
  op.values = {1, 2, 3, 4, 5, 6, 7, 0.5f, 2, 0.25f, 0.5f, 0.75f, 1.5f, 0.1f, 0.2f, 3.0f};
  const std::string texture = "/textures/particles/beam_white_01.dds";
  moho::SCreateBeamParams params;
  ASSERT_TRUE(faf::remote::client::BeamParamsFromOp(op, &texture, params));
  EXPECT_FLOAT_EQ(params.mEnd.z, 6.0f);
  EXPECT_FLOAT_EQ(params.mWidth, 0.5f);
  EXPECT_FLOAT_EQ(params.mSpawnTransform.mOrientation[0], 0.25f);
  EXPECT_FLOAT_EQ(params.mSpawnTransform.mOrientation[3], 1.5f);
  EXPECT_FLOAT_EQ(params.mSpawnTransform.mPosition.z, 3.0f);
  EXPECT_EQ(params.mBlendMode, 4);
  EXPECT_STREQ(params.mTexture.c_str(), texture.c_str());

  // The beam takes them as the sim's does (0x00654A70): the colour at start and end, the UV lanes.
  CFakeHost host;
  moho::CHostedEffectManager manager(host);
  moho::IEffect* const beam = manager.HostBeamWithParams(params, nullptr, -1);
  ASSERT_NE(beam, nullptr);
  const auto& impl = static_cast<const moho::CEffectImpl&>(*beam);
  EXPECT_FLOAT_EQ(impl.mParams.start_[moho::BEAM_STARTCOLOR_R], 0.25f);
  EXPECT_FLOAT_EQ(impl.mParams.start_[moho::BEAM_ENDCOLOR_A], 1.5f);
  EXPECT_FLOAT_EQ(impl.mParams.start_[moho::BEAM_USHIFT], 0.1f);
  EXPECT_FLOAT_EQ(impl.mParams.start_[moho::BEAM_REPEATRATE], 3.0f);

  // An older server's 9 floats: the parameters' defaults (white, no shift).
  op.values.resize(9);
  moho::SCreateBeamParams older;
  ASSERT_TRUE(faf::remote::client::BeamParamsFromOp(op, nullptr, older));
  EXPECT_FLOAT_EQ(older.mSpawnTransform.mOrientation[0], 1.0f);
  EXPECT_FLOAT_EQ(older.mSpawnTransform.mOrientation[3], 0.0f);
  EXPECT_FLOAT_EQ(older.mSpawnTransform.mPosition.x, 0.0f);
  op.values.resize(8);
  EXPECT_FALSE(faf::remote::client::BeamParamsFromOp(op, nullptr, older));
}

TEST(
  EffectHosting,
  ABeamsColourAndUvGoFromTheSimsCreateThroughTheLaneToTheClientsBeam
)
{
  // `UnitWeapon::DoInstaHit` gives its beam a colour: the recorder flattens it with the rest, the lane carries it, and
  // the client builds the same create parameters.
  moho::SCreateBeamParams sim;
  sim.mStart = Wm3::Vector3<float>(1.0f, 2.0f, 3.0f);
  sim.mEnd = Wm3::Vector3<float>(4.0f, 5.0f, 6.0f);
  sim.mLifetime = 2.0f;
  sim.mWidth = 0.3f;
  sim.mTexture = "/textures/particles/beam_white_01.dds";
  sim.mSpawnTransform.mOrientation = {0.9f, 0.1f, 0.2f, 0.7f};
  sim.mSpawnTransform.mPosition = Wm3::Vector3<float>(0.5f, 0.25f, 4.0f);
  sim.mBlendMode = 2;
  moho::SEffectOpArgs args{.effect = reinterpret_cast<const moho::IEffect*>(0x1000), .beam = &sim};
  std::vector<float> floats;
  faf::server::FlattenEffectOpArgs(args, floats);
  ASSERT_EQ(args.valueCount, 16u) << "start, end, lifetime, width, texture scale, colour, U and V shift, repeat rate";

  faf::server::CEffectOpEncoder encoder;
  encoder.Record(moho::EEffectOp::CreateBeam, args);
  faf::server::CEffectLaneNames names;
  std::vector<std::uint8_t> lane;
  names.Write(encoder.EndBeat(), lane);
  faf::remote::wire::CEffectLaneReader reader;
  std::vector<faf::remote::wire::SEffectLaneOp> ops;
  ASSERT_TRUE(reader.Read(lane, ops));
  ASSERT_EQ(ops.size(), 1u);
  ASSERT_EQ(ops[0].values.size(), 16u);

  moho::SCreateBeamParams client;
  ASSERT_TRUE(faf::remote::client::BeamParamsFromOp(ops[0], reader.Name(true, ops[0].texture), client));
  EXPECT_EQ(client.mSpawnTransform.mOrientation, sim.mSpawnTransform.mOrientation);
  EXPECT_FLOAT_EQ(client.mSpawnTransform.mPosition.x, 0.5f);
  EXPECT_FLOAT_EQ(client.mSpawnTransform.mPosition.y, 0.25f);
  EXPECT_FLOAT_EQ(client.mSpawnTransform.mPosition.z, 4.0f);
  EXPECT_FLOAT_EQ(client.mWidth, 0.3f);
  EXPECT_EQ(client.mBlendMode, 2);
  EXPECT_STREQ(client.mTexture.c_str(), sim.mTexture.c_str());
}
