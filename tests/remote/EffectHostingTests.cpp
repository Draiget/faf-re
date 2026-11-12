// Plan WP9.3 (hosting): the sim's effect classes run in a manager with no sim (moho/effects/rendering/
// CHostedEffectManager.h) over a host and follow targets (EffectHost.h), and the server-mode client's follow target
// (remote/client/EffectHosting.h). No window, no GPU: emitters without textures, beams without a camera.

#include <cstdint>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include "boost/shared_ptr.h"
#include "moho/effects/rendering/CEffectImpl.h"
#include "moho/effects/rendering/CEfxBeam.h"
#include "moho/effects/rendering/CHostedEffectManager.h"
#include "moho/effects/rendering/EffectHost.h"
#include "moho/effects/rendering/SEfxCurve.h"
#include "moho/particles/SParticleBuffer.h"
#include "moho/render/EEmitterCurve.h"
#include "moho/render/EEmitterParam.h"
#include "moho/resource/blueprints/RBeamBlueprint.h"
#include "remote/client/EffectHosting.h"

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
