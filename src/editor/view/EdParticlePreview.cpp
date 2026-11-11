#include "editor/view/EdParticlePreview.h"

#include "moho/particles/CParticleTextureCountedPtr.h"
#include "moho/particles/CWorldParticles.h"
#include "moho/particles/SWorldBeam.h"
#include "moho/particles/SWorldParticle.h"
#include "moho/particles/SWorldTrail.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/resource/CParticleTexture.h"
#include "gpg/core/utils/Logging.h"

#include <algorithm>
#include <cmath>

namespace faf::editor
{
  namespace
  {
    void Release(moho::CParticleTexture*& texture)
    {
      if (texture != nullptr) {
        (void)static_cast<moho::CountedObject*>(texture)->ReleaseReferenceAtomic();
        texture = nullptr;
      }
    }

    /** A texture for the particles, held by this preview (as WaveGenerator holds its own, WaveSystem.cpp). */
    moho::CParticleTexture* Make(const std::string& path)
    {
      if (path.empty()) {
        return nullptr;
      }
      auto* texture = new moho::CParticleTexture(path.c_str());
      static_cast<moho::CountedObject*>(texture)->AddReferenceAtomic();
      return texture;
    }
  } // namespace

  EdParticlePreview::~EdParticlePreview()
  {
    Release(mTexture);
    Release(mRamp);
  }

  void EdParticlePreview::SetFlat(const FlatBlueprint& blueprint)
  {
    mFlat = blueprint;
    mUseFlat = true;
    Retexture();
  }

  void EdParticlePreview::SetEmitter(const EmitterBlueprint& emitter)
  {
    mUseFlat = false;
    mEmitter = emitter;
    mTypeTag = EmitterTypeTag(emitter);
    Retexture();
  }

  void EdParticlePreview::SetPlace(const float x, const float y, const float z)
  {
    mX = x;
    mY = y;
    mZ = z;
  }

  void EdParticlePreview::Retexture()
  {
    const bool beam = mUseFlat && mFlat.kind == "BeamBlueprint";
    const std::string texture = !mUseFlat ? mEmitter.texture : mFlat.Text(beam ? "TextureName" : "RepeatTexture");
    const std::string ramp = !mUseFlat ? mEmitter.rampTexture : beam ? std::string() : mFlat.Text("RampTexture");
    if (texture != mTexturePath) {
      Release(mTexture);
      mTexturePath = texture;
      mTexture = Make(mTexturePath);
    }
    if (ramp != mRampPath) {
      Release(mRamp);
      mRampPath = ramp;
      mRamp = Make(mRampPath);
    }
  }

  void EdParticlePreview::FrameBeam(const int now)
  {
    // The beam list is the renderer's for one tick (CWorldParticles::AdvancementBeat clears it), so each tick adds it again.
    const float lifetime = mFlat.Number("Lifetime", 1.0f);
    const float cycle = std::max(lifetime, 1.0f) + 5.0f;
    for (int tick = std::max(mLastTick + 1, now - 20); tick <= now; ++tick) {
      moho::sWorldParticles.AdvancementBeat();
      mAge += 1.0f;
      if (std::fmod(mAge, cycle) >= std::max(lifetime, 1.0f)) {
        continue; // between two showings
      }
      ++mEmitted;
    }
    if (std::fmod(mAge, cycle) >= std::max(lifetime, 1.0f)) {
      return;
    }
    moho::SWorldBeam beam;
    beam.mCurStart.pos_ = Wm3::Vec3f(mX, mY, mZ);
    beam.mLastStart.pos_ = beam.mCurStart.pos_;
    beam.mFromStart = false;
    // Long beams (a weapon's 5000) shown 60 long, so the preview stays in view.
    const float length = std::clamp(mFlat.Number("Length", 10.0f), 1.0f, 60.0f);
    beam.mStart = Wm3::Vector3<float>(0.0f, 2.0f, 0.0f);
    beam.mEnd = Wm3::Vector3<float>(length * 0.8f, 2.0f + length * 0.6f, 0.0f);
    beam.mWidth = mFlat.Number("Thickness", 1.0f);
    const std::array<float, 4> start = mFlat.Color("StartColor", {1.0f, 1.0f, 1.0f, 0.0f});
    const std::array<float, 4> end = mFlat.Color("EndColor", {1.0f, 1.0f, 1.0f, 0.0f});
    beam.mStartColor = moho::Vector4f(start[0], start[1], start[2], start[3]);
    beam.mEndColor = moho::Vector4f(end[0], end[1], end[2], end[3]);
    (void)moho::AssignCountedParticleTexturePtr(&beam.mTexture1, mTexture);
    beam.mUShift = mFlat.Number("UShift", 0.0f);
    beam.mVShift = mFlat.Number("VShift", 0.0f);
    beam.mRepeatRate = mFlat.Number("RepeatRate", 0.0f);
    beam.mBlendMode = static_cast<moho::SWorldBeam::BlendMode>(std::clamp(static_cast<int>(mFlat.Number("Blendmode", 3.0f)), 0, 4));
    moho::sWorldParticles.AddBeam(beam);
  }

  void EdParticlePreview::FrameTrail(const int now)
  {
    // The point a trail emitter rides on: a circle 15 units out, 5 up, a turn every 40 ticks.
    const auto point = [&](const float age) {
      const float angle = age * (6.2831853f / 40.0f);
      return Wm3::Vec3f(mX + std::cos(angle) * 15.0f, mY + 5.0f, mZ + std::sin(angle) * 15.0f);
    };
    const float lifetime = mFlat.Number("Lifetime", 0.0f);
    for (int tick = std::max(mLastTick + 1, now - 20); tick <= now; ++tick) {
      if (lifetime >= 0.0f && mAge >= lifetime) {
        if (!mLoop) {
          break;
        }
        mAge = 0.0f;
        mTrailLength = 0.0f;
      }
      const Wm3::Vec3f from = point(mAge);
      const Wm3::Vec3f to = point(mAge + 1.0f);
      Wm3::Vec3f direction(to.x - from.x, to.y - from.y, to.z - from.z);
      const float length = std::sqrt(direction.x * direction.x + direction.y * direction.y + direction.z * direction.z);
      if (length > 1e-6f) {
        direction = Wm3::Vec3f(direction.x / length, direction.y / length, direction.z / length);
      }
      // CEfxTrailEmitter::Tick: the segment's two ends, their tangents, texture coordinates along the running length,
      // ages relative to the tick the renderer uploads it at.
      moho::SWorldTrail trail{};
      trail.mSortOrder = mFlat.Number("SortOrder", 0.0f);
      (void)moho::AssignCountedParticleTexturePtr(&trail.mTexture, mTexture);
      (void)moho::AssignCountedParticleTexturePtr(&trail.mRampTexture, mRamp);
      trail.mStartPos = Wm3::Vector3<float>(from.x, from.y, from.z);
      trail.mEndPos = Wm3::Vector3<float>(to.x, to.y, to.z);
      trail.mStartTangent = Wm3::Vector3<float>(direction.x, direction.y, direction.z);
      trail.mEndTangent = trail.mStartTangent;
      const float repeat = mFlat.Number("TextureRepeatRate", 0.0f);
      trail.mTexCoordStart = repeat * mTrailLength;
      mTrailLength += length;
      trail.mTexCoordEnd = repeat * mTrailLength;
      trail.mStartAge = -1.0f + static_cast<float>(tick - now);
      trail.mEndAge = trail.mStartAge + 1.0f;
      trail.mLifetime = mFlat.Number("TrailLength", 0.0f);
      trail.mEmitterAge = -mAge;
      trail.mSize = mFlat.Number("Size", 0.0f);
      trail.mTypeTag = "TPolyTrail";
      trail.mBlendMode = static_cast<std::int32_t>(mFlat.Number("BlendMode", 0.0f));
      moho::sWorldParticles.AddTrail(trail, nullptr);
      ++mEmitted;
      mAge += 1.0f;
    }
  }

  void EdParticlePreview::Frame()
  {
    // The renderer's clock: the editor's own between sessions (moho::gAppIdleClock), in ticks.
    const int now = moho::REN_GetGameTick();
    if (mRestart || now < mLastTick) {
      mLastTick = now;
      mAge = 0.0f;
      mCarry = 0.0f;
      mEmitted = 0;
      mTrailLength = 0.0f;
      mRestart = false;
    }
    if (!mPlaying) {
      mLastTick = now;
      return;
    }
    if (mUseFlat) {
      if (mFlat.kind == "BeamBlueprint") {
        FrameBeam(now);
      } else {
        FrameTrail(now);
      }
      mLastTick = now;
      return;
    }
    std::uniform_real_distribution<float> unit(0.0f, 1.0f);
    const auto random = [&] { return unit(mRandom); };
    const float frames = mEmitter.textureFrameCount > 0.0f ? mEmitter.textureFrameCount : 1.0f;
    const float strips = mEmitter.textureStripCount > 0.0f ? mEmitter.textureStripCount : 1.0f;
    // At most two seconds of ticks at once (a long stall doesn't flood the renderer).
    for (int tick = std::max(mLastTick + 1, now - 20); tick <= now; ++tick) {
      if (EmitterFinished(mEmitter, mAge)) {
        if (!mLoop) {
          break;
        }
        mAge = 0.0f;
        mCarry = 0.0f;
      }
      for (const EmittedParticle& p : EmitTick(mEmitter, mAge, mCarry, random)) {
        moho::SWorldParticle particle;
        particle.mDragEnabled = mEmitter.flags[kParticleResistance];
        particle.mResistance = p.resistance;
        particle.mPos.x = mX + p.pos[0];
        particle.mPos.y = mY + p.pos[1];
        particle.mPos.z = mZ + p.pos[2];
        particle.mDir.x = p.dir[0];
        particle.mDir.y = p.dir[1];
        particle.mDir.z = p.dir[2];
        particle.mAccel.x = p.accel[0];
        particle.mAccel.y = p.accel[1];
        particle.mAccel.z = p.accel[2];
        // Born `birth` into its tick; the renderer adds the tick it uploads at (ParticleRenderBuckets.cpp).
        particle.mInterop = p.birth + static_cast<float>(tick - now);
        particle.mLifetime = p.lifetime;
        particle.mFramerate = p.framerate;
        particle.mValue1 = 1.0f / frames;
        particle.mTextureSelection = p.textureSelection;
        particle.mValue3 = 1.0f / strips;
        particle.mRampSelection = p.rampSelection;
        particle.mBeginSize = p.beginSize;
        particle.mEndSize = p.endSize;
        particle.mAngle = p.angle;
        particle.mRotationCurve = p.rotationRate;
        particle.mReserved54 = mEmitter.sortOrder;
        (void)moho::AssignCountedParticleTexturePtr(&particle.mTexture, mTexture);
        (void)moho::AssignCountedParticleTexturePtr(&particle.mRampTexture, mRamp);
        particle.mTypeTag = mTypeTag.c_str();
        particle.mBlendMode = static_cast<moho::SWorldParticle::BlendMode>(std::clamp(static_cast<int>(mEmitter.blendMode), 0, 5));
        moho::sWorldParticles.AddWorldParticle(particle, nullptr);
        // The first particle and every 1000th: a line in the log: what the renderer was given (test runs read it).
        if (mEmitted % 1000 == 0) {
          gpg::Logf("editor: particle preview tick %d (age %.0f): at %.1f %.1f %.1f, born %+.2f, life %.1f, size %.2f-%.2f, dir %.3f %.3f %.3f, %s",
                    now, static_cast<double>(mAge), static_cast<double>(particle.mPos.x), static_cast<double>(particle.mPos.y),
                    static_cast<double>(particle.mPos.z), static_cast<double>(particle.mInterop), static_cast<double>(particle.mLifetime),
                    static_cast<double>(particle.mBeginSize), static_cast<double>(particle.mEndSize), static_cast<double>(particle.mDir.x),
                    static_cast<double>(particle.mDir.y), static_cast<double>(particle.mDir.z), mTypeTag.c_str());
        }
        ++mEmitted;
      }
      mAge += 1.0f;
    }
    mLastTick = now;
  }
} // namespace faf::editor
