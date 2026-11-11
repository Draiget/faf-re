#include "editor/view/EdParticlePreview.h"

#include "moho/particles/CParticleTextureCountedPtr.h"
#include "moho/particles/CWorldParticles.h"
#include "moho/particles/SWorldParticle.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/resource/CParticleTexture.h"
#include "gpg/core/utils/Logging.h"

#include <algorithm>

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

  void EdParticlePreview::SetEmitter(const EmitterBlueprint& emitter)
  {
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
    if (mEmitter.texture != mTexturePath) {
      Release(mTexture);
      mTexturePath = mEmitter.texture;
      mTexture = Make(mTexturePath);
    }
    if (mEmitter.rampTexture != mRampPath) {
      Release(mRamp);
      mRampPath = mEmitter.rampTexture;
      mRamp = Make(mRampPath);
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
      mRestart = false;
    }
    if (!mPlaying) {
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
