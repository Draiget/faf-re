#pragma once

#include "editor/doc/EdEmitter.h"

#include <cstdint>
#include <random>
#include <string>

namespace moho
{
  class CParticleTexture;
}

namespace faf::editor
{
  /**
   * The particle editor's live preview: an emitter blueprint emitting at a point of the map without a sim. Each frame
   * it emits what the emitter makes in the ticks the editor's clock (moho::gAppIdleClock) passed (EmitTick, after
   * CEfxEmitter::Tick) and hands the particles to the game's world particle renderer, which draws them in the map's
   * view and lets them expire, as the water's wave generator does (WaveSystem.cpp).
   */
  class EdParticlePreview
  {
  public:
    EdParticlePreview() = default;
    ~EdParticlePreview();
    EdParticlePreview(const EdParticlePreview&) = delete;
    EdParticlePreview& operator=(const EdParticlePreview&) = delete;

    /** The emitter to show (its curves and settings from now on; textures loaded when their paths change). */
    void SetEmitter(const EmitterBlueprint& emitter);
    /** Where it emits (game units). */
    void SetPlace(float x, float y, float z);
    void SetPlaying(bool playing) noexcept { mPlaying = playing; }
    /** Starts over at the emitter's tick 0 at the next frame. */
    void Restart() noexcept { mRestart = true; }
    /** Starts over each time the emitter's Lifetime ends. */
    void SetLoop(bool loop) noexcept { mLoop = loop; }

    /** Emits for the clock's ticks since the last frame; call once a frame while the preview shows. */
    void Frame();

    /** The emitter's age in ticks, and the particles emitted since it started. */
    [[nodiscard]] float Age() const noexcept { return mAge; }
    [[nodiscard]] std::uint64_t Emitted() const noexcept { return mEmitted; }

  private:
    void Retexture();

    EmitterBlueprint mEmitter;
    std::string mTexturePath;
    std::string mRampPath;
    moho::CParticleTexture* mTexture = nullptr;
    moho::CParticleTexture* mRamp = nullptr;
    std::string mTypeTag;
    float mX = 0.0f;
    float mY = 0.0f;
    float mZ = 0.0f;
    bool mPlaying = true;
    bool mLoop = true;
    bool mRestart = true;
    int mLastTick = 0;
    float mAge = 0.0f;
    float mCarry = 0.0f;
    std::uint64_t mEmitted = 0;
    std::mt19937 mRandom{12345u};
  };
} // namespace faf::editor
