#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/Vector.h"
#include "moho/effects/rendering/CEffectImpl.h"
#include "moho/effects/rendering/SEfxCurve.h"
#include "moho/particles/SWorldParticle.h"
#include "moho/render/EmitterType.h"
#include "Wm3Vector3.h"

namespace moho
{
  struct GeomCamera3;
  struct REmitterBlueprint;
  /**
   * Inline-buffer fastvector wrapper for `SEfxCurve` entries used as
   * `CEfxEmitter::mCurves`. Matches the binary's 4-pointer layout:
   * `mFirst`/`mLast` track the live range, `mEnd` is the capacity-end of
   * the inline buffer, and `mOriginalStorage` records the inline buffer
   * start for dtor-side heap-vs-inline detection.
   */
  struct CEfxCurveVectorRuntime
  {
    SEfxCurve* mFirst;          // +0x00
    SEfxCurve* mLast;           // +0x04
    SEfxCurve* mEnd;            // +0x08
    SEfxCurve* mOriginalStorage; // +0x0C

    [[nodiscard]] SEfxCurve* begin() noexcept
    {
      return mFirst;
    }

    [[nodiscard]] SEfxCurve* end() noexcept
    {
      return mLast;
    }

    [[nodiscard]] const SEfxCurve* begin() const noexcept
    {
      return mFirst;
    }

    [[nodiscard]] const SEfxCurve* end() const noexcept
    {
      return mLast;
    }
  };

  static_assert(sizeof(CEfxCurveVectorRuntime) == 0x10, "CEfxCurveVectorRuntime size must be 0x10");

  /**
   * VFTABLE: 0x00E240B4
   * COL: 0x00E7E5E4
   *
   * Particle emitter effect implementation with recovered visibility lanes.
   */
  class CEfxEmitter : public CEffectImpl
  {
  public:
    /**
     * Address: 0x0065DD70 (FUN_0065DD70, Moho::CEfxEmitter::dtr)
     *
     * What it does:
     * Runs emitter teardown and forwards into `CEffectImpl` destructor paths.
     */
    ~CEfxEmitter() override;

    /**
     * Address: 0x0065C290 (FUN_0065C290, Moho::CEfxEmitter::UpdateCurveMask)
     *
     * What it does:
     * Rebuilds the packed bitmask for Z-flat curves by probing every second
     * emitter curve lane and testing one-key Z magnitude against epsilon.
     */
    void UpdateCurveMask();

    /**
     * Address: 0x0065C320 (FUN_0065C320, Moho::CEfxEmitter::SetCurveParam)
     *
     * What it does:
     * Copies one source curve bounds lane into the destination emitter slot,
     * recomputes source-curve Y bounds from key payload, and invalidates one
     * emitter parameter lane.
     */
    void SetCurveParam(std::int32_t paramIndex, const void* curveData) override;

    /**
     * Address: 0x0065C390 (FUN_0065C390, Moho::CEfxEmitter::Invalidate1)
     *
     * What it does:
     * Clears emitter validity flag for one two-argument invalidation lane.
     */
    void Invalidate(std::int32_t paramIndex, std::int32_t valueCount) override;

    /**
     * Address: 0x0065C3A0 (FUN_0065C3A0, Moho::CEfxEmitter::Invalidate2)
     *
     * What it does:
     * Clears emitter validity flag for one single-argument invalidation lane.
     */
    void Invalidate2(std::int32_t paramIndex) override;

    /**
     * Address: 0x0065C420 (FUN_0065C420, Moho::CEfxEmitter::CanSeeCam)
     *
     * What it does:
     * Applies depth/frustum visibility checks and focused-army recon probes for
     * one camera.
     */
    [[nodiscard]] bool CanSeeCam(const GeomCamera3* camera);

    /**
     * Address: 0x0065C600 (FUN_0065C600, Moho::CEfxEmitter::IsVisible)
     *
     * What it does:
     * Scans sync cameras and returns whether this emitter should be processed
     * for the current tick.
     */
    [[nodiscard]] bool IsVisible();

    /**
     * Address: 0x006593E0 (FUN_006593E0, Moho::CEfxEmitter::InterpolatePosition)
     *
     * What it does:
     * Resolves entity transform history for one effect attachment lane, blends
     * orientation/position at `tick` + `interp`, and writes the resulting
     * world matrix (optionally composed with one parent-bone local transform).
     */
    [[nodiscard]] static bool InterpolatePosition(const CEffectImpl* effect, VMatrix4* outMatrix, int tick, float interp);

    /**
     * Address: 0x0065C1A0 (FUN_0065C1A0, Moho::CEfxEmitter::Interpolate)
     *
     * What it does:
     * Interpolates emitter attachment transform at `(tick=0, interp=0.0)` and
     * projects the first start-vector lane through that matrix into `mPos`.
     */
    void Interpolate();

    /**
     * Address: 0x0065C700 (FUN_0065C700, Moho::CEfxEmitter::ProcessLifetime)
     *
     * What it does:
     * Applies lifetime/attachment visibility gates and destroys the effect
     * when one terminal condition is met.
     */
    [[nodiscard]] bool ProcessLifetime();

    /**
     * Address: 0x00660280 (FUN_00660280, Moho::CEfxEmitter::MemberSerialize)
     *
     * What it does:
     * Serializes base effect lanes, emitter metadata, blueprint pointer,
     * particle payload, and visibility/lifetime state.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x006600D0 (FUN_006600D0, Moho::CEfxEmitter::MemberDeserialize)
     *
     * What it does:
     * Inverse of `MemberSerialize`: reads base effect lanes, emitter
     * metadata, curves vector, blueprint pointer, particle payload, and
     * visibility/lifetime state from one read archive in the same
     * field-by-field order that `MemberSerialize` wrote.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

  public:
    /**
     * Address: 0x0065B9B0 (FUN_0065B9B0, Moho::CEfxEmitter::CEfxEmitter)
     *
     * What it does:
     * Default-constructs one emitter: invokes the `CEffectImpl` base ctor,
     * publishes the `CEfxEmitter` vftable, zeroes the emitter type, binds
     * the embedded `mCurves` fastvector to the inline `mInlineCurveStorage`
     * buffer (21-entry capacity), default-constructs the particle slot, and
     * zero-initializes the remaining emitter-state fields.
     */
    CEfxEmitter();

    /**
     * Address: 0x0065BA80 (FUN_0065BA80, Moho::CEfxEmitter::CEfxEmitter)
     *
     * What it does:
     * Blueprint-driven emitter ctor. Chains the manager-bound `CEffectImpl` base
     * ctor, binds the inline `mCurves` buffer and fills its 21 default curves,
     * sizes the param/texture/string lanes, seeds the emit position and three
     * fixed defaults (tick-increment=1, tick-count=0, scale=1), and -- when a
     * blueprint is supplied -- rebuilds all 21 emitter curves from the blueprint
     * and publishes the 20 blueprint scalar parameters plus the two texture
     * names, then interpolates the initial attachment transform. (In the binary
     * the manager arrives in ecx and the object/position/token/blueprint are
     * stack args; IDA mislabels the symbol as the default ctor.)
     */
    CEfxEmitter(
      CEffectManagerImpl* manager,
      const Wm3::Vector3<float>& position,
      int scriptObjectToken,
      const REmitterBlueprint* blueprint
    );

  private:
    friend struct CEfxEmitterLayoutVerifier;

    /// Number of SEfxCurve slots in the inline curve buffer (matches binary).
    static constexpr std::size_t kInlineCurveCapacity = 21u;

    EmitterType mEmitterType;                                       // +0x190
    std::uint8_t mPad194[0x04];                                     // +0x194
    CEfxCurveVectorRuntime mCurves;                                 // +0x198 (16 bytes)
    std::uint8_t mInlineCurveStorage[kInlineCurveCapacity * 0x38];  // +0x1A8 (1176 bytes)
    REmitterBlueprint* mBlueprint;                                  // +0x640
    float mTotalEmissions;                  // +0x644
    std::uint32_t mLife;                    // +0x648
    SWorldParticle mParticle;               // +0x64C
    bool mValid;                            // +0x6D8
    std::uint8_t mPad6D9[0x03];             // +0x6D9
    std::uint32_t mZCurveMask;              // +0x6DC
    std::int32_t mMaxLifetime;              // +0x6E0
    bool mVisible;                          // +0x6E4
    std::uint8_t mPad6E5[0x03];             // +0x6E5
    std::uint32_t mLastUpdate;              // +0x6E8
    Wm3::Vec3f mPos;                        // +0x6EC
  };

  struct CEfxEmitterLayoutVerifier
  {
    static_assert(offsetof(CEfxEmitter, mEmitterType) == 0x190, "CEfxEmitter::mEmitterType offset must be 0x190");
    static_assert(offsetof(CEfxEmitter, mCurves) == 0x198, "CEfxEmitter::mCurves offset must be 0x198");
    static_assert(offsetof(CEfxEmitter, mInlineCurveStorage) == 0x1A8, "CEfxEmitter::mInlineCurveStorage offset must be 0x1A8");
    static_assert(offsetof(CEfxEmitter, mBlueprint) == 0x640, "CEfxEmitter::mBlueprint offset must be 0x640");
    static_assert(offsetof(CEfxEmitter, mTotalEmissions) == 0x644, "CEfxEmitter::mTotalEmissions offset must be 0x644");
    static_assert(offsetof(CEfxEmitter, mLife) == 0x648, "CEfxEmitter::mLife offset must be 0x648");
    static_assert(offsetof(CEfxEmitter, mParticle) == 0x64C, "CEfxEmitter::mParticle offset must be 0x64C");
    static_assert(offsetof(CEfxEmitter, mValid) == 0x6D8, "CEfxEmitter::mValid offset must be 0x6D8");
    static_assert(offsetof(CEfxEmitter, mZCurveMask) == 0x6DC, "CEfxEmitter::mZCurveMask offset must be 0x6DC");
    static_assert(offsetof(CEfxEmitter, mMaxLifetime) == 0x6E0, "CEfxEmitter::mMaxLifetime offset must be 0x6E0");
    static_assert(offsetof(CEfxEmitter, mVisible) == 0x6E4, "CEfxEmitter::mVisible offset must be 0x6E4");
    static_assert(offsetof(CEfxEmitter, mLastUpdate) == 0x6E8, "CEfxEmitter::mLastUpdate offset must be 0x6E8");
    static_assert(offsetof(CEfxEmitter, mPos) == 0x6EC, "CEfxEmitter::mPos offset must be 0x6EC");
    static_assert(sizeof(CEfxEmitter) == 0x6F8, "CEfxEmitter size must be 0x6F8");
  };
} // namespace moho
