#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/effects/rendering/CEffectImpl.h"
#include "Wm3Vector3.h"

namespace gpg
{
  class WriteArchive;
}

namespace moho
{
  struct GeomCamera3;
  struct RTrailBlueprint;

  /**
   * VFTABLE: 0x00E25E18
   *
   * Runtime trail-emitter effect implementation.
   *
   * Layout evidence:
   * - `CEffectManagerImpl::CreateTrail` allocates `0x1B8` bytes.
   * - `ProcessLifetime` reads `mTrailLength` at +0x194 and `mTotalTicks` at
   *   +0x198.
   */
  class CEfxTrailEmitter : public CEffectImpl
  {
  public:
    /**
     * Address: 0x00671200 (FUN_00671200, Moho::CEfxTrailEmitter::CEfxTrailEmitter)
     *
     * What it does:
     * Default-constructs one trail-emitter instance: chains to
     * `CEffectImpl::CEffectImpl()`, binds the `CEfxTrailEmitter` vtable, and
     * zero-initializes trail-specific fields (blueprint pointer, length,
     * timing lanes, vector payload, flags, last-update tick).
     */
    CEfxTrailEmitter();

    /**
     * Address: 0x00671420 (FUN_00671420, Moho::CEfxTrailEmitter::Invalidate1)
     *
     * What it does:
     * No-op invalidation lane used by the trail-emitter vtable.
     */
    void Invalidate(std::int32_t paramIndex, std::int32_t valueCount) override;

    /**
     * Address: 0x006717E0 (FUN_006717E0, Moho::CEfxTrailEmitter::ProcessLifetime)
     *
     * What it does:
     * Destroys the trail effect when lifetime is exhausted or when a required
     * attachment target disappears/is destroy-queued.
     */
    [[nodiscard]] bool ProcessLifetime();

    /**
     * Address: 0x00672820 (FUN_00672820, sub_672820)
     *
     * What it does:
     * Serializes base effect state, trail blueprint pointer, trail timing
     * lanes, one Vector3 payload lane, and visibility/update flags.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x00671550 (FUN_00671550, Moho::CEfxTrailEmitter::CanSeeCam)
     *
     * What it does:
     * Applies trail LOD/frustum checks and focused-army recon visibility probe
     * for one camera.
     */
    [[nodiscard]] bool CanSeeCam(const GeomCamera3* camera);

  public:
    RTrailBlueprint* mTrailBlueprint;      // +0x190
    std::int32_t mTrailLength;             // +0x194
    float mTotalTicks;                     // +0x198
    float mLife;                           // +0x19C
    float mLength;                         // +0x1A0
    Wm3::Vector3f mSerializedTrailPosition; // +0x1A4
    bool mCreated;                         // +0x1B0
    bool mVisible;                         // +0x1B1
    std::uint8_t mPad1B2[0x02];            // +0x1B2
    std::uint32_t mLastUpdate;             // +0x1B4
  };

  static_assert(
    offsetof(CEfxTrailEmitter, mTrailBlueprint) == 0x190,
    "CEfxTrailEmitter::mTrailBlueprint offset must be 0x190"
  );
  static_assert(
    offsetof(CEfxTrailEmitter, mTrailLength) == 0x194,
    "CEfxTrailEmitter::mTrailLength offset must be 0x194"
  );
  static_assert(
    offsetof(CEfxTrailEmitter, mTotalTicks) == 0x198,
    "CEfxTrailEmitter::mTotalTicks offset must be 0x198"
  );
  static_assert(
    offsetof(CEfxTrailEmitter, mLife) == 0x19C,
    "CEfxTrailEmitter::mLife offset must be 0x19C"
  );
  static_assert(
    offsetof(CEfxTrailEmitter, mLength) == 0x1A0,
    "CEfxTrailEmitter::mLength offset must be 0x1A0"
  );
  static_assert(
    offsetof(CEfxTrailEmitter, mSerializedTrailPosition) == 0x1A4,
    "CEfxTrailEmitter::mSerializedTrailPosition offset must be 0x1A4"
  );
  static_assert(
    offsetof(CEfxTrailEmitter, mCreated) == 0x1B0,
    "CEfxTrailEmitter::mCreated offset must be 0x1B0"
  );
  static_assert(
    offsetof(CEfxTrailEmitter, mVisible) == 0x1B1,
    "CEfxTrailEmitter::mVisible offset must be 0x1B1"
  );
  static_assert(
    offsetof(CEfxTrailEmitter, mLastUpdate) == 0x1B4,
    "CEfxTrailEmitter::mLastUpdate offset must be 0x1B4"
  );
  static_assert(sizeof(CEfxTrailEmitter) == 0x1B8, "CEfxTrailEmitter size must be 0x1B8");
} // namespace moho
