#include "moho/effects/rendering/CEfxTrailEmitter.h"

#include <cstdint>

#include "moho/effects/rendering/IEffectManager.h"
#include "moho/entity/Entity.h"
#include "moho/render/ETrailParam.h"

namespace
{
  [[nodiscard]] moho::IEffectManager* ResolveEffectManager(const moho::IEffect* const effect) noexcept
  {
    const std::uintptr_t rawManager = static_cast<std::uintptr_t>(effect->mUnknown3C);
    return reinterpret_cast<moho::IEffectManager*>(rawManager);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00671420 (FUN_00671420, Moho::CEfxTrailEmitter::Invalidate1)
   *
   * What it does:
   * No-op invalidation lane used by the trail-emitter vtable.
   */
  void CEfxTrailEmitter::Invalidate(const std::int32_t, const std::int32_t)
  {}

  /**
   * Address: 0x006717E0 (FUN_006717E0, Moho::CEfxTrailEmitter::ProcessLifetime)
   *
   * What it does:
   * Destroys the trail effect when lifetime expires, or when an attached
   * parent entity is required and has been detached/destroyed.
   */
  bool CEfxTrailEmitter::ProcessLifetime()
  {
    const float lifetime = mParams.start_[TRAIL_LIFETIME];
    if (!(lifetime < 0.0f || (static_cast<float>(mTrailLength) + mTotalTicks) < lifetime)) {
      ResolveEffectManager(this)->DestroyEffect(this);
      return true;
    }

    if (mNewAttachment == 0u) {
      return false;
    }

    const Entity* const attachedEntity = mEntityInfo.GetAttachTargetEntity();
    if (attachedEntity != nullptr && attachedEntity->DestroyQueuedFlag == 0u) {
      return false;
    }

    ResolveEffectManager(this)->DestroyEffect(this);
    return true;
  }
} // namespace moho
