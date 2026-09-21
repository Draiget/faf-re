#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "moho/misc/ManyToOneBroadcaster.h"

namespace moho
{
  /**
   * Recovered enum lane used by projectile impact broadcaster/listener chains.
   *
   * Enumerator values reconstructed 1:1 from `Projectile::Impact`
   * (FUN_0069DEC0, asm 0x0069E077-0x0069E10E): the projectile selects one of
   * three impact-event codes and notifies its single chained listener via the
   * `ManyToOneBroadcaster<EProjectileImpactEvent>` at `this+0x270`.
   *   - `didHit`                                         -> 0 (hit target)
   *   - projectile/underwater-projectile or a colliding
   *     entity whose id class == 0x40000000 (self/proj)  -> 2
   *   - otherwise                                        -> 1 (other/miss)
   */
  enum EProjectileImpactEvent : int
  {
    ProjectileImpactEvent_HitTarget = 0,
    // Retained 0-value alias for reflection/serializer startup lanes that
    // referenced the pre-reconstruction "none" enumerator.
    ProjectileImpactEvent_None = ProjectileImpactEvent_HitTarget,
    ProjectileImpactEvent_Other = 1,
    ProjectileImpactEvent_SelfOrProjectile = 2
  };

  /**
   * Single-listener sink for projectile impact events, and the broadcaster node
   * that binds to it. Both come from the one template pair in
   * `moho/misc/ManyToOneBroadcaster.h`.
   *
   * The listener half used to be an explicit specialization spelled out here,
   * and a second, WeakObject-less copy of it in ProjectileStartupRegistrations.h
   * - an ODR violation that broke the build outright (C2766). The broadcaster
   * half was a third hand-written copy in that same header. All three were
   * layout-identical to what the template emits.
   */
  using ManyToOneListener_EProjectileImpactEvent = ManyToOneListener<EProjectileImpactEvent>;
  using ManyToOneBroadcaster_EProjectileImpactEvent = ManyToOneBroadcaster<EProjectileImpactEvent>;
} // namespace moho

