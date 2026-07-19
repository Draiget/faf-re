#pragma once

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
} // namespace moho

