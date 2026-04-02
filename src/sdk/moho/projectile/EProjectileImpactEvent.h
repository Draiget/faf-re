#pragma once

namespace moho
{
  /**
   * Recovered enum lane used by projectile impact broadcaster/listener chains.
   *
   * Enumerator values are still pending full behavioral reconstruction; only the
   * ABI/storage lane is required for reflection/serializer startup recovery.
   */
  enum EProjectileImpactEvent : int
  {
    ProjectileImpactEvent_None = 0
  };
} // namespace moho

