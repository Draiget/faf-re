#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "moho/misc/WeakObject.h"

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
   * Address: 0x005D88F0 (FUN_005D88F0, ManyToOneListener_EProjectileImpactEvent ctor)
   *
   * Single-listener sink for projectile impact events.
   *
   * Canonical definition. This specialization was previously defined twice -
   * in ProjectileStartupRegistrations.h without the WeakObject base, and in
   * CAcquireTargetTask.h with it - an ODR violation that broke the build
   * outright (C2766). The two models were layout-identical: WeakObject is
   * 4 bytes with no vtable, so adding a virtual here puts the vptr at +0x00
   * and the owner link at +0x04 either way.
   *
   * Slot 0 takes the event: Projectile::Impact dispatches it with
   * `mov edx,[ecx]; mov eax,[edx]; call eax` at 0x0069E10E.
   */
  template <class TEvent>
  class ManyToOneListener;

  template <>
  class ManyToOneListener<EProjectileImpactEvent> : public WeakObject
  {
  public:
    static gpg::RType* sType;

    ManyToOneListener();

    virtual int OnEvent(EProjectileImpactEvent event) = 0;
  };
} // namespace moho

