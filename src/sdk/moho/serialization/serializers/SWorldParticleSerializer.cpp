
#include <cstddef>
#include "gpg/core/reflection/Reflection.h"
#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/particles/SWorldParticle.h"

namespace
{

  /**
   * Address: 0x00BC53C0 (FUN_00BC53C0, dynamic initializer for the global
   * `PrimitiveSerHelper<SWorldParticle::BlendMode,int>` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields (vtable slot 0 `Init()` dispatched later by
   * `gpg::SerHelperBase::InitNewHelpers`). The previous raw-struct stand-in
   * for this helper required an explicit
   * `register_SWorldParticleBlendModePrimitiveSerializer()` call from a
   * bootstrap struct to run its equivalent logic; the real binary never
   * does that -- the global's own dynamic initializer is the entire
   * registration.
   *
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::SWorldParticle::BlendMode,int>
   * VFTABLE: never constructed prior to this recovery -- see the ctor
   * Doxygen block on `gpg::PrimitiveSerHelper` in Reflection.h.
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4BlendMode@SWorldParticle@Moho@@H@gpg'`,
   * i.e. `BlendMode` nested inside `SWorldParticle` -- a distinct
   * instantiation from `SWorldBeam::BlendMode`'s, converted separately):
   * `FUN_00BC53C0` (real, `__xc_a`-reachable). No dead low-address
   * duplicate found for this one.
   */
  gpg::PrimitiveSerHelper<moho::SWorldParticle::BlendMode, int> gSWorldParticleBlendModePrimitiveSerializer;

  /**
   * Address: 0x00BC5420 (FUN_00BC5420, dynamic initializer for the global
   * `PrimitiveSerHelper<SWorldParticle::ZMode,int>` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields (vtable slot 0 `Init()` dispatched later by
   * `gpg::SerHelperBase::InitNewHelpers`). Same "never actually registered
   * before this recovery" story as `SWorldParticle::BlendMode` above.
   *
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::SWorldParticle::ZMode,int>
   * VFTABLE: never constructed prior to this recovery -- see the ctor
   * Doxygen block on `gpg::PrimitiveSerHelper` in Reflection.h.
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4ZMode@SWorldParticle@Moho@@H@gpg'`):
   * `FUN_00BC5420` (real, `__xc_a`-reachable). No dead low-address
   * duplicate found for this one.
   */
  gpg::PrimitiveSerHelper<moho::SWorldParticle::ZMode, int> gSWorldParticleZModePrimitiveSerializer;

} // namespace

namespace moho
{
} // namespace moho
