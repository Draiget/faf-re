
#include <cstddef>
#include "gpg/core/reflection/Reflection.h"
#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/particles/SWorldBeam.h"

namespace
{

  /**
   * Address: 0x00BC5300 (FUN_00BC5300, dynamic initializer for the global
   * `PrimitiveSerHelper<SWorldBeam::BlendMode,int>` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields (vtable slot 0 `Init()` dispatched later by
   * `gpg::SerHelperBase::InitNewHelpers`). The previous raw-struct stand-in
   * for this helper required an explicit
   * `register_SWorldBeamBlendModePrimitiveSerializer()` call from a
   * bootstrap struct to run its equivalent logic; the real binary never
   * does that -- the global's own dynamic initializer is the entire
   * registration.
   *
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::SWorldBeam::BlendMode,int>
   * VFTABLE: never constructed prior to this recovery -- see the ctor
   * Doxygen block on `gpg::PrimitiveSerHelper` in Reflection.h.
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4BlendMode@SWorldBeam@Moho@@H@gpg'`,
   * i.e. `BlendMode` nested inside `SWorldBeam`, not the top-level enum
   * some sibling classes use): `FUN_00BC5300` (real, `__xc_a`-reachable).
   * No dead low-address duplicate found for this one.
   */
  gpg::PrimitiveSerHelper<moho::SWorldBeam::BlendMode, int> gSWorldBeamBlendModePrimitiveSerializer;

} // namespace

namespace moho
{
} // namespace moho
