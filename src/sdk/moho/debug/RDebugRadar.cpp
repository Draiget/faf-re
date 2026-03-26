#include "moho/debug/RDebugRadar.h"

#include "moho/debug/RDebugOverlayReflectionHelpers.h"
#include "moho/sim/Sim.h"

namespace moho
{
  gpg::RType* RDebugRadar::sType = nullptr;

  /**
   * Address: 0x0064D880 (FUN_0064D880, Moho::RDebugRadar::GetClass)
   */
  gpg::RType* RDebugRadar::GetClass() const
  {
    return debug_reflection::ResolveObjectType<RDebugRadar>(sType);
  }

  /**
   * Address: 0x0064D8A0 (FUN_0064D8A0, Moho::RDebugRadar::GetDerivedObjectRef)
   */
  gpg::RRef RDebugRadar::GetDerivedObjectRef()
  {
    return debug_reflection::MakeRef(this, GetClass());
  }

  /**
   * Address: 0x0064ED70 (FUN_0064ED70, Moho::RDebugRadar::dtr)
   */
  RDebugRadar::~RDebugRadar() = default;

  /**
   * Address: 0x0064E020 (FUN_0064E020, Moho::RDebugRadar::OnTick)
   */
  void RDebugRadar::Tick(Sim* const sim)
  {
    if (sim == nullptr || sim->mMapData == nullptr) {
      return;
    }

    // FUN_0064E020 relies on the unrecovered radar-cell traversal and
    // recon-blip draw helpers (FUN_0064D9F0 family).
    (void)sim->GetDebugCanvas();
  }
} // namespace moho
