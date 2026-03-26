#include "moho/debug/RDebugGrid.h"

#include "moho/debug/RDebugOverlayReflectionHelpers.h"
#include "moho/sim/Sim.h"

namespace moho
{
  gpg::RType* RDebugGrid::sType = nullptr;

  /**
   * Address: 0x0064D020 (FUN_0064D020, Moho::RDebugGrid::GetClass)
   */
  gpg::RType* RDebugGrid::GetClass() const
  {
    return debug_reflection::ResolveObjectType<RDebugGrid>(sType);
  }

  /**
   * Address: 0x0064D040 (FUN_0064D040, Moho::RDebugGrid::GetDerivedObjectRef)
   */
  gpg::RRef RDebugGrid::GetDerivedObjectRef()
  {
    return debug_reflection::MakeRef(this, GetClass());
  }

  /**
   * Address: 0x0064ED30 (FUN_0064ED30, Moho::RDebugGrid::dtr)
   */
  RDebugGrid::~RDebugGrid() = default;

  /**
   * Address: 0x0064D7A0 (FUN_0064D7A0, Moho::RDebugGrid::OnTick)
   */
  void RDebugGrid::Tick(Sim* const sim)
  {
    if (sim == nullptr || sim->mMapData == nullptr) {
      return;
    }

    // FUN_0064D7A0 relies on the unrecovered recursive grid pass (FUN_0064D3A0 family).
    // Preserve current typed entry checks while helper lifting is pending.
    (void)sim->GetDebugCanvas();
  }
} // namespace moho
