#include "moho/debug/RDebugRadar.h"

#include "moho/debug/RDebugOverlayReflectionHelpers.h"
#include "moho/sim/Sim.h"

namespace
{
  /**
   * Address: 0x0064D860 (FUN_0064D860)
   *
   * What it does:
   * Resolves and caches the reflected runtime type for `RDebugRadar`.
   */
  [[nodiscard]] gpg::RType* ResolveRDebugRadarTypeCachePrimary()
  {
    gpg::RType* type = moho::RDebugRadar::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::RDebugRadar));
      moho::RDebugRadar::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x0064E290 (FUN_0064E290)
   *
   * What it does:
   * Secondary duplicate lane that resolves/caches `RDebugRadar` reflection
   * type.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* ResolveRDebugRadarTypeCacheSecondary()
  {
    gpg::RType* type = moho::RDebugRadar::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::RDebugRadar));
      moho::RDebugRadar::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x0064EDE0 (FUN_0064EDE0, Moho::RDebugRadar non-deleting dtor body)
   *
   * What it does:
   * Runs the typed debug-overlay intrusive unlink lane for one `RDebugRadar`
   * instance and restores singleton link state.
   */
  [[maybe_unused]] void DestroyRDebugRadarNonDeletingBody(moho::RDebugRadar* const overlay) noexcept
  {
    if (overlay == nullptr) {
      return;
    }

    auto* const node = static_cast<moho::TDatListItem<moho::RDebugOverlay, void>*>(static_cast<moho::RDebugOverlay*>(overlay));
    node->ListUnlinkSelf();
  }
} // namespace

namespace moho
{
  gpg::RType* RDebugRadar::sType = nullptr;

  /**
   * Address: 0x0064ED20 (FUN_0064ED20)
   *
   * What it does:
   * Initializes the radar-overlay vtable lane and inherited intrusive
   * debug-overlay links.
   */
  RDebugRadar::RDebugRadar() = default;

  /**
   * Address: 0x0064D880 (FUN_0064D880, Moho::RDebugRadar::GetClass)
   */
  gpg::RType* RDebugRadar::GetClass() const
  {
    return ResolveRDebugRadarTypeCachePrimary();
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
