#include "moho/debug/RDebugNavSteering.h"

#include <cstdint>

#include "moho/debug/RDebugOverlayReflectionHelpers.h"
#include "moho/entity/EntityDb.h"
#include "moho/sim/CDebugCanvas.h"
#include "moho/sim/Sim.h"
#include "moho/ui/SDebugLine.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/core/Unit.h"

namespace
{
  constexpr std::uint32_t kSteeringLineColor = 0xFF0000FFu;

  /**
   * Address: 0x00651020 (FUN_00651020, Moho::RDebugNavSteering non-deleting dtor body)
   *
   * What it does:
   * Runs the typed debug-overlay intrusive unlink lane for one
   * `RDebugNavSteering` instance and restores singleton link state.
   */
  [[maybe_unused]] void DestroyRDebugNavSteeringNonDeletingBody(moho::RDebugNavSteering* const overlay) noexcept
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
  gpg::RType* RDebugNavSteering::sType = nullptr;

  /**
   * Address: 0x00650EF0 (FUN_00650EF0)
   *
   * What it does:
   * Initializes the steering-overlay vtable lane and inherited intrusive
   * debug-overlay links.
   */
  RDebugNavSteering::RDebugNavSteering() = default;

  /**
   * Address: 0x00650930 (FUN_00650930, Moho::RDebugNavSteering::GetClass)
   */
  gpg::RType* RDebugNavSteering::GetClass() const
  {
    return debug_reflection::ResolveObjectType<RDebugNavSteering>(sType);
  }

  /**
   * Address: 0x00650950 (FUN_00650950, Moho::RDebugNavSteering::GetDerivedObjectRef)
   */
  gpg::RRef RDebugNavSteering::GetDerivedObjectRef()
  {
    return debug_reflection::MakeRef(this, GetClass());
  }

  /**
   * Address: 0x00650F80 (FUN_00650F80, Moho::RDebugNavSteering::dtr)
   */
  RDebugNavSteering::~RDebugNavSteering() = default;

  /**
   * Address: 0x00650AA0 (FUN_00650AA0, Moho::RDebugNavSteering::OnTick)
   */
  void RDebugNavSteering::Tick(Sim* const sim)
  {
    if (sim == nullptr || sim->mEntityDB == nullptr) {
      return;
    }

    CDebugCanvas* const debugCanvas = sim->GetDebugCanvas();
    if (debugCanvas == nullptr) {
      return;
    }

    CEntityDbAllUnitsNode* node = sim->mEntityDB->AllUnitsEnd(0u);
    CEntityDbAllUnitsNode* const endNode = sim->mEntityDB->AllUnitsEnd();
    while (node != endNode) {
      Unit* const unit = CEntityDb::UnitFromAllUnitsNode(node);
      if (unit == nullptr) {
        break;
      }

      CUnitMotion* const unitMotion = unit->UnitMotion;
      if (unitMotion != nullptr) {
        SDebugLine line{};
        line.p0 = unit->GetPosition();
        line.p1 = unitMotion->mTargetPosition;
        line.depth0 = static_cast<std::int32_t>(kSteeringLineColor);
        line.depth1 = static_cast<std::int32_t>(kSteeringLineColor);
        debugCanvas->DebugDrawLine(line);
      }

      node = CEntityDb::NextAllUnitsNode(node);
    }
  }
} // namespace moho
