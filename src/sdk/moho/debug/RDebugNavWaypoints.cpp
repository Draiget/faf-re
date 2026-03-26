#include "moho/debug/RDebugNavWaypoints.h"

#include <cstdint>

#include "moho/ai/IAiSteering.h"
#include "moho/debug/RDebugOverlayReflectionHelpers.h"
#include "moho/entity/EntityDb.h"
#include "moho/sim/CDebugCanvas.h"
#include "moho/sim/Sim.h"
#include "moho/unit/core/Unit.h"

namespace
{
  constexpr float kWaypointCircleRadius = 0.4f;
  constexpr std::uint32_t kWaypointCircleDepth = 0xFFFF0000u;
  constexpr std::uint32_t kWaypointCirclePrecision = 6u;

  void DrawSteeringWaypoints(moho::Sim* const sim, const Wm3::Vector3f* const waypoints, const int waypointCount)
  {
    if (sim == nullptr || waypoints == nullptr || waypointCount <= 0) {
      return;
    }

    moho::CDebugCanvas* const debugCanvas = sim->GetDebugCanvas();
    if (debugCanvas == nullptr) {
      return;
    }

    Wm3::Vector3f up{};
    up.x = 0.0f;
    up.y = 1.0f;
    up.z = 0.0f;

    for (int index = 0; index < waypointCount; ++index) {
      debugCanvas->AddWireCircle(
        up, waypoints[index], kWaypointCircleRadius, kWaypointCircleDepth, kWaypointCirclePrecision
      );
    }
  }
} // namespace

namespace moho
{
  gpg::RType* RDebugNavWaypoints::sType = nullptr;

  /**
   * Address: 0x00650730 (FUN_00650730, Moho::RDebugNavWaypoints::GetClass)
   */
  gpg::RType* RDebugNavWaypoints::GetClass() const
  {
    return debug_reflection::ResolveObjectType<RDebugNavWaypoints>(sType);
  }

  /**
   * Address: 0x00650750 (FUN_00650750, Moho::RDebugNavWaypoints::GetDerivedObjectRef)
   */
  gpg::RRef RDebugNavWaypoints::GetDerivedObjectRef()
  {
    return debug_reflection::MakeRef(this, GetClass());
  }

  /**
   * Address: 0x00650F40 (FUN_00650F40, Moho::RDebugNavWaypoints::dtr)
   */
  RDebugNavWaypoints::~RDebugNavWaypoints() = default;

  /**
   * Address: 0x006508A0 (FUN_006508A0, Moho::RDebugNavWaypoints::OnTick)
   */
  void RDebugNavWaypoints::Tick(Sim* const sim)
  {
    if (sim == nullptr || sim->mEntityDB == nullptr) {
      return;
    }

    CEntityDbAllUnitsNode* node = sim->mEntityDB->AllUnitsEnd(0u);
    CEntityDbAllUnitsNode* const endNode = sim->mEntityDB->AllUnitsEnd();
    while (node != endNode) {
      Unit* const unit = CEntityDb::UnitFromAllUnitsNode(node);
      if (unit == nullptr) {
        break;
      }

      IAiSteering* const steering = unit->AiSteering;
      if (steering != nullptr) {
        Wm3::Vector3f waypoints[4]{};
        const int waypointCount = steering->GetWaypoints(waypoints);
        DrawSteeringWaypoints(sim, waypoints, waypointCount);
      }

      node = CEntityDb::NextAllUnitsNode(node);
    }
  }
} // namespace moho
