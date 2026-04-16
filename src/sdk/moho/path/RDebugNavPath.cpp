#include "moho/path/RDebugNavPath.h"

#include <cstdint>
#include <typeinfo>

#include "moho/ai/IAiNavigator.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityDb.h"
#include "moho/sim/CDebugCanvas.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/Sim.h"
#include "moho/unit/core/Unit.h"

namespace
{
  constexpr std::uint32_t kPathCircleDepth = 0xFFFFC000u;
  constexpr std::uint32_t kPathLineColor = 0x0FFF8000u;

  [[nodiscard]] float ResolvePathPointElevation(
    const moho::STIMap& map, const moho::SFootprint& footprint, const float x, const float z
  )
  {
    const moho::CHeightField* const heightField = map.GetHeightField();
    if (heightField == nullptr) {
      return 0.0f;
    }

    float elevation = heightField->GetElevation(x, z);
    const bool seabedOnly =
      (static_cast<std::uint8_t>(footprint.mOccupancyCaps) & static_cast<std::uint8_t>(moho::EOccupancyCaps::OC_SEABED)) != 0u;
    if (!seabedOnly && map.mWaterEnabled != 0u && map.mWaterElevation > elevation) {
      elevation = map.mWaterElevation;
    }
    return elevation;
  }

  void DrawNavigatorPathOverlay(moho::Sim* const sim, const moho::SFootprint& footprint, const moho::SNavPath* const navPath)
  {
    if (sim == nullptr || sim->mMapData == nullptr || navPath == nullptr || navPath->start == nullptr ||
        navPath->finish == nullptr || navPath->finish <= navPath->start) {
      return;
    }

    moho::CDebugCanvas* const debugCanvas = sim->GetDebugCanvas();
    if (debugCanvas == nullptr) {
      return;
    }

    Wm3::Vector3f circleNormal{};
    circleNormal.x = 0.0f;
    circleNormal.y = 1.0f;
    circleNormal.z = 0.0f;

    Wm3::Vector3f previousCenter{};
    bool hasPrevious = false;

    for (const moho::SOCellPos* cell = navPath->start; cell != navPath->finish; ++cell) {
      Wm3::Vector3f center{};
      center.x = static_cast<float>(cell->x) + (static_cast<float>(footprint.mSizeX) * 0.5f);
      center.z = static_cast<float>(cell->z) + (static_cast<float>(footprint.mSizeZ) * 0.5f);
      center.y = ResolvePathPointElevation(*sim->mMapData, footprint, center.x, center.z);

      debugCanvas->AddWireCircle(
        circleNormal, center, 0.5f, kPathCircleDepth, 6u
      );

      if (hasPrevious) {
        moho::SDebugLine line{};
        line.p0 = previousCenter;
        line.p1 = center;
        line.depth0 = static_cast<std::int32_t>(kPathLineColor);
        line.depth1 = static_cast<std::int32_t>(kPathLineColor);
        debugCanvas->DebugDrawLine(line);
      }

      previousCenter = center;
      hasPrevious = true;
    }
  }

  /**
   * Address: 0x00650FC0 (FUN_00650FC0, Moho::RDebugNavPath non-deleting dtor body)
   *
   * What it does:
   * Runs the typed debug-overlay intrusive unlink lane for one
   * `RDebugNavPath` instance and restores singleton link state.
   */
  [[maybe_unused]] void DestroyRDebugNavPathNonDeletingBody(moho::RDebugNavPath* const overlay) noexcept
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
  gpg::RType* RDebugNavPath::sType = nullptr;

  /**
   * Address: 0x00650ED0 (FUN_00650ED0)
   *
   * What it does:
   * Initializes the nav-path overlay vtable lane and inherited intrusive
   * debug-overlay links.
   */
  RDebugNavPath::RDebugNavPath() = default;

  /**
   * Address: 0x00650520 (FUN_00650520, ?GetClass@RDebugNavPath@Moho@@UBEPAVRType@gpg@@XZ)
   */
  gpg::RType* RDebugNavPath::GetClass() const
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(RDebugNavPath));
    }
    return sType;
  }

  /**
   * Address: 0x00650540 (FUN_00650540, ?GetDerivedObjectRef@RDebugNavPath@Moho@@UAE?AVRRef@gpg@@XZ)
   */
  gpg::RRef RDebugNavPath::GetDerivedObjectRef()
  {
    gpg::RRef out{};
    out.mObj = this;
    out.mType = GetClass();
    return out;
  }

  /**
   * Address: 0x00650F00 (FUN_00650F00, scalar deleting body)
   */
  RDebugNavPath::~RDebugNavPath() = default;

  /**
   * Address: 0x00650690 (FUN_00650690, Moho::RDebugNavPath::OnTick)
   */
  void RDebugNavPath::Tick(Sim* const sim)
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

      IAiNavigator* const navigator = unit->AiNavigator;
      if (navigator != nullptr) {
        DrawNavigatorPathOverlay(sim, unit->GetFootprint(), navigator->GetNavPath());
      }

      node = CEntityDb::NextAllUnitsNode(node);
    }
  }
} // namespace moho
