#include "moho/unit/core/RDebugWeapons.h"

#include <cstddef>
#include <cmath>
#include <cstdint>

#include "moho/ai/CAiAttackerImpl.h"
#include "moho/debug/RDebugOverlayReflectionHelpers.h"
#include "moho/entity/EntityDb.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CDebugCanvas.h"
#include "moho/sim/Sim.h"
#include "moho/ui/SDebugWorldText.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UnitWeaponRuntimeView.h"
#include "Wm3Quaternion.h"
#include "Wm3Vector3.h"

namespace
{
  constexpr std::uint32_t kWeaponCirclePrecision = 0x20u;
  constexpr float kWeaponLabelAngleStep = 0.39269909f;
  constexpr float kWeaponLabelPitch = -0.7853981852531433f;
  constexpr std::int32_t kWeaponLabelStyle = 8;
  constexpr std::uint32_t kWeaponDepthAlpha = 0xAF000000u;
  constexpr std::uint32_t kWeaponDepthMask = 0x00FFFFFFu;

  [[nodiscard]] std::uint32_t ResolveWeaponDebugDepth(const moho::Sim* const sim) noexcept
  {
    const auto raw = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(sim));
    return (raw & kWeaponDepthMask) | kWeaponDepthAlpha;
  }

  [[nodiscard]] Wm3::Vector3f BuildWeaponLabelOffset(const float angle, const float radius) noexcept
  {
    Wm3::Vector3f orbitOffset{};
    orbitOffset.x = std::cos(angle) * radius;
    orbitOffset.y = std::sin(angle) * radius;
    orbitOffset.z = 0.0f;

    Wm3::Quaternionf labelPitch{};
    labelPitch.w = std::cos(kWeaponLabelPitch);
    labelPitch.x = std::sin(kWeaponLabelPitch);
    labelPitch.y = 0.0f;
    labelPitch.z = 0.0f;

    Wm3::Vector3f out{};
    Wm3::MultiplyQuaternionVector(&out, orbitOffset, labelPitch);
    return out;
  }
} // namespace

namespace moho
{
  gpg::RType* RDebugWeapons::sType = nullptr;

  /**
   * Address: 0x00652C90 (FUN_00652C90, ?GetClass@RDebugWeapons@Moho@@UBEPAVRType@gpg@@XZ)
   */
  gpg::RType* RDebugWeapons::GetClass() const
  {
    return debug_reflection::ResolveObjectType<RDebugWeapons>(sType);
  }

  /**
   * Address: 0x00652CB0 (FUN_00652CB0, ?GetDerivedObjectRef@RDebugWeapons@Moho@@UAE?AVRRef@gpg@@XZ)
   */
  gpg::RRef RDebugWeapons::GetDerivedObjectRef()
  {
    return debug_reflection::MakeRef(this, GetClass());
  }

  /**
   * Address: 0x006537E0 (FUN_006537E0, Moho::RDebugWeapons::dtr)
   */
  RDebugWeapons::~RDebugWeapons() = default;

  /**
   * Address: 0x00652E00 (FUN_00652E00, Moho::RDebugWeapons::OnTick)
   */
  void RDebugWeapons::Tick(Sim* const sim)
  {
    if (sim == nullptr || sim->mEntityDB == nullptr) {
      return;
    }

    CDebugCanvas* const debugCanvas = sim->GetDebugCanvas();
    if (debugCanvas == nullptr) {
      return;
    }

    const std::uint32_t depth = ResolveWeaponDebugDepth(sim);
    const Wm3::Vector3f upAxis{0.0f, 1.0f, 0.0f};

    CEntityDbAllUnitsNode* node = sim->mEntityDB->AllUnitsEnd(0u);
    CEntityDbAllUnitsNode* const endNode = sim->mEntityDB->AllUnitsEnd();
    while (node != endNode) {
      Unit* const unit = CEntityDb::UnitFromAllUnitsNode(node);
      if (unit == nullptr) {
        break;
      }

      CAiAttackerImpl* const attacker = unit->AiAttacker;
      if (attacker != nullptr) {
        const int weaponCount = attacker->GetWeaponCount();
        const RUnitBlueprint* const blueprint = unit->GetBlueprint();
        const auto* const weaponBlueprints = blueprint ? blueprint->Weapons.WeaponBlueprints.begin() : nullptr;
        const std::size_t weaponBlueprintCount = blueprint ? blueprint->Weapons.WeaponBlueprints.size() : 0u;

        for (int weaponIndex = 0; weaponIndex < weaponCount; ++weaponIndex) {
          const UnitWeapon* const weapon = reinterpret_cast<UnitWeapon*>(attacker->GetWeapon(weaponIndex));
          const float radius = ResolveDebugWeaponRadius(AsUnitWeaponRuntimeView(weapon));
          const Wm3::Vector3f unitPosition = unit->GetPosition();
          debugCanvas->AddWireCircle(upAxis, unitPosition, radius, depth, kWeaponCirclePrecision);

          if (weaponBlueprints != nullptr && static_cast<std::size_t>(weaponIndex) < weaponBlueprintCount) {
            const RUnitBlueprintWeapon& weaponBlueprint = weaponBlueprints[weaponIndex];

            SDebugWorldText label{};
            label.position = unitPosition + BuildWeaponLabelOffset(kWeaponLabelAngleStep * static_cast<float>(weaponIndex), radius);
            label.text.assign_owned(weaponBlueprint.DisplayName.view());
            label.style = kWeaponLabelStyle;
            label.depth = depth;
            debugCanvas->AddWorldText(label);
          }
        }
      }

      node = CEntityDb::NextAllUnitsNode(node);
    }
  }
} // namespace moho
