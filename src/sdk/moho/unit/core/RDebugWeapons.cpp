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
#include "moho/unit/core/UnitWeapon.h"
#include "Wm3Quaternion.h"
#include "Wm3Vector3.h"

namespace moho
{
  Wm3::Vector3f* MultQuadVec(Wm3::Vector3f* dest, const Wm3::Vector3f* vec, const Wm3::Quaternionf* quat);
}

namespace
{
  constexpr std::uint32_t kWeaponCirclePrecision = 0x20u;
  // 0x00652F7A loads this from the shared 1.0f pool at 0x00DFEC20.
  constexpr float kDefaultWeaponRadius = 1.0f;
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

  // Ground truth (FUN_00652E00.c, Moho::RDebugWeapons::OnTick) fills memory
  // lanes 0..3 with `cos, sin, 0, 0` - IDA names lane 0 `x` for this type, so
  // that is the scalar-first `{w = cos, x = sin, y = 0, z = 0}` the rest of
  // the engine uses: a rotation about X, which is what a label pitch is. It
  // then rotates via `Moho::MultQuadVec(&v47, &v41, &v36)`, not
  // `Wm3::MultiplyQuaternionVector`.
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
    moho::MultQuadVec(&out, &orbitOffset, &labelPitch);
    return out;
  }

  // FUN_00653790 (`msvc8::vector<moho::SDebugWorldText>::uninit_copy_n`'s
  // per-element step) and its null-guarded wrapper FUN_00653E00 are cited on
  // `uninit_copy_n` in src/sdk/legacy/containers/Vector.h (RULE ONE) - both
  // are zero-caller, zero-xref, linker-retained emissions of that template
  // member, not free-standing engine functions. The per-type free function
  // that used to be transcribed here (`CopyConstructDebugWorldTextCore`) was
  // removed 2026-09-14.

  /**
   * Address: 0x00652C70 (FUN_00652C70)
   *
   * What it does:
   * Resolves and caches the reflected runtime type for `RDebugWeapons`.
   */
  [[nodiscard]] gpg::RType* ResolveRDebugWeaponsTypeCachePrimary()
  {
    gpg::RType* type = moho::RDebugWeapons::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::RDebugWeapons));
      moho::RDebugWeapons::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00653260 (FUN_00653260)
   *
   * What it does:
   * Secondary duplicate lane that resolves/caches `RDebugWeapons`
   * reflection type.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* ResolveRDebugWeaponsTypeCacheSecondary()
  {
    gpg::RType* type = moho::RDebugWeapons::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::RDebugWeapons));
      moho::RDebugWeapons::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00653820 (FUN_00653820, Moho::RDebugWeapons non-deleting dtor body)
   *
   * What it does:
   * Runs the typed debug-overlay intrusive unlink lane for one
   * `RDebugWeapons` instance and restores singleton link state.
   */
  [[maybe_unused]] void DestroyRDebugWeaponsNonDeletingBody(moho::RDebugWeapons* const overlay) noexcept
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
  gpg::RType* RDebugWeapons::sType = nullptr;

  /**
   * Address: 0x006537D0 (FUN_006537D0)
   *
   * What it does:
   * Initializes the weapons-overlay vtable lane and inherited intrusive
   * debug-overlay links.
   */
  RDebugWeapons::RDebugWeapons() = default;

  /**
   * Address: 0x00652C90 (FUN_00652C90, ?GetClass@RDebugWeapons@Moho@@UBEPAVRType@gpg@@XZ)
   */
  gpg::RType* RDebugWeapons::GetClass() const
  {
    return ResolveRDebugWeaponsTypeCachePrimary();
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
          // 0x00652F4B branches on the weapon pointer only; the radius read at
          // 0x00652F63 is the unguarded `GetMaxRadius` expansion, so the
          // fallback constant belongs here rather than inside the getter.
          const UnitWeapon* const weapon = attacker->GetWeapon(weaponIndex);
          const float radius = (weapon != nullptr) ? weapon->mAttributes.GetMaxRadius() : kDefaultWeaponRadius;
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
