#include "moho/ai/CAiFormationInstance.h"

#include <cmath>
#include <new>

#include "moho/command/SSTICommandIssueData.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/unit/core/Unit.h"

namespace
{
  constexpr Wm3::Vec3f kZeroForwardVector{0.0f, 0.0f, 0.0f};
  constexpr Wm3::Quatf kZeroQuaternion{0.0f, 0.0f, 0.0f, 0.0f};

  struct SFormationLinkedUnitRefWordView
  {
    std::uint32_t ownerChainHeadWord;
    std::uint32_t nextChainLinkWord;
  };
  static_assert(
    sizeof(SFormationLinkedUnitRefWordView) == sizeof(moho::SFormationLinkedUnitRef),
    "SFormationLinkedUnitRefWordView size must match SFormationLinkedUnitRef"
  );

  [[nodiscard]] bool BinaryFloatNotEqual(const float lhs, const float rhs) noexcept
  {
    // Matches the recovered x87 `ucomiss` compare shape:
    // true only when values are different and both are not NaN.
    return ((std::isnan(lhs) || std::isnan(rhs)) == (lhs == rhs));
  }

  [[nodiscard]] bool QuaternionEqualsExact(const Wm3::Quatf& lhs, const Wm3::Quatf& rhs) noexcept
  {
    return lhs.w == rhs.w && lhs.x == rhs.x && lhs.y == rhs.y && lhs.z == rhs.z;
  }

  void DestroyCoordCacheSubtree(moho::SFormationCoordCacheNode* node, const moho::SFormationCoordCacheNode* head)
  {
    if (node == nullptr || node == head || node->isNil != 0u) {
      return;
    }

    DestroyCoordCacheSubtree(node->left, head);
    DestroyCoordCacheSubtree(node->right, head);
    delete node;
  }

  void ResetCoordCacheMap(moho::SFormationCoordCacheMap& cache)
  {
    moho::SFormationCoordCacheNode* const head = cache.head;
    if (head == nullptr) {
      cache.size = 0;
      return;
    }

    DestroyCoordCacheSubtree(head->parent, head);
    head->parent = head;
    head->left = head;
    head->right = head;
    cache.size = 0;
  }
} // namespace

namespace moho
{
  std::uint32_t* SFormationLinkedUnitRef::NextChainLinkSlot(const std::uint32_t linkWord) noexcept
  {
    auto* const link = reinterpret_cast<SFormationLinkedUnitRefWordView*>(static_cast<std::uintptr_t>(linkWord));
    return &link->nextChainLinkWord;
  }

  /**
   * Address: 0x0059BD60 (FUN_0059BD60, ??3CAiFormationInstance@Moho@@QAE@@Z)
   *
   * What it does:
   * Executes CAiFormationInstance teardown and conditionally frees this object
   * when `deleteFlags & 1` is set.
   */
  void CAiFormationInstance::operator_delete(const std::int32_t deleteFlags)
  {
    this->~CAiFormationInstance();
    if ((deleteFlags & 1) != 0) {
      ::operator delete(this);
    }
  }

  /**
   * Address: 0x00569A10 (FUN_00569A10)
   *
   * Moho::SCoordsVec2*
   *
   * What it does:
   * Copies the current formation center into `outCenter`.
   */
  SCoordsVec2* CAiFormationInstance::Func2(SCoordsVec2* const outCenter) const
  {
    outCenter->x = mFormationCenter.x;
    outCenter->z = mFormationCenter.z;
    return outCenter;
  }

  /**
   * Address: 0x00569A30 (FUN_00569A30)
   *
   * Moho::SCoordsVec2 const&
   *
   * What it does:
   * Applies a new center (if finite and changed), then invalidates slot and coord caches.
   */
  void CAiFormationInstance::Func3(const SCoordsVec2& center)
  {
    if (!BinaryFloatNotEqual(mFormationCenter.x, center.x) && !BinaryFloatNotEqual(mFormationCenter.z, center.z)) {
      return;
    }
    if (std::isnan(center.x) || std::isnan(center.z)) {
      return;
    }

    mFormationCenter = center;
    mOccupiedSlots.ResetStorageToInline();
    ResetCoordCacheMap(mCoordCachePrimary);
    ResetCoordCacheMap(mCoordCacheSecondary);
  }

  /**
   * Address: 0x0056A210 (FUN_0056A210)
   *
   * What it does:
   * Returns number of linked unit references currently tracked by this formation.
   */
  int CAiFormationInstance::UnitCount() const
  {
    return static_cast<int>(mUnits.end() - mUnits.begin());
  }

  /**
   * Address: 0x00569BD0 (FUN_00569BD0)
   *
   * Moho::Unit*
   *
   * What it does:
   * Classifies the unit into the air-motion bucket.
   */
  bool CAiFormationInstance::Func5(Unit* const unit) const
  {
    if (unit == nullptr) {
      return false;
    }

    const RUnitBlueprint* const blueprint = unit->GetBlueprint();
    return blueprint != nullptr && blueprint->Physics.MotionType == RULEUMT_Air;
  }

  /**
   * Address: 0x00569BF0 (FUN_00569BF0)
   *
   * What it does:
   * Returns true when current command type is one of the formation commands.
   */
  bool CAiFormationInstance::CommandIsForm() const
  {
    switch (mCommandType) {
    case EUnitCommandType::UNITCOMMAND_FormMove:
    case EUnitCommandType::UNITCOMMAND_FormAggressiveMove:
    case EUnitCommandType::UNITCOMMAND_FormPatrol:
    case EUnitCommandType::UNITCOMMAND_FormAttack:
    case EUnitCommandType::UNITCOMMAND_Guard:
      return true;
    default:
      return false;
    }
  }

  /**
   * Address: 0x0056A4F0 (FUN_0056A4F0)
   *
   * float
   *
   * What it does:
   * Updates formation scale and marks the plan for rebuild when value changed.
   */
  void CAiFormationInstance::Func22(const float scale)
  {
    if (!BinaryFloatNotEqual(mFormationUpdateScale, scale)) {
      return;
    }

    mFormationUpdateScale = scale;
    mPlanUpdateRequested = 1;
  }

  /**
   * Address: 0x0056A520 (FUN_0056A520)
   *
   * Wm3::Quaternion<float> const&
   *
   * What it does:
   * Sets formation orientation, recomputes forward vector, and requests a plan rebuild.
   */
  void CAiFormationInstance::SetOrientation(const Wm3::Quatf& orientation)
  {
    if (QuaternionEqualsExact(mOrientation, orientation)) {
      return;
    }

    mOrientation = orientation;
    if (QuaternionEqualsExact(mOrientation, kZeroQuaternion) || mCommandType == EUnitCommandType::UNITCOMMAND_Move) {
      mForwardVector = kZeroForwardVector;
    } else {
      const float x = mOrientation.x;
      const float y = mOrientation.y;
      const float z = mOrientation.z;
      const float w = mOrientation.w;
      mForwardVector.x = ((x * z) + (y * w)) * 2.0f;
      mForwardVector.y = ((z * w) - (x * y)) * 2.0f;
      mForwardVector.z = 1.0f - (((y * y) + (z * z)) * 2.0f);
    }

    mPlanUpdateRequested = 1;
  }

  /**
   * Address: 0x0056A680 (FUN_0056A680)
   *
   * Wm3::Quaternion<float>*
   *
   * What it does:
   * Copies the current orientation into `outOrientation`.
   */
  Wm3::Quatf* CAiFormationInstance::GetOrientation(Wm3::Quatf* const outOrientation) const
  {
    *outOrientation = mOrientation;
    return outOrientation;
  }

  /**
   * Address: 0x00569A00 (FUN_00569A00)
   *
   * What it does:
   * Returns the active command type for this formation.
   */
  EUnitCommandType CAiFormationInstance::GetCommandType() const
  {
    return mCommandType;
  }

  /**
   * Address: 0x0059A570 (FUN_0059A570)
   *
   * Moho::SCoordsVec2 const&, int, int
   *
   * What it does:
   * Returns true when no occupied slot for `laneToken` overlaps `position` by `footprintSize`.
   */
  bool CAiFormationInstance::Func27(
    const SCoordsVec2& position,
    const std::int32_t footprintSize,
    const std::int32_t laneToken
  ) const
  {
    const SFormationOccupiedSlot* slot = mOccupiedSlots.begin();
    const SFormationOccupiedSlot* const slotEnd = mOccupiedSlots.end();
    while (slot != slotEnd) {
      if (slot->laneToken == laneToken) {
        const std::int32_t maxFootprint =
          slot->footprintSize < footprintSize ? footprintSize : slot->footprintSize;
        const float dx = std::fabs(position.x - slot->position.x);
        if (dx < static_cast<float>(maxFootprint)) {
          const float dz = std::fabs(position.z - slot->position.z);
          if (dz < static_cast<float>(maxFootprint)) {
            return false;
          }
        }
      }
      ++slot;
    }

    return true;
  }
} // namespace moho
