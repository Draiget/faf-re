#include "moho/sim/CFormation.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>

#include "moho/entity/UserEntity.h"
#include "moho/sim/CWldSession.h"
#include "moho/ai/IFormationInstance.h"
#include "moho/unit/core/Unit.h"

namespace
{
  [[nodiscard]] moho::UserEntity* DecodeSelectionEntity(
    const moho::SSelectionWeakRefUserEntity& weakEntityRef
  ) noexcept
  {
    constexpr std::uintptr_t kWeakOwnerOffset = offsetof(moho::UserEntity, mIUnitChainHead);
    const std::uintptr_t rawOwnerSlot = reinterpret_cast<std::uintptr_t>(weakEntityRef.mOwnerLinkSlot);
    if (rawOwnerSlot == 0u || rawOwnerSlot < kWeakOwnerOffset) {
      return nullptr;
    }

    return reinterpret_cast<moho::UserEntity*>(rawOwnerSlot - kWeakOwnerOffset);
  }

  [[nodiscard]] moho::Unit* ResolveSelectionUnit(moho::UserEntity* const entity) noexcept
  {
    if (entity == nullptr) {
      return nullptr;
    }

    moho::UserUnit* const userUnitView = entity->IsUserUnit();
    if (userUnitView == nullptr) {
      return nullptr;
    }

    constexpr std::size_t kUserUnitSubobjectOffsetInUnit = 0x148;
    auto* const rawUserUnitView = reinterpret_cast<std::uint8_t*>(userUnitView);
    return reinterpret_cast<moho::Unit*>(rawUserUnitView - kUserUnitSubobjectOffsetInUnit);
  }

  /**
   * Address: 0x008381E0 (FUN_008381E0, func_GetFormationType)
   *
   * What it does:
   * Walks one weak-selection set, classifies live units by movement layer, and
   * returns formation-type lane `0` (surface), `1` (air), or `2` (mixed).
   */
  [[maybe_unused]] std::int32_t DetermineSelectionFormationType(
    moho::SSelectionSetUserEntity* const selection
  ) noexcept
  {
    constexpr std::int32_t kFormationTypeSurface = 0;
    constexpr std::int32_t kFormationTypeAir = 1;
    constexpr std::int32_t kFormationTypeMixed = 2;

    if (selection == nullptr || selection->mHead == nullptr) {
      return kFormationTypeSurface;
    }

    moho::SSelectionSetUserEntity::FindResult cursor{};
    selection->First(&cursor);
    if (cursor.mRes == selection->mHead) {
      return kFormationTypeSurface;
    }

    bool hasAirUnits = false;
    bool hasSurfaceUnits = false;

    moho::SSelectionSetUserEntity::Index iterator{};
    iterator.mOwnerSet = selection;
    iterator.mNode = cursor.mRes;
    while (iterator.mNode != selection->mHead) {
      moho::UserEntity* const entity = DecodeSelectionEntity(iterator.mNode->mEnt);
      moho::Unit* const unit = ResolveSelectionUnit(entity);
      if (unit != nullptr && unit->mCurrentLayer == moho::LAYER_Air) {
        hasAirUnits = true;
      } else {
        hasSurfaceUnits = true;
      }

      iterator.Next();
    }

    if (!hasAirUnits) {
      return kFormationTypeSurface;
    }
    return hasSurfaceUnits ? kFormationTypeMixed : kFormationTypeAir;
  }

  [[nodiscard]] moho::CFormation::Node* AllocateFormationNode()
  {
    auto* const node = static_cast<moho::CFormation::Node*>(::operator new(sizeof(moho::CFormation::Node), std::nothrow));
    if (node == nullptr) {
      return nullptr;
    }

    node->mLeft = nullptr;
    node->mParent = nullptr;
    node->mRight = nullptr;
    node->mValue = nullptr;
    node->mListPrev = nullptr;
    node->mListNext = nullptr;
    node->mColor = 1u;
    node->mIsSentinel = 0u;
    node->mPad1A[0] = 0u;
    node->mPad1A[1] = 0u;
    return node;
  }

  /**
   * Address: 0x007B45E0 (FUN_007B45E0, sub_7B45E0)
   *
   * What it does:
   * Recursively destroys one formation-node subtree in left-chain order,
   * unlinking each node from the owner-link lane rooted at `mListPrev`.
   */
  void DestroyFormationNodeTreeWithOwnerUnlink(moho::CFormation::Node* node)
  {
    moho::CFormation::Node* cursor = node;
    while (cursor != nullptr && cursor->mIsSentinel == 0u) {
      DestroyFormationNodeTreeWithOwnerUnlink(cursor->mRight);

      moho::CFormation::Node* const left = cursor->mLeft;
      moho::CFormation::Node* const owner = cursor->mListPrev;
      if (owner != nullptr) {
        auto* slotLane = reinterpret_cast<std::uintptr_t*>(&owner->mLeft);
        auto** const needle = reinterpret_cast<moho::CFormation::Node**>(&cursor->mListPrev);
        while (reinterpret_cast<moho::CFormation::Node**>(*slotLane) != needle) {
          slotLane = reinterpret_cast<std::uintptr_t*>(*slotLane + sizeof(std::uint32_t));
        }
        *slotLane = reinterpret_cast<std::uintptr_t>(cursor->mListNext);
      }

      ::operator delete(cursor);
      cursor = left;
    }
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00838070 (FUN_00838070, ??0CFormation@Moho@@QAE@@Z)
   */
  CFormation::CFormation()
    : mTreeAllocProxy(nullptr)
    , mNodeHead(nullptr)
    , mNodeCount(0)
    , mCurInstance(nullptr)
    , mReady(false)
    , mPad11{0u, 0u, 0u}
    , mType(0)
    , mStart()
    , mFinish()
    , mMousePos()
    , mBestFormation(-1)
    , mTravelFormation(-1)
    , mNumFormationScripts(0)
    , mDirectionX(0.0f)
    , mDirectionY(0.0f)
    , mDirectionZ(0.0f)
    , mDirectionW(1.0f)
    , mDirectionScale(1.0f)
    , mTimeLeft(0.5f)
    , mLastUpdate(0.0f)
  {
    Node* const head = AllocateFormationNode();
    mNodeHead = head;
    if (head != nullptr) {
      head->mIsSentinel = 1u;
      head->mParent = head;
      head->mLeft = head;
      head->mRight = head;
    }

    Reset();
  }

  /**
   * Address: 0x0089B370 (FUN_0089B370, ??1CFormation@Moho@@QAE@XZ)
   *
   * What it does:
   * Releases the active formation-instance lane, destroys the RB-tree node
   * chain under the sentinel head, and clears node-head/count ownership.
   */
  CFormation::~CFormation()
  {
    IFormationInstance* const curInstance = mCurInstance;
    mCurInstance = nullptr;
    if (curInstance != nullptr) {
      curInstance->operator_delete(1);
    }

    Node* const nodeHead = mNodeHead;
    if (nodeHead != nullptr) {
      DestroyFormationNodeTreeWithOwnerUnlink(nodeHead->mParent);
      ::operator delete(nodeHead);
      mNodeHead = nullptr;
    }
    mNodeCount = 0u;
  }

  /**
   * Address: 0x008380E0 (FUN_008380E0, Moho::CFormation::Reset)
   */
  void CFormation::Reset()
  {
    if (mNodeHead != nullptr) {
      DestroyFormationNodeTreeWithOwnerUnlink(mNodeHead->mParent);
      mNodeHead->mParent = mNodeHead;
      mNodeHead->mLeft = mNodeHead;
      mNodeHead->mRight = mNodeHead;
    }
    mNodeCount = 0u;

    IFormationInstance* const curInstance = mCurInstance;
    mCurInstance = nullptr;
    if (curInstance != nullptr) {
      curInstance->operator_delete(1);
    }

    mReady = false;
    mType = 2;

    std::memset(&mStart, 0, sizeof(mStart));
    std::memset(&mFinish, 0, sizeof(mFinish));
    std::memset(&mMousePos, 0, sizeof(mMousePos));

    mNumFormationScripts = 0;
    mDirectionX = 0.0f;
    mDirectionY = 0.0f;
    mDirectionZ = 0.0f;
    mDirectionW = 1.0f;
    mDirectionScale = 1.0f;
    mTimeLeft = 0.5f;
    mLastUpdate = 0.0f;
  }
} // namespace moho
