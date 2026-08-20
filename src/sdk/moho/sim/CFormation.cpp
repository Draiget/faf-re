#include "moho/sim/CFormation.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>

#include "moho/entity/Entity.h"
#include "moho/entity/UserEntity.h"
#include "moho/sim/CWldSession.h"
#include "moho/ai/CAiFormationInstance.h"
#include "moho/ai/IFormationInstance.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/unit/core/Unit.h"
#include "gpg/core/time/Timer.h"
#include "lua/LuaObject.h"
#include "Wm3Quaternion.h"
#include "Wm3Vector3.h"

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

  /**
   * Allocates one `SSelectionNodeUserEntity`-shaped tree node for
   * `CFormation`'s own participating-unit weak-set (see the field doc on
   * `CFormation::mNodeHead`). Kept as a local nothrow allocator (rather than
   * reusing `moho::AllocateWeakEntitySetHead()`, moho/sim/WeakEntitySet.h)
   * because `CFormation::CFormation` (0x00838070) is asm-verified to use a
   * `nothrow` allocation with an explicit null check, unlike the shared
   * helper's throwing `::operator new`.
   */
  [[nodiscard]] moho::SSelectionNodeUserEntity* AllocateFormationNode()
  {
    auto* const node =
      static_cast<moho::SSelectionNodeUserEntity*>(::operator new(sizeof(moho::SSelectionNodeUserEntity), std::nothrow));
    if (node == nullptr) {
      return nullptr;
    }

    node->mLeft = nullptr;
    node->mParent = nullptr;
    node->mRight = nullptr;
    node->mKey = 0u;
    node->mEnt.mOwnerLinkSlot = nullptr;
    node->mEnt.mNextOwner = nullptr;
    node->mColor = 1u;
    node->mIsSentinel = 0u;
    node->pad_1A[0] = 0u;
    node->pad_1A[1] = 0u;
    return node;
  }

  /**
   * Address: 0x007B45E0 (FUN_007B45E0, sub_7B45E0)
   *
   * What it does:
   * Recursively destroys one formation-node subtree in left-chain order,
   * unlinking each node from the owner-link lane rooted at `mEnt.mOwnerLinkSlot`
   * (the same intrusive owner-chain-head slot every weak-entity-set node in
   * the engine uses; see `SSelectionWeakRefUserEntity`).
   */
  void DestroyFormationNodeTreeWithOwnerUnlink(moho::SSelectionNodeUserEntity* node)
  {
    moho::SSelectionNodeUserEntity* cursor = node;
    while (cursor != nullptr && cursor->mIsSentinel == 0u) {
      DestroyFormationNodeTreeWithOwnerUnlink(cursor->mRight);

      moho::SSelectionNodeUserEntity* const left = cursor->mLeft;
      auto* const owner = static_cast<moho::SSelectionNodeUserEntity*>(cursor->mEnt.mOwnerLinkSlot);
      if (owner != nullptr) {
        auto* slotLane = reinterpret_cast<std::uintptr_t*>(&owner->mLeft);
        auto** const needle = reinterpret_cast<moho::SSelectionNodeUserEntity**>(&cursor->mEnt.mOwnerLinkSlot);
        while (reinterpret_cast<moho::SSelectionNodeUserEntity**>(*slotLane) != needle) {
          slotLane = reinterpret_cast<std::uintptr_t*>(*slotLane + sizeof(std::uint32_t));
        }
        *slotLane = reinterpret_cast<std::uintptr_t>(cursor->mEnt.mNextOwner);
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
    , mDirection(/*w*/ 0.0f, /*x*/ 0.0f, /*y*/ 0.0f, /*z*/ 1.0f)
    , mDirectionScale(1.0f)
    , mTimeLeft(0.5f)
    , mLastUpdate(0.0f)
  {
    SSelectionNodeUserEntity* const head = AllocateFormationNode();
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

    SSelectionNodeUserEntity* const nodeHead = mNodeHead;
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
    mDirection = Wm3::Quaternionf(/*w*/ 0.0f, /*x*/ 0.0f, /*y*/ 0.0f, /*z*/ 1.0f);
    mDirectionScale = 1.0f;
    mTimeLeft = 0.5f;
    mLastUpdate = 0.0f;
  }

  /**
   * Address: 0x00838860 (FUN_00838860, Moho::CFormation::UpdateOrientation)
   *
   * IDA signature:
   * void __fastcall Moho::CFormation::UpdateOrientation(
   *     Wm3::Vector3f *mouseWorldPos, Moho::CFormation *formation);
   *
   * What it does:
   * Advances the command-formation orientation timer; once it expires and the
   * mouse has moved far enough from both the last mouse position and the finish
   * point, recomputes the formation direction quaternion from (mouse - finish)
   * and pushes it into the live formation instance via SetOrientation, unless
   * the UI reports NIS mode (in which case the formation is reset).
   */
  void CFormation::UpdateOrientation(const Wm3::Vector3f& mouseWorldPos, CFormation* const formation)
  {
    if (!formation->mReady || formation->mCurInstance == nullptr) {
      return;
    }

    const float currentTime = gpg::time::GetSystemTimer().ElapsedSeconds();
    const float deltaSeconds = currentTime - formation->mLastUpdate;
    formation->mLastUpdate = currentTime;

    const float remainingTime = formation->mTimeLeft - deltaSeconds;
    formation->mTimeLeft = (remainingTime > 0.0f) ? remainingTime : 0.0f;
    if (formation->mTimeLeft > 0.0f) {
      return;
    }

    const float dxMouse = formation->mMousePos.x - mouseWorldPos.x;
    const float dyMouse = formation->mMousePos.y - mouseWorldPos.y;
    const float dzMouse = formation->mMousePos.z - mouseWorldPos.z;
    const float mouseDeltaSq = dxMouse * dxMouse + dyMouse * dyMouse + dzMouse * dzMouse;

    const float dxFinish = formation->mFinish.x - mouseWorldPos.x;
    const float dyFinish = formation->mFinish.y - mouseWorldPos.y;
    const float dzFinish = formation->mFinish.z - mouseWorldPos.z;
    const float finishDeltaSq = dxFinish * dxFinish + dyFinish * dyFinish + dzFinish * dzFinish;

    if (mouseDeltaSq < 0.0025f || finishDeltaSq < 0.0025f) {
      return;
    }

    LuaPlus::LuaState* const state = WLD_GetActiveSession()->mState;
    LuaPlus::LuaObject gameMainModule = SCR_Import(state, "/lua/ui/game/gamemain.lua");
    LuaPlus::LuaFunction<> isNisMode(gameMainModule["IsNISMode"]);
    if (isNisMode.Call_x_Bool()) {
      formation->Reset();
      return;
    }

    formation->mMousePos = mouseWorldPos;

    const Wm3::Vector3f directionVector(
      mouseWorldPos.x - formation->mFinish.x,
      0.0f,
      mouseWorldPos.z - formation->mFinish.z
    );
    formation->mDirection = COORDS_Orient(directionVector);

    IFormationInstance* const instance = formation->mCurInstance;
    if (instance != nullptr) {
      const Wm3::Quaternionf orientation = formation->mDirection;
      static_cast<CAiFormationInstance*>(instance)->SetOrientation(orientation);
    }
  }
} // namespace moho
