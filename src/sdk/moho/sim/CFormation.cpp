#include "moho/sim/CFormation.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>

#include "moho/entity/Entity.h"
#include "moho/entity/UserEntity.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/Sim.h"
#include "moho/ai/CAiFormationInstance.h"
#include "moho/ai/IAiFormationDB.h"
#include "moho/ai/IFormationInstance.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/math/Vector3f.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UserUnit.h"
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
  std::int32_t DetermineSelectionFormationType(
    moho::WeakEntitySetUserEntity& selection
  ) noexcept
  {
    constexpr std::int32_t kFormationTypeSurface = 0;
    constexpr std::int32_t kFormationTypeAir = 1;
    constexpr std::int32_t kFormationTypeMixed = 2;

    if (selection.mHead == nullptr) {
      return kFormationTypeSurface;
    }

    moho::SSelectionNodeUserEntity* node = nullptr;
    (void)moho::PruneTombstonesAndFindLive(selection, &node, selection.mHead->mLeft);
    if (node == selection.mHead) {
      return kFormationTypeSurface;
    }

    bool hasAirUnits = false;
    bool hasSurfaceUnits = false;

    while (node != selection.mHead) {
      moho::UserEntity* const entity = DecodeSelectionEntity(node->mEnt);
      moho::Unit* const unit = ResolveSelectionUnit(entity);
      if (unit != nullptr && unit->mCurrentLayer == moho::LAYER_Air) {
        hasAirUnits = true;
      } else {
        hasSurfaceUnits = true;
      }

      moho::SSelectionSetUserEntity::Iterator_inc(&node);
      (void)moho::PruneTombstonesAndFindLive(selection, &node, node);
    }

    if (!hasAirUnits) {
      return kFormationTypeSurface;
    }
    return hasSurfaceUnits ? kFormationTypeMixed : kFormationTypeAir;
  }

  /**
   * Allocates one `SSelectionNodeUserEntity`-shaped tree node for
   * `CFormation`'s own participating-unit weak-set (see the field doc on
   * `CFormation::mParticipants`). Kept as a local nothrow allocator (rather than
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
    : mParticipants{}
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
    mParticipants.mHead = head;
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

    SSelectionNodeUserEntity* const nodeHead = mParticipants.mHead;
    if (nodeHead != nullptr) {
      DestroyFormationNodeTreeWithOwnerUnlink(nodeHead->mParent);
      ::operator delete(nodeHead);
      mParticipants.mHead = nullptr;
    }
    mParticipants.mSize = 0u;
  }

  /**
   * Address: 0x008380E0 (FUN_008380E0, Moho::CFormation::Reset)
   */
  void CFormation::Reset()
  {
    if (SSelectionNodeUserEntity* const nodeHead = mParticipants.mHead; nodeHead != nullptr) {
      DestroyFormationNodeTreeWithOwnerUnlink(nodeHead->mParent);
      nodeHead->mParent = nodeHead;
      nodeHead->mLeft = nodeHead;
      nodeHead->mRight = nodeHead;
    }
    mParticipants.mSize = 0u;

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

  /**
   * Address: 0x008384C0 (FUN_008384C0, Moho::CFormation::ChooseFormation)
   */
  void CFormation::ChooseFormation(
    const Wm3::Vector3f& mouseWorldPos,
    WeakEntitySetUserEntity& selection,
    const bool useLastQueuedDestination
  )
  {
    mStart = Wm3::Vector3f(0.0f, 0.0f, 0.0f);

    // Walk the incoming selection, pruning tombstones exactly as
    // SSelectionSetUserEntity's own erase-walking members do (PruneTombstonesAndFindLive
    // deletes each tombstone it passes, matching the binary's fused
    // advance-then-erase loop).
    SSelectionNodeUserEntity* node = nullptr;
    (void)PruneTombstonesAndFindLive(selection, &node, selection.mHead->mLeft);
    while (node != selection.mHead) {
      UserEntity* const entity = DecodeSelectionEntity(node->mEnt);
      UserUnit* const unit = (entity != nullptr) ? reinterpret_cast<UserUnit*>(entity) : nullptr;

      // Track every visited unit in this formation's own participant weak set.
      // The binary calls `WeakSet<UserUnit>::Add` (0x00822270) here with `this`
      // pushed verbatim as the set argument, which is exactly `mParticipants`
      // at `this + 0x00`; the discarded `{iterator, inserted}` pair is the sret
      // slot the call site never reads back.
      WeakUnitSetUserUnit::AddResult participantAdd{};
      (void)WeakUnitSetUserUnit::Add(&participantAdd, &mParticipants, unit);

      Wm3::Vector3f unitPosition(0.0f, 0.0f, 0.0f);
      bool haveQueuedPosition = false;
      if (useLastQueuedDestination && unit != nullptr) {
        if (const QueuedUserCommandRecord* const anchor = GetLastQueuedUserCommandAnchor(unit); anchor != nullptr) {
          const Wm3::Vector3f queuedPosition = ResolveLastQueuedCommandAnchorPosition(anchor);
          if (IsValidVector3f(queuedPosition)) {
            unitPosition = queuedPosition;
            haveQueuedPosition = true;
          }
        }
      }
      if (!haveQueuedPosition) {
        unitPosition = unit->GetPosition();
      }

      mStart.x += unitPosition.x;
      mStart.y += unitPosition.y;
      mStart.z += unitPosition.z;

      SSelectionSetUserEntity::Iterator_inc(&node);
      (void)PruneTombstonesAndFindLive(selection, &node, node);
    }

    const std::int32_t participantCount = CountLiveUserEntityWeakSetEntriesAndPrune(mParticipants);
    if (participantCount == 0) {
      constexpr float kFltMax = 3.4028235e38f;
      mStart = Wm3::Vector3f(kFltMax, kFltMax, kFltMax);
    } else {
      const float invCount = 1.0f / static_cast<float>(participantCount);
      mStart.x *= invCount;
      mStart.y *= invCount;
      mStart.z *= invCount;
    }

    mType = DetermineSelectionFormationType(selection);

    mFinish = mouseWorldPos;
    mMousePos = mouseWorldPos;

    const Wm3::Vector3f headingDelta(mFinish.x - mStart.x, 0.0f, mFinish.z - mStart.z);
    mDirection = COORDS_Orient(headingDelta);

    LuaPlus::LuaState* const state = WLD_GetActiveSession()->mState;
    const auto formationType = static_cast<EFormationType>(mType);
    mNumFormationScripts = static_cast<std::int32_t>(FORMATION_GetNumScripts(state, formationType));

    if (mNumFormationScripts > 0) {
      const float dx = mFinish.x - mStart.x;
      const float dy = mFinish.y - mStart.y;
      const float dz = mFinish.z - mStart.z;
      const float dragDistance = std::sqrt(dx * dx + dy * dy + dz * dz);

      if (dragDistance > 200.0f) {
        mTravelFormation = FORMATION_PickTravelFormation(state, formationType, dragDistance);
      }

      const std::int32_t bestFormation = FORMATION_PickBestFormation(state, formationType, dragDistance);
      if (bestFormation != -1) {
        mBestFormation = bestFormation;
      }
      if (mBestFormation == -1) {
        mBestFormation = 0;
      }
    }
  }

  /**
   * Address: 0x008382A0 (FUN_008382A0, Moho::CFormation::Finalize)
   */
  void CFormation::Finalize()
  {
    IFormationInstance* const previousInstance = mCurInstance;
    mCurInstance = nullptr;
    if (previousInstance != nullptr) {
      previousInstance->operator_delete(1);
    }

    if (mBestFormation < 0) {
      return;
    }

    CWldSession* const session = WLD_GetActiveSession();
    LuaPlus::LuaState* const state = session->mState;
    RRuleGameRulesImpl* const gamerules = session->mRules;

    // Collect every live, still-mobile, unattached participant unit into a
    // transient weak-ref set. `mParticipants` is a `WeakUnitSetUserUnit`, not
    // an `SSelectionSetUserEntity` -- the binary calls the exact same prune
    // routine on it anyway (0x00838313/0x008383CC point `this` straight at
    // `CFormation`'s own `+0x00`), which is why `PruneTombstonesAndFindLive`
    // is generalized over the shared `WeakEntitySetUserEntity` header rather
    // than reinterpret_cast-ed through the wrong set type here. The collected
    // set feeds `CFormationInstance::Create`'s `mUnits` lane directly, so it
    // is built as a `SFormationLinkedUnitRefVec` (via `AppendLinkedUnitRef`)
    // rather than the `SFormationLayerUnitSet` shape `PreRunScript`/`Setup`/
    // `UpdateFormation` use for their own transient candidate sets.
    SFormationLinkedUnitRefVec collectedUnits{};

    SSelectionNodeUserEntity* node = nullptr;
    (void)PruneTombstonesAndFindLive(mParticipants, &node, mParticipants.mHead->mLeft);
    while (node != mParticipants.mHead) {
      // `DecodeSelectionEntity` recovers the live `UserEntity*` (or `nullptr`
      // for a tombstone) from the node's weak-ref pair; `mParticipants` only
      // ever stores units inserted through `WeakUnitSetUserUnit::Add(UserUnit*)`,
      // so every non-null result is safely a `UserUnit*` too (same
      // reinterpret_cast `Add`'s own body already relies on, since `UserUnit`'s
      // `UserEntity` base sits at offset zero).
      UserEntity* const entity = DecodeSelectionEntity(node->mEnt);
      if (entity != nullptr) {
        UserUnit* const candidateUnit = reinterpret_cast<UserUnit*>(entity);
        IUnit* const iunitBridge = GetIUnitBridge(candidateUnit);
        if (!iunitBridge->IsDead() && !entity->IsBeingBuilt() && entity->GetAttachmentParent() == nullptr) {
          AppendLinkedUnitRef(collectedUnits, iunitBridge);
        }
      }

      SSelectionSetUserEntity::Iterator_inc(&node);
      (void)PruneTombstonesAndFindLive(mParticipants, &node, node);
    }

    const auto formationType = static_cast<EFormationType>(mType);
    const char* const scriptName = FORMATION_GetScriptName(state, mBestFormation, formationType);

    const SCoordsVec2 coords{mFinish.x, mFinish.z};
    CFormationInstance* const newInstance =
      CFormationInstance::Create(gamerules, state, collectedUnits, scriptName, coords, mDirection);

    IFormationInstance* const staleInstance = mCurInstance;
    mCurInstance = newInstance;
    if (staleInstance != nullptr) {
      staleInstance->operator_delete(1);
    }

    mLastUpdate = gpg::time::GetSystemTimer().ElapsedSeconds();

    ClearLinkedUnitRefs(collectedUnits);
  }

  /**
   * Address: 0x00838A80 (FUN_00838A80, Moho::CFormation::LuaFinalize)
   *
   * What it does:
   * Lua-facing re-finalize: only fires once more than one formation script
   * is available, advancing `mBestFormation` to the next script round-robin
   * before calling `Finalize()` again, then resets `mTimeLeft` to force an
   * immediate next tick.
   *
   * Not yet invoked from recovered source: its sole caller,
   * `Moho::CUIWorldView::HandleEvent` (0x008704B0), is still unrecovered.
   */
  [[maybe_unused]] void CFormation::LuaFinalize()
  {
    if (mNumFormationScripts > 1) {
      mBestFormation = (mBestFormation + 1) % mNumFormationScripts;
      Finalize();
      mTimeLeft = 0.0f;
    }
  }

  /**
   * Address: 0x00838800 (FUN_00838800, Moho::CFormation::ProcessMouse)
   *
   * IDA signature:
   * void __userpurge Moho::CFormation::ProcessMouse(
   *     std::vector *a1@<eax>, Moho::CFormation *a2, char a3,
   *     Wm3::Vector3f *mousePos, bool a5);
   *
   * What it does:
   * `a1`'s decompiled `std::vector*` typing is the same decompiler
   * type-confusion `ChooseFormation` and `PruneTombstonesAndFindLive`
   * already document -- it is really the world session's
   * `SSelectionSetUserEntity*`. When the trigger flag is clear, or the
   * selection prunes down to no live entity, this drops the formation
   * (`mReady = false`, `Reset()`); otherwise it marks the formation ready
   * and forwards straight into `ChooseFormation()`/`Finalize()`.
   */
  void CFormation::ProcessMouse(
    SSelectionSetUserEntity* const selection,
    const bool triggerActive,
    const Wm3::Vector3f& mousePos,
    const bool useLastQueuedDestination
  )
  {
    SSelectionNodeUserEntity* firstLive = nullptr;
    const bool hasLiveSelection = triggerActive
      && (*PruneTombstonesAndFindLive(*selection, &firstLive, selection->mHead->mLeft) != selection->mHead);

    if (!hasLiveSelection) {
      mReady = false;
      Reset();
      return;
    }

    mReady = true;
    ChooseFormation(mousePos, *selection, useLastQueuedDestination);
    Finalize();
  }
} // namespace moho
