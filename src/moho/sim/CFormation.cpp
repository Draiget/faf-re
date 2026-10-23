#include "moho/sim/CFormation.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>

#include "moho/entity/Entity.h"
#include "moho/entity/UserEntity.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/Sim.h"
#include "moho/ai/CAiFormationInstance.h"
#include "moho/ai/IAiFormationDB.h"
#include "moho/ai/IFormationInstance.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/math/Vector3f.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UserUnit.h"
#include "gpg/core/time/Timer.h"
#include "lua/LuaObject.h"
#include "Wm3Quaternion.h"
#include "Wm3Vector3.h"

namespace
{
  /**
   * Address: 0x008381E0 (FUN_008381E0, func_GetFormationType)
   *
   * What it does:
   * Walks one weak-selection set, classifies live units by movement layer, and
   * returns formation-type lane `0` (surface), `1` (air), or `2` (mixed).
   */
  std::int32_t DetermineSelectionFormationType(moho::WeakSet<moho::UserUnit>& selection)
  {
    constexpr std::int32_t kFormationTypeSurface = 0;
    constexpr std::int32_t kFormationTypeAir = 1;
    constexpr std::int32_t kFormationTypeMixed = 2;

    auto it = selection.begin();
    if (it == selection.end()) {
      return kFormationTypeSurface;
    }

    bool hasAirUnits = false;
    bool hasSurfaceUnits = false;

    // Every entry is a unit; `GetBlueprint` is IUnit slot 7, through the
    // sub-object at UserUnit+0x148, and the test is `Physics.MotionType`
    // (+0x290).
    for (; it != selection.end(); ++it) {
      moho::UserUnit* const unit = *it;
      if (unit->GetBlueprint()->Physics.MotionType == moho::RULEUMT_Air) {
        hasAirUnits = true;
      } else {
        hasSurfaceUnits = true;
      }
    }

    if (!hasAirUnits) {
      return kFormationTypeSurface;
    }
    return hasSurfaceUnits ? kFormationTypeMixed : kFormationTypeAir;
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
    Reset();
  }

  /**
   * Address: 0x0089B370 (FUN_0089B370, ??1CFormation@Moho@@QAE@XZ)
   *
   * What it does:
   * Releases the formation instance; `mParticipants` is then destroyed as a
   * member (the set's `_Tidy`, its subtree erase at 0x007B45E0).
   */
  CFormation::~CFormation()
  {
    IFormationInstance* const curInstance = mCurInstance;
    mCurInstance = nullptr;
    delete curInstance;
  }

  /**
   * Address: 0x008380E0 (FUN_008380E0, Moho::CFormation::Reset)
   */
  void CFormation::Reset()
  {
    // The set's whole-tree erase: `_Erase(root)` (0x007B45E0), head relinked
    // to itself, count zero.
    mParticipants.Clear();

    IFormationInstance* const curInstance = mCurInstance;
    mCurInstance = nullptr;
    delete curInstance;

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
    WeakSet<UserUnit>& selection,
    const bool useLastQueuedDestination
  )
  {
    mStart = Wm3::Vector3f(0.0f, 0.0f, 0.0f);

    for (UserUnit* const unit : selection) {
      (void)mParticipants.Add(unit);

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
    }

    const std::int32_t participantCount = static_cast<std::int32_t>(mParticipants.Size());
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
    delete previousInstance;

    if (mBestFormation < 0) {
      return;
    }

    CWldSession* const session = WLD_GetActiveSession();
    LuaPlus::LuaState* const state = session->mState;
    RRuleGameRulesImpl* const gamerules = session->mRules;

    // Every live participant that is not dead, not being built and not
    // attached. Each `push_back` is the binary's construct-a-`WeakPtr<IUnit>`,
    // push, destroy-the-temporary sequence at 0x0083836D..0x008383B6, and the
    // vector's destructor is the unlink-and-free at 0x00838464..0x008384A3.
    gpg::fastvector_n<WeakPtr<IUnit>, 4> collectedUnits{};
    for (UserUnit* const unit : mParticipants) {
      IUnit* const iunitBridge = GetIUnitBridge(unit);
      if (!iunitBridge->IsDead() && !unit->IsBeingBuilt() && unit->GetAttachmentParent() == nullptr) {
        collectedUnits.push_back(WeakPtr<IUnit>(iunitBridge));
      }
    }

    const auto formationType = static_cast<EFormationType>(mType);
    const char* const scriptName = FORMATION_GetScriptName(state, mBestFormation, formationType);

    const SCoordsVec2 coords{mFinish.x, mFinish.z};
    CFormationInstance* const newInstance =
      CFormationInstance::Create(gamerules, state, collectedUnits, scriptName, coords, mDirection);

    IFormationInstance* const staleInstance = mCurInstance;
    mCurInstance = newInstance;
    delete staleInstance;

    mLastUpdate = gpg::time::GetSystemTimer().ElapsedSeconds();
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
   * Invocation: sole caller is `Moho::CUIWorldView::HandleEvent` (0x008704B0,
   * recovered in moho/ui/UiRuntimeTypes.cpp), from both the left-button-press
   * and left-button-double-click arms (0x00870BEF, shared by the jump at
   * 0x00870CC6) whenever a drag formation is already pending when the next
   * left click arrives.
   */
  void CFormation::LuaFinalize()
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
   * `a1` is the caller's `WeakSet<UserUnit>`. When the trigger flag is clear,
   * or the selection prunes down to no live entity, this drops the formation
   * (`mReady = false`, `Reset()`); otherwise it marks the formation ready
   * and forwards straight into `ChooseFormation()`/`Finalize()`.
   */
  void CFormation::ProcessMouse(
    WeakSet<UserUnit>* const selection,
    const bool triggerActive,
    const Wm3::Vector3f& mousePos,
    const bool useLastQueuedDestination
  )
  {
    const bool hasLiveSelection = triggerActive && !selection->Empty();

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
