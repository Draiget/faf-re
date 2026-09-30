#include "moho/render/camera/CameraImpl.h"

#include <Windows.h>

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>
#include <span>
#include <stdexcept>
#include <typeinfo>

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/reflection/Reflection.h"
#include "lua/LuaObject.h"
#include "moho/collision/CColPrimitiveBox3f.h"
#include "moho/entity/Entity.h"
#include "moho/entity/UserEntity.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/SCR_FromLua.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/misc/WeakPtr.h"
#include "moho/sim/COGrid.h"
#include "moho/task/CTaskEvent.h"
#include "moho/math/MathReflection.h"
#include "moho/math/Vector3f.h"
#include "gpg/core/time/Timer.h"
#include "gpg/core/utils/Logging.h"   // TEMPORARY PROBE (do not commit)
#include "moho/math/QuaternionMath.h"
#include "moho/mesh/Mesh.h"
#include "moho/render/RCamManager.h"
#include "moho/render/camera/CameraTrackingListener.h"
#include "moho/script/CScriptObject.h"
#include "moho/unit/Broadcaster.h"
#include "moho/script/CScriptEvent.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/UserArmy.h"

namespace moho
{
  int cfunc_GetCameraL(LuaPlus::LuaState* state);
  extern float cam_NearZoom;
  extern float cam_NearPitch;
  extern float cam_ZoomAmount;
  extern float cam_ZoomSpeedLarge;
  extern float cam_ZoomSpeedSmall;
  extern float cam_NearFOV;
  extern float cam_FarFOV;
  extern float cam_FarPitch;
  extern float cam_SpinSpeed;
  extern float cam_MinSpinPitch;
  extern float cam_ShakeMult;
  extern float cam_EntityBoxExpand;
  extern float ren_BorderSize;
  extern bool cam_Free;
  /** Address: 0x00F57FEC (?cam_PanSpeed@Moho@@3MA) */
  extern float cam_PanSpeed;
  int cfunc_CameraImplMoveToRegionL(LuaPlus::LuaState* state);
  int cfunc_CameraImplReset(lua_State* luaContext);
  int cfunc_CameraImplResetL(LuaPlus::LuaState* state);
  int cfunc_CameraImplTrackEntities(lua_State* luaContext);
  int cfunc_CameraImplTrackEntitiesL(LuaPlus::LuaState* state);
  int cfunc_CameraImplTargetEntities(lua_State* luaContext);
  int cfunc_CameraImplTargetEntitiesL(LuaPlus::LuaState* state);
  int cfunc_CameraImplNoseCam(lua_State* luaContext);
  int cfunc_CameraImplNoseCamL(LuaPlus::LuaState* state);
  int cfunc_CameraImplHoldRotation(lua_State* luaContext);
  int cfunc_CameraImplHoldRotationL(LuaPlus::LuaState* state);
  int cfunc_CameraImplRevertRotation(lua_State* luaContext);
  int cfunc_CameraImplRevertRotationL(LuaPlus::LuaState* state);
  int cfunc_CameraImplGetZoom(lua_State* luaContext);
  int cfunc_CameraImplGetZoomL(LuaPlus::LuaState* state);
  int cfunc_CameraImplGetFocusPosition(lua_State* luaContext);
  int cfunc_CameraImplGetFocusPositionL(LuaPlus::LuaState* state);
  int cfunc_CameraImplSaveSettings(lua_State* luaContext);
  int cfunc_CameraImplSaveSettingsL(LuaPlus::LuaState* state);
  int cfunc_CameraImplRestoreSettings(lua_State* luaContext);
  int cfunc_CameraImplRestoreSettingsL(LuaPlus::LuaState* state);
  int cfunc_CameraImplUseGameClock(lua_State* luaContext);
  int cfunc_CameraImplUseGameClockL(LuaPlus::LuaState* state);
  int cfunc_CameraImplUseSystemClock(lua_State* luaContext);
  int cfunc_CameraImplUseSystemClockL(LuaPlus::LuaState* state);
  int cfunc_CameraImplEnableEaseInOut(lua_State* luaContext);
  int cfunc_CameraImplEnableEaseInOutL(LuaPlus::LuaState* state);
  int cfunc_CameraImplDisableEaseInOut(lua_State* luaContext);
  int cfunc_CameraImplDisableEaseInOutL(LuaPlus::LuaState* state);
}

namespace
{
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kLuaExpectedBetweenArgsWarning = "%s\n  expected between %d and %d args, but got %d";
  constexpr const char* kGetCameraName = "GetCamera";
  constexpr const char* kGetCameraHelpText = "GetCamera(name)";
  constexpr const char* kGlobalLuaClassName = "<global>";
  constexpr const char* kCameraImplLuaClassName = "CameraImpl";
  constexpr const char* kCameraImplResetName = "Reset";
  constexpr const char* kCameraImplResetHelpText = "Camera:Reset()";
  constexpr const char* kCameraImplSnapToName = "SnapTo";
  constexpr const char* kCameraImplSnapToHelpText = "Camera:SnapTo(position, orientationHPR, zoom)";
  constexpr const char* kCameraImplTrackEntitiesName = "TrackEntities";
  constexpr const char* kCameraImplTrackEntitiesHelpText = "Camera:TrackEntities(ents,zoom,seconds)";
  constexpr const char* kCameraImplTargetEntitiesName = "TargetEntities";
  constexpr const char* kCameraImplTargetEntitiesHelpText = "Camera:TargetEntities(ents,zoom,seconds)";
  constexpr const char* kCameraImplNoseCamName = "NoseCam";
  constexpr const char* kCameraImplNoseCamHelpText = "Camera:NoseCam(ent,pitchAdjust,zoom,seconds,transition)";
  constexpr const char* kCameraImplHoldRotationName = "HoldRotation";
  constexpr const char* kCameraImplHoldRotationHelpText = "Camera:HoldRotation()";
  constexpr const char* kCameraImplRevertRotationName = "RevertRotation";
  constexpr const char* kCameraImplRevertRotationHelpText = "Camera:RevertRotation()";
  constexpr const char* kCameraImplMoveToName = "MoveTo";
  constexpr const char* kCameraImplMoveToHelpText = "Camera:MoveTo(position, orientationHPR, zoom, seconds)";
  constexpr const char* kCameraImplMoveToRegionName = "MoveToRegion";
  constexpr const char* kCameraImplMoveToRegionHelpText = "Camera:MoveTo(region[,seconds])";
  constexpr const char* kCameraImplGetZoomName = "GetZoom";
  constexpr const char* kCameraImplGetZoomHelpText = "Camera:GetZoom()";
  constexpr const char* kCameraImplGetFocusPositionName = "GetFocusPosition";
  constexpr const char* kCameraImplGetFocusPositionHelpText = "Camera:GetFocusPosition()";
  constexpr const char* kCameraImplSaveSettingsName = "SaveSettings";
  constexpr const char* kCameraImplSaveSettingsHelpText = "Camera:SaveSettings()";
  constexpr const char* kCameraImplRestoreSettingsName = "RestoreSettings";
  constexpr const char* kCameraImplRestoreSettingsHelpText = "Camera:RestoreSettings(settings)";
  constexpr const char* kCameraImplGetMinZoomName = "GetMinZoom";
  constexpr const char* kCameraImplGetMinZoomHelpText = "Camera:GetMinZoom()";
  constexpr const char* kCameraImplGetTargetZoomName = "GetTargetZoom";
  constexpr const char* kCameraImplGetTargetZoomHelpText = "Camera:GetTargetZoom()";
  constexpr const char* kCameraImplGetMaxZoomName = "GetMaxZoom";
  constexpr const char* kCameraImplGetMaxZoomHelpText = "Camera:GetMaxZoom()";
  constexpr const char* kCameraImplSetZoomHelpText = "Camera:SetZoom(zoom,seconds)";
  constexpr const char* kCameraImplSetTargetZoomName = "SetTargetZoom";
  constexpr const char* kCameraImplSetTargetZoomHelpText = "Camera:SetTargetZoom(zoom)";
  constexpr const char* kCameraImplSetMaxZoomMultName = "SetMaxZoomMult";
  constexpr const char* kCameraImplSetMaxZoomMultHelpText =
    "Camera:SetMaxZoomMult() - set zoom scale to allow zooming past or before the point where map fills control";
  constexpr const char* kCameraImplUseGameClockName = "UseGameClock";
  constexpr const char* kCameraImplUseGameClockHelpText = "Camera:UseGameClock()";
  constexpr const char* kCameraImplUseSystemClockName = "UseSystemClock";
  constexpr const char* kCameraImplUseSystemClockHelpText = "Camera:UseSystemClock()";
  constexpr const char* kCameraImplEnableEaseInOutName = "EnableEaseInOut";
  constexpr const char* kCameraImplEnableEaseInOutHelpText = "Camera:EnableEaseInOut()";
  constexpr const char* kCameraImplDisableEaseInOutName = "DisableEaseInOut";
  constexpr const char* kCameraImplDisableEaseInOutHelpText = "Camera:DisableEaseInOut()";
  constexpr const char* kCameraImplSetAccModeName = "SetAccMode";
  constexpr const char* kCameraImplSetAccModeHelpText = "Camera:SetAccMode(accTypeName)";
  constexpr const char* kCameraImplSpinName = "Spin";
  constexpr const char* kCameraImplSpinHelpText = "Camera:Spin(headingRate[,zoomRate])";
  constexpr float kDegreesToRadians = 0.017453292f;
  constexpr float kPi = 3.1415927f;
  constexpr float kHalfPi = 1.5707964f;
  constexpr float kTwoPi = 6.2831855f;
  constexpr float kCameraSpinPitchUpperBound = 1.5607964f;
  constexpr std::int32_t kCameraTargetTypeLocation = 0;
  constexpr std::int32_t kCameraTargetTypeBox = 1;
  constexpr std::int32_t kCameraTargetTypeEntity = 2;
  constexpr std::int32_t kCameraTargetTypeNoseCam = 3;
  constexpr std::int32_t kCameraTargetTypeHermite = 4;
  constexpr std::int32_t kCameraTimeSourceSystem = 0;
  constexpr std::int32_t kCameraTimeSourceGame = 1;
  constexpr std::int32_t kCameraAccTypeLinear = 0;
  constexpr std::int32_t kCameraAccTypeFastInSlowOut = 1;
  constexpr std::int32_t kCameraAccTypeSlowInOut = 2;
  constexpr const char* kCameraAccTypeLinearName = "Linear";
  constexpr const char* kCameraAccTypeFastInSlowOutName = "FastInSlowOut";
  constexpr const char* kCameraAccTypeSlowInOutName = "SlowInOut";

  using moho::CameraTimeSourceRuntime;

  class GameTimeSource final : public CameraTimeSourceRuntime
  {
  public:
    /**
     * Address: 0x007A66A0 (FUN_007A66A0, Moho::GameTimeSource::Time)
     *
     * What it does:
     * Returns active world-session game time (`(tick + partialTick) * 0.1f`)
     * or zero when no world-session is active.
     */
    float Time() override;

    /**
     * Address: 0x007A7EA0 (FUN_007A7EA0, Moho::GameTimeSource::dtr)
     *
     * What it does:
     * `GameTimeSource` adds no data members of its own, so the vtable-slot-2
     * scalar deleting destructor just restores this object's own
     * `ITimeSource`/`CameraTimeSourceRuntime` vftable then conditionally
     * frees the object -- exactly what a defaulted destructor produces for
     * a derived class with no extra state.
     */
    ~GameTimeSource() override = default;
  };

  class SystemTimeSource final : public CameraTimeSourceRuntime
  {
  public:
    /**
     * Address: 0x004E9DC0 (FUN_004E9DC0, Moho::SystemTimeSource::Time)
     *
     * What it does:
     * Returns elapsed wall-clock time in seconds from the global system timer.
     */
    float Time() override;

    /**
     * Address: 0x007A7E70 (FUN_007A7E70, Moho::SystemTimeSource::dtr)
     *
     * What it does:
     * `SystemTimeSource` adds no data members of its own, so the
     * vtable-slot-2 scalar deleting destructor just restores this object's
     * own `ITimeSource`/`CameraTimeSourceRuntime` vftable then conditionally
     * frees the object -- exactly what a defaulted destructor produces for
     * a derived class with no extra state.
     */
    ~SystemTimeSource() override = default;
  };

  /**
   * Address: 0x007A66A0 (FUN_007A66A0, Moho::GameTimeSource::Time)
   *
   * What it does:
   * Returns active world-session game time (`(tick + partialTick) * 0.1f`)
   * or zero when no world-session is active.
   */
  float GameTimeSource::Time()
  {
    const moho::CWldSession* const activeSession = moho::WLD_GetActiveSession();
    if (activeSession == nullptr) {
      return 0.0f;
    }

    return (static_cast<float>(activeSession->mGameTick) + activeSession->mTimeSinceLastTick) * 0.1f;
  }

  /**
   * Address: 0x004E9DC0 (FUN_004E9DC0, Moho::SystemTimeSource::Time)
   *
   * What it does:
   * Returns elapsed wall-clock time in seconds from the global system timer.
   */
  float SystemTimeSource::Time()
  {
    return gpg::time::GetSystemTimer().ElapsedSeconds();
  }

  class RecoveredITimeSourceVtableProbe final : public CameraTimeSourceRuntime
  {
  public:
    float Time() override
    {
      return 0.0f;
    }
  };

  [[nodiscard]] void* RecoveredITimeSourceVtable() noexcept
  {
    static RecoveredITimeSourceVtableProbe probe;
    return *reinterpret_cast<void**>(&probe);
  }

  [[nodiscard]] void* RecoveredSystemTimeSourceVtable() noexcept
  {
    static SystemTimeSource probe;
    return *reinterpret_cast<void**>(&probe);
  }

  [[nodiscard]] void* RecoveredGameTimeSourceVtable() noexcept
  {
    static GameTimeSource probe;
    return *reinterpret_cast<void**>(&probe);
  }

  /**
   * Address: 0x007A6500 (FUN_007A6500)
   *
   * What it does:
   * Restores one base `ITimeSource` vtable lane in place.
   */
  [[nodiscard]] CameraTimeSourceRuntime* InitializeCameraTimeSourceVtable(
    CameraTimeSourceRuntime* const timeSource
  ) noexcept
  {
    *reinterpret_cast<void**>(timeSource) = RecoveredITimeSourceVtable();
    return timeSource;
  }

  /**
   * Address: 0x007A7E00 (FUN_007A7E00)
   *
   * What it does:
   * Restores one `SystemTimeSource` vtable lane in place.
   */
  [[nodiscard]] SystemTimeSource* InitializeSystemTimeSourceVtable(SystemTimeSource* const timeSource) noexcept
  {
    *reinterpret_cast<void**>(timeSource) = RecoveredSystemTimeSourceVtable();
    return timeSource;
  }

  /**
   * Address: 0x007A7E10 (FUN_007A7E10)
   *
   * What it does:
   * Restores one `GameTimeSource` vtable lane in place.
   */
  [[nodiscard]] GameTimeSource* InitializeGameTimeSourceVtable(GameTimeSource* const timeSource) noexcept
  {
    *reinterpret_cast<void**>(timeSource) = RecoveredGameTimeSourceVtable();
    return timeSource;
  }

  /**
   * Address: 0x007A7E90 (FUN_007A7E90)
   *
   * What it does:
   * Alias entry that restores the same base `ITimeSource` vtable lane.
   */
  [[nodiscard]] CameraTimeSourceRuntime* InitializeCameraTimeSourceVtableAlias0(
    CameraTimeSourceRuntime* const timeSource
  ) noexcept
  {
    return InitializeCameraTimeSourceVtable(timeSource);
  }

  /**
   * Address: 0x007A7EE0 (FUN_007A7EE0)
   *
   * What it does:
   * Alias entry that restores the same base `ITimeSource` vtable lane.
   */
  [[nodiscard]] CameraTimeSourceRuntime* InitializeCameraTimeSourceVtableAlias1(
    CameraTimeSourceRuntime* const timeSource
  ) noexcept
  {
    return InitializeCameraTimeSourceVtable(timeSource);
  }

  /**
   * Address: 0x007A7EF0 (FUN_007A7EF0)
   *
   * What it does:
   * Alias entry that restores the same base `ITimeSource` vtable lane.
   */
  [[nodiscard]] CameraTimeSourceRuntime* InitializeCameraTimeSourceVtableAlias2(
    CameraTimeSourceRuntime* const timeSource
  ) noexcept
  {
    return InitializeCameraTimeSourceVtable(timeSource);
  }

  struct CameraTransitionFlagView
  {
    std::uint8_t mUnknown000To00F[0x10]{};
    std::uint8_t mTransitionPending = 0; // +0x10
  };
  static_assert(
    offsetof(CameraTransitionFlagView, mTransitionPending) == 0x10,
    "CameraTransitionFlagView::mTransitionPending offset must be 0x10"
  );

  [[nodiscard]] CameraTransitionFlagView* AsTransitionFlagView(moho::CameraImpl* const camera) noexcept
  {
    return reinterpret_cast<CameraTransitionFlagView*>(camera);
  }

  /**
   * Address: 0x007A6BF0 (FUN_007A6BF0, Moho::CameraImpl::TargetNothing)
   *
   * What it does:
   * Stops entity tracking notifications when needed and resets camera target
   * mode/timing lanes back to untargeted location mode.
   */
  void TargetNothingRuntime(moho::CameraImpl* const camera)
  {
    if (camera->mTargetType == kCameraTargetTypeEntity) {
      camera->BroadcastEvent(moho::SCameraTracking{camera->mName, 0});
    }

    camera->mTargetType = kCameraTargetTypeLocation;
    camera->mTargetTime = 0u;
    camera->mTargetTimeLeft = 0.0f;
  }

  [[nodiscard]] moho::UserEntity* FindSessionEntityById(moho::CWldSession* const session, const std::int32_t entityId)
  {
    return session != nullptr ? session->LookupEntityId(static_cast<moho::EntId>(entityId)) : nullptr;
  }

  void AppendLuaEntityIdArrayToSelectionSet(
    LuaPlus::LuaState* const state,
    const int tableArgIndex,
    moho::WeakSet<moho::UserEntity>& outSet
  )
  {
    lua_State* const rawState = state->m_state;
    const int count = static_cast<int>(lua_getn(rawState, tableArgIndex));
    if (count < 1) {
      return;
    }

    moho::CWldSession* const session = moho::WLD_GetActiveSession();
    for (int entryIndex = 1; entryIndex <= count; ++entryIndex) {
      lua_rawgeti(rawState, tableArgIndex, entryIndex);
      const int stackIndex = lua_gettop(rawState);
      const char* const entityIdText = lua_tostring(rawState, stackIndex);
      if (entityIdText == nullptr) {
        const LuaPlus::LuaStackObject valueArg(state, stackIndex);
        valueArg.TypeError("string");
      }

      const int entityId = entityIdText != nullptr ? std::atoi(entityIdText) : 0;
      if (moho::UserEntity* const entity = FindSessionEntityById(session, entityId); entity != nullptr) {
        (void)outSet.Add(entity);
      }
    }
  }

  [[nodiscard]] moho::UserEntity* ActiveCameraTargetEntity(const moho::CameraImpl& camera) noexcept
  {
    using TargetList = msvc8::list<moho::WeakPtr<moho::UserEntity>>;
    const TargetList::const_iterator active = camera.mActiveTarget;
    if (active == TargetList::const_iterator{} || active == camera.mTargetEntities.end()) {
      return nullptr;
    }
    return active->GetObjectPtr();
  }

  [[nodiscard]] float HeadingFromEntityOrientation(const Wm3::Quatf& orientation) noexcept
  {
    const float headingNumerator = ((orientation.z * orientation.x) + (orientation.y * orientation.w)) * 2.0f;
    const float headingDenominator = 1.0f - ((orientation.y * orientation.y + orientation.x * orientation.x) * 2.0f);
    return static_cast<float>(std::atan2(headingNumerator, headingDenominator));
  }

  [[nodiscard]] float PitchFromEntityOrientation(const Wm3::Quatf& orientation) noexcept
  {
    float pitchCarrier = ((orientation.w * orientation.z) - (orientation.y * orientation.x)) * -2.0f;
    if (pitchCarrier >= 1.0f) {
      pitchCarrier = 1.0f;
    } else if (pitchCarrier < -1.0f) {
      pitchCarrier = -1.0f;
    }

    const float sqrtTerm = std::sqrt(1.0f - pitchCarrier);
    const float poly =
      pitchCarrier *
        ((pitchCarrier * ((pitchCarrier * -0.018729299f) + 0.074261002f)) - 0.21211439f) +
      1.5707288f;
    return 1.5707963f - (sqrtTerm * poly);
  }

  /**
   * Address: 0x007A67C0 (FUN_007A67C0, func_CameraImplUpdateShake)
   *
   * What it does:
   * Builds one per-frame camera shake offset from center/range/time/magnitude
   * lanes and scales it by `cam_ShakeMult`.
   */
  Wm3::Vector3f* func_CameraImplUpdateShake(
    const Wm3::Vector3f* const cameraOffset,
    Wm3::Vector3f* const outShakeOffset,
    moho::SCamShakeState* const shakeParams
  )
  {
    if (shakeParams->mElapsed >= shakeParams->mDuration) {
      outShakeOffset->x = 0.0f;
      outShakeOffset->y = 0.0f;
      outShakeOffset->z = 0.0f;
      return outShakeOffset;
    }

    Wm3::Vector3f shakeDirection{};
    shakeDirection.x = shakeParams->mCenter.x - cameraOffset->x;
    shakeDirection.y = 0.0f;
    shakeDirection.z = shakeParams->mCenter.z - cameraOffset->z;

    const float centerDistance = Wm3::Vector3f::Normalize(&shakeDirection);
    if (centerDistance < 10.0f) {
      shakeDirection.x = static_cast<float>(moho::MathGlobalRandomRange(-1.0f, 1.0f));
      shakeDirection.y = 0.0f;
      shakeDirection.z = static_cast<float>(moho::MathGlobalRandomRange(-1.0f, 1.0f));
      (void)Wm3::Vector3f::Normalize(&shakeDirection);
    }

    float distanceFactor = centerDistance / shakeParams->mMaxRange;
    if (distanceFactor >= 1.0f) {
      distanceFactor = 1.0f;
    }

    const float magnitude =
      (1.0f - (shakeParams->mElapsed / shakeParams->mDuration)) *
      (((shakeParams->mMagnitudeAtMaxRange - shakeParams->mMagnitudeAtCenter) * distanceFactor) + shakeParams->mMagnitudeAtCenter);
    const float radialAmount =
      static_cast<float>(moho::MathGlobalRandomUnitScaled(magnitude)) * shakeParams->mScale * 0.5f;
    const float tangentialAmount = static_cast<float>(moho::MathGlobalRandomRange(-magnitude, magnitude)) * 0.25f;

    outShakeOffset->x = ((shakeDirection.x * radialAmount) + (shakeDirection.z * tangentialAmount)) * moho::cam_ShakeMult;
    outShakeOffset->y = ((shakeDirection.y * radialAmount) + (tangentialAmount * 0.0f)) * moho::cam_ShakeMult;
    outShakeOffset->z =
      ((shakeDirection.z * radialAmount) + ((0.0f - shakeDirection.x) * tangentialAmount)) * moho::cam_ShakeMult;
    return outShakeOffset;
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& UserLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("User"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("User");
    return fallbackSet;
  }

} // namespace

namespace moho
{
  CScrLuaMetatableFactory<CameraImpl> CScrLuaMetatableFactory<CameraImpl>::sInstance{};

  CScrLuaMetatableFactory<CameraImpl>& CScrLuaMetatableFactory<CameraImpl>::Instance()
  {
    return sInstance;
  }

  LuaPlus::LuaObject CScrLuaMetatableFactory<CameraImpl>::Create(LuaPlus::LuaState* const state)
  {
    return SCR_CreateSimpleMetatable(state);
  }

  /**
   * Address: 0x007B0A90 (FUN_007B0A90, func_CreateLuaCameraImpl)
   *
   * What it does:
   * Returns cached `CameraImpl` metatable object from Lua object-factory
   * storage.
   */
  LuaPlus::LuaObject* func_CreateLuaCameraImpl(LuaPlus::LuaObject* const object, LuaPlus::LuaState* const state)
  {
    if (object == nullptr) {
      return nullptr;
    }

    *object = CScrLuaMetatableFactory<CameraImpl>::Instance().Get(state);
    return object;
  }
} // namespace moho

/**
 * Address: 0x007AAC60 (FUN_007AAC60, ??1RCamCamera@Moho@@UAE@XZ,
 * Moho::RCamCamera::~RCamCamera)
 *
 * What it does:
 * Removes this camera from `RCamManager` ownership; the `Broadcaster` base's
 * destructor then unlinks the tracking ring (0x007AAC9D). Every live
 * `RCamCamera` subobject is the first base of a `CameraImpl` complete
 * object (see the class doc comment in CameraImpl.h), so `this` safely
 * converts back to the owning camera with zero pointer adjustment. Runs
 * automatically, chained after `CameraImpl::~CameraImpl`'s body, via
 * ordinary C++ base-destructor chaining.
 */
moho::RCamCamera::~RCamCamera()
{
  auto* const camera = static_cast<moho::CameraImpl*>(this);

  if (RCamManager* const manager = CAM_GetManager(); manager != nullptr) {
    manager->ForgetCamera(camera);
  }
}

/**
 * Address: 0x007A7950 (FUN_007A7950, ??0CameraImpl@Moho@@QAE@VStrArg@gpg@@ABVSTIMap@1@PAVLuaState@LuaPlus@@@Z)
 * Mangled: ??0CameraImpl@Moho@@QAE@VStrArg@gpg@@ABVSTIMap@1@PAVLuaState@LuaPlus@@@Z
 *
 * IDA signature:
 * Moho::CameraImpl *__stdcall Moho::CameraImpl::CameraImpl(
 *     Moho::CameraImpl *this, const char *name, Moho::STIMap *stiMap,
 *     LuaPlus::LuaState *state);
 *
 * What it does:
 * Builds one runtime camera in place over the 0x858-byte block that
 * `RCamManager::CreateCamera` allocates with `operator new(0x858)`. Self-links
 * the `RCamCamera` broadcaster base, constructs the `CScriptEvent` sub-object
 * at +0x0C, copies the camera name into `mName`, binds the terrain `STIMap`,
 * constructs the embedded `GeomCamera3`, and zero-seeds every camera state lane
 * (mode flags, zoom/pivot lanes, timed-move / Hermite transition deltas, and
 * the camera-shake parameter block with its scale seeded to 1.0). Allocates the
 * intrusive target-entity list head sentinel, nulls both `ITimeSource` slots and
 * installs a fresh `SystemTimeSource` (index 0) and `GameTimeSource` (index 1),
 * primes the three inline frustum weak-vector lanes, seeds the max-zoom
 * multiplier (1.4) and vertical-zoom metric scale (1.0), publishes the camera's
 * Lua object through `CScriptObject::CreateLuaObject`, then applies the default
 * unit viewport and runs one `CameraReset` to snap the initial basis.
 *
 * Sole caller: `RCamManager::CreateCamera` (0x007AA9C0, recovered in
 * src/sdk/moho/render/RCamManager.cpp), which placement-constructs this object.
 */
gpg::RType* moho::CameraImpl::sType = nullptr;

/**
 * Address: 0x007A6990 (FUN_007A6990, ?StaticGetClass@CameraImpl@Moho@@SAPAVRType@gpg@@XZ)
 */
gpg::RType* moho::CameraImpl::StaticGetClass()
{
  if (!sType) {
    sType = gpg::LookupRType(typeid(CameraImpl));
  }
  return sType;
}

/**
 * Address: 0x007A69B0 (FUN_007A69B0, ?GetClass@CameraImpl@Moho@@UBEPAVRType@gpg@@XZ)
 */
gpg::RType* moho::CameraImpl::GetClass() const
{
  return StaticGetClass();
}

moho::CameraImpl::CameraImpl(const gpg::StrArg name, const STIMap& map, LuaPlus::LuaState* const state)
  : RCamCamera()
  , CScriptEvent()
  // `std::string::string(name, strlen(name))` and the embedded solid-frustum
  // camera's default constructor. Both are members, so the compiler emits
  // these two constructions here from the initializer list -- placement-new
  // in the body would run them a second time over an already-live object.
  , mName(name, std::strlen(name))
  , mCam()
{
  // `RCamCamera` (vtable + broadcaster ring, +0x00..+0x0C) and
  // `CScriptEvent` (+0x0C..+0x50) are both real C++ bases and already fully
  // constructed by the initializer list above.

  // Bind terrain-map context.
  mTerrainMap = const_cast<moho::STIMap*>(&map);

  // Scalar state lanes seeded by the constructor.
  mVerticalZoomMetricScale = 1.0f;
  mIsOrtho = 0u;
  mIsRotated = 0u;
  mRevertRotation = 0u;
  mTargetZoom = 0.0f;
  mZoom = 0.0f;
  mPivot.x = 0.0f;
  mPivot.y = 0.0f;


  // Default to the wall-clock (System) time source and null both slots before
  // installing them (mirrors the binary's 2-element eh-vector zero-fill).
  mTimeSource = kCameraTimeSourceSystem;
  mTimeSources[0] = nullptr;
  mTimeSources[1] = nullptr;
  mLastFrameTime = 0.0f;

  // Timed-move / Hermite transition delta lanes (all zero at construction).
  mTimedMoveOffset = Wm3::Vec3f{0.0f, 0.0f, 0.0f};
  mTimedMoveZoom = 0.0f;
  mTimedMoveDuration = 0.0f;
  mTimedMoveTransitionParam = 0.0f;
  mTimedMoveStartTime = 0.0f;
  mTimedMovePitch = 0.0f;
  mTimedMoveHeading = 0.0f;
  mHermiteOffsetStartDelta = Wm3::Vec3f{0.0f, 0.0f, 0.0f};
  mHermiteOffsetEndDelta = Wm3::Vec3f{0.0f, 0.0f, 0.0f};
  mHermiteHeadingStartDelta = 0.0f;
  mHermiteHeadingEndDelta = 0.0f;
  mHermitePitchStartDelta = 0.0f;
  mHermitePitchEndDelta = 0.0f;
  mHermiteZoomStartDelta = 0.0f;
  mHermiteZoomEndDelta = 0.0f;

  // Camera-shake parameter block: zero every field, seed the shake scale to 1.0
  // (+0x448, byte-verified `a7` = 1.0 in .rdata).
  mCamShakeParams.mCenter = Wm3::Vec3f{0.0f, 0.0f, 0.0f};
  mCamShakeParams.mMaxRange = 0.0f;
  mCamShakeParams.mMagnitudeAtCenter = 0.0f;
  mCamShakeParams.mMagnitudeAtMaxRange = 0.0f;
  mCamShakeParams.mDuration = 0.0f;
  mCamShakeParams.mElapsed = 0.0f;
  mCamShakeParams.mScale = 1.0f;

  mCanShake = 1u;
  mAccType = kCameraAccTypeLinear;
  mFrustumCacheTimer = 0.0f;
  mFrustumCacheZoomMark = 0.0f;

  // Max-zoom multiplier (+0x850, byte-verified `dword_E4F98C` = 1.4).
  mMaxZoomMult = 1.4f;

  // Install the two heap-owned time sources. Each `new` allocates a vtable-only
  // node (`operator new(4)` + vtable store in the binary); the swap-and-release
  // of the prior slot value is inert here because both slots were just nulled.
  mTimeSources[0] = new SystemTimeSource();
  mTimeSources[1] = new GameTimeSource();

  // Publish the camera's script-side Lua object. The binary constructs three
  // empty Lua argument objects plus the cached `CameraImpl` metatable, then
  // hands them to the `CScriptObject` sub-object's `CreateLuaObject`, called
  // through `this` (the complete `CameraImpl` object) so the `CScriptObject*`
  // `SetLuaObject` publishes as `_c_object` -- and every downstream
  // `typeid(*object)` reflection lookup that reads it back, e.g.
  // `gpg::RRef_CScriptObject` -- resolves the object's dynamic type as
  // `CameraImpl`, not merely the `CScriptEvent` base subobject. Publishing
  // through a detached, non-base `CScriptEvent` (as an earlier, non-inheriting
  // recovery of this class did) reports the narrower dynamic type instead,
  // and every `SCR_FromLua_CameraImpl` upcast for that camera fails with
  // "Incorrect type of game object."
  {
    LuaPlus::LuaObject luaArg3{};
    LuaPlus::LuaObject luaArg2{};
    LuaPlus::LuaObject luaArg1{};
    LuaPlus::LuaObject luaMetatable{};
    func_CreateLuaCameraImpl(&luaMetatable, state);
    static_cast<moho::CScriptObject*>(this)
      ->CreateLuaObject(luaMetatable, luaArg1, luaArg2, luaArg3);
  }

  // Default unit viewport (origin {0,0}, extent {1,1}) then snap the basis.
  const Wm3::Vector2f viewportOrigin{0.0f, 0.0f};
  const Wm3::Vector2f viewportSize{1.0f, 1.0f};
  CameraSetViewport(viewportOrigin, viewportSize);
  CameraReset();
  // TEMPORARY PROBE (do not commit)
  gpg::Warnf("[CAMDIAG] ctor name=%s this=%08X", mName.c_str(),
             static_cast<unsigned>(reinterpret_cast<std::uintptr_t>(this)));
}

/**
 * Address: 0x007A7F00 (FUN_007A7F00, ??1CameraImpl@Moho@@UAE@XZ)
 * Mangled: ??1CameraImpl@Moho@@UAE@XZ
 *
 * IDA signature:
 * Moho::Broadcaster *__stdcall Moho::CameraImpl::~CameraImpl(int a1);
 *
 * What it does:
 * Reverses construction of one runtime camera. Detaches each of the three
 * inline frustum/spotter weak-vector lanes from their tracked entity owners
 * and releases any heap-grown storage. `mTargetEntities` goes as a member
 * (`clear` 0x007AE580, then the head). Releases the two
 * heap-allocated `CameraTimeSourceRuntime` slots (`SystemTimeSource` at index
 * 0 and `GameTimeSource` at index 1) through their scalar-deleting vtable
 * slot (mirroring the binary's `eh vector destructor iterator`). Destroys
 * the embedded `GeomCamera3` and `msvc8::string` name lanes, runs
 * `CScriptEvent::~CScriptEvent` on the sub-object at +0x0C, and finally
 * chains through `RCamCamera::~RCamCamera` (via `DetachRuntimeCameraBase`)
 * to forget this camera from the global manager and rejoin the broadcaster
 * ring to its self-linked idle state.
 *
 * Reached from the scalar-deleting wrapper at vtable slot 0 (FUN_007A7DC0),
 * which is referenced by the `CameraImpl` vtable at 0x00E3C474 and its
 * `CScriptEvent` / `CScriptObject` sub-object vtable thunks. The wrapper is
 * invoked at runtime via `delete camera` from `RCamManager::~RCamManager`
 * (0x007AA930).
 *
 * That wrapper is MSVC's own emission for a class with a virtual destructor
 * (`??_ECameraImpl@moho@@UAEPAXI@Z`), not a function anyone wrote: the
 * compiler produces it from `virtual ~RCamCamera()` and puts it in slot 0.
 * It used to be hand-written here as a virtual named `operator_delete`,
 * which gave the class a forty-fifth slot that nothing ever called and that
 * displaced every method below it.
 *
 * The `mTimeSources` cleanup loop below is the typed recovery of
 * `FUN_007AE630` (`ReleaseOwnedRuntimePointerSlotWithDeleteFlag`,
 * WinApiImportThunks.cpp): the binary passes `&sub_7AE630` as the
 * per-element destructor callback into the compiler's
 * `_eh_vector_destructor_iterator`-style helper (0x00A83AAC, `count=2,
 * elementSize=4`) at instruction 0x007A800D. `sub_7AE630` reads one owned
 * pointer from the slot and dispatches its own vtable slot 1 with delete
 * flag 1 -- exactly what `delete source` below compiles to for a
 * `CameraTimeSourceRuntime*` slot.
 */
moho::CameraImpl::~CameraImpl()
{
  // Detach the three inline weak-vector lanes (entity-tracker lists) used by
  // CameraImpl: the per-frame army-units-in-frustum cache at +0x700 first,
  // then the two rotating spotter lanes at +0x5B0 and +0x460. The binary
  // tears these down in reverse-construction order; each lane unlinks every
  // still-attached weak ref from its owner chain before releasing heap
  // storage.
  mArmyUnitsInFrustum.ResetStorageToInline();
  mFrustumLaneB.ResetStorageToInline();
  mFrustumLaneA.ResetStorageToInline();

  // Release both heap-owned `CameraTimeSourceRuntime` slots via their virtual
  // scalar-deleting destructor (vtable slot 1). Only indices 0 and 1 are
  // populated (`SystemTimeSource` and `GameTimeSource`); index 2 is unused.
  // The binary uses an `eh vector destructor iterator` over the two slots,
  // with `FUN_007AE630` as the per-element delete callback (see this
  // function's own doc comment above for the full citation).
  for (auto*& source : std::span{mTimeSources, 2}) {
    delete source;
    source = nullptr;
  }

  // The embedded `GeomCamera3` (which releases solid-frustum heap storage)
  // and the `mName` `msvc8::string` are destroyed by the compiler after this
  // body returns, because both are members. The binary's teardown of those
  // two lanes is that emitted epilogue, not a source line -- destroying them
  // explicitly here would run each destructor twice and double-free the
  // frustum storage.

  // `CScriptEvent` (+0x0C) and `RCamCamera` (+0x00, forgetting this camera
  // from the global manager and rejoining the broadcaster sentinel -- see
  // `RCamCamera::~RCamCamera`) are both real bases now and tear down
  // automatically, in reverse construction order, once this body returns.
}

/**
 * Address: 0x007A6E70 (FUN_007A6E70)
 * Mangled: ?CameraSetAccType@CameraImpl@Moho@@QAEXABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z
 *
 * What it does:
 * Applies one camera acceleration mode token to runtime lane `mAccType`.
 */
void moho::CameraImpl::CameraSetAccType(const msvc8::string& accType)
{
  if (_stricmp(accType.c_str(), kCameraAccTypeLinearName) == 0) {
    mAccType = kCameraAccTypeLinear;
    return;
  }

  if (_stricmp(accType.c_str(), kCameraAccTypeFastInSlowOutName) == 0) {
    mAccType = kCameraAccTypeFastInSlowOut;
    return;
  }

  if (_stricmp(accType.c_str(), kCameraAccTypeSlowInOutName) == 0) {
    mAccType = kCameraAccTypeSlowInOut;
  }
}

/**
 * Address: 0x007A6CE0 (FUN_007A6CE0, Moho::CameraImpl::CameraSpin)
 * Mangled: ?CameraSpin@CameraImpl@Moho@@UAEXABV?$Vector2@M@Wm3@@@Z
 *
 * What it does:
 * Applies heading/pitch spin deltas from one 2D input vector using the current
 * zoom metric scale, then normalizes heading and clamps pitch.
 */
void moho::CameraImpl::CameraSpin(const Wm3::Vector2f& spinDelta)
{
  // 0x007A6CFB divides `cam_SpinSpeed` by `[this+0x32C]`. `mCam` sits at +0x070 and
  // `GeomCamera3::viewport` at +0x284 within it, so +0x32C is `viewport.r[3].z` --
  // the viewport WIDTH in pixels ({X, Y, Width, Height}, the same lanes
  // `GeomCamera3::Unproject` reads). Spin is normalised per pixel of drag so that a
  // full-width sweep turns the same amount at any resolution. This divided by
  // `mVerticalZoomMetricScale` (+0x338, the ~1.33 aspect ratio) instead, making every
  // mouse pixel rotate the camera roughly 770x too far.
  const float spinScale = (cam_SpinSpeed / mCam.viewport.r[3].z) * kDegreesToRadians;
  const float headingDelta = spinDelta.x * spinScale;
  const float pitchDelta = spinDelta.y * spinScale;

  mIsRotated = 1u;
  mRevertRotation = 0u;

  CameraSetHeading(moho::NormalizeAngleSignedRadians(mHeading - headingDelta));

  float pitch = mFarPitch + pitchDelta;
  if (pitch > kCameraSpinPitchUpperBound) {
    pitch = kCameraSpinPitchUpperBound;
  }
  if (pitch < cam_MinSpinPitch) {
    pitch = cam_MinSpinPitch;
  }

  CameraSetPitch(pitch);
}

/**
 * Address: 0x007A8260 (FUN_007A8260, Moho::CameraImpl::CameraZoom)
 * Mangled: ?CameraZoom@CameraImpl@Moho@@UAEXM@Z
 *
 * What it does:
 * Applies exponential zoom scaling from one input delta and clamps the
 * resulting near-zoom lane against min/max zoom bounds.
 */
void moho::CameraImpl::CameraZoom(const float zoomDelta)
{
  mNearZoom = std::exp2((-cam_ZoomAmount) * zoomDelta) * mNearZoom;

  const float maxZoom = GetMaxZoom();
  float clampedZoom = mNearZoom;
  if (maxZoom <= clampedZoom) {
    clampedZoom = maxZoom;
  }
  if (cam_NearZoom > clampedZoom) {
    clampedZoom = cam_NearZoom;
  }

  mNearZoom = clampedZoom;
}

/**
 * Address: 0x007A6DF0 (FUN_007A6DF0, Moho::CameraImpl::CameraSetPitch)
 * Mangled: ?CameraSetPitch@CameraImpl@Moho@@UAEXM@Z
 *
 * What it does:
 * Arms rotated mode, clears revert state, and stores current pitch lane.
 */
void moho::CameraImpl::CameraSetPitch(const float pitchRadians)
{
  mIsRotated = 1u;
  mRevertRotation = 0u;
  mFarPitch = pitchRadians;
}

/**
 * Address: 0x007A6E10 (FUN_007A6E10, Moho::CameraImpl::CameraSetHeading)
 * Mangled: ?CameraSetHeading@CameraImpl@Moho@@UAEXM@Z
 *
 * What it does:
 * Arms rotated mode, clears revert state, and stores current heading lane.
 */
void moho::CameraImpl::CameraSetHeading(const float headingRadians)
{
  mIsRotated = 1u;
  mRevertRotation = 0u;
  mHeading = headingRadians;
}

/**
 * Address: 0x007A6DE0 (FUN_007A6DE0, Moho::CameraImpl::CameraHoldRotation)
 * Mangled: ?CameraHoldRotation@CameraImpl@Moho@@QAEXXZ
 *
 * What it does:
 * Arms camera rotation hold mode and clears any pending revert flag.
 */
void moho::CameraImpl::CameraHoldRotation()
{
  mIsRotated = 1u;
  mRevertRotation = 0u;
}

/**
 * Address: 0x007A6E40 (FUN_007A6E40, Moho::CameraImpl::CameraRevertRotation)
 * Mangled: ?CameraRevertRotation@CameraImpl@Moho@@UAEXXZ
 *
 * What it does:
 * Schedules a rotation revert when the camera is currently in rotated mode.
 */
void moho::CameraImpl::CameraRevertRotation()
{
  if (mIsRotated == 0u) {
    return;
  }

  mRevertRotation = 1u;
  if (mTargetType != kCameraTargetTypeEntity) {
    mTargetType = kCameraTargetTypeLocation;
  }
}

/**
 * Address: 0x007A8240 (FUN_007A8240, Moho::CameraImpl::CameraSetPivot)
 * Slot: 30 (+0x78 of ??_7CameraImpl@Moho@@6B@)
 *
 * IDA signature:
 * Wm3::Vector2f *__thiscall Moho::CameraImpl::CameraSetPivot(
 *     Moho::CameraImpl *this@<ecx>, Wm3::Vector2f *pivot);
 *
 * What it does:
 * Parks the screen-space point the next zoom or spin should pivot around.
 * The whole body is two float stores - 0x007A8246 `fstp dword ptr [ecx+36Ch]`
 * and 0x007A824F `fstp dword ptr [ecx+370h]` - which is exactly
 * `CameraImpl::mPivot`. The `Wm3::Vector2f*` in the IDA signature
 * is the incoming argument still sitting in `eax` at `retn 4`; no call site
 * reads it, so this is modelled as returning `void`.
 */
void moho::CameraImpl::CameraSetPivot(const Wm3::Vector2f& pivot)
{
  mPivot.x = pivot.X();
  mPivot.y = pivot.Y();
}

/**
 * Address: 0x007A80A0 (FUN_007A80A0, Moho::CameraImpl::CameraReset)
 * Mangled: ?CameraReset@CameraImpl@Moho@@UAEXXZ
 *
 * What it does:
 * Resets runtime camera orientation/target lanes to map-centered defaults.
 */
void moho::CameraImpl::CameraReset()
{
  // TEMPORARY PROBE (do not commit)
  {
    static int sBudget = 0;
    if (sBudget < 20) {
      ++sBudget;
      gpg::Warnf("[CAMDIAG] Reset name=%s this=%08X type=%d targetZoom=%.1f near=%.1f dur=%.2f",
                 mName.c_str(), static_cast<unsigned>(reinterpret_cast<std::uintptr_t>(this)),
                 mTargetType, mTargetZoom, mNearZoom, mTimedMoveDuration);
    }
  }

  mFarFov = cam_FarFOV * kDegreesToRadians;
  mHeading = kPi;
  mIsRotated = 0u;
  // 0x007A80EB..0x007A8116: the far pitch is stored into both the far-pitch
  // (+0x344) and current-pitch (+0x348) lanes, the nose-cam adjust (+0x3D0)
  // is zeroed, and the heading-zoom lane (+0x350) gets the same pi constant
  // as the heading (+0x34C), so a Hermite transition started right after a
  // reset holds the current heading and pitch instead of swinging to 0.
  mFarPitch = cam_FarPitch * kDegreesToRadians;
  mCurrentPitch = mFarPitch;
  mNoseCamPitchAdjust = 0.0f;
  mHeadingZoom = kPi;
  mEnableEaseInOut = 1u;

  mTargetLocation = {};
  if (const STIMap* const terrainMap = mTerrainMap; terrainMap != nullptr) {
    if (const CHeightField* const heightField = terrainMap->GetHeightField(); heightField != nullptr) {
      mTargetLocation.x = static_cast<float>(heightField->width - 1) * 0.5f;
      mTargetLocation.z = static_cast<float>(heightField->height - 1) * 0.5f;
      float targetElevation = heightField->GetElevation(mTargetLocation.x, mTargetLocation.z);
      if (terrainMap->IsWaterEnabled()) {
        const float waterElevation = terrainMap->GetWaterElevation();
        if (waterElevation > targetElevation) {
          targetElevation = waterElevation;
        }
      }
      mTargetLocation.y = targetElevation;
    }
  }

  mNearZoom = GetMaxZoom();
  mHeadingRate = 0.0f;
  mZoomRate = 0.0f;
  mTargetType = kCameraTargetTypeLocation;
  mTargetTime = 0u;
  mTargetTimeLeft = 0.0f;
  mOffset = mTargetLocation;
  mTargetZoom = mNearZoom;
}

/**
 * Address: 0x007A71B0 (FUN_007A71B0, Moho::CameraImpl::CameraFollow)
 * Mangled: ?CameraFollow@CameraImpl@Moho@@UAEXABUSCamFollowParams@2@@Z
 *
 * What it does:
 * Promotes one follow target into the active camera target list when the
 * current entity-id gate still matches.
 */
void moho::CameraImpl::CameraFollow(const SCamFollowParams& followParams)
{
  UserEntity* const currentTarget = GetTargetEntity();
  if (currentTarget == nullptr || currentTarget->mParams.mEntityId != followParams.mCurrentEntityId) {
    return;
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    return;
  }

  UserEntity* const nextTarget = FindSessionEntityById(session, followParams.mTargetEntityId);
  if (nextTarget == nullptr) {
    return;
  }

  // 0x007AE4E0: the new node goes in at the end and becomes the active target.
  mActiveTarget = mTargetEntities.insert(mTargetEntities.end(), WeakPtr<UserEntity>(nextTarget));

  mTargetTimeLeft = followParams.mTargetTimeLeft;
}

/**
 * Address: 0x007A69D0 (FUN_007A69D0, Moho::CameraImpl::GetDerivedObjectRef)
 * Mangled: ?GetDerivedObjectRef@CameraImpl@Moho@@UAE?AVRRef@gpg@@XZ
 *
 * What it does:
 * Overrides `CScriptEvent::GetDerivedObjectRef` (which packs only the
 * `CScriptEvent` sub-object) to pack `{this, GetClass()}` for the complete
 * `CameraImpl` object instead. Dispatched through the `CScriptObject`
 * sub-object's vtable slot, so callers holding only a `CScriptObject*`/
 * `CScriptEvent*` view still reach this override; the compiler-generated
 * this-adjustor thunk for that slot corrects `this` back to the `CameraImpl`
 * base before entering this body, so no manual offset math is needed here.
 */
gpg::RRef moho::CameraImpl::GetDerivedObjectRef()
{
  gpg::RRef objectRef{};
  objectRef.mObj = this;
  objectRef.mType = GetClass();
  return objectRef;
}

/**
 * Address: 0x007A69F0 (FUN_007A69F0, Moho::CameraImpl::CameraGetName)
 *
 * What it does:
 * Returns the camera runtime name-string buffer.
 */
const char* moho::CameraImpl::CameraGetName() const
{
  return mName.c_str();
}

/**
 * Address: 0x007A6A00 (FUN_007A6A00, Moho::CameraImpl::CameraGetView)
 *
 * What it does:
 * Returns one read-only view of the embedded camera transform/projection state.
 */
const moho::GeomCamera3& moho::CameraImpl::CameraGetView() const
{
  return mCam;
}

/**
 * Address: 0x007A6A80 (FUN_007A6A80, Moho::CameraImpl::CameraSetViewport)
 * Mangled: ?CameraSetViewport@CameraImpl@Moho@@QAEPAV?$Vector2@M@Wm3@@ABV34@0@Z
 *
 * What it does:
 * Stores viewport origin/extent lanes in camera state, rebuilds normalized
 * row-2 viewport coefficients from row-1 using inverse width, and updates
 * camera zoom metric scale from viewport aspect ratio.
 */
void moho::CameraImpl::CameraSetViewport(const Wm3::Vector2f& viewportOrigin, const Wm3::Vector2f& viewportSize)
{
  VMatrix4& viewport = mCam.viewport;

  viewport.r[3].x = viewportOrigin.x;
  viewport.r[3].y = viewportOrigin.y;
  viewport.r[3].z = viewportSize.x;
  viewport.r[3].w = viewportSize.y;

  const float inverseViewportWidth = 1.0f / viewport.r[3].z;
  viewport.r[2].x = viewport.r[1].x * inverseViewportWidth;
  viewport.r[2].y = viewport.r[1].y * inverseViewportWidth;
  viewport.r[2].z = viewport.r[1].z * inverseViewportWidth;
  viewport.r[2].w = viewport.r[1].w * inverseViewportWidth;

  mVerticalZoomMetricScale = viewportSize.x / viewportSize.y;
}

/**
 * Address: 0x007A6A10 (FUN_007A6A10, Moho::CameraImpl::CameraSetOrtho)
 * Mangled: ?CameraSetOrtho@CameraImpl@Moho@@UAEX_N@Z
 *
 * What it does:
 * Stores orthographic-camera mode flag lane.
 */
void moho::CameraImpl::CameraSetOrtho(const bool enabled)
{
  mIsOrtho = static_cast<std::uint8_t>(enabled ? 1 : 0);
}

/**
 * Address: 0x007A6A30 (FUN_007A6A30, Moho::CameraImpl::SetTimeSource)
 * Mangled: ?SetTimeSource@CameraImpl@Moho@@QAEXW4ECamTimeSource@2@@Z
 *
 * What it does:
 * Stores the active runtime time-source selector in the camera runtime view.
 */
void moho::CameraImpl::SetTimeSource(const ECamTimeSource timeSource)
{
  mTimeSource = static_cast<std::int32_t>(timeSource);
}

/**
 * Address: 0x007A6A20 (FUN_007A6A20, Moho::CameraImpl::CameraIsOrtho)
 *
 * What it does:
 * Returns orthographic-camera mode flag lane.
 */
bool moho::CameraImpl::CameraIsOrtho()
{
  return mIsOrtho != 0;
}

/**
 * Address: 0x007A6B20 (FUN_007A6B20, Moho::CameraImpl::CameraGetViewport)
 *
 * What it does:
 * Returns current camera viewport origin and viewport size lanes.
 */
void moho::CameraImpl::CameraGetViewport(Wm3::Vector2f& viewportOrigin, Wm3::Vector2f& viewportSize) const
{
  const VMatrix4& viewport = mCam.viewport;
  viewportOrigin.x = viewport.r[3].x;
  viewportOrigin.y = viewport.r[3].y;
  viewportSize.x = viewport.r[3].z;
  viewportSize.y = viewport.r[3].w;
}

/**
 * Address: 0x007A6C90 (FUN_007A6C90, Moho::CameraImpl::CameraGetZoom)
 *
 * What it does:
 * Returns current camera zoom lane.
 */
float moho::CameraImpl::CameraGetZoom() const
{
  return mZoom;
}

/**
 * Address: 0x007A6CC0 (FUN_007A6CC0, Moho::CameraImpl::CameraGetHeading)
 * Mangled: ?CameraGetHeading@CameraImpl@Moho@@UBEMXZ
 *
 * What it does:
 * Returns current camera heading lane in radians.
 */
float moho::CameraImpl::CameraGetHeading() const
{
  return mHeading;
}

/**
 * Address: 0x007A6CD0 (FUN_007A6CD0, Moho::CameraImpl::CameraGetPitch)
 * Mangled: ?CameraGetPitch@CameraImpl@Moho@@UBEMXZ
 *
 * What it does:
 * Returns current camera pitch lane in radians.
 */
float moho::CameraImpl::CameraGetPitch() const
{
  return mFarPitch;
}

/**
 * Address: 0x007A6E30 (FUN_007A6E30, Moho::CameraImpl::CameraIsRotated)
 * Mangled: ?CameraIsRotated@CameraImpl@Moho@@UBE_NXZ
 *
 * What it does:
 * Returns whether rotated-camera mode is currently enabled.
 */
bool moho::CameraImpl::CameraIsRotated() const
{
  return mIsRotated != 0;
}

/**
 * Address: 0x007A6B50 (FUN_007A6B50, ?Project@CameraImpl@Moho@@UBE?AV?$Vector2@M@Wm3@@ABV?$Vector3@M@4@@Z)
 *
 * What it does:
 * Projects one world-space point through the embedded camera view and
 * returns screen-space coordinates.
 */
Wm3::Vector2f moho::CameraImpl::Project(const Wm3::Vector3f& worldPoint) const
{
  return mCam.Project(worldPoint);
}

/**
 * Address: 0x007A6B70 (FUN_007A6B70, ?Unproject@CameraImpl@Moho@@UBE?AU?$GeomLine3@M@2@ABV?$Vector2@M@Wm3@@@Z)
 *
 * What it does:
 * Builds one world-space ray from a screen-space point using the embedded
 * camera view/projection/viewport lanes.
 */
moho::GeomLine3 moho::CameraImpl::Unproject(const Wm3::Vector2f& screenPoint) const
{
  return mCam.Unproject(screenPoint);
}

/**
 * Address: 0x007A6BB0 (FUN_007A6BB0, ?CameraScreenToSurface@CameraImpl@Moho@@UBE?AV?$Vector3@M@Wm3@@ABV?$Vector2@M@4@@Z)
 *
 * What it does:
 * Unprojects one screen-space point and resolves the terrain/water surface
 * intersection point on the active map.
 */
Wm3::Vector3f moho::CameraImpl::CameraScreenToSurface(const Wm3::Vector2f& screenPoint) const
{
  const GeomLine3 worldRay = Unproject(screenPoint);
  return mTerrainMap->SurfaceIntersection(worldRay, nullptr);
}

/**
 * Address: 0x007A72F0 (FUN_007A72F0, ?SetLODScale@CameraImpl@Moho@@UAEXM@Z)
 *
 * What it does:
 * Updates embedded camera LOD scale used by projection/unprojection lanes.
 */
void moho::CameraImpl::SetLODScale(const float scale)
{
  mCam.SetLODScale(scale);
}

/**
 * Address: 0x007A7120 (FUN_007A7120, Moho::CameraImpl::CanShake)
 * Mangled: ?CanShake@CameraImpl@Moho@@UAEX_N@Z
 *
 * What it does:
 * Enables or disables camera-shake application for this camera runtime.
 */
void moho::CameraImpl::CanShake(const bool canShake)
{
  mCanShake = canShake ? 1u : 0u;
}

/**
 * Address: 0x007A7130 (FUN_007A7130, Moho::CameraImpl::CameraShake)
 * Mangled: ?CameraShake@CameraImpl@Moho@@UAEXABUSCamShakeParams@2@@Z
 *
 * What it does:
 * Arms camera shake params when shaking is enabled and either the previous
 * shake finished or incoming shake has stronger minimum magnitude.
 */
void moho::CameraImpl::CameraShake(const SCamShakeParams& shakeParams)
{
  if (mCanShake == 0u) {
    return;
  }

  if (
    mCamShakeParams.mElapsed < mCamShakeParams.mDuration &&
    shakeParams.mMagnitudeAtCenter <= mCamShakeParams.mMagnitudeAtCenter
  ) {
    return;
  }

  mCamShakeParams.mCenter = shakeParams.mCenter;
  mCamShakeParams.mMaxRange = shakeParams.mMaxRange;
  mCamShakeParams.mMagnitudeAtCenter = shakeParams.mMagnitudeAtCenter;
  mCamShakeParams.mMagnitudeAtMaxRange = shakeParams.mMagnitudeAtMaxRange;
  mCamShakeParams.mDuration = shakeParams.mDuration;
  mCamShakeParams.mElapsed = 0.0f;
}

/**
 * Address: 0x007A7290 (FUN_007A7290, Moho::CameraImpl::GetTargetEntity)
 * Mangled: ?GetTargetEntity@CameraImpl@Moho@@UBEPAVUserEntity@2@XZ
 *
 * What it does:
 * Returns current live entity target when target mode is entity/nose-cam.
 */
moho::UserEntity* moho::CameraImpl::GetTargetEntity() const
{
  if (mTargetType != kCameraTargetTypeEntity && mTargetType != kCameraTargetTypeNoseCam) {
    return nullptr;
  }

  return ActiveCameraTargetEntity(*this);
}

/**
 * Address: 0x007A73E0 (FUN_007A73E0, Moho::CameraImpl::GetTargetPosition)
 * Mangled: ?GetTargetPosition@CameraImpl@Moho@@UBE?AV?$Vector3@M@Wm3@@XZ
 *
 * What it does:
 * Returns current target-position lane by value.
 */
Wm3::Vector3f moho::CameraImpl::GetTargetPosition() const
{
  return mTargetLocation;
}

/**
 * Address: 0x007A7900 (FUN_007A7900, Moho::CameraImpl::GetAllUnitsInFrustum)
 * Slot: 40 (see header for the byte-verified vtable evidence)
 *
 * What it does:
 * One-line accessor returning the camera's unfiltered "every unit currently
 * in frustum" lane (`mFrustumLaneB`, +0x5B0) - the sibling `mFrustumLaneA`
 * at +0x460 and `mArmyUnitsInFrustum` at +0x700 are separate lanes for
 * different consumers.
 */
gpg::core::FastVectorInline<moho::WeakPtr<moho::UserEntity>>* moho::CameraImpl::GetAllUnitsInFrustum()
{
  return &mFrustumLaneB;
}

/**
 * Address: 0x007A7910 (FUN_007A7910, Moho::CameraImpl::GetArmyUnitsInFrustum)
 *
 * What it does:
 * Returns one cached weak-vector view of focus-army units currently in camera
 * frustum.
 */
gpg::core::FastVectorInline<moho::WeakPtr<moho::UserEntity>>* moho::CameraImpl::GetArmyUnitsInFrustum()
{
  return &mArmyUnitsInFrustum;
}

/**
 * Address: 0x007A6C80 (FUN_007A6C80, Moho::CameraImpl::CameraGetOffset)
 *
 * What it does:
 * Returns one read-only camera target/offset vector lane.
 */
const Wm3::Vec3f& moho::CameraImpl::CameraGetOffset() const
{
  return mOffset;
}

/**
 * Address: 0x007A6CA0 (FUN_007A6CA0, Moho::CameraImpl::CameraGetTargetZoom)
 *
 * What it does:
 * Returns the active camera target-zoom scalar.
 */
float moho::CameraImpl::CameraGetTargetZoom() const
{
  return mTargetZoom;
}

/**
 * Address: 0x007A7310 (FUN_007A7310, Moho::CameraImpl::GetMaxZoom)
 *
 * What it does:
 * Computes max zoom from terrain dimensions, playable-rect policy, border size,
 * and camera zoom-multiplier runtime lanes.
 */
float moho::CameraImpl::GetMaxZoom() const
{
  const STIMap* const terrainMap = mTerrainMap;
  const CHeightField* const heightField = terrainMap != nullptr ? terrainMap->GetHeightField() : nullptr;

  int minX = 0;
  int minZ = 0;
  int maxX = (heightField != nullptr) ? (heightField->width - 1) : 0;
  int maxZ = (heightField != nullptr) ? (heightField->height - 1) : 0;

  bool useWholeMapBounds = false;
  if (const CWldSession* const session = WLD_GetActiveSession(); session != nullptr) {
    const int focusArmyIndex = session->FocusArmy;
    if (focusArmyIndex >= 0) {
      const std::size_t vectorIndex = static_cast<std::size_t>(focusArmyIndex);
      UserArmy* const focusArmy =
        (vectorIndex < session->userArmies.size()) ? session->userArmies[vectorIndex] : nullptr;
      useWholeMapBounds = (focusArmy != nullptr && focusArmy->mVarDat.mUseWholeMap != 0u);
    }
  }

  if (!useWholeMapBounds && terrainMap != nullptr) {
    minX = terrainMap->mPlayableRect.x0;
    minZ = terrainMap->mPlayableRect.z0;
    maxX = terrainMap->mPlayableRect.x1;
    maxZ = terrainMap->mPlayableRect.z1;
  }

  const float borderSize = moho::ren_BorderSize;
  const float maxZoomMult = mMaxZoomMult;
  const float horizontalExtent = (static_cast<float>(maxX - minX) + borderSize) * maxZoomMult;
  const float verticalExtent =
    (static_cast<float>(maxZ - minZ) + borderSize) * maxZoomMult * mVerticalZoomMetricScale;
  return std::max(verticalExtent, horizontalExtent);
}

/**
 * Address: 0x007A72C0 (FUN_007A72C0, Moho::CameraImpl::LODMetric)
 *
 * What it does:
 * Projects one offset vector into the camera viewport LOD-metric row.
 */
float moho::CameraImpl::LODMetric(const Wm3::Vec3f& offset) const
{
  const Vector4f& row = CameraGetView().viewport.r[1];
  return offset.x * row.x + offset.y * row.y + offset.z * row.z + row.w;
}

/**
 * Address: 0x007A78F0 (FUN_007A78F0, Moho::CameraImpl::GetAllSoundEntitiesInFrustum)
 * Slot: 39 (`??_7CameraImpl@Moho@@6B@` at 0x00E3C474; see the header for the
 * byte-verified slot evidence)
 *
 * What it does:
 * Hands back the sound/all-entities frustum cache at `camera + 0x460` -- the
 * lane `CacheCameraFrustumUnits` above fills with every live entity inside the
 * current camera view. The binary is a bare `lea eax, [ecx+460h]; retn`.
 */
gpg::core::FastVectorInline<moho::WeakPtr<moho::UserEntity>>& moho::CameraImpl::GetAllSoundEntitiesInFrustum()
{
  return mFrustumLaneA;
}

/**
 * Address: 0x007A73C0 (FUN_007A73C0)
 *
 * What it does:
 * Updates one runtime multiplier lane used by max-zoom gating.
 */
void moho::CameraImpl::SetMaxZoomMult(const float maxZoomMult)
{
  mMaxZoomMult = maxZoomMult;
}

/**
 * Address: 0x007A7410 (FUN_007A7410, ?GetViewBox@CameraImpl@Moho@@UBE?AV?$AxisAlignedBox3@M@Wm3@@XZ)
 * Mangled: ?GetViewBox@CameraImpl@Moho@@UBE?AV?$AxisAlignedBox3@M@Wm3@@XZ
 *
 * What it does:
 * Builds one target-centered AABB using half of current near-zoom for X/Z
 * extent while preserving the target Y lane in both min/max bounds.
 */
Wm3::AxisAlignedBox3f moho::CameraImpl::GetViewBox() const
{
  const float halfZoom = mNearZoom * 0.5f;

  Wm3::AxisAlignedBox3f viewBox{};
  viewBox.Min.x = mTargetLocation.x - halfZoom;
  viewBox.Min.y = mTargetLocation.y;
  viewBox.Min.z = mTargetLocation.z - halfZoom;
  viewBox.Max.x = mTargetLocation.x + halfZoom;
  viewBox.Max.y = mTargetLocation.y;
  viewBox.Max.z = mTargetLocation.z + halfZoom;
  return viewBox;
}

/**
 * Address: 0x007A74C0 (FUN_007A74C0, Moho::CameraImpl::TimedMoveInit)
 * Mangled: ?TimedMoveInit@CameraImpl@Moho@@QAEXMM@Z
 *
 * What it does:
 * Seeds timed-move state lanes for position/zoom/pitch/heading transition.
 */
void moho::CameraImpl::TimedMoveInit(const float seconds, const float transitionParam)
{
  mTimedMoveOffset = {0.0f, 0.0f, 0.0f};
  mTimedMoveZoom = 0.0f;
  mTimedMoveStartTime = 0.0f;
  mTimedMovePitch = 0.0f;
  mTimedMoveHeading = 0.0f;
  mTimedMoveDuration = seconds;
  mTimedMoveTransitionParam = transitionParam;

  if (seconds > 0.0f) {
    CameraTimeSourceRuntime* const timeSource = mTimeSources[mTimeSource];
    mTimedMoveStartTime = timeSource != nullptr ? timeSource->Time() : 0.0f;
    mTimedMoveOffset = mOffset;
    mTimedMoveZoom = mTargetZoom;
    mTimedMovePitch = mFarPitch;
    mTimedMoveHeading = moho::NormalizeAngleSignedRadians(mHeading);
    AsTransitionFlagView(this)->mTransitionPending = 0u;
  }
}

/**
 * Address: 0x007A88A0 (FUN_007A88A0, func_NormalizeQuadrant)
 *
 * What it does:
 * Normalizes one angle to [-pi, pi] and unwraps by +/-2pi so it remains
 * closest to a reference heading lane.
 */
[[nodiscard]] static float NormalizeQuadrantRelative(const float angleRadians, const float referenceRadians) noexcept
{
  float normalized = static_cast<float>(std::fmod(static_cast<double>(angleRadians), static_cast<double>(kTwoPi)));

  if (normalized < -kPi) {
    normalized += kTwoPi;
  } else if (normalized > kPi) {
    normalized -= kTwoPi;
  }

  if (std::fabs(normalized - referenceRadians) > kPi) {
    if (normalized < referenceRadians) {
      normalized += kTwoPi;
    } else {
      normalized -= kTwoPi;
    }
  }

  return normalized;
}

/**
 * Address: 0x007A8940 (FUN_007A8940, Moho::CameraImpl::SetupHermite)
 * Mangled: ?SetupHermite@CameraImpl@Moho@@QAEXXZ
 *
 * What it does:
 * Derives Hermite delta lanes for target offset/heading/pitch/zoom when
 * ease-in/out mode is disabled.
 */
void moho::CameraImpl::SetupHermite()
{
  if (mEnableEaseInOut != 0u) {
    return;
  }

  mHermiteOffsetStartDelta.x = mTargetLocation.x - mTimedMoveOffset.x;
  mHermiteOffsetStartDelta.y = mTargetLocation.y - mTimedMoveOffset.y;
  mHermiteOffsetStartDelta.z = mTargetLocation.z - mTimedMoveOffset.z;
  mHermiteOffsetEndDelta = mHermiteOffsetStartDelta;

  const float headingDelta = mHeadingZoom - mTimedMoveHeading;
  mHermiteHeadingStartDelta = headingDelta;
  mHermiteHeadingEndDelta = headingDelta;

  const float pitchDelta = mCurrentPitch - mTimedMovePitch;
  mHermitePitchStartDelta = pitchDelta;
  mHermitePitchEndDelta = pitchDelta;

  const float zoomDelta = mNearZoom - mTimedMoveZoom;
  mHermiteZoomStartDelta = zoomDelta;
  mHermiteZoomEndDelta = zoomDelta;
}

/**
 * Address: 0x007A9320 (FUN_007A9320, Moho::CameraImpl::ClampTargetPos)
 * Mangled: ?ClampTargetPos@CameraImpl@Moho@@QAEXXZ
 *
 * What it does:
 * Clamps target X/Z to map or playable-rect bounds using zoom-proportional
 * extents.
 */
void moho::CameraImpl::ClampTargetPos()
{
  STIMap* const stiMap = mTerrainMap;
  if (stiMap == nullptr) {
    return;
  }

  int minX = 0;
  int minZ = 0;
  int maxX = 0;
  int maxZ = 0;
  if (const CHeightField* const field = stiMap->mHeightField.get(); field != nullptr) {
    maxX = field->width - 1;
    maxZ = field->height - 1;
  }

  if (const CWldSession* const session = WLD_GetActiveSession(); session != nullptr) {
    const int focusArmyIndex = session->FocusArmy;
    bool useWholeMap = false;
    if (focusArmyIndex >= 0) {
      const std::size_t vectorIndex = static_cast<std::size_t>(focusArmyIndex);
      UserArmy* const focusArmy =
        (vectorIndex < session->userArmies.size()) ? session->userArmies[vectorIndex] : nullptr;
      useWholeMap = (focusArmy != nullptr && focusArmy->mVarDat.mUseWholeMap != 0u);
    }

    if (!useWholeMap) {
      minX = stiMap->mPlayableRect.x0;
      minZ = stiMap->mPlayableRect.z0;
      maxX = stiMap->mPlayableRect.x1;
      maxZ = stiMap->mPlayableRect.z1;
    }
  }

  const float maxZoom = GetMaxZoom();
  float clampedZoom = mTargetZoom;
  if (maxZoom <= clampedZoom) {
    clampedZoom = maxZoom;
  }
  if (clampedZoom < 0.0f) {
    clampedZoom = 0.0f;
  }

  const float halfSpanX = (clampedZoom / maxZoom) * (static_cast<float>(maxX - minX) * 0.5f);
  const float maxTargetX = static_cast<float>(maxX) - halfSpanX;
  const float minTargetX = static_cast<float>(minX) + halfSpanX;

  float targetX = mTargetLocation.x;
  if (maxTargetX <= targetX) {
    targetX = maxTargetX;
  }
  if (minTargetX > targetX) {
    targetX = minTargetX;
  }
  mTargetLocation.x = targetX;

  const float halfSpanZ = (clampedZoom / maxZoom) * (static_cast<float>(maxZ - minZ) * 0.5f);
  const float maxTargetZ = static_cast<float>(maxZ) - halfSpanZ;
  const float minTargetZ = static_cast<float>(minZ) + halfSpanZ;

  float targetZ = mTargetLocation.z;
  if (maxTargetZ <= targetZ) {
    targetZ = maxTargetZ;
  }
  if (minTargetZ > targetZ) {
    targetZ = minTargetZ;
  }
  mTargetLocation.z = targetZ;
}

/**
 * Address: 0x007A9470 (FUN_007A9470, Moho::CameraImpl::ClampFocusPos)
 * Mangled: ?ClampFocusPos@CameraImpl@Moho@@QAEXXZ
 *
 * What it does:
 * Projects one heading/pitch ray from current offset and snaps focus to the
 * terrain/water surface hit when valid.
 */
void moho::CameraImpl::ClampFocusPos()
{
  STIMap* const stiMap = mTerrainMap;
  if (stiMap == nullptr) {
    return;
  }

  moho::GeomLine3 line{};
  line.pos = mOffset;
  const float cosPitch = std::cos(mFarPitch);
  line.closest = gpg::nInf;
  line.farthest = gpg::pInf;
  line.dir.x = std::sin(mHeading) * cosPitch;
  line.dir.y = -std::sin(mFarPitch);
  line.dir.z = cosPitch * std::cos(mHeading);

  moho::CColHitResult hit{};
  const Wm3::Vec3f clampedFocus = stiMap->SurfaceIntersection(line, &hit);
  if (std::isfinite(clampedFocus.x) && std::isfinite(clampedFocus.y) && std::isfinite(clampedFocus.z)) {
    mOffset = clampedFocus;
  }
}

/**
 * Address: 0x007A9550 (FUN_007A9550, Moho::CameraImpl::CalculateFOV)
 * Mangled: ?CalculateFOV@CameraImpl@Moho@@QAEXXZ
 *
 * What it does:
 * Recomputes far-FOV from logarithmic zoom interpolation between near/far
 * camera zoom envelopes.
 */
void moho::CameraImpl::CalculateFOV()
{
  const float logMaxZoom = std::log(GetMaxZoom());
  const float logTargetZoom = std::log(mTargetZoom);
  const float logNearZoom = std::log(moho::cam_NearZoom);

  float clampedLogZoom = (logMaxZoom <= logTargetZoom) ? logMaxZoom : logTargetZoom;
  if (logNearZoom > clampedLogZoom) {
    clampedLogZoom = logNearZoom;
  }

  mFarFov =
    ((((clampedLogZoom - logNearZoom) / (logMaxZoom - logNearZoom)) * (moho::cam_FarFOV - moho::cam_NearFOV)) +
      moho::cam_NearFOV) *
    kDegreesToRadians;
}

namespace
{
  /**
   * Returns the log-zoom-interpolated camera pitch in radians, matching the
   * binary's `(((logTargetZoom - logNearZoom) / (logMaxZoom - logNearZoom)) *
   * (cam_FarPitch - cam_NearPitch) + cam_NearPitch) * (pi/180)` blend used by
   * `UpdateBasis`. The blend lane reads `mTargetZoom` so callers must already
   * have applied the per-frame zoom slew before invoking.
   */
  [[nodiscard]] float LogZoomInterpolatedPitchRadians(const moho::CameraImpl& camera, const float maxZoom) noexcept
  {
    const float logMaxZoom = std::log(maxZoom);
    const float logTargetZoom = std::log(camera.mTargetZoom);
    const float logNearZoom = std::log(moho::cam_NearZoom);

    float clampedLogZoom = (logMaxZoom <= logTargetZoom) ? logMaxZoom : logTargetZoom;
    if (logNearZoom > clampedLogZoom) {
      clampedLogZoom = logNearZoom;
    }

    return (((clampedLogZoom - logNearZoom) / (logMaxZoom - logNearZoom)) *
              (moho::cam_FarPitch - moho::cam_NearPitch) +
             moho::cam_NearPitch) *
           kDegreesToRadians;
  }
}

/**
 * Address: 0x007A95F0 (FUN_007A95F0, Moho::CameraImpl::UpdateBasis)
 * Mangled: ?UpdateBasis@CameraImpl@Moho@@QAEXMM@Z
 *
 * IDA signature:
 *   void __userpurge UpdateBasis(CameraImpl *this@<eax>, float interpolationAlpha, float frameSeconds)
 *
 * What it does:
 * Advances camera target-zoom along a log-space slew toward `mNearZoom`,
 * optionally pivot-shifts the focus when zooming out of Location/Hermite
 * targeting, recomputes FOV, then resolves heading and pitch lanes from the
 * current target type and finally re-clamps focus onto the terrain surface.
 */
void moho::CameraImpl::UpdateBasis(const float interpolationAlpha, const float frameSeconds)
{
  const float startTargetZoom = mTargetZoom;
  // TEMPORARY PROBE (do not commit)
  {
    static int sCalls = 0;
    static int sBudget = 0;
    if ((sCalls++ % 150) == 0 && sBudget < 40) {
      ++sBudget;
      gpg::Warnf("[CAMDIAG] UpdateBasis name=%s call=%d type=%d targetZoom=%.1f near=%.1f zoom=%.1f rotated=%u "
                 "target=(%.1f,%.1f,%.1f) offset=(%.1f,%.1f,%.1f) maxZoom=%.1f dt=%.4f",
                 mName.c_str(), sCalls, mTargetType, mTargetZoom, mNearZoom,
                 mZoom, static_cast<unsigned>(mIsRotated), mTargetLocation.x,
                 mTargetLocation.y, mTargetLocation.z, mOffset.x, mOffset.y,
                 mOffset.z, GetMaxZoom(), frameSeconds);
    }
  }

  // Move target-zoom in log2 space toward mNearZoom at a slew rate proportional
  // to the absolute log-distance plus a constant floor, both scaled by frame
  // seconds.
  const float logStart = std::log2(startTargetZoom);
  const float logTarget = std::log2(mNearZoom);
  const float logDelta = logTarget - logStart;
  const float logDeltaMagnitude = std::fabs(logDelta);

  float clampedMagnitude = logDeltaMagnitude;
  const float allowedStep =
    ((clampedMagnitude * moho::cam_ZoomSpeedLarge) + moho::cam_ZoomSpeedSmall) * frameSeconds;
  if (clampedMagnitude > allowedStep) {
    clampedMagnitude = allowedStep;
  }

  const float signedStep = std::copysign(clampedMagnitude, logDelta);
  mTargetZoom = std::exp2(logStart + signedStep);

  // Clamp target-zoom into [cam_NearZoom, GetMaxZoom()] unless rotated mode is
  // armed (rotated mode lets the user temporarily exceed the gameplay zoom
  // envelope without snap-back).
  if (mIsRotated == 0u) {
    const float maxZoomLane = GetMaxZoom();
    float clampedZoom = mTargetZoom;
    if (maxZoomLane <= clampedZoom) {
      clampedZoom = maxZoomLane;
    }
    if (moho::cam_NearZoom > clampedZoom) {
      clampedZoom = moho::cam_NearZoom;
    }
    mTargetZoom = clampedZoom;
  }

  // When zooming out of a stationary target (Location/Hermite), shift the
  // focus point along the screen-space pivot ray so the pivot world point
  // stays under the screen pivot through the zoom transition.
  const std::int32_t shiftAnchorType = mTargetType;
  if ((shiftAnchorType == kCameraTargetTypeLocation || shiftAnchorType == kCameraTargetTypeHermite) &&
      startTargetZoom > mTargetZoom) {
    moho::GeomLine3 pivotRay = mCam.Unproject(mPivot);
    pivotRay.closest = gpg::nInf;

    moho::CColHitResult hit{};
    if (STIMap* const stiMap = mTerrainMap; stiMap != nullptr) {
      const Wm3::Vec3f pivotSurfacePoint = stiMap->SurfaceIntersection(pivotRay, &hit);
      if (moho::IsValidVector3f(pivotSurfacePoint)) {
        float zoomScale = mTargetZoom;
        if (startTargetZoom <= zoomScale) {
          zoomScale = startTargetZoom;
        }
        if (zoomScale < 0.0f) {
          zoomScale = 0.0f;
        }
        const float scale = zoomScale / startTargetZoom;

        mTargetLocation.x =
          ((mTargetLocation.x - pivotSurfacePoint.x) * scale) + pivotSurfacePoint.x;
        mTargetLocation.y =
          ((mTargetLocation.y - pivotSurfacePoint.y) * scale) + pivotSurfacePoint.y;
        mTargetLocation.z =
          ((mTargetLocation.z - pivotSurfacePoint.z) * scale) + pivotSurfacePoint.z;
      }
    }
  }

  if (!moho::cam_Free) {
    ClampTargetPos();
  }
  mOffset = mTargetLocation;
  CalculateFOV();

  // Heading / pitch resolution branches by target type.
  const std::int32_t targetTypeAfterFov = mTargetType;

  if (targetTypeAfterFov == kCameraTargetTypeNoseCam) {
    UserEntity* const noseTarget = GetTargetEntity();
    const VTransform interpolated = noseTarget->GetInterpolatedTransform(interpolationAlpha);
    const Wm3::Quaternionf orient = interpolated.orient_;

    // Heading is the Y-axis yaw extracted from the quaternion:
    //   atan2(2*(w*y + x*z), 1 - 2*(x*x + y*y))
    const float orientX = orient.x;
    const float orientY = orient.y;
    const float orientZ = orient.z;
    const float orientW = orient.w;
    mHeading = std::atan2(
      ((orientW * orientY) + (orientX * orientZ)) * 2.0f,
      1.0f - (((orientX * orientX) + (orientY * orientY)) * 2.0f)
    );
    mFarPitch = moho::COORDS_Pitch(orient) + mNoseCamPitchAdjust;
    ClampFocusPos();
    return;
  }

  if (targetTypeAfterFov == kCameraTargetTypeHermite) {
    mHeading = mHeadingZoom;
    mFarPitch = mCurrentPitch;
    ClampFocusPos();
    return;
  }

  constexpr float kRotatedTolerance = 0.1f;

  if (mIsRotated != 0u) {
    if (mRevertRotation == 0u) {
      ClampFocusPos();
      return;
    }

    // Pitch slews toward the log-zoom-interpolated pitch within tolerance.
    const float interpolatedPitch = LogZoomInterpolatedPitchRadians(*this, GetMaxZoom());
    float pitchStep = interpolatedPitch;
    if (mFarPitch + kRotatedTolerance <= pitchStep) {
      pitchStep = mFarPitch + kRotatedTolerance;
    }
    if (mFarPitch - kRotatedTolerance > pitchStep) {
      pitchStep = mFarPitch - kRotatedTolerance;
    }
    mFarPitch = pitchStep;

    // Heading slews toward +pi (or -pi for negative heading) within tolerance.
    const float headingNow = mHeading;
    const float headingTarget = (headingNow <= 0.0f) ? -kPi : kPi;
    float headingStep = headingNow + kRotatedTolerance;
    if (headingStep > headingTarget) {
      headingStep = headingTarget;
    }
    if (headingNow - kRotatedTolerance > headingStep) {
      headingStep = headingNow - kRotatedTolerance;
    }
    mHeading = headingStep;

    if (std::fabs(headingStep - headingTarget) >= kRotatedTolerance ||
        std::fabs(pitchStep - interpolatedPitch) >= kRotatedTolerance) {
      ClampFocusPos();
      return;
    }

    // Both lanes settled — snap heading to +pi, pitch to the interpolated
    // value, and clear the rotation flags.
    mHeading = kPi;
    mFarPitch = interpolatedPitch;
    mRevertRotation = 0u;
    mIsRotated = 0u;
    ClampFocusPos();
    return;
  }

  // Non-rotated mode: pitch tracks the log-zoom-interpolated camera pitch.
  mFarPitch = LogZoomInterpolatedPitchRadians(*this, GetMaxZoom());
  ClampFocusPos();
}

/**
 * Address: 0x007A9110 (FUN_007A9110, Moho::CameraImpl::UpdateTargets)
 * Mangled: ?UpdateTargets@CameraImpl@Moho@@QAEXMM@Z
 *
 * IDA signature:
 *   void __thiscall UpdateTargets(CameraImpl *this, float interpolationAlpha, float frameSeconds)
 *
 * What it does:
 * Per-frame entity-target tracking update — see header docstring for the
 * target-type dispatch summary. Invoked from `CameraImpl::Frame` immediately
 * before `UpdateBasis`.
 */
void moho::CameraImpl::UpdateTargets(const float interpolationAlpha, const float frameSeconds)
{
  // Tracked-target countdown: when armed, decay toward zero and dispatch
  // TargetNextEntity through the virtual lane when it hits zero so the next
  // queued entity becomes active (or fallback behavior fires when empty).
  if (mTargetTime != 0u) {
    float remainingTime = mTargetTimeLeft - frameSeconds;
    if (remainingTime < 0.0f) {
      remainingTime = 0.0f;
    }
    mTargetTimeLeft = remainingTime;
    if (remainingTime == 0.0f) {
      TargetNextEntity();
    }
  }

  const std::int32_t targetType = mTargetType;
  if (targetType < kCameraTargetTypeEntity) {
    return;
  }

  if (targetType <= kCameraTargetTypeNoseCam) {
    UserEntity* const targetEntity = GetTargetEntity();
    if (targetEntity == nullptr) {
      // Live entity vanished: arm a tracking-stop broadcast for single-entity
      // entity-mode follow, demote target type to Location, and schedule a
      // rotation revert when we were previously in rotated mode.
      mTargetTime = 1u;
      const bool wasEntityMode = (mTargetType == kCameraTargetTypeEntity);
      if (wasEntityMode && mTargetEntities.size() <= 1) {
        BroadcastEvent(SCameraTracking{mName, 0});
      }
      const bool wasRotated = (mIsRotated != 0u);
      mTargetType = kCameraTargetTypeLocation;
      if (wasRotated) {
        mRevertRotation = 1u;
      }
      return;
    }

    // Live entity: snap the target lane to its interpolated world transform
    // each frame so the camera focus follows.
    const VTransform interpolated = targetEntity->GetInterpolatedTransform(interpolationAlpha);
    mTargetLocation = interpolated.pos_;

    if (mTargetType == kCameraTargetTypeNoseCam) {
      // NoseCam: derive pitch from the entity orientation plus the saved
      // pitch adjust into `mCurrentPitch`, and derive heading by extracting
      // the standard quaternion yaw and wrapping it relative to
      // `mTimedMoveHeading` so the camera does not flip orientation across
      // the +/-pi boundary.
      const Wm3::Quaternionf& orient = interpolated.orient_;
      mCurrentPitch = moho::COORDS_Pitch(orient) + mNoseCamPitchAdjust;

      const float orientX = orient.x;
      const float orientY = orient.y;
      const float orientZ = orient.z;
      const float orientW = orient.w;
      const float headingFromQuat = std::atan2(
        ((orientW * orientY) + (orientX * orientZ)) * 2.0f,
        1.0f - (((orientX * orientX) + (orientY * orientY)) * 2.0f)
      );
      mHeadingZoom = NormalizeQuadrantRelative(headingFromQuat, mTimedMoveHeading);
    }
    return;
  }

  if (targetType == kCameraTargetTypeHermite) {
    // Hermite spin lane: integrate heading at the cached angular rate (rev/s
    // -> rad via 2pi) and zoom at the linear rate, both scaled by delta.
    mHeadingZoom += mHeadingRate * frameSeconds * kTwoPi;
    mNearZoom += mZoomRate * frameSeconds;
  }
  // Location/Box: nothing to do.
}

/**
 * Address: 0x007A9030 (FUN_007A9030, Moho::CameraImpl::Frame)
 * Mangled: ?Frame@CameraImpl@Moho@@QAEXMM@Z
 *
 * IDA signature:
 *   void __userpurge Frame(CameraImpl *this@<eax>, float interpolationAlpha, float frameSeconds)
 *
 * What it does:
 * Advances one runtime camera for the current sim/frame delta pair. When the
 * camera is bound to the game clock, the frame delta is recomputed from the
 * game-time source against the last frame's time. Advances the camera-shake
 * elapsed timer (clamped to the shake duration), flips the shake phase sign,
 * then drives the per-frame lanes in order:
 *   - UpdateTargets       — entity-target tracking
 *   - UpdateBasis / InterpolateBasis — basis/zoom slew (the latter when a timed
 *                            transition is active, i.e. mTimedMoveDuration > 0)
 *   - UpdateCoords        — push view transform + projection into mCam
 *   - CacheCameraFrustumUnits — rebuild the cached in-frustum unit lists
 * and finally records the game-clock time for the next frame's delta.
 *
 * Invoked from `RCamManager::Frame` (0x007AABB0) over the camera loop.
 */
void moho::CameraImpl::Frame(const float interpolationAlpha, float frameSeconds)
{
  CameraTimeSourceRuntime* const gameTimeSource = mTimeSources[kCameraTimeSourceGame];

  // Game-clock cameras derive the per-frame delta from the game-time source
  // rather than the passed-in frame seconds.
  if (mTimeSource == kCameraTimeSourceGame) {
    frameSeconds = gameTimeSource->Time() - mLastFrameTime;
  }

  // Advance the shake elapsed timer, clamped to the shake duration; flip the
  // shake phase sign each frame (the binary alternates the shake scale sign).
  float shakeElapsed = mCamShakeParams.mElapsed + frameSeconds;
  if (mCamShakeParams.mDuration <= shakeElapsed) {
    shakeElapsed = mCamShakeParams.mDuration;
  }
  mCamShakeParams.mElapsed = shakeElapsed;
  mCamShakeParams.mScale = -mCamShakeParams.mScale;

  UpdateTargets(interpolationAlpha, frameSeconds);

  if (mTimedMoveDuration <= 0.0f) {
    UpdateBasis(interpolationAlpha, frameSeconds);
  } else {
    InterpolateBasis(interpolationAlpha, frameSeconds);
  }

  UpdateCoords(interpolationAlpha, frameSeconds);
  CacheCameraFrustumUnits(frameSeconds);

  // Record the game-clock time for next frame's game-delta computation.
  mLastFrameTime = gameTimeSource->Time();
}

namespace
{
  // Hermite basis polynomials evaluated at parameter `t` in [0,1], matching the
  // binary's open-coded cubic blend in `CameraImpl::InterpolateBasis`:
  //   h00 =  2t^3 - 3t^2 + 1   (start value)
  //   h10 =      t^3 - 2t^2 + t (start tangent)
  //   h01 =      t^3 -  t^2     (end tangent)
  //   h11 = -2t^3 + 3t^2       (end value)
  struct CameraHermiteWeights
  {
    float startValue;
    float startTangent;
    float endTangent;
    float endValue;
  };

  [[nodiscard]] CameraHermiteWeights MakeCameraHermiteWeights(const float t) noexcept
  {
    const float tt = t * t;
    const float ttt = tt * t;
    CameraHermiteWeights weights{};
    weights.startValue = ((ttt * 2.0f) - (tt * 3.0f)) + 1.0f;
    weights.startTangent = (ttt - (tt * 2.0f)) + t;
    weights.endTangent = ttt - tt;
    weights.endValue = (tt * 3.0f) - (ttt * 2.0f);
    return weights;
  }

  // Signals the camera's embedded `CScriptEvent` (a `CTaskEvent`) sub-object at
  // +0x0C that a timed transition has completed. Matches the binary's
  // `CTaskEvent::EventSetSignaled((CTaskEvent*)&this->CScriptEvent, 1)`.
  void EventSetSignaledCameraTransition(moho::CameraImpl& camera, const bool signaled) noexcept
  {
    // +0x0C is where the compiler puts it: `CameraImpl : public RCamCamera,
    // public CScriptEvent` with `sizeof(RCamCamera) == 0x0C`, so CScriptEvent is
    // the second base. Take it by cast rather than by adding 0x0C.
    static_cast<moho::CScriptEvent&>(camera).EventSetSignaled(signaled);
  }
}

/**
 * Address: 0x007A9BA0 (FUN_007A9BA0, Moho::CameraImpl::InterpolateBasis)
 * Mangled: ?InterpolateBasis@CameraImpl@Moho@@QAEXMM@Z
 *
 * IDA signature:
 *   int __userpurge InterpolateBasis@<eax>(CameraImpl *this@<ebx>, float interpolationAlpha)
 *   (declared `void(float, float)` by the mangled name; the second float is
 *   unused by this code path and passed only to keep the timed-move/Frame ABI
 *   identical to the sibling slew lanes.)
 *
 * What it does:
 * Drives one active timed-move / Hermite camera transition for the current
 * frame. Computes the linear transition progress from the active time source,
 * refreshes the entity target location when following an entity, and either
 * snaps to the transition endpoint (progress >= 1) or evaluates the
 * acceleration-curve-shaped progress and Hermite-blends offset / heading /
 * far-pitch / target-zoom between the cached start and end deltas. For
 * non-targeted (Location/Box) transitions it derives the far-pitch from the
 * log-zoom interpolation lane, then snaps the offset onto the terrain surface
 * and demotes finished Hermite/Box transitions back to Location mode.
 *
 * Invoked from the recovered `CameraImpl::Frame` (FUN_007A9030) on the
 * transition lane (`mTimedMoveDuration > 0`).
 */
void moho::CameraImpl::InterpolateBasis(const float interpolationAlpha, const float /*frameSeconds*/)
{
  // Linear transition progress = (now - startTime) / duration along the active
  // time source.
  CameraTimeSourceRuntime* const timeSource = mTimeSources[mTimeSource];
  float progress = (timeSource->Time() - mTimedMoveStartTime) / mTimedMoveDuration;
  // TEMPORARY PROBE (do not commit)
  {
    static int sBudget = 0;
    if (sBudget < 80) {
      ++sBudget;
      gpg::Warnf("[CAMDIAG] Interp name=%s progress=%.3f now=%.3f start=%.3f dur=%.2f type=%d targetZoom=%.1f near=%.1f "
                 "moveZoom=%.1f offset=(%.1f,%.1f,%.1f) target=(%.1f,%.1f,%.1f) moveOff=(%.1f,%.1f,%.1f) acc=%d",
                 mName.c_str(), progress, timeSource->Time(), mTimedMoveStartTime,
                 mTimedMoveDuration, mTargetType, mTargetZoom, mNearZoom,
                 mTimedMoveZoom, mOffset.x, mOffset.y, mOffset.z,
                 mTargetLocation.x, mTargetLocation.y, mTargetLocation.z,
                 mTimedMoveOffset.x, mTimedMoveOffset.y, mTimedMoveOffset.z,
                 mAccType);
    }
  }

  // Entity-follow transitions keep the target location pinned to the live
  // entity each frame.
  if (mTargetType == kCameraTargetTypeEntity) {
    if (UserEntity* const targetEntity = GetTargetEntity(); targetEntity != nullptr) {
      const VTransform interpolated = targetEntity->GetInterpolatedTransform(interpolationAlpha);
      mTargetLocation = interpolated.pos_;
    }
  }

  if (progress >= 1.0f) {
    // Transition complete: snap to the cached endpoint state.
    mOffset = mTargetLocation;
    const bool isBoxTransition = (mTargetType == kCameraTargetTypeHermite + kCameraTargetTypeBox);
    mTimedMoveDuration = 0.0f;
    mTargetZoom = mNearZoom;
    if (!isBoxTransition) {
      EventSetSignaledCameraTransition(*this, true);
    }
    if (mTargetType == kCameraTargetTypeHermite || mTargetType == kCameraTargetTypeNoseCam) {
      mIsRotated = 1u;
      mHeading = mHeadingZoom;
      mFarPitch = mTimedMovePitch;
    }
  } else {
    // NoseCam transitions use a separate (shorter) transition-parameter
    // duration to drive the acceleration curve.
    float curveInput = progress;
    if (mTargetType == kCameraTargetTypeNoseCam) {
      float noseProgress = 1.0f;
      if (mTimedMoveTransitionParam > 0.0f) {
        CameraTimeSourceRuntime* const noseSource = mTimeSources[mTimeSource];
        noseProgress =
          (noseSource->Time() - mTimedMoveStartTime) / mTimedMoveTransitionParam;
        if (noseProgress > 1.0f) {
          noseProgress = 1.0f;
        }
      }
      curveInput = noseProgress;
    }

    // Acceleration-shaped progress: ease-out (FastInSlowOut) or ease-in-out
    // (SlowInOut). Linear acceleration leaves the parameter untouched.
    float shapedProgress = curveInput;
    if (mAccType == kCameraAccTypeFastInSlowOut) {
      shapedProgress = std::sin(curveInput * kHalfPi);
    } else if (mAccType == kCameraAccTypeSlowInOut) {
      shapedProgress = (progress < 0.5f)
        ? (1.0f - std::cos(curveInput * kPi)) * 0.5f
        : (std::sin((curveInput - 0.5f) * kPi) * 0.5f) + 0.5f;
    }

    const float t = shapedProgress;
    const CameraHermiteWeights w = MakeCameraHermiteWeights(t);

    // Targeted (Hermite/NoseCam) transitions Hermite-blend heading and pitch
    // between the cached transition endpoints. The blend control points are
    // (startValue, startTangent, endTangent, endValue):
    //   far-pitch : mTimedMovePitch / mHermitePitchStartDelta /
    //               mHermitePitchEndDelta / mCurrentPitch
    //   heading   : mTimedMoveHeading / mHermiteHeadingStartDelta /
    //               mHermiteHeadingEndDelta / mHeadingZoom
    if (mTargetType == kCameraTargetTypeHermite || mTargetType == kCameraTargetTypeNoseCam) {
      mFarPitch =
        (mHermitePitchEndDelta * w.endTangent) +
        (mHermitePitchStartDelta * w.startTangent) +
        (mTimedMovePitch * w.startValue) +
        (mCurrentPitch * w.endValue);

      mHeading =
        (mTimedMoveHeading * w.startValue) +
        (mHermiteHeadingStartDelta * w.startTangent) +
        (mHermiteHeadingEndDelta * w.endTangent) +
        (mHeadingZoom * w.endValue);
      mIsRotated = 1u;
    }

    // Target-zoom is always Hermite-blended between the cached zoom endpoints:
    //   startValue=mTimedMoveZoom, startTangent=mHermiteZoomStartDelta,
    //   endTangent=mHermiteZoomEndDelta, endValue=mNearZoom.
    mTargetZoom =
      (mHermiteZoomStartDelta * w.startTangent) +
      (mTimedMoveZoom * w.startValue) +
      (mHermiteZoomEndDelta * w.endTangent) +
      (mNearZoom * w.endValue);

    // Offset is Hermite-blended between the cached offset endpoints:
    //   startValue=mTimedMoveOffset, startTangent=mHermiteOffsetEndDelta,
    //   endTangent=mHermiteOffsetStartDelta, endValue=mTargetLocation.
    mOffset.x =
      (mTimedMoveOffset.x * w.startValue) +
      (mTargetLocation.x * w.endValue) +
      (mHermiteOffsetEndDelta.x * w.startTangent) +
      (mHermiteOffsetStartDelta.x * w.endTangent);
    mOffset.y =
      (mTimedMoveOffset.y * w.startValue) +
      (mTargetLocation.y * w.endValue) +
      (mHermiteOffsetEndDelta.y * w.startTangent) +
      (mHermiteOffsetStartDelta.y * w.endTangent);
    mOffset.z =
      (mTimedMoveOffset.z * w.startValue) +
      (mTargetLocation.z * w.endValue) +
      (mHermiteOffsetEndDelta.z * w.startTangent) +
      (mHermiteOffsetStartDelta.z * w.endTangent);
  }

  // Non-targeted transitions (Location/Box) derive the far-pitch from the
  // log-zoom interpolation lane (matches CalculateFOV's blend domain).
  if (mTargetType != kCameraTargetTypeHermite &&
      mTargetType != kCameraTargetTypeNoseCam &&
      mTargetType != kCameraTargetTypeEntity) {
    const float logMaxZoom = std::log(GetMaxZoom());
    const float logTargetZoom = std::log(mTargetZoom);
    const float logNearZoom = std::log(moho::cam_NearZoom);
    float clampedLogZoom = (logMaxZoom <= logTargetZoom) ? logMaxZoom : logTargetZoom;
    if (logNearZoom > clampedLogZoom) {
      clampedLogZoom = logNearZoom;
    }
    mFarPitch =
      (((clampedLogZoom - logNearZoom) / (logMaxZoom - logNearZoom)) *
         (moho::cam_FarPitch - moho::cam_NearPitch) +
       moho::cam_NearPitch) *
      kDegreesToRadians;
  }

  CalculateFOV();

  // Snap the interpolated offset onto the terrain/water surface along the
  // heading/pitch ray.
  STIMap* const stiMap = mTerrainMap;
  moho::GeomLine3 line{};
  const float cosPitch = std::cos(mFarPitch);
  line.pos = mOffset;
  line.closest = 0.0f;
  line.farthest = gpg::pInf;
  line.dir.x = std::sin(mHeading) * cosPitch;
  line.dir.y = -std::sin(mFarPitch);
  line.dir.z = cosPitch * std::cos(mHeading);

  moho::CColHitResult hit{};
  const Wm3::Vec3f surfacePoint = stiMap->SurfaceIntersection(line, &hit);
  if (moho::IsValidVector3f(surfacePoint)) {
    mOffset = surfacePoint;
  }

  // When the transition has finished, demote Hermite/Box transitions to
  // Location mode (Entity/NoseCam stay tracked).
  if (progress >= 1.0f) {
    if (mTargetType != kCameraTargetTypeNoseCam &&
        mTargetType != kCameraTargetTypeEntity) {
      mTargetType = kCameraTargetTypeLocation;
    }
  }
}

/**
 * Address: 0x007A6F00 (FUN_007A6F00, Moho::CameraImpl::CameraPan)
 * Mangled: ?CameraPan@CameraImpl@Moho@@UAEXABV?$Vector2@M@Wm3@@@Z
 * Slot: 32 (vtable ??_7CameraImpl@Moho@@6B@ at 0x00E3C474, VTABLE_CONFIRMED)
 * Address: 0x00873BD0 (FUN_00873BD0 -- `CameraImpl::`vcall'{128}'`, the thunk MSVC
 *   emits for a pointer to this virtual: `mov eax,[ecx]; jmp [eax+80h]`. Taken as
 *   `&CameraImpl::CameraPan` by `CUIWorldView::HandleEvent` for its camera drag
 *   (0x00870B66), and called through `CameraDragger::mDragDelta`.)
 *
 * IDA signature:
 *   _DWORD *__thiscall CameraPan(CameraImpl *this, const Wm3::Vector2f *delta)
 *
 * What it does:
 * Pans the camera target location across the ground plane by a 2D screen
 * delta, unless the UI is in non-interactive (NIS) cinematic mode. Imports
 * `/lua/ui/game/gamemain.lua` and queries `IsNISMode()`; when not in NIS mode,
 * first clears any active entity target through the virtual `TargetNothing`
 * lane, then moves `mTargetLocation` along the camera's inverse-view right axis
 * (row 0) by the X delta and along a ground-flattened forward axis (row 1 with
 * Y zeroed and renormalized) by the Y delta. Both axes are scaled by the
 * current target zoom, the inverse viewport width, and `cam_PanSpeed`.
 */
void moho::CameraImpl::CameraPan(const Wm3::Vector2f& panDelta)
{
  // Skip panning entirely while the UI is in NIS (non-interactive scripted)
  // mode, as reported by the gamemain UI module.
  LuaPlus::LuaObject gameMain = moho::SCR_Import(mLuaObj.m_state, "/lua/ui/game/gamemain.lua");
  LuaPlus::LuaFunction isNisMode{gameMain["IsNISMode"]};
  if (isNisMode.Call_x_Bool()) {
    return;
  }

  // Panning releases any active entity target.
  TargetNothing();

  const moho::GeomCamera3& cam = mCam;
  const float viewportWidth = cam.viewport.r[3].z;
  const float inverseViewportWidth = 1.0f / viewportWidth;

  // Right axis = inverse-view row 0; ground-flattened forward axis = inverse-
  // view row 1 with Y zeroed and renormalized.
  const Vector4f& rightAxis = cam.inverseView.r[0];
  const Vector4f& forwardRow = cam.inverseView.r[1];

  Wm3::Vector3f flattenedForward{};
  flattenedForward.x = forwardRow.x;
  flattenedForward.y = 0.0f;
  flattenedForward.z = forwardRow.z;
  (void)Wm3::Vector3f::Normalize(&flattenedForward);

  // X delta moves along the (negated) right axis.
  const float panX = (mTargetZoom * inverseViewportWidth) * moho::cam_PanSpeed * panDelta.x;
  mTargetLocation.x -= panX * rightAxis.x;
  mTargetLocation.y -= panX * rightAxis.y;
  mTargetLocation.z -= panX * rightAxis.z;

  // Y delta moves along the flattened forward axis.
  const float panY = (mTargetZoom * inverseViewportWidth) * moho::cam_PanSpeed * panDelta.y;
  mTargetLocation.x += flattenedForward.x * panY;
  mTargetLocation.y += flattenedForward.y * panY;
  mTargetLocation.z += flattenedForward.z * panY;
}

/**
 * Address: 0x007A75A0 (FUN_007A75A0, Moho::CameraImpl::CacheCameraFrustumUnits)
 * Mangled: ?CacheCameraFrustumUnits@CameraImpl@Moho@@QAEXM@Z
 *
 * IDA signature:
 *   void __thiscall CacheCameraFrustumUnits(CameraImpl *this, float deltaFrame)
 *
 * What it does:
 * Periodically rebuilds the three cached "units in camera frustum" weak-vector
 * lanes (all-entities, all-units, focus-army units). A frame-time accumulator
 * (`mFrustumCacheTimer`) gates the rebuild so it runs at most a few times a
 * second: the cache refreshes when more than 0.5s have elapsed, or when the
 * near-zoom changed and more than 0.2s have elapsed. On rebuild it clears all
 * three lanes, queries the world spatial DB for every unit/entity intersecting
 * the current camera view, and for each live (non-dead) entity:
 *   - adds it to the sound/all-entities lane,
 *   - if it resolves to a `UserUnit` (virtual `IsUserUnit`), adds it to the
 *     all-units lane,
 *   - if it belongs to the current focus army, adds it to the focus-army lane.
 *
 * Invoked from the recovered `CameraImpl::Frame` (FUN_007A9030) as the final
 * per-frame step.
 */
void moho::CameraImpl::CacheCameraFrustumUnits(const float deltaFrame)
{
  moho::CWldSession* const session = moho::WLD_GetActiveSession();
  if (session == nullptr) {
    return;
  }

  // Frame-time gate: refresh the cache only every ~0.5s, or every ~0.2s when
  // the near-zoom has changed since the last refresh.
  const float elapsed = mFrustumCacheTimer + deltaFrame;
  mFrustumCacheTimer = elapsed;
  const bool nearZoomChanged = (mFrustumCacheZoomMark != mNearZoom);
  if (!(elapsed > 0.5f || (nearZoomChanged && elapsed > 0.2f))) {
    return;
  }

  mFrustumCacheZoomMark = mNearZoom;
  mFrustumCacheTimer = 0.0f;

  // Clear all three cached lanes (detaching any still-tracked weak refs and
  // releasing heap-grown storage) before the rebuild.
  mFrustumLaneA.ResetStorageToInline();
  mFrustumLaneB.ResetStorageToInline();
  mArmyUnitsInFrustum.ResetStorageToInline();

  UserArmy* const focusArmy = session->GetFocusArmy();

  // Collect every unit/entity intersecting the current camera view.
  gpg::fastvector<UserEntity*> unitsInView;
  auto* const spatialDb = session->GetEntitySpatialDbStorage();
  auto* const cameraView = const_cast<moho::GeomCamera3*>(&CameraGetView());
  spatialDb->CollectInView(
    cameraView, unitsInView, static_cast<EEntityType>(ENTITYTYPE_Unit | ENTITYTYPE_Entity)
  );

  for (UserEntity* const entity : unitsInView) {
    if (entity == nullptr) {
      continue;
    }
    // Skip entities flagged dead this frame.
    if (entity->mVariableData.mIsDead != 0u) {
      continue;
    }

    // Every live in-view entity goes into the sound/all-entities lane.
    mFrustumLaneA.push_back(WeakPtr<UserEntity>(entity));

    // Units (entities that resolve to a `UserUnit`) also go into the all-units
    // lane (virtual `IsUserUnit`, vtable slot 3).
    if (entity->IsUserUnit() != nullptr) {
      mFrustumLaneB.push_back(WeakPtr<UserEntity>(entity));

      // Units owned by the current focus army also go into the focus-army lane.
      if (focusArmy == entity->mArmy) {
        mArmyUnitsInFrustum.push_back(WeakPtr<UserEntity>(entity));
      }
    }
  }
}

namespace
{
  /**
   * Turns a `COORDS_Orient` look quaternion into the view orientation, by
   * post-multiplying a half turn about +Y: `look * (w=0, x=0, y=1, z=0)`.
   *
   * `UpdateCoords` (0x007AA330) open-codes this in both branches with the
   * roll factor folded to zero, so the decompile reads as a pile of `* 0.0`
   * terms. Reduced, it writes memory lanes `{-y, -z, w, x}` from an input
   * `{w, x, y, z}` - which is exactly the product above. Ordering the lanes
   * that way is only meaningful under the binary's scalar-first layout
   * (lane 0 is the scalar; see `QuatToMatrix` at 0x00452FD0, whose diagonals
   * pair only lanes 1..3).
   */
  [[nodiscard]] Wm3::Quaternionf ViewOrientFromLook(const Wm3::Quaternionf& look) noexcept
  {
    Wm3::Quaternionf orient{};
    orient.w = -look.y;
    orient.x = -look.z;
    orient.y = look.w;
    orient.z = look.x;
    return orient;
  }

  /**
   * Third column of the rotation matrix a unit quaternion expands to - the
   * axis `UpdateCoords` walks the eye back along from the camera target.
   *
   * Same terms `QuatToMatrix` writes to `[eax+08]`, `[eax+14h]` and
   * `[eax+20h]`.
   */
  [[nodiscard]] Wm3::Vector3f QuaternionForwardColumn(const Wm3::Quaternionf& q) noexcept
  {
    return Wm3::Vector3f{
      ((q.x * q.z) + (q.w * q.y)) * 2.0f,
      ((q.y * q.z) - (q.w * q.x)) * 2.0f,
      1.0f - (((q.x * q.x) + (q.y * q.y)) * 2.0f),
    };
  }
} // namespace

/**
 * Address: 0x007AA330 (FUN_007AA330, Moho::CameraImpl::UpdateCoords)
 * Mangled: ?UpdateCoords@CameraImpl@Moho@@QAEXMM@Z
 *
 * IDA signature:
 *   void __usercall UpdateCoords(CameraImpl *this@<eax>)
 *   (declared `void(float, float)` by the mangled name; both floats are unused
 *   by this code path and present only to keep the Frame-lane ABI identical to
 *   the sibling slew helpers.)
 *
 * What it does:
 * Rebuilds the embedded `GeomCamera3` view transform and projection from the
 * current camera state for one frame. Converts the target-zoom into a world
 * eye distance (`mZoom = targetZoom / tan(farFov/2) / 2`), derives near/far
 * clip planes from the eye distance, builds the camera orientation quaternion
 * (heading/pitch in perspective mode, a fixed top-down look in ortho mode),
 * places the eye at `mOffset` plus the rotated forward axis times the eye
 * distance (with per-frame shake applied in perspective mode), constructs the
 * projection matrix (D3D-style FOV perspective, or a hand-built orthographic
 * matrix), and finally re-initializes `mCam` via `GeomCamera3::Init`.
 *
 * Invoked from the recovered `CameraImpl::Frame` (FUN_007A9030) after the
 * per-frame basis/zoom slew.
 */
void moho::CameraImpl::UpdateCoords(const float /*interpolationAlpha*/, const float /*frameSeconds*/)
{
  const float targetZoom = mTargetZoom;

  // Eye distance: convert the target zoom (vertical world extent) into a camera
  // distance using the current vertical FOV, then halve it.
  const float eyeDistance = targetZoom / std::tan(mFarFov * 0.5f) / 2.0f;
  mZoom = eyeDistance;

  // Near clip = max(eyeDistance * 0.01, 0.01); far clip = eyeDistance + 17000.
  // Both are negated to match the binary's right-handed depth convention.
  float nearScale = eyeDistance * 0.0099999998f;
  if (nearScale < 0.0099999998f) {
    nearScale = 0.0099999998f;
  }
  const float nearClip = -nearScale;
  const float farClip = -(eyeDistance + 17000.0f);

  moho::VTransform viewTransform{};
  moho::VMatrix4 projection{};

  if (mIsOrtho != 0u) {
    // Orthographic mode: fixed top-down look (heading=pi, pitch=pi/2) and a
    // hand-built orthographic projection sized to the target zoom and its
    // metric-scaled vertical extent.
    const float verticalExtent = targetZoom / mVerticalZoomMetricScale;

    const Wm3::Quaternionf look = moho::COORDS_Orient(kPi, kHalfPi);
    viewTransform.orient_ = ViewOrientFromLook(look);

    const Wm3::Vector3f eyeAxis = QuaternionForwardColumn(viewTransform.orient_);
    viewTransform.pos_.x = mOffset.x + (eyeAxis.x * eyeDistance);
    viewTransform.pos_.y = mOffset.y + (eyeAxis.y * eyeDistance);
    viewTransform.pos_.z = mOffset.z + (eyeAxis.z * eyeDistance);

    // Orthographic projection rows (row-vector convention).
    projection.r[0] = Vector4f{};
    projection.r[1] = Vector4f{};
    projection.r[2] = Vector4f{};
    projection.r[3] = Vector4f{};
    projection.r[0].x = 2.0f / ((targetZoom * 0.5f) - (targetZoom * -0.5f));
    projection.r[1].y = 2.0f / ((verticalExtent * 0.5f) - (verticalExtent * -0.5f));
    projection.r[2].z = 1.0f / (farClip - nearClip);
    projection.r[3].x =
      (((targetZoom * -0.5f) + (targetZoom * 0.5f)) / ((targetZoom * -0.5f) - (targetZoom * 0.5f))) -
      (1.0f / static_cast<float>(static_cast<int>(targetZoom)));
    projection.r[3].y =
      (((verticalExtent * -0.5f) + (verticalExtent * 0.5f)) /
       ((verticalExtent * -0.5f) - (verticalExtent * 0.5f))) +
      (1.0f / static_cast<float>(static_cast<int>(verticalExtent)));
    projection.r[3].z = nearClip / (nearClip - farClip);
    projection.r[3].w = 1.0f;
  } else {
    // Perspective mode: build the orientation quaternion from heading/pitch.
    const Wm3::Quaternionf orient = moho::COORDS_Orient(mHeading, mFarPitch);
    viewTransform.orient_ = ViewOrientFromLook(orient);

    // Eye position = offset + rotated forward axis (from the quaternion) scaled
    // by the eye distance, before shake.
    const Wm3::Vector3f eyeAxis = QuaternionForwardColumn(viewTransform.orient_);
    const float eyeX = mOffset.x + (eyeAxis.x * eyeDistance);
    const float eyeY = mOffset.y + (eyeAxis.y * eyeDistance);
    const float eyeZ = mOffset.z + (eyeAxis.z * eyeDistance);

    // Apply per-frame camera shake to the eye position.
    Wm3::Vector3f shakeOffset{};
    Wm3::Vector3f* const shake =
      func_CameraImplUpdateShake(&mOffset, &shakeOffset, &mCamShakeParams);
    viewTransform.pos_.x = shake->x + eyeX;
    viewTransform.pos_.y = shake->y + eyeY;
    viewTransform.pos_.z = shake->z + eyeZ;

    // D3D-style perspective projection from the current FOV, clip planes, and
    // vertical metric scale (used as the aspect lane).
    projection = moho::VEC_D3DProjectionMatrixFOV(
      mFarFov, mFarFov, nearClip, farClip, mVerticalZoomMetricScale
    );
  }

  mCam.Init(viewTransform, projection);
}

/**
  * Alias of FUN_007A6BF0 (non-canonical helper lane).
 * Mangled: ?TargetNothing@CameraImpl@Moho@@UAEXXZ
 *
 * What it does:
 * Stops entity-tracking mode and returns camera targeting to location mode
 * with cleared target-time lanes.
 */
void moho::CameraImpl::TargetNothing()
{
  TargetNothingRuntime(this);
}

/**
 * Address: 0x007A82F0 (FUN_007A82F0, Moho::CameraImpl::TargetLocation)
 * Mangled: ?TargetLocation@CameraImpl@Moho@@UAEXABV?$Vector3@M@Wm3@@M@Z
 *
 * What it does:
 * Targets one world-space location with optional timed transition and
 * immediate focus/FOV update when `seconds == 0`.
 */
void moho::CameraImpl::TargetLocation(const Wm3::Vec3f& position, const float seconds)
{
  // TEMPORARY PROBE (do not commit)
  {
    static int sBudget = 0;
    if (sBudget < 20) {
      ++sBudget;
      gpg::Warnf("[CAMDIAG] TargetLocation name=%s pos=(%.1f,%.1f,%.1f) seconds=%.2f", mName.c_str(),
                 position.x, position.y, position.z, seconds);
    }
  }
  if (mTargetType == kCameraTargetTypeEntity) {
    BroadcastEvent(SCameraTracking{mName, 0});
  }

  TimedMoveInit(seconds, 0.0f);

  mTargetLocation = position;
  mTargetType = kCameraTargetTypeLocation;

  if (seconds == 0.0f) {
    mTargetZoom = mNearZoom;
    ClampTargetPos();
    mOffset = mTargetLocation;
    ClampFocusPos();
    CalculateFOV();
  } else {
    SetupHermite();
  }
}

/**
 * Address: 0x007A83E0 (FUN_007A83E0, Moho::CameraImpl::TargetBox)
 * Mangled: ?TargetBox@CameraImpl@Moho@@UAEXABV?$AxisAlignedBox3@M@Wm3@@M@Z
 *
 * What it does:
 * Targets one world-space AABB, derives focus/near-zoom lanes from box bounds,
 * and optionally applies immediate focus+FOV clamping.
 */
void moho::CameraImpl::TargetBox(const Wm3::AxisAlignedBox3f& targetBox, const float seconds)
{
  // TEMPORARY PROBE (do not commit)
  {
    static int sBudget = 0;
    if (sBudget < 20) {
      ++sBudget;
      CameraTimeSourceRuntime* const probeSource = mTimeSources[mTimeSource];
      gpg::Warnf("[CAMDIAG] TargetBox name=%s box=(%.1f,%.1f,%.1f)-(%.1f,%.1f,%.1f) seconds=%.2f | before type=%d "
                 "targetZoom=%.1f near=%.1f ease=%u timeSrc=%d now=%.3f maxZoom=%.1f offset=(%.1f,%.1f,%.1f)",
                 mName.c_str(), targetBox.Min.x, targetBox.Min.y, targetBox.Min.z, targetBox.Max.x,
                 targetBox.Max.y, targetBox.Max.z, seconds, mTargetType, mTargetZoom,
                 mNearZoom, static_cast<unsigned>(mEnableEaseInOut), mTimeSource,
                 probeSource != nullptr ? probeSource->Time() : -1.0f, GetMaxZoom(), mOffset.x,
                 mOffset.y, mOffset.z);
    }
  }
  if (mTargetType == kCameraTargetTypeEntity) {
    BroadcastEvent(SCameraTracking{mName, 0});
  }

  TimedMoveInit(seconds, 0.0f);

  mTargetBox = targetBox;
  mTargetLocation.x = (mTargetBox.Min.x + mTargetBox.Max.x) * 0.5f;
  mTargetLocation.y = (mTargetBox.Min.y + mTargetBox.Max.y) * 0.5f;
  mTargetLocation.z = (mTargetBox.Min.z + mTargetBox.Max.z) * 0.5f;

  float nearZoom = mTargetBox.Max.x - mTargetBox.Min.x;
  const float depthSpan = mTargetBox.Max.z - mTargetBox.Min.z;
  if (depthSpan > nearZoom) {
    nearZoom = depthSpan;
  }

  mNearZoom = nearZoom;
  mTargetType = kCameraTargetTypeBox;

  if (seconds == 0.0f) {
    mTargetZoom = nearZoom;
    ClampTargetPos();
    mOffset = mTargetLocation;
    ClampFocusPos();
    CalculateFOV();
  } else {
    SetupHermite();
  }
}

/**
 * Address: 0x007A8580 (FUN_007A8580, Moho::CameraImpl::TargetEntityBox)
 * Mangled: ?TargetEntityBox@CameraImpl@Moho@@UAEXPAVUserEntity@2@M@Z
 *
 * What it does:
 * Builds one world-space AABB from the entity's interpolated mesh-instance box
 * (or from the invalid Box3f sentinel when no mesh is attached), expands it on
 * the X/Z axes by `cam_EntityBoxExpand`, dispatches `TargetBox(expandedBox,
 * seconds)`, and additionally calls `TargetNothing` when `seconds == 0` so the
 * camera releases any active entity-tracking state after the framing snap.
 */
void moho::CameraImpl::TargetEntityBox(UserEntity* const entity, const float seconds)
{
  const Wm3::Box3f* sourceBox = nullptr;
  if (MeshInstance* const meshInstance = (entity != nullptr) ? entity->mMeshInstance : nullptr;
      meshInstance != nullptr) {
    meshInstance->UpdateInterpolatedFields();
    sourceBox = &meshInstance->box;
  } else {
    sourceBox = &Invalid<Wm3::Box3f>();
  }

  const Wm3::Box3f orientedBox(*sourceBox);
  Wm3::AxisAlignedBox3f expandedBox{};
  orientedBox.ComputeAABB(expandedBox.Min, expandedBox.Max);

  expandedBox.Max.x += cam_EntityBoxExpand;
  expandedBox.Max.z += cam_EntityBoxExpand;
  expandedBox.Min.x -= cam_EntityBoxExpand;
  expandedBox.Min.z -= cam_EntityBoxExpand;

  this->TargetBox(expandedBox, seconds);

  if (seconds == 0.0f) {
    this->TargetNothing();
  }
}

/**
 * Address: 0x007A8640 (FUN_007A8640, Moho::CameraImpl::TargetEntities)
 * Mangled: ?TargetEntities@CameraImpl@Moho@@UAEXABV?$WeakSet@VUserEntity@Moho@@@2@_NMM@Z
 *
 * What it does:
 * Replaces the camera target weak-list from one entity weak-set, seeds timed
 * move toward the first target entity, and optionally enters/clears
 * entity-tracking mode with broadcaster notifications.
 */
void moho::CameraImpl::TargetEntities(
  const WeakSet<UserEntity>& entities,
  const bool trackEntities,
  const float zoom,
  const float seconds
)
{
  // TEMPORARY PROBE (do not commit)
  {
    static int sBudget = 0;
    if (sBudget < 20) {
      ++sBudget;
      gpg::Warnf("[CAMDIAG] TargetEntities name=%s track=%d zoom=%.1f seconds=%.2f", mName.c_str(),
                 trackEntities ? 1 : 0, zoom, seconds);
    }
  }

  mTargetTimeLeft = 0.0f;
  mTargetTime = 0u;
  mTargetEntities.clear();
  for (UserEntity* const entity : entities) {
    if (entity != nullptr) {
      mTargetEntities.push_back(WeakPtr<UserEntity>(entity));
    }
  }

  mActiveTarget = mTargetEntities.begin();
  if (mTargetEntities.size() == 0) {
    return;
  }

  TimedMoveInit(seconds, 0.0f);

  const UserEntity* const targetEntity = ActiveCameraTargetEntity(*this);
  if (targetEntity == nullptr) {
    return;
  }

  mTargetLocation = targetEntity->mVariableData.mCurTransform.pos_;
  mNearZoom = zoom;

  if (trackEntities) {
    mTargetType = kCameraTargetTypeEntity;
    BroadcastEvent(SCameraTracking{mName, 1});
  } else {
    if (mTargetType == kCameraTargetTypeEntity) {
      BroadcastEvent(SCameraTracking{mName, 0});
    }
    mTargetType = kCameraTargetTypeLocation;
  }

  SetupHermite();
}

/**
 * Address: 0x007A8EE0 (FUN_007A8EE0, Moho::CameraImpl::TargetNextEntity)
 * Mangled: ?TargetNextEntity@CameraImpl@Moho@@UAEXXZ
 *
 * What it does:
 * Advances active entity-target cursor to the next live weak target entry,
 * removing stale weak-link nodes and broadcasting tracking stop/start updates.
 */
void moho::CameraImpl::TargetNextEntity()
{
  if (mTargetEntities.size() == 0) {
    return;
  }

  while (true) {
    if (mActiveTarget == decltype(mActiveTarget){}) {
      mActiveTarget = mTargetEntities.end();
    }
    if (mActiveTarget != mTargetEntities.end()) {
      ++mActiveTarget;
    }
    if (mActiveTarget == mTargetEntities.end()) {
      mActiveTarget = mTargetEntities.begin();
    }

    const UserEntity* const activeEntity = ActiveCameraTargetEntity(*this);
    if (activeEntity != nullptr) {
      mTargetType = kCameraTargetTypeEntity;
      mTargetTimeLeft = 0.0f;
      mTargetTime = 0u;
      BroadcastEvent(SCameraTracking{mName, 1});
      return;
    }

    BroadcastEvent(SCameraTracking{mName, 0});

    // The dead target's node goes; the cursor moves to the one after it.
    mActiveTarget = mTargetEntities.erase(mActiveTarget);
    if (mTargetEntities.size() == 0) {
      return;
    }
  }
}

/**
 * Address: 0x007A8A20 (FUN_007A8A20, Moho::CameraImpl::TargetNoseCam)
 * Mangled: ?TargetNoseCam@CameraImpl@Moho@@QAEXABV?$WeakSet@VUserEntity@Moho@@@2@MMMM@Z
 *
 * What it does:
 * Replaces target weak-list, seeds timed transition by `seconds` and
 * `transition`, then aligns camera heading/pitch/zoom to the first entity's
 * current transform plus pitch-adjust lane.
 */
void moho::CameraImpl::TargetNoseCam(
  const WeakSet<UserEntity>& entities,
  const float pitchAdjust,
  const float zoom,
  const float seconds,
  const float transition
)
{
  if (mTargetType == kCameraTargetTypeEntity) {
    BroadcastEvent(SCameraTracking{mName, 0});
  }

  mTargetTimeLeft = 0.0f;
  mTargetTime = 0u;
  mTargetEntities.clear();
  for (UserEntity* const entity : entities) {
    if (entity != nullptr) {
      mTargetEntities.push_back(WeakPtr<UserEntity>(entity));
    }
  }

  mActiveTarget = mTargetEntities.begin();
  if (mTargetEntities.size() == 0) {
    return;
  }

  TimedMoveInit(seconds, transition);

  const UserEntity* const targetEntity = ActiveCameraTargetEntity(*this);
  if (targetEntity == nullptr) {
    return;
  }

  const VTransform& targetTransform = targetEntity->mVariableData.mCurTransform;
  mTargetLocation = targetTransform.pos_;
  mHeadingZoom =
    NormalizeQuadrantRelative(HeadingFromEntityOrientation(targetTransform.orient_), mTimedMoveHeading);
  mCurrentPitch = PitchFromEntityOrientation(targetTransform.orient_) + pitchAdjust;
  mNearZoom = zoom;
  mNoseCamPitchAdjust = pitchAdjust;
  mFarPitch = mCurrentPitch;
  mTargetType = kCameraTargetTypeNoseCam;
  mHeading = mHeadingZoom;
  mTargetZoom = mNearZoom;
  mOffset = mTargetLocation;
  ClampFocusPos();
  CalculateFOV();
}

/**
 * Address: 0x007A8D40 (FUN_007A8D40, Moho::CameraImpl::TargetManual)
 * Mangled: ?TargetManual@CameraImpl@Moho@@UAEXABV?$Vector3@M@Wm3@@MMMM@Z
 *
 * What it does:
 * Targets one world-space location plus heading/pitch/zoom lanes and either
 * applies the result immediately or seeds Hermite transition state.
 */
void moho::CameraImpl::TargetManual(
  const Wm3::Vec3f& position, const float heading, const float pitch, const float zoom, const float seconds
)
{
  // TEMPORARY PROBE (do not commit)
  {
    static int sBudget = 0;
    if (sBudget < 20) {
      ++sBudget;
      gpg::Warnf("[CAMDIAG] TargetManual name=%s pos=(%.1f,%.1f,%.1f) heading=%.3f pitch=%.3f zoom=%.1f seconds=%.2f",
                 mName.c_str(), position.x, position.y, position.z, heading, pitch, zoom, seconds);
    }
  }
  if (mTargetType == kCameraTargetTypeEntity) {
    BroadcastEvent(SCameraTracking{mName, 0});
  }

  TimedMoveInit(seconds, 0.0f);

  mCurrentPitch = pitch;
  mHeadingZoom = NormalizeQuadrantRelative(heading, mHeading);
  mNearZoom = zoom;
  mTargetLocation = position;

  if (seconds == 0.0f) {
    mTargetType = kCameraTargetTypeLocation;
    mHeading = mHeadingZoom;
    mFarPitch = mCurrentPitch;
    mTargetZoom = mNearZoom;
    mOffset = mTargetLocation;
    mIsRotated = 1u;
    ClampFocusPos();
    CalculateFOV();
  } else {
    mTargetType = kCameraTargetTypeHermite;
    SetupHermite();
  }
}

/**
 * Address: 0x007A8E90 (FUN_007A8E90, Moho::CameraImpl::SetZoom)
 * Mangled: ?SetZoom@CameraImpl@Moho@@QAEXMM@Z
 *
 * What it does:
 * Re-applies manual targeting at the current target position while keeping
 * the active heading and far-pitch lanes and substituting a new zoom/seconds
 * pair.
 */
void moho::CameraImpl::SetZoom(const float zoom, const float seconds)
{
  TargetManual(mTargetLocation, mHeading, mFarPitch, zoom, seconds);
}

/**
 * Address: 0x007AB080 (FUN_007AB080, cfunc_GetCamera)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetCameraL`.
 */
int moho::cfunc_GetCamera(lua_State* const luaContext)
{
  return cfunc_GetCameraL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007AB0A0 (FUN_007AB0A0, func_GetCamera_LuaFuncDef)
 *
 * What it does:
 * Publishes global Lua binder metadata for `GetCamera(name)`.
 */
moho::CScrLuaInitForm* moho::func_GetCamera_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kGetCameraName,
    &moho::cfunc_GetCamera,
    nullptr,
    kGlobalLuaClassName,
    kGetCameraHelpText
  );
  return &binder;
}

/**
 * Address: 0x007AB100 (FUN_007AB100, cfunc_GetCameraL)
 *
 * What it does:
 * Resolves one camera name from Lua and pushes the camera script object or
 * nil when no camera matches.
 */
int moho::cfunc_GetCameraL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetCameraHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaStackObject cameraNameArg(state, 1);
  const char* const cameraName = lua_tostring(rawState, 1);
  if (cameraName == nullptr) {
    cameraNameArg.TypeError("string");
  }

  RCamManager* const manager = CAM_GetManager();
  CameraImpl* const camera = manager->GetCamera(cameraName);
  if (camera != nullptr) {
    camera->mLuaObj.PushStack(state);
  } else {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
  }
  return 1;
}

/**
 * Address: 0x007AB4E0 (FUN_007AB4E0, cfunc_CameraImplSnapTo)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CameraImplSnapToL`.
 */
int moho::cfunc_CameraImplSnapTo(lua_State* const luaContext)
{
  return cfunc_CameraImplSnapToL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007AB500 (FUN_007AB500, func_CameraImplSnapTo_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CameraImpl:SnapTo`.
 */
moho::CScrLuaInitForm* moho::func_CameraImplSnapTo_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kCameraImplSnapToName,
    &moho::cfunc_CameraImplSnapTo,
    &CScrLuaMetatableFactory<CameraImpl>::Instance(),
    kCameraImplLuaClassName,
    kCameraImplSnapToHelpText
  );
  return &binder;
}

/**
 * Address: 0x007AB560 (FUN_007AB560, cfunc_CameraImplSnapToL)
 *
 * What it does:
 * Validates `Camera:SnapTo(position, orientationHPR, zoom)`, resolves Lua
 * camera/vector payloads, and applies an immediate manual camera target.
 */
int moho::cfunc_CameraImplSnapToL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 4) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCameraImplSnapToHelpText, 4, argumentCount);
  }

  const LuaPlus::LuaObject cameraObject(LuaPlus::LuaStackObject(state, 1));
  CameraImpl* const camera = SCR_FromLua_CameraImpl(cameraObject, state);

  const LuaPlus::LuaObject positionObject(LuaPlus::LuaStackObject(state, 2));
  const Wm3::Vec3f targetPosition = SCR_FromLuaCopy<Wm3::Vec3f>(positionObject);

  const LuaPlus::LuaObject orientationObject(LuaPlus::LuaStackObject(state, 3));
  const Wm3::Vec3f orientationHpr = SCR_FromLuaCopy<Wm3::Vec3f>(orientationObject);

  const LuaPlus::LuaStackObject zoomArg(state, 4);
  if (lua_type(rawState, 4) != LUA_TNUMBER) {
    zoomArg.TypeError("number");
  }
  const float targetZoom = static_cast<float>(lua_tonumber(rawState, 4));

  camera->TargetManual(targetPosition, orientationHpr.x, orientationHpr.y, targetZoom, 0.0f);
  return 0;
}

/**
 * Address: 0x007AB6E0 (FUN_007AB6E0, cfunc_CameraImplMoveTo)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CameraImplMoveToL`.
 */
int moho::cfunc_CameraImplMoveTo(lua_State* const luaContext)
{
  return cfunc_CameraImplMoveToL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007AB1B0 (FUN_007AB1B0, cfunc_CameraImplMoveToRegion)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CameraImplMoveToRegionL`.
 */
int moho::cfunc_CameraImplMoveToRegion(lua_State* const luaContext)
{
  return cfunc_CameraImplMoveToRegionL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007AB1D0 (FUN_007AB1D0, func_CameraImplMoveToRegion_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CameraImpl:MoveToRegion`.
 */
moho::CScrLuaInitForm* moho::func_CameraImplMoveToRegion_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kCameraImplMoveToRegionName,
    &moho::cfunc_CameraImplMoveToRegion,
    &CScrLuaMetatableFactory<CameraImpl>::Instance(),
    kCameraImplLuaClassName,
    kCameraImplMoveToRegionHelpText
  );
  return &binder;
}

/**
 * Address: 0x007AB230 (FUN_007AB230, cfunc_CameraImplMoveToRegionL)
 *
 * What it does:
 * Validates `Camera:MoveTo(region[,seconds])`, quantizes region corners to
 * terrain grid cell centers, samples corner elevations, and targets one world
 * box transition.
 */
int moho::cfunc_CameraImplMoveToRegionL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 2 || argumentCount > 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedBetweenArgsWarning, kCameraImplMoveToRegionHelpText, 2, 3, argumentCount);
  }

  const LuaPlus::LuaObject cameraObject(LuaPlus::LuaStackObject(state, 1));
  CameraImpl* const camera = SCR_FromLua_CameraImpl(cameraObject, state);

  const LuaPlus::LuaObject regionObject(LuaPlus::LuaStackObject(state, 2));
  const gpg::Rect2f regionRect = SCR_FromLuaCopy<gpg::Rect2f>(regionObject);

  float transitionSeconds = 0.0f;
  if (argumentCount > 2) {
    const LuaPlus::LuaStackObject secondsArg(state, 3);
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      secondsArg.TypeError("number");
    }
    transitionSeconds = static_cast<float>(lua_tonumber(rawState, 3));
  }

  const std::int16_t startXCell = static_cast<std::int16_t>(static_cast<int>(regionRect.x0 - 0.5f));
  const std::int16_t startZCell = static_cast<std::int16_t>(static_cast<int>(regionRect.z0 - 0.5f));
  const std::int16_t endXCell = static_cast<std::int16_t>(static_cast<int>(regionRect.x1 - 0.5f));
  const std::int16_t endZCell = static_cast<std::int16_t>(static_cast<int>(regionRect.z1 - 0.5f));

  const float startX = static_cast<float>(startXCell) + 0.5f;
  const float startZ = static_cast<float>(startZCell) + 0.5f;
  const float endX = static_cast<float>(endXCell) + 0.5f;
  const float endZ = static_cast<float>(endZCell) + 0.5f;

  const CHeightField* const heightField = camera->mTerrainMap->mHeightField.get();
  const float startElevation = heightField->GetElevation(startX, startZ);
  const float endElevation = heightField->GetElevation(endX, endZ);

  Wm3::AxisAlignedBox3f targetBox{};
  targetBox.Min.x = startX;
  targetBox.Min.y = startElevation;
  targetBox.Min.z = startZ;
  targetBox.Max.x = endX;
  targetBox.Max.y = endElevation;
  targetBox.Max.z = endZ;
  camera->TargetBox(targetBox, transitionSeconds);
  return 0;
}

/**
 * Address: 0x007AB760 (FUN_007AB760, cfunc_CameraImplMoveToL)
 *
 * What it does:
 * Validates `Camera:MoveTo(position, orientationHPR, zoom, seconds)`,
 * resolves typed camera/vector payloads from Lua, and dispatches manual camera
 * targeting with heading/pitch plus zoom/time lanes.
 */
int moho::cfunc_CameraImplMoveToL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 5) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCameraImplMoveToHelpText, 5, argumentCount);
  }

  const LuaPlus::LuaObject cameraObject(LuaPlus::LuaStackObject(state, 1));
  CameraImpl* const camera = SCR_FromLua_CameraImpl(cameraObject, state);

  const LuaPlus::LuaObject positionObject(LuaPlus::LuaStackObject(state, 2));
  const Wm3::Vec3f targetPosition = SCR_FromLuaCopy<Wm3::Vec3f>(positionObject);

  const LuaPlus::LuaObject orientationObject(LuaPlus::LuaStackObject(state, 3));
  const Wm3::Vec3f orientationHpr = SCR_FromLuaCopy<Wm3::Vec3f>(orientationObject);

  const LuaPlus::LuaStackObject zoomObject(state, 4);
  if (lua_type(state->m_state, 4) != LUA_TNUMBER) {
    zoomObject.TypeError("number");
  }
  const float targetZoom = static_cast<float>(lua_tonumber(state->m_state, 4));

  const LuaPlus::LuaStackObject secondsObject(state, 5);
  if (lua_type(state->m_state, 5) != LUA_TNUMBER) {
    secondsObject.TypeError("number");
  }
  const float transitionSeconds = static_cast<float>(lua_tonumber(state->m_state, 5));

  camera->TargetManual(targetPosition, orientationHpr.x, orientationHpr.y, targetZoom, transitionSeconds);
  return 0;
}

/**
 * Address: 0x007AC760 (FUN_007AC760, cfunc_CameraImplSetZoom)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CameraImplSetZoomL`.
 */
int moho::cfunc_CameraImplSetZoom(lua_State* const luaContext)
{
  return cfunc_CameraImplSetZoomL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007AC780 (FUN_007AC780, func_CameraImplSetZoom_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CameraImpl:SetZoom`.
 */
moho::CScrLuaInitForm* moho::func_CameraImplSetZoom_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetZoom",
    &moho::cfunc_CameraImplSetZoom,
    &CScrLuaMetatableFactory<CameraImpl>::Instance(),
    kCameraImplLuaClassName,
    kCameraImplSetZoomHelpText
  );
  return &binder;
}

/**
 * Address: 0x007AC7E0 (FUN_007AC7E0, cfunc_CameraImplSetZoomL)
 *
 * What it does:
 * Validates `Camera:SetZoom(zoom,seconds)`, keeps current target position and
 * heading/pitch lanes, and dispatches manual camera targeting with new zoom
 * and transition seconds.
 */
int moho::cfunc_CameraImplSetZoomL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCameraImplSetZoomHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject cameraObject(LuaPlus::LuaStackObject(state, 1));
  CameraImpl* const camera = SCR_FromLua_CameraImpl(cameraObject, state);

  const LuaPlus::LuaStackObject secondsArg(state, 3);
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    secondsArg.TypeError("number");
  }
  const float transitionSeconds = static_cast<float>(lua_tonumber(rawState, 3));

  const LuaPlus::LuaStackObject zoomArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    zoomArg.TypeError("number");
  }
  const float targetZoom = static_cast<float>(lua_tonumber(rawState, 2));

  camera->SetZoom(targetZoom, transitionSeconds);
  return 0;
}

/**
 * Address: 0x007AC930 (FUN_007AC930, cfunc_CameraImplSetTargetZoom)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CameraImplSetTargetZoomL`.
 */
int moho::cfunc_CameraImplSetTargetZoom(lua_State* const luaContext)
{
  return cfunc_CameraImplSetTargetZoomL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007AC950 (FUN_007AC950, func_CameraImplSetTargetZoom_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CameraImpl:SetTargetZoom`.
 */
moho::CScrLuaInitForm* moho::func_CameraImplSetTargetZoom_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kCameraImplSetTargetZoomName,
    &moho::cfunc_CameraImplSetTargetZoom,
    &CScrLuaMetatableFactory<CameraImpl>::Instance(),
    kCameraImplLuaClassName,
    kCameraImplSetTargetZoomHelpText
  );
  return &binder;
}

/**
 * Address: 0x007AC9B0 (FUN_007AC9B0, cfunc_CameraImplSetTargetZoomL)
 *
 * What it does:
 * Validates `Camera:SetTargetZoom(zoom)` and updates one runtime near-zoom
 * lane directly from Lua.
 */
int moho::cfunc_CameraImplSetTargetZoomL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCameraImplSetTargetZoomHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject cameraObject(LuaPlus::LuaStackObject(state, 1));
  CameraImpl* const camera = SCR_FromLua_CameraImpl(cameraObject, state);

  const LuaPlus::LuaStackObject targetZoomArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    targetZoomArg.TypeError("number");
  }

  camera->mNearZoom = static_cast<float>(lua_tonumber(rawState, 2));
  return 0;
}

/**
 * Address: 0x007AB700 (FUN_007AB700, func_CameraImplMoveTo_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CameraImpl:MoveTo`.
 */
moho::CScrLuaInitForm* moho::func_CameraImplMoveTo_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kCameraImplMoveToName,
    &moho::cfunc_CameraImplMoveTo,
    &CScrLuaMetatableFactory<CameraImpl>::Instance(),
    kCameraImplLuaClassName,
    kCameraImplMoveToHelpText
  );
  return &binder;
}

/**
 * Address: 0x007AD650 (FUN_007AD650, cfunc_CameraImplGetMinZoom)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CameraImplGetMinZoomL`.
 */
int moho::cfunc_CameraImplGetMinZoom(lua_State* const luaContext)
{
  return cfunc_CameraImplGetMinZoomL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007AD670 (FUN_007AD670, func_CameraImplGetMinZoom_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CameraImpl:GetMinZoom`.
 */
moho::CScrLuaInitForm* moho::func_CameraImplGetMinZoom_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kCameraImplGetMinZoomName,
    &moho::cfunc_CameraImplGetMinZoom,
    &CScrLuaMetatableFactory<CameraImpl>::Instance(),
    kCameraImplLuaClassName,
    kCameraImplGetMinZoomHelpText
  );
  return &binder;
}

/**
 * Address: 0x007AD6D0 (FUN_007AD6D0, cfunc_CameraImplGetMinZoomL)
 *
 * What it does:
 * Validates `Camera:GetMinZoom()`, pushes the global near-zoom value, and
 * returns one Lua result.
 */
int moho::cfunc_CameraImplGetMinZoomL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCameraImplGetMinZoomHelpText, 1, argumentCount);
  }

  lua_pushnumber(rawState, cam_NearZoom);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x007AD720 (FUN_007AD720, cfunc_CameraImplSetMaxZoomMult)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CameraImplSetMaxZoomMultL`.
 */
int moho::cfunc_CameraImplSetMaxZoomMult(lua_State* const luaContext)
{
  return cfunc_CameraImplSetMaxZoomMultL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007AD740 (FUN_007AD740, func_CameraImplSetMaxZoomMult_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CameraImpl:SetMaxZoomMult`.
 */
moho::CScrLuaInitForm* moho::func_CameraImplSetMaxZoomMult_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kCameraImplSetMaxZoomMultName,
    &moho::cfunc_CameraImplSetMaxZoomMult,
    &CScrLuaMetatableFactory<CameraImpl>::Instance(),
    kCameraImplLuaClassName,
    kCameraImplSetMaxZoomMultHelpText
  );
  return &binder;
}

/**
 * Address: 0x007AD7A0 (FUN_007AD7A0, cfunc_CameraImplSetMaxZoomMultL)
 *
 * What it does:
 * Validates `Camera:SetMaxZoomMult(mult)` and applies one max-zoom multiplier
 * through the camera virtual lane.
 */
int moho::cfunc_CameraImplSetMaxZoomMultL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCameraImplSetMaxZoomMultHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject cameraObject(LuaPlus::LuaStackObject(state, 1));
  CameraImpl* const camera = SCR_FromLua_CameraImpl(cameraObject, state);

  const LuaPlus::LuaStackObject maxZoomMultArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    maxZoomMultArg.TypeError("number");
  }

  camera->SetMaxZoomMult(static_cast<float>(lua_tonumber(rawState, 2)));
  return 0;
}

/**
 * Address: 0x007ACAA0 (FUN_007ACAA0, cfunc_CameraImplSetAccMode)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CameraImplSetAccModeL`.
 */
int moho::cfunc_CameraImplSetAccMode(lua_State* const luaContext)
{
  return cfunc_CameraImplSetAccModeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007ACB20 (FUN_007ACB20, cfunc_CameraImplSetAccModeL)
 *
 * What it does:
 * Validates `Camera:SetAccMode(accTypeName)`, resolves typed camera payload
 * and one string acceleration token from Lua, then dispatches
 * `CameraImpl::CameraSetAccType`.
 */
int moho::cfunc_CameraImplSetAccModeL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCameraImplSetAccModeHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject cameraObject(LuaPlus::LuaStackObject(state, 1));
  CameraImpl* const camera = SCR_FromLua_CameraImpl(cameraObject, state);

  const LuaPlus::LuaStackObject modeObject(state, 2);
  const char* const modeText = lua_tostring(state->m_state, 2);
  if (modeText == nullptr) {
    modeObject.TypeError("string");
  }

  msvc8::string accTypeName{};
  accTypeName.assign_owned(modeText != nullptr ? modeText : "");
  camera->CameraSetAccType(accTypeName);
  return 0;
}

/**
 * Address: 0x007ACAC0 (FUN_007ACAC0, func_CameraImplSetAccMode_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CameraImpl:SetAccMode`.
 */
moho::CScrLuaInitForm* moho::func_CameraImplSetAccMode_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kCameraImplSetAccModeName,
    &moho::cfunc_CameraImplSetAccMode,
    &CScrLuaMetatableFactory<CameraImpl>::Instance(),
    kCameraImplLuaClassName,
    kCameraImplSetAccModeHelpText
  );
  return &binder;
}

/**
 * Address: 0x007AD890 (FUN_007AD890, cfunc_CameraImplSpin)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CameraImplSpinL`.
 */
int moho::cfunc_CameraImplSpin(lua_State* const luaContext)
{
  return cfunc_CameraImplSpinL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007AD910 (FUN_007AD910, cfunc_CameraImplSpinL)
 *
 * What it does:
 * Reads heading plus optional zoom spin rates from Lua and updates camera spin
 * control lanes.
 */
int moho::cfunc_CameraImplSpinL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount < 2 || argumentCount > 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedBetweenArgsWarning, kCameraImplSpinHelpText, 2, 3, argumentCount);
  }

  lua_settop(state->m_state, 3);

  const LuaPlus::LuaObject cameraObject(LuaPlus::LuaStackObject(state, 1));
  CameraImpl* const camera = SCR_FromLua_CameraImpl(cameraObject, state);

  float zoomRate = 0.0f;
  if (lua_type(state->m_state, 3) != LUA_TNIL) {
    const LuaPlus::LuaStackObject zoomRateArg(state, 3);
    if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
      zoomRateArg.TypeError("number");
    }
    zoomRate = static_cast<float>(lua_tonumber(state->m_state, 3));
  }

  const LuaPlus::LuaStackObject headingRateArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    headingRateArg.TypeError("number");
  }

  camera->mHeadingRate = static_cast<float>(lua_tonumber(state->m_state, 2));
  camera->mZoomRate = zoomRate;
  camera->mIsRotated = true;
  camera->mTargetType = kCameraTargetTypeHermite;
  return 0;
}

/**
 * Address: 0x007AD8B0 (FUN_007AD8B0, func_CameraImplSpin_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CameraImpl:Spin`.
 */
moho::CScrLuaInitForm* moho::func_CameraImplSpin_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kCameraImplSpinName,
    &moho::cfunc_CameraImplSpin,
    &CScrLuaMetatableFactory<CameraImpl>::Instance(),
    kCameraImplLuaClassName,
    kCameraImplSpinHelpText
  );
  return &binder;
}

/**
 * Address: 0x007AB930 (FUN_007AB930, cfunc_CameraImplReset)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CameraImplResetL`.
 */
int moho::cfunc_CameraImplReset(lua_State* const luaContext)
{
  return cfunc_CameraImplResetL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007AB9B0 (FUN_007AB9B0, cfunc_CameraImplResetL)
 *
 * What it does:
 * Validates `Camera:Reset()`, resolves one camera payload, and invokes
 * `CameraImpl::CameraReset`.
 */
int moho::cfunc_CameraImplResetL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCameraImplResetHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject cameraObject(LuaPlus::LuaStackObject(state, 1));
  CameraImpl* const camera = SCR_FromLua_CameraImpl(cameraObject, state);
  camera->CameraReset();
  return 0;
}

/**
 * Address: 0x007AB950 (FUN_007AB950, func_CameraImplReset_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CameraImpl:Reset`.
 */
moho::CScrLuaInitForm* moho::func_CameraImplReset_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kCameraImplResetName,
    &moho::cfunc_CameraImplReset,
    &CScrLuaMetatableFactory<CameraImpl>::Instance(),
    kCameraImplLuaClassName,
    kCameraImplResetHelpText
  );
  return &binder;
}

/**
 * Address: 0x007ABA80 (FUN_007ABA80, func_CameraImplTrackEntities_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CameraImpl:TrackEntities`.
 */
moho::CScrLuaInitForm* moho::func_CameraImplTrackEntities_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kCameraImplTrackEntitiesName,
    &moho::cfunc_CameraImplTrackEntities,
    &CScrLuaMetatableFactory<CameraImpl>::Instance(),
    kCameraImplLuaClassName,
    kCameraImplTrackEntitiesHelpText
  );
  return &binder;
}

/**
 * Address: 0x007ABA60 (FUN_007ABA60, cfunc_CameraImplTrackEntities)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CameraImplTrackEntitiesL`.
 */
int moho::cfunc_CameraImplTrackEntities(lua_State* const luaContext)
{
  return cfunc_CameraImplTrackEntitiesL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007ABAE0 (FUN_007ABAE0, cfunc_CameraImplTrackEntitiesL)
 *
 * What it does:
 * Validates `Camera:TrackEntities(ents,zoom,seconds)`, resolves one camera plus
 * weak-set of session entities from Lua string IDs, and dispatches
 * tracked-entity targeting.
 */
int moho::cfunc_CameraImplTrackEntitiesL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 4) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCameraImplTrackEntitiesHelpText, 4, argumentCount);
  }

  const LuaPlus::LuaObject cameraObject(LuaPlus::LuaStackObject(state, 1));
  CameraImpl* const camera = SCR_FromLua_CameraImpl(cameraObject, state);

  const LuaPlus::LuaStackObject secondsArg(state, 4);
  if (lua_type(rawState, 4) != LUA_TNUMBER) {
    secondsArg.TypeError("number");
  }
  const float seconds = static_cast<float>(lua_tonumber(rawState, 4));

  const LuaPlus::LuaStackObject zoomArg(state, 3);
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    zoomArg.TypeError("number");
  }
  const float zoom = static_cast<float>(lua_tonumber(rawState, 3));

  WeakSet<UserEntity> entitySet;
  AppendLuaEntityIdArrayToSelectionSet(state, 2, entitySet);

  camera->TargetEntities(entitySet, true, zoom, seconds);
  return 0;
}

/**
 * Address: 0x007ABE40 (FUN_007ABE40, cfunc_CameraImplTargetEntities)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CameraImplTargetEntitiesL`.
 */
int moho::cfunc_CameraImplTargetEntities(lua_State* const luaContext)
{
  return cfunc_CameraImplTargetEntitiesL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007ABEC0 (FUN_007ABEC0, cfunc_CameraImplTargetEntitiesL)
 *
 * What it does:
 * Validates `Camera:TargetEntities(ents,zoom,seconds)`, resolves one camera
 * plus weak-set of session entities from Lua string IDs, and dispatches
 * non-tracking multi-entity targeting.
 */
int moho::cfunc_CameraImplTargetEntitiesL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 4) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCameraImplTargetEntitiesHelpText, 4, argumentCount);
  }

  const LuaPlus::LuaObject cameraObject(LuaPlus::LuaStackObject(state, 1));
  CameraImpl* const camera = SCR_FromLua_CameraImpl(cameraObject, state);

  const LuaPlus::LuaStackObject secondsArg(state, 4);
  if (lua_type(rawState, 4) != LUA_TNUMBER) {
    secondsArg.TypeError("number");
  }
  const float seconds = static_cast<float>(lua_tonumber(rawState, 4));

  const LuaPlus::LuaStackObject zoomArg(state, 3);
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    zoomArg.TypeError("number");
  }
  const float zoom = static_cast<float>(lua_tonumber(rawState, 3));

  WeakSet<UserEntity> entitySet;
  AppendLuaEntityIdArrayToSelectionSet(state, 2, entitySet);

  camera->TargetEntities(entitySet, false, zoom, seconds);
  return 0;
}

/**
 * Address: 0x007AC1C0 (FUN_007AC1C0, cfunc_CameraImplNoseCam)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CameraImplNoseCamL`.
 */
int moho::cfunc_CameraImplNoseCam(lua_State* const luaContext)
{
  return cfunc_CameraImplNoseCamL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007AC240 (FUN_007AC240, cfunc_CameraImplNoseCamL)
 *
 * What it does:
 * Validates `Camera:NoseCam(ent,pitchAdjust,zoom,seconds,transition)`,
 * resolves one target entity by string ID, and dispatches nose-camera target
 * alignment.
 */
int moho::cfunc_CameraImplNoseCamL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 6) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCameraImplNoseCamHelpText, 6, argumentCount);
  }

  const LuaPlus::LuaObject cameraObject(LuaPlus::LuaStackObject(state, 1));
  CameraImpl* const camera = SCR_FromLua_CameraImpl(cameraObject, state);

  const LuaPlus::LuaStackObject entityIdArg(state, 2);
  const char* const entityIdText = lua_tostring(rawState, 2);
  if (entityIdText == nullptr) {
    entityIdArg.TypeError("string");
  }

  WeakSet<UserEntity> entitySet;
  const int entityId = entityIdText != nullptr ? std::atoi(entityIdText) : 0;
  if (UserEntity* const entity = FindSessionEntityById(moho::WLD_GetActiveSession(), entityId); entity != nullptr) {
    (void)entitySet.Add(entity);
  }

  const LuaPlus::LuaStackObject transitionArg(state, 6);
  if (lua_type(rawState, 6) != LUA_TNUMBER) {
    transitionArg.TypeError("number");
  }
  const float transition = static_cast<float>(lua_tonumber(rawState, 6));

  const LuaPlus::LuaStackObject secondsArg(state, 5);
  if (lua_type(rawState, 5) != LUA_TNUMBER) {
    secondsArg.TypeError("number");
  }
  const float seconds = static_cast<float>(lua_tonumber(rawState, 5));

  const LuaPlus::LuaStackObject zoomArg(state, 4);
  if (lua_type(rawState, 4) != LUA_TNUMBER) {
    zoomArg.TypeError("number");
  }
  const float zoom = static_cast<float>(lua_tonumber(rawState, 4));

  const LuaPlus::LuaStackObject pitchAdjustArg(state, 3);
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    pitchAdjustArg.TypeError("number");
  }
  const float pitchAdjust = static_cast<float>(lua_tonumber(rawState, 3));

  camera->TargetNoseCam(entitySet, pitchAdjust, zoom, seconds, transition);
  return 0;
}

/**
 * Address: 0x007ABE60 (FUN_007ABE60, func_CameraImplTargetEntities_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CameraImpl:TargetEntities`.
 */
moho::CScrLuaInitForm* moho::func_CameraImplTargetEntities_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kCameraImplTargetEntitiesName,
    &moho::cfunc_CameraImplTargetEntities,
    &CScrLuaMetatableFactory<CameraImpl>::Instance(),
    kCameraImplLuaClassName,
    kCameraImplTargetEntitiesHelpText
  );
  return &binder;
}

/**
 * Address: 0x007AC1E0 (FUN_007AC1E0, func_CameraImplNoseCam_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CameraImpl:NoseCam`.
 */
moho::CScrLuaInitForm* moho::func_CameraImplNoseCam_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kCameraImplNoseCamName,
    &moho::cfunc_CameraImplNoseCam,
    &CScrLuaMetatableFactory<CameraImpl>::Instance(),
    kCameraImplLuaClassName,
    kCameraImplNoseCamHelpText
  );
  return &binder;
}

/**
 * Address: 0x007AC500 (FUN_007AC500, cfunc_CameraImplHoldRotation)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CameraImplHoldRotationL`.
 */
int moho::cfunc_CameraImplHoldRotation(lua_State* const luaContext)
{
  return cfunc_CameraImplHoldRotationL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007AC580 (FUN_007AC580, cfunc_CameraImplHoldRotationL)
 *
 * What it does:
 * Validates `Camera:HoldRotation()`, resolves one camera payload, and applies
 * hold-rotation runtime flags.
 */
int moho::cfunc_CameraImplHoldRotationL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCameraImplHoldRotationHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject cameraObject(LuaPlus::LuaStackObject(state, 1));
  CameraImpl* const camera = SCR_FromLua_CameraImpl(cameraObject, state);
  camera->CameraHoldRotation();
  return 0;
}

/**
 * Address: 0x007AC520 (FUN_007AC520, func_CameraImplHoldRotation_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CameraImpl:HoldRotation`.
 */
moho::CScrLuaInitForm* moho::func_CameraImplHoldRotation_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kCameraImplHoldRotationName,
    &moho::cfunc_CameraImplHoldRotation,
    &CScrLuaMetatableFactory<CameraImpl>::Instance(),
    kCameraImplLuaClassName,
    kCameraImplHoldRotationHelpText
  );
  return &binder;
}

/**
 * Address: 0x007AC630 (FUN_007AC630, cfunc_CameraImplRevertRotation)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CameraImplRevertRotationL`.
 */
int moho::cfunc_CameraImplRevertRotation(lua_State* const luaContext)
{
  return cfunc_CameraImplRevertRotationL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007AC6B0 (FUN_007AC6B0, cfunc_CameraImplRevertRotationL)
 *
 * What it does:
 * Validates `Camera:RevertRotation()`, resolves one camera payload, and
 * invokes `CameraImpl::CameraRevertRotation`.
 */
int moho::cfunc_CameraImplRevertRotationL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCameraImplRevertRotationHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject cameraObject(LuaPlus::LuaStackObject(state, 1));
  CameraImpl* const camera = SCR_FromLua_CameraImpl(cameraObject, state);
  camera->CameraRevertRotation();
  return 0;
}

/**
 * Address: 0x007AC650 (FUN_007AC650, func_CameraImplRevertRotation_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CameraImpl:RevertRotation`.
 */
moho::CScrLuaInitForm* moho::func_CameraImplRevertRotation_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kCameraImplRevertRotationName,
    &moho::cfunc_CameraImplRevertRotation,
    &CScrLuaMetatableFactory<CameraImpl>::Instance(),
    kCameraImplLuaClassName,
    kCameraImplRevertRotationHelpText
  );
  return &binder;
}

/**
 * Address: 0x007ACC40 (FUN_007ACC40, cfunc_CameraImplGetZoom)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CameraImplGetZoomL`.
 */
int moho::cfunc_CameraImplGetZoom(lua_State* const luaContext)
{
  return cfunc_CameraImplGetZoomL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007ACCC0 (FUN_007ACCC0, cfunc_CameraImplGetZoomL)
 *
 * What it does:
 * Validates `Camera:GetZoom()`, resolves one camera payload, and pushes the
 * current target-zoom scalar.
 */
int moho::cfunc_CameraImplGetZoomL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCameraImplGetZoomHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject cameraObject(LuaPlus::LuaStackObject(state, 1));
  CameraImpl* const camera = SCR_FromLua_CameraImpl(cameraObject, state);
  lua_pushnumber(rawState, camera->CameraGetTargetZoom());
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x007ACC60 (FUN_007ACC60, func_CameraImplGetZoom_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CameraImpl:GetZoom`.
 */
moho::CScrLuaInitForm* moho::func_CameraImplGetZoom_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kCameraImplGetZoomName,
    &moho::cfunc_CameraImplGetZoom,
    &CScrLuaMetatableFactory<CameraImpl>::Instance(),
    kCameraImplLuaClassName,
    kCameraImplGetZoomHelpText
  );
  return &binder;
}

/**
 * Address: 0x007ACD80 (FUN_007ACD80, cfunc_CameraImplGetFocusPosition)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CameraImplGetFocusPositionL`.
 */
int moho::cfunc_CameraImplGetFocusPosition(lua_State* const luaContext)
{
  return cfunc_CameraImplGetFocusPositionL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007ACE00 (FUN_007ACE00, cfunc_CameraImplGetFocusPositionL)
 *
 * What it does:
 * Resolves one camera object and pushes its focus-position vector payload.
 */
int moho::cfunc_CameraImplGetFocusPositionL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCameraImplGetFocusPositionHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject cameraObject(LuaPlus::LuaStackObject(state, 1));
  CameraImpl* const camera = SCR_FromLua_CameraImpl(cameraObject, state);
  LuaPlus::LuaObject focusPositionObject = SCR_ToLua<Wm3::Vector3<float>>(state, camera->CameraGetOffset());
  focusPositionObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x007ACDA0 (FUN_007ACDA0, func_CameraImplGetFocusPosition_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CameraImpl:GetFocusPosition`.
 */
moho::CScrLuaInitForm* moho::func_CameraImplGetFocusPosition_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kCameraImplGetFocusPositionName,
    &moho::cfunc_CameraImplGetFocusPosition,
    &CScrLuaMetatableFactory<CameraImpl>::Instance(),
    kCameraImplLuaClassName,
    kCameraImplGetFocusPositionHelpText
  );
  return &binder;
}

/**
 * Address: 0x007ACEE0 (FUN_007ACEE0, cfunc_CameraImplSaveSettings)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CameraImplSaveSettingsL`.
 */
int moho::cfunc_CameraImplSaveSettings(lua_State* const luaContext)
{
  return cfunc_CameraImplSaveSettingsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007ACF60 (FUN_007ACF60, cfunc_CameraImplSaveSettingsL)
 *
 * What it does:
 * Captures one camera snapshot table (`Focus`, `Zoom`, `Pitch`, `Heading`)
 * from the current camera runtime and returns it to Lua.
 */
int moho::cfunc_CameraImplSaveSettingsL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCameraImplSaveSettingsHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject cameraObject(LuaPlus::LuaStackObject(state, 1));
  CameraImpl* const camera = SCR_FromLua_CameraImpl(cameraObject, state);

  LuaPlus::LuaObject settingsObject;
  settingsObject.AssignNewTable(state, 0, 0);

  LuaPlus::LuaObject focusObject = SCR_ToLua<Wm3::Vector3<float>>(state, camera->CameraGetOffset());
  settingsObject.SetObject("Focus", focusObject);
  settingsObject.SetNumber("Zoom", camera->CameraGetTargetZoom());
  settingsObject.SetNumber("Pitch", camera->mFarPitch);
  settingsObject.SetNumber("Heading", camera->mHeading);
  settingsObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x007ACF00 (FUN_007ACF00, func_CameraImplSaveSettings_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CameraImpl:SaveSettings`.
 */
moho::CScrLuaInitForm* moho::func_CameraImplSaveSettings_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kCameraImplSaveSettingsName,
    &moho::cfunc_CameraImplSaveSettings,
    &CScrLuaMetatableFactory<CameraImpl>::Instance(),
    kCameraImplLuaClassName,
    kCameraImplSaveSettingsHelpText
  );
  return &binder;
}

/**
 * Address: 0x007AD0D0 (FUN_007AD0D0, cfunc_CameraImplRestoreSettings)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CameraImplRestoreSettingsL`.
 */
int moho::cfunc_CameraImplRestoreSettings(lua_State* const luaContext)
{
  return cfunc_CameraImplRestoreSettingsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007AD150 (FUN_007AD150, cfunc_CameraImplRestoreSettingsL)
 *
 * What it does:
 * Reads one saved camera snapshot table (`Focus`, `Zoom`, `Pitch`,
 * `Heading`), restores manual target state immediately, then clears timed
 * targeting and reapplies rotation-revert semantics.
 */
int moho::cfunc_CameraImplRestoreSettingsL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCameraImplRestoreSettingsHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject cameraObject(LuaPlus::LuaStackObject(state, 1));
  CameraImpl* const camera = SCR_FromLua_CameraImpl(cameraObject, state);

  lua_pushstring(rawState, "Focus");
  lua_rawget(rawState, 2);
  const LuaPlus::LuaObject focusObject(LuaPlus::LuaStackObject(state, lua_gettop(rawState)));

  lua_pushstring(rawState, "Zoom");
  lua_rawget(rawState, 2);
  const int zoomIndex = lua_gettop(rawState);
  const LuaPlus::LuaStackObject zoomArg(state, zoomIndex);
  if (lua_type(rawState, zoomIndex) != LUA_TNUMBER) {
    zoomArg.TypeError("number");
  }
  const float zoom = static_cast<float>(lua_tonumber(rawState, zoomIndex));

  lua_pushstring(rawState, "Pitch");
  lua_rawget(rawState, 2);
  const int pitchIndex = lua_gettop(rawState);
  const LuaPlus::LuaStackObject pitchArg(state, pitchIndex);
  if (lua_type(rawState, pitchIndex) != LUA_TNUMBER) {
    pitchArg.TypeError("number");
  }
  const float pitch = static_cast<float>(lua_tonumber(rawState, pitchIndex));

  lua_pushstring(rawState, "Heading");
  lua_rawget(rawState, 2);
  const int headingIndex = lua_gettop(rawState);
  const LuaPlus::LuaStackObject headingArg(state, headingIndex);
  if (lua_type(rawState, headingIndex) != LUA_TNUMBER) {
    headingArg.TypeError("number");
  }
  const float heading = static_cast<float>(lua_tonumber(rawState, headingIndex));

  const Wm3::Vec3f focus = SCR_FromLuaCopy<Wm3::Vec3f>(focusObject);
  camera->TargetManual(focus, heading, pitch, zoom, 0.0f);
  TargetNothingRuntime(camera);
  camera->CameraRevertRotation();
  return 0;
}

/**
 * Address: 0x007AD0F0 (FUN_007AD0F0, func_CameraImplRestoreSettings_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CameraImpl:RestoreSettings`.
 */
moho::CScrLuaInitForm* moho::func_CameraImplRestoreSettings_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kCameraImplRestoreSettingsName,
    &moho::cfunc_CameraImplRestoreSettings,
    &CScrLuaMetatableFactory<CameraImpl>::Instance(),
    kCameraImplLuaClassName,
    kCameraImplRestoreSettingsHelpText
  );
  return &binder;
}

/**
 * Address: 0x007AD3D0 (FUN_007AD3D0, cfunc_CameraImplGetTargetZoom)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CameraImplGetTargetZoomL`.
 */
int moho::cfunc_CameraImplGetTargetZoom(lua_State* const luaContext)
{
  return cfunc_CameraImplGetTargetZoomL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007AD3F0 (FUN_007AD3F0, func_CameraImplGetTargetZoom_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CameraImpl:GetTargetZoom`.
 */
moho::CScrLuaInitForm* moho::func_CameraImplGetTargetZoom_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kCameraImplGetTargetZoomName,
    &moho::cfunc_CameraImplGetTargetZoom,
    &CScrLuaMetatableFactory<CameraImpl>::Instance(),
    kCameraImplLuaClassName,
    kCameraImplGetTargetZoomHelpText
  );
  return &binder;
}

/**
 * Address: 0x007AD450 (FUN_007AD450, cfunc_CameraImplGetTargetZoomL)
 *
 * What it does:
 * Validates `Camera:GetTargetZoom()`, resolves typed camera payload, pushes
 * current near-zoom lane, and returns one Lua result.
 */
int moho::cfunc_CameraImplGetTargetZoomL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCameraImplGetTargetZoomHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject cameraObject(LuaPlus::LuaStackObject(state, 1));
  CameraImpl* const camera = SCR_FromLua_CameraImpl(cameraObject, state);

  lua_pushnumber(rawState, camera->mNearZoom);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x007AD510 (FUN_007AD510, cfunc_CameraImplGetMaxZoom)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CameraImplGetMaxZoomL`.
 */
int moho::cfunc_CameraImplGetMaxZoom(lua_State* const luaContext)
{
  return cfunc_CameraImplGetMaxZoomL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007AD530 (FUN_007AD530, func_CameraImplGetMaxZoom_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CameraImpl:GetMaxZoom`.
 */
moho::CScrLuaInitForm* moho::func_CameraImplGetMaxZoom_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kCameraImplGetMaxZoomName,
    &moho::cfunc_CameraImplGetMaxZoom,
    &CScrLuaMetatableFactory<CameraImpl>::Instance(),
    kCameraImplLuaClassName,
    kCameraImplGetMaxZoomHelpText
  );
  return &binder;
}

/**
 * Address: 0x007AD590 (FUN_007AD590, cfunc_CameraImplGetMaxZoomL)
 *
 * What it does:
 * Validates `Camera:GetMaxZoom()`, resolves typed camera payload, queries
 * runtime max zoom through virtual lane, and returns one Lua result.
 */
int moho::cfunc_CameraImplGetMaxZoomL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCameraImplGetMaxZoomHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject cameraObject(LuaPlus::LuaStackObject(state, 1));
  CameraImpl* const camera = SCR_FromLua_CameraImpl(cameraObject, state);

  lua_pushnumber(rawState, camera->GetMaxZoom());
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x007ADA90 (FUN_007ADA90, cfunc_CameraImplUseGameClock)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CameraImplUseGameClockL`.
 */
int moho::cfunc_CameraImplUseGameClock(lua_State* const luaContext)
{
  return cfunc_CameraImplUseGameClockL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007ADB10 (FUN_007ADB10, cfunc_CameraImplUseGameClockL)
 *
 * What it does:
 * Validates `Camera:UseGameClock()`, resolves one camera payload, and switches
 * camera timing to game-clock mode.
 */
int moho::cfunc_CameraImplUseGameClockL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCameraImplUseGameClockHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject cameraObject(LuaPlus::LuaStackObject(state, 1));
  CameraImpl* const camera = SCR_FromLua_CameraImpl(cameraObject, state);
  camera->SetTimeSource(static_cast<ECamTimeSource>(kCameraTimeSourceGame));
  return 0;
}

/**
 * Address: 0x007ADAB0 (FUN_007ADAB0, func_CameraImplUseGameClock_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CameraImpl:UseGameClock`.
 */
moho::CScrLuaInitForm* moho::func_CameraImplUseGameClock_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kCameraImplUseGameClockName,
    &moho::cfunc_CameraImplUseGameClock,
    &CScrLuaMetatableFactory<CameraImpl>::Instance(),
    kCameraImplLuaClassName,
    kCameraImplUseGameClockHelpText
  );
  return &binder;
}

/**
 * Address: 0x007ADBC0 (FUN_007ADBC0, cfunc_CameraImplUseSystemClock)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CameraImplUseSystemClockL`.
 */
int moho::cfunc_CameraImplUseSystemClock(lua_State* const luaContext)
{
  return cfunc_CameraImplUseSystemClockL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007ADC40 (FUN_007ADC40, cfunc_CameraImplUseSystemClockL)
 *
 * What it does:
 * Validates `Camera:UseSystemClock()`, resolves one camera payload, and
 * switches camera timing to system-clock mode.
 */
int moho::cfunc_CameraImplUseSystemClockL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCameraImplUseSystemClockHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject cameraObject(LuaPlus::LuaStackObject(state, 1));
  CameraImpl* const camera = SCR_FromLua_CameraImpl(cameraObject, state);
  camera->SetTimeSource(static_cast<ECamTimeSource>(kCameraTimeSourceSystem));
  return 0;
}

/**
 * Address: 0x007ADBE0 (FUN_007ADBE0, func_CameraImplUseSystemClock_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CameraImpl:UseSystemClock`.
 */
moho::CScrLuaInitForm* moho::func_CameraImplUseSystemClock_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kCameraImplUseSystemClockName,
    &moho::cfunc_CameraImplUseSystemClock,
    &CScrLuaMetatableFactory<CameraImpl>::Instance(),
    kCameraImplLuaClassName,
    kCameraImplUseSystemClockHelpText
  );
  return &binder;
}

/**
 * Address: 0x007ADCF0 (FUN_007ADCF0, cfunc_CameraImplEnableEaseInOut)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CameraImplEnableEaseInOutL`.
 */
int moho::cfunc_CameraImplEnableEaseInOut(lua_State* const luaContext)
{
  return cfunc_CameraImplEnableEaseInOutL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007ADD70 (FUN_007ADD70, cfunc_CameraImplEnableEaseInOutL)
 *
 * What it does:
 * Validates `Camera:EnableEaseInOut()`, resolves one camera payload, and
 * enables ease-in/out targeting behavior.
 */
int moho::cfunc_CameraImplEnableEaseInOutL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCameraImplEnableEaseInOutHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject cameraObject(LuaPlus::LuaStackObject(state, 1));
  CameraImpl* const camera = SCR_FromLua_CameraImpl(cameraObject, state);
  camera->mEnableEaseInOut = 1u;
  return 0;
}

/**
 * Address: 0x007ADD10 (FUN_007ADD10, func_CameraImplEnableEaseInOut_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CameraImpl:EnableEaseInOut`.
 */
moho::CScrLuaInitForm* moho::func_CameraImplEnableEaseInOut_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kCameraImplEnableEaseInOutName,
    &moho::cfunc_CameraImplEnableEaseInOut,
    &CScrLuaMetatableFactory<CameraImpl>::Instance(),
    kCameraImplLuaClassName,
    kCameraImplEnableEaseInOutHelpText
  );
  return &binder;
}

/**
 * Address: 0x007ADE20 (FUN_007ADE20, cfunc_CameraImplDisableEaseInOut)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CameraImplDisableEaseInOutL`.
 */
int moho::cfunc_CameraImplDisableEaseInOut(lua_State* const luaContext)
{
  return cfunc_CameraImplDisableEaseInOutL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007ADEA0 (FUN_007ADEA0, cfunc_CameraImplDisableEaseInOutL)
 *
 * What it does:
 * Validates `Camera:DisableEaseInOut()`, resolves one camera payload, and
 * disables ease-in/out targeting behavior.
 */
int moho::cfunc_CameraImplDisableEaseInOutL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCameraImplDisableEaseInOutHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject cameraObject(LuaPlus::LuaStackObject(state, 1));
  CameraImpl* const camera = SCR_FromLua_CameraImpl(cameraObject, state);
  camera->mEnableEaseInOut = 0u;
  return 0;
}

/**
 * Address: 0x007ADE40 (FUN_007ADE40, func_CameraImplDisableEaseInOut_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CameraImpl:DisableEaseInOut`.
 */
moho::CScrLuaInitForm* moho::func_CameraImplDisableEaseInOut_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kCameraImplDisableEaseInOutName,
    &moho::cfunc_CameraImplDisableEaseInOut,
    &CScrLuaMetatableFactory<CameraImpl>::Instance(),
    kCameraImplLuaClassName,
    kCameraImplDisableEaseInOutHelpText
  );
  return &binder;
}

namespace
{
  /**
   * Drives this file's Lua binder definitions.
   *
   * Each `func_*_LuaFuncDef` builds a function-local `CScrLuaBinder` and
   * links it into its init-form set. In the shipped binary they are reached
   * through compiler-generated dynamic initializers that the CRT's static-init
   * array runs before `main`; nothing here reproduces that array, so a
   * definition no source line names is never run - the binder is never
   * constructed, the form never joins its set, and the Lua global or method it
   * publishes is simply absent, with no diagnostic beyond FAF's own "access to
   * nonexistent global variable".
   *
   * This object is that call, and the source-level invocation that keeps these
   * definitions off the linker's dead-strip list.
   */
  struct CameraImplLuaFuncDefBootstrap
  {
    CameraImplLuaFuncDefBootstrap()
    {
      (void)::moho::func_GetCamera_LuaFuncDef();
      (void)::moho::func_CameraImplSnapTo_LuaFuncDef();
      (void)::moho::func_CameraImplMoveToRegion_LuaFuncDef();
      (void)::moho::func_CameraImplSetZoom_LuaFuncDef();
      (void)::moho::func_CameraImplSetTargetZoom_LuaFuncDef();
      (void)::moho::func_CameraImplMoveTo_LuaFuncDef();
      (void)::moho::func_CameraImplGetMinZoom_LuaFuncDef();
      (void)::moho::func_CameraImplSetMaxZoomMult_LuaFuncDef();
      (void)::moho::func_CameraImplSetAccMode_LuaFuncDef();
      (void)::moho::func_CameraImplSpin_LuaFuncDef();
      (void)::moho::func_CameraImplReset_LuaFuncDef();
      (void)::moho::func_CameraImplTrackEntities_LuaFuncDef();
      (void)::moho::func_CameraImplTargetEntities_LuaFuncDef();
      (void)::moho::func_CameraImplNoseCam_LuaFuncDef();
      (void)::moho::func_CameraImplHoldRotation_LuaFuncDef();
      (void)::moho::func_CameraImplRevertRotation_LuaFuncDef();
      (void)::moho::func_CameraImplGetZoom_LuaFuncDef();
      (void)::moho::func_CameraImplGetFocusPosition_LuaFuncDef();
      (void)::moho::func_CameraImplSaveSettings_LuaFuncDef();
      (void)::moho::func_CameraImplRestoreSettings_LuaFuncDef();
      (void)::moho::func_CameraImplGetTargetZoom_LuaFuncDef();
      (void)::moho::func_CameraImplGetMaxZoom_LuaFuncDef();
      (void)::moho::func_CameraImplUseGameClock_LuaFuncDef();
      (void)::moho::func_CameraImplUseSystemClock_LuaFuncDef();
      (void)::moho::func_CameraImplEnableEaseInOut_LuaFuncDef();
      (void)::moho::func_CameraImplDisableEaseInOut_LuaFuncDef();
    }
  };

  const CameraImplLuaFuncDefBootstrap gCameraImplLuaFuncDefBootstrap{};
} // namespace
