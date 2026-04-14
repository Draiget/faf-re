#include "moho/render/camera/CameraImpl.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>

#include "lua/LuaObject.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/SCR_FromLua.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/math/MathReflection.h"
#include "moho/math/QuaternionMath.h"
#include "moho/render/RCamManager.h"
#include "moho/unit/Broadcaster.h"
#include "moho/script/CScriptEvent.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/UserArmy.h"

namespace moho
{
  int cfunc_GetCameraL(LuaPlus::LuaState* state);
  extern float cam_NearZoom;
  extern float cam_NearFOV;
  extern float cam_FarFOV;
  extern float cam_FarPitch;
  extern float cam_ShakeMult;
  extern float ren_BorderSize;
  int cfunc_CameraImplMoveToRegionL(LuaPlus::LuaState* state);
  int cfunc_CameraImplReset(lua_State* luaContext);
  int cfunc_CameraImplResetL(LuaPlus::LuaState* state);
  int cfunc_CameraImplTrackEntities(lua_State* luaContext);
  int cfunc_CameraImplTargetEntities(lua_State* luaContext);
  int cfunc_CameraImplNoseCam(lua_State* luaContext);
  int cfunc_CameraImplHoldRotation(lua_State* luaContext);
  int cfunc_CameraImplHoldRotationL(LuaPlus::LuaState* state);
  int cfunc_CameraImplRevertRotation(lua_State* luaContext);
  int cfunc_CameraImplRevertRotationL(LuaPlus::LuaState* state);
  int cfunc_CameraImplGetZoom(lua_State* luaContext);
  int cfunc_CameraImplGetFocusPosition(lua_State* luaContext);
  int cfunc_CameraImplGetFocusPositionL(LuaPlus::LuaState* state);
  int cfunc_CameraImplSaveSettings(lua_State* luaContext);
  int cfunc_CameraImplRestoreSettings(lua_State* luaContext);
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
  constexpr float kTwoPi = 6.2831855f;
  constexpr std::int32_t kCameraTargetTypeLocation = 0;
  constexpr std::int32_t kCameraTargetTypeBox = 1;
  constexpr std::int32_t kCameraTargetTypeEntity = 2;
  constexpr std::int32_t kCameraTargetTypeHermite = 4;
  constexpr std::int32_t kCameraTimeSourceSystem = 0;
  constexpr std::int32_t kCameraTimeSourceGame = 1;
  constexpr std::int32_t kCameraAccTypeLinear = 0;
  constexpr std::int32_t kCameraAccTypeFastInSlowOut = 1;
  constexpr std::int32_t kCameraAccTypeSlowInOut = 2;
  constexpr const char* kCameraAccTypeLinearName = "Linear";
  constexpr const char* kCameraAccTypeFastInSlowOutName = "FastInSlowOut";
  constexpr const char* kCameraAccTypeSlowInOutName = "SlowInOut";

  struct CameraShakeParamsView
  {
    Wm3::Vec3f mCenter{};                  // +0x00
    float mMaxRange = 0.0f;                // +0x0C
    float mMinMagnitude = 0.0f;            // +0x10
    float mMaxMagnitude = 0.0f;            // +0x14
    float mDuration = 0.0f;                // +0x18
    float mElapsed = 0.0f;                 // +0x1C
    float mScale = 0.0f;                   // +0x20
  };

  static_assert(sizeof(CameraShakeParamsView) == 0x24, "CameraShakeParamsView size must be 0x24");
  static_assert(offsetof(CameraShakeParamsView, mCenter) == 0x00, "CameraShakeParamsView::mCenter offset must be 0x00");
  static_assert(
    offsetof(CameraShakeParamsView, mMaxRange) == 0x0C,
    "CameraShakeParamsView::mMaxRange offset must be 0x0C"
  );
  static_assert(
    offsetof(CameraShakeParamsView, mMinMagnitude) == 0x10,
    "CameraShakeParamsView::mMinMagnitude offset must be 0x10"
  );
  static_assert(
    offsetof(CameraShakeParamsView, mMaxMagnitude) == 0x14,
    "CameraShakeParamsView::mMaxMagnitude offset must be 0x14"
  );
  static_assert(
    offsetof(CameraShakeParamsView, mDuration) == 0x18,
    "CameraShakeParamsView::mDuration offset must be 0x18"
  );
  static_assert(
    offsetof(CameraShakeParamsView, mElapsed) == 0x1C,
    "CameraShakeParamsView::mElapsed offset must be 0x1C"
  );
  static_assert(offsetof(CameraShakeParamsView, mScale) == 0x20, "CameraShakeParamsView::mScale offset must be 0x20");

  class CameraTimeSourceRuntime
  {
  public:
    virtual float Time() = 0;
  };

  struct CameraImplRuntimeView
  {
    std::uint8_t mUnknown000To03B[0x3C]{};
    LuaPlus::LuaObject mLuaObject{};                      // +0x03C
    msvc8::string mName{};                                // +0x050
    moho::STIMap* mTerrainMap = nullptr;                  // +0x06C
    moho::GeomCamera3 mCam{};                             // +0x070
    float mVerticalZoomMetricScale = 0.0f;                // +0x338
    std::uint8_t mUnknown33CTo33C[0x01]{};                // +0x33C
    std::uint8_t mIsRotated = 0;                          // +0x33D
    std::uint8_t mRevertRotation = 0;                     // +0x33E
    std::uint8_t mUnknown33FTo33F[0x01]{};                // +0x33F
    float mFarFov = 0.0f;                                 // +0x340
    float mHeading = 0.0f;                                // +0x344
    float mCurrentPitch = 0.0f;                           // +0x348
    float mFarPitch = 0.0f;                               // +0x34C
    float mHeadingZoom = 0.0f;                            // +0x350
    float mTargetZoom = 0.0f;                             // +0x354
    float mNearZoom = 0.0f;                               // +0x358
    std::uint8_t mUnknown35CTo35F[0x04]{};                // +0x35C
    Wm3::Vec3f mOffset{};                                 // +0x360
    std::uint8_t mUnknown36CTo373[0x08]{};                // +0x36C
    float mHeadingRate = 0.0f;                            // +0x374
    float mZoomRate = 0.0f;                               // +0x378
    std::int32_t mTargetType = 0;                         // +0x37C
    Wm3::Vec3f mTargetLocation{};                         // +0x380
    Wm3::AxisAlignedBox3f mTargetBox{};                   // +0x38C
    std::uint8_t mUnknown3A4To3B3[0x10]{};                // +0x3A4
    float mTargetTimeLeft = 0.0f;                         // +0x3B4
    std::uint8_t mTargetTime = 0;                         // +0x3B8
    std::uint8_t mUnknown3B9To3BB[0x03]{};                // +0x3B9
    std::int32_t mTimeSource = 0;                         // +0x3BC
    CameraTimeSourceRuntime* mTimeSources[3]{};           // +0x3C0
    std::uint8_t mEnableEaseInOut = 0;                    // +0x3CC
    std::uint8_t mUnknown3CDTo3CF[0x03]{};                // +0x3CD
    float mUnknown3D0 = 0.0f;                             // +0x3D0
    Wm3::Vec3f mTimedMoveOffset{};                        // +0x3D4
    float mTimedMoveZoom = 0.0f;                          // +0x3E0
    float mTimedMoveDuration = 0.0f;                      // +0x3E4
    float mTimedMoveTransitionParam = 0.0f;               // +0x3E8
    float mTimedMoveStartTime = 0.0f;                     // +0x3EC
    float mTimedMovePitch = 0.0f;                         // +0x3F0
    float mTimedMoveHeading = 0.0f;                       // +0x3F4
    Wm3::Vec3f mHermiteOffsetStartDelta{};                // +0x3F8
    Wm3::Vec3f mHermiteOffsetEndDelta{};                  // +0x404
    float mHermiteHeadingStartDelta = 0.0f;               // +0x410
    float mHermiteHeadingEndDelta = 0.0f;                 // +0x414
    float mHermitePitchStartDelta = 0.0f;                 // +0x418
    float mHermitePitchEndDelta = 0.0f;                   // +0x41C
    float mHermiteZoomStartDelta = 0.0f;                  // +0x420
    float mHermiteZoomEndDelta = 0.0f;                    // +0x424
    CameraShakeParamsView mCamShakeParams{};              // +0x428
    std::uint8_t mUnknown44CTo44F[0x04]{};                // +0x44C
    std::int32_t mAccType = 0;                            // +0x450
  };

  static_assert(
    offsetof(CameraImplRuntimeView, mLuaObject) == 0x03C,
    "CameraImplRuntimeView::mLuaObject offset must be 0x03C"
  );
  static_assert(
    offsetof(CameraImplRuntimeView, mIsRotated) == 0x33D,
    "CameraImplRuntimeView::mIsRotated offset must be 0x33D"
  );
  static_assert(
    offsetof(CameraImplRuntimeView, mRevertRotation) == 0x33E,
    "CameraImplRuntimeView::mRevertRotation offset must be 0x33E"
  );
  static_assert(
    offsetof(CameraImplRuntimeView, mFarFov) == 0x340,
    "CameraImplRuntimeView::mFarFov offset must be 0x340"
  );
  static_assert(
    offsetof(CameraImplRuntimeView, mTerrainMap) == 0x06C,
    "CameraImplRuntimeView::mTerrainMap offset must be 0x06C"
  );
  static_assert(offsetof(CameraImplRuntimeView, mCam) == 0x070, "CameraImplRuntimeView::mCam offset must be 0x070");
  static_assert(
    offsetof(CameraImplRuntimeView, mVerticalZoomMetricScale) == 0x338,
    "CameraImplRuntimeView::mVerticalZoomMetricScale offset must be 0x338"
  );
  static_assert(
    offsetof(CameraImplRuntimeView, mHeading) == 0x344,
    "CameraImplRuntimeView::mHeading offset must be 0x344"
  );
  static_assert(
    offsetof(CameraImplRuntimeView, mFarPitch) == 0x34C,
    "CameraImplRuntimeView::mFarPitch offset must be 0x34C"
  );
  static_assert(
    offsetof(CameraImplRuntimeView, mTargetZoom) == 0x354,
    "CameraImplRuntimeView::mTargetZoom offset must be 0x354"
  );
  static_assert(
    offsetof(CameraImplRuntimeView, mNearZoom) == 0x358,
    "CameraImplRuntimeView::mNearZoom offset must be 0x358"
  );
  static_assert(
    offsetof(CameraImplRuntimeView, mOffset) == 0x360,
    "CameraImplRuntimeView::mOffset offset must be 0x360"
  );
  static_assert(
    offsetof(CameraImplRuntimeView, mHeadingRate) == 0x374,
    "CameraImplRuntimeView::mHeadingRate offset must be 0x374"
  );
  static_assert(
    offsetof(CameraImplRuntimeView, mZoomRate) == 0x378,
    "CameraImplRuntimeView::mZoomRate offset must be 0x378"
  );
  static_assert(
    offsetof(CameraImplRuntimeView, mTargetType) == 0x37C,
    "CameraImplRuntimeView::mTargetType offset must be 0x37C"
  );
  static_assert(
    offsetof(CameraImplRuntimeView, mTargetLocation) == 0x380,
    "CameraImplRuntimeView::mTargetLocation offset must be 0x380"
  );
  static_assert(
    offsetof(CameraImplRuntimeView, mTargetBox) == 0x38C,
    "CameraImplRuntimeView::mTargetBox offset must be 0x38C"
  );
  static_assert(
    offsetof(CameraImplRuntimeView, mTargetTimeLeft) == 0x3B4,
    "CameraImplRuntimeView::mTargetTimeLeft offset must be 0x3B4"
  );
  static_assert(
    offsetof(CameraImplRuntimeView, mTargetTime) == 0x3B8,
    "CameraImplRuntimeView::mTargetTime offset must be 0x3B8"
  );
  static_assert(
    offsetof(CameraImplRuntimeView, mTimeSource) == 0x3BC,
    "CameraImplRuntimeView::mTimeSource offset must be 0x3BC"
  );
  static_assert(
    offsetof(CameraImplRuntimeView, mEnableEaseInOut) == 0x3CC,
    "CameraImplRuntimeView::mEnableEaseInOut offset must be 0x3CC"
  );
  static_assert(
    offsetof(CameraImplRuntimeView, mTimedMoveOffset) == 0x3D4,
    "CameraImplRuntimeView::mTimedMoveOffset offset must be 0x3D4"
  );
  static_assert(
    offsetof(CameraImplRuntimeView, mTimedMoveZoom) == 0x3E0,
    "CameraImplRuntimeView::mTimedMoveZoom offset must be 0x3E0"
  );
  static_assert(
    offsetof(CameraImplRuntimeView, mTimedMoveStartTime) == 0x3EC,
    "CameraImplRuntimeView::mTimedMoveStartTime offset must be 0x3EC"
  );
  static_assert(
    offsetof(CameraImplRuntimeView, mTimedMoveHeading) == 0x3F4,
    "CameraImplRuntimeView::mTimedMoveHeading offset must be 0x3F4"
  );
  static_assert(
    offsetof(CameraImplRuntimeView, mHermiteOffsetStartDelta) == 0x3F8,
    "CameraImplRuntimeView::mHermiteOffsetStartDelta offset must be 0x3F8"
  );
  static_assert(
    offsetof(CameraImplRuntimeView, mHermiteOffsetEndDelta) == 0x404,
    "CameraImplRuntimeView::mHermiteOffsetEndDelta offset must be 0x404"
  );
  static_assert(
    offsetof(CameraImplRuntimeView, mHermiteZoomEndDelta) == 0x424,
    "CameraImplRuntimeView::mHermiteZoomEndDelta offset must be 0x424"
  );
  static_assert(
    offsetof(CameraImplRuntimeView, mCamShakeParams) == 0x428,
    "CameraImplRuntimeView::mCamShakeParams offset must be 0x428"
  );
  static_assert(
    offsetof(CameraImplRuntimeView, mAccType) == 0x450,
    "CameraImplRuntimeView::mAccType offset must be 0x450"
  );
  static_assert(sizeof(CameraImplRuntimeView) == 0x454, "CameraImplRuntimeView size must be 0x454");

  [[nodiscard]] CameraImplRuntimeView* AsRuntimeView(moho::CameraImpl* const camera) noexcept
  {
    return reinterpret_cast<CameraImplRuntimeView*>(camera);
  }

  [[nodiscard]] const CameraImplRuntimeView* AsRuntimeView(const moho::CameraImpl* const camera) noexcept
  {
    return reinterpret_cast<const CameraImplRuntimeView*>(camera);
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

  struct RuntimeCameraBaseView
  {
    void* mVftable = nullptr;          // +0x00
    Broadcaster mBroadcaster{};        // +0x04
  };

  static_assert(sizeof(RuntimeCameraBaseView) == 0x0C, "RuntimeCameraBaseView size must be 0x0C");
  static_assert(
    offsetof(RuntimeCameraBaseView, mVftable) == 0x00, "RuntimeCameraBaseView::mVftable offset must be 0x00"
  );
  static_assert(
    offsetof(RuntimeCameraBaseView, mBroadcaster) == 0x04,
    "RuntimeCameraBaseView::mBroadcaster offset must be 0x04"
  );

  [[nodiscard]] RuntimeCameraBaseView* AsRuntimeCameraBaseView(moho::CameraImpl* const camera) noexcept
  {
    return reinterpret_cast<RuntimeCameraBaseView*>(camera);
  }

  struct CameraTrackingEvent
  {
    msvc8::string cameraName;
    std::uint8_t transitionFlag = 0;
  };

  struct CameraTrackingBroadcasterLink
  {
    CameraTrackingBroadcasterLink* mListNext = nullptr; // +0x00
    CameraTrackingBroadcasterLink* mListPrev = nullptr; // +0x04
  };
  static_assert(
    offsetof(CameraTrackingBroadcasterLink, mListNext) == 0x00,
    "CameraTrackingBroadcasterLink::mListNext offset must be 0x00"
  );
  static_assert(
    offsetof(CameraTrackingBroadcasterLink, mListPrev) == 0x04,
    "CameraTrackingBroadcasterLink::mListPrev offset must be 0x04"
  );
  static_assert(sizeof(CameraTrackingBroadcasterLink) == 0x08, "CameraTrackingBroadcasterLink size must be 0x08");

  struct CameraTrackingListenerLayout
  {
    void* vtable = nullptr;                      // +0x00
    CameraTrackingBroadcasterLink mLink{};       // +0x04
  };
  static_assert(
    offsetof(CameraTrackingListenerLayout, mLink) == 0x04,
    "CameraTrackingListenerLayout::mLink offset must be 0x04"
  );

  class CameraTrackingListenerVf
  {
  public:
    virtual void Receive(const CameraTrackingEvent& event) = 0;
  };

  [[nodiscard]] CameraTrackingBroadcasterLink* AsCameraTrackingBroadcaster(moho::CameraImpl* const camera) noexcept
  {
    return reinterpret_cast<CameraTrackingBroadcasterLink*>(reinterpret_cast<std::uint8_t*>(camera) + 0x04);
  }

  void CameraTrackingSelfLink(CameraTrackingBroadcasterLink* const node) noexcept
  {
    node->mListPrev = node;
    node->mListNext = node;
  }

  void CameraTrackingDetach(CameraTrackingBroadcasterLink* const node) noexcept
  {
    node->mListNext->mListPrev = node->mListPrev;
    node->mListPrev->mListNext = node->mListNext;
    CameraTrackingSelfLink(node);
  }

  void CameraTrackingAttachAfter(
    CameraTrackingBroadcasterLink* const node, CameraTrackingBroadcasterLink* const anchor
  ) noexcept
  {
    CameraTrackingDetach(node);
    node->mListNext = anchor->mListNext;
    node->mListPrev = anchor;
    anchor->mListNext = node;
    node->mListNext->mListPrev = node;
  }

  [[nodiscard]] CameraTrackingListenerVf* CameraTrackingListenerFromLink(
    CameraTrackingBroadcasterLink* const listenerLink
  ) noexcept
  {
    auto* const layout = reinterpret_cast<CameraTrackingListenerLayout*>(
      reinterpret_cast<std::uint8_t*>(listenerLink) - offsetof(CameraTrackingListenerLayout, mLink)
    );
    return reinterpret_cast<CameraTrackingListenerVf*>(layout);
  }

  /**
   * Address: 0x007AE2B0 (FUN_007AE2B0, Moho::Broadcaster<Moho::SCameraTracking>::BroadcastEvent)
   *
   * What it does:
   * Moves listeners into a snapshot ring, iterates safely while relinking each
   * listener back to broadcaster head, and dispatches one camera-tracking event
   * payload (`cameraName`, `transitionFlag`) per listener.
   */
  void BroadcastCameraTrackingEvent(
    CameraTrackingBroadcasterLink* const broadcaster, const msvc8::string& cameraName, const std::uint8_t transitionFlag
  )
  {
    CameraTrackingBroadcasterLink snapshot{};
    CameraTrackingSelfLink(&snapshot);

    if (broadcaster->mListPrev != broadcaster) {
      snapshot.mListPrev = broadcaster->mListPrev;
      snapshot.mListNext = broadcaster->mListNext;
      snapshot.mListNext->mListPrev = &snapshot;
      snapshot.mListPrev->mListNext = &snapshot;
      CameraTrackingSelfLink(broadcaster);

      while (snapshot.mListPrev != &snapshot) {
        CameraTrackingBroadcasterLink* const listenerLink = snapshot.mListPrev;
        CameraTrackingDetach(listenerLink);
        CameraTrackingAttachAfter(listenerLink, broadcaster);

        CameraTrackingEvent event{};
        event.cameraName = cameraName;
        event.transitionFlag = transitionFlag;
        CameraTrackingListenerFromLink(listenerLink)->Receive(event);
      }
    }

    snapshot.mListNext->mListPrev = snapshot.mListPrev;
    snapshot.mListPrev->mListNext = snapshot.mListNext;
    CameraTrackingSelfLink(&snapshot);
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
    CameraShakeParamsView* const shakeParams
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
      (((shakeParams->mMaxMagnitude - shakeParams->mMinMagnitude) * distanceFactor) + shakeParams->mMinMagnitude);
    const float radialAmount =
      static_cast<float>(moho::MathGlobalRandomUnitScaled(magnitude)) * shakeParams->mScale * 0.5f;
    const float tangentialAmount = static_cast<float>(moho::MathGlobalRandomRange(-magnitude, magnitude)) * 0.25f;

    outShakeOffset->x = ((shakeDirection.x * radialAmount) + (shakeDirection.z * tangentialAmount)) * moho::cam_ShakeMult;
    outShakeOffset->y = ((shakeDirection.y * radialAmount) + (tangentialAmount * 0.0f)) * moho::cam_ShakeMult;
    outShakeOffset->z =
      ((shakeDirection.z * radialAmount) + ((0.0f - shakeDirection.x) * tangentialAmount)) * moho::cam_ShakeMult;
    return outShakeOffset;
  }

  struct CameraImplZoomLimitView
  {
    std::uint8_t mUnknown000To84F[0x850]{};
    float mMaxZoomMult = 0.0f; // +0x850
  };

  static_assert(
    offsetof(CameraImplZoomLimitView, mMaxZoomMult) == 0x850,
    "CameraImplZoomLimitView::mMaxZoomMult offset must be 0x850"
  );

  struct CameraFrustumUserEntityStorage
  {
    moho::CameraFrustumUserEntityList mView;              // +0x00
    moho::CameraUserEntityWeakRef mInlineStorage[40]{}; // +0x10
  };

  static_assert(sizeof(CameraFrustumUserEntityStorage) == 0x150, "CameraFrustumUserEntityStorage size must be 0x150");
  static_assert(
    offsetof(CameraFrustumUserEntityStorage, mView) == 0x00,
    "CameraFrustumUserEntityStorage::mView offset must be 0x00"
  );
  static_assert(
    offsetof(CameraFrustumUserEntityStorage, mInlineStorage) == 0x10,
    "CameraFrustumUserEntityStorage::mInlineStorage offset must be 0x10"
  );

  struct CameraImplArmyFrustumView
  {
    std::uint8_t mUnknown000To6FF[0x700]{};
    CameraFrustumUserEntityStorage mArmyUnitsInFrustum; // +0x700
  };

  static_assert(
    offsetof(CameraImplArmyFrustumView, mArmyUnitsInFrustum) == 0x700,
    "CameraImplArmyFrustumView::mArmyUnitsInFrustum offset must be 0x700"
  );
  static_assert(
    offsetof(CameraImplArmyFrustumView, mArmyUnitsInFrustum) + sizeof(CameraFrustumUserEntityStorage) ==
      offsetof(CameraImplZoomLimitView, mMaxZoomMult),
    "CameraImplArmyFrustumView::mArmyUnitsInFrustum must end at mMaxZoomMult"
  );

  [[nodiscard]] CameraImplArmyFrustumView* AsArmyFrustumView(moho::CameraImpl* const camera) noexcept
  {
    return reinterpret_cast<CameraImplArmyFrustumView*>(camera);
  }

  [[nodiscard]] CameraImplZoomLimitView* AsZoomLimitView(moho::CameraImpl* const camera) noexcept
  {
    return reinterpret_cast<CameraImplZoomLimitView*>(camera);
  }

  [[nodiscard]] const CameraImplZoomLimitView* AsZoomLimitView(const moho::CameraImpl* const camera) noexcept
  {
    return reinterpret_cast<const CameraImplZoomLimitView*>(camera);
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
} // namespace moho

/**
 * Address: 0x007AAC60 (FUN_007AAC60, Moho::RCamCamera::~RCamCamera)
 *
 * What it does:
 * Removes one runtime camera from manager ownership and restores the base
 * broadcaster node to its self-linked idle state.
 */
[[nodiscard]] Broadcaster* moho::DetachRuntimeCameraBase(CameraImpl* const camera)
{
  RuntimeCameraBaseView* const base = AsRuntimeCameraBaseView(camera);

  if (RCamManager* const manager = CAM_GetManager(); manager != nullptr) {
    auto& cameras = manager->mCams;
    const auto cameraIt = std::find(cameras.begin(), cameras.end(), camera);
    if (cameraIt != cameras.end()) {
      cameras.erase(cameraIt);
    }
  }

  Broadcaster& broadcaster = base->mBroadcaster;
  broadcaster.mNext->mPrev = broadcaster.mPrev;
  broadcaster.mPrev->mNext = broadcaster.mNext;
  broadcaster.mPrev = &broadcaster;
  broadcaster.mNext = &broadcaster;
  return &broadcaster;
}

/**
 * Address: 0x007A7DC0 (FUN_007A7DC0, CameraImpl deleting wrapper)
 *
 * What it does:
 * Executes CameraImpl teardown and conditionally frees this object when
 * `deleteFlags & 1` is set.
 */
void moho::CameraImpl::operator_delete(const std::int32_t deleteFlags)
{
  this->~CameraImpl();
  (void)DetachRuntimeCameraBase(this);
  if ((deleteFlags & 1) != 0) {
    ::operator delete(this);
  }
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
  CameraImplRuntimeView* const runtime = AsRuntimeView(this);
  if (_stricmp(accType.c_str(), kCameraAccTypeLinearName) == 0) {
    runtime->mAccType = kCameraAccTypeLinear;
    return;
  }

  if (_stricmp(accType.c_str(), kCameraAccTypeFastInSlowOutName) == 0) {
    runtime->mAccType = kCameraAccTypeFastInSlowOut;
    return;
  }

  if (_stricmp(accType.c_str(), kCameraAccTypeSlowInOutName) == 0) {
    runtime->mAccType = kCameraAccTypeSlowInOut;
  }
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
  CameraImplRuntimeView* const runtime = AsRuntimeView(this);
  runtime->mIsRotated = 1u;
  runtime->mRevertRotation = 0u;
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
  CameraImplRuntimeView* const runtime = AsRuntimeView(this);
  if (runtime->mIsRotated == 0u) {
    return;
  }

  runtime->mRevertRotation = 1u;
  if (runtime->mTargetType != kCameraTargetTypeEntity) {
    runtime->mTargetType = kCameraTargetTypeLocation;
  }
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
  CameraImplRuntimeView* const runtime = AsRuntimeView(this);

  runtime->mFarFov = cam_FarFOV * kDegreesToRadians;
  runtime->mHeading = kPi;
  runtime->mIsRotated = 0u;
  runtime->mFarPitch = cam_FarPitch * kDegreesToRadians;
  runtime->mCurrentPitch = 0.0f;
  runtime->mUnknown3D0 = 0.0f;
  runtime->mHeadingZoom = runtime->mFarPitch;
  runtime->mEnableEaseInOut = 1u;

  runtime->mTargetLocation = {};
  if (const STIMap* const terrainMap = runtime->mTerrainMap; terrainMap != nullptr) {
    if (const CHeightField* const heightField = terrainMap->GetHeightField(); heightField != nullptr) {
      runtime->mTargetLocation.x = static_cast<float>(heightField->width - 1) * 0.5f;
      runtime->mTargetLocation.z = static_cast<float>(heightField->height - 1) * 0.5f;
      float targetElevation = heightField->GetElevation(runtime->mTargetLocation.x, runtime->mTargetLocation.z);
      if (terrainMap->IsWaterEnabled()) {
        const float waterElevation = terrainMap->GetWaterElevation();
        if (waterElevation > targetElevation) {
          targetElevation = waterElevation;
        }
      }
      runtime->mTargetLocation.y = targetElevation;
    }
  }

  runtime->mNearZoom = GetMaxZoom();
  runtime->mHeadingRate = 0.0f;
  runtime->mZoomRate = 0.0f;
  runtime->mTargetType = kCameraTargetTypeLocation;
  runtime->mTargetTime = 0u;
  runtime->mTargetTimeLeft = 0.0f;
  runtime->mOffset = runtime->mTargetLocation;
  runtime->mTargetZoom = runtime->mNearZoom;
}

/**
 * Address: 0x007A69F0 (FUN_007A69F0, Moho::CameraImpl::CameraGetName)
 *
 * What it does:
 * Returns the camera runtime name-string buffer.
 */
const char* moho::CameraImpl::CameraGetName() const
{
  return AsRuntimeView(this)->mName.c_str();
}

/**
 * Address: 0x007A6A00 (FUN_007A6A00, Moho::CameraImpl::CameraGetView)
 *
 * What it does:
 * Returns one read-only view of the embedded camera transform/projection state.
 */
const moho::GeomCamera3& moho::CameraImpl::CameraGetView() const
{
  return AsRuntimeView(this)->mCam;
}

/**
 * Address: 0x007A7910 (FUN_007A7910, Moho::CameraImpl::GetArmyUnitsInFrustum)
 *
 * What it does:
 * Returns one cached weak-vector view of focus-army units currently in camera
 * frustum.
 */
moho::CameraFrustumUserEntityList* moho::CameraImpl::GetArmyUnitsInFrustum()
{
  return &AsArmyFrustumView(this)->mArmyUnitsInFrustum.mView;
}

/**
 * Address: 0x007A6C80 (FUN_007A6C80, Moho::CameraImpl::CameraGetOffset)
 *
 * What it does:
 * Returns one read-only camera target/offset vector lane.
 */
const Wm3::Vec3f& moho::CameraImpl::CameraGetOffset() const
{
  return AsRuntimeView(this)->mOffset;
}

/**
 * Address: 0x007A6CA0 (FUN_007A6CA0, Moho::CameraImpl::CameraGetTargetZoom)
 *
 * What it does:
 * Returns the active camera target-zoom scalar.
 */
float moho::CameraImpl::CameraGetTargetZoom() const
{
  return AsRuntimeView(this)->mTargetZoom;
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
  const CameraImplRuntimeView* const runtime = AsRuntimeView(this);
  const STIMap* const terrainMap = runtime->mTerrainMap;
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
  const float maxZoomMult = AsZoomLimitView(this)->mMaxZoomMult;
  const float horizontalExtent = (static_cast<float>(maxX - minX) + borderSize) * maxZoomMult;
  const float verticalExtent =
    (static_cast<float>(maxZ - minZ) + borderSize) * maxZoomMult * runtime->mVerticalZoomMetricScale;
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
 * Address: 0x007A73C0 (FUN_007A73C0)
 *
 * What it does:
 * Updates one runtime multiplier lane used by max-zoom gating.
 */
void moho::CameraImpl::SetMaxZoomMult(const float maxZoomMult)
{
  AsZoomLimitView(this)->mMaxZoomMult = maxZoomMult;
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
  CameraImplRuntimeView* const runtime = AsRuntimeView(this);
  runtime->mTimedMoveOffset = {0.0f, 0.0f, 0.0f};
  runtime->mTimedMoveZoom = 0.0f;
  runtime->mTimedMoveStartTime = 0.0f;
  runtime->mTimedMovePitch = 0.0f;
  runtime->mTimedMoveHeading = 0.0f;
  runtime->mTimedMoveDuration = seconds;
  runtime->mTimedMoveTransitionParam = transitionParam;

  if (seconds > 0.0f) {
    CameraTimeSourceRuntime* const timeSource = runtime->mTimeSources[runtime->mTimeSource];
    runtime->mTimedMoveStartTime = timeSource != nullptr ? timeSource->Time() : 0.0f;
    runtime->mTimedMoveOffset = runtime->mOffset;
    runtime->mTimedMoveZoom = runtime->mTargetZoom;
    runtime->mTimedMovePitch = runtime->mFarPitch;
    runtime->mTimedMoveHeading = moho::NormalizeAngleSignedRadians(runtime->mHeading);
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
  CameraImplRuntimeView* const runtime = AsRuntimeView(this);
  if (runtime->mEnableEaseInOut != 0u) {
    return;
  }

  runtime->mHermiteOffsetStartDelta.x = runtime->mTargetLocation.x - runtime->mTimedMoveOffset.x;
  runtime->mHermiteOffsetStartDelta.y = runtime->mTargetLocation.y - runtime->mTimedMoveOffset.y;
  runtime->mHermiteOffsetStartDelta.z = runtime->mTargetLocation.z - runtime->mTimedMoveOffset.z;
  runtime->mHermiteOffsetEndDelta = runtime->mHermiteOffsetStartDelta;

  const float headingDelta = runtime->mHeadingZoom - runtime->mTimedMoveHeading;
  runtime->mHermiteHeadingStartDelta = headingDelta;
  runtime->mHermiteHeadingEndDelta = headingDelta;

  const float pitchDelta = runtime->mCurrentPitch - runtime->mTimedMovePitch;
  runtime->mHermitePitchStartDelta = pitchDelta;
  runtime->mHermitePitchEndDelta = pitchDelta;

  const float zoomDelta = runtime->mNearZoom - runtime->mTimedMoveZoom;
  runtime->mHermiteZoomStartDelta = zoomDelta;
  runtime->mHermiteZoomEndDelta = zoomDelta;
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
  CameraImplRuntimeView* const runtime = AsRuntimeView(this);
  STIMap* const stiMap = runtime->mTerrainMap;
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
  float clampedZoom = runtime->mTargetZoom;
  if (maxZoom <= clampedZoom) {
    clampedZoom = maxZoom;
  }
  if (clampedZoom < 0.0f) {
    clampedZoom = 0.0f;
  }

  const float halfSpanX = (clampedZoom / maxZoom) * (static_cast<float>(maxX - minX) * 0.5f);
  const float maxTargetX = static_cast<float>(maxX) - halfSpanX;
  const float minTargetX = static_cast<float>(minX) + halfSpanX;

  float targetX = runtime->mTargetLocation.x;
  if (maxTargetX <= targetX) {
    targetX = maxTargetX;
  }
  if (minTargetX > targetX) {
    targetX = minTargetX;
  }
  runtime->mTargetLocation.x = targetX;

  const float halfSpanZ = (clampedZoom / maxZoom) * (static_cast<float>(maxZ - minZ) * 0.5f);
  const float maxTargetZ = static_cast<float>(maxZ) - halfSpanZ;
  const float minTargetZ = static_cast<float>(minZ) + halfSpanZ;

  float targetZ = runtime->mTargetLocation.z;
  if (maxTargetZ <= targetZ) {
    targetZ = maxTargetZ;
  }
  if (minTargetZ > targetZ) {
    targetZ = minTargetZ;
  }
  runtime->mTargetLocation.z = targetZ;
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
  CameraImplRuntimeView* const runtime = AsRuntimeView(this);
  STIMap* const stiMap = runtime->mTerrainMap;
  if (stiMap == nullptr) {
    return;
  }

  moho::GeomLine3 line{};
  line.pos = runtime->mOffset;
  const float cosPitch = std::cos(runtime->mFarPitch);
  line.closest = -std::numeric_limits<float>::infinity();
  line.farthest = std::numeric_limits<float>::infinity();
  line.dir.x = std::sin(runtime->mHeading) * cosPitch;
  line.dir.y = -std::sin(runtime->mFarPitch);
  line.dir.z = cosPitch * std::cos(runtime->mHeading);

  moho::CColHitResult hit{};
  const Wm3::Vec3f clampedFocus = stiMap->SurfaceIntersection(line, &hit);
  if (std::isfinite(clampedFocus.x) && std::isfinite(clampedFocus.y) && std::isfinite(clampedFocus.z)) {
    runtime->mOffset = clampedFocus;
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
  CameraImplRuntimeView* const runtime = AsRuntimeView(this);
  const float logMaxZoom = std::log(GetMaxZoom());
  const float logTargetZoom = std::log(runtime->mTargetZoom);
  const float logNearZoom = std::log(moho::cam_NearZoom);

  float clampedLogZoom = (logMaxZoom <= logTargetZoom) ? logMaxZoom : logTargetZoom;
  if (logNearZoom > clampedLogZoom) {
    clampedLogZoom = logNearZoom;
  }

  runtime->mFarFov =
    ((((clampedLogZoom - logNearZoom) / (logMaxZoom - logNearZoom)) * (moho::cam_FarFOV - moho::cam_NearFOV)) +
      moho::cam_NearFOV) *
    kDegreesToRadians;
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
  CameraImplRuntimeView* const runtime = AsRuntimeView(this);
  if (runtime->mTargetType == kCameraTargetTypeEntity) {
    BroadcastCameraTrackingEvent(AsCameraTrackingBroadcaster(this), runtime->mName, 0u);
  }

  TimedMoveInit(seconds, 0.0f);

  runtime->mTargetLocation = position;
  runtime->mTargetType = kCameraTargetTypeLocation;

  if (seconds == 0.0f) {
    runtime->mTargetZoom = runtime->mNearZoom;
    ClampTargetPos();
    runtime->mOffset = runtime->mTargetLocation;
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
  CameraImplRuntimeView* const runtime = AsRuntimeView(this);
  if (runtime->mTargetType == kCameraTargetTypeEntity) {
    BroadcastCameraTrackingEvent(AsCameraTrackingBroadcaster(this), runtime->mName, 0u);
  }

  TimedMoveInit(seconds, 0.0f);

  runtime->mTargetBox = targetBox;
  runtime->mTargetLocation.x = (runtime->mTargetBox.Min.x + runtime->mTargetBox.Max.x) * 0.5f;
  runtime->mTargetLocation.y = (runtime->mTargetBox.Min.y + runtime->mTargetBox.Max.y) * 0.5f;
  runtime->mTargetLocation.z = (runtime->mTargetBox.Min.z + runtime->mTargetBox.Max.z) * 0.5f;

  float nearZoom = runtime->mTargetBox.Max.x - runtime->mTargetBox.Min.x;
  const float depthSpan = runtime->mTargetBox.Max.z - runtime->mTargetBox.Min.z;
  if (depthSpan > nearZoom) {
    nearZoom = depthSpan;
  }

  runtime->mNearZoom = nearZoom;
  runtime->mTargetType = kCameraTargetTypeBox;

  if (seconds == 0.0f) {
    runtime->mTargetZoom = nearZoom;
    ClampTargetPos();
    runtime->mOffset = runtime->mTargetLocation;
    ClampFocusPos();
    CalculateFOV();
  } else {
    SetupHermite();
  }
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
  CameraImplRuntimeView* const runtime = AsRuntimeView(this);
  if (runtime->mTargetType == kCameraTargetTypeEntity) {
    BroadcastCameraTrackingEvent(AsCameraTrackingBroadcaster(this), runtime->mName, 0u);
  }

  TimedMoveInit(seconds, 0.0f);

  runtime->mCurrentPitch = pitch;
  runtime->mHeadingZoom = NormalizeQuadrantRelative(heading, runtime->mHeading);
  runtime->mNearZoom = zoom;
  runtime->mTargetLocation = position;

  if (seconds == 0.0f) {
    runtime->mTargetType = kCameraTargetTypeLocation;
    runtime->mHeading = runtime->mHeadingZoom;
    runtime->mFarPitch = runtime->mCurrentPitch;
    runtime->mTargetZoom = runtime->mNearZoom;
    runtime->mOffset = runtime->mTargetLocation;
    runtime->mIsRotated = 1u;
    ClampFocusPos();
    CalculateFOV();
  } else {
    runtime->mTargetType = kCameraTargetTypeHermite;
    SetupHermite();
  }
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
    AsRuntimeView(camera)->mLuaObject.PushStack(state);
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

  CameraImplRuntimeView* const runtime = AsRuntimeView(camera);
  camera->TargetManual(runtime->mTargetLocation, runtime->mHeading, runtime->mFarPitch, targetZoom, transitionSeconds);
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

  AsRuntimeView(camera)->mNearZoom = static_cast<float>(lua_tonumber(rawState, 2));
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

  CameraImplRuntimeView* const runtime = AsRuntimeView(camera);
  runtime->mHeadingRate = static_cast<float>(lua_tonumber(state->m_state, 2));
  runtime->mZoomRate = zoomRate;
  runtime->mIsRotated = true;
  runtime->mTargetType = kCameraTargetTypeHermite;
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

  lua_pushnumber(rawState, AsRuntimeView(camera)->mNearZoom);
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
  AsRuntimeView(camera)->mTimeSource = kCameraTimeSourceGame;
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
  AsRuntimeView(camera)->mTimeSource = kCameraTimeSourceSystem;
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
  AsRuntimeView(camera)->mEnableEaseInOut = 1u;
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
  AsRuntimeView(camera)->mEnableEaseInOut = 0u;
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



