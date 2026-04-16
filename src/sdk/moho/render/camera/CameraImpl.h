#pragma once

#include <cstddef>

#include "gpg/core/containers/String.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/math/Vector2f.h"
#include "moho/render/camera/GeomCamera3.h"
#include "Wm3AxisAlignedBox3.h"
#include "Wm3Vector3.h"

struct lua_State;

namespace LuaPlus
{
  class LuaState;
}

namespace gpg
{
  class RRef;
}

namespace moho
{
  class Broadcaster;
  class CScrLuaInitForm;
  class STIMap;
  class UserEntity;
  enum ECamTimeSource : std::int32_t;
  struct SSelectionSetUserEntity;

  struct CameraUserEntityWeakRef
  {
    void* mOwnerLinkSlot;                  // +0x00
    CameraUserEntityWeakRef* mNextOwnerRef; // +0x04
  };

  static_assert(sizeof(CameraUserEntityWeakRef) == 0x08, "CameraUserEntityWeakRef size must be 0x08");
  static_assert(
    offsetof(CameraUserEntityWeakRef, mOwnerLinkSlot) == 0x00,
    "CameraUserEntityWeakRef::mOwnerLinkSlot offset must be 0x00"
  );
  static_assert(
    offsetof(CameraUserEntityWeakRef, mNextOwnerRef) == 0x04,
    "CameraUserEntityWeakRef::mNextOwnerRef offset must be 0x04"
  );

  struct CameraFrustumUserEntityList
  {
    CameraUserEntityWeakRef* mStart;        // +0x00
    CameraUserEntityWeakRef* mFinish;       // +0x04
    CameraUserEntityWeakRef* mCapacity;     // +0x08
    CameraUserEntityWeakRef* mInlineOrigin; // +0x0C
  };

  static_assert(sizeof(CameraFrustumUserEntityList) == 0x10, "CameraFrustumUserEntityList size must be 0x10");
  static_assert(
    offsetof(CameraFrustumUserEntityList, mStart) == 0x00, "CameraFrustumUserEntityList::mStart offset must be 0x00"
  );
  static_assert(
    offsetof(CameraFrustumUserEntityList, mFinish) == 0x04, "CameraFrustumUserEntityList::mFinish offset must be 0x04"
  );
  static_assert(
    offsetof(CameraFrustumUserEntityList, mCapacity) == 0x08, "CameraFrustumUserEntityList::mCapacity offset must be 0x08"
  );
  static_assert(
    offsetof(CameraFrustumUserEntityList, mInlineOrigin) == 0x0C,
    "CameraFrustumUserEntityList::mInlineOrigin offset must be 0x0C"
  );

  struct SCamShakeParams
  {
    Wm3::Vec3f mCenter{};         // +0x00
    float mMaxRange = 0.0f;       // +0x0C
    float mMinMagnitude = 0.0f;   // +0x10
    float mMaxMagnitude = 0.0f;   // +0x14
    float mDuration = 0.0f;       // +0x18
  };

  static_assert(sizeof(SCamShakeParams) == 0x1C, "SCamShakeParams size must be 0x1C");
  static_assert(offsetof(SCamShakeParams, mCenter) == 0x00, "SCamShakeParams::mCenter offset must be 0x00");
  static_assert(offsetof(SCamShakeParams, mMaxRange) == 0x0C, "SCamShakeParams::mMaxRange offset must be 0x0C");
  static_assert(
    offsetof(SCamShakeParams, mMinMagnitude) == 0x10,
    "SCamShakeParams::mMinMagnitude offset must be 0x10"
  );
  static_assert(
    offsetof(SCamShakeParams, mMaxMagnitude) == 0x14,
    "SCamShakeParams::mMaxMagnitude offset must be 0x14"
  );
  static_assert(offsetof(SCamShakeParams, mDuration) == 0x18, "SCamShakeParams::mDuration offset must be 0x18");

  struct SCamFollowParams
  {
    std::int32_t mCurrentEntityId = 0; // +0x00
    std::int32_t mTargetEntityId = 0;  // +0x04
    float mTargetTimeLeft = 0.0f;      // +0x08
  };

  static_assert(sizeof(SCamFollowParams) == 0x0C, "SCamFollowParams size must be 0x0C");
  static_assert(
    offsetof(SCamFollowParams, mCurrentEntityId) == 0x00,
    "SCamFollowParams::mCurrentEntityId offset must be 0x00"
  );
  static_assert(
    offsetof(SCamFollowParams, mTargetEntityId) == 0x04,
    "SCamFollowParams::mTargetEntityId offset must be 0x04"
  );
  static_assert(
    offsetof(SCamFollowParams, mTargetTimeLeft) == 0x08,
    "SCamFollowParams::mTargetTimeLeft offset must be 0x08"
  );

  class CameraImpl
  {
  public:
    /**
     * Address: 0x007A7950 (FUN_007A7950, ??0CameraImpl@Moho@@QAE@VStrArg@gpg@@ABVSTIMap@1@PAVLuaState@LuaPlus@@@Z)
     * Mangled: ??0CameraImpl@Moho@@QAE@VStrArg@gpg@@ABVSTIMap@1@PAVLuaState@LuaPlus@@@Z
     *
     * What it does:
     * Builds one runtime camera instance bound to terrain-map context and
     * optional Lua state ownership.
     */
    CameraImpl(gpg::StrArg name, const STIMap& map, LuaPlus::LuaState* luaState);

    /**
     * Address: 0x007A69D0 (FUN_007A69D0, Moho::CameraImpl::GetDerivedObjectRef)
     * Mangled: ?GetDerivedObjectRef@CameraImpl@Moho@@UAE?AVRRef@gpg@@XZ
     *
     * What it does:
     * Packs `{scriptSubobject, scriptSubobject->GetClass()}` as a reflected
     * object reference.
     */
    [[nodiscard]] gpg::RRef GetDerivedObjectRef();

    /**
     * Address context: called from `RCamManager::Frame` (`0x007AABB0`) camera-loop lane.
     *
     * What it does:
     * Advances one camera runtime for the current sim/frame delta pair.
     */
    void Frame(float simDeltaSeconds, float frameSeconds);

    /**
     * Address: 0x007A6E70 (FUN_007A6E70, Moho::CameraImpl::CameraSetAccType)
     * Mangled: ?CameraSetAccType@CameraImpl@Moho@@QAEXABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z
     *
     * What it does:
     * Applies one acceleration mode token (`Linear`, `FastInSlowOut`,
     * `SlowInOut`) into the camera runtime acceleration lane.
     */
    void CameraSetAccType(const msvc8::string& accType);

    /**
     * Address: 0x007A6CE0 (FUN_007A6CE0, Moho::CameraImpl::CameraSpin)
     * Mangled: ?CameraSpin@CameraImpl@Moho@@UAEXABV?$Vector2@M@Wm3@@@Z
     *
     * What it does:
     * Applies heading/pitch spin deltas from one 2D input vector using
     * zoom-scaled spin speed and clamps pitch to valid camera limits.
     */
    virtual void CameraSpin(const Wm3::Vector2f& spinDelta);

    /**
     * Address: 0x007A8260 (FUN_007A8260, Moho::CameraImpl::CameraZoom)
     * Mangled: ?CameraZoom@CameraImpl@Moho@@UAEXM@Z
     *
     * What it does:
     * Scales near-zoom exponentially from wheel/input delta and clamps it to
     * `[cam_NearZoom, GetMaxZoom()]`.
     */
    virtual void CameraZoom(float zoomDelta);

    /**
     * Address: 0x007A6DF0 (FUN_007A6DF0, Moho::CameraImpl::CameraSetPitch)
     * Mangled: ?CameraSetPitch@CameraImpl@Moho@@UAEXM@Z
     *
     * What it does:
     * Arms rotated mode, clears revert state, and stores current pitch lane.
     */
    virtual void CameraSetPitch(float pitchRadians);

    /**
     * Address: 0x007A6E10 (FUN_007A6E10, Moho::CameraImpl::CameraSetHeading)
     * Mangled: ?CameraSetHeading@CameraImpl@Moho@@UAEXM@Z
     *
     * What it does:
     * Arms rotated mode, clears revert state, and stores current heading lane.
     */
    virtual void CameraSetHeading(float headingRadians);

    /**
     * Address: 0x007A6DE0 (FUN_007A6DE0, Moho::CameraImpl::CameraHoldRotation)
     * Mangled: ?CameraHoldRotation@CameraImpl@Moho@@QAEXXZ
     *
     * What it does:
     * Arms camera rotation hold mode and clears any pending revert flag.
     */
    void CameraHoldRotation();

    /**
     * Address: 0x007A80A0 (FUN_007A80A0, Moho::CameraImpl::CameraReset)
     * Mangled: ?CameraReset@CameraImpl@Moho@@UAEXXZ
     *
     * What it does:
     * Resets runtime camera orientation/target lanes to map-centered defaults.
     */
    virtual void CameraReset();

    /**
     * Address: 0x007A6E40 (FUN_007A6E40, Moho::CameraImpl::CameraRevertRotation)
     * Mangled: ?CameraRevertRotation@CameraImpl@Moho@@UAEXXZ
     *
     * What it does:
     * Schedules a rotation revert when the camera is currently in rotated mode.
     */
    virtual void CameraRevertRotation();

    /**
     * Address: 0x007A7DC0 (FUN_007A7DC0, CameraImpl deleting wrapper)
     * Slot: 0
     *
     * What it does:
     * Runs `CameraImpl` teardown and frees object storage when
     * `deleteFlags & 1` is set.
     */
    virtual void operator_delete(std::int32_t deleteFlags);

    /**
     * Address: 0x007A69F0 (Moho::CameraImpl::CameraGetName)
     * Slot: 1
     */
    [[nodiscard]] virtual const char* CameraGetName() const;

    /**
     * Address: 0x007A6A00 (Moho::CameraImpl::CameraGetView)
     * Slot: 2
     */
    [[nodiscard]] virtual const GeomCamera3& CameraGetView() const;

    /**
     * Address: 0x007A7410 (FUN_007A7410, Moho::CameraImpl::GetViewBox)
     * Mangled: ?GetViewBox@CameraImpl@Moho@@UBE?AV?$AxisAlignedBox3@M@Wm3@@XZ
     *
     * What it does:
     * Returns an axis-aligned box centered on the target location with half
     * extents derived from half of the current near-zoom lane.
     */
    [[nodiscard]] virtual Wm3::AxisAlignedBox3f GetViewBox() const;

    /**
     * Address: 0x007A6A80 (FUN_007A6A80, Moho::CameraImpl::CameraSetViewport)
     * Mangled: ?CameraSetViewport@CameraImpl@Moho@@QAEPAV?$Vector2@M@Wm3@@ABV34@0@Z
     *
     * What it does:
     * Updates camera viewport origin/size lanes, rebuilds viewport row-2
     * normalization from row-1, and refreshes zoom-metric aspect scaling.
     */
    void CameraSetViewport(const Wm3::Vector2f& viewportOrigin, const Wm3::Vector2f& viewportSize);

    /**
     * Address: 0x007A6A10 (FUN_007A6A10, Moho::CameraImpl::CameraSetOrtho)
     * Mangled: ?CameraSetOrtho@CameraImpl@Moho@@UAEX_N@Z
     *
     * What it does:
     * Stores orthographic-camera mode flag lane.
     */
    virtual void CameraSetOrtho(bool enabled);

    /**
     * Address: 0x007A6A20 (FUN_007A6A20, Moho::CameraImpl::CameraIsOrtho)
     * Mangled: ?CameraIsOrtho@CameraImpl@Moho@@UAE_NXZ
     *
     * What it does:
     * Returns orthographic-camera mode flag lane.
     */
    [[nodiscard]] virtual bool CameraIsOrtho();

    /**
     * Address: 0x007A6B20 (FUN_007A6B20, Moho::CameraImpl::CameraGetViewport)
     * Mangled: ?CameraGetViewport@CameraImpl@Moho@@UBEXAAV?$Vector2@M@Wm3@@0@Z
     *
     * What it does:
     * Returns current camera viewport origin and viewport size lanes.
     */
    virtual void CameraGetViewport(Wm3::Vector2f& viewportOrigin, Wm3::Vector2f& viewportSize) const;

    /**
     * Address: 0x007A6C90 (FUN_007A6C90, Moho::CameraImpl::CameraGetZoom)
     * Mangled: ?CameraGetZoom@CameraImpl@Moho@@UBEMXZ
     *
     * What it does:
     * Returns current camera zoom lane.
     */
    [[nodiscard]] virtual float CameraGetZoom() const;

    /**
     * Address: 0x007A6CC0 (FUN_007A6CC0, Moho::CameraImpl::CameraGetHeading)
     * Mangled: ?CameraGetHeading@CameraImpl@Moho@@UBEMXZ
     *
     * What it does:
     * Returns current camera heading lane in radians.
     */
    [[nodiscard]] virtual float CameraGetHeading() const;

    /**
     * Address: 0x007A6CD0 (FUN_007A6CD0, Moho::CameraImpl::CameraGetPitch)
     * Mangled: ?CameraGetPitch@CameraImpl@Moho@@UBEMXZ
     *
     * What it does:
     * Returns current camera pitch lane in radians.
     */
    [[nodiscard]] virtual float CameraGetPitch() const;

    /**
     * Address: 0x007A6E30 (FUN_007A6E30, Moho::CameraImpl::CameraIsRotated)
     * Mangled: ?CameraIsRotated@CameraImpl@Moho@@UBE_NXZ
     *
     * What it does:
     * Returns whether rotated-camera mode is currently enabled.
     */
    [[nodiscard]] virtual bool CameraIsRotated() const;

    /**
     * Address: 0x007A6B50 (FUN_007A6B50, ?Project@CameraImpl@Moho@@UBE?AV?$Vector2@M@Wm3@@ABV?$Vector3@M@4@@Z)
     *
     * What it does:
     * Projects one world-space point through the embedded camera view and
     * returns screen-space coordinates.
     */
    [[nodiscard]] virtual Wm3::Vector2f Project(const Wm3::Vector3f& worldPoint) const;

    /**
     * Address: 0x007A6B70 (FUN_007A6B70, ?Unproject@CameraImpl@Moho@@UBE?AU?$GeomLine3@M@2@ABV?$Vector2@M@Wm3@@@Z)
     *
     * What it does:
     * Builds one world-space ray from a screen-space point using the embedded
     * camera view/projection/viewport lanes.
     */
    [[nodiscard]] virtual GeomLine3 Unproject(const Wm3::Vector2f& screenPoint) const;

    /**
     * Address: 0x007A6BB0 (FUN_007A6BB0, ?CameraScreenToSurface@CameraImpl@Moho@@UBE?AV?$Vector3@M@Wm3@@ABV?$Vector2@M@4@@Z)
     *
     * What it does:
     * Unprojects one screen-space point and resolves the terrain/water surface
     * intersection point on the active map.
     */
    [[nodiscard]] virtual Wm3::Vector3f CameraScreenToSurface(const Wm3::Vector2f& screenPoint) const;

    /**
     * Address: 0x007A72F0 (FUN_007A72F0, ?SetLODScale@CameraImpl@Moho@@UAEXM@Z)
     *
     * What it does:
     * Updates embedded camera LOD scale used by projection/unprojection lanes.
     */
    virtual void SetLODScale(float scale);

    /**
     * Address: 0x007A7120 (FUN_007A7120, Moho::CameraImpl::CanShake)
     * Mangled: ?CanShake@CameraImpl@Moho@@UAEX_N@Z
     *
     * What it does:
     * Enables or disables camera-shake application for this camera runtime.
     */
    virtual void CanShake(bool canShake);

    /**
     * Address: 0x007A7130 (FUN_007A7130, Moho::CameraImpl::CameraShake)
     * Mangled: ?CameraShake@CameraImpl@Moho@@UAEXABUSCamShakeParams@2@@Z
     *
     * What it does:
     * Arms camera shake params when shaking is enabled and either the previous
     * shake finished or incoming shake has stronger minimum magnitude.
     */
    virtual void CameraShake(const SCamShakeParams& shakeParams);

    /**
     * Address: 0x007A7910 (FUN_007A7910, Moho::CameraImpl::GetArmyUnitsInFrustum)
     *
     * What it does:
     * Returns one cached weak-vector view of focus-army units currently in
     * camera frustum.
     */
    [[nodiscard]] CameraFrustumUserEntityList* GetArmyUnitsInFrustum();

    /**
      * Alias of FUN_007A6BF0 (non-canonical helper lane).
     * Mangled: ?TargetNothing@CameraImpl@Moho@@UAEXXZ
     *
     * What it does:
     * Stops entity tracking broadcasts when needed, resets target mode to
     * location, and clears target-time lanes.
     */
    virtual void TargetNothing();

    /**
     * Address: 0x007A7290 (FUN_007A7290, Moho::CameraImpl::GetTargetEntity)
     * Mangled: ?GetTargetEntity@CameraImpl@Moho@@UBEPAVUserEntity@2@XZ
     *
     * What it does:
     * Returns current live entity target when target mode is entity/nose-cam.
     */
    [[nodiscard]] virtual UserEntity* GetTargetEntity() const;

    /**
     * Address: 0x007A71B0 (FUN_007A71B0, Moho::CameraImpl::CameraFollow)
     * Mangled: ?CameraFollow@CameraImpl@Moho@@UAEXABUSCamFollowParams@2@@Z
     *
     * What it does:
     * Promotes one follow target into the active camera target list when the
     * current entity-id gate still matches.
     */
    virtual void CameraFollow(const SCamFollowParams& followParams);

    /**
     * Address: 0x007A73E0 (FUN_007A73E0, Moho::CameraImpl::GetTargetPosition)
     * Mangled: ?GetTargetPosition@CameraImpl@Moho@@UBE?AV?$Vector3@M@Wm3@@XZ
     *
     * What it does:
     * Returns current target-position lane by value.
     */
    [[nodiscard]] virtual Wm3::Vector3f GetTargetPosition() const;

    /**
     * Address: 0x007A82F0 (FUN_007A82F0, Moho::CameraImpl::TargetLocation)
     * Mangled: ?TargetLocation@CameraImpl@Moho@@UAEXABV?$Vector3@M@Wm3@@M@Z
     *
     * What it does:
     * Targets one world-space location with optional timed transition and
     * immediate focus/FOV update when `seconds == 0`.
     */
    virtual void TargetLocation(const Wm3::Vec3f& position, float seconds);

    /**
     * Address: 0x007A8D40 (FUN_007A8D40, Moho::CameraImpl::TargetManual)
     * Mangled: ?TargetManual@CameraImpl@Moho@@UAEXABV?$Vector3@M@Wm3@@MMMM@Z
     *
     * What it does:
     * Targets one world-space location plus heading/pitch/zoom lanes and
     * either applies the result immediately or seeds Hermite transition state.
     */
    virtual void TargetManual(const Wm3::Vec3f& position, float heading, float pitch, float zoom, float seconds);

    /**
     * Address: 0x007A8E90 (FUN_007A8E90, Moho::CameraImpl::SetZoom)
     * Mangled: ?SetZoom@CameraImpl@Moho@@QAEXMM@Z
     *
     * What it does:
     * Re-applies manual targeting at the current target position while keeping
     * the active heading and far-pitch lanes and substituting a new
     * zoom/seconds pair.
     */
    void SetZoom(float zoom, float seconds);

    /**
     * Address: 0x007A83E0 (FUN_007A83E0, Moho::CameraImpl::TargetBox)
     * Mangled: ?TargetBox@CameraImpl@Moho@@UAEXABV?$AxisAlignedBox3@M@Wm3@@M@Z
     *
     * What it does:
     * Targets one world-space AABB, derives focus/near-zoom lanes from box
     * bounds, and optionally applies immediate focus+FOV clamping.
     */
    virtual void TargetBox(const Wm3::AxisAlignedBox3f& targetBox, float seconds);

    /**
     * Address: 0x007A8640 (FUN_007A8640, Moho::CameraImpl::TargetEntities)
     * Mangled: ?TargetEntities@CameraImpl@Moho@@UAEXABV?$WeakSet@VUserEntity@Moho@@@2@_NMM@Z
     *
     * What it does:
     * Replaces camera target weak-list from one entity weak-set, then starts
     * tracked or untracked multi-entity target behavior.
     */
    virtual void TargetEntities(
      const SSelectionSetUserEntity& entities,
      bool trackEntities,
      float zoom,
      float seconds
    );

    /**
     * Address: 0x007A8EE0 (FUN_007A8EE0, Moho::CameraImpl::TargetNextEntity)
     * Mangled: ?TargetNextEntity@CameraImpl@Moho@@UAEXXZ
     *
     * What it does:
     * Advances active entity-target cursor to the next live weak target,
     * prunes stale weak nodes, and emits tracking stop/start notifications.
     */
    virtual void TargetNextEntity();

    /**
     * Address: 0x007A8A20 (FUN_007A8A20, Moho::CameraImpl::TargetNoseCam)
     * Mangled: ?TargetNoseCam@CameraImpl@Moho@@QAEXABV?$WeakSet@VUserEntity@Moho@@@2@MMMM@Z
     *
     * What it does:
     * Targets one entity list in nose-camera mode with pitch-adjust, zoom,
     * transition seconds, and transition parameter lanes.
     */
    void TargetNoseCam(
      const SSelectionSetUserEntity& entities,
      float pitchAdjust,
      float zoom,
      float seconds,
      float transition
    );

    /**
     * Address: 0x007A74C0 (FUN_007A74C0, Moho::CameraImpl::TimedMoveInit)
     * Mangled: ?TimedMoveInit@CameraImpl@Moho@@QAEXMM@Z
     *
     * What it does:
     * Seeds timed-move state lanes for position/zoom/pitch/heading transition.
     */
    void TimedMoveInit(float seconds, float transitionParam);

    /**
     * Address: 0x007A8940 (FUN_007A8940, Moho::CameraImpl::SetupHermite)
     * Mangled: ?SetupHermite@CameraImpl@Moho@@QAEXXZ
     *
     * What it does:
     * Derives Hermite delta lanes for target offset/heading/pitch/zoom when
     * ease-in/out mode is disabled.
     */
    void SetupHermite();

    /**
     * Address: 0x007A9320 (FUN_007A9320, Moho::CameraImpl::ClampTargetPos)
     * Mangled: ?ClampTargetPos@CameraImpl@Moho@@QAEXXZ
     *
     * What it does:
     * Clamps target X/Z to map or playable-rect bounds using zoom-proportional
     * extents.
     */
    void ClampTargetPos();

    /**
     * Address: 0x007A9470 (FUN_007A9470, Moho::CameraImpl::ClampFocusPos)
     * Mangled: ?ClampFocusPos@CameraImpl@Moho@@QAEXXZ
     *
     * What it does:
     * Projects one heading/pitch ray from current offset and snaps focus to the
     * terrain/water surface hit when valid.
     */
    void ClampFocusPos();

    /**
     * Address: 0x007A9550 (FUN_007A9550, Moho::CameraImpl::CalculateFOV)
     * Mangled: ?CalculateFOV@CameraImpl@Moho@@QAEXXZ
     *
     * What it does:
     * Recomputes far-FOV from logarithmic zoom interpolation between near/far
     * camera zoom envelopes.
     */
    void CalculateFOV();

    /**
     * Address: 0x007A6C80 (Moho::CameraImpl::CameraGetOffset)
     * Slot: 18
     *
     * What it does:
     * Returns the world-camera offset vector used by listener metric updates.
     */
    [[nodiscard]] virtual const Wm3::Vec3f& CameraGetOffset() const;

    /**
     * Address: 0x007A6CA0 (Moho::CameraImpl::CameraGetTargetZoom)
     * Slot: 19
     */
    [[nodiscard]] virtual float CameraGetTargetZoom() const;

    /**
     * Address: 0x007A7310 (Moho::CameraImpl::GetMaxZoom)
     * Slot: 20
     */
    [[nodiscard]] virtual float GetMaxZoom() const;

    /**
     * Address: 0x007A73C0 (FUN_007A73C0, Moho::CameraImpl::SetMaxZoomMult)
     * Slot: 21
     *
     * What it does:
     * Updates one runtime multiplier that scales the max zoom limit.
     */
    virtual void SetMaxZoomMult(float maxZoomMult);

    /**
     * Address: 0x007A6A30 (FUN_007A6A30, Moho::CameraImpl::SetTimeSource)
     * Mangled: ?SetTimeSource@CameraImpl@Moho@@QAEXW4ECamTimeSource@2@@Z
     *
     * What it does:
     * Stores the active runtime time-source selector in the camera runtime
     * view.
     */
    void SetTimeSource(ECamTimeSource timeSource);

    /**
     * Address: 0x007A72C0 (FUN_007A72C0, Moho::CameraImpl::LODMetric)
     * Slot: 45
     */
    [[nodiscard]] virtual float LODMetric(const Wm3::Vec3f& offset) const;
  };

  /**
   * Address: 0x007AAC60 (FUN_007AAC60, Moho::RCamCamera::~RCamCamera)
   *
   * What it does:
   * Removes one runtime camera from manager ownership and restores the base
   * broadcaster node to a self-linked idle state.
   */
  [[nodiscard]] Broadcaster* DetachRuntimeCameraBase(CameraImpl* camera);

  template <>
  class CScrLuaMetatableFactory<CameraImpl> final : public CScrLuaObjectFactory
  {
  public:
    [[nodiscard]]
    static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<CameraImpl>) == 0x08,
    "CScrLuaMetatableFactory<CameraImpl> size must be 0x08"
  );

  /**
   * Address: 0x007B0A90 (FUN_007B0A90, func_CreateLuaCameraImpl)
   *
   * What it does:
   * Returns cached `CameraImpl` metatable object from Lua object-factory
   * storage.
   */
  LuaPlus::LuaObject* func_CreateLuaCameraImpl(LuaPlus::LuaObject* object, LuaPlus::LuaState* state);

  /**
   * Address: 0x007AB080 (FUN_007AB080, cfunc_GetCamera)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_GetCameraL`.
   */
  int cfunc_GetCamera(lua_State* luaContext);

  /**
   * Address: 0x007AB0A0 (FUN_007AB0A0, func_GetCamera_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder metadata for `GetCamera(name)`.
   */
  CScrLuaInitForm* func_GetCamera_LuaFuncDef();

  /**
   * Address: 0x007AB100 (FUN_007AB100, cfunc_GetCameraL)
   *
   * What it does:
   * Resolves one camera name from Lua and pushes the camera script object or
   * nil when no camera matches.
   */
  int cfunc_GetCameraL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AB4E0 (FUN_007AB4E0, cfunc_CameraImplSnapTo)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CameraImplSnapToL`.
   */
  int cfunc_CameraImplSnapTo(lua_State* luaContext);

  /**
   * Address: 0x007AB500 (FUN_007AB500, func_CameraImplSnapTo_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:SnapTo`.
   */
  CScrLuaInitForm* func_CameraImplSnapTo_LuaFuncDef();

  /**
   * Address: 0x007AB560 (FUN_007AB560, cfunc_CameraImplSnapToL)
   *
   * What it does:
   * Validates `Camera:SnapTo(position, orientationHPR, zoom)`, resolves Lua
   * payloads, and dispatches immediate manual camera targeting.
   */
  int cfunc_CameraImplSnapToL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AB6E0 (FUN_007AB6E0, cfunc_CameraImplMoveTo)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplMoveToL`.
   */
  int cfunc_CameraImplMoveTo(lua_State* luaContext);

  /**
   * Address: 0x007AB1B0 (FUN_007AB1B0, cfunc_CameraImplMoveToRegion)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplMoveToRegionL`.
   */
  int cfunc_CameraImplMoveToRegion(lua_State* luaContext);

  /**
   * Address: 0x007AB1D0 (FUN_007AB1D0, func_CameraImplMoveToRegion_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:MoveToRegion`.
   */
  CScrLuaInitForm* func_CameraImplMoveToRegion_LuaFuncDef();

  /**
   * Address: 0x007AB230 (FUN_007AB230, cfunc_CameraImplMoveToRegionL)
   *
   * What it does:
   * Validates `Camera:MoveTo(region[,seconds])`, quantizes region corners to
   * terrain grid cell centers, samples corner elevations, and targets one
   * world box transition.
   */
  int cfunc_CameraImplMoveToRegionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AB760 (FUN_007AB760, cfunc_CameraImplMoveToL)
   *
   * What it does:
   * Validates `Camera:MoveTo(position, orientationHPR, zoom, seconds)`,
   * resolves typed camera/vector payloads from Lua, and dispatches the manual
   * camera-target lane.
   */
  int cfunc_CameraImplMoveToL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AC760 (FUN_007AC760, cfunc_CameraImplSetZoom)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplSetZoomL`.
   */
  int cfunc_CameraImplSetZoom(lua_State* luaContext);

  /**
   * Address: 0x007AC780 (FUN_007AC780, func_CameraImplSetZoom_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:SetZoom`.
   */
  CScrLuaInitForm* func_CameraImplSetZoom_LuaFuncDef();

  /**
   * Address: 0x007AC7E0 (FUN_007AC7E0, cfunc_CameraImplSetZoomL)
   *
   * What it does:
   * Validates `Camera:SetZoom(zoom,seconds)`, keeps current target position and
   * heading/pitch lanes, and dispatches manual camera targeting with new zoom
   * and transition seconds.
   */
  int cfunc_CameraImplSetZoomL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AC930 (FUN_007AC930, cfunc_CameraImplSetTargetZoom)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplSetTargetZoomL`.
   */
  int cfunc_CameraImplSetTargetZoom(lua_State* luaContext);

  /**
   * Address: 0x007AC950 (FUN_007AC950, func_CameraImplSetTargetZoom_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:SetTargetZoom`.
   */
  CScrLuaInitForm* func_CameraImplSetTargetZoom_LuaFuncDef();

  /**
   * Address: 0x007AC9B0 (FUN_007AC9B0, cfunc_CameraImplSetTargetZoomL)
   *
   * What it does:
   * Validates `Camera:SetTargetZoom(zoom)` and updates one runtime near-zoom
   * lane directly from Lua.
   */
  int cfunc_CameraImplSetTargetZoomL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AD720 (FUN_007AD720, cfunc_CameraImplSetMaxZoomMult)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplSetMaxZoomMultL`.
   */
  int cfunc_CameraImplSetMaxZoomMult(lua_State* luaContext);

  /**
   * Address: 0x007AD740 (FUN_007AD740, func_CameraImplSetMaxZoomMult_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:SetMaxZoomMult`.
   */
  CScrLuaInitForm* func_CameraImplSetMaxZoomMult_LuaFuncDef();

  /**
   * Address: 0x007AD7A0 (FUN_007AD7A0, cfunc_CameraImplSetMaxZoomMultL)
   *
   * What it does:
   * Validates `Camera:SetMaxZoomMult(mult)` and applies one max-zoom
   * multiplier through the camera virtual lane.
   */
  int cfunc_CameraImplSetMaxZoomMultL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AB700 (FUN_007AB700, func_CameraImplMoveTo_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:MoveTo`.
   */
  CScrLuaInitForm* func_CameraImplMoveTo_LuaFuncDef();

  /**
   * Address: 0x007AB930 (FUN_007AB930, cfunc_CameraImplReset)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CameraImplResetL`.
   */
  int cfunc_CameraImplReset(lua_State* luaContext);

  /**
   * Address: 0x007AB9B0 (FUN_007AB9B0, cfunc_CameraImplResetL)
   *
   * What it does:
   * Validates `Camera:Reset()`, resolves one camera payload, and invokes
   * `CameraImpl::CameraReset`.
   */
  int cfunc_CameraImplResetL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AB950 (FUN_007AB950, func_CameraImplReset_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:Reset`.
   */
  CScrLuaInitForm* func_CameraImplReset_LuaFuncDef();

  /**
   * Address: 0x007ABA80 (FUN_007ABA80, func_CameraImplTrackEntities_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:TrackEntities`.
   */
  CScrLuaInitForm* func_CameraImplTrackEntities_LuaFuncDef();

  /**
   * Address: 0x007ABA60 (FUN_007ABA60, cfunc_CameraImplTrackEntities)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplTrackEntitiesL`.
   */
  int cfunc_CameraImplTrackEntities(lua_State* luaContext);

  /**
   * Address: 0x007ABAE0 (FUN_007ABAE0, cfunc_CameraImplTrackEntitiesL)
   *
   * What it does:
   * Validates `Camera:TrackEntities(ents,zoom,seconds)` and dispatches tracked
   * multi-entity targeting.
   */
  int cfunc_CameraImplTrackEntitiesL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007ABE60 (FUN_007ABE60, func_CameraImplTargetEntities_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:TargetEntities`.
   */
  CScrLuaInitForm* func_CameraImplTargetEntities_LuaFuncDef();

  /**
   * Address: 0x007ABE40 (FUN_007ABE40, cfunc_CameraImplTargetEntities)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplTargetEntitiesL`.
   */
  int cfunc_CameraImplTargetEntities(lua_State* luaContext);

  /**
   * Address: 0x007ABEC0 (FUN_007ABEC0, cfunc_CameraImplTargetEntitiesL)
   *
   * What it does:
   * Validates `Camera:TargetEntities(ents,zoom,seconds)` and dispatches
   * untracked multi-entity targeting.
   */
  int cfunc_CameraImplTargetEntitiesL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AC1E0 (FUN_007AC1E0, func_CameraImplNoseCam_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:NoseCam`.
   */
  CScrLuaInitForm* func_CameraImplNoseCam_LuaFuncDef();

  /**
   * Address: 0x007AC1C0 (FUN_007AC1C0, cfunc_CameraImplNoseCam)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CameraImplNoseCamL`.
   */
  int cfunc_CameraImplNoseCam(lua_State* luaContext);

  /**
   * Address: 0x007AC240 (FUN_007AC240, cfunc_CameraImplNoseCamL)
   *
   * What it does:
   * Validates `Camera:NoseCam(ent,pitchAdjust,zoom,seconds,transition)` and
   * dispatches nose-camera targeting.
   */
  int cfunc_CameraImplNoseCamL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AC520 (FUN_007AC520, func_CameraImplHoldRotation_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:HoldRotation`.
   */
  CScrLuaInitForm* func_CameraImplHoldRotation_LuaFuncDef();

  /**
   * Address: 0x007AC500 (FUN_007AC500, cfunc_CameraImplHoldRotation)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplHoldRotationL`.
   */
  int cfunc_CameraImplHoldRotation(lua_State* luaContext);

  /**
   * Address: 0x007AC580 (FUN_007AC580, cfunc_CameraImplHoldRotationL)
   *
   * What it does:
   * Validates `Camera:HoldRotation()`, resolves one camera payload, and
   * applies hold-rotation runtime flags.
   */
  int cfunc_CameraImplHoldRotationL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AC650 (FUN_007AC650, func_CameraImplRevertRotation_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:RevertRotation`.
   */
  CScrLuaInitForm* func_CameraImplRevertRotation_LuaFuncDef();

  /**
   * Address: 0x007AC630 (FUN_007AC630, cfunc_CameraImplRevertRotation)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplRevertRotationL`.
   */
  int cfunc_CameraImplRevertRotation(lua_State* luaContext);

  /**
   * Address: 0x007AC6B0 (FUN_007AC6B0, cfunc_CameraImplRevertRotationL)
   *
   * What it does:
   * Validates `Camera:RevertRotation()`, resolves one camera payload, and
   * invokes `CameraImpl::CameraRevertRotation`.
   */
  int cfunc_CameraImplRevertRotationL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AD650 (FUN_007AD650, cfunc_CameraImplGetMinZoom)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplGetMinZoomL`.
   */
  int cfunc_CameraImplGetMinZoom(lua_State* luaContext);

  /**
   * Address: 0x007AD670 (FUN_007AD670, func_CameraImplGetMinZoom_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:GetMinZoom`.
   */
  CScrLuaInitForm* func_CameraImplGetMinZoom_LuaFuncDef();

  /**
   * Address: 0x007ACC40 (FUN_007ACC40, cfunc_CameraImplGetZoom)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplGetZoomL`.
   */
  int cfunc_CameraImplGetZoom(lua_State* luaContext);

  /**
   * Address: 0x007ACC60 (FUN_007ACC60, func_CameraImplGetZoom_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:GetZoom`.
   */
  CScrLuaInitForm* func_CameraImplGetZoom_LuaFuncDef();

  /**
   * Address: 0x007ACCC0 (FUN_007ACCC0, cfunc_CameraImplGetZoomL)
   *
   * What it does:
   * Validates `Camera:GetZoom()`, resolves one camera payload, and pushes the
   * current target-zoom scalar.
   */
  int cfunc_CameraImplGetZoomL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007ACDA0 (FUN_007ACDA0, func_CameraImplGetFocusPosition_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:GetFocusPosition`.
   */
  CScrLuaInitForm* func_CameraImplGetFocusPosition_LuaFuncDef();

  /**
   * Address: 0x007ACEE0 (FUN_007ACEE0, cfunc_CameraImplSaveSettings)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplSaveSettingsL`.
   */
  int cfunc_CameraImplSaveSettings(lua_State* luaContext);

  /**
   * Address: 0x007ACF00 (FUN_007ACF00, func_CameraImplSaveSettings_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:SaveSettings`.
   */
  CScrLuaInitForm* func_CameraImplSaveSettings_LuaFuncDef();

  /**
   * Address: 0x007ACF60 (FUN_007ACF60, cfunc_CameraImplSaveSettingsL)
   *
   * What it does:
   * Captures one camera snapshot table (`Focus`, `Zoom`, `Pitch`, `Heading`)
   * from the current camera runtime and returns it to Lua.
   */
  int cfunc_CameraImplSaveSettingsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AD0D0 (FUN_007AD0D0, cfunc_CameraImplRestoreSettings)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplRestoreSettingsL`.
   */
  int cfunc_CameraImplRestoreSettings(lua_State* luaContext);

  /**
   * Address: 0x007AD0F0 (FUN_007AD0F0, func_CameraImplRestoreSettings_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:RestoreSettings`.
   */
  CScrLuaInitForm* func_CameraImplRestoreSettings_LuaFuncDef();

  /**
   * Address: 0x007AD150 (FUN_007AD150, cfunc_CameraImplRestoreSettingsL)
   *
   * What it does:
   * Reads one saved camera snapshot table (`Focus`, `Zoom`, `Pitch`,
   * `Heading`), restores manual target state immediately, then clears timed
   * targeting and reapplies rotation-revert semantics.
   */
  int cfunc_CameraImplRestoreSettingsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AD3D0 (FUN_007AD3D0, cfunc_CameraImplGetTargetZoom)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplGetTargetZoomL`.
   */
  int cfunc_CameraImplGetTargetZoom(lua_State* luaContext);

  /**
   * Address: 0x007AD3F0 (FUN_007AD3F0, func_CameraImplGetTargetZoom_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:GetTargetZoom`.
   */
  CScrLuaInitForm* func_CameraImplGetTargetZoom_LuaFuncDef();

  /**
   * Address: 0x007AD450 (FUN_007AD450, cfunc_CameraImplGetTargetZoomL)
   *
   * What it does:
   * Validates `Camera:GetTargetZoom()`, resolves typed camera payload, pushes
   * current near-zoom lane, and returns one Lua result.
   */
  int cfunc_CameraImplGetTargetZoomL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AD510 (FUN_007AD510, cfunc_CameraImplGetMaxZoom)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplGetMaxZoomL`.
   */
  int cfunc_CameraImplGetMaxZoom(lua_State* luaContext);

  /**
   * Address: 0x007AD530 (FUN_007AD530, func_CameraImplGetMaxZoom_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:GetMaxZoom`.
   */
  CScrLuaInitForm* func_CameraImplGetMaxZoom_LuaFuncDef();

  /**
   * Address: 0x007AD590 (FUN_007AD590, cfunc_CameraImplGetMaxZoomL)
   *
   * What it does:
   * Validates `Camera:GetMaxZoom()`, resolves typed camera payload, queries
   * runtime max zoom through virtual lane, and returns one Lua result.
   */
  int cfunc_CameraImplGetMaxZoomL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AD6D0 (FUN_007AD6D0, cfunc_CameraImplGetMinZoomL)
   *
   * What it does:
   * Validates `Camera:GetMinZoom()`, pushes the global near-zoom value, and
   * returns one Lua result.
   */
  int cfunc_CameraImplGetMinZoomL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007ACAA0 (FUN_007ACAA0, cfunc_CameraImplSetAccMode)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplSetAccModeL`.
   */
  int cfunc_CameraImplSetAccMode(lua_State* luaContext);

  /**
   * Address: 0x007ACB20 (FUN_007ACB20, cfunc_CameraImplSetAccModeL)
   *
   * What it does:
   * Validates `Camera:SetAccMode(accTypeName)`, resolves typed camera payload
   * and one string mode token from Lua, then dispatches
   * `CameraImpl::CameraSetAccType`.
   */
  int cfunc_CameraImplSetAccModeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007ACAC0 (FUN_007ACAC0, func_CameraImplSetAccMode_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:SetAccMode`.
   */
  CScrLuaInitForm* func_CameraImplSetAccMode_LuaFuncDef();

  /**
   * Address: 0x007AD890 (FUN_007AD890, cfunc_CameraImplSpin)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CameraImplSpinL`.
   */
  int cfunc_CameraImplSpin(lua_State* luaContext);

  /**
   * Address: 0x007AD910 (FUN_007AD910, cfunc_CameraImplSpinL)
   *
   * What it does:
   * Reads heading/optional zoom spin rates from Lua and arms camera spin target
   * lanes for Hermite targeting.
   */
  int cfunc_CameraImplSpinL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AD8B0 (FUN_007AD8B0, func_CameraImplSpin_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:Spin`.
   */
  CScrLuaInitForm* func_CameraImplSpin_LuaFuncDef();

  /**
   * Address: 0x007ADAB0 (FUN_007ADAB0, func_CameraImplUseGameClock_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:UseGameClock`.
   */
  CScrLuaInitForm* func_CameraImplUseGameClock_LuaFuncDef();

  /**
   * Address: 0x007ADA90 (FUN_007ADA90, cfunc_CameraImplUseGameClock)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplUseGameClockL`.
   */
  int cfunc_CameraImplUseGameClock(lua_State* luaContext);

  /**
   * Address: 0x007ADB10 (FUN_007ADB10, cfunc_CameraImplUseGameClockL)
   *
   * What it does:
   * Validates `Camera:UseGameClock()`, resolves one camera payload, and
   * switches camera timing to game-clock mode.
   */
  int cfunc_CameraImplUseGameClockL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007ADBE0 (FUN_007ADBE0, func_CameraImplUseSystemClock_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:UseSystemClock`.
   */
  CScrLuaInitForm* func_CameraImplUseSystemClock_LuaFuncDef();

  /**
   * Address: 0x007ADBC0 (FUN_007ADBC0, cfunc_CameraImplUseSystemClock)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplUseSystemClockL`.
   */
  int cfunc_CameraImplUseSystemClock(lua_State* luaContext);

  /**
   * Address: 0x007ADC40 (FUN_007ADC40, cfunc_CameraImplUseSystemClockL)
   *
   * What it does:
   * Validates `Camera:UseSystemClock()`, resolves one camera payload, and
   * switches camera timing to system-clock mode.
   */
  int cfunc_CameraImplUseSystemClockL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007ADD10 (FUN_007ADD10, func_CameraImplEnableEaseInOut_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:EnableEaseInOut`.
   */
  CScrLuaInitForm* func_CameraImplEnableEaseInOut_LuaFuncDef();

  /**
   * Address: 0x007ADCF0 (FUN_007ADCF0, cfunc_CameraImplEnableEaseInOut)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplEnableEaseInOutL`.
   */
  int cfunc_CameraImplEnableEaseInOut(lua_State* luaContext);

  /**
   * Address: 0x007ADD70 (FUN_007ADD70, cfunc_CameraImplEnableEaseInOutL)
   *
   * What it does:
   * Validates `Camera:EnableEaseInOut()`, resolves one camera payload, and
   * enables ease-in/out targeting behavior.
   */
  int cfunc_CameraImplEnableEaseInOutL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007ADE40 (FUN_007ADE40, func_CameraImplDisableEaseInOut_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:DisableEaseInOut`.
   */
  CScrLuaInitForm* func_CameraImplDisableEaseInOut_LuaFuncDef();

  /**
   * Address: 0x007ADE20 (FUN_007ADE20, cfunc_CameraImplDisableEaseInOut)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplDisableEaseInOutL`.
   */
  int cfunc_CameraImplDisableEaseInOut(lua_State* luaContext);

  /**
   * Address: 0x007ADEA0 (FUN_007ADEA0, cfunc_CameraImplDisableEaseInOutL)
   *
   * What it does:
   * Validates `Camera:DisableEaseInOut()`, resolves one camera payload, and
   * disables ease-in/out targeting behavior.
   */
  int cfunc_CameraImplDisableEaseInOutL(LuaPlus::LuaState* state);

  static_assert(sizeof(CameraImpl) == sizeof(void*), "CameraImpl size must be pointer-sized");
} // namespace moho
