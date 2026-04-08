#pragma once

#include "gpg/core/containers/String.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/render/camera/GeomCamera3.h"
#include "wm3/Vector3.h"

struct lua_State;

namespace LuaPlus
{
  class LuaState;
}

namespace moho
{
  class CScrLuaInitForm;

  class CameraImpl
  {
  public:
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
     * Address: 0x007A7DC0 (sub_7A7DC0)
     * Slot: 0
     */
    virtual void Reserved00() = 0;

    /**
     * Address: 0x007A69F0 (Moho::CameraImpl::CameraGetName)
     * Slot: 1
     */
    [[nodiscard]] virtual const char* CameraGetName() const = 0;

    /**
     * Address: 0x007A6A00 (Moho::CameraImpl::CameraGetView)
     * Slot: 2
     */
    [[nodiscard]] virtual const GeomCamera3& CameraGetView() const = 0;

    /**
     * Address context: called from `cfunc_CameraImplMoveToL` (`0x007AB760`)
     * through vftable slot 14 (`+0x38`).
     *
     * What it does:
     * Starts manual camera movement toward `position` with heading/pitch lanes
     * and transition controls.
     */
    virtual void TargetManual(const Wm3::Vec3f& position, float heading, float pitch, float zoom, float seconds) = 0;

    /**
     * Address: 0x007A6C80 (Moho::CameraImpl::CameraGetOffset)
     * Slot: 18
     *
     * What it does:
     * Returns the world-camera offset vector used by listener metric updates.
     */
    [[nodiscard]] virtual const Wm3::Vec3f& CameraGetOffset() const = 0;

    /**
     * Address: 0x007A6CA0 (Moho::CameraImpl::CameraGetTargetZoom)
     * Slot: 19
     */
    [[nodiscard]] virtual float CameraGetTargetZoom() const = 0;

    /**
     * Address: 0x007A7310 (Moho::CameraImpl::GetMaxZoom)
     * Slot: 20
     */
    [[nodiscard]] virtual float GetMaxZoom() const = 0;

    /**
     * Address: 0x007A73C0 (FUN_007A73C0, Moho::CameraImpl::SetMaxZoomMult)
     * Slot: 21
     *
     * What it does:
     * Updates one runtime multiplier that scales the max zoom limit.
     */
    virtual void SetMaxZoomMult(float maxZoomMult);

    /**
     * Address: 0x007A79E0 (Moho::CameraImpl::LODMetric)
     * Slot: 45
     */
    [[nodiscard]] virtual float LODMetric(const Wm3::Vec3f& offset) const = 0;
  };

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
   * Address: 0x007ABE60 (FUN_007ABE60, func_CameraImplTargetEntities_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:TargetEntities`.
   */
  CScrLuaInitForm* func_CameraImplTargetEntities_LuaFuncDef();

  /**
   * Address: 0x007AC1E0 (FUN_007AC1E0, func_CameraImplNoseCam_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:NoseCam`.
   */
  CScrLuaInitForm* func_CameraImplNoseCam_LuaFuncDef();

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
   * Address: 0x007ACC60 (FUN_007ACC60, func_CameraImplGetZoom_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:GetZoom`.
   */
  CScrLuaInitForm* func_CameraImplGetZoom_LuaFuncDef();

  /**
   * Address: 0x007ACDA0 (FUN_007ACDA0, func_CameraImplGetFocusPosition_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:GetFocusPosition`.
   */
  CScrLuaInitForm* func_CameraImplGetFocusPosition_LuaFuncDef();

  /**
   * Address: 0x007ACF00 (FUN_007ACF00, func_CameraImplSaveSettings_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:SaveSettings`.
   */
  CScrLuaInitForm* func_CameraImplSaveSettings_LuaFuncDef();

  /**
   * Address: 0x007AD0F0 (FUN_007AD0F0, func_CameraImplRestoreSettings_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:RestoreSettings`.
   */
  CScrLuaInitForm* func_CameraImplRestoreSettings_LuaFuncDef();

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
