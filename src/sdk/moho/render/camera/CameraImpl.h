#pragma once

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
   * Address: 0x007AB6E0 (FUN_007AB6E0, cfunc_CameraImplMoveTo)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplMoveToL`.
   */
  int cfunc_CameraImplMoveTo(lua_State* luaContext);

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
   * Address: 0x007AB700 (FUN_007AB700, func_CameraImplMoveTo_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:MoveTo`.
   */
  CScrLuaInitForm* func_CameraImplMoveTo_LuaFuncDef();

  static_assert(sizeof(CameraImpl) == sizeof(void*), "CameraImpl size must be pointer-sized");
} // namespace moho
