#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "moho/projectile/CProjectileAttributes.h"
#include "moho/projectile/EProjectileImpactEvent.h"

struct lua_State;

namespace LuaPlus
{
  class LuaState;
}

namespace gpg
{
  struct SerHelperBase;
}

namespace moho
{
  class CScrLuaInitForm;

  template <class TEvent>
  class ManyToOneListener;

  template <class TEvent>
  class ManyToOneBroadcaster
  {
  public:
    inline static gpg::RType* sType = nullptr;
  };

  template <>
  class ManyToOneBroadcaster<EProjectileImpactEvent>
  {
  public:
    static gpg::RType* sType;

    void* ownerLinkSlot; // +0x00
    void* nextInOwner;   // +0x04

    /**
     * Address: 0x005DC230 (FUN_005DC230, Moho::ManyToOneBroadcaster_EProjectileImpactEvent::BroadcastEvent)
     *
     * What it does:
     * Rebinds this projectile-impact broadcaster node to the supplied listener
     * chain head while preserving intrusive owner-chain integrity.
     */
    void BroadcastEvent(ManyToOneListener<EProjectileImpactEvent>* listener);
  };

  template <class TEvent>
  class ManyToOneListener
  {
  public:
    inline static gpg::RType* sType = nullptr;
  };

  using ManyToOneBroadcaster_EProjectileImpactEvent = ManyToOneBroadcaster<EProjectileImpactEvent>;
  using ManyToOneListener_EProjectileImpactEvent = ManyToOneListener<EProjectileImpactEvent>;

  static_assert(
    sizeof(ManyToOneBroadcaster_EProjectileImpactEvent) == 0x08,
    "ManyToOneBroadcaster<EProjectileImpactEvent> size must be 0x08"
  );
  static_assert(
    offsetof(ManyToOneBroadcaster_EProjectileImpactEvent, ownerLinkSlot) == 0x00,
    "ManyToOneBroadcaster<EProjectileImpactEvent>::ownerLinkSlot offset must be 0x00"
  );
  static_assert(
    offsetof(ManyToOneBroadcaster_EProjectileImpactEvent, nextInOwner) == 0x04,
    "ManyToOneBroadcaster<EProjectileImpactEvent>::nextInOwner offset must be 0x04"
  );

  class EProjectileImpactEventTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x0069A720 (FUN_0069A720, Moho::EProjectileImpactEventTypeInfo::EProjectileImpactEventTypeInfo)
     */
    EProjectileImpactEventTypeInfo();

    /**
     * Address: 0x0069A7B0 (FUN_0069A7B0, Moho::EProjectileImpactEventTypeInfo::dtr)
     */
    ~EProjectileImpactEventTypeInfo() override;

    /**
     * Address: 0x0069A7A0 (FUN_0069A7A0, Moho::EProjectileImpactEventTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0069A780 (FUN_0069A780, Moho::EProjectileImpactEventTypeInfo::Init)
     */
    void Init() override;
  };

  /**
   * Address: 0x00BFD510 (FUN_00BFD510, cleanup_TConVar_dbg_Projectile)
   *
   * What it does:
   * Unregisters recovered `dbg_Projectile` console variable at process exit.
   */
  void cleanup_TConVar_dbg_Projectile();

  /**
   * Address: 0x00BD62F0 (FUN_00BD62F0, register_TConVar_dbg_Projectile)
   *
   * What it does:
   * Registers startup `dbg_Projectile` `TConVar<bool>` and installs exit cleanup.
   */
  void register_TConVar_dbg_Projectile();

  /**
   * Address: 0x00BFD540 (FUN_00BFD540, cleanup_EProjectileImpactEventTypeInfo)
   *
   * What it does:
   * Tears down startup `EProjectileImpactEventTypeInfo` storage.
   */
  void cleanup_EProjectileImpactEventTypeInfo();

  /**
   * Address: 0x00BD6330 (FUN_00BD6330, register_EProjectileImpactEventTypeInfo)
   *
   * What it does:
   * Constructs/preregisters `EProjectileImpactEventTypeInfo` and installs
   * process-exit cleanup.
   */
  int register_EProjectileImpactEventTypeInfo();

  /**
   * Address: 0x00BFD550 (FUN_00BFD550, cleanup_EProjectileImpactEventPrimitiveSerializer)
   *
   * What it does:
   * Unlinks primitive serializer helper links for `EProjectileImpactEvent`.
   */
  gpg::SerHelperBase* cleanup_EProjectileImpactEventPrimitiveSerializer();

  /**
   * Address: 0x00BD6350 (FUN_00BD6350, register_EProjectileImpactEventPrimitiveSerializer)
   *
   * What it does:
   * Initializes primitive enum serializer callback lanes for
   * `EProjectileImpactEvent` and installs process-exit cleanup.
   */
  int register_EProjectileImpactEventPrimitiveSerializer();

  /**
   * Address: 0x00BFD7C0 (FUN_00BFD7C0, cleanup_ManyToOneBroadcaster_EProjectileImpactEvent_TypeInfo)
   *
   * What it does:
   * Tears down startup type-info storage for
   * `ManyToOneBroadcaster<EProjectileImpactEvent>`.
   */
  void cleanup_ManyToOneBroadcaster_EProjectileImpactEvent_TypeInfo();

  /**
   * Address: 0x00BD64C0 (FUN_00BD64C0, register_ManyToOneBroadcaster_EProjectileImpactEvent_TypeInfo)
   *
   * What it does:
   * Constructs/preregisters startup type-info for
   * `ManyToOneBroadcaster<EProjectileImpactEvent>` and installs exit cleanup.
   */
  int register_ManyToOneBroadcaster_EProjectileImpactEvent_TypeInfo();

  /**
   * Address: 0x00BFD760 (FUN_00BFD760, cleanup_ManyToOneListener_EProjectileImpactEvent_TypeInfo)
   *
   * What it does:
   * Tears down startup type-info storage for
   * `ManyToOneListener<EProjectileImpactEvent>`.
   */
  void cleanup_ManyToOneListener_EProjectileImpactEvent_TypeInfo();

  /**
   * Address: 0x00BD64E0 (FUN_00BD64E0, register_ManyToOneListener_EProjectileImpactEvent_TypeInfo)
   *
   * What it does:
   * Constructs/preregisters startup type-info for
   * `ManyToOneListener<EProjectileImpactEvent>` and installs exit cleanup.
   */
  int register_ManyToOneListener_EProjectileImpactEvent_TypeInfo();

  /**
   * Address: 0x006A19C0 (FUN_006A19C0, cfunc_ProjectileSetNewTargetGround)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileSetNewTargetGroundL`.
   */
  int cfunc_ProjectileSetNewTargetGround(lua_State* luaContext);

  /**
   * Address: 0x006A1A40 (FUN_006A1A40, cfunc_ProjectileSetNewTargetGroundL)
   *
   * What it does:
   * Reads `(projectile, location)` from Lua and rewrites projectile target data
   * to one ground target at the supplied world-space location.
   */
  int cfunc_ProjectileSetNewTargetGroundL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006A19E0 (FUN_006A19E0, func_ProjectileSetNewTargetGround_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetNewTargetGround(location)` Lua binder definition
   * in the `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetNewTargetGround_LuaFuncDef();

  /**
   * Address: 0x006A1B90 (FUN_006A1B90, cfunc_ProjectileSetLifetime)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_ProjectileSetLifetimeL`.
   */
  int cfunc_ProjectileSetLifetime(lua_State* luaContext);

  /**
   * Address: 0x006A1C10 (FUN_006A1C10, cfunc_ProjectileSetLifetimeL)
   *
   * What it does:
   * Reads `(projectile, seconds)` from Lua, updates projectile lifetime end
   * tick, then returns the projectile Lua object.
   */
  int cfunc_ProjectileSetLifetimeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006A1BB0 (FUN_006A1BB0, func_ProjectileSetLifetime_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetLifetime(seconds)` Lua binder definition in the
   * `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetLifetime_LuaFuncDef();

  /**
   * Address: 0x006A1D30 (FUN_006A1D30, cfunc_ProjectileSetDamage)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileSetDamageL`.
   */
  int cfunc_ProjectileSetDamage(lua_State* luaContext);

  /**
   * Address: 0x006A1DB0 (FUN_006A1DB0, cfunc_ProjectileSetDamageL)
   *
   * What it does:
   * Reads `(projectile, amount?, radius?)` from Lua and applies each non-nil
   * numeric argument to the projectile damage lane.
   */
  int cfunc_ProjectileSetDamageL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006A1D50 (FUN_006A1D50, func_ProjectileSetDamage_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetDamage(amount, radius)` Lua binder definition in
   * the `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetDamage_LuaFuncDef();

  /**
   * Address: 0x006A1F10 (FUN_006A1F10, cfunc_ProjectileSetMaxSpeed)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_ProjectileSetMaxSpeedL`.
   */
  int cfunc_ProjectileSetMaxSpeed(lua_State* luaContext);

  /**
   * Address: 0x006A1F90 (FUN_006A1F90, cfunc_ProjectileSetMaxSpeedL)
   *
   * What it does:
   * Reads `(projectile, speed)` from Lua, writes projectile max-speed lane,
   * and returns the projectile Lua object.
   */
  int cfunc_ProjectileSetMaxSpeedL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006A1F30 (FUN_006A1F30, func_ProjectileSetMaxSpeed_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetMaxSpeed(speed)` Lua binder definition in the
   * `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetMaxSpeed_LuaFuncDef();

  /**
   * Address: 0x006A2090 (FUN_006A2090, cfunc_ProjectileSetAcceleration)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileSetAccelerationL`.
   */
  int cfunc_ProjectileSetAcceleration(lua_State* luaContext);

  /**
   * Address: 0x006A2110 (FUN_006A2110, cfunc_ProjectileSetAccelerationL)
   *
   * What it does:
   * Reads `(projectile, acceleration)` from Lua, writes projectile
   * acceleration lane, and returns the projectile Lua object.
   */
  int cfunc_ProjectileSetAccelerationL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006A20B0 (FUN_006A20B0, func_ProjectileSetAcceleration_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetAcceleration(accel)` Lua binder definition in the
   * `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetAcceleration_LuaFuncDef();

  /**
   * Address: 0x006A2210 (FUN_006A2210, cfunc_ProjectileSetBallisticAcceleration)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileSetBallisticAccelerationL`.
   */
  int cfunc_ProjectileSetBallisticAcceleration(lua_State* luaContext);

  /**
   * Address: 0x006A2290 (FUN_006A2290, cfunc_ProjectileSetBallisticAccelerationL)
   *
   * What it does:
   * Reads ballistic acceleration args from Lua (`self`, optional components),
   * writes projectile ballistic acceleration vector, and returns projectile Lua
   * object.
   */
  int cfunc_ProjectileSetBallisticAccelerationL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006A2230 (FUN_006A2230, func_ProjectileSetBallisticAcceleration_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetBallisticAcceleration(...)` Lua binder definition
   * in the `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetBallisticAcceleration_LuaFuncDef();

  /**
   * Address: 0x006A2470 (FUN_006A2470, cfunc_ProjectileSetDestroyOnWater)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileSetDestroyOnWaterL`.
   */
  int cfunc_ProjectileSetDestroyOnWater(lua_State* luaContext);

  /**
   * Address: 0x006A24F0 (FUN_006A24F0, cfunc_ProjectileSetDestroyOnWaterL)
   *
   * What it does:
   * Reads `(projectile, flag)` from Lua and writes projectile
   * `destroy-on-water` lane.
   */
  int cfunc_ProjectileSetDestroyOnWaterL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006A2490 (FUN_006A2490, func_ProjectileSetDestroyOnWater_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetDestroyOnWater(flag)` Lua binder definition in
   * the `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetDestroyOnWater_LuaFuncDef();

  /**
   * Address: 0x006A25B0 (FUN_006A25B0, cfunc_ProjectileSetTurnRate)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileSetTurnRateL`.
   */
  int cfunc_ProjectileSetTurnRate(lua_State* luaContext);

  /**
   * Address: 0x006A2630 (FUN_006A2630, cfunc_ProjectileSetTurnRateL)
   *
   * What it does:
   * Reads `(projectile, radiansPerSecond)` from Lua, writes projectile
   * turn-rate lane, and returns the projectile Lua object.
   */
  int cfunc_ProjectileSetTurnRateL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006A25D0 (FUN_006A25D0, func_ProjectileSetTurnRate_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetTurnRate(radians_per_second)` Lua binder
   * definition in the `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetTurnRate_LuaFuncDef();

  /**
   * Address: 0x006A2730 (FUN_006A2730, cfunc_ProjectileGetCurrentSpeed)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileGetCurrentSpeedL`.
   */
  int cfunc_ProjectileGetCurrentSpeed(lua_State* luaContext);

  /**
   * Address: 0x006A27B0 (FUN_006A27B0, cfunc_ProjectileGetCurrentSpeedL)
   *
   * What it does:
   * Reads one projectile arg, computes current velocity magnitude, and returns
   * one Lua numeric result.
   */
  int cfunc_ProjectileGetCurrentSpeedL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006A2750 (FUN_006A2750, func_ProjectileGetCurrentSpeed_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:GetCurrentSpeed() -> val` Lua binder definition in
   * the `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileGetCurrentSpeed_LuaFuncDef();

  /**
   * Address: 0x006A2A10 (FUN_006A2A10, cfunc_ProjectileSetVelocity)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileSetVelocityL`.
   */
  int cfunc_ProjectileSetVelocity(lua_State* luaContext);

  /**
   * Address: 0x006A2A90 (FUN_006A2A90, cfunc_ProjectileSetVelocityL)
   *
   * What it does:
   * Reads `(projectile, speed)` or `(projectile, vx, vy, vz)` from Lua,
   * updates projectile velocity, and returns the projectile Lua object.
   */
  int cfunc_ProjectileSetVelocityL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006A2A30 (FUN_006A2A30, func_ProjectileSetVelocity_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetVelocity(speed)` /
   * `Projectile:SetVelocity(vx,vy,vz)` Lua binder definition in the `sim`
   * init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetVelocity_LuaFuncDef();

  /**
   * Address: 0x006A2CF0 (FUN_006A2CF0, cfunc_ProjectileSetScaleVelocity)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileSetScaleVelocityL`.
   */
  int cfunc_ProjectileSetScaleVelocity(lua_State* luaContext);

  /**
   * Address: 0x006A2D70 (FUN_006A2D70, cfunc_ProjectileSetScaleVelocityL)
   *
   * What it does:
   * Reads `(projectile, uniformScaleVelocity)` or
   * `(projectile, x, y, z)` from Lua, writes `mScaleVelocity`, and returns the
   * projectile Lua object (or `nil` when projectile resolution fails).
   */
  int cfunc_ProjectileSetScaleVelocityL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006A2D10 (FUN_006A2D10, func_ProjectileSetScaleVelocity_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetScaleVelocity(vs)` /
   * `Projectile:SetScaleVelocity(vsx, vsy, vsz)` Lua binder definition in the
   * `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetScaleVelocity_LuaFuncDef();

  /**
   * Address: 0x006A2F60 (FUN_006A2F60, cfunc_ProjectileSetLocalAngularVelocity)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileSetLocalAngularVelocityL`.
   */
  int cfunc_ProjectileSetLocalAngularVelocity(lua_State* luaContext);

  /**
   * Address: 0x006A2FE0 (FUN_006A2FE0, cfunc_ProjectileSetLocalAngularVelocityL)
   *
   * What it does:
   * Reads projectile plus local angular velocity `(x, y, z)` from Lua and
   * writes projectile local angular velocity lanes before returning the
   * projectile Lua object.
   */
  int cfunc_ProjectileSetLocalAngularVelocityL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006A2F80 (FUN_006A2F80, func_ProjectileSetLocalAngularVelocity_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetLocalAngularVelocity(x,y,z)` Lua binder definition
   * in the `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetLocalAngularVelocity_LuaFuncDef();

  /**
   * Address: 0x006A3170 (FUN_006A3170, cfunc_ProjectileSetCollision)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileSetCollisionL`.
   */
  int cfunc_ProjectileSetCollision(lua_State* luaContext);

  /**
   * Address: 0x006A31F0 (FUN_006A31F0, cfunc_ProjectileSetCollisionL)
   *
   * What it does:
   * Reads `(projectile, enabled)` from Lua, updates both collision booleans,
   * and returns the projectile Lua object.
   */
  int cfunc_ProjectileSetCollisionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006A3190 (FUN_006A3190, func_ProjectileSetCollision_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetCollision(onoff)` Lua binder definition in the
   * `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetCollision_LuaFuncDef();

  /**
   * Address: 0x006A32E0 (FUN_006A32E0, cfunc_ProjectileSetCollideSurface)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileSetCollideSurfaceL`.
   */
  int cfunc_ProjectileSetCollideSurface(lua_State* luaContext);

  /**
   * Address: 0x006A3360 (FUN_006A3360, cfunc_ProjectileSetCollideSurfaceL)
   *
   * What it does:
   * Reads `(projectile, enabled)` from Lua, updates surface-collision lane, and
   * returns the projectile Lua object.
   */
  int cfunc_ProjectileSetCollideSurfaceL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006A3300 (FUN_006A3300, func_ProjectileSetCollideSurface_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetCollideSurface(onoff)` Lua binder definition in
   * the `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetCollideSurface_LuaFuncDef();

  /**
   * Address: 0x006A3430 (FUN_006A3430, cfunc_ProjectileSetCollideEntity)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileSetCollideEntityL`.
   */
  int cfunc_ProjectileSetCollideEntity(lua_State* luaContext);

  /**
   * Address: 0x006A34B0 (FUN_006A34B0, cfunc_ProjectileSetCollideEntityL)
   *
   * What it does:
   * Reads `(projectile, enabled)` from Lua, updates entity-collision lane, and
   * returns the projectile Lua object.
   */
  int cfunc_ProjectileSetCollideEntityL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006A3450 (FUN_006A3450, func_ProjectileSetCollideEntity_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetCollideEntity(onoff)` Lua binder definition in the
   * `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetCollideEntity_LuaFuncDef();

  /**
   * Address: 0x006A3580 (FUN_006A3580, cfunc_ProjectileStayUnderwater)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileStayUnderwaterL`.
   */
  int cfunc_ProjectileStayUnderwater(lua_State* luaContext);

  /**
   * Address: 0x006A3600 (FUN_006A3600, cfunc_ProjectileStayUnderwaterL)
   *
   * What it does:
   * Reads `(projectile, enabled)` from Lua, updates stay-underwater flag, and
   * returns the projectile Lua object.
   */
  int cfunc_ProjectileStayUnderwaterL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006A35A0 (FUN_006A35A0, func_ProjectileStayUnderwater_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:StayUnderwater(onoff)` Lua binder definition in the
   * `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileStayUnderwater_LuaFuncDef();

  /**
   * Address: 0x006A36D0 (FUN_006A36D0, cfunc_ProjectileTrackTarget)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_ProjectileTrackTargetL`.
   */
  int cfunc_ProjectileTrackTarget(lua_State* luaContext);

  /**
   * Address: 0x006A3750 (FUN_006A3750, cfunc_ProjectileTrackTargetL)
   *
   * What it does:
   * Reads `(projectile, enabled)` from Lua, updates target-tracking flag, and
   * returns the projectile Lua object.
   */
  int cfunc_ProjectileTrackTargetL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006A36F0 (FUN_006A36F0, func_ProjectileTrackTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:TrackTarget(onoff)` Lua binder definition in the
   * `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileTrackTarget_LuaFuncDef();

  /**
   * Address: 0x006A3820 (FUN_006A3820, cfunc_ProjectileSetStayUpright)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileSetStayUprightL`.
   */
  int cfunc_ProjectileSetStayUpright(lua_State* luaContext);

  /**
   * Address: 0x006A38A0 (FUN_006A38A0, cfunc_ProjectileSetStayUprightL)
   *
   * What it does:
   * Reads `(projectile, enabled)` from Lua and updates stay-upright flag.
   */
  int cfunc_ProjectileSetStayUprightL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006A3840 (FUN_006A3840, func_ProjectileSetStayUpright_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetStayUpright(truefalse)` Lua binder definition in
   * the `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetStayUpright_LuaFuncDef();

  /**
   * Address: 0x006A3960 (FUN_006A3960, cfunc_ProjectileSetVelocityAlign)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileSetVelocityAlignL`.
   */
  int cfunc_ProjectileSetVelocityAlign(lua_State* luaContext);

  /**
   * Address: 0x006A39E0 (FUN_006A39E0, cfunc_ProjectileSetVelocityAlignL)
   *
   * What it does:
   * Reads `(projectile, enabled)` from Lua and updates velocity-align flag.
   */
  int cfunc_ProjectileSetVelocityAlignL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006A3980 (FUN_006A3980, func_ProjectileSetVelocityAlign_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetVelocityAlign(truefalse)` Lua binder definition in
   * the `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetVelocityAlign_LuaFuncDef();

  /**
   * Address: 0x006A3AA0 (FUN_006A3AA0, cfunc_ProjectileCreateChildProjectile)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileCreateChildProjectileL`.
   */
  int cfunc_ProjectileCreateChildProjectile(lua_State* luaContext);

  /**
   * Address: 0x006A3B20 (FUN_006A3B20, cfunc_ProjectileCreateChildProjectileL)
   *
   * What it does:
   * Reads `(projectile, blueprintId)`, creates one child projectile from the
   * source projectile launch profile, and returns the created Lua projectile.
   */
  int cfunc_ProjectileCreateChildProjectileL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006A3AC0 (FUN_006A3AC0, func_ProjectileCreateChildProjectile_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:CreateChildProjectile(blueprint)` Lua binder
   * definition in the `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileCreateChildProjectile_LuaFuncDef();

  /**
   * Address: 0x006A3CF0 (FUN_006A3CF0, cfunc_ProjectileSetVelocityRandomUpVector)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileSetVelocityRandomUpVectorL`.
   */
  int cfunc_ProjectileSetVelocityRandomUpVector(lua_State* luaContext);

  /**
   * Address: 0x006A3D70 (FUN_006A3D70, cfunc_ProjectileSetVelocityRandomUpVectorL)
   *
   * What it does:
   * Reads one projectile arg and replaces projectile velocity with a random
   * upward-direction vector scaled to projectile blueprint max speed.
   */
  int cfunc_ProjectileSetVelocityRandomUpVectorL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006A3D10 (FUN_006A3D10, func_ProjectileSetVelocityRandomUpVector_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetVelocityRandomUpVector(self)` Lua binder
   * definition in the `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetVelocityRandomUpVector_LuaFuncDef();

  /**
   * Address: 0x006A3F00 (FUN_006A3F00, cfunc_ProjectileChangeMaxZigZag)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileChangeMaxZigZagL`.
   */
  int cfunc_ProjectileChangeMaxZigZag(lua_State* luaContext);

  /**
   * Address: 0x006A3F80 (FUN_006A3F80, cfunc_ProjectileChangeMaxZigZagL)
   *
   * What it does:
   * Reads `(projectile, value)` from Lua and updates projectile zig-zag
   * amplitude lane.
   */
  int cfunc_ProjectileChangeMaxZigZagL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006A3F20 (FUN_006A3F20, func_ProjectileChangeMaxZigZag_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:ChangeMaxZigZag(value)` Lua binder definition in the
   * `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileChangeMaxZigZag_LuaFuncDef();

  /**
   * Address: 0x006A4070 (FUN_006A4070, cfunc_ProjectileChangeZigZagFrequency)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileChangeZigZagFrequencyL`.
   */
  int cfunc_ProjectileChangeZigZagFrequency(lua_State* luaContext);

  /**
   * Address: 0x006A40F0 (FUN_006A40F0, cfunc_ProjectileChangeZigZagFrequencyL)
   *
   * What it does:
   * Reads `(projectile, value)` from Lua and updates projectile zig-zag
   * frequency lane.
   */
  int cfunc_ProjectileChangeZigZagFrequencyL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006A4090 (FUN_006A4090, func_ProjectileChangeZigZagFrequency_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:ChangeZigZagFrequency(value)` Lua binder definition
   * in the `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileChangeZigZagFrequency_LuaFuncDef();

  /**
   * Address: 0x006A41E0 (FUN_006A41E0, cfunc_ProjectileChangeDetonateAboveHeight)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileChangeDetonateAboveHeightL`.
   */
  int cfunc_ProjectileChangeDetonateAboveHeight(lua_State* luaContext);

  /**
   * Address: 0x006A4260 (FUN_006A4260, cfunc_ProjectileChangeDetonateAboveHeightL)
   *
   * What it does:
   * Reads `(projectile, value)` from Lua and updates projectile detonate-above
   * height lane.
   */
  int cfunc_ProjectileChangeDetonateAboveHeightL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006A4200 (FUN_006A4200, func_ProjectileChangeDetonateAboveHeight_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:ChangeDetonateAboveHeight(value)` Lua binder
   * definition in the `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileChangeDetonateAboveHeight_LuaFuncDef();

  /**
   * Address: 0x006A4350 (FUN_006A4350, cfunc_ProjectileChangeDetonateBelowHeight)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileChangeDetonateBelowHeightL`.
   */
  int cfunc_ProjectileChangeDetonateBelowHeight(lua_State* luaContext);

  /**
   * Address: 0x006A43D0 (FUN_006A43D0, cfunc_ProjectileChangeDetonateBelowHeightL)
   *
   * What it does:
   * Reads `(projectile, value)` from Lua and updates projectile detonate-below
   * height lane.
   */
  int cfunc_ProjectileChangeDetonateBelowHeightL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006A4370 (FUN_006A4370, func_ProjectileChangeDetonateBelowHeight_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:ChangeDetonateBelowHeight(value)` Lua binder
   * definition in the `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileChangeDetonateBelowHeight_LuaFuncDef();
} // namespace moho
