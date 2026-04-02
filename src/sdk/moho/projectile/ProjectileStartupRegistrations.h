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
  class ManyToOneBroadcaster
  {
  public:
    inline static gpg::RType* sType = nullptr;
  };

  template <class TEvent>
  class ManyToOneListener
  {
  public:
    inline static gpg::RType* sType = nullptr;
  };

  using ManyToOneBroadcaster_EProjectileImpactEvent = ManyToOneBroadcaster<EProjectileImpactEvent>;
  using ManyToOneListener_EProjectileImpactEvent = ManyToOneListener<EProjectileImpactEvent>;

  class EProjectileImpactEventTypeInfo final : public gpg::REnumType
  {
  public:
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
} // namespace moho
