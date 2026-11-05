#pragma once

// Private to moho/entity: helpers the pieces of the former Entity.cpp share.

#include "Entity.h"
#if FAF_SERVER_MODE
#include "remote/UnderlayPaths.h"
#endif
#include "platform/Interlocked.h"

#include <utility>
#include "legacy/math/X87Math.h"
#include <algorithm>
#include <bit>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>
#include <atomic>
#include <string>
#include <unordered_map>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/audio/CSimSoundManager.h"
#include "moho/audio/CSndParams.h"
#include "moho/ai/CAiBrain.h"
#include "moho/ai/CAiTarget.h"
#include "moho/entity/CTextureScroller.h"
#include "moho/entity/EntityCategoryLookupResolver.h"
#include "moho/collision/CColPrimitiveBase.h"
#include "moho/entity/EntityDb.h"
#include "moho/entity/Motor.h"
#include "moho/entity/SSTIEntityConstantData.h"
#include "moho/entity/Prop.h"
#include "moho/entity/UserEntity.h"
#include "moho/entity/MotorFallDown.h"
#include "moho/sim/SimArchiveMode.h"
#include "moho/entity/MotorSinkAway.h"
#include "moho/entity/PositionHistory.h"
#include "moho/entity/EVisibilityModeTypeInfo.h"
#include "moho/entity/intel/CIntel.h"
#include "moho/projectile/Projectile.h"
#include "moho/sim/ReconBlip.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/SCR_FromLua.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/misc/CDiskWatch.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/misc/WeakPtr.h"
#include "moho/entity/REntityBlueprintTypeInfo.h"
#include "moho/resource/RResId.h"
#include "moho/resource/RScmResource.h"
#include "moho/resource/blueprints/RBlueprint.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/resource/blueprints/RPropBlueprint.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/animation/CAniSkel.h"
#include "moho/render/camera/VTransform.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "moho/math/QuaternionMath.h"
#include "moho/math/Angle.h"
#include "moho/script/CScriptEvent.h"
#include "moho/misc/StatItem.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CArmyStats.h"
#include "moho/sim/CSimConVarInstanceBase.h"
#include "moho/sim/EAllianceTypeInfo.h"
#include "moho/sim/SimDebugCommandRegistrations.h"
#include "moho/sim/CRandomStream.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/UnitUpdateFill.h"
#include "moho/sim/SPhysBody.h"
#include "moho/sim/STIMap.h"
#include "moho/unit/core/Unit.h"

#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/console/CConCommand.h"

namespace moho
{

}

namespace
{
  using moho::CArmyImpl;
  using moho::Entity;
  using moho::Sim;

  [[nodiscard]] const char* ResolveEntityBlueprintId(const Entity* const entity) noexcept
  {
    if (entity == nullptr || entity->BluePrint == nullptr || entity->BluePrint->mBlueprintId.empty()) {
      return "";
    }
    return entity->BluePrint->mBlueprintId.c_str();
  }

  /**
   * The `Sound{}` userdata holds a `CSndParams*`, so what the reflection
   * upcast yields is the *slot*, not the object - `func_GetCObj_CSndParams`
   * (0x004E4B40) is typed `CSndParams**` for exactly that reason, and every
   * ground-truth caller dereferences it (`v8 = *CObj_CSndParams` in
   * cfunc_EntityPlaySoundL 0x0068CCB0, cfunc_EntitySetAmbientSoundL
   * 0x0068CE40, cfunc_UnitWeaponPlaySoundL 0x006D7C50).
   *
   * A local resolver here used to upcast to the *object* type and hand back
   * `upcast.mObj` undereferenced, so callers received the address of the
   * pointer variable inside the Lua userdata block and read that block as if
   * it were a CSndParams. Use the canonical accessor instead.
   */

  /**
   * Address: 0x0067F100 (FUN_0067F100, func_CastRPropBlueprint)
   *
   * What it does:
   * Upcasts one reflected object reference to `RPropBlueprint` and returns
   * the typed pointer when compatible.
   */
  [[maybe_unused]] [[nodiscard]] moho::RPropBlueprint* func_CastRPropBlueprint(const gpg::RRef& source)
  {
    gpg::RType* type = moho::RPropBlueprint::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::RPropBlueprint));
      moho::RPropBlueprint::sType = type;
    }

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, type);
    return static_cast<moho::RPropBlueprint*>(upcast.mObj);
  }
}

namespace moho
{
  int cfunc_EntityPushOver(lua_State* luaContext);
  int cfunc_EntityPushOverL(LuaPlus::LuaState* state);
  int cfunc_EntityFallDown(lua_State* luaContext);
  int cfunc_EntityFallDownL(LuaPlus::LuaState* state);
  int cfunc_EntitySinkAway(lua_State* luaContext);
  int cfunc_EntitySinkAwayL(LuaPlus::LuaState* state);
}

namespace moho
{
  Wm3::Vector3f* CopyEntityDrawScaleToVector( Wm3::Vector3f* const outScale, const Entity* const entity ) noexcept;
  TDatListItem<Entity, EntityDirtyList>* SetEntityDrawScaleAndRelinkCoordNode( Entity* const entity, const Wm3::Vector3f* const drawScale ) noexcept;
  CScrLuaInitForm* func__c_CreateEntity_LuaFuncDef();
  CScrLuaInitForm* func_EntityFallDown_LuaFuncDef();
  CScrLuaInitForm* func_EntitySinkAway_LuaFuncDef();
  CScrLuaInitForm* func_EntityPushOver_LuaFuncDef();
}
