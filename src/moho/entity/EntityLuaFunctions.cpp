#include "moho/entity/EntityPrivate.h"
#include "moho/lua/CScrLuaInitForm.h"

namespace
{
  // _c_CreateEntity global Lua factory (name/help preserved from FUN_006922D0).
  constexpr const char* kCreateEntityName = "_c_CreateEntity";
  constexpr const char* kCreateEntityHelpText = "_c_CreateEntity(spec)";
}

namespace
{
  using moho::CArmyStatItem;
  using moho::CArmyStats;
  using moho::StatItem;

  constexpr const char* kEntityAttachBoneToHelpText = "Entity:AttachBoneTo(selfbone, entity, bone)";
  constexpr const char* kEntityAttachFailureError = "Failed to attach entity %s to %s on bone %d";
  constexpr const char* kEntityCreateProjectileName = "CreateProjectile";
  constexpr const char* kEntityCreateProjectileAtBoneName = "CreateProjectileAtBone";
  constexpr const char* kGetBlueprintSimName = "GetBlueprint";
  constexpr const char* kEntityGetAIBrainName = "GetAIBrain";
  constexpr const char* kEntityGetBlueprintName = "GetBlueprint";
  constexpr const char* kEntityGetArmyName = "GetArmy";
  constexpr const char* kEntityGetBoneDirectionName = "GetBoneDirection";
  constexpr const char* kEntityIsValidBoneName = "IsValidBone";
  constexpr const char* kEntityGetBoneCountName = "GetBoneCount";
  constexpr const char* kEntityGetBoneNameName = "GetBoneName";
  constexpr const char* kEntityRequestRefreshUIName = "RequestRefreshUI";
  constexpr const char* kEntityAttachBoneToName = "AttachBoneTo";
  constexpr const char* kEntitySetParentOffsetName = "SetParentOffset";
  constexpr const char* kEntityDetachFromName = "DetachFrom";
  constexpr const char* kEntityGetParentName = "GetParent";
  constexpr const char* kEntityGetCollisionExtentsName = "GetCollisionExtents";
  constexpr const char* kEntityPlaySoundName = "PlaySound";
  constexpr const char* kEntitySetAmbientSoundName = "SetAmbientSound";
  constexpr const char* kEntityGetFractionCompleteName = "GetFractionComplete";
  constexpr const char* kEntityAdjustHealthName = "AdjustHealth";
  constexpr const char* kEntityGetHealthName = "GetHealth";
  constexpr const char* kEntityGetMaxHealthName = "GetMaxHealth";
  constexpr const char* kEntitySetHealthName = "SetHealth";
  constexpr const char* kEntitySetMaxHealthName = "SetMaxHealth";
  constexpr const char* kEntitySetVizToFocusPlayerName = "SetVizToFocusPlayer";
  constexpr const char* kEntitySetVizToEnemiesName = "SetVizToEnemies";
  constexpr const char* kEntitySetVizToAlliesName = "SetVizToAllies";
  constexpr const char* kEntitySetVizToNeutralsName = "SetVizToNeutrals";
  constexpr const char* kEntitySetCollisionShapeName = "SetCollisionShape";
  constexpr const char* kEntityAddLocalImpulseName = "AddLocalImpulse";
  constexpr const char* kEntityAddWorldImpulseName = "AddWorldImpulse";
  constexpr const char* kEntityReachedMaxShootersName = "ReachedMaxShooters";
  constexpr const char* kEntityGetOrientationName = "GetOrientation";
  constexpr const char* kEntityGetHeadingName = "GetHeading";
  constexpr const char* kEntitySetMeshName = "SetMesh";
  constexpr const char* kEntityGetScaleName = "GetScale";
  constexpr const char* kEntitySetScaleName = "SetScale";
  constexpr const char* kEntityAddManualScrollerName = "AddManualScroller";
  constexpr const char* kEntityAddThreadScrollerName = "AddThreadScroller";
  constexpr const char* kEntityAddPingPongScrollerName = "AddPingPongScroller";
  constexpr const char* kEntityRemoveScrollerName = "RemoveScroller";
  constexpr const char* kEntityDestroyName = "Destroy";
  constexpr const char* kEntityBeenDestroyedName = "BeenDestroyed";
  constexpr const char* kEntityKillName = "Kill";
  constexpr const char* kEntityPushOverName = "PushOver";
  constexpr const char* kEntityFallDownName = "FallDown";
  constexpr const char* kEntitySinkAwayName = "SinkAway";
  constexpr const char* kEntitySetCollisionShapeHelpText =
    "Entity:SetCollisionShape(['Box'|'Sphere'|'None'], centerX, Y, Z, size) -- size is radius for sphere, x,y,z extent for box";
  constexpr const char* kEntityAddLocalImpulseHelpText = "AddLocalImpulse(self, Ix, Iy, Iz, Px, Py, Pz)";
  constexpr const char* kEntityAddWorldImpulseHelpText = "AddWorldImpulse(self, Ix, Iy, Iz, Px, Py, Pz)";
  constexpr const char* kEntityReachedMaxShootersHelpText = "ReachedMaxShooters()";
  constexpr const char* kEntityGetOrientationHelpText = "Entity:GetOrientation()";
  constexpr const char* kEntityGetHeadingHelpText = "Entity:GetHeading()";
  constexpr const char* kEntitySetMeshHelpText = "Entity:SetMesh(meshBp, bool keepActor): Change mesh on the fly";
  constexpr const char* kEntityGetScaleHelpText = "Entity:GetScale() -> sx,sy,sz -- return current draw scale of this entity";
  constexpr const char* kEntitySetScaleHelpText = "Entity:SetScale(s) or Entity:SetScale(sx,sy,sz)";
  constexpr const char* kEntityAddManualScrollerHelpText = "Entity:AddManualScroller(scrollSpeed1, scrollSpeed2)";
  constexpr const char* kEntityAddThreadScrollerHelpText = "Entity:AddThreadScroller(sideDist, scrollMult)";
  constexpr const char* kEntityAddPingPongScrollerHelpText =
    "Entity:AddPingPongScroller(ping1, pingSpeed1, pong1, pongSpeed1, ping2, pingSpeed2, pong2, pongSpeed2)";
  constexpr const char* kEntityRemoveScrollerHelpText = "Entity:RemoveScroller()";
  constexpr const char* kEntityDestroyHelpText = "Entity:Destroy()";
  constexpr const char* kEntityBeenDestroyedHelpText = "Entity:BeenDestroyed()";
  constexpr const char* kEntityKillHelpText = "Entity:Kill(instigator,type,excessDamageRatio)";
  constexpr const char* kEntityPushOverHelpText = "Entity:PushOver(nx, ny, nz, depth)";
  constexpr const char* kEntityFallDownHelpText = "Entity:FallDown(dx,dy,dz,force) -- start falling down";
  constexpr const char* kEntitySinkAwayHelpText = "Entity:SinkAway(vy) -- sink into the ground";
  constexpr const char* kEntityGetEntityIdName = "GetEntityId";
  constexpr const char* kEntityDetachAllName = "DetachAll";
  constexpr const char* kEntitySetDrawScaleName = "SetDrawScale";
  constexpr const char* kEntityKillCounterStatName = "KILLS";
  constexpr const char* kEntityKillBenignCategoryName = "BENIGN";
  constexpr const char* kEntityRealtimeStatsPrefix = "RealTimeStats_";
  constexpr const char* kEntitySetVizToFocusPlayerHelpText = "SetVizToFocusPlayer(type)";
  constexpr const char* kEntitySetVizToEnemiesHelpText = "SetVizToEnemies(type)";
  constexpr const char* kEntitySetVizToAlliesHelpText = "SetVizToAllies(type)";
  constexpr const char* kEntitySetVizToNeutralsHelpText = "SetVizToNeutrals(type)";
  constexpr const char* kGetBlueprintSimHelpText = "blueprint = GetBlueprint(entity)";
  constexpr const char* kEntityGetAIBrainHelpText = "GetAIBrain(self)";
  constexpr const char* kEntityGetBlueprintHelpText = "blueprint = Entity:GetBlueprint()";
  constexpr const char* kEntityGetArmyHelpText = "GetArmy(self)";
  constexpr const char* kEntityGetBoneDirectionHelpText = "Entity:GetBoneDirection(bone_name)";
  constexpr const char* kEntityIsValidBoneHelpText = "Entity:IsValidBone(nameOrIndex,allowNil=false)";
  constexpr const char* kEntityGetBoneCountHelpText =
    "Entity:GetBoneCount() -- returns number of bones in this entity's skeleton";
  constexpr const char* kEntityGetBoneNameHelpText =
    "Entity:GetBoneName(i) -- return the name of the i'th bone of this entity (counting from 0)";
  constexpr const char* kEntityRequestRefreshUIHelpText = "Entity:RequestRefreshUI()";
  constexpr const char* kEntitySetParentOffsetHelpText = "Entity:SetParentOffset(vector)";
  constexpr const char* kEntityDetachFromHelpText = "Entity:DetachFrom([skipBallistic])";
  constexpr const char* kEntityGetParentHelpText = "Entity:GetParent()";
  constexpr const char* kEntityGetCollisionExtentsHelpText = "Entity:GetCollisionExtents()";
  constexpr const char* kEntityPlaySoundHelpText = "Entity:PlaySound(params)";
  constexpr const char* kEntitySetAmbientSoundHelpText = "Entity:SetAmbientSound(paramTableDetail,paramTableRumble)";
  constexpr const char* kEntityGetFractionCompleteHelpText = "Entity:GetFractionComplete()";
  constexpr const char* kEntityAdjustHealthHelpText = "Entity:AdjustHealth(instigator, delta)";
  constexpr const char* kEntityGetHealthHelpText = "Entity:GetHealth()";
  constexpr const char* kEntityGetMaxHealthHelpText = "Entity:GetMaxHealth()";
  constexpr const char* kEntitySetHealthHelpText = "Entity:SetHealth(instigator,health)";
  constexpr const char* kEntitySetMaxHealthHelpText = "Entity:SetMaxHealth(maxhealth)";
  constexpr const char* kEntityGetEntityIdHelpText = "Entity:GetEntityId()";
  constexpr const char* kEntityDetachAllHelpText = "Entity:DetachAll(bone,[skipBallistic])";
  constexpr const char* kEntitySetDrawScaleHelpText = "Entity:SetDrawScale(size): Change mesh scale on the fly";
  constexpr const char* kEntityCreateProjectileHelpText = "Entity:CreateProjectile(proj_bp, [ox, oy, oz], [dx, dy, dz]";
  constexpr const char* kEntityCreateProjectileAtBoneHelpText =
    "Entity:CreateProjectileAtBone(projectile_blueprint, bone)";
  constexpr const char* kEntityShakeCameraName = "ShakeCamera";
  constexpr const char* kEntityShakeCameraHelpText =
    "Entity:ShakeCamera(radius, max, min, duration)\n"
    "Shake the camera. This is a method of entities rather than a global function\n"
    "because it takes the position of the entity as the epicenter where it shakes more.\n"
    "\n"
    "    radius - distance from epicenter at which shaking falls off to 'min'\n"
    "    max - size of shaking in world units, when looking at epicenter\n"
    "    min - size of shaking in world units, when at 'radius' distance or farther\n"
    "    duration - length of time to shake for, in seconds";
  constexpr const char* kEntityLuaClassName = "Entity";

  [[nodiscard]] float ReadLuaNumberArgument(LuaPlus::LuaState* const state, const int stackIndex)
  {
    LuaPlus::LuaStackObject arg(state, stackIndex);
    if (lua_type(state->m_state, stackIndex) != LUA_TNUMBER) {
      arg.TypeError("number");
    }
    return static_cast<float>(lua_tonumber(state->m_state, stackIndex));
  }

  void AddStatCounter(StatItem* const statItem, const long delta) noexcept
  {
    if (!statItem) {
      return;
    }
#if defined(_WIN32)
    statItem->AddPrimaryBits(delta);
#else
    statItem->mPrimaryValueBits += static_cast<std::int32_t>(delta);
#endif
  }

  void AccumulateArmyRealtimeStat(CArmyImpl* const army, const fa::string& statPath, const long delta)
  {
    if (army == nullptr || statPath.empty()) {
      return;
    }

    CArmyStats* const armyStats = army->GetArmyStats();
    if (armyStats == nullptr) {
      return;
    }

    CArmyStatItem* const statItem = armyStats->TraverseTables(statPath.c_str(), true);
    if (statItem == nullptr) {
      return;
    }

    statItem->SynchronizeAsInt();
    AddStatCounter(statItem, delta);
  }

  void UpdateEntityKillRealtimeStats(Entity* const victim, Entity* const instigator)
  {
    if (victim == nullptr || instigator == nullptr) {
      return;
    }

    // 0x00692080 / 0x00692181 (cfunc_EntityKillL): each lane is gated on that
    // entity's own `RealtimeStatsEnabled` byte (+0x1F8) before its ArmyRef.
    if (victim->IsRealtimeStatsEnabled() && victim->ArmyRef != nullptr) {
      fa::string statPath = fa::string(kEntityRealtimeStatsPrefix) + victim->GetUniqueName();
      statPath += gpg::STR_Printf("_KilledBy_Army%d_", instigator->GetArmyIndex()); // 0x006920E6: 0-based
      statPath += ResolveEntityBlueprintId(instigator);
      AccumulateArmyRealtimeStat(victim->ArmyRef, statPath, 1L);
    }

    if (instigator->IsRealtimeStatsEnabled() && instigator->ArmyRef != nullptr) {
      fa::string statPath = fa::string(kEntityRealtimeStatsPrefix) + instigator->GetUniqueName();
      statPath += gpg::STR_Printf("_Kills_Army%d_", victim->GetArmyIndex()); // 0x006921E6: 0-based
      statPath += ResolveEntityBlueprintId(victim);
      AccumulateArmyRealtimeStat(instigator->ArmyRef, statPath, 1L);
    }
  }

  /**
   * Address: 0x0051C400 (FUN_0051C400)
   *
   * What it does:
   * Samples one randomized projectile spawn offset from blueprint position lanes
   * using symmetric per-axis spread ranges.
   */
  [[nodiscard]] Wm3::Vector3f SampleProjectileSpawnOffset(
    moho::CRandomStream& random,
    const moho::RProjectileBlueprint& blueprint
  ) noexcept
  {
    const auto sampleAxis = [&random](const float base, const float range) noexcept -> float {
      return random.FRand(-range, range) + base;
    };

    Wm3::Vector3f out{};
    out.x = sampleAxis(blueprint.Physics.PositionX, blueprint.Physics.PositionXRange);
    out.y = sampleAxis(blueprint.Physics.PositionY, blueprint.Physics.PositionYRange);
    out.z = sampleAxis(blueprint.Physics.PositionZ, blueprint.Physics.PositionZRange);
    return out;
  }

  /**
   * Inlined in `cfunc_EntitySetCollisionShapeL` (0x0068F2D5-0x0068F301).
   *
   * What it does:
   * Resolves the shape name through the reflected `ECollisionShape` enum
   * (`IsEnumType()->GetEnumValue`, 0x008D9FD0), whose option match is a CRT
   * `_stricmp` -- "box", "SPHERE" etc. are accepted exactly as in retail.
   */
  [[nodiscard]] bool TryParseCollisionShapeName(
    const char* const shapeName,
    moho::ECollisionShape* const outShape
  )
  {
    static gpg::RType* sCollisionShapeType = nullptr;
    if (sCollisionShapeType == nullptr) {
      sCollisionShapeType = gpg::LookupRType(typeid(moho::ECollisionShape));
    }

    int shapeValue = static_cast<int>(*outShape);
    const bool found = sCollisionShapeType->IsEnumType()->GetEnumValue(shapeName, &shapeValue);
    *outShape = static_cast<moho::ECollisionShape>(shapeValue);
    return found;
  }

  [[nodiscard]] Wm3::Box3f BuildAxisAlignedCollisionBox(
    const Wm3::Vector3f& center,
    const Wm3::Vector3f& extents
  ) noexcept
  {
    Wm3::Box3f localBox{};
    localBox.Center[0] = center.x;
    localBox.Center[1] = center.y;
    localBox.Center[2] = center.z;

    localBox.Axis[0][0] = 1.0f;
    localBox.Axis[0][1] = 0.0f;
    localBox.Axis[0][2] = 0.0f;
    localBox.Axis[1][0] = 0.0f;
    localBox.Axis[1][1] = 1.0f;
    localBox.Axis[1][2] = 0.0f;
    localBox.Axis[2][0] = 0.0f;
    localBox.Axis[2][1] = 0.0f;
    localBox.Axis[2][2] = 1.0f;

    localBox.Extent[0] = extents.x;
    localBox.Extent[1] = extents.y;
    localBox.Extent[2] = extents.z;
    return localBox;
  }

  [[nodiscard]] Wm3::Vector3f BuildRandomProjectileOffset(
    moho::CRandomStream* const random,
    const moho::RProjectileBlueprint& blueprint
  ) noexcept
  {
    if (random == nullptr) {
      return Wm3::Vector3f{
        blueprint.Physics.PositionX,
        blueprint.Physics.PositionY,
        blueprint.Physics.PositionZ
      };
    }

    return SampleProjectileSpawnOffset(*random, blueprint);
  }

  /**
   * Inlined in `cfunc_EntityCreateProjectileAtBoneL` (0x0068A8EF-0x0068A96C).
   *
   * What it does:
   * Returns the bone's local +Z axis rotated by `orient_` (w,x,y,z), exactly
   * as the binary computes it in SSE single precision and WITHOUT
   * normalising it:
   *   x = (z*x + y*w) * 2
   *   y = (z*y - x*w) * 2
   *   z = 1 - (y*y + x*x) * 2
   */
  [[nodiscard]] Wm3::Vector3f ResolveBoneForwardVector(const moho::VTransform& transform) noexcept
  {
    const float qw = transform.orient_.w;
    const float qx = transform.orient_.x;
    const float qy = transform.orient_.y;
    const float qz = transform.orient_.z;
    return Wm3::Vector3f{
      ((qz * qx) + (qy * qw)) * 2.0f,
      ((qz * qy) - (qx * qw)) * 2.0f,
      1.0f - (((qy * qy) + (qx * qx)) * 2.0f),
    };
  }

  [[nodiscard]] moho::CAiTarget MakeDefaultProjectileTarget() noexcept
  {
    moho::CAiTarget target{};
    target.targetType = moho::EAiTargetType::AITARGET_None;
    target.targetEntity = moho::WeakPtr<moho::Entity>{};
    target.position = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    target.targetPoint = -1;
    target.targetIsMobile = false;
    return target;
  }

  /**
   * Address: 0x00692700 (FUN_00692700, func_ShakeCamera)
   *
   * What it does:
   * Appends one camera-shake request to the sim sync camera-shake queue.
   */
  void func_ShakeCamera(fa::vector<moho::SCamShakeParams>& shakeQueue, const moho::SCamShakeParams& request)
  {
    shakeQueue.push_back(request);
  }

  [[nodiscard]] gpg::RRef MakeVisibilityModeRef(moho::EVisibilityMode* const visibilityMode)
  {
    gpg::RRef enumRef{};
    if (visibilityMode == nullptr) {
      return enumRef;
    }

    static gpg::RType* sVisibilityModeType = nullptr;
    if (sVisibilityModeType == nullptr) {
      sVisibilityModeType = gpg::LookupRType(typeid(moho::EVisibilityMode));
    }

    enumRef.mObj = visibilityMode;
    enumRef.mType = sVisibilityModeType;
    return enumRef;
  }

  struct EntityVisibilityArgs
  {
    moho::Entity* entity;
    moho::EVisibilityMode mode;
  };

  [[nodiscard]] EntityVisibilityArgs DecodeEntityVisibilityArgs(
    LuaPlus::LuaState* const state,
    const char* const helpText
  )
  {
    EntityVisibilityArgs args{};
    args.entity = nullptr;
    args.mode = moho::VIZMODE_Always;

    lua_State* const rawState = state->m_state;
    moho::SCR_ExpectExactArgs(state, 2, helpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    args.entity = moho::SCR_FromLua_Entity(entityObject, state);

    gpg::RRef enumRef = MakeVisibilityModeRef(&args.mode);
    const LuaPlus::LuaStackObject modeArg(state, 2);
    const char* const modeName = lua_tostring(rawState, 2);
    if (modeName == nullptr) {
      modeArg.TypeError("string");
    }
    moho::SCR_GetEnum(state, modeName, enumRef);
    return args;
  }

  struct EntityDetachAllArgs
  {
    moho::Entity* entity;
    std::int32_t parentBoneIndex;
    bool skipBallistic;
  };

  [[nodiscard]] EntityDetachAllArgs DecodeEntityDetachAllArgs(LuaPlus::LuaState* const state)
  {
    EntityDetachAllArgs args{};
    args.entity = nullptr;
    args.parentBoneIndex = -1;
    args.skipBallistic = false;

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount < 2 || argumentCount > 3) {
      LuaPlus::LuaState::Error(state, "%s\n  expected between %d and %d args, but got %d", kEntityDetachAllHelpText, 2, 3, argumentCount);
    }

    lua_settop(rawState, 3);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    args.entity = moho::SCR_FromLua_Entity(entityObject, state);

    LuaPlus::LuaStackObject parentBoneArg(state, 2);
    args.parentBoneIndex = moho::ENTSCR_ResolveBoneIndex(args.entity, parentBoneArg, false);

    if (lua_type(rawState, 3) != LUA_TNIL) {
      args.skipBallistic = LuaPlus::LuaStackObject(state, 3).GetBoolean();
    }

    return args;
  }

  [[nodiscard]] LuaPlus::LuaObject GetBlueprintLuaObject(
    const moho::REntityBlueprint* const blueprint,
    LuaPlus::LuaState* const state
  )
  {
    if (blueprint == nullptr) {
      return {};
    }

    const auto* const baseBlueprint = reinterpret_cast<const moho::RBlueprint*>(blueprint);
    return baseBlueprint->GetLuaBlueprint(state);
  }

  [[nodiscard]] const char* ResolveEntityBlueprintName(const moho::Entity* entity) noexcept
  {
    if (!entity || !entity->BluePrint) {
      return "";
    }

    const moho::REntityBlueprint* const blueprint = entity->BluePrint;
    if (!blueprint->mBlueprintLabel.empty()) {
      return blueprint->mBlueprintLabel.c_str();
    }
    if (!blueprint->mBlueprintId.empty()) {
      return blueprint->mBlueprintId.c_str();
    }
    return "";
  }
}

namespace moho
{

  /**
   * Address: 0x0068A090 (FUN_0068A090, cfunc_EntityCreateProjectile)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityCreateProjectileL`.
   */
  int cfunc_EntityCreateProjectile(lua_State* const luaContext)
  {
    return cfunc_EntityCreateProjectileL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068A0B0 (FUN_0068A0B0, func_EntityCreateProjectile_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:CreateProjectile(proj_bp, [ox,oy,oz], [dx,dy,dz])`
   * Lua binder.
   */
  CScrLuaInitForm* func_EntityCreateProjectile_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityCreateProjectileName,
      &cfunc_EntityCreateProjectile,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityCreateProjectileHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068A110 (FUN_0068A110, cfunc_EntityCreateProjectileL)
   *
   * What it does:
   * Spawns one projectile from `(entity, projectileBlueprint[, offset][,dir])`
   * and returns the spawned projectile Lua object.
   */
  int cfunc_EntityCreateProjectileL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    lua_settop(rawState, 8);

    Sim* const sim = lua_getglobaluserdata(rawState);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    LuaPlus::LuaStackObject blueprintArg(state, 2);
    const char* projectileBlueprintName = lua_tostring(rawState, 2);
    if (!projectileBlueprintName) {
      blueprintArg.TypeError("string");
      projectileBlueprintName = "";
    }

    // STR_InitFilename + GetProjectileBlueprint, remembered per name (sim_BlueprintNameCache).
    RProjectileBlueprint* const projectileBlueprint =
      (sim && sim->mRules) ? RULE_FindProjectileBlueprintByName(sim->mRules, projectileBlueprintName) : nullptr;
    if (!projectileBlueprint) {
      LuaPlus::LuaState::Error(state, "CreateProjectile: Invalid blueprint %s", projectileBlueprintName);
    }

    Wm3::Vector3f launchOffset{};
    if (lua_type(rawState, 3) != LUA_TNIL) {
      LuaPlus::LuaStackObject offsetXArg(state, 3);
      if (lua_type(rawState, 3) != LUA_TNUMBER) {
        offsetXArg.TypeError("number");
      }
      launchOffset.x = static_cast<float>(lua_tonumber(rawState, 3));

      LuaPlus::LuaStackObject offsetYArg(state, 4);
      if (lua_type(rawState, 4) != LUA_TNUMBER) {
        offsetYArg.TypeError("number");
      }
      launchOffset.y = static_cast<float>(lua_tonumber(rawState, 4));

      LuaPlus::LuaStackObject offsetZArg(state, 5);
      if (lua_type(rawState, 5) != LUA_TNUMBER) {
        offsetZArg.TypeError("number");
      }
      launchOffset.z = static_cast<float>(lua_tonumber(rawState, 5));
    } else {
      launchOffset = BuildRandomProjectileOffset(sim ? sim->mRngState : nullptr, *projectileBlueprint);
    }

    Wm3::Vector3f launchDirection{};
    if (lua_type(rawState, 6) != LUA_TNIL) {
      LuaPlus::LuaStackObject dirXArg(state, 6);
      if (lua_type(rawState, 6) != LUA_TNUMBER) {
        dirXArg.TypeError("number");
      }
      launchDirection.x = static_cast<float>(lua_tonumber(rawState, 6));

      LuaPlus::LuaStackObject dirYArg(state, 7);
      if (lua_type(rawState, 7) != LUA_TNUMBER) {
        dirYArg.TypeError("number");
      }
      launchDirection.y = static_cast<float>(lua_tonumber(rawState, 7));

      LuaPlus::LuaStackObject dirZArg(state, 8);
      if (lua_type(rawState, 8) != LUA_TNUMBER) {
        dirZArg.TypeError("number");
      }
      launchDirection.z = static_cast<float>(lua_tonumber(rawState, 8));
    } else {
      (void)BuildRandomDirectionVector(sim->mRngState, &launchDirection, projectileBlueprint);
    }

    const VTransform sourceTransform = entity->GetBoneWorldTransform(-2);

    VTransform launchTransform{};
    launchTransform.orient_ = COORDS_Orient(launchDirection);
    launchTransform.pos_.x = sourceTransform.pos_.x + launchOffset.x;
    launchTransform.pos_.y = sourceTransform.pos_.y + launchOffset.y;
    launchTransform.pos_.z = sourceTransform.pos_.z + launchOffset.z;

    const CAiTarget target = MakeDefaultProjectileTarget();
    const fa::string damageTypeName("Normal");

    Projectile* const projectile = PROJ_Create(
      sim,
      projectileBlueprint,
      entity->ArmyRef,
      entity,
      launchTransform,
      0.0f,
      0.0f,
      damageTypeName,
      target,
      true
    );
    projectile->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x0068A670 (FUN_0068A670, cfunc_EntityCreateProjectileAtBone)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_EntityCreateProjectileAtBoneL`.
   */
  int cfunc_EntityCreateProjectileAtBone(lua_State* const luaContext)
  {
    return cfunc_EntityCreateProjectileAtBoneL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068A690 (FUN_0068A690, func_EntityCreateProjectileAtBone_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:CreateProjectileAtBone(projectile_blueprint, bone)`
   * Lua binder.
   */
  CScrLuaInitForm* func_EntityCreateProjectileAtBone_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityCreateProjectileAtBoneName,
      &cfunc_EntityCreateProjectileAtBone,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityCreateProjectileAtBoneHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068A6F0 (FUN_0068A6F0, cfunc_EntityCreateProjectileAtBoneL)
   *
   * What it does:
   * Spawns one projectile from a resolved entity bone, applies randomized
   * launch speed, and returns the spawned projectile Lua object.
   */
  int cfunc_EntityCreateProjectileAtBoneL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    moho::SCR_ExpectExactArgs(state, 3, kEntityCreateProjectileAtBoneHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    LuaPlus::LuaStackObject blueprintArg(state, 2);
    const char* projectileBlueprintName = lua_tostring(rawState, 2);
    if (!projectileBlueprintName) {
      blueprintArg.TypeError("string");
      projectileBlueprintName = "";
    }

    // STR_InitFilename + GetProjectileBlueprint, remembered per name (sim_BlueprintNameCache).
    RProjectileBlueprint* const projectileBlueprint =
      (entity && entity->SimulationRef && entity->SimulationRef->mRules)
        ? RULE_FindProjectileBlueprintByName(entity->SimulationRef->mRules, projectileBlueprintName)
        : nullptr;
    if (!projectileBlueprint) {
      const fa::string message = gpg::STR_Printf("CreateProjectileAtBone: Invalid blueprint %s", projectileBlueprintName);
      lua_pushstring(rawState, message.c_str());
      (void)lua_gettop(rawState);
      lua_error(rawState);
      return 0;
    }

    LuaPlus::LuaStackObject boneArg(state, 3);
    const int boneIndex = ENTSCR_ResolveBoneIndex(entity, boneArg, false);

    const VTransform launchTransform = entity->GetBoneWorldTransform(boneIndex);

    CRandomStream* const random = entity->SimulationRef->mRngState;
    Wm3::Vector3f launchDirection{};
    (void)BuildRandomDirectionVector(random, &launchDirection, projectileBlueprint);

    const Wm3::Vector3f zero = Wm3::Vector3f::Zero();
    if (launchDirection == zero) {
      launchDirection = ResolveBoneForwardVector(launchTransform);
    }

    const float launchSpeed = projectileBlueprint->GetRandomInitialSpeed(random);

    const CAiTarget target = MakeDefaultProjectileTarget();
    const fa::string damageTypeName("Normal");

    Projectile* const projectile = PROJ_Create(
      entity->SimulationRef,
      projectileBlueprint,
      entity->ArmyRef,
      entity,
      launchTransform,
      0.0f,
      0.0f,
      damageTypeName,
      target,
      true
    );

    projectile->mVelocity.x = launchDirection.x * launchSpeed;
    projectile->mVelocity.y = launchDirection.y * launchSpeed;
    projectile->mVelocity.z = launchDirection.z * launchSpeed;
    projectile->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x0068AAF0 (FUN_0068AAF0, cfunc_EntityShakeCamera)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityShakeCameraL`.
   */
  int cfunc_EntityShakeCamera(lua_State* const luaContext)
  {
    return cfunc_EntityShakeCameraL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068AB10 (FUN_0068AB10, func_EntityShakeCamera_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:ShakeCamera(radius, max, min, duration)` Lua binder.
   */
  CScrLuaInitForm* func_EntityShakeCamera_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityShakeCameraName,
      &cfunc_EntityShakeCamera,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityShakeCameraHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068AB70 (FUN_0068AB70, cfunc_EntityShakeCameraL)
   *
   * What it does:
   * Resolves `(entity, radius, max, min, duration)` and enqueues one camera
   * shake request centered on the entity world position.
   */
  int cfunc_EntityShakeCameraL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    moho::SCR_ExpectExactArgs(state, 5, kEntityShakeCameraHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    LuaPlus::LuaStackObject radiusArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      radiusArg.TypeError("number");
    }
    const float radius = static_cast<float>(lua_tonumber(rawState, 2));

    LuaPlus::LuaStackObject maxArg(state, 3);
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      maxArg.TypeError("number");
    }
    const float maxIntensity = static_cast<float>(lua_tonumber(rawState, 3));

    LuaPlus::LuaStackObject minArg(state, 4);
    if (lua_type(rawState, 4) != LUA_TNUMBER) {
      minArg.TypeError("number");
    }
    const float minIntensity = static_cast<float>(lua_tonumber(rawState, 4));

    LuaPlus::LuaStackObject durationArg(state, 5);
    if (lua_type(rawState, 5) != LUA_TNUMBER) {
      durationArg.TypeError("number");
    }
    const float durationSeconds = static_cast<float>(lua_tonumber(rawState, 5));

    Sim* const sim = lua_getglobaluserdata(rawState);
    if (sim != nullptr) {
      moho::SCamShakeParams request{};
      request.mCenter = entity->mVarDat.mCurTransform.pos_;
      request.mMaxRange = radius;
      request.mMagnitudeAtCenter = maxIntensity;
      request.mMagnitudeAtMaxRange = minIntensity;
      request.mDuration = durationSeconds;
      func_ShakeCamera(sim->mSyncCamShake, request);
    }

    return 0;
  }

  /**
   * Address: 0x0068B0D0 (FUN_0068B0D0, func_GetBlueprintSim_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua function `GetBlueprint(entity)`.
   */
  CScrLuaInitForm* func_GetBlueprintSim_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kGetBlueprintSimName,
      &cfunc_GetBlueprintSim,
      nullptr,
      "<global>",
      kGetBlueprintSimHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00692330 (FUN_00692330, cfunc__c_CreateEntityL)
   *
   * IDA signature:
   * int __usercall cfunc__c_CreateEntityL@<eax>(LuaPlus::LuaState *this@<ebx>);
   *
   * What it does:
   * Global Lua `_c_CreateEntity(spec)` factory. Requires exactly 2 args, resolves
   * the Sim from the Lua global userdata, and derives the owning army index from
   * the spec table's "Owner" (integer or game-object) / "Army" (one-based) fields,
   * defaulting to 255. Reserves a created-entity id `((army|0x500)<<20)`,
   * heap-constructs one Entity bound to arg 1's Lua object, and pushes the new
   * entity's Lua userdata.
   */
  int cfunc__c_CreateEntityL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    moho::SCR_ExpectExactArgs(state, 2, kCreateEntityHelpText);

    Sim* const sim = lua_getglobaluserdata(rawState);
    const LuaPlus::LuaStackObject specObject(state, 1);

    int armyIndex = 255;
    if (lua_type(rawState, 2) == LUA_TTABLE) {
      lua_pushstring(rawState, "Owner");
      lua_gettable(rawState, 2);
      const LuaPlus::LuaStackObject ownerObject(state, lua_gettop(rawState));

      lua_pushstring(rawState, "Army");
      lua_gettable(rawState, 2);
      const LuaPlus::LuaStackObject armyObject(state, lua_gettop(rawState));

      if (lua_type(rawState, ownerObject.m_stackIndex) != LUA_TNIL) {
        if (lua_type(rawState, ownerObject.m_stackIndex) == LUA_TNUMBER) {
          armyIndex = ownerObject.GetInteger();
        } else {
          const LuaPlus::LuaObject ownerLuaObject(ownerObject);
          Entity* const owner = SCR_FromLua_EntityOpt(ownerLuaObject);
          armyIndex = (owner != nullptr) ? owner->ArmyRef->mConstDat.mArmyIndex : 255;
        }
      } else if (lua_type(rawState, armyObject.m_stackIndex) != LUA_TNIL) {
        armyIndex = armyObject.GetInteger() - 1;
        if (armyIndex < 0) {
          LuaPlus::LuaState::Error(state, "Army < 0 passed in");
        }
      }
    }

    const LuaPlus::LuaObject entityLuaObject(specObject);
    const EntId reservedId = static_cast<EntId>(
      sim->mEntityDB->DoReserveId((static_cast<std::uint32_t>(armyIndex) | 0x500u) << moho::kEntityIdSourceShift)
    );
    Entity* const created = new Entity(entityLuaObject, sim, reservedId);

    created->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x006922B0 (FUN_006922B0, cfunc__c_CreateEntity)
   *
   * IDA signature:
   * int __cdecl cfunc__c_CreateEntity(lua_State *a1);
   *
   * What it does:
   * Unwraps the raw Lua callback context and forwards to `cfunc__c_CreateEntityL`.
   */
  int cfunc__c_CreateEntity(lua_State* const luaContext)
  {
    return cfunc__c_CreateEntityL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006922D0 (FUN_006922D0, func__c_CreateEntity_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua factory `_c_CreateEntity(spec)` binder.
   */
  CScrLuaInitForm* func__c_CreateEntity_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kCreateEntityName,
      &cfunc__c_CreateEntity,
      nullptr,
      "<global>",
      kCreateEntityHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068B0B0 (FUN_0068B0B0, cfunc_GetBlueprintSim)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_GetBlueprintSimL`.
   */
  int cfunc_GetBlueprintSim(lua_State* const luaContext)
  {
    return cfunc_GetBlueprintSimL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068B130 (FUN_0068B130, cfunc_GetBlueprintSimL)
   *
   * What it does:
   * Resolves one entity arg and pushes that entity blueprint Lua table.
   */
  int cfunc_GetBlueprintSimL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    moho::SCR_ExpectExactArgs(state, 1, kGetBlueprintSimHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);
    if (entity != nullptr && entity->BluePrint != nullptr) {
      LuaPlus::LuaObject blueprintObject = GetBlueprintLuaObject(entity->BluePrint, state);
      blueprintObject.PushStack(state);
    } else {
      lua_pushnil(rawState);
    }
    return 1;
  }

  /**
   * Address: 0x0068AD80 (FUN_0068AD80, func_EntityGetAIBrain_LuaFuncDef)
   *
   * What it does:
   * Publishes the `GetAIBrain(self)` Lua binder.
   */
  CScrLuaInitForm* func_EntityGetAIBrain_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityGetAIBrainName,
      &cfunc_EntityGetAIBrain,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityGetAIBrainHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068AD60 (FUN_0068AD60, cfunc_EntityGetAIBrain)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityGetAIBrainL`.
   */
  int cfunc_EntityGetAIBrain(lua_State* const luaContext)
  {
    return cfunc_EntityGetAIBrainL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068ADE0 (FUN_0068ADE0, cfunc_EntityGetAIBrainL)
   *
   * What it does:
   * Resolves one entity and returns owning army brain Lua object when present.
   */
  int cfunc_EntityGetAIBrainL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    moho::SCR_ExpectExactArgs(state, 1, kEntityGetAIBrainHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    CArmyImpl* army = nullptr;
    if (Unit* const unit = entity->IsUnit(); unit != nullptr) {
      army = unit->ArmyRef;
    } else if (ReconBlip* const reconBlip = entity->IsReconBlip(); reconBlip != nullptr) {
      if (Unit* const sourceUnit = reconBlip->GetSourceUnit(); sourceUnit != nullptr) {
        army = sourceUnit->ArmyRef;
      }
    }

    if (army == nullptr) {
      lua_pushnil(rawState);
      return 1;
    }

    CAiBrain* const brain = army->GetArmyBrain();
    if (brain == nullptr) {
      lua_pushnil(rawState);
      return 1;
    }

    brain->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x0068AF50 (FUN_0068AF50, func_EntityGetBlueprint_LuaFuncDef)
   *
   * What it does:
   * Publishes the `blueprint = Entity:GetBlueprint()` Lua binder.
   */
  CScrLuaInitForm* func_EntityGetBlueprint_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityGetBlueprintName,
      &cfunc_EntityGetBlueprint,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityGetBlueprintHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068AF30 (FUN_0068AF30, cfunc_EntityGetBlueprint)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityGetBlueprintL`.
   */
  int cfunc_EntityGetBlueprint(lua_State* const luaContext)
  {
    return cfunc_EntityGetBlueprintL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068AFB0 (FUN_0068AFB0, cfunc_EntityGetBlueprintL)
   *
   * What it does:
   * Resolves one optional entity and pushes its blueprint Lua table or nil.
   */
  int cfunc_EntityGetBlueprintL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    moho::SCR_ExpectExactArgs(state, 1, kEntityGetBlueprintHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLuaNoError_Entity(entityObject);
    if (entity != nullptr && entity->BluePrint != nullptr) {
      LuaPlus::LuaObject blueprintObject = GetBlueprintLuaObject(entity->BluePrint, state);
      blueprintObject.PushStack(state);
    } else {
      lua_pushnil(rawState);
    }
    return 1;
  }

  /**
   * Address: 0x0068B230 (FUN_0068B230, func_EntityGetArmy_LuaFuncDef)
   *
   * What it does:
   * Publishes `Entity:GetArmy()` Lua binder.
   */
  CScrLuaInitForm* func_EntityGetArmy_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityGetArmyName,
      &cfunc_EntityGetArmy,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityGetArmyHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068B210 (FUN_0068B210, cfunc_EntityGetArmy)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityGetArmyL`.
   */
  int cfunc_EntityGetArmy(lua_State* const luaContext)
  {
    return cfunc_EntityGetArmyL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068B290 (FUN_0068B290, cfunc_EntityGetArmyL)
   *
   * What it does:
   * Returns one-based army index for this entity, or `-1` when unowned.
   */
  int cfunc_EntityGetArmyL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    moho::SCR_ExpectExactArgs(state, 1, kEntityGetArmyHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    int armyIndex = -1;
    if (entity != nullptr && entity->ArmyRef != nullptr) {
      armyIndex = entity->ArmyRef->mConstDat.mArmyIndex;
    }
    if (armyIndex != -1) {
      ++armyIndex;
    }

    lua_pushnumber(rawState, static_cast<float>(armyIndex));
    return 1;
  }

  /**
   * Address: 0x0068B390 (FUN_0068B390, func_EntityGetBoneDirection_LuaFuncDef)
   *
   * What it does:
   * Publishes `Entity:GetBoneDirection(bone_name)` Lua binder.
   */
  CScrLuaInitForm* func_EntityGetBoneDirection_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityGetBoneDirectionName,
      &cfunc_EntityGetBoneDirection,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityGetBoneDirectionHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068B370 (FUN_0068B370, cfunc_EntityGetBoneDirection)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityGetBoneDirectionL`.
   */
  int cfunc_EntityGetBoneDirection(lua_State* const luaContext)
  {
    return cfunc_EntityGetBoneDirectionL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068B3F0 (FUN_0068B3F0, cfunc_EntityGetBoneDirectionL)
   *
   * What it does:
   * Resolves one bone transform and returns its forward direction vector.
   *
   * Ground truth (`FUN_0068B3F0.c`) rotates via `Moho::MultQuadVec(&n, &obj,
   * (Wm3::Quaternionf*)&v10)`, not the generic `Quaternion::Rotate` (upstream
   * WildMagic, `.w`-scalar `ToMat3()`) this replaces -- `boneTransform.
   * orient_` is always this engine's scalar-first convention.
   */
  int cfunc_EntityGetBoneDirectionL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    moho::SCR_ExpectExactArgs(state, 2, kEntityGetBoneDirectionHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    LuaPlus::LuaStackObject boneArg(state, 2);
    const int boneIndex = ENTSCR_ResolveBoneIndex(entity, boneArg, false);
    const VTransform boneTransform = entity->GetBoneWorldTransform(boneIndex);

    const Wm3::Vector3f forwardAxis{0.0f, 0.0f, 1.0f};
    Wm3::Vector3f direction{};
    MultQuadVec(&direction, &forwardAxis, &boneTransform.orient_);

    lua_pushnumber(rawState, direction.x);
    lua_pushnumber(rawState, direction.y);
    lua_pushnumber(rawState, direction.z);
    return 3;
  }

  /**
   * Address: 0x0068B590 (FUN_0068B590, func_EntityIsValidBone_LuaFuncDef)
   *
   * What it does:
   * Publishes `Entity:IsValidBone(nameOrIndex,allowNil=false)` Lua binder.
   */
  CScrLuaInitForm* func_EntityIsValidBone_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityIsValidBoneName,
      &cfunc_EntityIsValidBone,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityIsValidBoneHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068B570 (FUN_0068B570, cfunc_EntityIsValidBone)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityIsValidBoneL`.
   */
  int cfunc_EntityIsValidBone(lua_State* const luaContext)
  {
    return cfunc_EntityIsValidBoneL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068B5F0 (FUN_0068B5F0, cfunc_EntityIsValidBoneL)
   *
   * What it does:
   * Validates one bone identifier (name/index) and returns boolean validity.
   */
  int cfunc_EntityIsValidBoneL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount < 2 || argumentCount > 3) {
      LuaPlus::LuaState::Error(
        state, "%s\n  expected between %d and %d args, but got %d", kEntityIsValidBoneHelpText, 2, 3, argumentCount
      );
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    const LuaPlus::LuaStackObject boneIdentifier(state, 2);
    const bool allowNil = (argumentCount >= 3) ? LuaPlus::LuaStackObject(state, 3).GetBoolean() : false;

    bool isValid = false;
    if (lua_type(rawState, 2) == LUA_TNUMBER) {
      if (lua_type(rawState, 2) != LUA_TNUMBER) {
        boneIdentifier.TypeError("integer");
      }

      const int boneIndex = static_cast<int>(lua_tonumber(rawState, 2));
      const int minBoneIndex = allowNil ? -1 : 0;
      isValid = (boneIndex >= minBoneIndex) && (boneIndex < entity->GetBoneCount());
    } else if (lua_isstring(rawState, 2) != 0) {
      const char* const boneName = lua_tostring(rawState, 2);
      if (boneName == nullptr) {
        boneIdentifier.TypeError("string");
      }
      isValid = (entity->ResolveBoneIndex(boneName) != -1);
    } else if (allowNil) {
      if (lua_type(rawState, 2) != LUA_TNIL) {
        LuaPlus::LuaState::Error(state, "Invalid bone identifier; must be a string or integer");
      }
    } else {
      LuaPlus::LuaState::Error(state, "Invalid bone identifier; must be a string, integer, or nil");
    }

    lua_pushboolean(rawState, isValid ? 1 : 0);
    return 1;
  }

  /**
   * Address: 0x0068B810 (FUN_0068B810, func_EntityGetBoneCount_LuaFuncDef)
   *
   * What it does:
   * Publishes `Entity:GetBoneCount()` Lua binder.
   */
  CScrLuaInitForm* func_EntityGetBoneCount_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityGetBoneCountName,
      &cfunc_EntityGetBoneCount,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityGetBoneCountHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068B7F0 (FUN_0068B7F0, cfunc_EntityGetBoneCount)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityGetBoneCountL`.
   */
  int cfunc_EntityGetBoneCount(lua_State* const luaContext)
  {
    return cfunc_EntityGetBoneCountL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068B870 (FUN_0068B870, cfunc_EntityGetBoneCountL)
   *
   * What it does:
   * Resolves one entity arg and pushes skeleton bone count.
   */
  int cfunc_EntityGetBoneCountL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    moho::SCR_ExpectExactArgs(state, 1, kEntityGetBoneCountHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);
    lua_pushnumber(rawState, static_cast<float>(entity->GetBoneCount()));
    return 1;
  }

  /**
   * Address: 0x0068B960 (FUN_0068B960, func_EntityGetBoneName_LuaFuncDef)
   *
   * What it does:
   * Publishes `Entity:GetBoneName(i)` Lua binder.
   */
  CScrLuaInitForm* func_EntityGetBoneName_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityGetBoneNameName,
      &cfunc_EntityGetBoneName,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityGetBoneNameHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068B940 (FUN_0068B940, cfunc_EntityGetBoneName)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityGetBoneNameL`.
   */
  int cfunc_EntityGetBoneName(lua_State* const luaContext)
  {
    return cfunc_EntityGetBoneNameL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068B9C0 (FUN_0068B9C0, cfunc_EntityGetBoneNameL)
   *
   * What it does:
   * Resolves one bone index and pushes its name or nil.
   */
  int cfunc_EntityGetBoneNameL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    moho::SCR_ExpectExactArgs(state, 2, kEntityGetBoneNameHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    const LuaPlus::LuaStackObject boneIndexArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      boneIndexArg.TypeError("integer");
    }

    const int boneIndex = static_cast<int>(lua_tonumber(rawState, 2));
    const char* const boneName =
      (entity != nullptr && boneIndex >= 0) ? entity->GetBoneName(static_cast<std::uint32_t>(boneIndex)) : nullptr;
    if (boneName != nullptr) {
      lua_pushstring(rawState, boneName);
    } else {
      lua_pushnil(rawState);
    }
    return 1;
  }

  /**
   * Address: 0x0068BB00 (FUN_0068BB00, func_EntityRequestRefreshUI_LuaFuncDef)
   *
   * What it does:
   * Publishes `Entity:RequestRefreshUI()` Lua binder.
   */
  CScrLuaInitForm* func_EntityRequestRefreshUI_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityRequestRefreshUIName,
      &cfunc_EntityRequestRefreshUI,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityRequestRefreshUIHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068BAE0 (FUN_0068BAE0, cfunc_EntityRequestRefreshUI)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityRequestRefreshUIL`.
   */
  int cfunc_EntityRequestRefreshUI(lua_State* const luaContext)
  {
    return cfunc_EntityRequestRefreshUIL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068BB60 (FUN_0068BB60, cfunc_EntityRequestRefreshUIL)
   *
   * What it does:
   * Resolves one entity and marks it dirty for downstream UI refresh.
   */
  int cfunc_EntityRequestRefreshUIL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 1, kEntityRequestRefreshUIHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);
    entity->mVarDat.mRequestRefreshUI = 1;
    return 0;
  }

  /**
   * Address: 0x0068C030 (FUN_0068C030, func_EntityAttachBoneTo_LuaFuncDef)
   *
   * What it does:
   * Publishes `Entity:AttachBoneTo(selfbone, entity, bone)` Lua binder.
   */
  CScrLuaInitForm* func_EntityAttachBoneTo_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityAttachBoneToName,
      &cfunc_EntityAttachBoneTo,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityAttachBoneToHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068C010 (FUN_0068C010, cfunc_EntityAttachBoneTo)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityAttachBoneToL`.
   */
  int cfunc_EntityAttachBoneTo(lua_State* const luaContext)
  {
    return cfunc_EntityAttachBoneToL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068C2D0 (FUN_0068C2D0, func_EntitySetParentOffset_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:SetParentOffset(vector)` Lua binder.
   */
  CScrLuaInitForm* func_EntitySetParentOffset_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntitySetParentOffsetName,
      &cfunc_EntitySetParentOffset,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntitySetParentOffsetHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068C2B0 (FUN_0068C2B0, cfunc_EntitySetParentOffset)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntitySetParentOffsetL`.
   */
  int cfunc_EntitySetParentOffset(lua_State* const luaContext)
  {
    return cfunc_EntitySetParentOffsetL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068C330 (FUN_0068C330, cfunc_EntitySetParentOffsetL)
   *
   * What it does:
   * Rewrites relative attach position/orientation for an already-attached child.
   */
  int cfunc_EntitySetParentOffsetL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 2, kEntitySetParentOffsetHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);
    if (entity->mAttachInfo.GetAttachTargetEntity() == nullptr) {
      LuaPlus::LuaState::Error(state, "SetParentOffset: Entity has no parent.");
    }

    const LuaPlus::LuaObject parentOffsetObject(LuaPlus::LuaStackObject(state, 2));
    const Wm3::Vector3f parentOffset = SCR_FromLuaCopy<Wm3::Vector3f>(parentOffsetObject);

    VTransform offsetTransform;
    offsetTransform.pos_ = parentOffset;
    entity->mAttachInfo.mRelativeTransform = offsetTransform;
    return 0;
  }

  /**
   * Address: 0x0068C4C0 (FUN_0068C4C0, func_EntityDetachFrom_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:DetachFrom([skipBallistic])` Lua binder.
   */
  CScrLuaInitForm* func_EntityDetachFrom_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityDetachFromName,
      &cfunc_EntityDetachFrom,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityDetachFromHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068C4A0 (FUN_0068C4A0, cfunc_EntityDetachFrom)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityDetachFromL`.
   */
  int cfunc_EntityDetachFrom(lua_State* const luaContext)
  {
    return cfunc_EntityDetachFromL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068C520 (FUN_0068C520, cfunc_EntityDetachFromL)
   *
   * What it does:
   * Detaches this entity from its current parent and pushes success boolean.
   */
  int cfunc_EntityDetachFromL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount < 1 || argumentCount > 2) {
      LuaPlus::LuaState::Error(
        state, "%s\n  expected between %d and %d args, but got %d", kEntityDetachFromHelpText, 1, 2, argumentCount
      );
    }

    lua_settop(rawState, 2);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    bool skipBallistic = false;
    if (lua_type(rawState, 2) != LUA_TNIL) {
      skipBallistic = LuaPlus::LuaStackObject(state, 2).GetBoolean();
    }

    bool didDetach = false;
    Entity* const parentForProbe = entity->mAttachInfo.GetAttachTargetEntity();
    if (Entity* const parent = parentForProbe; parent != nullptr) {
      didDetach = entity->DetachFrom(parent, skipBallistic);
    }

    lua_pushboolean(rawState, didDetach ? 1 : 0);
    return 1;
  }

  /**
   * Address: 0x0068C8D0 (FUN_0068C8D0, func_EntityGetParent_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:GetParent()` Lua binder.
   */
  CScrLuaInitForm* func_EntityGetParent_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityGetParentName,
      &cfunc_EntityGetParent,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityGetParentHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068C8B0 (FUN_0068C8B0, cfunc_EntityGetParent)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityGetParentL`.
   */
  int cfunc_EntityGetParent(lua_State* const luaContext)
  {
    return cfunc_EntityGetParentL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068C930 (FUN_0068C930, cfunc_EntityGetParentL)
   *
   * What it does:
   * Pushes attached parent entity Lua object, or `self` when detached.
   */
  int cfunc_EntityGetParentL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 1, kEntityGetParentHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    if (Entity* const parent = entity->mAttachInfo.GetAttachTargetEntity(); parent != nullptr) {
      parent->mLuaObj.PushStack(state);
    } else {
      entity->mLuaObj.PushStack(state);
    }
    return 1;
  }

  /**
   * Address: 0x0068CA20 (FUN_0068CA20, func_EntityGetCollisionExtents_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:GetCollisionExtents()` Lua binder.
   */
  CScrLuaInitForm* func_EntityGetCollisionExtents_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityGetCollisionExtentsName,
      &cfunc_EntityGetCollisionExtents,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityGetCollisionExtentsHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068CA00 (FUN_0068CA00, cfunc_EntityGetCollisionExtents)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_EntityGetCollisionExtentsL`.
   */
  int cfunc_EntityGetCollisionExtents(lua_State* const luaContext)
  {
    return cfunc_EntityGetCollisionExtentsL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068CC50 (FUN_0068CC50, func_EntityPlaySound_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:PlaySound(params)` Lua binder.
   */
  CScrLuaInitForm* func_EntityPlaySound_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityPlaySoundName,
      &cfunc_EntityPlaySound,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityPlaySoundHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068CC30 (FUN_0068CC30, cfunc_EntityPlaySound)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityPlaySoundL`.
   */
  int cfunc_EntityPlaySound(lua_State* const luaContext)
  {
    return cfunc_EntityPlaySoundL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068CCB0 (FUN_0068CCB0, cfunc_EntityPlaySoundL)
   *
   * What it does:
   * Resolves `(entity, soundParams)` and queues one entity-bound sound request.
   */
  int cfunc_EntityPlaySoundL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    moho::SCR_ExpectExactArgs(state, 2, kEntityPlaySoundHelpText);

    Sim* const sim = lua_getglobaluserdata(rawState);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    const LuaPlus::LuaObject paramsObject(LuaPlus::LuaStackObject(state, 2));
    CSndParams* const params = *func_GetCObj_CSndParams(paramsObject);

    if (sim && sim->mSoundManager) {
      sim->mSoundManager->AddEntitySound(entity, params);
    }
    return 0;
  }

  /**
   * Address: 0x0068CDE0 (FUN_0068CDE0, func_EntitySetAmbientSound_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:SetAmbientSound(paramTableDetail,paramTableRumble)`
   * Lua binder.
   */
  CScrLuaInitForm* func_EntitySetAmbientSound_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntitySetAmbientSoundName,
      &cfunc_EntitySetAmbientSound,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntitySetAmbientSoundHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068CDC0 (FUN_0068CDC0, cfunc_EntitySetAmbientSound)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntitySetAmbientSoundL`.
   */
  int cfunc_EntitySetAmbientSound(lua_State* const luaContext)
  {
    return cfunc_EntitySetAmbientSoundL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068CE40 (FUN_0068CE40, cfunc_EntitySetAmbientSoundL)
   *
   * What it does:
   * Resolves optional detail/rumble sound params and updates entity ambient
   * sound lanes.
   */
  int cfunc_EntitySetAmbientSoundL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    moho::SCR_ExpectExactArgs(state, 3, kEntitySetAmbientSoundHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    CSndParams* ambientSound = nullptr;
    if (lua_type(rawState, 2) != LUA_TNIL) {
      const LuaPlus::LuaObject ambientObject(LuaPlus::LuaStackObject(state, 2));
      ambientSound = *func_GetCObj_CSndParams(ambientObject);
    }

    CSndParams* rumbleSound = nullptr;
    if (lua_type(rawState, 3) != LUA_TNIL) {
      const LuaPlus::LuaObject rumbleObject(LuaPlus::LuaStackObject(state, 3));
      rumbleSound = *func_GetCObj_CSndParams(rumbleObject);
    }

    entity->mVarDat.mAmbientSound = ambientSound;
    entity->mVarDat.mRumbleSound = rumbleSound;
    return 0;
  }

  /**
   * Address: 0x0068CF80 (FUN_0068CF80, func_EntityGetFractionComplete_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:GetFractionComplete()` Lua binder.
   */
  CScrLuaInitForm* func_EntityGetFractionComplete_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityGetFractionCompleteName,
      &cfunc_EntityGetFractionComplete,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityGetFractionCompleteHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068CF60 (FUN_0068CF60, cfunc_EntityGetFractionComplete)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityGetFractionCompleteL`.
   */
  int cfunc_EntityGetFractionComplete(lua_State* const luaContext)
  {
    return cfunc_EntityGetFractionCompleteL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068CFE0 (FUN_0068CFE0, cfunc_EntityGetFractionCompleteL)
   *
   * What it does:
   * Resolves `self` and returns current build fraction as one Lua number.
   */
  int cfunc_EntityGetFractionCompleteL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    moho::SCR_ExpectExactArgs(state, 1, kEntityGetFractionCompleteHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);
    lua_pushnumber(rawState, entity->mVarDat.mFractionComplete);
    return 1;
  }

  /**
   * Address: 0x0068D0C0 (FUN_0068D0C0, func_EntityAdjustHealth_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:AdjustHealth(instigator, delta)` Lua binder.
   */
  CScrLuaInitForm* func_EntityAdjustHealth_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityAdjustHealthName,
      &cfunc_EntityAdjustHealth,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityAdjustHealthHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068D0A0 (FUN_0068D0A0, cfunc_EntityAdjustHealth)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityAdjustHealthL`.
   */
  int cfunc_EntityAdjustHealth(lua_State* const luaContext)
  {
    return cfunc_EntityAdjustHealthL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068D120 (FUN_0068D120, cfunc_EntityAdjustHealthL)
   *
   * What it does:
   * Resolves `(entity, [instigator], delta)`, logs the delta, and applies one
   * `Entity::AdjustHealth` dispatch.
   */
  int cfunc_EntityAdjustHealthL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    moho::SCR_ExpectExactArgs(state, 3, kEntityAdjustHealthHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    Entity* instigator = nullptr;
    if (lua_type(rawState, 2) != LUA_TNIL) {
      const LuaPlus::LuaObject instigatorObject(LuaPlus::LuaStackObject(state, 2));
      instigator = SCR_FromLua_EntityOpt(instigatorObject);
    }

    LuaPlus::LuaStackObject deltaArg(state, 3);
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      deltaArg.TypeError("number");
    }
    const float delta = static_cast<float>(lua_tonumber(rawState, 3));

    entity->SimulationRef->Logf("Entity[0x%08x]:AdjustHealth(%.5f)\n", static_cast<std::uint32_t>(entity->id_), delta);
    entity->AdjustHealth(instigator, delta);
    return 0;
  }

  /**
   * Address: 0x0068D2D0 (FUN_0068D2D0, func_EntityGetHealth_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:GetHealth()` Lua binder.
   */
  CScrLuaInitForm* func_EntityGetHealth_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityGetHealthName,
      &cfunc_EntityGetHealth,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityGetHealthHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068D2B0 (FUN_0068D2B0, cfunc_EntityGetHealth)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityGetHealthL`.
   */
  int cfunc_EntityGetHealth(lua_State* const luaContext)
  {
    return cfunc_EntityGetHealthL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068D330 (FUN_0068D330, cfunc_EntityGetHealthL)
   *
   * What it does:
   * Resolves `self` and returns current entity health as one Lua number.
   */
  int cfunc_EntityGetHealthL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    moho::SCR_ExpectExactArgs(state, 1, kEntityGetHealthHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);
    lua_pushnumber(rawState, entity->mVarDat.mHealth);
    return 1;
  }

  /**
   * Address: 0x0068D410 (FUN_0068D410, func_EntityGetMaxHealth_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:GetMaxHealth()` Lua binder.
   */
  CScrLuaInitForm* func_EntityGetMaxHealth_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityGetMaxHealthName,
      &cfunc_EntityGetMaxHealth,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityGetMaxHealthHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068D3F0 (FUN_0068D3F0, cfunc_EntityGetMaxHealth)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityGetMaxHealthL`.
   */
  int cfunc_EntityGetMaxHealth(lua_State* const luaContext)
  {
    return cfunc_EntityGetMaxHealthL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068D470 (FUN_0068D470, cfunc_EntityGetMaxHealthL)
   *
   * What it does:
   * Resolves `self` and returns current entity max-health as one Lua number.
   */
  int cfunc_EntityGetMaxHealthL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    moho::SCR_ExpectExactArgs(state, 1, kEntityGetMaxHealthHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);
    lua_pushnumber(rawState, entity->mVarDat.mMaxHealth);
    return 1;
  }

  /**
   * Address: 0x0068D550 (FUN_0068D550, func_EntitySetHealth_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:SetHealth(instigator,health)` Lua binder.
   */
  CScrLuaInitForm* func_EntitySetHealth_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntitySetHealthName,
      &cfunc_EntitySetHealth,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntitySetHealthHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068D530 (FUN_0068D530, cfunc_EntitySetHealth)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntitySetHealthL`.
   */
  int cfunc_EntitySetHealth(lua_State* const luaContext)
  {
    return cfunc_EntitySetHealthL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068D5B0 (FUN_0068D5B0, cfunc_EntitySetHealthL)
   *
   * What it does:
   * Resolves `(entity, [instigator], health)` and applies delta through one
   * `Entity::AdjustHealth` call.
   */
  int cfunc_EntitySetHealthL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    moho::SCR_ExpectExactArgs(state, 3, kEntitySetHealthHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    Entity* instigator = nullptr;
    if (lua_type(rawState, 2) != LUA_TNIL) {
      const LuaPlus::LuaObject instigatorObject(LuaPlus::LuaStackObject(state, 2));
      instigator = SCR_FromLua_EntityOpt(instigatorObject);
    }

    LuaPlus::LuaStackObject healthArg(state, 3);
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      healthArg.TypeError("number");
    }
    const float targetHealth = static_cast<float>(lua_tonumber(rawState, 3));
    entity->AdjustHealth(instigator, targetHealth - entity->mVarDat.mHealth);
    return 0;
  }

  /**
   * Address: 0x0068D730 (FUN_0068D730, func_EntitySetMaxHealth_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:SetMaxHealth(maxhealth)` Lua binder.
   */
  CScrLuaInitForm* func_EntitySetMaxHealth_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntitySetMaxHealthName,
      &cfunc_EntitySetMaxHealth,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntitySetMaxHealthHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068D710 (FUN_0068D710, cfunc_EntitySetMaxHealth)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntitySetMaxHealthL`.
   */
  int cfunc_EntitySetMaxHealth(lua_State* const luaContext)
  {
    return cfunc_EntitySetMaxHealthL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068D790 (FUN_0068D790, cfunc_EntitySetMaxHealthL)
   *
   * What it does:
   * Resolves `(entity, maxhealth)` and writes one new max-health value.
   */
  int cfunc_EntitySetMaxHealthL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    moho::SCR_ExpectExactArgs(state, 2, kEntitySetMaxHealthHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    LuaPlus::LuaStackObject maxHealthArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      maxHealthArg.TypeError("number");
    }
    entity->mVarDat.mMaxHealth = static_cast<float>(lua_tonumber(rawState, 2));
    return 0;
  }

  /**
   * Address: 0x0068D8A0 (FUN_0068D8A0, func_EntitySetVizToFocusPlayer_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:SetVizToFocusPlayer(type)` Lua binder.
   */
  CScrLuaInitForm* func_EntitySetVizToFocusPlayer_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntitySetVizToFocusPlayerName,
      &cfunc_EntitySetVizToFocusPlayer,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntitySetVizToFocusPlayerHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068D880 (FUN_0068D880, cfunc_EntitySetVizToFocusPlayer)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_EntitySetVizToFocusPlayerL`.
   */
  int cfunc_EntitySetVizToFocusPlayer(lua_State* const luaContext)
  {
    return cfunc_EntitySetVizToFocusPlayerL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068D900 (FUN_0068D900, cfunc_EntitySetVizToFocusPlayerL)
   *
   * What it does:
   * Resolves `(entity, visibilityMode)` and applies
   * `Entity::SetVizToFocusPlayer`.
   */
  int cfunc_EntitySetVizToFocusPlayerL(LuaPlus::LuaState* const state)
  {
    const EntityVisibilityArgs args = DecodeEntityVisibilityArgs(state, kEntitySetVizToFocusPlayerHelpText);
    args.entity->SetVizToFocusPlayer(args.mode);
    return 0;
  }

  /**
   * Address: 0x0068DA20 (FUN_0068DA20, func_EntitySetVizToEnemies_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:SetVizToEnemies(type)` Lua binder.
   */
  CScrLuaInitForm* func_EntitySetVizToEnemies_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntitySetVizToEnemiesName,
      &cfunc_EntitySetVizToEnemies,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntitySetVizToEnemiesHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068DA00 (FUN_0068DA00, cfunc_EntitySetVizToEnemies)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_EntitySetVizToEnemiesL`.
   */
  int cfunc_EntitySetVizToEnemies(lua_State* const luaContext)
  {
    return cfunc_EntitySetVizToEnemiesL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068DA80 (FUN_0068DA80, cfunc_EntitySetVizToEnemiesL)
   *
   * What it does:
   * Resolves `(entity, visibilityMode)` and applies `Entity::SetVizToEnemies`.
   */
  int cfunc_EntitySetVizToEnemiesL(LuaPlus::LuaState* const state)
  {
    const EntityVisibilityArgs args = DecodeEntityVisibilityArgs(state, kEntitySetVizToEnemiesHelpText);
    args.entity->SetVizToEnemies(args.mode);
    return 0;
  }

  /**
   * Address: 0x0068DBA0 (FUN_0068DBA0, func_EntitySetVizToAllies_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:SetVizToAllies(type)` Lua binder.
   */
  CScrLuaInitForm* func_EntitySetVizToAllies_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntitySetVizToAlliesName,
      &cfunc_EntitySetVizToAllies,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntitySetVizToAlliesHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068DB80 (FUN_0068DB80, cfunc_EntitySetVizToAllies)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntitySetVizToAlliesL`.
   */
  int cfunc_EntitySetVizToAllies(lua_State* const luaContext)
  {
    return cfunc_EntitySetVizToAlliesL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068DC00 (FUN_0068DC00, cfunc_EntitySetVizToAlliesL)
   *
   * What it does:
   * Resolves `(entity, visibilityMode)` and applies `Entity::SetVizToAllies`.
   */
  int cfunc_EntitySetVizToAlliesL(LuaPlus::LuaState* const state)
  {
    const EntityVisibilityArgs args = DecodeEntityVisibilityArgs(state, kEntitySetVizToAlliesHelpText);
    args.entity->SetVizToAllies(args.mode);
    return 0;
  }

  /**
   * Address: 0x0068DD20 (FUN_0068DD20, func_EntitySetVizToNeutrals_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:SetVizToNeutrals(type)` Lua binder.
   */
  CScrLuaInitForm* func_EntitySetVizToNeutrals_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntitySetVizToNeutralsName,
      &cfunc_EntitySetVizToNeutrals,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntitySetVizToNeutralsHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068DD00 (FUN_0068DD00, cfunc_EntitySetVizToNeutrals)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_EntitySetVizToNeutralsL`.
   */
  int cfunc_EntitySetVizToNeutrals(lua_State* const luaContext)
  {
    return cfunc_EntitySetVizToNeutralsL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068DD80 (FUN_0068DD80, cfunc_EntitySetVizToNeutralsL)
   *
   * What it does:
   * Resolves `(entity, visibilityMode)` and applies `Entity::SetVizToNeutrals`.
   */
  int cfunc_EntitySetVizToNeutralsL(LuaPlus::LuaState* const state)
  {
    const EntityVisibilityArgs args = DecodeEntityVisibilityArgs(state, kEntitySetVizToNeutralsHelpText);
    args.entity->SetVizToNeutrals(args.mode);
    return 0;
  }

  /**
   * Address: 0x0068BC30 (FUN_0068BC30, func_EntityGetEntityId_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:GetEntityId()` Lua binder.
   */
  CScrLuaInitForm* func_EntityGetEntityId_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityGetEntityIdName,
      &cfunc_EntityGetEntityId,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityGetEntityIdHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068BC10 (FUN_0068BC10, cfunc_EntityGetEntityId)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityGetEntityIdL`.
   */
  int cfunc_EntityGetEntityId(lua_State* const luaContext)
  {
    return cfunc_EntityGetEntityIdL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068BC90 (FUN_0068BC90, cfunc_EntityGetEntityIdL)
   *
   * What it does:
   * Resolves `self` and pushes the numeric entity id as a Lua string.
   */
  int cfunc_EntityGetEntityIdL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    moho::SCR_ExpectExactArgs(state, 1, kEntityGetEntityIdHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);
    const fa::string entityIdText = gpg::STR_Printf("%d", static_cast<int>(entity->id_));
    lua_pushstring(rawState, entityIdText.c_str());
    return 1;
  }

  /**
   * Address: 0x0068C670 (FUN_0068C670, func_EntityDetachAll_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:DetachAll(bone,[skipBallistic])` Lua binder.
   */
  CScrLuaInitForm* func_EntityDetachAll_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityDetachAllName,
      &cfunc_EntityDetachAll,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityDetachAllHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068C650 (FUN_0068C650, cfunc_EntityDetachAll)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityDetachAllL`.
   */
  int cfunc_EntityDetachAll(lua_State* const luaContext)
  {
    return cfunc_EntityDetachAllL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068C6D0 (FUN_0068C6D0, cfunc_EntityDetachAllL)
   *
   * What it does:
   * Detaches every child attached on one parent-bone lane and returns `self`.
   */
  int cfunc_EntityDetachAllL(LuaPlus::LuaState* const state)
  {
    const EntityDetachAllArgs args = DecodeEntityDetachAllArgs(state);
    const fa::vector<Entity*> attachedSnapshot(args.entity->GetAttachedEntities());

    for (Entity* const attached : attachedSnapshot) {
      if (attached == nullptr || attached->mAttachInfo.mParentBoneIndex != args.parentBoneIndex) {
        continue;
      }
      (void)attached->DetachFrom(args.entity, args.skipBallistic);
    }

    lua_settop(state->m_state, 1);
    return 1;
  }

  /**
   * Address: 0x0068C090 (FUN_0068C090, cfunc_EntityAttachBoneToL)
   *
   * What it does:
   * Validates `Entity:AttachBoneTo(selfbone, entity, bone)`, resolves child and
   * parent entities with bone indices, and dispatches one typed `AttachTo`
   * operation.
   */
  int cfunc_EntityAttachBoneToL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 4, kEntityAttachBoneToHelpText);

    const LuaPlus::LuaObject childObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const childEntity = SCR_FromLua_Entity(childObject, state);

    LuaPlus::LuaStackObject childBoneArg(state, 2);
    const int childBoneIndex = ENTSCR_ResolveBoneIndex(childEntity, childBoneArg, true);

    const LuaPlus::LuaObject parentObject(LuaPlus::LuaStackObject(state, 3));
    Entity* const parentEntity = SCR_FromLua_Entity(parentObject, state);

    LuaPlus::LuaStackObject parentBoneArg(state, 4);
    const int parentBoneIndex = ENTSCR_ResolveBoneIndex(parentEntity, parentBoneArg, true);

    SEntAttachInfo attachInfo(parentEntity, childBoneIndex, parentBoneIndex, VTransform());
    const bool didAttach = childEntity->AttachTo(attachInfo);
    attachInfo.TargetWeakLink().UnlinkFromOwnerChain();

    if (!didAttach) {
      const char* const parentName = ResolveEntityBlueprintName(parentEntity);
      const char* const childName = ResolveEntityBlueprintName(childEntity);
      LuaPlus::LuaState::Error(state, kEntityAttachFailureError, childName, parentName, parentBoneIndex);
    }

    return 0;
  }

  /**
   * Address: 0x0068F1A0 (FUN_0068F1A0, func_EntitySetCollisionShape_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:SetCollisionShape(...)` Lua binder.
   */
  CScrLuaInitForm* func_EntitySetCollisionShape_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntitySetCollisionShapeName,
      &cfunc_EntitySetCollisionShape,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntitySetCollisionShapeHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068F180 (FUN_0068F180, cfunc_EntitySetCollisionShape)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntitySetCollisionShapeL`.
   */
  int cfunc_EntitySetCollisionShape(lua_State* const luaContext)
  {
    return cfunc_EntitySetCollisionShapeL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068F200 (FUN_0068F200, cfunc_EntitySetCollisionShapeL)
   *
   * What it does:
   * Applies collision-shape runtime override (`None`/`Box`/`Sphere`) from Lua args.
   */
  int cfunc_EntitySetCollisionShapeL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount < 2 || argumentCount > 8) {
      LuaPlus::LuaState::Error(state, "%s\n  expected between %d and %d args, but got %d", kEntitySetCollisionShapeHelpText, 2, 8, argumentCount);
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    LuaPlus::LuaStackObject shapeArg(state, 2);
    const char* const shapeName = lua_tostring(rawState, 2);
    if (shapeName == nullptr) {
      shapeArg.TypeError("string");
    }

    ECollisionShape shape = COLSHAPE_None;
    if (!TryParseCollisionShapeName(shapeName, &shape)) {
      LuaPlus::LuaState::Error(state, "Unknown shape type %s; should be None, Box, or Sphere", shapeName ? shapeName : "");
    }

    if (shape == COLSHAPE_None) {
      // 0x0068F4DC: `SetCollisionShape('None')` clears the primitive outright;
      // it is the only Lua entry point that does, and it is a different
      // function from `RevertCollisionShape` (0x0067AE70).
      entity->SetCollisionShapeNone();
      return 0;
    }

    if (shape == COLSHAPE_Box) {
      const float centerX = static_cast<float>(LuaPlus::LuaStackObject(state, 3).GetNumber());
      const float centerY = static_cast<float>(LuaPlus::LuaStackObject(state, 4).GetNumber());
      const float centerZ = static_cast<float>(LuaPlus::LuaStackObject(state, 5).GetNumber());
      const float extentX = static_cast<float>(LuaPlus::LuaStackObject(state, 6).GetNumber());
      const float extentY = static_cast<float>(LuaPlus::LuaStackObject(state, 7).GetNumber());
      const float extentZ = static_cast<float>(LuaPlus::LuaStackObject(state, 8).GetNumber());

      const Wm3::Vector3f center{centerX, centerY, centerZ};
      const Wm3::Vector3f extents{extentX, extentY, extentZ};
      entity->SetCollisionBoxShape(BuildAxisAlignedCollisionBox(center, extents));
      return 0;
    }

    const Wm3::Vec3f center{
      static_cast<float>(LuaPlus::LuaStackObject(state, 3).GetNumber()),
      static_cast<float>(LuaPlus::LuaStackObject(state, 4).GetNumber()),
      static_cast<float>(LuaPlus::LuaStackObject(state, 5).GetNumber()),
    };
    const float radius = static_cast<float>(LuaPlus::LuaStackObject(state, 6).GetNumber());
    entity->SetCollisionSphereShape(center, radius);
    return 0;
  }

  /**
   * Address: 0x0068F050 (FUN_0068F050, func_EntityReachedMaxShooters_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:ReachedMaxShooters()` Lua binder.
   */
  CScrLuaInitForm* func_EntityReachedMaxShooters_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityReachedMaxShootersName,
      &cfunc_EntityReachedMaxShooters,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityReachedMaxShootersHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068F030 (FUN_0068F030, cfunc_EntityReachedMaxShooters)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_EntityReachedMaxShootersL`.
   */
  int cfunc_EntityReachedMaxShooters(lua_State* const luaContext)
  {
    return cfunc_EntityReachedMaxShootersL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068F0B0 (FUN_0068F0B0, cfunc_EntityReachedMaxShootersL)
   *
   * What it does:
   * Returns whether the current shooter count has reached the blueprint cap.
   */
  int cfunc_EntityReachedMaxShootersL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    moho::SCR_ExpectExactArgs(state, 1, kEntityReachedMaxShootersHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    const int desiredShooterCap = entity->BluePrint->mDesiredShooterCap;
    const bool reached = static_cast<int>(entity->mShooters.Size()) >= desiredShooterCap;
    lua_pushboolean(rawState, reached ? 1 : 0);
    return 1;
  }

  /**
   * Address: 0x0068F520 (FUN_0068F520, func_EntityGetOrientation_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:GetOrientation()` Lua binder.
   */
  CScrLuaInitForm* func_EntityGetOrientation_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityGetOrientationName,
      &cfunc_EntityGetOrientation,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityGetOrientationHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068F500 (FUN_0068F500, cfunc_EntityGetOrientation)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityGetOrientationL`.
   */
  int cfunc_EntityGetOrientation(lua_State* const luaContext)
  {
    return cfunc_EntityGetOrientationL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068F580 (FUN_0068F580, cfunc_EntityGetOrientationL)
   *
   * What it does:
   * Pushes the entity world orientation quaternion as one Lua object.
   */
  int cfunc_EntityGetOrientationL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 1, kEntityGetOrientationHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    const Wm3::Quaternionf orientation = entity->mVarDat.mCurTransform.orient_;

    LuaPlus::LuaObject luaOrientation = SCR_ToLua<Wm3::Quaternion<float>>(state, orientation);
    luaOrientation.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x0068F880 (FUN_0068F880, func_EntityGetHeading_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:GetHeading()` Lua binder.
   */
  CScrLuaInitForm* func_EntityGetHeading_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityGetHeadingName,
      &cfunc_EntityGetHeading,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityGetHeadingHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0068F860 (FUN_0068F860, cfunc_EntityGetHeading)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityGetHeadingL`.
   */
  int cfunc_EntityGetHeading(lua_State* const luaContext)
  {
    return cfunc_EntityGetHeadingL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0068F8E0 (FUN_0068F8E0, cfunc_EntityGetHeadingL)
   *
   * What it does:
   * Computes one yaw heading from the entity world orientation quaternion.
   */
  int cfunc_EntityGetHeadingL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    moho::SCR_ExpectExactArgs(state, 1, kEntityGetHeadingHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    // 0x0068F968..0x0068F9D5: the forward axis' x/z components --
    // `(z*x + w*y) * 2` over `1 - (y*y + x*x) * 2` -- into a float `fpatan`
    // (0x004E9DF0) stored as float. The denominator summed z*z + y*y, which
    // agrees only for a level orientation; a structure on a slope reported a
    // heading off by ~1e-4 rad (replay 26935800 beat 618, UEF build effect).
    const Wm3::Quatf& orientation = entity->mVarDat.mCurTransform.orient_;
    const float numerator = ((orientation.z * orientation.x) + (orientation.w * orientation.y)) * 2.0f;
    const float denominator = 1.0f - (((orientation.y * orientation.y) + (orientation.x * orientation.x)) * 2.0f);
    const float heading = fa::atan2f(numerator, denominator);
    lua_pushnumber(rawState, heading);
    return 1;
  }

  /**
   * Address: 0x00690BB0 (FUN_00690BB0, func_EntityGetScale_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:GetScale()` Lua binder.
   */
  CScrLuaInitForm* func_EntityGetScale_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityGetScaleName,
      &cfunc_EntityGetScale,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityGetScaleHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00690B90 (FUN_00690B90, cfunc_EntityGetScale)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityGetScaleL`.
   */
  int cfunc_EntityGetScale(lua_State* const luaContext)
  {
    return cfunc_EntityGetScaleL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00690C10 (FUN_00690C10, cfunc_EntityGetScaleL)
   *
   * What it does:
   * Pushes the current draw scale as `(sx, sy, sz)`.
   */
  int cfunc_EntityGetScaleL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    moho::SCR_ExpectExactArgs(state, 1, kEntityGetScaleHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);
    Wm3::Vector3f drawScale{};
    (void)CopyEntityDrawScaleToVector(&drawScale, entity);
    lua_pushnumber(rawState, drawScale.x);
    lua_pushnumber(rawState, drawScale.y);
    lua_pushnumber(rawState, drawScale.z);
    return 3;
  }

  /**
   * Address: 0x00690100 (FUN_00690100, func_EntityAddLocalImpulse_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:AddLocalImpulse(...)` Lua binder.
   */
  CScrLuaInitForm* func_EntityAddLocalImpulse_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityAddLocalImpulseName,
      &cfunc_EntityAddLocalImpulse,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityAddLocalImpulseHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006900E0 (FUN_006900E0, cfunc_EntityAddLocalImpulse)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityAddLocalImpulseL`.
   */
  int cfunc_EntityAddLocalImpulse(lua_State* const luaContext)
  {
    return cfunc_EntityAddLocalImpulseL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00690160 (FUN_00690160, cfunc_EntityAddLocalImpulseL)
   *
   * What it does:
   * Forwards local impulse+point to entity physics body state when present.
   *
   * Ground truth (`FUN_00690160.c`) does not inline any local-to-world
   * conversion here at all -- it parses the 7 Lua args and calls
   * `Moho::SPhysBody::AddLocalImpulse(mPhysBody, &a2, &a3)` directly, the same
   * method `Entity::AddLocalImpulse` and `Unit::AddLocalImpulse` already
   * delegate to. The previous body reimplemented that conversion inline via
   * `Wm3::MultiplyQuaternionVector` (the quaternion-convention mismatch
   * shared with every other `mOrientation`/`orient_`-consuming site) and, on
   * top of that, never applied `mCollisionOffset` at all -- a second,
   * independent divergence from `SPhysBody::AddLocalImpulse`'s real behavior.
   */
  int cfunc_EntityAddLocalImpulseL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 7, kEntityAddLocalImpulseHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);
    // 0x006901F6..0x00690382 type-checks and reads all six numbers before the
    // 0x006903A1 body null test, so a bad argument errors even without a body.
    const Wm3::Vector3f localImpulse{
      ReadLuaNumberArgument(state, 2),
      ReadLuaNumberArgument(state, 3),
      ReadLuaNumberArgument(state, 4),
    };
    const Wm3::Vector3f localPoint{
      ReadLuaNumberArgument(state, 5),
      ReadLuaNumberArgument(state, 6),
      ReadLuaNumberArgument(state, 7),
    };

    moho::SPhysBody* const body = entity->mPhysBody;
    if (body != nullptr) {
      body->AddLocalImpulse(localImpulse, localPoint);
    }

    return 0;
  }

  /**
   * Address: 0x00690400 (FUN_00690400, func_EntityAddWorldImpulse_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:AddWorldImpulse(...)` Lua binder.
   */
  CScrLuaInitForm* func_EntityAddWorldImpulse_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityAddWorldImpulseName,
      &cfunc_EntityAddWorldImpulse,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityAddWorldImpulseHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006903E0 (FUN_006903E0, cfunc_EntityAddWorldImpulse)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityAddWorldImpulseL`.
   */
  int cfunc_EntityAddWorldImpulse(lua_State* const luaContext)
  {
    return cfunc_EntityAddWorldImpulseL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00690460 (FUN_00690460, cfunc_EntityAddWorldImpulseL)
   *
   * What it does:
   * Applies one world-space impulse at one world-space point to entity physics
   * body state when present.
   */
  int cfunc_EntityAddWorldImpulseL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 7, kEntityAddWorldImpulseHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);
    const Wm3::Vector3f impulse{
      ReadLuaNumberArgument(state, 2),
      ReadLuaNumberArgument(state, 3),
      ReadLuaNumberArgument(state, 4),
    };
    const Wm3::Vector3f worldPoint{
      ReadLuaNumberArgument(state, 5),
      ReadLuaNumberArgument(state, 6),
      ReadLuaNumberArgument(state, 7),
    };
    entity->AddWorldImpulse(impulse, worldPoint);

    return 0;
  }

  /**
   * Address: 0x006907B0 (FUN_006907B0, func_EntitySetMesh_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:SetMesh(meshBp, keepActor)` Lua binder.
   */
  CScrLuaInitForm* func_EntitySetMesh_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntitySetMeshName,
      &cfunc_EntitySetMesh,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntitySetMeshHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00690790 (FUN_00690790, cfunc_EntitySetMesh)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntitySetMeshL`.
   */
  int cfunc_EntitySetMesh(lua_State* const luaContext)
  {
    return cfunc_EntitySetMeshL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00690810 (FUN_00690810, cfunc_EntitySetMeshL)
   *
   * What it does:
   * Resolves mesh id + keep-actor flag and dispatches to `Entity::SetMesh`.
   */
  int cfunc_EntitySetMeshL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount < 2 || argumentCount > 3) {
      LuaPlus::LuaState::Error(state, "%s\n  expected between %d and %d args, but got %d", kEntitySetMeshHelpText, 2, 3, argumentCount);
    }

    lua_settop(rawState, 3);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    LuaPlus::LuaStackObject meshArg(state, 2);
    const char* meshName = lua_tostring(rawState, 2);
    if (meshName == nullptr) {
      meshArg.TypeError("string");
      meshName = "";
    }

    const fa::string meshResourcePath(meshName);
    const std::string meshPathStd = meshResourcePath.to_std();
    if (meshPathStd.find("<none>") == std::string::npos) {
      const bool keepActor = LuaPlus::LuaStackObject(state, 3).GetBoolean();
      const bool allowExplicitPlaceholder = !keepActor;

      fa::string normalizedPath;
      gpg::STR_CopyFilename(&normalizedPath, &meshResourcePath);

      RResId meshResourceId{};
      meshResourceId.name = normalizedPath;
      entity->SetMesh(meshResourceId, nullptr, allowExplicitPlaceholder);

      if (!meshResourcePath.empty() && !boost::HasSharedResource(entity->mVarDat.mScmResource)) {
        LuaPlus::LuaState::Error(state, "SetMesh failed with %s", meshResourcePath.raw_data_unsafe());
      }
    }

    return 0;
  }

  /**
   * Address: 0x00690D40 (FUN_00690D40, func_EntitySetScale_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:SetScale(s)` / `Entity:SetScale(sx,sy,sz)` Lua binder.
   */
  CScrLuaInitForm* func_EntitySetScale_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntitySetScaleName,
      &cfunc_EntitySetScale,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntitySetScaleHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00690D20 (FUN_00690D20, cfunc_EntitySetScale)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntitySetScaleL`.
   */
  int cfunc_EntitySetScale(lua_State* const luaContext)
  {
    return cfunc_EntitySetScaleL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00690DA0 (FUN_00690DA0, cfunc_EntitySetScaleL)
   *
   * What it does:
   * Applies non-uniform draw scale override and returns `self`.
   */
  int cfunc_EntitySetScaleL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2 && argumentCount != 4) {
      LuaPlus::LuaState::Error(
        state,
        "Wrong number of arguments to Entity:SetScale, expected 2 or 4 but got %d",
        argumentCount
      );
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    float scaleX = 0.0f;
    float scaleY = 0.0f;
    float scaleZ = 0.0f;
    if (argumentCount == 2) {
      LuaPlus::LuaStackObject uniformArg(state, 2);
      if (lua_type(rawState, 2) != LUA_TNUMBER) {
        uniformArg.TypeError("number");
      }
      const float uniform = static_cast<float>(lua_tonumber(rawState, 2));
      scaleX = uniform;
      scaleY = uniform;
      scaleZ = uniform;
    } else {
      LuaPlus::LuaStackObject scaleXArg(state, 2);
      if (lua_type(rawState, 2) != LUA_TNUMBER) {
        scaleXArg.TypeError("number");
      }
      scaleX = static_cast<float>(lua_tonumber(rawState, 2));

      LuaPlus::LuaStackObject scaleYArg(state, 3);
      if (lua_type(rawState, 3) != LUA_TNUMBER) {
        scaleYArg.TypeError("number");
      }
      scaleY = static_cast<float>(lua_tonumber(rawState, 3));

      LuaPlus::LuaStackObject scaleZArg(state, 4);
      if (lua_type(rawState, 4) != LUA_TNUMBER) {
        scaleZArg.TypeError("number");
      }
      scaleZ = static_cast<float>(lua_tonumber(rawState, 4));
    }

    const Wm3::Vector3f drawScale{scaleX, scaleY, scaleZ};
    (void)SetEntityDrawScaleAndRelinkCoordNode(entity, &drawScale);

    entity->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x00691050 (FUN_00691050, func_EntityAddManualScroller_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:AddManualScroller(scrollSpeed1, scrollSpeed2)` Lua
   * binder.
   */
  CScrLuaInitForm* func_EntityAddManualScroller_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityAddManualScrollerName,
      &cfunc_EntityAddManualScroller,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityAddManualScrollerHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00691030 (FUN_00691030, cfunc_EntityAddManualScroller)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_EntityAddManualScrollerL`.
   */
  int cfunc_EntityAddManualScroller(lua_State* const luaContext)
  {
    return cfunc_EntityAddManualScrollerL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006910B0 (FUN_006910B0, cfunc_EntityAddManualScrollerL)
   *
   * What it does:
   * Installs one manual texture-scroller definition on the entity and keeps
   * Lua stack shape compatible with original callback lane.
   */
  int cfunc_EntityAddManualScrollerL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 3, kEntityAddManualScrollerHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);
    SScroller definition;
    definition.mType = SCROLLTYPE_Manual;
    definition.mFloat04 = ReadLuaNumberArgument(state, 2);
    definition.mFloat08 = ReadLuaNumberArgument(state, 3);
    entity->ChangeScroller(definition);

    return 1;
  }

  /**
   * Address: 0x00691280 (FUN_00691280, func_EntityAddThreadScroller_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:AddThreadScroller(sideDist, scrollMult)` Lua binder.
   */
  CScrLuaInitForm* func_EntityAddThreadScroller_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityAddThreadScrollerName,
      &cfunc_EntityAddThreadScroller,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityAddThreadScrollerHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00691260 (FUN_00691260, cfunc_EntityAddThreadScroller)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_EntityAddThreadScrollerL`.
   */
  int cfunc_EntityAddThreadScroller(lua_State* const luaContext)
  {
    return cfunc_EntityAddThreadScrollerL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006912E0 (FUN_006912E0, cfunc_EntityAddThreadScrollerL)
   *
   * What it does:
   * Installs one threaded texture-scroller definition on the entity.
   */
  int cfunc_EntityAddThreadScrollerL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 3, kEntityAddThreadScrollerHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);
    SScroller definition;
    definition.mType = SCROLLTYPE_MotionDerived;
    definition.mFloat24 = ReadLuaNumberArgument(state, 2);
    definition.mFloat28 = ReadLuaNumberArgument(state, 3);
    entity->ChangeScroller(definition);

    return 1;
  }

  /**
   * Address: 0x006914A0 (FUN_006914A0, func_EntityAddPingPongScroller_LuaFuncDef)
   *
   * What it does:
   * Publishes the eight-parameter ping-pong scroller Lua binder.
   */
  CScrLuaInitForm* func_EntityAddPingPongScroller_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityAddPingPongScrollerName,
      &cfunc_EntityAddPingPongScroller,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityAddPingPongScrollerHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00691480 (FUN_00691480, cfunc_EntityAddPingPongScroller)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_EntityAddPingPongScrollerL`.
   */
  int cfunc_EntityAddPingPongScroller(lua_State* const luaContext)
  {
    return cfunc_EntityAddPingPongScrollerL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00691500 (FUN_00691500, cfunc_EntityAddPingPongScrollerL)
   *
   * What it does:
   * Installs one ping-pong texture-scroller definition on the entity.
   */
  int cfunc_EntityAddPingPongScrollerL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 9, kEntityAddPingPongScrollerHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);
    SScroller definition;
    definition.mType = SCROLLTYPE_PingPong;
    definition.mFloat04 = ReadLuaNumberArgument(state, 3);
    definition.mFloat08 = ReadLuaNumberArgument(state, 5);
    definition.mFloat0C = ReadLuaNumberArgument(state, 7);
    definition.mFloat10 = ReadLuaNumberArgument(state, 9);
    definition.mScroll1.x = ReadLuaNumberArgument(state, 2);
    definition.mScroll1.y = ReadLuaNumberArgument(state, 6);
    definition.mScroll2.x = ReadLuaNumberArgument(state, 4);
    definition.mScroll2.y = ReadLuaNumberArgument(state, 8);
    entity->ChangeScroller(definition);

    return 1;
  }

  /**
   * Address: 0x00691860 (FUN_00691860, func_EntityRemoveScroller_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:RemoveScroller()` Lua binder.
   */
  CScrLuaInitForm* func_EntityRemoveScroller_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityRemoveScrollerName,
      &cfunc_EntityRemoveScroller,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityRemoveScrollerHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00691840 (FUN_00691840, cfunc_EntityRemoveScroller)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityRemoveScrollerL`.
   */
  int cfunc_EntityRemoveScroller(lua_State* const luaContext)
  {
    return cfunc_EntityRemoveScrollerL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006918C0 (FUN_006918C0, cfunc_EntityRemoveScrollerL)
   *
   * What it does:
   * Replaces entity scroller state with one neutral/no-op definition.
   */
  int cfunc_EntityRemoveScrollerL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 1, kEntityRemoveScrollerHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);
    entity->ChangeScroller(SScroller{});
    return 1;
  }

  /**
   * Address: 0x00691A20 (FUN_00691A20, func_EntityDestroy_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:Destroy()` Lua binder.
   */
  CScrLuaInitForm* func_EntityDestroy_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityDestroyName,
      &cfunc_EntityDestroy,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityDestroyHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00691A00 (FUN_00691A00, cfunc_EntityDestroy)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityDestroyL`.
   */
  int cfunc_EntityDestroy(lua_State* const luaContext)
  {
    return cfunc_EntityDestroyL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00691A80 (FUN_00691A80, cfunc_EntityDestroyL)
   *
   * What it does:
   * Resolves optional entity arg, logs script-side destroy request, and queues
   * entity destruction when present.
   */
  int cfunc_EntityDestroyL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 1, kEntityDestroyHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    // 0x00691AF0: retail resolves through the raising `SCR_FromLua_EntityOpt`
    // (non-game-object / wrong type -> Lua error; destroyed -> nullptr).
    Entity* const entity = SCR_FromLua_EntityOpt(entityObject);
    if (entity != nullptr) {
      if (entity->SimulationRef != nullptr) {
        entity->SimulationRef->Logf("Entity:Destroy() called from script, id=0x%08x.\n", static_cast<unsigned int>(entity->id_));
      }
      entity->Destroy();
    }

    return 1;
  }

  /**
   * Address: 0x00691B60 (FUN_00691B60, func_EntityBeenDestroyed_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:BeenDestroyed()` Lua binder.
   */
  CScrLuaInitForm* func_EntityBeenDestroyed_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityBeenDestroyedName,
      &cfunc_EntityBeenDestroyed,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityBeenDestroyedHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00691B40 (FUN_00691B40, cfunc_EntityBeenDestroyed)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityBeenDestroyedL`.
   */
  int cfunc_EntityBeenDestroyed(lua_State* const luaContext)
  {
    return cfunc_EntityBeenDestroyedL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00691BC0 (FUN_00691BC0, cfunc_EntityBeenDestroyedL)
   *
   * What it does:
   * Returns `true` when the entity handle is nil/invalid or destroy-queued.
   */
  int cfunc_EntityBeenDestroyedL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    moho::SCR_ExpectExactArgs(state, 1, kEntityBeenDestroyedHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    // 0x00691C30: retail resolves through the raising `SCR_FromLua_EntityOpt`.
    Entity* const entity = SCR_FromLua_EntityOpt(entityObject);
    const bool beenDestroyed = (entity == nullptr) || (entity->DestroyQueuedFlag != 0u);
    lua_pushboolean(rawState, beenDestroyed ? 1 : 0);
    return 1;
  }

  /**
   * Address: 0x00691C90 (FUN_00691C90, cfunc_EntityKill)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityKillL`.
   */
  int cfunc_EntityKill(lua_State* const luaContext)
  {
    return cfunc_EntityKillL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00691CB0 (FUN_00691CB0, func_EntityKill_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:Kill(instigator, type, excessDamageRatio)` Lua
   * binder.
   */
  CScrLuaInitForm* func_EntityKill_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityKillName,
      &cfunc_EntityKill,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityKillHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00691D10 (FUN_00691D10, cfunc_EntityKillL)
   *
   * What it does:
   * Resolves `(self, [instigator], [killType], [excessDamageRatio])`,
   * dispatches `Entity::Kill`, and updates realtime kill stat lanes.
   */
  int cfunc_EntityKillL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount < 1 || argumentCount > 4) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected between %d and %d args, but got %d",
        kEntityKillHelpText,
        1,
        4,
        argumentCount
      );
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    Entity* instigator = nullptr;
    if (argumentCount > 1 && lua_type(rawState, 2) != LUA_TNIL) {
      const LuaPlus::LuaObject instigatorObject(LuaPlus::LuaStackObject(state, 2));
      instigator = SCR_FromLua_EntityOpt(instigatorObject);
    }

    const char* killType = "";
    if (argumentCount > 2) {
      LuaPlus::LuaStackObject killTypeArg(state, 3);
      killType = lua_tostring(rawState, 3);
      if (killType == nullptr) {
        killTypeArg.TypeError("string");
        killType = "";
      }
    }

    float excessDamageRatio = 0.0f;
    if (argumentCount > 3) {
      LuaPlus::LuaStackObject excessDamageRatioArg(state, 4);
      if (lua_type(rawState, 4) != LUA_TNUMBER) {
        excessDamageRatioArg.TypeError("number");
      }
      excessDamageRatio = static_cast<float>(lua_tonumber(rawState, 4));
    }

    if (entity != nullptr && entity->mVarDat.mIsDead != 0u) {
      return 0;
    }

    Entity* const instigatorWithArmy = (instigator != nullptr && instigator->ArmyRef != nullptr) ? instigator : nullptr;
    entity->Kill(instigatorWithArmy, killType, excessDamageRatio);

    Unit* const instigatorUnit = (instigator != nullptr) ? instigator->IsUnit() : nullptr;
    if (instigatorUnit != nullptr && (entity->IsUnit() != nullptr || entity->IsProjectile() != nullptr)) {
      bool shouldAwardKillCounter = true;
      if (entity->IsBeingBuilt()) {
        shouldAwardKillCounter = false;
      }
      if (entity->IsInCategory(kEntityKillBenignCategoryName)) {
        shouldAwardKillCounter = false;
      }
      if (entity->ArmyRef == instigator->ArmyRef) {
        shouldAwardKillCounter = false;
      }

      if (shouldAwardKillCounter) {
        const int defaultCounterValue = 0;
        StatItem* const killCounterStat = instigatorUnit->GetStat(kEntityKillCounterStatName, defaultCounterValue);
        AddStatCounter(killCounterStat, 1L);
      }

      UpdateEntityKillRealtimeStats(entity, instigator);
    }

    return 0;
  }

  /**
   * Address: 0x00690A10 (FUN_00690A10, func_EntitySetDrawScale_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:SetDrawScale(size)` Lua binder.
   */
  CScrLuaInitForm* func_EntitySetDrawScale_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntitySetDrawScaleName,
      &cfunc_EntitySetDrawScale,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntitySetDrawScaleHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006909F0 (FUN_006909F0, cfunc_EntitySetDrawScale)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntitySetDrawScaleL`.
   */
  int cfunc_EntitySetDrawScale(lua_State* const luaContext)
  {
    return cfunc_EntitySetDrawScaleL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00690A70 (FUN_00690A70, cfunc_EntitySetDrawScaleL)
   *
   * What it does:
   * Resolves `(entity, size)`, updates uniform draw scale, and requeues the
   * entity in the sim coord-update list.
   */
  int cfunc_EntitySetDrawScaleL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    moho::SCR_ExpectExactArgs(state, 2, kEntitySetDrawScaleHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    LuaPlus::LuaStackObject scaleArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      scaleArg.TypeError("number");
    }

    const float drawScaleScalar = static_cast<float>(lua_tonumber(rawState, 2));
    const Wm3::Vector3f drawScale{drawScaleScalar, drawScaleScalar, drawScaleScalar};
    (void)SetEntityDrawScaleAndRelinkCoordNode(entity, &drawScale);
    return 0;
  }

  /**
   * Address: 0x00695580 (FUN_00695580, cfunc_EntityFallDown)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityFallDownL`.
   */
  int cfunc_EntityFallDown(lua_State* const luaContext)
  {
    return cfunc_EntityFallDownL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00695600 (FUN_00695600, cfunc_EntityFallDownL)
   *
   * What it does:
   * Reads one entity argument, creates one `MotorFallDown` motor bound to the
   * Lua state, sets it on the entity, and returns the motor Lua object.
   */
  int cfunc_EntityFallDownL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    moho::SCR_ExpectExactArgs(state, 1, kEntityFallDownHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    MotorFallDown* const motor = new MotorFallDown(state);
    motor->mLuaObj.PushStack(state);

    fa::auto_ptr<Motor> motorOwnership(motor);
    entity->SetMotor(motorOwnership);
    return 1;
  }

  /**
   * Address: 0x006955A0 (FUN_006955A0, func_EntityFallDown_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:FallDown(dx,dy,dz,force)` Lua binder.
   */
  CScrLuaInitForm* func_EntityFallDown_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityFallDownName,
      &cfunc_EntityFallDown,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityFallDownHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006969E0 (FUN_006969E0, cfunc_EntitySinkAway)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntitySinkAwayL`.
   */
  int cfunc_EntitySinkAway(lua_State* const luaContext)
  {
    return cfunc_EntitySinkAwayL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00696A60 (FUN_00696A60, cfunc_EntitySinkAwayL)
   *
   * What it does:
   * Reads `(entity, sinkDeltaY)`, creates one `MotorSinkAway` motor bound to the
   * Lua state and sink velocity, sets it on the entity, and returns the motor
   * Lua object.
   */
  int cfunc_EntitySinkAwayL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    moho::SCR_ExpectExactArgs(state, 2, kEntitySinkAwayHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    LuaPlus::LuaStackObject sinkArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&sinkArg, "number");
    }
    const float sinkDeltaY = static_cast<float>(lua_tonumber(rawState, 2));

    MotorSinkAway* const motor = new MotorSinkAway(state, sinkDeltaY);
    motor->mLuaObj.PushStack(state);

    fa::auto_ptr<Motor> motorOwnership(motor);
    entity->SetMotor(motorOwnership);
    return 1;
  }

  /**
   * Address: 0x00696A00 (FUN_00696A00, func_EntitySinkAway_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:SinkAway(vy)` Lua binder.
   */
  CScrLuaInitForm* func_EntitySinkAway_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntitySinkAwayName,
      &cfunc_EntitySinkAway,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntitySinkAwayHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006FCA80 (FUN_006FCA80, cfunc_EntityPushOver)
   *
   * IDA signature:
   * int __cdecl cfunc_EntityPushOver(int a1);
   *
   * What it does:
   * Unwraps the Lua callback context and forwards to `cfunc_EntityPushOverL`.
   */
  int cfunc_EntityPushOver(lua_State* const luaContext)
  {
    return cfunc_EntityPushOverL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006FCB00 (FUN_006FCB00, cfunc_EntityPushOverL)
   *
   * IDA signature:
   * int __thiscall cfunc_EntityPushOverL(LuaPlus::LuaState *this);
   *
   * What it does:
   * Implements `Entity:PushOver(nx, ny, nz, depth)`. Reads the entity plus one
   * push direction (nx,ny,nz) scaled by depth, adds it to the entity's bone-tip
   * world position to form a target surface normal (clamped so the entity is
   * not pushed below its own Y), and — when that normal is non-degenerate —
   * tilts the entity's current orientation so its local up-axis aligns to the
   * pushed normal (shortest-arc pre-multiply), then commits the result as a
   * pending transform.
   *
   * Ground truth (`FUN_006FCB00.c`) re-derived term-by-term: the final
   * compose is `tran.orient = tiltDelta * o` (delta left/first, existing
   * orientation right/second) using `tiltDelta.w` as the delta's scalar lane
   * -- matching `BuildTiltShortestArcDelta`'s corrected labelling above, not
   * the generic `Wm3::Quaternionf::Multiply` (`.w`-scalar on both operands),
   * which produced a wrong composite once `tiltDelta` was mislabelled.
   */
  int cfunc_EntityPushOverL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    moho::SCR_ExpectExactArgs(state, 5, kEntityPushOverHelpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    LuaPlus::LuaStackObject nxArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&nxArg, "number");
    }
    const float pushNormalX = static_cast<float>(lua_tonumber(rawState, 2));

    LuaPlus::LuaStackObject nyArg(state, 3);
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&nyArg, "number");
    }
    const float pushNormalY = static_cast<float>(lua_tonumber(rawState, 3));

    LuaPlus::LuaStackObject nzArg(state, 4);
    if (lua_type(rawState, 4) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&nzArg, "number");
    }
    const float pushNormalZ = static_cast<float>(lua_tonumber(rawState, 4));

    LuaPlus::LuaStackObject depthArg(state, 5);
    if (lua_type(rawState, 5) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&depthArg, "number");
    }
    const float pushDepth = static_cast<float>(lua_tonumber(rawState, 5));

    VTransform tran = entity->GetTransformWm3();
    const VTransform boneTip = entity->GetBoneWorldTransform(-1);

    float targetY = (pushDepth * pushNormalY) + boneTip.pos_.y;
    const float targetZ = (pushDepth * pushNormalZ) + boneTip.pos_.z;
    if (tran.pos_.y > targetY) {
      targetY = tran.pos_.y;
    }

    Wm3::Vector3f pushedUp{
      ((pushDepth * pushNormalX) + boneTip.pos_.x) - tran.pos_.x,
      targetY - tran.pos_.y,
      targetZ - tran.pos_.z,
    };

    if (Wm3::Vector3f::Normalize(&pushedUp) != 0.0f) {
      const Wm3::Quaternionf o = tran.orient_;

      // Local up-axis from the current orientation, spelled with the raw
      // VTransform::orient_ union lanes exactly as the binary reads Entity's
      // Orientation Vector4f (the same construct as the recovered COORDS_Tilt).
      const Wm3::Vector3f currentUp{
        // Column 1 of the rotation matrix - the local up axis - in the
        // scalar-first form: (2(xy-wz), 1-2(x*x+z*z), 2(yz+wx)). Identical to
        // the sibling extraction further down this file and to
        // `QuaternionExtractYAxisColumn` (0x00694AF0). The previous spelling
        // carried a `w*w` diagonal term, which the binary never computes.
        ((o.y * o.x) - (o.w * o.z)) * 2.0f,
        1.0f - (((o.z * o.z) + (o.x * o.x)) * 2.0f),
        ((o.z * o.y) + (o.w * o.x)) * 2.0f,
      };

      Wm3::Quaternionf tiltDelta{};
      BuildTiltShortestArcDelta(pushedUp, &tiltDelta, currentUp);

      // 0x006FCE1D-0x006FCF08: `tiltDelta * o`, scalar-first, inlined with
      // its own add grouping -- the `delta.w` term joins the first sum and
      // the `o.w` term comes third, which is NOT the grouping `MultiplyQuat`
      // carries for 0x0054BC00, so the lanes are spelled here as emitted.
      const Wm3::Quaternionf& d = tiltDelta;
      tran.orient_.w = (((d.w * o.w) - (d.x * o.x)) - (d.y * o.y)) - (d.z * o.z);
      tran.orient_.x = (((d.y * o.z) + (d.w * o.x)) + (d.x * o.w)) - (d.z * o.y);
      tran.orient_.y = (((d.z * o.x) + (d.w * o.y)) + (d.y * o.w)) - (d.x * o.z);
      tran.orient_.z = (((d.x * o.y) + (d.w * o.z)) + (d.z * o.w)) - (d.y * o.x);
      NormalizeQuatInPlace(&tran.orient_);
      entity->SetPendingTransform(tran, 1.0f);
    }
    return 0;
  }

  /**
   * Address: 0x006FCAA0 (FUN_006FCAA0, func_EntityPushOver_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:PushOver(nx, ny, nz, depth)` Lua binder form.
   */
  CScrLuaInitForm* func_EntityPushOver_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      moho::SCR_SimLuaInitSet(),
      kEntityPushOverName,
      &cfunc_EntityPushOver,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityLuaClassName,
      kEntityPushOverHelpText
    );
    return &binder;
  }
}

