#include "Entity.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/audio/CSimSoundManager.h"
#include "moho/audio/CSndParams.h"
#include "moho/ai/CAiBrain.h"
#include "moho/ai/CAiTarget.h"
#include "moho/entity/EntityCategoryLookupResolver.h"
#include "moho/entity/EntityCollisionUpdater.h"
#include "moho/entity/EntityDb.h"
#include "moho/entity/EntityMotor.h"
#include "moho/entity/MotorFallDown.h"
#include "moho/entity/EntityTransformPayload.h"
#include "moho/entity/EVisibilityModeTypeInfo.h"
#include "moho/entity/intel/CIntel.h"
#include "moho/projectile/Projectile.h"
#include "moho/sim/ReconBlip.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/SCR_FromLua.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/resource/RResId.h"
#include "moho/resource/RScmResource.h"
#include "moho/resource/blueprints/RBlueprint.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "moho/animation/CAniSkel.h"
#include "moho/render/camera/VTransform.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "moho/script/CScriptEvent.h"
#include "moho/misc/StatItem.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CArmyStats.h"
#include "moho/sim/CRandomStream.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SPhysBody.h"
#include "moho/sim/STIMap.h"
#include "moho/unit/core/Unit.h"

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };

  class SerSaveConstructArgsResult
  {
  public:
    void SetUnowned(unsigned int value);
  };
} // namespace gpg

namespace
{
  using moho::CArmyImpl;
  using moho::CArmyStatItem;
  using moho::CArmyStats;
  using moho::Entity;
  using moho::Sim;
  using moho::StatItem;

  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
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
  constexpr const char* kMotorFallDownWhackName = "Whack";
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
  constexpr const char* kMotorFallDownWhackHelpText = "MotorFallDown:Whack(nx,ny,nz,f,dobreak)";
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

  struct EntityProjectileVelocityRuntimeView
  {
    std::uint8_t mUnknown0000[0x280];
    Wm3::Vector3f mVelocity; // +0x280
  };

  static_assert(
    offsetof(EntityProjectileVelocityRuntimeView, mVelocity) == 0x280,
    "EntityProjectileVelocityRuntimeView::mVelocity offset must be 0x280"
  );

  [[nodiscard]] Wm3::Vector3f& AccessProjectileVelocity(moho::Projectile& projectile) noexcept
  {
    return reinterpret_cast<EntityProjectileVelocityRuntimeView*>(&projectile)->mVelocity;
  }

  enum class TextureScrollerMode : std::int32_t
  {
    None = 0,
    PingPong = 1,
    Manual = 2,
    Thread = 3,
  };

  struct TextureScrollerDefinition
  {
    std::int32_t mType;
    float mFloat04;
    float mFloat08;
    float mFloat0C;
    float mFloat10;
    Wm3::Vector2f mScroll1;
    Wm3::Vector2f mScroll2;
    float mFloat24;
    float mFloat28;
  };

  static_assert(sizeof(TextureScrollerDefinition) == 0x2C, "TextureScrollerDefinition size must be 0x2C");

  struct TextureScrollerRuntimeView
  {
    moho::Entity* mOwner; // +0x00
    TextureScrollerDefinition mScroller; // +0x04
    std::uint8_t mDir[2]; // +0x30
    std::uint8_t mPad32[2];
    std::int32_t mSpeed[2]; // +0x34
  };

  static_assert(sizeof(TextureScrollerRuntimeView) == 0x3C, "TextureScrollerRuntimeView size must be 0x3C");
  static_assert(offsetof(TextureScrollerRuntimeView, mScroller) == 0x04, "TextureScrollerRuntimeView::mScroller offset must be 0x04");
  static_assert(offsetof(TextureScrollerRuntimeView, mDir) == 0x30, "TextureScrollerRuntimeView::mDir offset must be 0x30");
  static_assert(offsetof(TextureScrollerRuntimeView, mSpeed) == 0x34, "TextureScrollerRuntimeView::mSpeed offset must be 0x34");

  struct EntityLuaBindingRuntimeView
  {
    std::uint8_t mUnknown0000[0x1F0];
    TextureScrollerRuntimeView* mTextureScroller; // +0x1F0
    moho::SPhysBody* mPhysBody; // +0x1F4
  };

  static_assert(
    offsetof(EntityLuaBindingRuntimeView, mTextureScroller) == 0x1F0,
    "EntityLuaBindingRuntimeView::mTextureScroller offset must be 0x1F0"
  );
  static_assert(
    offsetof(EntityLuaBindingRuntimeView, mPhysBody) == 0x1F4,
    "EntityLuaBindingRuntimeView::mPhysBody offset must be 0x1F4"
  );

  [[nodiscard]] EntityLuaBindingRuntimeView& AccessEntityLuaBindingRuntime(moho::Entity& entity) noexcept
  {
    return *reinterpret_cast<EntityLuaBindingRuntimeView*>(&entity);
  }

  [[nodiscard]] moho::SPhysBody*& AccessEntityPhysBody(moho::Entity& entity) noexcept
  {
    return AccessEntityLuaBindingRuntime(entity).mPhysBody;
  }

  [[nodiscard]] TextureScrollerRuntimeView*& AccessEntityTextureScrollerSlot(moho::Entity& entity) noexcept
  {
    return AccessEntityLuaBindingRuntime(entity).mTextureScroller;
  }

  void InitializeTextureScrollerRuntime(TextureScrollerRuntimeView& scroller, moho::Entity* const owner) noexcept
  {
    scroller.mOwner = owner;
    scroller.mScroller.mType = static_cast<std::int32_t>(TextureScrollerMode::None);
    scroller.mScroller.mFloat04 = 0.0f;
    scroller.mScroller.mFloat08 = 0.0f;
    scroller.mScroller.mFloat0C = 0.0f;
    scroller.mScroller.mFloat10 = 0.0f;
    scroller.mScroller.mScroll1.x = 0.0f;
    scroller.mScroller.mScroll1.y = 0.0f;
    scroller.mScroller.mScroll2.x = 0.0f;
    scroller.mScroller.mScroll2.y = 0.0f;
    scroller.mScroller.mFloat24 = 1.0f;
    scroller.mScroller.mFloat28 = 1.0f;
    scroller.mDir[0] = 0u;
    scroller.mDir[1] = 0u;
    scroller.mSpeed[0] = 0;
    scroller.mSpeed[1] = 0;
  }

  void ApplyTextureScrollerDefinition(
    TextureScrollerRuntimeView& scroller,
    const TextureScrollerDefinition& definition
  ) noexcept
  {
    scroller.mScroller = definition;

    if (definition.mType == static_cast<std::int32_t>(TextureScrollerMode::Thread)) {
      scroller.mDir[0] = 0u;
      scroller.mDir[1] = 0u;
      scroller.mSpeed[0] = 0;
      scroller.mSpeed[1] = 0;
    }
  }

  [[nodiscard]] TextureScrollerRuntimeView* EnsureEntityTextureScroller(moho::Entity& entity)
  {
    TextureScrollerRuntimeView*& scroller = AccessEntityTextureScrollerSlot(entity);
    if (scroller == nullptr) {
      scroller = new TextureScrollerRuntimeView{};
      InitializeTextureScrollerRuntime(*scroller, &entity);
    }
    return scroller;
  }

  [[nodiscard]] float ReadLuaNumberArgument(LuaPlus::LuaState* const state, const int stackIndex)
  {
    LuaPlus::LuaStackObject arg(state, stackIndex);
    if (lua_type(state->m_state, stackIndex) != LUA_TNUMBER) {
      arg.TypeError("number");
    }
    return static_cast<float>(lua_tonumber(state->m_state, stackIndex));
  }

  void ApplyWorldImpulseToBody(
    moho::SPhysBody& body,
    const Wm3::Vector3f& impulse,
    const Wm3::Vector3f& applicationPoint
  ) noexcept
  {
    const float mass = body.mMass;
    float impulseXOverMass = std::numeric_limits<float>::max();
    float impulseYOverMass = std::numeric_limits<float>::max();
    float impulseZOverMass = std::numeric_limits<float>::max();
    if (mass != 0.0f) {
      const float invMass = 1.0f / mass;
      impulseXOverMass = impulse.x * invMass;
      impulseYOverMass = impulse.y * invMass;
      impulseZOverMass = impulse.z * invMass;
    }

    body.mVelocity.x += impulseXOverMass;
    body.mVelocity.y += impulseYOverMass;
    body.mVelocity.z += impulseZOverMass;

    const float deltaX = applicationPoint.x - body.mPos.x;
    const float deltaY = applicationPoint.y - body.mPos.y;
    const float deltaZ = applicationPoint.z - body.mPos.z;

    body.mWorldImpulse.x += (deltaY * impulse.z) - (deltaZ * impulse.y);
    body.mWorldImpulse.y += (deltaZ * impulse.x) - (deltaX * impulse.z);
    body.mWorldImpulse.z += (deltaX * impulse.y) - (deltaY * impulse.x);
  }

  [[nodiscard]] std::string BuildInstanceCounterStatPath(const char* const rawTypeName)
  {
    std::string path("Instance Counts_");
    if (!rawTypeName) {
      return path;
    }

    for (const char* it = rawTypeName; *it != '\0'; ++it) {
      if (*it != '_') {
        path.push_back(*it);
      }
    }

    return path;
  }

  void AddStatCounter(StatItem* const statItem, const long delta) noexcept
  {
    if (!statItem) {
      return;
    }
#if defined(_WIN32)
    InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&statItem->mPrimaryValueBits), delta);
#else
    statItem->mPrimaryValueBits += static_cast<std::int32_t>(delta);
#endif
  }

  [[nodiscard]] int ResolveEntityArmyIndexOneBased(const Entity* const entity) noexcept
  {
    if (entity == nullptr || entity->ArmyRef == nullptr) {
      return -1;
    }
    return entity->ArmyRef->ArmyId + 1;
  }

  [[nodiscard]] const char* ResolveEntityBlueprintId(const Entity* const entity) noexcept
  {
    if (entity == nullptr || entity->BluePrint == nullptr || entity->BluePrint->mBlueprintId.empty()) {
      return "";
    }
    return entity->BluePrint->mBlueprintId.c_str();
  }

  void AccumulateArmyRealtimeStat(CArmyImpl* const army, const msvc8::string& statPath, const long delta)
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

    if (victim->ArmyRef != nullptr) {
      msvc8::string statPath = msvc8::string(kEntityRealtimeStatsPrefix) + victim->GetUniqueName();
      statPath += gpg::STR_Printf("_KilledBy_Army%d_", ResolveEntityArmyIndexOneBased(instigator));
      statPath += ResolveEntityBlueprintId(instigator);
      AccumulateArmyRealtimeStat(victim->ArmyRef, statPath, 1L);
    }

    if (instigator->ArmyRef != nullptr) {
      msvc8::string statPath = msvc8::string(kEntityRealtimeStatsPrefix) + instigator->GetUniqueName();
      statPath += gpg::STR_Printf("_Kills_Army%d_", ResolveEntityArmyIndexOneBased(victim));
      statPath += ResolveEntityBlueprintId(victim);
      AccumulateArmyRealtimeStat(instigator->ArmyRef, statPath, 1L);
    }
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& SimLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("sim"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("sim");
    return fallbackSet;
  }

  [[nodiscard]] float SampleSymmetricRange(moho::CRandomStream* const random, const float range) noexcept
  {
    if (random == nullptr || range == 0.0f) {
      return 0.0f;
    }

    const float unit = moho::CMersenneTwister::ToUnitFloat(random->twister.NextUInt32());
    return (-range) + (2.0f * range * unit);
  }

  [[nodiscard]] float VectorLength(const Wm3::Vector3f& value) noexcept
  {
    return std::sqrt((value.x * value.x) + (value.y * value.y) + (value.z * value.z));
  }

  void NormalizeInPlace(Wm3::Vector3f& value) noexcept
  {
    const float length = VectorLength(value);
    if (length <= 1.0e-6f) {
      value = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
      return;
    }

    const float invLength = 1.0f / length;
    value.x *= invLength;
    value.y *= invLength;
    value.z *= invLength;
  }

  void SetVectorLengthIfNonZero(Wm3::Vector3f& value, const float targetLength) noexcept
  {
    NormalizeInPlace(value);
    value.x *= targetLength;
    value.y *= targetLength;
    value.z *= targetLength;
  }

  [[nodiscard]] bool TryParseCollisionShapeName(
    const char* const shapeName,
    moho::ECollisionShape* const outShape
  ) noexcept
  {
    if (shapeName == nullptr || outShape == nullptr) {
      return false;
    }

    if (std::strcmp(shapeName, "None") == 0) {
      *outShape = moho::COLSHAPE_None;
      return true;
    }
    if (std::strcmp(shapeName, "Box") == 0) {
      *outShape = moho::COLSHAPE_Box;
      return true;
    }
    if (std::strcmp(shapeName, "Sphere") == 0) {
      *outShape = moho::COLSHAPE_Sphere;
      return true;
    }
    return false;
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
    Wm3::Vector3f offset{};
    offset.x = blueprint.Physics.PositionX + SampleSymmetricRange(random, blueprint.Physics.PositionXRange);
    offset.y = blueprint.Physics.PositionY + SampleSymmetricRange(random, blueprint.Physics.PositionYRange);
    offset.z = blueprint.Physics.PositionZ + SampleSymmetricRange(random, blueprint.Physics.PositionZRange);
    return offset;
  }

  [[nodiscard]] Wm3::Vector3f BuildRandomProjectileDirection(
    moho::CRandomStream* const random,
    const moho::RProjectileBlueprint& blueprint
  ) noexcept
  {
    Wm3::Vector3f direction{};
    direction.x = blueprint.Physics.DirectionX + SampleSymmetricRange(random, blueprint.Physics.DirectionXRange);
    direction.y = blueprint.Physics.DirectionY + SampleSymmetricRange(random, blueprint.Physics.DirectionYRange);
    direction.z = blueprint.Physics.DirectionZ + SampleSymmetricRange(random, blueprint.Physics.DirectionZRange);
    NormalizeInPlace(direction);
    return direction;
  }

  [[nodiscard]] Wm3::Vector3f ResolveBoneForwardVector(const moho::VTransform& transform) noexcept
  {
    const Wm3::Vector3f forwardAxis{0.0f, 0.0f, 1.0f};
    Wm3::Vector3f out = transform.orient_.Rotate(forwardAxis);
    NormalizeInPlace(out);
    return out;
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

  struct SyncCameraShakeRequest
  {
    float centerX;
    float centerY;
    float centerZ;
    float radius;
    float maxIntensity;
    float minIntensity;
    float durationSeconds;
  };
  static_assert(sizeof(SyncCameraShakeRequest) == 0x1C, "SyncCameraShakeRequest size must be 0x1C");

  struct SimCameraShakeQueueView
  {
    std::uint8_t pad_0000[0x09C8];
    msvc8::vector<SyncCameraShakeRequest> mSyncCamShake;
  };
  static_assert(
    offsetof(SimCameraShakeQueueView, mSyncCamShake) == 0x09C8,
    "SimCameraShakeQueueView::mSyncCamShake offset must be 0x09C8"
  );

  /**
   * Address: 0x00692700 (FUN_00692700, func_ShakeCamera)
   *
   * What it does:
   * Appends one camera-shake request to the sim sync camera-shake queue.
   */
  void func_ShakeCamera(Sim& sim, const SyncCameraShakeRequest& request)
  {
    auto* const queueView = reinterpret_cast<SimCameraShakeQueueView*>(&sim);
    queueView->mSyncCamShake.push_back(request);
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
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, helpText, 2, argumentCount);
    }

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

  [[nodiscard]] gpg::RRef ExtractLuaUserDataRef(const LuaPlus::LuaObject& userDataObject)
  {
    gpg::RRef out{};
    if (!userDataObject.IsUserData()) {
      return out;
    }

    lua_State* const rawState = userDataObject.GetActiveCState();
    if (!rawState) {
      return out;
    }

    const int top = lua_gettop(rawState);
    const_cast<LuaPlus::LuaObject&>(userDataObject).PushStack(rawState);
    void* const rawUserData = lua_touserdata(rawState, -1);
    if (rawUserData != nullptr) {
      out = *static_cast<gpg::RRef*>(rawUserData);
    }
    lua_settop(rawState, top);
    return out;
  }

  [[nodiscard]] moho::CSndParams* ResolveSoundParamsFromLuaObject(const LuaPlus::LuaObject& object)
  {
    LuaPlus::LuaObject payload(object);
    if (payload.IsTable()) {
      payload = moho::SCR_GetLuaTableField(payload.GetActiveState(), payload, "_c_object");
    }

    if (!payload.IsUserData()) {
      return nullptr;
    }

    const gpg::RRef userDataRef = ExtractLuaUserDataRef(payload);
    if (!userDataRef.mObj) {
      return nullptr;
    }

    static gpg::RType* sSoundParamsType = nullptr;
    if (!sSoundParamsType) {
      sSoundParamsType = gpg::LookupRType(typeid(moho::CSndParams));
    }

    if (sSoundParamsType) {
      const gpg::RRef upcast = gpg::REF_UpcastPtr(userDataRef, sSoundParamsType);
      if (upcast.mObj != nullptr) {
        return static_cast<moho::CSndParams*>(upcast.mObj);
      }
    }

    const char* const typeName = userDataRef.GetTypeName();
    if (typeName != nullptr && std::strstr(typeName, "CSndParams") != nullptr) {
      return static_cast<moho::CSndParams*>(userDataRef.mObj);
    }

    return nullptr;
  }

  enum class BlueprintKind : std::uint8_t
  {
    Unknown = 0,
    Unit,
    Projectile,
    Prop
  };

  [[nodiscard]] BlueprintKind GuessBlueprintKind(const moho::REntityBlueprint* blueprint)
  {
    if (!blueprint) {
      return BlueprintKind::Unknown;
    }

    const std::string scriptModule = blueprint->mScriptModule.to_std();
    if (gpg::STR_ContainsNoCase(scriptModule.c_str(), "projectile")) {
      return BlueprintKind::Projectile;
    }
    if (gpg::STR_ContainsNoCase(scriptModule.c_str(), "unit")) {
      return BlueprintKind::Unit;
    }
    if (gpg::STR_ContainsNoCase(scriptModule.c_str(), "prop")) {
      return BlueprintKind::Prop;
    }

    const std::string scriptClass = blueprint->mScriptClass.to_std();
    if (gpg::STR_EqualsNoCase(scriptClass.c_str(), "Projectile")) {
      return BlueprintKind::Projectile;
    }
    if (gpg::STR_EqualsNoCase(scriptClass.c_str(), "Unit")) {
      return BlueprintKind::Unit;
    }
    if (gpg::STR_EqualsNoCase(scriptClass.c_str(), "Prop")) {
      return BlueprintKind::Prop;
    }

    const std::string id = blueprint->mBlueprintId.to_std();
    if (gpg::STR_ContainsNoCase(id.c_str(), "/projectiles/")) {
      return BlueprintKind::Projectile;
    }
    if (gpg::STR_ContainsNoCase(id.c_str(), "/units/")) {
      return BlueprintKind::Unit;
    }
    if (gpg::STR_ContainsNoCase(id.c_str(), "/props/")) {
      return BlueprintKind::Prop;
    }

    return BlueprintKind::Unknown;
  }

  struct ScriptFallbackSpec
  {
    const char* module;
    const char* className;
  };

  [[nodiscard]] ScriptFallbackSpec GetScriptFallbackSpec(const BlueprintKind kind)
  {
    switch (kind) {
    case BlueprintKind::Unit:
      return {"/lua/sim/unit.lua", "Unit"};
    case BlueprintKind::Projectile:
      return {"/lua/sim/projectile.lua", "Projectile"};
    case BlueprintKind::Prop:
      return {"/lua/sim/prop.lua", "Prop"};
    default:
      return {nullptr, nullptr};
    }
  }

  [[nodiscard]] std::string BuildBlueprintScriptModuleFromId(const moho::REntityBlueprint* blueprint)
  {
    if (!blueprint) {
      return {};
    }

    std::string id = blueprint->mBlueprintId.to_std();
    if (id.empty()) {
      return {};
    }

    gpg::STR_NormalizeFilenameLowerSlash(id);

    std::size_t start = 0;
    if (!id.empty() && id.front() == '/') {
      start = 1;
    }
    const std::size_t underscorePos = id.find('_', start);
    if (underscorePos == std::string::npos || underscorePos <= start) {
      return {};
    }

    return "/" + id.substr(start, underscorePos - start) + "_script.lua";
  }

  /**
   * Address: 0x00677360 (FUN_00677360, func_FindBlueprintScriptModule)
   *
   * What it does:
   * Resolves blueprint script factory tables by trying blueprint-specific module/class
   * first, then falling back to type-default `unit/projectile/prop` script modules.
   */
  [[nodiscard]] LuaPlus::LuaObject
  ResolveBlueprintScriptFactory(moho::Sim* sim, const moho::REntityBlueprint* blueprint)
  {
    if (!sim || !sim->mLuaState) {
      return {};
    }

    const BlueprintKind kind = GuessBlueprintKind(blueprint);
    const ScriptFallbackSpec fallback = GetScriptFallbackSpec(kind);
    if (!fallback.module || !fallback.className) {
      const char* id = (blueprint && !blueprint->mBlueprintId.empty()) ? blueprint->mBlueprintId.c_str() : "<unknown>";
      gpg::Warnf("Can't tell the type of blueprint id '%s'.  No scripts for you -- one year.", id);
      return {};
    }

    const char* requestedClass = "TypeClass";
    if (blueprint && !blueprint->mScriptClass.empty()) {
      requestedClass = blueprint->mScriptClass.c_str();
    }

    std::string requestedModuleStorage;
    const char* requestedModule = nullptr;
    if (blueprint && !blueprint->mScriptModule.empty()) {
      requestedModule = blueprint->mScriptModule.c_str();
    } else {
      requestedModuleStorage = BuildBlueprintScriptModuleFromId(blueprint);
      if (!requestedModuleStorage.empty()) {
        requestedModule = requestedModuleStorage.c_str();
      }
    }

    if (requestedModule && *requestedModule) {
      LuaPlus::LuaObject requestedModuleObj = moho::SCR_ImportLuaModule(sim->mLuaState, requestedModule);
      if (requestedModuleObj) {
        LuaPlus::LuaObject factoryObj =
          moho::SCR_GetLuaTableField(sim->mLuaState, requestedModuleObj, requestedClass);
        if (factoryObj) {
          return factoryObj;
        }

        gpg::Warnf(
          "Script module '%s' exists but doesn't define '%s'.\nFalling back to '%s' in module '%s'.",
          requestedModule,
          requestedClass,
          fallback.className,
          fallback.module
        );
      } else {
        gpg::Warnf(
          "Problems loading module '%s'.  Falling back to '%s' in '%s'.",
          requestedModule,
          fallback.className,
          fallback.module
        );
      }
    }

    LuaPlus::LuaObject fallbackModuleObj = moho::SCR_ImportLuaModule(sim->mLuaState, fallback.module);
    if (fallbackModuleObj) {
      LuaPlus::LuaObject fallbackFactory =
        moho::SCR_GetLuaTableField(sim->mLuaState, fallbackModuleObj, fallback.className);
      if (fallbackFactory) {
        return fallbackFactory;
      }

      gpg::Warnf(
        "Script module '%s' exists but doesn't define '%s'.\nNo scripts for you -- one year.",
        fallback.module,
        fallback.className
      );
    } else {
      gpg::Warnf("Can't find module '%s'.  No scripts for you -- one year.", fallback.module);
    }

    return {};
  }

  [[nodiscard]] moho::CArmyImpl* ResolveEntityArmyFromEntityId(moho::Sim* sim, const moho::EntId entityId) noexcept
  {
    if (!sim) {
      return nullptr;
    }

    const std::uint8_t sourceIndex = moho::ExtractEntityIdSourceIndex(static_cast<std::uint32_t>(entityId));
    if (sourceIndex == moho::kEntityIdSourceIndexInvalid) {
      return nullptr;
    }

    if (sourceIndex >= sim->mArmiesList.size()) {
      return nullptr;
    }

    return sim->mArmiesList[sourceIndex];
  }

  [[nodiscard]] moho::EntityCollisionSpatialGrid* ResolveEntityCollisionGrid(moho::Sim* sim) noexcept
  {
    if (!sim || !sim->mOGrid) {
      return nullptr;
    }

    auto* const rawEntityGrid = reinterpret_cast<std::uint8_t*>(&sim->mOGrid->entityGrid);
    return reinterpret_cast<moho::EntityCollisionSpatialGrid*>(rawEntityGrid + 0x04);
  }

  void RegisterEntityInDbIfMissing(moho::Sim* sim, moho::Entity* entity)
  {
    if (!sim || !entity || !sim->mEntityDB) {
      return;
    }

    auto& entities = sim->mEntityDB->Entities();
    for (auto it = entities.begin(); it != entities.end(); ++it) {
      if (*it == entity) {
        return;
      }
    }
    entities.push_back(entity);
  }

  [[nodiscard]] std::uint8_t ComputeFootprintOccupancyMask(
    const moho::Entity* entity, const moho::SFootprint& footprint, const Wm3::Vec3f&
  ) noexcept
  {
    (void)entity;
    // 0x007209E0 (`Moho::OCCUPY_FootprintFits`) also considers dynamic map blockers;
    // current typed recovery keeps the capability mask for layer bootstrap.
    return static_cast<std::uint8_t>(footprint.mOccupancyCaps);
  }

  [[nodiscard]] float SampleHeightFieldBilinear(const moho::CHeightField* field, const float x, const float z) noexcept
  {
    if (!field || !field->data || field->width <= 0 || field->height <= 0) {
      return 0.0f;
    }

    const int width = field->width;
    const int height = field->height;

    const int baseX = static_cast<int>(std::floor(static_cast<double>(x)));
    const int baseZ = static_cast<int>(std::floor(static_cast<double>(z)));
    const float fracX = x - static_cast<float>(baseX);
    const float fracZ = z - static_cast<float>(baseZ);

    auto sample = [&](int sx, int sz) -> float {
      if (sx < 0) {
        sx = 0;
      } else if (sx >= width) {
        sx = width - 1;
      }
      if (sz < 0) {
        sz = 0;
      } else if (sz >= height) {
        sz = height - 1;
      }

      const std::uint16_t packed = field->data[sz * width + sx];
      return static_cast<float>(packed) * 0.0078125f;
    };

    const float h00 = sample(baseX, baseZ);
    const float h10 = sample(baseX + 1, baseZ);
    const float h01 = sample(baseX, baseZ + 1);
    const float h11 = sample(baseX + 1, baseZ + 1);

    const float h0 = h00 + (h10 - h00) * fracX;
    const float h1 = h01 + (h11 - h01) * fracX;
    return h0 + (h1 - h0) * fracZ;
  }

  [[nodiscard]] Wm3::Vector3f RotateVectorByQuaternion(const moho::Vector4f& q, const Wm3::Vector3f& v) noexcept
  {
    // Entity orientation is packed as (w,x,y,z) in Vector4f::x/y/z/w slots.
    const Wm3::Quatf quaternion{q.x, q.y, q.z, q.w};
    Wm3::Vector3f out{};
    Wm3::MultiplyQuaternionVector(&out, v, quaternion);
    return out;
  }

  [[nodiscard]] std::uint8_t LayerToOccupancyBit(const moho::ELayer layer) noexcept
  {
    switch (layer) {
    case moho::LAYER_Land:
      return static_cast<std::uint8_t>(moho::EOccupancyCaps::OC_LAND);
    case moho::LAYER_Seabed:
      return static_cast<std::uint8_t>(moho::EOccupancyCaps::OC_SEABED);
    case moho::LAYER_Sub:
      return static_cast<std::uint8_t>(moho::EOccupancyCaps::OC_SUB);
    case moho::LAYER_Water:
      return static_cast<std::uint8_t>(moho::EOccupancyCaps::OC_WATER);
    case moho::LAYER_Air:
      return static_cast<std::uint8_t>(moho::EOccupancyCaps::OC_AIR);
    case moho::LAYER_Orbit:
      return static_cast<std::uint8_t>(moho::EOccupancyCaps::OC_ORBIT);
    default:
      return 0u;
    }
  }

  [[nodiscard]] bool HasOccupancyBit(const moho::EOccupancyCaps caps, const std::uint8_t bit) noexcept
  {
    return (static_cast<std::uint8_t>(caps) & bit) != 0u;
  }

  struct CollisionCellRect
  {
    std::uint16_t startX;
    std::uint16_t startZ;
    std::uint16_t width;
    std::uint16_t height;
  };

  [[nodiscard]] int FloorToInt(const float value) noexcept
  {
    return static_cast<int>(std::floor(static_cast<double>(value)));
  }

  [[nodiscard]] int CeilToInt(const float value) noexcept
  {
    return static_cast<int>(std::ceil(static_cast<double>(value)));
  }

  [[nodiscard]] std::uint16_t ClampCellStartToU16(const int value) noexcept
  {
    if (value <= 0) {
      return 0;
    }
    if (value >= 0xFFFF) {
      return 0xFFFFu;
    }
    return static_cast<std::uint16_t>(value);
  }

  [[nodiscard]] std::uint16_t ClampCellExtentToU16(const int extentCandidate, const std::uint16_t startCell) noexcept
  {
    const int maxExtent = 0xFFFF - static_cast<int>(startCell);
    int extent = extentCandidate;
    if (extent >= maxExtent) {
      extent = maxExtent;
    }
    if (extent < 0) {
      extent = 0;
    }
    return static_cast<std::uint16_t>(extent);
  }

  /**
   * Address: 0x004FCBE0 (FUN_004FCBE0)
   *
   * What it does:
   * Converts world-space AABB bounds into quantized collision-cell rectangle:
   * {startX,startZ,width,height}.
   */
  [[nodiscard]] CollisionCellRect
  BuildCollisionCellRectFromBounds(const moho::EntityCollisionBoundsView& bounds) noexcept
  {
    const int minCellX = FloorToInt(bounds.minX) >> 2;
    const int minCellZ = FloorToInt(bounds.minZ) >> 2;
    const int maxCellX = (CeilToInt(bounds.maxX) + 3) >> 2;
    const int maxCellZ = (CeilToInt(bounds.maxZ) + 3) >> 2;

    CollisionCellRect rect{};
    rect.startX = ClampCellStartToU16(minCellX);
    rect.startZ = ClampCellStartToU16(minCellZ);
    rect.width = ClampCellExtentToU16(maxCellX - static_cast<int>(rect.startX), rect.startX);
    rect.height = ClampCellExtentToU16(maxCellZ - static_cast<int>(rect.startZ), rect.startZ);
    return rect;
  }

  /**
   * Address: 0x004FD9B0 (FUN_004FD9B0, append-path subset)
   *
   * What it does:
   * Pushes one chunk-base pointer into the grid chunk-pointer vector
   * (layout at +0x28/+0x2C/+0x30).
   */
  void AppendCollisionChunkPointer(moho::EntityCollisionSpatialGrid& grid, moho::EntityCollisionCellNode* chunkBase)
  {
    auto** begin = grid.mChunkBlocksBegin;
    auto** end = grid.mChunkBlocksEnd;
    auto** capacityEnd = grid.mChunkBlocksCapacityEnd;

    if (begin && end < capacityEnd) {
      *end = chunkBase;
      grid.mChunkBlocksEnd = end + 1;
      return;
    }

    const std::size_t size = begin ? static_cast<std::size_t>(end - begin) : 0u;
    const std::size_t capacity = begin ? static_cast<std::size_t>(capacityEnd - begin) : 0u;

    if (capacity >= 0x3FFFFFFFu) {
      throw std::length_error("vector<T> too long");
    }

    std::size_t newCapacity = capacity + (capacity >> 1);
    const std::size_t minCapacity = size + 1u;
    if (newCapacity < minCapacity) {
      newCapacity = minCapacity;
    }
    if (newCapacity > 0x3FFFFFFFu) {
      newCapacity = minCapacity;
    }

    auto** newBegin = static_cast<moho::EntityCollisionCellNode**>(
      ::operator new(newCapacity * sizeof(moho::EntityCollisionCellNode*))
    );
    if (size != 0u && begin) {
      std::memmove(newBegin, begin, size * sizeof(*begin));
    }
    newBegin[size] = chunkBase;

    if (begin) {
      ::operator delete(begin);
    }

    grid.mChunkBlocksBegin = newBegin;
    grid.mChunkBlocksEnd = newBegin + size + 1u;
    grid.mChunkBlocksCapacityEnd = newBegin + newCapacity;
  }

  /**
   * Address: 0x004FCE90 (FUN_004FCE90)
   *
   * What it does:
   * Ensures free-node list contains at least `requiredFreeNodes` entries by
   * allocating 0x2000-node chunks (0x10000 bytes each) and linking them.
   */
  void EnsureCollisionFreeNodes(moho::EntityCollisionSpatialGrid& grid, const int requiredFreeNodes)
  {
    while (grid.mFreeNodeCount < requiredFreeNodes) {
      auto* chunk = static_cast<moho::EntityCollisionCellNode*>(::operator new(0x10000u));
      for (int i = 0; i < 0x1FFF; ++i) {
        chunk[i].next = &chunk[i + 1];
      }

      chunk[0x1FFF].next = grid.mFreeNodeHead;
      grid.mFreeNodeHead = chunk;

      AppendCollisionChunkPointer(grid, chunk);
      grid.mFreeNodeCount += 0x2000;
    }
  }

  [[nodiscard]] moho::EntityCollisionCellNode**
  SelectCollisionBucketHeadArray(moho::EntityCollisionSpatialGrid& grid, const std::uint32_t bucketFlags) noexcept
  {
    if ((bucketFlags & 0x100u) != 0u) {
      return grid.mBucketHeads100;
    }
    if ((bucketFlags & 0x200u) != 0u) {
      return grid.mBucketHeads200;
    }
    if ((bucketFlags & 0x0C00u) != 0u) {
      return grid.mBucketHeadsC00;
    }
    return nullptr;
  }

  /**
   * Address: 0x004FCF20 (FUN_004FCF20)
   *
   * What it does:
   * Pops one node from the grid free-list, tags ownership to `span`, then
   * prepends it to the selected collision bucket chain.
   */
  void InsertSpanNodeIntoBucket(moho::EntityCollisionCellSpan& span, const int bucketIndex)
  {
    if ((span.mBucketFlags & 0x0F00u) == 0u) {
      return;
    }

    moho::EntityCollisionSpatialGrid& grid = *span.mSpatialGrid;
    moho::EntityCollisionCellNode* const node = grid.mFreeNodeHead;
    grid.mFreeNodeHead = node->next;
    node->owner = &span;

    moho::EntityCollisionCellNode** const bucketHeads = SelectCollisionBucketHeadArray(grid, span.mBucketFlags);
    node->next = bucketHeads[bucketIndex];
    bucketHeads[bucketIndex] = node;

    --grid.mFreeNodeCount;
  }

  /**
   * Address: 0x004FCF90 (FUN_004FCF90)
   *
   * What it does:
   * Removes `span` node from the selected bucket chain and returns the node
   * to the grid free-list.
   */
  void RemoveSpanNodeFromBucket(
    const int bucketIndex, moho::EntityCollisionSpatialGrid& grid, moho::EntityCollisionCellSpan& span
  )
  {
    if ((span.mBucketFlags & 0x0F00u) == 0u) {
      return;
    }

    moho::EntityCollisionCellNode** const bucketHeads = SelectCollisionBucketHeadArray(grid, span.mBucketFlags);
    moho::EntityCollisionCellNode** link = &bucketHeads[bucketIndex];
    moho::EntityCollisionCellNode* node = *link;
    while (node->owner != &span) {
      link = &node->next;
      node = node->next;
    }

    *link = node->next;
    node->owner = nullptr;
    node->next = grid.mFreeNodeHead;
    ++grid.mFreeNodeCount;
    grid.mFreeNodeHead = node;
  }

  /**
   * Address: 0x004FD420 (FUN_004FD420)
   *
   * What it does:
   * Adds current span membership into collision buckets for all covered cells.
   */
  void AddSpanMembership(moho::EntityCollisionCellSpan& span)
  {
    moho::EntityCollisionSpatialGrid& grid = *span.mSpatialGrid;
    const std::int32_t requiredNodes = static_cast<std::int32_t>(
      static_cast<std::uint32_t>(span.mCellWidth) * static_cast<std::uint32_t>(span.mCellHeight)
    );
    EnsureCollisionFreeNodes(grid, requiredNodes);

    int rowBase = static_cast<int>(span.mCellStartX) + (static_cast<int>(span.mCellStartZ) << grid.mRowShift);
    for (int row = 0; row < static_cast<int>(span.mCellHeight); ++row) {
      for (int col = 0; col < static_cast<int>(span.mCellWidth); ++col) {
        const int bucketIndex = (rowBase + col) & static_cast<int>(grid.mBucketMask);
        InsertSpanNodeIntoBucket(span, bucketIndex);
      }
      rowBase += grid.mRowStride;
    }
  }

  /**
   * Address: 0x004FD490 (FUN_004FD490)
   *
   * What it does:
   * Removes current span membership from collision buckets for all covered cells.
   */
  void RemoveSpanMembership(moho::EntityCollisionCellSpan& span)
  {
    moho::EntityCollisionSpatialGrid& grid = *span.mSpatialGrid;
    int rowBase = static_cast<int>(span.mCellStartX) + (static_cast<int>(span.mCellStartZ) << grid.mRowShift);
    for (int row = 0; row < static_cast<int>(span.mCellHeight); ++row) {
      for (int col = 0; col < static_cast<int>(span.mCellWidth); ++col) {
        const int bucketIndex = (rowBase + col) & static_cast<int>(grid.mBucketMask);
        RemoveSpanNodeFromBucket(bucketIndex, grid, span);
      }
      rowBase += grid.mRowStride;
    }
  }

  [[nodiscard]] bool
  CollisionCellRectEqualsSpan(const CollisionCellRect& rect, const moho::EntityCollisionCellSpan& span) noexcept
  {
    return rect.startX == span.mCellStartX && rect.startZ == span.mCellStartZ && rect.width == span.mCellWidth &&
      rect.height == span.mCellHeight;
  }

  void RelinkSpanToRectIfChanged(moho::EntityCollisionCellSpan& span, const CollisionCellRect& nextRect)
  {
    if (CollisionCellRectEqualsSpan(nextRect, span)) {
      return;
    }

    RemoveSpanMembership(span);
    span.mCellStartX = nextRect.startX;
    span.mCellStartZ = nextRect.startZ;
    span.mCellWidth = nextRect.width;
    span.mCellHeight = nextRect.height;
    AddSpanMembership(span);
  }

  /**
   * Address: 0x004FD590 (FUN_004FD590)
   *
   * What it does:
   * Rebuilds quantized collision-cell rectangle directly from bounds and
   * relinks bucket membership only when span changed.
   */
  void RelinkSpanFromBoundsIfChanged(moho::EntityCollisionCellSpan& span, const moho::EntityCollisionBoundsView& bounds)
  {
    const CollisionCellRect nextRect = BuildCollisionCellRectFromBounds(bounds);
    RelinkSpanToRectIfChanged(span, nextRect);
  }

  /**
   * Address: 0x004FD4F0 (FUN_004FD4F0)
   *
   * What it does:
   * Reads primitive AABB, rebuilds quantized span rectangle, and if changed:
   * removes old bucket membership, writes new rectangle, then re-adds membership.
   */
  void RelinkSpanFromCollisionPrimitive(
    moho::EntityCollisionCellSpan& span, const moho::EntityCollisionUpdater* collisionPrimitive
  )
  {
    if (collisionPrimitive) {
      moho::EntityCollisionBoundsScratch scratchBounds{};
      const moho::EntityCollisionBoundsView* const bounds = collisionPrimitive->GetBoundingBox(&scratchBounds);
      RelinkSpanFromBoundsIfChanged(span, *bounds);
      return;
    }

    RelinkSpanToRectIfChanged(span, CollisionCellRect{});
  }

  void RefreshCollisionBoundsSnapshot(moho::Entity& entity)
  {
    if (!entity.CollisionExtents) {
      return;
    }

    moho::EntityCollisionBoundsScratch scratchBounds{};
    const moho::EntityCollisionBoundsView* const bounds = entity.CollisionExtents->GetBoundingBox(&scratchBounds);
    entity.mCollisionBoundsMin.x = bounds->minX;
    entity.mCollisionBoundsMin.y = bounds->minY;
    entity.mCollisionBoundsMin.z = bounds->minZ;
    entity.mCollisionBoundsMax.x = bounds->maxX;
    entity.mCollisionBoundsMax.y = bounds->maxY;
    entity.mCollisionBoundsMax.z = bounds->maxZ;
  }

  /**
   * Address: 0x0067AE00 (shared body used by FUN_0067AC40/FUN_0067AD30/FUN_0067AE00)
   *
   * What it does:
   * Replaces collision primitive pointer, relinks span as needed, and keeps
   * cached collision bounds in sync.
   */
  void InstallCollisionPrimitiveAndRefresh(moho::Entity& entity, moho::EntityCollisionUpdater* replacement)
  {
    moho::EntityCollisionUpdater* const old = entity.CollisionExtents;
    entity.CollisionExtents = replacement;
    ::operator delete(old);

    if (!entity.CollisionExtents) {
      RelinkSpanToRectIfChanged(entity.mCollisionCellSpan, CollisionCellRect{});
      return;
    }

    const moho::EntityTransformPayload current = moho::ReadEntityTransformPayload(entity.Orientation, entity.Position);
    entity.CollisionExtents->SetTransform(current);
    RelinkSpanFromCollisionPrimitive(entity.mCollisionCellSpan, entity.CollisionExtents);
    RefreshCollisionBoundsSnapshot(entity);
  }

  [[nodiscard]] Wm3::Box3f BuildBlueprintCollisionBox(const moho::REntityBlueprint& blueprint)
  {
    Wm3::Box3f localBox{};
    localBox.Center[0] = blueprint.mCollisionOffsetX;
    localBox.Center[1] = blueprint.mCollisionOffsetY + blueprint.mSizeY * 0.5f;
    localBox.Center[2] = blueprint.mCollisionOffsetZ;

    localBox.Axis[0][0] = 1.0f;
    localBox.Axis[0][1] = 0.0f;
    localBox.Axis[0][2] = 0.0f;
    localBox.Axis[1][0] = 0.0f;
    localBox.Axis[1][1] = 1.0f;
    localBox.Axis[1][2] = 0.0f;
    localBox.Axis[2][0] = 0.0f;
    localBox.Axis[2][1] = 0.0f;
    localBox.Axis[2][2] = 1.0f;

    localBox.Extent[0] = blueprint.mSizeX * 0.5f;
    localBox.Extent[1] = blueprint.mSizeY * 0.5f;
    localBox.Extent[2] = blueprint.mSizeZ * 0.5f;
    return localBox;
  }

  [[nodiscard]] Wm3::Vec3f BuildBlueprintCollisionCenter(const moho::REntityBlueprint& blueprint)
  {
    Wm3::Vec3f center{};
    center.x = blueprint.mCollisionOffsetX;
    center.y = blueprint.mCollisionOffsetY + blueprint.mSizeY * 0.5f;
    center.z = blueprint.mCollisionOffsetZ;
    return center;
  }

  [[nodiscard]] std::uint32_t ReadBlueprintCategoryBitIndex(const moho::REntityBlueprint* blueprint) noexcept
  {
    return blueprint ? blueprint->mCategoryBitIndex : 0u;
  }

  struct MeshBoneEntryView
  {
    std::uint8_t bytes[0x58];
  };

  static_assert(sizeof(MeshBoneEntryView) == 0x58, "MeshBoneEntryView size must be 0x58");

  struct MeshObjectBoneSpanView
  {
    std::uint8_t pad_00_10[0x10];
    const MeshBoneEntryView* boneBegin; // +0x10
    const MeshBoneEntryView* boneEnd;   // +0x14
  };

  static_assert(
    offsetof(MeshObjectBoneSpanView, boneBegin) == 0x10, "MeshObjectBoneSpanView::boneBegin offset must be 0x10"
  );
  static_assert(
    offsetof(MeshObjectBoneSpanView, boneEnd) == 0x14, "MeshObjectBoneSpanView::boneEnd offset must be 0x14"
  );

  [[nodiscard]] const char* ResolveMeshBoneName(const moho::Entity* const entity, const int boneIndex) noexcept
  {
    if (entity == nullptr || entity->mMeshRef.mObj == nullptr || boneIndex < 0) {
      return nullptr;
    }

    const auto* const meshObject = static_cast<const MeshObjectBoneSpanView*>(entity->mMeshRef.mObj);
    const MeshBoneEntryView* const begin = meshObject->boneBegin;
    const MeshBoneEntryView* const end = meshObject->boneEnd;
    if (begin == nullptr || end == nullptr || end <= begin) {
      return nullptr;
    }

    const std::ptrdiff_t boneCount = end - begin;
    if (boneIndex >= boneCount) {
      return nullptr;
    }

    const auto* const bone = reinterpret_cast<const moho::SAniSkelBone*>(begin + boneIndex);
    return bone->mBoneName;
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

  struct AttachRuntimeNodeView
  {
    AttachRuntimeNodeView* next;
    AttachRuntimeNodeView* prev;
    std::uint8_t pad_08[0x04];
    AttachRuntimeNodeView** owner;
    std::uint8_t pad_10[0x04];
    std::int32_t pendingValue;
    std::uint8_t queuedFlag;
    std::uint8_t pad_19[0x03];
  };

  static_assert(offsetof(AttachRuntimeNodeView, owner) == 0x0C, "AttachRuntimeNodeView::owner offset must be 0x0C");
  static_assert(
    offsetof(AttachRuntimeNodeView, pendingValue) == 0x14, "AttachRuntimeNodeView::pendingValue offset must be 0x14"
  );
  static_assert(
    offsetof(AttachRuntimeNodeView, queuedFlag) == 0x18, "AttachRuntimeNodeView::queuedFlag offset must be 0x18"
  );

  /**
   * Address: 0x00679550 (inlined block)
   *
   * What it does:
   * Relinks an attached runtime node back to its owner list when it is marked queued.
   */
  void ResetAttachRuntimeNodeIfQueued(moho::Entity* entity)
  {
    if (!entity) {
      return;
    }

    auto* node = reinterpret_cast<AttachRuntimeNodeView*>(entity->mSubtask);
    if (!node || node->queuedFlag == 0u) {
      return;
    }

    node->pendingValue = 0;

    AttachRuntimeNodeView* const next = node->next;
    AttachRuntimeNodeView* const prev = node->prev;
    if (next && prev) {
      next->prev = prev;
      prev->next = next;
    }

    node->next = node;
    node->prev = node;

    AttachRuntimeNodeView** const owner = node->owner;
    if (owner) {
      node->next = *owner;
      node->prev = reinterpret_cast<AttachRuntimeNodeView*>(owner);
      *owner = node;
      if (node->next) {
        node->next->prev = node;
      }
    }

    node->queuedFlag = 0u;
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

  [[nodiscard]] moho::SEntAttachInfo BuildAttachInfoFromBones(
    moho::Entity* const parent,
    const int childBoneIndex,
    const int parentBoneIndex,
    const float relativeTransform[7]
  ) noexcept
  {
    moho::SEntAttachInfo attachInfo = moho::SEntAttachInfo::MakeDetached();
    attachInfo.TargetWeakLink().ResetFromObject(parent);
    attachInfo.mParentBoneIndex = parentBoneIndex;
    attachInfo.mChildBoneIndex = childBoneIndex;
    attachInfo.mRelativeOrientX = relativeTransform[0];
    attachInfo.mRelativeOrientY = relativeTransform[1];
    attachInfo.mRelativeOrientZ = relativeTransform[2];
    attachInfo.mRelativeOrientW = relativeTransform[3];
    attachInfo.mRelativePosX = relativeTransform[4];
    attachInfo.mRelativePosY = relativeTransform[5];
    attachInfo.mRelativePosZ = relativeTransform[6];
    return attachInfo;
  }

  /**
   * Address: 0x00679680 (FUN_00679680)
   *
   * What it does:
   * Applies attach-link/local transform from `src` into `dst`, including
   * intrusive weak-chain rewire when attach owner changes.
   */
  void ApplyAttachInfo(moho::SEntAttachInfo& dst, const moho::SEntAttachInfo& src)
  {
    moho::WeakPtr<moho::Entity>& dstWeak = dst.TargetWeakLink();
    const moho::WeakPtr<moho::Entity>& srcWeak = src.TargetWeakLink();

    if (dstWeak.ownerLinkSlot != srcWeak.ownerLinkSlot) {
      dstWeak.ResetFromOwnerLinkSlot(srcWeak.ownerLinkSlot);
    }

    dst.mParentBoneIndex = src.mParentBoneIndex;
    dst.mChildBoneIndex = src.mChildBoneIndex;
    dst.mRelativeOrientX = src.mRelativeOrientX;
    dst.mRelativeOrientY = src.mRelativeOrientY;
    dst.mRelativeOrientZ = src.mRelativeOrientZ;
    dst.mRelativeOrientW = src.mRelativeOrientW;
    dst.mRelativePosX = src.mRelativePosX;
    dst.mRelativePosY = src.mRelativePosY;
    dst.mRelativePosZ = src.mRelativePosZ;
  }

  struct DestroyQueueNodeView
  {
    DestroyQueueNodeView* next;
    DestroyQueueNodeView* prev;
    moho::Entity* entity;
  };

  static_assert(sizeof(DestroyQueueNodeView) == 0x0C, "DestroyQueueNodeView size must be 0x0C");

  struct CommandDbDestroyQueueView
  {
    std::uint8_t pad_00[0x20];
    std::int32_t count;         // +0x20
    DestroyQueueNodeView* head; // +0x24
  };

  static_assert(
    offsetof(CommandDbDestroyQueueView, count) == 0x20, "CommandDbDestroyQueueView::count offset must be 0x20"
  );
  static_assert(
    offsetof(CommandDbDestroyQueueView, head) == 0x24, "CommandDbDestroyQueueView::head offset must be 0x24"
  );

  /**
   * Address: 0x00679B80 (inlined with FUN_0067DE00/FUN_0067DE40)
   *
   * What it does:
   * Inserts entity into command-db destroy queue linked-list and increments queue size.
   */
  void QueueEntityForDestroy(moho::Entity* entity)
  {
    if (!entity || !entity->SimulationRef || !entity->SimulationRef->mCommandDB) {
      return;
    }

    auto* queue = reinterpret_cast<CommandDbDestroyQueueView*>(entity->SimulationRef->mCommandDB);
    DestroyQueueNodeView* const head = queue->head;
    if (!head) {
      return;
    }

    if (queue->count == 0x3FFFFFFF) {
      throw std::length_error("list<T> too long");
    }

    auto* node = reinterpret_cast<DestroyQueueNodeView*>(::operator new(sizeof(DestroyQueueNodeView)));
    node->next = head;
    node->prev = head->prev;
    node->entity = entity;

    ++queue->count;
    head->prev = node;
    node->prev->next = node;
  }
} // namespace

namespace moho
{
  Wm3::Quaternionf* QuatCrossAdd(Wm3::Quaternionf* dest, Wm3::Vector3f v1, Wm3::Vector3f v2);
  int cfunc_EntityPushOver(lua_State* luaContext);
  int cfunc_EntityFallDown(lua_State* luaContext);
  int cfunc_EntityFallDownL(LuaPlus::LuaState* state);
  int cfunc_MotorFallDownWhack(lua_State* luaContext);
  int cfunc_EntitySinkAway(lua_State* luaContext);

  /**
   * Address: 0x0067CBC0 (FUN_0067CBC0, Moho::InstanceCounter<Moho::Entity>::GetStatItem)
   *
   * What it does:
   * Lazily resolves and caches the engine stat slot used for
   * `Entity` instance counting.
   */
  template <>
  moho::StatItem* moho::InstanceCounter<moho::Entity>::GetStatItem()
  {
    static moho::StatItem* sStatItem = nullptr;
    if (sStatItem) {
      return sStatItem;
    }

    moho::EngineStats* const engineStats = moho::GetEngineStats();
    if (!engineStats) {
      return nullptr;
    }

    const std::string statPath = BuildInstanceCounterStatPath(typeid(moho::Entity).name());
    sStatItem = engineStats->GetItem(statPath.c_str(), true);
    return sStatItem;
  }

  /**
   * Address: 0x00676C40
   *
   * What it does:
   * Returns cached reflection descriptor for Entity.
   */
  gpg::RType* Entity::GetClass() const
  {
    static gpg::RType* sEntityType = nullptr;
    if (!sEntityType) {
      sEntityType = gpg::LookupRType(typeid(Entity));
    }
    return sEntityType;
  }

  /**
   * Address: 0x0067CFA0 (FUN_0067CFA0, Moho::Entity::GetPointerType)
   *
   * What it does:
   * Returns cached reflection descriptor for `Entity*`.
   */
  gpg::RType* Entity::GetPointerType()
  {
    static gpg::RType* sEntityPointerType = nullptr;
    if (!sEntityPointerType) {
      sEntityPointerType = gpg::LookupRType(typeid(Entity*));
    }
    return sEntityPointerType;
  }

  /**
   * Address: 0x00676C60
   *
   * What it does:
   * Packs {this, GetClass()} as a reflection reference handle.
   */
  gpg::RRef Entity::GetDerivedObjectRef()
  {
    gpg::RRef ref{};
    ref.mObj = this;
    ref.mType = GetClass();
    return ref;
  }

  /**
   * Address: 0x0067B470 (FUN_0067B470,
   * ?MemberSaveConstructArgs@Entity@Moho@@AAEXAAVWriteArchive@gpg@@HABVRRef@4@AAVSerSaveConstructArgsResult@4@@Z)
   *
   * What it does:
   * Saves construct payload (`Sim*`) as an unowned tracked-pointer lane.
   */
  void Entity::MemberSaveConstructArgs(
    gpg::WriteArchive& archive,
    const int,
    const gpg::RRef&,
    gpg::SerSaveConstructArgsResult& result
  )
  {
    static gpg::RType* sSimType = nullptr;
    if (!sSimType) {
      sSimType = gpg::LookupRType(typeid(Sim));
    }

    gpg::RRef simRef{};
    simRef.mObj = SimulationRef;
    simRef.mType = SimulationRef ? sSimType : nullptr;

    gpg::WriteRawPointer(&archive, simRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});
    result.SetUnowned(0u);
  }

  /**
   * Address: 0x0067B570 (FUN_0067B570,
   * ?MemberConstruct@Entity@Moho@@CAXAAVReadArchive@gpg@@HABVRRef@4@AAVSerConstructResult@4@@Z)
   *
   * What it does:
   * Reads construct payload (`Sim*`) and allocates one `Entity` with
   * default entity collision-bucket flags (`0x800`).
   */
  void Entity::MemberConstruct(gpg::ReadArchive& archive, const int, const gpg::RRef&, gpg::SerConstructResult& result)
  {
    static gpg::RType* sSimType = nullptr;
    static gpg::RType* sEntityType = nullptr;
    if (!sSimType) {
      sSimType = gpg::LookupRType(typeid(Sim));
    }
    if (!sEntityType) {
      sEntityType = gpg::LookupRType(typeid(Entity));
    }

    Sim* ownerSim = nullptr;
    const gpg::TrackedPointerInfo trackedOwner = gpg::ReadRawPointer(&archive, gpg::RRef{});
    if (trackedOwner.object != nullptr) {
      gpg::RRef sourceRef{};
      sourceRef.mObj = trackedOwner.object;
      sourceRef.mType = trackedOwner.type;
      const gpg::RRef upcastOwner = gpg::REF_UpcastPtr(sourceRef, sSimType);
      ownerSim = static_cast<Sim*>(upcastOwner.mObj);
    }

    (void)ownerSim;
    Entity* const object = nullptr;
    gpg::RRef objectRef{};
    objectRef.mObj = object;
    objectRef.mType = object ? object->GetClass() : sEntityType;
    result.SetUnowned(objectRef, 0u);
  }

  /**
   * Address: 0x00677C60 (FUN_00677C60, scalar deleting destructor thunk)
   *
   * What it does:
   * Provides the required out-of-line body for Entity's pure-virtual
   * destructor so deleting-thunk wrappers can call base teardown.
   */
  Entity::~Entity() = default;

  /**
   * Address: 0x006779E0 (FUN_006779E0)
   *
   * What it does:
   * Initializes Entity storage for serializer-owned construction paths and
   * links the entity node into `Sim::mCoordEntities`.
   */
  Entity::Entity(Sim* sim, const std::uint32_t collisionBucketFlags)
    : CTask(nullptr, false)
  {
    std::memset(pad_011E, 0, sizeof(pad_011E));
    std::memset(pad_0128, 0, sizeof(pad_0128));
    std::memset(pad_0174, 0, sizeof(pad_0174));
    std::memset(pad_01BB, 0, sizeof(pad_01BB));
    std::memset(pad_01ED, 0, sizeof(pad_01ED));
    std::memset(pad_01F8_01FC, 0, sizeof(pad_01F8_01FC));

    mCollisionCellSpan.mCellStartX = 0u;
    mCollisionCellSpan.mCellStartZ = 0u;
    mCollisionCellSpan.mCellWidth = 0u;
    mCollisionCellSpan.mCellHeight = 0u;
    mCollisionCellSpan.mSpatialGrid = ResolveEntityCollisionGrid(sim);
    mCollisionCellSpan.mReserved0C = 0u;
    mCollisionCellSpan.mBucketFlags = collisionBucketFlags;

    mCoordNode.ListUnlink();

    id_ = static_cast<EntId>(moho::ToRaw(moho::EEntityIdSentinel::Invalid));
    BluePrint = nullptr;
    mTickCreated = 0u;
    mReserved74 = 0u;

    mMeshRef = {};
    mMeshTypeClassId = 0;

    mDrawScaleX = 1.0f;
    mDrawScaleY = 1.0f;
    mDrawScaleZ = 1.0f;

    Health = 0.0f;
    MaxHealth = 0.0f;
    BeingBuilt = 0u;
    Dead = 0u;
    DirtySyncState = 0u;
    mDestroyedByKill = 0u;

    Orientation = {1.0f, 0.0f, 0.0f, 0.0f};
    Position = {0.0f, 0.0f, 0.0f};
    PrevOrientation = {1.0f, 0.0f, 0.0f, 0.0f};
    PrevPosition = {0.0f, 0.0f, 0.0f};
    mVelocityScale = 0.0f;
    FractionCompleted = 0.0f;

    mVisibilityState = 0u;
    mFootprintLayer = 0;
    mCurrentLayer = LAYER_None;
    mUseAltFootprint = 0u;
    mUseAltFootprintSecondary = 0u;

    SimulationRef = sim;
    ArmyRef = nullptr;

    PendingOrientation = {1.0f, 0.0f, 0.0f, 0.0f};
    PendingPosition = {0.0f, 0.0f, 0.0f};
    mPositionHistory = nullptr;
    mPendingVelocityScale = 0.0f;
    CollisionExtents = nullptr;

    mAttachedEntities.clear();
    mAttachInfo = SEntAttachInfo::MakeDetached();

    mQueueRelinkBlocked = 0u;
    DestroyQueuedFlag = 0u;
    mOnDestroyDispatched = 0u;
    mIntelManager = nullptr;
    mVisibilityLayerFriendly = 2;
    mVisibilityLayerEnemy = 2;
    mVisibilityLayerNeutral = 2;
    mVisibilityLayerDefault = 2;
    mInterfaceCreated = 0u;
    readinessFlags = 0;
    mCollisionBoundsMin = {0.0f, 0.0f, 0.0f};
    mCollisionBoundsMax = {0.0f, 0.0f, 0.0f};
    mMotor = nullptr;

    if (sim != nullptr) {
      mCoordNode.ListLinkBefore(&sim->mCoordEntities);
    }
  }

  /**
   * Address: 0x00677C90 (FUN_00677C90)
   *
   * What it does:
   * Initializes Entity base state blocks, binds script object from blueprint module,
   * seeds collision/grid metadata, and dispatches `StandardInit`.
   */
  Entity::Entity(REntityBlueprint* blueprint, Sim* sim, const EntId entityId, const std::uint32_t collisionBucketFlags)
    : CTask(nullptr, false)
  {
    std::memset(pad_011E, 0, sizeof(pad_011E));
    std::memset(pad_0128, 0, sizeof(pad_0128));
    std::memset(pad_0174, 0, sizeof(pad_0174));
    std::memset(pad_01BB, 0, sizeof(pad_01BB));
    std::memset(pad_01ED, 0, sizeof(pad_01ED));
    std::memset(pad_01F8_01FC, 0, sizeof(pad_01F8_01FC));

    LuaPlus::LuaObject arg1{};
    LuaPlus::LuaObject arg2{};
    LuaPlus::LuaObject arg3{};
    LuaPlus::LuaObject scriptFactory = ResolveBlueprintScriptFactory(sim, blueprint);
    CreateLuaObject(scriptFactory, arg1, arg2, arg3);

    mCollisionCellSpan.mCellStartX = 0u;
    mCollisionCellSpan.mCellStartZ = 0u;
    mCollisionCellSpan.mCellWidth = 0u;
    mCollisionCellSpan.mCellHeight = 0u;
    mCollisionCellSpan.mSpatialGrid = ResolveEntityCollisionGrid(sim);
    mCollisionCellSpan.mReserved0C = 0u;
    mCollisionCellSpan.mBucketFlags = collisionBucketFlags;

    mCoordNode.ListUnlink();

    id_ = static_cast<EntId>(moho::ToRaw(moho::EEntityIdSentinel::Invalid));
    BluePrint = nullptr;
    mTickCreated = 0u;
    mReserved74 = 0u;

    mMeshRef = {};
    mMeshTypeClassId = 0;

    mDrawScaleX = 1.0f;
    mDrawScaleY = 1.0f;
    mDrawScaleZ = 1.0f;

    Health = 0.0f;
    MaxHealth = 0.0f;
    BeingBuilt = 0u;
    Dead = 0u;
    DirtySyncState = 0u;
    mDestroyedByKill = 0u;

    Orientation = {1.0f, 0.0f, 0.0f, 0.0f};
    Position = {0.0f, 0.0f, 0.0f};
    PrevOrientation = {1.0f, 0.0f, 0.0f, 0.0f};
    PrevPosition = {0.0f, 0.0f, 0.0f};
    mVelocityScale = 0.0f;
    FractionCompleted = 0.0f;

    mVisibilityState = 0u;
    mFootprintLayer = 0;
    mCurrentLayer = LAYER_None;
    mUseAltFootprint = 0u;
    mUseAltFootprintSecondary = 0u;

    SimulationRef = nullptr;
    ArmyRef = nullptr;

    PendingOrientation = {1.0f, 0.0f, 0.0f, 0.0f};
    PendingPosition = {0.0f, 0.0f, 0.0f};
    mPositionHistory = nullptr;
    mPendingVelocityScale = 1.0f;
    CollisionExtents = nullptr;

    mAttachInfo = SEntAttachInfo::MakeDetached();

    mQueueRelinkBlocked = 0u;
    DestroyQueuedFlag = 0u;
    mOnDestroyDispatched = 0u;
    mIntelManager = nullptr;
    mVisibilityLayerFriendly = 2;
    mVisibilityLayerEnemy = 2;
    mVisibilityLayerNeutral = 4;
    mVisibilityLayerDefault = 2;
    mInterfaceCreated = 0u;
    readinessFlags = 0;
    mCollisionBoundsMin = {0.0f, 0.0f, 0.0f};
    mCollisionBoundsMax = {0.0f, 0.0f, 0.0f};
    mMotor = nullptr;

    BluePrint = blueprint;
    StandardInit(sim, entityId);
  }

  /**
   * Address: 0x00677F40 (FUN_00677F40, ??0Entity@Moho@@QAE@ABVLuaObject@LuaPlus@@PAVSim@1@VEntId@1@H@Z)
   *
   * LuaPlus::LuaObject const &,Moho::Sim *,Moho::EntId
   *
   * IDA signature:
   * LuaPlus::LuaObject *__userpurge Moho::Entity::Entity@<eax>(Moho::Sim *a1@<edi>, LuaPlus::LuaObject *result, LuaPlus::LuaObject *a2, unsigned int a4);
   *
   * What it does:
   * Initializes Entity base state for Lua-side spawned entities, applies the
   * default collision bucket mask `0x800`, then binds the provided Lua object.
   */
  Entity::Entity(const LuaPlus::LuaObject& luaObject, Sim* sim, const EntId entityId)
    : CTask(nullptr, false)
  {
    std::memset(pad_011E, 0, sizeof(pad_011E));
    std::memset(pad_0128, 0, sizeof(pad_0128));
    std::memset(pad_0174, 0, sizeof(pad_0174));
    std::memset(pad_01BB, 0, sizeof(pad_01BB));
    std::memset(pad_01ED, 0, sizeof(pad_01ED));
    std::memset(pad_01F8_01FC, 0, sizeof(pad_01F8_01FC));

    mCollisionCellSpan.mCellStartX = 0u;
    mCollisionCellSpan.mCellStartZ = 0u;
    mCollisionCellSpan.mCellWidth = 0u;
    mCollisionCellSpan.mCellHeight = 0u;
    mCollisionCellSpan.mSpatialGrid = ResolveEntityCollisionGrid(sim);
    mCollisionCellSpan.mReserved0C = 0u;
    mCollisionCellSpan.mBucketFlags = 0x800u;

    mCoordNode.ListUnlink();

    id_ = static_cast<EntId>(moho::ToRaw(moho::EEntityIdSentinel::Invalid));
    BluePrint = nullptr;
    mTickCreated = 0u;
    mReserved74 = 0u;

    mMeshRef = {};
    mMeshTypeClassId = 0;

    mDrawScaleX = 1.0f;
    mDrawScaleY = 1.0f;
    mDrawScaleZ = 1.0f;

    Health = 0.0f;
    MaxHealth = 0.0f;
    BeingBuilt = 0u;
    Dead = 0u;
    DirtySyncState = 0u;
    mDestroyedByKill = 0u;

    Orientation = {1.0f, 0.0f, 0.0f, 0.0f};
    Position = {0.0f, 0.0f, 0.0f};
    PrevOrientation = {1.0f, 0.0f, 0.0f, 0.0f};
    PrevPosition = {0.0f, 0.0f, 0.0f};
    mVelocityScale = 0.0f;
    FractionCompleted = 0.0f;

    mVisibilityState = 0u;
    mFootprintLayer = 0;
    mCurrentLayer = LAYER_None;
    mUseAltFootprint = 0u;
    mUseAltFootprintSecondary = 0u;

    SimulationRef = nullptr;
    ArmyRef = nullptr;

    PendingOrientation = {1.0f, 0.0f, 0.0f, 0.0f};
    PendingPosition = {0.0f, 0.0f, 0.0f};
    mPositionHistory = nullptr;
    mPendingVelocityScale = 1.0f;
    CollisionExtents = nullptr;

    mAttachInfo = SEntAttachInfo::MakeDetached();

    mQueueRelinkBlocked = 0u;
    DestroyQueuedFlag = 0u;
    mOnDestroyDispatched = 0u;
    mIntelManager = nullptr;
    mVisibilityLayerFriendly = 2;
    mVisibilityLayerEnemy = 2;
    mVisibilityLayerNeutral = 4;
    mVisibilityLayerDefault = 2;
    mInterfaceCreated = 0u;
    readinessFlags = 0;
    mCollisionBoundsMin = {0.0f, 0.0f, 0.0f};
    mCollisionBoundsMax = {0.0f, 0.0f, 0.0f};
    mMotor = nullptr;

    StandardInit(sim, entityId);
    SetLuaObject(luaObject);
  }

  /**
   * Address: 0x00678370 (FUN_00678370)
   *
   * What it does:
   * Applies runtime identity ownership (sim/army/id), initializes interface/visibility
   * defaults, registers entity in sim db/lists, and initializes collision shape.
   */
  void Entity::StandardInit(Sim* sim, const EntId entityId)
  {
    SimulationRef = sim;
    ArmyRef = ResolveEntityArmyFromEntityId(sim, entityId);
    id_ = entityId;
    mTickCreated = sim ? sim->mCurTick : 0u;
    mReserved74 = 0u;

    Dead = 0u;
    mCurrentLayer = LAYER_None;
    mPendingVelocityScale = 1.0f;
    mQueueRelinkBlocked = 0u;
    DestroyQueuedFlag = 0u;
    mOnDestroyDispatched = 0u;
    readinessFlags = 0;
    mInterfaceCreated = 0u;

    mVisibilityLayerFriendly = 2;
    mVisibilityLayerEnemy = 2;
    mVisibilityLayerNeutral = 4;
    mVisibilityLayerDefault = 2;

    RegisterEntityInDbIfMissing(sim, this);
    RefreshCollisionShapeFromBlueprint();

    if (SimulationRef) {
      mCoordNode.ListLinkBefore(&SimulationRef->mCoordEntities);
    }
  }

  /**
   * Address: 0x0062AD30 / 0x00678880 (FUN_0062AD30/FUN_00678880)
   *
   * What it does:
   * Chooses initial simulation layer from footprint occupancy, category hints,
   * map water elevation and terrain elevation at spawn coordinates.
   */
  ELayer Entity::GetStartingLayer(const Wm3::Vec3f& worldPos, const ELayer desiredLayer) const
  {
    const SFootprint& footprint = GetFootprint();
    const std::uint8_t occupancyMask = ComputeFootprintOccupancyMask(this, footprint, worldPos);

    const bool isExperimental = IsInCategory("EXPERIMENTAL");
    const bool isBeacon = IsInCategory("FERRYBEACON");

    const std::uint8_t desiredMaskBit = LayerToOccupancyBit(desiredLayer);
    if ((occupancyMask & desiredMaskBit) != 0u) {
      return desiredLayer;
    }

    if ((occupancyMask & static_cast<std::uint8_t>(EOccupancyCaps::OC_AIR)) != 0u) {
      return isExperimental ? LAYER_Land : LAYER_Air;
    }

    const STIMap* const mapData = (SimulationRef ? SimulationRef->mMapData : nullptr);
    const float waterElevation = (mapData && mapData->IsWaterEnabled()) ? mapData->GetWaterElevation() : -10000.0f;
    const float terrainElevation =
      SampleHeightFieldBilinear((mapData ? mapData->GetHeightField() : nullptr), worldPos.x, worldPos.z);

    if (waterElevation <= terrainElevation) {
      return LAYER_Land;
    }

    if (HasOccupancyBit(footprint.mOccupancyCaps, static_cast<std::uint8_t>(EOccupancyCaps::OC_SUB)) &&
        !isExperimental) {
      return LAYER_Sub;
    }

    if (HasOccupancyBit(footprint.mOccupancyCaps, static_cast<std::uint8_t>(EOccupancyCaps::OC_WATER)) || isBeacon) {
      return LAYER_Water;
    }

    return LAYER_Seabed;
  }

  /**
   * Address: 0x00678D40
   *
   * What it does:
   * Base error text provider for script/runtime diagnostics.
   */
  msvc8::string Entity::GetErrorDescription()
  {
    return {};
  }

  /**
   * Address: 0x005BDB10
   */
  Unit* Entity::IsUnit()
  {
    return nullptr;
  }

  /**
   * Address: 0x005BDB20
   */
  Prop* Entity::IsProp()
  {
    return nullptr;
  }

  /**
   * Address: 0x005BDB30
   */
  Projectile* Entity::IsProjectile()
  {
    return nullptr;
  }

  /**
   * Address: 0x00672BB0
   */
  ReconBlip* Entity::IsReconBlip()
  {
    return nullptr;
  }

  /**
   * Address: 0x005BDB40
   */
  CollisionBeamEntity* Entity::IsCollisionBeam()
  {
    return nullptr;
  }

  /**
   * Address: 0x005BDB50
   */
  Shield* Entity::IsShield()
  {
    return nullptr;
  }

  /**
   * Address: 0x00678BB0
   *
   * What it does:
   * Returns mesh bone count from the loaded mesh skeleton block.
   */
  int Entity::GetBoneCount() const
  {
    if (!mMeshRef.mObj) {
      return 0;
    }

    const auto* const meshObject = static_cast<const MeshObjectBoneSpanView*>(mMeshRef.mObj);
    const MeshBoneEntryView* const begin = meshObject->boneBegin;
    const MeshBoneEntryView* const end = meshObject->boneEnd;
    if (!begin || !end || end < begin) {
      return 0;
    }

    return static_cast<int>(end - begin);
  }

  /**
   * Address: 0x00678B90 (FUN_00678B90, Moho::Entity::GetArmyIndex)
   *
   * What it does:
   * Returns the owning army id when present, otherwise `-1`.
   */
  int Entity::GetArmyIndex() const
  {
    return (ArmyRef != nullptr) ? ArmyRef->ArmyId : -1;
  }

  /**
   * Address: 0x00678CC0 (FUN_00678CC0, Moho::Entity::ResolveBoneIndex)
   *
   * What it does:
   * Resolves one bone-name token through the current SCM skeleton, returning
   * `-1` when the mesh/skeleton lane is missing.
   */
  int Entity::ResolveBoneIndex(const char* const boneName) const
  {
    auto* const scmResource = static_cast<RScmResource*>(mMeshRef.mObj);
    if (scmResource == nullptr) {
      return -1;
    }

    const boost::shared_ptr<const CAniSkel> skeleton = scmResource->GetSkeleton();
    const CAniSkel* const skel = skeleton.get();
    if (skel == nullptr) {
      return -1;
    }

    return skel->FindBoneIndex(boneName);
  }

  /**
   * Address: 0x005BDB60
   */
  bool Entity::IsBeingBuilt() const
  {
    return BeingBuilt != 0u;
  }

  /**
   * Address: 0x0067A0A0
   *
   * What it does:
   * Updates visibility + interface sync state and clears dirty-sync marker.
   */
  void Entity::Sync(SSyncData* syncData)
  {
    UpdateVisibility();

    if (mOnDestroyDispatched != 0u || mVisibilityState == 0u) {
      if (mInterfaceCreated != 0u) {
        DestroyInterface(syncData);
      }
    } else {
      if (mInterfaceCreated == 0u) {
        CreateInterface(syncData);
      }
      SyncInterface(syncData);
    }

    DirtySyncState = 0u;

    if (mQueueRelinkBlocked == 0u) {
      mCoordNode.ListUnlink();
    }
  }

  /**
   * Address: 0x0067A720 (FUN_0067A720)
   *
   * What it does:
   * Resolves mesh resource id (or explicit placeholder) and updates mesh binding.
   */
  void
  Entity::SetMesh(const RResId& meshResId, RMeshBlueprint* explicitPlaceholder, const bool allowExplicitPlaceholder)
  {
    RMeshBlueprint* meshBlueprint = nullptr;

    if (SimulationRef && SimulationRef->mRules && !meshResId.name.empty()) {
      meshBlueprint = SimulationRef->mRules->GetMeshBlueprint(meshResId);
    }

    if (!meshBlueprint && allowExplicitPlaceholder) {
      meshBlueprint = explicitPlaceholder;
    }

    mMeshRef.mObj = meshBlueprint;
    mMeshRef.mType = nullptr;
    mMeshTypeClassId = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(meshBlueprint));

    if (!meshBlueprint && !meshResId.name.empty()) {
      gpg::Warnf("Failed to load mesh for blueprint %s", meshResId.name.raw_data_unsafe());
    }
  }

  /**
   * Address: 0x005BDBD0
   */
  float Entity::GetUniformScale() const
  {
    return 1.0f;
  }

  /**
   * Address: 0x00678DC0
   *
   * What it does:
   * Returns frame velocity from current/previous positions scaled by mVelocityScale.
   */
  Wm3::Vec3f Entity::GetVelocity() const
  {
    Wm3::Vec3f velocity{};
    velocity.x = (Position.x - PrevPosition.x) * mVelocityScale;
    velocity.y = (Position.y - PrevPosition.y) * mVelocityScale;
    velocity.z = (Position.z - PrevPosition.z) * mVelocityScale;
    return velocity;
  }

  /**
   * Address: 0x005BDBF0
   */
  bool Entity::IsMobile() const
  {
    return true;
  }

  /**
   * Address: 0x00679F70
   *
   * What it does:
   * CTask execution entry point, forwarding to motion tick logic.
   */
  int Entity::Execute()
  {
    return MotionTick();
  }

  /**
   * Address: 0x00679CE0
   *
   * What it does:
   * Returns world transform for the requested bone (or entity/world-anchor fallback).
   */
  VTransform Entity::GetBoneWorldTransform(const int boneIndex) const
  {
    VTransform result = BuildVTransformFromEntityTransformPayload(ReadEntityTransformPayload(Orientation, Position));

    if (boneIndex != -1 || !BluePrint) {
      return result;
    }

    const Wm3::Vector3f localAnchor{
      BluePrint->mCollisionOffsetX,
      BluePrint->mCollisionOffsetY + BluePrint->mSizeY * 0.5f,
      BluePrint->mCollisionOffsetZ,
    };
    const Wm3::Vector3f rotatedOffset = RotateVectorByQuaternion(Orientation, localAnchor);
    result.pos_.x += rotatedOffset.x;
    result.pos_.y += rotatedOffset.y;
    result.pos_.z += rotatedOffset.z;
    return result;
  }

  /**
   * Address: 0x00679E20
   *
   * What it does:
   * Returns local-space transform for a bone index, with `-1` fallback to blueprint anchor.
   */
  VTransform Entity::GetBoneLocalTransform(const int boneIndex) const
  {
    VTransform result{};
    result.orient_.w = 1.0f;
    result.orient_.x = 0.0f;
    result.orient_.y = 0.0f;
    result.orient_.z = 0.0f;
    result.pos_.x = 0.0f;
    result.pos_.y = 0.0f;
    result.pos_.z = 0.0f;

    if (boneIndex == -1 && BluePrint) {
      result.pos_.x = BluePrint->mCollisionOffsetX;
      result.pos_.y = BluePrint->mCollisionOffsetY + BluePrint->mSizeY * 0.5f;
      result.pos_.z = BluePrint->mCollisionOffsetZ;
    }

    return result;
  }

  /**
   * Address: 0x00679120 (FUN_00679120, Moho::Entity::UpdateIntel)
   *
   * What it does:
   * Pushes current world position (with +1 Y probe offset) into intel manager
   * update path for the current simulation tick.
   */
  void Entity::UpdateIntel()
  {
    if (!mIntelManager || !SimulationRef) {
      return;
    }

    const Wm3::Vec3f probePosition{
      Position.x,
      Position.y + 1.0f,
      Position.z,
    };
    mIntelManager->Update(probePosition, static_cast<std::int32_t>(SimulationRef->mCurTick));
  }

  /**
   * Address: 0x00679290 (FUN_00679290, ?GetPhysBody@Entity@Moho@@QAEPAUSPhysBody@2@_N@Z)
   * Mangled: ?GetPhysBody@Entity@Moho@@QAEPAUSPhysBody@2@_N@Z
   *
   * What it does:
   * Returns cached physics body, lazily constructing it from blueprint-derived
   * mass/inertia/collision-offset lanes and current entity transform when absent.
   */
  SPhysBody* Entity::GetPhysBody(const bool unusedFlag)
  {
    (void)unusedFlag;

    SPhysBody*& cachedBody = AccessEntityPhysBody(*this);
    if (cachedBody != nullptr) {
      return cachedBody;
    }

    float mass = 1.0f;
    Wm3::Vector3f inertiaTensor{1.0f, 1.0f, 1.0f};
    Wm3::Vector3f collisionOffset{};
    if (BluePrint != nullptr) {
      collisionOffset.x = BluePrint->mCollisionOffsetX;
      collisionOffset.y = (BluePrint->mSizeY * 0.5f) + BluePrint->mCollisionOffsetY;
      collisionOffset.z = BluePrint->mCollisionOffsetZ;
      mass = (BluePrint->mAverageDensity * BluePrint->mSizeZ) * BluePrint->mSizeX * BluePrint->mSizeY;
      inertiaTensor.x = BluePrint->mInertiaTensorX;
      inertiaTensor.y = BluePrint->mInertiaTensorY;
      inertiaTensor.z = BluePrint->mInertiaTensorZ;
    }

    SPhysBody* const newBody = new (std::nothrow) SPhysBody{};
    if (newBody != nullptr) {
      newBody->mConstants = SimulationRef ? SimulationRef->mPhysConstants : nullptr;
      newBody->mMass = mass;
      newBody->mInvInertiaTensor.x = 1.0f / (mass * inertiaTensor.x);
      newBody->mInvInertiaTensor.y = 1.0f / (mass * inertiaTensor.y);
      newBody->mInvInertiaTensor.z = 1.0f / (mass * inertiaTensor.z);
      newBody->mCollisionOffset = collisionOffset;
      newBody->mPos = {};
      newBody->mOrientation = {1.0f, 0.0f, 0.0f, 0.0f};
      newBody->mVelocity = {};
      newBody->mWorldImpulse = {};

      const Wm3::Vector3f rotatedOffset = RotateVectorByQuaternion(Orientation, newBody->mCollisionOffset);
      newBody->mOrientation = {Orientation.x, Orientation.y, Orientation.z, Orientation.w};
      newBody->mPos.x = rotatedOffset.x + Position.x;
      newBody->mPos.y = rotatedOffset.y + Position.y;
      newBody->mPos.z = rotatedOffset.z + Position.z;
    }

    SPhysBody* const oldBody = cachedBody;
    cachedBody = newBody;
    delete oldBody;
    return cachedBody;
  }

  /**
   * Address: 0x00679210 (FUN_00679210)
   *
   * What it does:
   * Writes pending transform, advances twice, then updates entity intel manager.
   */
  void Entity::Warp(const VTransform& transform)
  {
    SetPendingTransform(transform, 1.0f);
    AdvanceCoords();
    AdvanceCoords();

    if (mIntelManager && SimulationRef) {
      const EntityTransformPayload current = ReadEntityTransformPayload(Orientation, Position);
      const Wm3::Vec3f probePosition{
        current.posX,
        current.posY + 1.0f,
        current.posZ,
      };
      mIntelManager->Update(probePosition, static_cast<std::int32_t>(SimulationRef->mCurTick));
    }
  }

  /**
   * Address: 0x00678E90 (FUN_00678E90, ?SetPendingTransform@Entity@Moho@@QAEXABVVTransform@2@M@Z)
   *
   * What it does:
   * Stores pending transform/scalar and links the coord-node into Sim list
   * when it is currently detached.
   */
  void Entity::SetPendingTransform(const VTransform& transform, const float pendingVelocityScale)
  {
    const EntityTransformPayload pending = ReadEntityTransformPayload(transform);
    WriteEntityTransformPayload(PendingOrientation, PendingPosition, pending);
    mPendingVelocityScale = pendingVelocityScale;

    if (SimulationRef && mCoordNode.ListIsSingleton()) {
      mCoordNode.ListLinkBefore(&SimulationRef->mCoordEntities);
    }
  }

  /**
   * Address: 0x00679F70
   *
   * What it does:
   * Advances the active motor when not attached; returns engine task status code.
   */
  int Entity::MotionTick()
  {
    if (!mAttachInfo.HasAttachTarget()) {
      if (!mMotor) {
        return -2;
      }

      mMotor->Update(this);
    }

    return 1;
  }

  /**
   * Address: 0x00679FA0 (FUN_00679FA0)
   *
   * What it does:
   * Replaces entity motor from auto_ptr handoff storage.
   */
  void Entity::SetMotor(msvc8::auto_ptr<EntityMotor>& motor)
  {
    EntityMotor* const newMotor = motor.release();
    EntityMotor* oldMotor = mMotor;
    mMotor = newMotor;

    if (oldMotor) {
      delete oldMotor;
    }

    if (mMotor) {
      mMotor->BindEntity(this);
    }
  }

  /**
   * Address: 0x005BDC10
   */
  msvc8::vector<Entity*>& Entity::GetAttachedEntities()
  {
    return mAttachedEntities;
  }

  /**
   * Address: 0x0067A220
   */
  void Entity::CreateInterface(SSyncData*)
  {
    mInterfaceCreated = 1u;
  }

  /**
   * Address: 0x0067A260
   */
  void Entity::DestroyInterface(SSyncData*)
  {
    mInterfaceCreated = 0u;
  }

  /**
   * Address: 0x0067A290
   */
  void Entity::SyncInterface(SSyncData*)
  {
    // 0x0067A290 serializes interface visibility channels into sync payload.
  }

  /**
   * Address: 0x00679550 (FUN_00679550)
   *
   * What it does:
   * Validates parent attach chain, appends this entity to parent attached-list,
   * repairs queued runtime-link state, then applies attach payload into `mAttachInfo`.
   */
  bool Entity::AttachTo(const SEntAttachInfo& attachInfo)
  {
    if (mAttachInfo.HasAttachTarget()) {
      return false;
    }

    Entity* const parent = attachInfo.GetAttachTargetEntity();
    if (!parent) {
      return false;
    }

    for (Entity* ancestor = parent; ancestor != nullptr; ancestor = ancestor->mAttachInfo.GetAttachTargetEntity()) {
      if (ancestor == this) {
        return false;
      }
      if (!ancestor->mAttachInfo.HasAttachTarget()) {
        break;
      }
    }

    msvc8::vector<Entity*>& parentChildren = parent->GetAttachedEntities();
    if (std::find(parentChildren.begin(), parentChildren.end(), this) != parentChildren.end()) {
      return false;
    }

    parentChildren.push_back(this);
    ResetAttachRuntimeNodeIfQueued(this);
    ApplyAttachInfo(mAttachInfo, attachInfo);
    return true;
  }

  /**
   * Address: 0x006796F0 (FUN_006796F0)
   *
   * What it does:
   * Removes this entity from parent attached-list and applies detached defaults
   * to the local attach-info block.
   */
  bool Entity::DetachFrom(Entity* parent, bool)
  {
    if (!parent) {
      return false;
    }

    msvc8::vector<Entity*>& parentChildren = parent->GetAttachedEntities();
    for (Entity** it = parentChildren.begin(); it != parentChildren.end(); ++it) {
      if (*it != this) {
        continue;
      }

      parentChildren.erase(it);

      SEntAttachInfo detached = SEntAttachInfo::MakeDetached();
      ApplyAttachInfo(mAttachInfo, detached);

      return true;
    }

    return false;
  }

  /**
   * Address: 0x006797E0
   */
  void Entity::AttachedEntityDestroyed(Entity*)
  {
    CallbackStr("OnAttachedDestroyed");
  }

  /**
   * Address: 0x00679800
   */
  void Entity::AttachedEntityKilled(Entity*)
  {
    CallbackStr("OnAttachedKilled");
  }

  /**
   * Address: 0x00679820
   */
  void Entity::ParentEntityDestroyed(Entity*)
  {
    CallbackStr("OnParentDestroyed");
  }

  /**
   * Address: 0x00679840
   */
  void Entity::ParentEntityKilled(Entity*)
  {
    CallbackStr("OnParentKilled");
  }

  /**
   * Address: 0x005BDC20
   */
  float Entity::Materialize(float)
  {
    return 0.0f;
  }

  /**
   * Address: 0x00679940
   *
   * What it does:
   * Sets absolute health, triggers OnHealthChanged on 0.25-step bucket changes,
   * and ensures the coord-node is queued into Sim coord list.
   */
  void Entity::SetHealth(const float newHealth)
  {
    if (MaxHealth <= 0.0f) {
      Health = newHealth;
      return;
    }

    const float invMaxHealth = 1.0f / MaxHealth;
    const float prevBucket = std::floor(invMaxHealth * Health * 4.0f) * 0.25f;
    const float nextBucket = std::floor(invMaxHealth * newHealth * 4.0f) * 0.25f;

    Health = newHealth;

    if (nextBucket != prevBucket) {
      CallbackStr("OnHealthChanged");
    }

    if (SimulationRef && mCoordNode.ListIsSingleton()) {
      mCoordNode.ListLinkBefore(&SimulationRef->mCoordEntities);
    }
  }

  /**
   * Address: 0x00679860
   *
   * What it does:
   * Applies delta health with dead/heal guard and clamp to [0, MaxHealth].
   */
  void Entity::AdjustHealth(Entity*, const float delta)
  {
    if (std::isnan(delta) || delta == 0.0f) {
      return;
    }

    if (Dead && delta > 0.0f) {
      return;
    }

    float next = Health + delta;
    if (next > MaxHealth) {
      next = MaxHealth;
    }
    if (next < 0.0f) {
      next = 0.0f;
    }

    if (next != Health) {
      SetHealth(next);
    }
  }

  /**
   * Address: 0x00679A80
   *
   * What it does:
   * Dispatches attached/parent killed notifications and marks entity dead/dirty.
   */
  void Entity::Kill(Entity*, gpg::StrArg, float)
  {
    Entity* const parent = mAttachInfo.GetAttachTargetEntity();
    if (parent) {
      parent->AttachedEntityKilled(this);
    }

    for (Entity* child : mAttachedEntities) {
      if (child) {
        child->ParentEntityKilled(this);
      }
    }

    DirtySyncState = 1;
    Dead = 1;
  }

  /**
   * Address: 0x00679B80 (FUN_00679B80)
   *
   * What it does:
   * Marks destroy dispatch, queues this entity in Sim destroy queue, emits script
   * callback, detaches from parent, and notifies attached children.
   */
  void Entity::OnDestroy()
  {
    mOnDestroyDispatched = 1;
    QueueEntityForDestroy(this);
    CallbackStr("OnDestroy");

    Entity* const parent = mAttachInfo.GetAttachTargetEntity();
    if (parent) {
      parent->AttachedEntityDestroyed(this);
      (void)DetachFrom(parent, false);
    }

    for (Entity* child : mAttachedEntities) {
      if (child) {
        child->ParentEntityDestroyed(this);
      }
    }
  }

  /**
   * Address: 0x00679AF0 (FUN_00679AF0, ?Destroy@Entity@Moho@@QAEXXZ)
   *
   * What it does:
   * Marks this entity as destroy-queued once, enqueues it into `Sim::mDeletionQueue`,
   * logs the queue event, and moves the coord node to the sim coord tail list.
   */
  void Entity::Destroy()
  {
    if (DestroyQueuedFlag != 0u) {
      return;
    }

    DestroyQueuedFlag = 1u;
    SimulationRef->mDeletionQueue.push_back(this);
    SimulationRef->Logf("Entity 0x%08x queued for delete.\n", static_cast<unsigned int>(id_));

    mCoordNode.ListLinkBefore(&SimulationRef->mCoordEntities);
  }

  /**
   * Address: 0x006791D0 (FUN_006791D0)
   *
   * What it does:
   * Pushes current transform to collision primitive, relinks collision-cell
   * bucket membership, and refreshes cached world-space bounds at +0x240.
   */
  void Entity::UpdateCollision()
  {
    if (!CollisionExtents) {
      return;
    }

    auto* collision = CollisionExtents;
    const EntityTransformPayload current = ReadEntityTransformPayload(Orientation, Position);
    collision->SetTransform(current);
    RelinkSpanFromCollisionPrimitive(mCollisionCellSpan, collision);
    RefreshCollisionBoundsSnapshot(*this);
  }

  /**
   * Address: 0x0067AC40 (FUN_0067AC40)
   *
   * What it does:
   * Builds a box collision primitive from supplied local box and installs it.
   */
  void Entity::SetCollisionBoxShape(const Wm3::Box3f& localBox)
  {
    InstallCollisionPrimitiveAndRefresh(*this, new BoxCollisionPrimitive(localBox));
  }

  /**
   * Address: 0x0067AD30 (FUN_0067AD30)
   *
   * What it does:
   * Builds a sphere collision primitive from local center/radius and installs it.
   */
  void Entity::SetCollisionSphereShape(const Wm3::Vec3f& localCenter, const float radius)
  {
    InstallCollisionPrimitiveAndRefresh(*this, new SphereCollisionPrimitive(localCenter, radius));
  }

  /**
   * Address: 0x0067AE00 (FUN_0067AE00)
   *
   * What it does:
   * Clears active collision primitive and resets collision-cell span to zero.
   */
  void Entity::RevertCollisionShape()
  {
    InstallCollisionPrimitiveAndRefresh(*this, nullptr);
  }

  /**
   * Address: 0x0067AE70 (FUN_0067AE70)
   *
   * What it does:
   * Recreates collision primitive from blueprint shape descriptor.
   */
  void Entity::RefreshCollisionShapeFromBlueprint()
  {
    if (!BluePrint) {
      RevertCollisionShape();
      return;
    }

    switch (BluePrint->mCollisionShape) {
    case COLSHAPE_None:
      RevertCollisionShape();
      break;
    case COLSHAPE_Box:
      SetCollisionBoxShape(BuildBlueprintCollisionBox(*BluePrint));
      break;
    case COLSHAPE_Sphere:
      SetCollisionSphereShape(BuildBlueprintCollisionCenter(*BluePrint), BluePrint->mSizeX * 0.5f);
      break;
    default:
      break;
    }
  }

  void Entity::MarkNeedsSyncGameData() noexcept
  {
    DirtySyncState = 1;
  }

  /**
   * Address: 0x00689F20 (FUN_00689F20, Moho::Entity::GetUniqueName)
   *
   * What it does:
   * Returns the entity's unique runtime name string.
   */
  msvc8::string Entity::GetUniqueName() const
  {
    return msvc8::string(mUniqueName.data(), mUniqueName.size());
  }

  /**
   * Address: 0x00678880 (FUN_00678880, ?GetFootprint@Entity@Moho@@QBEABUSFootprint@2@XZ)
   *
   * What it does:
   * Returns active footprint (default or alt footprint).
   * Throws when blueprint pointer is missing.
   */
  const SFootprint& Entity::GetFootprint() const
  {
    if (!BluePrint) {
      throw std::runtime_error("Attempt to get footprint on nameless entity");
    }

    const bool useAlt = (mUseAltFootprint != 0u) || (mUseAltFootprintSecondary != 0u);
    return useAlt ? BluePrint->mAltFootprint : BluePrint->mFootprint;
  }

  /**
   * Address: 0x0067AFF0 (FUN_0067AFF0, ?SetCurrentLayer@Entity@Moho@@QAEXW4ELayer@2@@Z)
   *
   * What it does:
   * Updates current layer and issues `OnLayerChange(new, old)` callback.
   */
  void Entity::SetCurrentLayer(const ELayer newLayer)
  {
    const ELayer oldLayer = mCurrentLayer;
    mCurrentLayer = newLayer;
    if (newLayer == oldLayer) {
      return;
    }

    const char* oldName = LayerToString(oldLayer);
    const char* newName = LayerToString(newLayer);
    const char* newNameArg = newName;
    const char* oldNameArg = oldName;
    CallbackStr("OnLayerChange", &newNameArg, &oldNameArg);
  }

  /**
   * Address: 0x0067B050 (FUN_0067B050)
   *
   * What it does:
   * Resolves category text through Sim rules and tests the blueprint category bit.
   */
  bool Entity::IsInCategory(const char* categoryName) const noexcept
  {
    if (!categoryName || !BluePrint || !SimulationRef || !SimulationRef->mRules) {
      return false;
    }

    const CategoryWordRangeView* const range = SimulationRef->mRules->GetEntityCategory(categoryName);
    if (!range) {
      return false;
    }

    const std::uint32_t bitIndex = ReadBlueprintCategoryBitIndex(BluePrint);
    const auto wordIt = range->FindWord(bitIndex >> 5u);
    if (wordIt == range->cend()) {
      return false;
    }

    return (((*wordIt) >> (bitIndex & 0x1Fu)) & 1u) != 0u;
  }

  /**
   * Address: 0x0067B0C0 (FUN_0067B0C0, ?SetStrategicUnderlay@Entity@Moho@@QAEXABVRResId@2@@Z)
   *
   * What it does:
   * Resolves one strategic underlay icon id into
   * `/textures/ui/common/game/strategicicons/<icon>_rest.dds`,
   * updates the underlay texture pointer, and relinks this entity in the
   * coord-entities update list.
   */
  void Entity::SetStrategicUnderlay(const RResId& underlayId)
  {
    if (underlayId.name.empty()) {
      mStrategicUnderlayTexture.reset();
      return;
    }

    const char* const underlayName = underlayId.name.c_str();
    if (FILE_IsAbsolute(underlayName)) {
      return;
    }

    std::string underlayPath("/textures/ui/common/game/strategicicons/");
    underlayPath.append(underlayName, std::strlen(underlayName));
    underlayPath.append("_rest.dds", 9u);

    mStrategicUnderlayTexture = CD3DBatchTexture::FromFile(underlayPath.c_str(), 0u);

    mCoordNode.ListLinkBefore(&SimulationRef->mCoordEntities);
  }

  Wm3::Vec3f const& Entity::GetPositionWm3() const noexcept
  {
    return *reinterpret_cast<Wm3::Vec3f const*>(&Position);
  }

  VTransform const& Entity::GetTransformWm3() const noexcept
  {
    return *reinterpret_cast<VTransform const*>(&Orientation);
  }

  /**
   * Address: 0x00678800 (FUN_00678800, ?InitPositionHistory@Entity@Moho@@QAEXXZ)
   *
   * What it does:
   * Rebuilds the rolling position-history ring with identity/default samples.
   */
  void Entity::InitPositionHistory()
  {
    PositionHistory* const rebuiltHistory = new (std::nothrow) PositionHistory;
    if (rebuiltHistory) {
      InitializePositionHistory(*rebuiltHistory);
    }

    delete mPositionHistory;
    mPositionHistory = rebuiltHistory;
  }

  /**
   * Address: 0x00678F10 (FUN_00678F10, ?AdvanceCoords@Entity@Moho@@QAEXXZ)
   *
   * What it does:
   * Commits pending transform to current, archives previous/current snapshots,
   * updates collision when movement changed, runs intel force-update pass,
   * then relinks coord node into Sim's coord-entities list when needed.
   */
  void Entity::AdvanceCoords()
  {
    const EntityTransformPayload previous = ReadEntityTransformPayload(Orientation, Position);
    const EntityTransformPayload current = ReadEntityTransformPayload(PendingOrientation, PendingPosition);

    WriteEntityTransformPayload(PrevOrientation, PrevPosition, previous);
    WriteEntityTransformPayload(Orientation, Position, current);
    mVelocityScale = mPendingVelocityScale;

    if (mPositionHistory) {
      RecordEntityPositionHistory(*mPositionHistory, previous, current);
    }

    if (CollisionExtents &&
        (EntityTransformPositionDiffers(current, previous) || EntityTransformOrientationDiffers(current, previous))) {
      UpdateCollision();
    }

    if (mIntelManager && SimulationRef) {
      const Wm3::Vec3f probePosition{
        current.posX,
        current.posY + 1.0f,
        current.posZ,
      };
      mIntelManager->ForceUpdate(probePosition, static_cast<std::int32_t>(SimulationRef->mCurTick));
    }

    if (SimulationRef && mCoordNode.ListIsSingleton()) {
      mCoordNode.ListLinkBefore(&SimulationRef->mCoordEntities);
    }
  }

  /**
   * Address: 0x00678A70
   *
   * What it does:
   * Resolves entity visibility channel for current sync context.
   */
  void Entity::UpdateVisibility()
  {
    int resolvedLayer = mVisibilityLayerDefault;
    if (ArmyRef) {
      if (SimulationRef && SimulationRef->mSyncArmy == -1) {
        resolvedLayer = mVisibilityLayerFriendly;
      }
    }

    mFootprintLayer = resolvedLayer;
    mVisibilityState = static_cast<std::uint8_t>(resolvedLayer != static_cast<int>(LAYER_Land));
  }

  /**
   * Address: 0x00678930 (FUN_00678930, Moho::Entity::SetVizToFocusPlayer)
   *
   * What it does:
   * Updates focus-player visibility mode, refreshes derived visibility state,
   * and queues this entity in Sim coord-visibility refresh list when needed.
   */
  void Entity::SetVizToFocusPlayer(const EVisibilityMode mode)
  {
    mVisibilityLayerFriendly = static_cast<std::int32_t>(mode);
    UpdateVisibility();
    if (SimulationRef != nullptr && mCoordNode.ListIsSingleton()) {
      mCoordNode.ListLinkBefore(&SimulationRef->mCoordEntities);
    }
  }

  /**
   * Address: 0x00678980 (FUN_00678980, Moho::Entity::SetVizToEnemies)
   *
   * What it does:
   * Updates enemy visibility mode, refreshes derived visibility state,
   * and queues this entity in Sim coord-visibility refresh list when needed.
   */
  void Entity::SetVizToEnemies(const EVisibilityMode mode)
  {
    mVisibilityLayerEnemy = static_cast<std::int32_t>(mode);
    UpdateVisibility();
    if (SimulationRef != nullptr && mCoordNode.ListIsSingleton()) {
      mCoordNode.ListLinkBefore(&SimulationRef->mCoordEntities);
    }
  }

  /**
   * Address: 0x006789D0 (FUN_006789D0, Moho::Entity::SetVizToAllies)
   *
   * What it does:
   * Updates allied visibility mode, refreshes derived visibility state,
   * and queues this entity in Sim coord-visibility refresh list when needed.
   */
  void Entity::SetVizToAllies(const EVisibilityMode mode)
  {
    mVisibilityLayerDefault = static_cast<std::int32_t>(mode);
    UpdateVisibility();
    if (SimulationRef != nullptr && mCoordNode.ListIsSingleton()) {
      mCoordNode.ListLinkBefore(&SimulationRef->mCoordEntities);
    }
  }

  /**
   * Address: 0x00678A20 (FUN_00678A20, Moho::Entity::SetVizToNeutrals)
   *
   * What it does:
   * Updates neutral visibility mode, refreshes derived visibility state,
   * and queues this entity in Sim coord-visibility refresh list when needed.
   */
  void Entity::SetVizToNeutrals(const EVisibilityMode mode)
  {
    mVisibilityLayerNeutral = static_cast<std::int32_t>(mode);
    UpdateVisibility();
    if (SimulationRef != nullptr && mCoordNode.ListIsSingleton()) {
      mCoordNode.ListLinkBefore(&SimulationRef->mCoordEntities);
    }
  }

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
      SimLuaInitSet(),
      kEntityCreateProjectileName,
      &cfunc_EntityCreateProjectile,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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

    RResId projectileId{};
    gpg::STR_InitFilename(&projectileId.name, projectileBlueprintName);

    RProjectileBlueprint* const projectileBlueprint =
      (sim && sim->mRules) ? sim->mRules->GetProjectileBlueprint(projectileId) : nullptr;
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
      launchDirection = BuildRandomProjectileDirection(sim ? sim->mRngState : nullptr, *projectileBlueprint);
    }

    const VTransform sourceTransform = entity->GetBoneWorldTransform(-2);

    VTransform launchTransform{};
    launchTransform.orient_ = COORDS_Orient(launchDirection);
    launchTransform.pos_.x = sourceTransform.pos_.x + launchOffset.x;
    launchTransform.pos_.y = sourceTransform.pos_.y + launchOffset.y;
    launchTransform.pos_.z = sourceTransform.pos_.z + launchOffset.z;

    const CAiTarget target = MakeDefaultProjectileTarget();
    const msvc8::string damageTypeName("Normal");

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
      SimLuaInitSet(),
      kEntityCreateProjectileAtBoneName,
      &cfunc_EntityCreateProjectileAtBone,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 3) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityCreateProjectileAtBoneHelpText, 3, argumentCount);
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    LuaPlus::LuaStackObject blueprintArg(state, 2);
    const char* projectileBlueprintName = lua_tostring(rawState, 2);
    if (!projectileBlueprintName) {
      blueprintArg.TypeError("string");
      projectileBlueprintName = "";
    }

    RResId projectileId{};
    gpg::STR_InitFilename(&projectileId.name, projectileBlueprintName);

    RProjectileBlueprint* const projectileBlueprint =
      (entity && entity->SimulationRef && entity->SimulationRef->mRules)
        ? entity->SimulationRef->mRules->GetProjectileBlueprint(projectileId)
        : nullptr;
    if (!projectileBlueprint) {
      const msvc8::string message = gpg::STR_Printf("CreateProjectileAtBone: Invalid blueprint %s", projectileBlueprintName);
      lua_pushstring(rawState, message.c_str());
      (void)lua_gettop(rawState);
      lua_error(rawState);
      return 0;
    }

    LuaPlus::LuaStackObject boneArg(state, 3);
    const int boneIndex = ENTSCR_ResolveBoneIndex(entity, boneArg, false);

    const VTransform launchTransform = entity->GetBoneWorldTransform(boneIndex);

    CRandomStream* const random = (entity->SimulationRef ? entity->SimulationRef->mRngState : nullptr);
    Wm3::Vector3f launchDirection = BuildRandomProjectileDirection(random, *projectileBlueprint);

    const Wm3::Vector3f zero = Wm3::Vector3f::Zero();
    if (!Wm3::Vector3f::Compare(&launchDirection, &zero)) {
      launchDirection = ResolveBoneForwardVector(launchTransform);
    }

    const float launchSpeed =
      projectileBlueprint->Physics.InitialSpeed + SampleSymmetricRange(random, projectileBlueprint->Physics.InitialSpeedRange);

    const CAiTarget target = MakeDefaultProjectileTarget();
    const msvc8::string damageTypeName("Normal");

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

    Wm3::Vector3f& projectileVelocity = AccessProjectileVelocity(*projectile);
    projectileVelocity.x = launchDirection.x * launchSpeed;
    projectileVelocity.y = launchDirection.y * launchSpeed;
    projectileVelocity.z = launchDirection.z * launchSpeed;
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
      SimLuaInitSet(),
      kEntityShakeCameraName,
      &cfunc_EntityShakeCamera,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 5) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityShakeCameraHelpText, 5, argumentCount);
    }

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
      SyncCameraShakeRequest request{};
      request.centerX = entity->Position.x;
      request.centerY = entity->Position.y;
      request.centerZ = entity->Position.z;
      request.radius = radius;
      request.maxIntensity = maxIntensity;
      request.minIntensity = minIntensity;
      request.durationSeconds = durationSeconds;
      func_ShakeCamera(*sim, request);
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
      SimLuaInitSet(),
      kGetBlueprintSimName,
      &cfunc_GetBlueprintSim,
      nullptr,
      "<global>",
      kGetBlueprintSimHelpText
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
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetBlueprintSimHelpText, 1, argumentCount);
    }

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
      SimLuaInitSet(),
      kEntityGetAIBrainName,
      &cfunc_EntityGetAIBrain,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityGetAIBrainHelpText, 1, argumentCount);
    }

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
      SimLuaInitSet(),
      kEntityGetBlueprintName,
      &cfunc_EntityGetBlueprint,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityGetBlueprintHelpText, 1, argumentCount);
    }

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
      SimLuaInitSet(),
      kEntityGetArmyName,
      &cfunc_EntityGetArmy,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityGetArmyHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    int armyIndex = -1;
    if (entity != nullptr && entity->ArmyRef != nullptr) {
      armyIndex = entity->ArmyRef->ArmyId;
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
      SimLuaInitSet(),
      kEntityGetBoneDirectionName,
      &cfunc_EntityGetBoneDirection,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
   */
  int cfunc_EntityGetBoneDirectionL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityGetBoneDirectionHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    LuaPlus::LuaStackObject boneArg(state, 2);
    const int boneIndex = ENTSCR_ResolveBoneIndex(entity, boneArg, false);
    const VTransform boneTransform = entity->GetBoneWorldTransform(boneIndex);

    const Wm3::Vector3f forwardAxis{0.0f, 0.0f, 1.0f};
    const Wm3::Vector3f direction = boneTransform.orient_.Rotate(forwardAxis);

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
      SimLuaInitSet(),
      kEntityIsValidBoneName,
      &cfunc_EntityIsValidBone,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
      SimLuaInitSet(),
      kEntityGetBoneCountName,
      &cfunc_EntityGetBoneCount,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityGetBoneCountHelpText, 1, argumentCount);
    }

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
      SimLuaInitSet(),
      kEntityGetBoneNameName,
      &cfunc_EntityGetBoneName,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityGetBoneNameHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    const LuaPlus::LuaStackObject boneIndexArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      boneIndexArg.TypeError("integer");
    }

    const int boneIndex = static_cast<int>(lua_tonumber(rawState, 2));
    const char* const boneName = ResolveMeshBoneName(entity, boneIndex);
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
      SimLuaInitSet(),
      kEntityRequestRefreshUIName,
      &cfunc_EntityRequestRefreshUI,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityRequestRefreshUIHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);
    entity->DirtySyncState = 1;
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
      SimLuaInitSet(),
      kEntityAttachBoneToName,
      &cfunc_EntityAttachBoneTo,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
      SimLuaInitSet(),
      kEntitySetParentOffsetName,
      &cfunc_EntitySetParentOffset,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntitySetParentOffsetHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);
    if (entity->mAttachInfo.GetAttachTargetEntity() == nullptr) {
      LuaPlus::LuaState::Error(state, "SetParentOffset: Entity has no parent.");
    }

    const LuaPlus::LuaObject parentOffsetObject(LuaPlus::LuaStackObject(state, 2));
    const Wm3::Vector3f parentOffset = SCR_FromLuaCopy<Wm3::Vector3f>(parentOffsetObject);

    entity->mAttachInfo.mRelativeOrientX = 1.0f;
    entity->mAttachInfo.mRelativeOrientY = 0.0f;
    entity->mAttachInfo.mRelativeOrientZ = 0.0f;
    entity->mAttachInfo.mRelativeOrientW = 0.0f;
    entity->mAttachInfo.mRelativePosX = parentOffset.x;
    entity->mAttachInfo.mRelativePosY = parentOffset.y;
    entity->mAttachInfo.mRelativePosZ = parentOffset.z;
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
      SimLuaInitSet(),
      kEntityDetachFromName,
      &cfunc_EntityDetachFrom,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    if (Entity* const parent = entity->mAttachInfo.GetAttachTargetEntity(); parent != nullptr) {
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
      SimLuaInitSet(),
      kEntityGetParentName,
      &cfunc_EntityGetParent,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityGetParentHelpText, 1, argumentCount);
    }

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
      SimLuaInitSet(),
      kEntityGetCollisionExtentsName,
      &cfunc_EntityGetCollisionExtents,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
      SimLuaInitSet(),
      kEntityPlaySoundName,
      &cfunc_EntityPlaySound,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityPlaySoundHelpText, 2, argumentCount);
    }

    Sim* const sim = lua_getglobaluserdata(rawState);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    const LuaPlus::LuaObject paramsObject(LuaPlus::LuaStackObject(state, 2));
    CSndParams* const params = ResolveSoundParamsFromLuaObject(paramsObject);

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
      SimLuaInitSet(),
      kEntitySetAmbientSoundName,
      &cfunc_EntitySetAmbientSound,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 3) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntitySetAmbientSoundHelpText, 3, argumentCount);
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    CSndParams* ambientSound = nullptr;
    if (lua_type(rawState, 2) != LUA_TNIL) {
      const LuaPlus::LuaObject ambientObject(LuaPlus::LuaStackObject(state, 2));
      ambientSound = ResolveSoundParamsFromLuaObject(ambientObject);
    }

    CSndParams* rumbleSound = nullptr;
    if (lua_type(rawState, 3) != LUA_TNIL) {
      const LuaPlus::LuaObject rumbleObject(LuaPlus::LuaStackObject(state, 3));
      rumbleSound = ResolveSoundParamsFromLuaObject(rumbleObject);
    }

    entity->mAmbientSound = ambientSound;
    entity->mRumbleSound = rumbleSound;
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
      SimLuaInitSet(),
      kEntityGetFractionCompleteName,
      &cfunc_EntityGetFractionComplete,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityGetFractionCompleteHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);
    lua_pushnumber(rawState, entity->FractionCompleted);
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
      SimLuaInitSet(),
      kEntityAdjustHealthName,
      &cfunc_EntityAdjustHealth,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 3) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityAdjustHealthHelpText, 3, argumentCount);
    }

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
      SimLuaInitSet(),
      kEntityGetHealthName,
      &cfunc_EntityGetHealth,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityGetHealthHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);
    lua_pushnumber(rawState, entity->Health);
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
      SimLuaInitSet(),
      kEntityGetMaxHealthName,
      &cfunc_EntityGetMaxHealth,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityGetMaxHealthHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);
    lua_pushnumber(rawState, entity->MaxHealth);
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
      SimLuaInitSet(),
      kEntitySetHealthName,
      &cfunc_EntitySetHealth,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 3) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntitySetHealthHelpText, 3, argumentCount);
    }

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
    entity->AdjustHealth(instigator, targetHealth - entity->Health);
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
      SimLuaInitSet(),
      kEntitySetMaxHealthName,
      &cfunc_EntitySetMaxHealth,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntitySetMaxHealthHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    LuaPlus::LuaStackObject maxHealthArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      maxHealthArg.TypeError("number");
    }
    entity->MaxHealth = static_cast<float>(lua_tonumber(rawState, 2));
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
      SimLuaInitSet(),
      kEntitySetVizToFocusPlayerName,
      &cfunc_EntitySetVizToFocusPlayer,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
      SimLuaInitSet(),
      kEntitySetVizToEnemiesName,
      &cfunc_EntitySetVizToEnemies,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
      SimLuaInitSet(),
      kEntitySetVizToAlliesName,
      &cfunc_EntitySetVizToAllies,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
      SimLuaInitSet(),
      kEntitySetVizToNeutralsName,
      &cfunc_EntitySetVizToNeutrals,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
      SimLuaInitSet(),
      kEntityGetEntityIdName,
      &cfunc_EntityGetEntityId,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityGetEntityIdHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);
    const msvc8::string entityIdText = gpg::STR_Printf("%d", static_cast<int>(entity->id_));
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
      SimLuaInitSet(),
      kEntityDetachAllName,
      &cfunc_EntityDetachAll,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    const msvc8::vector<Entity*> attachedSnapshot(args.entity->GetAttachedEntities());

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
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 4) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityAttachBoneToHelpText, 4, argumentCount);
    }

    const LuaPlus::LuaObject childObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const childEntity = SCR_FromLua_Entity(childObject, state);

    LuaPlus::LuaStackObject childBoneArg(state, 2);
    const int childBoneIndex = ENTSCR_ResolveBoneIndex(childEntity, childBoneArg, true);

    const LuaPlus::LuaObject parentObject(LuaPlus::LuaStackObject(state, 3));
    Entity* const parentEntity = SCR_FromLua_Entity(parentObject, state);

    LuaPlus::LuaStackObject parentBoneArg(state, 4);
    const int parentBoneIndex = ENTSCR_ResolveBoneIndex(parentEntity, parentBoneArg, true);

    const float relativeTransform[7] = {
      1.0f, // orientation lane #0 (as copied by FUN_005E3B50)
      0.0f,
      0.0f,
      0.0f,
      0.0f,
      0.0f,
      0.0f,
    };

    SEntAttachInfo attachInfo = BuildAttachInfoFromBones(parentEntity, childBoneIndex, parentBoneIndex, relativeTransform);
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
      SimLuaInitSet(),
      kEntitySetCollisionShapeName,
      &cfunc_EntitySetCollisionShape,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
      entity->RevertCollisionShape();
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
      SimLuaInitSet(),
      kEntityReachedMaxShootersName,
      &cfunc_EntityReachedMaxShooters,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityReachedMaxShootersHelpText, 1, argumentCount);
    }

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
      SimLuaInitSet(),
      kEntityGetOrientationName,
      &cfunc_EntityGetOrientation,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityGetOrientationHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    const EntityTransformPayload current = ReadEntityTransformPayload(entity->Orientation, entity->Position);
    Wm3::Quaternionf orientation{};
    orientation.w = current.quatW;
    orientation.x = current.quatX;
    orientation.y = current.quatY;
    orientation.z = current.quatZ;

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
      SimLuaInitSet(),
      kEntityGetHeadingName,
      &cfunc_EntityGetHeading,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityGetHeadingHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    const EntityTransformPayload current = ReadEntityTransformPayload(entity->Orientation, entity->Position);
    const float numerator = 2.0f * ((current.quatW * current.quatY) + (current.quatX * current.quatZ));
    const float denominator = 1.0f - (2.0f * ((current.quatZ * current.quatZ) + (current.quatY * current.quatY)));
    const double heading = std::atan2(static_cast<double>(numerator), static_cast<double>(denominator));
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
      SimLuaInitSet(),
      kEntityGetScaleName,
      &cfunc_EntityGetScale,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityGetScaleHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);
    lua_pushnumber(rawState, entity->mDrawScaleX);
    lua_pushnumber(rawState, entity->mDrawScaleY);
    lua_pushnumber(rawState, entity->mDrawScaleZ);
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
      SimLuaInitSet(),
      kEntityAddLocalImpulseName,
      &cfunc_EntityAddLocalImpulse,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
   * Converts local impulse+point into world space and applies it to entity
   * physics body state when present.
   */
  int cfunc_EntityAddLocalImpulseL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 7) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityAddLocalImpulseHelpText, 7, argumentCount);
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);
    moho::SPhysBody* const body = AccessEntityPhysBody(*entity);
    if (body != nullptr) {
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

      Wm3::Vector3f worldPoint{};
      Wm3::MultiplyQuaternionVector(&worldPoint, localPoint, body->mOrientation);
      worldPoint.x += body->mPos.x;
      worldPoint.y += body->mPos.y;
      worldPoint.z += body->mPos.z;

      Wm3::Vector3f worldImpulse{};
      Wm3::MultiplyQuaternionVector(&worldImpulse, localImpulse, body->mOrientation);
      ApplyWorldImpulseToBody(*body, worldImpulse, worldPoint);
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
      SimLuaInitSet(),
      kEntityAddWorldImpulseName,
      &cfunc_EntityAddWorldImpulse,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 7) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityAddWorldImpulseHelpText, 7, argumentCount);
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);
    moho::SPhysBody* const body = AccessEntityPhysBody(*entity);
    if (body != nullptr) {
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
      ApplyWorldImpulseToBody(*body, impulse, worldPoint);
    }

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
      SimLuaInitSet(),
      kEntitySetMeshName,
      &cfunc_EntitySetMesh,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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

    const msvc8::string meshResourcePath(meshName);
    const std::string meshPathStd = meshResourcePath.to_std();
    if (meshPathStd.find("<none>") == std::string::npos) {
      const bool keepActor = LuaPlus::LuaStackObject(state, 3).GetBoolean();
      const bool allowExplicitPlaceholder = !keepActor;

      msvc8::string normalizedPath;
      gpg::STR_CopyFilename(&normalizedPath, &meshResourcePath);

      RResId meshResourceId{};
      meshResourceId.name = normalizedPath;
      entity->SetMesh(meshResourceId, nullptr, allowExplicitPlaceholder);

      if (!meshResourcePath.empty() && entity->mMeshRef.mObj == nullptr) {
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
      SimLuaInitSet(),
      kEntitySetScaleName,
      &cfunc_EntitySetScale,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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

    entity->mDrawScaleX = scaleX;
    entity->mDrawScaleY = scaleY;
    entity->mDrawScaleZ = scaleZ;
    entity->mCoordNode.ListLinkBefore(&entity->SimulationRef->mCoordEntities);

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
      SimLuaInitSet(),
      kEntityAddManualScrollerName,
      &cfunc_EntityAddManualScroller,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 3) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityAddManualScrollerHelpText, 3, argumentCount);
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);
    TextureScrollerRuntimeView* const scroller = EnsureEntityTextureScroller(*entity);

    TextureScrollerDefinition definition{};
    definition.mType = static_cast<std::int32_t>(TextureScrollerMode::Manual);
    definition.mFloat04 = ReadLuaNumberArgument(state, 2);
    definition.mFloat08 = ReadLuaNumberArgument(state, 3);
    definition.mFloat24 = 1.0f;
    definition.mFloat28 = 1.0f;
    ApplyTextureScrollerDefinition(*scroller, definition);

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
      SimLuaInitSet(),
      kEntityAddThreadScrollerName,
      &cfunc_EntityAddThreadScroller,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 3) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityAddThreadScrollerHelpText, 3, argumentCount);
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);
    TextureScrollerRuntimeView* const scroller = EnsureEntityTextureScroller(*entity);

    TextureScrollerDefinition definition{};
    definition.mType = static_cast<std::int32_t>(TextureScrollerMode::Thread);
    definition.mFloat24 = ReadLuaNumberArgument(state, 2);
    definition.mFloat28 = ReadLuaNumberArgument(state, 3);
    ApplyTextureScrollerDefinition(*scroller, definition);

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
      SimLuaInitSet(),
      kEntityAddPingPongScrollerName,
      &cfunc_EntityAddPingPongScroller,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 9) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityAddPingPongScrollerHelpText, 9, argumentCount);
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);
    TextureScrollerRuntimeView* const scroller = EnsureEntityTextureScroller(*entity);

    TextureScrollerDefinition definition{};
    definition.mType = static_cast<std::int32_t>(TextureScrollerMode::PingPong);
    definition.mFloat04 = ReadLuaNumberArgument(state, 3);
    definition.mFloat08 = ReadLuaNumberArgument(state, 5);
    definition.mFloat0C = ReadLuaNumberArgument(state, 7);
    definition.mFloat10 = ReadLuaNumberArgument(state, 9);
    definition.mScroll1.x = ReadLuaNumberArgument(state, 2);
    definition.mScroll1.y = ReadLuaNumberArgument(state, 6);
    definition.mScroll2.x = ReadLuaNumberArgument(state, 4);
    definition.mScroll2.y = ReadLuaNumberArgument(state, 8);
    definition.mFloat24 = 1.0f;
    definition.mFloat28 = 1.0f;
    ApplyTextureScrollerDefinition(*scroller, definition);

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
      SimLuaInitSet(),
      kEntityRemoveScrollerName,
      &cfunc_EntityRemoveScroller,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityRemoveScrollerHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);
    TextureScrollerRuntimeView* const scroller = EnsureEntityTextureScroller(*entity);
    InitializeTextureScrollerRuntime(*scroller, entity);
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
      SimLuaInitSet(),
      kEntityDestroyName,
      &cfunc_EntityDestroy,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityDestroyHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLuaNoError_Entity(entityObject);
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
      SimLuaInitSet(),
      kEntityBeenDestroyedName,
      &cfunc_EntityBeenDestroyed,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityBeenDestroyedHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLuaNoError_Entity(entityObject);
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
      SimLuaInitSet(),
      kEntityKillName,
      &cfunc_EntityKill,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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

    if (entity != nullptr && entity->Dead != 0u) {
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
      SimLuaInitSet(),
      kEntitySetDrawScaleName,
      &cfunc_EntitySetDrawScale,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntitySetDrawScaleHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    LuaPlus::LuaStackObject scaleArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      scaleArg.TypeError("number");
    }

    const float drawScale = static_cast<float>(lua_tonumber(rawState, 2));
    entity->mDrawScaleX = drawScale;
    entity->mDrawScaleY = drawScale;
    entity->mDrawScaleZ = drawScale;
    entity->mCoordNode.ListLinkBefore(&entity->SimulationRef->mCoordEntities);
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

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityFallDownHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    MotorFallDown* const motor = new MotorFallDown(state);
    motor->mLuaObj.PushStack(state);

    msvc8::auto_ptr<EntityMotor> motorOwnership(motor);
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
      SimLuaInitSet(),
      kEntityFallDownName,
      &cfunc_EntityFallDown,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
      kEntityLuaClassName,
      kEntityFallDownHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00695740 (FUN_00695740, func_MotorFallDownWhack_LuaFuncDef)
   *
   * What it does:
   * Publishes the `MotorFallDown:Whack(nx,ny,nz,f,dobreak)` Lua binder.
   */
  CScrLuaInitForm* func_MotorFallDownWhack_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kMotorFallDownWhackName,
      &cfunc_MotorFallDownWhack,
      &CScrLuaMetatableFactory<MotorFallDown>::Instance(),
      "MotorFallDown",
      kMotorFallDownWhackHelpText
    );
    return &binder;
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
      SimLuaInitSet(),
      kEntitySinkAwayName,
      &cfunc_EntitySinkAway,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
      kEntityLuaClassName,
      kEntitySinkAwayHelpText
    );
    return &binder;
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
      SimLuaInitSet(),
      kEntityPushOverName,
      &cfunc_EntityPushOver,
      &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
      kEntityLuaClassName,
      kEntityPushOverHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00692580 (FUN_00692580, Moho::ENTSCR_ResolveBoneIndex)
   *
   * What it does:
   * Resolves one Lua bone identifier (integer index, string name, or optional
   * nil lane) into one validated entity bone index.
   */
  int ENTSCR_ResolveBoneIndex(
    Entity* const entity,
    LuaPlus::LuaStackObject& boneIdentifier,
    const bool allowNilAndSpecialIndices
  )
  {
    if (!entity || !boneIdentifier.m_state || !boneIdentifier.m_state->m_state) {
      return -1;
    }

    LuaPlus::LuaState* const state = boneIdentifier.m_state;
    lua_State* const rawState = state->m_state;
    const int stackIndex = boneIdentifier.m_stackIndex;

    if (lua_type(rawState, stackIndex) == LUA_TNUMBER) {
      if (lua_type(rawState, stackIndex) != LUA_TNUMBER) {
        boneIdentifier.TypeError("integer");
      }

      const int boneIndex = static_cast<int>(lua_tonumber(rawState, stackIndex));
      const int minBoneIndex = allowNilAndSpecialIndices ? -2 : 0;
      const int boneCount = entity->GetBoneCount();
      if (boneIndex < minBoneIndex || boneIndex >= boneCount) {
        LuaPlus::LuaState::Error(
          state,
          "Invalid bone index of %d; must be bettern %d (inclusive) and %d (exclusive)",
          boneIndex,
          minBoneIndex,
          boneCount
        );
      }
      return boneIndex;
    }

    if (lua_isstring(rawState, stackIndex) != 0) {
      const char* boneName = lua_tostring(rawState, stackIndex);
      if (!boneName) {
        boneIdentifier.TypeError("string");
        boneName = "";
      }

      const int boneIndex = entity->ResolveBoneIndex(boneName);
      if (boneIndex < 0) {
        LuaPlus::LuaState::Error(state, "Invalid bone name \"%s\".", boneIdentifier.GetString());
      }
      return boneIndex;
    }

    if (allowNilAndSpecialIndices) {
      if (lua_type(rawState, stackIndex) == LUA_TNIL) {
        return -1;
      }

      LuaPlus::LuaState::Error(state, "Invalid bone identifier; must be a string or integer");
      return -1;
    }

    LuaPlus::LuaState::Error(state, "Invalid bone identifier; must be a string, integer, or nil");
    return -1;
  }

  /**
   * Address: 0x0050B480 (FUN_0050B480, ?COORDS_Orient@Moho@@YA?AV?$Quaternion@M@Wm3@@ABV?$Vector3@M@3@@Z)
   *
   * What it does:
   * Builds an orientation quaternion whose forward axis follows `direction`,
   * with fixed fallback quaternions for zero-length and vertical vectors.
   */
  Wm3::Quaternionf COORDS_Orient(const Wm3::Vector3f& direction) noexcept
  {
    Wm3::Vector3f forward = direction;
    if (Wm3::Vector3f::Normalize(&forward) == 0.0f) {
      return Wm3::Quaternionf::Identity();
    }

    Wm3::Vector3f right{forward.z, 0.0f, -forward.x};
    if (Wm3::Vector3f::Normalize(&right) == 0.0f) {
      constexpr float kHalfSqrtTwo = 0.70710677f;
      const float yLane = direction.y > 0.0f ? -kHalfSqrtTwo : kHalfSqrtTwo;
      return Wm3::Quaternionf{0.0f, kHalfSqrtTwo, yLane, 0.0f};
    }

    const Wm3::Vector3f up{
      (forward.y * right.z) - (forward.z * right.y),
      (forward.z * right.x) - (right.z * forward.x),
      (right.y * forward.x) - (forward.y * right.x),
    };

    const float m00 = right.x;
    const float m01 = right.y;
    const float m02 = right.z;
    const float m10 = up.x;
    const float m11 = up.y;
    const float m12 = up.z;
    const float m20 = forward.x;
    const float m21 = forward.y;
    const float m22 = forward.z;

    Wm3::Quaternionf orientation{};
    const float trace = m00 + m11 + m22;
    if (trace > 0.0f) {
      const float s = std::sqrt(trace + 1.0f) * 2.0f;
      orientation.w = 0.25f * s;
      orientation.x = (m21 - m12) / s;
      orientation.y = (m02 - m20) / s;
      orientation.z = (m10 - m01) / s;
    } else if (m00 > m11 && m00 > m22) {
      const float s = std::sqrt(1.0f + m00 - m11 - m22) * 2.0f;
      orientation.w = (m21 - m12) / s;
      orientation.x = 0.25f * s;
      orientation.y = (m01 + m10) / s;
      orientation.z = (m02 + m20) / s;
    } else if (m11 > m22) {
      const float s = std::sqrt(1.0f + m11 - m00 - m22) * 2.0f;
      orientation.w = (m02 - m20) / s;
      orientation.x = (m01 + m10) / s;
      orientation.y = 0.25f * s;
      orientation.z = (m12 + m21) / s;
    } else {
      const float s = std::sqrt(1.0f + m22 - m00 - m11) * 2.0f;
      orientation.w = (m10 - m01) / s;
      orientation.x = (m02 + m20) / s;
      orientation.y = (m12 + m21) / s;
      orientation.z = 0.25f * s;
    }

    (void)orientation.Normalize();
    return orientation;
  }

  /**
   * Address: 0x0050B820 (FUN_0050B820, ?COORDS_Tilt@Moho@@YAXPAV?$Quaternion@M@Wm3@@V?$Vector3@M@3@@Z)
   *
   * What it does:
   * Tilts one orientation so its local up-axis aligns to `surfaceNormal`,
   * preserving heading by pre-multiplying one shortest-arc delta quaternion.
   */
  void COORDS_Tilt(Wm3::Quaternionf* const orientation, Wm3::Vector3f surfaceNormal) noexcept
  {
    if (orientation == nullptr) {
      return;
    }

    if (Wm3::Vector3f::Normalize(&surfaceNormal) <= 0.0f) {
      return;
    }

    const Wm3::Quaternionf oldOrientation = *orientation;
    const Wm3::Vector3f currentUp{
      ((oldOrientation.y * oldOrientation.x) - (oldOrientation.w * oldOrientation.z)) * 2.0f,
      1.0f - (((oldOrientation.z * oldOrientation.z) + (oldOrientation.x * oldOrientation.x)) * 2.0f),
      ((oldOrientation.z * oldOrientation.y) + (oldOrientation.w * oldOrientation.x)) * 2.0f,
    };

    Wm3::Quaternionf tiltDelta{};
    QuatCrossAdd(&tiltDelta, currentUp, surfaceNormal);
    *orientation = Wm3::Quaternionf::Multiply(tiltDelta, oldOrientation);
  }

  /**
   * Address: 0x0050AE10 (FUN_0050AE10, ?COORDS_StringToLayer@Moho@@YA?AW4ELayer@1@PBD@Z)
   *
   * What it does:
   * Maps canonical layer text names to enum lanes and returns `LAYER_None`
   * when no supported name matches.
   */
  ELayer COORDS_StringToLayer(const char* const layerName) noexcept
  {
    if (_stricmp(layerName, "Land") == 0) {
      return LAYER_Land;
    }
    if (_stricmp(layerName, "Seabed") == 0) {
      return LAYER_Seabed;
    }
    if (_stricmp(layerName, "Sub") == 0) {
      return LAYER_Sub;
    }
    if (_stricmp(layerName, "Water") == 0) {
      return LAYER_Water;
    }
    if (_stricmp(layerName, "Air") == 0) {
      return LAYER_Air;
    }
    return _stricmp(layerName, "Orbit") == 0 ? LAYER_Orbit : LAYER_None;
  }

  /**
   * Address: 0x0050B0F0 (FUN_0050B0F0, ?COORDS_ToWorldPos@Moho@@YA?AV?$Vector3@M@Wm3@@PBVSTIMap@1@ABUSOCellPos@1@EHH@Z)
   *
   * What it does:
   * Converts one footprint-origin cell position into world center position and
   * samples terrain/water elevation by requested layer.
   */
  Wm3::Vector3f
  COORDS_ToWorldPos(const STIMap* const map, const SOCellPos& cellPos, const ELayer layer, const int sizeX, const int sizeZ) noexcept
  {
    Wm3::Vector3f outPos{};
    const float worldX = static_cast<float>(cellPos.x) + (static_cast<float>(sizeX) * 0.5f);
    const float worldZ = static_cast<float>(cellPos.z) + (static_cast<float>(sizeZ) * 0.5f);
    outPos.x = worldX;
    outPos.z = worldZ;

    const CHeightField* const field = map->mHeightField.get();
    const float terrainElevation = field->GetElevation(worldX, worldZ);
    if ((static_cast<std::int32_t>(layer) & static_cast<std::int32_t>(LAYER_Seabed)) != 0 || map->mWaterEnabled == 0u) {
      outPos.y = terrainElevation;
    } else {
      outPos.y = (map->mWaterElevation > terrainElevation) ? map->mWaterElevation : terrainElevation;
    }

    return outPos;
  }

  /**
   * Address: 0x0050B1A0 (FUN_0050B1A0, ?COORDS_ToWorldPos@Moho@@YA?AV?$Vector3@M@Wm3@@PBVSTIMap@1@ABUSOCellPos@1@ABUSFootprint@1@@Z)
   *
   * What it does:
   * Convenience overload that converts one cell position using a footprint's
   * layer and dimensions.
   */
  Wm3::Vector3f COORDS_ToWorldPos(const STIMap* const map, const SOCellPos& cellPos, const SFootprint& footprint) noexcept
  {
    return COORDS_ToWorldPos(
      map,
      cellPos,
      static_cast<ELayer>(static_cast<std::uint8_t>(footprint.mOccupancyCaps)),
      static_cast<int>(footprint.mSizeX),
      static_cast<int>(footprint.mSizeZ)
    );
  }

  /**
   * Address: 0x0050B260 (FUN_0050B260, ?COORDS_GridSnap@Moho@@YA?AV?$Vector3@M@Wm3@@PBVSTIMap@1@ABUSCoordsVec2@1@ABUSFootprint@1@W4ELayer@1@@Z)
   *
   * What it does:
   * Snaps one world XZ center to footprint-origin cell coordinates and returns
   * the corresponding world-aligned snapped position.
   */
  Wm3::Vector3f
  COORDS_GridSnap(const STIMap* const map, const SCoordsVec2& worldPos, const SFootprint& footprint, ELayer layer) noexcept
  {
    if (layer == LAYER_None) {
      layer = static_cast<ELayer>(static_cast<std::uint8_t>(footprint.mOccupancyCaps));
    }

    SOCellPos cellPos{};
    cellPos.x = static_cast<std::int16_t>(static_cast<int>(worldPos.x - (static_cast<float>(footprint.mSizeX) * 0.5f)));
    cellPos.z = static_cast<std::int16_t>(static_cast<int>(worldPos.z - (static_cast<float>(footprint.mSizeZ) * 0.5f)));
    return COORDS_ToWorldPos(
      map,
      cellPos,
      layer,
      static_cast<int>(footprint.mSizeX),
      static_cast<int>(footprint.mSizeZ)
    );
  }

  /**
   * Address: 0x0050AD80 (FUN_0050AD80, ?COORDS_LayerToString@Moho@@YAPBDW4ELayer@1@@Z)
   *
   * What it does:
   * Maps canonical single-layer enum values to their text names and returns an
   * empty string for mixed-bit layer masks.
   */
  const char* Entity::LayerToString(const ELayer layer) noexcept
  {
    switch (layer) {
    case LAYER_None:
      return "None";
    case LAYER_Land:
      return "Land";
    case LAYER_Seabed:
      return "Seabed";
    case LAYER_Sub:
      return "Sub";
    case LAYER_Water:
      return "Water";
    case LAYER_Air:
      return "Air";
    case LAYER_Orbit:
      return "Orbit";
    default:
      return "";
    }
  }
} // namespace moho

