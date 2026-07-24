#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/ai/CAiTarget.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/misc/WeakPtr.h"
#include "moho/script/CScriptEvent.h"
#include "moho/serialization/SBlackListInfo.h"
#include "moho/sim/EImpactTypeTypeInfo.h"
#include "moho/unit/core/CWeaponAttributes.h"
#include "Wm3Vector3.h"
#include "Wm3Quaternion.h"
#include "boost/shared_ptr.h"

struct lua_State;
namespace LuaPlus
{
  class LuaState;
}

namespace moho
{
  class CAiAttackerImpl;
  class CFireWeaponTask;
  class Entity;
  class IAiAttacker;
  class Projectile;
  class RD3DTextureResource;
  struct RProjectileBlueprint;
  struct RUnitBlueprintWeapon;
  class Sim;
  class Unit;
  class UnitWeapon;

  /**
   * Collision candidate lane used by beam-impact filtering.
   *
   * Address evidence:
   * - `UnitWeapon::GetClosestCollision` (0x006D6A00) iterates 0x20-byte entries
   *   with `entity` at +0x00 and hit distance at +0x1C.
   */
  struct WeaponCollisionEntry
  {
    Entity* entity;              // +0x00
    Wm3::Vector3f collisionAxis; // +0x04
    Wm3::Vector3f contactPoint;  // +0x10
    float dist;                  // +0x1C
  };
  static_assert(sizeof(WeaponCollisionEntry) == 0x20, "WeaponCollisionEntry size must be 0x20");
  static_assert(offsetof(WeaponCollisionEntry, entity) == 0x00, "WeaponCollisionEntry::entity offset must be 0x00");
  static_assert(offsetof(WeaponCollisionEntry, dist) == 0x1C, "WeaponCollisionEntry::dist offset must be 0x1C");

  using WeaponCollisionEntryVec = gpg::fastvector_n<WeaponCollisionEntry, 10>;

  enum class ESolutionStatus : std::int32_t
  {
    TRS_Available = 0,
    TRS_InsideMinRange = 1,
    TRS_NoSolution = 2,
    TRS_OutsideMaxRange = 3,
  };
  static_assert(sizeof(ESolutionStatus) == 0x04, "ESolutionStatus size must be 0x04");

  /**
   * One-segment world-space beam ray (origin + unit direction) carried inside a
   * `CollisionBeamHelper`. Distinct from `moho::GeomLine3` (which adds
   * `closest`/`farthest` clip bounds); this is just the placed beam center line.
   */
  struct WeaponBeamLine
  {
    Wm3::Vector3f Origin;    // +0x00
    Wm3::Vector3f Direction; // +0x0C
  };
  static_assert(sizeof(WeaponBeamLine) == 0x18, "WeaponBeamLine size must be 0x18");

  /**
   * Transient beam-impact resolution payload built by
   * `UnitWeapon::CreateCollisionBeamHelper` and consumed by
   * `CollisionBeamEntity::CheckCollision` / `UnitWeapon::DoInstaHit`. Carries the
   * resolved impact entity/target, contact point, beam length, impact type, and
   * the placed beam center line. Holds two intrusive weak-entity links
   * (`mTarget.targetEntity` and `mEntity`) that the destructor unlinks.
   *
   * Address evidence:
   * - ctor body inside `CreateCollisionBeamHelper` (0x006D6B00) writes these
   *   offsets directly; destructor at 0x00673580.
   */
  struct CollisionBeamHelper
  {
    /**
     * Address: 0x006D6B00 sub-flow (inline init inside CreateCollisionBeamHelper)
     *
     * What it does:
     * Zero-initializes the impact lane, copy-binds the source target, and resets
     * the resolved-impact weak-entity link.
     */
    CollisionBeamHelper();

    /**
     * Address: 0x00673580 (FUN_00673580, Moho::CollisionBeamHelper::~CollisionBeamHelper)
     *
     * What it does:
     * Unlinks the resolved-impact and bound-target weak-entity links from their
     * owner chains before teardown.
     */
    ~CollisionBeamHelper();

    CollisionBeamHelper(const CollisionBeamHelper&) = delete;
    CollisionBeamHelper& operator=(const CollisionBeamHelper&) = delete;

    EImpactType mImpactType;     // +0x00
    CAiTarget mTarget;           // +0x04
    WeakPtr<Entity> mEntity;     // +0x24
    Wm3::Vector3f mPos;          // +0x2C
    float mBeamLength;           // +0x38
    WeaponBeamLine mLine;        // +0x3C
    float mLineScale;            // +0x54
  };
  static_assert(sizeof(CollisionBeamHelper) == 0x58, "CollisionBeamHelper size must be 0x58");
  static_assert(offsetof(CollisionBeamHelper, mImpactType) == 0x00, "CollisionBeamHelper::mImpactType offset must be 0x00");
  static_assert(offsetof(CollisionBeamHelper, mTarget) == 0x04, "CollisionBeamHelper::mTarget offset must be 0x04");
  static_assert(offsetof(CollisionBeamHelper, mEntity) == 0x24, "CollisionBeamHelper::mEntity offset must be 0x24");
  static_assert(offsetof(CollisionBeamHelper, mPos) == 0x2C, "CollisionBeamHelper::mPos offset must be 0x2C");
  static_assert(offsetof(CollisionBeamHelper, mBeamLength) == 0x38, "CollisionBeamHelper::mBeamLength offset must be 0x38");
  static_assert(offsetof(CollisionBeamHelper, mLine) == 0x3C, "CollisionBeamHelper::mLine offset must be 0x3C");
  static_assert(offsetof(CollisionBeamHelper, mLineScale) == 0x54, "CollisionBeamHelper::mLineScale offset must be 0x54");

  class UnitWeapon : public CScriptEvent
  {
  public:
    static gpg::RType* sType;
    static gpg::RType* sPointerType;

    /**
     * Address: 0x006D4100 (FUN_006D4100, sub_6D4100)
     *
     * What it does:
     * Initializes UnitWeapon runtime lanes, category filters, and default target
     * state for weapon task dispatch.
     */
    UnitWeapon();

    /**
     * Address: 0x006D4310 (FUN_006D4310, Moho::UnitWeapon::UnitWeapon)
     *
     * What it does:
     * Binds this weapon to one attacker/blueprint lane, allocates its fire
     * task thread, creates Lua script instance state, and applies parsed
     * target-restriction category filters.
     */
    UnitWeapon(CAiAttackerImpl* attackerImpl, RUnitBlueprintWeapon* weaponBlueprint, int weaponIndex);

    /**
     * Address: 0x006D4A90 (FUN_006D4A90, Moho::UnitWeapon::~UnitWeapon)
     *
     * What it does:
     * Releases the owned fire-task lane before member/base teardown.
     */
    ~UnitWeapon() override;

    /**
     * Address: 0x0062FD70 (FUN_0062FD70, Moho::UnitWeapon::GetLabel)
     *
     * What it does:
     * Copies this weapon label text into caller-provided output storage.
     */
    msvc8::string* GetLabel(msvc8::string* outLabel) const;

    /**
     * Address: 0x006A4C70 (FUN_006A4C70, Moho::UnitWeapon::GetCat1)
     *
     * What it does:
     * Copies this weapon primary target category set into caller-provided
     * output storage.
     */
    EntityCategorySet* GetCat1(EntityCategorySet* outCategory) const;

    /**
     * Address: 0x006A4CA0 (FUN_006A4CA0, Moho::UnitWeapon::GetCat2)
     *
     * What it does:
     * Copies secondary category filter payload into caller-provided storage.
     */
    EntityCategorySet* GetCat2(EntityCategorySet* outCategory) const;

    /**
     * Address: 0x006A4C60 (FUN_006A4C60, Moho::UnitWeapon::GetBone)
     *
     * What it does:
     * Returns the configured muzzle/bone index lane.
     */
    [[nodiscard]] std::int32_t GetBone() const;

    /**
     * Address: 0x006D34B0 (FUN_006D34B0)
     *
     * What it does:
     * Lazily resolves and caches reflected RTTI for `UnitWeapon`.
     */
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x005DCD70 (FUN_005DCD70, Moho::UnitWeapon::GetPointerType)
     *
     * What it does:
     * Lazily resolves and caches reflected RTTI for `UnitWeapon*`.
     */
    [[nodiscard]] static gpg::RType* GetPointerType();

    /**
     * Address: 0x006D3540 (FUN_006D3540)
     *
     * What it does:
     * Sets weapon firing-randomness lane.
     */
    UnitWeapon* SetFiringRandomness(float value);

    /**
     * Address: 0x006D3550 (FUN_006D3550)
     *
     * What it does:
     * Returns current firing-randomness lane.
     */
    [[nodiscard]] float GetFiringRandomness() const;

    /**
     * Address: 0x006D3560 (FUN_006D3560)
     *
     * What it does:
     * Sets fire-target-layer caps and marks owner unit sync-data lane dirty.
     */
    UnitWeapon* SetFireTargetLayerCaps(ELayer layerMask);

    /**
     * Address: 0x006DF3A0 (FUN_006DF3A0, Moho::UnitWeapon::MemberDeserialize)
     *
     * What it does:
     * Loads the serialized `UnitWeapon` payload from archive storage.
     */
    void MemberDeserialize(gpg::ReadArchive& archive);

    /**
     * Address: 0x006DF6E0 (FUN_006DF6E0, Moho::UnitWeapon::MemberSerialize)
     *
     * What it does:
     * Saves the serialized `UnitWeapon` payload into archive storage.
     */
    void MemberSerialize(gpg::WriteArchive& archive) const;

    /**
     * Address: 0x006D5DE0 (FUN_006D5DE0, Moho::UnitWeapon::PickNewTargetAimSpot)
     *
     * What it does:
     * Logs and checksums current target lanes, then picks one target-point
     * according to weapon above/below-water targeting rules.
     */
    void PickNewTargetAimSpot();

    /**
     * Address: 0x006D64E0 (FUN_006D64E0, Moho::UnitWeapon::CreateProjectile)
     *
     * What it does:
     * Spawns one projectile from the requested muzzle bone and returns the
     * script projectile wrapper when creation succeeds.
     */
    Projectile* CreateProjectile(std::int32_t muzzleBoneIndex);

    /**
     * Address: 0x006D75D0 (FUN_006D75D0, Moho::UnitWeapon::DoInstaHit)
     *
     * Fires one instant-hit beam from `bone`: applies impact damage / shot-tracking
     * and spawns a one-shot white beam effect. `colorAndGlow` is the packed Lua
     * color+glow quaternion; `textureSheet` is the caller-owned texture handle (kept
     * alive across the call, otherwise unused -- the beam texture is hardcoded).
     */
    void DoInstaHit(
      const Wm3::Quaternionf& colorAndGlow,
      std::int32_t bone,
      float thickness,
      float lifetime,
      boost::shared_ptr<RD3DTextureResource> textureSheet
    );

    /**
     * Address: 0x006D5F30 (FUN_006D5F30, Moho::UnitWeapon::SetTarget)
     *
     * What it does:
     * Replaces this weapon's active AI target: fires lost/got-target scripts,
     * maintains the old/new target entities' shooter sets, updates the owning
     * unit's focus/target-blip lanes, re-aims, and restages the fire task.
     */
    void SetTarget(CAiTarget* target);

    /**
     * Address: 0x006D61F0 (FUN_006D61F0, Moho::UnitWeapon::Fire)
     *
     * What it does:
     * Performs one weapon fire: when the owner is unstunned, accounts realtime
     * shot/fire-range statistics (if enabled), runs the `OnFire` script, and
     * increments the shots-at-target counter.
     */
    void Fire();

    /**
     * Address: 0x006D6B00 (FUN_006D6B00, Moho::UnitWeapon::CreateCollisionBeamHelper)
     *
     * What it does:
     * Resolves one instant-beam collision result for the given muzzle bone:
     * places the beam center line, queries entity/terrain/water intersections,
     * and fills `outHelper` with the resolved contact entity, point, beam length,
     * and impact type.
     */
    void CreateCollisionBeamHelper(CollisionBeamHelper* outHelper, std::int32_t bone);

    /**
     * Address: 0x006D4740 (FUN_006D4740, Moho::UnitWeapon::CreateInstance)
     *
     * What it does:
     * Resolves weapon script class from blueprint label/index and binds one Lua
     * script instance for this weapon object.
     */
    void CreateInstance();

    /**
     * Address: 0x006D53C0 (FUN_006D53C0, Moho::UnitWeapon::ChangeProjectileBlueprint)
     *
     * What it does:
     * Resolves one projectile blueprint id text into a projectile blueprint
     * resource and updates this weapon's silo-dependent projectile lane.
     */
    void ChangeProjectileBlueprint(const msvc8::string& blueprint);

    /**
     * Address: 0x006D61E0 (FUN_006D61E0)
     *
     * What it does:
     * Dispatches the weapon script callback lane `OnGotTarget`.
     */
    void NotifyOnGotTarget();

    /**
     * Address: 0x006D5330 (FUN_006D5330, Moho::UnitWeapon::GetTransform)
     *
     * What it does:
     * Writes this weapon world position into caller-provided output storage,
     * using muzzle-bone transform when a valid muzzle bone is configured.
     */
    Wm3::Vector3f* GetTransform(Wm3::Vector3f* outPosition) const;

    /**
     * Address: 0x006D5720 (FUN_006D5720, Moho::UnitWeapon::CanAttackTarget)
     *
     * What it does:
     * Validates whether `weapon` can currently attack `target`, including
     * entity layer/category gates and ground water-surface layer gates.
     */
    [[nodiscard]] static bool CanAttackTarget(CAiTarget* target, UnitWeapon* weapon);

    /**
     * Address: 0x006D4C80 (FUN_006D4C80, Moho::UnitWeapon::CanFire)
     *
     * What it does:
     * Evaluates one weapon-owner fire gate lane (state, movement, water level,
     * bomb-drop release timing, and heading constraints) for one target payload.
     */
    [[nodiscard]] static bool CanFire(UnitWeapon* weapon, CAiTarget* targetData);

    /**
     * Address: 0x006D5500 (FUN_006D5500, Moho::UnitWeapon::CheckSilo)
     *
     * What it does:
     * Validates counted-projectile silo storage availability for this weapon.
     */
    [[nodiscard]] bool CheckSilo();

    /**
     * Address: 0x006D5810 (FUN_006D5810, Moho::UnitWeapon::TargetIsTooCloseMelee)
     *
     * What it does:
     * Evaluates melee-only collision/footprint reachability against one target
     * entity and returns one target-solution status lane.
     */
    [[nodiscard]] ESolutionStatus TargetIsTooCloseMelee(Entity* targetEntity);

    /**
     * Address: 0x006D5B40 (FUN_006D5B40, Moho::UnitWeapon::TargetSolutionStatusGun)
     *
     * What it does:
     * Evaluates one gun-target point against radius/height/heading constraints
     * and returns one target-solution status lane.
     */
    [[nodiscard]] ESolutionStatus TargetSolutionStatusGun(const Wm3::Vector3f* targetPosition, float* inOutDistanceSq);

    /**
     * Address: 0x006D5D40 (FUN_006D5D40, Moho::UnitWeapon::GetSolutionStatus)
     *
     * What it does:
     * Resolves one target entity into melee/gun solution-status logic for this
     * weapon.
     */
    [[nodiscard]] ESolutionStatus GetSolutionStatus(Entity* targetEntity);

    /**
     * Address: 0x006D5D80 (FUN_006D5D80, Moho::UnitWeapon::TargetIsTooClose)
     *
     * What it does:
     * Returns the current target-solution status for one AI target payload,
     * dispatching to melee or gun status lanes.
     */
    [[nodiscard]] ESolutionStatus TargetIsTooClose(CAiTarget* targetData);

    /**
     * Address: 0x006D6A00 (FUN_006D6A00, Moho::UnitWeapon::GetClosestCollision)
     *
     * What it does:
     * Scans collision candidates, applies script and ally filters, and returns
     * the nearest surviving collision lane.
     */
    [[nodiscard]] static WeaponCollisionEntry*
    GetClosestCollision(WeaponCollisionEntryVec* collisions, UnitWeapon* weapon, Unit* ownerUnit, bool ignoreAlly);

    /**
     * Address: 0x006D5200 (FUN_006D5200, sub_6D5200)
     *
     * What it does:
     * Computes this weapon forward vector from either owner transform or muzzle
     * bone world transform quaternion lanes.
     */
    [[nodiscard]] static Wm3::Vector3f GetForwardVector(const UnitWeapon* weapon);

    /**
     * Address: 0x006D78C0 (FUN_006D78C0, sub_6D78C0)
     *
     * What it does:
     * Returns whether `entity` is present in weapon blacklist rows.
     */
    [[nodiscard]] static bool IsEntityBlacklisted(const UnitWeapon* weapon, const Entity* entity);

  private:
    /**
     * Address: 0x006D78F0 (FUN_006D78F0, sub_6D78F0)
     *
     * What it does:
     * Ages the per-weapon target blacklist: decrements each row's remaining-tick
     * counter and erases rows whose entity is gone, has moved, or whose counter
     * has expired. Invoked by `SetTarget` whenever the active target changes.
     */
    void AgeBlacklist();

  public:
    Sim* mSim;                                  // +0x44
    RUnitBlueprintWeapon* mWeaponBlueprint;     // +0x48
    RProjectileBlueprint* mProjectileBlueprint; // +0x4C
    IAiAttacker* mAttacker;                     // +0x50
    CWeaponAttributes mAttributes;              // +0x54
    Unit* mUnit;                                // +0xA0
    std::int32_t mWeaponIndex;                  // +0xA4
    std::int32_t mBone;                         // +0xA8
    std::uint8_t mEnabled;                      // +0xAC
    std::uint8_t mPadAD[3];                     // +0xAD
    msvc8::string mLabel;                       // +0xB0
    CAiTarget mTarget;                          // +0xCC
    CFireWeaponTask* mFireWeaponTask;           // +0xEC
    std::uint8_t mCanFire;                      // +0xF0
    std::uint8_t mPadF1ToF7[7];                 // +0xF1
    EntityCategorySet mCat1;                    // +0xF8
    EntityCategorySet mCat2;                    // +0x120
    ELayer mFireTargetLayerCaps;                // +0x148
    float mFiringRandomness;                    // +0x14C
    msvc8::vector<EntityCategorySet> mTargetPriorities; // +0x150
    msvc8::vector<SBlackListInfo> mBlacklist;           // +0x160
    std::int32_t mUnknown170;                   // +0x170
    std::uint8_t mUnknown174;                   // +0x174
    std::uint8_t mPad175To177[3];               // +0x175
    Wm3::Vector3f mAimingAt;                    // +0x178
    std::int32_t mShotsAtTarget;                // +0x184
  };

  /**
   * Address: 0x006D7BD0 (FUN_006D7BD0, cfunc_UnitWeaponPlaySound)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponPlaySoundL`.
   */
  int cfunc_UnitWeaponPlaySound(lua_State* luaContext);

  /**
   * Address: 0x006D7BF0 (FUN_006D7BF0, func_UnitWeaponPlaySound_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:PlaySound(weapon,ParamTable)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponPlaySound_LuaFuncDef();

  /**
   * Address: 0x006D7C50 (FUN_006D7C50, cfunc_UnitWeaponPlaySoundL)
   *
   * What it does:
   * Resolves `(weapon, soundParams)` and queues one weapon-owner sound request.
   */
  int cfunc_UnitWeaponPlaySoundL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006D7D70 (FUN_006D7D70, cfunc_UnitWeaponSetEnabled)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponSetEnabledL`.
   */
  int cfunc_UnitWeaponSetEnabled(lua_State* luaContext);

  /**
   * Address: 0x006D7D90 (FUN_006D7D90, func_UnitWeaponSetEnabled_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:SetEnabled(enabled)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponSetEnabled_LuaFuncDef();

  /**
   * Address: 0x006D7DF0 (FUN_006D7DF0, cfunc_UnitWeaponSetEnabledL)
   *
   * What it does:
   * Updates enabled state and unstages the fire task thread when re-enabled.
   */
  int cfunc_UnitWeaponSetEnabledL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006D7F20 (FUN_006D7F20, func_UnitWeaponSetTargetEntity_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:SetTargetEntity(entity)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponSetTargetEntity_LuaFuncDef();

  /**
   * Address: 0x006D80E0 (FUN_006D80E0, func_UnitWeaponSetTargetGround_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:SetTargetGround(location)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponSetTargetGround_LuaFuncDef();

  /**
   * Address: 0x006D8340 (FUN_006D8340, func_UnitWeaponResetTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:ResetTarget()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponResetTarget_LuaFuncDef();

  /**
   * Address: 0x006D8490 (FUN_006D8490, cfunc_UnitWeaponCreateProjectile)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponCreateProjectileL`.
   */
  int cfunc_UnitWeaponCreateProjectile(lua_State* luaContext);

  /**
   * Address: 0x006D84B0 (FUN_006D84B0, func_UnitWeaponCreateProjectile_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:CreateProjectile(muzzlebone)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponCreateProjectile_LuaFuncDef();

  /**
   * Address: 0x006D8510 (FUN_006D8510, cfunc_UnitWeaponCreateProjectileL)
   *
   * What it does:
   * Resolves `(weapon, muzzlebone)`, spawns one projectile, and returns that
   * projectile Lua object when creation succeeds.
   */
  int cfunc_UnitWeaponCreateProjectileL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006D8630 (FUN_006D8630, func_UnitWeaponDoInstaHit_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:DoInstaHit(...)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponDoInstaHit_LuaFuncDef();

  /**
   * Address: 0x006D8C30 (FUN_006D8C30, func_UnitWeaponGetProjectileBlueprint_LuaFuncDef)
   *
   * What it does:
   * Publishes `blueprint = UnitWeapon:GetProjectileBlueprint()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponGetProjectileBlueprint_LuaFuncDef();

  /**
   * Address: 0x006D8D90 (FUN_006D8D90, func_UnitWeaponHasTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes `bool = UnitWeapon:HasTarget()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponHasTarget_LuaFuncDef();

  /**
   * Address: 0x006D8ED0 (FUN_006D8ED0, func_UnitWeaponFireWeapon_LuaFuncDef)
   *
   * What it does:
   * Publishes `bool = UnitWeapon:FireWeapon()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponFireWeapon_LuaFuncDef();

  /**
   * Address: 0x006D9170 (FUN_006D9170, func_UnitWeaponIsFireControl_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:IsFireControl(label)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponIsFireControl_LuaFuncDef();

  /**
   * Address: 0x006D9150 (FUN_006D9150, cfunc_UnitWeaponIsFireControl)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponIsFireControlL`.
   */
  int cfunc_UnitWeaponIsFireControl(lua_State* luaContext);

  /**
   * Address: 0x006D91D0 (FUN_006D91D0, cfunc_UnitWeaponIsFireControlL)
   *
   * What it does:
   * Compares one label string against `UnitWeapon::mLabel` (case-insensitive)
   * and pushes one boolean result.
   */
  int cfunc_UnitWeaponIsFireControlL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006D9330 (FUN_006D9330, func_UnitWeaponGetCurrentTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:GetCurrentTarget()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponGetCurrentTarget_LuaFuncDef();

  /**
   * Address: 0x006D94B0 (FUN_006D94B0, func_UnitWeaponGetCurrentTargetPos_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:GetCurrentTargetPos()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponGetCurrentTargetPos_LuaFuncDef();

  /**
   * Address: 0x006D9650 (FUN_006D9650, func_UnitWeaponCanFire_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:CanFire()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponCanFire_LuaFuncDef();

  /**
   * Address: 0x006DA500 (FUN_006DA500, func_UnitWeaponSetTargetingPriorities_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:SetTargetingPriorities(...)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponSetTargetingPriorities_LuaFuncDef();

  /**
   * Address: 0x006DA6D0 (FUN_006DA6D0, func_UnitWeaponGetFiringRandomness_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:GetFiringRandomness()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponGetFiringRandomness_LuaFuncDef();

  /**
   * Address: 0x006DA980 (FUN_006DA980, func_UnitWeaponGetFireClockPct_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:GetFireClockPct()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponGetFireClockPct_LuaFuncDef();

  /**
   * Address: 0x006DAB00 (FUN_006DAB00, func_UnitWeaponChangeProjectileBlueprint_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:ChangeProjectileBlueprint(...)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponChangeProjectileBlueprint_LuaFuncDef();

  /**
   * Address: 0x006DACA0 (FUN_006DACA0, func_UnitWeaponTransferTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:TransferTarget(...)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponTransferTarget_LuaFuncDef();

  /**
   * Address: 0x006DAE10 (FUN_006DAE10, func_UnitWeaponBeenDestroyed_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:BeenDestroyed()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponBeenDestroyed_LuaFuncDef();

  /**
   * Address: 0x006D8C10 (FUN_006D8C10, cfunc_UnitWeaponGetProjectileBlueprint)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponGetProjectileBlueprintL`.
   */
  int cfunc_UnitWeaponGetProjectileBlueprint(lua_State* luaContext);

  /**
   * Address: 0x006D8C90 (FUN_006D8C90, cfunc_UnitWeaponGetProjectileBlueprintL)
   *
   * What it does:
   * Pushes the current projectile blueprint Lua table for this weapon.
   */
  int cfunc_UnitWeaponGetProjectileBlueprintL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006D8D70 (FUN_006D8D70, cfunc_UnitWeaponHasTarget)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponHasTargetL`.
   */
  int cfunc_UnitWeaponHasTarget(lua_State* luaContext);

  /**
   * Address: 0x006D8DF0 (FUN_006D8DF0, cfunc_UnitWeaponHasTargetL)
   *
   * What it does:
   * Pushes whether this weapon currently has any non-none target payload.
   */
  int cfunc_UnitWeaponHasTargetL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006D9310 (FUN_006D9310, cfunc_UnitWeaponGetCurrentTarget)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponGetCurrentTargetL`.
   */
  int cfunc_UnitWeaponGetCurrentTarget(lua_State* luaContext);

  /**
   * Address: 0x006D9390 (FUN_006D9390, cfunc_UnitWeaponGetCurrentTargetL)
   *
   * What it does:
   * Pushes the current target entity Lua object, or `nil` when target is empty.
   */
  int cfunc_UnitWeaponGetCurrentTargetL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006D9490 (FUN_006D9490, cfunc_UnitWeaponGetCurrentTargetPos)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponGetCurrentTargetPosL`.
   */
  int cfunc_UnitWeaponGetCurrentTargetPos(lua_State* luaContext);

  /**
   * Address: 0x006D9510 (FUN_006D9510, cfunc_UnitWeaponGetCurrentTargetPosL)
   *
   * What it does:
   * Pushes current weapon target position or `nil` when target position is invalid.
   */
  int cfunc_UnitWeaponGetCurrentTargetPosL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006D9630 (FUN_006D9630, cfunc_UnitWeaponCanFire)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponCanFireL`.
   */
  int cfunc_UnitWeaponCanFire(lua_State* luaContext);

  /**
   * Address: 0x006D96B0 (FUN_006D96B0, cfunc_UnitWeaponCanFireL)
   *
   * What it does:
   * Evaluates target/silo/range gates and pushes one fire-availability boolean.
   */
  int cfunc_UnitWeaponCanFireL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006DA4E0 (FUN_006DA4E0, cfunc_UnitWeaponSetTargetingPriorities)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponSetTargetingPrioritiesL`.
   */
  int cfunc_UnitWeaponSetTargetingPriorities(lua_State* luaContext);

  /**
   * Address: 0x006DA560 (FUN_006DA560, cfunc_UnitWeaponSetTargetingPrioritiesL)
   *
   * What it does:
   * Rebuilds `mTargetPriorities` from a Lua table of `EntityCategory` values.
   */
  int cfunc_UnitWeaponSetTargetingPrioritiesL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006DA6B0 (FUN_006DA6B0, cfunc_UnitWeaponGetFiringRandomness)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponGetFiringRandomnessL`.
   */
  int cfunc_UnitWeaponGetFiringRandomness(lua_State* luaContext);

  /**
   * Address: 0x006DA730 (FUN_006DA730, cfunc_UnitWeaponGetFiringRandomnessL)
   *
   * What it does:
   * Pushes the current weapon firing-randomness scalar.
   */
  int cfunc_UnitWeaponGetFiringRandomnessL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006DA960 (FUN_006DA960, cfunc_UnitWeaponGetFireClockPct)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponGetFireClockPctL`.
   */
  int cfunc_UnitWeaponGetFireClockPct(lua_State* luaContext);

  /**
   * Address: 0x006DA9E0 (FUN_006DA9E0, cfunc_UnitWeaponGetFireClockPctL)
   *
   * What it does:
   * Pushes normalized fire cooldown progress in `[0, 1]`.
   */
  int cfunc_UnitWeaponGetFireClockPctL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006DAAE0 (FUN_006DAAE0, cfunc_UnitWeaponChangeProjectileBlueprint)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponChangeProjectileBlueprintL`.
   */
  int cfunc_UnitWeaponChangeProjectileBlueprint(lua_State* luaContext);

  /**
   * Address: 0x006DAB60 (FUN_006DAB60, cfunc_UnitWeaponChangeProjectileBlueprintL)
   *
   * What it does:
   * Resolves a projectile blueprint id from Lua text and updates this weapon.
   */
  int cfunc_UnitWeaponChangeProjectileBlueprintL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006DAC80 (FUN_006DAC80, cfunc_UnitWeaponTransferTarget)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponTransferTargetL`.
   */
  int cfunc_UnitWeaponTransferTarget(lua_State* luaContext);

  /**
   * Address: 0x006DAD00 (FUN_006DAD00, cfunc_UnitWeaponTransferTargetL)
   *
   * What it does:
   * Copies one weapon target payload onto another weapon.
   */
  int cfunc_UnitWeaponTransferTargetL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006DADF0 (FUN_006DADF0, cfunc_UnitWeaponBeenDestroyed)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponBeenDestroyedL`.
   */
  int cfunc_UnitWeaponBeenDestroyed(lua_State* luaContext);

  /**
   * Address: 0x006DAE70 (FUN_006DAE70, cfunc_UnitWeaponBeenDestroyedL)
   *
   * What it does:
   * Pushes true when the passed weapon handle resolves to no live object.
   */
  int cfunc_UnitWeaponBeenDestroyedL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006D8A60 (FUN_006D8A60, cfunc_UnitWeaponGetBlueprint)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponGetBlueprintL`.
   */
  int cfunc_UnitWeaponGetBlueprint(lua_State* luaContext);

  /**
   * Address: 0x006D8A80 (FUN_006D8A80, func_UnitWeaponGetBlueprint_LuaFuncDef)
   *
   * What it does:
   * Publishes `blueprint = UnitWeapon:GetBlueprint()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponGetBlueprint_LuaFuncDef();

  /**
   * Address: 0x006D8AE0 (FUN_006D8AE0, cfunc_UnitWeaponGetBlueprintL)
   *
   * What it does:
   * Resolves a weapon from arg#1 and pushes the per-weapon blueprint entry.
   */
  int cfunc_UnitWeaponGetBlueprintL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006D8FE0 (FUN_006D8FE0, cfunc_UnitWeaponSetFireControl)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponSetFireControlL`.
   */
  int cfunc_UnitWeaponSetFireControl(lua_State* luaContext);

  /**
   * Address: 0x006D9000 (FUN_006D9000, func_UnitWeaponSetFireControl_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:SetFireControl(label)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponSetFireControl_LuaFuncDef();

  /**
   * Address: 0x006D9060 (FUN_006D9060, cfunc_UnitWeaponSetFireControlL)
   *
   * What it does:
   * Resolves `(weapon, label)` and rewrites `UnitWeapon::mLabel`.
   */
  int cfunc_UnitWeaponSetFireControlL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006D97C0 (FUN_006D97C0, cfunc_UnitWeaponChangeFiringTolerance)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponChangeFiringToleranceL`.
   */
  int cfunc_UnitWeaponChangeFiringTolerance(lua_State* luaContext);

  /**
   * Address: 0x006D97E0 (FUN_006D97E0, func_UnitWeaponChangeFiringTolerance_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:ChangeFiringTolerance(value)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponChangeFiringTolerance_LuaFuncDef();

  /**
   * Address: 0x006D9840 (FUN_006D9840, cfunc_UnitWeaponChangeFiringToleranceL)
   *
   * What it does:
   * Resolves `(weapon, value)` and writes `CWeaponAttributes::mFiringTolerance`.
   */
  int cfunc_UnitWeaponChangeFiringToleranceL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006D9920 (FUN_006D9920, cfunc_UnitWeaponChangeRateOfFire)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponChangeRateOfFireL`.
   */
  int cfunc_UnitWeaponChangeRateOfFire(lua_State* luaContext);

  /**
   * Address: 0x006D9940 (FUN_006D9940, func_UnitWeaponChangeRateOfFire_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:ChangeRateOfFire(value)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponChangeRateOfFire_LuaFuncDef();

  /**
   * Address: 0x006D99A0 (FUN_006D99A0, cfunc_UnitWeaponChangeRateOfFireL)
   *
   * What it does:
   * Resolves `(weapon, value)` and writes `CWeaponAttributes::mRateOfFire`.
   */
  int cfunc_UnitWeaponChangeRateOfFireL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006D9A80 (FUN_006D9A80, cfunc_UnitWeaponChangeMinRadius)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponChangeMinRadiusL`.
   */
  int cfunc_UnitWeaponChangeMinRadius(lua_State* luaContext);

  /**
   * Address: 0x006D9AA0 (FUN_006D9AA0, func_UnitWeaponChangeMinRadius_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:ChangeMinRadius(value)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponChangeMinRadius_LuaFuncDef();

  /**
   * Address: 0x006D9B00 (FUN_006D9B00, cfunc_UnitWeaponChangeMinRadiusL)
   *
   * What it does:
   * Writes min radius and cached squared radius, then marks unit focus dirty.
   */
  int cfunc_UnitWeaponChangeMinRadiusL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006D9C00 (FUN_006D9C00, cfunc_UnitWeaponChangeMaxRadius)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponChangeMaxRadiusL`.
   */
  int cfunc_UnitWeaponChangeMaxRadius(lua_State* luaContext);

  /**
   * Address: 0x006D9C20 (FUN_006D9C20, func_UnitWeaponChangeMaxRadius_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:ChangeMaxRadius(value)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponChangeMaxRadius_LuaFuncDef();

  /**
   * Address: 0x006D9C80 (FUN_006D9C80, cfunc_UnitWeaponChangeMaxRadiusL)
   *
   * What it does:
   * Writes max radius and cached squared radius, then marks unit focus dirty.
   */
  int cfunc_UnitWeaponChangeMaxRadiusL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006D9D80 (FUN_006D9D80, cfunc_UnitWeaponChangeMaxHeightDiff)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponChangeMaxHeightDiffL`.
   */
  int cfunc_UnitWeaponChangeMaxHeightDiff(lua_State* luaContext);

  /**
   * Address: 0x006D9DA0 (FUN_006D9DA0, func_UnitWeaponChangeMaxHeightDiff_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:ChangeMaxHeightDiff(value)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponChangeMaxHeightDiff_LuaFuncDef();

  /**
   * Address: 0x006D9E00 (FUN_006D9E00, cfunc_UnitWeaponChangeMaxHeightDiffL)
   *
   * What it does:
   * Resolves `(weapon, value)` and writes `CWeaponAttributes::mMaxHeightDiff`.
   */
  int cfunc_UnitWeaponChangeMaxHeightDiffL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006D9EE0 (FUN_006D9EE0, cfunc_UnitWeaponChangeDamageType)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponChangeDamageTypeL`.
   */
  int cfunc_UnitWeaponChangeDamageType(lua_State* luaContext);

  /**
   * Address: 0x006D9F00 (FUN_006D9F00, func_UnitWeaponChangeDamageType_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:ChangeDamageType(typeName)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponChangeDamageType_LuaFuncDef();

  /**
   * Address: 0x006D9F60 (FUN_006D9F60, cfunc_UnitWeaponChangeDamageTypeL)
   *
   * What it does:
   * Resolves a weapon from arg#1 and rewrites its damage type string from arg#2.
   */
  int cfunc_UnitWeaponChangeDamageTypeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006DA070 (FUN_006DA070, cfunc_UnitWeaponChangeDamageRadius)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponChangeDamageRadiusL`.
   */
  int cfunc_UnitWeaponChangeDamageRadius(lua_State* luaContext);

  /**
   * Address: 0x006DA090 (FUN_006DA090, func_UnitWeaponChangeDamageRadius_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:ChangeDamageRadius(value)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponChangeDamageRadius_LuaFuncDef();

  /**
   * Address: 0x006DA0F0 (FUN_006DA0F0, cfunc_UnitWeaponChangeDamageRadiusL)
   *
   * What it does:
   * Resolves `(weapon, value)` and writes `CWeaponAttributes::mDamageRadius`.
   */
  int cfunc_UnitWeaponChangeDamageRadiusL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006DA1E0 (FUN_006DA1E0, cfunc_UnitWeaponChangeDamage)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitWeaponChangeDamageL`.
   */
  int cfunc_UnitWeaponChangeDamage(lua_State* luaContext);

  /**
   * Address: 0x006DA200 (FUN_006DA200, func_UnitWeaponChangeDamage_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:ChangeDamage(value)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponChangeDamage_LuaFuncDef();

  /**
   * Address: 0x006DA260 (FUN_006DA260, cfunc_UnitWeaponChangeDamageL)
   *
   * What it does:
   * Resolves `(weapon, value)` and writes `CWeaponAttributes::mDamage`.
   */
  int cfunc_UnitWeaponChangeDamageL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006DA7F0 (FUN_006DA7F0, cfunc_UnitWeaponSetFiringRandomness)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponSetFiringRandomnessL`.
   */
  int cfunc_UnitWeaponSetFiringRandomness(lua_State* luaContext);

  /**
   * Address: 0x006DA810 (FUN_006DA810, func_UnitWeaponSetFiringRandomness_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:SetFiringRandomness(value)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponSetFiringRandomness_LuaFuncDef();

  /**
   * Address: 0x006DA870 (FUN_006DA870, cfunc_UnitWeaponSetFiringRandomnessL)
   *
   * What it does:
   * Resolves `(weapon, value)` and writes `UnitWeapon::mFiringRandomness`.
   */
  int cfunc_UnitWeaponSetFiringRandomnessL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006DA350 (FUN_006DA350, cfunc_UnitWeaponSetFireTargetLayerCaps)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponSetFireTargetLayerCapsL`.
   */
  int cfunc_UnitWeaponSetFireTargetLayerCaps(lua_State* luaContext);

  /**
   * Address: 0x006DA370 (FUN_006DA370, func_UnitWeaponSetFireTargetLayerCaps_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:SetFireTargetLayerCaps(mask)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponSetFireTargetLayerCaps_LuaFuncDef();

  /**
   * Address: 0x006DA3D0 (FUN_006DA3D0, cfunc_UnitWeaponSetFireTargetLayerCapsL)
   *
   * What it does:
   * Resolves `(weapon, layerName)` and updates one weapon fire-target layer mask.
   */
  int cfunc_UnitWeaponSetFireTargetLayerCapsL(LuaPlus::LuaState* state);

  static_assert(offsetof(UnitWeapon, mWeaponBlueprint) == 0x48, "UnitWeapon::mWeaponBlueprint offset must be 0x48");
  static_assert(
    offsetof(UnitWeapon, mProjectileBlueprint) == 0x4C, "UnitWeapon::mProjectileBlueprint offset must be 0x4C"
  );
  static_assert(offsetof(UnitWeapon, mAttributes) == 0x54, "UnitWeapon::mAttributes offset must be 0x54");
  static_assert(offsetof(UnitWeapon, mEnabled) == 0xAC, "UnitWeapon::mEnabled offset must be 0xAC");
  static_assert(offsetof(UnitWeapon, mCat1) == 0xF8, "UnitWeapon::mCat1 offset must be 0xF8");
  static_assert(offsetof(UnitWeapon, mCat2) == 0x120, "UnitWeapon::mCat2 offset must be 0x120");
  static_assert(
    offsetof(UnitWeapon, mFireTargetLayerCaps) == 0x148,
    "UnitWeapon::mFireTargetLayerCaps offset must be 0x148"
  );
  static_assert(
    offsetof(UnitWeapon, mFiringRandomness) == 0x14C, "UnitWeapon::mFiringRandomness offset must be 0x14C"
  );
  static_assert(
    offsetof(UnitWeapon, mTargetPriorities) == 0x150, "UnitWeapon::mTargetPriorities offset must be 0x150"
  );
  static_assert(offsetof(UnitWeapon, mBlacklist) == 0x160, "UnitWeapon::mBlacklist offset must be 0x160");
  static_assert(offsetof(UnitWeapon, mAimingAt) == 0x178, "UnitWeapon::mAimingAt offset must be 0x178");
  static_assert(offsetof(UnitWeapon, mShotsAtTarget) == 0x184, "UnitWeapon::mShotsAtTarget offset must be 0x184");
  static_assert(sizeof(UnitWeapon) == 0x188, "UnitWeapon size must be 0x188");
  static_assert(WeakPtr<UnitWeapon>::kOwnerLinkOffset == 0x14, "UnitWeapon weak-owner slot offset must be 0x14");

  /**
   * Address: 0x006D5590 (FUN_006D5590, func_PickTargetPoint)
   *
   * What it does:
   * Validates one entity target against a weapon's layer/category constraints
   * and resolves above/below-water aim-point requirements, returning true when
   * the weapon may target the entity. Public entry point onto the recovered body
   * so cross-subsystem callers (e.g. `CAiAttackerImpl::TrackToTarget`) can invoke
   * it by name as the binary does.
   */
  [[nodiscard]] bool WeaponCanAttackEntityTarget(Entity* targetEntity, UnitWeapon* weapon);

  /**
   * Address: 0x006DBD70 (FUN_006DBD70)
   *
   * What it does:
   * Clears a weapon's target blacklist: unlinks every blacklist entry's weak
   * entity reference and rewinds the vector to empty without releasing capacity.
   * Public entry point onto the recovered body so the acquire-target task can
   * invoke it by name (e.g. after the owning unit moves).
   */
  void WeaponResetBlacklist(UnitWeapon& weapon);
} // namespace moho
