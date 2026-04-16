#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/entity/ECollisionBeamEvent.h"
#include "moho/entity/Entity.h"
#include "moho/misc/WeakPtr.h"

namespace LuaPlus
{
  class LuaObject;
}

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
  class SerConstructResult;
}

namespace moho
{
  class IEffect;
  class Sim;
  class UnitWeapon;

  class CollisionBeamEntity : public Entity
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x006746F0 (FUN_006746F0)
     *
     * What it does:
     * Returns cached reflected type metadata for `CollisionBeamEntity`,
     * resolving it through RTTI lookup on first use.
     */
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x00672F80 (FUN_00672F80, Moho::CollisionBeamEntity::CollisionBeamEntity)
     * Mangled: ??0CollisionBeamEntity@Moho@@QAE@ABVLuaObject@LuaPlus@@PAVUnitWeapon@1@@Z
     *
     * What it does:
     * Constructs one collision-beam entity from Lua creation spec and launcher weapon.
     */
    CollisionBeamEntity(const LuaPlus::LuaObject& specObject, UnitWeapon* launcherWeapon);

    /**
     * Address: 0x00672E90 (FUN_00672E90, Moho::CollisionBeamEntity::dtr)
     * Address: 0x00672EC0 (FUN_00672EC0, Moho::CollisionBeamEntity destructor body)
     *
     * What it does:
     * Unlinks collision-beam weak/listener intrusive nodes, decrements instance
     * counter, and tears down base `Entity` state.
     */
    ~CollisionBeamEntity() override;

    /**
     * Address: 0x00672C30 (FUN_00672C30, Moho::CollisionBeamEntity::SetEfxBeam)
     * Mangled: ?SetEfxBeam@CollisionBeamEntity@Moho@@QAEXPAVIEffect@2@_N@Z
     *
     * What it does:
     * Updates the owned beam-emitter weak link and optionally runs collision
     * update checks immediately.
     */
    void SetEfxBeam(IEffect* beamEmitter, bool checkCollision);

    /**
     * Address: 0x00672C60 (FUN_00672C60, Moho::CollisionBeamEntity::SetCollisionCheckInterval)
     * Mangled: ?SetCollisionCheckInterval@CollisionBeamEntity@Moho@@QAEXH@Z
     *
     * What it does:
     * Sets the interval (in ticks) between automatic collision checks.
     */
    void SetCollisionCheckInterval(std::int32_t intervalTicks);

    /**
     * Address: 0x00672C00 (FUN_00672C00, Moho::CollisionBeamEntity::GetDerivedObjectRef)
     * Mangled: ?GetDerivedObjectRef@CollisionBeamEntity@Moho@@UAE?AVRRef@gpg@@XZ
     *
     * What it does:
     * Returns a typed reflection reference pair for this collision-beam entity.
     */
    [[nodiscard]] gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x00672C20 (FUN_00672C20, Moho::CollisionBeamEntity::IsCollisionBeam)
     * Mangled: ?IsCollisionBeam@CollisionBeamEntity@Moho@@UAEPAV12@XZ
     *
     * What it does:
     * Returns `this` to identify the runtime entity as a collision-beam owner.
     */
    [[nodiscard]] CollisionBeamEntity* IsCollisionBeam() override;

    /**
     * Address: 0x00672C70 (FUN_00672C70, Moho::CollisionBeamEntity::GetLauncher)
     * Mangled: ?GetLauncher@CollisionBeamEntity@Moho@@QBEPAVEntity@2@XZ
     *
     * What it does:
     * Returns the launcher unit's `Entity` base pointer when launcher weak-link
     * ownership resolves; otherwise returns `nullptr`.
     */
    [[nodiscard]] Entity* GetLauncher() const;

    /**
     * Address: 0x00672CB0 (FUN_00672CB0, Moho::CollisionBeamEntity::GetBoneCount)
     * Mangled: ?GetBoneCount@CollisionBeamEntity@Moho@@UBEHXZ
     *
     * What it does:
     * Returns the fixed collision-beam skeleton bone count.
     */
    [[nodiscard]] int GetBoneCount() const override;

    /**
     * Address: 0x006731A0 (FUN_006731A0, Moho::CollisionBeamEntity::GetBoneLocalTransform)
     * Mangled: ?GetBoneLocalTransform@CollisionBeamEntity@Moho@@UBE?AVVTransform@2@H@Z
     *
     * What it does:
     * Returns an identity local transform and extends local Z by current beam
     * length for bone index `1`.
     */
    [[nodiscard]] VTransform GetBoneLocalTransform(int boneIndex) const override;

    /**
     * Address: 0x006730B0 (FUN_006730B0, Moho::CollisionBeamEntity::GetBoneWorldTransform)
     * Mangled: ?GetBoneWorldTransform@CollisionBeamEntity@Moho@@UBE?AVVTransform@2@H@Z
     *
     * What it does:
     * Returns entity world transform lanes and extends translation by beam
     * length along oriented local +Z when `boneIndex != 0`.
     */
    [[nodiscard]] VTransform GetBoneWorldTransform(int boneIndex) const override;

    /**
     * Address: 0x006731F0 (FUN_006731F0, Moho::CollisionBeamEntity::EnableCollisionCheck)
     * Mangled: ?EnableCollisionCheck@CollisionBeamEntity@Moho@@QAEX_N@Z
     *
     * What it does:
     * Toggles collision-check processing for the beam entity.
     */
    void EnableCollisionCheck(bool enabled);

    /**
     * Address: 0x006732C0 (FUN_006732C0, ?IsEnabled@CollisionBeamEntity@Moho@@QBE_NXZ)
     *
     * What it does:
     * Returns whether collision-check processing is currently enabled.
     */
    [[nodiscard]] bool IsEnabled() const;

    /**
     * Address: 0x006732D0 (FUN_006732D0, Moho::CollisionBeamEntity::CheckCollision)
     * Mangled: ?CheckCollision@CollisionBeamEntity@Moho@@IAEXXZ
     *
     * What it does:
     * Executes one collision-check/update pass for the active beam link.
     */
    void CheckCollision();

    /**
     * Address: 0x006735C0 (FUN_006735C0, Moho::CollisionBeamEntity::MotionTick)
     * Mangled: ?MotionTick@CollisionBeamEntity@Moho@@UAE?AW4ETaskStatus@2@XZ
     *
     * What it does:
     * Validates launcher/attach state, performs interval-gated collision checks,
     * and draws optional debug wireframe for active beam state.
     */
    int MotionTick() override;

    /**
     * Address: 0x006736B0 (FUN_006736B0, Moho::CollisionBeamEntity::OnDestroy)
     * Mangled: ?OnDestroy@CollisionBeamEntity@Moho@@UAEXXZ
     *
     * What it does:
     * Forwards base destroy flow, tears down active beam effect ownership, and
     * unlinks the effect weak-pointer lane from its owner chain.
     */
    void OnDestroy() override;

    /**
     * Address: 0x00673A50 (FUN_00673A50, Moho::CollisionBeamEntity::MemberConstruct)
     * Mangled: ?MemberConstruct@CollisionBeamEntity@Moho@@CAXAAVReadArchive@gpg@@HABVRRef@4@AAVSerConstructResult@4@@Z
     *
     * What it does:
     * Reads construct payload (`Sim*`), allocates one `CollisionBeamEntity`,
     * and publishes it as an unowned construct result.
     */
    static void MemberConstruct(
      gpg::ReadArchive& archive,
      int version,
      const gpg::RRef& ownerRef,
      gpg::SerConstructResult& result
    );

    /**
     * Address: 0x006762F0 (FUN_006762F0, Moho::CollisionBeamEntity::MemberDeserialize)
     *
     * What it does:
     * Loads base/entity listener state, weak links, and collision-check runtime
     * lanes from archive payload.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x00676450 (FUN_00676450, Moho::CollisionBeamEntity::MemberSerialize)
     *
     * What it does:
     * Saves base/entity listener state, weak links, and collision-check runtime
     * lanes to archive payload.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

  protected:
    /**
     * Address: 0x00672DD0 (FUN_00672DD0, Moho::CollisionBeamEntity::CollisionBeamEntity)
     * Mangled: ??0CollisionBeamEntity@Moho@@IAE@PAVSim@1@@Z
     *
     * What it does:
     * Constructs one collision-beam entity for serializer construct paths.
     */
    explicit CollisionBeamEntity(Sim* ownerSim);

  public:
    ManyToOneBroadcaster_ECollisionBeamEvent mListener; // +0x270
    float mSerializedBeamState;                         // +0x278
    std::int32_t mCollisionCheckInterval;               // +0x27C
    float mLastBeamLength;                              // +0x280
    WeakPtr<IEffect> mEffect;                           // +0x284
    WeakPtr<UnitWeapon> mLauncher;                      // +0x28C
    std::uint8_t mEnabled;                              // +0x294
    std::uint8_t mCollisionListenerBound;               // +0x295
    std::uint8_t mPad296_297[0x02];                    // +0x296
    std::int32_t mCollisionCheckTickCounter;            // +0x298
    std::uint8_t mPad29C_29F[0x04];                    // +0x29C
  };

  static_assert(sizeof(CollisionBeamEntity) == 0x2A0, "CollisionBeamEntity size must be 0x2A0");
  static_assert(offsetof(CollisionBeamEntity, mListener) == 0x270, "CollisionBeamEntity::mListener offset must be 0x270");
  static_assert(
    offsetof(CollisionBeamEntity, mSerializedBeamState) == 0x278,
    "CollisionBeamEntity::mSerializedBeamState offset must be 0x278"
  );
  static_assert(
    offsetof(CollisionBeamEntity, mCollisionCheckInterval) == 0x27C,
    "CollisionBeamEntity::mCollisionCheckInterval offset must be 0x27C"
  );
  static_assert(
    offsetof(CollisionBeamEntity, mLastBeamLength) == 0x280,
    "CollisionBeamEntity::mLastBeamLength offset must be 0x280"
  );
  static_assert(offsetof(CollisionBeamEntity, mEffect) == 0x284, "CollisionBeamEntity::mEffect offset must be 0x284");
  static_assert(offsetof(CollisionBeamEntity, mLauncher) == 0x28C, "CollisionBeamEntity::mLauncher offset must be 0x28C");
  static_assert(offsetof(CollisionBeamEntity, mEnabled) == 0x294, "CollisionBeamEntity::mEnabled offset must be 0x294");
  static_assert(
    offsetof(CollisionBeamEntity, mCollisionListenerBound) == 0x295,
    "CollisionBeamEntity::mCollisionListenerBound offset must be 0x295"
  );
  static_assert(
    offsetof(CollisionBeamEntity, mCollisionCheckTickCounter) == 0x298,
    "CollisionBeamEntity::mCollisionCheckTickCounter offset must be 0x298"
  );

  /**
   * VFTABLE: 0x00E26E54
   * COL: 0x00E994DC
   */
  class CollisionBeamEntityTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00673720 (FUN_00673720, Moho::CollisionBeamEntityTypeInfo::CollisionBeamEntityTypeInfo)
     *
     * What it does:
     * Constructs and preregisters reflected RTTI ownership for `CollisionBeamEntity`.
     */
    CollisionBeamEntityTypeInfo();

    /**
     * Address: 0x006737C0 (FUN_006737C0, Moho::CollisionBeamEntityTypeInfo::dtr)
     */
    ~CollisionBeamEntityTypeInfo() override;

    /**
     * Address: 0x006737B0 (FUN_006737B0, Moho::CollisionBeamEntityTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00673780 (FUN_00673780, Moho::CollisionBeamEntityTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * What it does:
     * Adds `Entity` as reflected base metadata at offset `0`.
     */
    static void AddBase_Entity(gpg::RType* typeInfo);
  };

  /**
   * Address: 0x00BD4C40 (FUN_00BD4C40, register_CollisionBeamEntityTypeInfo)
   *
   * What it does:
   * Materializes startup `CollisionBeamEntityTypeInfo` storage and installs
   * process-exit cleanup.
   */
  int register_CollisionBeamEntityTypeInfo();

  static_assert(sizeof(CollisionBeamEntityTypeInfo) == 0x64, "CollisionBeamEntityTypeInfo size must be 0x64");
} // namespace moho
