#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "legacy/containers/String.h"
#include "moho/containers/TDatList.h"
#include "moho/entity/SSTIEntityVariableData.h"
#include "moho/misc/WeakObject.h"
#include "moho/render/camera/VTransform.h"
#include "moho/vision/VisionDB.h"

namespace moho
{
  class CWldSession;
  class UserUnit;
  class UserCommandQueue;
  class CAniPose;
  class MeshInstance;
  class CD3DBatchTexture;
  class UserArmy;
  class CSndParams;
  struct HSndEntityLoop;
  struct REntityBlueprint;

  struct SCreateEntityParams
  {
    std::uint32_t mEntityId;            // 0x00
    const REntityBlueprint* mBlueprint; // 0x04
    std::uint32_t mUnknown08;           // 0x08
  };
  static_assert(sizeof(SCreateEntityParams) == 0x0C, "SCreateEntityParams size must be 0x0C");

  using UserEntityLinkNode = TDatListItem<void, void>;
  static_assert(sizeof(UserEntityLinkNode) == 0x08, "UserEntityLinkNode size must be 0x08");

  struct UserEntitySpatialDbEntry
  {
    void* mSpatialDb;      // 0x00
    std::int32_t mEntryId; // 0x04
  };
  static_assert(sizeof(UserEntitySpatialDbEntry) == 0x08, "UserEntitySpatialDbEntry size must be 0x08");

  class UserEntity : public WeakObject
  {
  public:
    /**
     * Address: 0x008B85E0 (FUN_008B85E0, ??0UserEntity@Moho@@QAE@AAVCWldSession@1@ABUSCreateEntityParams@1@@Z)
     *
     * What it does:
     * Initializes runtime links/state, copies create params, seeds variable data,
     * derives owner army/category mask from entity id, then registers in session spatial DB.
     */
    UserEntity(CWldSession& session, const SCreateEntityParams& createParams);

    /**
     * Address: 0x008B87A0 (FUN_008B87A0, ??1UserEntity@Moho@@UAE@XZ)
     *
     * What it does:
     * Tears down mesh/pose/runtime links and detaches this user-entity from
     * spatial/auxiliary runtime systems.
     */
    virtual ~UserEntity();

    /**
     * Address: 0x008B8CD0 (FUN_008B8CD0, ?Tick@UserEntity@Moho@@UAEXVCSeqNo@2@@Z)
     *
     * What it does:
     * Base user-entity tick hook; default implementation is a no-op.
     */
    virtual void Tick(std::int32_t seqNo);

    /**
     * Address: 0x008B84D0 (FUN_008B84D0, ?IsUserUnit@UserEntity@Moho@@UBEPBVUserUnit@2@XZ)
     *
     * What it does:
     * Returns typed const unit view when this entity is a user-unit.
     */
    [[nodiscard]] virtual const UserUnit* IsUserUnit() const;

    /**
     * Address: 0x008B84C0 (FUN_008B84C0, ?IsUserUnit@UserEntity@Moho@@UAEPAVUserUnit@2@XZ)
     *
     * What it does:
     * Returns typed mutable unit view when this entity is a user-unit.
     */
    [[nodiscard]] virtual UserUnit* IsUserUnit();

    /**
     * Address: 0x008B84E0 (FUN_008B84E0, ?GetUniformScale@UserEntity@Moho@@UBEMXZ)
     *
     * What it does:
     * Returns model uniform-scale multiplier.
     */
    [[nodiscard]] virtual float GetUniformScale() const;

    /**
     * Address: 0x008B8510 (FUN_008B8510, ?GetCommandQueue@UserEntity@Moho@@UBEPBVUserCommandQueue@2@XZ)
     *
     * What it does:
     * Returns read-only command queue for this entity.
     */
    [[nodiscard]] virtual const UserCommandQueue* GetCommandQueue() const;

    /**
     * Address: 0x008B84F0 (FUN_008B84F0, ?GetCommandQueue@UserEntity@Moho@@UAEPAVUserCommandQueue@2@XZ)
     *
     * What it does:
     * Returns mutable command queue for this entity.
     */
    [[nodiscard]] virtual UserCommandQueue* GetCommandQueue();

    /**
     * Address: 0x008B8520 (FUN_008B8520, ?GetFactoryCommandQueue@UserEntity@Moho@@UBEPBVUserCommandQueue@2@XZ)
     *
     * What it does:
     * Returns read-only factory command queue for this entity.
     */
    [[nodiscard]] virtual const UserCommandQueue* GetFactoryCommandQueue() const;

    /**
     * Address: 0x008B8500 (FUN_008B8500, ?GetFactoryCommandQueue@UserEntity@Moho@@UAEPAVUserCommandQueue@2@XZ)
     *
     * What it does:
     * Returns mutable factory command queue for this entity.
     */
    [[nodiscard]] virtual UserCommandQueue* GetFactoryCommandQueue();

    /**
     * Address: 0x008B8EB0 (FUN_008B8EB0, ?UpdateEntityData@UserEntity@Moho@@UAEXABUSSTIEntityVariableData@2@@Z)
     *
     * What it does:
     * Applies replicated variable snapshot data to the user-entity.
     */
    virtual void UpdateEntityData(const SSTIEntityVariableData& variableData);

    /**
     * Address: 0x008B9580 (FUN_008B9580, ?UpdateVisibility@UserEntity@Moho@@UAEXXZ)
     *
     * What it does:
     * Updates render visibility state against active intel/view rules.
     */
    virtual void UpdateVisibility();

    /**
     * Address: 0x008B8530 (FUN_008B8530, ?RequiresUIRefresh@UserEntity@Moho@@UBE_NXZ)
     *
     * What it does:
     * Returns whether UI refresh is requested by replicated state.
     */
    [[nodiscard]] virtual bool RequiresUIRefresh() const;

    /**
     * Address: 0x008B8540 (FUN_008B8540, ?IsSelectable@UserEntity@Moho@@UBE_NXZ)
     *
     * What it does:
     * Returns whether this entity belongs to the SELECTABLE category.
     */
    [[nodiscard]] virtual bool IsSelectable() const;

    /**
     * Address: 0x008B85C0 (FUN_008B85C0, ?IsBeingBuilt@UserEntity@Moho@@UBE_NXZ)
     *
     * What it does:
     * Returns replicated "being built" state.
     */
    [[nodiscard]] virtual bool IsBeingBuilt() const;

    /**
     * Address: 0x008B85D0 (FUN_008B85D0, ?NotifyFocusArmyUnitDamaged@UserEntity@Moho@@UAEXXZ)
     *
     * What it does:
     * Hook fired when focused army unit damage is detected.
     */
    virtual void NotifyFocusArmyUnitDamaged();

    /**
     * Address: 0x008B88D0 (FUN_008B88D0, ?CreateMeshInstance@UserEntity@Moho@@MAEX_N@Z)
     *
     * What it does:
     * Creates/initializes render mesh instance and animation pose chain.
     */
    virtual void CreateMeshInstance(bool forUnitPose);

    /**
     * Address: 0x008B8B10 (FUN_008B8B10, ?DestroyMeshInstance@UserEntity@Moho@@MAEXXZ)
     *
     * What it does:
     * Releases mesh instance and animation pose resources.
     */
    virtual void DestroyMeshInstance();

    /**
     * Address: 0x007FD3F0 (FUN_007FD3F0, Moho::UserEntity::GetSelectionBracketTexture)
     *
     * What it does:
     * Selects UI selection-bracket texture lane from alliance relation and unit
     * intel-state flags.
     */
    [[nodiscard]] boost::shared_ptr<CD3DBatchTexture> GetSelectionBracketTexture(const UserArmy* viewingArmy) const;

    /**
     * Address: 0x008B97C0 (FUN_008B97C0,
     * ?IsInCategory@UserEntity@Moho@@QBE_NABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z)
     *
     * What it does:
     * Resolves category bitset and tests membership for this entity category id.
     */
    [[nodiscard]] bool IsInCategory(const msvc8::string& category) const;

    /**
     * Address: 0x008B8CF0 (FUN_008B8CF0, ?GetInterpolatedTransform@UserEntity@Moho@@QBE?AVVTransform@2@M@Z)
     *
     * What it does:
     * Updates cached interpolated transform for `interpolationAlpha` and
     * returns the cached transform by value.
     */
    [[nodiscard]] VTransform GetInterpolatedTransform(float interpolationAlpha) const;

  public:
    void* mWeakObjectRuntimeHead;               // 0x04
    UserEntityLinkNode* mIUnitChainHead;        // 0x08
    CWldSession* mSession;                      // 0x0C
    UserEntitySpatialDbEntry mSpatialDbEntry;   // 0x10
    VisionDB::Handle* mVisionHandle;            // 0x18
    boost::shared_ptr<CAniPose> mPosePrimary;   // 0x1C
    boost::shared_ptr<CAniPose> mPoseSecondary; // 0x24
    MeshInstance* mMeshInstance;                // 0x2C
    UserEntityLinkNode* mRuntimeLinkHead;       // 0x30
    std::int32_t mRuntimeSelectionToken;        // 0x34
    CSndParams* mCachedAmbientSound;            // 0x38
    HSndEntityLoop* mRumbleLoopHandle;          // 0x3C
    std::int32_t mLastFocusDamageGameTick;      // 0x40
    SCreateEntityParams mParams;                // 0x44
    SSTIEntityVariableData mVariableData;       // 0x50
    UserArmy* mArmy;                // 0x120
    VTransform mTransform;          // 0x124
    float mLastInterpAmt;           // 0x140
    std::uint8_t mHasInitialUpdate; // 0x144
    std::uint8_t mHasRuntimePose;   // 0x145
    std::uint8_t pad_0146_0147[0x02]{};
  };

#if defined(MOHO_STRICT_LAYOUT_ASSERTS)
  static_assert(sizeof(UserEntity) == 0x148, "UserEntity size must be 0x148");
  static_assert(offsetof(UserEntity, mSession) == 0x0C, "UserEntity::mSession offset must be 0x0C");
  static_assert(offsetof(UserEntity, mIUnitChainHead) == 0x08, "UserEntity::mIUnitChainHead offset must be 0x08");
  static_assert(offsetof(UserEntity, mSpatialDbEntry) == 0x10, "UserEntity::mSpatialDbEntry offset must be 0x10");
  static_assert(offsetof(UserEntity, mVisionHandle) == 0x18, "UserEntity::mVisionHandle offset must be 0x18");
  static_assert(offsetof(UserEntity, mPosePrimary) == 0x1C, "UserEntity::mPosePrimary offset must be 0x1C");
  static_assert(offsetof(UserEntity, mPoseSecondary) == 0x24, "UserEntity::mPoseSecondary offset must be 0x24");
  static_assert(offsetof(UserEntity, mMeshInstance) == 0x2C, "UserEntity::mMeshInstance offset must be 0x2C");
  static_assert(offsetof(UserEntity, mRuntimeLinkHead) == 0x30, "UserEntity::mRuntimeLinkHead offset must be 0x30");
  static_assert(
    offsetof(UserEntity, mRuntimeSelectionToken) == 0x34, "UserEntity::mRuntimeSelectionToken offset must be 0x34"
  );
  static_assert(
    offsetof(UserEntity, mRumbleLoopHandle) == 0x3C, "UserEntity::mRumbleLoopHandle offset must be 0x3C"
  );
  static_assert(
    offsetof(UserEntity, mLastFocusDamageGameTick) == 0x40, "UserEntity::mLastFocusDamageGameTick offset must be 0x40"
  );
  static_assert(offsetof(UserEntity, mParams) == 0x44, "UserEntity::mParams offset must be 0x44");
  static_assert(offsetof(UserEntity, mVariableData) == 0x50, "UserEntity::mVariableData offset must be 0x50");
  static_assert(offsetof(UserEntity, mArmy) == 0x120, "UserEntity::mArmy offset must be 0x120");
  static_assert(offsetof(UserEntity, mTransform) == 0x124, "UserEntity::mTransform offset must be 0x124");
  static_assert(offsetof(UserEntity, mLastInterpAmt) == 0x140, "UserEntity::mLastInterpAmt offset must be 0x140");
  static_assert(offsetof(UserEntity, mHasInitialUpdate) == 0x144, "UserEntity::mHasInitialUpdate offset must be 0x144");
  static_assert(offsetof(UserEntity, mHasRuntimePose) == 0x145, "UserEntity::mHasRuntimePose offset must be 0x145");
#endif
} // namespace moho
