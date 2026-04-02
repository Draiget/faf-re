#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>

#include "../script/CScriptObject.h"
#include "../task/CTask.h"
#include "EntityId.h"
#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/String.h"
#include "legacy/containers/AutoPtr.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/containers/TDatList.h"
#include "moho/math/Vector4f.h"
#include "REntityBlueprint.h"
#include "SEntAttachInfo.h"
#include "wm3/Box3.h"
#include "wm3/Quaternion.h"
#include "wm3/Vector3.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
  class SerConstructResult;
  class SerSaveConstructArgsResult;
} // namespace gpg

namespace moho
{
  typedef int32_t EntId;
  typedef int32_t EntIdUniverse;
  class Entity;
  class CollisionBeamEntity;
  class Projectile;
  class Prop;
  class RResId;
  class RMeshBlueprint;
  class ReconBlip;
  class Shield;
  class Sim;
  class Unit;
  class VTransform;
  class CIntel;
  class EntityMotor;
  class EntityCollisionUpdater;
  class CArmyImpl;
  struct PositionHistory;
  struct SSyncData;

  enum ELayer : std::int32_t
  {
    LAYER_None = 0,
    LAYER_Land = 1,
    LAYER_Seabed = 2,
    LAYER_Sub = 4,
    LAYER_Water = 8,
    LAYER_Air = 16,
    LAYER_Orbit = 32,
  };

  struct EntityCollisionCellSpan;

  struct EntityCollisionCellNode
  {
    EntityCollisionCellNode* next;  // +0x00
    EntityCollisionCellSpan* owner; // +0x04
  };
  static_assert(sizeof(EntityCollisionCellNode) == 0x08, "EntityCollisionCellNode size must be 0x08");
  static_assert(offsetof(EntityCollisionCellNode, next) == 0x00, "EntityCollisionCellNode::next offset must be 0x00");
  static_assert(offsetof(EntityCollisionCellNode, owner) == 0x04, "EntityCollisionCellNode::owner offset must be 0x04");

  /**
   * Prefix layout used by collision-cell linking helpers (0x004FCF20/0x004FCF90/0x004FCE90).
   *
   * Notes:
   * - This is a recovered view of the hot-path prefix only.
   * - Offsets >= +0x34 may exist in the real object and remain unresolved.
   */
  struct EntityCollisionSpatialGrid
  {
    std::int32_t mRowStride;                           // +0x00
    std::uint32_t mReserved04;                         // +0x04
    std::uint32_t mBucketMask;                         // +0x08
    std::uint32_t mRowShift;                           // +0x0C
    EntityCollisionCellNode** mBucketHeads100;         // +0x10
    EntityCollisionCellNode** mBucketHeads200;         // +0x14
    EntityCollisionCellNode** mBucketHeadsC00;         // +0x18
    EntityCollisionCellNode* mFreeNodeHead;            // +0x1C
    std::int32_t mFreeNodeCount;                       // +0x20
    std::uint32_t mReserved24;                         // +0x24
    EntityCollisionCellNode** mChunkBlocksBegin;       // +0x28
    EntityCollisionCellNode** mChunkBlocksEnd;         // +0x2C
    EntityCollisionCellNode** mChunkBlocksCapacityEnd; // +0x30
  };

  static_assert(sizeof(EntityCollisionSpatialGrid) == 0x34, "EntityCollisionSpatialGrid prefix size must be 0x34");
  static_assert(
    offsetof(EntityCollisionSpatialGrid, mRowStride) == 0x00,
    "EntityCollisionSpatialGrid::mRowStride offset must be 0x00"
  );
  static_assert(
    offsetof(EntityCollisionSpatialGrid, mBucketMask) == 0x08,
    "EntityCollisionSpatialGrid::mBucketMask offset must be 0x08"
  );
  static_assert(
    offsetof(EntityCollisionSpatialGrid, mRowShift) == 0x0C, "EntityCollisionSpatialGrid::mRowShift offset must be 0x0C"
  );
  static_assert(
    offsetof(EntityCollisionSpatialGrid, mBucketHeads100) == 0x10,
    "EntityCollisionSpatialGrid::mBucketHeads100 offset must be 0x10"
  );
  static_assert(
    offsetof(EntityCollisionSpatialGrid, mBucketHeads200) == 0x14,
    "EntityCollisionSpatialGrid::mBucketHeads200 offset must be 0x14"
  );
  static_assert(
    offsetof(EntityCollisionSpatialGrid, mBucketHeadsC00) == 0x18,
    "EntityCollisionSpatialGrid::mBucketHeadsC00 offset must be 0x18"
  );
  static_assert(
    offsetof(EntityCollisionSpatialGrid, mFreeNodeHead) == 0x1C,
    "EntityCollisionSpatialGrid::mFreeNodeHead offset must be 0x1C"
  );
  static_assert(
    offsetof(EntityCollisionSpatialGrid, mFreeNodeCount) == 0x20,
    "EntityCollisionSpatialGrid::mFreeNodeCount offset must be 0x20"
  );
  static_assert(
    offsetof(EntityCollisionSpatialGrid, mChunkBlocksBegin) == 0x28,
    "EntityCollisionSpatialGrid::mChunkBlocksBegin offset must be 0x28"
  );
  static_assert(
    offsetof(EntityCollisionSpatialGrid, mChunkBlocksEnd) == 0x2C,
    "EntityCollisionSpatialGrid::mChunkBlocksEnd offset must be 0x2C"
  );
  static_assert(
    offsetof(EntityCollisionSpatialGrid, mChunkBlocksCapacityEnd) == 0x30,
    "EntityCollisionSpatialGrid::mChunkBlocksCapacityEnd offset must be 0x30"
  );

  /**
   * Address owner: Entity + 0x4C
   *
   * What it does:
   * Stores quantized collision-cell rectangle and grid-link metadata used by
   * 0x004FD420 / 0x004FD490 relink paths.
   */
  struct EntityCollisionCellSpan
  {
    std::uint16_t mCellStartX;                // +0x00
    std::uint16_t mCellStartZ;                // +0x02
    std::uint16_t mCellWidth;                 // +0x04
    std::uint16_t mCellHeight;                // +0x06
    EntityCollisionSpatialGrid* mSpatialGrid; // +0x08
    std::uint32_t mReserved0C;                // +0x0C
    std::uint32_t mBucketFlags;               // +0x10
  };

  static_assert(sizeof(EntityCollisionCellSpan) == 0x14, "EntityCollisionCellSpan size must be 0x14");
  static_assert(
    offsetof(EntityCollisionCellSpan, mCellStartX) == 0x00, "EntityCollisionCellSpan::mCellStartX offset must be 0x00"
  );
  static_assert(
    offsetof(EntityCollisionCellSpan, mCellWidth) == 0x04, "EntityCollisionCellSpan::mCellWidth offset must be 0x04"
  );
  static_assert(
    offsetof(EntityCollisionCellSpan, mSpatialGrid) == 0x08, "EntityCollisionCellSpan::mSpatialGrid offset must be 0x08"
  );
  static_assert(
    offsetof(EntityCollisionCellSpan, mBucketFlags) == 0x10, "EntityCollisionCellSpan::mBucketFlags offset must be 0x10"
  );

  /**
   * Address: 0x0050B480 (FUN_0050B480, ?COORDS_Orient@Moho@@YA?AV?$Quaternion@M@Wm3@@ABV?$Vector3@M@3@@Z)
   *
   * What it does:
   * Builds an orientation quaternion whose forward axis follows `direction`,
   * with fixed fallback quaternions for zero-length and vertical vectors.
   */
  [[nodiscard]] Wm3::Quaternionf COORDS_Orient(const Wm3::Vector3f& direction) noexcept;

  class Entity : public CScriptObject, public CTask
  {
    // Primary vftable (38 entries)
  public:
    /**
     * Address: 0x00676C40
     * VFTable SLOT: 0
     */
    [[nodiscard]]
    virtual gpg::RType* GetClass() const override;

    /**
     * Address: 0x00676C60
     * VFTable SLOT: 1
     */
    virtual gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x00677C60
     * VFTable SLOT: 2
     */
    virtual ~Entity() = 0;

    /**
     * Address: 0x006779E0 (FUN_006779E0)
     *
     * Moho::Sim *,int
     *
     * What it does:
     * Serialization constructor lane that seeds base entity storage directly
     * from `Sim` and collision-bucket flags without blueprint script binding.
     */
    Entity(Sim* sim, std::uint32_t collisionBucketFlags);

    /**
     * Address: 0x00677C90 (FUN_00677C90)
     *
     * What it does:
     * Base entity constructor path used by derived classes (Unit/Prop/etc).
     * Initializes collision span/list nodes, default transform/state blocks,
     * then executes `StandardInit`.
     */
    Entity(REntityBlueprint* blueprint, Sim* sim, EntId entityId, std::uint32_t collisionBucketFlags);

    /**
     * Address: 0x00677F40 (FUN_00677F40)
     *
     * LuaPlus::LuaObject const &,Moho::Sim *,Moho::EntId
     *
     * What it does:
     * Initializes base entity state from a pre-created Lua object, seeds
     * default collision grid bucket flags (`0x800`), runs `StandardInit`,
     * then binds the script object via `SetLuaObject`.
     */
    Entity(const LuaPlus::LuaObject& luaObject, Sim* sim, EntId entityId);

    /**
     * Address: 0x0067B470 (FUN_0067B470,
     * ?MemberSaveConstructArgs@Entity@Moho@@AAEXAAVWriteArchive@gpg@@HABVRRef@4@AAVSerSaveConstructArgsResult@4@@Z)
     *
     * What it does:
     * Saves construct payload (`Sim*`) as an unowned tracked-pointer lane.
     */
    void MemberSaveConstructArgs(
      gpg::WriteArchive& archive,
      int version,
      const gpg::RRef& ownerRef,
      gpg::SerSaveConstructArgsResult& result
    );

    /**
     * Address: 0x0067B570 (FUN_0067B570,
     * ?MemberConstruct@Entity@Moho@@CAXAAVReadArchive@gpg@@HABVRRef@4@AAVSerConstructResult@4@@Z)
     *
     * What it does:
     * Reads construct payload (`Sim*`) and allocates one `Entity` with
     * default entity collision-bucket flags (`0x800`).
     */
    static void MemberConstruct(
      gpg::ReadArchive& archive,
      int version,
      const gpg::RRef& ownerRef,
      gpg::SerConstructResult& result
    );

    /**
     * Address: 0x00679F70
     * (CTask secondary vtable Execute slot forwards to MotionTick path.)
     */
    int Execute() override;

    /**
     * Address: 0x00678D40
     * VFTable SLOT: 3
     */
    virtual msvc8::string GetErrorDescription() override;

    /**
     * Address: 0x005BDB10
     * VFTable SLOT: 4
     */
    virtual Unit* IsUnit();

    /**
     * Address: 0x005BDB20
     * VFTable SLOT: 5
     */
    virtual Prop* IsProp();

    /**
     * Address: 0x005BDB30
     * VFTable SLOT: 6
     */
    virtual Projectile* IsProjectile();

    /**
     * Address: 0x00672BB0
     * VFTable SLOT: 7
     */
    virtual ReconBlip* IsReconBlip();

    /**
     * Address: 0x005BDB40
     * VFTable SLOT: 8
     */
    virtual CollisionBeamEntity* IsCollisionBeam();

    /**
     * Address: 0x005BDB50
     * VFTable SLOT: 9
     */
    virtual Shield* IsShield();

    /**
     * Address: 0x00678BB0
     * VFTable SLOT: 10
     */
    virtual int GetBoneCount() const;

    /**
     * Address: 0x00678CC0 (FUN_00678CC0, Moho::Entity::ResolveBoneIndex)
     *
     * What it does:
     * Resolves one bone name through the entity's current mesh/skeleton lane,
     * returning `-1` when no skeleton is available.
     */
    [[nodiscard]] int ResolveBoneIndex(const char* boneName) const;

    /**
     * Address: 0x005BDB60
     * VFTable SLOT: 11
     */
    virtual bool IsBeingBuilt() const;

    /**
     * Address: 0x0067A0A0
     * VFTable SLOT: 12
     */
    virtual void Sync(SSyncData*);

    /**
     * Address: 0x0067A720 (FUN_0067A720)
     * VFTable SLOT: 13
     *
     * What it does:
     * Applies mesh resource id (usually from blueprint) and optional mesh override.
     */
    virtual void SetMesh(const RResId&, class RMeshBlueprint*, bool);

    /**
     * Address: 0x005BDBD0
     * VFTable SLOT: 14
     */
    virtual float GetUniformScale() const;

    /**
     * Address: 0x00678DC0
     * VFTable SLOT: 15
     */
    virtual Wm3::Vec3f GetVelocity() const;

    /**
     * Address: 0x005BDBF0
     * VFTable SLOT: 16
     */
    virtual bool IsMobile() const;

    /**
     * Address: 0x00679210
     * VFTable SLOT: 17
     */
    virtual void Warp(const VTransform&);

    /**
     * Address: 0x00678E90 (FUN_00678E90, ?SetPendingTransform@Entity@Moho@@QAEXABVVTransform@2@M@Z)
     *
     * What it does:
     * Writes pending transform payload + pending velocity scale and ensures
     * this entity is linked into the Sim coord update list.
     */
    void SetPendingTransform(const VTransform& transform, float pendingVelocityScale);

    /** Address: 0x00679CE0, VFTable SLOT: 18 */
    virtual VTransform GetBoneWorldTransform(int) const;

    /** Address: 0x00679E20, VFTable SLOT: 19 */
    virtual VTransform GetBoneLocalTransform(int) const;

    /** Address: 0x00679F70, VFTable SLOT: 20 */
    virtual int MotionTick();

    /**
     * Address: 0x00679FA0 (FUN_00679FA0)
     * VFTable SLOT: 21
     *
     * std::auto_ptr<Moho::Motor>&
     */
    virtual void SetMotor(msvc8::auto_ptr<EntityMotor>&);

    /**
     * Address: 0x005BDC10
     * VFTable SLOT: 22
     */
    virtual msvc8::vector<Entity*>& GetAttachedEntities();

    /**
     * Address: 0x00679550 (FUN_00679550)
     * VFTable SLOT: 23
     *
     * What it does:
     * Validates parent attach chain, appends this entity to parent attached-list,
     * and applies attach-link/local-transform payload into `mAttachInfo`.
     */
    virtual bool AttachTo(const SEntAttachInfo&);

    /**
     * Address: 0x006796F0 (FUN_006796F0)
     * VFTable SLOT: 24
     *
     * What it does:
     * Removes this entity from the given parent attached-list and clears `mAttachInfo`.
     */
    virtual bool DetachFrom(Entity*, bool);

    /** Address: 0x006797E0, VFTable SLOT: 25 */
    virtual void AttachedEntityDestroyed(Entity*);

    /** Address: 0x00679800, VFTable SLOT: 26 */
    virtual void AttachedEntityKilled(Entity*);

    /** Address: 0x00679820, VFTable SLOT: 27 */
    virtual void ParentEntityDestroyed(Entity*);

    /** Address: 0x00679840, VFTable SLOT: 28 */
    virtual void ParentEntityKilled(Entity*);

    /**
     * Address: 0x005BDC20
     * VFTable SLOT: 29
     */
    virtual float Materialize(float);

    /** Address: 0x00679860, VFTable SLOT: 30 */
    virtual void AdjustHealth(Entity*, float);

    /** Address: 0x00679A80, VFTable SLOT: 31 */
    virtual void Kill(Entity*, gpg::StrArg, float);

    /**
     * Address: 0x00679B80 (FUN_00679B80)
     * VFTable SLOT: 32
     *
     * What it does:
     * Marks destroy dispatch, queues this entity in Sim destroy tracking, notifies script,
     * detaches from parent, and notifies attached children.
     */
    virtual void OnDestroy();

    /**
     * Address: 0x00679B80 callsite alias
     *
     * What it does:
     * Public non-virtual helper used by Sim command paths to trigger
     * the standard destroy dispatch.
     */
    void Destroy();

    /**
     * Address: 0x006791D0 (FUN_006791D0)
     * VFTable SLOT: 33
     *
     * What it does:
     * Applies current transform to collision primitive, relinks collision-cell
     * grid membership, and refreshes cached bounds.
     */
    virtual void UpdateCollision();

    /**
     * Address: 0x0067AC40 (FUN_0067AC40)
     *
     * What it does:
     * Installs a box collision primitive, applies current transform, relinks
     * collision-cell membership, and refreshes cached bounds.
     */
    void SetCollisionBoxShape(const Wm3::Box3f& localBox);

    /**
     * Address: 0x0067AD30 (FUN_0067AD30)
     *
     * What it does:
     * Installs a sphere collision primitive, applies current transform,
     * relinks collision-cell membership, and refreshes cached bounds.
     */
    void SetCollisionSphereShape(const Wm3::Vec3f& localCenter, float radius);

    /**
     * Address: 0x0067AE00 (FUN_0067AE00)
     *
     * What it does:
     * Deletes active collision primitive and clears collision-cell span.
     */
    void RevertCollisionShape();

    /**
     * Address: 0x0067AE70 (FUN_0067AE70)
     *
     * What it does:
     * Rebuilds collision primitive from blueprint collision-shape fields.
     */
    void RefreshCollisionShapeFromBlueprint();

    /** Address: 0x0067A220, VFTable SLOT: 34 */
    virtual void CreateInterface(SSyncData*);

    /** Address: 0x0067A260, VFTable SLOT: 35 */
    virtual void DestroyInterface(SSyncData*);

    /** Address: 0x0067A290, VFTable SLOT: 36 */
    virtual void SyncInterface(SSyncData*);

    /** Address: 0x00678A70, VFTable SLOT: 37 */
    virtual void UpdateVisibility();

    /**
     * Address: 0x00679940
     *
     * What it does:
     * Applies absolute health with 0.25-quantized callback thresholding.
     */
    void SetHealth(float newHealth);

    void MarkNeedsSyncGameData() noexcept;

    /**
     * Address: 0x00678880 (FUN_00678880, ?GetFootprint@Entity@Moho@@QBEABUSFootprint@2@XZ)
     *
     * What it does:
     * Returns active footprint (default or alt footprint).
     * Throws when blueprint pointer is missing.
     */
    [[nodiscard]] const SFootprint& GetFootprint() const;

    /**
     * Address: 0x0067AFF0 (FUN_0067AFF0, ?SetCurrentLayer@Entity@Moho@@QAEXW4ELayer@2@@Z)
     *
     * What it does:
     * Updates current layer and issues `OnLayerChange(new, old)` callback.
     */
    void SetCurrentLayer(const ELayer newLayer);

    /**
     * Address: 0x0067B050 (FUN_0067B050)
     *
     * What it does:
     * Resolves category expression via Sim rules and tests this blueprint bit.
     */
    [[nodiscard]] bool IsInCategory(const char* categoryName) const noexcept;

    [[nodiscard]] Wm3::Vec3f const& GetPositionWm3() const noexcept;

    [[nodiscard]] VTransform const& GetTransformWm3() const noexcept;

    /**
     * Address: 0x00678800 (FUN_00678800, ?InitPositionHistory@Entity@Moho@@QAEXXZ)
     *
     * What it does:
     * Rebuilds the rolling position-history ring with identity/default samples.
     */
    void InitPositionHistory();

    /**
     * Address: 0x00678F10 (FUN_00678F10)
     *
     * What it does:
     * Commits this frame transform into previous/history slots and processes coord-side effects.
     */
    void AdvanceCoords();

    /**
     * Address: 0x00678370 (FUN_00678370)
     *
     * What it does:
     * Finalizes runtime identity/state ownership in Sim lists and initializes
     * per-entity defaults after base construction.
     */
    void StandardInit(Sim* sim, EntId entityId);

    /**
     * Address: 0x0062AD30 / 0x00678880 (FUN_0062AD30/FUN_00678880)
     *
     * What it does:
     * Chooses initial simulation layer from footprint occupancy, category hints,
     * and current map water state.
     */
    [[nodiscard]] ELayer GetStartingLayer(const Wm3::Vec3f& worldPos, ELayer desiredLayer) const;

    /**
     * Address: 0x00689F20 (FUN_00689F20, Moho::Entity::GetUniqueName)
     *
     * What it does:
     * Returns the entity's unique runtime name string.
     */
    [[nodiscard]] msvc8::string GetUniqueName() const;

  public:
    /**
     * Address: 0x0050AD80 (FUN_0050AD80, ?COORDS_LayerToString@Moho@@YAPBDW4ELayer@1@@Z)
     *
     * What it does:
     * Returns debug/script text for a single-layer enum value and falls back to
     * an empty string for bitmask combinations.
     */
    [[nodiscard]] static const char* LayerToString(const ELayer layer) noexcept;

    // Entity data begins after CScriptObject(+0x34) and CTask(+0x18) subobjects.
    EntityCollisionCellSpan mCollisionCellSpan; // 0x004C

    // 0x60: intrusive node used by Sim::mCoordEntities (+0xA5C in Sim).
    TDatListItem<Entity, void> mCoordNode;
    EntId id_;                     // 0x0068
    REntityBlueprint* BluePrint;   // 0x006C
    std::uint32_t mTickCreated;    // 0x0070
    std::uint32_t mReserved74;     // 0x0074
    gpg::RRef mMeshRef;            // 0x0078
    std::int32_t mMeshTypeClassId; // 0x0080
    float mDrawScaleX;             // 0x0084
    float mDrawScaleY;             // 0x0088
    float mDrawScaleZ;             // 0x008C
    float Health;                  // 0x0090
    float MaxHealth;               // 0x0094
    std::uint8_t BeingBuilt;       // 0x0098
    std::uint8_t Dead;             // 0x0099
    std::uint8_t DirtySyncState;   // 0x009A: set by Unit state mutators for sync replication
    std::uint8_t mDestroyedByKill; // 0x009B
    // Current world transform payload (quaternion xyzw + position), split to preserve ABI layout.
    Vector4f Orientation;   // 0x009C
    Wm3::Vector3f Position; // 0x00AC
    // Previous frame transform payload, same split layout.
    Vector4f PrevOrientation;                  // 0x00B8
    Wm3::Vector3f PrevPosition;                // 0x00C8
    float mVelocityScale;                      // 0x00D4
    float FractionCompleted;                   // 0x00D8
    std::uint8_t pad_00DC_0110[0x110 - 0x0DC]; // 0x00DC
    std::uint8_t mVisibilityState;             // 0x0110
    char pad_0111[3];                          // 0x0111
    std::int32_t mFootprintLayer;              // 0x0114
    ELayer mCurrentLayer;                      // 0x0118
    std::uint8_t mUseAltFootprint;             // 0x011C
    std::uint8_t mUseAltFootprintSecondary;    // 0x011D
    char pad_011E[2];                          // 0x011E
    char pad_0120[0x28];                       // 0x0120
    Sim* SimulationRef;                        // 0x0148
    // +0x014C is the owning army pointer in constructor/init and callsite evidence.
    // Attachment parent linkage is represented by mAttachInfo (+0x018C).
    CArmyImpl* ArmyRef;                           // 0x014C
    // Pending transform payload (equivalent logical role to VTransform: orientation + position).
    Vector4f PendingOrientation;                   // 0x0150
    Wm3::Vector3f PendingPosition;                 // 0x0160
    PositionHistory* mPositionHistory;             // 0x016C
    float mPendingVelocityScale;                   // 0x0170
    char pad_0174[4];                              // 0x0174
    EntityCollisionUpdater* CollisionExtents;      // 0x0178
    msvc8::vector<Entity*> mAttachedEntities;      // 0x017C
    SEntAttachInfo mAttachInfo;                    // 0x018C
    std::uint8_t mQueueRelinkBlocked;              // 0x01B8
    std::uint8_t DestroyQueuedFlag;                // 0x01B9
    std::uint8_t mOnDestroyDispatched;             // 0x01BA
    char pad_01BB[0x1D];                           // 0x01BB
    CIntel* mIntelManager;                // 0x01D8
    std::int32_t mVisibilityLayerFriendly; // 0x01DC
    std::int32_t mVisibilityLayerEnemy;    // 0x01E0
    std::int32_t mVisibilityLayerNeutral;  // 0x01E4
    std::int32_t mVisibilityLayerDefault;  // 0x01E8
    std::uint8_t mInterfaceCreated;        // 0x01EC
    char pad_01ED[0x07];                   // 0x01ED
    std::int32_t readinessFlags;           // 0x01F4
    char pad_01F8_01FC[0x04];              // 0x01F8
    msvc8::string mUniqueName;             // 0x01FC (FUN_00689F20)
    char pad_0218_0240[0x28];              // 0x0218
    Wm3::Vector3f mCollisionBoundsMin;     // 0x0240
    Wm3::Vector3f mCollisionBoundsMax;     // 0x024C
    char pad_0258[0x14];                   // 0x0258
    EntityMotor* mMotor;                   // 0x026C
  };

  /**
   * Address: 0x00692580 (FUN_00692580, Moho::ENTSCR_ResolveBoneIndex)
   *
   * What it does:
   * Resolves one Lua bone identifier (integer index, string name, or optional
   * nil lane) into one validated entity bone index.
   */
  int ENTSCR_ResolveBoneIndex(Entity* entity, LuaPlus::LuaStackObject& boneIdentifier, bool allowNilAndSpecialIndices);

  static_assert(sizeof(Entity) == 0x270, "Entity size must be 0x270");
  static_assert(offsetof(Entity, mCollisionCellSpan) == 0x4C, "Entity::mCollisionCellSpan offset must be 0x4C");
  static_assert(offsetof(Entity, mCoordNode) == 0x60, "Entity::mCoordNode offset must be 0x60");
  static_assert(offsetof(Entity, id_) == 0x68, "Entity::id_ offset must be 0x68");
  static_assert(offsetof(Entity, BluePrint) == 0x6C, "Entity::BluePrint offset must be 0x6C");
  static_assert(offsetof(Entity, mTickCreated) == 0x70, "Entity::mTickCreated offset must be 0x70");
  static_assert(offsetof(Entity, mReserved74) == 0x74, "Entity::mReserved74 offset must be 0x74");
  static_assert(offsetof(Entity, Health) == 0x90, "Entity::Health offset must be 0x90");
  static_assert(offsetof(Entity, MaxHealth) == 0x94, "Entity::MaxHealth offset must be 0x94");
  static_assert(offsetof(Entity, BeingBuilt) == 0x98, "Entity::BeingBuilt offset must be 0x98");
  static_assert(offsetof(Entity, Orientation) == 0x9C, "Entity::Orientation offset must be 0x9C");
  static_assert(offsetof(Entity, Position) == 0xAC, "Entity::Position offset must be 0xAC");
  static_assert(offsetof(Entity, PrevOrientation) == 0xB8, "Entity::PrevOrientation offset must be 0xB8");
  static_assert(offsetof(Entity, PrevPosition) == 0xC8, "Entity::PrevPosition offset must be 0xC8");
  static_assert(offsetof(Entity, FractionCompleted) == 0xD8, "Entity::FractionCompleted offset must be 0xD8");
  static_assert(offsetof(Entity, mVisibilityState) == 0x110, "Entity::mVisibilityState offset must be 0x110");
  static_assert(offsetof(Entity, mFootprintLayer) == 0x114, "Entity::mFootprintLayer offset must be 0x114");
  static_assert(offsetof(Entity, mCurrentLayer) == 0x118, "Entity::mCurrentLayer offset must be 0x118");
  static_assert(offsetof(Entity, mUseAltFootprint) == 0x11C, "Entity::mUseAltFootprint offset must be 0x11C");
  static_assert(
    offsetof(Entity, mUseAltFootprintSecondary) == 0x11D, "Entity::mUseAltFootprintSecondary offset must be 0x11D"
  );
  static_assert(offsetof(Entity, SimulationRef) == 0x148, "Entity::SimulationRef offset must be 0x148");
  static_assert(offsetof(Entity, ArmyRef) == 0x14C, "Entity::ArmyRef offset must be 0x14C");
  static_assert(offsetof(Entity, PendingOrientation) == 0x150, "Entity::PendingOrientation offset must be 0x150");
  static_assert(offsetof(Entity, PendingPosition) == 0x160, "Entity::PendingPosition offset must be 0x160");
  static_assert(offsetof(Entity, mPositionHistory) == 0x16C, "Entity::mPositionHistory offset must be 0x16C");
  static_assert(offsetof(Entity, mPendingVelocityScale) == 0x170, "Entity::mPendingVelocityScale offset must be 0x170");
  static_assert(offsetof(Entity, CollisionExtents) == 0x178, "Entity::CollisionExtents offset must be 0x178");
  static_assert(offsetof(Entity, mAttachedEntities) == 0x17C, "Entity::mAttachedEntities offset must be 0x17C");
  static_assert(offsetof(Entity, mAttachInfo) == 0x18C, "Entity::mAttachInfo offset must be 0x18C");
  static_assert(offsetof(Entity, DestroyQueuedFlag) == 0x1B9, "Entity::DestroyQueuedFlag offset must be 0x1B9");
  static_assert(offsetof(Entity, mIntelManager) == 0x1D8, "Entity::mIntelManager offset must be 0x1D8");
  static_assert(offsetof(Entity, mInterfaceCreated) == 0x1EC, "Entity::mInterfaceCreated offset must be 0x1EC");
  static_assert(offsetof(Entity, mUniqueName) == 0x1FC, "Entity::mUniqueName offset must be 0x1FC");
  static_assert(offsetof(Entity, mCollisionBoundsMin) == 0x240, "Entity::mCollisionBoundsMin offset must be 0x240");
  static_assert(offsetof(Entity, mCollisionBoundsMax) == 0x24C, "Entity::mCollisionBoundsMax offset must be 0x24C");
  static_assert(offsetof(Entity, mMotor) == 0x26C, "Entity::mMotor offset must be 0x26C");

  template <class T>
  class EntitySetTemplate
    : public TDatList<EntitySetTemplate<T>, void>
  {
  public:
    inline static gpg::RType* sType = nullptr;

    using storage_type = gpg::fastvector_n<Entity*, 4>;
    using iterator = Entity**;
    using const_iterator = Entity* const*;

    struct InsertResult
    {
      iterator position;
      bool inserted;
    };

    EntitySetTemplate() noexcept = default;

    EntitySetTemplate(const EntitySetTemplate&) = delete;
    EntitySetTemplate& operator=(const EntitySetTemplate&) = delete;

    EntitySetTemplate(EntitySetTemplate&& other) noexcept
      : TDatList<EntitySetTemplate<T>, void>{}
      , mVec()
    {
      mVec.ResetFrom(other.mVec);
      other.Clear();
    }

    EntitySetTemplate& operator=(EntitySetTemplate&& other) noexcept
    {
      if (this == &other) {
        return *this;
      }

      Clear();
      this->ListUnlink();
      mVec.ResetFrom(other.mVec);
      other.Clear();
      return *this;
    }

    /**
     * Address: 0x005C23A0 (FUN_005C23A0)
     *
     * What it does:
     * Resets fastvector_n storage back to inline capacity and unlinks this
     * intrusive list node from its owner chain.
     */
    ~EntitySetTemplate()
    {
      Clear();
      this->ListUnlink();
    }

    [[nodiscard]] bool Empty() const noexcept
    {
      return mVec.begin() == mVec.end();
    }

    [[nodiscard]] std::size_t Size() const noexcept
    {
      return static_cast<std::size_t>(mVec.end() - mVec.begin());
    }

    [[nodiscard]] iterator begin() noexcept
    {
      return mVec.begin();
    }

    [[nodiscard]] iterator end() noexcept
    {
      return mVec.end();
    }

    [[nodiscard]] const_iterator begin() const noexcept
    {
      return mVec.begin();
    }

    [[nodiscard]] const_iterator end() const noexcept
    {
      return mVec.end();
    }

    [[nodiscard]] bool Contains(const Entity* const entity) const noexcept
    {
      if (!entity) {
        return false;
      }

      const std::uint32_t key = static_cast<std::uint32_t>(entity->id_);
      const const_iterator it = LowerBoundByEntityId(begin(), end(), key);
      return it != end() && *it == entity;
    }

    [[nodiscard]] bool Add(Entity* const entity)
    {
      if (!entity) {
        return false;
      }

      return InsertUniqueByEntityId(mVec, entity).inserted;
    }

    void Clear() noexcept
    {
      mVec.ResetStorageToInline();
    }

  public:
    storage_type mVec;

  private:
    template <typename Iter>
    [[nodiscard]] static Iter LowerBoundByEntityIdImpl(Iter first, Iter last, const std::uint32_t targetId) noexcept
    {
      std::ptrdiff_t count = last - first;
      while (count > 0) {
        const std::ptrdiff_t step = count / 2;
        Iter mid = first + step;
        const Entity* const candidate = *mid;
        const std::uint32_t candidateId = candidate ? static_cast<std::uint32_t>(candidate->id_) : 0u;
        if (candidateId < targetId) {
          first = mid + 1;
          count -= step + 1;
        } else {
          count = step;
        }
      }
      return first;
    }

    /**
     * Address: 0x005CB710 (FUN_005CB710)
     *
     * What it does:
     * Binary-search lower-bound over a sorted `Entity*` span by `Entity::id_`.
     */
    [[nodiscard]] static iterator LowerBoundByEntityId(
      iterator first, iterator last, const std::uint32_t targetId
    ) noexcept
    {
      return LowerBoundByEntityIdImpl(first, last, targetId);
    }

    /**
     * Address: 0x005CB710 (FUN_005CB710)
     *
     * What it does:
     * Const overload of lower-bound search over sorted `Entity*` span.
     */
    [[nodiscard]] static const_iterator LowerBoundByEntityId(
      const_iterator first, const_iterator last, const std::uint32_t targetId
    ) noexcept
    {
      return LowerBoundByEntityIdImpl(first, last, targetId);
    }

    /**
     * Address: 0x005C3A90 (FUN_005C3A90)
     *
     * What it does:
     * Inserts one entity pointer into sorted storage when missing and returns
     * `{position, inserted}` semantics.
     */
    [[nodiscard]] static InsertResult InsertUniqueByEntityId(storage_type& vec, Entity* const entity) noexcept
    {
      iterator first = vec.begin();
      iterator last = vec.end();
      const std::uint32_t key = static_cast<std::uint32_t>(entity->id_);
      iterator it = LowerBoundByEntityId(first, last, key);
      if (it != last && *it == entity) {
        return InsertResult{it, false};
      }

      const std::ptrdiff_t insertionIndex = it - first;
      vec.InsertAt(it, &entity, &entity + 1);
      return InsertResult{vec.begin() + insertionIndex, true};
    }
  };

  static_assert(
    offsetof(EntitySetTemplate<Entity>, mVec) == 0x08, "EntitySetTemplate<Entity>::mVec offset must be 0x08"
  );
  static_assert(sizeof(EntitySetTemplate<Entity>) == 0x28, "EntitySetTemplate<Entity> size must be 0x28");

  /**
   * Binary-facing alias wrapper for `EntitySetTemplate<Entity>` with independent RTTI slot.
   */
  class EntitySetBase : public EntitySetTemplate<Entity>
  {
  public:
    inline static gpg::RType* sType = nullptr;
  };

  /**
   * Binary-facing weak set wrapper that preserves legacy RTTI identity while reusing
   * `EntitySetTemplate<T>` storage/layout lanes.
   */
  template <class T>
  class WeakEntitySetTemplate : public EntitySetTemplate<T>
  {
  public:
    inline static gpg::RType* sType = nullptr;
  };

  using UnitSet = EntitySetTemplate<Unit>;
  using WeakUnitSet = WeakEntitySetTemplate<Unit>;

  static_assert(sizeof(EntitySetBase) == 0x28, "EntitySetBase size must be 0x28");
  static_assert(sizeof(WeakEntitySetTemplate<Unit>) == 0x28, "WeakEntitySetTemplate<Unit> size must be 0x28");
} // namespace moho
