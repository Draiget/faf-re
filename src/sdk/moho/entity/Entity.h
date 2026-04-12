#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
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
#include "Wm3Box3.h"
#include "Wm3Quaternion.h"
#include "Wm3Vector3.h"

struct lua_State;

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
  struct RResId;
  struct RMeshBlueprint;
  class ReconBlip;
  class Shield;
  class Sim;
  struct SPhysBody;
  class Unit;
  class CD3DBatchTexture;
  class VTransform;
  class CIntel;
  class EntityMotor;
  class EntityCollisionUpdater;
  class CArmyImpl;
  class CSndParams;
  class STIMap;
  enum EVisibilityMode : std::int32_t;
  struct PositionHistory;
  struct SCoordsVec2;
  struct SOCellPos;
  struct SFootprint;
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

  /**
   * Address: 0x0050B820 (FUN_0050B820, ?COORDS_Tilt@Moho@@YAXPAV?$Quaternion@M@Wm3@@V?$Vector3@M@3@@Z)
   *
   * What it does:
   * Tilts `orientation` so its local up-axis follows `surfaceNormal` while
   * preserving heading by pre-multiplying one shortest-arc tilt quaternion.
   */
  void COORDS_Tilt(Wm3::Quaternionf* orientation, Wm3::Vector3f surfaceNormal) noexcept;

  /**
   * Address: 0x0050AE10 (FUN_0050AE10, ?COORDS_StringToLayer@Moho@@YA?AW4ELayer@1@PBD@Z)
   *
   * What it does:
   * Parses one layer-name string and returns the matching `ELayer` value,
   * defaulting to `LAYER_None` for unknown text.
   */
  [[nodiscard]] ELayer COORDS_StringToLayer(const char* layerName) noexcept;

  /**
   * Address: 0x0050B0F0 (FUN_0050B0F0, ?COORDS_ToWorldPos@Moho@@YA?AV?$Vector3@M@Wm3@@PBVSTIMap@1@ABUSOCellPos@1@EHH@Z)
   *
   * What it does:
   * Converts one footprint-origin cell position into world center position and
   * samples terrain/water elevation by requested layer.
   */
  [[nodiscard]] Wm3::Vector3f
  COORDS_ToWorldPos(const STIMap* map, const SOCellPos& cellPos, ELayer layer, int sizeX, int sizeZ) noexcept;

  /**
   * Address: 0x0050B1A0 (FUN_0050B1A0, ?COORDS_ToWorldPos@Moho@@YA?AV?$Vector3@M@Wm3@@PBVSTIMap@1@ABUSOCellPos@1@ABUSFootprint@1@@Z)
   *
   * What it does:
   * Convenience overload that converts one cell position using a footprint's
   * layer and dimensions.
   */
  [[nodiscard]] Wm3::Vector3f
  COORDS_ToWorldPos(const STIMap* map, const SOCellPos& cellPos, const SFootprint& footprint) noexcept;

  /**
   * Address: 0x0050B260 (FUN_0050B260, ?COORDS_GridSnap@Moho@@YA?AV?$Vector3@M@Wm3@@PBVSTIMap@1@ABUSCoordsVec2@1@ABUSFootprint@1@W4ELayer@1@@Z)
   *
   * What it does:
   * Snaps one world XZ center to footprint-origin cell coordinates and returns
   * the corresponding world-aligned snapped position.
   */
  [[nodiscard]] Wm3::Vector3f
  COORDS_GridSnap(const STIMap* map, const SCoordsVec2& worldPos, const SFootprint& footprint, ELayer layer) noexcept;

  template <class T>
  class EntitySetTemplate
    : public TDatList<EntitySetTemplate<T>, void>
  {
  public:
    inline static gpg::RType* sType = nullptr;

    using storage_type = gpg::fastvector_n<T*, 4>;
    using iterator = T**;
    using const_iterator = T* const*;

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

    [[nodiscard]] bool Contains(const T* const entity) const noexcept
    {
      if (!entity) {
        return false;
      }

      const std::uint32_t key = static_cast<std::uint32_t>(entity->id_);
      const const_iterator it = LowerBoundByEntityId(begin(), end(), key);
      return it != end() && *it == entity;
    }

    [[nodiscard]] bool Add(T* const entity)
    {
      if (!entity) {
        return false;
      }

      return InsertUniqueByEntityId(mVec, entity).inserted;
    }

    /**
     * Address: 0x0067BCE0 (FUN_0067BCE0, Moho::EntitySetTemplate_Entity::Remove)
     *
     * What it does:
     * Removes one exact entity pointer from sorted storage when present and
     * compacts trailing elements.
     */
    [[nodiscard]] bool Remove(T* const entity) noexcept
    {
      if (!entity) {
        return false;
      }

      iterator first = mVec.begin();
      iterator last = mVec.end();
      const std::uint32_t key = static_cast<std::uint32_t>(entity->id_);
      iterator it = LowerBoundByEntityId(first, last, key);
      if (it == last || *it != entity) {
        return false;
      }

      mVec.erase(it, it + 1);
      return true;
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
        const T* const candidate = *mid;
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
    [[nodiscard]] static InsertResult InsertUniqueByEntityId(storage_type& vec, T* const entity) noexcept
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
     * Address: 0x0067CFA0 (FUN_0067CFA0, Moho::Entity::GetPointerType)
     *
     * What it does:
     * Lazily resolves and returns reflected pointer type descriptor for
     * `Entity*`.
     */
    [[nodiscard]] static gpg::RType* GetPointerType();

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
     * Address: 0x00678B90 (FUN_00678B90, Moho::Entity::GetArmyIndex)
     *
     * What it does:
     * Returns owning army id for this entity, or `-1` when no army owner is
     * bound.
     */
    [[nodiscard]] int GetArmyIndex() const;

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
    virtual void SetMesh(const RResId&, struct RMeshBlueprint*, bool);

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

    /**
     * Address: 0x00679120 (FUN_00679120, Moho::Entity::UpdateIntel)
     *
     * What it does:
     * Updates intel manager probe position from current transform payload.
     */
    void UpdateIntel();

    /**
     * Address: 0x00679290 (FUN_00679290, ?GetPhysBody@Entity@Moho@@QAEPAUSPhysBody@2@_N@Z)
     *
     * What it does:
     * Returns cached physics-body state, lazily creating and initializing it
     * from blueprint + current transform lanes when absent.
     */
    [[nodiscard]] SPhysBody* GetPhysBody(bool unusedFlag = false);

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
     * Address: 0x00679AF0 (FUN_00679AF0, ?Destroy@Entity@Moho@@QAEXXZ)
     *
     * What it does:
     * Queues this entity once for Sim deletion processing, logs the queue event,
     * and relinks its coord-update node at the Sim coord tail.
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
     * Address: 0x00678930 (FUN_00678930, Moho::Entity::SetVizToFocusPlayer)
     *
     * What it does:
     * Updates focus-player visibility mode and requests coord-visibility refresh.
     */
    void SetVizToFocusPlayer(EVisibilityMode mode);

    /**
     * Address: 0x00678980 (FUN_00678980, Moho::Entity::SetVizToEnemies)
     *
     * What it does:
     * Updates enemy visibility mode and requests coord-visibility refresh.
     */
    void SetVizToEnemies(EVisibilityMode mode);

    /**
     * Address: 0x006789D0 (FUN_006789D0, Moho::Entity::SetVizToAllies)
     *
     * What it does:
     * Updates ally visibility mode and requests coord-visibility refresh.
     */
    void SetVizToAllies(EVisibilityMode mode);

    /**
     * Address: 0x00678A20 (FUN_00678A20, Moho::Entity::SetVizToNeutrals)
     *
     * What it does:
     * Updates neutral visibility mode and requests coord-visibility refresh.
     */
    void SetVizToNeutrals(EVisibilityMode mode);

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

    /**
     * Address: 0x0067B0C0 (FUN_0067B0C0, ?SetStrategicUnderlay@Entity@Moho@@QAEXABVRResId@2@@Z)
     *
     * What it does:
     * Applies one strategic underlay icon id by resolving the icon rest texture
     * path and re-queueing this entity in the coord update list.
     */
    void SetStrategicUnderlay(const RResId& underlayId);

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
    std::uint8_t pad_00DC_0108[0x108 - 0x0DC]; // 0x00DC
    CSndParams* mAmbientSound;                 // 0x0108
    CSndParams* mRumbleSound;                  // 0x010C
    std::uint8_t mVisibilityState;             // 0x0110
    char pad_0111[3];                          // 0x0111
    std::int32_t mFootprintLayer;              // 0x0114
    ELayer mCurrentLayer;                      // 0x0118
    std::uint8_t mUseAltFootprint;             // 0x011C
    std::uint8_t mUseAltFootprintSecondary;    // 0x011D
    char pad_011E[2];                          // 0x011E
    boost::shared_ptr<CD3DBatchTexture> mStrategicUnderlayTexture; // 0x0120
    char pad_0128[0x20];                                         // 0x0128
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
    EntitySetBase mShooters;               // 0x0218 (Entity:AddShooter/RemoveShooter ownership set)
    Wm3::Vector3f mCollisionBoundsMin;     // 0x0240
    Wm3::Vector3f mCollisionBoundsMax;     // 0x024C
    LuaPlus::LuaObject mLuaPositionCache;  // 0x0258 (cached `Entity:GetPosition()` vector table)
    EntityMotor* mMotor;                   // 0x026C
  };

  /**
   * Address: 0x0068A0B0 (FUN_0068A0B0, func_EntityCreateProjectile_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:CreateProjectile(proj_bp, [ox,oy,oz], [dx,dy,dz])`
   * Lua binder.
   */
  CScrLuaInitForm* func_EntityCreateProjectile_LuaFuncDef();

  /**
   * Address: 0x0068A090 (FUN_0068A090, cfunc_EntityCreateProjectile)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_EntityCreateProjectileL`.
   */
  int cfunc_EntityCreateProjectile(lua_State* luaContext);

  /**
   * Address: 0x0068A110 (FUN_0068A110, cfunc_EntityCreateProjectileL)
   *
   * What it does:
   * Spawns one projectile from `(entity, projectileBlueprint[, offset][,dir])`
   * and returns the spawned projectile Lua object.
   */
  int cfunc_EntityCreateProjectileL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068A690 (FUN_0068A690, func_EntityCreateProjectileAtBone_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:CreateProjectileAtBone(projectile_blueprint, bone)`
   * Lua binder.
   */
  CScrLuaInitForm* func_EntityCreateProjectileAtBone_LuaFuncDef();

  /**
   * Address: 0x0068A670 (FUN_0068A670, cfunc_EntityCreateProjectileAtBone)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_EntityCreateProjectileAtBoneL`.
   */
  int cfunc_EntityCreateProjectileAtBone(lua_State* luaContext);

  /**
   * Address: 0x0068A6F0 (FUN_0068A6F0, cfunc_EntityCreateProjectileAtBoneL)
   *
   * What it does:
   * Spawns one projectile from a resolved entity bone, applies randomized
   * launch speed, and returns the spawned projectile Lua object.
   */
  int cfunc_EntityCreateProjectileAtBoneL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068AB10 (FUN_0068AB10, func_EntityShakeCamera_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:ShakeCamera(radius, max, min, duration)` Lua binder.
   */
  CScrLuaInitForm* func_EntityShakeCamera_LuaFuncDef();

  /**
   * Address: 0x0068AAF0 (FUN_0068AAF0, cfunc_EntityShakeCamera)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityShakeCameraL`.
   */
  int cfunc_EntityShakeCamera(lua_State* luaContext);

  /**
   * Address: 0x0068AB70 (FUN_0068AB70, cfunc_EntityShakeCameraL)
   *
   * What it does:
   * Resolves `(entity, radius, max, min, duration)` and enqueues one camera
   * shake request centered on the entity world position.
   */
  int cfunc_EntityShakeCameraL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068B0D0 (FUN_0068B0D0, func_GetBlueprintSim_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua function `GetBlueprint(entity)`.
   */
  CScrLuaInitForm* func_GetBlueprintSim_LuaFuncDef();

  /**
   * Address: 0x0068B0B0 (FUN_0068B0B0, cfunc_GetBlueprintSim)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_GetBlueprintSimL`.
   */
  int cfunc_GetBlueprintSim(lua_State* luaContext);

  /**
   * Address: 0x0068B130 (FUN_0068B130, cfunc_GetBlueprintSimL)
   *
   * What it does:
   * Resolves one entity arg and pushes that entity blueprint Lua table.
   */
  int cfunc_GetBlueprintSimL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068AD80 (FUN_0068AD80, func_EntityGetAIBrain_LuaFuncDef)
   *
   * What it does:
   * Publishes the `GetAIBrain(self)` Lua binder.
   */
  CScrLuaInitForm* func_EntityGetAIBrain_LuaFuncDef();

  /**
   * Address: 0x0068AD60 (FUN_0068AD60, cfunc_EntityGetAIBrain)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityGetAIBrainL`.
   */
  int cfunc_EntityGetAIBrain(lua_State* luaContext);

  /**
   * Address: 0x0068ADE0 (FUN_0068ADE0, cfunc_EntityGetAIBrainL)
   *
   * What it does:
   * Resolves one entity and returns owning army brain Lua object when present.
   */
  int cfunc_EntityGetAIBrainL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068AF50 (FUN_0068AF50, func_EntityGetBlueprint_LuaFuncDef)
   *
   * What it does:
   * Publishes the `blueprint = Entity:GetBlueprint()` Lua binder.
   */
  CScrLuaInitForm* func_EntityGetBlueprint_LuaFuncDef();

  /**
   * Address: 0x0068AF30 (FUN_0068AF30, cfunc_EntityGetBlueprint)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityGetBlueprintL`.
   */
  int cfunc_EntityGetBlueprint(lua_State* luaContext);

  /**
   * Address: 0x0068AFB0 (FUN_0068AFB0, cfunc_EntityGetBlueprintL)
   *
   * What it does:
   * Resolves one optional entity and pushes its blueprint Lua table or nil.
   */
  int cfunc_EntityGetBlueprintL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068B230 (FUN_0068B230, func_EntityGetArmy_LuaFuncDef)
   *
   * What it does:
   * Publishes `Entity:GetArmy()` Lua binder.
   */
  CScrLuaInitForm* func_EntityGetArmy_LuaFuncDef();

  /**
   * Address: 0x0068B210 (FUN_0068B210, cfunc_EntityGetArmy)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityGetArmyL`.
   */
  int cfunc_EntityGetArmy(lua_State* luaContext);

  /**
   * Address: 0x0068B290 (FUN_0068B290, cfunc_EntityGetArmyL)
   *
   * What it does:
   * Returns one-based army index for this entity, or `-1` when unowned.
   */
  int cfunc_EntityGetArmyL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068B390 (FUN_0068B390, func_EntityGetBoneDirection_LuaFuncDef)
   *
   * What it does:
   * Publishes `Entity:GetBoneDirection(bone_name)` Lua binder.
   */
  CScrLuaInitForm* func_EntityGetBoneDirection_LuaFuncDef();

  /**
   * Address: 0x0068B370 (FUN_0068B370, cfunc_EntityGetBoneDirection)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityGetBoneDirectionL`.
   */
  int cfunc_EntityGetBoneDirection(lua_State* luaContext);

  /**
   * Address: 0x0068B3F0 (FUN_0068B3F0, cfunc_EntityGetBoneDirectionL)
   *
   * What it does:
   * Resolves one bone transform and returns its forward direction vector.
   */
  int cfunc_EntityGetBoneDirectionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068B590 (FUN_0068B590, func_EntityIsValidBone_LuaFuncDef)
   *
   * What it does:
   * Publishes `Entity:IsValidBone(nameOrIndex,allowNil=false)` Lua binder.
   */
  CScrLuaInitForm* func_EntityIsValidBone_LuaFuncDef();

  /**
   * Address: 0x0068B570 (FUN_0068B570, cfunc_EntityIsValidBone)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityIsValidBoneL`.
   */
  int cfunc_EntityIsValidBone(lua_State* luaContext);

  /**
   * Address: 0x0068B5F0 (FUN_0068B5F0, cfunc_EntityIsValidBoneL)
   *
   * What it does:
   * Validates one bone identifier (name/index) and returns boolean validity.
   */
  int cfunc_EntityIsValidBoneL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068B810 (FUN_0068B810, func_EntityGetBoneCount_LuaFuncDef)
   *
   * What it does:
   * Publishes `Entity:GetBoneCount()` Lua binder.
   */
  CScrLuaInitForm* func_EntityGetBoneCount_LuaFuncDef();

  /**
   * Address: 0x0068B7F0 (FUN_0068B7F0, cfunc_EntityGetBoneCount)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityGetBoneCountL`.
   */
  int cfunc_EntityGetBoneCount(lua_State* luaContext);

  /**
   * Address: 0x0068B870 (FUN_0068B870, cfunc_EntityGetBoneCountL)
   *
   * What it does:
   * Resolves one entity arg and pushes skeleton bone count.
   */
  int cfunc_EntityGetBoneCountL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068B960 (FUN_0068B960, func_EntityGetBoneName_LuaFuncDef)
   *
   * What it does:
   * Publishes `Entity:GetBoneName(i)` Lua binder.
   */
  CScrLuaInitForm* func_EntityGetBoneName_LuaFuncDef();

  /**
   * Address: 0x0068B940 (FUN_0068B940, cfunc_EntityGetBoneName)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityGetBoneNameL`.
   */
  int cfunc_EntityGetBoneName(lua_State* luaContext);

  /**
   * Address: 0x0068B9C0 (FUN_0068B9C0, cfunc_EntityGetBoneNameL)
   *
   * What it does:
   * Resolves one bone index and pushes its name or nil.
   */
  int cfunc_EntityGetBoneNameL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068BB00 (FUN_0068BB00, func_EntityRequestRefreshUI_LuaFuncDef)
   *
   * What it does:
   * Publishes `Entity:RequestRefreshUI()` Lua binder.
   */
  CScrLuaInitForm* func_EntityRequestRefreshUI_LuaFuncDef();

  /**
   * Address: 0x0068BAE0 (FUN_0068BAE0, cfunc_EntityRequestRefreshUI)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityRequestRefreshUIL`.
   */
  int cfunc_EntityRequestRefreshUI(lua_State* luaContext);

  /**
   * Address: 0x0068BB60 (FUN_0068BB60, cfunc_EntityRequestRefreshUIL)
   *
   * What it does:
   * Resolves one entity and marks it dirty for downstream UI refresh.
   */
  int cfunc_EntityRequestRefreshUIL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068C030 (FUN_0068C030, func_EntityAttachBoneTo_LuaFuncDef)
   *
   * What it does:
   * Publishes `Entity:AttachBoneTo(selfbone, entity, bone)` Lua binder.
   */
  CScrLuaInitForm* func_EntityAttachBoneTo_LuaFuncDef();

  /**
   * Address: 0x0068C010 (FUN_0068C010, cfunc_EntityAttachBoneTo)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityAttachBoneToL`.
   */
  int cfunc_EntityAttachBoneTo(lua_State* luaContext);

  /**
   * Address: 0x0068C2D0 (FUN_0068C2D0, func_EntitySetParentOffset_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:SetParentOffset(vector)` Lua binder.
   */
  CScrLuaInitForm* func_EntitySetParentOffset_LuaFuncDef();

  /**
   * Address: 0x0068C2B0 (FUN_0068C2B0, cfunc_EntitySetParentOffset)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntitySetParentOffsetL`.
   */
  int cfunc_EntitySetParentOffset(lua_State* luaContext);

  /**
   * Address: 0x0068C330 (FUN_0068C330, cfunc_EntitySetParentOffsetL)
   *
   * What it does:
   * Rewrites relative attach position/orientation for an already-attached child.
   */
  int cfunc_EntitySetParentOffsetL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068C4C0 (FUN_0068C4C0, func_EntityDetachFrom_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:DetachFrom([skipBallistic])` Lua binder.
   */
  CScrLuaInitForm* func_EntityDetachFrom_LuaFuncDef();

  /**
   * Address: 0x0068C4A0 (FUN_0068C4A0, cfunc_EntityDetachFrom)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityDetachFromL`.
   */
  int cfunc_EntityDetachFrom(lua_State* luaContext);

  /**
   * Address: 0x0068C520 (FUN_0068C520, cfunc_EntityDetachFromL)
   *
   * What it does:
   * Detaches this entity from its current parent and pushes success boolean.
   */
  int cfunc_EntityDetachFromL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068C8D0 (FUN_0068C8D0, func_EntityGetParent_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:GetParent()` Lua binder.
   */
  CScrLuaInitForm* func_EntityGetParent_LuaFuncDef();

  /**
   * Address: 0x0068C8B0 (FUN_0068C8B0, cfunc_EntityGetParent)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityGetParentL`.
   */
  int cfunc_EntityGetParent(lua_State* luaContext);

  /**
   * Address: 0x0068C930 (FUN_0068C930, cfunc_EntityGetParentL)
   *
   * What it does:
   * Pushes attached parent entity Lua object, or `self` when detached.
   */
  int cfunc_EntityGetParentL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068CA20 (FUN_0068CA20, func_EntityGetCollisionExtents_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:GetCollisionExtents()` Lua binder.
   */
  CScrLuaInitForm* func_EntityGetCollisionExtents_LuaFuncDef();

  /**
   * Address: 0x0068CA00 (FUN_0068CA00, cfunc_EntityGetCollisionExtents)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityGetCollisionExtentsL`.
   */
  int cfunc_EntityGetCollisionExtents(lua_State* luaContext);

  /**
   * Address: 0x0068CC50 (FUN_0068CC50, func_EntityPlaySound_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:PlaySound(params)` Lua binder.
   */
  CScrLuaInitForm* func_EntityPlaySound_LuaFuncDef();

  /**
   * Address: 0x0068CC30 (FUN_0068CC30, cfunc_EntityPlaySound)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityPlaySoundL`.
   */
  int cfunc_EntityPlaySound(lua_State* luaContext);

  /**
   * Address: 0x0068CCB0 (FUN_0068CCB0, cfunc_EntityPlaySoundL)
   *
   * What it does:
   * Resolves `(entity, soundParams)` and queues one entity-bound sound request.
   */
  int cfunc_EntityPlaySoundL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068CDE0 (FUN_0068CDE0, func_EntitySetAmbientSound_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:SetAmbientSound(paramTableDetail,paramTableRumble)` Lua binder.
   */
  CScrLuaInitForm* func_EntitySetAmbientSound_LuaFuncDef();

  /**
   * Address: 0x0068CDC0 (FUN_0068CDC0, cfunc_EntitySetAmbientSound)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntitySetAmbientSoundL`.
   */
  int cfunc_EntitySetAmbientSound(lua_State* luaContext);

  /**
   * Address: 0x0068CE40 (FUN_0068CE40, cfunc_EntitySetAmbientSoundL)
   *
   * What it does:
   * Resolves optional detail/rumble sound params and updates entity ambient sound lanes.
   */
  int cfunc_EntitySetAmbientSoundL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068CF80 (FUN_0068CF80, func_EntityGetFractionComplete_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:GetFractionComplete()` Lua binder.
   */
  CScrLuaInitForm* func_EntityGetFractionComplete_LuaFuncDef();

  /**
   * Address: 0x0068CF60 (FUN_0068CF60, cfunc_EntityGetFractionComplete)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityGetFractionCompleteL`.
   */
  int cfunc_EntityGetFractionComplete(lua_State* luaContext);

  /**
   * Address: 0x0068CFE0 (FUN_0068CFE0, cfunc_EntityGetFractionCompleteL)
   *
   * What it does:
   * Resolves `self` and returns current build fraction as one Lua number.
   */
  int cfunc_EntityGetFractionCompleteL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068D0C0 (FUN_0068D0C0, func_EntityAdjustHealth_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:AdjustHealth(instigator, delta)` Lua binder.
   */
  CScrLuaInitForm* func_EntityAdjustHealth_LuaFuncDef();

  /**
   * Address: 0x0068D0A0 (FUN_0068D0A0, cfunc_EntityAdjustHealth)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityAdjustHealthL`.
   */
  int cfunc_EntityAdjustHealth(lua_State* luaContext);

  /**
   * Address: 0x0068D120 (FUN_0068D120, cfunc_EntityAdjustHealthL)
   *
   * What it does:
   * Resolves `(entity, [instigator], delta)`, logs the delta, and applies one
   * `Entity::AdjustHealth` dispatch.
   */
  int cfunc_EntityAdjustHealthL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068D2D0 (FUN_0068D2D0, func_EntityGetHealth_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:GetHealth()` Lua binder.
   */
  CScrLuaInitForm* func_EntityGetHealth_LuaFuncDef();

  /**
   * Address: 0x0068D2B0 (FUN_0068D2B0, cfunc_EntityGetHealth)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityGetHealthL`.
   */
  int cfunc_EntityGetHealth(lua_State* luaContext);

  /**
   * Address: 0x0068D330 (FUN_0068D330, cfunc_EntityGetHealthL)
   *
   * What it does:
   * Resolves `self` and returns current entity health as one Lua number.
   */
  int cfunc_EntityGetHealthL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068D410 (FUN_0068D410, func_EntityGetMaxHealth_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:GetMaxHealth()` Lua binder.
   */
  CScrLuaInitForm* func_EntityGetMaxHealth_LuaFuncDef();

  /**
   * Address: 0x0068D3F0 (FUN_0068D3F0, cfunc_EntityGetMaxHealth)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityGetMaxHealthL`.
   */
  int cfunc_EntityGetMaxHealth(lua_State* luaContext);

  /**
   * Address: 0x0068D470 (FUN_0068D470, cfunc_EntityGetMaxHealthL)
   *
   * What it does:
   * Resolves `self` and returns current entity max-health as one Lua number.
   */
  int cfunc_EntityGetMaxHealthL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068D550 (FUN_0068D550, func_EntitySetHealth_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:SetHealth(instigator,health)` Lua binder.
   */
  CScrLuaInitForm* func_EntitySetHealth_LuaFuncDef();

  /**
   * Address: 0x0068D530 (FUN_0068D530, cfunc_EntitySetHealth)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntitySetHealthL`.
   */
  int cfunc_EntitySetHealth(lua_State* luaContext);

  /**
   * Address: 0x0068D5B0 (FUN_0068D5B0, cfunc_EntitySetHealthL)
   *
   * What it does:
   * Resolves `(entity, [instigator], health)` and applies delta through one
   * `Entity::AdjustHealth` call.
   */
  int cfunc_EntitySetHealthL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068D730 (FUN_0068D730, func_EntitySetMaxHealth_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:SetMaxHealth(maxhealth)` Lua binder.
   */
  CScrLuaInitForm* func_EntitySetMaxHealth_LuaFuncDef();

  /**
   * Address: 0x0068D710 (FUN_0068D710, cfunc_EntitySetMaxHealth)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntitySetMaxHealthL`.
   */
  int cfunc_EntitySetMaxHealth(lua_State* luaContext);

  /**
   * Address: 0x0068D790 (FUN_0068D790, cfunc_EntitySetMaxHealthL)
   *
   * What it does:
   * Resolves `(entity, maxhealth)` and writes one new max-health value.
   */
  int cfunc_EntitySetMaxHealthL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068D8A0 (FUN_0068D8A0, func_EntitySetVizToFocusPlayer_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:SetVizToFocusPlayer(type)` Lua binder.
   */
  CScrLuaInitForm* func_EntitySetVizToFocusPlayer_LuaFuncDef();

  /**
   * Address: 0x0068D880 (FUN_0068D880, cfunc_EntitySetVizToFocusPlayer)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntitySetVizToFocusPlayerL`.
   */
  int cfunc_EntitySetVizToFocusPlayer(lua_State* luaContext);

  /**
   * Address: 0x0068D900 (FUN_0068D900, cfunc_EntitySetVizToFocusPlayerL)
   *
   * What it does:
   * Resolves `(entity, visibilityMode)` and applies `Entity::SetVizToFocusPlayer`.
   */
  int cfunc_EntitySetVizToFocusPlayerL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068DA20 (FUN_0068DA20, func_EntitySetVizToEnemies_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:SetVizToEnemies(type)` Lua binder.
   */
  CScrLuaInitForm* func_EntitySetVizToEnemies_LuaFuncDef();

  /**
   * Address: 0x0068DA00 (FUN_0068DA00, cfunc_EntitySetVizToEnemies)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntitySetVizToEnemiesL`.
   */
  int cfunc_EntitySetVizToEnemies(lua_State* luaContext);

  /**
   * Address: 0x0068DA80 (FUN_0068DA80, cfunc_EntitySetVizToEnemiesL)
   *
   * What it does:
   * Resolves `(entity, visibilityMode)` and applies `Entity::SetVizToEnemies`.
   */
  int cfunc_EntitySetVizToEnemiesL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068DBA0 (FUN_0068DBA0, func_EntitySetVizToAllies_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:SetVizToAllies(type)` Lua binder.
   */
  CScrLuaInitForm* func_EntitySetVizToAllies_LuaFuncDef();

  /**
   * Address: 0x0068DB80 (FUN_0068DB80, cfunc_EntitySetVizToAllies)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntitySetVizToAlliesL`.
   */
  int cfunc_EntitySetVizToAllies(lua_State* luaContext);

  /**
   * Address: 0x0068DC00 (FUN_0068DC00, cfunc_EntitySetVizToAlliesL)
   *
   * What it does:
   * Resolves `(entity, visibilityMode)` and applies `Entity::SetVizToAllies`.
   */
  int cfunc_EntitySetVizToAlliesL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068DD20 (FUN_0068DD20, func_EntitySetVizToNeutrals_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:SetVizToNeutrals(type)` Lua binder.
   */
  CScrLuaInitForm* func_EntitySetVizToNeutrals_LuaFuncDef();

  /**
   * Address: 0x0068DD00 (FUN_0068DD00, cfunc_EntitySetVizToNeutrals)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntitySetVizToNeutralsL`.
   */
  int cfunc_EntitySetVizToNeutrals(lua_State* luaContext);

  /**
   * Address: 0x0068DD80 (FUN_0068DD80, cfunc_EntitySetVizToNeutralsL)
   *
   * What it does:
   * Resolves `(entity, visibilityMode)` and applies `Entity::SetVizToNeutrals`.
   */
  int cfunc_EntitySetVizToNeutralsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068BC30 (FUN_0068BC30, func_EntityGetEntityId_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:GetEntityId()` Lua binder.
   */
  CScrLuaInitForm* func_EntityGetEntityId_LuaFuncDef();

  /**
   * Address: 0x0068BC10 (FUN_0068BC10, cfunc_EntityGetEntityId)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityGetEntityIdL`.
   */
  int cfunc_EntityGetEntityId(lua_State* luaContext);

  /**
   * Address: 0x0068BC90 (FUN_0068BC90, cfunc_EntityGetEntityIdL)
   *
   * What it does:
   * Resolves `self` and pushes the numeric entity id as a Lua string.
   */
  int cfunc_EntityGetEntityIdL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068C670 (FUN_0068C670, func_EntityDetachAll_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:DetachAll(bone,[skipBallistic])` Lua binder.
   */
  CScrLuaInitForm* func_EntityDetachAll_LuaFuncDef();

  /**
   * Address: 0x0068C650 (FUN_0068C650, cfunc_EntityDetachAll)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityDetachAllL`.
   */
  int cfunc_EntityDetachAll(lua_State* luaContext);

  /**
   * Address: 0x0068C6D0 (FUN_0068C6D0, cfunc_EntityDetachAllL)
   *
   * What it does:
   * Detaches every child attached on one parent-bone lane and returns `self`.
   */
  int cfunc_EntityDetachAllL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068C090 (FUN_0068C090, cfunc_EntityAttachBoneToL)
   *
   * What it does:
   * Validates `Entity:AttachBoneTo(selfbone, entity, bone)`, resolves child and
   * parent entities with bone indices, and dispatches one typed `AttachTo`
   * operation.
   */
  int cfunc_EntityAttachBoneToL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068F1A0 (FUN_0068F1A0, func_EntitySetCollisionShape_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:SetCollisionShape(...)` Lua binder.
   */
  CScrLuaInitForm* func_EntitySetCollisionShape_LuaFuncDef();

  /**
   * Address: 0x0068F180 (FUN_0068F180, cfunc_EntitySetCollisionShape)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntitySetCollisionShapeL`.
   */
  int cfunc_EntitySetCollisionShape(lua_State* luaContext);

  /**
   * Address: 0x0068F200 (FUN_0068F200, cfunc_EntitySetCollisionShapeL)
   *
   * What it does:
   * Applies collision-shape runtime override (`None`/`Box`/`Sphere`) from Lua args.
   */
  int cfunc_EntitySetCollisionShapeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068F050 (FUN_0068F050, func_EntityReachedMaxShooters_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:ReachedMaxShooters()` Lua binder.
   */
  CScrLuaInitForm* func_EntityReachedMaxShooters_LuaFuncDef();

  /**
   * Address: 0x0068F030 (FUN_0068F030, cfunc_EntityReachedMaxShooters)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_EntityReachedMaxShootersL`.
   */
  int cfunc_EntityReachedMaxShooters(lua_State* luaContext);

  /**
   * Address: 0x0068F0B0 (FUN_0068F0B0, cfunc_EntityReachedMaxShootersL)
   *
   * What it does:
   * Returns whether the current shooter count has reached the blueprint cap.
   */
  int cfunc_EntityReachedMaxShootersL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068F520 (FUN_0068F520, func_EntityGetOrientation_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:GetOrientation()` Lua binder.
   */
  CScrLuaInitForm* func_EntityGetOrientation_LuaFuncDef();

  /**
   * Address: 0x0068F500 (FUN_0068F500, cfunc_EntityGetOrientation)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityGetOrientationL`.
   */
  int cfunc_EntityGetOrientation(lua_State* luaContext);

  /**
   * Address: 0x0068F580 (FUN_0068F580, cfunc_EntityGetOrientationL)
   *
   * What it does:
   * Pushes the entity world orientation quaternion as one Lua object.
   */
  int cfunc_EntityGetOrientationL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068F880 (FUN_0068F880, func_EntityGetHeading_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:GetHeading()` Lua binder.
   */
  CScrLuaInitForm* func_EntityGetHeading_LuaFuncDef();

  /**
   * Address: 0x0068F860 (FUN_0068F860, cfunc_EntityGetHeading)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityGetHeadingL`.
   */
  int cfunc_EntityGetHeading(lua_State* luaContext);

  /**
   * Address: 0x0068F8E0 (FUN_0068F8E0, cfunc_EntityGetHeadingL)
   *
   * What it does:
   * Computes one yaw heading from the entity world orientation quaternion.
   */
  int cfunc_EntityGetHeadingL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00690BB0 (FUN_00690BB0, func_EntityGetScale_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:GetScale()` Lua binder.
   */
  CScrLuaInitForm* func_EntityGetScale_LuaFuncDef();

  /**
   * Address: 0x00690B90 (FUN_00690B90, cfunc_EntityGetScale)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityGetScaleL`.
   */
  int cfunc_EntityGetScale(lua_State* luaContext);

  /**
   * Address: 0x00690C10 (FUN_00690C10, cfunc_EntityGetScaleL)
   *
   * What it does:
   * Pushes the current draw scale as `(sx, sy, sz)`.
   */
  int cfunc_EntityGetScaleL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00691A20 (FUN_00691A20, func_EntityDestroy_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:Destroy()` Lua binder.
   */
  CScrLuaInitForm* func_EntityDestroy_LuaFuncDef();

  /**
   * Address: 0x00691A00 (FUN_00691A00, cfunc_EntityDestroy)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityDestroyL`.
   */
  int cfunc_EntityDestroy(lua_State* luaContext);

  /**
   * Address: 0x00691A80 (FUN_00691A80, cfunc_EntityDestroyL)
   *
   * What it does:
   * Resolves optional entity arg, logs script-side destroy request, and queues
   * entity destruction when present.
   */
  int cfunc_EntityDestroyL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00691B60 (FUN_00691B60, func_EntityBeenDestroyed_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:BeenDestroyed()` Lua binder.
   */
  CScrLuaInitForm* func_EntityBeenDestroyed_LuaFuncDef();

  /**
   * Address: 0x00691B40 (FUN_00691B40, cfunc_EntityBeenDestroyed)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityBeenDestroyedL`.
   */
  int cfunc_EntityBeenDestroyed(lua_State* luaContext);

  /**
   * Address: 0x00691BC0 (FUN_00691BC0, cfunc_EntityBeenDestroyedL)
   *
   * What it does:
   * Returns `true` when the entity handle is nil/invalid or destroy-queued.
   */
  int cfunc_EntityBeenDestroyedL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00691CB0 (FUN_00691CB0, func_EntityKill_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:Kill(instigator, type, excessDamageRatio)` Lua
   * binder.
   */
  CScrLuaInitForm* func_EntityKill_LuaFuncDef();

  /**
   * Address: 0x00691C90 (FUN_00691C90, cfunc_EntityKill)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityKillL`.
   */
  int cfunc_EntityKill(lua_State* luaContext);

  /**
   * Address: 0x00691D10 (FUN_00691D10, cfunc_EntityKillL)
   *
   * What it does:
   * Resolves `(self, [instigator], [killType], [excessDamageRatio])`, dispatches
   * `Entity::Kill`, and updates realtime kill stat lanes for army reporting.
   */
  int cfunc_EntityKillL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00690100 (FUN_00690100, func_EntityAddLocalImpulse_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:AddLocalImpulse(...)` Lua binder.
   */
  CScrLuaInitForm* func_EntityAddLocalImpulse_LuaFuncDef();

  /**
   * Address: 0x006900E0 (FUN_006900E0, cfunc_EntityAddLocalImpulse)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityAddLocalImpulseL`.
   */
  int cfunc_EntityAddLocalImpulse(lua_State* luaContext);

  /**
   * Address: 0x00690160 (FUN_00690160, cfunc_EntityAddLocalImpulseL)
   *
   * What it does:
   * Converts local impulse+point into world space and applies it to entity
   * physics body state when present.
   */
  int cfunc_EntityAddLocalImpulseL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00690400 (FUN_00690400, func_EntityAddWorldImpulse_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:AddWorldImpulse(...)` Lua binder.
   */
  CScrLuaInitForm* func_EntityAddWorldImpulse_LuaFuncDef();

  /**
   * Address: 0x006903E0 (FUN_006903E0, cfunc_EntityAddWorldImpulse)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityAddWorldImpulseL`.
   */
  int cfunc_EntityAddWorldImpulse(lua_State* luaContext);

  /**
   * Address: 0x00690460 (FUN_00690460, cfunc_EntityAddWorldImpulseL)
   *
   * What it does:
   * Applies one world-space impulse at one world-space point to entity physics
   * body state when present.
   */
  int cfunc_EntityAddWorldImpulseL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006907B0 (FUN_006907B0, func_EntitySetMesh_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:SetMesh(meshBp, keepActor)` Lua binder.
   */
  CScrLuaInitForm* func_EntitySetMesh_LuaFuncDef();

  /**
   * Address: 0x00690790 (FUN_00690790, cfunc_EntitySetMesh)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntitySetMeshL`.
   */
  int cfunc_EntitySetMesh(lua_State* luaContext);

  /**
   * Address: 0x00690810 (FUN_00690810, cfunc_EntitySetMeshL)
   *
   * What it does:
   * Resolves mesh id + keep-actor flag and dispatches to `Entity::SetMesh`.
   */
  int cfunc_EntitySetMeshL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00690A10 (FUN_00690A10, func_EntitySetDrawScale_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:SetDrawScale(size)` Lua binder.
   */
  CScrLuaInitForm* func_EntitySetDrawScale_LuaFuncDef();

  /**
   * Address: 0x006909F0 (FUN_006909F0, cfunc_EntitySetDrawScale)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntitySetDrawScaleL`.
   */
  int cfunc_EntitySetDrawScale(lua_State* luaContext);

  /**
   * Address: 0x00690A70 (FUN_00690A70, cfunc_EntitySetDrawScaleL)
   *
   * What it does:
   * Resolves `(entity, size)`, updates uniform draw scale, and requeues the
   * entity in the sim coord-update list.
   */
  int cfunc_EntitySetDrawScaleL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00690D40 (FUN_00690D40, func_EntitySetScale_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:SetScale(s)` / `Entity:SetScale(sx,sy,sz)` Lua binder.
   */
  CScrLuaInitForm* func_EntitySetScale_LuaFuncDef();

  /**
   * Address: 0x00690D20 (FUN_00690D20, cfunc_EntitySetScale)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntitySetScaleL`.
   */
  int cfunc_EntitySetScale(lua_State* luaContext);

  /**
   * Address: 0x00690DA0 (FUN_00690DA0, cfunc_EntitySetScaleL)
   *
   * What it does:
   * Applies non-uniform draw scale override and returns `self`.
   */
  int cfunc_EntitySetScaleL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00691050 (FUN_00691050, func_EntityAddManualScroller_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:AddManualScroller(scrollSpeed1, scrollSpeed2)` Lua
   * binder.
   */
  CScrLuaInitForm* func_EntityAddManualScroller_LuaFuncDef();

  /**
   * Address: 0x00691030 (FUN_00691030, cfunc_EntityAddManualScroller)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_EntityAddManualScrollerL`.
   */
  int cfunc_EntityAddManualScroller(lua_State* luaContext);

  /**
   * Address: 0x006910B0 (FUN_006910B0, cfunc_EntityAddManualScrollerL)
   *
   * What it does:
   * Installs one manual texture-scroller definition on the entity and keeps
   * Lua stack shape compatible with original callback lane.
   */
  int cfunc_EntityAddManualScrollerL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00691280 (FUN_00691280, func_EntityAddThreadScroller_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:AddThreadScroller(sideDist, scrollMult)` Lua binder.
   */
  CScrLuaInitForm* func_EntityAddThreadScroller_LuaFuncDef();

  /**
   * Address: 0x00691260 (FUN_00691260, cfunc_EntityAddThreadScroller)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_EntityAddThreadScrollerL`.
   */
  int cfunc_EntityAddThreadScroller(lua_State* luaContext);

  /**
   * Address: 0x006912E0 (FUN_006912E0, cfunc_EntityAddThreadScrollerL)
   *
   * What it does:
   * Installs one threaded texture-scroller definition on the entity.
   */
  int cfunc_EntityAddThreadScrollerL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006914A0 (FUN_006914A0, func_EntityAddPingPongScroller_LuaFuncDef)
   *
   * What it does:
   * Publishes the eight-parameter ping-pong scroller Lua binder.
   */
  CScrLuaInitForm* func_EntityAddPingPongScroller_LuaFuncDef();

  /**
   * Address: 0x00691480 (FUN_00691480, cfunc_EntityAddPingPongScroller)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_EntityAddPingPongScrollerL`.
   */
  int cfunc_EntityAddPingPongScroller(lua_State* luaContext);

  /**
   * Address: 0x00691500 (FUN_00691500, cfunc_EntityAddPingPongScrollerL)
   *
   * What it does:
   * Installs one ping-pong texture-scroller definition on the entity.
   */
  int cfunc_EntityAddPingPongScrollerL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00691860 (FUN_00691860, func_EntityRemoveScroller_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:RemoveScroller()` Lua binder.
   */
  CScrLuaInitForm* func_EntityRemoveScroller_LuaFuncDef();

  /**
   * Address: 0x00691840 (FUN_00691840, cfunc_EntityRemoveScroller)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityRemoveScrollerL`.
   */
  int cfunc_EntityRemoveScroller(lua_State* luaContext);

  /**
   * Address: 0x006918C0 (FUN_006918C0, cfunc_EntityRemoveScrollerL)
   *
   * What it does:
   * Replaces entity scroller state with one neutral/no-op definition.
   */
  int cfunc_EntityRemoveScrollerL(LuaPlus::LuaState* state);

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
  static_assert(offsetof(Entity, mAmbientSound) == 0x108, "Entity::mAmbientSound offset must be 0x108");
  static_assert(offsetof(Entity, mRumbleSound) == 0x10C, "Entity::mRumbleSound offset must be 0x10C");
  static_assert(offsetof(Entity, mVisibilityState) == 0x110, "Entity::mVisibilityState offset must be 0x110");
  static_assert(offsetof(Entity, mFootprintLayer) == 0x114, "Entity::mFootprintLayer offset must be 0x114");
  static_assert(offsetof(Entity, mCurrentLayer) == 0x118, "Entity::mCurrentLayer offset must be 0x118");
  static_assert(offsetof(Entity, mUseAltFootprint) == 0x11C, "Entity::mUseAltFootprint offset must be 0x11C");
  static_assert(
    offsetof(Entity, mUseAltFootprintSecondary) == 0x11D, "Entity::mUseAltFootprintSecondary offset must be 0x11D"
  );
  static_assert(
    offsetof(Entity, mStrategicUnderlayTexture) == 0x120, "Entity::mStrategicUnderlayTexture offset must be 0x120"
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
  static_assert(offsetof(Entity, mShooters) == 0x218, "Entity::mShooters offset must be 0x218");
  static_assert(offsetof(Entity, mCollisionBoundsMin) == 0x240, "Entity::mCollisionBoundsMin offset must be 0x240");
  static_assert(offsetof(Entity, mCollisionBoundsMax) == 0x24C, "Entity::mCollisionBoundsMax offset must be 0x24C");
  static_assert(offsetof(Entity, mLuaPositionCache) == 0x258, "Entity::mLuaPositionCache offset must be 0x258");
  static_assert(offsetof(Entity, mMotor) == 0x26C, "Entity::mMotor offset must be 0x26C");

} // namespace moho
