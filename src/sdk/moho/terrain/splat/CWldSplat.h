#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "legacy/containers/Vector.h"
#include "moho/render/CWldTerrainDecal.h"

namespace gpg
{
  class BinaryReader;
  class BinaryWriter;
}

namespace moho
{
  class CD3DBatchTexture;
  class CD3DTextureBatcher;
  class CDecalGroup;
  class UserEntity;
  struct GeomCamera3;
  struct SDecalInfo;

  struct DecalGroupLookupNode
  {
    DecalGroupLookupNode* mLeft;     // +0x00
    DecalGroupLookupNode* mParent;   // +0x04
    DecalGroupLookupNode* mRight;    // +0x08
    std::uint32_t mKey;              // +0x0C
    std::int32_t mGroupIndex;        // +0x10
    std::uint8_t mColor;             // +0x14
    std::uint8_t mIsNil;             // +0x15
    std::uint8_t mPad16_17[0x02];    // +0x16
  };

  static_assert(sizeof(DecalGroupLookupNode) == 0x18, "DecalGroupLookupNode size must be 0x18");
  static_assert(offsetof(DecalGroupLookupNode, mLeft) == 0x00, "DecalGroupLookupNode::mLeft offset must be 0x00");
  static_assert(offsetof(DecalGroupLookupNode, mParent) == 0x04, "DecalGroupLookupNode::mParent offset must be 0x04");
  static_assert(offsetof(DecalGroupLookupNode, mRight) == 0x08, "DecalGroupLookupNode::mRight offset must be 0x08");
  static_assert(offsetof(DecalGroupLookupNode, mKey) == 0x0C, "DecalGroupLookupNode::mKey offset must be 0x0C");
  static_assert(
    offsetof(DecalGroupLookupNode, mGroupIndex) == 0x10, "DecalGroupLookupNode::mGroupIndex offset must be 0x10"
  );
  static_assert(offsetof(DecalGroupLookupNode, mColor) == 0x14, "DecalGroupLookupNode::mColor offset must be 0x14");
  static_assert(offsetof(DecalGroupLookupNode, mIsNil) == 0x15, "DecalGroupLookupNode::mIsNil offset must be 0x15");

  struct DecalGroupLookupTree
  {
    std::uint32_t mUnknown00;         // +0x00
    DecalGroupLookupNode* mHead;      // +0x04
    std::uint32_t mNodeCount;         // +0x08
    std::uint32_t mUnknown0C;         // +0x0C
  };

  static_assert(sizeof(DecalGroupLookupTree) == 0x10, "DecalGroupLookupTree size must be 0x10");
  static_assert(offsetof(DecalGroupLookupTree, mHead) == 0x04, "DecalGroupLookupTree::mHead offset must be 0x04");

  /**
   * CWldTerrainDecal specialization that owns one terrain-splat quad and one
   * retained batch-texture lane.
   */
  class CWldSplat : public CWldTerrainDecal
  {
  public:
    struct SplatVertex
    {
      Wm3::Vec3f mPosition;       // +0x00
      std::uint8_t mPad0C_0F[0x4];
      Wm3::Vec2f mTexCoord;       // +0x10
      std::uint8_t mPad18_1B[0x4];
    };

    /**
     * Address: 0x0089DF70 (FUN_0089DF70, Moho::CWldSplat::CWldSplat)
     *
     * What it does:
     * Seeds the splat's base decal state and leaves the batch-texture lane
     * empty until a name is assigned.
     */
    CWldSplat(SpatialDB_MeshInstance* spatialDbOwner, IWldTerrainRes* terrainRes);

    /**
     * Address: 0x0089DFE0 (FUN_0089DFE0, Moho::CWldSplat::dtr)
     * Address: 0x0089E010 (FUN_0089E010, Moho::CWldSplat::~CWldSplat)
     *
     * What it does:
     * Releases the retained batch texture and then tears down the terrain
     * decal base lanes.
     */
    ~CWldSplat() override;

    /**
     * Address: 0x0089E2C0 (FUN_0089E2C0, Moho::CWldSplat::SetName)
     *
     * What it does:
     * Stores the splat name, resolves the texture from disk when non-empty,
     * and keeps the previous texture lane intact when the name is empty.
     */
    void SetName(const msvc8::string& name, int slot) override;

    /**
     * Address: 0x0089E090 (FUN_0089E090, Moho::CWldSplat::Update)
     *
     * What it does:
     * Advances the base decal state and refreshes the splat vertex positions.
     */
    void Update() override;

    /**
     * Address: 0x0089E0B0 (FUN_0089E0B0, Moho::CWldSplat::UpdateVertices)
     *
     * What it does:
     * Projects the unit quad into world space and samples terrain elevation
     * for each corner.
     */
    void UpdateVertices();

    /**
     * Address: 0x0089E1F0 (FUN_0089E1F0, Moho::CWldSplat::UpdateBatchTexture)
     *
     * What it does:
     * Adds the retained batch texture to the atlas and writes the returned UV
     * rectangle into the splat quad.
     */
    void UpdateBatchTexture(CD3DTextureBatcher* batcher);

    /**
     * Address: 0x0089E2B0 (FUN_0089E2B0, Moho::CWldSplat::GetSplatVertices)
     *
     * What it does:
     * Returns the first vertex lane for the splat quad.
     */
    [[nodiscard]]
    SplatVertex* GetSplatVertices() noexcept;

  public:
    SplatVertex mSplatVertices[4];                  // +0x170
    boost::shared_ptr<CD3DBatchTexture> mTex;       // +0x1E0
  };

  static_assert(offsetof(CWldSplat::SplatVertex, mPosition) == 0x00, "CWldSplat::SplatVertex::mPosition offset must be 0x00");
  static_assert(offsetof(CWldSplat::SplatVertex, mTexCoord) == 0x10, "CWldSplat::SplatVertex::mTexCoord offset must be 0x10");
  static_assert(sizeof(CWldSplat::SplatVertex) == 0x1C, "CWldSplat::SplatVertex size must be 0x1C");
  static_assert(offsetof(CWldSplat, mSplatVertices) == 0x170, "CWldSplat::mSplatVertices offset must be 0x170");
  static_assert(offsetof(CWldSplat, mTex) == 0x1E0, "CWldSplat::mTex offset must be 0x1E0");
  static_assert(sizeof(CWldSplat) == 0x1E8, "CWldSplat size must be 0x1E8");

  /**
   * Terrain decal manager lane that owns decals, splat overlays, and one
   * spatial-db registration used by newly created decals.
   */
  class IDecalManager
  {
  public:
    /**
     * Address: 0x00877250 (FUN_00877250, ??0IDecalManager@Moho@@QAE@XZ)
     * Address: 0x00878D20 (FUN_00878D20, IDecalManager ctor lane)
     *
     * What it does:
     * Initializes one decal-manager base interface object.
     */
    IDecalManager();

    virtual ~IDecalManager() = default;
  };

  static_assert(sizeof(IDecalManager) == 0x04, "IDecalManager size must be 0x04");

  /**
   * Terrain decal manager lane that owns decals, splat overlays, and one
   * spatial-db registration used by newly created decals.
   */
  class CDecalManager : public IDecalManager
  {
  public:
    /**
     * Address: 0x00877A60 (FUN_00877A60, Moho::CDecalManager::CDecalManager)
     *
     * What it does:
     * Initializes decal vectors, keyed lookup sentinels, and embedded spatial
     * db storage for the owning terrain map.
     */
    explicit CDecalManager(IWldTerrainRes* terrainRes);

    /**
     * Address: 0x00877B70 (FUN_00877B70, Moho::CDecalManager::~CDecalManager)
     *
     * What it does:
     * Deletes active decals/groups/splats, clears both keyed lookup trees, and
     * tears down embedded spatial-db registration storage.
     */
    ~CDecalManager() override;

    // ---- virtual dispatch table, declared in binary slot order ----
    //
    // The manager is reached through its vtable, not by direct call: the
    // terrain resource stores it as an IDecalManager and dispatches. Slot 0 is
    // the destructor declared above, whose scalar-deleting thunk lives at
    // 0x00878D00; the rest follow in the order the vtable at 0x00E4982C lists
    // them, because MSVC assigns slots in declaration order and a member moved
    // out of order silently sends every caller to the wrong function.
    //
    // Slots 4 and up (GetDecalCount, GetDecal, Func5, LoadDecal, ...) are still
    // modelled as ordinary members further down and are not part of the table
    // yet, so nothing may dispatch them virtually until they move up here.

    /**
     * Address: 0x00877CB0 (FUN_00877CB0, Moho::CDecalManager::Func1)
     * Slot: 1
     *
     * What it does:
     * Returns one entry of the decal-area decile histogram, clamping the index
     * into the 0..9 range the table holds.
     */
    [[nodiscard]] virtual float GetLodThreshold(std::int32_t lodIndex) const;

    /**
     * Address: 0x00877CD0 (FUN_00877CD0, Moho::CDecalManager::Load)
     * Slot: 2
     *
     * IDA signature:
     * void __thiscall Moho::CDecalManager::Load(CDecalManager *this, gpg::BinaryReader *reader, unsigned int version);
     *
     * What it does:
     * Inverse of Save: reads decal counts, deserializes each decal (new
     * CWldTerrainDecal + DecalLoad + LoadDecal), then each decal group (new
     * CDecalGroup + ReadFromStream + LoadDecalGroup), reindexes the decal
     * vector, and rebuilds the LOD decile histogram.
     */
    virtual void Load(gpg::BinaryReader& reader, unsigned int version);

    /**
     * Address: 0x00877E40 (FUN_00877E40, Moho::CDecalManager::Save)
     * Slot: 3
     *
     * What it does:
     * Writes manager decal counts, serializes active decals, then serializes
     * all decal groups to the binary writer.
     */
    virtual void Save(gpg::BinaryWriter& writer);

    /**
     * Address: 0x00878D90 (FUN_00878D90, Moho::CDecalManager::operator new)
     * Mangled: ??2CDecalManager@Moho@@QAE@@Z
     *
     * IDA signature:
     * Moho::CDecalManager *__cdecl Moho::CDecalManager::operator new(Moho::CWldTerrainRes *a1);
     *
     * What it does:
     * Class-static allocating factory: reserves 0x114 bytes via the global
     * throwing operator new, and on a non-null block constructs one
     * CDecalManager owned by `terrainRes`. Returns the constructed manager, or
     * nullptr when the raw allocation yielded null.
     *
     * (The binary mangling is the class allocating `operator new`; recovered as
     * an intent-named static factory per the symbol-naming contract. The
     * parameter is spelled IWldTerrainRes* — every caller passes a
     * CWldTerrainRes* which upcasts to its IWldTerrainRes primary base.)
     */
    static CDecalManager* Create(IWldTerrainRes* terrainRes);

  public:
    /**
     * Address: 0x00877FF0 (FUN_00877FF0, Moho::CDecalManager::Func5)
     *
     * What it does:
     * Looks up one decal-index key in the decal-group lookup tree and returns
     * the mapped group index, or `0` when the key is absent.
     */
    [[nodiscard]] std::int32_t FindGroupByDecalIndex(std::uint32_t decalIndex) const;

    /**
     * Address: 0x00878250 (FUN_00878250, Moho::CDecalManager::DestroyDecal)
     *
     * What it does:
     * Removes one decal from group memberships and manager storage, destroys
     * the decal object, and compacts vector-index lanes.
     */
    void DestroyDecal(CWldTerrainDecal* decal);

    /**
     * Address: 0x008782A0 (FUN_008782A0, Moho::CDecalManager::Func10)
     *
     * What it does:
     * Looks up one splat/decal-index key in the secondary lookup tree and
     * returns the mapped group index, or `0` when the key is absent.
     */
    [[nodiscard]] std::int32_t FindGroupBySplatIndex(std::uint32_t splatIndex) const;

    /**
     * Address: 0x00878650 (FUN_00878650, Moho::CDecalManager::AddDecals)
     * Slot: 22 (`??_7CDecalManager@Moho@@6B@` + 0x58)
     *
     * IDA signature:
     * std::vector *__thiscall Moho::CDecalManager::Func20(Moho::CDecalManager *this, std::vector *a2);
     *
     * What it does:
     * Materializes one sync packet's worth of sim-authored decals. Splat
     * records become `CWldSplat` overlays; the rest resolve their type name
     * against `CWldTerrainDecal::sTypeDesc` and become plain terrain decals.
     * Both paths copy the transform, apply the resolved texture names, carry
     * the handle / fade deadline / army / fidelity lanes across, and settle the
     * cutoff LOD.
     */
    void AddDecals(const msvc8::vector<SDecalInfo>& decals);

    /**
     * Address: 0x00878A40 (FUN_00878A40, Moho::CDecalManager::RemoveDecals)
     * Slot: 23 (`??_7CDecalManager@Moho@@6B@` + 0x5C)
     *
     * What it does:
     * Scans all active decals for each requested runtime handle and marks
     * matching decals for deferred removal.
     */
    void RemoveDecals(const msvc8::vector<std::int32_t>& decalHandles);

    /**
     * Address: 0x008776D0 (FUN_008776D0, Moho::CDecalManager::Reindex)
     *
     * What it does:
     * Refreshes each decal's `mVecIndex` lane to match the current `mDecals`
     * vector order.
     */
    void Reindex();

    /**
     * Address: 0x00878590 (FUN_00878590, Moho::CDecalManager::Func17)
     *
     * What it does:
     * Finds one decal in `mDecals`, moves it to the front while preserving
     * relative order of earlier entries, then reindexes the decal lane.
     */
    void MoveDecalToFront(CWldTerrainDecal* decal);

    /**
     * Address: 0x008785D0 (FUN_008785D0, Moho::CDecalManager::Func18)
     *
     * What it does:
     * Finds one decal in `mDecals`, swaps it with the next entry when it is
     * not the last element, then reindexes when the decal exists.
     */
    void MoveDecalTowardBack(CWldTerrainDecal* decal);

    /**
     * Address: 0x00878610 (FUN_00878610, Moho::CDecalManager::Func19)
     *
     * What it does:
     * Finds one decal in `mDecals`, swaps it with the previous entry when it
     * is not the first element, then reindexes when a swap is applied.
     */
    void MoveDecalTowardFront(CWldTerrainDecal* decal);

    /**
     * Address: 0x00878020 (FUN_00878020, Moho::CDecalManager::NewDecal)
     *
     * What it does:
     * Allocates one terrain decal for the requested runtime index, marks the
     * manager dirty, and forwards to `LoadDecal`.
     */
    [[nodiscard]] CWldTerrainDecal* NewDecal(std::int32_t decalIndex);

    /**
     * Address: 0x008780A0 (FUN_008780A0, Moho::CDecalManager::LoadDecal)
     *
     * What it does:
     * Loads one existing decal (or allocates a new one), appends it to active
     * manager storage, and updates the decal-index lookup lane.
     */
    [[nodiscard]] CWldTerrainDecal* LoadDecal(CWldTerrainDecal* decal);

    /**
     * Address: 0x00878460 (FUN_00878460, Moho::CDecalManager::DestroyDecalGroup)
     *
     * What it does:
     * Removes one decal-group mapping, erases the group from manager storage,
     * then deletes the group object.
     */
    std::int32_t DestroyDecalGroup(CDecalGroup* group);

    /**
     * Address: 0x00878530 (FUN_00878530, Moho::CDecalManager::AddSplat)
     *
     * What it does:
     * Moves one existing decal pointer to the end of the active decal vector
     * and reindexes after the move.
     */
    void AddSplat(CWldTerrainDecal* decal);

    /**
     * Address: 0x00878A90 (FUN_00878A90, Moho::CDecalManager::ProcessRemovals)
     *
     * What it does:
     * Fades scheduled decals/splats toward zero alpha and erases fully faded
     * entries from manager storage.
     */
    void ProcessRemovals(std::int32_t tick);

    /**
     * Address: 0x00878BE0 (FUN_00878BE0, Moho::CDecalManager::EntitiesInView)
     *
     * What it does:
     * Collects one camera-visible entity lane from the manager spatial-db
     * registration and sorts the collected pointer range.
     */
    std::int32_t EntitiesInView(GeomCamera3* camera, gpg::fastvector<UserEntity*>& entities, bool ignoreDecalLod);

    /**
     * Address: 0x00878C40 (FUN_00878C40, Moho::CDecalManager::PropsInView)
     *
     * What it does:
     * Collects one camera-visible prop lane from the manager spatial-db
     * registration and sorts the collected pointer range.
     */
    std::int32_t PropsInView(GeomCamera3* camera, gpg::fastvector<UserEntity*>& props, bool ignoreDecalLod);

    /**
     * Address: 0x00878CB0 (FUN_00878CB0, Moho::CDecalManager::Func26)
     * Slot: 28 (`??_7CDecalManager@Moho@@6B@` + 0x70)
     *
     * What it does:
     * Returns whether this manager has pending decal/splat changes since the
     * flag was last cleared elsewhere (e.g. `AddDecals`/`RemoveDecals`/
     * `ProcessRemovals` setting `mDidSomething`). Read-only - does not clear
     * the flag itself.
     */
    [[nodiscard]] bool HasPendingChanges() const;

  public:
    /**
     * Address: 0x00878190 (FUN_00878190, Moho::CDecalManager::NewSplat)
     *
     * What it does:
     * Allocates one `CWldSplat`, initializes it with this manager's spatial-db
     * owner and terrain resource, then appends it to `mSplats`.
     */
    [[nodiscard]] CWldSplat* NewSplat();

    /**
     * Address: 0x008784C0 (FUN_008784C0, Moho::CDecalManager::NewSplatAt)
     *
     * What it does:
     * Creates one splat, applies type/name/transform defaults, refreshes the
     * splat runtime state, and reports success.
     */
    bool NewSplatAt(const Wm3::Vec3f& position, EWldTerrainDecalType type, const msvc8::string& name);

    /**
     * Address: 0x008782D0 (FUN_008782D0, Moho::CDecalManager::LoadDecalGroup)
     *
     * What it does:
     * Get-or-create decal group: when `group` is null, allocates a new
     * CDecalGroup(mNumDecals++) and names it "Group_<index>"; appends the group
     * to mDecalGroups and maps its index into the splat-index lookup lane.
     */
    CDecalGroup* LoadDecalGroup(CDecalGroup* group);

    /**
     * Address: 0x00877730 (FUN_00877730, Moho::CDecalManager::RebuildLodHistogram)
     *
     * What it does:
     * Rebuilds the 10-entry decal-area decile histogram (mLodThresholds): dedups
     * every decal's scale-area (mScale.z * mScale.x) through a set, collecting the
     * distinct areas in first-seen order, then sets mLodThresholds[0]=0 and
     * mLodThresholds[i] = the decile element at index floor(count * i * 0.1) for
     * i in 1..9.
     */
    void RebuildLodHistogram();

  public:
    std::uint32_t mDecalCount; // +0x04
    std::uint32_t mNumDecals; // +0x08
    std::uint8_t mUnknown0C_0F[0x04]; // +0x0C
    msvc8::vector<CWldTerrainDecal*> mDecals; // +0x10
    DecalGroupLookupTree mDecalGroupLookupByDecalIndex; // +0x1C
    msvc8::vector<CDecalGroup*> mDecalGroups; // +0x2C
    DecalGroupLookupTree mDecalGroupLookupBySplatIndex; // +0x38
    msvc8::vector<CWldSplat*> mSplats; // +0x48
    std::uint8_t mSpatialDbOwnerStorage[0x90]; // +0x54
    IWldTerrainRes* mWldTerrain; // +0xE4
    float mLodThresholds[10]; // +0xE8 (decal-area decile LOD histogram)
    std::uint8_t mDidSomething; // +0x110
    std::uint8_t mPad111_113[0x03];
  };

#if defined(MOHO_ABI_MSVC8_COMPAT)
  static_assert(offsetof(CDecalManager, mDecalCount) == 0x04, "CDecalManager::mDecalCount offset must be 0x04");
  static_assert(offsetof(CDecalManager, mDecals) == 0x10, "CDecalManager::mDecals offset must be 0x10");
  static_assert(
    offsetof(CDecalManager, mDecalGroupLookupByDecalIndex) == 0x1C,
    "CDecalManager::mDecalGroupLookupByDecalIndex offset must be 0x1C"
  );
  static_assert(offsetof(CDecalManager, mDecalGroups) == 0x2C, "CDecalManager::mDecalGroups offset must be 0x2C");
  static_assert(
    offsetof(CDecalManager, mDecalGroupLookupBySplatIndex) == 0x38,
    "CDecalManager::mDecalGroupLookupBySplatIndex offset must be 0x38"
  );
  static_assert(offsetof(CDecalManager, mSplats) == 0x48, "CDecalManager::mSplats offset must be 0x48");
  static_assert(
    offsetof(CDecalManager, mSpatialDbOwnerStorage) == 0x54,
    "CDecalManager::mSpatialDbOwnerStorage offset must be 0x54"
  );
  static_assert(offsetof(CDecalManager, mWldTerrain) == 0xE4, "CDecalManager::mWldTerrain offset must be 0xE4");
  static_assert(
    offsetof(CDecalManager, mLodThresholds) == 0xE8,
    "CDecalManager::mLodThresholds offset must be 0xE8"
  );
  static_assert(
    offsetof(CDecalManager, mDidSomething) == 0x110,
    "CDecalManager::mDidSomething offset must be 0x110"
  );
  static_assert(sizeof(CDecalManager) == 0x114, "CDecalManager size must be 0x114");
#endif
} // namespace moho
