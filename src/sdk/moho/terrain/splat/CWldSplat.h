#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "legacy/containers/Vector.h"
#include "moho/render/CWldTerrainDecal.h"

namespace gpg
{
  class BinaryWriter;
}

namespace moho
{
  class CD3DBatchTexture;
  class CD3DTextureBatcher;
  class CDecalGroup;

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
  class CDecalManager
  {
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
     * Address: 0x00878A40 (FUN_00878A40, Moho::CDecalManager::RemoveDecals)
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
     * Address: 0x00877E40 (FUN_00877E40, Moho::CDecalManager::Save)
     *
     * What it does:
     * Writes manager decal counts, serializes active decals, then serializes
     * all decal groups to the binary writer.
     */
    void Save(gpg::BinaryWriter& writer);

  public:
    void* mVtable; // +0x00
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
    float mUnknownE8_10F[0x0A]; // +0xE8
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
    offsetof(CDecalManager, mDidSomething) == 0x110,
    "CDecalManager::mDidSomething offset must be 0x110"
  );
#endif
} // namespace moho
