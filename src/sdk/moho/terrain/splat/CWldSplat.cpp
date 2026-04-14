#include "moho/terrain/splat/CWldSplat.h"

#include <cstring>

#include "gpg/core/streams/BinaryWriter.h"
#include "moho/render/CDecalGroup.h"
#include "moho/render/d3d/CD3DTextureBatcher.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "moho/sim/STIMap.h"

namespace
{
  struct CWldTerrainResRuntimeView
  {
    void* mVftable;
    moho::STIMap* mMap;
  };

  static_assert(sizeof(CWldTerrainResRuntimeView) == 0x08, "CWldTerrainResRuntimeView size must be 0x08");
  static_assert(
    offsetof(CWldTerrainResRuntimeView, mMap) == 0x04,
    "CWldTerrainResRuntimeView::mMap offset must be 0x04"
  );

  [[nodiscard]] const CWldTerrainResRuntimeView*
  AsCWldTerrainResRuntimeView(const moho::IWldTerrainRes* const terrainRes) noexcept
  {
    return reinterpret_cast<const CWldTerrainResRuntimeView*>(terrainRes);
  }

  [[nodiscard]] const moho::DecalGroupLookupNode* FindLookupNodeByKey(
    const moho::DecalGroupLookupTree& lookupTree, const std::uint32_t key
  ) noexcept
  {
    const moho::DecalGroupLookupNode* const head = lookupTree.mHead;
    if (head == nullptr) {
      return nullptr;
    }

    const moho::DecalGroupLookupNode* best = head;
    const moho::DecalGroupLookupNode* cursor = head->mParent;
    while (cursor != nullptr && cursor->mIsNil == 0u) {
      if (cursor->mKey >= key) {
        best = cursor;
        cursor = cursor->mLeft;
      } else {
        cursor = cursor->mRight;
      }
    }

    if (best == head || key < best->mKey) {
      return head;
    }

    return best;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00877FF0 (FUN_00877FF0, Moho::CDecalManager::Func5)
   *
   * What it does:
   * Looks up one decal-index key in the decal-group lookup tree and returns
   * the mapped group index, or `0` when the key is absent.
   */
  std::int32_t CDecalManager::FindGroupByDecalIndex(const std::uint32_t decalIndex) const
  {
    const DecalGroupLookupNode* const node = FindLookupNodeByKey(mDecalGroupLookupByDecalIndex, decalIndex);
    if (node == nullptr || node == mDecalGroupLookupByDecalIndex.mHead) {
      return 0;
    }

    return node->mGroupIndex;
  }

  /**
   * Address: 0x00878250 (FUN_00878250, Moho::CDecalManager::DestroyDecal)
   *
   * What it does:
   * Removes one decal from group memberships and manager storage, destroys
   * the decal object, and compacts vector-index lanes.
   */
  void CDecalManager::DestroyDecal(CWldTerrainDecal* const decal)
  {
    if (decal == nullptr) {
      return;
    }

    const auto& groupsView = msvc8::AsVectorRuntimeView(mDecalGroups);
    for (CDecalGroup** groupIt = groupsView.begin; groupIt != groupsView.end; ++groupIt) {
      CDecalGroup* const group = *groupIt;
      if (group != nullptr) {
        group->RemoveFromGroup(decal->mIndex);
      }
    }

    auto& decalsView = msvc8::AsVectorRuntimeView(mDecals);
    CWldTerrainDecal** found = decalsView.begin;
    while (found != decalsView.end) {
      if (*found == decal) {
        break;
      }
      ++found;
    }
    if (found == decalsView.end) {
      return;
    }

    CWldTerrainDecal* const removedDecal = *found;
    const std::ptrdiff_t trailingCount = decalsView.end - (found + 1);
    if (trailingCount > 0) {
      const std::size_t bytesToMove = static_cast<std::size_t>(trailingCount) * sizeof(CWldTerrainDecal*);
      (void)::memmove_s(found, bytesToMove, found + 1, bytesToMove);
    }
    --decalsView.end;

    delete removedDecal;

    for (CWldTerrainDecal** decalIt = decalsView.begin; decalIt != decalsView.end; ++decalIt) {
      CWldTerrainDecal* const activeDecal = *decalIt;
      if (activeDecal != nullptr) {
        activeDecal->mVecIndex = static_cast<std::uint32_t>(decalIt - decalsView.begin);
      }
    }

    mDidSomething = 1u;
  }

  /**
   * Address: 0x008782A0 (FUN_008782A0, Moho::CDecalManager::Func10)
   *
   * What it does:
   * Looks up one splat/decal-index key in the secondary lookup tree and
   * returns the mapped group index, or `0` when the key is absent.
   */
  std::int32_t CDecalManager::FindGroupBySplatIndex(const std::uint32_t splatIndex) const
  {
    const DecalGroupLookupNode* const node = FindLookupNodeByKey(mDecalGroupLookupBySplatIndex, splatIndex);
    if (node == nullptr || node == mDecalGroupLookupBySplatIndex.mHead) {
      return 0;
    }

    return node->mGroupIndex;
  }

  /**
   * Address: 0x00878A40 (FUN_00878A40, Moho::CDecalManager::RemoveDecals)
   *
   * What it does:
   * Scans all active decals for each requested runtime handle and marks
   * matching decals for deferred removal.
   */
  void CDecalManager::RemoveDecals(const msvc8::vector<std::int32_t>& decalHandles)
  {
    const auto& handleView = msvc8::AsVectorRuntimeView(decalHandles);
    for (const std::int32_t* handleIt = handleView.begin; handleIt != handleView.end; ++handleIt) {
      const auto& decalsView = msvc8::AsVectorRuntimeView(mDecals);
      for (CWldTerrainDecal** decalIt = decalsView.begin; decalIt != decalsView.end; ++decalIt) {
        CWldTerrainDecal* const decal = *decalIt;
        if (decal->mRuntimeHandle == *handleIt) {
          decal->mRemoveTick = 1;
          break;
        }
      }
    }
  }

  /**
   * Address: 0x008776D0 (FUN_008776D0, Moho::CDecalManager::Reindex)
   *
   * What it does:
   * Refreshes each decal's `mVecIndex` lane to match the current `mDecals`
   * vector order.
   */
  void CDecalManager::Reindex()
  {
    auto& decalsView = msvc8::AsVectorRuntimeView(mDecals);
    for (CWldTerrainDecal** decalIt = decalsView.begin; decalIt != decalsView.end; ++decalIt) {
      CWldTerrainDecal* const decal = *decalIt;
      decal->mVecIndex = static_cast<std::uint32_t>(decalIt - decalsView.begin);
    }
  }

  /**
   * Address: 0x00878590 (FUN_00878590, Moho::CDecalManager::Func17)
   *
   * What it does:
   * Finds one decal in `mDecals`, moves it to the front while preserving
   * relative order of earlier entries, then reindexes the decal lane.
   */
  void CDecalManager::MoveDecalToFront(CWldTerrainDecal* const decal)
  {
    auto& decalsView = msvc8::AsVectorRuntimeView(mDecals);

    CWldTerrainDecal** found = decalsView.begin;
    while (found != decalsView.end) {
      if (*found == decal) {
        break;
      }
      ++found;
    }

    if (found == decalsView.end) {
      return;
    }

    if (found != decalsView.begin) {
      do {
        CWldTerrainDecal* const previous = *(found - 1);
        *found = previous;
        --found;
      } while (found != decalsView.begin);
    }

    *found = decal;
    Reindex();
  }

  /**
   * Address: 0x008785D0 (FUN_008785D0, Moho::CDecalManager::Func18)
   *
   * What it does:
   * Finds one decal in `mDecals`, swaps it with the next entry when it is
   * not the last element, then reindexes when the decal exists.
   */
  void CDecalManager::MoveDecalTowardBack(CWldTerrainDecal* const decal)
  {
    auto& decalsView = msvc8::AsVectorRuntimeView(mDecals);

    CWldTerrainDecal** found = decalsView.begin;
    while (found != decalsView.end) {
      if (*found == decal) {
        break;
      }
      ++found;
    }

    if (found == decalsView.end) {
      return;
    }

    CWldTerrainDecal** const next = found + 1;
    if (next != decalsView.end) {
      *found = *next;
      *next = decal;
    }

    Reindex();
  }

  /**
   * Address: 0x00878610 (FUN_00878610, Moho::CDecalManager::Func19)
   *
   * What it does:
   * Finds one decal in `mDecals`, swaps it with the previous entry when it
   * is not the first element, then reindexes when a swap is applied.
   */
  void CDecalManager::MoveDecalTowardFront(CWldTerrainDecal* const decal)
  {
    auto& decalsView = msvc8::AsVectorRuntimeView(mDecals);

    CWldTerrainDecal** found = decalsView.begin;
    while (found != decalsView.end) {
      if (*found == decal) {
        break;
      }
      ++found;
    }

    if (found != decalsView.end && found != decalsView.begin) {
      *found = *(found - 1);
      *(found - 1) = decal;
      Reindex();
    }
  }

  /**
   * Address: 0x0089DF70 (FUN_0089DF70, Moho::CWldSplat::CWldSplat)
   *
   * What it does:
   * Seeds the splat's base decal state and leaves the batch-texture lane
   * empty until a name is assigned.
   */
  CWldSplat::CWldSplat(SpatialDB_MeshInstance* const spatialDbOwner, IWldTerrainRes* const terrainRes)
    : CWldTerrainDecal(spatialDbOwner, terrainRes)
    , mTex()
  {}

  /**
   * Address: 0x0089DFE0 (FUN_0089DFE0, Moho::CWldSplat::dtr)
   * Address: 0x0089E010 (FUN_0089E010, Moho::CWldSplat::~CWldSplat)
   *
   * What it does:
   * Releases the retained batch texture and then tears down the terrain
   * decal base lanes.
   */
  CWldSplat::~CWldSplat() = default;

  /**
   * Address: 0x0089E2C0 (FUN_0089E2C0, Moho::CWldSplat::SetName)
   *
   * What it does:
   * Stores the splat name, resolves the texture from disk when non-empty,
   * and keeps the previous texture lane intact when the name is empty.
   */
  void CWldSplat::SetName(const msvc8::string& name, const int slot)
  {
    (void)slot;

    mNames[0] = name;
    if (mNames[0].empty()) {
      return;
    }

    mTex = CD3DBatchTexture::FromFile(mNames[0].c_str(), 0u);
  }

  /**
   * Address: 0x0089E090 (FUN_0089E090, Moho::CWldSplat::Update)
   *
   * What it does:
   * Advances the base decal state and refreshes the splat vertex positions.
   */
  void CWldSplat::Update()
  {
    CWldTerrainDecal::Update();
    UpdateVertices();
  }

  /**
   * Address: 0x0089E0B0 (FUN_0089E0B0, Moho::CWldSplat::UpdateVertices)
   *
   * What it does:
   * Projects the unit quad into world space and samples terrain elevation
   * for each corner.
   */
  void CWldSplat::UpdateVertices()
  {
    const auto* const terrainView = AsCWldTerrainResRuntimeView(mTerrainRes);
    const STIMap* const map = terrainView->mMap;
    const CHeightField* const heightField = map->mHeightField.get();

    const Wm3::Vec2f localCorners[4]{
      {0.0f, 0.0f},
      {1.0f, 0.0f},
      {1.0f, 1.0f},
      {0.0f, 1.0f},
    };

    for (std::size_t index = 0; index < 4; ++index) {
      const Wm3::Vec2f corner = ComputeCorner(localCorners[index]);
      SplatVertex& vertex = mSplatVertices[index];
      vertex.mPosition.x = corner.x;
      vertex.mPosition.z = corner.y;
      vertex.mPosition.y = heightField->GetElevation(vertex.mPosition.x, vertex.mPosition.z);
    }
  }

  /**
   * Address: 0x0089E1F0 (FUN_0089E1F0, Moho::CWldSplat::UpdateBatchTexture)
   *
   * What it does:
   * Adds the retained batch texture to the atlas and writes the returned UV
   * rectangle into the splat quad.
   */
  void CWldSplat::UpdateBatchTexture(CD3DTextureBatcher* const batcher)
  {
    if (mTex) {
      const gpg::Rect2f* const uvRect = batcher->AddTexture(mTex);
      if (uvRect != nullptr) {
        mSplatVertices[0].mTexCoord.x = uvRect->x0;
        mSplatVertices[0].mTexCoord.y = uvRect->z0;
        mSplatVertices[1].mTexCoord.x = uvRect->x1;
        mSplatVertices[1].mTexCoord.y = uvRect->z0;
        mSplatVertices[2].mTexCoord.x = uvRect->x1;
        mSplatVertices[2].mTexCoord.y = uvRect->z1;
        mSplatVertices[3].mTexCoord.x = uvRect->x0;
        mSplatVertices[3].mTexCoord.y = uvRect->z1;
      }
    }
  }

  /**
   * Address: 0x0089E2B0 (FUN_0089E2B0, Moho::CWldSplat::GetSplatVertices)
   *
   * What it does:
   * Returns the first vertex lane for the splat quad.
   */
  CWldSplat::SplatVertex* CWldSplat::GetSplatVertices() noexcept
  {
    return mSplatVertices;
  }

  /**
   * Address: 0x00878190 (FUN_00878190, Moho::CDecalManager::NewSplat)
   *
   * What it does:
   * Allocates one `CWldSplat`, seeds it from this manager's spatial-db owner
   * and terrain resource lanes, and appends it to `mSplats`.
   */
  CWldSplat* CDecalManager::NewSplat()
  {
    auto* const spatialDbOwner = reinterpret_cast<SpatialDB_MeshInstance*>(mSpatialDbOwnerStorage);
    CWldSplat* const splat = new CWldSplat(spatialDbOwner, mWldTerrain);
    mSplats.push_back(splat);
    return splat;
  }

  /**
   * Address: 0x008784C0 (FUN_008784C0, Moho::CDecalManager::NewSplatAt)
   *
   * What it does:
   * Creates one splat, assigns type/name/default transform lanes, updates the
   * splat runtime state, and reports success.
   */
  bool CDecalManager::NewSplatAt(
    const Wm3::Vec3f& position,
    const EWldTerrainDecalType type,
    const msvc8::string& name
  )
  {
    CWldSplat* const splat = NewSplat();
    splat->mType = type;
    splat->SetName(name, 0);
    splat->mScale.x = 1.0f;
    splat->mScale.y = 1.0f;
    splat->mScale.z = 1.0f;
    splat->mPosition = position;
    splat->mOrientation.x = 0.0f;
    splat->mOrientation.y = 0.0f;
    splat->mOrientation.z = 0.0f;
    splat->Update();
    return true;
  }

  /**
   * Address: 0x00877E40 (FUN_00877E40, Moho::CDecalManager::Save)
   *
   * What it does:
   * Writes manager decal counts, serializes active decals, then serializes
   * all decal groups to the binary writer.
   */
  void CDecalManager::Save(gpg::BinaryWriter& writer)
  {
    writer.Write(mDecalCount);
    writer.Write(mNumDecals);

    const auto& decalsView = msvc8::AsVectorRuntimeView(mDecals);

    std::uint32_t activeDecalCount = 0u;
    for (CWldTerrainDecal** decalIt = decalsView.begin; decalIt != decalsView.end; ++decalIt) {
      CWldTerrainDecal* const decal = *decalIt;
      if (decal != nullptr && decal->mUnknownA0 == 0u) {
        ++activeDecalCount;
      }
    }
    writer.Write(activeDecalCount);

    for (CWldTerrainDecal** decalIt = decalsView.begin; decalIt != decalsView.end; ++decalIt) {
      CWldTerrainDecal* const decal = *decalIt;
      if (decal != nullptr && decal->mUnknownA0 == 0u) {
        decal->DecalSave(writer);
      }
    }

    const auto& groupsView = msvc8::AsVectorRuntimeView(mDecalGroups);
    const std::uint32_t groupCount =
      groupsView.begin != nullptr ? static_cast<std::uint32_t>(groupsView.end - groupsView.begin) : 0u;
    writer.Write(groupCount);

    for (CDecalGroup** groupIt = groupsView.begin; groupIt != groupsView.end; ++groupIt) {
      CDecalGroup* const group = *groupIt;
      if (group != nullptr) {
        group->WriteToStream(writer);
      }
    }
  }

} // namespace moho
