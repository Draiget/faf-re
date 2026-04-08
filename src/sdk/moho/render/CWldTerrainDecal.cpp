#include "moho/render/CWldTerrainDecal.h"

#include <cstddef>

namespace
{
  void ReleaseTrackedCountedObjectPtr(moho::CountedPtr<moho::CountedObject>& ptr) noexcept
  {
    if (ptr.tex != nullptr) {
      ptr.tex->ReleaseReference();
      ptr.tex = nullptr;
    }
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0089CA60 (FUN_0089CA60, Moho::CWldTerrainDecal::CWldTerrainDecal)
   *
   * What it does:
   * Seeds the terrain-decal defaults, registers the decal into the spatial
   * database, and initializes the default scale/position/orientation lanes.
   */
  CWldTerrainDecal::CWldTerrainDecal(SpatialDB_MeshInstance* const spatialDbOwner, IWldTerrainRes* const terrainRes)
    : mLinkHead(nullptr)
    , mTerrainRes(terrainRes)
    , mEntry{}
    , mVecIndex(0)
    , mIndex(0)
    , mType(WldTerrainDecalType_Undefined)
    , mRuntimeActive(1)
    , mPad21_23{0, 0, 0}
    , mNames{}
    , mScale{8.0f, 8.0f, 8.0f}
    , mPosition{}
    , mOrientation{}
    , mUnknown80(0.0f)
    , mUnknown84(0.0f)
    , mUnknown88(0.0f)
    , mUnknown8C(1.0f)
    , mUnknown90(5.0f)
    , mUnknown94(0.0f)
    , mUnknown98(0)
    , mUnknown9C(-1)
    , mUnknownA0(0)
    , mPadA1_A3{0, 0, 0}
    , mResourceRefs{}
    , mPadAC_13B{0}
    , mFlag13C(1)
    , mFlag13D(0)
    , mFlag13E(0)
    , mPad13F(0)
  {
    mEntry.Register(spatialDbOwner, this, 0x800);
  }

  /**
   * Address: 0x0089CBB0 (FUN_0089CBB0, Moho::CWldTerrainDecal::dtr)
   * Address: 0x0089CBF0 (FUN_0089CBF0, Moho::CWldTerrainDecal::~CWldTerrainDecal body)
   *
   * What it does:
   * Releases the counted runtime reference lanes and clears spatial-db
   * registration before object teardown.
   */
  CWldTerrainDecal::~CWldTerrainDecal()
  {
    for (std::size_t index = 2; index > 0; --index) {
      ReleaseTrackedCountedObjectPtr(mResourceRefs[index - 1]);
    }

    mEntry.ClearRegistration();

    while (mLinkHead != nullptr) {
      CWldTerrainDecalLink* const nextLink = mLinkHead->mNext;
      mLinkHead->mPrev = nullptr;
      mLinkHead->mNext = nullptr;
      mLinkHead = nextLink;
    }
  }
} // namespace moho
