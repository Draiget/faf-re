#include "CIntelGrid.h"

#include <cmath>
#include <cstring>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/utils/Global.h"
#include "moho/math/GridPos.h"
#include "moho/sim/STIMap.h"

namespace gpg
{
  class SerSaveConstructArgsResult
  {
  public:
    void SetUnowned(unsigned int value);
  };
} // namespace gpg

namespace
{
  gpg::RType* CachedIntelGridType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CIntelGrid));
    }
    return cached;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00507720 (FUN_00507720, ??0CIntelGrid@Moho@@QAE@PBVSTIMap@1@H@Z)
   *
   * What it does:
   * Binds map source, allocates byte coverage grid, and sets delayed-update
   * storage to empty.
   */
  CIntelGrid::CIntelGrid(const STIMap* const map, const std::uint32_t size)
  {
    mMapData = const_cast<STIMap*>(map);
    const CHeightField* const heightField = mMapData ? mMapData->mHeightField.get() : nullptr;
    GPG_ASSERT(heightField != nullptr);

    const std::int32_t cellSize = static_cast<std::int32_t>(size);
    const std::int32_t width = (heightField->width - 1) / cellSize;
    const std::int32_t height = (heightField->height - 1) / cellSize;

    mWidth = static_cast<std::uint32_t>(width);
    mHeight = static_cast<std::uint32_t>(height);

    const std::size_t cellCount = static_cast<std::size_t>(width) * static_cast<std::size_t>(height);
    mGrid = static_cast<std::int8_t*>(::operator new(cellCount));
    std::memset(mGrid, 0, cellCount);

    mUpdateList.mStart = nullptr;
    mUpdateList.mFinish = nullptr;
    mUpdateList.mCapacity = nullptr;
    mGridSize = size;
  }

  /**
   * Address: 0x005089F0 (FUN_005089F0, ??1CIntelGrid@Moho@@QAE@XZ)
   */
  CIntelGrid::~CIntelGrid()
  {
    if (mUpdateList.mStart) {
      ::operator delete(mUpdateList.mStart);
    }
    mUpdateList.mStart = nullptr;
    mUpdateList.mFinish = nullptr;
    mUpdateList.mCapacity = nullptr;

    ::operator delete(mGrid);
  }

  /**
   * Address: 0x005BE150 (FUN_005BE150, ?IsVisible@CIntelGrid@Moho@@QBE_NHH@Z)
   */
  bool CIntelGrid::IsVisible(const std::int32_t x, const std::int32_t z) const
  {
    if (x < 0 || z < 0) {
      return false;
    }

    const std::uint32_t ux = static_cast<std::uint32_t>(x);
    const std::uint32_t uz = static_cast<std::uint32_t>(z);
    if (ux >= mWidth || uz >= mHeight) {
      return false;
    }

    return mGrid[uz * mWidth + ux] != 0;
  }

  /**
   * Address: 0x00507670 (FUN_00507670, ?AddCircle@CIntelGrid@Moho@@QAEXABV?$Vector3@M@Wm3@@I@Z)
   */
  void CIntelGrid::AddCircle(const Wm3::Vec3f& position, const std::uint32_t radius)
  {
    Raster(position, radius / mGridSize, true);
  }

  /**
   * Address: 0x00507690 (FUN_00507690, ?SubtractCircle@CIntelGrid@Moho@@QAEXABV?$Vector3@M@Wm3@@I@Z)
   */
  void CIntelGrid::SubtractCircle(const Wm3::Vec3f& position, const std::uint32_t radius)
  {
    Raster(position, radius / mGridSize, false);
  }

  /**
   * Address: 0x005076B0 (FUN_005076B0, ?DelayedSubtractCircle@CIntelGrid@Moho@@QAEXABV?$Vector3@M@Wm3@@I@Z)
   */
  void CIntelGrid::DelayedSubtractCircle(const Wm3::Vec3f& position, const std::uint32_t radius)
  {
    SDelayedSubVizInfo update{};
    update.mLastPos = position;
    update.mRadius = static_cast<float>(radius);
    update.mTicksTilUpdate = 30;
    PushDelayedUpdate(update);
  }

  /**
   * Address: 0x005077B0 (FUN_005077B0, ?Tick@CIntelGrid@Moho@@QAEXH@Z)
   */
  void CIntelGrid::Tick(const std::int32_t dTicks)
  {
    if (!mUpdateList.mStart || mUpdateList.mStart == mUpdateList.mFinish) {
      return;
    }

    for (SDelayedSubVizInfo* update = mUpdateList.mStart; update != mUpdateList.mFinish;) {
      update->mTicksTilUpdate -= dTicks;
      if (update->mTicksTilUpdate > 0) {
        ++update;
        continue;
      }

      const auto radiusInCells = static_cast<std::uint32_t>(update->mRadius / static_cast<float>(mGridSize));
      Raster(update->mLastPos, radiusInCells, false);

      SDelayedSubVizInfo* const next = update + 1;
      if (next != mUpdateList.mFinish) {
        const std::size_t tailCount = static_cast<std::size_t>(mUpdateList.mFinish - next);
        std::memmove(update, next, tailCount * sizeof(SDelayedSubVizInfo));
      }

      --mUpdateList.mFinish;
    }
  }

  /**
   * Address: 0x005072D0 (FUN_005072D0,
   * ?MemberSaveConstructArgs@CIntelGrid@Moho@@AAEXAAVWriteArchive@gpg@@HABVRRef@4@AAVSerSaveConstructArgsResult@4@@Z)
   */
  void CIntelGrid::MemberSaveConstructArgs(
    gpg::WriteArchive& archive, int /*version*/, const gpg::RRef& ownerRef, gpg::SerSaveConstructArgsResult& result
  )
  {
    gpg::RRef mapRef{};
    mapRef.mObj = mMapData;
    mapRef.mType = gpg::LookupRType(typeid(STIMap));

    gpg::WriteRawPointer(&archive, mapRef, gpg::TrackedPointerState::Unowned, ownerRef);
    archive.WriteInt(static_cast<std::int32_t>(mGridSize));
    result.SetUnowned(0);
  }

  /**
   * Address: 0x00507540 (FUN_00507540, ?Raster@CIntelGrid@Moho@@AAEXABV?$Vector3@M@Wm3@@I_N@Z)
   */
  void CIntelGrid::Raster(const Wm3::Vec3f& position, const std::uint32_t radiusInCells, const bool doAdd)
  {
    Wm3::Vec3f mutablePos = position;
    GridPos gridPos(&mutablePos, static_cast<std::int32_t>(mGridSize));

    const std::int32_t width = static_cast<std::int32_t>(mWidth);
    const std::int32_t height = static_cast<std::int32_t>(mHeight);
    const std::int32_t radius = static_cast<std::int32_t>(radiusInCells);

    std::int32_t x = gridPos.x - radius;
    if (x >= width) {
      x = width;
    }
    if (x < 0) {
      x = 0;
    }

    std::int32_t xMax = width;
    if (gridPos.x + radius < width) {
      xMax = gridPos.x + radius;
    }
    if (xMax < 0) {
      xMax = 0;
    }

    if (x >= xMax) {
      return;
    }

    const std::int32_t radiusSq = radius * radius;
    const std::int8_t cellDelta = static_cast<std::int8_t>(doAdd ? 1 : -1);
    std::int32_t xDistance = gridPos.x - x;

    for (; x < xMax; ++x, --xDistance) {
      const std::int32_t leg =
        static_cast<std::int32_t>(std::sqrt(static_cast<float>(radiusSq - xDistance * xDistance)));

      std::int32_t z = gridPos.z - leg;
      if (z >= height) {
        z = height;
      }
      if (z < 0) {
        z = 0;
      }

      std::int32_t zMax = gridPos.z + leg;
      if (zMax >= height) {
        zMax = height;
      }
      if (zMax < 0) {
        zMax = 0;
      }

      for (; z < zMax; ++z) {
        std::int8_t& cell = mGrid[x + z * width];
        cell = static_cast<std::int8_t>(cell + cellDelta);
      }
    }
  }

  void CIntelGrid::PushDelayedUpdate(const SDelayedSubVizInfo& update)
  {
    if (mUpdateList.mStart && mUpdateList.mFinish < mUpdateList.mCapacity) {
      *mUpdateList.mFinish = update;
      ++mUpdateList.mFinish;
      return;
    }

    const std::size_t count =
      mUpdateList.mStart ? static_cast<std::size_t>(mUpdateList.mFinish - mUpdateList.mStart) : 0u;
    const std::size_t oldCapacity =
      mUpdateList.mStart ? static_cast<std::size_t>(mUpdateList.mCapacity - mUpdateList.mStart) : 0u;

    std::size_t newCapacity = oldCapacity ? (oldCapacity + oldCapacity / 2u) : 1u;
    if (newCapacity <= count) {
      newCapacity = count + 1u;
    }

    auto* const newBuffer = static_cast<SDelayedSubVizInfo*>(::operator new(newCapacity * sizeof(SDelayedSubVizInfo)));
    if (count != 0u) {
      std::memcpy(newBuffer, mUpdateList.mStart, count * sizeof(SDelayedSubVizInfo));
      ::operator delete(mUpdateList.mStart);
    }

    mUpdateList.mStart = newBuffer;
    mUpdateList.mFinish = newBuffer + count;
    mUpdateList.mCapacity = newBuffer + newCapacity;

    *mUpdateList.mFinish = update;
    ++mUpdateList.mFinish;
  }

  /**
   * Address: 0x00507D60 (FUN_00507D60, sub_507D60)
   */
  void CIntelGridSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* const type = CachedIntelGridType();
    GPG_ASSERT(type->serSaveConstructArgsFunc_ == nullptr);
    type->serSaveConstructArgsFunc_ = mSerSaveConstructArgsFunc;
  }

  /**
   * Address: 0x00507DE0 (FUN_00507DE0, sub_507DE0)
   */
  void CIntelGridConstruct::RegisterConstructFunction()
  {
    gpg::RType* const type = CachedIntelGridType();
    GPG_ASSERT(type->serConstructFunc_ == nullptr);
    type->serConstructFunc_ = mSerConstructFunc;
    type->deleteFunc_ = mDeleteFunc;
  }

  /**
   * Address: 0x00507E60 (FUN_00507E60, sub_507E60)
   */
  void CIntelGridSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedIntelGridType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mSerLoadFunc;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerSaveFunc;
  }

  /**
   * Address: 0x00507160 (FUN_00507160, gpg::RType::~RType thunk)
   */
  CIntelGridTypeInfo::~CIntelGridTypeInfo() = default;

  /**
   * Address: 0x00507150 (FUN_00507150, Moho::CIntelGridTypeInfo::GetName)
   */
  const char* CIntelGridTypeInfo::GetName() const
  {
    return "CIntelGrid";
  }

  /**
   * Address: 0x00507130 (FUN_00507130, Moho::CIntelGridTypeInfo::Init)
   */
  void CIntelGridTypeInfo::Init()
  {
    size_ = sizeof(CIntelGrid);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho
