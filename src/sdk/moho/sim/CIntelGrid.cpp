#include "CIntelGrid.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/utils/Global.h"
#include "moho/math/GridPos.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/STIMapReflection.h"

#pragma init_seg(lib)

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };

  class SerSaveConstructArgsResult
  {
  public:
    void SetUnowned(unsigned int value);
  };
} // namespace gpg

namespace
{
  moho::CIntelGridTypeInfo gCIntelGridTypeInfo;
  moho::CIntelGridSaveConstruct gCIntelGridSaveConstruct;
  moho::CIntelGridConstruct gCIntelGridConstruct;
  moho::CIntelGridSerializer gCIntelGridSerializer;

  template <class THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mNext);
  }

  template <class THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mNext = self;
    helper.mPrev = self;
  }

  template <class THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    if (helper.mNext != nullptr && helper.mPrev != nullptr) {
      helper.mNext->mPrev = helper.mPrev;
      helper.mPrev->mNext = helper.mNext;
    }

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mPrev = self;
    helper.mNext = self;
    return self;
  }

  template <class TTypeInfo>
  void ResetTypeInfoVectors(TTypeInfo& typeInfo) noexcept
  {
    typeInfo.fields_ = msvc8::vector<gpg::RField>{};
    typeInfo.bases_ = msvc8::vector<gpg::RField>{};
  }

  gpg::RType* CachedIntelGridType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CIntelGrid));
    }
    return cached;
  }

  [[nodiscard]] std::int32_t FloorDivToGridCell(const std::int32_t value, const std::int32_t gridSize) noexcept
  {
    const float scaled = static_cast<float>(value) / static_cast<float>(gridSize);
    return static_cast<std::int32_t>(std::floor(scaled));
  }

  [[nodiscard]] std::int32_t CeilDivToGridCell(const std::int32_t value, const std::int32_t gridSize) noexcept
  {
    const float scaled = static_cast<float>(value) / static_cast<float>(gridSize);
    return static_cast<std::int32_t>(std::ceil(scaled));
  }

  /**
   * Address: 0x005BE080 (FUN_005BE080, func_RectToGrid)
   *
   * gpg::Rect2<int> const &, int
   *
   * IDA signature:
   * gpg::Rect2i *__usercall func_RectToGrid@<eax>(
   *   gpg::Rect2i *out@<ecx>,
   *   gpg::Rect2i *rect@<esi>,
   *   int gridSize)
   *
   * What it does:
   * Converts world-space rect bounds into grid-space bounds using floor for
   * min coordinates and ceil for max coordinates.
   */
  [[nodiscard]] gpg::Rect2i RectToGridCellBounds(const gpg::Rect2<int>& rect, const std::int32_t gridSize) noexcept
  {
    gpg::Rect2i out{};
    out.x0 = FloorDivToGridCell(rect.x0, gridSize);
    out.z0 = FloorDivToGridCell(rect.z0, gridSize);
    out.x1 = CeilDivToGridCell(rect.x1, gridSize);
    out.z1 = CeilDivToGridCell(rect.z1, gridSize);
    return out;
  }

  [[nodiscard]] gpg::RRef MakeCIntelGridRef(moho::CIntelGrid* const object) noexcept
  {
    gpg::RRef out{};
    out.mObj = object;
    out.mType = CachedIntelGridType();
    return out;
  }

  template <class TObject, class TBuildRef>
  [[nodiscard]] gpg::WriteArchive* WriteUnownedPointerSlot_UsingRRefBuilder(
    TObject* const* const objectSlot,
    gpg::WriteArchive* const archive,
    const gpg::RRef& ownerRef,
    TBuildRef&& buildRef
  )
  {
    if (!archive || !objectSlot) {
      return archive;
    }

    gpg::RRef pointerRef{};
    buildRef(&pointerRef, *objectSlot);
    gpg::WriteRawPointer(archive, pointerRef, gpg::TrackedPointerState::Unowned, ownerRef);
    return archive;
  }

  [[nodiscard]] moho::STIMap* ReadUnownedSTIMapPointer(gpg::ReadArchive* const archive, const gpg::RRef& ownerRef)
  {
    if (!archive) {
      return nullptr;
    }
    return gpg::ReadPointerSTIMap(archive, ownerRef);
  }

  /**
   * Address: 0x005089B0 (FUN_005089B0, CIntelGrid save-construct forwarding lane)
   */
  [[maybe_unused]] void ForwardCIntelGridMemberSaveConstructArgs(
    gpg::SerSaveConstructArgsResult* const result,
    moho::CIntelGrid* const intelGrid,
    gpg::WriteArchive* const archive,
    const int version,
    const gpg::RRef& ownerRef
  )
  {
    if (result && intelGrid && archive) {
      intelGrid->MemberSaveConstructArgs(*archive, version, ownerRef, *result);
    }
  }

  /**
   * Address: 0x005089C0 (FUN_005089C0, STIMap unowned pointer write helper)
   */
  [[maybe_unused]] [[nodiscard]] gpg::WriteArchive* WriteUnownedSTIMapPointerVariant1(
    moho::STIMap* const* const mapSlot, gpg::WriteArchive* const archive, const gpg::RRef& ownerRef
  )
  {
    return WriteUnownedPointerSlot_UsingRRefBuilder(
      mapSlot,
      archive,
      ownerRef,
      [](gpg::RRef* const outRef, moho::STIMap* const value) {
        if (!outRef) {
          return;
        }
        (void)gpg::RRef_STIMap(outRef, value);
      }
    );
  }

  /**
   * Address: 0x00508A40 (FUN_00508A40, STIMap unowned pointer read helper)
   */
  [[maybe_unused]] [[nodiscard]] gpg::ReadArchive* ReadUnownedSTIMapPointerVariant1(
    const gpg::RRef& ownerRef, gpg::ReadArchive* const archive, moho::STIMap** const mapSlot
  )
  {
    if (mapSlot) {
      *mapSlot = ReadUnownedSTIMapPointer(archive, ownerRef);
    }
    return archive;
  }

  /**
   * Address: 0x00508A50 (FUN_00508A50, CIntelGrid RRef fill helper)
   */
  [[maybe_unused]] [[nodiscard]] gpg::RRef* FillCIntelGridRef(
    moho::CIntelGrid* const value, gpg::RRef* const outRef
  )
  {
    return gpg::RRef_CIntelGrid(outRef, value);
  }

  /**
   * Address: 0x00508D80 (FUN_00508D80, CIntelGrid storage-release helper)
   */
  [[maybe_unused]] void DestroyCIntelGridInPlace(moho::CIntelGrid* const intelGrid)
  {
    if (!intelGrid) {
      return;
    }

    if (intelGrid->mUpdateList.mStart) {
      ::operator delete(intelGrid->mUpdateList.mStart);
    }
    intelGrid->mUpdateList.mStart = nullptr;
    intelGrid->mUpdateList.mFinish = nullptr;
    intelGrid->mUpdateList.mCapacity = nullptr;

    ::operator delete[](intelGrid->mGrid);
  }

  /**
   * Address: 0x00508D40 (FUN_00508D40, CIntelGrid destroy-and-delete helper)
   */
  [[maybe_unused]] [[nodiscard]] moho::CIntelGrid* DestroyCIntelGridAndDeleteSelf(
    moho::CIntelGrid* const intelGrid
  )
  {
    if (!intelGrid) {
      return nullptr;
    }

    DestroyCIntelGridInPlace(intelGrid);
    ::operator delete(intelGrid);
    return intelGrid;
  }

  /**
   * Address: 0x00508E50 (FUN_00508E50, STIMap unowned pointer read helper duplicate)
   */
  [[maybe_unused]] [[nodiscard]] gpg::ReadArchive* ReadUnownedSTIMapPointerVariant2(
    const gpg::RRef& ownerRef, moho::STIMap** const mapSlot, gpg::ReadArchive* const archive
  )
  {
    return ReadUnownedSTIMapPointerVariant1(ownerRef, archive, mapSlot);
  }

  /**
   * Address: 0x00508E60 (FUN_00508E60, STIMap unowned pointer write helper duplicate)
   */
  [[maybe_unused]] void WriteUnownedSTIMapPointerVariant2(
    moho::STIMap* const* const mapSlot, gpg::WriteArchive* const archive, const gpg::RRef& ownerRef
  )
  {
    (void)WriteUnownedSTIMapPointerVariant1(mapSlot, archive, ownerRef);
  }

  void CleanupSaveConstructAtexit()
  {
    (void)moho::cleanup_CIntelGridSaveConstruct();
  }

  void CleanupConstructAtexit()
  {
    (void)moho::cleanup_CIntelGridConstruct();
  }

  void CleanupSerializerAtexit()
  {
    (void)moho::cleanup_CIntelGridSerializer();
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
   * Address: 0x00508D80 (FUN_00508D80, CIntelGrid storage-release lane)
   */
  CIntelGrid::~CIntelGrid()
  {
    DestroyCIntelGridInPlace(this);
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
   * Address: 0x005BE210 (FUN_005BE210, ?IsVisible@CIntelGrid@Moho@@QBE_NABV?$Rect2@H@gpg@@_N@Z)
   *
   * gpg::Rect2<int> const &, bool
   *
   * IDA signature:
   * bool __usercall Moho::CIntelGrid::IsVisible@<al>(Moho::CIntelGrid *this@<eax>, gpg::Rect2i *rect@<ecx>)
   *
   * What it does:
   * Converts world-space rectangle to grid-cell bounds and returns true when any
   * covered cell in the intel grid is non-zero.
   */
  bool CIntelGrid::IsVisible(const gpg::Rect2<int>& rect, const bool /*unused*/) const
  {
    if (!mGrid || mGridSize == 0u || mWidth == 0u || mHeight == 0u) {
      return false;
    }

    const gpg::Rect2i gridRect = RectToGridCellBounds(rect, static_cast<std::int32_t>(mGridSize));

    const std::int32_t minX = std::max<std::int32_t>(0, gridRect.x0);
    const std::int32_t minZ = std::max<std::int32_t>(0, gridRect.z0);
    const std::int32_t maxX = std::min<std::int32_t>(gridRect.x1, static_cast<std::int32_t>(mWidth));
    const std::int32_t maxZ = std::min<std::int32_t>(gridRect.z1, static_cast<std::int32_t>(mHeight));
    if (minX >= maxX || minZ >= maxZ) {
      return false;
    }

    for (std::int32_t z = minZ; z < maxZ; ++z) {
      const std::size_t rowBase = static_cast<std::size_t>(z) * static_cast<std::size_t>(mWidth);
      for (std::int32_t x = minX; x < maxX; ++x) {
        const std::size_t index = rowBase + static_cast<std::size_t>(x);
        if (mGrid[index] != 0) {
          return true;
        }
      }
    }
    return false;
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
   * Address: 0x00507880 (FUN_00507880, ?UpdateChecksum@CIntelGrid@Moho@@QAEXAAVMD5Context@gpg@@@Z)
   */
  void CIntelGrid::UpdateChecksum(gpg::MD5Context& /*context*/)
  {
    // Binary implementation is an explicit no-op (`retn`).
  }

  /**
   * Address: 0x005072D0 (FUN_005072D0,
   * ?MemberSaveConstructArgs@CIntelGrid@Moho@@AAEXAAVWriteArchive@gpg@@HABVRRef@4@AAVSerSaveConstructArgsResult@4@@Z)
   */
  void CIntelGrid::MemberSaveConstructArgs(
    gpg::WriteArchive& archive, int /*version*/, const gpg::RRef& ownerRef, gpg::SerSaveConstructArgsResult& result
  )
  {
    (void)WriteUnownedSTIMapPointerVariant1(&mMapData, &archive, ownerRef);
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
   * Address: 0x00507240 (FUN_00507240, CIntelGridSaveConstruct::SaveConstruct)
   */
  void CIntelGridSaveConstruct::SaveConstruct(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const intelGrid = reinterpret_cast<CIntelGrid*>(objectPtr);
    if (archive == nullptr || intelGrid == nullptr || result == nullptr) {
      return;
    }

    const gpg::RRef fallbackOwner{};
    ForwardCIntelGridMemberSaveConstructArgs(
      result, intelGrid, archive, version, ownerRef != nullptr ? *ownerRef : fallbackOwner
    );
  }

  /**
   * Address: 0x005073C0 (FUN_005073C0, Moho::CIntelGridConstruct::Construct)
   */
  void CIntelGridConstruct::Construct(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::SerConstructResult* const result
  )
  {
    if (archive == nullptr || result == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    STIMap* map = nullptr;
    (void)ReadUnownedSTIMapPointerVariant1(ownerRef, archive, &map);

    unsigned int gridSize = 0u;
    archive->ReadUInt(&gridSize);

    CIntelGrid* const intelGrid = new CIntelGrid(map, gridSize);
    gpg::RRef outRef{};
    (void)FillCIntelGridRef(intelGrid, &outRef);
    result->SetUnowned(outRef, 0u);

    (void)objectPtr;
    (void)version;
  }

  /**
   * Address: 0x005089F0 (FUN_005089F0, Moho::CIntelGridConstruct::Deconstruct)
   */
  void CIntelGridConstruct::Deconstruct(void* const objectPtr)
  {
    auto* const intelGrid = static_cast<CIntelGrid*>(objectPtr);
    if (intelGrid == nullptr) {
      return;
    }

    (void)DestroyCIntelGridAndDeleteSelf(intelGrid);
  }

  /**
   * Address: 0x00507490 (FUN_00507490, Moho::CIntelGridSerializer::Deserialize)
   */
  void CIntelGridSerializer::Deserialize(gpg::ReadArchive*, int, int, gpg::RRef*)
  {
    // Binary callback is an explicit no-op (`retn`).
  }

  /**
   * Address: 0x005074A0 (FUN_005074A0, Moho::CIntelGridSerializer::Serialize)
   */
  void CIntelGridSerializer::Serialize(gpg::WriteArchive*, int, int, gpg::RRef*)
  {
    // Binary callback is an explicit no-op (`retn`).
  }

  /**
   * Address: 0x00507D60 (FUN_00507D60, Moho::CIntelGridSaveConstruct::RegisterSaveConstructArgsFunction)
   */
  void CIntelGridSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* const type = CachedIntelGridType();
    GPG_ASSERT(type->serSaveConstructArgsFunc_ == nullptr || type->serSaveConstructArgsFunc_ == mSerSaveConstructArgsFunc);
    type->serSaveConstructArgsFunc_ = mSerSaveConstructArgsFunc;
  }

  /**
   * Address: 0x00507DE0 (FUN_00507DE0, Moho::CIntelGridConstruct::RegisterConstructFunction)
   */
  void CIntelGridConstruct::RegisterConstructFunction()
  {
    gpg::RType* const type = CachedIntelGridType();
    GPG_ASSERT(type->serConstructFunc_ == nullptr || type->serConstructFunc_ == mSerConstructFunc);
    GPG_ASSERT(type->deleteFunc_ == nullptr || type->deleteFunc_ == mDeleteFunc);
    type->serConstructFunc_ = mSerConstructFunc;
    type->deleteFunc_ = mDeleteFunc;
  }

  /**
   * Address: 0x00507E60 (FUN_00507E60, Moho::CIntelGridSerializer::RegisterSerializeFunctions)
   */
  void CIntelGridSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedIntelGridType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mSerLoadFunc);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerSaveFunc);
    type->serLoadFunc_ = mSerLoadFunc;
    type->serSaveFunc_ = mSerSaveFunc;
  }

  /**
   * Address: 0x005070D0 (FUN_005070D0, Moho::CIntelGridTypeInfo::CIntelGridTypeInfo)
   */
  CIntelGridTypeInfo::CIntelGridTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CIntelGrid), this);
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

  /**
   * Address: 0x00BF1D90 (FUN_00BF1D90, cleanup_CIntelGridTypeInfo)
   */
  void cleanup_CIntelGridTypeInfo()
  {
    ResetTypeInfoVectors(gCIntelGridTypeInfo);
  }

  /**
   * Address: 0x00BF1DF0 (FUN_00BF1DF0, cleanup_CIntelGridSaveConstruct)
   */
  gpg::SerHelperBase* cleanup_CIntelGridSaveConstruct()
  {
    return UnlinkHelperNode(gCIntelGridSaveConstruct);
  }

  /**
   * Address: 0x00BF1E20 (FUN_00BF1E20, cleanup_CIntelGridConstruct)
   */
  gpg::SerHelperBase* cleanup_CIntelGridConstruct()
  {
    return UnlinkHelperNode(gCIntelGridConstruct);
  }

  /**
   * Address: 0x00BF1E50 (FUN_00BF1E50, cleanup_CIntelGridSerializer)
   */
  gpg::SerHelperBase* cleanup_CIntelGridSerializer()
  {
    return UnlinkHelperNode(gCIntelGridSerializer);
  }

  /**
   * Address: 0x00BC7920 (FUN_00BC7920, register_CIntelGridTypeInfo)
   */
  void register_CIntelGridTypeInfo()
  {
    (void)gCIntelGridTypeInfo;
    (void)std::atexit(&cleanup_CIntelGridTypeInfo);
  }

  /**
   * Address: 0x00BC7940 (FUN_00BC7940, register_CIntelGridSaveConstruct)
   */
  void register_CIntelGridSaveConstruct()
  {
    InitializeHelperNode(gCIntelGridSaveConstruct);
    gCIntelGridSaveConstruct.mSerSaveConstructArgsFunc =
      reinterpret_cast<gpg::RType::save_construct_args_func_t>(&CIntelGridSaveConstruct::SaveConstruct);
    gCIntelGridSaveConstruct.RegisterSaveConstructArgsFunction();
    (void)std::atexit(&CleanupSaveConstructAtexit);
  }

  /**
   * Address: 0x00BC7970 (FUN_00BC7970, register_CIntelGridConstruct)
   */
  void register_CIntelGridConstruct()
  {
    InitializeHelperNode(gCIntelGridConstruct);
    gCIntelGridConstruct.mSerConstructFunc = reinterpret_cast<gpg::RType::construct_func_t>(&CIntelGridConstruct::Construct);
    gCIntelGridConstruct.mDeleteFunc = &CIntelGridConstruct::Deconstruct;
    gCIntelGridConstruct.RegisterConstructFunction();
    (void)std::atexit(&CleanupConstructAtexit);
  }

  /**
   * Address: 0x00BC79B0 (FUN_00BC79B0, register_CIntelGridSerializer)
   */
  void register_CIntelGridSerializer()
  {
    InitializeHelperNode(gCIntelGridSerializer);
    gCIntelGridSerializer.mSerLoadFunc = reinterpret_cast<gpg::RType::load_func_t>(&CIntelGridSerializer::Deserialize);
    gCIntelGridSerializer.mSerSaveFunc = reinterpret_cast<gpg::RType::save_func_t>(&CIntelGridSerializer::Serialize);
    gCIntelGridSerializer.RegisterSerializeFunctions();
    (void)std::atexit(&CleanupSerializerAtexit);
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x00509200 (FUN_00509200, gpg::RRef_CIntelGrid)
   */
  gpg::RRef* RRef_CIntelGrid(gpg::RRef* const outRef, moho::CIntelGrid* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    *outRef = MakeCIntelGridRef(value);
    return outRef;
  }
} // namespace gpg

namespace
{
  struct CIntelGridReflectionBootstrap
  {
    CIntelGridReflectionBootstrap()
    {
      moho::register_CIntelGridTypeInfo();
      moho::register_CIntelGridSaveConstruct();
      moho::register_CIntelGridConstruct();
      moho::register_CIntelGridSerializer();
    }
  };

  [[maybe_unused]] CIntelGridReflectionBootstrap gCIntelGridReflectionBootstrap;
} // namespace
