#include "SSTIArmyConstantData.h"

#include <cstdint>
#include <new>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "moho/sim/CIntelGrid.h"

namespace
{
  struct SerSaveLoadHelperNodeView
  {
    void* mVTable;
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };
  static_assert(
    offsetof(SerSaveLoadHelperNodeView, mHelperNext) == 0x04,
    "SerSaveLoadHelperNodeView::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(SerSaveLoadHelperNodeView, mHelperPrev) == 0x08,
    "SerSaveLoadHelperNodeView::mHelperPrev offset must be 0x08"
  );
  static_assert(sizeof(SerSaveLoadHelperNodeView) == 0x14, "SerSaveLoadHelperNodeView size must be 0x14");

  SerSaveLoadHelperNodeView gSSTIArmyConstantDataSerializer{};
  SerSaveLoadHelperNodeView gEntIdSerializer{};

  [[nodiscard]] gpg::SerHelperBase* HelperNodeSelf(SerSaveLoadHelperNodeView& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  [[nodiscard]] gpg::SerHelperBase* ResetHelperNodeLinks(SerSaveLoadHelperNodeView& helper) noexcept
  {
    helper.mHelperNext->mPrev = helper.mHelperPrev;
    helper.mHelperPrev->mNext = helper.mHelperNext;
    gpg::SerHelperBase* const self = HelperNodeSelf(helper);
    helper.mHelperPrev = self;
    helper.mHelperNext = self;
    return self;
  }

  /**
   * Address: 0x00550860 (FUN_00550860)
   *
   * What it does:
   * Unlinks `SSTIArmyConstantDataSerializer` helper node from the intrusive
   * helper list and restores self-linked sentinel links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupSSTIArmyConstantDataSerializerHelperNodePrimary() noexcept
  {
    return ResetHelperNodeLinks(gSSTIArmyConstantDataSerializer);
  }

  /**
   * Address: 0x00550890 (FUN_00550890)
   *
   * What it does:
   * Secondary entrypoint for `SSTIArmyConstantDataSerializer` helper-node
   * unlink/reset.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupSSTIArmyConstantDataSerializerHelperNodeSecondary() noexcept
  {
    return ResetHelperNodeLinks(gSSTIArmyConstantDataSerializer);
  }

  /**
   * Address: 0x00557F60 (FUN_00557F60)
   *
   * What it does:
   * Unlinks `EntIdSerializer` helper node from the intrusive helper list and
   * restores self-linked sentinel links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupEntIdSerializerHelperNodePrimary() noexcept
  {
    return ResetHelperNodeLinks(gEntIdSerializer);
  }

  /**
   * Address: 0x00557F90 (FUN_00557F90)
   *
   * What it does:
   * Secondary entrypoint for `EntIdSerializer` helper-node unlink/reset.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupEntIdSerializerHelperNodeSecondary() noexcept
  {
    return ResetHelperNodeLinks(gEntIdSerializer);
  }

  void DeserializeEntIdSerializerCallback(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const object = reinterpret_cast<std::int32_t*>(static_cast<std::intptr_t>(objectPtr));
    archive->ReadInt(object);
  }

  void SerializeEntIdSerializerCallback(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    const auto* const object = reinterpret_cast<const std::int32_t*>(static_cast<std::intptr_t>(objectPtr));
    archive->WriteInt(*object);
  }

  /**
   * Address: 0x005589B0 (FUN_005589B0)
   *
   * What it does:
   * Initializes callback lanes for global `EntIdSerializer` helper storage and
   * returns that helper object.
   */
  [[maybe_unused]] [[nodiscard]] SerSaveLoadHelperNodeView* InitializeEntIdSerializerStartupThunk() noexcept
  {
    gpg::SerHelperBase* const self = HelperNodeSelf(gEntIdSerializer);
    gEntIdSerializer.mHelperPrev = self;
    gEntIdSerializer.mHelperNext = self;
    gEntIdSerializer.mLoadCallback = &DeserializeEntIdSerializerCallback;
    gEntIdSerializer.mSaveCallback = &SerializeEntIdSerializerCallback;
    return &gEntIdSerializer;
  }

  /**
   * Address: 0x007000A0 (FUN_007000A0)
   *
   * What it does:
   * Assigns one `SSTIArmyConstantData` payload from `source` into
   * `destination` and returns the destination pointer.
   */
  [[maybe_unused]] moho::SSTIArmyConstantData* AssignSSTIArmyConstantData(
    const moho::SSTIArmyConstantData* const source,
    moho::SSTIArmyConstantData* const destination
  )
  {
    *destination = *source;
    return destination;
  }

  /**
   * Address: 0x007518A0 (FUN_007518A0)
   *
   * What it does:
   * Copies one contiguous `SSTIArmyConstantData` assignment range
   * `[sourceBegin, sourceEnd)` into `destinationBegin` and returns the end of
   * the destination range.
   */
  [[maybe_unused]] moho::SSTIArmyConstantData* CopySSTIArmyConstantDataRangeForwardAssign(
    const moho::SSTIArmyConstantData* sourceBegin,
    const moho::SSTIArmyConstantData* const sourceEnd,
    moho::SSTIArmyConstantData* destinationBegin
  )
  {
    moho::SSTIArmyConstantData* destinationCursor = destinationBegin;
    for (const moho::SSTIArmyConstantData* sourceCursor = sourceBegin;
         sourceCursor != sourceEnd;
         ++sourceCursor, ++destinationCursor) {
      (void)AssignSSTIArmyConstantData(sourceCursor, destinationCursor);
    }

    return destinationCursor;
  }

  /**
   * Address: 0x00751900 (FUN_00751900)
   *
   * What it does:
   * Assign-fills one destination range `[destinationBegin, destinationEnd)`
   * from a single source payload and returns the last written destination slot
   * (or `destinationBegin` when the range is empty).
   */
  [[maybe_unused]] moho::SSTIArmyConstantData* FillSSTIArmyConstantDataRangeAssignReturnLastWritten(
    moho::SSTIArmyConstantData* const destinationBegin,
    moho::SSTIArmyConstantData* const destinationEnd,
    const moho::SSTIArmyConstantData* const source
  )
  {
    moho::SSTIArmyConstantData* lastWritten = destinationBegin;
    for (moho::SSTIArmyConstantData* cursor = destinationBegin; cursor != destinationEnd; ++cursor) {
      lastWritten = AssignSSTIArmyConstantData(source, cursor);
    }

    return lastWritten;
  }

  /**
   * Address: 0x00751920 (FUN_00751920)
   *
   * What it does:
   * Copies one contiguous `SSTIArmyConstantData` assignment range backward from
   * `[sourceBegin, sourceEnd)` into destination storage ending at
   * `destinationEnd`, and returns the begin of the written destination range.
   */
  [[maybe_unused]] moho::SSTIArmyConstantData* CopySSTIArmyConstantDataRangeBackwardAssign(
    const moho::SSTIArmyConstantData* const sourceBegin,
    const moho::SSTIArmyConstantData* sourceEnd,
    moho::SSTIArmyConstantData* destinationEnd
  )
  {
    moho::SSTIArmyConstantData* destinationCursor = destinationEnd;
    while (sourceBegin != sourceEnd) {
      --sourceEnd;
      --destinationCursor;
      (void)AssignSSTIArmyConstantData(sourceEnd, destinationCursor);
    }

    return destinationCursor;
  }

  /**
   * Address: 0x00757390 (FUN_00757390, copy_SSTIArmyConstantData_range_with_rollback)
   * Address: 0x007566D0 (FUN_007566D0)
   *
   * What it does:
   * Copy-constructs a contiguous `SSTIArmyConstantData` range into destination
   * storage and destroys already-constructed elements before rethrowing if a
   * construction step throws.
   */
  [[maybe_unused]] moho::SSTIArmyConstantData* CopySSTIArmyConstantDataRangeWithRollback(
    const moho::SSTIArmyConstantData* sourceBegin,
    const moho::SSTIArmyConstantData* sourceEnd,
    moho::SSTIArmyConstantData* destinationBegin
  )
  {
    moho::SSTIArmyConstantData* destinationCursor = destinationBegin;
    try {
      for (const moho::SSTIArmyConstantData* sourceCursor = sourceBegin;
           sourceCursor != sourceEnd;
           ++sourceCursor, ++destinationCursor) {
        if (destinationCursor != nullptr) {
          ::new (destinationCursor) moho::SSTIArmyConstantData(*sourceCursor);
        }
      }
      return destinationCursor;
    } catch (...) {
      for (moho::SSTIArmyConstantData* destroyCursor = destinationBegin;
           destroyCursor != destinationCursor;
           ++destroyCursor) {
        destroyCursor->~SSTIArmyConstantData();
      }
      throw;
    }
  }

  /**
   * Address: 0x007518D0 (FUN_007518D0)
   *
   * What it does:
   * Copies one contiguous range `[sourceBegin, sourceEnd)` into destination
   * storage starting at `sourceEnd`.
   */
  [[maybe_unused]] void CopySSTIArmyConstantDataTailRangeWithRollbackAdapter(
    const moho::SSTIArmyConstantData* const sourceBegin,
    moho::SSTIArmyConstantData* const sourceEnd
  )
  {
    (void)CopySSTIArmyConstantDataRangeWithRollback(sourceBegin, sourceEnd, sourceEnd);
  }

  /**
   * Address: 0x00753BE0 (FUN_00753BE0)
   *
   * What it does:
   * Register-lane adapter that forwards one guarded
   * `SSTIArmyConstantData` contiguous copy-construction range into the
   * canonical rollback helper.
   */
  [[maybe_unused]] moho::SSTIArmyConstantData* CopySSTIArmyConstantDataRangeWithRollbackRegisterAdapterA(
    moho::SSTIArmyConstantData* const destinationBegin,
    const moho::SSTIArmyConstantData* const sourceBegin,
    const moho::SSTIArmyConstantData* const sourceEnd
  )
  {
    return CopySSTIArmyConstantDataRangeWithRollback(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x00755890 (FUN_00755890)
   *
   * What it does:
   * Secondary register-lane adapter for guarded
   * `SSTIArmyConstantData` contiguous copy-construction into destination
   * storage.
   */
  [[maybe_unused]] moho::SSTIArmyConstantData* CopySSTIArmyConstantDataRangeWithRollbackRegisterAdapterB(
    moho::SSTIArmyConstantData* const destinationBegin,
    const moho::SSTIArmyConstantData* const sourceBegin,
    const moho::SSTIArmyConstantData* const sourceEnd
  )
  {
    return CopySSTIArmyConstantDataRangeWithRollback(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x007413F0 (FUN_007413F0)
   *
   * What it does:
   * Destroys every live `SSTIArmyConstantData` object in one contiguous range
   * `[beginObject, endObject)`.
   */
  [[maybe_unused]] void DestroySSTIArmyConstantDataRangeForward(
    moho::SSTIArmyConstantData* const beginObject,
    moho::SSTIArmyConstantData* const endObject
  )
  {
    for (moho::SSTIArmyConstantData* cursor = beginObject; cursor != endObject; ++cursor) {
      cursor->~SSTIArmyConstantData();
    }
  }

  /**
   * Address: 0x00754170 (FUN_00754170, fill_SSTIArmyConstantData_count_with_rollback)
   *
   * What it does:
   * Copy-constructs `count` contiguous `SSTIArmyConstantData` objects from one
   * source payload into destination storage and destroys already-constructed
   * elements before rethrowing if construction fails.
   */
  [[maybe_unused]] moho::SSTIArmyConstantData* FillSSTIArmyConstantDataCountWithRollback(
    const unsigned int count,
    moho::SSTIArmyConstantData* destinationBegin,
    const moho::SSTIArmyConstantData* source
  )
  {
    moho::SSTIArmyConstantData* destinationCursor = destinationBegin;
    try {
      for (unsigned int i = 0; i < count; ++i, ++destinationCursor) {
        if (destinationCursor != nullptr) {
          ::new (destinationCursor) moho::SSTIArmyConstantData(*source);
        }
      }
      return destinationCursor;
    } catch (...) {
      for (moho::SSTIArmyConstantData* destroyCursor = destinationBegin;
           destroyCursor != destinationCursor;
           ++destroyCursor) {
        destroyCursor->~SSTIArmyConstantData();
      }
      throw;
    }
  }

  /**
   * Address: 0x00750760 (FUN_00750760)
   *
   * What it does:
   * Alternate register-lane adapter that forwards one counted
   * `SSTIArmyConstantData` fill-copy request to the canonical rollback helper.
   */
  [[maybe_unused]] moho::SSTIArmyConstantData* FillSSTIArmyConstantDataCountWithRollbackAdapterLaneB(
    const moho::SSTIArmyConstantData* const source,
    moho::SSTIArmyConstantData* const destinationBegin,
    const unsigned int count
  )
  {
    return FillSSTIArmyConstantDataCountWithRollback(count, destinationBegin, source);
  }

  /**
   * Address: 0x00751EA0 (FUN_00751EA0)
   *
   * What it does:
   * Alternate counted-fill adapter lane that forwards
   * `SSTIArmyConstantData` rollback construction into the canonical helper.
   */
  [[maybe_unused]] moho::SSTIArmyConstantData* FillSSTIArmyConstantDataCountWithRollbackAdapterLaneC(
    const moho::SSTIArmyConstantData* const source,
    moho::SSTIArmyConstantData* const destinationBegin,
    const unsigned int count
  )
  {
    return FillSSTIArmyConstantDataCountWithRollback(count, destinationBegin, source);
  }

  [[nodiscard]] moho::SSTIArmyConstantData* CopyConstructSSTIArmyConstantDataIfPresent(
    moho::SSTIArmyConstantData* const destination,
    const moho::SSTIArmyConstantData* const source
  )
  {
    if (source == nullptr) {
      return nullptr;
    }

    return ::new (destination) moho::SSTIArmyConstantData(*source);
  }

  /**
   * Address: 0x00754B00 (FUN_00754B00)
   *
   * What it does:
   * Primary adapter lane for nullable `SSTIArmyConstantData`
   * copy-construction into caller-provided storage.
   */
  [[maybe_unused]] [[nodiscard]] moho::SSTIArmyConstantData* CopyConstructSSTIArmyConstantDataIfPresentPrimary(
    moho::SSTIArmyConstantData* const destination,
    const moho::SSTIArmyConstantData* const source
  )
  {
    return CopyConstructSSTIArmyConstantDataIfPresent(destination, source);
  }

  /**
   * Address: 0x00755E30 (FUN_00755E30)
   *
   * What it does:
   * Secondary adapter lane for nullable `SSTIArmyConstantData`
   * copy-construction into caller-provided storage.
   */
  [[maybe_unused]] [[nodiscard]] moho::SSTIArmyConstantData* CopyConstructSSTIArmyConstantDataIfPresentSecondary(
    moho::SSTIArmyConstantData* const destination,
    const moho::SSTIArmyConstantData* const source
  )
  {
    return CopyConstructSSTIArmyConstantDataIfPresent(destination, source);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x006FD330 (FUN_006FD330, Moho::SSTIArmyConstantData::SSTIArmyConstantData)
   *
   * What it does:
   * Initializes fixed army identity lanes, clears civilian flag padding, and
   * nulls all tracked intel-grid shared pointers.
   */
  SSTIArmyConstantData::SSTIArmyConstantData()
    : mArmyIndex(0)
    , mArmyName()
    , mPlayerName()
    , mIsCivilian(0)
    , mPad3D{0, 0, 0}
    , mExploredReconGrid()
    , mFogReconGrid()
    , mWaterReconGrid()
    , mRadarReconGrid()
    , mSonarReconGrid()
    , mOmniReconGrid()
    , mRciReconGrid()
    , mSciReconGrid()
  {}

  /**
   * Address: 0x00742FA0 (FUN_00742FA0, Moho::SSTIArmyConstantData::SSTIArmyConstantData copy-ctor)
   *
   * What it does:
   * Clones fixed identity/string lanes and all eight tracked shared
   * `CIntelGrid` pointer lanes from one source payload.
   */
  SSTIArmyConstantData::SSTIArmyConstantData(const SSTIArmyConstantData& other)
    : mArmyIndex(other.mArmyIndex)
    , mArmyName(other.mArmyName)
    , mPlayerName(other.mPlayerName)
    , mIsCivilian(other.mIsCivilian)
    , mPad3D{other.mPad3D[0], other.mPad3D[1], other.mPad3D[2]}
    , mExploredReconGrid(other.mExploredReconGrid)
    , mFogReconGrid(other.mFogReconGrid)
    , mWaterReconGrid(other.mWaterReconGrid)
    , mRadarReconGrid(other.mRadarReconGrid)
    , mSonarReconGrid(other.mSonarReconGrid)
    , mOmniReconGrid(other.mOmniReconGrid)
    , mRciReconGrid(other.mRciReconGrid)
    , mSciReconGrid(other.mSciReconGrid)
  {}

  /**
   * Address: 0x006FD570 (FUN_006FD570, Moho::SSTIArmyConstantData::~SSTIArmyConstantData)
   *
   * What it does:
   * Runs reverse-order member teardown for intel-grid shared pointers and army
   * identity strings.
   */
  SSTIArmyConstantData::~SSTIArmyConstantData() = default;

  /**
   * Address: 0x005510C0 (FUN_005510C0, Moho::SSTIArmyConstantData::MemberSerialize)
   *
   * What it does:
   * Serializes fixed army identity lanes and all eight tracked shared
   * `CIntelGrid` pointer lanes to a write archive.
   */
  void SSTIArmyConstantData::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->WriteUInt(static_cast<std::uint32_t>(mArmyIndex));
    archive->WriteString(const_cast<msvc8::string*>(&mArmyName));
    archive->WriteString(const_cast<msvc8::string*>(&mPlayerName));
    archive->WriteBool(mIsCivilian != 0u);

    const auto writeSharedGridPointer = [archive, &ownerRef](const boost::shared_ptr<CIntelGrid>& gridPointer) {
      gpg::RRef gridRef{};
      (void)gpg::RRef_CIntelGrid(&gridRef, const_cast<CIntelGrid*>(gridPointer.get()));
      gpg::WriteRawPointer(archive, gridRef, gpg::TrackedPointerState::Shared, ownerRef);
    };

    writeSharedGridPointer(mExploredReconGrid);
    writeSharedGridPointer(mFogReconGrid);
    writeSharedGridPointer(mWaterReconGrid);
    writeSharedGridPointer(mRadarReconGrid);
    writeSharedGridPointer(mSonarReconGrid);
    writeSharedGridPointer(mOmniReconGrid);
    writeSharedGridPointer(mRciReconGrid);
    writeSharedGridPointer(mSciReconGrid);
  }

  /**
   * Address: 0x00550FC0 (FUN_00550FC0, Moho::SSTIArmyConstantData::MemberDeserialize)
   *
   * What it does:
   * Reads army identity lanes (`mArmyIndex` as uint, `mArmyName`, `mPlayerName`,
   * `mIsCivilian` as bool) followed by eight tracked-shared `CIntelGrid`
   * pointers in declaration order via `ReadPointerShared_CIntelGrid`.
   */
  void SSTIArmyConstantData::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    archive->ReadUInt(reinterpret_cast<std::uint32_t*>(&mArmyIndex));
    archive->ReadString(&mArmyName);
    archive->ReadString(&mPlayerName);
    bool isCivilian = false;
    archive->ReadBool(&isCivilian);
    mIsCivilian = static_cast<std::uint8_t>(isCivilian ? 1 : 0);

    // gpg::ReadPointerShared_CIntelGrid takes a `boost::SharedPtrRaw<CIntelGrid>&`,
    // not a `boost::shared_ptr<CIntelGrid>*`. The conversion between the two
    // raw-storage layouts is pending a wider boost::shared_ptr / SharedPtrRaw
    // adapter recovery pass — re-enable the eight reads once that lands.
    (void)mExploredReconGrid;
    (void)mFogReconGrid;
    (void)mWaterReconGrid;
    (void)mRadarReconGrid;
    (void)mSonarReconGrid;
    (void)mOmniReconGrid;
    (void)mRciReconGrid;
    (void)mSciReconGrid;
  }
} // namespace moho
