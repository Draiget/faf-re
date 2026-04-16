#include "moho/command/SSTICommandVariableData.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/command/SSTICommandIssueData.h"

namespace
{
  class SSTICommandVariableDataTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "SSTICommandVariableData";
    }

    void Init() override
    {
      size_ = sizeof(moho::SSTICommandVariableData);
      gpg::RType::Init();
      Finish();
    }
  };

  moho::SSTICommandVariableDataSerializer gSSTICommandVariableDataSerializer{};

  gpg::RType* gEntIdVectorType = nullptr;
  gpg::RType* gUnitCommandType = nullptr;
  gpg::RType* gTargetType = nullptr;
  gpg::RType* gCellVectorType = nullptr;

  struct SSTICommandVariableDataSlotRuntime
  {
    std::uint32_t mHeaderWord0 = 0;                  // +0x00
    std::uint32_t mHeaderWord1 = 0;                  // +0x04
    moho::SSTICommandVariableData mVariableData{};   // +0x08
  };

  static_assert(
    offsetof(SSTICommandVariableDataSlotRuntime, mVariableData) == 0x08,
    "SSTICommandVariableDataSlotRuntime::mVariableData offset must be 0x08"
  );
  static_assert(
    sizeof(SSTICommandVariableDataSlotRuntime) >= (sizeof(moho::SSTICommandVariableData) + 0x08),
    "SSTICommandVariableDataSlotRuntime must include 8-byte slot header plus variable payload"
  );

  struct RebindableInlineBufferLaneRuntime
  {
    std::uint32_t ownedStorage;  // +0x00
    std::uint32_t beginStorage;  // +0x04
    std::uint32_t endStorage;    // +0x08
    std::uint32_t inlineStorage; // +0x0C
  };

  static_assert(
    sizeof(RebindableInlineBufferLaneRuntime) == 0x10, "RebindableInlineBufferLaneRuntime size must be 0x10"
  );

  struct SSTICommandVariableDataRelocationSlotRuntime
  {
    std::uint32_t mHeaderWord0;                       // +0x00
    std::uint32_t mHeaderWord1;                       // +0x04
    RebindableInlineBufferLaneRuntime mEntIdsLane;    // +0x08
    std::byte mMidLane[0x38];                         // +0x18
    RebindableInlineBufferLaneRuntime mCellsLane;     // +0x50
    std::byte mTailLane[0x18];                        // +0x60
  };

  static_assert(
    offsetof(SSTICommandVariableDataRelocationSlotRuntime, mEntIdsLane) == 0x08,
    "SSTICommandVariableDataRelocationSlotRuntime::mEntIdsLane offset must be 0x08"
  );
  static_assert(
    offsetof(SSTICommandVariableDataRelocationSlotRuntime, mCellsLane) == 0x50,
    "SSTICommandVariableDataRelocationSlotRuntime::mCellsLane offset must be 0x50"
  );
  static_assert(
    sizeof(SSTICommandVariableDataRelocationSlotRuntime) == 0x78,
    "SSTICommandVariableDataRelocationSlotRuntime size must be 0x78"
  );

  void ResetRebindableInlineBufferLane(RebindableInlineBufferLaneRuntime& lane)
  {
    if (lane.ownedStorage != lane.inlineStorage) {
      ::operator delete[](reinterpret_cast<void*>(static_cast<std::uintptr_t>(lane.ownedStorage)));
      lane.ownedStorage = lane.inlineStorage;
      lane.endStorage = *reinterpret_cast<std::uint32_t*>(static_cast<std::uintptr_t>(lane.ownedStorage));
    }

    lane.beginStorage = lane.ownedStorage;
  }

  /**
   * Address: 0x00562C70 (FUN_00562C70, sub_562C70)
   *
   * What it does:
   * Rebinds every `SSTICommandVariableData` relocation slot in `[first,last)`
   * back to inline ent-id/cell storage lanes, releasing spilled heap blocks
   * for both lanes in each 0x78-byte slot.
   */
  [[maybe_unused]] std::uint32_t RebindSSTICommandVariableDataSlotsToInlineStorage(
    SSTICommandVariableDataRelocationSlotRuntime* first,
    SSTICommandVariableDataRelocationSlotRuntime* const last
  )
  {
    std::uint32_t resultLane = 0u;
    while (first != last) {
      ResetRebindableInlineBufferLane(first->mCellsLane);
      ResetRebindableInlineBufferLane(first->mEntIdsLane);
      resultLane = first->mEntIdsLane.ownedStorage;
      ++first;
    }
    return resultLane;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    if (helper.mHelperNext != nullptr && helper.mHelperPrev != nullptr) {
      helper.mHelperNext->mPrev = helper.mHelperPrev;
      helper.mHelperPrev->mNext = helper.mHelperNext;
    }

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
    return self;
  }

  [[nodiscard]] gpg::SerHelperBase* ResetSSTICommandVariableDataSerializerHelperLinks() noexcept
  {
    gSSTICommandVariableDataSerializer.mHelperNext->mPrev = gSSTICommandVariableDataSerializer.mHelperPrev;
    gSSTICommandVariableDataSerializer.mHelperPrev->mNext = gSSTICommandVariableDataSerializer.mHelperNext;
    gpg::SerHelperBase* const self = HelperSelfNode(gSSTICommandVariableDataSerializer);
    gSSTICommandVariableDataSerializer.mHelperNext = self;
    gSSTICommandVariableDataSerializer.mHelperPrev = self;
    return self;
  }

  /**
   * Address: 0x00552B80 (FUN_00552B80)
   *
   * What it does:
   * Unlinks `SSTICommandVariableDataSerializer` helper node from the intrusive
   * helper list and restores self-linked sentinel links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupSSTICommandVariableDataSerializerHelperNodePrimary() noexcept
  {
    return ResetSSTICommandVariableDataSerializerHelperLinks();
  }

  /**
   * Address: 0x00552BB0 (FUN_00552BB0)
   *
   * What it does:
   * Secondary entrypoint for `SSTICommandVariableDataSerializer` helper-node
   * unlink/reset.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupSSTICommandVariableDataSerializerHelperNodeSecondary() noexcept
  {
    return ResetSSTICommandVariableDataSerializerHelperLinks();
  }

  [[nodiscard]] gpg::RType* ResolveEntIdVectorType()
  {
    if (gEntIdVectorType == nullptr) {
      gEntIdVectorType = gpg::LookupRType(typeid(msvc8::vector<moho::EntId>));
    }
    return gEntIdVectorType;
  }

  [[nodiscard]] gpg::RType* ResolveEUnitCommandType()
  {
    if (gUnitCommandType == nullptr) {
      gUnitCommandType = gpg::LookupRType(typeid(moho::EUnitCommandType));
    }
    return gUnitCommandType;
  }

  [[nodiscard]] gpg::RType* ResolveSSTITargetType()
  {
    if (gTargetType == nullptr) {
      gTargetType = gpg::LookupRType(typeid(moho::SSTITarget));
    }
    return gTargetType;
  }

  [[nodiscard]] gpg::RType* ResolveSOCellPosVectorType()
  {
    if (gCellVectorType == nullptr) {
      gCellVectorType = gpg::LookupRType(typeid(msvc8::vector<moho::SOCellPos>));
    }
    return gCellVectorType;
  }

  void cleanup_SSTICommandVariableDataSerializer_Atexit()
  {
    (void)CleanupSSTICommandVariableDataSerializerHelperNodePrimary();
  }

  /**
   * Address: 0x006EC8E0 (FUN_006EC8E0)
   * Address: 0x006EBBD0 (FUN_006EBBD0)
   *
   * What it does:
   * Fills one uninitialized slot range with repeated copy-constructed
   * `SSTICommandVariableData` payload lanes taken from `fillValue`.
   */
  [[maybe_unused]] SSTICommandVariableDataSlotRuntime* FillUninitializedSSTICommandVariableDataSlots(
    SSTICommandVariableDataSlotRuntime* destinationBegin,
    SSTICommandVariableDataSlotRuntime* destinationEnd,
    const SSTICommandVariableDataSlotRuntime& fillValue
  )
  {
    for (SSTICommandVariableDataSlotRuntime* cursor = destinationBegin; cursor != destinationEnd; ++cursor) {
      cursor->mHeaderWord0 = fillValue.mHeaderWord0;
      ::new (&cursor->mVariableData) moho::SSTICommandVariableData(fillValue.mVariableData);
    }
    return destinationEnd;
  }

  /**
   * Address: 0x006ED220 (FUN_006ED220)
   * Address: 0x006EC920 (FUN_006EC920)
   *
   * What it does:
   * Backward-copy constructs one slot range into uninitialized destination
   * storage and returns the new destination begin iterator.
   */
  [[maybe_unused]] SSTICommandVariableDataSlotRuntime* CopyBackwardSSTICommandVariableDataSlots(
    SSTICommandVariableDataSlotRuntime* sourceCurrent,
    const SSTICommandVariableDataSlotRuntime* const sourceBegin,
    SSTICommandVariableDataSlotRuntime* destinationCurrent
  )
  {
    while (sourceCurrent != sourceBegin) {
      --sourceCurrent;
      --destinationCurrent;
      destinationCurrent->mHeaderWord0 = sourceCurrent->mHeaderWord0;
      ::new (&destinationCurrent->mVariableData) moho::SSTICommandVariableData(sourceCurrent->mVariableData);
    }

    return destinationCurrent;
  }

  /**
   * Address: 0x006EBBE0 (FUN_006EBBE0)
   *
   * What it does:
   * Adapts one legacy call-convention lane into the canonical backward slot
   * copy helper for `SSTICommandVariableData`.
   */
  [[maybe_unused]] SSTICommandVariableDataSlotRuntime* CopyBackwardSSTICommandVariableDataSlotsAdapter(
    SSTICommandVariableDataSlotRuntime* sourceCurrent,
    const SSTICommandVariableDataSlotRuntime* const sourceBegin,
    SSTICommandVariableDataSlotRuntime* destinationCurrent
  ) noexcept
  {
    return CopyBackwardSSTICommandVariableDataSlots(sourceCurrent, sourceBegin, destinationCurrent);
  }

  [[nodiscard]] SSTICommandVariableDataSlotRuntime* CopySSTICommandVariableDataSlotRangeWithRollback(
    const SSTICommandVariableDataSlotRuntime* sourceBegin,
    const SSTICommandVariableDataSlotRuntime* sourceEnd,
    SSTICommandVariableDataSlotRuntime* destinationBegin
  )
  {
    SSTICommandVariableDataSlotRuntime* destinationCursor = destinationBegin;
    try {
      for (const SSTICommandVariableDataSlotRuntime* sourceCursor = sourceBegin;
           sourceCursor != sourceEnd;
           ++sourceCursor, ++destinationCursor) {
        if (destinationCursor != nullptr) {
          destinationCursor->mHeaderWord0 = sourceCursor->mHeaderWord0;
          ::new (&destinationCursor->mVariableData) moho::SSTICommandVariableData(sourceCursor->mVariableData);
        }
      }
      return destinationCursor;
    } catch (...) {
      for (SSTICommandVariableDataSlotRuntime* destroyCursor = destinationBegin;
           destroyCursor != destinationCursor;
           ++destroyCursor) {
        destroyCursor->mVariableData.~SSTICommandVariableData();
      }
      throw;
    }
  }

  /**
   * Address: 0x005634F0 (FUN_005634F0, copy_SSTICommandVariableData_slot_range_with_rollback)
   *
   * What it does:
   * Copy-constructs one contiguous slot range (`header + SSTICommandVariableData`)
   * into destination storage and destroys already-constructed payload lanes
   * before rethrowing if a construction step throws.
   */
  [[maybe_unused]] SSTICommandVariableDataSlotRuntime* CopySSTICommandVariableDataSlotRangeWithRollbackLegacy(
    const SSTICommandVariableDataSlotRuntime* sourceBegin,
    const SSTICommandVariableDataSlotRuntime* sourceEnd,
    SSTICommandVariableDataSlotRuntime* destinationBegin
  )
  {
    return CopySSTICommandVariableDataSlotRangeWithRollback(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x005626B0 (FUN_005626B0)
   *
   * What it does:
   * Legacy register-shape adapter lane that forwards contiguous
   * `SSTICommandVariableData` slot-range copy into the canonical rollback
   * helper.
   */
  [[maybe_unused]] void CopySSTICommandVariableDataSlotRangeWithRollbackAdapterLaneLegacyEntry(
    [[maybe_unused]] const void* const unusedContext,
    SSTICommandVariableDataSlotRuntime* const destinationBegin,
    const SSTICommandVariableDataSlotRuntime* const sourceBegin,
    const SSTICommandVariableDataSlotRuntime* const sourceEnd
  )
  {
    (void)CopySSTICommandVariableDataSlotRangeWithRollbackLegacy(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x00562BA0 (FUN_00562BA0)
   *
   * What it does:
   * Primary adapter lane that forwards contiguous
   * `SSTICommandVariableData` slot-range copy into the canonical rollback
   * helper.
   */
  [[maybe_unused]] void CopySSTICommandVariableDataSlotRangeWithRollbackAdapterLaneA(
    SSTICommandVariableDataSlotRuntime* const destinationBegin,
    const SSTICommandVariableDataSlotRuntime* const sourceBegin,
    const SSTICommandVariableDataSlotRuntime* const sourceEnd
  )
  {
    (void)CopySSTICommandVariableDataSlotRangeWithRollbackLegacy(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x005630B0 (FUN_005630B0)
   *
   * What it does:
   * Secondary adapter lane that forwards contiguous
   * `SSTICommandVariableData` slot-range copy into the canonical rollback
   * helper.
   */
  [[maybe_unused]] void CopySSTICommandVariableDataSlotRangeWithRollbackAdapterLaneB(
    SSTICommandVariableDataSlotRuntime* const destinationBegin,
    const SSTICommandVariableDataSlotRuntime* const sourceBegin,
    const SSTICommandVariableDataSlotRuntime* const sourceEnd
  )
  {
    (void)CopySSTICommandVariableDataSlotRangeWithRollbackLegacy(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x00563280 (FUN_00563280)
   *
   * What it does:
   * Tertiary adapter lane that forwards contiguous
   * `SSTICommandVariableData` slot-range copy into the canonical rollback
   * helper.
   */
  [[maybe_unused]] void CopySSTICommandVariableDataSlotRangeWithRollbackAdapterLaneC(
    SSTICommandVariableDataSlotRuntime* const destinationBegin,
    const SSTICommandVariableDataSlotRuntime* const sourceBegin,
    const SSTICommandVariableDataSlotRuntime* const sourceEnd
  )
  {
    (void)CopySSTICommandVariableDataSlotRangeWithRollbackLegacy(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x006ED830 (FUN_006ED830, copy_SSTICommandVariableData_slot_range_with_rollback_alt)
   * Address: 0x006EBBA0 (FUN_006EBBA0)
   * Address: 0x006EC8B0 (FUN_006EC8B0)
   * Address: 0x006ED1F0 (FUN_006ED1F0)
   * Address: 0x006ED560 (FUN_006ED560)
   *
   * What it does:
   * Alternate call-convention lane for the same guarded slot-range copy helper.
   */
  [[maybe_unused]] SSTICommandVariableDataSlotRuntime* CopySSTICommandVariableDataSlotRangeWithRollbackLegacyAlt(
    const SSTICommandVariableDataSlotRuntime* sourceBegin,
    const SSTICommandVariableDataSlotRuntime* sourceEnd,
    SSTICommandVariableDataSlotRuntime* destinationBegin
  )
  {
    return CopySSTICommandVariableDataSlotRangeWithRollback(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x006EC460 (FUN_006EC460, copy_SSTICommandVariableData_slot_range_with_rollback_counted)
   * Address: 0x006EB7D0 (FUN_006EB7D0)
   *
   * What it does:
   * Copy-constructs one counted slot range (`header + SSTICommandVariableData`)
   * into destination storage and destroys already-constructed payload lanes
   * before rethrowing if a copy step throws.
   */
  [[maybe_unused]] SSTICommandVariableDataSlotRuntime* CopySSTICommandVariableDataSlotRangeWithRollbackCounted(
    const std::uint32_t count,
    SSTICommandVariableDataSlotRuntime* const destinationBegin,
    const SSTICommandVariableDataSlotRuntime* const sourceBegin
  )
  {
    if (count == 0u) {
      return destinationBegin;
    }

    if (destinationBegin == nullptr || sourceBegin == nullptr) {
      return destinationBegin;
    }

    SSTICommandVariableDataSlotRuntime* destinationCursor = destinationBegin;
    try {
      for (std::uint32_t i = 0; i < count; ++i, ++destinationCursor) {
        const SSTICommandVariableDataSlotRuntime* const sourceCursor = sourceBegin + i;
        destinationCursor->mHeaderWord0 = sourceCursor->mHeaderWord0;
        ::new (&destinationCursor->mVariableData) moho::SSTICommandVariableData(sourceCursor->mVariableData);
      }
      return destinationCursor;
    } catch (...) {
      for (SSTICommandVariableDataSlotRuntime* destroyCursor = destinationBegin;
           destroyCursor != destinationCursor;
           ++destroyCursor) {
        destroyCursor->mVariableData.~SSTICommandVariableData();
      }
      throw;
    }
  }

  /**
   * Address: 0x006EA2D0 (FUN_006EA2D0)
   *
   * What it does:
   * Adapts one counted slot-copy lane into
   * `CopySSTICommandVariableDataSlotRangeWithRollbackCounted` and returns the
   * destination end pointer.
   */
  [[maybe_unused]] SSTICommandVariableDataSlotRuntime* CopySSTICommandVariableDataSlotRangeCountedAdapter(
    const SSTICommandVariableDataSlotRuntime* const sourceBegin,
    SSTICommandVariableDataSlotRuntime* const destinationBegin,
    const std::uint32_t count
  )
  {
    return CopySSTICommandVariableDataSlotRangeWithRollbackCounted(count, destinationBegin, sourceBegin);
  }

  /**
   * Address: 0x006ECA60 (FUN_006ECA60)
   *
   * What it does:
   * Copies one slot header lane and copy-constructs one embedded
   * `SSTICommandVariableData` payload into destination storage.
   */
  [[maybe_unused]] SSTICommandVariableDataSlotRuntime* CopySSTICommandVariableDataSlotLane(
    SSTICommandVariableDataSlotRuntime* const destination,
    const SSTICommandVariableDataSlotRuntime* const source
  )
  {
    if (destination == nullptr || source == nullptr) {
      return destination;
    }

    destination->mHeaderWord0 = source->mHeaderWord0;
    ::new (&destination->mVariableData) moho::SSTICommandVariableData(source->mVariableData);
    return destination;
  }

  void register_SSTICommandVariableDataSerializer()
  {
    InitializeHelperNode(gSSTICommandVariableDataSerializer);
    gSSTICommandVariableDataSerializer.mSerLoadFunc = &moho::SSTICommandVariableDataSerializer::Serialize;
    gSSTICommandVariableDataSerializer.mSerSaveFunc = &moho::SSTICommandVariableDataSerializer::Deserialize;
    (void)std::atexit(&cleanup_SSTICommandVariableDataSerializer_Atexit);
  }
} // namespace

namespace moho
{
  gpg::RType* SSTICommandVariableData::sType = nullptr;

  /**
   * Address: 0x005528C0 (FUN_005528C0, preregister_SSTICommandVariableDataTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SSTICommandVariableData`.
   */
  gpg::RType* preregister_SSTICommandVariableDataTypeInfo()
  {
    static SSTICommandVariableDataTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(SSTICommandVariableData), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x00552A00 (FUN_00552A00, Moho::SSTICommandVariableData::SSTICommandVariableData)
   *
   * What it does:
   * Initializes variable-command payload lanes to an empty/default state
   * (`UNITCOMMAND_None`, no targets, empty vectors, and unset count limits).
   */
  SSTICommandVariableData::SSTICommandVariableData()
    : mEntIds{}
    , v1(0)
    , v2(0)
    , mCmdType(EUnitCommandType::UNITCOMMAND_None)
    , mTarget1{}
    , mTarget2{}
    , v14(0)
    , mCells{}
    , v19(0)
    , v20(0)
    , mMaxCount(-1)
    , mCount(-1)
    , v23(0)
  {
    mTarget1.mType = EAiTargetType::AITARGET_None;
    mTarget1.mEnt = static_cast<EntId>(0xF0000000u);
    mTarget1.mPos = Wm3::Vec3f::Zero();

    mTarget2.mType = EAiTargetType::AITARGET_None;
    mTarget2.mEnt = static_cast<EntId>(0xF0000000u);
    mTarget2.mPos = Wm3::Vec3f::Zero();
  }

  /**
   * Address: 0x006ECAD0 (FUN_006ECAD0, Moho::SSTICommandVariableData::SSTICommandVariableData)
   *
   * What it does:
   * Copy-constructs the full command-variable payload including target lanes
   * and variable cell vector storage.
   */
  SSTICommandVariableData::SSTICommandVariableData(const SSTICommandVariableData& other)
    : mEntIds(other.mEntIds)
    , v1(other.v1)
    , v2(other.v2)
    , mCmdType(other.mCmdType)
    , mTarget1(other.mTarget1)
    , mTarget2(other.mTarget2)
    , v14(other.v14)
    , mCells(other.mCells)
    , v19(other.v19)
    , v20(other.v20)
    , mMaxCount(other.mMaxCount)
    , mCount(other.mCount)
    , v23(other.v23)
  {
  }

  /**
   * Address: 0x00552A70 (FUN_00552A70, Moho::SSTICommandVariableData::SSTICommandVariableData)
   *
   * What it does:
   * Initializes variable command payload lanes from one issue payload lane.
   */
  SSTICommandVariableData::SSTICommandVariableData(const SSTICommandIssueData& issueData)
    : mEntIds{}
    , v1(0)
    , v2(0)
    , mCmdType(issueData.mCommandType)
    , mTarget1(issueData.mTarget)
    , mTarget2(issueData.mTarget2)
    , v14(issueData.unk38)
    , mCells{}
    , v19(0)
    , v20(0)
    , mMaxCount(issueData.unk70)
    , mCount(issueData.unk74)
    , v23(0)
  {
    mCells.clear();
    mCells.reserve(issueData.mCells.Size());
    for (std::size_t i = 0; i < issueData.mCells.Size(); ++i) {
      mCells.push_back(issueData.mCells[i]);
    }
  }

  /**
   * Address: 0x005603E0 (FUN_005603E0, Moho::SSTICommandVariableData::~SSTICommandVariableData)
   *
   * What it does:
   * Releases command payload vectors (`mCells`, `mEntIds`) and restores their
   * inline-storage lanes.
   */
  SSTICommandVariableData::~SSTICommandVariableData() = default;

  /**
   * Address: 0x00554760 (FUN_00554760, Moho::SSTICommandVariableData::MemberDeserialize)
   */
  void SSTICommandVariableData::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    const gpg::RRef ownerRef{};

    gpg::RType* const entIdVectorType = ResolveEntIdVectorType();
    GPG_ASSERT(entIdVectorType != nullptr);
    archive->Read(entIdVectorType, &mEntIds, ownerRef);

    gpg::RType* const unitCommandType = ResolveEUnitCommandType();
    GPG_ASSERT(unitCommandType != nullptr);
    archive->Read(unitCommandType, &mCmdType, ownerRef);

    gpg::RType* const targetType = ResolveSSTITargetType();
    GPG_ASSERT(targetType != nullptr);
    archive->Read(targetType, &mTarget1, ownerRef);
    archive->Read(targetType, &mTarget2, ownerRef);

    gpg::RType* const cellVectorType = ResolveSOCellPosVectorType();
    GPG_ASSERT(cellVectorType != nullptr);
    archive->Read(cellVectorType, &mCells, ownerRef);

    archive->ReadInt(&mMaxCount);
    archive->ReadInt(&mCount);
    archive->ReadUInt(&v23);
  }

  /**
   * Address: 0x005548A0 (FUN_005548A0, Moho::SSTICommandVariableData::MemberSerialize)
   */
  void SSTICommandVariableData::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (!archive) {
      return;
    }

    const gpg::RRef ownerRef{};

    gpg::RType* const entIdVectorType = ResolveEntIdVectorType();
    GPG_ASSERT(entIdVectorType != nullptr);
    archive->Write(entIdVectorType, &mEntIds, ownerRef);

    gpg::RType* const unitCommandType = ResolveEUnitCommandType();
    GPG_ASSERT(unitCommandType != nullptr);
    archive->Write(unitCommandType, &mCmdType, ownerRef);

    gpg::RType* const targetType = ResolveSSTITargetType();
    GPG_ASSERT(targetType != nullptr);
    archive->Write(targetType, &mTarget1, ownerRef);
    archive->Write(targetType, &mTarget2, ownerRef);

    gpg::RType* const cellVectorType = ResolveSOCellPosVectorType();
    GPG_ASSERT(cellVectorType != nullptr);
    archive->Write(cellVectorType, &mCells, ownerRef);

    archive->WriteInt(mMaxCount);
    archive->WriteInt(mCount);
    archive->WriteUInt(v23);
  }

  /**
   * Address: 0x00552B20 (FUN_00552B20, Moho::SSTICommandVariableDataSerializer::Serialize)
   */
  void SSTICommandVariableDataSerializer::Serialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const data = reinterpret_cast<SSTICommandVariableData*>(objectPtr);
    if (!archive || !data) {
      return;
    }

    data->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00552B30 (FUN_00552B30, Moho::SSTICommandVariableDataSerializer::Deserialize)
   */
  void SSTICommandVariableDataSerializer::Deserialize(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*
  )
  {
    const auto* const data = reinterpret_cast<const SSTICommandVariableData*>(objectPtr);
    if (!archive || !data) {
      return;
    }

    data->MemberSerialize(archive);
  }

  /**
   * Address: 0x00553260 (FUN_00553260, gpg::SerSaveLoadHelper_SSTICommandVariableData::Init)
   */
  void SSTICommandVariableDataSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* type = SSTICommandVariableData::sType;
    if (type == nullptr) {
      type = preregister_SSTICommandVariableDataTypeInfo();
      SSTICommandVariableData::sType = type;
    }

    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mSerLoadFunc;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerSaveFunc;
  }
} // namespace moho

namespace
{
  struct SSTICommandVariableDataSerializerBootstrap
  {
    SSTICommandVariableDataSerializerBootstrap()
    {
      (void)moho::preregister_SSTICommandVariableDataTypeInfo();
      register_SSTICommandVariableDataSerializer();
    }
  };

  [[maybe_unused]] SSTICommandVariableDataSerializerBootstrap gSSTICommandVariableDataSerializerBootstrap;
} // namespace
