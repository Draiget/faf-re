#include "CAniSkel.h"

#include <cstring>
#include <new>

#include <boost/detail/sp_counted_impl.hpp>

#include "CAniDefaultSkel.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/containers/Map.h"
#include "legacy/containers/Set.h"
#include "moho/animation/CAniPose.h"
#include "moho/console/CConCommand.h"
#include "moho/entity/UserEntity.h"
#include "moho/math/QuaternionMath.h"
#include "moho/resource/SScmFile.h"
#include "moho/sim/CWldSession.h"
#include "Wm3Vector3.h"

// Forward-declared (no shared header) rather than `#include`d: the recovered
// MSVC8 std::_Sort introsort family lives in SimRecoveryRuntime.cpp, which
// has no header of its own -- this matches that file's own ad-hoc extern
// convention (see e.g. its `wxGetOsVersion` forward declaration). Only the
// entry point (FUN_0054E4B0) is declared here; its partition helper
// (FUN_0054EE30) is called internally and stays local to that file.
struct StringRankLaneRuntime;
void SortStringRankLaneRuntimeRange(StringRankLaneRuntime* first, StringRankLaneRuntime* last, std::ptrdiff_t ideal);

namespace
{
  struct HeapBackedRangeHandleRuntimeView
  {
    std::uint32_t reserved00; // +0x00
    void* heapStorage;        // +0x04
    void* rangeEnd;           // +0x08
    void* rangeCapacityEnd;   // +0x0C
  };

  static_assert(
    offsetof(HeapBackedRangeHandleRuntimeView, heapStorage) == 0x04,
    "HeapBackedRangeHandleRuntimeView::heapStorage offset must be 0x04"
  );
  static_assert(
    offsetof(HeapBackedRangeHandleRuntimeView, rangeEnd) == 0x08,
    "HeapBackedRangeHandleRuntimeView::rangeEnd offset must be 0x08"
  );
  static_assert(
    offsetof(HeapBackedRangeHandleRuntimeView, rangeCapacityEnd) == 0x0C,
    "HeapBackedRangeHandleRuntimeView::rangeCapacityEnd offset must be 0x0C"
  );
  static_assert(sizeof(HeapBackedRangeHandleRuntimeView) == 0x10, "HeapBackedRangeHandleRuntimeView size must be 0x10");

  /**
   * On-disk skeleton-bone record inside the SScmFile bone chunk.
   *
   * The chunk begins at `SScmFile::mBoneTableOffset`; the SCM bone-name string
   * block that precedes each record's names starts at file offset 0x40 (see
   * `FillSScmBoneNamePointers`). Each record is 0x6C bytes and stores the local
   * rest transform as a row-major 3x4 basis (the 4th column of each of the
   * three rows is unused padding), followed by rest-position, hierarchy links,
   * and local offset/scale lanes.
   *
   * Field offsets are byte-verified against the CAniSkel ctor (FUN_0054A0A0).
   */
  struct SScmBoneRecord
  {
    float mBasisRow0[4];        // +0x00 (row 0: x,y,z used, w padding)
    float mBasisRow1[4];        // +0x10 (row 1)
    float mBasisRow2[4];        // +0x20 (row 2)
    float mRestPositionX;       // +0x30
    float mRestPositionY;       // +0x34
    float mRestPositionZ;       // +0x38
    float mPad3C;               // +0x3C
    float mChildStartIndex;     // +0x40 (copied verbatim as float bits)
    float mChildCount;          // +0x44
    float mFlags;               // +0x48
    float mLocalOffsetX;        // +0x4C
    float mLocalOffsetY;        // +0x50
    float mLocalOffsetZ;        // +0x54
    float mLocalScale;          // +0x58
    std::uint8_t mUnknown5C[4]; // +0x5C
    std::int32_t mParentBoneIndex; // +0x60
    std::uint8_t mUnknown64[8]; // +0x64
  };

  static_assert(offsetof(SScmBoneRecord, mBasisRow0) == 0x00, "SScmBoneRecord::mBasisRow0 offset must be 0x00");
  static_assert(offsetof(SScmBoneRecord, mBasisRow1) == 0x10, "SScmBoneRecord::mBasisRow1 offset must be 0x10");
  static_assert(offsetof(SScmBoneRecord, mBasisRow2) == 0x20, "SScmBoneRecord::mBasisRow2 offset must be 0x20");
  static_assert(offsetof(SScmBoneRecord, mRestPositionX) == 0x30, "SScmBoneRecord::mRestPositionX offset must be 0x30");
  static_assert(offsetof(SScmBoneRecord, mChildStartIndex) == 0x40, "SScmBoneRecord::mChildStartIndex offset must be 0x40");
  static_assert(offsetof(SScmBoneRecord, mChildCount) == 0x44, "SScmBoneRecord::mChildCount offset must be 0x44");
  static_assert(offsetof(SScmBoneRecord, mFlags) == 0x48, "SScmBoneRecord::mFlags offset must be 0x48");
  static_assert(offsetof(SScmBoneRecord, mLocalOffsetX) == 0x4C, "SScmBoneRecord::mLocalOffsetX offset must be 0x4C");
  static_assert(offsetof(SScmBoneRecord, mLocalScale) == 0x58, "SScmBoneRecord::mLocalScale offset must be 0x58");
  static_assert(offsetof(SScmBoneRecord, mParentBoneIndex) == 0x60, "SScmBoneRecord::mParentBoneIndex offset must be 0x60");
  static_assert(sizeof(SScmBoneRecord) == 0x6C, "SScmBoneRecord size must be 0x6C");

  void DefaultAniSkelNoDelete(void*) noexcept {}

  struct NoDeleteAniSkel
  {
    void operator()(const moho::CAniSkel* const skeleton) const noexcept
    {
      DefaultAniSkelNoDelete(const_cast<moho::CAniSkel*>(skeleton));
    }
  };

  [[nodiscard]] moho::CAniDefaultSkel& DefaultAniSkelSingleton() noexcept
  {
    static moho::CAniDefaultSkel defaultSkeleton{};
    return defaultSkeleton;
  }

  using DefaultAniSkelSharedControl = boost::detail::sp_counted_impl_pd<moho::CAniDefaultSkel*, void(__cdecl*)(void*)>;

  /**
   * Address: 0x0054EDA0 (FUN_0054EDA0)
   *
   * What it does:
   * Initializes one in-place Boost shared-count control block for the
   * process-default animation skeleton with no-delete semantics.
   */
  DefaultAniSkelSharedControl* InitializeDefaultAniSkelSharedControlInPlace(
    DefaultAniSkelSharedControl* const outControl
  ) noexcept
  {
    return ::new (outControl) DefaultAniSkelSharedControl(&DefaultAniSkelSingleton(), &DefaultAniSkelNoDelete);
  }

  boost::shared_ptr<const moho::CAniSkel>* BuildDefaultAniSkelSharedPtr(
    boost::shared_ptr<const moho::CAniSkel>* outShared
  );

  /**
   * Address: 0x0054DE70 (FUN_0054DE70, sub_54DE70)
   *
   * What it does:
   * Initializes one caller-provided shared-pointer lane with the process-global
   * default skeleton and preserves shared-from-this wiring on that storage.
   */
  boost::shared_ptr<const moho::CAniSkel>* InitializeDefaultAniSkelSharedPtrLane(
    boost::shared_ptr<const moho::CAniSkel>* const outShared
  )
  {
    if (outShared == nullptr) {
      return nullptr;
    }

    return BuildDefaultAniSkelSharedPtr(outShared);
  }

  /**
   * Address: 0x0054E5A0 (FUN_0054E5A0)
   *
   * What it does:
   * Builds the shared-pointer control lane for the process-global default
   * animation skeleton and binds the no-delete deleter.
   */
  boost::shared_ptr<const moho::CAniSkel>* BuildDefaultAniSkelSharedPtr(
    boost::shared_ptr<const moho::CAniSkel>* const outShared
  )
  {
    if (outShared != nullptr) {
      *outShared = boost::shared_ptr<const moho::CAniSkel>(
        static_cast<const moho::CAniSkel*>(&DefaultAniSkelSingleton()),
        NoDeleteAniSkel{}
      );
    }

    return outShared;
  }

  /**
   * Address: 0x0054CA40 (FUN_0054CA40)
   *
   * What it does:
   * Sets `vector<SAniSkelBone>` length to `requestedCount` by destroying tail
   * lanes on shrink and value-initializing new lanes on growth.
   */
  [[nodiscard]] std::size_t ResizeAniSkelBoneVector(
    msvc8::vector<moho::SAniSkelBone>& storage,
    const std::size_t requestedCount
  )
  {
    // Both arms are resize(): shrink destroys the surplus tail and rebases
    // mLast, grow value-initialises the new slots.
    storage.resize(requestedCount);
    return requestedCount;
  }

  /**
   * Address: 0x0054C080 (FUN_0054C080)
   *
   * What it does:
   * Register-shape adapter that forwards one `(storage,count)` lane to the
   * canonical `ResizeAniSkelBoneVector` implementation.
   */
  [[nodiscard]] std::uint32_t ResizeAniSkelBoneVectorRegisterAdapter(
    msvc8::vector<moho::SAniSkelBone>& storage,
    const std::uint32_t requestedCount
  )
  {
    return static_cast<std::uint32_t>(ResizeAniSkelBoneVector(storage, requestedCount));
  }

  /**
   * Address: 0x0054CB80 (FUN_0054CB80)
   *
   * What it does:
   * Sets `vector<SAniSkelBoneNameIndex>` length to `requestedCount` using one
   * caller-provided fill lane for growth.
   */
  [[nodiscard]] std::size_t ResizeAniSkelBoneNameIndexVectorWithFill(
    msvc8::vector<moho::SAniSkelBoneNameIndex>& storage,
    const std::size_t requestedCount,
    const moho::SAniSkelBoneNameIndex& fillValue
  )
  {
    // Both arms are resize(n, val). SAniSkelBoneNameIndex is trivially
    // destructible, which is why the binary's shrink is a bare mLast rebase.
    storage.resize(requestedCount, fillValue);
    return requestedCount;
  }

  /**
   * Address: 0x0054C190 (FUN_0054C190)
   *
   * What it does:
   * Resizes `vector<SAniSkelBoneNameIndex>` to `requestedCount` using one
   * zero-initialized fill lane for growth.
   */
  [[nodiscard]] std::size_t ResizeAniSkelBoneNameIndexVectorWithDefaultFill(
    msvc8::vector<moho::SAniSkelBoneNameIndex>& storage,
    const std::size_t requestedCount
  )
  {
    const moho::SAniSkelBoneNameIndex defaultFill{};
    return ResizeAniSkelBoneNameIndexVectorWithFill(storage, requestedCount, defaultFill);
  }

  /**
   * Address: 0x0054C200 (FUN_0054C200)
   *
   * What it does:
   * Returns true when one pointer-lane slot currently holds null.
   */
  [[nodiscard]] bool IsAniSkelBoneNameIndexPointerLaneNull(
    const moho::SAniSkelBoneNameIndex* const* const pointerSlot
  ) noexcept
  {
    return *pointerSlot == nullptr;
  }

  /**
   * Address: 0x0054D880 (FUN_0054D880)
   *
   * What it does:
   * Materializes one `SAniSkelBoneNameIndex` pointer at `base + index` into
   * caller-owned output storage.
   */
  [[nodiscard]] moho::SAniSkelBoneNameIndex** SelectAniSkelBoneNameIndexPointerAt(
    moho::SAniSkelBoneNameIndex** const outPointer,
    moho::SAniSkelBoneNameIndex* const* const basePointer,
    const std::int32_t index
  ) noexcept
  {
    *outPointer = *basePointer + index;
    return outPointer;
  }

  /**
   * Address: 0x0054D890 (FUN_0054D890)
   *
   * What it does:
   * Stores one `SAniSkelBoneNameIndex` pointer into caller-owned output
   * storage.
   */
  [[nodiscard]] moho::SAniSkelBoneNameIndex** StoreAniSkelBoneNameIndexPointer(
    moho::SAniSkelBoneNameIndex** const outPointer,
    moho::SAniSkelBoneNameIndex* const value
  ) noexcept
  {
    *outPointer = value;
    return outPointer;
  }

  /**
   * Address: 0x0054DB10 (FUN_0054DB10)
   *
   * What it does:
   * Returns the span between two dword-pointer lanes in 32-bit word units.
   */
  [[nodiscard]] std::int32_t CountDwordPointerSpan(
    const std::uint32_t* const* const endPointer,
    const std::uint32_t* const* const beginPointer
  ) noexcept
  {
    return static_cast<std::int32_t>(*endPointer - *beginPointer);
  }

  /**
   * Address: 0x0054DB20 (FUN_0054DB20)
   *
   * What it does:
   * Materializes one `SAniSkelBone` pointer at `base + index` into
   * caller-owned output storage.
   */
  [[nodiscard]] moho::SAniSkelBone** SelectAniSkelBonePointerAt(
    moho::SAniSkelBone** const outPointer,
    moho::SAniSkelBone* const* const basePointer,
    const std::int32_t index
  ) noexcept
  {
    *outPointer = *basePointer + index;
    return outPointer;
  }

  /**
   * Address: 0x0054DD20 (FUN_0054DD20)
   *
   * What it does:
   * Advances one `SAniSkelBoneNameIndex` pointer lane by `offset` elements.
   */
  [[nodiscard]] moho::SAniSkelBoneNameIndex** AdvanceAniSkelBoneNameIndexPointerLane(
    moho::SAniSkelBoneNameIndex** const pointerSlot,
    const std::int32_t offset
  ) noexcept
  {
    *pointerSlot += offset;
    return pointerSlot;
  }

  /**
   * Address: 0x0054DD40 (FUN_0054DD40)
   *
   * What it does:
   * Secondary entrypoint returning one dword-pointer span in 32-bit word
   * units.
   */
  [[nodiscard]] std::int32_t CountDwordPointerSpanSecondary(
    const std::uint32_t* const* const endPointer,
    const std::uint32_t* const* const beginPointer
  ) noexcept
  {
    return CountDwordPointerSpan(endPointer, beginPointer);
  }

  /**
   * Address: 0x0054DD50 (FUN_0054DD50)
   *
   * What it does:
   * Stores one `SAniSkelBone` pointer into caller-owned output storage.
   */
  [[nodiscard]] moho::SAniSkelBone** StoreAniSkelBonePointer(
    moho::SAniSkelBone** const outPointer,
    moho::SAniSkelBone* const value
  ) noexcept
  {
    *outPointer = value;
    return outPointer;
  }

  /**
   * Address: 0x0054DD60 (FUN_0054DD60)
   *
   * What it does:
   * Advances one `SAniSkelBone` pointer lane by `offset` elements.
   */
  [[nodiscard]] moho::SAniSkelBone** AdvanceAniSkelBonePointerLane(
    moho::SAniSkelBone** const pointerSlot,
    const std::int32_t offset
  ) noexcept
  {
    *pointerSlot += offset;
    return pointerSlot;
  }

  void ResetHeapBackedRangeHandle(HeapBackedRangeHandleRuntimeView& view) noexcept
  {
    if (view.heapStorage != nullptr) {
      ::operator delete(view.heapStorage);
    }
    view.heapStorage = nullptr;
    view.rangeEnd = nullptr;
    view.rangeCapacityEnd = nullptr;
  }

  /**
   * Address: 0x0054CB30 (FUN_0054CB30)
   *
   * What it does:
   * Releases one heap-backed range-handle lane and clears all active range
   * pointers.
   */
  void ResetHeapBackedRangeHandleLaneA(HeapBackedRangeHandleRuntimeView& view) noexcept
  {
    ResetHeapBackedRangeHandle(view);
  }

  /**
   * Address: 0x0054CC40 (FUN_0054CC40)
   *
   * What it does:
   * Secondary release/clear lane for the same heap-backed range-handle
   * runtime shape.
   */
  void ResetHeapBackedRangeHandleLaneB(HeapBackedRangeHandleRuntimeView& view) noexcept
  {
    ResetHeapBackedRangeHandle(view);
  }

  /**
   * Address: 0x0054CD70 (FUN_0054CD70)
   *
   * What it does:
   * Third release/clear lane for the same heap-backed range-handle runtime
   * shape.
   */
  void ResetHeapBackedRangeHandleLaneC(HeapBackedRangeHandleRuntimeView& view) noexcept
  {
    ResetHeapBackedRangeHandle(view);
  }

  /**
   * Address: 0x0054D3B0 (FUN_0054D3B0)
   *
   * What it does:
   * Deletes one heap-allocated runtime object lane.
   */
  void DeleteRuntimeObjectLaneA(void* const objectStorage) noexcept
  {
    ::operator delete(objectStorage);
  }

  /**
   * Address: 0x0054D710 (FUN_0054D710)
   *
   * What it does:
   * Secondary deleting lane for the same heap-runtime object contract.
   */
  void DeleteRuntimeObjectLaneB(void* const objectStorage) noexcept
  {
    ::operator delete(objectStorage);
  }

  /**
   * Address: 0x0054DB30 (FUN_0054DB30)
   *
   * What it does:
   * Copies one `SAniSkelBone` payload into destination storage.
   */
  [[nodiscard]] moho::SAniSkelBone* CopyAniSkelBone(
    moho::SAniSkelBone* const destination,
    const moho::SAniSkelBone* const source
  ) noexcept
  {
    if (destination != nullptr && source != nullptr) {
      *destination = *source;
    }
    return destination;
  }

  /**
   * Address: 0x0054ECD0 (FUN_0054ECD0)
   *
   * What it does:
   * Copies one `SAniSkelBone` payload with non-null source/destination lanes.
   */
  [[nodiscard]] moho::SAniSkelBone* CopyAniSkelBoneNonNull(
    moho::SAniSkelBone* const destination,
    const moho::SAniSkelBone* const source
  ) noexcept
  {
    *destination = *source;
    return destination;
  }

  [[nodiscard]] moho::SAniSkelBone* FillAniSkelBoneRangeFromSingleValueNullable(
    std::uint32_t count,
    moho::SAniSkelBone* destination,
    const moho::SAniSkelBone* const value
  ) noexcept
  {
    while (count != 0u) {
      if (destination != nullptr) {
        (void)CopyAniSkelBone(destination, value);
      }
      --count;
      ++destination;
    }
    return destination;
  }

  /**
   * Address: 0x0054EC00 (FUN_0054EC00)
   *
   * What it does:
   * Copies `count` lanes from one source-bone value into contiguous destination
   * storage when destination lanes are present.
   */
  [[nodiscard]] moho::SAniSkelBone* CopyAniSkelBoneCountedNullable(
    std::uint32_t count,
    moho::SAniSkelBone* destination,
    const moho::SAniSkelBone* const value
  ) noexcept
  {
    std::uintptr_t rawResult = count;
    while (count != 0u) {
      if (destination != nullptr) {
        rawResult = reinterpret_cast<std::uintptr_t>(CopyAniSkelBone(destination, value));
      }
      ++destination;
      --count;
    }
    return reinterpret_cast<moho::SAniSkelBone*>(rawResult);
  }

  /**
   * Address: 0x0054E2D0 (FUN_0054E2D0)
   *
   * What it does:
   * Register-shape adapter that fills one contiguous skeleton-bone lane range
   * from a single source lane.
   */
  [[nodiscard]] moho::SAniSkelBone* FillAniSkelBoneRangeRegisterAdapter(
    const moho::SAniSkelBone* const value,
    moho::SAniSkelBone* const destination,
    const std::uint32_t count
  ) noexcept
  {
    return CopyAniSkelBoneCountedNullable(count, destination, value);
  }

  /**
   * Address: 0x0054E000 (FUN_0054E000)
   *
   * What it does:
   * Copies one contiguous source-bone range forward into destination storage
   * using the non-null single-bone lane copier.
   */
  [[nodiscard]] moho::SAniSkelBone* CopyAniSkelBoneRangeForwardNonNull(
    const moho::SAniSkelBone* sourceBegin,
    moho::SAniSkelBone* destinationBegin,
    const moho::SAniSkelBone* sourceEnd
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      (void)CopyAniSkelBoneNonNull(destinationBegin, sourceBegin);
      ++sourceBegin;
      ++destinationBegin;
    }

    return destinationBegin;
  }

  /**
   * Address: 0x0054E070 (FUN_0054E070)
   *
   * What it does:
   * Fills one destination-bone range from a single template-bone lane using
   * non-null copy semantics.
   */
  [[nodiscard]] moho::SAniSkelBone* FillAniSkelBoneRangeFromSingleNonNull(
    moho::SAniSkelBone* destinationBegin,
    const moho::SAniSkelBone* const value,
    const moho::SAniSkelBone* const destinationEnd
  ) noexcept
  {
    moho::SAniSkelBone* result = destinationBegin;
    while (destinationBegin != destinationEnd) {
      result = CopyAniSkelBoneNonNull(destinationBegin, value);
      ++destinationBegin;
    }
    return result;
  }

  /**
   * Address: 0x0054E090 (FUN_0054E090)
   *
   * What it does:
   * Copies one source-bone range backward into destination storage for overlap-
   * safe insertion-style moves.
   */
  [[nodiscard]] moho::SAniSkelBone* CopyAniSkelBoneRangeBackwardNonNull(
    const moho::SAniSkelBone* sourceEnd,
    moho::SAniSkelBone* destinationEnd,
    const moho::SAniSkelBone* sourceBegin
  ) noexcept
  {
    const moho::SAniSkelBone* sourceCursor = sourceEnd;
    moho::SAniSkelBone* destinationCursor = destinationEnd;

    while (sourceCursor != sourceBegin) {
      --sourceCursor;
      --destinationCursor;
      (void)CopyAniSkelBoneNonNull(destinationCursor, sourceCursor);
    }

    return destinationCursor;
  }

  /**
   * Address: 0x0054DC60 (FUN_0054DC60)
   *
   * What it does:
   * Runs one counted nullable-copy lane with a null source pointer and returns
   * the destination pointer advanced by `count` skeleton-bone lanes.
   */
  [[nodiscard]] moho::SAniSkelBone* AdvanceAniSkelBoneAfterCountedNullFill(
    moho::SAniSkelBone* const destinationBegin,
    const std::uint32_t count
  ) noexcept
  {
    (void)CopyAniSkelBoneCountedNullable(count, destinationBegin, nullptr);
    return destinationBegin + count;
  }

  /**
   * Address: 0x0054D050 (FUN_0054D050)
   *
   * What it does:
   * Conditionally copies one source-tail range into destination storage,
   * updates one runtime range-end lane, and stores the destination begin lane
   * through one caller-provided pointer slot.
   */
  [[nodiscard]] moho::SAniSkelBone** CopyAniSkelBoneTailAndStoreDestinationBegin(
    moho::SAniSkelBone** const outDestinationBegin,
    HeapBackedRangeHandleRuntimeView* const rangeHandle,
    moho::SAniSkelBone* const destinationBegin,
    const moho::SAniSkelBone* const sourceBegin
  ) noexcept
  {
    if (destinationBegin != sourceBegin) {
      rangeHandle->rangeEnd = CopyAniSkelBoneRangeForwardNonNull(
        sourceBegin,
        destinationBegin,
        static_cast<const moho::SAniSkelBone*>(rangeHandle->rangeEnd)
      );
    }

    *outDestinationBegin = destinationBegin;
    return outDestinationBegin;
  }

  /**
   * Address: 0x0054FED0 (FUN_0054FED0)
   *
   * What it does:
   * Copies one half-open `SAniSkelBone` source range into destination storage
   * and returns the destination end pointer.
   */
  [[nodiscard]] moho::SAniSkelBone* CopyAniSkelBoneRange(
    const moho::SAniSkelBone* sourceBegin,
    moho::SAniSkelBone* destinationBegin,
    const moho::SAniSkelBone* sourceEnd
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      if (destinationBegin != nullptr) {
        (void)CopyAniSkelBone(destinationBegin, sourceBegin);
      }
      ++sourceBegin;
      ++destinationBegin;
    }

    return destinationBegin;
  }

  /**
   * Address: 0x0054E8E0 (FUN_0054E8E0)
   * Address: 0x0054F6E0 (FUN_0054F6E0)
   * Address: 0x0054FB30 (FUN_0054FB30)
   *
   * What it does:
   * Register-shape adapter for one contiguous `SAniSkelBone` range copy.
   */
  [[nodiscard]] moho::SAniSkelBone* CopyAniSkelBoneRangeRegisterAdapterLaneB(
    const moho::SAniSkelBone* const sourceBegin,
    moho::SAniSkelBone* const destinationBegin,
    const moho::SAniSkelBone* const sourceEnd
  ) noexcept
  {
    return CopyAniSkelBoneRange(sourceBegin, destinationBegin, sourceEnd);
  }

  [[nodiscard]] moho::SAniSkelBoneNameIndex* CopyAniSkelBoneNameIndexRangeNullable(
    moho::SAniSkelBoneNameIndex* destination,
    const moho::SAniSkelBoneNameIndex* sourceBegin,
    const moho::SAniSkelBoneNameIndex* const sourceEnd
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      if (destination != nullptr) {
        *destination = *sourceBegin;
      }
      ++sourceBegin;
      ++destination;
    }
    return destination;
  }

  /**
   * Address: 0x0054E9B0 (FUN_0054E9B0)
   * Address: 0x0054F730 (FUN_0054F730)
   * Address: 0x0054FB50 (FUN_0054FB50)
   *
   * What it does:
   * Register-shape adapter for one contiguous `SAniSkelBoneNameIndex` range
   * copy.
   */
  [[nodiscard]] moho::SAniSkelBoneNameIndex* CopyAniSkelBoneNameIndexRangeRegisterAdapter(
    const moho::SAniSkelBoneNameIndex* const sourceBegin,
    moho::SAniSkelBoneNameIndex* const destinationBegin,
    const moho::SAniSkelBoneNameIndex* const sourceEnd
  ) noexcept
  {
    return CopyAniSkelBoneNameIndexRangeNullable(destinationBegin, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x0054E040 (FUN_0054E040)
   *
   * What it does:
   * Adapts one register-lane caller shape into the canonical skeleton-bone
   * range-copy helper.
   */
  [[nodiscard]] moho::SAniSkelBone* CopyAniSkelBoneRangeRegisterAdapter(
    const moho::SAniSkelBone* const sourceBegin,
    const moho::SAniSkelBone* const sourceEnd,
    moho::SAniSkelBone* const destinationBegin
  ) noexcept
  {
    return CopyAniSkelBoneRange(sourceBegin, destinationBegin, sourceEnd);
  }

  /**
   * `Moho::ANI_DumpSkeleton`'s per-parent-bone dedup map is a real
   * `msvc8::map<std::uint32_t, msvc8::set<std::uint32_t>>` (see the
   * `operator[]`/`insert_unique`/`erase_range` citations in
   * `legacy/containers/Map.h` and `RbTree.h`, and `WeakEntitySetUserEntity::
   * BuyNode`/`alloc_raw` in `WeakEntitySet.h`/`RbTree.h`) - a hand-rolled
   * `AniSkeletonVisitedBoneNodeLanes` node struct used to stand in for that
   * template before those instantiations were identified and cited; it and
   * its `InitializeAniSkeletonVisitedBoneNode`/`StageAniSkeletonVisitedBoneNode`
   * helpers (reached only from a static bootstrap object invented purely to
   * keep them reachable-by-name, never from real engine code) are removed
   * below in favor of `Moho::ANI_DumpSkeleton` building and tearing down its
   * dedup tree and selection set through those typed containers directly.
   */

  /**
   * Address: 0x007B2372-0x007B2385 (inlined in `Moho::ANI_DumpSkeleton`,
   * FUN_007B22B0)
   *
   * What it does:
   * Resolves the `UserEntity*` a selection weak-ref slot points at, or null
   * for an empty/tombstoned slot (`nullptr` or the sentinel `(void*)8`).
   * Same `WeakObject` sub-object `-offsetof(UserEntity, mIUnitChainHead)`
   * adjust as `DecodeUserEntityFromSelectionSlot` (CConCommand.cpp) and
   * `DecodeSelectionEntity` (CFormation.cpp); re-homed here as this file's
   * own copy of the pattern rather than reaching into another TU's
   * anonymous namespace.
   */
  [[nodiscard]] moho::UserEntity* DecodeAniSkeletonSelectionEntity(
    const moho::SSelectionWeakRefUserEntity& weakRef
  ) noexcept
  {
    void* const ownerLinkSlot = weakRef.mOwnerLinkSlot;
    if (ownerLinkSlot == nullptr || ownerLinkSlot == reinterpret_cast<void*>(static_cast<std::uintptr_t>(8u))) {
      return nullptr;
    }

    constexpr std::uintptr_t kWeakOwnerOffset = offsetof(moho::UserEntity, mIUnitChainHead);
    const std::uintptr_t raw = reinterpret_cast<std::uintptr_t>(ownerLinkSlot);
    if (raw < kWeakOwnerOffset) {
      return nullptr;
    }

    return reinterpret_cast<moho::UserEntity*>(raw - kWeakOwnerOffset);
  }

  /**
   * The record `PrintAniSkeletonBoneHierarchy` (FUN_007B2050) reads through
   * each bone pointer stored in a per-parent dedup set. Proven from raw
   * `.asm` (movss reads at `[pointer+0x08]`/`+0x0C`/`+0x10`/`+0x14`/`+0x18`/
   * `+0x1C`/`+0x20`, name read at `[pointer+0x00]`): this does NOT match
   * either `SAniSkelBone` (name@0x00 matches, but its `mBoneTransform` sits
   * at +0x24, with `mLocalOffsetX/Y/Z`/`mLocalScale`/`mChildStartIndex`/
   * `mChildCount`/`mFlags` in between that this dump never reads) or
   * `CAniPoseBone` (`mCompositeTransform` at +0x00, no name field at all).
   *
   * The pointer stored in the dedup set is independently proven (from
   * `Moho::ANI_DumpSkeleton`'s per-bone loop, 0x007B2421-0x007B2432) to be a
   * genuine `&skel->mBones[i]`, i.e. a real `SAniSkelBone*` - so the shipped
   * binary's `ANI_DumpSkeleton` debug command reads its name/quaternion/
   * position fields at byte offsets that do not correspond to
   * `SAniSkelBone`'s current fields beyond the shared name prefix.
   * Reproduced 1:1 as a raw offset view rather than "corrected" to
   * `SAniSkelBone`'s named fields, matching the binary's actual (evidently
   * stale relative to the current on-disk bone format) reads exactly - per
   * this project's typed-placeholder-struct allowance for fields not yet
   * fully owned. Whether this reflects a console command that was never
   * updated after `SAniSkelBone`'s on-disk layout changed, or some other
   * historical mismatch, is not resolved by this pass.
   */
  struct AniSkeletonBoneDumpFieldsView
  {
    const char* mName;        // +0x00
    std::uint32_t field_0x04; // +0x04 (never read by the dump)
    float mQuatW;             // +0x08
    float mQuatX;              // +0x0C
    float mQuatY;               // +0x10
    float mQuatZ;                // +0x14
    float mPosX;                  // +0x18
    float mPosY;                   // +0x1C
    float mPosZ;                    // +0x20
  };
  static_assert(
    offsetof(AniSkeletonBoneDumpFieldsView, mQuatW) == 0x08,
    "AniSkeletonBoneDumpFieldsView::mQuatW offset must be 0x08"
  );
  static_assert(
    offsetof(AniSkeletonBoneDumpFieldsView, mPosX) == 0x18,
    "AniSkeletonBoneDumpFieldsView::mPosX offset must be 0x18"
  );
  static_assert(
    sizeof(AniSkeletonBoneDumpFieldsView) == 0x24, "AniSkeletonBoneDumpFieldsView size must be 0x24"
  );

  /**
   * Address: 0x007B2050 (FUN_007B2050, sub_7B2050)
   *
   * IDA signature:
   * _DWORD *__cdecl sub_7B2050(int arg0, unsigned int a2, int a3);
   *
   * What it does:
   * Recursive, indented bone-hierarchy printer for `ANI_DumpSkeleton`. Walks
   * `children` in order; for each stored bone pointer, formats
   * "<indent><name><pad>p=<x,y,z> q=<x,y,z,w>" (name right-padded so the
   * `p=` column lands at ~50 characters, clamped to at least 2 spaces) via
   * `gpg::STR_Printf`, emits it through both `Moho::CON_Printf` and
   * `gpg::Logf`, then recurses into that bone's own children
   * (`dedupTree[boneKey]`) with `indent + 2`.
   *
   * `dedupTree` is threaded through explicitly - it is the binary's third
   * parameter, proven via raw `.asm` at 0x007B2233-0x007B224E to be the
   * outer map pointer loaded into `ecx` as `this` for the recursive
   * `operator[]` call, not an inert/unused context value (the top-level
   * decompiler pseudocode's `(int)&v18._Myend` naming for this argument at
   * the initial call site does not survive a register-level check either;
   * the pushed value is `&a2._Myval`, the same outer-map local the per-bone
   * loop already builds).
   */
  void PrintAniSkeletonBoneHierarchy(
    const msvc8::set<std::uint32_t>& children,
    const std::uint32_t indent,
    msvc8::map<std::uint32_t, msvc8::set<std::uint32_t>>& dedupTree
  )
  {
    for (const std::uint32_t boneKey : children) {
      const auto* const fields =
        reinterpret_cast<const AniSkeletonBoneDumpFieldsView*>(static_cast<std::uintptr_t>(boneKey));

      const std::size_t nameLength = std::strlen(fields->mName);
      const int rawPadWidth = 50 - static_cast<int>(nameLength) - static_cast<int>(indent);
      const std::size_t namePadWidth = static_cast<std::size_t>(rawPadWidth > 2 ? rawPadWidth : 2);

      msvc8::string indentPad;
      (void)indentPad.assign(static_cast<std::size_t>(indent), ' ');
      msvc8::string namePad;
      (void)namePad.assign(namePadWidth, ' ');

      const msvc8::string line = gpg::STR_Printf(
        "%s%s%sp=<%5.2f,%5.2f,%5.2f> q=<%5.2f,%5.2f,%5.2f,%5.2f>",
        indentPad.c_str(),
        fields->mName,
        namePad.c_str(),
        fields->mPosX,
        fields->mPosY,
        fields->mPosZ,
        fields->mQuatX,
        fields->mQuatY,
        fields->mQuatZ,
        fields->mQuatW
      );

      moho::CON_Printf("%s", line.c_str());
      gpg::Logf("%s", line.c_str());

      PrintAniSkeletonBoneHierarchy(dedupTree[boneKey], indent + 2u, dedupTree);
    }
  }
} // namespace

namespace moho
{
  gpg::RType* CAniSkel::sType = nullptr;

  /**
   * Address: 0x0054A0A0 (FUN_0054A0A0,
   * ??0CAniSkel@Moho@@QAE@ABV?$shared_ptr@$$CBUSScmFile@Moho@@@boost@@@Z)
   * Mangled: ??0CAniSkel@Moho@@QAE@ABV?$shared_ptr@$$CBUSScmFile@Moho@@@boost@@@Z
   *
   * IDA signature:
   * Moho::CAniSkel *__userpurge CAniSkel(Moho::CAniSkel *this, boost::shared_ptr<const SScmFile> *file);
   *
   * What it does:
   * Retains the shared SScmFile, gathers the bone-name pointer table from the
   * file's name string block, sizes the bone + name->index vectors to the
   * file's bone count, then populates each bone: name pointer, parent index,
   * child link range, local offset/scale, and a rest transform whose
   * orientation is the quaternion of the on-disk 3x4 basis and whose
   * translation is the on-disk rest position. The name->index table is then
   * sorted (strcmp primary key, ascending index tie-break) so `FindBoneIndex`
   * can binary-search it, and per-bone bounds are rebuilt.
   */
  CAniSkel::CAniSkel(const boost::shared_ptr<const SScmFile>& file)
    : mFile(file)
  {
    const SScmFile& scmFile = *file;
    const std::uint32_t boneCount = scmFile.mBoneTotalCount;

    // Gather one name pointer per bone from the file's name string block.
    msvc8::vector<const char*> boneNamePointers{};
    moho::scm_file::FillBoneNamePointers(scmFile, boneNamePointers);

    (void)ResizeAniSkelBoneVector(mBones, boneCount);
    (void)ResizeAniSkelBoneNameIndexVectorWithFill(
      mBoneNameToIndex, boneCount, SAniSkelBoneNameIndex{nullptr, 0}
    );

    const auto* const boneRecords = reinterpret_cast<const SScmBoneRecord*>(
      reinterpret_cast<const std::uint8_t*>(&scmFile) + scmFile.mBoneTableOffset
    );
    SAniSkelBone* const bones = mBones.begin();
    SAniSkelBoneNameIndex* const nameToIndex = mBoneNameToIndex.begin();
    const char* const* const namePointers = boneNamePointers.begin();

    for (std::uint32_t boneIndex = 0; boneIndex < boneCount; ++boneIndex) {
      const SScmBoneRecord& record = boneRecords[boneIndex];
      const char* const boneName = namePointers[boneIndex];

      nameToIndex[boneIndex].mBoneName = boneName;
      nameToIndex[boneIndex].mBoneIndex = static_cast<std::int32_t>(boneIndex);

      SAniSkelBone& bone = bones[boneIndex];
      bone.mBoneName = boneName;
      bone.mParentBoneIndex = record.mParentBoneIndex;

      // The child-link and offset/scale lanes are copied as raw float bits in
      // the binary (fld/fstp), matching the on-disk record layout exactly.
      std::memcpy(&bone.mChildStartIndex, &record.mChildStartIndex, sizeof(float));
      std::memcpy(&bone.mChildCount, &record.mChildCount, sizeof(float));
      std::memcpy(&bone.mFlags, &record.mFlags, sizeof(float));
      bone.mLocalOffsetX = record.mLocalOffsetX;
      bone.mLocalOffsetY = record.mLocalOffsetY;
      bone.mLocalOffsetZ = record.mLocalOffsetZ;
      bone.mLocalScale = record.mLocalScale;

      // Convert the on-disk 3x4 basis to a quaternion. The binary passes the
      // three rows (first three floats of each) as the "columns" argument of
      // MatrixColumnsToQuatCanonical (FUN_004F0AE0), which transposes them.
      const Wm3::Vector3f basisColumns[3] = {
        Wm3::Vector3f{record.mBasisRow0[0], record.mBasisRow0[1], record.mBasisRow0[2]},
        Wm3::Vector3f{record.mBasisRow1[0], record.mBasisRow1[1], record.mBasisRow1[2]},
        Wm3::Vector3f{record.mBasisRow2[0], record.mBasisRow2[1], record.mBasisRow2[2]},
      };
      (void)MatrixColumnsToQuatCanonical(basisColumns, &bone.mBoneTransform.orient_);

      bone.mBoneTransform.pos_.x = record.mRestPositionX;
      bone.mBoneTransform.pos_.y = record.mRestPositionY;
      bone.mBoneTransform.pos_.z = record.mRestPositionZ;
    }

    // Address: 0x0054A32C -- calls the recovered MSVC8 std::_Sort introsort
    // family directly: SortStringRankLaneRuntimeRange (FUN_0054E4B0), which
    // partitions via PartitionStringRankLaneRuntimeRange (FUN_0054EE30),
    // both in SimRecoveryRuntime.cpp. `StringRankLaneRuntime` is the layout
    // twin of `SAniSkelBoneNameIndex` (`const char*` then `std::int32_t` in
    // both, so the two standard-layout types share a common initial
    // sequence). The binary pushes a dead-null predicate argument at this
    // call site (`IsStringRankLessRuntime` is stateless and its strcmp-then-
    // index ordering -- byte-verified equal to this file's former
    // `AniSkelBoneNameIndexLess` comparator -- is inlined at every
    // comparison instead), and seeds the recursion budget with the initial
    // element count, matching `std::sort`'s `_Sort(first,last,last-first,pred)`
    // entry contract.
    SAniSkelBoneNameIndex* const nameIndexFirst = mBoneNameToIndex.begin();
    SAniSkelBoneNameIndex* const nameIndexLast = mBoneNameToIndex.end();
    SortStringRankLaneRuntimeRange(
      reinterpret_cast<StringRankLaneRuntime*>(nameIndexFirst),
      reinterpret_cast<StringRankLaneRuntime*>(nameIndexLast),
      nameIndexLast - nameIndexFirst
    );

    UpdateBoneBounds();
  }

  /**
   * Address: 0x0054A370 (FUN_0054A370, scalar deleting destructor thunk)
   * Mangled: ??_GCAniSkel@Moho@@UAEPAXI@Z
   *
   * What it does:
   * Tears down bone containers/shared state and optionally deletes `this`.
   */
  CAniSkel::~CAniSkel() = default;

  /**
   * Address: 0x00549E20 (FUN_00549E20)
   *
   * unsigned int
   *
   * IDA signature:
   * int __userpurge FUN_00549e20@<eax>(int this@<esi>, uint index@<edi>);
   *
   * What it does:
   * Returns a bone pointer for a valid index, otherwise null.
   */
  const SAniSkelBone* CAniSkel::GetBone(const std::uint32_t boneIndex) const
  {
    const SAniSkelBone* const begin = mBones.begin();
    if (!begin) {
      return nullptr;
    }

    if (boneIndex >= static_cast<std::uint32_t>(mBones.size())) {
      return nullptr;
    }

    return begin + boneIndex;
  }

  /**
   * Address: 0x0054A840 (FUN_0054A840)
   *
   * What it does:
   * Collects the indices of every bone parented to `parentBoneIndex`. Bones
   * only carry the upward link, so this is a full scan of the bone array
   * (0x0054A853 walks it at the 88-byte `SAniSkelBone` stride, comparing the
   * +0x04 parent lane).
   */
  void CAniSkel::CollectChildBoneIndices(
    const std::int32_t parentBoneIndex,
    msvc8::vector<std::int32_t>& outIndices
  ) const
  {
    outIndices.clear();

    const SAniSkelBone* const begin = mBones.begin();
    if (begin == nullptr) {
      return;
    }

    const std::size_t boneCount = mBones.size();
    for (std::size_t boneIndex = 0; boneIndex < boneCount; ++boneIndex) {
      if (begin[boneIndex].mParentBoneIndex == parentBoneIndex) {
        outIndices.push_back(static_cast<std::int32_t>(boneIndex));
      }
    }
  }

  /**
   * Address: 0x0054A7B0 (FUN_0054A7B0)
   *
   * char const *
   *
   * IDA signature:
   * int __thiscall FUN_0054a7b0(void *this, byte *name);
   *
   * What it does:
   * Binary-searches the sorted bone-name table and returns index or `-1`.
   */
  std::int32_t CAniSkel::FindBoneIndex(const char* const boneName) const
  {
    if (!boneName) {
      return -1;
    }

    const SAniSkelBoneNameIndex* const begin = mBoneNameToIndex.begin();
    if (!begin) {
      return -1;
    }

    std::int32_t low = 0;
    std::int32_t high = static_cast<std::int32_t>(mBoneNameToIndex.size());
    while (low < high) {
      const std::int32_t middle = (low + high) >> 1;
      const char* const middleName = begin[middle].mBoneName ? begin[middle].mBoneName : "";
      const std::int32_t compareResult = std::strcmp(boneName, middleName);
      if (compareResult < 0) {
        high = middle;
        continue;
      }

      if (compareResult > 0) {
        low = middle + 1;
        continue;
      }

      return begin[middle].mBoneIndex;
    }

    return -1;
  }

  /**
   * Address: 0x0054AC90 (FUN_0054AC90)
   *
   * What it does:
   * Returns a shared pointer to process-global default skeleton storage.
   */
  boost::shared_ptr<const CAniSkel> CAniSkel::GetDefaultSkeleton()
  {
    boost::shared_ptr<const CAniSkel> result{};
    (void)BuildDefaultAniSkelSharedPtr(&result);
    return result;
  }

  /**
   * Address: 0x0054A540 (FUN_0054A540)
   * Mangled: ?UpdateBoneBounds@CAniSkel@Moho@@AAEXXZ
   *
   * What it does:
   * Rebuilds per-bone min/max bounds from SCM sample mapping data.
   *
   * Ground truth (`FUN_0054A540.c`) rotates via
   * `Moho::MultQuadVec(&v31, v11, &v12->ori)`, not the generic
   * `Wm3::MultiplyQuaternionVector` -- same quaternion-convention
   * convention mismatch as the other `orient_`-consuming sites (this bone
   * transform's quaternion is always in `VMatrix4::Set`'s convention).
   */
  void CAniSkel::UpdateBoneBounds()
  {
    SAniSkelBone* const boneStart = mBones.begin();
    SAniSkelBone* const boneFinish = mBones.end();
    for (SAniSkelBone* bone = boneStart; bone && bone != boneFinish; ++bone) {
      bone->mBoundsMinX = 0.0f;
      bone->mBoundsMinY = 0.0f;
      bone->mBoundsMinZ = 0.0f;
      bone->mBoundsMaxX = 0.0f;
      bone->mBoundsMaxY = 0.0f;
      bone->mBoundsMaxZ = 0.0f;
    }

    const SScmFile* const sourceFile = mFile.get();
    if (sourceFile == nullptr || boneStart == nullptr) {
      return;
    }

    const std::uint32_t boneCount = static_cast<std::uint32_t>(mBones.size());
    const std::uint32_t sampleCount = sourceFile->mBoneBoundsSampleCount;
    if (sampleCount == 0u) {
      return;
    }

    const SScmBoneBoundsSample* const samples = scm_file::GetBoneBoundsSamples(*sourceFile);
    if (samples == nullptr) {
      return;
    }

    for (std::uint32_t sampleIndex = 0; sampleIndex < sampleCount; ++sampleIndex) {
      const SScmBoneBoundsSample& sample = samples[sampleIndex];
      const std::uint32_t boneIndex = sample.mBoneIndex;
      if (boneIndex >= boneCount) {
        gpg::Warnf("Encoutered bad SCM file. Dumping out data");
        for (std::uint32_t dumpIndex = 0; dumpIndex < boneCount; ++dumpIndex) {
          const char* const boneName = boneStart[dumpIndex].mBoneName ? boneStart[dumpIndex].mBoneName : "";
          gpg::Warnf(" dumping bone %d name = %s", dumpIndex, boneName);
        }

        GPG_ASSERT(!"Invalid bone index in SCM bounds sample");
        return;
      }

      SAniSkelBone& bone = boneStart[boneIndex];
      const Wm3::Vec3f localPosition{sample.mLocalPositionX, sample.mLocalPositionY, sample.mLocalPositionZ};
      Wm3::Vec3f rotatedPosition{};
      MultQuadVec(&rotatedPosition, &localPosition, &bone.mBoneTransform.orient_);

      const float mappedX = bone.mBoneTransform.pos_.x + rotatedPosition.x;
      const float mappedY = bone.mBoneTransform.pos_.y + rotatedPosition.y;
      const float mappedZ = bone.mBoneTransform.pos_.z + rotatedPosition.z;

      if (mappedX < bone.mBoundsMinX) {
        bone.mBoundsMinX = mappedX;
      }
      if (mappedY < bone.mBoundsMinY) {
        bone.mBoundsMinY = mappedY;
      }
      if (mappedZ < bone.mBoundsMinZ) {
        bone.mBoundsMinZ = mappedZ;
      }

      if (mappedX > bone.mBoundsMaxX) {
        bone.mBoundsMaxX = mappedX;
      }
      if (mappedY > bone.mBoundsMaxY) {
        bone.mBoundsMaxY = mappedY;
      }
      if (mappedZ > bone.mBoundsMaxZ) {
        bone.mBoundsMaxZ = mappedZ;
      }
    }
  }

  /**
   * The active world session (`Moho::sWldSession`, 0x010A6470). The global
   * has no owning header in this tree yet, so it is declared here where it
   * is used, matching the established pattern (Cartographic.cpp,
   * WxRuntimeTypes.cpp).
   */
  extern CWldSession* sWldSession;

  /**
   * Address: 0x007B22B0 (FUN_007B22B0, Moho::ANI_DumpSkeleton)
   *
   * IDA signature:
   * void __cdecl Moho::ANI_DumpSkeleton();
   *
   * What it does:
   * The `ANI_DumpSkeleton` console command. Resolves the current selection's
   * first live unit, prints its animation skeleton's bone hierarchy
   * (indented, parent-then-children) through both the console and the log,
   * then releases the transient selection snapshot and per-parent dedup
   * tree it built to reconstruct that hierarchy from the skeleton's flat,
   * parent-index-only bone array. Prints "There is no selected unit." when
   * the selection is empty or has no live entries. The binary reads
   * `mPoseSecondary` (+0x24) unconditionally once a live entity is found,
   * with no null check on the resulting `CAniPose*` before calling
   * `GetSkeleton()` - reproduced as-is.
   *
   * The dedup map (`dedupTree`) and its nested per-parent sets, and the
   * transient selection snapshot (`selectionGuard`), are released by their
   * own destructors at scope exit - the same cleanup the binary performs
   * explicitly (`erase_range` + `operator delete` on both, cited in
   * `legacy/containers/RbTree.h` / `moho/sim/WeakEntitySet.h`).
   */
  void ANI_DumpSkeleton()
  {
    ScopedLocalUnitSet selectionGuard;
    WeakUnitSetUserUnit& selection = selectionGuard.get();
    // 0x007B22FD/0x007B2308: reads the global session and calls straight
    // through with no null check - reproduced as-is.
    WLD_GetActiveSession()->GetSelectionUnits(selection);

    UserEntity* selectedEntity = nullptr;
    if (!selection.IsEmptyAfterPrune()) {
      SSelectionNodeUserEntity* liveNode = nullptr;
      (void)PruneTombstonesAndFindLive(selection, &liveNode, selection.mHead->mLeft);
      selectedEntity = DecodeAniSkeletonSelectionEntity(liveNode->mEnt);
    }

    if (selectedEntity == nullptr) {
      CON_Printf("There is no selected unit.");
      return;
    }

    CAniPose* const pose = selectedEntity->mPoseSecondary.get();

    // The binary extracts the raw skeleton pointer and releases the
    // temporary `shared_ptr<const CAniSkel>` handle immediately
    // (`Moho::WeakPtr_CAniSkel_D::release`, 0x00538320) rather than holding
    // it for the whole function - matched here with a tight scope instead of
    // keeping the shared_ptr alive across the walk below.
    const CAniSkel* skel;
    {
      const boost::shared_ptr<const CAniSkel> skelHandle = pose->GetSkeleton();
      skel = skelHandle.get();
    }

    msvc8::map<std::uint32_t, msvc8::set<std::uint32_t>> dedupTree;
    for (const SAniSkelBone& bone : skel->mBones) {
      const SAniSkelBone* const parentBone = skel->GetBone(static_cast<std::uint32_t>(bone.mParentBoneIndex));
      const std::uint32_t parentKey = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(parentBone));
      const std::uint32_t boneKey = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(&bone));
      (void)dedupTree[parentKey].insert(boneKey);
    }

    PrintAniSkeletonBoneHierarchy(dedupTree[0u], 0u, dedupTree);
  }
} // namespace moho
