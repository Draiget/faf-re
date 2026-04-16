#include "CAniSkel.h"

#include <cstring>
#include <new>

#include <boost/detail/sp_counted_impl.hpp>

#include "CAniDefaultSkel.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "moho/resource/SScmFile.h"
#include "Wm3Vector3.h"

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
   * Address: 0x0054AC80 (FUN_0054AC80, nullsub_2)
   *
   * What it does:
   * Preserves the default-skeleton shared-pointer deleter lane as a deliberate
   * no-op.
   */
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
  [[maybe_unused]] DefaultAniSkelSharedControl* InitializeDefaultAniSkelSharedControlInPlace(
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
  [[maybe_unused]] boost::shared_ptr<const moho::CAniSkel>* InitializeDefaultAniSkelSharedPtrLane(
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
  [[maybe_unused]] [[nodiscard]] std::size_t ResizeAniSkelBoneVector(
    msvc8::vector<moho::SAniSkelBone>& storage,
    const std::size_t requestedCount
  )
  {
    auto& view = msvc8::AsVectorRuntimeView(storage);
    const std::size_t currentCount = view.begin ? static_cast<std::size_t>(view.end - view.begin) : 0u;

    if (requestedCount < currentCount) {
      if (view.begin && view.end) {
        moho::SAniSkelBone* const eraseBegin = view.begin + requestedCount;
        for (moho::SAniSkelBone* cursor = eraseBegin; cursor != view.end; ++cursor) {
          cursor->~SAniSkelBone();
        }
        view.end = eraseBegin;
      }
      return requestedCount;
    }

    if (requestedCount > currentCount) {
      storage.resize(requestedCount);
    }

    return requestedCount;
  }

  /**
   * Address: 0x0054C080 (FUN_0054C080)
   *
   * What it does:
   * Register-shape adapter that forwards one `(storage,count)` lane to the
   * canonical `ResizeAniSkelBoneVector` implementation.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t ResizeAniSkelBoneVectorRegisterAdapter(
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
  [[maybe_unused]] [[nodiscard]] std::size_t ResizeAniSkelBoneNameIndexVectorWithFill(
    msvc8::vector<moho::SAniSkelBoneNameIndex>& storage,
    const std::size_t requestedCount,
    const moho::SAniSkelBoneNameIndex& fillValue
  )
  {
    auto& view = msvc8::AsVectorRuntimeView(storage);
    const std::size_t currentCount = view.begin ? static_cast<std::size_t>(view.end - view.begin) : 0u;

    if (requestedCount < currentCount) {
      if (view.begin) {
        view.end = view.begin + requestedCount;
      }
      return requestedCount;
    }

    if (requestedCount > currentCount) {
      storage.resize(requestedCount, fillValue);
    }

    return requestedCount;
  }

  /**
   * Address: 0x0054C190 (FUN_0054C190)
   *
   * What it does:
   * Resizes `vector<SAniSkelBoneNameIndex>` to `requestedCount` using one
   * zero-initialized fill lane for growth.
   */
  [[maybe_unused]] [[nodiscard]] std::size_t ResizeAniSkelBoneNameIndexVectorWithDefaultFill(
    msvc8::vector<moho::SAniSkelBoneNameIndex>& storage,
    const std::size_t requestedCount
  )
  {
    const moho::SAniSkelBoneNameIndex defaultFill{};
    return ResizeAniSkelBoneNameIndexVectorWithFill(storage, requestedCount, defaultFill);
  }

  /**
   * Address: 0x0054C170 (FUN_0054C170)
   *
   * What it does:
   * Copies one `vector<SAniSkelBoneNameIndex>` begin pointer lane into
   * caller-provided output storage.
   */
  [[maybe_unused]] [[nodiscard]] moho::SAniSkelBoneNameIndex** ReadAniSkelBoneNameIndexBeginPointerLane(
    moho::SAniSkelBoneNameIndex** const outPointer,
    const msvc8::vector_runtime_view<moho::SAniSkelBoneNameIndex>& view
  ) noexcept
  {
    *outPointer = view.begin;
    return outPointer;
  }

  /**
   * Address: 0x0054C180 (FUN_0054C180)
   *
   * What it does:
   * Copies one `vector<SAniSkelBoneNameIndex>` end pointer lane into
   * caller-provided output storage.
   */
  [[maybe_unused]] [[nodiscard]] moho::SAniSkelBoneNameIndex** ReadAniSkelBoneNameIndexEndPointerLane(
    moho::SAniSkelBoneNameIndex** const outPointer,
    const msvc8::vector_runtime_view<moho::SAniSkelBoneNameIndex>& view
  ) noexcept
  {
    *outPointer = view.end;
    return outPointer;
  }

  /**
   * Address: 0x0054C1B0 (FUN_0054C1B0)
   *
   * What it does:
   * Returns active element count for one `vector<SAniSkelBoneNameIndex>`
   * runtime lane when begin storage is present.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t CountAniSkelBoneNameIndexActiveLanes(
    const msvc8::vector_runtime_view<moho::SAniSkelBoneNameIndex>& view
  ) noexcept
  {
    if (view.begin == nullptr) {
      return 0u;
    }

    return static_cast<std::uint32_t>(view.end - view.begin);
  }

  /**
   * Address: 0x0054C200 (FUN_0054C200)
   *
   * What it does:
   * Returns true when one pointer-lane slot currently holds null.
   */
  [[maybe_unused]] [[nodiscard]] bool IsAniSkelBoneNameIndexPointerLaneNull(
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
  [[maybe_unused]] [[nodiscard]] moho::SAniSkelBoneNameIndex** SelectAniSkelBoneNameIndexPointerAt(
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
  [[maybe_unused]] [[nodiscard]] moho::SAniSkelBoneNameIndex** StoreAniSkelBoneNameIndexPointer(
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
  [[maybe_unused]] [[nodiscard]] std::int32_t CountDwordPointerSpan(
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
  [[maybe_unused]] [[nodiscard]] moho::SAniSkelBone** SelectAniSkelBonePointerAt(
    moho::SAniSkelBone** const outPointer,
    moho::SAniSkelBone* const* const basePointer,
    const std::int32_t index
  ) noexcept
  {
    *outPointer = *basePointer + index;
    return outPointer;
  }

  /**
   * Address: 0x0054DC40 (FUN_0054DC40)
   *
   * What it does:
   * Returns capacity element count for one `vector<SAniSkelBone>` runtime view
   * when begin storage is present; otherwise returns zero.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t CountAniSkelBoneCapacityLanes(
    const msvc8::vector_runtime_view<moho::SAniSkelBone>& view
  ) noexcept
  {
    if (view.begin == nullptr) {
      return 0u;
    }

    return static_cast<std::uint32_t>(view.capacityEnd - view.begin);
  }

  /**
   * Address: 0x0054DCA0 (FUN_0054DCA0)
   *
   * What it does:
   * Returns capacity element count for one
   * `vector<SAniSkelBoneNameIndex>` runtime view when begin storage is
   * present; otherwise returns zero.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t CountAniSkelBoneNameIndexCapacityLanes(
    const msvc8::vector_runtime_view<moho::SAniSkelBoneNameIndex>& view
  ) noexcept
  {
    if (view.begin == nullptr) {
      return 0u;
    }

    return static_cast<std::uint32_t>(view.capacityEnd - view.begin);
  }

  /**
   * Address: 0x0054DD20 (FUN_0054DD20)
   *
   * What it does:
   * Advances one `SAniSkelBoneNameIndex` pointer lane by `offset` elements.
   */
  [[maybe_unused]] [[nodiscard]] moho::SAniSkelBoneNameIndex** AdvanceAniSkelBoneNameIndexPointerLane(
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
  [[maybe_unused]] [[nodiscard]] std::int32_t CountDwordPointerSpanSecondary(
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
  [[maybe_unused]] [[nodiscard]] moho::SAniSkelBone** StoreAniSkelBonePointer(
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
  [[maybe_unused]] [[nodiscard]] moho::SAniSkelBone** AdvanceAniSkelBonePointerLane(
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
  [[maybe_unused]] void ResetHeapBackedRangeHandleLaneA(HeapBackedRangeHandleRuntimeView& view) noexcept
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
  [[maybe_unused]] void ResetHeapBackedRangeHandleLaneB(HeapBackedRangeHandleRuntimeView& view) noexcept
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
  [[maybe_unused]] void ResetHeapBackedRangeHandleLaneC(HeapBackedRangeHandleRuntimeView& view) noexcept
  {
    ResetHeapBackedRangeHandle(view);
  }

  /**
   * Address: 0x0054D3B0 (FUN_0054D3B0)
   *
   * What it does:
   * Deletes one heap-allocated runtime object lane.
   */
  [[maybe_unused]] void DeleteRuntimeObjectLaneA(void* const objectStorage) noexcept
  {
    ::operator delete(objectStorage);
  }

  /**
   * Address: 0x0054D710 (FUN_0054D710)
   *
   * What it does:
   * Secondary deleting lane for the same heap-runtime object contract.
   */
  [[maybe_unused]] void DeleteRuntimeObjectLaneB(void* const objectStorage) noexcept
  {
    ::operator delete(objectStorage);
  }

  /**
   * Address: 0x0054DB30 (FUN_0054DB30)
   *
   * What it does:
   * Copies one `SAniSkelBone` payload into destination storage.
   */
  [[maybe_unused]] [[nodiscard]] moho::SAniSkelBone* CopyAniSkelBone(
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
  [[maybe_unused]] [[nodiscard]] moho::SAniSkelBone* CopyAniSkelBoneNonNull(
    moho::SAniSkelBone* const destination,
    const moho::SAniSkelBone* const source
  ) noexcept
  {
    *destination = *source;
    return destination;
  }

  [[maybe_unused]] [[nodiscard]] moho::SAniSkelBone* FillAniSkelBoneRangeFromSingleValueNullable(
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
  [[maybe_unused]] [[nodiscard]] moho::SAniSkelBone* CopyAniSkelBoneCountedNullable(
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
  [[maybe_unused]] [[nodiscard]] moho::SAniSkelBone* FillAniSkelBoneRangeRegisterAdapter(
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
  [[maybe_unused]] [[nodiscard]] moho::SAniSkelBone* CopyAniSkelBoneRangeForwardNonNull(
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
  [[maybe_unused]] [[nodiscard]] moho::SAniSkelBone* FillAniSkelBoneRangeFromSingleNonNull(
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
  [[maybe_unused]] [[nodiscard]] moho::SAniSkelBone* CopyAniSkelBoneRangeBackwardNonNull(
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
  [[maybe_unused]] [[nodiscard]] moho::SAniSkelBone* AdvanceAniSkelBoneAfterCountedNullFill(
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
  [[maybe_unused]] [[nodiscard]] moho::SAniSkelBone** CopyAniSkelBoneTailAndStoreDestinationBegin(
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
  [[maybe_unused]] [[nodiscard]] moho::SAniSkelBone* CopyAniSkelBoneRange(
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
  [[maybe_unused]] [[nodiscard]] moho::SAniSkelBone* CopyAniSkelBoneRangeRegisterAdapterLaneB(
    const moho::SAniSkelBone* const sourceBegin,
    moho::SAniSkelBone* const destinationBegin,
    const moho::SAniSkelBone* const sourceEnd
  ) noexcept
  {
    return CopyAniSkelBoneRange(sourceBegin, destinationBegin, sourceEnd);
  }

  [[maybe_unused]] [[nodiscard]] moho::SAniSkelBoneNameIndex* CopyAniSkelBoneNameIndexRangeNullable(
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
  [[maybe_unused]] [[nodiscard]] moho::SAniSkelBoneNameIndex* CopyAniSkelBoneNameIndexRangeRegisterAdapter(
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
  [[maybe_unused]] [[nodiscard]] moho::SAniSkelBone* CopyAniSkelBoneRangeRegisterAdapter(
    const moho::SAniSkelBone* const sourceBegin,
    const moho::SAniSkelBone* const sourceEnd,
    moho::SAniSkelBone* const destinationBegin
  ) noexcept
  {
    return CopyAniSkelBoneRange(sourceBegin, destinationBegin, sourceEnd);
  }
} // namespace

namespace moho
{
  gpg::RType* CAniSkel::sType = nullptr;

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
      Wm3::MultiplyQuaternionVector(&rotatedPosition, localPosition, bone.mBoneTransform.orient_);

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
} // namespace moho
