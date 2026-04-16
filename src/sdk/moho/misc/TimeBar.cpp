#include "moho/misc/TimeBar.h"

#include "platform/Platform.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <map>
#include <mutex>
#include <vector>

#include "boost/mutex.h"
#include "boost/shared_ptr.h"
#include "gpg/core/containers/CheckedArrayAllocationLanes.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/time/Timer.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "legacy/containers/Vector.h"
#include "moho/math/Vector3f.h"
#include "moho/render/d3d/CD3DFont.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"

namespace moho
{
  // Address: 0x00F57E5C (ren_FrameTimeSeconds)
  extern float ren_FrameTimeSeconds;

  namespace
  {
    constexpr std::int32_t kTimeBarHistoryCapacity = 10000;
    constexpr std::uint32_t kDefaultThreadColorTag = 0xFFFFFFFFu;
    constexpr std::int32_t kFontPointSize = 10;
    constexpr const char* kFontFaceName = "Times New Roman";
    constexpr float kMinWindowSeconds = 0.000001f;
    constexpr float kLabelPadding = 2.0f;

    struct TimeBarEventView
    {
      const STimeBarEventRecord* mRecord;
      std::int64_t mStartCycles;
      std::int64_t mEndCycles;
    };

    struct TimeBarTrackLayout
    {
      const char* mName;
      float mRowY;
    };

    struct TimeBarTrackNodeHeadRuntimeView
    {
      std::uint32_t parent = 0;      // +0x00
      std::uint32_t left = 0;        // +0x04
      std::uint32_t right = 0;       // +0x08
      std::uint8_t reserved0C[0x8]{}; // +0x0C
      std::uint8_t color = 0;        // +0x14
      std::uint8_t isNil = 0;        // +0x15
      std::uint8_t reserved16[0x2]{}; // +0x16
    };
    static_assert(
      offsetof(TimeBarTrackNodeHeadRuntimeView, color) == 0x14,
      "TimeBarTrackNodeHeadRuntimeView::color offset must be 0x14"
    );
    static_assert(
      offsetof(TimeBarTrackNodeHeadRuntimeView, isNil) == 0x15,
      "TimeBarTrackNodeHeadRuntimeView::isNil offset must be 0x15"
    );
    static_assert(sizeof(TimeBarTrackNodeHeadRuntimeView) == 0x18, "TimeBarTrackNodeHeadRuntimeView size must be 0x18");

    /**
     * Address: 0x004E99A0 (FUN_004E99A0)
     *
     * What it does:
     * Allocates and zero-seeds one 24-byte tree-head node used by the
     * time-bar track-name map lane, preserving color/isNil defaults.
     */
    [[maybe_unused]] [[nodiscard]] TimeBarTrackNodeHeadRuntimeView* AllocateTimeBarTrackNodeHeadRuntime()
    {
      auto* const node = static_cast<TimeBarTrackNodeHeadRuntimeView*>(gpg::core::legacy::AllocateChecked24ByteLane(1u));
      if (node != nullptr) {
        node->parent = 0;
      }
      if (node != reinterpret_cast<TimeBarTrackNodeHeadRuntimeView*>(-4)) {
        node->left = 0;
      }
      if (node != reinterpret_cast<TimeBarTrackNodeHeadRuntimeView*>(-8)) {
        node->right = 0;
      }
      node->color = 1;
      node->isNil = 0;
      return node;
    }

    struct CaseInsensitiveCStringLess
    {
      [[nodiscard]] bool operator()(const char* lhs, const char* rhs) const noexcept
      {
        if (lhs == rhs) {
          return false;
        }
        if (!lhs) {
          return rhs != nullptr;
        }
        if (!rhs) {
          return false;
        }
        return gpg::STR_CompareNoCase(lhs, rhs) < 0;
      }
    };

    using TimeBarTrackMap = std::map<const char*, TimeBarTrackLayout, CaseInsensitiveCStringLess>;

    /**
     * Address: 0x004E8EB0 (FUN_004E8EB0, timebar track map lower-bound helper)
     *
     * What it does:
     * Finds the case-insensitive lower-bound insertion point for one event-name
     * key in the track-layout map.
     */
    [[nodiscard]] TimeBarTrackMap::iterator FindTimeBarTrackLowerBound(
      TimeBarTrackMap& tracks,
      const char* const eventName
    )
    {
      return tracks.lower_bound(eventName);
    }

    struct TimeBarState
    {
      boost::mutex mLock;
      STimeBarThreadInfo mThreadListSentinel;
      std::array<STimeBarEventRecord, kTimeBarHistoryCapacity> mHistory;
      std::int32_t mOldestHistoryIndex;
      std::int32_t mNextHistoryIndex;

      TimeBarState()
        : mLock{}
        , mThreadListSentinel{}
        , mHistory{}
        , mOldestHistoryIndex(0)
        , mNextHistoryIndex(0)
      {
        mThreadListSentinel.mPrevNode = &mThreadListSentinel;
        mThreadListSentinel.mNextNode = &mThreadListSentinel;
        mThreadListSentinel.mCurrentSection = nullptr;
        mThreadListSentinel.mColorTag = kDefaultThreadColorTag;
      }
    };

    struct IntrusiveLinkRuntime
    {
      IntrusiveLinkRuntime* next = nullptr; // +0x00
      IntrusiveLinkRuntime* prev = nullptr; // +0x04
    };
    static_assert(sizeof(IntrusiveLinkRuntime) == 0x08, "IntrusiveLinkRuntime size must be 0x08");

    struct PointerSlotRuntime
    {
      void* value = nullptr; // +0x00
    };
    static_assert(sizeof(PointerSlotRuntime) == 0x04, "PointerSlotRuntime size must be 0x04");

    struct PointerPairRuntime
    {
      void* first = nullptr;  // +0x00
      void* second = nullptr; // +0x04
    };
    static_assert(sizeof(PointerPairRuntime) == 0x08, "PointerPairRuntime size must be 0x08");

    struct Element24SpanRuntime
    {
      STimeBarEventRecord* begin = nullptr; // +0x00
      STimeBarEventRecord* end = nullptr;   // +0x04
    };
    static_assert(sizeof(Element24SpanRuntime) == 0x08, "Element24SpanRuntime size must be 0x08");

    struct Element24CursorRuntime
    {
      STimeBarEventRecord* base = nullptr; // +0x00
      std::int32_t index = 0;              // +0x04
    };
    static_assert(sizeof(Element24CursorRuntime) == 0x08, "Element24CursorRuntime size must be 0x08");

    struct Element24StorageRuntime
    {
      STimeBarEventRecord* begin = nullptr; // +0x00
    };
    static_assert(sizeof(Element24StorageRuntime) == 0x04, "Element24StorageRuntime size must be 0x04");

    struct TimeBarRingStateRuntime
    {
      std::uint8_t reserved0[0x3A980]{}; // +0x000000
      std::int32_t oldestIndex = 0;      // +0x03A980
      std::int32_t nextIndex = 0;        // +0x03A984
    };
    static_assert(
      offsetof(TimeBarRingStateRuntime, oldestIndex) == 0x3A980,
      "TimeBarRingStateRuntime::oldestIndex offset must be 0x3A980"
    );
    static_assert(
      offsetof(TimeBarRingStateRuntime, nextIndex) == 0x3A984,
      "TimeBarRingStateRuntime::nextIndex offset must be 0x3A984"
    );

    struct TimeBarRingHandleRuntime
    {
      TimeBarRingStateRuntime* owner = nullptr; // +0x00
      std::int32_t index = 0;                   // +0x04
    };
    static_assert(sizeof(TimeBarRingHandleRuntime) == 0x08, "TimeBarRingHandleRuntime size must be 0x08");

    struct InlineElement24Storage1000Runtime
    {
      STimeBarEventRecord* begin = nullptr;   // +0x00
      STimeBarEventRecord* current = nullptr; // +0x04
      STimeBarEventRecord* end = nullptr;     // +0x08
      STimeBarEventRecord* origin = nullptr;  // +0x0C
      STimeBarEventRecord storage[1000]{};    // +0x10
    };
    static_assert(offsetof(InlineElement24Storage1000Runtime, storage) == 0x10, "storage offset must be 0x10");
    static_assert(sizeof(InlineElement24Storage1000Runtime) == 0x5DD0, "InlineElement24Storage1000Runtime size must be 0x5DD0");

    struct Element24RangeRuntime
    {
      STimeBarEventRecord* begin = nullptr;   // +0x00
      STimeBarEventRecord* current = nullptr; // +0x04
      STimeBarEventRecord* end = nullptr;     // +0x08
      STimeBarEventRecord* origin = nullptr;  // +0x0C
    };
    static_assert(sizeof(Element24RangeRuntime) == 0x10, "Element24RangeRuntime size must be 0x10");

    /**
     * Address: 0x004E5470 (FUN_004E5470)
     *
     * What it does:
     * Advances one pointer slot to the first pointer lane of the object it
     * currently references.
     */
    [[maybe_unused]] PointerSlotRuntime* AdvancePointerSlotToPointeeNext(PointerSlotRuntime* const slot) noexcept
    {
      slot->value = *reinterpret_cast<void**>(slot->value);
      return slot;
    }

    /**
     * Address: 0x004E6900 (FUN_004E6900)
     *
     * What it does:
     * Initializes one 24-byte event record from six scalar/pointer lanes.
     */
    [[maybe_unused]] STimeBarEventRecord* InitializeTimeBarEventRecordFromRawLanes(
      STimeBarEventRecord* const outRecord,
      const std::uint32_t startCycleLo,
      const std::uint32_t startCycleHi,
      const std::uint32_t endCycleLo,
      const std::uint32_t endCycleHi,
      const char* const name,
      const std::uint32_t colorTag
    ) noexcept
    {
      outRecord->mStartCycleLo = startCycleLo;
      outRecord->mStartCycleHi = startCycleHi;
      outRecord->mEndCycleLo = endCycleLo;
      outRecord->mEndCycleHi = endCycleHi;
      outRecord->mName = name;
      outRecord->mColorTag = colorTag;
      return outRecord;
    }

    /**
     * Address: 0x004E6930 (FUN_004E6930)
     *
     * What it does:
     * Initializes one event record using the section start-cycle/name lanes
     * and explicit end-cycle/color lanes.
     */
    [[maybe_unused]] STimeBarEventRecord* InitializeTimeBarEventRecordFromSectionStartAndEndLanes(
      STimeBarEventRecord* const outRecord,
      const CTimeBarSection* const section,
      const std::uint32_t endCycleLo,
      const std::uint32_t endCycleHi,
      const std::uint32_t colorTag
    ) noexcept
    {
      outRecord->mStartCycleLo = section->mStartCycleLo;
      outRecord->mStartCycleHi = section->mStartCycleHi;
      outRecord->mEndCycleLo = endCycleLo;
      outRecord->mEndCycleHi = endCycleHi;
      outRecord->mName = section->mName;
      outRecord->mColorTag = colorTag;
      return outRecord;
    }

    /**
     * Address: 0x004E7000 (FUN_004E7000)
     *
     * What it does:
     * Initializes one intrusive link node as a self-linked sentinel.
     */
    [[maybe_unused]] IntrusiveLinkRuntime* InitializeIntrusiveLinkSelfA(IntrusiveLinkRuntime* const link) noexcept
    {
      link->prev = link;
      link->next = link;
      return link;
    }

    /**
     * Address: 0x004E7010 (FUN_004E7010)
     *
     * What it does:
     * Unlinks one intrusive list node from its neighbors and re-seeds it as a
     * self-linked sentinel.
     */
    [[maybe_unused]] IntrusiveLinkRuntime* UnlinkIntrusiveLinkAndResetA(IntrusiveLinkRuntime* const link) noexcept
    {
      link->next->prev = link->prev;
      link->prev->next = link->next;
      link->prev = link;
      link->next = link;
      return link;
    }

    /**
     * Address: 0x004E7030 (FUN_004E7030)
     *
     * What it does:
     * Initializes one intrusive link node as a self-linked sentinel.
     */
    [[maybe_unused]] IntrusiveLinkRuntime* InitializeIntrusiveLinkSelfB(IntrusiveLinkRuntime* const link) noexcept
    {
      link->prev = link;
      link->next = link;
      return link;
    }

    /**
     * Address: 0x004E7040 (FUN_004E7040)
     *
     * What it does:
     * Loads the intrusive link `prev` pointer into one pointer slot.
     */
    [[maybe_unused]] PointerSlotRuntime* LoadPointerSlotFromLinkPrev(
      PointerSlotRuntime* const outSlot,
      const IntrusiveLinkRuntime* const link
    ) noexcept
    {
      outSlot->value = link->prev;
      return outSlot;
    }

    /**
     * Address: 0x004E7050 (FUN_004E7050)
     *
     * What it does:
     * Initializes one pointer slot from one pointer lane.
     */
    [[maybe_unused]] PointerSlotRuntime* InitializePointerSlotFromPointerA(
      PointerSlotRuntime* const outSlot,
      void* const value
    ) noexcept
    {
      outSlot->value = value;
      return outSlot;
    }

    /**
     * Address: 0x004E7080 (FUN_004E7080)
     *
     * What it does:
     * Checks whether writing one additional event would make next-index collide
     * with oldest-index in the fixed 10000-entry history ring.
     */
    [[maybe_unused]] bool IsTimeBarHistoryRingFullOnNextWrite(const TimeBarRingStateRuntime* const state) noexcept
    {
      return ((state->nextIndex + 1) % kTimeBarHistoryCapacity) == state->oldestIndex;
    }

    /**
     * Address: 0x004E70F0 (FUN_004E70F0)
     *
     * What it does:
     * Advances the oldest-index modulo history capacity and returns one wrap
     * carry lane.
     */
    [[maybe_unused]] std::int32_t AdvanceTimeBarHistoryOldestIndexWithWrapCount(TimeBarRingStateRuntime* const state) noexcept
    {
      const std::int32_t linearIndex = state->oldestIndex + 1;
      state->oldestIndex = linearIndex % kTimeBarHistoryCapacity;
      return linearIndex / kTimeBarHistoryCapacity;
    }

    /**
     * Address: 0x004E7110 (FUN_004E7110)
     *
     * What it does:
     * Initializes one ring-handle lane from the current oldest index.
     */
    [[maybe_unused]] TimeBarRingHandleRuntime* InitializeTimeBarRingHandleFromOldestIndex(
      TimeBarRingHandleRuntime* const outHandle,
      TimeBarRingStateRuntime* const state
    ) noexcept
    {
      outHandle->owner = state;
      outHandle->index = state->oldestIndex;
      return outHandle;
    }

    /**
     * Address: 0x004E7120 (FUN_004E7120)
     *
     * What it does:
     * Initializes one ring-handle lane from the current next index.
     */
    [[maybe_unused]] TimeBarRingHandleRuntime* InitializeTimeBarRingHandleFromNextIndex(
      TimeBarRingHandleRuntime* const outHandle,
      TimeBarRingStateRuntime* const state
    ) noexcept
    {
      outHandle->owner = state;
      outHandle->index = state->nextIndex;
      return outHandle;
    }

    /**
     * Address: 0x004E7260 (FUN_004E7260)
     *
     * What it does:
     * Returns one signed element count for a 24-byte element span lane.
     */
    [[maybe_unused]] std::int32_t CountElement24RangeLength(const Element24SpanRuntime* const span) noexcept
    {
      const auto spanBytes = reinterpret_cast<const std::uint8_t*>(span->end)
                           - reinterpret_cast<const std::uint8_t*>(span->begin);
      return static_cast<std::int32_t>(spanBytes / static_cast<std::ptrdiff_t>(sizeof(STimeBarEventRecord)));
    }

    /**
     * Address: 0x004E7330 (FUN_004E7330)
     *
     * What it does:
     * Resolves one element pointer from base-plus-index lanes for 24-byte
     * records.
     */
    [[maybe_unused]] STimeBarEventRecord* GetElement24PointerFromCursorA(const Element24CursorRuntime* const cursor) noexcept
    {
      return cursor->base + cursor->index;
    }

    /**
     * Address: 0x004E7340 (FUN_004E7340)
     *
     * What it does:
     * Resolves one element pointer from base-plus-index lanes for 24-byte
     * records.
     */
    [[maybe_unused]] STimeBarEventRecord* GetElement24PointerFromCursorB(const Element24CursorRuntime* const cursor) noexcept
    {
      return cursor->base + cursor->index;
    }

    /**
     * Address: 0x004E7350 (FUN_004E7350)
     *
     * What it does:
     * Moves one 24-byte cursor index backward by one slot modulo 10000.
     */
    [[maybe_unused]] Element24CursorRuntime* MoveElement24CursorBackwardModCapacity(Element24CursorRuntime* const cursor) noexcept
    {
      cursor->index = (cursor->index + (kTimeBarHistoryCapacity - 1)) % kTimeBarHistoryCapacity;
      return cursor;
    }

    /**
     * Address: 0x004E7370 (FUN_004E7370)
     *
     * What it does:
     * Compares two 24-byte cursor lanes for index inequality.
     */
    [[maybe_unused]] bool AreElement24CursorIndicesDifferent(
      const Element24CursorRuntime* const lhs,
      const Element24CursorRuntime* const rhs
    ) noexcept
    {
      return lhs->index != rhs->index;
    }

    /**
     * Address: 0x004E73A0 (FUN_004E73A0)
     *
     * What it does:
     * Unlinks one intrusive list node from its neighbors and re-seeds it as a
     * self-linked sentinel.
     */
    [[maybe_unused]] IntrusiveLinkRuntime* UnlinkIntrusiveLinkAndResetB(IntrusiveLinkRuntime* const link) noexcept
    {
      link->next->prev = link->prev;
      link->prev->next = link->next;
      link->prev = link;
      link->next = link;
      return link;
    }

    /**
     * Address: 0x004E73D0 (FUN_004E73D0)
     *
     * What it does:
     * Drains the oldest-index lane toward the current next-index by advancing
     * modulo history capacity, then resets both ring indices to zero.
     */
    [[maybe_unused]] std::int32_t ResetTimeBarHistoryIndicesAfterDrain(TimeBarRingStateRuntime* const state) noexcept
    {
      if (state->oldestIndex != state->nextIndex) {
        std::int32_t drainedIndex = state->oldestIndex;
        do {
          drainedIndex = (state->oldestIndex + 1) % kTimeBarHistoryCapacity;
          state->oldestIndex = drainedIndex;
        } while (drainedIndex != state->nextIndex);
      }

      state->oldestIndex = 0;
      state->nextIndex = 0;
      return 0;
    }

    /**
     * Address: 0x004E7410 (FUN_004E7410)
     *
     * What it does:
     * Checks whether oldest-index equals next-index in the fixed history ring.
     */
    [[maybe_unused]] bool IsTimeBarHistoryRingEmpty(const TimeBarRingStateRuntime* const state) noexcept
    {
      return state->oldestIndex == state->nextIndex;
    }

    /**
     * Address: 0x004E75D0 (FUN_004E75D0)
     *
     * What it does:
     * Initializes one pointer slot from one pointer lane.
     */
    [[maybe_unused]] PointerSlotRuntime* InitializePointerSlotFromPointerB(
      PointerSlotRuntime* const outSlot,
      void* const value
    ) noexcept
    {
      outSlot->value = value;
      return outSlot;
    }

    /**
     * Address: 0x004E75E0 (FUN_004E75E0)
     *
     * What it does:
     * Initializes one two-pointer lane from source pointer lanes.
     */
    [[maybe_unused]] PointerPairRuntime* InitializePointerPairFromLanesA(
      PointerPairRuntime* const outPair,
      void* const first,
      void* const second
    ) noexcept
    {
      outPair->first = first;
      outPair->second = second;
      return outPair;
    }

    /**
     * Address: 0x004E7630 (FUN_004E7630)
     *
     * What it does:
     * Unlinks one intrusive list node from its neighbors and re-seeds it as a
     * self-linked sentinel.
     */
    [[maybe_unused]] IntrusiveLinkRuntime* UnlinkIntrusiveLinkAndResetC(IntrusiveLinkRuntime* const link) noexcept
    {
      link->next->prev = link->prev;
      link->prev->next = link->next;
      link->prev = link;
      link->next = link;
      return link;
    }

    /**
     * Address: 0x004E7780 (FUN_004E7780)
     *
     * What it does:
     * Initializes one pointer slot from one pointer lane.
     */
    [[maybe_unused]] PointerSlotRuntime* InitializePointerSlotFromPointerC(
      PointerSlotRuntime* const outSlot,
      void* const value
    ) noexcept
    {
      outSlot->value = value;
      return outSlot;
    }

    /**
     * Address: 0x004E7790 (FUN_004E7790)
     *
     * What it does:
     * Initializes one two-pointer lane from source pointer lanes.
     */
    [[maybe_unused]] PointerPairRuntime* InitializePointerPairFromLanesB(
      PointerPairRuntime* const outPair,
      void* const first,
      void* const second
    ) noexcept
    {
      outPair->first = first;
      outPair->second = second;
      return outPair;
    }

    /**
     * Address: 0x004E8DD0 (FUN_004E8DD0)
     *
     * What it does:
     * Initializes one inline 1000-entry 24-byte range descriptor and points
     * begin/current/origin to its internal storage lane.
     */
    [[maybe_unused]] InlineElement24Storage1000Runtime* InitializeInlineElement24BufferRangeWithInternalStorage1000(
      InlineElement24Storage1000Runtime* const outRange
    ) noexcept
    {
      outRange->begin = outRange->storage;
      outRange->current = outRange->storage;
      outRange->end = outRange->storage + 1000;
      outRange->origin = outRange->storage;
      return outRange;
    }

    /**
     * Address: 0x004E8E20 (FUN_004E8E20)
     *
     * What it does:
     * Resolves one element pointer from one base storage lane plus one
     * 24-byte-record index.
     */
    [[maybe_unused]] STimeBarEventRecord* GetElement24PointerFromStorageAndIndex(
      const std::int32_t index,
      const Element24StorageRuntime* const storage
    ) noexcept
    {
      return storage->begin + index;
    }

    /**
     * Address: 0x004E8E90 (FUN_004E8E90)
     *
     * What it does:
     * Loads one pointer slot from the pointee referenced by a pair's second
     * lane.
     */
    [[maybe_unused]] PointerSlotRuntime* LoadPointerSlotFromPairSecondPointee(
      PointerSlotRuntime* const outSlot,
      const PointerPairRuntime* const sourcePair
    ) noexcept
    {
      outSlot->value = *reinterpret_cast<void**>(sourcePair->second);
      return outSlot;
    }

    /**
     * Address: 0x004E8EA0 (FUN_004E8EA0)
     *
     * What it does:
     * Loads one pointer slot from a pair's second pointer lane.
     */
    [[maybe_unused]] PointerSlotRuntime* LoadPointerSlotFromPairSecond(
      PointerSlotRuntime* const outSlot,
      const PointerPairRuntime* const sourcePair
    ) noexcept
    {
      outSlot->value = sourcePair->second;
      return outSlot;
    }

    /**
     * Address: 0x004E9030 (FUN_004E9030)
     *
     * What it does:
     * Initializes one 1000-entry 24-byte range descriptor from external
     * contiguous storage lanes.
     */
    [[maybe_unused]] Element24RangeRuntime* InitializeElement24BufferRangeFromExternalStorage1000(
      Element24RangeRuntime* const outRange,
      STimeBarEventRecord* const storage
    ) noexcept
    {
      outRange->begin = storage;
      outRange->current = storage;
      outRange->end = storage + 1000;
      outRange->origin = storage;
      return outRange;
    }

    /**
     * Address: 0x004E9320 (FUN_004E9320)
     *
     * What it does:
     * Initializes one pointer slot from one pointer lane.
     */
    [[maybe_unused]] PointerSlotRuntime* InitializePointerSlotFromPointerD(
      PointerSlotRuntime* const outSlot,
      void* const value
    ) noexcept
    {
      outSlot->value = value;
      return outSlot;
    }

    TimeBarState* gTimeBarState = nullptr;
    std::once_flag gTimeBarStateInitOnce;

    [[nodiscard]] std::int64_t CombineCycles(const std::uint32_t lo, const std::uint32_t hi) noexcept
    {
      const std::uint64_t value = (static_cast<std::uint64_t>(hi) << 32) | lo;
      return static_cast<std::int64_t>(value);
    }

    void SplitCycles(const std::int64_t cycles, std::uint32_t& lo, std::uint32_t& hi) noexcept
    {
      lo = static_cast<std::uint32_t>(cycles & 0xFFFFFFFFll);
      hi = static_cast<std::uint32_t>((static_cast<std::uint64_t>(cycles) >> 32) & 0xFFFFFFFFull);
    }

    [[nodiscard]] std::int64_t QueryCurrentCycles()
    {
      const gpg::time::Timer& timer = gpg::time::GetSystemTimer();
      return timer.ElapsedCycles();
    }

    void InitializeTimeBarState()
    {
      gTimeBarState = new TimeBarState{};
    }

    void ShutdownTimeBarStateAtProcessExit()
    {
      delete gTimeBarState;
      gTimeBarState = nullptr;
    }

    /**
     * Address: 0x004E6D00 (FUN_004E6D00)
     *
     * What it does:
     * Performs one-time time-bar runtime initialization and registers process
     * exit teardown for the time-bar global state.
     */
    void EnsureTimeBarRuntimeInitialized()
    {
      std::call_once(gTimeBarStateInitOnce, []() {
        InitializeTimeBarState();
        std::atexit(ShutdownTimeBarStateAtProcessExit);
      });
    }

    [[nodiscard]] TimeBarState& GetTimeBarState()
    {
      EnsureTimeBarRuntimeInitialized();
      return *gTimeBarState;
    }

    void UnlinkThreadInfoNoLock(STimeBarThreadInfo* const info) noexcept
    {
      if (!info || !info->mPrevNode || !info->mNextNode) {
        return;
      }

      info->mPrevNode->mNextNode = info->mNextNode;
      info->mNextNode->mPrevNode = info->mPrevNode;
      info->mPrevNode = info;
      info->mNextNode = info;
    }

    void ReleaseThreadInfo(STimeBarThreadInfo* info) noexcept
    {
      if (!info) {
        return;
      }

      if (gTimeBarState) {
        TimeBarState& state = *gTimeBarState;
        boost::mutex::scoped_lock guard(state.mLock);
        UnlinkThreadInfoNoLock(info);
      }

      delete info;
    }

    struct TimeBarThreadSlot
    {
      STimeBarThreadInfo* mInfo = nullptr;

      ~TimeBarThreadSlot()
      {
        ReleaseThreadInfo(mInfo);
        mInfo = nullptr;
      }
    };

    thread_local TimeBarThreadSlot gThreadSlot;

    void LinkThreadInfoNoLock(TimeBarState& state, STimeBarThreadInfo* const info) noexcept
    {
      STimeBarThreadInfo* const sentinel = &state.mThreadListSentinel;

      info->mPrevNode = sentinel;
      info->mNextNode = sentinel->mNextNode;
      sentinel->mNextNode->mPrevNode = info;
      sentinel->mNextNode = info;
    }

    [[nodiscard]] STimeBarThreadInfo* GetOrCreateThreadInfo(TimeBarState& state)
    {
      if (gThreadSlot.mInfo) {
        return gThreadSlot.mInfo;
      }

      auto* info = new STimeBarThreadInfo{};
      info->mPrevNode = info;
      info->mNextNode = info;
      info->mCurrentSection = nullptr;
      info->mColorTag = kDefaultThreadColorTag;

      {
        boost::mutex::scoped_lock guard(state.mLock);
        LinkThreadInfoNoLock(state, info);
      }

      gThreadSlot.mInfo = info;
      return info;
    }

    /**
     * Address: 0x004E70A0 (FUN_004E70A0)
     *
     * What it does:
     * Writes one event record into the current history write slot and advances
     * the ring write index modulo history capacity.
     */
    [[maybe_unused]] std::int32_t PushTimeBarHistoryRecordAndAdvanceWriteIndex(
      TimeBarState& state,
      const STimeBarEventRecord& record
    ) noexcept
    {
      const std::int32_t writeIndex = state.mNextHistoryIndex;
      state.mHistory[writeIndex] = record;

      const std::int32_t linearNext = writeIndex + 1;
      state.mNextHistoryIndex = linearNext % kTimeBarHistoryCapacity;
      return linearNext / kTimeBarHistoryCapacity;
    }

    /**
     * Address: 0x004E6A20 (FUN_004E6A20)
     *
     * What it does:
     * Pushes one event record into the fixed-size history ring while holding
     * the time-bar mutex and advancing oldest/newest indices on wrap.
     */
    void PushHistoryRecord(TimeBarState& state, const STimeBarEventRecord& record)
    {
      boost::mutex::scoped_lock guard(state.mLock);

      const std::int32_t nextIndex = (state.mNextHistoryIndex + 1) % kTimeBarHistoryCapacity;
      if (nextIndex == state.mOldestHistoryIndex) {
        state.mOldestHistoryIndex = (state.mOldestHistoryIndex + 1) % kTimeBarHistoryCapacity;
      }

      (void)PushTimeBarHistoryRecordAndAdvanceWriteIndex(state, record);
    }

    [[nodiscard]] CD3DPrimBatcher::Vertex MakeVertex(const float x, const float y, const std::uint32_t colorTag)
    {
      CD3DPrimBatcher::Vertex vertex{};
      vertex.mX = x;
      vertex.mY = y;
      vertex.mZ = 0.0f;
      vertex.mColor = colorTag;
      vertex.mU = 0.0f;
      vertex.mV = 0.0f;
      return vertex;
    }

    void DrawPanelRect(
      CD3DPrimBatcher& primBatcher,
      const float left,
      const float top,
      const float right,
      const float bottom,
      const std::uint32_t colorTag
    )
    {
      const CD3DPrimBatcher::Vertex topLeft = MakeVertex(left, top, colorTag);
      const CD3DPrimBatcher::Vertex topRight = MakeVertex(right, top, colorTag);
      const CD3DPrimBatcher::Vertex bottomRight = MakeVertex(right, bottom, colorTag);
      const CD3DPrimBatcher::Vertex bottomLeft = MakeVertex(left, bottom, colorTag);
      primBatcher.DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
    }

    void DrawPanelLine(
      CD3DPrimBatcher& primBatcher,
      const float startX,
      const float startY,
      const float endX,
      const float endY,
      const std::uint32_t colorTag
    )
    {
      const CD3DPrimBatcher::Vertex start = MakeVertex(startX, startY, colorTag);
      const CD3DPrimBatcher::Vertex end = MakeVertex(endX, endY, colorTag);
      primBatcher.DrawLine(start, end);
    }

    void BuildEventViews(const msvc8::vector<STimeBarEventRecord>& events, std::vector<TimeBarEventView>& outEventViews)
    {
      outEventViews.clear();
      outEventViews.reserve(events.size());

      for (const STimeBarEventRecord& eventRecord : events) {
        TimeBarEventView view{};
        view.mRecord = &eventRecord;
        view.mStartCycles = CombineCycles(eventRecord.mStartCycleLo, eventRecord.mStartCycleHi);
        view.mEndCycles = CombineCycles(eventRecord.mEndCycleLo, eventRecord.mEndCycleHi);
        outEventViews.push_back(view);
      }
    }

    void BuildTrackLayout(
      CD3DFont& font,
      const std::vector<TimeBarEventView>& eventViews,
      const float top,
      TimeBarTrackMap& outTracks,
      float& outMaxLabelWidth
    )
    {
      outTracks.clear();
      outMaxLabelWidth = 0.0f;

      for (const TimeBarEventView& eventView : eventViews) {
        if (!eventView.mRecord->mName) {
          continue;
        }

        auto insertPos = FindTimeBarTrackLowerBound(outTracks, eventView.mRecord->mName);
        const bool alreadyPresent =
          insertPos != outTracks.end()
          && insertPos->first != nullptr
          && gpg::STR_CompareNoCase(insertPos->first, eventView.mRecord->mName) == 0;

        if (!alreadyPresent) {
          outTracks.emplace_hint(
            insertPos,
            eventView.mRecord->mName,
            TimeBarTrackLayout{
              eventView.mRecord->mName,
              0.0f,
            }
          );
        }
      }

      float rowY = top + font.mAscent + 1.0f;
      for (auto& [name, track] : outTracks) {
        track.mName = name;
        track.mRowY = rowY;
        rowY += font.mHeight + font.mExternalLeading;
        outMaxLabelWidth = std::max(outMaxLabelWidth, font.GetAdvance(name, -1) + kLabelPadding);
      }
    }

    void RenderTrackLabels(
      CD3DFont& font,
      CD3DPrimBatcher& primBatcher,
      const float left,
      const float maxLabelWidth,
      const TimeBarTrackMap& tracks
    )
    {
      const Vector3f xAxis{1.0f, 0.0f, 0.0f};
      const Vector3f yAxis{0.0f, 1.0f, 0.0f};
      constexpr std::uint32_t kLabelColor = 0xFFFFFFFFu;
      const float maxAdvance = std::numeric_limits<float>::infinity();

      for (const auto& [name, track] : tracks) {
        if (!name) {
          continue;
        }

        const float labelWidth = font.GetAdvance(name, -1);
        const Vector3f origin{left + maxLabelWidth - labelWidth, track.mRowY, 0.0f};
        (void)font.Render(name, &primBatcher, origin, xAxis, yAxis, kLabelColor, 0.0f, maxAdvance);
      }
    }
  } // namespace

  std::int64_t CTimeBarSection::GetStartCycle() const noexcept
  {
    return CombineCycles(mStartCycleLo, mStartCycleHi);
  }

  void CTimeBarSection::SetStartCycle(const std::int64_t cycles) noexcept
  {
    SplitCycles(cycles, mStartCycleLo, mStartCycleHi);
  }

  /**
   * Address: 0x004E6DF0 (FUN_004E6DF0)
   * Mangled: ??0CTimeBarSection@Moho@@QAE@PBD@Z
   *
   * char const *
   *
   * What it does:
   * Opens a scoped time-bar section on the current thread and snapshots the parent segment.
   */
  CTimeBarSection::CTimeBarSection(const char* const name)
  {
    TimeBarState& state = GetTimeBarState();
    STimeBarThreadInfo* const threadInfo = GetOrCreateThreadInfo(state);

    mName = name;
    mPreviousSection = threadInfo->mCurrentSection;
    threadInfo->mCurrentSection = this;

    const std::int64_t nowCycles = QueryCurrentCycles();
    if (mPreviousSection) {
      STimeBarEventRecord parentSplitRecord{};
      SplitCycles(mPreviousSection->GetStartCycle(), parentSplitRecord.mStartCycleLo, parentSplitRecord.mStartCycleHi);
      SplitCycles(nowCycles, parentSplitRecord.mEndCycleLo, parentSplitRecord.mEndCycleHi);
      parentSplitRecord.mName = mPreviousSection->mName;
      parentSplitRecord.mColorTag = threadInfo->mColorTag;
      PushHistoryRecord(state, parentSplitRecord);
    }

    SetStartCycle(nowCycles);
  }

  /**
   * Address: 0x004E6E90 (FUN_004E6E90)
   * Mangled: ??1CTimeBarSection@Moho@@QAE@XZ
   *
   * void
   *
   * What it does:
   * Closes the current scope, records its elapsed cycle range, and restores the parent section.
   */
  CTimeBarSection::~CTimeBarSection()
  {
    TimeBarState& state = GetTimeBarState();
    STimeBarThreadInfo* const threadInfo = GetOrCreateThreadInfo(state);

    const std::int64_t nowCycles = QueryCurrentCycles();

    STimeBarEventRecord completedRecord{};
    SplitCycles(GetStartCycle(), completedRecord.mStartCycleLo, completedRecord.mStartCycleHi);
    SplitCycles(nowCycles, completedRecord.mEndCycleLo, completedRecord.mEndCycleHi);
    completedRecord.mName = mName;
    completedRecord.mColorTag = threadInfo->mColorTag;
    PushHistoryRecord(state, completedRecord);

    if (mPreviousSection) {
      mPreviousSection->SetStartCycle(nowCycles);
      threadInfo->mCurrentSection = mPreviousSection;
    } else {
      threadInfo->mCurrentSection = nullptr;
    }
  }

  /**
   * Address: 0x004E6F30 (FUN_004E6F30)
   * Mangled: ?TIME_TimeBarEvent@Moho@@YAXPBD@Z
   *
   * char const *
   *
   * What it does:
   * Emits an instantaneous named marker event into the global time-bar history.
   */
  void TIME_TimeBarEvent(const char* const name)
  {
    TimeBarState& state = GetTimeBarState();
    STimeBarThreadInfo* const threadInfo = GetOrCreateThreadInfo(state);

    const std::int64_t nowCycles = QueryCurrentCycles();

    STimeBarEventRecord eventRecord{};
    SplitCycles(nowCycles, eventRecord.mStartCycleLo, eventRecord.mStartCycleHi);
    SplitCycles(nowCycles, eventRecord.mEndCycleLo, eventRecord.mEndCycleHi);
    eventRecord.mName = name;
    eventRecord.mColorTag = threadInfo->mColorTag;
    PushHistoryRecord(state, eventRecord);
  }

  /**
   * Address: 0x004E6FD0 (FUN_004E6FD0)
   *
   * int
   *
   * What it does:
   * Updates the current thread's time-bar color tag used for subsequent samples.
   */
  void TIME_SetTimeBarColor(const std::uint32_t colorTag)
  {
    TimeBarState& state = GetTimeBarState();
    STimeBarThreadInfo* const threadInfo = GetOrCreateThreadInfo(state);
    threadInfo->mColorTag = colorTag;
  }

  /**
   * Address: 0x004E6FA0 (FUN_004E6FA0)
   * Address: 0x004E6AE0 (FUN_004E6AE0)
   *
   * msvc8::vector<moho::STimeBarEventRecord> &,float
   *
   * What it does:
   * Captures active sections plus recent history events into `outEvents`, newest-first.
   */
  void TIME_CollectTimeBarEvents(msvc8::vector<STimeBarEventRecord>& outEvents, const float maxAgeSeconds)
  {
    TimeBarState& state = GetTimeBarState();

    // Match the original behavior: reset output each call before collecting.
    outEvents = msvc8::vector<STimeBarEventRecord>{};

    const std::int64_t nowCycles = QueryCurrentCycles();

    boost::mutex::scoped_lock guard(state.mLock);

    for (STimeBarThreadInfo* node = state.mThreadListSentinel.mNextNode; node != &state.mThreadListSentinel;
         node = node->mNextNode) {
      if (!node->mCurrentSection) {
        continue;
      }

      STimeBarEventRecord activeRecord{};
      SplitCycles(node->mCurrentSection->GetStartCycle(), activeRecord.mStartCycleLo, activeRecord.mStartCycleHi);
      SplitCycles(nowCycles, activeRecord.mEndCycleLo, activeRecord.mEndCycleHi);
      activeRecord.mName = node->mCurrentSection->mName;
      activeRecord.mColorTag = node->mColorTag;
      outEvents.push_back(activeRecord);
    }

    std::int32_t historyIndex = state.mNextHistoryIndex;
    while (historyIndex != state.mOldestHistoryIndex) {
      historyIndex = (historyIndex + (kTimeBarHistoryCapacity - 1)) % kTimeBarHistoryCapacity;

      const STimeBarEventRecord& record = state.mHistory[historyIndex];
      if (maxAgeSeconds >= 0.0f) {
        const std::int64_t startCycles = CombineCycles(record.mStartCycleLo, record.mStartCycleHi);
        const float ageSeconds = gpg::time::CyclesToSeconds(nowCycles - startCycles);
        if (ageSeconds > maxAgeSeconds) {
          break;
        }
      }

      outEvents.push_back(record);
    }
  }

  /**
   * Address: 0x004E83A0 (FUN_004E83A0)
   * Mangled: ?TIME_RenderTimeBars@Moho@@YAXPAVCD3DPrimBatcher@1@MMMMM@Z
   *
   * Moho::CD3DPrimBatcher *,float,float,float,float
   *
   * What it does:
   * Renders the time-bar panel background, labels, and clipped event timeline segments.
   */
  void TIME_RenderTimeBars(
    CD3DPrimBatcher* const primBatcher, const float left, const float top, const float width, const float height
  )
  {
    if (!primBatcher) {
      return;
    }

    const float right = left + width;
    const float bottom = top + height;

    const boost::shared_ptr<CD3DBatchTexture> whiteTexture = CD3DBatchTexture::FromSolidColor(0xFFFFFFFFu);
    primBatcher->SetTexture(whiteTexture);
    DrawPanelRect(*primBatcher, left, top, right, bottom, 0xFFFFFFFFu);

    boost::SharedPtrRaw<CD3DFont> rawFont = CD3DFont::Create(kFontPointSize, kFontFaceName);
    const boost::shared_ptr<CD3DFont> font = boost::SharedPtrFromRawRetained(rawFont);
    rawFont.release();

    msvc8::vector<STimeBarEventRecord> events;
    TIME_CollectTimeBarEvents(events, ren_FrameTimeSeconds);

    std::vector<TimeBarEventView> eventViews;
    BuildEventViews(events, eventViews);

    TimeBarTrackMap tracks;
    float maxLabelWidth = 0.0f;
    if (font) {
      BuildTrackLayout(*font, eventViews, top, tracks, maxLabelWidth);
      RenderTrackLabels(*font, *primBatcher, left, maxLabelWidth, tracks);
    }

    primBatcher->SetTexture(whiteTexture);

    DrawPanelLine(*primBatcher, left, top, right, top, 0xFFFFFFFFu);
    DrawPanelLine(*primBatcher, right, top, right, bottom, 0xFFFFFFFFu);
    DrawPanelLine(*primBatcher, right, bottom, left, bottom, 0xFFFFFFFFu);
    DrawPanelLine(*primBatcher, left, bottom, left, top, 0xFFFFFFFFu);

    if (eventViews.empty()) {
      return;
    }

    const std::int64_t nowCycles = QueryCurrentCycles();
    const float windowSeconds = std::max(ren_FrameTimeSeconds, kMinWindowSeconds);
    const std::int64_t windowCycles = std::max<std::int64_t>(1, gpg::time::SecondsToCycles(windowSeconds));
    const float timelineLeft = left + maxLabelWidth;
    const float timelineRight = right;
    const float timelineRightClamp = timelineRight - 1.0f;
    const float timelineWidth = std::max(0.0f, width - maxLabelWidth);
    const double cyclesToPixels = static_cast<double>(timelineWidth) / static_cast<double>(windowCycles);
    const double xBase = static_cast<double>(timelineRight) - (cyclesToPixels * static_cast<double>(nowCycles));

    for (const TimeBarEventView& eventView : eventViews) {
      const char* const eventName = eventView.mRecord->mName;
      if (!eventName) {
        continue;
      }

      const auto trackIt = tracks.find(eventName);
      if (trackIt == tracks.end()) {
        continue;
      }

      const float rowY = trackIt->second.mRowY;

      float startX = static_cast<float>(xBase + cyclesToPixels * static_cast<double>(eventView.mStartCycles));
      startX = std::min(startX, timelineRightClamp);
      startX = std::max(startX, timelineLeft);

      float endX = static_cast<float>(xBase + cyclesToPixels * static_cast<double>(eventView.mEndCycles));
      endX = std::min(endX, timelineRight);
      endX = std::max(endX, timelineLeft);
      endX = std::max(endX, startX + 1.0f);

      DrawPanelLine(*primBatcher, startX, rowY, endX, rowY, eventView.mRecord->mColorTag);
    }
  }
} // namespace moho
