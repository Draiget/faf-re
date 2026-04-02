#include "moho/sim/SDelayedSubVizInfoReflection.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"

#pragma init_seg(lib)

namespace
{
  using DelayedSubVizVector = msvc8::vector<moho::SDelayedSubVizInfo>;
  using DelayedSubVizVectorType = gpg::RVectorType<moho::SDelayedSubVizInfo>;

  alignas(DelayedSubVizVectorType) unsigned char gDelayedSubVizVectorTypeStorage[sizeof(DelayedSubVizVectorType)];
  bool gDelayedSubVizVectorTypeConstructed = false;

  msvc8::string gDelayedSubVizVectorTypeName;
  bool gDelayedSubVizVectorTypeNameCleanupRegistered = false;

  moho::SDelayedSubVizInfoSerializer gSDelayedSubVizInfoSerializer;
  [[nodiscard]] DelayedSubVizVectorType* AcquireDelayedSubVizVectorType();
  [[nodiscard]] moho::SDelayedSubVizInfo* CopyDelayedSubVizInfoRangeVariant1(
    moho::SDelayedSubVizInfo* destination,
    const moho::SDelayedSubVizInfo* sourceBegin,
    const moho::SDelayedSubVizInfo* sourceEnd
  );
  [[nodiscard]] moho::SDelayedSubVizInfo* FillDelayedSubVizInfoRange(
    const moho::SDelayedSubVizInfo& value,
    moho::SDelayedSubVizInfo* destinationBegin,
    moho::SDelayedSubVizInfo* destinationEnd
  );

  template <class T>
  [[nodiscard]] std::size_t RuntimeVectorSize(const msvc8::vector<T>& storage) noexcept
  {
    const auto& view = msvc8::AsVectorRuntimeView(storage);
    return view.begin ? static_cast<std::size_t>(view.end - view.begin) : 0u;
  }

  template <class T>
  [[nodiscard]] std::size_t RuntimeVectorCapacity(const msvc8::vector<T>& storage) noexcept
  {
    const auto& view = msvc8::AsVectorRuntimeView(storage);
    return view.begin ? static_cast<std::size_t>(view.capacityEnd - view.begin) : 0u;
  }

  template <class T>
  [[nodiscard]] T* RuntimeVectorPointerAt(msvc8::vector<T>& storage, const std::size_t index) noexcept
  {
    auto& view = msvc8::AsVectorRuntimeView(storage);
    return view.begin + index;
  }

  template <class T>
  void RuntimeVectorAssignPointers(
    msvc8::vector<T>& storage, T* const begin, const std::size_t size, const std::size_t capacity
  ) noexcept
  {
    auto& view = msvc8::AsVectorRuntimeView(storage);
    view.begin = begin;
    view.end = begin + size;
    view.capacityEnd = begin + capacity;
  }

  /**
   * Address: 0x00508040 (FUN_00508040, delayed-sub-viz no-op lane)
   */
  [[maybe_unused]] void noop_DelayedSubVizLaneVariant1()
  {
  }

  /**
   * Address: 0x005080A0 (FUN_005080A0, delayed-sub-viz no-op lane)
   */
  [[maybe_unused]] void noop_DelayedSubVizLaneVariant2(int)
  {
  }

  /**
   * Address: 0x005080B0 (FUN_005080B0, delayed-sub-viz no-op lane)
   */
  [[maybe_unused]] void noop_DelayedSubVizLaneVariant3()
  {
  }

  /**
   * Address: 0x005087C0 (FUN_005087C0, delayed-sub-viz no-op lane)
   */
  [[maybe_unused]] void noop_DelayedSubVizLaneVariant4()
  {
  }

  /**
   * Address: 0x00508460 (FUN_00508460, delayed-sub-viz vector max-count lane)
   *
   * What it does:
   * Returns the max element count guard used by legacy `vector<T>` growth
   * checks for 0x14-byte elements.
   */
  [[nodiscard]] constexpr std::size_t DelayedSubVizVectorMaxCountVariant2() noexcept
  {
    return 0x0CCCCCCCu;
  }

  /**
   * Address: 0x005088A0 (FUN_005088A0, delayed-sub-viz vector max-count lane duplicate)
   *
   * What it does:
   * Returns the same max element count guard as `FUN_00508460`.
   */
  [[nodiscard]] constexpr std::size_t DelayedSubVizVectorMaxCountVariant1() noexcept
  {
    return DelayedSubVizVectorMaxCountVariant2();
  }

  /**
   * Address: 0x00508CB0 (FUN_00508CB0, delayed-sub-viz element-buffer allocation)
   *
   * What it does:
   * Allocates raw storage for `count` delayed-sub-viz elements with overflow
   * guard semantics matching the binary lane.
   */
  [[nodiscard]] void* AllocateDelayedSubVizElementStorage(const std::size_t count)
  {
    if (count > 0u && count > (static_cast<std::size_t>(std::numeric_limits<unsigned int>::max()) / sizeof(moho::SDelayedSubVizInfo))) {
      throw std::bad_alloc{};
    }

    return ::operator new(count * sizeof(moho::SDelayedSubVizInfo));
  }

  /**
   * Address: 0x005087E0 (FUN_005087E0, delayed-sub-viz conditional allocation)
   *
   * What it does:
   * Allocates one delayed-sub-viz element buffer when `elementCount` is
   * non-zero; otherwise forwards to `operator new(0)`.
   */
  [[maybe_unused]] [[nodiscard]] void* AllocateDelayedSubVizStorage(const std::size_t elementCount)
  {
    if (elementCount) {
      return AllocateDelayedSubVizElementStorage(elementCount);
    }
    return ::operator new(0);
  }

  /**
   * Address: 0x005087D0 (FUN_005087D0, delayed-sub-viz delete lane)
   */
  [[maybe_unused]] void DeleteDelayedSubVizStorage(void* const storage)
  {
    ::operator delete(storage);
  }

  /**
   * Address: 0x00508050 (FUN_00508050, delayed-sub-viz vector-storage reset)
   *
   * What it does:
   * Releases one raw delayed-sub-viz storage triplet and nulls begin/end/capacity lanes.
   */
  [[maybe_unused]] void ReleaseDelayedSubVizVectorStorage(DelayedSubVizVector& storage)
  {
    auto& view = msvc8::AsVectorRuntimeView(storage);
    if (view.begin) {
      DeleteDelayedSubVizStorage(view.begin);
    }
    view.begin = nullptr;
    view.end = nullptr;
    view.capacityEnd = nullptr;
  }

  /**
   * Address: 0x00508740 (FUN_00508740, delayed-sub-viz vector too-long throw)
   *
   * What it does:
   * Throws the legacy MSVC vector-length exception lane.
   */
  [[noreturn]] void ThrowDelayedSubVizVectorTooLong()
  {
    throw std::length_error("vector<T> too long");
  }

  [[nodiscard]] gpg::RType* ResolveVector3fType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Vector3<float>));
    }
    return cached;
  }

  /**
   * Address: 0x00508270 (FUN_00508270, delayed-sub-viz RTTI cache resolve)
   */
  [[nodiscard]] gpg::RType* ResolveSDelayedSubVizInfoType()
  {
    gpg::RType* type = moho::SDelayedSubVizInfo::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SDelayedSubVizInfo));
      moho::SDelayedSubVizInfo::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00508290 (FUN_00508290, intel-grid RTTI cache resolve)
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* ResolveCIntelGridType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CIntelGrid));
    }
    return cached;
  }

  struct DelayedSubVizPointerSlot
  {
    moho::SDelayedSubVizInfo* element;
  };

  /**
   * Address: 0x00508830 (FUN_00508830, delayed-sub-viz pointer-slot assign duplicate)
   */
  [[maybe_unused]] DelayedSubVizPointerSlot* AssignDelayedSubVizPointerSlotVariant2(
    DelayedSubVizPointerSlot* const outSlot, moho::SDelayedSubVizInfo* const value
  )
  {
    GPG_ASSERT(outSlot != nullptr);
    if (!outSlot) {
      return nullptr;
    }
    outSlot->element = value;
    return outSlot;
  }

  /**
   * Address: 0x00508800 (FUN_00508800, delayed-sub-viz pointer-slot from base+index)
   */
  [[maybe_unused]] DelayedSubVizPointerSlot* SetDelayedSubVizPointerSlotFromBaseAndIndex(
    DelayedSubVizPointerSlot* const outSlot, const DelayedSubVizPointerSlot* const baseSlot, const int index
  )
  {
    GPG_ASSERT(outSlot != nullptr);
    GPG_ASSERT(baseSlot != nullptr);
    if (!outSlot || !baseSlot) {
      return outSlot;
    }

    outSlot->element = baseSlot->element ? (baseSlot->element + index) : nullptr;
    return outSlot;
  }

  /**
   * Address: 0x00508810 (FUN_00508810, delayed-sub-viz pointer-slot distance)
   */
  [[maybe_unused]] [[nodiscard]] int DelayedSubVizPointerSlotDistanceVariant1(
    const DelayedSubVizPointerSlot* const lhs, const DelayedSubVizPointerSlot* const rhs
  )
  {
    GPG_ASSERT(lhs != nullptr);
    GPG_ASSERT(rhs != nullptr);
    if (!lhs || !rhs || !lhs->element || !rhs->element) {
      return 0;
    }
    return static_cast<int>(lhs->element - rhs->element);
  }

  /**
   * Address: 0x005088C0 (FUN_005088C0, delayed-sub-viz pointer-slot distance duplicate)
   */
  [[maybe_unused]] [[nodiscard]] int DelayedSubVizPointerSlotDistanceVariant2(
    const DelayedSubVizPointerSlot* const lhs, const DelayedSubVizPointerSlot* const rhs
  )
  {
    return DelayedSubVizPointerSlotDistanceVariant1(lhs, rhs);
  }

  /**
   * Address: 0x005088B0 (FUN_005088B0, delayed-sub-viz pointer-slot advance by count)
   */
  [[maybe_unused]] DelayedSubVizPointerSlot* AdvanceDelayedSubVizPointerSlotByVariant1(
    DelayedSubVizPointerSlot* const slot, const int count
  )
  {
    GPG_ASSERT(slot != nullptr);
    if (slot) {
      slot->element += count;
    }
    return slot;
  }

  /**
   * Address: 0x005088E0 (FUN_005088E0, delayed-sub-viz pointer-slot advance by count duplicate)
   */
  [[maybe_unused]] DelayedSubVizPointerSlot* AdvanceDelayedSubVizPointerSlotByVariant2(
    DelayedSubVizPointerSlot* const slot, const int count
  )
  {
    return AdvanceDelayedSubVizPointerSlotByVariant1(slot, count);
  }

  /**
   * Address: 0x00508840 (FUN_00508840, delayed-sub-viz element copy lane)
   */
  [[maybe_unused]] [[nodiscard]] moho::SDelayedSubVizInfo* CopyDelayedSubVizInfoVariant1(
    moho::SDelayedSubVizInfo* const destination, const moho::SDelayedSubVizInfo* const source
  )
  {
    GPG_ASSERT(destination != nullptr);
    GPG_ASSERT(source != nullptr);
    if (destination && source) {
      *destination = *source;
    }
    return destination;
  }

  /**
   * Address: 0x00508080 (FUN_00508080, delayed-sub-viz default-fill helper)
   */
  [[maybe_unused]] [[nodiscard]] moho::SDelayedSubVizInfo* FillDefaultDelayedSubVizInfoSpan(
    const std::size_t fillCount, moho::SDelayedSubVizInfo* const destination, const std::size_t returnAdvanceCount
  )
  {
    moho::SDelayedSubVizInfo* cursor = destination;
    const moho::SDelayedSubVizInfo zeroValue{};
    for (std::size_t i = 0; i < fillCount; ++i) {
      if (cursor) {
        *cursor = zeroValue;
      }
      if (cursor) {
        ++cursor;
      }
    }

    return destination ? (destination + returnAdvanceCount) : nullptr;
  }

  /**
   * Address: 0x00508860 (FUN_00508860, delayed-sub-viz tail erase helper)
   *
   * What it does:
   * Erases `[newEnd, oldEnd)` from vector storage and writes `newEnd` to
   * output pointer slot.
   */
  [[maybe_unused]] DelayedSubVizPointerSlot* EraseDelayedSubVizVectorTail(
    DelayedSubVizVector& storage, DelayedSubVizPointerSlot* const outSlot, moho::SDelayedSubVizInfo* const newEnd
  )
  {
    auto& view = msvc8::AsVectorRuntimeView(storage);
    if (newEnd != view.end && newEnd != nullptr) {
      storage.erase(newEnd, view.end);
    }

    if (outSlot) {
      outSlot->element = newEnd;
    }
    return outSlot;
  }

  /**
   * Address: 0x00508230 (FUN_00508230, delayed-sub-viz pointer-slot assign)
   */
  [[maybe_unused]] DelayedSubVizPointerSlot* AssignDelayedSubVizPointerSlotVariant1(
    DelayedSubVizPointerSlot* const outSlot, moho::SDelayedSubVizInfo* const value
  )
  {
    GPG_ASSERT(outSlot != nullptr);
    if (!outSlot) {
      return nullptr;
    }
    outSlot->element = value;
    return outSlot;
  }

  /**
   * Address: 0x00508240 (FUN_00508240, delayed-sub-viz pointer-slot dereference)
   */
  [[maybe_unused]] [[nodiscard]] moho::SDelayedSubVizInfo* ReadDelayedSubVizPointerSlot(
    const DelayedSubVizPointerSlot* const slot
  )
  {
    GPG_ASSERT(slot != nullptr);
    return slot ? slot->element : nullptr;
  }

  /**
   * Address: 0x00508250 (FUN_00508250, delayed-sub-viz pointer-slot increment)
   */
  [[maybe_unused]] DelayedSubVizPointerSlot* AdvanceDelayedSubVizPointerSlot(
    DelayedSubVizPointerSlot* const slot
  )
  {
    GPG_ASSERT(slot != nullptr);
    if (slot) {
      slot->element += 1;
    }
    return slot;
  }

  /**
   * Address: 0x00508260 (FUN_00508260, delayed-sub-viz pointer-slot equality)
   */
  [[maybe_unused]] [[nodiscard]] bool AreDelayedSubVizPointerSlotsEqual(
    const DelayedSubVizPointerSlot* const lhs, const DelayedSubVizPointerSlot* const rhs
  )
  {
    GPG_ASSERT(lhs != nullptr);
    GPG_ASSERT(rhs != nullptr);
    return lhs && rhs ? (lhs->element == rhs->element) : (lhs == rhs);
  }

  /**
   * Address: 0x00508470 (FUN_00508470, delayed-sub-viz vector index -> pointer)
   */
  [[nodiscard]] moho::SDelayedSubVizInfo* DelayedSubVizVectorPointerAt(
    DelayedSubVizVector& storage, const std::size_t index
  ) noexcept
  {
    return RuntimeVectorPointerAt(storage, index);
  }

  /**
   * Address: 0x005082B0 (FUN_005082B0, delayed-sub-viz vector reserve-exact)
   *
   * What it does:
   * Ensures exact storage capacity for at least `requiredCapacity` entries,
   * preserving existing elements and element count.
   */
  [[nodiscard]] moho::SDelayedSubVizInfo* EnsureDelayedSubVizVectorCapacity(
    DelayedSubVizVector& storage, const std::size_t requiredCapacity
  )
  {
    if (requiredCapacity > DelayedSubVizVectorMaxCountVariant1()) {
      ThrowDelayedSubVizVectorTooLong();
    }

    auto& view = msvc8::AsVectorRuntimeView(storage);
    const std::size_t currentCapacity = RuntimeVectorCapacity(storage);
    if (currentCapacity >= requiredCapacity) {
      return view.begin;
    }

    const std::size_t currentSize = RuntimeVectorSize(storage);
    moho::SDelayedSubVizInfo* const oldBegin = view.begin;
    moho::SDelayedSubVizInfo* const newBegin =
      static_cast<moho::SDelayedSubVizInfo*>(AllocateDelayedSubVizStorage(requiredCapacity));

    for (std::size_t i = 0; i < currentSize; ++i) {
      (void)CopyDelayedSubVizInfoVariant1(&newBegin[i], &oldBegin[i]);
    }

    if (oldBegin) {
      DeleteDelayedSubVizStorage(oldBegin);
    }

    RuntimeVectorAssignPointers(storage, newBegin, currentSize, requiredCapacity);
    return newBegin;
  }

  /**
   * Address: 0x00508480 (FUN_00508480, delayed-sub-viz vector insert-fill)
   *
   * What it does:
   * Inserts `count` copies of `value` at `insertPosition`, growing storage when
   * needed, and returns pointer to first inserted element.
   */
  [[nodiscard]] moho::SDelayedSubVizInfo* InsertDelayedSubVizInfoCopies(
    DelayedSubVizVector& storage,
    const std::size_t count,
    moho::SDelayedSubVizInfo* const insertPosition,
    const moho::SDelayedSubVizInfo& value
  )
  {
    auto& view = msvc8::AsVectorRuntimeView(storage);
    const std::size_t currentSize = RuntimeVectorSize(storage);
    const std::size_t currentCapacity = RuntimeVectorCapacity(storage);

    if (count == 0u) {
      return insertPosition;
    }

    if (DelayedSubVizVectorMaxCountVariant1() - currentSize < count) {
      ThrowDelayedSubVizVectorTooLong();
    }

    std::size_t insertIndex = currentSize;
    if (view.begin && insertPosition) {
      if (insertPosition <= view.begin) {
        insertIndex = 0u;
      } else if (insertPosition >= view.end) {
        insertIndex = currentSize;
      } else {
        insertIndex = static_cast<std::size_t>(insertPosition - view.begin);
      }
    }

    if (currentCapacity >= currentSize + count) {
      for (std::size_t i = currentSize; i > insertIndex; --i) {
        view.begin[(i - 1u) + count] = view.begin[i - 1u];
      }

      (void)FillDelayedSubVizInfoRange(value, view.begin + insertIndex, view.begin + insertIndex + count);

      view.end += count;
      return view.begin + insertIndex;
    }

    std::size_t grownCapacity = 0u;
    if (DelayedSubVizVectorMaxCountVariant1() - (currentCapacity >> 1u) >= currentCapacity) {
      grownCapacity = currentCapacity + (currentCapacity >> 1u);
    }
    if (grownCapacity < currentSize + count) {
      grownCapacity = currentSize + count;
    }

    moho::SDelayedSubVizInfo* const oldBegin = view.begin;
    moho::SDelayedSubVizInfo* const newBegin =
      static_cast<moho::SDelayedSubVizInfo*>(AllocateDelayedSubVizStorage(grownCapacity));

    (void)CopyDelayedSubVizInfoRangeVariant1(newBegin, oldBegin, oldBegin + insertIndex);
    (void)FillDelayedSubVizInfoRange(value, newBegin + insertIndex, newBegin + insertIndex + count);
    (void)CopyDelayedSubVizInfoRangeVariant1(newBegin + insertIndex + count, oldBegin + insertIndex, oldBegin + currentSize);

    if (oldBegin) {
      DeleteDelayedSubVizStorage(oldBegin);
    }

    RuntimeVectorAssignPointers(storage, newBegin, currentSize + count, grownCapacity);
    return newBegin + insertIndex;
  }

  /**
   * Address: 0x005083C0 (FUN_005083C0, delayed-sub-viz vector resize with fill)
   *
   * What it does:
   * Resizes vector payload to `desiredCount` by appending fill entries or
   * erasing tail entries.
   */
  [[nodiscard]] moho::SDelayedSubVizInfo* ResizeDelayedSubVizVectorWithFill(
    DelayedSubVizVector& storage, const std::size_t desiredCount, const moho::SDelayedSubVizInfo& fillValue
  )
  {
    auto& view = msvc8::AsVectorRuntimeView(storage);
    const std::size_t currentSize = RuntimeVectorSize(storage);

    if (currentSize < desiredCount) {
      return InsertDelayedSubVizInfoCopies(storage, desiredCount - currentSize, view.end, fillValue);
    }

    if (desiredCount < currentSize && view.begin) {
      DelayedSubVizPointerSlot out{};
      (void)EraseDelayedSubVizVectorTail(storage, &out, view.begin + desiredCount);
    }

    return view.begin;
  }

  /**
   * Address: 0x00508A80 (FUN_00508A80, delayed-sub-viz no-op lane)
   */
  [[maybe_unused]] void noop_DelayedSubVizLaneVariant5()
  {
  }

  /**
   * Address: 0x00508A90 (FUN_00508A90, delayed-sub-viz no-op lane)
   */
  [[maybe_unused]] void noop_DelayedSubVizLaneVariant6()
  {
  }

  /**
   * Address: 0x00508B00 (FUN_00508B00, delayed-sub-viz no-op lane)
   */
  [[maybe_unused]] void noop_DelayedSubVizLaneVariant7()
  {
  }

  /**
   * Address: 0x00508AA0 (FUN_00508AA0, delayed-sub-viz span transform helper)
   *
   * What it does:
   * Moves one overlapping range `[first, middle)` so it ends at `last`.
   */
  [[maybe_unused]] [[nodiscard]] moho::SDelayedSubVizInfo* MoveDelayedSubVizInfoSpanToEnd(
    moho::SDelayedSubVizInfo* const first,
    moho::SDelayedSubVizInfo* const middle,
    moho::SDelayedSubVizInfo* const last
  )
  {
    if (!first || !middle || !last || first == middle) {
      return last;
    }

    const std::size_t count = static_cast<std::size_t>(middle - first);
    std::memmove(last - count, first, count * sizeof(moho::SDelayedSubVizInfo));
    return last;
  }

  /**
   * Address: 0x00508B10 (FUN_00508B10, delayed-sub-viz element copy helper)
   */
  [[maybe_unused]] [[nodiscard]] moho::SDelayedSubVizInfo* CopyDelayedSubVizInfoVariant2(
    moho::SDelayedSubVizInfo* const destination, const moho::SDelayedSubVizInfo* const source
  )
  {
    return CopyDelayedSubVizInfoVariant1(destination, source);
  }

  /**
   * Address: 0x00508BE0 (FUN_00508BE0, delayed-sub-viz range-copy helper)
   *
   * What it does:
   * Copies one source range `[sourceBegin, sourceEnd)` into destination and
   * returns one-past-last written destination.
   */
  [[maybe_unused]] [[nodiscard]] moho::SDelayedSubVizInfo* CopyDelayedSubVizInfoRangeVariant1(
    moho::SDelayedSubVizInfo* destination,
    const moho::SDelayedSubVizInfo* sourceBegin,
    const moho::SDelayedSubVizInfo* const sourceEnd
  )
  {
    while (sourceBegin != sourceEnd) {
      (void)CopyDelayedSubVizInfoVariant1(destination, sourceBegin);
      ++destination;
      ++sourceBegin;
    }
    return destination;
  }

  /**
   * Address: 0x00508C40 (FUN_00508C40, delayed-sub-viz fill range helper)
   *
   * What it does:
   * Fills `[destinationBegin, destinationEnd)` with copies of `value`.
   */
  [[maybe_unused]] [[nodiscard]] moho::SDelayedSubVizInfo* FillDelayedSubVizInfoRange(
    const moho::SDelayedSubVizInfo& value,
    moho::SDelayedSubVizInfo* destinationBegin,
    moho::SDelayedSubVizInfo* const destinationEnd
  )
  {
    while (destinationBegin != destinationEnd) {
      (void)CopyDelayedSubVizInfoVariant1(destinationBegin, &value);
      ++destinationBegin;
    }
    return destinationBegin;
  }

  /**
   * Address: 0x00508C10 (FUN_00508C10, delayed-sub-viz zero-fill range helper)
   */
  [[maybe_unused]] [[nodiscard]] moho::SDelayedSubVizInfo* ZeroFillDelayedSubVizInfoRange(
    moho::SDelayedSubVizInfo* const destinationBegin, moho::SDelayedSubVizInfo* const destinationEnd
  )
  {
    const moho::SDelayedSubVizInfo zeroValue{};
    return FillDelayedSubVizInfoRange(zeroValue, destinationBegin, destinationEnd);
  }

  /**
   * Address: 0x00508C80 (FUN_00508C80, delayed-sub-viz overlap move helper)
   *
   * What it does:
   * Moves `[sourceBegin, sourceEnd)` so the moved range ends at `destinationEnd`.
   */
  [[maybe_unused]] void MoveDelayedSubVizInfoRangeToEnd(
    moho::SDelayedSubVizInfo* const sourceBegin,
    moho::SDelayedSubVizInfo* const sourceEnd,
    moho::SDelayedSubVizInfo* const destinationEnd
  )
  {
    if (!sourceBegin || !sourceEnd || !destinationEnd || sourceBegin == sourceEnd) {
      return;
    }

    const std::size_t count = static_cast<std::size_t>(sourceEnd - sourceBegin);
    std::memmove(destinationEnd - count, sourceBegin, count * sizeof(moho::SDelayedSubVizInfo));
  }

  /**
   * Address: 0x00508B70 (FUN_00508B70, delayed-sub-viz storage pointer swap)
   */
  [[maybe_unused]] moho::SDelayedSubVizInfoVectorStorage* SwapDelayedSubVizStoragePointersVariant1(
    moho::SDelayedSubVizInfoVectorStorage* const lhs, moho::SDelayedSubVizInfoVectorStorage* const rhs
  )
  {
    GPG_ASSERT(lhs != nullptr);
    GPG_ASSERT(rhs != nullptr);
    if (!lhs || !rhs) {
      return lhs;
    }

    moho::SDelayedSubVizInfo* temp = rhs->mStart;
    rhs->mStart = lhs->mStart;
    lhs->mStart = temp;

    temp = rhs->mFinish;
    rhs->mFinish = lhs->mFinish;
    lhs->mFinish = temp;

    temp = rhs->mCapacity;
    rhs->mCapacity = lhs->mCapacity;
    lhs->mCapacity = temp;
    return lhs;
  }

  /**
   * Address: 0x00508DB0 (FUN_00508DB0, delayed-sub-viz storage pointer swap duplicate)
   */
  [[maybe_unused]] moho::SDelayedSubVizInfoVectorStorage* SwapDelayedSubVizStoragePointersVariant2(
    moho::SDelayedSubVizInfoVectorStorage* const lhs, moho::SDelayedSubVizInfoVectorStorage* const rhs
  )
  {
    return SwapDelayedSubVizStoragePointersVariant1(lhs, rhs);
  }

  /**
   * Address: 0x00508D00 (FUN_00508D00, delayed-sub-viz vector-type runtime cleanup)
   *
   * What it does:
   * Clears owned reflection field/bases vectors for delayed-sub-viz vector type.
   */
  [[maybe_unused]] void ResetDelayedSubVizVectorTypeRuntime(DelayedSubVizVectorType& type)
  {
    type.fields_ = msvc8::vector<gpg::RField>{};
    type.bases_ = msvc8::vector<gpg::RField>{};
  }

  /**
   * Address: 0x00508DE0 (FUN_00508DE0, delayed-sub-viz vector-type construct/register)
   */
  [[nodiscard]] gpg::RType* ConstructAndRegisterDelayedSubVizVectorType()
  {
    DelayedSubVizVectorType* const type = AcquireDelayedSubVizVectorType();
    gpg::PreRegisterRType(typeid(msvc8::vector<moho::SDelayedSubVizInfo>), type);
    return type;
  }

  /**
   * Address: 0x00508EF0 (FUN_00508EF0, delayed-sub-viz vector-type destroy helper)
   */
  [[maybe_unused]] DelayedSubVizVectorType* DestroyDelayedSubVizVectorType(
    DelayedSubVizVectorType* const type, const bool deleteSelf
  )
  {
    if (!type) {
      return nullptr;
    }

    type->~DelayedSubVizVectorType();
    if (deleteSelf) {
      ::operator delete(type);
    }
    return type;
  }

  /**
   * Address: 0x00508F50 (FUN_00508F50, delayed-sub-viz storage deep-copy helper)
   */
  [[maybe_unused]] moho::SDelayedSubVizInfoVectorStorage* CopyDelayedSubVizStorageDeep(
    const moho::SDelayedSubVizInfoVectorStorage& source,
    moho::SDelayedSubVizInfoVectorStorage* const destination
  )
  {
    GPG_ASSERT(destination != nullptr);
    if (!destination) {
      return nullptr;
    }

    destination->mStart = nullptr;
    destination->mFinish = nullptr;
    destination->mCapacity = nullptr;

    const std::size_t count = source.mStart ? static_cast<std::size_t>(source.mFinish - source.mStart) : 0u;
    if (count == 0u) {
      return destination;
    }

    moho::SDelayedSubVizInfo* const copied =
      static_cast<moho::SDelayedSubVizInfo*>(AllocateDelayedSubVizStorage(count));
    moho::SDelayedSubVizInfo* const copiedEnd =
      CopyDelayedSubVizInfoRangeVariant1(copied, source.mStart, source.mFinish);

    destination->mStart = copied;
    destination->mFinish = copiedEnd;
    destination->mCapacity = copied + count;
    return destination;
  }

  /**
   * Address: 0x00509880 (FUN_00509880, delayed-sub-viz element copy helper)
   */
  [[maybe_unused]] [[nodiscard]] moho::SDelayedSubVizInfo* CopyDelayedSubVizInfoUnchecked(
    moho::SDelayedSubVizInfo* const destination, const moho::SDelayedSubVizInfo* const source
  )
  {
    GPG_ASSERT(destination != nullptr);
    GPG_ASSERT(source != nullptr);
    if (!destination || !source) {
      return destination;
    }

    *destination = *source;
    return destination;
  }

  /**
   * Address: 0x005098A0 (FUN_005098A0, delayed-sub-viz nullable element copy helper)
   */
  [[maybe_unused]] [[nodiscard]] moho::SDelayedSubVizInfo* CopyDelayedSubVizInfoIfNotNullVariant1(
    moho::SDelayedSubVizInfo* const destination, const moho::SDelayedSubVizInfo* const source
  )
  {
    if (destination && source) {
      *destination = *source;
    }
    return destination;
  }

  /**
   * Address: 0x00509A40 (FUN_00509A40, delayed-sub-viz nullable element copy helper duplicate)
   */
  [[maybe_unused]] [[nodiscard]] moho::SDelayedSubVizInfo* CopyDelayedSubVizInfoIfNotNullVariant2(
    moho::SDelayedSubVizInfo* const destination, const moho::SDelayedSubVizInfo* const source
  )
  {
    return CopyDelayedSubVizInfoIfNotNullVariant1(destination, source);
  }

  /**
   * Address: 0x005093E0 (FUN_005093E0, delayed-sub-viz forward range copy helper)
   *
   * What it does:
   * Copies `[sourceBegin, sourceEnd)` into `destination` and returns one-past-last
   * written destination pointer.
   */
  [[maybe_unused]] [[nodiscard]] moho::SDelayedSubVizInfo* CopyDelayedSubVizInfoRangeVariant2(
    moho::SDelayedSubVizInfo* destination,
    const moho::SDelayedSubVizInfo* sourceBegin,
    const moho::SDelayedSubVizInfo* const sourceEnd
  )
  {
    if (!destination) {
      return nullptr;
    }

    while (sourceBegin != sourceEnd) {
      *destination = *sourceBegin;
      ++destination;
      ++sourceBegin;
    }
    return destination;
  }

  /**
   * Address: 0x00509C70 (FUN_00509C70, delayed-sub-viz forward range copy helper duplicate)
   */
  [[maybe_unused]] [[nodiscard]] moho::SDelayedSubVizInfo* CopyDelayedSubVizInfoRangeVariant7(
    moho::SDelayedSubVizInfo* const destination,
    const moho::SDelayedSubVizInfo* const sourceBegin,
    const moho::SDelayedSubVizInfo* const sourceEnd
  )
  {
    return CopyDelayedSubVizInfoRangeVariant2(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x00509CB0 (FUN_00509CB0, delayed-sub-viz forward range copy helper duplicate)
   */
  [[maybe_unused]] [[nodiscard]] moho::SDelayedSubVizInfo* CopyDelayedSubVizInfoRangeVariant8(
    moho::SDelayedSubVizInfo* const destination,
    const moho::SDelayedSubVizInfo* const sourceBegin,
    const moho::SDelayedSubVizInfo* const sourceEnd
  )
  {
    return CopyDelayedSubVizInfoRangeVariant2(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x00509D20 (FUN_00509D20, delayed-sub-viz forward range copy helper duplicate)
   */
  [[maybe_unused]] [[nodiscard]] moho::SDelayedSubVizInfo* CopyDelayedSubVizInfoRangeVariant9(
    moho::SDelayedSubVizInfo* const destination,
    const moho::SDelayedSubVizInfo* const sourceBegin,
    const moho::SDelayedSubVizInfo* const sourceEnd
  )
  {
    return CopyDelayedSubVizInfoRangeVariant2(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x00509820 (FUN_00509820, delayed-sub-viz forward range copy wrapper)
   */
  [[maybe_unused]] [[nodiscard]] moho::SDelayedSubVizInfo* CopyDelayedSubVizInfoRangeVariant3(
    moho::SDelayedSubVizInfo* const destination,
    const moho::SDelayedSubVizInfo* const sourceBegin,
    const moho::SDelayedSubVizInfo* const sourceEnd
  )
  {
    return CopyDelayedSubVizInfoRangeVariant7(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x00509920 (FUN_00509920, delayed-sub-viz forward range copy wrapper)
   */
  [[maybe_unused]] [[nodiscard]] moho::SDelayedSubVizInfo* CopyDelayedSubVizInfoRangeVariant4(
    moho::SDelayedSubVizInfo* const destination,
    const moho::SDelayedSubVizInfo* const sourceBegin,
    const moho::SDelayedSubVizInfo* const sourceEnd
  )
  {
    return CopyDelayedSubVizInfoRangeVariant9(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x005099F0 (FUN_005099F0, delayed-sub-viz forward range copy wrapper)
   */
  [[maybe_unused]] [[nodiscard]] moho::SDelayedSubVizInfo* CopyDelayedSubVizInfoRangeVariant5(
    moho::SDelayedSubVizInfo* const destination,
    const moho::SDelayedSubVizInfo* const sourceBegin,
    const moho::SDelayedSubVizInfo* const sourceEnd
  )
  {
    return CopyDelayedSubVizInfoRangeVariant7(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x00509A80 (FUN_00509A80, delayed-sub-viz forward range copy wrapper)
   */
  [[maybe_unused]] [[nodiscard]] moho::SDelayedSubVizInfo* CopyDelayedSubVizInfoRangeVariant6(
    moho::SDelayedSubVizInfo* const destination,
    const moho::SDelayedSubVizInfo* const sourceBegin,
    const moho::SDelayedSubVizInfo* const sourceEnd
  )
  {
    return CopyDelayedSubVizInfoRangeVariant9(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x00509850 (FUN_00509850, delayed-sub-viz tail copy wrapper)
   */
  [[maybe_unused]] [[nodiscard]] moho::SDelayedSubVizInfo* CopyDelayedSubVizInfoTail(
    moho::SDelayedSubVizInfo* const destination,
    const moho::SDelayedSubVizInfo* const sourceBegin,
    const moho::SDelayedSubVizInfo* const sourceEnd
  )
  {
    return CopyDelayedSubVizInfoRangeVariant8(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x00509970 (FUN_00509970, delayed-sub-viz backward overlap move helper)
   *
   * What it does:
   * Moves `[sourceBegin, sourceEnd)` so the moved range ends at `destinationEnd`
   * by copying from the tail backward.
   */
  [[maybe_unused]] [[nodiscard]] moho::SDelayedSubVizInfo* CopyDelayedSubVizInfoRangeBackward(
    moho::SDelayedSubVizInfo* destinationEnd,
    const moho::SDelayedSubVizInfo* const sourceBegin,
    const moho::SDelayedSubVizInfo* sourceEnd
  )
  {
    if (!destinationEnd) {
      return nullptr;
    }

    while (sourceEnd != sourceBegin) {
      --sourceEnd;
      --destinationEnd;
      *destinationEnd = *sourceEnd;
    }
    return destinationEnd;
  }

  /**
   * Address: 0x005091B0 (FUN_005091B0, delayed-sub-viz export begin pointer helper)
   */
  [[maybe_unused]] moho::SDelayedSubVizInfo** ExportDelayedSubVizBeginPointer(
    moho::SDelayedSubVizInfo** const outBegin, const DelayedSubVizVector& storage
  )
  {
    if (outBegin) {
      *outBegin = msvc8::AsVectorRuntimeView(storage).begin;
    }
    return outBegin;
  }

  /**
   * Address: 0x005091C0 (FUN_005091C0, delayed-sub-viz export end pointer helper)
   */
  [[maybe_unused]] moho::SDelayedSubVizInfo** ExportDelayedSubVizEndPointer(
    moho::SDelayedSubVizInfo** const outEnd, const DelayedSubVizVector& storage
  )
  {
    if (outEnd) {
      *outEnd = msvc8::AsVectorRuntimeView(storage).end;
    }
    return outEnd;
  }

  /**
   * Address: 0x005091D0 (FUN_005091D0, delayed-sub-viz in-place normalize helper)
   *
   * What it does:
   * Runs a no-op self-copy over current live span and keeps `end` synchronized
   * with the resulting one-past-last pointer.
   */
  [[maybe_unused]] moho::SDelayedSubVizInfo* NormalizeDelayedSubVizFinish(DelayedSubVizVector& storage)
  {
    auto& view = msvc8::AsVectorRuntimeView(storage);
    if (view.begin != view.end && view.begin) {
      view.end = CopyDelayedSubVizInfoRangeVariant2(view.begin, view.begin, view.end);
    }
    return view.end;
  }

  /**
   * Address: 0x00509010 (FUN_00509010, delayed-sub-viz vector assignment helper)
   *
   * What it does:
   * Assigns one delayed-sub-viz vector storage into another while preserving
   * legacy growth/reuse behavior.
   */
  [[maybe_unused]] DelayedSubVizVector* AssignDelayedSubVizVector(
    DelayedSubVizVector* const destination, const DelayedSubVizVector* const source
  )
  {
    if (!destination || !source || destination == source) {
      return destination;
    }

    auto& destinationView = msvc8::AsVectorRuntimeView(*destination);
    const auto& sourceView = msvc8::AsVectorRuntimeView(*source);

    const std::size_t sourceSize = sourceView.begin ? static_cast<std::size_t>(sourceView.end - sourceView.begin) : 0u;
    if (sourceSize == 0u) {
      (void)NormalizeDelayedSubVizFinish(*destination);
      return destination;
    }

    const std::size_t destinationSize = RuntimeVectorSize(*destination);
    if (sourceSize > destinationSize) {
      const std::size_t destinationCapacity = RuntimeVectorCapacity(*destination);
      if (destinationView.begin && sourceSize <= destinationCapacity) {
        const moho::SDelayedSubVizInfo* const sourceSplit = sourceView.begin + destinationSize;
        if (destinationSize) {
          (void)CopyDelayedSubVizInfoRangeVariant2(destinationView.begin, sourceView.begin, sourceSplit);
        }

        destinationView.end = CopyDelayedSubVizInfoTail(destinationView.end, sourceSplit, sourceView.end);
        return destination;
      }

      ReleaseDelayedSubVizVectorStorage(*destination);
      if (sourceSize && EnsureDelayedSubVizVectorCapacity(*destination, sourceSize)) {
        auto& refreshedView = msvc8::AsVectorRuntimeView(*destination);
        refreshedView.end = CopyDelayedSubVizInfoTail(refreshedView.begin, sourceView.begin, sourceView.end);
      }
      return destination;
    }

    (void)CopyDelayedSubVizInfoRangeVariant2(destinationView.begin, sourceView.begin, sourceView.end);
    destinationView.end = destinationView.begin ? (destinationView.begin + sourceSize) : nullptr;
    return destination;
  }

  /**
   * Address: 0x00509950 (FUN_00509950, delayed-sub-viz zero-width copy helper)
   */
  [[maybe_unused]] [[nodiscard]] moho::SDelayedSubVizInfo* ZeroWidthDelayedSubVizCopy(
    moho::SDelayedSubVizInfo* const destination, const moho::SDelayedSubVizInfo* const sourceCursor
  )
  {
    return CopyDelayedSubVizInfoRangeVariant8(destination, sourceCursor, sourceCursor);
  }

  /**
   * Address: 0x00509A20 (FUN_00509A20, delayed-sub-viz zero-width self copy helper)
   */
  [[maybe_unused]] [[nodiscard]] moho::SDelayedSubVizInfo* ZeroWidthDelayedSubVizSelfCopy(
    moho::SDelayedSubVizInfo* const cursor
  )
  {
    return CopyDelayedSubVizInfoRangeVariant8(cursor, cursor, cursor);
  }

  /**
   * Address: 0x00509AB0 (FUN_00509AB0, delayed-sub-viz first word read helper)
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t ReadDelayedSubVizFirstWord(
    const moho::SDelayedSubVizInfo* const value
  )
  {
    if (!value) {
      return 0u;
    }

    const auto* const raw = reinterpret_cast<const std::uint32_t*>(value);
    return raw[0];
  }

  /**
   * Address: 0x00509C60 (FUN_00509C60, delayed-sub-viz high-byte flag read helper)
   */
  [[maybe_unused]] [[nodiscard]] std::uint8_t ReadHighByteFlagVariant1(const std::uint32_t value) noexcept
  {
    return static_cast<std::uint8_t>((value >> 8u) & 0xFFu);
  }

  /**
   * Address: 0x00509D10 (FUN_00509D10, delayed-sub-viz high-byte flag read helper duplicate)
   */
  [[maybe_unused]] [[nodiscard]] std::uint8_t ReadHighByteFlagVariant2(const std::uint32_t value) noexcept
  {
    return ReadHighByteFlagVariant1(value);
  }

  /**
   * Address: 0x00508B30 (FUN_00508B30, delayed-sub-viz typed read helper)
   */
  [[maybe_unused]] gpg::ReadArchive* ReadDelayedSubVizInfoViaRTypeVariant1(
    gpg::ReadArchive* const archive, void* const object, const gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const elementType = ResolveSDelayedSubVizInfoType();
    if (archive && object && elementType) {
      archive->Read(elementType, object, ownerRef ? *ownerRef : gpg::RRef{});
    }
    return archive;
  }

  /**
   * Address: 0x00508E90 (FUN_00508E90, delayed-sub-viz typed read helper duplicate)
   */
  [[maybe_unused]] void ReadDelayedSubVizInfoViaRTypeVariant2(
    gpg::ReadArchive* const archive, void* const object, const gpg::RRef* const ownerRef
  )
  {
    (void)ReadDelayedSubVizInfoViaRTypeVariant1(archive, object, ownerRef);
  }

  /**
   * Address: 0x00508BA0 (FUN_00508BA0, delayed-sub-viz typed write helper)
   */
  [[maybe_unused]] gpg::WriteArchive* WriteDelayedSubVizInfoViaRTypeVariant1(
    gpg::WriteArchive* const archive, const void* const object, const gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const elementType = ResolveSDelayedSubVizInfoType();
    if (archive && object && elementType) {
      archive->Write(elementType, object, ownerRef ? *ownerRef : gpg::RRef{});
    }
    return archive;
  }

  /**
   * Address: 0x00508EC0 (FUN_00508EC0, delayed-sub-viz typed write helper duplicate)
   */
  [[maybe_unused]] void WriteDelayedSubVizInfoViaRTypeVariant2(
    gpg::WriteArchive* const archive, const void* const object, const gpg::RRef* const ownerRef
  )
  {
    (void)WriteDelayedSubVizInfoViaRTypeVariant1(archive, object, ownerRef);
  }

  /**
   * Address: 0x00508AD0 (FUN_00508AD0, delayed-sub-viz RRef fill helper)
   */
  [[maybe_unused]] gpg::RRef* FillDelayedSubVizRef(
    moho::SDelayedSubVizInfo* const value, gpg::RRef* const outRef
  )
  {
    return gpg::RRef_SDelayedSubVizInfo(outRef, value);
  }

  [[nodiscard]] DelayedSubVizVectorType* AcquireDelayedSubVizVectorType()
  {
    if (!gDelayedSubVizVectorTypeConstructed) {
      new (gDelayedSubVizVectorTypeStorage) DelayedSubVizVectorType();
      gDelayedSubVizVectorTypeConstructed = true;
    }
    return reinterpret_cast<DelayedSubVizVectorType*>(gDelayedSubVizVectorTypeStorage);
  }

  [[nodiscard]] DelayedSubVizVectorType* PeekDelayedSubVizVectorType() noexcept
  {
    if (!gDelayedSubVizVectorTypeConstructed) {
      return nullptr;
    }
    return reinterpret_cast<DelayedSubVizVectorType*>(gDelayedSubVizVectorTypeStorage);
  }

  [[nodiscard]] gpg::SerHelperBase* DelayedSubVizSerializerSelfNode(moho::SDelayedSubVizInfoSerializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  [[nodiscard]] gpg::SerHelperBase* UnlinkDelayedSubVizSerializerNode() noexcept
  {
    if (gSDelayedSubVizInfoSerializer.mHelperNext && gSDelayedSubVizInfoSerializer.mHelperPrev) {
      gSDelayedSubVizInfoSerializer.mHelperNext->mPrev = gSDelayedSubVizInfoSerializer.mHelperPrev;
      gSDelayedSubVizInfoSerializer.mHelperPrev->mNext = gSDelayedSubVizInfoSerializer.mHelperNext;
    }

    gpg::SerHelperBase* const self = DelayedSubVizSerializerSelfNode(gSDelayedSubVizInfoSerializer);
    gSDelayedSubVizInfoSerializer.mHelperPrev = self;
    gSDelayedSubVizInfoSerializer.mHelperNext = self;
    return self;
  }

  /**
   * Address: 0x00BF1E80 (FUN_00BF1E80, delayed-sub-viz vector name cleanup)
   *
   * What it does:
   * Releases cached `vector<SDelayedSubVizInfo>` type-name storage.
   */
  void cleanup_SDelayedSubVizInfoVectorTypeName()
  {
    gDelayedSubVizVectorTypeName = msvc8::string{};
    gDelayedSubVizVectorTypeNameCleanupRegistered = false;
  }

  /**
   * Address: 0x00507F80 (FUN_00507F80, delayed-sub-viz vector growth lane)
   *
   * What it does:
   * Appends one delayed-sub-viz entry with growth/reallocation when needed and
   * returns pointer to inserted slot.
   */
  [[nodiscard]] moho::SDelayedSubVizInfo* GrowAndInsertDelayedSubVizInfo(
    DelayedSubVizVector& storage, const moho::SDelayedSubVizInfo& value
  )
  {
    const std::size_t insertionIndex = RuntimeVectorSize(storage);
    moho::SDelayedSubVizInfo* const insertionPosition = msvc8::AsVectorRuntimeView(storage).end;
    (void)InsertDelayedSubVizInfoCopies(storage, 1u, insertionPosition, value);
    return DelayedSubVizVectorPointerAt(storage, insertionIndex);
  }

  /**
   * Address: 0x005079C0 (FUN_005079C0, std::vector_SDelayedSubVizInfo::push_back)
   *
   * What it does:
   * Pushes one delayed-sub-viz entry, routing growth cases through
   * `FUN_00507F80`.
   */
  [[nodiscard]] moho::SDelayedSubVizInfo* PushBackDelayedSubVizInfo(
    DelayedSubVizVector& storage, const moho::SDelayedSubVizInfo& value
  )
  {
    const auto& view = msvc8::AsVectorRuntimeView(storage);
    const std::size_t size = RuntimeVectorSize(storage);
    const std::size_t capacity = RuntimeVectorCapacity(storage);

    if (view.begin && size < capacity) {
      storage.push_back(value);
      return DelayedSubVizVectorPointerAt(storage, size);
    }

    return GrowAndInsertDelayedSubVizInfo(storage, value);
  }

  /**
   * Address: 0x005080C0 (FUN_005080C0, gpg::RVectorType_SDelayedSubVizInfo::SerLoad)
   *
   * What it does:
   * Loads delayed-sub-viz vector elements from archive and replaces destination
   * storage.
   */
  void LoadSDelayedSubVizInfoVector(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const out = reinterpret_cast<DelayedSubVizVector*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(out != nullptr);
    if (!archive || !out) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);

    DelayedSubVizVector loaded{};
    (void)EnsureDelayedSubVizVectorCapacity(loaded, static_cast<std::size_t>(count));
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    gpg::RType* const elementType = ResolveSDelayedSubVizInfoType();

    for (unsigned int i = 0; i < count; ++i) {
      moho::SDelayedSubVizInfo element{};
      if (elementType) {
        (void)ReadDelayedSubVizInfoViaRTypeVariant1(archive, &element, &owner);
      } else {
        element.MemberDeserialize(archive);
      }
      (void)PushBackDelayedSubVizInfo(loaded, element);
    }

    *out = loaded;
  }

  /**
   * Address: 0x005081B0 (FUN_005081B0, gpg::RVectorType_SDelayedSubVizInfo::SerSave)
   *
   * What it does:
   * Saves delayed-sub-viz vector payload to archive element-by-element.
   */
  void SaveSDelayedSubVizInfoVector(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const source = reinterpret_cast<const DelayedSubVizVector*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(source != nullptr);
    if (!archive || !source) {
      return;
    }

    const unsigned int count = static_cast<unsigned int>(source->size());
    archive->WriteUInt(count);

    gpg::RType* const elementType = ResolveSDelayedSubVizInfoType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};

    for (unsigned int i = 0; i < count; ++i) {
      const moho::SDelayedSubVizInfo& element = (*source)[static_cast<std::size_t>(i)];
      if (elementType) {
        (void)WriteDelayedSubVizInfoViaRTypeVariant1(archive, &element, &owner);
      } else {
        element.MemberSerialize(archive);
      }
    }
  }

  /**
   * What it does:
   * Destroys delayed-sub-viz vector type storage lanes at process exit.
   */
  void cleanup_SDelayedSubVizInfoVectorType()
  {
    DelayedSubVizVectorType* const type = PeekDelayedSubVizVectorType();
    if (!type) {
      return;
    }

    (void)DestroyDelayedSubVizVectorType(type, false);
    gDelayedSubVizVectorTypeConstructed = false;
  }

  void CleanupSDelayedSubVizInfoSerializerAtexit()
  {
    (void)moho::cleanup_SDelayedSubVizInfoSerializerVariant1();
  }

  struct SDelayedSubVizInfoReflectionBootstrap
  {
    SDelayedSubVizInfoReflectionBootstrap()
    {
      (void)moho::initialize_SDelayedSubVizInfoSerializer();
      gSDelayedSubVizInfoSerializer.RegisterSerializeFunctions();
      (void)std::atexit(&CleanupSDelayedSubVizInfoSerializerAtexit);
      (void)&moho::cleanup_SDelayedSubVizInfoSerializerVariant2;
      (void)moho::register_SDelayedSubVizInfoVectorType_AtExit();
    }
  };

  SDelayedSubVizInfoReflectionBootstrap gSDelayedSubVizInfoReflectionBootstrap;
} // namespace

namespace moho
{
  gpg::RType* SDelayedSubVizInfo::sType = nullptr;

  gpg::RType* SDelayedSubVizInfo::StaticGetClass()
  {
    return ResolveSDelayedSubVizInfoType();
  }

  /**
   * Address: 0x005088F0 (FUN_005088F0, Moho::SDelayedSubVizInfo::MemberDeserialize)
   */
  void SDelayedSubVizInfo::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    gpg::RType* const vector3Type = ResolveVector3fType();
    gpg::RRef ownerRef{};
    archive->Read(vector3Type, &mLastPos, ownerRef);
    archive->ReadFloat(&mRadius);
    archive->ReadInt(&mTicksTilUpdate);
  }

  /**
   * Address: 0x00508950 (FUN_00508950, Moho::SDelayedSubVizInfo::MemberSerialize)
   */
  void SDelayedSubVizInfo::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    gpg::RType* const vector3Type = ResolveVector3fType();
    gpg::RRef ownerRef{};
    archive->Write(vector3Type, &mLastPos, ownerRef);
    archive->WriteFloat(mRadius);
    archive->WriteInt(mTicksTilUpdate);
  }

  /**
   * Address: 0x00507010 (FUN_00507010, Moho::SDelayedSubVizInfoSerializer::Deserialize)
   */
  void SDelayedSubVizInfoSerializer::Deserialize(gpg::ReadArchive* archive, int objectStorage, int, gpg::RRef*)
  {
    auto* const object = reinterpret_cast<SDelayedSubVizInfo*>(objectStorage);
    if (object) {
      object->MemberDeserialize(archive);
    }
  }

  /**
   * Address: 0x00507020 (FUN_00507020, Moho::SDelayedSubVizInfoSerializer::Serialize)
   */
  void SDelayedSubVizInfoSerializer::Serialize(gpg::WriteArchive* archive, int objectStorage, int, gpg::RRef*)
  {
    auto* const object = reinterpret_cast<const SDelayedSubVizInfo*>(objectStorage);
    if (object) {
      object->MemberSerialize(archive);
    }
  }

  /**
   * Address: 0x00507040 (FUN_00507040, init_SDelayedSubVizInfoSerializer)
   */
  SDelayedSubVizInfoSerializer* initialize_SDelayedSubVizInfoSerializer()
  {
    gpg::SerHelperBase* const self = DelayedSubVizSerializerSelfNode(gSDelayedSubVizInfoSerializer);
    gSDelayedSubVizInfoSerializer.mHelperNext = self;
    gSDelayedSubVizInfoSerializer.mHelperPrev = self;
    gSDelayedSubVizInfoSerializer.mDeserialize = &SDelayedSubVizInfoSerializer::Deserialize;
    gSDelayedSubVizInfoSerializer.mSerialize = &SDelayedSubVizInfoSerializer::Serialize;
    return &gSDelayedSubVizInfoSerializer;
  }

  /**
   * Address: 0x00507070 (FUN_00507070, cleanup_SDelayedSubVizInfoSerializer)
   */
  gpg::SerHelperBase* cleanup_SDelayedSubVizInfoSerializerVariant1()
  {
    return UnlinkDelayedSubVizSerializerNode();
  }

  /**
   * Address: 0x005070A0 (FUN_005070A0, cleanup_SDelayedSubVizInfoSerializer duplicate lane)
   */
  gpg::SerHelperBase* cleanup_SDelayedSubVizInfoSerializerVariant2()
  {
    return UnlinkDelayedSubVizSerializerNode();
  }

  /**
   * Address: 0x00507CC0 (FUN_00507CC0, gpg::SerSaveLoadHelper<Moho::SDelayedSubVizInfo>::Init)
   */
  void SDelayedSubVizInfoSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = ResolveSDelayedSubVizInfoType();
    GPG_ASSERT(type != nullptr);
    if (!type) {
      return;
    }

    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
    type->serLoadFunc_ = mDeserialize;

    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
    type->serSaveFunc_ = mSerialize;
  }

  gpg::RType* register_SDelayedSubVizInfoVectorType()
  {
    return ConstructAndRegisterDelayedSubVizVectorType();
  }

  int register_SDelayedSubVizInfoVectorType_AtExit()
  {
    (void)register_SDelayedSubVizInfoVectorType();
    return std::atexit(&cleanup_SDelayedSubVizInfoVectorType);
  }
} // namespace moho

/**
 * Address: 0x00509410 (FUN_00509410, gpg::RRef_SDelayedSubVizInfo)
 */
gpg::RRef* gpg::RRef_SDelayedSubVizInfo(gpg::RRef* const outRef, moho::SDelayedSubVizInfo* const value)
{
  if (!outRef) {
    return nullptr;
  }

  outRef->mObj = value;
  outRef->mType = moho::SDelayedSubVizInfo::StaticGetClass();
  return outRef;
}

/**
 * Address: 0x00507AA0 (FUN_00507AA0, gpg::RVectorType_SDelayedSubVizInfo::GetName)
 */
const char* gpg::RVectorType<moho::SDelayedSubVizInfo>::GetName() const
{
  if (gDelayedSubVizVectorTypeName.empty()) {
    const gpg::RType* const elementType = moho::SDelayedSubVizInfo::StaticGetClass();
    const char* const elementName = elementType ? elementType->GetName() : "SDelayedSubVizInfo";
    gDelayedSubVizVectorTypeName = gpg::STR_Printf("vector<%s>", elementName ? elementName : "SDelayedSubVizInfo");

    if (!gDelayedSubVizVectorTypeNameCleanupRegistered) {
      gDelayedSubVizVectorTypeNameCleanupRegistered = true;
      (void)std::atexit(&cleanup_SDelayedSubVizInfoVectorTypeName);
    }
  }

  return gDelayedSubVizVectorTypeName.c_str();
}

/**
 * Address: 0x00507B60 (FUN_00507B60, gpg::RVectorType_SDelayedSubVizInfo::GetLexical)
 */
msvc8::string gpg::RVectorType<moho::SDelayedSubVizInfo>::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
}

/**
 * Address: 0x00507BF0 (FUN_00507BF0, gpg::RVectorType_SDelayedSubVizInfo::IsIndexed)
 */
const gpg::RIndexed* gpg::RVectorType<moho::SDelayedSubVizInfo>::IsIndexed() const
{
  return this;
}

/**
 * Address: 0x00507B40 (FUN_00507B40, gpg::RVectorType_SDelayedSubVizInfo::Init)
 */
void gpg::RVectorType<moho::SDelayedSubVizInfo>::Init()
{
  size_ = 0x10;
  version_ = 1;
  serLoadFunc_ = &LoadSDelayedSubVizInfoVector;
  serSaveFunc_ = &SaveSDelayedSubVizInfoVector;
}

/**
 * Address: 0x00507C50 (FUN_00507C50, gpg::RVectorType_SDelayedSubVizInfo::SubscriptIndex)
 */
gpg::RRef gpg::RVectorType<moho::SDelayedSubVizInfo>::SubscriptIndex(void* const obj, const int ind) const
{
  auto* const storage = static_cast<DelayedSubVizVector*>(obj);
  GPG_ASSERT(storage != nullptr);
  GPG_ASSERT(ind >= 0);
  GPG_ASSERT(storage != nullptr && static_cast<std::size_t>(ind) < storage->size());

  gpg::RRef out{};
  gpg::RRef_SDelayedSubVizInfo(&out, nullptr);
  if (!storage || ind < 0 || static_cast<std::size_t>(ind) >= storage->size()) {
    return out;
  }

  gpg::RRef_SDelayedSubVizInfo(&out, &(*storage)[static_cast<std::size_t>(ind)]);
  return out;
}

/**
 * Address: 0x00507C00 (FUN_00507C00, gpg::RVectorType_SDelayedSubVizInfo::GetCount)
 */
size_t gpg::RVectorType<moho::SDelayedSubVizInfo>::GetCount(void* const obj) const
{
  if (!obj) {
    return 0u;
  }

  return RuntimeVectorSize(*static_cast<const DelayedSubVizVector*>(obj));
}

/**
 * Address: 0x00507C30 (FUN_00507C30, gpg::RVectorType_SDelayedSubVizInfo::SetCount)
 */
void gpg::RVectorType<moho::SDelayedSubVizInfo>::SetCount(void* const obj, const int count) const
{
  auto* const storage = static_cast<DelayedSubVizVector*>(obj);
  GPG_ASSERT(storage != nullptr);
  GPG_ASSERT(count >= 0);
  if (!storage || count < 0) {
    return;
  }

  const moho::SDelayedSubVizInfo zeroFill{};
  (void)ResizeDelayedSubVizVectorWithFill(*storage, static_cast<std::size_t>(count), zeroFill);
}
