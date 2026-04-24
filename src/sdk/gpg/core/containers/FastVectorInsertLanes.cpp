#include "gpg/core/containers/FastVectorInsertLanes.h"

#include <cstdint>
#include <cstring>
#include <intrin.h>
#include <limits>
#include <new>
#include <stdexcept>

namespace
{
  using gpg::core::legacy::FastVectorInsertRuntimeView;

  constexpr std::size_t kWordStride = 0x2u;
  constexpr std::size_t kDwordStride = 0x4u;
  constexpr std::size_t kQwordStride = 0x8u;
  constexpr std::size_t kTwelveStride = 0xCu;
  constexpr std::size_t kSixteenStride = 0x10u;
  constexpr std::size_t kTwentyStride = 0x14u;
  constexpr std::size_t kTwentyFourStride = 0x18u;
  constexpr std::size_t kTwentyEightStride = 0x1Cu;
  constexpr std::size_t kThirtyTwoStride = 0x20u;
  constexpr std::size_t kFortyStride = 0x28u;
  constexpr std::size_t kFiftyTwoStride = 0x34u;
  constexpr std::size_t kFiftySixStride = 0x38u;
  constexpr std::size_t kInlineCapacityByteCount280000 = 0x445C0u;
  constexpr std::size_t kInlineCapacityByteCount520000 = 0x7EF40u;
  constexpr std::size_t kInlineCapacityByteCount320000 = 0x4E200u;
  constexpr std::size_t kInlineCapacityByteCount1120 = 0x460u;

  using CopyForwardFn = std::byte* (*)(std::byte*, const std::byte*, const std::byte*) noexcept;
  using GrowInsertFn =
    std::byte* (*)(FastVectorInsertRuntimeView&, std::size_t, const std::byte*, const std::byte*, std::byte*);

  struct IntrusiveListNodeRuntimeView
  {
    IntrusiveListNodeRuntimeView* next = nullptr; // +0x00
    IntrusiveListNodeRuntimeView* prev = nullptr; // +0x04
  };
  static_assert(offsetof(IntrusiveListNodeRuntimeView, next) == 0x00, "IntrusiveListNodeRuntimeView::next offset must be 0x00");
  static_assert(offsetof(IntrusiveListNodeRuntimeView, prev) == 0x04, "IntrusiveListNodeRuntimeView::prev offset must be 0x04");

  struct FastVectorInlineOriginHeaderRuntimeView
  {
    FastVectorInsertRuntimeView view;       // +0x00
    std::byte inlineOriginStorage[1];       // +0x10
  };
  static_assert(
    offsetof(FastVectorInlineOriginHeaderRuntimeView, inlineOriginStorage) == 0x10,
    "FastVectorInlineOriginHeaderRuntimeView::inlineOriginStorage offset must be 0x10"
  );

  using SerializerWord = std::uint32_t;

  struct SerializerSlot36ByPointerVTable
  {
    void* reserved[9];
    int(__thiscall* invoke)(void* self, SerializerWord* value);
  };

  struct SerializerSlot36ByValueVTable
  {
    void* reserved[9];
    int(__thiscall* invoke)(void* self, SerializerWord value);
  };

  struct SerializerSlot36RuntimeByPointer
  {
    SerializerSlot36ByPointerVTable* vtable;
  };

  struct SerializerSlot36RuntimeByValue
  {
    SerializerSlot36ByValueVTable* vtable;
  };

  struct DeletingDestructorSlot8VTable
  {
    void* reserved0;
    int(__thiscall* invoke)(void* self, unsigned int deleteFlag);
  };

  struct DeletingDestructorSlot8Runtime
  {
    DeletingDestructorSlot8VTable* vtable;
  };

  /**
   * Address: 0x006D2800 (FUN_006D2800)
   *
   * What it does:
   * Copies one fixed 0x24-byte lane from `source` into `destination` and
   * returns `destination`.
   */
  [[maybe_unused]] void* CopyFixed36ByteLane(const void* const source, void* const destination) noexcept
  {
    std::memcpy(destination, source, 0x24u);
    return destination;
  }

  /**
   * Address: 0x0072A9B0 (FUN_0072A9B0)
   *
   * What it does:
   * Invokes serializer virtual slot `+0x24` with a by-reference temporary and
   * writes the updated 32-bit value back to `valueSlot`.
   */
  [[maybe_unused]] int InvokePrimitiveSerializerWordByPointerLane(
    void* const helperObject,
    SerializerWord* const valueSlot
  )
  {
    auto* const helper = static_cast<SerializerSlot36RuntimeByPointer*>(helperObject);
    SerializerWord value = static_cast<SerializerWord>(reinterpret_cast<std::uintptr_t>(helperObject));
    const int result = helper->vtable->invoke(helperObject, &value);
    *valueSlot = value;
    return result;
  }

  /**
   * Address: 0x0072A9D0 (FUN_0072A9D0)
   *
   * What it does:
   * Forwards one 32-bit primitive value lane through serializer virtual slot
   * `+0x24`.
   */
  [[maybe_unused]] int InvokePrimitiveSerializerWordByValueLane(
    void* const helperObject,
    SerializerWord* const valueSlot
  )
  {
    auto* const helper = static_cast<SerializerSlot36RuntimeByValue*>(helperObject);
    return helper->vtable->invoke(helperObject, *valueSlot);
  }

  /**
   * Address: 0x0072AC50 (FUN_0072AC50)
   *
   * What it does:
   * Calls the deleting-destructor virtual lane (`+0x08`) when
   * `objectStorage` is non-null.
   */
  [[maybe_unused]] void DeleteConstructedRuntimeObjectStorage(void* const objectStorage)
  {
    if (objectStorage == nullptr) {
      return;
    }

    auto* const runtime = static_cast<DeletingDestructorSlot8Runtime*>(objectStorage);
    (void)runtime->vtable->invoke(objectStorage, 1u);
  }

  /**
   * Address: 0x004E7430 (FUN_004E7430)
   *
   * What it does:
   * Unlinks one intrusive list node from its current ring and releases the
   * node storage.
   */
  [[maybe_unused]] void FreeIntrusiveListNodeRuntime(IntrusiveListNodeRuntimeView* const node) noexcept
  {
    if (node == nullptr) {
      return;
    }

    node->next->prev = node->prev;
    node->prev->next = node->next;
    node->prev = node;
    node->next = node;
    ::operator delete(node);
  }

  [[nodiscard]] std::size_t ElementCount(const std::byte* begin, const std::byte* end, const std::size_t stride) noexcept
  {
    if (begin == nullptr || end == nullptr || end < begin || stride == 0u) {
      return 0u;
    }
    return static_cast<std::size_t>(end - begin) / stride;
  }

  [[nodiscard]] std::size_t ByteCountForElements(const std::size_t count, const std::size_t stride) noexcept
  {
    return count * stride;
  }

  [[nodiscard]] bool TryAcquireStorageForStride(
    FastVectorInsertRuntimeView& vectorView,
    const std::size_t elementCount,
    const std::size_t stride
  ) noexcept
  {
    if (elementCount == 0u || stride == 0u) {
      return elementCount == 0u;
    }

    constexpr std::size_t kMaxSize = std::numeric_limits<std::size_t>::max();
    if (elementCount > (kMaxSize / stride)) {
      return false;
    }

    const std::size_t storageBytes = elementCount * stride;
    auto* const storage = static_cast<std::byte*>(::operator new(storageBytes, std::nothrow));
    if (storage == nullptr) {
      return false;
    }

    vectorView.start = storage;
    vectorView.finish = storage;
    vectorView.capacity = storage + storageBytes;
    return true;
  }

  [[nodiscard]] FastVectorInsertRuntimeView& InitializeInlineBackedFastVectorRuntimeView(
    FastVectorInsertRuntimeView& vectorView,
    std::byte* const inlineOrigin,
    const std::size_t capacityByteCount
  ) noexcept
  {
    vectorView.start = inlineOrigin;
    vectorView.finish = inlineOrigin;
    vectorView.capacity = inlineOrigin + capacityByteCount;
    vectorView.inlineOrigin = inlineOrigin;
    return vectorView;
  }

  [[nodiscard]] std::byte* CopyForwardStride(
    std::byte* destination,
    const std::byte* sourceEnd,
    const std::byte* sourceBegin,
    const std::size_t stride
  ) noexcept
  {
    for (const std::byte* source = sourceBegin; source != sourceEnd; source += stride) {
      if (destination != nullptr) {
        std::memcpy(destination, source, stride);
      }
      destination += stride;
    }
    return destination;
  }

  [[nodiscard]] std::byte* CopyBackwardStride(
    std::byte* destination,
    const std::byte* sourceEnd,
    const std::byte* sourceBegin,
    const std::size_t stride
  ) noexcept
  {
    std::byte* write = destination;
    const std::byte* source = sourceEnd;
    while (source != sourceBegin) {
      source -= stride;
      write -= stride;
      std::memcpy(write, source, stride);
    }
    return write;
  }

  void FillRangeFromSingleStride(
    std::byte* destinationBegin,
    std::byte* destinationEnd,
    const std::byte* sourceElement,
    const std::size_t stride
  ) noexcept
  {
    if (destinationBegin == nullptr || destinationEnd == nullptr || sourceElement == nullptr) {
      return;
    }

    for (std::byte* destination = destinationBegin; destination != destinationEnd; destination += stride) {
      std::memcpy(destination, sourceElement, stride);
    }
  }

  [[nodiscard]] std::byte* GrowInsertGeneric(
    FastVectorInsertRuntimeView& vectorView,
    const std::size_t elementStride,
    const std::size_t requestedCapacity,
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* splitPosition,
    const CopyForwardFn copyForward
  )
  {
    const std::size_t storageBytes = ByteCountForElements(requestedCapacity, elementStride);
    auto* const newStorage = static_cast<std::byte*>(::operator new(storageBytes));

    std::byte* write = copyForward(newStorage, splitPosition, vectorView.start);
    write = copyForward(write, sourceEnd, sourceBegin);
    write = copyForward(write, vectorView.finish, splitPosition);

    if (vectorView.start == vectorView.inlineOrigin) {
      if (vectorView.inlineOrigin != nullptr) {
        *reinterpret_cast<std::byte**>(vectorView.inlineOrigin) = vectorView.capacity;
      }
    } else if (vectorView.start != nullptr) {
      ::operator delete[](vectorView.start);
    }

    vectorView.start = newStorage;
    vectorView.finish = write;
    vectorView.capacity = newStorage + storageBytes;
    return vectorView.finish;
  }

  [[nodiscard]] std::byte* AppendRangeGeneric(
    FastVectorInsertRuntimeView& vectorView,
    std::byte* insertPosition,
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    const std::size_t elementStride,
    const CopyForwardFn copyForward,
    const GrowInsertFn growInsert
  )
  {
    const std::size_t insertCount = ElementCount(sourceBegin, sourceEnd, elementStride);
    if (insertCount == 0u) {
      return insertPosition;
    }

    const std::size_t currentCount = ElementCount(vectorView.start, vectorView.finish, elementStride);
    std::size_t requiredCount = currentCount + insertCount;
    const std::size_t currentCapacity = ElementCount(vectorView.start, vectorView.capacity, elementStride);
    if (requiredCount > currentCapacity) {
      std::size_t grownCapacity = currentCapacity * 2u;
      if (grownCapacity < requiredCount) {
        grownCapacity = requiredCount;
      }
      return growInsert(vectorView, grownCapacity, sourceBegin, sourceEnd, insertPosition);
    }

    const std::size_t insertBytes = ByteCountForElements(insertCount, elementStride);
    std::byte* const originalFinish = vectorView.finish;

    if (insertPosition + insertBytes <= originalFinish) {
      std::byte* const tailBegin = originalFinish - insertBytes;
      vectorView.finish = copyForward(originalFinish, originalFinish, tailBegin);

      const std::size_t middleBytes = static_cast<std::size_t>(tailBegin - insertPosition);
      if (middleBytes > 0u) {
        std::memmove(originalFinish - middleBytes, insertPosition, middleBytes);
      }

      std::memmove(insertPosition, sourceBegin, insertBytes);
      return insertPosition;
    }

    const std::byte* const spillBegin = sourceBegin + static_cast<std::size_t>(originalFinish - insertPosition);
    std::byte* write = copyForward(originalFinish, sourceEnd, spillBegin);
    vectorView.finish = copyForward(write, originalFinish, insertPosition);

    const std::size_t prefixBytes = static_cast<std::size_t>(originalFinish - insertPosition);
    if (prefixBytes > 0u) {
      std::memmove(insertPosition, sourceBegin, prefixBytes);
    }
    return insertPosition;
  }
} // namespace

namespace gpg::core::legacy
{
  /**
   * Address: 0x00762530 (FUN_00762530)
   * Address: 0x0080ABE0 (FUN_0080ABE0)
   * Address: 0x00693430 (FUN_00693430)
   * Address: 0x00693110 (FUN_00693110)
   * Address: 0x00762850 (FUN_00762850)
   * Address: 0x00561E60 (FUN_00561E60)
   * Address: 0x005B5250 (FUN_005B5250)
   *
   * What it does:
   * Copies 28-byte elements from `[sourceBegin, sourceEnd)` into `destination`
   * and returns the advanced destination lane.
   */
  std::byte* CopyForward28ByteLane(
    std::byte* destination,
    const std::byte* sourceEnd,
    const std::byte* sourceBegin
  ) noexcept
  {
    return CopyForwardStride(destination, sourceEnd, sourceBegin, kTwentyEightStride);
  }

  /**
   * Address: 0x00693240 (FUN_00693240)
   *
   * What it does:
   * Register-shape adapter that forwards one forward 28-byte range copy lane.
   */
  [[maybe_unused]] std::byte* CopyForward28ByteLaneRegisterAdapterA(
    const std::byte* const sourceBegin,
    std::byte* const destination,
    const std::byte* const sourceEnd
  ) noexcept
  {
    return CopyForward28ByteLane(destination, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x00693370 (FUN_00693370)
   *
   * What it does:
   * Secondary register-shape adapter that forwards one forward 28-byte range
   * copy lane.
   */
  [[maybe_unused]] std::byte* CopyForward28ByteLaneRegisterAdapterB(
    const std::byte* const sourceBegin,
    std::byte* const destination,
    const std::byte* const sourceEnd
  ) noexcept
  {
    return CopyForward28ByteLane(destination, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x00693410 (FUN_00693410)
   * Address: 0x006D2880 (FUN_006D2880)
   *
   * What it does:
   * Third register-shape adapter that forwards one forward 28-byte range copy
   * lane.
   */
  [[maybe_unused]] std::byte* CopyForward28ByteLaneRegisterAdapterC(
    const std::byte* const sourceBegin,
    std::byte* const destination,
    const std::byte* const sourceEnd
  ) noexcept
  {
    return CopyForward28ByteLane(destination, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x00762590 (FUN_00762590)
   * Address: 0x007625C0 (FUN_007625C0)
   * Address: 0x0080B670 (FUN_0080B670)
   * Address: 0x0080B6E0 (FUN_0080B6E0)
   * Address: 0x005B5C50 (FUN_005B5C50)
   * Address: 0x005B5CC0 (FUN_005B5CC0)
   * Address: 0x00693390 (FUN_00693390)
   * Address: 0x00762A30 (FUN_00762A30)
   * Address: 0x00762A90 (FUN_00762A90)
   *
   * What it does:
   * Copies 28-byte elements backward from `[sourceBegin, sourceEnd)` into the
   * destination tail lane.
   */
  std::byte* CopyBackward28ByteLane(
    std::byte* destination,
    const std::byte* sourceEnd,
    const std::byte* sourceBegin
  ) noexcept
  {
    return CopyBackwardStride(destination, sourceEnd, sourceBegin, kTwentyEightStride);
  }

  /**
   * Address: 0x006932C0 (FUN_006932C0)
   *
   * What it does:
   * Register-shape adapter that forwards one backward 28-byte range copy lane.
   */
  [[maybe_unused]] std::byte* CopyBackward28ByteLaneRegisterAdapterA(
    const std::byte* const sourceBegin,
    const std::byte* const sourceEnd,
    std::byte* const destinationEnd
  ) noexcept
  {
    return CopyBackward28ByteLane(destinationEnd, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x005B5740 (FUN_005B5740)
   *
   * What it does:
   * Register-shape adapter that forwards one source-first backward 28-byte
   * lane copy through `FUN_005B5C50`.
   */
  [[maybe_unused]] std::byte* CopyBackward28ByteLaneSourceFirstDelegatePrimary(
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* destinationEnd
  ) noexcept
  {
    return CopyBackward28ByteLane(destinationEnd, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x005B5770 (FUN_005B5770)
   *
   * What it does:
   * Secondary register-shape adapter for source-first backward 28-byte lane
   * copy, forwarding to `FUN_005B5CC0`.
   */
  [[maybe_unused]] std::byte* CopyBackward28ByteLaneSourceFirstDelegateSecondary(
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* destinationEnd
  ) noexcept
  {
    return CopyBackward28ByteLane(destinationEnd, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x0080B4A0 (FUN_0080B4A0)
   *
   * What it does:
   * Tertiary source-first delegate for one backward 28-byte range-copy lane.
   */
  [[maybe_unused]] std::byte* CopyBackward28ByteLaneSourceFirstDelegateTertiary(
    const std::byte* const sourceBegin,
    const std::byte* const sourceEnd,
    std::byte* const destinationEnd
  ) noexcept
  {
    return CopyBackward28ByteLane(destinationEnd, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x0080B4D0 (FUN_0080B4D0)
   *
   * What it does:
   * Quaternary source-first delegate for one backward 28-byte range-copy lane.
   */
  [[maybe_unused]] std::byte* CopyBackward28ByteLaneSourceFirstDelegateQuaternary(
    const std::byte* const sourceBegin,
    const std::byte* const sourceEnd,
    std::byte* const destinationEnd
  ) noexcept
  {
    return CopyBackward28ByteLane(destinationEnd, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x0080AB00 (FUN_0080AB00)
   * Address: 0x00561460 (FUN_00561460, SSyncData 28-byte grow/insert lane)
   * Address: 0x005B5170 (FUN_005B5170, CPathPoint 28-byte grow/insert lane)
   *
   * What it does:
   * Allocates replacement storage for one 28-byte fastvector lane and
   * materializes prefix/insert/suffix slices into the new storage.
   */
  std::byte* GrowInsert28ByteLane(
    FastVectorInsertRuntimeView& vectorView,
    const std::size_t requestedCapacity,
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* splitPosition
  )
  {
    return GrowInsertGeneric(
      vectorView,
      kTwentyEightStride,
      requestedCapacity,
      sourceBegin,
      sourceEnd,
      splitPosition,
      &CopyForward28ByteLane
    );
  }

  /**
   * Address: 0x0080A340 (FUN_0080A340)
   *
   * What it does:
   * Inserts one 28-byte range before `insertPosition`, growing storage when
   * capacity is insufficient.
   */
  std::byte* AppendRange28ByteLane(
    FastVectorInsertRuntimeView& vectorView,
    std::byte* insertPosition,
    const std::byte* sourceBegin,
    const std::byte* sourceEnd
  )
  {
    return AppendRangeGeneric(
      vectorView,
      insertPosition,
      sourceBegin,
      sourceEnd,
      kTwentyEightStride,
      &CopyForward28ByteLane,
      &GrowInsert28ByteLane
    );
  }

  /**
   * Address: 0x0080B150 (FUN_0080B150)
   * Address: 0x0080B2B0 (FUN_0080B2B0)
   * Address: 0x0080B3E0 (FUN_0080B3E0)
   *
   * What it does:
   * Copies 24-byte elements from `[sourceBegin, sourceEnd)` into `destination`
   * and returns the advanced destination lane.
   */
  std::byte* CopyForward24ByteLane(
    std::byte* destination,
    const std::byte* sourceEnd,
    const std::byte* sourceBegin
  ) noexcept
  {
    return CopyForwardStride(destination, sourceEnd, sourceBegin, kTwentyFourStride);
  }

  /**
   * Address: 0x0080B750 (FUN_0080B750)
   * Address: 0x0080B7B0 (FUN_0080B7B0)
   * Address: 0x0080B810 (FUN_0080B810)
   * Address: 0x0080B870 (FUN_0080B870)
   * Address: 0x0080B8D0 (FUN_0080B8D0)
   * Address: 0x0080B930 (FUN_0080B930)
   * Address: 0x004E7AA0 (FUN_004E7AA0)
   * Address: 0x00584220 (FUN_00584220)
   *
   * What it does:
   * Copies 24-byte elements backward from `[sourceBegin, sourceEnd)` into the
   * destination tail lane.
   */
  std::byte* CopyBackward24ByteLane(
    std::byte* destination,
    const std::byte* sourceEnd,
    const std::byte* sourceBegin
  ) noexcept
  {
    return CopyBackwardStride(destination, sourceEnd, sourceBegin, kTwentyFourStride);
  }

  /**
   * Address: 0x004E7B00 (FUN_004E7B00)
   *
   * What it does:
   * Alias lane of `CopyBackward24ByteLane` used by one adjacent VC8 vector
   * helper instantiation.
   */
  [[maybe_unused]] std::byte* CopyBackward24ByteLaneAlias(
    std::byte* destination,
    const std::byte* sourceEnd,
    const std::byte* sourceBegin
  ) noexcept
  {
    return CopyBackward24ByteLane(destination, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x004E7890 (FUN_004E7890)
   *
   * What it does:
   * Adapts one register-lane caller shape into the canonical
   * backward 24-byte range-copy helper.
   */
  [[maybe_unused]] std::byte* CopyBackward24ByteLaneRegisterAdapterA(
    const std::byte* const sourceBegin,
    const std::byte* const sourceEnd,
    std::byte* const destinationEnd
  ) noexcept
  {
    return CopyBackward24ByteLane(destinationEnd, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x004E78C0 (FUN_004E78C0)
   *
   * What it does:
   * Second register-lane adapter for backward 24-byte range-copy dispatch.
   */
  [[maybe_unused]] std::byte* CopyBackward24ByteLaneRegisterAdapterB(
    const std::byte* const sourceBegin,
    const std::byte* const sourceEnd,
    std::byte* const destinationEnd
  ) noexcept
  {
    return CopyBackward24ByteLaneAlias(destinationEnd, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x005821C0 (FUN_005821C0)
   * Address: 0x00583720 (FUN_00583720)
   *
   * What it does:
   * Third register-shape adapter for backward 24-byte range-copy dispatch.
   */
  [[maybe_unused]] std::byte* CopyBackward24ByteLaneRegisterAdapterC(
    const std::byte* const sourceBegin,
    const std::byte* const sourceEnd,
    std::byte* const destinationEnd
  ) noexcept
  {
    return CopyBackward24ByteLane(destinationEnd, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x0080B500 (FUN_0080B500)
   *
   * What it does:
   * Forwards one source-first backward 24-byte range-copy lane through the
   * shared canonical helper.
   */
  [[maybe_unused]] std::byte* CopyBackward24ByteLaneSourceFirstDelegatePrimary(
    const std::byte* const sourceBegin,
    const std::byte* const sourceEnd,
    std::byte* const destinationEnd
  ) noexcept
  {
    return CopyBackward24ByteLane(destinationEnd, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x0080B530 (FUN_0080B530)
   *
   * What it does:
   * Secondary source-first delegate for one backward 24-byte range-copy lane.
   */
  [[maybe_unused]] std::byte* CopyBackward24ByteLaneSourceFirstDelegateSecondary(
    const std::byte* const sourceBegin,
    const std::byte* const sourceEnd,
    std::byte* const destinationEnd
  ) noexcept
  {
    return CopyBackward24ByteLane(destinationEnd, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x0080B560 (FUN_0080B560)
   *
   * What it does:
   * Tertiary source-first delegate for one backward 24-byte range-copy lane.
   */
  [[maybe_unused]] std::byte* CopyBackward24ByteLaneSourceFirstDelegateTertiary(
    const std::byte* const sourceBegin,
    const std::byte* const sourceEnd,
    std::byte* const destinationEnd
  ) noexcept
  {
    return CopyBackward24ByteLane(destinationEnd, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x0080B590 (FUN_0080B590)
   *
   * What it does:
   * Quaternary source-first delegate for one backward 24-byte range-copy
   * lane.
   */
  [[maybe_unused]] std::byte* CopyBackward24ByteLaneSourceFirstDelegateQuaternary(
    const std::byte* const sourceBegin,
    const std::byte* const sourceEnd,
    std::byte* const destinationEnd
  ) noexcept
  {
    return CopyBackward24ByteLane(destinationEnd, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x0080B5C0 (FUN_0080B5C0)
   *
   * What it does:
   * Quinary source-first delegate for one backward 24-byte range-copy lane.
   */
  [[maybe_unused]] std::byte* CopyBackward24ByteLaneSourceFirstDelegateQuinary(
    const std::byte* const sourceBegin,
    const std::byte* const sourceEnd,
    std::byte* const destinationEnd
  ) noexcept
  {
    return CopyBackward24ByteLane(destinationEnd, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x0080B5F0 (FUN_0080B5F0)
   *
   * What it does:
   * Senary source-first delegate for one backward 24-byte range-copy lane.
   */
  [[maybe_unused]] std::byte* CopyBackward24ByteLaneSourceFirstDelegateSenary(
    const std::byte* const sourceBegin,
    const std::byte* const sourceEnd,
    std::byte* const destinationEnd
  ) noexcept
  {
    return CopyBackward24ByteLane(destinationEnd, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x005836D0 (FUN_005836D0)
   *
   * What it does:
   * Writes one repeated 24-byte source lane into destination slots in
   * `[destinationBegin, destinationEnd)`.
   */
  void Fill24ByteLaneRangeFromSingle(
    std::byte* const destinationBegin,
    std::byte* const destinationEnd,
    const std::byte* const sourceElement
  ) noexcept
  {
    FillRangeFromSingleStride(destinationBegin, destinationEnd, sourceElement, kTwentyFourStride);
  }

  /**
   * Address: 0x005821B0 (FUN_005821B0)
   *
   * What it does:
   * Register-shape adapter that forwards one repeated 24-byte fill lane into
   * the canonical range-fill helper.
   */
  [[maybe_unused]] void Fill24ByteLaneRangeFromSingleRegisterAdapter(
    std::byte* const destinationBegin,
    std::byte* const destinationEnd,
    const std::byte* const sourceElement
  ) noexcept
  {
    Fill24ByteLaneRangeFromSingle(destinationBegin, destinationEnd, sourceElement);
  }

  /**
   * Address: 0x0080B080 (FUN_0080B080)
   * Address: 0x0080B1E0 (FUN_0080B1E0)
   * Address: 0x0080B310 (FUN_0080B310)
   *
   * What it does:
   * Allocates replacement storage for one 24-byte fastvector lane and
   * materializes prefix/insert/suffix slices into the new storage.
   */
  std::byte* GrowInsert24ByteLane(
    FastVectorInsertRuntimeView& vectorView,
    const std::size_t requestedCapacity,
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* splitPosition
  )
  {
    return GrowInsertGeneric(
      vectorView,
      kTwentyFourStride,
      requestedCapacity,
      sourceBegin,
      sourceEnd,
      splitPosition,
      &CopyForward24ByteLane
    );
  }

  /**
   * Address: 0x0080A8C0 (FUN_0080A8C0)
   * Address: 0x0080ACB0 (FUN_0080ACB0)
   * Address: 0x0080AE70 (FUN_0080AE70)
   * Address: 0x004E7460 (FUN_004E7460)
   *
   * What it does:
   * Inserts one 24-byte range before `insertPosition`, growing storage when
   * capacity is insufficient.
   */
  std::byte* AppendRange24ByteLane(
    FastVectorInsertRuntimeView& vectorView,
    std::byte* insertPosition,
    const std::byte* sourceBegin,
    const std::byte* sourceEnd
  )
  {
    return AppendRangeGeneric(
      vectorView,
      insertPosition,
      sourceBegin,
      sourceEnd,
      kTwentyFourStride,
      &CopyForward24ByteLane,
      &GrowInsert24ByteLane
    );
  }

  [[nodiscard]] std::byte* PushBack24ByteElementLaneCommon(
    FastVectorInsertRuntimeView& vectorView,
    const std::byte* const sourceElement
  )
  {
    std::byte* const write = vectorView.finish;
    if (write == vectorView.capacity) {
      return AppendRange24ByteLane(vectorView, write, sourceElement, sourceElement + kTwentyFourStride);
    }

    if (write != nullptr && sourceElement != nullptr) {
      auto* const writeWords = reinterpret_cast<std::uint32_t*>(write);
      const auto* const sourceWords = reinterpret_cast<const std::uint32_t*>(sourceElement);
      writeWords[0] = sourceWords[0];
      writeWords[1] = sourceWords[1];
      writeWords[2] = sourceWords[2];
      writeWords[3] = sourceWords[3];
      writeWords[4] = sourceWords[4];
      writeWords[5] = sourceWords[5];
    }

    vectorView.finish = write + kTwentyFourStride;
    return reinterpret_cast<std::byte*>(&vectorView);
  }

  /**
   * Address: 0x0080A1A0 (FUN_0080A1A0)
   *
   * What it does:
   * Appends one 24-byte element lane, delegating to range-insert growth when
   * the destination fastvector has no spare capacity.
   */
  [[maybe_unused]] std::byte* PushBack24ByteElementLaneA(
    FastVectorInsertRuntimeView& vectorView,
    const std::byte* const sourceElement
  )
  {
    return PushBack24ByteElementLaneCommon(vectorView, sourceElement);
  }

  /**
   * Address: 0x0080A710 (FUN_0080A710)
   *
   * What it does:
   * Appends one 24-byte element lane, delegating to range-insert growth when
   * the destination fastvector has no spare capacity.
   */
  [[maybe_unused]] std::byte* PushBack24ByteElementLaneB(
    FastVectorInsertRuntimeView& vectorView,
    const std::byte* const sourceElement
  )
  {
    return PushBack24ByteElementLaneCommon(vectorView, sourceElement);
  }

  /**
   * Address: 0x0080A810 (FUN_0080A810)
   *
   * What it does:
   * Appends one 24-byte element lane, delegating to range-insert growth when
   * the destination fastvector has no spare capacity.
   */
  [[maybe_unused]] std::byte* PushBack24ByteElementLaneC(
    FastVectorInsertRuntimeView& vectorView,
    const std::byte* const sourceElement
  )
  {
    return PushBack24ByteElementLaneCommon(vectorView, sourceElement);
  }

  /**
   * Address: 0x00722EC0 (FUN_00722EC0)
   *
   * What it does:
   * Appends one 24-byte element into a collision-result style fastvector lane
   * and grows storage through `AppendRange24ByteLane` when full.
   */
  [[maybe_unused]] std::byte* PushBack24ByteElementLaneCollisionResult(
    FastVectorInsertRuntimeView& vectorView,
    const std::byte* const sourceElement
  )
  {
    return PushBack24ByteElementLaneCommon(vectorView, sourceElement);
  }

  [[nodiscard]] std::byte* ResetInlineBackedVectorStorageCommon(FastVectorInsertRuntimeView& vectorView) noexcept
  {
    std::byte* result = vectorView.start;
    if (vectorView.start == vectorView.inlineOrigin) {
      vectorView.finish = result;
      return result;
    }

    ::operator delete[](vectorView.start);
    vectorView.start = vectorView.inlineOrigin;
    result = *reinterpret_cast<std::byte**>(vectorView.start);
    vectorView.capacity = result;
    vectorView.finish = vectorView.start;
    return result;
  }

  /**
   * Address: 0x004E7280 (FUN_004E7280)
   *
   * What it does:
   * Resets one 24-byte fastvector lane to its inline origin storage, releasing
   * heap storage when the active lane is not already inline.
   */
  [[maybe_unused]] std::byte* Reset24ByteVectorToInlineOrigin(FastVectorInsertRuntimeView& vectorView) noexcept
  {
    return ResetInlineBackedVectorStorageCommon(vectorView);
  }

  /**
   * Address: 0x004E72B0 (FUN_004E72B0)
   *
   * What it does:
   * Appends one 24-byte element into the destination fastvector lane and
   * delegates to range-grow insertion when capacity is exhausted.
   */
  [[maybe_unused]] std::byte* PushBack24ByteElementLaneLegacy(
    FastVectorInsertRuntimeView& vectorView,
    const std::byte* const sourceElement
  )
  {
    return PushBack24ByteElementLaneCommon(vectorView, sourceElement);
  }

  namespace
  {
    /**
     * Address: 0x00548460 (FUN_00548460)
     *
     * What it does:
     * Copies 20-byte elements from `[sourceBegin, sourceEnd)` into `destination`
     * and returns the advanced destination lane.
     */
    [[nodiscard]] std::byte* CopyForward20ByteLane(
      std::byte* destination,
      const std::byte* sourceEnd,
      const std::byte* sourceBegin
    ) noexcept
    {
      return CopyForwardStride(destination, sourceEnd, sourceBegin, kTwentyStride);
    }

    [[nodiscard]] std::byte* GrowInsert20ByteLane(
      FastVectorInsertRuntimeView& vectorView,
      const std::size_t requestedCapacity,
      const std::byte* sourceBegin,
      const std::byte* sourceEnd,
      std::byte* splitPosition
    )
    {
      return GrowInsertGeneric(
        vectorView,
        kTwentyStride,
        requestedCapacity,
        sourceBegin,
        sourceEnd,
        splitPosition,
        &CopyForward20ByteLane
      );
    }
  } // namespace

  /**
   * Address: 0x00547C70 (FUN_00547C70)
   *
   * What it does:
   * Inserts one 20-byte range before `insertPosition`, growing storage when
   * capacity is insufficient.
   */
  std::byte* AppendRange20ByteLane(
    FastVectorInsertRuntimeView& vectorView,
    std::byte* insertPosition,
    const std::byte* sourceBegin,
    const std::byte* sourceEnd
  )
  {
    return AppendRangeGeneric(
      vectorView,
      insertPosition,
      sourceBegin,
      sourceEnd,
      kTwentyStride,
      &CopyForward20ByteLane,
      &GrowInsert20ByteLane
    );
  }

  /**
   * Address: 0x005477E0 (FUN_005477E0)
   *
   * What it does:
   * Appends one 20-byte element lane and delegates to range-insert growth when
   * the destination fastvector has no spare capacity.
   */
  [[maybe_unused]] std::byte* PushBack20ByteElementLaneResourceDeposit(
    FastVectorInsertRuntimeView& vectorView,
    const std::byte* const sourceElement
  )
  {
    std::byte* const write = vectorView.finish;
    if (write == vectorView.capacity) {
      return AppendRange20ByteLane(vectorView, write, sourceElement, sourceElement + kTwentyStride);
    }

    if (write != nullptr && sourceElement != nullptr) {
      auto* const writeWords = reinterpret_cast<std::uint32_t*>(write);
      const auto* const sourceWords = reinterpret_cast<const std::uint32_t*>(sourceElement);
      writeWords[0] = sourceWords[0];
      writeWords[1] = sourceWords[1];
      writeWords[2] = sourceWords[2];
      writeWords[3] = sourceWords[3];
      writeWords[4] = sourceWords[4];
    }

    vectorView.finish = write + kTwentyStride;
    return write;
  }

  /**
   * Address: 0x00548B20 (FUN_00548B20)
   *
   * What it does:
   * Writes one repeated 20-byte source lane into destination slots in
   * `[destinationBegin, destinationEnd)`.
   */
  void Fill20ByteLaneRangeFromSingle(
    std::byte* const destinationBegin,
    std::byte* const destinationEnd,
    const std::byte* const sourceElement
  ) noexcept
  {
    FillRangeFromSingleStride(destinationBegin, destinationEnd, sourceElement, kTwentyStride);
  }

  /**
   * Address: 0x005EF7D0 (FUN_005EF7D0)
   * Address: 0x00548A50 (FUN_00548A50)
   * Address: 0x00548A80 (FUN_00548A80)
   * Address: 0x00548B50 (FUN_00548B50)
   *
   * What it does:
   * Copies 20-byte elements backward from `[sourceBegin, sourceEnd)` into the
   * destination tail lane.
   */
  std::byte* CopyBackward20ByteLane(
    std::byte* destination,
    const std::byte* sourceEnd,
    const std::byte* sourceBegin
  ) noexcept
  {
    return CopyBackwardStride(destination, sourceEnd, sourceBegin, kTwentyStride);
  }

  /**
   * Address: 0x0054CCF0 (FUN_0054CCF0)
   *
   * What it does:
   * Resets one inline-backed fastvector lane to inline storage and releases
   * heap storage when the active lane is not already inline.
   */
  [[maybe_unused]] std::byte* ResetInlineBackedVectorStorageLaneA(FastVectorInsertRuntimeView& vectorView) noexcept
  {
    return ResetInlineBackedVectorStorageCommon(vectorView);
  }

  /**
   * Address: 0x0054D760 (FUN_0054D760)
   *
   * What it does:
   * Alias reset lane for the same inline-backed fastvector storage contract.
   */
  [[maybe_unused]] std::byte* ResetInlineBackedVectorStorageLaneB(FastVectorInsertRuntimeView& vectorView) noexcept
  {
    return ResetInlineBackedVectorStorageCommon(vectorView);
  }

  /**
   * Address: 0x006FD160 (FUN_006FD160)
   *
   * What it does:
   * Resets one inline-backed fastvector lane to inline storage and releases
   * heap storage when the active lane is not already inline.
   */
  [[maybe_unused]] std::byte* ResetInlineBackedVectorStorageLaneC(FastVectorInsertRuntimeView& vectorView) noexcept
  {
    return ResetInlineBackedVectorStorageCommon(vectorView);
  }

  /**
   * Address: 0x006FD190 (FUN_006FD190)
   *
   * What it does:
   * Alias reset lane for the same inline-backed fastvector storage contract.
   */
  [[maybe_unused]] std::byte* ResetInlineBackedVectorStorageLaneD(FastVectorInsertRuntimeView& vectorView) noexcept
  {
    return ResetInlineBackedVectorStorageCommon(vectorView);
  }

  /**
   * Address: 0x0072A440 (FUN_0072A440)
   *
   * What it does:
   * Resets one inline-backed fastvector lane to inline storage and frees heap
   * storage when the active lane is not already inline.
   */
  [[maybe_unused]] std::byte* ResetInlineBackedVectorStorageLanePlatoonA(
    FastVectorInsertRuntimeView& vectorView
  ) noexcept
  {
    return ResetInlineBackedVectorStorageCommon(vectorView);
  }

  /**
   * Address: 0x0072A970 (FUN_0072A970)
   *
   * What it does:
   * Alias reset lane for the same inline-backed fastvector storage contract.
   */
  [[maybe_unused]] std::byte* ResetInlineBackedVectorStorageLanePlatoonB(
    FastVectorInsertRuntimeView& vectorView
  ) noexcept
  {
    return ResetInlineBackedVectorStorageCommon(vectorView);
  }

  /**
   * Address: 0x007AE790 (FUN_007AE790)
   *
   * What it does:
   * Alias reset lane for the same inline-backed fastvector storage contract.
   */
  [[maybe_unused]] std::byte* ResetInlineBackedVectorStorageLaneGameplay(
    FastVectorInsertRuntimeView& vectorView
  ) noexcept
  {
    return ResetInlineBackedVectorStorageCommon(vectorView);
  }

  /**
   * Address: 0x0080F460 (FUN_0080F460)
   * Address: 0x006D28A0 (FUN_006D28A0)
   * Address: 0x006D2530 (FUN_006D2530)
   * Address: 0x006D2560 (FUN_006D2560)
   * Address: 0x007A26D0 (FUN_007A26D0)
   * Address: 0x006AF7B0 (FUN_006AF7B0)
   * Address: 0x007678A0 (FUN_007678A0)
   *
   * What it does:
   * Copies 8-byte elements from `[sourceBegin, sourceEnd)` into `destination`
   * and returns the advanced destination lane.
   */
  std::byte* CopyForward8ByteLane(
    std::byte* destination,
    const std::byte* sourceEnd,
    const std::byte* sourceBegin
  ) noexcept
  {
    return CopyForwardStride(destination, sourceEnd, sourceBegin, kQwordStride);
  }

  /**
   * Address: 0x006D2750 (FUN_006D2750)
   * Address: 0x006D2820 (FUN_006D2820)
   *
   * What it does:
   * Register-shape adapter that forwards one 8-byte forward range copy lane
   * into the canonical null-tolerant copy helper.
   */
  [[maybe_unused]] std::byte* CopyForward8ByteLaneRegisterAdapterAllowNullDestination(
    const std::byte* const sourceBegin,
    const std::byte* const sourceEnd,
    std::byte* const destination
  ) noexcept
  {
    return CopyForward8ByteLane(destination, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x00754850 (FUN_00754850)
   *
   * What it does:
   * Bridges one 8-byte source-first copy lane where the source-end bound was
   * supplied through a hidden register lane in the original call shape.
   */
  [[maybe_unused]] std::byte* CopyForward8ByteLaneSourceFirstHiddenEndRegisterAdapter(
    const std::byte* const sourceBegin,
    const std::byte* const sourceEnd,
    std::byte* const destination
  ) noexcept
  {
    return CopyForward8ByteLane(destination, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x00540C00 (FUN_00540C00)
   * Address: 0x0054E170 (FUN_0054E170)
   * Address: 0x0075FD20 (FUN_0075FD20)
   *
   * What it does:
   * Writes one repeated 8-byte source lane into destination slots in
   * `[destinationBegin, destinationEnd)` and returns `destinationEnd`.
   */
  std::byte* Fill8ByteLaneRangeFromSingleAndReturnEnd(
    std::byte* const destinationBegin,
    std::byte* const destinationEnd,
    const std::byte* const sourceElement
  ) noexcept
  {
    FillRangeFromSingleStride(destinationBegin, destinationEnd, sourceElement, kQwordStride);
    return destinationEnd;
  }

  /**
   * Address: 0x00760065 (FUN_00760065)
   * Address: 0x007A2830 (FUN_007A2830)
   * Address: 0x00540C20 (FUN_00540C20)
   * Address: 0x0054E190 (FUN_0054E190)
   * Address: 0x006D2580 (FUN_006D2580)
   * Address: 0x0075FD40 (FUN_0075FD40)
   * Address: 0x007A2860 (FUN_007A2860)
   *
   * What it does:
   * Copies 8-byte elements backward from `[sourceBegin, sourceEnd)` into the
   * destination tail lane and returns the destination begin.
   */
  std::byte* CopyBackward8ByteLane(
    std::byte* destinationEnd,
    const std::byte* sourceEnd,
    const std::byte* sourceBegin
  ) noexcept
  {
    return CopyBackwardStride(destinationEnd, sourceEnd, sourceBegin, kQwordStride);
  }

  struct QwordVectorBeginEndCapacityAt4RuntimeView
  {
    std::uint32_t lane00 = 0u;       // +0x00
    const std::uint64_t* begin = nullptr;    // +0x04
    const std::uint64_t* end = nullptr;      // +0x08
    const std::uint64_t* capacity = nullptr; // +0x0C
  };
  static_assert(
    offsetof(QwordVectorBeginEndCapacityAt4RuntimeView, begin) == 0x04,
    "QwordVectorBeginEndCapacityAt4RuntimeView::begin offset must be 0x04"
  );
  static_assert(
    offsetof(QwordVectorBeginEndCapacityAt4RuntimeView, end) == 0x08,
    "QwordVectorBeginEndCapacityAt4RuntimeView::end offset must be 0x08"
  );
  static_assert(
    offsetof(QwordVectorBeginEndCapacityAt4RuntimeView, capacity) == 0x0C,
    "QwordVectorBeginEndCapacityAt4RuntimeView::capacity offset must be 0x0C"
  );

  struct NineFloatLaneRuntimeView
  {
    float lanes[9]{}; // +0x00 .. +0x20
  };
  static_assert(sizeof(NineFloatLaneRuntimeView) == 0x24, "NineFloatLaneRuntimeView size must be 0x24");

  /**
   * Address: 0x006D19D0 (FUN_006D19D0)
   *
   * What it does:
   * Returns 8-byte element capacity count from one begin/capacity span at
   * offsets `(+0x04,+0x0C)`; returns zero when begin is null.
   */
  [[maybe_unused]] std::int32_t CountQwordElementsBeginAt4CapacityAtC(
    const QwordVectorBeginEndCapacityAt4RuntimeView* const vectorLane
  ) noexcept
  {
    if (vectorLane == nullptr || vectorLane->begin == nullptr) {
      return 0;
    }
    return static_cast<std::int32_t>(vectorLane->capacity - vectorLane->begin);
  }

  /**
   * Address: 0x006D1A00 (FUN_006D1A00)
   *
   * What it does:
   * Returns 8-byte element count from one begin/end span at offsets
   * `(+0x04,+0x08)`; returns zero when begin is null.
   */
  [[maybe_unused]] std::int32_t CountQwordElementsBeginAt4EndAt8(
    const QwordVectorBeginEndCapacityAt4RuntimeView* const vectorLane
  ) noexcept
  {
    if (vectorLane == nullptr || vectorLane->begin == nullptr) {
      return 0;
    }
    return static_cast<std::int32_t>(vectorLane->end - vectorLane->begin);
  }

  /**
   * Address: 0x006D1CF0 (FUN_006D1CF0)
   *
   * What it does:
   * Stores one computed address lane `*baseAddress + index * 8`.
   */
  [[maybe_unused]] std::uintptr_t* StoreAddressFromBaseAndQwordIndex(
    std::uintptr_t* const outAddress,
    const std::uintptr_t* const baseAddress,
    const std::int32_t index
  ) noexcept
  {
    *outAddress = *baseAddress + (static_cast<std::uintptr_t>(index) * kQwordStride);
    return outAddress;
  }

  /**
   * Address: 0x006D1D00 (FUN_006D1D00)
   * Address: 0x006D1DF0 (FUN_006D1DF0)
   *
   * What it does:
   * Returns one 8-byte index distance between two stored address lanes.
   */
  [[maybe_unused]] std::int32_t AddressDistanceInQwordElements(
    const std::uintptr_t* const lhsAddress,
    const std::uintptr_t* const rhsAddress
  ) noexcept
  {
    return static_cast<std::int32_t>(
      (static_cast<std::intptr_t>(*lhsAddress) - static_cast<std::intptr_t>(*rhsAddress)) /
      static_cast<std::intptr_t>(kQwordStride)
    );
  }

  /**
   * Address: 0x006D1DD0 (FUN_006D1DD0)
   * Address: 0x006D1E10 (FUN_006D1E10)
   *
   * What it does:
   * Advances one stored address lane by `index * 8` bytes.
   */
  [[maybe_unused]] std::uintptr_t* AdvanceStoredAddressByQwordIndex(
    std::uintptr_t* const addressSlot,
    const std::int32_t index
  ) noexcept
  {
    *addressSlot += (static_cast<std::uintptr_t>(index) * kQwordStride);
    return addressSlot;
  }

  /**
   * Address: 0x006D2600 (FUN_006D2600)
   *
   * What it does:
   * Initializes one fixed 0x24-byte lane from nine scalar float inputs.
   */
  [[maybe_unused]] NineFloatLaneRuntimeView* InitializeNineFloatLane(
    NineFloatLaneRuntimeView* const outLane,
    const float lane00,
    const float lane04,
    const float lane08,
    const float lane0C,
    const float lane10,
    const float lane14,
    const float lane18,
    const float lane1C,
    const float lane20
  ) noexcept
  {
    outLane->lanes[0] = lane00;
    outLane->lanes[1] = lane04;
    outLane->lanes[2] = lane08;
    outLane->lanes[3] = lane0C;
    outLane->lanes[4] = lane10;
    outLane->lanes[5] = lane14;
    outLane->lanes[6] = lane18;
    outLane->lanes[7] = lane1C;
    outLane->lanes[8] = lane20;
    return outLane;
  }

  /**
   * Address: 0x006D2770 (FUN_006D2770)
   *
   * What it does:
   * Fills one 8-byte destination range with a repeated single 8-byte source
   * lane and returns the destination end pointer.
   */
  [[maybe_unused]] std::byte* Fill8ByteLaneRangeFromSingleAndReturnEndAlias(
    std::byte* const destinationBegin,
    std::byte* const destinationEnd,
    const std::byte* const sourceElement
  ) noexcept
  {
    FillRangeFromSingleStride(destinationBegin, destinationEnd, sourceElement, kQwordStride);
    return destinationEnd;
  }

  /**
   * Address: 0x006D27B0 (FUN_006D27B0)
   * Address: 0x006D2840 (FUN_006D2840)
   *
   * What it does:
   * Alias lane for backward 8-byte range copy.
   */
  [[maybe_unused]] std::byte* CopyBackward8ByteLaneAlias(
    std::byte* const destinationEnd,
    const std::byte* const sourceEnd,
    const std::byte* const sourceBegin
  ) noexcept
  {
    return CopyBackward8ByteLane(destinationEnd, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x006D27E0 (FUN_006D27E0)
   * Address: 0x006D2860 (FUN_006D2860)
   *
   * What it does:
   * Copies one 8-byte source lane when destination storage is non-null.
   */
  [[maybe_unused]] std::byte* CopyOptionalSingle8ByteLane(
    std::byte* const destination,
    const std::byte* const source
  ) noexcept
  {
    if (destination != nullptr) {
      std::memcpy(destination, source, kQwordStride);
    }
    return destination;
  }

  /**
   * Address: 0x0080F390 (FUN_0080F390)
   *
   * What it does:
   * Allocates replacement storage for one 8-byte fastvector lane and
   * materializes prefix/insert/suffix slices into the new storage.
   */
  std::byte* GrowInsert8ByteLane(
    FastVectorInsertRuntimeView& vectorView,
    const std::size_t requestedCapacity,
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* splitPosition
  )
  {
    return GrowInsertGeneric(
      vectorView,
      kQwordStride,
      requestedCapacity,
      sourceBegin,
      sourceEnd,
      splitPosition,
      &CopyForward8ByteLane
    );
  }

  /**
   * Address: 0x0080EF20 (FUN_0080EF20)
   * Address: 0x007A24B0 (FUN_007A24B0)
   *
   * What it does:
   * Inserts one 8-byte range before `insertPosition`, growing storage when
   * capacity is insufficient.
   */
  std::byte* AppendRange8ByteLane(
    FastVectorInsertRuntimeView& vectorView,
    std::byte* insertPosition,
    const std::byte* sourceBegin,
    const std::byte* sourceEnd
  )
  {
    return AppendRangeGeneric(
      vectorView,
      insertPosition,
      sourceBegin,
      sourceEnd,
      kQwordStride,
      &CopyForward8ByteLane,
      &GrowInsert8ByteLane
    );
  }

  /**
   * Address: 0x0080F550 (FUN_0080F550)
   * Address: 0x0056FA10 (FUN_0056FA10)
   * Address: 0x00723530 (FUN_00723530)
   *
   * What it does:
   * Copies 32-byte elements from `[sourceBegin, sourceEnd)` into `destination`
   * and returns the advanced destination lane.
   */
  std::byte* CopyForward32ByteLane(
    std::byte* destination,
    const std::byte* sourceEnd,
    const std::byte* sourceBegin
  ) noexcept
  {
    return CopyForwardStride(destination, sourceEnd, sourceBegin, kThirtyTwoStride);
  }

  /**
   * Address: 0x00572F80 (FUN_00572F80)
   * Address: 0x00572F20 (FUN_00572F20)
   * Address: 0x00723850 (FUN_00723850)
   * Address: 0x007238D0 (FUN_007238D0)
   *
   * What it does:
   * Copies 32-byte elements backward from `[sourceBegin, sourceEnd)` into the
   * destination tail lane.
   */
  std::byte* CopyBackward32ByteLane(
    std::byte* destination,
    const std::byte* sourceEnd,
    const std::byte* sourceBegin
  ) noexcept
  {
    return CopyBackwardStride(destination, sourceEnd, sourceBegin, kThirtyTwoStride);
  }

  /**
   * Address: 0x005715D0 (FUN_005715D0)
   *
   * What it does:
   * Adapts one source-first 32-byte backward copy lane through
   * `FUN_00572F20`.
   */
  [[maybe_unused]] std::byte* CopyBackward32ByteLaneRegisterAdapterA(
    const std::byte* const sourceBegin,
    const std::byte* const sourceEnd,
    std::byte* const destinationEnd
  ) noexcept
  {
    return CopyBackward32ByteLane(destinationEnd, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x00571600 (FUN_00571600)
   *
   * What it does:
   * Secondary source-first adapter lane for the 32-byte backward copy
   * dispatcher via `FUN_00572F80`.
   */
  [[maybe_unused]] std::byte* CopyBackward32ByteLaneRegisterAdapterB(
    const std::byte* const sourceBegin,
    const std::byte* const sourceEnd,
    std::byte* const destinationEnd
  ) noexcept
  {
    return CopyBackward32ByteLane(destinationEnd, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x00723670 (FUN_00723670)
   *
   * What it does:
   * Tiny adapter lane that forwards destination-only dispatch to the canonical
   * backward 32-byte copy helper with an empty source range.
   */
  [[maybe_unused]] std::byte* CopyBackward32ByteLaneEmptyRangeAdapterA(
    std::byte* const destinationEnd,
    const std::byte* const unusedRangeToken
  ) noexcept
  {
    (void)unusedRangeToken;
    return CopyBackward32ByteLane(destinationEnd, nullptr, nullptr);
  }

  /**
   * Address: 0x007236A0 (FUN_007236A0)
   * Address: 0x007BEBE0 (FUN_007BEBE0)
   *
   * What it does:
   * Secondary destination-only adapter that forwards an empty source range to
   * the canonical backward 32-byte copy helper.
   */
  [[maybe_unused]] std::byte* CopyBackward32ByteLaneEmptyRangeAdapterB(
    std::byte* const destinationEnd,
    const std::byte* const unusedRangeToken
  ) noexcept
  {
    (void)unusedRangeToken;
    return CopyBackward32ByteLane(destinationEnd, nullptr, nullptr);
  }

  /**
   * Address: 0x0080F490 (FUN_0080F490)
   *
   * What it does:
   * Allocates replacement storage for one 32-byte fastvector lane and
   * materializes prefix/insert/suffix slices into the new storage.
   */
  std::byte* GrowInsert32ByteLane(
    FastVectorInsertRuntimeView& vectorView,
    const std::size_t requestedCapacity,
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* splitPosition
  )
  {
    return GrowInsertGeneric(
      vectorView,
      kThirtyTwoStride,
      requestedCapacity,
      sourceBegin,
      sourceEnd,
      splitPosition,
      &CopyForward32ByteLane
    );
  }

  /**
   * Address: 0x0080F0A0 (FUN_0080F0A0)
   * Address: 0x0056E4A0 (FUN_0056E4A0)
   * Address: 0x00723200 (FUN_00723200)
   *
   * What it does:
   * Inserts one 32-byte range before `insertPosition`, growing storage when
   * capacity is insufficient.
   */
  std::byte* AppendRange32ByteLane(
    FastVectorInsertRuntimeView& vectorView,
    std::byte* insertPosition,
    const std::byte* sourceBegin,
    const std::byte* sourceEnd
  )
  {
    return AppendRangeGeneric(
      vectorView,
      insertPosition,
      sourceBegin,
      sourceEnd,
      kThirtyTwoStride,
      &CopyForward32ByteLane,
      &GrowInsert32ByteLane
    );
  }

  /**
   * Address: 0x00722F10 (FUN_00722F10)
   *
   * What it does:
   * Appends one 32-byte element lane and delegates to range growth insertion
   * when the destination fastvector has no spare capacity.
   */
  [[maybe_unused]] std::byte* PushBack32ByteElementLane(
    FastVectorInsertRuntimeView& vectorView,
    const std::byte* const sourceElement
  )
  {
    std::byte* const write = vectorView.finish;
    if (write == vectorView.capacity) {
      return AppendRange32ByteLane(vectorView, write, sourceElement, sourceElement + kThirtyTwoStride);
    }

    if (write != nullptr && sourceElement != nullptr) {
      std::memcpy(write, sourceElement, kThirtyTwoStride);
    }

    vectorView.finish = write + kThirtyTwoStride;
    return write;
  }

  /**
   * Address: 0x0081BC90 (FUN_0081BC90)
   * Address: 0x0065FA50 (FUN_0065FA50)
   * Address: 0x006A0F70 (FUN_006A0F70)
   * Address: 0x006828B0 (FUN_006828B0)
   * Address: 0x0069FA60 (FUN_0069FA60)
   * Address: 0x0069FA90 (FUN_0069FA90)
   * Address: 0x0067F950 (FUN_0067F950)
   * Address: 0x00516670 (FUN_00516670)
   *
   * What it does:
   * Copies 12-byte elements from `[sourceBegin, sourceEnd)` into `destination`
   * and returns the advanced destination lane.
   */
  std::byte* CopyForward12ByteLane(
    std::byte* destination,
    const std::byte* sourceEnd,
    const std::byte* sourceBegin
  ) noexcept
  {
    return CopyForwardStride(destination, sourceEnd, sourceBegin, kTwelveStride);
  }

  /**
   * Address: 0x0067F920 (FUN_0067F920)
   * Address: 0x00680B10 (FUN_00680B10)
   * Address: 0x00681C20 (FUN_00681C20)
   * Address: 0x00682340 (FUN_00682340)
   * Address: 0x006A02A0 (FUN_006A02A0)
   * Address: 0x006A0CF0 (FUN_006A0CF0)
   * Address: 0x006A0E70 (FUN_006A0E70)
   *
   * What it does:
   * Register-shape adapter that forwards one 12-byte forward range copy lane
   * into the canonical null-tolerant copy helper.
   */
  [[maybe_unused]] std::byte* CopyForward12ByteLaneRegisterAdapterAllowNullDestination(
    const std::byte* const sourceBegin,
    const std::byte* const sourceEnd,
    std::byte* const destination
  ) noexcept
  {
    return CopyForward12ByteLane(destination, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x00517090 (FUN_00517090)
   * Address: 0x005170C0 (FUN_005170C0)
   * Address: 0x0069FAB0 (FUN_0069FAB0)
   * Address: 0x0067F970 (FUN_0067F970)
   *
   * What it does:
   * Copies 12-byte elements backward from `[sourceBegin, sourceEnd)` into the
   * destination tail lane.
   */
  std::byte* CopyBackward12ByteLane(
    std::byte* destinationEnd,
    const std::byte* sourceEnd,
    const std::byte* sourceBegin
  ) noexcept
  {
    return CopyBackwardStride(destinationEnd, sourceEnd, sourceBegin, kTwelveStride);
  }

  /**
   * Address: 0x0081BBC0 (FUN_0081BBC0)
   * Address: 0x005165A0 (FUN_005165A0, Vector3f fastvector grow-insert inline clone)
   *
   * What it does:
   * Allocates replacement storage for one 12-byte fastvector lane and
   * materializes prefix/insert/suffix slices into the new storage. The
   * 0x005165A0 entry is a separate compiler-emitted inline clone used by
   * `RFastVectorType_Vector3f::SetCount`, the matching `AppendRange12ByteLane`
   * caller, the in-place assign lane, and a stubbed shim; both addresses
   * share identical semantics and feed every 12-byte fastvector grow path
   * through this single function.
   */
  std::byte* GrowInsert12ByteLane(
    FastVectorInsertRuntimeView& vectorView,
    const std::size_t requestedCapacity,
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* splitPosition
  )
  {
    return GrowInsertGeneric(
      vectorView,
      kTwelveStride,
      requestedCapacity,
      sourceBegin,
      sourceEnd,
      splitPosition,
      &CopyForward12ByteLane
    );
  }

  /**
   * Address: 0x0081B830 (FUN_0081B830)
   * Address: 0x00515E30 (FUN_00515E30, 12-byte append-range lane for Unit/decal clipping callers)
   *
   * What it does:
   * Inserts one 12-byte range before `insertPosition`, growing storage when
   * capacity is insufficient.
   */
  std::byte* AppendRange12ByteLane(
    FastVectorInsertRuntimeView& vectorView,
    std::byte* insertPosition,
    const std::byte* sourceBegin,
    const std::byte* sourceEnd
  )
  {
    return AppendRangeGeneric(
      vectorView,
      insertPosition,
      sourceBegin,
      sourceEnd,
      kTwelveStride,
      &CopyForward12ByteLane,
      &GrowInsert12ByteLane
    );
  }

  /**
   * Address: 0x0081B6E0 (FUN_0081B6E0, gpg::fastvector_Circle2f::push_back)
   *
   * What it does:
   * Appends one 12-byte element lane and delegates to range growth insertion
   * when the destination fastvector has no spare capacity.
   */
  [[maybe_unused]] std::byte* PushBack12ByteElementLane(
    FastVectorInsertRuntimeView& vectorView,
    const std::byte* const sourceElement
  )
  {
    std::byte* const write = vectorView.finish;
    if (write == vectorView.capacity) {
      return AppendRange12ByteLane(vectorView, write, sourceElement, sourceElement + kTwelveStride);
    }

    if (write != nullptr && sourceElement != nullptr) {
      std::memcpy(write, sourceElement, kTwelveStride);
    }

    vectorView.finish = write + kTwelveStride;
    return write;
  }

  namespace
  {
    /**
     * Address: 0x006C1030 (FUN_006C1030)
     *
     * What it does:
     * Copies 16-byte elements from `[sourceBegin, sourceEnd)` into `destination`
     * and returns the advanced destination lane.
     */
    [[nodiscard]] std::byte* CopyForward16ByteLaneInternal(
      std::byte* destination,
      const std::byte* sourceEnd,
      const std::byte* sourceBegin
    ) noexcept
    {
      return CopyForwardStride(destination, sourceEnd, sourceBegin, kSixteenStride);
    }

    [[nodiscard]] std::byte* GrowInsert16ByteLane(
      FastVectorInsertRuntimeView& vectorView,
      const std::size_t requestedCapacity,
      const std::byte* sourceBegin,
      const std::byte* sourceEnd,
      std::byte* splitPosition
    )
    {
      return GrowInsertGeneric(
        vectorView,
        kSixteenStride,
        requestedCapacity,
        sourceBegin,
        sourceEnd,
        splitPosition,
        &CopyForward16ByteLaneInternal
      );
    }
  } // namespace

  /**
   * Address: 0x006C0DE0 (FUN_006C0DE0)
   *
   * What it does:
   * Inserts one 16-byte range before `insertPosition`, growing storage when
   * capacity is insufficient.
   */
  std::byte* AppendRange16ByteLane(
    FastVectorInsertRuntimeView& vectorView,
    std::byte* insertPosition,
    const std::byte* sourceBegin,
    const std::byte* sourceEnd
  )
  {
    return AppendRangeGeneric(
      vectorView,
      insertPosition,
      sourceBegin,
      sourceEnd,
      kSixteenStride,
      &CopyForward16ByteLaneInternal,
      &GrowInsert16ByteLane
    );
  }

  /**
   * Address: 0x007F0C50 (FUN_007F0C50)
   *
   * What it does:
   * Copies 16-byte elements from `[sourceBegin, rangeEnd)` into `destination`,
   * stores the copied begin in `outBegin`, and advances `rangeEnd` to the
   * copied tail.
   */
  std::byte* CopyForward16ByteLaneWithBeginOut(
    std::byte*& outBegin,
    std::byte* destination,
    std::byte*& rangeEnd,
    const std::byte* sourceBegin
  ) noexcept
  {
    std::byte* const copiedEnd = CopyForwardStride(destination, rangeEnd, sourceBegin, kSixteenStride);
    rangeEnd = copiedEnd;
    outBegin = destination;
    return copiedEnd;
  }

  /**
   * Address: 0x0067F8F0 (FUN_0067F8F0)
   * Address: 0x00517200 (FUN_00517200)
   *
   * What it does:
   * Copies 16-byte elements from `[sourceBegin, sourceEnd)` into `destination`
   * and returns the advanced destination lane.
   */
  std::byte* CopyForward16ByteLane(
    std::byte* destination,
    const std::byte* sourceEnd,
    const std::byte* sourceBegin
  ) noexcept
  {
    return CopyForwardStride(destination, sourceEnd, sourceBegin, kSixteenStride);
  }

  /**
   * Address: 0x0059DC60 (FUN_0059DC60)
   * Address: 0x006C1170 (FUN_006C1170)
   * Address: 0x006C11B0 (FUN_006C11B0)
   *
   * What it does:
   * Copies 16-byte elements backward from `[sourceBegin, sourceEnd)` into the
   * destination tail lane and returns the destination begin.
   */
  std::byte* CopyBackward16ByteLane(
    std::byte* destinationEnd,
    const std::byte* sourceEnd,
    const std::byte* sourceBegin
  ) noexcept
  {
    return CopyBackwardStride(destinationEnd, sourceEnd, sourceBegin, kSixteenStride);
  }

  /**
   * Address: 0x0056F2A0 (FUN_0056F2A0)
   *
   * What it does:
   * Copies 16-byte lanes from `[sourceBegin, vectorView.finish)` into
   * `destinationBegin`, advances `vectorView.finish`, and returns
   * `destinationBegin`.
   */
  std::byte* CopyForward16ByteLaneAndUpdateFinish(
    std::byte* const destinationBegin,
    std::byte* const sourceBegin,
    FastVectorInsertRuntimeView& vectorView
  ) noexcept
  {
    if (destinationBegin == sourceBegin) {
      return destinationBegin;
    }

    std::byte* const write = CopyForwardStride(destinationBegin, vectorView.finish, sourceBegin, kSixteenStride);
    vectorView.finish = write;
    return destinationBegin;
  }

  /**
   * Address: 0x008F63C0 (FUN_008F63C0)
   * Address: 0x00693260 (FUN_00693260)
   *
   * What it does:
   * Writes one repeated 28-byte source lane into destination slots in
   * `[destinationBegin, destinationEnd)`.
   */
  void Fill28ByteLaneRangeFromSingle(
    std::byte* const destinationBegin,
    std::byte* const destinationEnd,
    const std::byte* const sourceElement
  ) noexcept
  {
    FillRangeFromSingleStride(destinationBegin, destinationEnd, sourceElement, kTwentyEightStride);
  }

  /**
   * Address: 0x00693140 (FUN_00693140)
   *
   * What it does:
   * Tail-thunk alias that forwards 28-byte repeated-fill lanes into the shared
   * fill body.
   */
  [[maybe_unused]] void Fill28ByteLaneRangeFromSingleThunk(
    std::byte* const destinationBegin,
    std::byte* const destinationEnd,
    const std::byte* const sourceElement
  ) noexcept
  {
    Fill28ByteLaneRangeFromSingle(destinationBegin, destinationEnd, sourceElement);
  }

  /**
   * Address: 0x0064F7C0 (FUN_0064F7C0)
   *
   * What it does:
   * Tail-thunk alias that forwards 52-byte repeated-fill lanes into the shared
   * fill body.
   */
  [[maybe_unused]] void Fill52ByteLaneRangeFromSingleThunk(
    std::byte* const destinationBegin,
    std::byte* const destinationEnd,
    const std::byte* const sourceElement
  ) noexcept
  {
    Fill52ByteLaneRangeFromSingle(destinationBegin, destinationEnd, sourceElement);
  }

  /**
   * Address: 0x0064FB10 (FUN_0064FB10)
   *
   * What it does:
   * Writes one repeated 52-byte source lane into destination slots in
   * `[destinationBegin, destinationEnd)`.
   */
  void Fill52ByteLaneRangeFromSingle(
    std::byte* const destinationBegin,
    std::byte* const destinationEnd,
    const std::byte* const sourceElement
  ) noexcept
  {
    FillRangeFromSingleStride(destinationBegin, destinationEnd, sourceElement, kFiftyTwoStride);
  }

  /**
   * Address: 0x0065004D (FUN_0065004D)
   *
   * What it does:
   * Debug-trap adapter lane that breaks into debugger and then forwards to the
   * shared 52-byte backward-copy helper.
   */
  [[maybe_unused]] std::byte* CopyBackward52ByteLaneDebugTrapAdapter(
    std::byte* const destination,
    const std::byte* const sourceEnd,
    const std::byte* const sourceBegin
  ) noexcept
  {
#if defined(_MSC_VER)
    __debugbreak();
#endif
    return CopyBackwardStride(destination, sourceEnd, sourceBegin, kFiftyTwoStride);
  }

  /**
   * Address: 0x00650050 (FUN_00650050)
   *
   * What it does:
   * Copies 52-byte elements backward from `[sourceBegin, sourceEnd)` into the
   * destination tail lane.
   */
  std::byte* CopyBackward52ByteLane(
    std::byte* destination,
    const std::byte* sourceEnd,
    const std::byte* sourceBegin
  ) noexcept
  {
    return CopyBackwardStride(destination, sourceEnd, sourceBegin, kFiftyTwoStride);
  }

  /**
   * Address: 0x0064FB90 (FUN_0064FB90)
   *
   * What it does:
   * Adapts one legacy register/stack caller shape into the canonical
   * backward 52-byte range-copy helper.
   */
  [[maybe_unused]] std::byte* CopyBackward52ByteLaneRegisterAdapter(
    const std::byte* const sourceBegin,
    const std::byte* const sourceEnd,
    std::byte* const destinationEnd
  ) noexcept
  {
    return CopyBackward52ByteLane(destinationEnd, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x0092BD70 (FUN_0092BD70)
   *
   * What it does:
   * Copies 2-byte elements from `[sourceBegin, sourceEnd)` into `destination`
   * and returns the advanced destination lane.
   */
  std::byte* CopyForwardWordLane(
    std::byte* destination,
    const std::byte* sourceEnd,
    const std::byte* sourceBegin
  ) noexcept
  {
    return CopyForwardStride(destination, sourceEnd, sourceBegin, kWordStride);
  }

  /**
   * Address: 0x0092CBF0 (FUN_0092CBF0)
   *
   * What it does:
   * Allocates replacement storage for one 2-byte fastvector lane and
   * materializes prefix/insert/suffix slices into the new storage.
   */
  std::byte* GrowInsertWordLane(
    FastVectorInsertRuntimeView& vectorView,
    const std::size_t requestedCapacity,
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* splitPosition
  )
  {
    return GrowInsertGeneric(
      vectorView,
      kWordStride,
      requestedCapacity,
      sourceBegin,
      sourceEnd,
      splitPosition,
      &CopyForwardWordLane
    );
  }

  /**
   * Address: 0x0092D9B0 (FUN_0092D9B0)
   *
   * What it does:
   * Inserts one 2-byte range before `insertPosition`, growing storage when
   * capacity is insufficient.
   */
  std::byte* AppendRangeWordLane(
    FastVectorInsertRuntimeView& vectorView,
    std::byte* insertPosition,
    const std::byte* sourceBegin,
    const std::byte* sourceEnd
  )
  {
    return AppendRangeGeneric(
      vectorView,
      insertPosition,
      sourceBegin,
      sourceEnd,
      kWordStride,
      &CopyForwardWordLane,
      &GrowInsertWordLane
    );
  }

  struct FastVectorWordLaneRuntimeView
  {
    std::int16_t* start;        // +0x00
    std::int16_t* end;          // +0x04
    std::int16_t* capacity;     // +0x08
    std::int16_t* inlineOrigin; // +0x0C
  };
  static_assert(sizeof(FastVectorWordLaneRuntimeView) == sizeof(FastVectorInsertRuntimeView), "FastVectorWordLaneRuntimeView size must match FastVectorInsertRuntimeView");

  /**
   * Address: 0x0092E380 (FUN_0092E380)
   *
   * What it does:
   * Appends one 2-byte element at the tail of one fastvector word lane,
   * growing storage through `AppendRangeWordLane` when the tail reaches
   * capacity.
   */
  [[maybe_unused]] std::int16_t* AppendSingleWordLaneFromPointerAtTail(
    FastVectorWordLaneRuntimeView* const vector,
    const std::int16_t* const sourceValue
  )
  {
    std::int16_t* const tail = vector->end;
    if (tail == vector->capacity) {
      auto& insertView = reinterpret_cast<FastVectorInsertRuntimeView&>(*vector);
      const std::byte* const sourceBegin = reinterpret_cast<const std::byte*>(sourceValue);
      const std::byte* const sourceEnd = sourceBegin + sizeof(std::int16_t);
      return reinterpret_cast<std::int16_t*>(
        AppendRangeWordLane(
          insertView,
          reinterpret_cast<std::byte*>(tail),
          sourceBegin,
          sourceEnd
        )
      );
    }

    if (tail != nullptr) {
      *tail = *sourceValue;
    }
    vector->end = tail + 1;
    return tail;
  }

  /**
   * Address: 0x0080F660 (FUN_0080F660)
   * Address: 0x0082E7A0 (FUN_0082E7A0)
   * Address: 0x0084ED40 (FUN_0084ED40)
   * Address: 0x00868500 (FUN_00868500)
   * Address: 0x005407F0 (FUN_005407F0)
   * Address: 0x0059D370 (FUN_0059D370)
   * Address: 0x005C6CF0 (FUN_005C6CF0)
   * Address: 0x005D44A0 (FUN_005D44A0)
   * Address: 0x006FBE40 (FUN_006FBE40)
   * Address: 0x00702E40 (FUN_00702E40)
   * Address: 0x0072AB30 (FUN_0072AB30)
   * Address: 0x00774260 (FUN_00774260)
   * Address: 0x006E3ED0 (FUN_006E3ED0)
   * Address: 0x00706080 (FUN_00706080)
   * Address: 0x006E2D10 (FUN_006E2D10)
   * Address: 0x006E35A0 (FUN_006E35A0)
   * Address: 0x00704270 (FUN_00704270)
   *
   * What it does:
   * Copies 4-byte elements from `[sourceBegin, sourceEnd)` into `destination`
   * and returns the advanced destination lane.
   */
  std::byte* CopyForwardDwordLane(
    std::byte* destination,
    const std::byte* sourceEnd,
    const std::byte* sourceBegin
  ) noexcept
  {
    return CopyForwardStride(destination, sourceEnd, sourceBegin, kDwordStride);
  }

  /**
   * Address: 0x007052D0 (FUN_007052D0)
   *
   * What it does:
   * Register-order adapter that forwards one 4-byte range copy lane to
   * `CopyForwardDwordLane`.
   */
  [[maybe_unused]] std::byte* CopyForwardDwordLaneRegisterOrderAdapter(
    const std::byte* sourceEnd,
    const std::byte* sourceBegin,
    std::byte* destination
  ) noexcept
  {
    return CopyForwardDwordLane(destination, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x007655C0 (FUN_007655C0)
   *
   * What it does:
   * Register-order adapter that forwards one 4-byte range copy lane to
   * `CopyForwardDwordLane`.
   */
  [[maybe_unused]] std::byte* CopyForwardDwordLaneRegisterOrderAdapterVariantA(
    const std::byte* sourceEnd,
    const std::byte* sourceBegin,
    std::byte* destination
  ) noexcept
  {
    return CopyForwardDwordLane(destination, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x007656E0 (FUN_007656E0)
   *
   * What it does:
   * Register-order adapter that forwards one 4-byte range copy lane to
   * `CopyForwardDwordLane`.
   */
  [[maybe_unused]] std::byte* CopyForwardDwordLaneRegisterOrderAdapterVariantB(
    const std::byte* sourceEnd,
    const std::byte* sourceBegin,
    std::byte* destination
  ) noexcept
  {
    return CopyForwardDwordLane(destination, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x006E34C0 (FUN_006E34C0)
   *
   * What it does:
   * Register-shape forwarding lane for one dword copy range into
   * `CopyForwardDwordLane`.
   */
  [[maybe_unused]] std::byte* CopyForwardDwordLaneRegisterOrderAdapterVariantC(
    const std::byte* sourceEnd,
    const std::byte* sourceBegin,
    std::byte* destination
  ) noexcept
  {
    return CopyForwardDwordLane(destination, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x006E3D10 (FUN_006E3D10)
   *
   * What it does:
   * Mirrored register-shape forwarding lane for one dword copy range into
   * `CopyForwardDwordLane`.
   */
  [[maybe_unused]] std::byte* CopyForwardDwordLaneRegisterOrderAdapterVariantD(
    const std::byte* sourceEnd,
    const std::byte* sourceBegin,
    std::byte* destination
  ) noexcept
  {
    return CopyForwardDwordLane(destination, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x0080F590 (FUN_0080F590)
   * Address: 0x0082E6D0 (FUN_0082E6D0)
   * Address: 0x0084EC70 (FUN_0084EC70)
   * Address: 0x00868430 (FUN_00868430)
   * Address: 0x00540720 (FUN_00540720)
   * Address: 0x0059D2A0 (FUN_0059D2A0)
   * Address: 0x005C6C20 (FUN_005C6C20)
   * Address: 0x005D43D0 (FUN_005D43D0)
   * Address: 0x006FBD70 (FUN_006FBD70)
   * Address: 0x00702D70 (FUN_00702D70)
   * Address: 0x0072AA60 (FUN_0072AA60)
   * Address: 0x00774190 (FUN_00774190)
   * Address: 0x00553B90 (FUN_00553B90, SSyncData uint dword grow/insert lane)
   * Address: 0x00559190 (FUN_00559190, SSTIEntityAttachInfo dword grow/insert lane)
   * Address: 0x00657F60 (FUN_00657F60, fastvector<float> dword grow/insert lane)
   *
   * What it does:
   * Allocates replacement storage for one 4-byte fastvector lane and
   * materializes prefix/insert/suffix slices into the new storage.
   */
  std::byte* GrowInsertDwordLane(
    FastVectorInsertRuntimeView& vectorView,
    const std::size_t requestedCapacity,
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* splitPosition
  )
  {
    return GrowInsertGeneric(
      vectorView,
      kDwordStride,
      requestedCapacity,
      sourceBegin,
      sourceEnd,
      splitPosition,
      &CopyForwardDwordLane
    );
  }

  /**
   * Address: 0x0080F210 (FUN_0080F210)
   * Address: 0x0082CF20 (FUN_0082CF20)
   * Address: 0x0084E740 (FUN_0084E740)
   * Address: 0x00867D40 (FUN_00867D40)
   * Address: 0x00540130 (FUN_00540130)
   * Address: 0x0059CD10 (FUN_0059CD10)
   * Address: 0x005C5270 (FUN_005C5270)
   * Address: 0x005D4020 (FUN_005D4020)
   * Address: 0x006FBC40 (FUN_006FBC40)
   * Address: 0x00702330 (FUN_00702330)
   * Address: 0x0072A850 (FUN_0072A850)
   * Address: 0x00774000 (FUN_00774000)
   *
   * What it does:
   * Inserts one 4-byte range before `insertPosition`, growing storage when
   * capacity is insufficient.
   */
  std::byte* AppendRangeDwordLane(
    FastVectorInsertRuntimeView& vectorView,
    std::byte* insertPosition,
    const std::byte* sourceBegin,
    const std::byte* sourceEnd
  )
  {
    return AppendRangeGeneric(
      vectorView,
      insertPosition,
      sourceBegin,
      sourceEnd,
      kDwordStride,
      &CopyForwardDwordLane,
      &GrowInsertDwordLane
    );
  }

  /**
   * Address: 0x008224E0 (FUN_008224E0, gpg::fastvector_UserUnit::push_back)
   *
   * What it does:
   * Inserts one `UserUnit*` pointer range into the destination dword lane,
   * preserving the legacy overlap-safe copy/move path and grow semantics.
   */
  std::byte* PushBackUserUnitPointerRange(
    FastVectorInsertRuntimeView& vectorView,
    std::byte* insertPosition,
    const std::byte* sourceBegin,
    const std::byte* sourceEnd
  )
  {
    return AppendRangeDwordLane(vectorView, insertPosition, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x0072A470 (FUN_0072A470)
   *
   * What it does:
   * Appends one 4-byte element lane and delegates to range growth insertion
   * when the destination fastvector has no spare capacity.
   */
  [[maybe_unused]] std::byte* PushBackDwordElementLane(
    FastVectorInsertRuntimeView& vectorView,
    const std::byte* const sourceElement
  )
  {
    std::byte* const write = vectorView.finish;
    if (write == vectorView.capacity) {
      return AppendRangeDwordLane(vectorView, write, sourceElement, sourceElement + kDwordStride);
    }

    if (write != nullptr && sourceElement != nullptr) {
      *reinterpret_cast<std::uint32_t*>(write) = *reinterpret_cast<const std::uint32_t*>(sourceElement);
    }

    vectorView.finish = write + kDwordStride;
    return write;
  }

  /**
   * Address: 0x008D8190 (FUN_008D8190)
   * Address: 0x008D81C0 (FUN_008D81C0)
   *
   * What it does:
   * Copies 4-byte elements from `[sourceBegin, sourceEnd)` into `destination`
   * when the source range is provided first.
   */
  std::byte* CopyForwardDwordLaneSourceFirst(
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* destination
  ) noexcept
  {
    return CopyForwardStride(destination, sourceEnd, sourceBegin, kDwordStride);
  }

  /**
   * Address: 0x008D7DF0 (FUN_008D7DF0)
   *
   * What it does:
   * Forwards one source-first 4-byte lane copy through the shared
   * `FUN_008D8190` dword source-first copy lane.
   */
  [[maybe_unused]] std::byte* CopyForwardDwordLaneSourceFirstDelegatePrimary(
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* destination
  ) noexcept
  {
    return CopyForwardDwordLaneSourceFirst(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x008D7E50 (FUN_008D7E50)
   *
   * What it does:
   * Forwards one source-first 4-byte lane copy through the shared
   * `FUN_008D81C0` dword source-first copy lane.
   */
  [[maybe_unused]] std::byte* CopyForwardDwordLaneSourceFirstDelegateSecondary(
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* destination
  ) noexcept
  {
    return CopyForwardDwordLaneSourceFirst(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x008EA850 (FUN_008EA850)
   *
   * What it does:
   * Forwards one source-first 4-byte lane copy through the shared
   * `FUN_008D8190` dword source-first copy lane.
   */
  [[maybe_unused]] std::byte* CopyForwardDwordLaneSourceFirstDelegateTertiary(
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* destination
  ) noexcept
  {
    return CopyForwardDwordLaneSourceFirst(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x008EA880 (FUN_008EA880)
   *
   * What it does:
   * Forwards one source-first 4-byte lane copy through the shared
   * `FUN_008D81C0` dword source-first copy lane.
   */
  [[maybe_unused]] std::byte* CopyForwardDwordLaneSourceFirstDelegateQuaternary(
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* destination
  ) noexcept
  {
    return CopyForwardDwordLaneSourceFirst(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x008EA450 (FUN_008EA450)
   *
   * What it does:
   * Adapter lane forwarding one source-first 4-byte copy range through
   * `CopyForwardDwordLaneSourceFirst`.
   */
  [[maybe_unused]] std::byte* CopyForwardDwordLaneSourceFirstAdapterA(
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* destination
  ) noexcept
  {
    return CopyForwardDwordLaneSourceFirst(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x008EA470 (FUN_008EA470)
   *
   * What it does:
   * Secondary adapter lane forwarding one source-first 4-byte copy range
   * through `CopyForwardDwordLaneSourceFirst`.
   */
  [[maybe_unused]] std::byte* CopyForwardDwordLaneSourceFirstAdapterB(
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* destination
  ) noexcept
  {
    return CopyForwardDwordLaneSourceFirst(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x008EA660 (FUN_008EA660)
   *
   * What it does:
   * Third adapter lane forwarding one source-first 4-byte copy range through
   * `CopyForwardDwordLaneSourceFirst`.
   */
  [[maybe_unused]] std::byte* CopyForwardDwordLaneSourceFirstAdapterC(
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* destination
  ) noexcept
  {
    return CopyForwardDwordLaneSourceFirst(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x008EA690 (FUN_008EA690)
   *
   * What it does:
   * Fourth adapter lane forwarding one source-first 4-byte copy range through
   * `CopyForwardDwordLaneSourceFirst`.
   */
  [[maybe_unused]] std::byte* CopyForwardDwordLaneSourceFirstAdapterD(
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* destination
  ) noexcept
  {
    return CopyForwardDwordLaneSourceFirst(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x008D7F90 (FUN_008D7F90)
   *
   * What it does:
   * Forwards one source-first 12-byte lane copy through the shared
   * `FUN_008D8150` 12-byte source-first copy lane.
   */
  std::byte* CopyForward12ByteLaneSourceFirstInlineAdapter(
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* destination
  ) noexcept
  {
    return CopyForward12ByteLaneSourceFirst(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x008D8000 (FUN_008D8000)
   *
   * What it does:
   * Forwards one source-first 4-byte lane copy through the shared
   * `FUN_008D8190` dword source-first copy lane.
   */
  std::byte* CopyForwardDwordLaneSourceFirstInlineAdapterPrimary(
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* destination
  ) noexcept
  {
    return CopyForwardDwordLaneSourceFirst(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x008D8070 (FUN_008D8070)
   *
   * What it does:
   * Forwards one source-first 4-byte lane copy through the shared
   * `FUN_008D81C0` dword source-first copy lane.
   */
  std::byte* CopyForwardDwordLaneSourceFirstInlineAdapterSecondary(
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* destination
  ) noexcept
  {
    return CopyForwardDwordLaneSourceFirst(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x0072AE40 (FUN_0072AE40)
   *
   * What it does:
   * Moves one dword range `[sourceBegin, sourceEnd)` into a destination tail
   * ending at `destinationEnd` and returns the destination begin pointer.
   */
  [[maybe_unused]] std::byte* MoveDwordRangeToTail(
    std::byte* const sourceEnd,
    std::byte* const destinationEnd,
    const std::byte* const sourceBegin
  ) noexcept
  {
    const std::ptrdiff_t elementCount = (sourceEnd - sourceBegin) / static_cast<std::ptrdiff_t>(kDwordStride);
    std::byte* const destinationBegin = destinationEnd - (elementCount * static_cast<std::ptrdiff_t>(kDwordStride));
    if (elementCount > 0) {
      const std::size_t bytes = static_cast<std::size_t>(elementCount) * kDwordStride;
      (void)memmove_s(destinationBegin, bytes, sourceBegin, bytes);
    }
    return destinationBegin;
  }

  /**
   * Address: 0x008D8150 (FUN_008D8150)
   *
   * What it does:
   * Copies 12-byte elements from `[sourceBegin, sourceEnd)` into `destination`
   * when the source range is provided first.
   */
  std::byte* CopyForward12ByteLaneSourceFirst(
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* destination
  ) noexcept
  {
    return CopyForwardStride(destination, sourceEnd, sourceBegin, kTwelveStride);
  }

  /**
   * Address: 0x007547D0 (FUN_007547D0)
   *
   * What it does:
   * Bridges one 12-byte source-first copy lane where the source-end bound was
   * supplied through a hidden register lane in the original call shape.
   */
  [[maybe_unused]] std::byte* CopyForward12ByteLaneSourceFirstHiddenEndRegisterAdapter(
    const std::byte* const sourceBegin,
    const std::byte* const sourceEnd,
    std::byte* const destination
  ) noexcept
  {
    return CopyForward12ByteLane(destination, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x008EA820 (FUN_008EA820)
   *
   * What it does:
   * Forwards one source-first 12-byte lane copy through the shared
   * `FUN_008D8150` 12-byte source-first copy lane.
   */
  [[maybe_unused]] std::byte* CopyForward12ByteLaneSourceFirstDelegate(
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* destination
  ) noexcept
  {
    return CopyForward12ByteLaneSourceFirst(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x008EA430 (FUN_008EA430)
   *
   * What it does:
   * Adapter lane forwarding one source-first 12-byte copy range through
   * `CopyForward12ByteLaneSourceFirst`.
   */
  [[maybe_unused]] std::byte* CopyForward12ByteLaneSourceFirstAdapterA(
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* destination
  ) noexcept
  {
    return CopyForward12ByteLaneSourceFirst(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x008EA630 (FUN_008EA630)
   *
   * What it does:
   * Secondary adapter lane forwarding one source-first 12-byte copy range
   * through `CopyForward12ByteLaneSourceFirst`.
   */
  [[maybe_unused]] std::byte* CopyForward12ByteLaneSourceFirstAdapterB(
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* destination
  ) noexcept
  {
    return CopyForward12ByteLaneSourceFirst(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x008F64A0 (FUN_008F64A0)
   * Address: 0x008F64D0 (FUN_008F64D0)
   * Address: 0x008F6810 (FUN_008F6810)
   *
   * What it does:
   * Copies 28-byte elements from `[sourceBegin, sourceEnd)` into `destination`
   * when the source range is provided first.
   */
  std::byte* CopyForward28ByteLaneSourceFirst(
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* destination
  ) noexcept
  {
    return CopyForwardStride(destination, sourceEnd, sourceBegin, kTwentyEightStride);
  }

  /**
   * Address: 0x008F6620 (FUN_008F6620)
   *
   * What it does:
   * Forwarding lane that routes one source-first 28-byte range copy into
   * `FUN_008F64D0`.
   */
  [[maybe_unused]] std::byte* CopyForward28ByteLaneSourceFirstAdapterA(
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* destination
  ) noexcept
  {
    return CopyForward28ByteLaneSourceFirst(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x008F66C0 (FUN_008F66C0)
   *
   * What it does:
   * Secondary forwarding lane that routes one source-first 28-byte range
   * copy into `FUN_008F64D0`.
   */
  [[maybe_unused]] std::byte* CopyForward28ByteLaneSourceFirstAdapterB(
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* destination
  ) noexcept
  {
    return CopyForward28ByteLaneSourceFirst(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x008F6760 (FUN_008F6760)
   *
   * What it does:
   * Tertiary forwarding lane that routes one source-first 28-byte range copy
   * into `FUN_008F64D0`.
   */
  [[maybe_unused]] std::byte* CopyForward28ByteLaneSourceFirstAdapterC(
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* destination
  ) noexcept
  {
    return CopyForward28ByteLaneSourceFirst(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x008F66E0 (FUN_008F66E0)
   *
   * What it does:
   * Forwards one source-first 28-byte lane copy through the shared
   * `FUN_008F64D0` 28-byte source-first copy lane.
   */
  [[maybe_unused]] std::byte* CopyForward28ByteLaneSourceFirstDelegate(
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* destination
  ) noexcept
  {
    return CopyForward28ByteLaneSourceFirst(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x00756990 (FUN_00756990)
   * Address: 0x00753D60 (FUN_00753D60)
   *
   * What it does:
   * Copies 40-byte elements from `[sourceBegin, sourceEnd)` into `destination`
   * when the source range is provided first.
   */
  std::byte* CopyForward40ByteLaneSourceFirst(
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* destination
  ) noexcept
  {
    return CopyForwardStride(destination, sourceEnd, sourceBegin, kFortyStride);
  }

  /**
   * Address: 0x00751B20 (FUN_00751B20)
   *
   * What it does:
   * Tail-jump adapter lane that forwards one 40-byte source-first copy range
   * into `FUN_00753D60`.
   */
  [[maybe_unused]] std::byte* CopyForward40ByteLaneSourceFirstJumpAdapter(
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* destination
  ) noexcept
  {
    return CopyForward40ByteLaneSourceFirst(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x00753D40 (FUN_00753D40)
   *
   * What it does:
   * Source-first forwarding adapter lane that routes one 40-byte range copy
   * into `FUN_00756990` while discarding one zero scratch lane.
   */
  [[maybe_unused]] std::byte* CopyForward40ByteLaneSourceFirstNullScratchAdapterA(
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* destination
  ) noexcept
  {
    return CopyForward40ByteLaneSourceFirst(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x00755950 (FUN_00755950)
   *
   * What it does:
   * Duplicate source-first forwarding adapter lane for one 40-byte range copy
   * into `FUN_00756990`.
   */
  [[maybe_unused]] std::byte* CopyForward40ByteLaneSourceFirstNullScratchAdapterB(
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* destination
  ) noexcept
  {
    return CopyForward40ByteLaneSourceFirst(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x00755D90 (FUN_00755D90)
   *
   * What it does:
   * Third source-first forwarding adapter lane for one 40-byte range copy
   * into `FUN_00756990`.
   */
  [[maybe_unused]] std::byte* CopyForward40ByteLaneSourceFirstNullScratchAdapterC(
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* destination
  ) noexcept
  {
    return CopyForward40ByteLaneSourceFirst(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x00755970 (FUN_00755970)
   *
   * What it does:
   * Copies 40-byte elements backward from `[sourceBegin, sourceEnd)` into the
   * destination tail lane when caller lanes are provided as source-first.
   */
  std::byte* CopyBackward40ByteLaneSourceFirst(
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* destinationEnd
  ) noexcept
  {
    return CopyBackwardStride(destinationEnd, sourceEnd, sourceBegin, kFortyStride);
  }

  /**
   * Address: 0x00753DD0 (FUN_00753DD0)
   *
   * What it does:
   * Source-first forwarding adapter lane that routes one 40-byte backward copy
   * into `FUN_00755970` while discarding one zero scratch lane.
   */
  [[maybe_unused]] std::byte* CopyBackward40ByteLaneSourceFirstNullScratchAdapter(
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* destinationEnd
  ) noexcept
  {
    return CopyBackward40ByteLaneSourceFirst(sourceBegin, sourceEnd, destinationEnd);
  }

  /**
   * Address: 0x00751B30 (FUN_00751B30)
   *
   * What it does:
   * Duplicate source-first forwarding adapter lane that routes one 40-byte
   * backward copy into `FUN_00755970` while discarding one zero scratch lane.
   */
  [[maybe_unused]] std::byte* CopyBackward40ByteLaneSourceFirstNullScratchAdapterB(
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* destinationEnd
  ) noexcept
  {
    return CopyBackward40ByteLaneSourceFirst(sourceBegin, sourceEnd, destinationEnd);
  }

  /**
   * Address: 0x0071D700 (FUN_0071D700)
   * Address: 0x0071FC60 (FUN_0071FC60)
   * Address: 0x0071E950 (FUN_0071E950)
   * Address: 0x0071F510 (FUN_0071F510)
   * Address: 0x0071F6D0 (FUN_0071F6D0)
   *
   * What it does:
   * Copies 56-byte elements from `[sourceBegin, sourceEnd)` into `destination`
   * when the source range is provided first.
   */
  std::byte* CopyForward56ByteLaneSourceFirst(
    const std::byte* sourceBegin,
    const std::byte* sourceEnd,
    std::byte* destination
  ) noexcept
  {
    return CopyForwardStride(destination, sourceEnd, sourceBegin, kFiftySixStride);
  }

  /**
   * Address: 0x0071EC90 (FUN_0071EC90)
   *
   * What it does:
   * Register-shape adapter lane that forwards one 56-byte source-first copy
   * into `CopyForward56ByteLaneSourceFirst`.
   */
  [[maybe_unused]] std::byte* CopyForward56ByteLaneSourceFirstAdapterA(
    const std::byte* const sourceBegin,
    const std::byte* const sourceEnd,
    std::byte* const destination
  ) noexcept
  {
    return CopyForward56ByteLaneSourceFirst(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x0071D450 (FUN_0071D450)
   *
   * What it does:
   * Copies `rangeCount` trailing 56-byte lanes ending at `destinationEnd`
   * into uninitialized storage starting at `destinationEnd`.
   */
  [[maybe_unused]] std::byte* CopyForward56ByteTailRangeByCountAdapter(
    const std::int32_t rangeCount,
    std::byte* const destinationEnd
  ) noexcept
  {
    if (rangeCount <= 0 || destinationEnd == nullptr) {
      return destinationEnd;
    }

    const std::size_t elementCount = static_cast<std::size_t>(rangeCount);
    const std::size_t byteCount = elementCount * kFiftySixStride;
    const std::byte* const sourceBegin = destinationEnd - byteCount;
    return CopyForward56ByteLaneSourceFirst(sourceBegin, destinationEnd, destinationEnd);
  }

  /**
   * Address: 0x00751AF0 (FUN_00751AF0)
   *
   * What it does:
   * Copies one 40-byte lane range `[sourceBegin, sourceEnd)` into destination
   * storage starting at `sourceEnd`.
   */
  [[maybe_unused]] std::byte* CopyForward40ByteTailRangeAdapter(
    const std::byte* const sourceBegin,
    std::byte* const sourceEnd
  ) noexcept
  {
    return CopyForward40ByteLaneSourceFirst(sourceBegin, sourceEnd, sourceEnd);
  }

  /**
   * Address: 0x007535B0 (FUN_007535B0)
   *
   * What it does:
   * Copies one 12-byte tail range `[sourceCursor, owner.finish)` into
   * `destinationBegin`, updates `owner.finish`, and stores `destinationBegin`
   * through `outBegin`.
   */
  [[maybe_unused]] std::byte** CopyForward12ByteTailRangeUpdateFinishAndStoreBegin(
    std::byte** const outBegin,
    FastVectorInsertRuntimeView& owner,
    std::byte* const destinationBegin,
    const std::byte* sourceCursor
  ) noexcept
  {
    if (destinationBegin != sourceCursor) {
      std::byte* writeCursor = destinationBegin;
      if (sourceCursor != owner.finish) {
        writeCursor = CopyForward12ByteLane(destinationBegin, owner.finish, sourceCursor);
      }
      owner.finish = writeCursor;
    }

    *outBegin = destinationBegin;
    return outBegin;
  }

  /**
   * Address: 0x00753680 (FUN_00753680)
   *
   * What it does:
   * Copies one 40-byte tail range `[sourceCursor, owner.finish)` into
   * `destinationBegin`, updates `owner.finish`, and stores `destinationBegin`
   * through `outBegin`.
   */
  [[maybe_unused]] std::byte** CopyForward40ByteTailRangeUpdateFinishAndStoreBegin(
    std::byte** const outBegin,
    FastVectorInsertRuntimeView& owner,
    std::byte* const destinationBegin,
    const std::byte* const sourceCursor
  ) noexcept
  {
    if (destinationBegin != sourceCursor) {
      owner.finish = CopyForward40ByteLaneSourceFirst(sourceCursor, owner.finish, destinationBegin);
    }

    *outBegin = destinationBegin;
    return outBegin;
  }

  /**
   * Address: 0x00752830 (FUN_00752830)
   *
   * What it does:
   * Replaces destination 12-byte fastvector content with source content,
   * reusing storage when possible and reacquiring storage when capacity is
   * insufficient.
   */
  [[maybe_unused]] FastVectorInsertRuntimeView& Assign12ByteVectorRangeExactCapacity(
    FastVectorInsertRuntimeView& destination,
    const FastVectorInsertRuntimeView& source
  )
  {
    if (&destination == &source) {
      return destination;
    }

    const std::size_t sourceCount = ElementCount(source.start, source.finish, kTwelveStride);
    if (sourceCount == 0u) {
      std::byte* destinationBegin = destination.start;
      (void)CopyForward12ByteTailRangeUpdateFinishAndStoreBegin(
        &destinationBegin,
        destination,
        destination.start,
        destination.finish
      );
      return destination;
    }

    const std::size_t destinationCount = ElementCount(destination.start, destination.finish, kTwelveStride);
    if (sourceCount <= destinationCount) {
      CopyForward12ByteLane(destination.start, source.finish, source.start);
      destination.finish = destination.start + ByteCountForElements(sourceCount, kTwelveStride);
      return destination;
    }

    const std::size_t destinationCapacity = ElementCount(destination.start, destination.capacity, kTwelveStride);
    if (sourceCount <= destinationCapacity) {
      const std::byte* const splitSource = source.start + ByteCountForElements(destinationCount, kTwelveStride);
      CopyForward12ByteLane(destination.start, splitSource, source.start);
      destination.finish =
        CopyForward12ByteLaneSourceFirstHiddenEndRegisterAdapter(splitSource, source.finish, destination.finish);
      return destination;
    }

    if (destination.start != nullptr) {
      ::operator delete(destination.start);
    }

    destination.start = nullptr;
    destination.finish = nullptr;
    destination.capacity = nullptr;

    if (sourceCount != 0u && TryAcquireStorageForStride(destination, sourceCount, kTwelveStride)) {
      destination.finish =
        CopyForward12ByteLaneSourceFirstHiddenEndRegisterAdapter(source.start, source.finish, destination.start);
    }

    return destination;
  }

  /**
   * Address: 0x00752A70 (FUN_00752A70)
   *
   * What it does:
   * Replaces destination 8-byte fastvector content with source content,
   * reusing storage when possible and reacquiring storage when capacity is
   * insufficient.
   */
  [[maybe_unused]] FastVectorInsertRuntimeView& Assign8ByteVectorRangeExactCapacity(
    FastVectorInsertRuntimeView& destination,
    const FastVectorInsertRuntimeView& source
  )
  {
    if (&destination == &source) {
      return destination;
    }

    const std::size_t sourceCount = ElementCount(source.start, source.finish, kQwordStride);
    if (sourceCount == 0u) {
      if (destination.start != destination.finish) {
        destination.finish = destination.start;
      }
      return destination;
    }

    const std::size_t destinationCount = ElementCount(destination.start, destination.finish, kQwordStride);
    if (sourceCount <= destinationCount) {
      CopyForward8ByteLane(destination.start, source.finish, source.start);
      destination.finish = destination.start + ByteCountForElements(sourceCount, kQwordStride);
      return destination;
    }

    const std::size_t destinationCapacity = ElementCount(destination.start, destination.capacity, kQwordStride);
    if (sourceCount <= destinationCapacity) {
      const std::byte* const splitSource = source.start + ByteCountForElements(destinationCount, kQwordStride);
      CopyForward8ByteLane(destination.start, splitSource, source.start);
      destination.finish =
        CopyForward8ByteLaneSourceFirstHiddenEndRegisterAdapter(splitSource, source.finish, destination.finish);
      return destination;
    }

    if (destination.start != nullptr) {
      ::operator delete(destination.start);
    }

    destination.start = nullptr;
    destination.finish = nullptr;
    destination.capacity = nullptr;

    if (sourceCount != 0u && TryAcquireStorageForStride(destination, sourceCount, kQwordStride)) {
      destination.finish =
        CopyForward8ByteLaneSourceFirstHiddenEndRegisterAdapter(source.start, source.finish, destination.start);
    }

    return destination;
  }

  /**
   * Address: 0x006AF6E0 (FUN_006AF6E0)
   *
   * What it does:
   * Grows one 8-byte fastvector lane to `requestedCapacity` and materializes
   * prefix/insert/suffix slices into the replacement storage, returning the
   * requested element count lane.
   */
  [[maybe_unused]] std::size_t GrowInsert8ByteLaneAndReturnRequestedCapacity(
    const std::size_t requestedCapacity,
    FastVectorInsertRuntimeView& vectorView,
    std::byte* const splitPosition,
    const std::byte* const sourceBegin,
    const std::byte* const sourceEnd
  )
  {
    (void)GrowInsert8ByteLane(vectorView, requestedCapacity, sourceBegin, sourceEnd, splitPosition);
    return requestedCapacity;
  }

  /**
   * Address: 0x006AEAD0 (FUN_006AEAD0)
   *
   * What it does:
   * Inserts one 8-byte source range before `insertPosition`, growing storage
   * when required and preserving overlap-safe lane movement semantics.
   */
  [[maybe_unused]] std::byte* InsertRange8ByteLaneReuseOrGrow(
    FastVectorInsertRuntimeView& vectorView,
    std::byte* const insertPosition,
    const std::byte* const sourceBegin,
    const std::byte* const sourceEnd
  )
  {
    const std::size_t insertCount = ElementCount(sourceBegin, sourceEnd, kQwordStride);
    const std::size_t currentCount = ElementCount(vectorView.start, vectorView.finish, kQwordStride);
    std::size_t requiredCount = currentCount + insertCount;
    const std::size_t capacityCount = ElementCount(vectorView.start, vectorView.capacity, kQwordStride);

    if (requiredCount > capacityCount) {
      std::size_t grownCount = capacityCount * 2u;
      if (requiredCount > grownCount) {
        grownCount = requiredCount;
      }

      (void)GrowInsert8ByteLaneAndReturnRequestedCapacity(
        grownCount,
        vectorView,
        insertPosition,
        sourceBegin,
        sourceEnd
      );
      return const_cast<std::byte*>(sourceBegin);
    }

    const std::size_t insertBytes = ByteCountForElements(insertCount, kQwordStride);
    const std::byte* const originalFinish = vectorView.finish;
    std::byte* const insertionEnd = insertPosition + insertBytes;

    if (insertionEnd <= originalFinish) {
      const std::byte* const tailBegin = originalFinish - insertBytes;
      vectorView.finish = CopyForward8ByteLane(vectorView.finish, originalFinish, tailBegin);

      if (insertPosition != tailBegin) {
        std::byte* readCursor = const_cast<std::byte*>(tailBegin);
        while (readCursor != insertPosition) {
          readCursor -= kQwordStride;
          std::memcpy(readCursor + insertBytes, readCursor, kQwordStride);
        }
      }

      if (sourceBegin != sourceEnd) {
        (void)CopyBackward8ByteLane(insertionEnd, sourceEnd, sourceBegin);
      }
      return const_cast<std::byte*>(sourceBegin);
    }

    const std::size_t tailCount = ElementCount(insertPosition, originalFinish, kQwordStride);
    const std::byte* const spillBegin = sourceBegin + ByteCountForElements(tailCount, kQwordStride);

    vectorView.finish = CopyForward8ByteLane(vectorView.finish, sourceEnd, spillBegin);
    vectorView.finish = CopyForward8ByteLane(vectorView.finish, originalFinish, insertPosition);

    if (sourceBegin != spillBegin) {
      const std::ptrdiff_t delta = originalFinish - spillBegin;
      std::byte* readCursor = const_cast<std::byte*>(spillBegin);
      while (readCursor != sourceBegin) {
        readCursor -= kQwordStride;
        auto* const destinationLane = reinterpret_cast<std::byte*>(
          reinterpret_cast<std::uintptr_t>(readCursor) + static_cast<std::intptr_t>(delta)
        );
        std::memcpy(destinationLane, readCursor, kQwordStride);
      }
    }

    return const_cast<std::byte*>(spillBegin);
  }

  /**
   * Address: 0x00750A80 (FUN_00750A80)
   *
   * What it does:
   * Replaces destination 8-byte fastvector content with source content,
   * reusing capacity when possible and growing when required.
   */
  FastVectorInsertRuntimeView&
  Assign8ByteVectorRange(FastVectorInsertRuntimeView& destination, const FastVectorInsertRuntimeView& source)
  {
    if (&destination == &source) {
      return destination;
    }

    const std::size_t destinationCount = ElementCount(destination.start, destination.finish, kQwordStride);
    const std::size_t sourceCount = ElementCount(source.start, source.finish, kQwordStride);

    if (destinationCount >= sourceCount) {
      CopyForward8ByteLane(destination.start, source.finish, source.start);
      destination.finish = destination.start + ByteCountForElements(sourceCount, kQwordStride);
      return destination;
    }

    const std::size_t destinationCapacity = ElementCount(destination.start, destination.capacity, kQwordStride);
    if (sourceCount > destinationCapacity) {
      (void)GrowInsert8ByteLaneAndReturnRequestedCapacity(
        sourceCount,
        destination,
        destination.start,
        destination.start,
        destination.start
      );
    }

    const std::byte* const splitSource = source.start + ByteCountForElements(destinationCount, kQwordStride);
    CopyForward8ByteLane(destination.start, splitSource, source.start);
    (void)InsertRange8ByteLaneReuseOrGrow(destination, destination.finish, splitSource, source.finish);
    return destination;
  }

  struct InlineQwordVectorWithTagRuntimeView
  {
    FastVectorInsertRuntimeView vector; // +0x00
    std::uint64_t inlineQword = 0u;    // +0x10
    std::uint32_t valueTag = 0u;       // +0x18
    std::uint32_t valuePad = 0u;       // +0x1C
  };
  static_assert(sizeof(InlineQwordVectorWithTagRuntimeView) == 0x20, "InlineQwordVectorWithTagRuntimeView size must be 0x20");
  static_assert(
    offsetof(InlineQwordVectorWithTagRuntimeView, inlineQword) == 0x10,
    "InlineQwordVectorWithTagRuntimeView::inlineQword offset must be 0x10"
  );
  static_assert(
    offsetof(InlineQwordVectorWithTagRuntimeView, valueTag) == 0x18,
    "InlineQwordVectorWithTagRuntimeView::valueTag offset must be 0x18"
  );

  struct InlineQwordVectorWithTagStorageRuntimeView
  {
    std::uint32_t proxy = 0u;                             // +0x00
    InlineQwordVectorWithTagRuntimeView* first = nullptr; // +0x04
    InlineQwordVectorWithTagRuntimeView* last = nullptr;  // +0x08
    InlineQwordVectorWithTagRuntimeView* end = nullptr;   // +0x0C
  };
  static_assert(sizeof(InlineQwordVectorWithTagStorageRuntimeView) == 0x10, "InlineQwordVectorWithTagStorageRuntimeView size must be 0x10");
  static_assert(
    offsetof(InlineQwordVectorWithTagStorageRuntimeView, first) == 0x04,
    "InlineQwordVectorWithTagStorageRuntimeView::first offset must be 0x04"
  );
  static_assert(
    offsetof(InlineQwordVectorWithTagStorageRuntimeView, last) == 0x08,
    "InlineQwordVectorWithTagStorageRuntimeView::last offset must be 0x08"
  );
  static_assert(
    offsetof(InlineQwordVectorWithTagStorageRuntimeView, end) == 0x0C,
    "InlineQwordVectorWithTagStorageRuntimeView::end offset must be 0x0C"
  );

  constexpr std::size_t kInlineQwordVectorWithTagMaxCount = 0x07FFFFFFu;

  [[nodiscard]] InlineQwordVectorWithTagRuntimeView& InitializeInlineQwordVectorStorage(
    InlineQwordVectorWithTagRuntimeView& value
  ) noexcept
  {
    auto* const inlineStorage = reinterpret_cast<std::byte*>(&value.inlineQword);
    value.vector.start = inlineStorage;
    value.vector.finish = inlineStorage;
    value.vector.capacity = inlineStorage + kQwordStride;
    value.vector.inlineOrigin = inlineStorage;
    return value;
  }

  /**
   * Address: 0x007423F0 (FUN_007423F0)
   *
   * What it does:
   * Resets one inline-backed 8-byte fastvector lane to inline storage,
   * releasing dynamic storage when present.
   */
  [[maybe_unused]] std::byte* ResetInlineQwordVectorStorage(
    InlineQwordVectorWithTagRuntimeView& value
  ) noexcept
  {
    std::byte* const storage = value.vector.start;
    if (storage == value.vector.inlineOrigin) {
      value.vector.finish = storage;
      return storage;
    }

    ::operator delete[](storage);
    std::byte* const inlineStorage = value.vector.inlineOrigin;
    value.vector.start = inlineStorage;
    std::byte* const restoredCapacity = *reinterpret_cast<std::byte**>(inlineStorage);
    value.vector.capacity = restoredCapacity;
    value.vector.finish = inlineStorage;
    return restoredCapacity;
  }

  void ResetInlineQwordVectorWithTagRange(
    InlineQwordVectorWithTagRuntimeView* const begin,
    InlineQwordVectorWithTagRuntimeView* const end
  ) noexcept
  {
    if (begin == nullptr) {
      return;
    }

    for (InlineQwordVectorWithTagRuntimeView* cursor = begin; cursor != end; ++cursor) {
      (void)ResetInlineQwordVectorStorage(*cursor);
    }
  }

  [[nodiscard]] std::size_t CountInlineQwordVectorWithTagElements(
    const InlineQwordVectorWithTagStorageRuntimeView& storage
  ) noexcept
  {
    if (storage.first == nullptr) {
      return 0u;
    }
    return static_cast<std::size_t>(storage.last - storage.first);
  }

  [[nodiscard]] std::size_t CountInlineQwordVectorWithTagCapacity(
    const InlineQwordVectorWithTagStorageRuntimeView& storage
  ) noexcept
  {
    if (storage.first == nullptr) {
      return 0u;
    }
    return static_cast<std::size_t>(storage.end - storage.first);
  }

  [[nodiscard]] bool AllocateInlineQwordVectorWithTagStorage(
    InlineQwordVectorWithTagStorageRuntimeView& storage,
    const std::size_t elementCount
  )
  {
    storage.first = nullptr;
    storage.last = nullptr;
    storage.end = nullptr;

    if (elementCount == 0u) {
      return true;
    }

    if (elementCount > kInlineQwordVectorWithTagMaxCount) {
      throw std::length_error("vector<T> too long");
    }

    auto* const begin = static_cast<InlineQwordVectorWithTagRuntimeView*>(
      ::operator new(elementCount * sizeof(InlineQwordVectorWithTagRuntimeView))
    );
    storage.first = begin;
    storage.last = begin;
    storage.end = begin + elementCount;
    return true;
  }

  void ReleaseInlineQwordVectorWithTagStorage(
    InlineQwordVectorWithTagStorageRuntimeView& storage
  ) noexcept
  {
    if (storage.first != nullptr) {
      ResetInlineQwordVectorWithTagRange(storage.first, storage.last);
      ::operator delete(storage.first);
    }
    storage.first = nullptr;
    storage.last = nullptr;
    storage.end = nullptr;
  }

  struct InlineQwordVectorWithTagInsertScratch
  {
    InlineQwordVectorWithTagRuntimeView value{};

    ~InlineQwordVectorWithTagInsertScratch()
    {
      (void)ResetInlineQwordVectorStorage(value);
    }
  };

  /**
   * Address: 0x007506F0 (FUN_007506F0)
   *
   * What it does:
   * Initializes one inline-backed 8-byte vector-with-tag lane from `source`
   * by wiring inline storage and assigning the vector payload.
   */
  [[maybe_unused]] InlineQwordVectorWithTagRuntimeView* InitializeInlineQwordVectorWithTagFromSource(
    InlineQwordVectorWithTagRuntimeView* const destination,
    const InlineQwordVectorWithTagRuntimeView* const source
  )
  {
    InitializeInlineQwordVectorStorage(*destination);
    (void)Assign8ByteVectorRange(destination->vector, source->vector);
    return destination;
  }

  /**
   * Address: 0x00755EF0 (FUN_00755EF0)
   *
   * What it does:
   * Initializes one inline-backed 8-byte vector-with-tag lane from `source`
   * and copies the scalar tag lane at `+0x18`.
   */
  [[maybe_unused]] InlineQwordVectorWithTagRuntimeView* InitializeInlineQwordVectorWithTagFromSourceAndCopyTag(
    InlineQwordVectorWithTagRuntimeView* const destination,
    const InlineQwordVectorWithTagRuntimeView* const source
  )
  {
    if (destination == nullptr) {
      return destination;
    }

    InitializeInlineQwordVectorStorage(*destination);
    (void)Assign8ByteVectorRange(destination->vector, source->vector);
    destination->valueTag = source->valueTag;
    return destination;
  }

  /**
   * Address: 0x00751BF0 (FUN_00751BF0)
   *
   * What it does:
   * Fills `[destinationBegin, destinationEnd)` by assigning each entry from
   * one shared source vector-with-tag lane.
   */
  [[maybe_unused]] InlineQwordVectorWithTagRuntimeView* FillAssignInlineQwordVectorWithTagRange(
    InlineQwordVectorWithTagRuntimeView* destinationBegin,
    InlineQwordVectorWithTagRuntimeView* destinationEnd,
    const InlineQwordVectorWithTagRuntimeView* const source
  )
  {
    auto* destination = destinationBegin;
    while (destination != destinationEnd) {
      (void)Assign8ByteVectorRange(destination->vector, source->vector);
      destination->valueTag = source->valueTag;
      ++destination;
    }
    return destination;
  }

  /**
   * Address: 0x00755A00 (FUN_00755A00)
   * Address: 0x00751C10 (FUN_00751C10)
   * Address: 0x00753E70 (FUN_00753E70)
   *
   * What it does:
   * Copies one vector-with-tag range backward from
   * `[sourceBegin, sourceEnd)` into destination lanes ending at
   * `destinationEnd`.
   */
  [[maybe_unused]] InlineQwordVectorWithTagRuntimeView* CopyAssignInlineQwordVectorWithTagRangeBackward(
    const InlineQwordVectorWithTagRuntimeView* sourceBegin,
    const InlineQwordVectorWithTagRuntimeView* sourceEnd,
    InlineQwordVectorWithTagRuntimeView* destinationEnd
  )
  {
    auto* destination = destinationEnd;
    auto* source = sourceEnd;
    while (source != sourceBegin) {
      --source;
      --destination;
      (void)Assign8ByteVectorRange(destination->vector, source->vector);
      destination->valueTag = source->valueTag;
    }
    return destination;
  }

  /**
   * Address: 0x00755DE0 (FUN_00755DE0)
   * Address: 0x007549D0 (FUN_007549D0)
   *
   * What it does:
   * Copies one vector-with-tag range forward from `[sourceBegin, sourceEnd)`
   * into destination lanes beginning at `destinationBegin`.
   */
  [[maybe_unused]] InlineQwordVectorWithTagRuntimeView* CopyAssignInlineQwordVectorWithTagRangeForward(
    const InlineQwordVectorWithTagRuntimeView* sourceBegin,
    const InlineQwordVectorWithTagRuntimeView* sourceEnd,
    InlineQwordVectorWithTagRuntimeView* destinationBegin
  )
  {
    auto* destination = destinationBegin;
    auto* source = sourceBegin;
    while (source != sourceEnd) {
      (void)Assign8ByteVectorRange(destination->vector, source->vector);
      destination->valueTag = source->valueTag;
      ++source;
      ++destination;
    }
    return destination;
  }

  /**
   * Address: 0x00753AF0 (FUN_00753AF0)
   * Address: 0x0074DBF0 (FUN_0074DBF0)
   * Address: 0x00751800 (FUN_00751800)
   *
   * What it does:
   * Constructs `count` entries at `destination` by filling each with one
   * source vector-with-tag lane; unwinds partially constructed entries on
   * exceptions.
   */
  [[maybe_unused]] InlineQwordVectorWithTagRuntimeView* UninitializedFillInlineQwordVectorWithTagByCount(
    const InlineQwordVectorWithTagRuntimeView* const source,
    std::size_t count,
    InlineQwordVectorWithTagRuntimeView* const destination
  )
  {
    auto* cursor = destination;
    try {
      while (count != 0u) {
        InitializeInlineQwordVectorStorage(*cursor);
        (void)Assign8ByteVectorRange(cursor->vector, source->vector);
        cursor->valueTag = source->valueTag;
        ++cursor;
        --count;
      }
      return cursor;
    } catch (...) {
      for (auto* it = destination; it != cursor; ++it) {
        (void)ResetInlineQwordVectorStorage(*it);
      }
      throw;
    }
  }

  /**
   * Address: 0x00756A00 (FUN_00756A00)
   * Address: 0x007549A0 (FUN_007549A0)
   * Address: 0x00755DB0 (FUN_00755DB0)
   *
   * What it does:
   * Uninitialized-copies one vector-with-tag range from
   * `[sourceBegin, sourceEnd)` into destination lanes, unwinding partially
   * constructed entries on exceptions.
   */
  [[maybe_unused]] InlineQwordVectorWithTagRuntimeView* UninitializedCopyInlineQwordVectorWithTagRange(
    const InlineQwordVectorWithTagRuntimeView* sourceBegin,
    const InlineQwordVectorWithTagRuntimeView* sourceEnd,
    InlineQwordVectorWithTagRuntimeView* destination
  )
  {
    auto* source = sourceBegin;
    auto* cursor = destination;
    try {
      while (source != sourceEnd) {
        InitializeInlineQwordVectorStorage(*cursor);
        (void)Assign8ByteVectorRange(cursor->vector, source->vector);
        cursor->valueTag = source->valueTag;
        ++source;
        ++cursor;
      }
      return cursor;
    } catch (...) {
      for (auto* it = destination; it != cursor; ++it) {
        (void)ResetInlineQwordVectorStorage(*it);
      }
      throw;
    }
  }

  /**
   * Address: 0x00756AB0 (FUN_00756AB0)
   * Address: 0x00751BC0 (FUN_00751BC0)
   * Address: 0x00753E00 (FUN_00753E00)
   * Address: 0x00754A00 (FUN_00754A00)
   * Address: 0x007559D0 (FUN_007559D0)
   * Address: 0x00755E10 (FUN_00755E10)
   *
   * What it does:
   * Alternate call-shape lane for uninitialized-copy of one vector-with-tag
   * range.
   */
  [[maybe_unused]] InlineQwordVectorWithTagRuntimeView* UninitializedCopyInlineQwordVectorWithTagRangeAlias(
    const InlineQwordVectorWithTagRuntimeView* sourceBegin,
    const InlineQwordVectorWithTagRuntimeView* sourceEnd,
    InlineQwordVectorWithTagRuntimeView* destination
  )
  {
    return UninitializedCopyInlineQwordVectorWithTagRange(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x0074F3E0 (FUN_0074F3E0)
   *
   * What it does:
   * Inserts one vector-with-tag value at `insertPosition`, growing storage and
   * shifting tail lanes as needed.
   */
  [[maybe_unused]] void InsertInlineQwordVectorWithTagSlowPath(
    const InlineQwordVectorWithTagRuntimeView* const sourceValue,
    InlineQwordVectorWithTagStorageRuntimeView* const destination,
    InlineQwordVectorWithTagRuntimeView* const insertPosition
  )
  {
    InlineQwordVectorWithTagInsertScratch inserted{};
    InitializeInlineQwordVectorWithTagFromSource(&inserted.value, sourceValue);
    inserted.value.valueTag = sourceValue->valueTag;

    const std::size_t currentSize = CountInlineQwordVectorWithTagElements(*destination);
    const std::size_t currentCapacity = CountInlineQwordVectorWithTagCapacity(*destination);
    if (currentSize == kInlineQwordVectorWithTagMaxCount) {
      throw std::length_error("vector<T> too long");
    }

    if (currentCapacity < (currentSize + 1u)) {
      std::size_t grownCapacity = currentCapacity + (currentCapacity >> 1u);
      if ((kInlineQwordVectorWithTagMaxCount - (currentCapacity >> 1u)) < currentCapacity) {
        grownCapacity = 0u;
      }

      const std::size_t requiredCapacity = currentSize + 1u;
      if (grownCapacity < requiredCapacity) {
        grownCapacity = requiredCapacity;
      }

      auto* const newStorage = static_cast<InlineQwordVectorWithTagRuntimeView*>(
        ::operator new(grownCapacity * sizeof(InlineQwordVectorWithTagRuntimeView))
      );
      InlineQwordVectorWithTagRuntimeView* write = newStorage;
      try {
        write = UninitializedCopyInlineQwordVectorWithTagRangeAlias(destination->first, insertPosition, write);
        write = UninitializedFillInlineQwordVectorWithTagByCount(&inserted.value, 1u, write);
        write = UninitializedCopyInlineQwordVectorWithTagRangeAlias(insertPosition, destination->last, write);
      } catch (...) {
        ResetInlineQwordVectorWithTagRange(newStorage, write);
        ::operator delete(newStorage);
        throw;
      }

      ReleaseInlineQwordVectorWithTagStorage(*destination);
      destination->first = newStorage;
      destination->last = write;
      destination->end = newStorage + grownCapacity;
      return;
    }

    InlineQwordVectorWithTagRuntimeView* const oldLast = destination->last;
    const std::size_t tailCount = static_cast<std::size_t>(oldLast - insertPosition);
    if (tailCount == 0u) {
      destination->last = UninitializedFillInlineQwordVectorWithTagByCount(&inserted.value, 1u, oldLast);
      return;
    }

    (void)UninitializedCopyInlineQwordVectorWithTagRangeAlias(oldLast - 1, oldLast, oldLast);
    destination->last = oldLast + 1;
    (void)CopyAssignInlineQwordVectorWithTagRangeBackward(insertPosition, oldLast - 1, oldLast);
    (void)FillAssignInlineQwordVectorWithTagRange(insertPosition, insertPosition + 1, &inserted.value);
  }

  /**
   * Address: 0x0074C160 (FUN_0074C160)
   *
   * What it does:
   * Appends one vector-with-tag element to the destination storage, using the
   * in-place fast path when capacity is available.
   */
  [[maybe_unused]] void PushBackInlineQwordVectorWithTag(
    const InlineQwordVectorWithTagRuntimeView* const sourceValue,
    InlineQwordVectorWithTagStorageRuntimeView* const destination
  )
  {
    const std::size_t usedCount = CountInlineQwordVectorWithTagElements(*destination);
    if (destination->first != nullptr && usedCount < CountInlineQwordVectorWithTagCapacity(*destination)) {
      destination->last = UninitializedFillInlineQwordVectorWithTagByCount(sourceValue, 1u, destination->last);
      return;
    }

    InsertInlineQwordVectorWithTagSlowPath(sourceValue, destination, destination->last);
  }

  /**
   * Address: 0x00753020 (FUN_00753020)
   *
   * What it does:
   * Copy-constructs one vector-with-tag storage owner from `source`.
   */
  [[maybe_unused]] InlineQwordVectorWithTagStorageRuntimeView* CopyConstructInlineQwordVectorWithTagStorage(
    const InlineQwordVectorWithTagStorageRuntimeView* const source,
    InlineQwordVectorWithTagStorageRuntimeView* const destination
  )
  {
    destination->first = nullptr;
    destination->last = nullptr;
    destination->end = nullptr;

    const std::size_t sourceCount = CountInlineQwordVectorWithTagElements(*source);
    if (sourceCount == 0u) {
      return destination;
    }

    if (AllocateInlineQwordVectorWithTagStorage(*destination, sourceCount)) {
      try {
        destination->last = UninitializedCopyInlineQwordVectorWithTagRange(source->first, source->last, destination->first);
      } catch (...) {
        ReleaseInlineQwordVectorWithTagStorage(*destination);
        throw;
      }
    }

    return destination;
  }

  /**
   * Address: 0x007530C0 (FUN_007530C0)
   *
   * What it does:
   * Assigns one vector-with-tag storage owner from `source`, reusing capacity
   * when possible and reallocating when required.
   */
  [[maybe_unused]] InlineQwordVectorWithTagStorageRuntimeView* AssignInlineQwordVectorWithTagStorage(
    InlineQwordVectorWithTagStorageRuntimeView* const destination,
    const InlineQwordVectorWithTagStorageRuntimeView* const source
  )
  {
    if (destination == source) {
      return destination;
    }

    const std::size_t sourceCount = CountInlineQwordVectorWithTagElements(*source);
    if (sourceCount == 0u) {
      ResetInlineQwordVectorWithTagRange(destination->first, destination->last);
      destination->last = destination->first;
      return destination;
    }

    const std::size_t destinationCount = CountInlineQwordVectorWithTagElements(*destination);
    if (sourceCount <= destinationCount) {
      InlineQwordVectorWithTagRuntimeView* const copiedEnd =
        CopyAssignInlineQwordVectorWithTagRangeForward(source->first, source->last, destination->first);
      ResetInlineQwordVectorWithTagRange(copiedEnd, destination->last);
      destination->last = destination->first + sourceCount;
      return destination;
    }

    const std::size_t destinationCapacity = CountInlineQwordVectorWithTagCapacity(*destination);
    if (sourceCount <= destinationCapacity) {
      const InlineQwordVectorWithTagRuntimeView* const sourceSplit = source->first + destinationCount;
      (void)CopyAssignInlineQwordVectorWithTagRangeForward(source->first, sourceSplit, destination->first);
      destination->last = UninitializedCopyInlineQwordVectorWithTagRangeAlias(sourceSplit, source->last, destination->last);
      return destination;
    }

    ReleaseInlineQwordVectorWithTagStorage(*destination);
    if (AllocateInlineQwordVectorWithTagStorage(*destination, sourceCount)) {
      destination->last = UninitializedCopyInlineQwordVectorWithTagRangeAlias(source->first, source->last, destination->first);
    }

    return destination;
  }

  /**
   * Address: 0x007654F0 (FUN_007654F0)
   *
   * What it does:
   * Copies one dword lane range `[sourceBegin, sourceEnd)` into destination
   * storage starting at `sourceEnd`.
   */
  [[maybe_unused]] std::uint32_t* CopyForwardDwordTailRangeAdapter(
    const std::uint32_t* const sourceBegin,
    std::uint32_t* const sourceEnd
  ) noexcept
  {
    return reinterpret_cast<std::uint32_t*>(
      CopyForwardDwordLane(
        reinterpret_cast<std::byte*>(sourceEnd),
        reinterpret_cast<const std::byte*>(sourceEnd),
        reinterpret_cast<const std::byte*>(sourceBegin)
      )
    );
  }

  /**
   * Address: 0x0065F240 (FUN_0065F240)
   *
   * What it does:
   * Replaces destination 12-byte fastvector content with source content,
   * reusing capacity when possible and growing when required.
   */
  [[maybe_unused]] FastVectorInsertRuntimeView&
  Assign12ByteVectorRange(FastVectorInsertRuntimeView& destination, const FastVectorInsertRuntimeView& source)
  {
    if (&destination == &source) {
      return destination;
    }

    const std::size_t destinationCount = ElementCount(destination.start, destination.finish, kTwelveStride);
    const std::size_t sourceCount = ElementCount(source.start, source.finish, kTwelveStride);

    if (destinationCount >= sourceCount) {
      CopyForward12ByteLane(destination.start, source.finish, source.start);
      destination.finish = destination.start + ByteCountForElements(sourceCount, kTwelveStride);
      return destination;
    }

    const std::size_t destinationCapacity = ElementCount(destination.start, destination.capacity, kTwelveStride);
    if (sourceCount > destinationCapacity) {
      GrowInsert12ByteLane(destination, sourceCount, destination.start, destination.start, destination.start);
    }

    const std::byte* const splitSource = source.start + ByteCountForElements(destinationCount, kTwelveStride);
    CopyForward12ByteLane(destination.start, splitSource, source.start);
    AppendRange12ByteLane(destination, destination.finish, splitSource, source.finish);
    return destination;
  }

  /**
   * Address: 0x0082D030 (FUN_0082D030)
   *
   * What it does:
   * Replaces destination 4-byte fastvector content with source content,
   * reusing capacity when possible and growing when required.
   */
  FastVectorInsertRuntimeView&
  AssignDwordVectorRange(FastVectorInsertRuntimeView& destination, const FastVectorInsertRuntimeView& source)
  {
    if (&destination == &source) {
      return destination;
    }

    const std::size_t sourceCount = ElementCount(source.start, source.finish, kDwordStride);
    const std::size_t destinationCount = ElementCount(destination.start, destination.finish, kDwordStride);

    if (sourceCount == 0u) {
      destination.finish = destination.start;
      return destination;
    }

    if (destinationCount >= sourceCount) {
      if (sourceCount > 0u) {
        std::memmove(destination.start, source.start, ByteCountForElements(sourceCount, kDwordStride));
      }
      destination.finish = destination.start + ByteCountForElements(sourceCount, kDwordStride);
      return destination;
    }

    const std::size_t destinationCapacity = ElementCount(destination.start, destination.capacity, kDwordStride);
    if (sourceCount > destinationCapacity) {
      GrowInsertDwordLane(destination, sourceCount, destination.start, destination.start, destination.start);
    }

    if (destinationCount > 0u) {
      std::memmove(destination.start, source.start, ByteCountForElements(destinationCount, kDwordStride));
    }

    AppendRangeDwordLane(
      destination,
      destination.finish,
      source.start + ByteCountForElements(destinationCount, kDwordStride),
      source.finish
    );
    return destination;
  }

  /**
   * Address: 0x0082E5E0 (FUN_0082E5E0)
   *
   * What it does:
   * Initializes one stack-style inline dword-vector scratch lane and assigns
   * source content into that lane via `AssignDwordVectorRange`.
   */
  DwordVectorInlineScratch* InitializeDwordInlineScratchFromView(
    DwordVectorInlineScratch* const destination,
    const FastVectorInsertRuntimeView& source
  )
  {
    if (destination == nullptr) {
      return nullptr;
    }

    std::byte* const inlineStorage = reinterpret_cast<std::byte*>(&destination->inlineElement);
    destination->view.start = inlineStorage;
    destination->view.finish = inlineStorage;
    destination->view.capacity = inlineStorage + kDwordStride;
    destination->view.inlineOrigin = inlineStorage;
    AssignDwordVectorRange(destination->view, source);
    return destination;
  }

  /**
   * Address: 0x0080A290 (FUN_0080A290)
   *
   * What it does:
   * Initializes one inline-backed fastvector runtime view where the inline
   * origin is embedded at `result+0x10` and capacity spans 0x445C0 bytes.
   */
  [[maybe_unused]] FastVectorInsertRuntimeView* InitializeInlineBackedFastVectorLane280000(
    FastVectorInsertRuntimeView* const result
  ) noexcept
  {
    auto& header = reinterpret_cast<FastVectorInlineOriginHeaderRuntimeView&>(*result);
    InitializeInlineBackedFastVectorRuntimeView(
      header.view,
      header.inlineOriginStorage,
      kInlineCapacityByteCount280000
    );
    return result;
  }

  /**
   * Address: 0x0080EBD0 (FUN_0080EBD0)
   *
   * What it does:
   * Initializes one inline-backed fastvector runtime view where the inline
   * origin is embedded at `result+0x10` and capacity spans 0x7EF40 bytes.
   */
  [[maybe_unused]] FastVectorInsertRuntimeView* InitializeInlineBackedFastVectorLane520000(
    FastVectorInsertRuntimeView* const result
  ) noexcept
  {
    auto& header = reinterpret_cast<FastVectorInlineOriginHeaderRuntimeView&>(*result);
    InitializeInlineBackedFastVectorRuntimeView(
      header.view,
      header.inlineOriginStorage,
      kInlineCapacityByteCount520000
    );
    return result;
  }

  /**
   * Address: 0x0080ED20 (FUN_0080ED20)
   *
   * What it does:
   * Initializes one inline-backed fastvector runtime view where the inline
   * origin is embedded at `result+0x10` and capacity spans 0x4E200 bytes.
   */
  [[maybe_unused]] FastVectorInsertRuntimeView* InitializeInlineBackedFastVectorLane320000(
    FastVectorInsertRuntimeView* const result
  ) noexcept
  {
    auto& header = reinterpret_cast<FastVectorInlineOriginHeaderRuntimeView&>(*result);
    InitializeInlineBackedFastVectorRuntimeView(
      header.view,
      header.inlineOriginStorage,
      kInlineCapacityByteCount320000
    );
    return result;
  }

  /**
   * Address: 0x0056B610 (FUN_0056B610)
   *
   * What it does:
   * Initializes one inline-backed fastvector runtime view where the inline
   * origin is embedded at `result+0x10` and capacity spans 0x100 bytes.
   */
  [[maybe_unused]] FastVectorInsertRuntimeView* InitializeInlineBackedFastVectorLane256(
    FastVectorInsertRuntimeView* const result
  ) noexcept
  {
    auto& header = reinterpret_cast<FastVectorInlineOriginHeaderRuntimeView&>(*result);
    InitializeInlineBackedFastVectorRuntimeView(header.view, header.inlineOriginStorage, 0x100u);
    return result;
  }

  /**
   * Address: 0x0056C5A0 (FUN_0056C5A0)
   *
   * What it does:
   * Initializes one inline-backed fastvector runtime view where the inline
   * origin is embedded at `result+0x10` and capacity spans 0x80 bytes.
   */
  [[maybe_unused]] FastVectorInsertRuntimeView* InitializeInlineBackedFastVectorLane128(
    FastVectorInsertRuntimeView* const result
  ) noexcept
  {
    auto& header = reinterpret_cast<FastVectorInlineOriginHeaderRuntimeView&>(*result);
    InitializeInlineBackedFastVectorRuntimeView(header.view, header.inlineOriginStorage, 0x80u);
    return result;
  }

  /**
   * Address: 0x0056C740 (FUN_0056C740)
   *
   * What it does:
   * Initializes one inline-backed fastvector runtime view where the inline
   * origin is embedded at `result+0x10` and capacity spans 0x200 bytes.
   */
  [[maybe_unused]] FastVectorInsertRuntimeView* InitializeInlineBackedFastVectorLane512(
    FastVectorInsertRuntimeView* const result
  ) noexcept
  {
    auto& header = reinterpret_cast<FastVectorInlineOriginHeaderRuntimeView&>(*result);
    InitializeInlineBackedFastVectorRuntimeView(header.view, header.inlineOriginStorage, 0x200u);
    return result;
  }

  /**
   * Address: 0x0056C880 (FUN_0056C880)
   *
   * What it does:
   * Initializes one inline-backed fastvector runtime view where the inline
   * origin is embedded at `result+0x10` and capacity spans 0x480 bytes.
   */
  [[maybe_unused]] FastVectorInsertRuntimeView* InitializeInlineBackedFastVectorLane1152(
    FastVectorInsertRuntimeView* const result
  ) noexcept
  {
    auto& header = reinterpret_cast<FastVectorInlineOriginHeaderRuntimeView&>(*result);
    InitializeInlineBackedFastVectorRuntimeView(header.view, header.inlineOriginStorage, 0x480u);
    return result;
  }

  /**
   * Address: 0x00576C00 (FUN_00576C00)
   *
   * What it does:
   * Initializes one inline-backed fastvector runtime view where the inline
   * origin is embedded at `result+0x10` and capacity spans 0x460 bytes.
   */
  [[maybe_unused]] FastVectorInsertRuntimeView* InitializeInlineBackedFastVectorLane1120(
    FastVectorInsertRuntimeView* const result
  ) noexcept
  {
    auto& header = reinterpret_cast<FastVectorInlineOriginHeaderRuntimeView&>(*result);
    InitializeInlineBackedFastVectorRuntimeView(header.view, header.inlineOriginStorage, kInlineCapacityByteCount1120);
    return result;
  }

  /**
   * Address: 0x00558960 (FUN_00558960)
   *
   * What it does:
   * Initializes one inline-backed fastvector runtime view where the inline
   * origin is embedded at `result+0x10` and capacity spans 0x4 bytes.
   */
  [[maybe_unused]] FastVectorInsertRuntimeView* InitializeInlineBackedFastVectorLane4(
    FastVectorInsertRuntimeView* const result
  ) noexcept
  {
    auto& header = reinterpret_cast<FastVectorInlineOriginHeaderRuntimeView&>(*result);
    InitializeInlineBackedFastVectorRuntimeView(header.view, header.inlineOriginStorage, kDwordStride);
    return result;
  }

  /**
   * Address: 0x00558F40 (FUN_00558F40)
   *
   * What it does:
   * Initializes one fastvector runtime view from caller-provided inline origin
   * storage and sets capacity to `inlineOrigin+0x4`.
   */
  [[maybe_unused]] FastVectorInsertRuntimeView* InitializeFastVectorLane4FromInlineOrigin(
    FastVectorInsertRuntimeView* const result,
    std::byte* const inlineOrigin
  ) noexcept
  {
    InitializeInlineBackedFastVectorRuntimeView(*result, inlineOrigin, kDwordStride);
    return result;
  }

  /**
   * Address: 0x005613C0 (FUN_005613C0)
   * Address: 0x0056D260 (FUN_0056D260)
   *
   * What it does:
   * Initializes one fastvector runtime view from caller-provided inline origin
   * storage and sets capacity to `inlineOrigin+0x20`.
   */
  [[maybe_unused]] FastVectorInsertRuntimeView* InitializeFastVectorLane32FromInlineOrigin(
    FastVectorInsertRuntimeView* const result,
    std::byte* const inlineOrigin
  ) noexcept
  {
    InitializeInlineBackedFastVectorRuntimeView(*result, inlineOrigin, kThirtyTwoStride);
    return result;
  }

  /**
   * Address: 0x00561410 (FUN_00561410)
   * Address: 0x0056D5F0 (FUN_0056D5F0)
   *
   * What it does:
   * Initializes one fastvector runtime view from caller-provided inline origin
   * storage and sets capacity to `inlineOrigin+0x98`.
   */
  [[maybe_unused]] FastVectorInsertRuntimeView* InitializeFastVectorLane152FromInlineOrigin(
    FastVectorInsertRuntimeView* const result,
    std::byte* const inlineOrigin
  ) noexcept
  {
    InitializeInlineBackedFastVectorRuntimeView(*result, inlineOrigin, 0x98u);
    return result;
  }

  /**
   * Address: 0x0056D6E0 (FUN_0056D6E0)
   *
   * What it does:
   * Initializes one fastvector runtime view from caller-provided inline origin
   * storage and sets capacity to `inlineOrigin+0x100`.
   */
  [[maybe_unused]] FastVectorInsertRuntimeView* InitializeFastVectorLane256FromInlineOrigin(
    FastVectorInsertRuntimeView* const result,
    std::byte* const inlineOrigin
  ) noexcept
  {
    InitializeInlineBackedFastVectorRuntimeView(*result, inlineOrigin, 0x100u);
    return result;
  }

  /**
   * Address: 0x0056E3E0 (FUN_0056E3E0)
   *
   * What it does:
   * Initializes one fastvector runtime view from caller-provided inline origin
   * storage and sets capacity to `inlineOrigin+0x80`.
   */
  [[maybe_unused]] FastVectorInsertRuntimeView* InitializeFastVectorLane128FromInlineOrigin(
    FastVectorInsertRuntimeView* const result,
    std::byte* const inlineOrigin
  ) noexcept
  {
    InitializeInlineBackedFastVectorRuntimeView(*result, inlineOrigin, 0x80u);
    return result;
  }

  /**
   * Address: 0x0056E5C0 (FUN_0056E5C0)
   *
   * What it does:
   * Initializes one fastvector runtime view from caller-provided inline origin
   * storage and sets capacity to `inlineOrigin+0x200`.
   */
  [[maybe_unused]] FastVectorInsertRuntimeView* InitializeFastVectorLane512FromInlineOrigin(
    FastVectorInsertRuntimeView* const result,
    std::byte* const inlineOrigin
  ) noexcept
  {
    InitializeInlineBackedFastVectorRuntimeView(*result, inlineOrigin, 0x200u);
    return result;
  }

  /**
   * Address: 0x0056E780 (FUN_0056E780)
   *
   * What it does:
   * Initializes one fastvector runtime view from caller-provided inline origin
   * storage and sets capacity to `inlineOrigin+0x480`.
   */
  [[maybe_unused]] FastVectorInsertRuntimeView* InitializeFastVectorLane1152FromInlineOrigin(
    FastVectorInsertRuntimeView* const result,
    std::byte* const inlineOrigin
  ) noexcept
  {
    InitializeInlineBackedFastVectorRuntimeView(*result, inlineOrigin, 0x480u);
    return result;
  }

  /**
   * Address: 0x00576ED0 (FUN_00576ED0)
   *
   * What it does:
   * Initializes one fastvector runtime view from caller-provided inline origin
   * storage and sets capacity to `inlineOrigin+0x460`.
   */
  [[maybe_unused]] FastVectorInsertRuntimeView* InitializeFastVectorLane1120FromInlineOrigin(
    FastVectorInsertRuntimeView* const result,
    std::byte* const inlineOrigin
  ) noexcept
  {
    InitializeInlineBackedFastVectorRuntimeView(*result, inlineOrigin, kInlineCapacityByteCount1120);
    return result;
  }

  /**
   * Address: 0x0080F030 (FUN_0080F030)
   *
   * What it does:
   * Initializes one fastvector runtime view from caller-provided inline origin
   * storage and sets capacity to `inlineOrigin+0x7EF40`.
   */
  [[maybe_unused]] FastVectorInsertRuntimeView* InitializeFastVectorLane520000FromInlineOrigin(
    FastVectorInsertRuntimeView* const result,
    std::byte* const inlineOrigin
  ) noexcept
  {
    InitializeInlineBackedFastVectorRuntimeView(*result, inlineOrigin, kInlineCapacityByteCount520000);
    return result;
  }

  /**
   * Address: 0x0080F1B0 (FUN_0080F1B0)
   *
   * What it does:
   * Initializes one fastvector runtime view from caller-provided inline origin
   * storage and sets capacity to `inlineOrigin+0x4E200`.
   */
  [[maybe_unused]] FastVectorInsertRuntimeView* InitializeFastVectorLane320000FromInlineOrigin(
    FastVectorInsertRuntimeView* const result,
    std::byte* const inlineOrigin
  ) noexcept
  {
    InitializeInlineBackedFastVectorRuntimeView(*result, inlineOrigin, kInlineCapacityByteCount320000);
    return result;
  }
} // namespace gpg::core::legacy
