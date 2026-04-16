#include "moho/sim/IdPool.h"

#include "gpg/core/time/Timer.h"
#include "lua/LuaObject.h"
#include "legacy/containers/String.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/sim/ArmyUnitSet.h"
#include "moho/sim/SSTIArmyConstantData.h"
#include "moho/sim/SSTIArmyVariableData.h"
#include "moho/sim/SimDriver.h"
#include "moho/misc/WeakPtr.h"
#include "moho/containers/BVIntSet.h"
#include "moho/render/CDecalTypes.h"
#include "moho/unit/core/Unit.h"
#include "moho/net/CClientManagerImpl.h"
#include "boost/bind.hpp"
#include "boost/function/function_base.hpp"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <cmath>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <exception>
#include <limits>
#include <new>
#include <memory>
#include <stdexcept>
#include <string>
#include <typeinfo>
#include <type_traits>
#include <xmmintrin.h>

int wxGetOsVersion(int* majorVsn, int* minorVsn);

namespace
{
  constexpr std::size_t kIdPoolHistoryCapacity = 100u;

  struct Element12Runtime
  {
    std::uint32_t lane0;
    std::uint32_t lane1;
    std::uint32_t lane2;
  };
  static_assert(sizeof(Element12Runtime) == 0x0C, "Element12Runtime size must be 0x0C");

  struct Element8Runtime
  {
    std::uint32_t lane0;
    std::uint32_t lane1;
  };
  static_assert(sizeof(Element8Runtime) == 0x08, "Element8Runtime size must be 0x08");

  struct Element28Runtime
  {
    std::uint32_t lanes[7];
  };
  static_assert(sizeof(Element28Runtime) == 0x1C, "Element28Runtime size must be 0x1C");

  struct Element60Runtime
  {
    std::uint32_t lanes[15];
  };
  static_assert(sizeof(Element60Runtime) == 0x3C, "Element60Runtime size must be 0x3C");

  struct Element316Runtime
  {
    std::uint32_t lanes[79];
  };
  static_assert(sizeof(Element316Runtime) == 0x13C, "Element316Runtime size must be 0x13C");

  struct Float7Runtime
  {
    float lanes[7];
  };
  static_assert(sizeof(Float7Runtime) == 0x1C, "Float7Runtime size must be 0x1C");

  struct Element16Runtime
  {
    std::uint32_t lanes[4];
  };
  static_assert(sizeof(Element16Runtime) == 0x10, "Element16Runtime size must be 0x10");

  struct Element24Runtime
  {
    std::byte lanes[0x18];
  };
  static_assert(sizeof(Element24Runtime) == 0x18, "Element24Runtime size must be 0x18");

  struct Element24WordLuaObjectRuntime
  {
    std::uint32_t lane00;
    LuaPlus::LuaObject lane04;
  };
  static_assert(sizeof(Element24WordLuaObjectRuntime) == 0x18, "Element24WordLuaObjectRuntime size must be 0x18");

  struct Element36Runtime
  {
    std::byte lanes[0x24];
  };
  static_assert(sizeof(Element36Runtime) == 0x24, "Element36Runtime size must be 0x24");

  struct Element52Runtime
  {
    std::byte lanes[0x34];
  };
  static_assert(sizeof(Element52Runtime) == 0x34, "Element52Runtime size must be 0x34");

  struct Element204Runtime
  {
    std::byte lanes[0xCC];
  };
  static_assert(sizeof(Element204Runtime) == 0xCC, "Element204Runtime size must be 0xCC");

  template <typename T>
  struct LegacyVectorStorageRuntime
  {
    std::uint32_t allocatorCookie;
    T* begin;
    T* end;
    T* capacity;
  };

  template <typename T>
  [[nodiscard]] std::size_t VectorSize(const LegacyVectorStorageRuntime<T>& vector) noexcept
  {
    if (vector.begin == nullptr || vector.end == nullptr || vector.end < vector.begin) {
      return 0u;
    }

    return static_cast<std::size_t>(vector.end - vector.begin);
  }

  template <typename T>
  [[nodiscard]] std::size_t VectorCapacity(const LegacyVectorStorageRuntime<T>& vector) noexcept
  {
    if (vector.begin == nullptr || vector.capacity == nullptr || vector.capacity < vector.begin) {
      return 0u;
    }

    return static_cast<std::size_t>(vector.capacity - vector.begin);
  }

  template <typename T>
  [[nodiscard]] bool ReserveTrivialVector(
    LegacyVectorStorageRuntime<T>* const vector,
    const std::size_t desiredCapacity
  )
  {
    static_assert(std::is_trivially_copyable_v<T>, "ReserveTrivialVector requires trivially copyable element types");

    if (vector == nullptr) {
      return false;
    }

    const std::size_t currentCapacity = VectorCapacity(*vector);
    if (desiredCapacity <= currentCapacity) {
      return true;
    }

    T* const newStorage = static_cast<T*>(::operator new(sizeof(T) * desiredCapacity, std::nothrow));
    if (newStorage == nullptr) {
      return false;
    }

    const std::size_t currentSize = VectorSize(*vector);
    if (vector->begin != nullptr && currentSize != 0u) {
      std::memcpy(newStorage, vector->begin, currentSize * sizeof(T));
    }

    ::operator delete(vector->begin);
    vector->begin = newStorage;
    vector->end = newStorage + currentSize;
    vector->capacity = newStorage + desiredCapacity;
    return true;
  }

  template <typename T>
  [[nodiscard]] T* AppendTrivialValue(
    LegacyVectorStorageRuntime<T>* const vector,
    const T& value
  )
  {
    static_assert(std::is_trivially_copyable_v<T>, "AppendTrivialValue requires trivially copyable element types");

    if (vector == nullptr) {
      return nullptr;
    }

    const std::size_t previousSize = VectorSize(*vector);
    if (!ReserveTrivialVector(vector, previousSize + 1u)) {
      return nullptr;
    }

    T* const inserted = vector->begin + previousSize;
    *inserted = value;
    vector->end = inserted + 1;
    return inserted;
  }

  template <typename T>
  [[nodiscard]] T* ResizeTrivialVectorWithFill(
    LegacyVectorStorageRuntime<T>* const vector,
    const std::size_t desiredSize,
    const T& fillValue
  )
  {
    static_assert(std::is_trivially_copyable_v<T>, "ResizeTrivialVectorWithFill requires trivially copyable element types");

    if (vector == nullptr) {
      return nullptr;
    }

    const std::size_t previousSize = VectorSize(*vector);
    if (desiredSize > previousSize) {
      if (!ReserveTrivialVector(vector, desiredSize)) {
        return vector->begin;
      }

      for (std::size_t index = previousSize; index < desiredSize; ++index) {
        vector->begin[index] = fillValue;
      }
    }

    if (vector->begin != nullptr) {
      vector->end = vector->begin + desiredSize;
    } else {
      vector->end = nullptr;
    }
    return vector->begin;
  }

  template <typename T>
  [[nodiscard]] T* InsertTrivialValueAtPosition(
    LegacyVectorStorageRuntime<T>* const vector,
    T* const position,
    const T& value
  )
  {
    static_assert(std::is_trivially_copyable_v<T>, "InsertTrivialValueAtPosition requires trivially copyable element types");

    if (vector == nullptr) {
      return nullptr;
    }

    const std::size_t previousSize = VectorSize(*vector);
    std::size_t index = previousSize;
    if (vector->begin != nullptr && position != nullptr && position >= vector->begin && position <= vector->end) {
      index = static_cast<std::size_t>(position - vector->begin);
    }

    if (!ReserveTrivialVector(vector, previousSize + 1u)) {
      return nullptr;
    }

    T* const insertLane = vector->begin + index;
    if (index < previousSize) {
      std::memmove(insertLane + 1, insertLane, (previousSize - index) * sizeof(T));
    }

    *insertLane = value;
    vector->end = vector->begin + previousSize + 1u;
    return insertLane;
  }

  struct OwnedBufferRuntime
  {
    std::uint32_t allocatorCookie;
    std::byte* storage;
    std::uint32_t logicalState;
  };

  [[nodiscard]] std::int32_t ResetOwnedBufferRuntime(OwnedBufferRuntime* const owner) noexcept
  {
    if (owner == nullptr) {
      return 0;
    }

    ::operator delete(owner->storage);
    owner->storage = nullptr;
    owner->logicalState = 0u;
    return 0;
  }

  struct LegacyBufferTripleRuntime
  {
    std::uint32_t allocatorCookie;
    std::byte* begin;
    std::byte* end;
    std::byte* capacity;
  };

#if INTPTR_MAX == INT32_MAX
  static_assert(offsetof(LegacyBufferTripleRuntime, begin) == 0x04, "LegacyBufferTripleRuntime::begin offset must be 0x04");
  static_assert(offsetof(LegacyBufferTripleRuntime, end) == 0x08, "LegacyBufferTripleRuntime::end offset must be 0x08");
  static_assert(
    offsetof(LegacyBufferTripleRuntime, capacity) == 0x0C, "LegacyBufferTripleRuntime::capacity offset must be 0x0C"
  );
  static_assert(sizeof(LegacyBufferTripleRuntime) == 0x10, "LegacyBufferTripleRuntime size must be 0x10");
#endif

  struct IntrusiveNodeRuntime
  {
    IntrusiveNodeRuntime* next; // +0x00
    IntrusiveNodeRuntime* prev; // +0x04
  };
  static_assert(sizeof(IntrusiveNodeRuntime) == 0x08, "IntrusiveNodeRuntime size must be 0x08");

  struct IntrusiveNodeListRuntime
  {
    std::uint32_t lane00;
    IntrusiveNodeRuntime* sentinel; // +0x04
    std::uint32_t size;             // +0x08
  };
  static_assert(sizeof(IntrusiveNodeListRuntime) == 0x0C, "IntrusiveNodeListRuntime size must be 0x0C");

  struct IntrusivePayloadNode32Runtime
  {
    IntrusivePayloadNode32Runtime* next; // +0x00
    IntrusivePayloadNode32Runtime* prev; // +0x04
    std::uint32_t payload[8];            // +0x08
  };
  static_assert(sizeof(IntrusivePayloadNode32Runtime) == 0x28, "IntrusivePayloadNode32Runtime size must be 0x28");

  struct IntrusivePayloadNode24Runtime
  {
    IntrusivePayloadNode24Runtime* next; // +0x00
    IntrusivePayloadNode24Runtime* prev; // +0x04
    std::uint32_t payload[6];            // +0x08
  };
  static_assert(sizeof(IntrusivePayloadNode24Runtime) == 0x20, "IntrusivePayloadNode24Runtime size must be 0x20");

  struct IntrusivePayloadListRuntime
  {
    std::uint32_t lane00;
    void* lane04;
    std::uint32_t size; // +0x08
  };
  static_assert(sizeof(IntrusivePayloadListRuntime) == 0x0C, "IntrusivePayloadListRuntime size must be 0x0C");

  [[nodiscard]] std::uint32_t IncrementIntrusivePayloadListSizeWithBound(
    IntrusivePayloadListRuntime* const list,
    const std::uint32_t maxSize
  )
  {
    if (maxSize - list->size < 1u) {
      throw std::length_error("list<T> too long");
    }

    ++list->size;
    return list->size;
  }

  [[nodiscard]] IntrusivePayloadNode32Runtime* AllocateIntrusivePayloadNode32(
    IntrusivePayloadNode32Runtime* const next,
    IntrusivePayloadNode32Runtime* const prev,
    const std::uint32_t* const payloadWords
  )
  {
    auto* const node = static_cast<IntrusivePayloadNode32Runtime*>(::operator new(sizeof(IntrusivePayloadNode32Runtime)));
    node->next = next;
    node->prev = prev;
    if (payloadWords != nullptr) {
      std::memcpy(node->payload, payloadWords, sizeof(node->payload));
    } else {
      std::memset(node->payload, 0, sizeof(node->payload));
    }
    return node;
  }

  [[nodiscard]] IntrusivePayloadNode24Runtime* AllocateIntrusivePayloadNode24(
    IntrusivePayloadNode24Runtime* const next,
    IntrusivePayloadNode24Runtime* const prev,
    const std::uint32_t* const payloadWords
  )
  {
    auto* const node = static_cast<IntrusivePayloadNode24Runtime*>(::operator new(sizeof(IntrusivePayloadNode24Runtime)));
    node->next = next;
    node->prev = prev;
    if (payloadWords != nullptr) {
      std::memcpy(node->payload, payloadWords, sizeof(node->payload));
    } else {
      std::memset(node->payload, 0, sizeof(node->payload));
    }
    return node;
  }

  struct LookupCacheRuntime
  {
    bool (*containsFn)(void* state, std::uint32_t key);
    std::uint32_t (*resolveFn)(std::uint32_t context, std::uint32_t key, std::uint32_t argument);
    void* containsState;
    std::uint32_t context;
    std::uint32_t cachedValue;
  };

  struct MapInsertStatusRuntime
  {
    void* node;
    std::uint8_t inserted;
    std::uint8_t reserved[3];
  };

#if INTPTR_MAX == INT32_MAX
  static_assert(offsetof(MapInsertStatusRuntime, inserted) == 0x04, "MapInsertStatusRuntime::inserted offset must be 0x04");
  static_assert(sizeof(MapInsertStatusRuntime) == 0x08, "MapInsertStatusRuntime size must be 0x08");
#endif

#pragma pack(push, 1)
  struct MapNodeNil21Runtime
  {
    MapNodeNil21Runtime* left;
    MapNodeNil21Runtime* parent;
    MapNodeNil21Runtime* right;
    std::uint32_t key;
    std::uint8_t pad10[0x05];
    std::uint8_t isNil;
  };

  struct MapNodeNil25Runtime
  {
    MapNodeNil25Runtime* left;
    MapNodeNil25Runtime* parent;
    MapNodeNil25Runtime* right;
    std::uint32_t key;
    std::uint8_t pad10[0x09];
    std::uint8_t isNil;
  };

  struct MapNodeNil61Runtime
  {
    MapNodeNil61Runtime* left;
    MapNodeNil61Runtime* parent;
    MapNodeNil61Runtime* right;
    std::uint32_t key;
    std::uint8_t pad10[0x2D];
    std::uint8_t isNil;
  };
#pragma pack(pop)

#if INTPTR_MAX == INT32_MAX
  static_assert(offsetof(MapNodeNil21Runtime, key) == 0x0C, "MapNodeNil21Runtime::key offset must be 0x0C");
  static_assert(offsetof(MapNodeNil21Runtime, isNil) == 0x15, "MapNodeNil21Runtime::isNil offset must be 0x15");
  static_assert(offsetof(MapNodeNil25Runtime, key) == 0x0C, "MapNodeNil25Runtime::key offset must be 0x0C");
  static_assert(offsetof(MapNodeNil25Runtime, isNil) == 0x19, "MapNodeNil25Runtime::isNil offset must be 0x19");
  static_assert(offsetof(MapNodeNil61Runtime, key) == 0x0C, "MapNodeNil61Runtime::key offset must be 0x0C");
  static_assert(offsetof(MapNodeNil61Runtime, isNil) == 0x3D, "MapNodeNil61Runtime::isNil offset must be 0x3D");
#endif

  template <typename NodeT>
  struct LegacyMapStorageRuntime
  {
    void* allocatorCookie;
    NodeT* head;
    std::uint32_t size;
  };

  template <typename NodeT>
  [[nodiscard]] NodeT* EnsureMapHead(LegacyMapStorageRuntime<NodeT>* const map)
  {
    if (map == nullptr) {
      return nullptr;
    }

    if (map->head != nullptr) {
      return map->head;
    }

    NodeT* const head = static_cast<NodeT*>(::operator new(sizeof(NodeT), std::nothrow));
    if (head == nullptr) {
      return nullptr;
    }

    std::memset(head, 0, sizeof(NodeT));
    head->left = head;
    head->parent = head;
    head->right = head;
    head->isNil = 1u;

    map->head = head;
    map->size = 0u;
    return head;
  }

  template <typename NodeT>
  [[nodiscard]] NodeT* InsertMapNode(
    LegacyMapStorageRuntime<NodeT>* const map,
    NodeT* const parent,
    const bool insertLeft,
    const std::uint32_t key
  )
  {
    if (map == nullptr) {
      return nullptr;
    }

    NodeT* const head = EnsureMapHead(map);
    if (head == nullptr) {
      return nullptr;
    }

    NodeT* const inserted = static_cast<NodeT*>(::operator new(sizeof(NodeT), std::nothrow));
    if (inserted == nullptr) {
      return nullptr;
    }

    std::memset(inserted, 0, sizeof(NodeT));
    inserted->left = head;
    inserted->right = head;
    inserted->parent = parent != nullptr ? parent : head;
    inserted->key = key;
    inserted->isNil = 0u;

    if (parent == nullptr || parent == head || parent->isNil != 0u) {
      head->parent = inserted;
      head->left = inserted;
      head->right = inserted;
    } else if (insertLeft) {
      parent->left = inserted;
      if (head->left == parent || head->left == head) {
        head->left = inserted;
      }
    } else {
      parent->right = inserted;
      if (head->right == parent || head->right == head) {
        head->right = inserted;
      }
    }

    ++map->size;
    return inserted;
  }

  template <typename NodeT>
  [[nodiscard]] MapInsertStatusRuntime* FindOrInsertMapNodeByKey(
    LegacyMapStorageRuntime<NodeT>* const map,
    const std::uint32_t* const key,
    MapInsertStatusRuntime* const outResult
  )
  {
    if (outResult == nullptr) {
      return nullptr;
    }

    outResult->node = nullptr;
    outResult->inserted = 0u;
    outResult->reserved[0] = 0u;
    outResult->reserved[1] = 0u;
    outResult->reserved[2] = 0u;

    if (map == nullptr || key == nullptr) {
      return outResult;
    }

    NodeT* const head = EnsureMapHead(map);
    if (head == nullptr) {
      return outResult;
    }

    NodeT* parent = head;
    NodeT* cursor = head->parent;
    bool goLeft = true;

    while (cursor != nullptr && cursor != head && cursor->isNil == 0u) {
      parent = cursor;
      if (*key < cursor->key) {
        goLeft = true;
        cursor = cursor->left;
      } else if (cursor->key < *key) {
        goLeft = false;
        cursor = cursor->right;
      } else {
        outResult->node = cursor;
        return outResult;
      }
    }

    NodeT* const inserted = InsertMapNode(map, parent, goLeft, *key);
    outResult->node = inserted;
    outResult->inserted = inserted != nullptr ? 1u : 0u;
    return outResult;
  }

  template <typename NodeT>
  [[nodiscard]] NodeT* FindMapNodeEqualOrHeadByKeyRuntime(
    NodeT* const head,
    const std::uint32_t key
  ) noexcept
  {
    if (head == nullptr) {
      return nullptr;
    }

    NodeT* candidate = head;
    NodeT* cursor = head->parent;
    while (cursor != nullptr && cursor->isNil == 0u) {
      if (cursor->key >= key) {
        candidate = cursor;
        cursor = cursor->left;
      } else {
        cursor = cursor->right;
      }
    }

    if (candidate == head || key < candidate->key) {
      return head;
    }
    return candidate;
  }

  template <typename NodeT>
  void FindMapEqualRangeByKeyRuntime(
    NodeT* const head,
    const std::uint32_t key,
    NodeT** const outLowerBound,
    NodeT** const outUpperBound
  ) noexcept
  {
    NodeT* lowerBound = head;
    NodeT* upperBound = head;
    if (head != nullptr) {
      NodeT* cursor = head->parent;
      while (cursor != nullptr && cursor->isNil == 0u) {
        if (key >= cursor->key) {
          cursor = cursor->right;
        } else {
          upperBound = cursor;
          cursor = cursor->left;
        }
      }

      cursor = head->parent;
      while (cursor != nullptr && cursor->isNil == 0u) {
        if (cursor->key >= key) {
          lowerBound = cursor;
          cursor = cursor->left;
        } else {
          cursor = cursor->right;
        }
      }
    }

    if (outLowerBound != nullptr) {
      *outLowerBound = lowerBound;
    }
    if (outUpperBound != nullptr) {
      *outUpperBound = upperBound;
    }
  }

  [[nodiscard]] const moho::BVIntSet& AsIdPoolSnapshot(const moho::SimSubRes3& slot) noexcept
  {
    return *reinterpret_cast<const moho::BVIntSet*>(&slot);
  }

  struct TimerAccumulatorRuntime
  {
    std::uintptr_t counterOwner;
    gpg::time::Timer elapsedTimer;
  };

  struct SSTIUnitVariableDataSlotRuntime
  {
    std::uint32_t mHeadWord0;
    std::uint32_t mHeadWord1;
    moho::SSTIUnitVariableData mVariableData;
    std::uint32_t mTailWord0;
    std::uint32_t mTailWord1;
  };
  static_assert(
    offsetof(SSTIUnitVariableDataSlotRuntime, mVariableData) == 0x08,
    "SSTIUnitVariableDataSlotRuntime::mVariableData offset must be 0x08"
  );
  static_assert(
    offsetof(SSTIUnitVariableDataSlotRuntime, mTailWord0) == 0x230,
    "SSTIUnitVariableDataSlotRuntime::mTailWord0 offset must be 0x230"
  );
  static_assert(sizeof(SSTIUnitVariableDataSlotRuntime) == 0x238, "SSTIUnitVariableDataSlotRuntime size must be 0x238");

  struct CameraCopyContextRuntime
  {
    std::uint32_t lane0;
    std::uint32_t lane4;
    moho::GeomCamera3* destinationEnd;
  };

  struct OpaqueLaneRebuildRuntime
  {
    std::uint32_t lane0;
    std::uint32_t lane4;
    std::byte* storage;
  };

  [[nodiscard]] std::byte* RebuildOpaqueLaneStorage(
    std::byte* const previousStorage,
    const std::size_t requestedBytes,
    const bool zeroFill
  )
  {
    std::byte* replacement = nullptr;
    if (requestedBytes != 0u) {
      replacement = static_cast<std::byte*>(::operator new(requestedBytes, std::nothrow));
      if (replacement != nullptr && zeroFill) {
        std::memset(replacement, 0, requestedBytes);
      }
    }

    ::operator delete(previousStorage);
    return replacement;
  }

  struct CacheWordVectorRuntime
  {
    std::uint32_t lane0;
    std::uint32_t* begin;
    std::uint32_t* end;
    std::uint32_t lane3;
    std::uint32_t lane4;
    std::int32_t stagedBeginIndex;
    std::int32_t stagedEndIndex;
    std::uint32_t lane7;
    std::int32_t cachedIndex;
  };

  template <typename T>
  struct FourLanePagedRuntime
  {
    std::uint32_t reserved0;
    T** pages;
    std::uint32_t pageCount;
    std::uint32_t baseIndex;
    std::uint32_t size;
  };

  template <typename T>
  struct RangeOwnerRuntime
  {
    std::uint32_t reserved0;
    T* begin;
    T* end;
    std::uint32_t reserved12;
  };

  struct StringRangeBlock16Runtime
  {
    std::uint32_t reserved0;
    msvc8::string* begin;
    msvc8::string* end;
    std::uint32_t reserved12;
  };

  struct SharedControlLane12Runtime
  {
    std::uint32_t reserved0;
    std::uint32_t reserved4;
    volatile long* control;
  };

  static_assert(sizeof(StringRangeBlock16Runtime) == 0x10, "StringRangeBlock16Runtime size must be 0x10");
  static_assert(sizeof(SharedControlLane12Runtime) == 0x0C, "SharedControlLane12Runtime size must be 0x0C");

  template <typename T>
  [[nodiscard]] T** GrowPagedArray(T** const pages, const std::uint32_t currentPageCount, const std::uint32_t desiredPageCount)
  {
    if (desiredPageCount <= currentPageCount) {
      return pages;
    }

    auto* const newPages = static_cast<T**>(::operator new(sizeof(T*) * desiredPageCount, std::nothrow));
    if (newPages == nullptr) {
      return pages;
    }

    for (std::uint32_t i = 0u; i < desiredPageCount; ++i) {
      newPages[i] = nullptr;
    }

    for (std::uint32_t i = 0u; i < currentPageCount; ++i) {
      newPages[i] = pages != nullptr ? pages[i] : nullptr;
    }

    ::operator delete(static_cast<void*>(pages));
    return newPages;
  }

  template <typename T>
  [[nodiscard]] T** EnsurePagedFourLanePage(
    FourLanePagedRuntime<T>* const runtime,
    const std::uint32_t logicalIndex
  )
  {
    if (runtime == nullptr) {
      return nullptr;
    }

    const std::uint32_t pageIndex = logicalIndex >> 2u;
    if (runtime->pages == nullptr || pageIndex >= runtime->pageCount) {
      const std::uint32_t desiredPageCount = std::max(runtime->pageCount == 0u ? 8u : runtime->pageCount * 2u, pageIndex + 1u);
      runtime->pages = GrowPagedArray(runtime->pages, runtime->pageCount, desiredPageCount);
      if (runtime->pages == nullptr) {
        return nullptr;
      }
      runtime->pageCount = desiredPageCount;
    }

    if (runtime->pages[pageIndex] == nullptr) {
      runtime->pages[pageIndex] = static_cast<T*>(::operator new(sizeof(T) * 4u, std::nothrow));
      if (runtime->pages[pageIndex] == nullptr) {
        return nullptr;
      }
    }

    return &runtime->pages[pageIndex];
  }

  template <typename T>
  void DestroyRangeAndRelease(T* begin, T* end)
  {
    if (begin == nullptr) {
      return;
    }

    for (T* cursor = begin; cursor != end; ++cursor) {
      std::destroy_at(cursor);
    }
  }

  template <typename T>
  void DestroyPagedFourLaneRange(
    FourLanePagedRuntime<T>* const runtime,
    std::uint32_t beginIndex,
    const std::uint32_t endIndex
  )
  {
    if (runtime == nullptr || runtime->pages == nullptr) {
      return;
    }

    while (beginIndex != endIndex) {
      const std::uint32_t pageIndex = beginIndex >> 2u;
      const std::uint32_t laneIndex = beginIndex & 3u;
      if (pageIndex < runtime->pageCount && runtime->pages[pageIndex] != nullptr) {
        T& entry = runtime->pages[pageIndex][laneIndex];
        if constexpr (std::is_pointer_v<T>) {
          if (entry != nullptr) {
            delete entry;
          }
        } else {
          std::destroy_at(&entry);
        }
      }
      ++beginIndex;
    }
  }

  template <typename T>
  [[nodiscard]] T* AllocateZeroedRuntimeNode() noexcept
  {
    auto* const node = static_cast<T*>(::operator new(sizeof(T), std::nothrow));
    if (node != nullptr) {
      std::memset(node, 0, sizeof(T));
    }
    return node;
  }

#pragma pack(push, 1)
  struct RbNodeFlag45Runtime
  {
    RbNodeFlag45Runtime* left;
    RbNodeFlag45Runtime* parent;
    RbNodeFlag45Runtime* right;
    std::uint32_t lane0C;
    std::uint32_t storageWord0;
    std::uint32_t storageWord1;
    std::uint32_t storageWord2;
    std::uint32_t storageWord3;
    std::uint32_t stringSize;
    std::uint32_t stringCapacity;
    std::uint32_t lane28;
    std::uint8_t sentinel44;
    std::uint8_t isNil45;
    std::uint8_t pad46[2];
  };

  struct RbNodeFlag21Runtime
  {
    RbNodeFlag21Runtime* left;
    RbNodeFlag21Runtime* parent;
    RbNodeFlag21Runtime* right;
    std::uint32_t lane0C;
    std::uint32_t lane10;
    std::uint8_t sentinel20;
    std::uint8_t isNil21;
    std::uint8_t pad22[2];
  };

  struct RbNodeFlag17Runtime
  {
    RbNodeFlag17Runtime* left;
    RbNodeFlag17Runtime* parent;
    RbNodeFlag17Runtime* right;
    std::uint32_t lane0C;
    std::uint8_t sentinel16;
    std::uint8_t isNil17;
    std::uint8_t pad18[2];
  };

  struct RbNodeFlag29Runtime
  {
    RbNodeFlag29Runtime* left;
    RbNodeFlag29Runtime* parent;
    RbNodeFlag29Runtime* right;
    std::uint32_t lane0C;
    std::uint32_t lane10;
    std::uint32_t lane14;
    std::uint32_t lane18;
    std::uint8_t sentinel28;
    std::uint8_t isNil29;
    std::uint8_t pad2A[2];
  };

  struct LinkedTreeNode37Runtime
  {
    LinkedTreeNode37Runtime* left;
    LinkedTreeNode37Runtime* parent;
    LinkedTreeNode37Runtime* right;
    std::uint32_t lane0C;
    std::uint32_t lane10;
    std::uint32_t lane14;
    std::uint32_t lane18;
    std::uint32_t lane1C;
    std::uint32_t lane20;
    std::uint32_t lane24;
  };

  struct RbNodeFlag65Runtime
  {
    RbNodeFlag65Runtime* left;
    RbNodeFlag65Runtime* parent;
    RbNodeFlag65Runtime* right;
    std::byte payload[53];
    std::uint8_t isNil65;
  };
#pragma pack(pop)

#if INTPTR_MAX == INT32_MAX
  static_assert(offsetof(RbNodeFlag45Runtime, sentinel44) == 0x2C, "RbNodeFlag45Runtime::sentinel44 offset must be 0x2C");
  static_assert(offsetof(RbNodeFlag45Runtime, isNil45) == 0x2D, "RbNodeFlag45Runtime::isNil45 offset must be 0x2D");
  static_assert(offsetof(RbNodeFlag21Runtime, sentinel20) == 0x14, "RbNodeFlag21Runtime::sentinel20 offset must be 0x14");
  static_assert(offsetof(RbNodeFlag21Runtime, isNil21) == 0x15, "RbNodeFlag21Runtime::isNil21 offset must be 0x15");
  static_assert(offsetof(RbNodeFlag17Runtime, sentinel16) == 0x10, "RbNodeFlag17Runtime::sentinel16 offset must be 0x10");
  static_assert(offsetof(RbNodeFlag17Runtime, isNil17) == 0x11, "RbNodeFlag17Runtime::isNil17 offset must be 0x11");
  static_assert(offsetof(RbNodeFlag29Runtime, sentinel28) == 0x1C, "RbNodeFlag29Runtime::sentinel28 offset must be 0x1C");
  static_assert(offsetof(RbNodeFlag29Runtime, isNil29) == 0x1D, "RbNodeFlag29Runtime::isNil29 offset must be 0x1D");
  static_assert(offsetof(RbNodeFlag65Runtime, isNil65) == 0x41, "RbNodeFlag65Runtime::isNil65 offset must be 0x41");
  static_assert(offsetof(LinkedTreeNode37Runtime, lane24) == 0x24, "LinkedTreeNode37Runtime::lane24 offset must be 0x24");
#endif

  struct LinearTreeNodeRuntime
  {
    LinearTreeNodeRuntime* next;
    LinearTreeNodeRuntime* prev;
  };

  struct LinearTreeStorageRuntime
  {
    std::uint32_t lane0;
    LinearTreeNodeRuntime* head;
    std::uint32_t size;
  };

  struct SwapBackedArrayRuntimeA
  {
    std::uint32_t lane0;
    std::uint32_t lane4;
    std::uint32_t* activeBuffer;  // +0x08
    std::uint32_t* cursor;        // +0x0C
    std::uint32_t cachedFirst;    // +0x10
    std::uint32_t* fallbackBuffer; // +0x14
  };

  struct SwapBackedArrayRuntimeB
  {
    std::uint32_t lane0;
    std::uint32_t lane4;
    std::uint32_t lane8;
    std::uint32_t laneC;
    std::uint32_t* activeBuffer;   // +0x10
    std::uint32_t* cursor;         // +0x14
    std::uint32_t cachedFirst;     // +0x18
    std::uint32_t* fallbackBuffer; // +0x1C
  };

  struct LinkedBufferOwnerRuntime
  {
    LinkedBufferOwnerRuntime* next; // +0x00
    LinkedBufferOwnerRuntime* prev; // +0x04
    std::uint32_t* activeBuffer;    // +0x08
    std::uint32_t* cursor;          // +0x0C
    std::uint32_t cachedFirst;      // +0x10
    std::uint32_t* fallbackBuffer;  // +0x14
  };

  struct TripleIntNodeRuntime
  {
    std::int32_t lane0;
    std::int32_t lane4;
    std::int32_t lane8;
  };

  struct StringFloatMapNodeRuntime
  {
    StringFloatMapNodeRuntime* left;
    StringFloatMapNodeRuntime* parent;
    StringFloatMapNodeRuntime* right;
    std::uint8_t color;
    std::uint8_t isNil;
    std::uint8_t pad0E[2];
    std::string key;
    float value;
  };

  struct StringFloatMapRuntime
  {
    StringFloatMapNodeRuntime* head;
  };

  struct RbMapFlag65Runtime
  {
    std::uint32_t allocatorCookie;
    RbNodeFlag65Runtime* head;
    std::uint32_t size;
  };

  struct RbMapFlag21Runtime
  {
    std::uint32_t allocatorCookie;
    RbNodeFlag21Runtime* head;
    std::uint32_t size;
  };

  struct Float4Runtime
  {
    float lanes[4];
  };

  using Float4FinalizeFn = std::int32_t (*)(
    Float4Runtime* heapBase,
    std::int32_t arg4,
    std::int32_t arg5,
    std::int32_t arg6,
    std::int32_t arg7
  );

  using RangeEraseRuntimeFn = std::int32_t (*)(void* owner, void* begin, void* rangeBegin, void* rangeEnd);
  using ForwardCleanupFn = void (*)(void* owner);
  using TaggedInsertRuntimeFn = std::int32_t (*)(std::uint32_t* begin, std::uint32_t tag, const std::uint32_t* value);
  using LaneConstructFn52 = void (*)(void* destination, const void* sourceContext);
  using CloneTree65Fn = RbNodeFlag65Runtime* (*)(RbNodeFlag65Runtime* sourceRoot, RbNodeFlag65Runtime* destinationHead);
  using CloneTree21Fn = RbNodeFlag21Runtime* (*)(RbNodeFlag21Runtime* sourceRoot, RbNodeFlag21Runtime* destinationHead);

  [[nodiscard]] bool NodeHasSentinelFlag(const void* const node, const std::size_t flagOffset) noexcept
  {
    if (node == nullptr) {
      return true;
    }

    const auto* const bytes = static_cast<const std::uint8_t*>(node);
    return bytes[flagOffset] != 0u;
  }

  template <typename NodeT, std::size_t NilOffset>
  [[nodiscard]] NodeT* DescendRightUntilSentinelRuntime(NodeT* node) noexcept
  {
    if (node == nullptr) {
      return nullptr;
    }

    NodeT* cursor = node->right;
    while (!NodeHasSentinelFlag(cursor, NilOffset)) {
      node = cursor;
      cursor = cursor->right;
    }
    return node;
  }

  template <typename NodeT, std::size_t NilOffset>
  [[nodiscard]] NodeT* DescendLeftUntilSentinelRuntime(NodeT* node) noexcept
  {
    if (node == nullptr) {
      return nullptr;
    }

    NodeT* cursor = node->left;
    while (!NodeHasSentinelFlag(cursor, NilOffset)) {
      node = cursor;
      cursor = cursor->left;
    }
    return node;
  }

  template <typename NodeT>
  void RecomputeHeadExtrema(NodeT* const head, const std::size_t nilFlagOffset)
  {
    if (head == nullptr) {
      return;
    }

    NodeT* const root = head->parent;
    if (root == nullptr || root == head || NodeHasSentinelFlag(root, nilFlagOffset)) {
      head->left = head;
      head->right = head;
      return;
    }

    NodeT* leftmost = root;
    while (leftmost->left != nullptr && !NodeHasSentinelFlag(leftmost->left, nilFlagOffset)) {
      leftmost = leftmost->left;
    }

    NodeT* rightmost = root;
    while (rightmost->right != nullptr && !NodeHasSentinelFlag(rightmost->right, nilFlagOffset)) {
      rightmost = rightmost->right;
    }

    head->left = leftmost;
    head->right = rightmost;
  }

  void DestroyRecursiveStringTree(RbNodeFlag45Runtime* node)
  {
    RbNodeFlag45Runtime* previous = node;
    RbNodeFlag45Runtime* cursor = node;
    while (cursor != nullptr && cursor->isNil45 == 0u) {
      DestroyRecursiveStringTree(cursor->right);
      cursor = cursor->left;

      if (previous->stringCapacity >= 16u) {
        const auto storageAddress = static_cast<std::uintptr_t>(previous->storageWord0);
        ::operator delete(reinterpret_cast<void*>(storageAddress));
      }

      previous->stringCapacity = 15u;
      previous->stringSize = 0u;
      previous->storageWord0 &= 0xFFFFFF00u;
      ::operator delete(previous);
      previous = cursor;
    }
  }

  void PatchBackReferenceChain(
    const std::uint32_t startWord,
    const std::uint32_t* const targetFieldAddress,
    const std::uint32_t replacementWord
  )
  {
    std::uint32_t* cursor = reinterpret_cast<std::uint32_t*>(static_cast<std::uintptr_t>(startWord));
    std::uint32_t guard = 0u;
    while (cursor != nullptr && guard < 0x100000u) {
      const auto* const pointedWord = reinterpret_cast<std::uint32_t*>(static_cast<std::uintptr_t>(*cursor));
      if (pointedWord == targetFieldAddress) {
        *cursor = replacementWord;
        return;
      }

      cursor = reinterpret_cast<std::uint32_t*>(static_cast<std::uintptr_t>(*cursor + 4u));
      ++guard;
    }
  }

  struct RangeOwnerByteRuntime
  {
    std::uint32_t lane0;
    std::uint32_t lane4;
    std::uint32_t lane8;
    std::byte* rangeBegin;
    std::uint32_t rangeByteSize;
  };

  struct TaggedInsertCursorRuntime
  {
    std::uint32_t lane0;
    std::uint32_t* begin;
    std::uint32_t* end;
  };

  struct FloatPayloadNodeRuntime
  {
    std::int32_t lane0;
    std::int32_t lane4;
    float lanes[7];
  };

  struct RbNodeFlag25Runtime
  {
    RbNodeFlag25Runtime* left;
    RbNodeFlag25Runtime* parent;
    RbNodeFlag25Runtime* right;
    std::byte payload[13];
    std::uint8_t isNil25;
  };

  struct RbNodeLinksRuntime
  {
    RbNodeLinksRuntime* left;
    RbNodeLinksRuntime* parent;
    RbNodeLinksRuntime* right;
  };

  struct RbNodeKeyFlag3145Runtime
  {
    RbNodeKeyFlag3145Runtime* left;       // +0x00
    RbNodeKeyFlag3145Runtime* parent;     // +0x04
    RbNodeKeyFlag3145Runtime* right;      // +0x08
    std::uint32_t lane0C = 0;             // +0x0C
    std::uint32_t key = 0;                // +0x10
    std::uint8_t reserved14_0C48[0x0C35]{};
    std::uint8_t isNil3145 = 0;           // +0x0C49
  };
  static_assert(offsetof(RbNodeKeyFlag3145Runtime, key) == 0x10, "RbNodeKeyFlag3145Runtime::key offset must be 0x10");
  static_assert(
    offsetof(RbNodeKeyFlag3145Runtime, isNil3145) == 0x0C49,
    "RbNodeKeyFlag3145Runtime::isNil3145 offset must be 0x0C49"
  );

  struct RbTreeSentinelFlag3145Runtime
  {
    std::uint32_t lane00 = 0;                  // +0x00
    RbNodeKeyFlag3145Runtime* root = nullptr;  // +0x04
  };

  RbTreeSentinelFlag3145Runtime* gFlag3145TreeSentinelRuntime = nullptr;

  struct WxArrayStringLaneRuntime
  {
    std::uint32_t lane0;
    std::uint32_t count;
    const wchar_t** entries;
  };

  struct WxLookupOwnerRuntime
  {
    std::byte pad00[36];
    WxArrayStringLaneRuntime* arrayLane;
  };

  struct DispatchWindowRuntime
  {
    void** vtable;
    std::byte payload[312];
    WNDPROC previousWindowProc;
  };

  struct DistanceVector2fRuntime
  {
    void* vtable;
    std::int32_t dimension;
    float epsilon;
    float initialDistance;
    float pad10;
    float pad14;
    float pad18;
    float pad1C;
    std::uint8_t hasRawResult;
    std::uint8_t hasFinalResult;
    std::uint8_t pad22[2];
    float minClamp;
    float maxClamp;
  };

  struct DistanceVector2dRuntime
  {
    void* vtable;
    std::int32_t dimension;
    std::byte pad0C[4];
    double epsilon;
    double initialDistance;
    double minClamp;
    double maxClamp;
    std::byte pad34[0x10];
    std::uint8_t hasRawResult;
    std::uint8_t hasFinalResult;
    std::uint8_t pad42[6];
  };

  struct DistVector2Box2fRuntime final : DistanceVector2fRuntime
  {
    const void* vector2Runtime = nullptr; // +0x2C
    const void* box2Runtime = nullptr;    // +0x30
  };
  static_assert(
    offsetof(DistVector2Box2fRuntime, vector2Runtime) == 0x2C,
    "DistVector2Box2fRuntime::vector2Runtime offset must be 0x2C"
  );
  static_assert(
    offsetof(DistVector2Box2fRuntime, box2Runtime) == 0x30,
    "DistVector2Box2fRuntime::box2Runtime offset must be 0x30"
  );

  struct DistVector2Box2dRuntime final : DistanceVector2dRuntime
  {
    std::byte reserved48_57[0x10]{};
    const void* vector2Runtime = nullptr; // +0x58
    const void* box2Runtime = nullptr;    // +0x5C
  };
  static_assert(
    offsetof(DistVector2Box2dRuntime, vector2Runtime) == 0x58,
    "DistVector2Box2dRuntime::vector2Runtime offset must be 0x58"
  );
  static_assert(
    offsetof(DistVector2Box2dRuntime, box2Runtime) == 0x5C,
    "DistVector2Box2dRuntime::box2Runtime offset must be 0x5C"
  );

  struct BasisPointerResetRuntimeF
  {
    std::byte pad00[20];
    float** basisPair;
    float* outputPrimary;
    float* outputSecondary;
    std::uint8_t wasReset;
  };

  struct BasisPointerResetRuntimeD
  {
    std::byte pad00[20];
    double** basisPair;
    double* outputPrimary;
    double* outputSecondary;
    std::uint8_t wasReset;
  };

  struct IntArrayLookupRuntime
  {
    std::int32_t lane0;
    std::uint32_t count;
    std::int32_t* values;
  };

  struct VirtualDispatch44Runtime
  {
    void** vtable;
  };

  struct LinkPatchRuntime
  {
    std::byte pad00[8];
    std::uint32_t lane08;
    std::uint32_t lane0C;
    std::uint32_t lane10;
    std::uint32_t lane14;
  };

#pragma pack(push, 1)
  struct RefCountedPayload49Runtime
  {
    std::uint32_t lane00;
    std::uint32_t lane04;
    float lane08;
    float lane0C;
    float lane10;
    std::uint32_t lane14;
    std::uint32_t ref18;
    std::uint32_t lane1C;
    std::uint32_t ref20;
    std::uint32_t lane24;
    std::uint32_t ref28;
    std::uint8_t tail2C;
    std::uint8_t tail2D;
    std::uint8_t tail2E;
    std::uint8_t tail2F;
    std::uint8_t tail30;
  };
#pragma pack(pop)

  struct WxObjectRuntime
  {
    void* vtable;
  };

  struct WxFontDescriptorRuntime
  {
    std::uint32_t lane00;
    std::uint32_t lane04;
    std::int32_t pointSize;
    std::int32_t family;
    std::int32_t style;
    std::int32_t weight;
    std::uint8_t underlined;
    std::uint8_t pad19[3];
    std::byte faceNameStorage[8];
    std::int32_t encoding;
    std::int32_t lane24;
    std::byte pad28[0x58];
    std::uint8_t lane84;
  };

  struct WxSharedStringOwnerRuntime
  {
    std::uint32_t lane00;
    std::uint32_t stringLane04;
    std::uint32_t stringLane08;
    std::uint32_t stringLane0C;
    std::byte pad10[16];
    std::uint32_t stringLane20;
  };

  struct Div10PairOwnerRuntime
  {
    std::byte pad00[0x0C];
    std::int32_t lane0C;
    std::int32_t lane10;
    std::byte pad14[0x58];
    std::uint32_t sourceLane6C;
  };

  struct VtableOnlyRuntime
  {
    void* vtable;
  };

  struct WxSocketOutputStreamRuntime
  {
    void* vtable;
    std::byte pad04[8];
    std::int32_t socketHandle;
  };

  struct WxSocketInputStreamRuntime
  {
    void* vtable;
    std::byte pad04[0x14];
    std::int32_t socketHandle;
  };

  struct WxSocketStreamRuntime
  {
    WxSocketInputStreamRuntime inputBase;
    WxSocketOutputStreamRuntime outputBase;
  };

  struct WxHttpStreamRuntime
  {
    void* vtable;
    std::byte pad04[0x14];
    std::int32_t socketInputHandle;
    std::int32_t socketHandle;
  };

  struct HashBucketCleanupOwnerRuntime
  {
    void** bucketHeads;
    std::uint32_t bucketCount;
    std::uint32_t lane08;
  };

  struct CartographicDecalNodeRuntime
  {
    CartographicDecalNodeRuntime* next;
    CartographicDecalNodeRuntime* prev;
    void* vtable;
  };

  struct CartographicDecalListRuntime
  {
    std::uint32_t lane00;
    CartographicDecalNodeRuntime* sentinel;
    std::uint32_t size;
  };

  struct SmallStringSboRuntime
  {
    union
    {
      char inlineStorage[16];
      char* heapStorage;
    };
    std::uint32_t size;
    std::uint32_t capacity;
  };

  struct WaveParametersRuntime
  {
    void* vtable;               // +0x00
    msvc8::string lane04Text;   // +0x04
    msvc8::string lane20Text;   // +0x20
    float lane3C;               // +0x3C
    float lane40;               // +0x40
    float lane44;               // +0x44
    float lane48;               // +0x48
    float lane4C;               // +0x4C
    float lane50;               // +0x50
    float lane54;               // +0x54
    float lane58;               // +0x58
    float lane5C;               // +0x5C
    std::uint32_t lane60;       // +0x60
    std::uint32_t lane64;       // +0x64
    float lane68;               // +0x68
    float lane6C;               // +0x6C
    float lane70;               // +0x70
    float lane74;               // +0x74
    float lane78;               // +0x78
    float lane7C;               // +0x7C
    float lane80;               // +0x80
    float lane84;               // +0x84
  };

  struct WindowTextMetricOwnerRuntime
  {
    std::byte pad00[264];
    HWND windowHandle;
  };

  struct RegionNodeRuntime
  {
    std::byte pad00[8];
    HRGN regionHandle;
  };

  struct RegionOwnerRuntime
  {
    std::uint32_t lane00;
    RegionNodeRuntime* node;
  };

  struct EmitterCurveKeyRuntime
  {
    void* vtable;
    float lane04;
    float lane08;
    float lane0C;
  };

  struct TimeSplitRuntime
  {
    std::byte pad00[0x24];
    std::uint32_t seconds;
    std::uint32_t microseconds;
  };

  struct TimeSplitOwnerRuntime
  {
    std::byte pad00[0x08];
    TimeSplitRuntime* splitTime;
    std::byte pad0C[0x18];
    std::int32_t lane24;
  };

  struct BuildQueueSnapshotRuntime
  {
    std::uint32_t lane00;
    const std::byte* begin;
    const std::byte* end;
  };

  struct BuildQueueRangeRuntime
  {
    const std::byte* start;
    const std::byte* end;
  };

  struct BuildQueueCompareStateRuntime
  {
    std::uint8_t lane00;
    std::uint8_t pad01[3];
  };

  struct BuildQueueCompareResultRuntime
  {
    const std::byte* cursor;
  };

  struct OccupySourceBindingRuntime
  {
    void* vtable;
    std::uint32_t lane04;
    std::uint32_t lane08;
  };

  struct ClutterSeedRuntime
  {
    void* vtable;
    float lane04;
    float lane08;
    std::uint32_t lane0C;
  };

  struct WideIoStreamOffsetsRuntime
  {
    std::ptrdiff_t wiosOffset;
    std::ptrdiff_t iosbOffset;
    std::ptrdiff_t wistreamOffset;
  };

  struct TreeStorageOwnerRuntime
  {
    std::uint32_t lane00;
    void* treeStorage;
    std::uint32_t size;
  };

#pragma pack(push, 1)
  struct MapNodeNil17Runtime
  {
    MapNodeNil17Runtime* left;
    MapNodeNil17Runtime* parent;
    MapNodeNil17Runtime* right;
    std::uint32_t key;
    std::uint8_t pad10;
    std::uint8_t isNil;
  };

  struct MapNodeNil29Runtime
  {
    MapNodeNil29Runtime* left;
    MapNodeNil29Runtime* parent;
    MapNodeNil29Runtime* right;
    std::uint32_t key;
    std::uint8_t pad10[0x0D];
    std::uint8_t isNil;
  };

  struct SetCharNodeNil14Runtime
  {
    SetCharNodeNil14Runtime* left;
    SetCharNodeNil14Runtime* parent;
    SetCharNodeNil14Runtime* right;
    std::int8_t value;
    std::uint8_t color;
    std::uint8_t isNil;
  };

  struct PairKeyNodeNil37Runtime
  {
    PairKeyNodeNil37Runtime* left;
    PairKeyNodeNil37Runtime* parent;
    PairKeyNodeNil37Runtime* right;
    std::uint8_t pad0C[0x04];
    std::uint32_t keyHigh;
    std::uint32_t keyLow;
    std::uint8_t pad18[0x0D];
    std::uint8_t isNil;
  };
#pragma pack(pop)

  struct WrappedPointerArrayRuntime
  {
    std::uint32_t lane00;
    std::uint32_t* entries;
    std::uint32_t baseIndex;
  };

  struct WrappedArrayCursorRuntime
  {
    WrappedPointerArrayRuntime* owner;
    std::uint32_t logicalIndex;
  };

  struct NetCommandRecordRuntime
  {
    std::byte storage[0x30];
  };

  struct Vector16ByteOwnerRuntime
  {
    std::uint32_t lane00;
    std::byte* begin;
    std::byte* end;
    std::byte* capacity;
  };

  struct SharedRefRuntime
  {
    void* object;
    void* counter;
  };

  struct SharedRefInitRuntime
  {
    void* object;
    void* counter;
  };

  struct PairKeyRuntime
  {
    std::uint32_t high;
    std::uint32_t low;
  };

  struct PairNodeRuntime
  {
    union
    {
      PairNodeRuntime* left; // +0x00
      std::int32_t lane00;
    };
    union
    {
      PairNodeRuntime* parent; // +0x04
      std::int32_t lane04;
    };
    union
    {
      PairNodeRuntime* right; // +0x08
      std::int32_t lane08;
    };
    std::byte payload0C[0x18];
    std::uint8_t color;
    std::uint8_t isNil;
  };

  struct PairNodeMeshKeyPayloadRuntime
  {
    void* vtable = nullptr;                                   // +0x00
    std::uint32_t lane04 = 0;                                 // +0x04
    void* sharedObjectLane08 = nullptr;                       // +0x08
    boost::detail::sp_counted_base* sharedControlLane0C = nullptr; // +0x0C
    void* weakObjectLane10 = nullptr;                         // +0x10
    boost::detail::sp_counted_base* weakControlLane14 = nullptr; // +0x14
  };
  static_assert(
    offsetof(PairNodeMeshKeyPayloadRuntime, sharedControlLane0C) == 0x0C,
    "PairNodeMeshKeyPayloadRuntime::sharedControlLane0C offset must be 0x0C"
  );
  static_assert(
    offsetof(PairNodeMeshKeyPayloadRuntime, weakControlLane14) == 0x14,
    "PairNodeMeshKeyPayloadRuntime::weakControlLane14 offset must be 0x14"
  );
  static_assert(sizeof(PairNodeMeshKeyPayloadRuntime) == 0x18, "PairNodeMeshKeyPayloadRuntime size must be 0x18");

  std::uint8_t gPairNodeMeshKeyPayloadRuntimeVTableTag = 0u;

  struct IntrusiveListNodeRuntime
  {
    IntrusiveListNodeRuntime* next;
    IntrusiveListNodeRuntime* prev;
  };

  struct IntrusiveListRuntime
  {
    std::uint32_t lane00;
    IntrusiveListNodeRuntime* head;
    std::uint32_t size;
  };

  struct IntrusiveOwnerSlotRuntime
  {
    IntrusiveOwnerSlotRuntime** ownerSlot;
    IntrusiveOwnerSlotRuntime* next;
  };

  struct IntrusiveOwnerAnchorRuntime
  {
    std::uint32_t lane00;
    IntrusiveOwnerSlotRuntime* head;
  };
#if INTPTR_MAX == INT32_MAX
  static_assert(offsetof(IntrusiveOwnerAnchorRuntime, head) == 0x04, "IntrusiveOwnerAnchorRuntime::head offset must be 0x04");
#endif

  struct AssistingUnitListOwnerRuntime
  {
    std::byte pad00[0x3C0];
    void* ownerLinkSlot;
  };
#if INTPTR_MAX == INT32_MAX
  static_assert(
    offsetof(AssistingUnitListOwnerRuntime, ownerLinkSlot) == 0x3C0,
    "AssistingUnitListOwnerRuntime::ownerLinkSlot offset must be 0x3C0"
  );
#endif

  struct MeshThumbnailListNodeRuntime
  {
    MeshThumbnailListNodeRuntime* next;
    MeshThumbnailListNodeRuntime* prev;
    std::byte thumbnailStorage[1];
  };

  struct Stride136VectorRuntime
  {
    std::uint32_t lane00;
    std::byte* begin;
    std::byte* end;
    std::byte* capacity;
  };

  class CameraSnapshotViewRuntime
  {
  public:
    explicit CameraSnapshotViewRuntime(void* storage) noexcept
      : bytes_(static_cast<std::byte*>(storage))
    {
    }

    explicit CameraSnapshotViewRuntime(const void* storage) noexcept
      : bytes_(const_cast<std::byte*>(static_cast<const std::byte*>(storage)))
    {
    }

    [[nodiscard]] std::uint32_t& lane08() const noexcept
    {
      return *reinterpret_cast<std::uint32_t*>(bytes_ + 0x08);
    }

    [[nodiscard]] void* cameraStorage() const noexcept
    {
      return bytes_ + 0x10;
    }

    [[nodiscard]] std::uint32_t& lane2D8() const noexcept
    {
      return *reinterpret_cast<std::uint32_t*>(bytes_ + 0x2D8);
    }

    [[nodiscard]] float& lane2DC() const noexcept
    {
      return *reinterpret_cast<float*>(bytes_ + 0x2DC);
    }

    [[nodiscard]] float& lane2E0() const noexcept
    {
      return *reinterpret_cast<float*>(bytes_ + 0x2E0);
    }

    [[nodiscard]] float& lane2E4() const noexcept
    {
      return *reinterpret_cast<float*>(bytes_ + 0x2E4);
    }

    [[nodiscard]] float& lane2E8() const noexcept
    {
      return *reinterpret_cast<float*>(bytes_ + 0x2E8);
    }

    [[nodiscard]] std::uint32_t& lane2EC() const noexcept
    {
      return *reinterpret_cast<std::uint32_t*>(bytes_ + 0x2EC);
    }

    [[nodiscard]] std::uint32_t& lane2F0() const noexcept
    {
      return *reinterpret_cast<std::uint32_t*>(bytes_ + 0x2F0);
    }

    [[nodiscard]] std::uint32_t& lane2F4() const noexcept
    {
      return *reinterpret_cast<std::uint32_t*>(bytes_ + 0x2F4);
    }

    [[nodiscard]] std::uint32_t& lane2F8() const noexcept
    {
      return *reinterpret_cast<std::uint32_t*>(bytes_ + 0x2F8);
    }

    [[nodiscard]] std::uint32_t& lane2FC() const noexcept
    {
      return *reinterpret_cast<std::uint32_t*>(bytes_ + 0x2FC);
    }

    [[nodiscard]] std::uint32_t& lane300() const noexcept
    {
      return *reinterpret_cast<std::uint32_t*>(bytes_ + 0x300);
    }

    [[nodiscard]] void*& weakCounter304() const noexcept
    {
      return *reinterpret_cast<void**>(bytes_ + 0x304);
    }

  private:
    std::byte* bytes_;
  };

  class UnitSelectionStateViewRuntime
  {
  public:
    explicit UnitSelectionStateViewRuntime(const void* storage) noexcept
      : bytes_(static_cast<const std::byte*>(storage))
    {
    }

    [[nodiscard]] std::int32_t selectedIndex() const noexcept
    {
      return *reinterpret_cast<const std::int32_t*>(bytes_ + 0x488);
    }

    [[nodiscard]] void* const* entries() const noexcept
    {
      const auto entriesWord = *reinterpret_cast<const std::uint32_t*>(bytes_ + 0x3F0);
      return reinterpret_cast<void* const*>(static_cast<std::uintptr_t>(entriesWord));
    }

  private:
    const std::byte* bytes_;
  };

  class UnitSelectionEntryViewRuntime
  {
  public:
    explicit UnitSelectionEntryViewRuntime(const void* storage) noexcept
      : bytes_(static_cast<const std::byte*>(storage))
    {
    }

    [[nodiscard]] std::int32_t sampleCount() const noexcept
    {
      return *reinterpret_cast<const std::int32_t*>(bytes_ + 0x1C4);
    }

    [[nodiscard]] float minX() const noexcept
    {
      return *reinterpret_cast<const float*>(bytes_ + 0x1BC);
    }

    [[nodiscard]] float minY() const noexcept
    {
      return *reinterpret_cast<const float*>(bytes_ + 0x1C0);
    }

    [[nodiscard]] float minZ() const noexcept
    {
      return *reinterpret_cast<const float*>(bytes_ + 0x1C8);
    }

    [[nodiscard]] float extX() const noexcept
    {
      return *reinterpret_cast<const float*>(bytes_ + 0x1CC);
    }

    [[nodiscard]] float extY() const noexcept
    {
      return *reinterpret_cast<const float*>(bytes_ + 0x1D0);
    }

  private:
    const std::byte* bytes_;
  };

  using WxUnrefFn = void (*)(void*);
  using WxGetDefaultPointSizeFn = std::int32_t (*)();
  using WxStringAssignFn = void (*)(void* destination, const void* source);
  using WxControlDtorFn = int (*)(void*);
  using WxProtocolCtorFn = VtableOnlyRuntime* (*)(VtableOnlyRuntime* protocol);
  using WxProtocolInitializeFn = void (*)(int lane0);
  using WxSocketOutputBaseCtorFn = void (*)(void* stream);
  using WxInputStreamCtorFn = void (*)(void* stream);
  using WxSocketInputCtorFn = WxSocketInputStreamRuntime* (*)(WxSocketInputStreamRuntime* stream, std::int32_t socketHandle);
  using WxSocketOutputCtorFn = WxSocketOutputStreamRuntime* (*)(WxSocketOutputStreamRuntime* stream, std::int32_t socketHandle);
  using HashBucketDestroyFn = void (__cdecl*)(void* node);
  using HashBucketClearFn = void* (*)(std::uint32_t bucketCount, void** bucketHeads, HashBucketDestroyFn destroyNode);
  using PairLookupFn = void (*)(std::int32_t outPair[2], std::uint32_t key);
  using NormalizePackedDoubleFn = std::int16_t (*)(std::uint16_t* words);
  using BuildQueueCompareFn = BuildQueueCompareResultRuntime* (*)(BuildQueueCompareStateRuntime* state, const std::byte* lhsBegin, const std::byte* lhsEnd, const std::byte* rhsBegin, std::uint32_t lane4, std::uint32_t lane5);
  using IosBaseDtorFn = void (*)(void* iosBaseLane);
  using RuntimeFailureDispatchFn = void (*)(int arg0, int arg1);
  using OwnerTreeClearFn = void (*)(TreeStorageOwnerRuntime* owner);
  using TreeClearFn = void (*)(void* scratch, void* root, void* head);
  using TreeClearWithOwnerFn = void (*)(void* owner, void* scratch, void* root, void* head);
  using NetCommandRecordCopyFn = void (*)(void* destinationRecord, const void* sourceRecord);
  using Vector16ConstructFn = int (*)(void* destination, std::uint32_t lane0, std::uint32_t lane1);
  using Vector16GrowFn = int (*)(Vector16ByteOwnerRuntime* owner, void* tail, std::uint32_t inputWord);
  using LookupNodeByTextFn = void* (*)(void* owner, const void* key);
  using AppendLookupTextFn = int (*)(void* sink, const void* node);
  using InitSharedRefFn = void (*)(SharedRefInitRuntime* outRef, void* object);
  using EnableSharedFromThisFn = void (*)(SharedRefInitRuntime* outRef, void* sharedOwner, void* rawObject);
  using PairMapInsertNodeFn = PairKeyNodeNil37Runtime* (*)(PairKeyNodeNil37Runtime** parentSlot, std::uint8_t insertLeft, const PairKeyRuntime* key);
  using PairMapFixupFn = void (*)(PairKeyNodeNil37Runtime** parentSlot);
  using PairNodeAllocFn = PairNodeRuntime* (*)(std::uint32_t count);
  using PairNodePayloadInitFn = void (*)(void* payloadStorage, std::int32_t sourceWord);
  using ObjectPreDeleteFn = void (*)(void* object);
  using ListClearFn = void (*)(IntrusiveListRuntime* list);
  using ListSpliceFn = void (*)(IntrusiveListRuntime* destination, IntrusiveListNodeRuntime* destinationPosition, IntrusiveListNodeRuntime* first, IntrusiveListNodeRuntime* last, IntrusiveListNodeRuntime* sourceNext);
  using CameraCopyFn = void (*)(void* destinationCamera, const void* sourceCamera);
  using WeakReleaseFn = void (*)(void* counter);
  using MeshThumbnailDtorFn = void (*)(void* thumbnail);
  using BuildSelectionRangeFn = void (*)(void* outRange, void* owner, void* begin, void* end);
  using SubmitSelectionQuadFn = int (*)(const float* quadVertices, void* owner);
  using ConstructStride136Fn = void (*)(std::byte* destination, std::uint32_t count, std::uint32_t lane4, std::uint32_t lane5);
  using GrowStride136Fn = void (*)(Stride136VectorRuntime* owner, void* scratch, std::byte* tail, void* source);
  using CloneTreeStorageFn = void* (*)(std::uint8_t lane0, std::uint8_t lane1, std::uint8_t lane2, void* sourceRoot);
  using CloneTreePayloadFn = void (*)(void* destinationRoot, void* sourceRoot);
  using SimpleDtorFn = void (*)(void* object);
  using TesselatorGetIndexFn = std::uint16_t (*)(void* tesselator, std::uint32_t size, const std::uint8_t* rowToken, std::int32_t column);
  using TesselatorAddTriangleFn = void (*)(void* tesselator, std::uint32_t source, std::uint32_t middle, std::uint32_t destination);

  [[nodiscard]] std::uint32_t DivideBy1000Fast(const std::uint32_t value) noexcept
  {
    return static_cast<std::uint32_t>((static_cast<std::uint64_t>(value) * 0x10624DD3ull) >> 38u);
  }

  [[nodiscard]] std::ptrdiff_t CountStride48Elements(
    const std::byte* const begin,
    const std::byte* const end
  ) noexcept
  {
    if (begin == nullptr || end == nullptr || end < begin) {
      return 0;
    }
    return (end - begin) / 48;
  }

  void ReleaseSharedWxStringLane(const std::uint32_t laneWord) noexcept
  {
    if (laneWord == 0u) {
      return;
    }

    auto* const header = reinterpret_cast<std::int32_t*>(static_cast<std::uintptr_t>(laneWord) - 12u);
    const std::int32_t refCount = *header;
    if (refCount == -1) {
      return;
    }

    *header = refCount - 1;
    if (refCount == 1) {
      ::operator delete(header);
    }
  }

  void ResetSmallStringLane(SmallStringSboRuntime* const value)
  {
    if (value == nullptr) {
      return;
    }

    if (value->capacity >= 16u) {
      ::operator delete(value->heapStorage);
    }

    value->capacity = 15u;
    value->size = 0u;
    value->inlineStorage[0] = '\0';
  }

  [[nodiscard]] std::uint32_t ResolveWrappedPointerWord(
    const WrappedPointerArrayRuntime* const cursorOwner,
    const std::uint32_t logicalIndex
  ) noexcept
  {
    if (cursorOwner == nullptr || cursorOwner->entries == nullptr) {
      return 0u;
    }

    std::uint32_t resolvedIndex = logicalIndex;
    if (cursorOwner->baseIndex <= logicalIndex) {
      resolvedIndex = logicalIndex - cursorOwner->baseIndex;
    }

    return cursorOwner->entries[resolvedIndex];
  }

  [[nodiscard]] PairKeyNodeNil37Runtime* EnsurePairMapHeadRuntime(
    LegacyMapStorageRuntime<PairKeyNodeNil37Runtime>* const map
  )
  {
    if (map == nullptr) {
      return nullptr;
    }

    if (map->head != nullptr) {
      return map->head;
    }

    auto* const head = static_cast<PairKeyNodeNil37Runtime*>(::operator new(sizeof(PairKeyNodeNil37Runtime), std::nothrow));
    if (head == nullptr) {
      return nullptr;
    }

    std::memset(head, 0, sizeof(PairKeyNodeNil37Runtime));
    head->left = head;
    head->parent = head;
    head->right = head;
    head->isNil = 1u;

    map->head = head;
    map->size = 0u;
    return head;
  }

  [[nodiscard]] bool PairKeyLessRuntime(const PairKeyRuntime& lhs, const PairKeyRuntime& rhs) noexcept
  {
    if (lhs.high < rhs.high) {
      return true;
    }
    if (rhs.high < lhs.high) {
      return false;
    }
    return lhs.low < rhs.low;
  }

  void ReleaseSharedCounterRuntime(void* counter) noexcept
  {
    if (counter == nullptr) {
      return;
    }

    auto* const bytes = static_cast<std::byte*>(counter);
    auto* const strong = reinterpret_cast<volatile LONG*>(bytes + 4);
    if (::InterlockedExchangeAdd(strong, -1) == 1) {
      auto** const vtable = *reinterpret_cast<void***>(counter);
      using DisposeFn = void (__thiscall*)(void*);
      const auto dispose = reinterpret_cast<DisposeFn>(vtable[1]);
      if (dispose != nullptr) {
        dispose(counter);
      }

      auto* const weak = reinterpret_cast<volatile LONG*>(bytes + 8);
      if (::InterlockedExchangeAdd(weak, -1) == 1) {
        using DestroyFn = void (__thiscall*)(void*);
        const auto destroy = reinterpret_cast<DestroyFn>(vtable[2]);
        if (destroy != nullptr) {
          destroy(counter);
        }
      }
    }
  }

  [[nodiscard]] std::ptrdiff_t CountStride136Elements(
    const std::byte* const begin,
    const std::byte* const end
  ) noexcept
  {
    if (begin == nullptr || end == nullptr || end < begin) {
      return 0;
    }
    return (end - begin) / 136;
  }

#if INTPTR_MAX == INT32_MAX
  static_assert(offsetof(RbNodeFlag25Runtime, isNil25) == 0x19, "RbNodeFlag25Runtime::isNil25 offset must be 0x19");
  static_assert(offsetof(DistanceVector2fRuntime, hasRawResult) == 0x20, "DistanceVector2fRuntime::hasRawResult offset must be 0x20");
  static_assert(offsetof(DistanceVector2dRuntime, hasRawResult) == 0x40, "DistanceVector2dRuntime::hasRawResult offset must be 0x40");
  static_assert(offsetof(LinkPatchRuntime, lane10) == 0x10, "LinkPatchRuntime::lane10 offset must be 0x10");
  static_assert(sizeof(RefCountedPayload49Runtime) == 0x31, "RefCountedPayload49Runtime size must be 0x31");
  static_assert(offsetof(WxFontDescriptorRuntime, pointSize) == 0x08, "WxFontDescriptorRuntime::pointSize offset must be 0x08");
  static_assert(offsetof(WxFontDescriptorRuntime, faceNameStorage) == 0x1C, "WxFontDescriptorRuntime::faceNameStorage offset must be 0x1C");
  static_assert(offsetof(WxFontDescriptorRuntime, lane84) == 0x84, "WxFontDescriptorRuntime::lane84 offset must be 0x84");
  static_assert(offsetof(WxSharedStringOwnerRuntime, stringLane20) == 0x20, "WxSharedStringOwnerRuntime::stringLane20 offset must be 0x20");
  static_assert(offsetof(Div10PairOwnerRuntime, sourceLane6C) == 0x6C, "Div10PairOwnerRuntime::sourceLane6C offset must be 0x6C");
  static_assert(offsetof(WxSocketOutputStreamRuntime, socketHandle) == 0x0C, "WxSocketOutputStreamRuntime::socketHandle offset must be 0x0C");
  static_assert(offsetof(WxSocketInputStreamRuntime, socketHandle) == 0x18, "WxSocketInputStreamRuntime::socketHandle offset must be 0x18");
  static_assert(offsetof(WxSocketStreamRuntime, outputBase) == 0x1C, "WxSocketStreamRuntime::outputBase offset must be 0x1C");
  static_assert(offsetof(WxHttpStreamRuntime, socketInputHandle) == 0x18, "WxHttpStreamRuntime::socketInputHandle offset must be 0x18");
  static_assert(offsetof(WxHttpStreamRuntime, socketHandle) == 0x1C, "WxHttpStreamRuntime::socketHandle offset must be 0x1C");
  static_assert(sizeof(HashBucketCleanupOwnerRuntime) == 0x0C, "HashBucketCleanupOwnerRuntime size must be 0x0C");
  static_assert(sizeof(SmallStringSboRuntime) == 0x18, "SmallStringSboRuntime size must be 0x18");
  static_assert(sizeof(WaveParametersRuntime) == 0x88, "WaveParametersRuntime size must be 0x88");
  static_assert(offsetof(WaveParametersRuntime, lane04Text) == 0x04, "WaveParametersRuntime::lane04Text offset must be 0x04");
  static_assert(offsetof(WaveParametersRuntime, lane20Text) == 0x20, "WaveParametersRuntime::lane20Text offset must be 0x20");
  static_assert(offsetof(WaveParametersRuntime, lane3C) == 0x3C, "WaveParametersRuntime::lane3C offset must be 0x3C");
  static_assert(offsetof(WaveParametersRuntime, lane60) == 0x60, "WaveParametersRuntime::lane60 offset must be 0x60");
  static_assert(offsetof(WaveParametersRuntime, lane84) == 0x84, "WaveParametersRuntime::lane84 offset must be 0x84");
  static_assert(offsetof(WindowTextMetricOwnerRuntime, windowHandle) == 0x108, "WindowTextMetricOwnerRuntime::windowHandle offset must be 0x108");
  static_assert(offsetof(RegionNodeRuntime, regionHandle) == 0x08, "RegionNodeRuntime::regionHandle offset must be 0x08");
  static_assert(sizeof(EmitterCurveKeyRuntime) == 0x10, "EmitterCurveKeyRuntime size must be 0x10");
  static_assert(offsetof(TimeSplitRuntime, seconds) == 0x24, "TimeSplitRuntime::seconds offset must be 0x24");
  static_assert(offsetof(TimeSplitRuntime, microseconds) == 0x28, "TimeSplitRuntime::microseconds offset must be 0x28");
  static_assert(offsetof(TimeSplitOwnerRuntime, splitTime) == 0x08, "TimeSplitOwnerRuntime::splitTime offset must be 0x08");
  static_assert(offsetof(TimeSplitOwnerRuntime, lane24) == 0x24, "TimeSplitOwnerRuntime::lane24 offset must be 0x24");
  static_assert(offsetof(BuildQueueSnapshotRuntime, begin) == 0x04, "BuildQueueSnapshotRuntime::begin offset must be 0x04");
  static_assert(offsetof(BuildQueueSnapshotRuntime, end) == 0x08, "BuildQueueSnapshotRuntime::end offset must be 0x08");
  static_assert(sizeof(OccupySourceBindingRuntime) == 0x0C, "OccupySourceBindingRuntime size must be 0x0C");
  static_assert(sizeof(ClutterSeedRuntime) == 0x10, "ClutterSeedRuntime size must be 0x10");
  static_assert(offsetof(MapNodeNil17Runtime, key) == 0x0C, "MapNodeNil17Runtime::key offset must be 0x0C");
  static_assert(offsetof(MapNodeNil17Runtime, isNil) == 0x11, "MapNodeNil17Runtime::isNil offset must be 0x11");
  static_assert(offsetof(MapNodeNil29Runtime, key) == 0x0C, "MapNodeNil29Runtime::key offset must be 0x0C");
  static_assert(offsetof(MapNodeNil29Runtime, isNil) == 0x1D, "MapNodeNil29Runtime::isNil offset must be 0x1D");
  static_assert(offsetof(SetCharNodeNil14Runtime, value) == 0x0C, "SetCharNodeNil14Runtime::value offset must be 0x0C");
  static_assert(offsetof(SetCharNodeNil14Runtime, isNil) == 0x0E, "SetCharNodeNil14Runtime::isNil offset must be 0x0E");
  static_assert(offsetof(PairKeyNodeNil37Runtime, keyHigh) == 0x10, "PairKeyNodeNil37Runtime::keyHigh offset must be 0x10");
  static_assert(offsetof(PairKeyNodeNil37Runtime, keyLow) == 0x14, "PairKeyNodeNil37Runtime::keyLow offset must be 0x14");
  static_assert(offsetof(PairKeyNodeNil37Runtime, isNil) == 0x25, "PairKeyNodeNil37Runtime::isNil offset must be 0x25");
  static_assert(offsetof(PairNodeRuntime, payload0C) == 0x0C, "PairNodeRuntime::payload0C offset must be 0x0C");
  static_assert(offsetof(PairNodeRuntime, color) == 0x24, "PairNodeRuntime::color offset must be 0x24");
  static_assert(offsetof(PairNodeRuntime, isNil) == 0x25, "PairNodeRuntime::isNil offset must be 0x25");
#endif

  template <typename NodeT, std::size_t NilOffset>
  [[nodiscard]] NodeT* AdvanceRbIteratorRuntime(NodeT** const cursor) noexcept
  {
    if (cursor == nullptr || *cursor == nullptr) {
      return nullptr;
    }

    NodeT* const node = *cursor;
    if (NodeHasSentinelFlag(node, NilOffset)) {
      return node;
    }

    NodeT* right = node->right;
    if (NodeHasSentinelFlag(right, NilOffset)) {
      NodeT* parent = node->parent;
      while (!NodeHasSentinelFlag(parent, NilOffset)) {
        if (*cursor != parent->right) {
          break;
        }
        *cursor = parent;
        parent = parent->parent;
      }

      *cursor = parent;
      return parent;
    }

    while (!NodeHasSentinelFlag(right->left, NilOffset)) {
      right = right->left;
    }
    *cursor = right;
    return right;
  }

  template <typename NodeT, std::size_t NilOffset>
  [[nodiscard]] NodeT* RetreatRbIteratorRuntime(NodeT** const cursor) noexcept
  {
    if (cursor == nullptr || *cursor == nullptr) {
      return nullptr;
    }

    NodeT* const node = *cursor;
    if (NodeHasSentinelFlag(node, NilOffset)) {
      NodeT* const right = node->right;
      *cursor = right;
      return right;
    }

    NodeT* left = node->left;
    if (NodeHasSentinelFlag(left, NilOffset)) {
      NodeT* parent = node->parent;
      while (!NodeHasSentinelFlag(parent, NilOffset)) {
        if (*cursor != parent->left) {
          break;
        }
        *cursor = parent;
        parent = parent->parent;
      }

      if (!NodeHasSentinelFlag(*cursor, NilOffset)) {
        *cursor = parent;
      }
      return parent;
    }

    NodeT* right = left->right;
    while (!NodeHasSentinelFlag(right, NilOffset)) {
      left = right;
      right = right->right;
    }

    *cursor = left;
    return right;
  }

  [[nodiscard]] std::uint32_t SignalingExponentMask(const double value) noexcept
  {
    const std::uint64_t bits = std::bit_cast<std::uint64_t>(value);
    return static_cast<std::uint32_t>((bits >> 32u) & 0x7FF00000u);
  }
}

/**
 * Address: 0x00626E10 (FUN_00626E10)
 *
 * What it does:
 * Appends one 12-byte pickup-info lane into a legacy growth vector,
 * expanding storage when the current capacity is exhausted.
 */
[[maybe_unused]] Element12Runtime* AppendPickupInfoLaneRuntime(
  const Element12Runtime* const value,
  LegacyVectorStorageRuntime<Element12Runtime>* const vector
)
{
  const Element12Runtime copy = value != nullptr ? *value : Element12Runtime{};
  return AppendTrivialValue(vector, copy);
}

/**
 * Address: 0x00642180 (FUN_00642180)
 *
 * What it does:
 * Verifies one key in a lookup cache and refreshes the cached resolved lane
 * when the key is currently present.
 */
[[maybe_unused]] bool TryResolveLookupAndCacheRuntime(
  const std::uint32_t key,
  LookupCacheRuntime* const cache,
  const std::uint32_t argument
)
{
  if (cache == nullptr || cache->containsFn == nullptr) {
    return false;
  }

  if (!cache->containsFn(cache->containsState, key)) {
    return false;
  }

  if (cache->resolveFn != nullptr) {
    cache->cachedValue = cache->resolveFn(cache->context, key, argument);
  }

  return true;
}

/**
 * Address: 0x0067DAA0 (FUN_0067DAA0)
 *
 * What it does:
 * Resizes one 32-bit pointer/id vector to `desiredCount` and zero-fills any
 * newly appended lanes.
 */
[[maybe_unused]] std::uint32_t* ResizePointerVectorRuntime(
  const std::uint32_t desiredCount,
  LegacyVectorStorageRuntime<std::uint32_t>* const vector
)
{
  return ResizeTrivialVectorWithFill(vector, desiredCount, 0u);
}

/**
 * Address: 0x0067CAA0 (FUN_0067CAA0)
 *
 * What it does:
 * Thunk adapter lane that forwards one pointer/id-vector resize dispatch to
 * `ResizePointerVectorRuntime`.
 */
[[maybe_unused]] std::uint32_t* ResizePointerVectorRuntimeThunk(
  const std::uint32_t desiredCount,
  LegacyVectorStorageRuntime<std::uint32_t>* const vector
)
{
  return ResizePointerVectorRuntime(desiredCount, vector);
}

namespace
{
  struct PriorityQueueEntry20Runtime
  {
    std::int32_t priority = 0;           // +0x00
    std::int32_t boundedTick = 0;        // +0x04
    std::uint32_t ownerLinkSlot = 0;     // +0x08
    std::uint32_t nextInOwner = 0;       // +0x0C
    std::uint32_t lane10 = 0;            // +0x10
  };
  static_assert(sizeof(PriorityQueueEntry20Runtime) == 0x14, "PriorityQueueEntry20Runtime size must be 0x14");

  struct PriorityQueueNode24Runtime
  {
    std::uint32_t lane00 = 0;
    std::uint32_t lane04 = 0;
    std::uint32_t lane08 = 0;
    std::uint32_t lane0C = 0;
    std::uint32_t lane10 = 0;
    std::uint8_t lane14 = 0;
    std::uint8_t lane15 = 0;
    std::uint8_t padding16_17[2]{};
  };
  static_assert(sizeof(PriorityQueueNode24Runtime) == 0x18, "PriorityQueueNode24Runtime size must be 0x18");

  struct PriorityQueueEntry12Runtime
  {
    std::uint32_t lane00 = 0;
    float score = 0.0f;
    std::uint32_t lane08 = 0;
  };
  static_assert(sizeof(PriorityQueueEntry12Runtime) == 0x0C, "PriorityQueueEntry12Runtime size must be 0x0C");

  struct Element40Runtime
  {
    std::uint32_t lanes[10]{};
  };
  static_assert(sizeof(Element40Runtime) == 0x28, "Element40Runtime size must be 0x28");

  [[nodiscard]] bool IsLowerPriorityEntry(
    const PriorityQueueEntry20Runtime& lhs,
    const PriorityQueueEntry20Runtime& rhs
  ) noexcept
  {
    if (lhs.priority != rhs.priority) {
      return lhs.priority < rhs.priority;
    }
    return lhs.boundedTick < rhs.boundedTick;
  }

  [[nodiscard]] std::int32_t ParentHeapIndexRuntime(const std::int32_t index) noexcept
  {
    std::int32_t parent = index - 1;
    if (parent < 0) {
      ++parent;
    }
    return parent / 2;
  }

  struct IndexedPriorityQueueRuntimeOwner
  {
    std::uint32_t allocatorCookie;
    PriorityQueueEntry12Runtime* entries;
    std::uint32_t lane08;
    std::uint32_t lane0C;
    std::uint32_t lane10;
    std::int32_t* reverseIndex;
  };
  static_assert(
    offsetof(IndexedPriorityQueueRuntimeOwner, entries) == 0x04,
    "IndexedPriorityQueueRuntimeOwner::entries offset must be 0x04"
  );
  static_assert(
    offsetof(IndexedPriorityQueueRuntimeOwner, reverseIndex) == 0x14,
    "IndexedPriorityQueueRuntimeOwner::reverseIndex offset must be 0x14"
  );

  [[nodiscard]] std::int32_t* SwapPriorityQueueEntriesAndUpdateReverseIndex(
    IndexedPriorityQueueRuntimeOwner* const owner,
    const std::int32_t leftIndex,
    const std::int32_t rightIndex
  ) noexcept
  {
    if (owner == nullptr || owner->entries == nullptr || owner->reverseIndex == nullptr || leftIndex < 0 || rightIndex < 0) {
      return owner != nullptr ? owner->reverseIndex : nullptr;
    }

    PriorityQueueEntry12Runtime& left = owner->entries[leftIndex];
    PriorityQueueEntry12Runtime& right = owner->entries[rightIndex];
    std::swap(left, right);

    owner->reverseIndex[static_cast<std::int32_t>(left.lane08)] = leftIndex;
    owner->reverseIndex[static_cast<std::int32_t>(right.lane08)] = rightIndex;
    return owner->reverseIndex;
  }
}

/**
 * Address: 0x0092C3F0 (FUN_0092C3F0)
 *
 * What it does:
 * Swaps two 12-byte heap-entry lanes and updates the reverse-index map for
 * both moved entry ids.
 */
[[maybe_unused]] std::int32_t* SwapIndexedPriorityQueueEntriesRuntime(
  IndexedPriorityQueueRuntimeOwner* const owner,
  const std::int32_t leftIndex,
  const std::int32_t rightIndex
) noexcept
{
  return SwapPriorityQueueEntriesAndUpdateReverseIndex(owner, leftIndex, rightIndex);
}

/**
 * Address: 0x0092CB10 (FUN_0092CB10)
 *
 * What it does:
 * Performs one max-heap upward insertion for a 16-bit value lane and returns
 * the final parent index lane from the insertion walk.
 */
[[maybe_unused]] std::int32_t PushUInt16HeapEntryUpRuntime(
  std::uint16_t* const heapValues,
  std::int32_t insertionIndex,
  const std::int32_t lowerBoundIndex,
  const std::uint16_t insertedValue
) noexcept
{
  if (heapValues == nullptr || insertionIndex < 0) {
    return insertionIndex > 0 ? (insertionIndex - 1) / 2 : insertionIndex;
  }

  std::int32_t parentIndex = (insertionIndex - 1) / 2;
  if (lowerBoundIndex >= insertionIndex) {
    heapValues[insertionIndex] = insertedValue;
    return parentIndex;
  }

  while (lowerBoundIndex < insertionIndex) {
    const std::uint16_t parentValue = heapValues[parentIndex];
    if (parentValue >= insertedValue) {
      break;
    }

    heapValues[insertionIndex] = parentValue;
    insertionIndex = parentIndex;
    parentIndex = (parentIndex - 1) / 2;
  }

  heapValues[insertionIndex] = insertedValue;
  return parentIndex;
}

/**
 * Address: 0x0067E960 (FUN_0067E960)
 * Address: 0x00767EE0 (FUN_00767EE0)
 *
 * What it does:
 * Moves one pointer-word range left within contiguous storage, then updates
 * vector-end and returns the destination cursor lane.
 */
[[maybe_unused]] std::uint32_t* ShiftPointerWordRangeLeftRuntime(
  LegacyVectorStorageRuntime<std::uint32_t>* const vector,
  std::uint32_t* const outCursor,
  std::uint32_t* const destination,
  const std::uint32_t* const source
)
{
  if (outCursor == nullptr) {
    return nullptr;
  }

  if (vector != nullptr && destination != nullptr && source != nullptr && destination != source && vector->end != nullptr
      && vector->end >= source)
  {
    const std::size_t wordCount = static_cast<std::size_t>(vector->end - source);
    if (wordCount != 0u) {
      std::memmove(destination, source, wordCount * sizeof(std::uint32_t));
    }
    vector->end = destination + wordCount;
  }

  *outCursor = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(destination));
  return outCursor;
}

/**
 * Address: 0x0067F650 (FUN_0067F650)
 *
 * What it does:
 * Copies one pointer-word range into destination storage and returns the
 * advanced destination cursor lane.
 */
[[maybe_unused]] std::uint32_t* CopyPointerWordRangeRuntime(
  const std::uint32_t* const sourceBegin,
  const std::uint32_t* const sourceEnd,
  std::uint32_t* const destinationBegin
)
{
  if (sourceBegin == nullptr || sourceEnd == nullptr || destinationBegin == nullptr || sourceEnd < sourceBegin) {
    return destinationBegin;
  }

  const std::size_t wordCount = static_cast<std::size_t>(sourceEnd - sourceBegin);
  if (wordCount != 0u) {
    std::memmove(destinationBegin, sourceBegin, wordCount * sizeof(std::uint32_t));
  }
  return destinationBegin + wordCount;
}

/**
 * Address: 0x0067FB40 (FUN_0067FB40)
 * Address: 0x00765540 (FUN_00765540)
 * Address: 0x00768E60 (FUN_00768E60)
 *
 * What it does:
 * Copies one pointer-word range into storage ending at `destinationEnd` and
 * returns the begin lane of the copied range.
 */
[[maybe_unused]] std::uint32_t* CopyPointerWordRangeBackwardRuntime(
  const std::uint32_t* const sourceBegin,
  const std::uint32_t* const sourceEnd,
  std::uint32_t* const destinationEnd
)
{
  if (sourceBegin == nullptr || sourceEnd == nullptr || destinationEnd == nullptr || sourceEnd < sourceBegin) {
    return destinationEnd;
  }

  const std::size_t wordCount = static_cast<std::size_t>(sourceEnd - sourceBegin);
  std::uint32_t* const destinationBegin = destinationEnd - wordCount;
  if (wordCount != 0u) {
    std::memmove(destinationBegin, sourceBegin, wordCount * sizeof(std::uint32_t));
  }
  return destinationBegin;
}

/**
 * Address: 0x00680370 (FUN_00680370)
 * Address: 0x00753430 (FUN_00753430)
 *
 * What it does:
 * Resets one pointer vector logical end to begin, preserving capacity.
 */
[[maybe_unused]] void ResetPointerVectorEndToBeginRuntime(
  LegacyVectorStorageRuntime<std::uint32_t>* const vector
)
{
  if (vector != nullptr && vector->begin != vector->end) {
    vector->end = vector->begin;
  }
}

namespace
{
  struct CopyEndCursor8ByteRuntime
  {
    std::uint32_t lane00;
    Element8Runtime* cursor;
  };

  static_assert(sizeof(CopyEndCursor8ByteRuntime) == 0x08, "CopyEndCursor8ByteRuntime size must be 0x08");
}

/**
 * Address: 0x00750E70 (FUN_00750E70)
 *
 * What it does:
 * Copies one contiguous 8-byte element range into `destinationBegin` up to the
 * cursor owner lane, then commits the advanced cursor.
 */
[[maybe_unused]] Element8Runtime* CopyEightByteLaneRangeAndCommitCursorRuntime(
  Element8Runtime* const destinationBegin,
  const Element8Runtime* sourceBegin,
  CopyEndCursor8ByteRuntime* const cursorOwner
)
{
  Element8Runtime* destination = destinationBegin;
  if (destinationBegin != sourceBegin && cursorOwner != nullptr) {
    const Element8Runtime* const sourceEnd = cursorOwner->cursor;
    while (sourceBegin != sourceEnd) {
      *destination = *sourceBegin;
      ++destination;
      ++sourceBegin;
    }
    cursorOwner->cursor = destination;
  }
  return destinationBegin;
}

/**
 * Address: 0x00760850 (FUN_00760850)
 *
 * What it does:
 * Sifts one 8-byte `(lane0,lane1)` heap entry up toward `minIndexExclusive`
 * ordered by the second dword lane.
 */
[[maybe_unused]] std::uint32_t SiftElement8LanePairUpBySecondWordRuntime(
  std::uint32_t heapIndex,
  const std::uint32_t minIndexExclusive,
  Element8Runtime* const entries,
  const std::uint32_t lane0,
  const std::uint32_t lane1
) noexcept
{
  if (entries == nullptr) {
    return lane0;
  }

  while (minIndexExclusive < heapIndex) {
    const std::uint32_t parentIndex = (heapIndex - 1u) >> 1u;
    if (static_cast<std::int32_t>(lane1) >= static_cast<std::int32_t>(entries[parentIndex].lane1)) {
      break;
    }

    entries[heapIndex] = entries[parentIndex];
    heapIndex = parentIndex;
  }

  entries[heapIndex].lane0 = lane0;
  entries[heapIndex].lane1 = lane1;
  return lane0;
}

/**
 * Address: 0x00760720 (FUN_00760720)
 *
 * What it does:
 * Sifts one 8-byte `(lane0,lane1)` heap hole down by signed `lane1` ordering,
 * then reinserts the displaced lane by the companion sift-up helper.
 */
[[maybe_unused]] std::int32_t SiftElement8LanePairDownThenInsertBySecondWordRuntime(
  std::int32_t holeIndex,
  const std::int32_t lastIndex,
  Element8Runtime* const entries,
  const std::int32_t minIndexExclusive,
  const std::uint32_t lane0,
  const std::uint32_t lane1
) noexcept
{
  if (entries == nullptr) {
    return static_cast<std::int32_t>(lane0);
  }

  std::int32_t childIndex = (holeIndex * 2) + 2;
  while (childIndex < lastIndex) {
    if (static_cast<std::int32_t>(entries[childIndex - 1].lane1)
        < static_cast<std::int32_t>(entries[childIndex].lane1)) {
      --childIndex;
    }

    entries[holeIndex] = entries[childIndex];
    holeIndex = childIndex;
    childIndex = (childIndex * 2) + 2;
  }

  if (childIndex == lastIndex) {
    entries[holeIndex] = entries[lastIndex - 1];
    holeIndex = lastIndex - 1;
  }

  return static_cast<std::int32_t>(SiftElement8LanePairUpBySecondWordRuntime(
    static_cast<std::uint32_t>(holeIndex),
    static_cast<std::uint32_t>(minIndexExclusive),
    entries,
    lane0,
    lane1
  ));
}

/**
 * Address: 0x00760290 (FUN_00760290)
 * Address: 0x007605E0 (FUN_007605E0)
 * Address: 0x00734210 (FUN_00734210)
 * Address: 0x00733F50 (FUN_00733F50)
 *
 * What it does:
 * Repeatedly pops the root lane to the range tail and restores heap order over
 * the shrinking prefix until one lane remains.
 */
[[maybe_unused]] std::int32_t HeapSortElement8RangeTailPassRuntime(
  Element8Runtime* const heapBegin,
  Element8Runtime* const heapEnd,
  const std::int32_t minIndexExclusive
) noexcept
{
  if (heapBegin == nullptr || heapEnd == nullptr || heapEnd < heapBegin) {
    return 0;
  }

  std::int32_t spanBytes = static_cast<std::int32_t>(
    reinterpret_cast<const std::byte*>(heapEnd) - reinterpret_cast<const std::byte*>(heapBegin)
  );
  std::int32_t elementCount = spanBytes >> 3;
  while (elementCount > 1) {
    Element8Runtime* const tail = reinterpret_cast<Element8Runtime*>(
      reinterpret_cast<std::byte*>(heapBegin) + spanBytes - sizeof(Element8Runtime)
    );
    const Element8Runtime displaced = *tail;
    *tail = *heapBegin;

    const std::int32_t lastIndex = (spanBytes - static_cast<std::int32_t>(sizeof(Element8Runtime))) >> 3;
    (void)SiftElement8LanePairDownThenInsertBySecondWordRuntime(
      0,
      lastIndex,
      heapBegin,
      minIndexExclusive,
      displaced.lane0,
      displaced.lane1
    );

    spanBytes -= static_cast<std::int32_t>(sizeof(Element8Runtime));
    elementCount = spanBytes >> 3;
  }

  return elementCount;
}

/**
 * Address: 0x007608A0 (FUN_007608A0)
 *
 * What it does:
 * Swaps one heap root with its predecessor tail lane and restores heap order
 * over the remaining prefix.
 */
[[maybe_unused]] std::int32_t PopElement8TailIntoRootAndSiftRuntime(
  Element8Runtime* const heapBegin,
  Element8Runtime* const heapTail,
  const std::int32_t minIndexExclusive
) noexcept
{
  if (heapBegin == nullptr || heapTail == nullptr || heapTail <= heapBegin) {
    return 0;
  }

  Element8Runtime* const predecessor = heapTail - 1;
  const Element8Runtime displaced = *predecessor;
  *predecessor = *heapBegin;

  const std::int32_t lastIndex = static_cast<std::int32_t>(predecessor - heapBegin);
  return SiftElement8LanePairDownThenInsertBySecondWordRuntime(
    0,
    lastIndex,
    heapBegin,
    minIndexExclusive,
    displaced.lane0,
    displaced.lane1
  );
}

/**
 * Address: 0x00771860 (FUN_00771860)
 *
 * What it does:
 * Unlinks one intrusive list node from its ring and resets it to a
 * self-linked sentinel lane.
 */
[[maybe_unused]] IntrusiveListNodeRuntime* UnlinkIntrusiveNodeAndResetSelfLinksRuntime(
  IntrusiveListNodeRuntime* const node
) noexcept
{
  if (node == nullptr || node->next == nullptr || node->prev == nullptr) {
    return node;
  }

  node->next->prev = node->prev;
  node->prev->next = node->next;
  node->prev = node;
  node->next = node;
  return node;
}

namespace
{
  struct Element20Runtime
  {
    std::uint32_t lanes[5];
  };

  static_assert(sizeof(Element20Runtime) == 0x14, "Element20Runtime size must be 0x14");
}

/**
 * Address: 0x007982D0 (FUN_007982D0)
 *
 * What it does:
 * Returns the logical element count for one 20-byte legacy vector lane.
 */
[[maybe_unused]] std::int32_t CountElement20VectorRuntime(
  const LegacyVectorStorageRuntime<Element20Runtime>* const vector
) noexcept
{
  if (vector == nullptr || vector->begin == nullptr) {
    return 0;
  }

  return static_cast<std::int32_t>(vector->end - vector->begin);
}

/**
 * Address: 0x007A5610 (FUN_007A5610)
 *
 * What it does:
 * Rebinds one intrusive owner-slot node to the requested owner head slot.
 */
[[maybe_unused]] IntrusiveOwnerSlotRuntime* RebindIntrusiveOwnerSlotNodeRuntime(
  IntrusiveOwnerSlotRuntime* const node,
  IntrusiveOwnerSlotRuntime*** const requestedOwnerSlotLane
) noexcept
{
  if (node == nullptr || requestedOwnerSlotLane == nullptr) {
    return node;
  }

  IntrusiveOwnerSlotRuntime** const requestedOwnerSlot = *requestedOwnerSlotLane;
  if (requestedOwnerSlot == node->ownerSlot) {
    return node;
  }

  if (node->ownerSlot != nullptr) {
    IntrusiveOwnerSlotRuntime** cursor = node->ownerSlot;
    while (*cursor != node) {
      cursor = &(*cursor)->next;
    }
    *cursor = node->next;
  }

  node->ownerSlot = requestedOwnerSlot;
  if (requestedOwnerSlot == nullptr) {
    node->next = nullptr;
  } else {
    node->next = *requestedOwnerSlot;
    *requestedOwnerSlot = node;
  }
  return node;
}

/**
 * Address: 0x007B35E0 (FUN_007B35E0)
 *
 * What it does:
 * Walks left links until the flag-17 RB sentinel is reached and returns the
 * last non-sentinel node.
 */
[[maybe_unused]] RbNodeFlag17Runtime* DescendLeftUntilFlag17SentinelRuntime(
  RbNodeFlag17Runtime* node
) noexcept
{
  if (node == nullptr) {
    return nullptr;
  }

  RbNodeFlag17Runtime* cursor = node->left;
  if (cursor != nullptr && cursor->isNil17 == 0u) {
    do {
      node = cursor;
      cursor = cursor->left;
    } while (cursor->isNil17 == 0u);
  }
  return node;
}

/**
 * Address: 0x00686740 (FUN_00686740)
 *
 * What it does:
 * Sifts one priority-queue entry up toward the root using
 * `(priority,boundedTick)` ordering and returns the final index.
 */
[[maybe_unused]] std::uint32_t SiftPriorityQueueEntryUpRuntime(
  std::uint32_t index,
  PriorityQueueEntry20Runtime* const entries
)
{
  if (entries == nullptr) {
    return index;
  }

  while (index != 0u) {
    const std::uint32_t parentIndex = (index - 1u) >> 1u;
    PriorityQueueEntry20Runtime& node = entries[index];
    PriorityQueueEntry20Runtime& parent = entries[parentIndex];
    if (IsLowerPriorityEntry(parent, node)) {
      break;
    }

    std::swap(parent, node);
    index = parentIndex;
  }
  return index;
}

/**
 * Address: 0x00686790 (FUN_00686790)
 *
 * What it does:
 * Acquires one handle slot from a free-list lane when available; otherwise
 * appends one new handle lane and returns its index.
 */
[[maybe_unused]] std::int32_t AcquireOrReusePriorityHandleRuntime(
  std::int32_t* const lastHandle,
  LegacyVectorStorageRuntime<std::int32_t>* const handleLanes,
  const std::int32_t payload
)
{
  if (lastHandle == nullptr || handleLanes == nullptr) {
    return -1;
  }

  if (*lastHandle == -1) {
    const std::int32_t index = static_cast<std::int32_t>(VectorSize(*handleLanes));
    (void)AppendTrivialValue(handleLanes, payload);
    return index;
  }

  const std::int32_t reusedIndex = *lastHandle;
  if (handleLanes->begin == nullptr || reusedIndex < 0) {
    return -1;
  }

  *lastHandle = handleLanes->begin[reusedIndex];
  handleLanes->begin[reusedIndex] = payload;
  return reusedIndex;
}

/**
 * Address: 0x006877F0 (FUN_006877F0)
 *
 * What it does:
 * Constructs `count` 20-byte weak-link lanes from one zeroed source lane and
 * returns one-past-the-last written lane.
 */
[[maybe_unused]] moho::PrefixedWeakPtrDwordPayloadLane* ConstructPrefixedWeakPtrDwordLaneRangeFromZeroRuntime(
  const std::uint32_t count,
  moho::PrefixedWeakPtrDwordPayloadLane* const destination
)
{
  if (destination == nullptr) {
    return nullptr;
  }

  moho::PrefixedWeakPtrDwordPayloadLane zeroLane{};
  auto* cursor = destination;
  for (std::uint32_t index = 0u; index < count; ++index) {
    cursor = moho::CopyPrefixedWeakPtrDwordPayloadLane(cursor, &zeroLane);
    ++cursor;
  }
  return cursor;
}

/**
 * Address: 0x00686FE0 (FUN_00686FE0)
 *
 * What it does:
 * Allocates one 24-byte queue-node lane and seeds scalar/key-link fields.
 */
[[maybe_unused]] PriorityQueueNode24Runtime* AllocatePriorityQueueNode24Runtime(
  const std::uint32_t* const keyPairLane,
  const std::uint32_t lane00,
  const std::uint32_t lane04,
  const std::uint32_t lane08
)
{
  auto* const node = static_cast<PriorityQueueNode24Runtime*>(::operator new(sizeof(PriorityQueueNode24Runtime), std::nothrow));
  if (node == nullptr) {
    return nullptr;
  }

  node->lane00 = lane00;
  node->lane04 = lane04;
  node->lane08 = lane08;
  node->lane0C = keyPairLane != nullptr ? keyPairLane[0] : 0u;
  node->lane10 = keyPairLane != nullptr ? keyPairLane[1] : 0u;
  node->lane14 = 0u;
  node->lane15 = 0u;
  return node;
}

/**
 * Address: 0x006875F0 (FUN_006875F0)
 *
 * What it does:
 * Sifts one priority-queue entry down toward leaves using
 * `(priority,boundedTick)` ordering.
 */
[[maybe_unused]] std::uint32_t SiftPriorityQueueEntryDownRuntime(
  std::uint32_t index,
  PriorityQueueEntry20Runtime* const entries,
  const std::uint32_t count
)
{
  if (entries == nullptr) {
    return index;
  }

  std::uint32_t nextChild = 2u * index + 1u;
  while (nextChild < count) {
    std::uint32_t best = index;
    if (IsLowerPriorityEntry(entries[nextChild], entries[best])) {
      best = nextChild;
    }

    const std::uint32_t right = nextChild + 1u;
    if (right < count && IsLowerPriorityEntry(entries[right], entries[best])) {
      best = right;
    }

    if (best == index) {
      break;
    }

    std::swap(entries[index], entries[best]);
    index = best;
    nextChild = 2u * index + 1u;
  }

  return nextChild;
}

/**
 * Address: 0x00687B40 (FUN_00687B40)
 *
 * What it does:
 * Inserts one dword lane at `insertPosition` and writes the rebased cursor
 * lane into `outCursor`.
 */
[[maybe_unused]] std::uint32_t* InsertDwordLaneAndRebaseCursorRuntime(
  LegacyVectorStorageRuntime<std::uint32_t>* const vector,
  std::uint32_t* const outCursor,
  std::uint32_t* const insertPosition,
  const std::uint32_t* const valueLane
)
{
  if (vector == nullptr || outCursor == nullptr) {
    return outCursor;
  }

  std::size_t index = 0u;
  if (vector->begin != nullptr && vector->end != nullptr && vector->end > vector->begin && insertPosition != nullptr) {
    index = static_cast<std::size_t>(insertPosition - vector->begin);
  }

  const std::uint32_t copy = valueLane != nullptr ? *valueLane : 0u;
  (void)InsertTrivialValueAtPosition(vector, insertPosition, copy);
  *outCursor = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(vector->begin + index));
  return outCursor;
}

/**
 * Address: 0x00688E20 (FUN_00688E20)
 *
 * What it does:
 * Fills one contiguous destination lane range with copies of one source
 * prefixed-weak lane.
 */
[[maybe_unused]] moho::PrefixedWeakPtrDwordPayloadLane* FillPrefixedWeakPtrDwordLaneRangeFromSingleLaneRuntime(
  const moho::PrefixedWeakPtrDwordPayloadLane* const sourceLane,
  moho::PrefixedWeakPtrDwordPayloadLane* const destinationBegin,
  moho::PrefixedWeakPtrDwordPayloadLane* const destinationEnd
)
{
  moho::PrefixedWeakPtrDwordPayloadLane* lastWritten = const_cast<moho::PrefixedWeakPtrDwordPayloadLane*>(sourceLane);
  for (auto* destination = destinationBegin; destination != destinationEnd; ++destination) {
    lastWritten = moho::CopyPrefixedWeakPtrDwordPayloadLane(destination, sourceLane);
  }
  return lastWritten;
}

/**
 * Address: 0x00688E50 (FUN_00688E50)
 *
 * What it does:
 * Copies one prefixed-weak lane range backward from `[sourceBegin, sourceEnd)`
 * into storage ending at `destinationEnd`.
 */
[[maybe_unused]] moho::PrefixedWeakPtrDwordPayloadLane* CopyPrefixedWeakPtrDwordLaneRangeBackwardRuntime(
  const moho::PrefixedWeakPtrDwordPayloadLane* sourceEnd,
  moho::PrefixedWeakPtrDwordPayloadLane* destinationEnd,
  const moho::PrefixedWeakPtrDwordPayloadLane* const sourceBegin
)
{
  auto* destination = destinationEnd;
  auto* source = sourceEnd;
  while (source != sourceBegin) {
    --destination;
    --source;
    (void)moho::CopyPrefixedWeakPtrDwordPayloadLane(destination, source);
  }
  return destination;
}

/**
 * Address: 0x00692870 (FUN_00692870)
 *
 * What it does:
 * Inserts one 28-byte lane into a float7 vector and writes the rebased cursor
 * lane to `outCursor`.
 */
[[maybe_unused]] std::uint32_t* InsertFloat7LaneAndRebaseCursorRuntime(
  LegacyVectorStorageRuntime<Float7Runtime>* const vector,
  std::uint32_t* const outCursor,
  Float7Runtime* const insertPosition,
  const Float7Runtime* const value
)
{
  if (outCursor == nullptr || vector == nullptr) {
    return outCursor;
  }

  std::size_t index = 0u;
  if (vector->begin != nullptr && vector->end != nullptr && vector->end > vector->begin && insertPosition != nullptr) {
    index = static_cast<std::size_t>(insertPosition - vector->begin);
  }

  const Float7Runtime copy = value != nullptr ? *value : Float7Runtime{};
  (void)InsertTrivialValueAtPosition(vector, insertPosition, copy);
  *outCursor = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(vector->begin + index));
  return outCursor;
}

/**
 * Address: 0x00693150 (FUN_00693150)
 *
 * What it does:
 * Copies one contiguous float7 lane range backwards and returns the rebased
 * destination begin lane.
 */
[[maybe_unused]] Float7Runtime* CopyFloat7RangeBackwardRuntime(
  Float7Runtime* destinationEnd,
  const Float7Runtime* sourceEnd,
  const Float7Runtime* const sourceBegin
)
{
  while (sourceEnd != sourceBegin) {
    --sourceEnd;
    --destinationEnd;
    *destinationEnd = *sourceEnd;
  }
  return destinationEnd;
}

/**
 * Address: 0x0069ED40 (FUN_0069ED40)
 *
 * What it does:
 * Inserts one 12-byte lane into an element12 vector and writes the rebased
 * cursor lane to `outCursor`.
 */
[[maybe_unused]] std::uint32_t* InsertElement12LaneAndRebaseCursorRuntime(
  LegacyVectorStorageRuntime<Element12Runtime>* const vector,
  std::uint32_t* const outCursor,
  Element12Runtime* const insertPosition,
  const Element12Runtime* const value
)
{
  if (outCursor == nullptr || vector == nullptr) {
    return outCursor;
  }

  std::size_t index = 0u;
  if (vector->begin != nullptr && vector->end != nullptr && vector->end > vector->begin && insertPosition != nullptr) {
    index = static_cast<std::size_t>(insertPosition - vector->begin);
  }

  const Element12Runtime copy = value != nullptr ? *value : Element12Runtime{};
  (void)InsertTrivialValueAtPosition(vector, insertPosition, copy);
  *outCursor = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(vector->begin + index));
  return outCursor;
}

/**
 * Address: 0x0069EDB0 (FUN_0069EDB0)
 *
 * What it does:
 * Constructs `count` 12-byte dword-triple lanes from one zero source lane and
 * returns one-past-the-last written lane.
 */
[[maybe_unused]] Element12Runtime* ConstructElement12LaneRangeFromZeroRuntime(
  const std::uint32_t count,
  Element12Runtime* const destination
)
{
  if (destination == nullptr) {
    return nullptr;
  }

  const Element12Runtime zeroLane{};
  Element12Runtime* cursor = destination;
  for (std::uint32_t index = 0u; index < count; ++index) {
    *cursor = zeroLane;
    ++cursor;
  }
  return cursor;
}

/**
 * Address: 0x006DBAE0 (FUN_006DBAE0)
 *
 * What it does:
 * Inserts one 40-byte lane into an element40 vector and writes the rebased
 * cursor lane to `outCursor`.
 */
[[maybe_unused]] std::uint32_t* InsertElement40LaneAndRebaseCursorRuntime(
  LegacyVectorStorageRuntime<Element40Runtime>* const vector,
  std::uint32_t* const outCursor,
  Element40Runtime* const insertPosition,
  const Element40Runtime* const value
)
{
  if (outCursor == nullptr || vector == nullptr) {
    return outCursor;
  }

  std::size_t index = 0u;
  if (vector->begin != nullptr && vector->end != nullptr && vector->end > vector->begin && insertPosition != nullptr) {
    index = static_cast<std::size_t>(insertPosition - vector->begin);
  }

  const Element40Runtime copy = value != nullptr ? *value : Element40Runtime{};
  (void)InsertTrivialValueAtPosition(vector, insertPosition, copy);
  *outCursor = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(vector->begin + index));
  return outCursor;
}

/**
 * Address: 0x006DBE70 (FUN_006DBE70)
 *
 * What it does:
 * Constructs `count` weak-link+payload lanes from one zero source lane and
 * returns one-past-the-last written lane.
 */
[[maybe_unused]] moho::WeakPtrPayloadLane<std::uint32_t>* ConstructWeakPtrDwordPayloadLaneRangeFromZeroRuntime(
  const std::uint32_t count,
  moho::WeakPtrPayloadLane<std::uint32_t>* const destination
)
{
  if (destination == nullptr) {
    return nullptr;
  }

  moho::WeakPtrPayloadLane<std::uint32_t> zeroLane{};
  auto* cursor = destination;
  for (std::uint32_t index = 0u; index < count; ++index) {
    cursor = moho::CopyWeakPtrDwordPayloadRangeStdOrder(cursor, &zeroLane, &zeroLane + 1);
  }
  return cursor;
}

/**
 * Address: 0x006E2180 (FUN_006E2180)
 *
 * What it does:
 * Releases one legacy contiguous storage lane and resets begin/end/capacity
 * cursors to null.
 */
[[maybe_unused]] void ReleaseLegacyBufferTripleRuntime(
  LegacyBufferTripleRuntime* const owner
)
{
  if (owner == nullptr) {
    return;
  }

  ::operator delete(owner->begin);
  owner->begin = nullptr;
  owner->end = nullptr;
  owner->capacity = nullptr;
}

/**
 * Address: 0x006E23F0 (FUN_006E23F0)
 * Address: 0x005A1450 (FUN_005A1450)
 *
 * What it does:
 * Allocates one 24-byte queue-node lane and seeds scalar/key-link fields.
 */
[[maybe_unused]] PriorityQueueNode24Runtime* AllocatePriorityQueueNode24RuntimeB(
  const std::uint32_t* const keyPairLane,
  const std::uint32_t lane00,
  const std::uint32_t lane04,
  const std::uint32_t lane08
)
{
  return AllocatePriorityQueueNode24Runtime(keyPairLane, lane00, lane04, lane08);
}

/**
 * Address: 0x006E79D0 (FUN_006E79D0)
 *
 * What it does:
 * Builds one begin-iterator lane for an `EntIdSet` payload by caching the
 * backing `BVIntSet` pointer and first live id.
 */
[[maybe_unused]] std::uint32_t* BuildEntIdSetBeginIteratorRuntime(
  moho::BVIntSet* const set,
  std::uint32_t* const outIteratorLanes
)
{
  if (outIteratorLanes == nullptr) {
    return nullptr;
  }

  outIteratorLanes[1] = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(set));
  outIteratorLanes[2] = (set != nullptr) ? set->GetNext(static_cast<unsigned int>(-1)) : 0u;
  return outIteratorLanes;
}

/**
 * Address: 0x006842E0 (FUN_006842E0)
 *
 * What it does:
 * Releases one owned node-buffer lane and resets the owning storage metadata.
 */
[[maybe_unused]] std::int32_t ReleaseEntityDbNodeBufferRuntime(
  OwnedBufferRuntime* const owner
)
{
  return ResetOwnedBufferRuntime(owner);
}

/**
 * Address: 0x00685350 (FUN_00685350)
 *
 * What it does:
 * Finds-or-inserts one entity-db tree node by `EntId` and returns the
 * iterator/insert-status pair lane.
 */
[[maybe_unused]] MapInsertStatusRuntime* FindOrInsertEntityNodeByIdRuntime(
  LegacyMapStorageRuntime<MapNodeNil21Runtime>* const map,
  const std::uint32_t* const key,
  MapInsertStatusRuntime* const outResult
)
{
  return FindOrInsertMapNodeByKey(map, key, outResult);
}

/**
 * Address: 0x006870D0 (FUN_006870D0)
 *
 * What it does:
 * Finds-or-inserts one id-pool map node by key and emits the
 * `(node, inserted)` status pair.
 */
[[maybe_unused]] MapInsertStatusRuntime* FindOrInsertIdPoolNodeByKeyRuntime(
  LegacyMapStorageRuntime<MapNodeNil21Runtime>* const map,
  const std::uint32_t* const key,
  MapInsertStatusRuntime* const outResult
)
{
  return FindOrInsertMapNodeByKey(map, key, outResult);
}

/**
 * Address: 0x00687AF0 (FUN_00687AF0)
 *
 * What it does:
 * Rebuilds one 100-slot IdPool history ring from another ring by replaying
 * each active snapshot lane in order.
 */
[[maybe_unused]] moho::SimSubRes2* CopyIdPoolHistoryRingRuntime(
  moho::SimSubRes2* const destination,
  const moho::SimSubRes2* const source
)
{
  if (destination == nullptr || source == nullptr || destination == source) {
    return destination;
  }

  destination->Reset();
  for (int index = source->mStart; index != source->mEnd; index = (index + 1) % static_cast<int>(kIdPoolHistoryCapacity)) {
    destination->PushSnapshot(AsIdPoolSnapshot(source->mData[index]));
  }
  return destination;
}

/**
 * Address: 0x0069E6D0 (FUN_0069E6D0)
 *
 * What it does:
 * Appends one 12-byte projectile lane into a legacy growth vector with
 * automatic capacity expansion.
 */
[[maybe_unused]] Element12Runtime* AppendProjectileLaneRuntime(
  const Element12Runtime* const value,
  LegacyVectorStorageRuntime<Element12Runtime>* const vector
)
{
  const Element12Runtime copy = value != nullptr ? *value : Element12Runtime{};
  return AppendTrivialValue(vector, copy);
}

/**
 * Address: 0x0069A490 (FUN_0069A490)
 *
 * What it does:
 * Adapter lane that appends one projectile lane into the owner vector stored
 * at offset `+0x9B8`.
 */
[[maybe_unused]] Element12Runtime* AppendProjectileLaneFromOwnerOffsetRuntime(
  std::byte* const ownerBase,
  const Element12Runtime* const value
)
{
  auto* const vector = reinterpret_cast<LegacyVectorStorageRuntime<Element12Runtime>*>(ownerBase + 0x9B8);
  return AppendProjectileLaneRuntime(value, vector);
}

/**
 * Address: 0x006AF120 (FUN_006AF120)
 *
 * What it does:
 * Resizes one recon-blip pointer vector and fills newly exposed lanes with the
 * caller-provided pointer value.
 */
[[maybe_unused]] std::uint32_t ResizeReconBlipPointerVectorRuntime(
  const std::uint32_t desiredCount,
  const std::uint32_t* const fillValue,
  LegacyVectorStorageRuntime<std::uint32_t>* const vector
)
{
  if (vector == nullptr) {
    return 0u;
  }

  const std::uint32_t value = fillValue != nullptr ? *fillValue : 0u;
  (void)ResizeTrivialVectorWithFill(vector, desiredCount, value);
  return static_cast<std::uint32_t>(VectorSize(*vector));
}

/**
 * Address: 0x006D1960 (FUN_006D1960)
 * Address: 0x006C38E0 (FUN_006C38E0)
 *
 * What it does:
 * Appends one 8-byte pair lane into a legacy vector used by upgrade-notify
 * pipelines.
 */
[[maybe_unused]] Element8Runtime* AppendUpgradePairLaneRuntime(
  const Element8Runtime* const value,
  LegacyVectorStorageRuntime<Element8Runtime>* const vector
)
{
  const Element8Runtime copy = value != nullptr ? *value : Element8Runtime{};
  return AppendTrivialValue(vector, copy);
}

/**
 * Address: 0x006DB150 (FUN_006DB150)
 *
 * What it does:
 * Appends one 12-byte command lane into a legacy vector with on-demand growth.
 */
[[maybe_unused]] Element12Runtime* AppendUnitCommandLaneRuntime(
  const Element12Runtime* const value,
  LegacyVectorStorageRuntime<Element12Runtime>* const vector
)
{
  const Element12Runtime copy = value != nullptr ? *value : Element12Runtime{};
  return AppendTrivialValue(vector, copy);
}

/**
 * Address: 0x006E0A40 (FUN_006E0A40)
 *
 * What it does:
 * Releases one CommandDatabase-owned node buffer and clears ownership lanes.
 */
[[maybe_unused]] std::int32_t ReleaseCommandDatabaseNodeBufferRuntime(
  OwnedBufferRuntime* const owner
)
{
  return ResetOwnedBufferRuntime(owner);
}

/**
 * Address: 0x006E15B0 (FUN_006E15B0)
 *
 * What it does:
 * Finds-or-inserts one command-db tree node by command id and writes
 * `(node, inserted)` to the caller-provided status lane.
 */
[[maybe_unused]] MapInsertStatusRuntime* FindOrInsertCommandNodeByIdRuntime(
  LegacyMapStorageRuntime<MapNodeNil21Runtime>* const map,
  const std::uint32_t* const key,
  MapInsertStatusRuntime* const outResult
)
{
  return FindOrInsertMapNodeByKey(map, key, outResult);
}

/**
 * Address: 0x006FD8B0 (FUN_006FD8B0)
 *
 * What it does:
 * Releases one CArmyStats-owned node buffer and clears ownership lanes.
 */
[[maybe_unused]] std::int32_t ReleaseArmyStatsNodeBufferRuntime(
  OwnedBufferRuntime* const owner
)
{
  return ResetOwnedBufferRuntime(owner);
}

/**
 * Address: 0x007108D0 (FUN_007108D0)
 *
 * What it does:
 * Finds-or-inserts one army-stats tree node by key and emits the insertion
 * status pair for callers.
 */
[[maybe_unused]] MapInsertStatusRuntime* FindOrInsertArmyStatsNodeByKeyRuntime(
  LegacyMapStorageRuntime<MapNodeNil21Runtime>* const map,
  const std::uint32_t* const key,
  MapInsertStatusRuntime* const outResult
)
{
  return FindOrInsertMapNodeByKey(map, key, outResult);
}

/**
 * Address: 0x00715440 (FUN_00715440)
 *
 * What it does:
 * Releases one influence-grid entry tree head and clears set ownership lanes.
 */
[[maybe_unused]] std::int32_t ResetInfluenceGridEntryStorageRuntime(
  OwnedBufferRuntime* const owner
)
{
  return ResetOwnedBufferRuntime(owner);
}

/**
 * Address: 0x0071A9A0 (FUN_0071A9A0)
 *
 * What it does:
 * Finds-or-inserts one wide-node influence map entry (sentinel flag lane at
 * +0x3D) and reports insertion status.
 */
[[maybe_unused]] MapInsertStatusRuntime* FindOrInsertInfluenceNodeWideRuntime(
  LegacyMapStorageRuntime<MapNodeNil61Runtime>* const map,
  const std::uint32_t* const key,
  MapInsertStatusRuntime* const outResult
)
{
  return FindOrInsertMapNodeByKey(map, key, outResult);
}

/**
 * Address: 0x0071B360 (FUN_0071B360)
 *
 * What it does:
 * Finds-or-inserts one influence map entry node (sentinel flag lane at +0x15)
 * and returns the iterator/insert-status pair.
 */
[[maybe_unused]] MapInsertStatusRuntime* FindOrInsertInfluenceNodeRuntime(
  LegacyMapStorageRuntime<MapNodeNil21Runtime>* const map,
  const std::uint32_t* const key,
  MapInsertStatusRuntime* const outResult
)
{
  return FindOrInsertMapNodeByKey(map, key, outResult);
}

/**
 * Address: 0x0071C300 (FUN_0071C300)
 *
 * What it does:
 * Allocates one influence-node storage lane and, on success, invokes the
 * caller-provided link/init callback.
 */
[[maybe_unused]] void* AllocateInfluenceNodeAndInitRuntime(
  const std::size_t nodeSize,
  void (*const initFn)(std::int32_t, std::int32_t, std::uint8_t),
  const std::int32_t initArg0,
  const std::int32_t initArg1,
  const std::uint8_t initSide
)
{
  const std::size_t allocationSize = nodeSize == 0u ? 1u : nodeSize;
  void* const node = ::operator new(allocationSize, std::nothrow);
  if (node != nullptr && initFn != nullptr) {
    initFn(initArg0, initArg1, initSide);
  }
  return node;
}

struct DwordTimerLaneRuntime
{
  std::uint32_t lane00 = 0; // +0x00
  std::uint32_t lane04 = 0; // +0x04
  gpg::time::Timer timer{}; // +0x08
};
static_assert(offsetof(DwordTimerLaneRuntime, timer) == 0x08, "DwordTimerLaneRuntime::timer offset must be 0x08");

/**
 * Address: 0x0073B050 (FUN_0073B050)
 *
 * What it does:
 * Writes one input dword to the destination head lane and default-constructs
 * the embedded timer lane at `+0x08`.
 */
[[maybe_unused]] DwordTimerLaneRuntime* InitializeDwordTimerLane(
  DwordTimerLaneRuntime* const destination,
  const std::uint32_t lane00
)
{
  if (destination == nullptr) {
    return nullptr;
  }

  destination->lane00 = lane00;
  new (&destination->timer) gpg::time::Timer();
  return destination;
}

struct DwordAndFastVectorLaneRuntime
{
  std::uint32_t lane00 = 0;      // +0x00
  std::uint32_t lane04 = 0;      // +0x04
  std::uint32_t copiedLane08 = 0; // +0x08
  std::uint32_t lane0C = 0;      // +0x0C
  gpg::fastvector<std::uint32_t> words{}; // +0x10
};
static_assert(
  offsetof(DwordAndFastVectorLaneRuntime, copiedLane08) == 0x08,
  "DwordAndFastVectorLaneRuntime::copiedLane08 offset must be 0x08"
);
static_assert(
  offsetof(DwordAndFastVectorLaneRuntime, words) == 0x10,
  "DwordAndFastVectorLaneRuntime::words offset must be 0x10"
);

/**
 * Address: 0x0073B550 (FUN_0073B550)
 *
 * What it does:
 * Copies the dword lane at `+0x08` and deep-copies the embedded
 * `gpg::fastvector_uint` lane at `+0x10`.
 */
[[maybe_unused]] DwordAndFastVectorLaneRuntime* CopyDwordAndFastVectorLane(
  const DwordAndFastVectorLaneRuntime* const source,
  DwordAndFastVectorLaneRuntime* const destination
)
{
  if (destination == nullptr || source == nullptr) {
    return destination;
  }

  destination->copiedLane08 = source->copiedLane08;
  destination->words.clear();
  destination->words.reserve(source->words.size());
  for (const std::uint32_t word : source->words) {
    destination->words.push_back(word);
  }
  return destination;
}

struct ByteAndStringLaneRuntime
{
  std::uint8_t flag = 0; // +0x00
  std::uint8_t pad01_03[0x03]{};
  msvc8::string text{}; // +0x04
};
static_assert(offsetof(ByteAndStringLaneRuntime, text) == 0x04, "ByteAndStringLaneRuntime::text offset must be 0x04");

/**
 * Address: 0x0073C3E0 (FUN_0073C3E0)
 *
 * What it does:
 * Copies one leading byte lane, then assigns the embedded legacy string lane.
 */
[[maybe_unused]] ByteAndStringLaneRuntime* CopyByteAndStringLane(
  const ByteAndStringLaneRuntime* const source,
  ByteAndStringLaneRuntime* const destination
)
{
  if (destination == nullptr || source == nullptr) {
    return destination;
  }

  destination->flag = source->flag;
  destination->text.assign(source->text, 0u, msvc8::string::npos);
  return destination;
}

/**
 * Address: 0x0073B060 (FUN_0073B060)
 *
 * What it does:
 * Converts elapsed cycles from the embedded timer lane into microseconds and
 * atomically accumulates them into the owner counter at `+0x24`.
 */
[[maybe_unused]] std::int32_t AccumulateTimerElapsedMicrosecondsRuntime(
  TimerAccumulatorRuntime* const runtime
)
{
  if (runtime == nullptr || runtime->counterOwner == 0u) {
    return 0;
  }

  const LONGLONG elapsedCycles = runtime->elapsedTimer.ElapsedCycles();
  const std::int32_t elapsedMicros = static_cast<std::int32_t>(gpg::time::CyclesToMicroseconds(elapsedCycles));
  auto* const ownerBase = reinterpret_cast<std::uint8_t*>(runtime->counterOwner);
  auto* const target = reinterpret_cast<volatile LONG*>(ownerBase + 36u);
  return static_cast<std::int32_t>(::InterlockedExchangeAdd(const_cast<LONG*>(target), elapsedMicros));
}

/**
 * Address: 0x00740AF0 (FUN_00740AF0)
 *
 * What it does:
 * Destroys one vector lane of `SSTIArmyConstantData` entries and releases the
 * backing storage block.
 */
[[maybe_unused]] void DestroyArmyConstantDataVectorRuntime(
  LegacyVectorStorageRuntime<moho::SSTIArmyConstantData>* const vector
)
{
  if (vector == nullptr) {
    return;
  }

  if (vector->begin != nullptr) {
    for (moho::SSTIArmyConstantData* cursor = vector->begin; cursor != vector->end; ++cursor) {
      cursor->~SSTIArmyConstantData();
    }
    ::operator delete(vector->begin);
  }

  vector->begin = nullptr;
  vector->end = nullptr;
  vector->capacity = nullptr;
}

/**
 * Address: 0x00740370 (FUN_00740370)
 *
 * What it does:
 * Tail-forwards one `SSyncData` army-constant vector teardown thunk into the
 * canonical vector-destroy helper body.
 */
[[maybe_unused]] void DestroyArmyConstantDataVectorThunk(
  LegacyVectorStorageRuntime<moho::SSTIArmyConstantData>* const vector
)
{
  DestroyArmyConstantDataVectorRuntime(vector);
}

/**
 * Address: 0x00740B40 (FUN_00740B40)
 *
 * What it does:
 * Destroys one vector lane of `SSTIArmyVariableData` entries and releases the
 * backing storage block.
 */
[[maybe_unused]] void DestroyArmyVariableDataVectorRuntime(
  LegacyVectorStorageRuntime<moho::SSTIArmyVariableData>* const vector
)
{
  if (vector == nullptr) {
    return;
  }

  if (vector->begin != nullptr) {
    for (moho::SSTIArmyVariableData* cursor = vector->begin; cursor != vector->end; ++cursor) {
      cursor->~SSTIArmyVariableData();
    }
    ::operator delete(vector->begin);
  }

  vector->begin = nullptr;
  vector->end = nullptr;
  vector->capacity = nullptr;
}

/**
 * Address: 0x00740380 (FUN_00740380)
 * Address: 0x00607F00 (FUN_00607F00)
 *
 * What it does:
 * Tail-forwards one `SSyncData` army-variable vector teardown thunk into the
 * canonical vector-destroy helper body.
 */
[[maybe_unused]] void DestroyArmyVariableDataVectorThunk(
  LegacyVectorStorageRuntime<moho::SSTIArmyVariableData>* const vector
)
{
  DestroyArmyVariableDataVectorRuntime(vector);
}

/**
 * Address: 0x00740C50 (FUN_00740C50)
 *
 * What it does:
 * Destroys one vector lane of `SSTIUnitVariableData` slot wrappers
 * (`0x8-byte header + payload + tail`) and releases storage.
 */
[[maybe_unused]] void DestroyUnitVariableDataSlotVectorRuntime(
  LegacyVectorStorageRuntime<SSTIUnitVariableDataSlotRuntime>* const vector
)
{
  if (vector == nullptr) {
    return;
  }

  if (vector->begin != nullptr) {
    for (SSTIUnitVariableDataSlotRuntime* cursor = vector->begin; cursor != vector->end; ++cursor) {
      cursor->mVariableData.~SSTIUnitVariableData();
    }
    ::operator delete(vector->begin);
  }

  vector->begin = nullptr;
  vector->end = nullptr;
  vector->capacity = nullptr;
}

/**
 * Address: 0x00740410 (FUN_00740410)
 *
 * What it does:
 * Tail-forwards one `SSyncData` unit-variable slot vector teardown thunk into
 * the canonical vector-destroy helper body.
 */
[[maybe_unused]] void DestroyUnitVariableDataSlotVectorThunk(
  LegacyVectorStorageRuntime<SSTIUnitVariableDataSlotRuntime>* const vector
)
{
  DestroyUnitVariableDataSlotVectorRuntime(vector);
}

/**
 * Address: 0x00740F00 (FUN_00740F00)
 *
 * What it does:
 * Copies one GeomCamera range into destination lanes and destroys any now-extra
 * destination tail entries.
 */
[[maybe_unused]] moho::GeomCamera3** CopyGeomCameraRangeAndPruneTailRuntime(
  CameraCopyContextRuntime* const context,
  moho::GeomCamera3** const outIterator,
  moho::GeomCamera3* const destinationBegin,
  const moho::GeomCamera3* const sourceBegin
)
{
  moho::GeomCamera3* destination = destinationBegin;
  if (context != nullptr && destinationBegin != sourceBegin) {
    moho::GeomCamera3* const previousEnd = context->destinationEnd;
    moho::GeomCamera3* const copiedEnd =
      moho::CopyGeomCameraRangeAndReturnEnd(sourceBegin, destinationBegin, previousEnd);

    if (previousEnd != nullptr) {
      for (moho::GeomCamera3* cursor = copiedEnd; cursor != previousEnd; ++cursor) {
        cursor->~GeomCamera3();
      }
    }

    context->destinationEnd = copiedEnd;
  }

  if (outIterator != nullptr) {
    *outIterator = destination;
  }
  return outIterator;
}

/**
 * Address: 0x00753630 (FUN_00753630)
 *
 * What it does:
 * Rebuilds one opaque pointer lane when requested/current lanes differ, then
 * returns the requested lane through `outValue`.
 */
[[maybe_unused]] std::uint32_t* AssignRebuiltOpaqueLaneRuntimeA(
  OpaqueLaneRebuildRuntime* const context,
  std::uint32_t* const outValue,
  const std::uint32_t requestedLane,
  const std::uint32_t currentLane
)
{
  if (context != nullptr && requestedLane != currentLane) {
    context->storage = RebuildOpaqueLaneStorage(context->storage, static_cast<std::size_t>(requestedLane), false);
  }

  if (outValue != nullptr) {
    *outValue = requestedLane;
  }
  return outValue;
}

/**
 * Address: 0x007536D0 (FUN_007536D0)
 *
 * What it does:
 * Rebuilds one opaque pointer lane with zero-initialized replacement storage
 * when requested/current lanes differ, then writes the requested lane out.
 */
[[maybe_unused]] std::uint32_t* AssignRebuiltOpaqueLaneRuntimeB(
  OpaqueLaneRebuildRuntime* const context,
  std::uint32_t* const outValue,
  const std::uint32_t requestedLane,
  const std::uint32_t currentLane
)
{
  if (context != nullptr && requestedLane != currentLane) {
    context->storage = RebuildOpaqueLaneStorage(context->storage, static_cast<std::size_t>(requestedLane), true);
  }

  if (outValue != nullptr) {
    *outValue = requestedLane;
  }
  return outValue;
}

/**
 * Address: 0x0075F050 (FUN_0075F050)
 *
 * What it does:
 * Appends one 12-byte pose-copy lane into a legacy growth vector.
 */
[[maybe_unused]] Element12Runtime* AppendPoseCopyLaneRuntime(
  const Element12Runtime* const value,
  LegacyVectorStorageRuntime<Element12Runtime>* const vector
)
{
  const Element12Runtime copy = value != nullptr ? *value : Element12Runtime{};
  return AppendTrivialValue(vector, copy);
}

/**
 * Address: 0x00762120 (FUN_00762120)
 *
 * What it does:
 * Resizes one vector of packed seven-float payload lanes (`0x1C` each),
 * filling new lanes from the caller-provided sample value.
 */
[[maybe_unused]] std::uint32_t ResizeFloat7VectorWithFillRuntime(
  const std::uint32_t desiredCount,
  LegacyVectorStorageRuntime<Float7Runtime>* const vector,
  const Float7Runtime* const fillValue
)
{
  if (vector == nullptr) {
    return 0u;
  }

  const Float7Runtime value = fillValue != nullptr ? *fillValue : Float7Runtime{};
  (void)ResizeTrivialVectorWithFill(vector, desiredCount, value);
  return static_cast<std::uint32_t>(VectorSize(*vector));
}

/**
 * Address: 0x00765130 (FUN_00765130)
 *
 * What it does:
 * Resizes one word vector to `desiredCount`, trimming tail lanes when shrinking
 * and filling appended lanes with `fillByte` when growing.
 */
[[maybe_unused]] std::uint32_t* ResizeWordVectorWithFillByteRuntime(
  const std::uint32_t desiredCount,
  LegacyVectorStorageRuntime<std::uint32_t>* const vector,
  const std::uint8_t fillByte
)
{
  const std::uint32_t fillWord = static_cast<std::uint32_t>(fillByte);
  return ResizeTrivialVectorWithFill(vector, desiredCount, fillWord);
}

/**
 * Address: 0x00767D00 (FUN_00767D00)
 *
 * What it does:
 * Compacts one trailing 12-byte-word lane range `[sourceCursor, end)` into
 * `destination` and advances the owner vector end cursor to the compacted tail.
 */
[[maybe_unused]] std::uint32_t** CompactWordVectorTailFromCursorRuntime(
  std::uint32_t** const outBeginStorage,
  CacheWordVectorRuntime* const runtime,
  std::uint32_t* const destination,
  std::uint32_t* sourceCursor
)
{
  if (destination != sourceCursor) {
    std::uint32_t* const sourceEnd = runtime->end;
    std::uint32_t* writeCursor = destination;
    if (sourceCursor != sourceEnd) {
      do {
        writeCursor[0] = sourceCursor[0];
        writeCursor[1] = sourceCursor[1];
        writeCursor[2] = sourceCursor[2];
        sourceCursor += 3;
        writeCursor += 3;
      } while (sourceCursor != sourceEnd);
    }
    runtime->end = writeCursor;
  }

  *outBeginStorage = destination;
  return outBeginStorage;
}

/**
 * Address: 0x007672E0 (FUN_007672E0)
 *
 * What it does:
 * Finalizes one cached word-vector lane, synchronizes staged begin/end cursors,
 * and invalidates the cached index lane.
 */
[[maybe_unused]] std::int32_t FinalizeWordVectorCacheStateRuntime(
  CacheWordVectorRuntime* const runtime
)
{
  std::uint32_t* compactedBegin = nullptr;
  (void)CompactWordVectorTailFromCursorRuntime(&compactedBegin, runtime, runtime->begin, runtime->end);

  if (runtime->stagedBeginIndex != runtime->stagedEndIndex) {
    compactedBegin = nullptr;
    runtime->stagedEndIndex = runtime->stagedBeginIndex;
  }

  runtime->cachedIndex = -1;
  return static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(compactedBegin));
}

/**
 * Address: 0x00530D30 (FUN_00530D30)
 *
 * What it does:
 * Allocates one RB-tree node lane with null links and marks it as the
 * sentinel-style root marker (`+0x2C=1`, `+0x2D=0`).
 */
[[maybe_unused]] RbNodeFlag45Runtime* AllocateRuleTreeNodeRuntime()
{
  auto* const node = AllocateZeroedRuntimeNode<RbNodeFlag45Runtime>();
  if (node == nullptr) {
    return nullptr;
  }

  node->left = nullptr;
  node->parent = nullptr;
  node->right = nullptr;
  node->sentinel44 = 1u;
  node->isNil45 = 0u;
  return node;
}

/**
 * Address: 0x00530FA0 (FUN_00530FA0)
 *
 * What it does:
 * Recursively destroys one RB-tree lane and releases dynamic string storage
 * when capacity is heap-backed (`capacity >= 16`).
 */
[[maybe_unused]] void DestroyRuleTreeNodeRecursiveRuntime(
  RbNodeFlag45Runtime* const node
)
{
  DestroyRecursiveStringTree(node);
}

/**
 * Address: 0x005347A0 (FUN_005347A0)
 *
 * What it does:
 * Appends one 32-bit blueprint-registry word into a legacy vector lane.
 */
[[maybe_unused]] std::uint32_t AppendBlueprintRegistryWordRuntime(
  const std::uint32_t* const value,
  LegacyVectorStorageRuntime<std::uint32_t>* const vector
)
{
  if (value == nullptr || vector == nullptr) {
    return 0u;
  }

  std::uint32_t* const inserted = AppendTrivialValue(vector, *value);
  return inserted != nullptr ? *inserted : *value;
}

/**
 * Address: 0x00545280 (FUN_00545280)
 *
 * What it does:
 * Resets one swap-backed dynamic array lane to its fallback storage block and
 * refreshes cached cursor/first-value lanes.
 */
[[maybe_unused]] std::uint32_t ResetSwapBackedArrayRuntimeA(
  SwapBackedArrayRuntimeA* const runtime
)
{
  if (runtime == nullptr) {
    return 0u;
  }

  if (runtime->activeBuffer == runtime->fallbackBuffer) {
    runtime->cursor = runtime->activeBuffer;
    return runtime->activeBuffer != nullptr ? *runtime->activeBuffer : 0u;
  }

  ::operator delete[](runtime->activeBuffer);
  runtime->activeBuffer = runtime->fallbackBuffer;
  runtime->cachedFirst = runtime->activeBuffer != nullptr ? *runtime->activeBuffer : 0u;
  runtime->cursor = runtime->activeBuffer;
  return runtime->cachedFirst;
}

/**
 * Address: 0x00556DE0 (FUN_00556DE0)
 *
 * What it does:
 * Allocates one category-map node lane with cleared links and sentinel-state
 * flags (`+0x14=1`, `+0x15=0`).
 */
[[maybe_unused]] RbNodeFlag21Runtime* AllocateCategoryMapNodeRuntime()
{
  auto* const node = AllocateZeroedRuntimeNode<RbNodeFlag21Runtime>();
  if (node == nullptr) {
    return nullptr;
  }

  node->left = nullptr;
  node->parent = nullptr;
  node->right = nullptr;
  node->sentinel20 = 1u;
  node->isNil21 = 0u;
  return node;
}

/**
 * Address: 0x0055D940 (FUN_0055D940)
 *
 * What it does:
 * Destroys one contiguous range of `UnitWeaponInfo` entries (`0x98` bytes per
 * lane).
 */
[[maybe_unused]] std::uint8_t* DestroyUnitWeaponInfoRangeRuntime(
  std::uint8_t* const begin,
  const std::uint8_t* const end
)
{
  if (begin == nullptr) {
    return nullptr;
  }

  for (std::uint8_t* cursor = begin; cursor != end; cursor += 152u) {
    reinterpret_cast<moho::UnitWeaponInfo*>(cursor)->~UnitWeaponInfo();
  }
  return begin;
}

/**
 * Address: 0x0056EC00 (FUN_0056EC00)
 *
 * What it does:
 * Copies one RB-map header lane (size/root) and recomputes cached
 * leftmost/rightmost pointers for `isNil` flag offset `+0x41`.
 */
[[maybe_unused]] RbMapFlag65Runtime* CopyMapHeaderAndExtremaFlag65Runtime(
  RbMapFlag65Runtime* const destination,
  const RbMapFlag65Runtime* const source,
  const CloneTree65Fn cloneFn
)
{
  if (destination == nullptr || source == nullptr || destination->head == nullptr || source->head == nullptr) {
    return destination;
  }

  RbNodeFlag65Runtime* sourceRoot = source->head->parent;
  if (cloneFn != nullptr && !NodeHasSentinelFlag(sourceRoot, 0x41u)) {
    sourceRoot = cloneFn(sourceRoot, destination->head);
  }
  destination->head->parent = sourceRoot;
  destination->size = source->size;
  RecomputeHeadExtrema(destination->head, 0x41u);
  return destination;
}

/**
 * Address: 0x00578FE0 (FUN_00578FE0)
 *
 * What it does:
 * Copy-constructs `count` consecutive `LuaObject` lanes from one source
 * object.
 */
[[maybe_unused]] void CopyConstructLuaObjectRangeRuntime(
  std::int32_t count,
  LuaPlus::LuaObject* destination,
  const LuaPlus::LuaObject* const source
)
{
  while (count > 0) {
    if (destination != nullptr && source != nullptr) {
      ::new (destination) LuaPlus::LuaObject(*source);
    }
    --count;
    ++destination;
  }
}

/**
 * Address: 0x005812C0 (FUN_005812C0)
 *
 * What it does:
 * Recursively destroys one linked tree lane and patches both back-reference
 * chains stored in words `+0x14/+0x18` and `+0x1C/+0x20`.
 */
[[maybe_unused]] void DestroyLinkedTreeNodeRecursiveRuntime(
  LinkedTreeNode37Runtime* node
)
{
  LinkedTreeNode37Runtime* previous = node;
  LinkedTreeNode37Runtime* cursor = node;
  while (cursor != nullptr && !NodeHasSentinelFlag(cursor, 0x25u)) {
    DestroyLinkedTreeNodeRecursiveRuntime(cursor->right);
    cursor = cursor->left;

    PatchBackReferenceChain(previous->lane1C, &previous->lane1C, previous->lane20);
    PatchBackReferenceChain(previous->lane14, &previous->lane14, previous->lane18);
    ::operator delete(previous);
    previous = cursor;
  }
}

/**
 * Address: 0x005CC2D0 (FUN_005CC2D0)
 * Address: 0x005CA240 (FUN_005CA240)
 *
 * What it does:
 * Initializes `count` contiguous lanes with stride `0x34` using one
 * caller-supplied construction callback.
 */
[[maybe_unused]] std::int32_t ConstructStride52RangeRuntime(
  std::int32_t count,
  std::byte* destination,
  const void* const sourceContext,
  const LaneConstructFn52 constructFn
)
{
  std::int32_t constructed = 0;
  while (count > 0) {
    if (destination != nullptr && constructFn != nullptr) {
      constructFn(destination, sourceContext);
      ++constructed;
    }
    destination += 52;
    --count;
  }
  return constructed;
}

/**
 * Address: 0x005D02F0 (FUN_005D02F0)
 *
 * What it does:
 * Allocates one 3-word node and writes `{a1, a2, *a3}` payload lanes.
 */
[[maybe_unused]] TripleIntNodeRuntime* AllocateTripleIntNodeRuntime(
  const std::int32_t lane0,
  const std::int32_t lane4,
  const std::int32_t* const lane8Source
)
{
  auto* const node = AllocateZeroedRuntimeNode<TripleIntNodeRuntime>();
  if (node == nullptr) {
    return nullptr;
  }

  node->lane0 = lane0;
  node->lane4 = lane4;
  node->lane8 = lane8Source != nullptr ? *lane8Source : 0;
  return node;
}

/**
 * Address: 0x006874E0 (FUN_006874E0)
 *
 * What it does:
 * Clears one linearized tree list lane by unlinking head sentinels and
 * deleting each chained node.
 */
[[maybe_unused]] LinearTreeNodeRuntime* ClearLinearTreeStorageRuntime(
  LinearTreeStorageRuntime* const storage
)
{
  if (storage == nullptr || storage->head == nullptr) {
    if (storage != nullptr) {
      storage->size = 0u;
    }
    return nullptr;
  }

  LinearTreeNodeRuntime* const head = storage->head;
  LinearTreeNodeRuntime* cursor = head->next;
  head->next = head;
  head->prev = head;
  storage->size = 0u;

  while (cursor != nullptr && cursor != head) {
    LinearTreeNodeRuntime* const next = cursor->next;
    ::operator delete(cursor);
    cursor = next;
  }

  return cursor;
}

/**
 * Address: 0x00687BC0 (FUN_00687BC0)
 *
 * What it does:
 * Allocates one IdPool-map node lane with cleared links and sentinel-state
 * flags (`+0x14=1`, `+0x15=0`).
 */
[[maybe_unused]] RbNodeFlag21Runtime* AllocateIdPoolMapNodeRuntime()
{
  auto* const node = AllocateZeroedRuntimeNode<RbNodeFlag21Runtime>();
  if (node == nullptr) {
    return nullptr;
  }

  node->left = nullptr;
  node->parent = nullptr;
  node->right = nullptr;
  node->sentinel20 = 1u;
  node->isNil21 = 0u;
  return node;
}

/**
 * Address: 0x00688180 (FUN_00688180)
 *
 * What it does:
 * Allocates one `map<uint, IdPool>` node lane with cleared links and
 * sentinel-state flags (`+0x14=1`, `+0x15=0`).
 */
[[maybe_unused]] RbNodeFlag21Runtime* AllocateUintIdPoolMapNodeRuntime()
{
  auto* const node = AllocateZeroedRuntimeNode<RbNodeFlag21Runtime>();
  if (node == nullptr) {
    return nullptr;
  }

  node->left = nullptr;
  node->parent = nullptr;
  node->right = nullptr;
  node->sentinel20 = 1u;
  node->isNil21 = 0u;
  return node;
}

/**
 * Address: 0x006AFBF0 (FUN_006AFBF0)
 *
 * What it does:
 * Returns lower-bound candidate node for one key in a string->float RB-tree.
 */
[[maybe_unused]] StringFloatMapNodeRuntime* LowerBoundStringFloatMapRuntime(
  StringFloatMapRuntime* const map,
  const std::string* const key
)
{
  if (map == nullptr || map->head == nullptr) {
    return nullptr;
  }

  const std::string emptyKey;
  const std::string& lookupKey = key != nullptr ? *key : emptyKey;

  StringFloatMapNodeRuntime* candidate = map->head;
  StringFloatMapNodeRuntime* cursor = map->head->parent;
  while (cursor != nullptr && cursor->isNil == 0u) {
    const int compare = cursor->key.compare(lookupKey);
    if (compare >= 0) {
      candidate = cursor;
      cursor = cursor->left;
    } else {
      cursor = cursor->right;
    }
  }
  return candidate;
}

/**
 * Address: 0x006DF040 (FUN_006DF040)
 *
 * What it does:
 * Resets one swap-backed dynamic array lane (`+0x10` storage block) to fallback
 * storage and refreshes cached lanes.
 */
[[maybe_unused]] std::uint32_t ResetSwapBackedArrayRuntimeB(
  SwapBackedArrayRuntimeB* const runtime
)
{
  if (runtime == nullptr) {
    return 0u;
  }

  if (runtime->activeBuffer == runtime->fallbackBuffer) {
    runtime->cursor = runtime->activeBuffer;
    return runtime->activeBuffer != nullptr ? *runtime->activeBuffer : 0u;
  }

  ::operator delete[](runtime->activeBuffer);
  runtime->activeBuffer = runtime->fallbackBuffer;
  runtime->cachedFirst = runtime->activeBuffer != nullptr ? *runtime->activeBuffer : 0u;
  runtime->cursor = runtime->activeBuffer;
  return runtime->cachedFirst;
}

/**
 * Address: 0x006E2840 (FUN_006E2840)
 *
 * What it does:
 * Allocates one command-db map node lane with cleared links and sentinel-state
 * flags (`+0x14=1`, `+0x15=0`).
 */
[[maybe_unused]] RbNodeFlag21Runtime* AllocateCommandDbMapNodeRuntime()
{
  auto* const node = AllocateZeroedRuntimeNode<RbNodeFlag21Runtime>();
  if (node == nullptr) {
    return nullptr;
  }

  node->left = nullptr;
  node->parent = nullptr;
  node->right = nullptr;
  node->sentinel20 = 1u;
  node->isNil21 = 0u;
  return node;
}

/**
 * Address: 0x00703A10 (FUN_00703A10)
 *
 * What it does:
 * Allocates one RB-tree node lane with null links and marks it as
 * sentinel-root style (`+0x2C=1`, `+0x2D=0`).
 */
[[maybe_unused]] RbNodeFlag45Runtime* AllocateArmyStatsTreeNodeRuntime()
{
  auto* const node = AllocateZeroedRuntimeNode<RbNodeFlag45Runtime>();
  if (node == nullptr) {
    return nullptr;
  }

  node->left = nullptr;
  node->parent = nullptr;
  node->right = nullptr;
  node->sentinel44 = 1u;
  node->isNil45 = 0u;
  return node;
}

/**
 * Address: 0x00703C30 (FUN_00703C30)
 *
 * What it does:
 * Recursively destroys one RB-tree lane and releases dynamic string storage
 * when capacity is heap-backed (`capacity >= 16`).
 */
[[maybe_unused]] void DestroyArmyStatsTreeNodeRecursiveRuntime(
  RbNodeFlag45Runtime* const node
)
{
  DestroyRecursiveStringTree(node);
}

/**
 * Address: 0x00705B30 (FUN_00705B30)
 *
 * What it does:
 * Resets one linked owner lane to fallback array storage and unlinks the node
 * from its intrusive next/prev chain.
 */
[[maybe_unused]] LinkedBufferOwnerRuntime* ResetLinkedBufferOwnerRuntime(
  LinkedBufferOwnerRuntime* const owner
)
{
  if (owner == nullptr) {
    return nullptr;
  }

  if (owner->activeBuffer != owner->fallbackBuffer) {
    ::operator delete[](owner->activeBuffer);
    owner->activeBuffer = owner->fallbackBuffer;
    owner->cachedFirst = owner->activeBuffer != nullptr ? *owner->activeBuffer : 0u;
  }
  owner->cursor = owner->activeBuffer;

  LinkedBufferOwnerRuntime* const previous = owner->prev;
  LinkedBufferOwnerRuntime* const next = owner->next;
  if (next != nullptr) {
    next->prev = previous;
  }
  if (previous != nullptr) {
    previous->next = next;
  }

  owner->prev = owner;
  owner->next = owner;
  return previous;
}

/**
 * Address: 0x0070F810 (FUN_0070F810)
 *
 * What it does:
 * Copies one RB-map header lane (size/root) and recomputes cached
 * leftmost/rightmost pointers for `isNil` flag offset `+0x15`.
 */
[[maybe_unused]] RbMapFlag21Runtime* CopyMapHeaderAndExtremaFlag21Runtime(
  RbMapFlag21Runtime* const destination,
  const RbMapFlag21Runtime* const source,
  const CloneTree21Fn cloneFn
)
{
  if (destination == nullptr || source == nullptr || destination->head == nullptr || source->head == nullptr) {
    return destination;
  }

  RbNodeFlag21Runtime* sourceRoot = source->head->parent;
  if (cloneFn != nullptr && !NodeHasSentinelFlag(sourceRoot, 0x15u)) {
    sourceRoot = cloneFn(sourceRoot, destination->head);
  }
  destination->head->parent = sourceRoot;
  destination->size = source->size;
  RecomputeHeadExtrema(destination->head, 0x15u);
  return destination;
}

/**
 * Address: 0x00711EE0 (FUN_00711EE0)
 *
 * What it does:
 * Allocates one compact RB-tree node lane with null links and sentinel-state
 * flags (`+0x10=1`, `+0x11=0`).
 */
[[maybe_unused]] RbNodeFlag17Runtime* AllocateCompactTreeNodeRuntime()
{
  auto* const node = AllocateZeroedRuntimeNode<RbNodeFlag17Runtime>();
  if (node == nullptr) {
    return nullptr;
  }

  node->left = nullptr;
  node->parent = nullptr;
  node->right = nullptr;
  node->sentinel16 = 1u;
  node->isNil17 = 0u;
  return node;
}

/**
 * Address: 0x00720010 (FUN_00720010)
 *
 * What it does:
 * Performs one sift-down step on a 4-float heap lane and then invokes the
 * caller-provided finalize callback.
 */
[[maybe_unused]] std::int32_t SiftDownFloat4HeapAndFinalizeRuntime(
  std::int32_t heapIndex,
  const std::int32_t heapLast,
  Float4Runtime* const heapBase,
  const std::int32_t arg4,
  const std::int32_t arg5,
  const std::int32_t arg6,
  const std::int32_t arg7,
  const Float4FinalizeFn finalizeFn
)
{
  if (heapBase == nullptr) {
    return finalizeFn != nullptr ? finalizeFn(heapBase, arg4, arg5, arg6, arg7) : 0;
  }

  std::int32_t child = (heapIndex * 2) + 2;
  while (child < heapLast) {
    if (heapBase[child].lanes[3] > heapBase[child - 1].lanes[3]) {
      --child;
    }

    heapBase[heapIndex] = heapBase[child];
    heapIndex = child;
    child = (child * 2) + 2;
  }

  if (child == heapLast) {
    heapBase[heapIndex] = heapBase[heapLast - 1];
  }

  return finalizeFn != nullptr ? finalizeFn(heapBase, arg4, arg5, arg6, arg7) : 0;
}

/**
 * Address: 0x00739E50 (FUN_00739E50)
 *
 * What it does:
 * Allocates one doubly-linked sentinel lane and self-links both first words.
 */
[[maybe_unused]] LinearTreeNodeRuntime* AllocateSelfLinkedPairNodeRuntime()
{
  auto* const node = AllocateZeroedRuntimeNode<LinearTreeNodeRuntime>();
  if (node == nullptr) {
    return nullptr;
  }

  node->next = node;
  node->prev = node;
  return node;
}

/**
 * Address: 0x00739B50 (FUN_00739B50)
 *
 * What it does:
 * Initializes one linear-tree storage lane by allocating its self-linked head
 * sentinel and resetting the tracked element count to zero.
 */
[[maybe_unused]] [[nodiscard]] LinearTreeStorageRuntime* InitializeLinearTreeStorageHeadAndSize(
  LinearTreeStorageRuntime* const storage
)
{
  storage->head = AllocateSelfLinkedPairNodeRuntime();
  storage->size = 0u;
  return storage;
}

/**
 * Address: 0x007407F0 (FUN_007407F0)
 *
 * What it does:
 * Forwards one owner range `[begin, begin + size)` into the supplied range
 * erase callback.
 */
[[maybe_unused]] std::int32_t EraseOwnerRangeRuntime(
  RangeOwnerByteRuntime* const owner,
  const RangeEraseRuntimeFn eraseFn
)
{
  if (owner == nullptr || eraseFn == nullptr) {
    return 0;
  }

  std::byte* const begin = owner->rangeBegin;
  return eraseFn(owner, begin, owner, begin + owner->rangeByteSize);
}

/**
 * Address: 0x00740860 (FUN_00740860)
 *
 * What it does:
 * Pure forwarding thunk to one owner cleanup callback.
 */
[[maybe_unused]] void ForwardOwnerCleanupThunkRuntime(
  void* const owner,
  const ForwardCleanupFn cleanupFn
)
{
  if (cleanupFn != nullptr) {
    cleanupFn(owner);
  }
}

/**
 * Address: 0x00767C70 (FUN_00767C70)
 *
 * What it does:
 * Collapses one tagged-insert cursor (`end = begin` when non-empty) and emits
 * one tagged insert call with key `9`.
 */
[[maybe_unused]] std::int32_t ResetCursorAndInsertTaggedWordRuntime(
  const std::uint32_t* const value,
  TaggedInsertCursorRuntime* const cursor,
  const TaggedInsertRuntimeFn insertFn
)
{
  if (value == nullptr || cursor == nullptr) {
    return 0;
  }

  std::uint32_t localValue = *value;
  if (cursor->begin != cursor->end) {
    cursor->end = cursor->begin;
  }

  if (insertFn != nullptr) {
    return insertFn(cursor->begin, 9u, &localValue);
  }

  if (cursor->begin != nullptr) {
    *cursor->begin = localValue;
    return static_cast<std::int32_t>(localValue);
  }
  return 0;
}

/**
 * Address: 0x0076A2E0 (FUN_0076A2E0)
 *
 * What it does:
 * Allocates one payload node lane and copies two integer lanes plus seven
 * float lanes from source.
 */
[[maybe_unused]] FloatPayloadNodeRuntime* AllocateFloatPayloadNodeRuntime(
  const float* const sourceFloats,
  const std::int32_t lane0,
  const std::int32_t lane4
)
{
  auto* const node = AllocateZeroedRuntimeNode<FloatPayloadNodeRuntime>();
  if (node == nullptr) {
    return nullptr;
  }

  node->lane0 = lane0;
  node->lane4 = lane4;
  if (sourceFloats != nullptr) {
    for (std::size_t index = 0; index < 7u; ++index) {
      node->lanes[index] = sourceFloats[index];
    }
  }
  return node;
}

/**
 * Address: 0x0077CAA0 (FUN_0077CAA0)
 *
 * What it does:
 * Allocates one decal-buffer tree node lane with null links and sentinel-state
 * flags (`+0x1C=1`, `+0x1D=0`).
 */
[[maybe_unused]] RbNodeFlag29Runtime* AllocateDecalBufferTreeNodeRuntime()
{
  auto* const node = AllocateZeroedRuntimeNode<RbNodeFlag29Runtime>();
  if (node == nullptr) {
    return nullptr;
  }

  node->left = nullptr;
  node->parent = nullptr;
  node->right = nullptr;
  node->sentinel28 = 1u;
  node->isNil29 = 0u;
  return node;
}

/**
 * Address: 0x0077BE50 (FUN_0077BE50)
 *
 * What it does:
 * Initializes one `RbNodeFlag29Runtime` tree-storage lane by allocating a head
 * sentinel node, wiring self-links, and clearing the element count.
 */
[[maybe_unused]] RbNodeFlag29Runtime* InitializeDecalBufferTreeStorageHeadRuntime(
  LegacyMapStorageRuntime<RbNodeFlag29Runtime>* const storage
)
{
  RbNodeFlag29Runtime* const head = AllocateDecalBufferTreeNodeRuntime();
  storage->head = head;
  head->isNil29 = 1u;
  head->parent = head;
  head->left = head;
  head->right = head;
  storage->size = 0u;
  return head;
}

/**
 * Address: 0x0077A220 (FUN_0077A220)
 *
 * What it does:
 * Initializes one decal-buffer tree-storage lane by allocating a sentinel
 * head node, wiring self-links, clearing count, and returning the storage.
 */
[[maybe_unused]] LegacyMapStorageRuntime<RbNodeFlag29Runtime>* InitializeDecalBufferTreeStorageAndReturnStorageA(
  LegacyMapStorageRuntime<RbNodeFlag29Runtime>* const storage
)
{
  RbNodeFlag29Runtime* const head = AllocateDecalBufferTreeNodeRuntime();
  storage->head = head;
  head->isNil29 = 1u;
  head->parent = head;
  head->left = head;
  head->right = head;
  storage->size = 0u;
  return storage;
}

/**
 * Address: 0x0077AEF0 (FUN_0077AEF0)
 *
 * What it does:
 * Sibling alias for the same decal-buffer tree-storage sentinel wiring lane;
 * returns the input storage pointer.
 */
[[maybe_unused]] LegacyMapStorageRuntime<RbNodeFlag29Runtime>* InitializeDecalBufferTreeStorageAndReturnStorageB(
  LegacyMapStorageRuntime<RbNodeFlag29Runtime>* const storage
)
{
  RbNodeFlag29Runtime* const head = AllocateDecalBufferTreeNodeRuntime();
  storage->head = head;
  head->isNil29 = 1u;
  head->parent = head;
  head->left = head;
  head->right = head;
  storage->size = 0u;
  return storage;
}

/**
 * Address: 0x0077CC20 (FUN_0077CC20)
 *
 * What it does:
 * Recursively destroys one compact RB-tree lane where `isNil` lives at
 * offset `+0x11`.
 */
[[maybe_unused]] void DestroyCompactTreeNodeRecursiveRuntime(
  RbNodeFlag17Runtime* node
)
{
  RbNodeFlag17Runtime* previous = node;
  RbNodeFlag17Runtime* cursor = node;
  while (cursor != nullptr && cursor->isNil17 == 0u) {
    DestroyCompactTreeNodeRecursiveRuntime(cursor->right);
    cursor = cursor->left;
    ::operator delete(previous);
    previous = cursor;
  }
}

/**
 * Address: 0x0077C520 (FUN_0077C520)
 *
 * What it does:
 * Destroys every compact-tree child node reachable from the current head
 * parent lane, then rewires the storage back to an empty sentinel state.
 */
[[maybe_unused]] RbNodeFlag17Runtime* ResetCompactTreeStorageHeadRuntime(
  LegacyMapStorageRuntime<RbNodeFlag17Runtime>* const storage
)
{
  DestroyCompactTreeNodeRecursiveRuntime(storage->head->parent);
  storage->head->parent = storage->head;
  storage->size = 0u;
  storage->head->left = storage->head;
  storage->head->right = storage->head;
  return storage->head;
}

/**
 * Address: 0x00A9A4B1 (FUN_00A9A4B1)
 *
 * What it does:
 * Maps math-domain/range classification codes into `errno` (`EDOM`/`ERANGE`)
 * and returns the original pointer lane.
 */
[[maybe_unused]] int* MapErrnoForMathInputRuntime(
  const int classificationCode
)
{
  int* const result = reinterpret_cast<int*>(static_cast<std::uintptr_t>(classificationCode));
  if (classificationCode == 1) {
    *_errno() = EDOM;
  } else if (classificationCode > 1 && classificationCode <= 3) {
    *_errno() = ERANGE;
  }
  return result;
}

/**
 * Address: 0x006F8F10 (FUN_006F8F10)
 *
 * What it does:
 * Iterates one pointer-word range and adds each resolved `Unit*` lane into one
 * unit-set container.
 */
[[maybe_unused]] void AddUnitRangeFromPointerWordsRuntime(
  moho::SEntitySetTemplateUnit* const unitSet,
  const std::uint32_t* pointerBegin,
  const std::uint32_t* const pointerEnd
)
{
  if (unitSet == nullptr) {
    return;
  }

  while (pointerBegin != pointerEnd) {
    moho::Unit* unit = nullptr;
    if (*pointerBegin != 0u) {
      unit = reinterpret_cast<moho::Unit*>(static_cast<std::uintptr_t>(*pointerBegin) - 8u);
    }
    (void)unitSet->AddUnit(unit);
    ++pointerBegin;
  }
}

/**
 * Address: 0x00686E80 (FUN_00686E80)
 *
 * What it does:
 * Appends one integer lane into a legacy vector payload.
 */
[[maybe_unused]] std::int32_t* AppendLegacyIntVectorLaneRuntime(
  LegacyVectorStorageRuntime<std::int32_t>* const vector,
  const std::int32_t* const value
)
{
  if (vector == nullptr || value == nullptr) {
    return nullptr;
  }

  std::int32_t* const inserted = AppendTrivialValue(vector, *value);
  return inserted != nullptr ? inserted + 1 : vector->end;
}

/**
 * Address: 0x00982080 (FUN_00982080)
 * Address: 0x00982E90 (FUN_00982E90)
 *
 * What it does:
 * Resolves one owner-backed string-array index, advances by one lane, and
 * returns the mapped value when in range.
 */
[[maybe_unused]] std::uint32_t* ResolveWxOwnerArrayValueRuntime(
  std::uint32_t* const outValue,
  const std::uint32_t* const objectHandleWord
)
{
  if (outValue == nullptr) {
    return nullptr;
  }

  *outValue = 0u;
  if (objectHandleWord == nullptr || *objectHandleWord == 0u) {
    return outValue;
  }

  const std::uintptr_t objectAddress = static_cast<std::uintptr_t>(*objectHandleWord);
  const auto* const owner = *reinterpret_cast<WxLookupOwnerRuntime* const*>(objectAddress + 36u);
  if (owner == nullptr || owner->arrayLane == nullptr) {
    return outValue;
  }

  const auto* const array = owner->arrayLane;
  const wchar_t* const lookupValue = reinterpret_cast<const wchar_t*>(objectAddress);
  std::size_t index = static_cast<std::size_t>(array->count);
  for (std::size_t i = 0; i < static_cast<std::size_t>(array->count); ++i) {
    const wchar_t* const entry = array->entries != nullptr ? array->entries[i] : nullptr;
    if ((entry == lookupValue) || (entry != nullptr && lookupValue != nullptr && std::wcscmp(entry, lookupValue) == 0)) {
      index = i;
      break;
    }
  }

  const std::size_t mappedIndex = index + 1u;
  if (mappedIndex >= static_cast<std::size_t>(array->count) || array->entries == nullptr) {
    *outValue = 0u;
    return outValue;
  }

  *outValue = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(array->entries[mappedIndex]));
  return outValue;
}

/**
 * Address: 0x0056E7E0 (FUN_0056E7E0)
 *
 * What it does:
 * Normalizes one contiguous formation lane range by restoring each record to
 * fallback storage and updating cached cursors.
 */
[[maybe_unused]] std::uint32_t* NormalizeFormationLaneRangeRuntime(
  std::uint32_t* laneBegin,
  std::uint32_t* const laneEnd
)
{
  std::uint32_t* lastResult = laneBegin;
  while (laneBegin != laneEnd) {
    const std::uint32_t activeWord = laneBegin[12];
    const std::uint32_t fallbackWord = laneBegin[15];
    if (activeWord != fallbackWord) {
      ::operator delete[](reinterpret_cast<void*>(static_cast<std::uintptr_t>(activeWord)));
      laneBegin[12] = fallbackWord;
      const auto* const fallback = reinterpret_cast<const std::uint32_t*>(static_cast<std::uintptr_t>(fallbackWord));
      laneBegin[14] = fallback != nullptr ? *fallback : 0u;
      lastResult = reinterpret_cast<std::uint32_t*>(laneBegin[14]);
    }

    laneBegin[13] = laneBegin[12];
    laneBegin += 18;
  }
  return lastResult;
}

/**
 * Address: 0x009600E0 (FUN_009600E0)
 *
 * What it does:
 * Parses one full wide-string double lane and reports strict-consume success.
 */
[[maybe_unused]] bool ParseWideDoubleStrictRuntime(
  const wchar_t** const sourceText,
  double* const outValue
)
{
  if (sourceText == nullptr || outValue == nullptr || *sourceText == nullptr) {
    return false;
  }

  const wchar_t* const begin = *sourceText;
  wchar_t* end = nullptr;
  *outValue = std::wcstod(begin, &end);
  return end != begin && end != nullptr && *end == L'\0';
}

/**
 * Address: 0x00960040 (FUN_00960040)
 *
 * What it does:
 * Parses one full wide-string integer lane using the supplied radix and
 * reports strict-consume success.
 */
[[maybe_unused]] bool ParseWideLongStrictRuntime(
  const wchar_t** const sourceText,
  std::uint32_t* const outValue,
  const std::uint32_t radix
)
{
  if (sourceText == nullptr || outValue == nullptr || *sourceText == nullptr) {
    return false;
  }

  const wchar_t* const begin = *sourceText;
  wchar_t* end = nullptr;
  *outValue = static_cast<std::uint32_t>(std::wcstol(begin, &end, static_cast<int>(radix)));
  return end != begin && end != nullptr && *end == L'\0';
}

/**
 * Address: 0x007AE180 (FUN_007AE180)
 *
 * What it does:
 * Initializes one command-mode RB-tree storage head and resets size lanes.
 */
[[maybe_unused]] std::uint32_t InitializeCommandModeTreeRuntime(
  std::uint8_t* const ownerBytes,
  RbNodeFlag25Runtime* (*const allocateNodeFn)()
)
{
  if (ownerBytes == nullptr || allocateNodeFn == nullptr) {
    return 0u;
  }

  RbNodeFlag25Runtime* const head = allocateNodeFn();
  if (head == nullptr) {
    return 0u;
  }

  *reinterpret_cast<RbNodeFlag25Runtime**>(ownerBytes + 4u) = head;
  head->isNil25 = 1u;
  head->parent = head;
  head->left = head;
  head->right = head;
  *reinterpret_cast<std::uint32_t*>(ownerBytes + 8u) = 0u;
  return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(ownerBytes));
}

/**
 * Address: 0x009A0A10 (FUN_009A0A10)
 *
 * What it does:
 * Resolves one runtime object from context and dispatches virtual slot `+0x20`
 * when available.
 */
[[maybe_unused]] int DispatchResolvedObjectSlot32Runtime(
  const int context,
  const int dispatchArg,
  void* (*const resolveFn)(int, int)
)
{
  if (resolveFn == nullptr) {
    return 0;
  }

  void* const object = resolveFn(context, 0);
  if (object == nullptr) {
    return 0;
  }

  using DispatchFn = int (__thiscall*)(void*, int);
  auto* const vtable = *reinterpret_cast<void***>(object);
  const auto dispatch = reinterpret_cast<DispatchFn>(vtable[8]);
  return dispatch != nullptr ? dispatch(object, dispatchArg) : 0;
}

/**
 * Address: 0x009D3710 (FUN_009D3710)
 *
 * What it does:
 * Window-proc hook lane that forwards selected messages through one object
 * dispatcher before chaining to the previous window procedure.
 */
[[maybe_unused]] LRESULT CALLBACK DispatchWindowMessageHookRuntime(
  HWND window,
  UINT message,
  WPARAM wParam,
  LPARAM lParam
)
{
  auto* const runtime = reinterpret_cast<DispatchWindowRuntime*>(::GetWindowLongW(window, GWL_USERDATA));
  if (runtime == nullptr) {
    return 0;
  }

  switch (message) {
  case WM_SETFOCUS:
    if (runtime->previousWindowProc == reinterpret_cast<WNDPROC>(wParam)) {
      break;
    }
    [[fallthrough]];
  case WM_KILLFOCUS:
  case WM_KEYDOWN:
  case WM_KEYUP:
  case WM_CHAR:
  case WM_DEADCHAR: {
    using MsgDispatchFn = void (__thiscall*)(void*, UINT, WPARAM, LPARAM);
    auto* const vtable = runtime->vtable;
    const auto dispatch = reinterpret_cast<MsgDispatchFn>(vtable[124]);
    if (dispatch != nullptr) {
      dispatch(runtime, message, wParam, lParam);
      if (!::IsWindow(window) || reinterpret_cast<DispatchWindowRuntime*>(::GetWindowLongW(window, GWL_USERDATA)) != runtime) {
        return 0;
      }
    }
    break;
  }
  case WM_GETDLGCODE:
    return 128;
  default:
    break;
  }

  return ::CallWindowProcW(runtime->previousWindowProc, window, message, wParam, lParam);
}

/**
 * Address: 0x009C7700 (FUN_009C7700)
 *
 * What it does:
 * Routes profile-string writes to global-profile or private-profile API based
 * on whether target filename equals `L\"Default\"`.
 */
[[maybe_unused]] BOOL WriteProfileStringDispatchRuntime(
  LPCWSTR* const section,
  LPCWSTR* const key,
  LPCWSTR* const value,
  LPCWSTR* const fileName
)
{
  static const wchar_t kDefaultName[] = L"Default";

  const LPCWSTR sectionText = section != nullptr ? *section : nullptr;
  const LPCWSTR keyText = key != nullptr ? *key : nullptr;
  const LPCWSTR valueText = value != nullptr ? *value : nullptr;
  const LPCWSTR fileText = fileName != nullptr ? *fileName : nullptr;

  if (fileText != nullptr && std::wcscmp(fileText, kDefaultName) == 0) {
    return ::WriteProfileStringW(sectionText, keyText, valueText);
  }
  return ::WritePrivateProfileStringW(sectionText, keyText, valueText, fileText);
}

struct WxStringRefDataRuntime
{
  std::int32_t referenceCount;
  std::int32_t length;
  std::int32_t capacity;
};
static_assert(sizeof(WxStringRefDataRuntime) == 0x0C, "WxStringRefDataRuntime size must be 0x0C");

struct WxStringRuntime
{
  LPCWSTR m_pchData;
};
#if INTPTR_MAX == INT32_MAX
static_assert(sizeof(WxStringRuntime) == 0x04, "WxStringRuntime size must be 0x04");
#endif

[[nodiscard]] LPCWSTR GetSharedWxEmptyStringRuntime() noexcept
{
  struct SharedWxEmptyStringRuntime
  {
    WxStringRefDataRuntime refData;
    wchar_t text[1];
  };

  static SharedWxEmptyStringRuntime sEmpty = {
    {-1, 0, 0},
    {L'\0'}
  };
  return sEmpty.text;
}

[[nodiscard]] bool FormatWxStringRuntime(
  WxStringRuntime* const destination,
  const wchar_t* const format,
  ...
)
{
  if (destination == nullptr || format == nullptr) {
    return false;
  }

  destination->m_pchData = GetSharedWxEmptyStringRuntime();

  va_list arguments;
  va_start(arguments, format);
  const int requiredCharacters = ::_vscwprintf(format, arguments);
  va_end(arguments);
  if (requiredCharacters < 0) {
    return false;
  }

  const std::size_t bufferCharacters = static_cast<std::size_t>(requiredCharacters) + 1u;
  auto* const refData = static_cast<WxStringRefDataRuntime*>(::operator new(
    sizeof(WxStringRefDataRuntime) + (bufferCharacters * sizeof(wchar_t)),
    std::nothrow
  ));
  if (refData == nullptr) {
    return false;
  }

  auto* const buffer = reinterpret_cast<wchar_t*>(refData + 1);
  va_start(arguments, format);
  const int writtenCharacters = ::vswprintf_s(buffer, bufferCharacters, format, arguments);
  va_end(arguments);
  if (writtenCharacters < 0) {
    ::operator delete(refData);
    return false;
  }

  refData->referenceCount = 1;
  refData->length = writtenCharacters;
  refData->capacity = writtenCharacters;
  destination->m_pchData = buffer;
  return true;
}

void ReleaseWxStringRuntime(WxStringRuntime* const value) noexcept
{
  if (value == nullptr || value->m_pchData == nullptr) {
    return;
  }

#if INTPTR_MAX == INT32_MAX
  ReleaseSharedWxStringLane(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(value->m_pchData)));
#else
  auto* const refData = reinterpret_cast<WxStringRefDataRuntime*>(
    reinterpret_cast<std::byte*>(const_cast<wchar_t*>(value->m_pchData)) - sizeof(WxStringRefDataRuntime)
  );
  if (refData->referenceCount != -1) {
    --refData->referenceCount;
    if (refData->referenceCount == 0) {
      ::operator delete(refData);
    }
  }
#endif

  value->m_pchData = GetSharedWxEmptyStringRuntime();
}

/**
 * Address: 0x009C7790 (FUN_009C7790)
 *
 * What it does:
 * Formats one float lane as `"%.4f"` into a temporary wx-string lane, routes
 * it through profile-string dispatch, then releases temporary string ref-data.
 */
[[maybe_unused]] BOOL WriteProfileFormattedFloatRuntime(
  LPCWSTR* const section,
  LPCWSTR* const key,
  const float value,
  LPCWSTR* const fileName
)
{
  WxStringRuntime temporaryValue{GetSharedWxEmptyStringRuntime()};
  (void)FormatWxStringRuntime(&temporaryValue, L"%.4f", value);

  const BOOL dispatchResult = WriteProfileStringDispatchRuntime(section, key, &temporaryValue.m_pchData, fileName);
  ReleaseWxStringRuntime(&temporaryValue);
  return dispatchResult;
}

/**
 * Address: 0x009C7830 (FUN_009C7830)
 *
 * What it does:
 * Formats one signed long lane as `"%ld"` into a temporary wx-string lane,
 * routes it through profile-string dispatch, then releases string ref-data.
 */
[[maybe_unused]] BOOL WriteProfileFormattedLongRuntime(
  LPCWSTR* const section,
  LPCWSTR* const key,
  const long value,
  LPCWSTR* const fileName
)
{
  WxStringRuntime temporaryValue{GetSharedWxEmptyStringRuntime()};
  (void)FormatWxStringRuntime(&temporaryValue, L"%ld", value);

  const BOOL dispatchResult = WriteProfileStringDispatchRuntime(section, key, &temporaryValue.m_pchData, fileName);
  ReleaseWxStringRuntime(&temporaryValue);
  return dispatchResult;
}

/**
 * Address: 0x009C78D0 (FUN_009C78D0)
 *
 * What it does:
 * Formats one signed int lane as `"%d"` into a temporary wx-string lane,
 * routes it through profile-string dispatch, then releases string ref-data.
 */
[[maybe_unused]] BOOL WriteProfileFormattedIntRuntime(
  LPCWSTR* const section,
  LPCWSTR* const key,
  const int value,
  LPCWSTR* const fileName
)
{
  WxStringRuntime temporaryValue{GetSharedWxEmptyStringRuntime()};
  (void)FormatWxStringRuntime(&temporaryValue, L"%d", value);

  const BOOL dispatchResult = WriteProfileStringDispatchRuntime(section, key, &temporaryValue.m_pchData, fileName);
  ReleaseWxStringRuntime(&temporaryValue);
  return dispatchResult;
}

/**
 * Address: 0x009C81C0 (FUN_009C81C0)
 *
 * What it does:
 * On wx OS-family `18`, enables `SeShutdownPrivilege` on the current process
 * token before mode-gated shutdown; otherwise directly calls `ExitWindowsEx`
 * when `mode < 2`.
 */
[[maybe_unused]] bool ShutdownSystemWithPrivilegeRuntime(const unsigned int mode)
{
  if (wxGetOsVersion(nullptr, nullptr) != 18) {
    return (mode < 2u) && (::ExitWindowsEx(7u, 0u) != FALSE);
  }

  HANDLE tokenHandle = nullptr;
  bool result = (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &tokenHandle) != FALSE);
  if (result) {
    TOKEN_PRIVILEGES privilegeState{};
    (void)::LookupPrivilegeValueW(nullptr, L"SeShutdownPrivilege", &privilegeState.Privileges[0].Luid);
    privilegeState.PrivilegeCount = 1u;
    privilegeState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    (void)::AdjustTokenPrivileges(tokenHandle, FALSE, &privilegeState, 0u, nullptr, nullptr);

    result = (::GetLastError() == ERROR_SUCCESS);
    if (result) {
      return (mode < 2u) && (::ExitWindowsEx(7u, 0u) != FALSE);
    }
  }

  return result;
}

/**
 * Address: 0x00A39EE0 (FUN_00A39EE0)
 *
 * What it does:
 * Initializes one float-distance runtime lane with default tolerance/clamp
 * bounds.
 */
[[maybe_unused]] DistanceVector2fRuntime* InitializeDistanceVector2fRuntime(
  DistanceVector2fRuntime* const runtime,
  void* const vtableToken
)
{
  if (runtime == nullptr) {
    return nullptr;
  }

  runtime->vtable = vtableToken;
  runtime->dimension = 8;
  runtime->epsilon = 0.000001f;
  runtime->minClamp = 0.001f;
  runtime->maxClamp = 499.99997f;
  runtime->hasRawResult = 0u;
  runtime->initialDistance = std::numeric_limits<float>::max();
  runtime->hasFinalResult = 0u;
  return runtime;
}

/**
 * Address: 0x00A39F60 (FUN_00A39F60)
 *
 * What it does:
 * Initializes one double-distance runtime lane with default tolerance/clamp
 * bounds.
 */
[[maybe_unused]] DistanceVector2dRuntime* InitializeDistanceVector2dRuntime(
  DistanceVector2dRuntime* const runtime,
  void* const vtableToken
)
{
  if (runtime == nullptr) {
    return nullptr;
  }

  runtime->vtable = vtableToken;
  runtime->dimension = 8;
  runtime->epsilon = 0.00000001;
  runtime->minClamp = 0.001;
  runtime->maxClamp = 500.0;
  runtime->hasRawResult = 0u;
  runtime->initialDistance = std::numeric_limits<double>::max();
  runtime->hasFinalResult = 0u;
  return runtime;
}

/**
 * Address: 0x00A4BA90 (FUN_00A4BA90)
 *
 * What it does:
 * Builds one 2-point support sphere lane `(center.xyz, radiusSquared)` from
 * two 3D points.
 */
[[maybe_unused]] double* ComputeTwoPointSupportSphereRuntime(
  double* const outSphere4,
  const double* const pointA3,
  const double* const pointB3
) noexcept
{
  if (outSphere4 == nullptr || pointA3 == nullptr || pointB3 == nullptr) {
    return outSphere4;
  }

  const double centerX = (pointA3[0] + pointB3[0]) * 0.5;
  const double centerY = (pointA3[1] + pointB3[1]) * 0.5;
  const double centerZ = (pointA3[2] + pointB3[2]) * 0.5;

  outSphere4[0] = centerX;
  outSphere4[1] = centerY;
  outSphere4[2] = centerZ;

  const double deltaX = pointB3[0] - pointA3[0];
  const double deltaY = pointB3[1] - pointA3[1];
  const double deltaZ = pointB3[2] - pointA3[2];
  outSphere4[3] = ((deltaX * deltaX) + (deltaY * deltaY) + (deltaZ * deltaZ)) * 0.25;
  return outSphere4;
}

/**
 * Address: 0x00A4BB00 (FUN_00A4BB00)
 *
 * What it does:
 * Computes one triangle-derived closest-point lane and squared distance; emits
 * `DBL_MAX` sentinel output when determinant is under tolerance.
 */
[[maybe_unused]] double* ComputeTriangleClosestPointRuntime(
  const double* const toleranceLane,
  double* const outPoint4,
  const double* const p3,
  const double* const p4,
  const double* const p5
)
{
  if (toleranceLane == nullptr || outPoint4 == nullptr || p3 == nullptr || p4 == nullptr || p5 == nullptr) {
    return outPoint4;
  }

  const double v5 = p3[0] - p5[0];
  const double v6 = p3[1] - p5[1];
  const double v24 = p3[2] - p5[2];
  const double v20 = p4[0] - p5[0];
  const double v21 = p4[1] - p5[1];
  const double v22 = p4[2] - p5[2];
  const double v7 = (v24 * v22) + (v20 * v5) + (v21 * v6);
  const double v8 = (v5 * v5) + (v6 * v6) + (v24 * v24);
  const double v9 = (v21 * v21) + (v20 * v20) + (v22 * v22);
  const long double determinant = static_cast<long double>((v9 * v8) - (v7 * v7));

  if (std::fabs(static_cast<double>(determinant)) <= *toleranceLane) {
    outPoint4[0] = std::numeric_limits<double>::max();
    outPoint4[1] = std::numeric_limits<double>::max();
    outPoint4[2] = std::numeric_limits<double>::max();
    outPoint4[3] = std::numeric_limits<double>::max();
    return outPoint4;
  }

  const long double halfInvDeterminant = 0.5L / determinant;
  const long double baryS = static_cast<long double>((v8 - v7)) * (halfInvDeterminant * static_cast<long double>(v9));
  const long double baryT = static_cast<long double>(v8) * halfInvDeterminant * static_cast<long double>(v9 - v7);
  const long double baryU = 1.0L - baryS - baryT;

  const long double x = (static_cast<long double>(p5[0]) * baryU)
                      + (static_cast<long double>(p3[0]) * baryS)
                      + (static_cast<long double>(p4[0]) * baryT);
  const long double y = (static_cast<long double>(p5[1]) * baryU)
                      + (static_cast<long double>(p3[1]) * baryS)
                      + (static_cast<long double>(p4[1]) * baryT);
  const long double z = (static_cast<long double>(p5[2]) * baryU)
                      + (static_cast<long double>(p3[2]) * baryS)
                      + (static_cast<long double>(p4[2]) * baryT);

  outPoint4[0] = static_cast<double>(x);
  outPoint4[1] = static_cast<double>(y);
  outPoint4[2] = static_cast<double>(z);

  const long double dz = (baryS * static_cast<long double>(v24)) + (baryT * static_cast<long double>(v22));
  const long double dx = (static_cast<long double>(v20) * baryT) + (static_cast<long double>(v5) * baryS);
  const long double dy = (static_cast<long double>(v21) * baryT) + (static_cast<long double>(v6) * baryS);
  outPoint4[3] = static_cast<double>((dz * dz) + (dx * dx) + (dy * dy));
  return outPoint4;
}

/**
 * Address: 0x00570410 (FUN_00570410)
 *
 * What it does:
 * Advances one RB-tree iterator lane using sentinel flag offset `+0x19`.
 */
[[maybe_unused]] RbNodeFlag25Runtime* AdvanceTreeIteratorFlag25Runtime(
  const std::uint32_t /*unused*/,
  RbNodeFlag25Runtime** const iteratorLane
)
{
  return AdvanceRbIteratorRuntime<RbNodeFlag25Runtime, 0x19u>(iteratorLane);
}

/**
 * Address: 0x006B02E0 (FUN_006B02E0)
 *
 * What it does:
 * Advances one RB-tree iterator lane using sentinel flag offset `+0x2D`.
 */
[[maybe_unused]] RbNodeFlag45Runtime* AdvanceTreeIteratorFlag45RuntimeA(
  const std::uint32_t /*unused*/,
  RbNodeFlag45Runtime** const iteratorLane
)
{
  return AdvanceRbIteratorRuntime<RbNodeFlag45Runtime, 0x2Du>(iteratorLane);
}

/**
 * Address: 0x007CA280 (FUN_007CA280)
 *
 * What it does:
 * Advances one map iterator lane using sentinel flag offset `+0x15`.
 */
[[maybe_unused]] void AdvanceMapIteratorFlag21RuntimeA(
  RbNodeFlag21Runtime** const iteratorLane
)
{
  (void)AdvanceRbIteratorRuntime<RbNodeFlag21Runtime, 0x15u>(iteratorLane);
}

/**
 * Address: 0x007C8E30 (FUN_007C8E30)
 *
 * What it does:
 * Adapter lane that advances one map iterator slot through
 * `AdvanceMapIteratorFlag21RuntimeA` and returns the original slot pointer.
 */
[[maybe_unused]] RbNodeFlag21Runtime** AdvanceMapIteratorFlag21RuntimeReturnSlotAdapterA(
  RbNodeFlag21Runtime** const iteratorLane
)
{
  AdvanceMapIteratorFlag21RuntimeA(iteratorLane);
  return iteratorLane;
}

/**
 * Address: 0x007C9770 (FUN_007C9770)
 *
 * What it does:
 * Secondary adapter lane that advances one map iterator slot through
 * `AdvanceMapIteratorFlag21RuntimeA` and returns the original slot pointer.
 */
[[maybe_unused]] RbNodeFlag21Runtime** AdvanceMapIteratorFlag21RuntimeReturnSlotAdapterB(
  RbNodeFlag21Runtime** const iteratorLane
)
{
  AdvanceMapIteratorFlag21RuntimeA(iteratorLane);
  return iteratorLane;
}

/**
 * Address: 0x007F2CD0 (FUN_007F2CD0)
 *
 * What it does:
 * Advances one string-map iterator lane using sentinel flag offset `+0x2D`.
 */
[[maybe_unused]] RbNodeFlag45Runtime* AdvanceRangeExtractorIteratorRuntime(
  RbNodeFlag45Runtime** const iteratorLane
)
{
  return AdvanceRbIteratorRuntime<RbNodeFlag45Runtime, 0x2Du>(iteratorLane);
}

/**
 * Address: 0x0083C0B0 (FUN_0083C0B0)
 *
 * What it does:
 * Advances one RB-tree iterator lane using sentinel flag offset `+0x2D`.
 */
[[maybe_unused]] RbNodeFlag45Runtime* AdvanceTreeIteratorFlag45RuntimeB(
  const std::uint32_t /*unused*/,
  RbNodeFlag45Runtime** const iteratorLane
)
{
  return AdvanceRbIteratorRuntime<RbNodeFlag45Runtime, 0x2Du>(iteratorLane);
}

/**
 * Address: 0x008495B0 (FUN_008495B0)
 *
 * What it does:
 * Advances one entity-map iterator lane using sentinel flag offset `+0x15`.
 */
[[maybe_unused]] void AdvanceMapIteratorFlag21RuntimeB(
  RbNodeFlag21Runtime** const iteratorLane
)
{
  (void)AdvanceRbIteratorRuntime<RbNodeFlag21Runtime, 0x15u>(iteratorLane);
}

/**
 * Address: 0x0085F740 (FUN_0085F740)
 *
 * What it does:
 * Copies one 0x31-byte payload lane and increments embedded intrusive
 * reference counters (`+0x18`, `+0x20`, `+0x28`) when present.
 */
[[maybe_unused]] RefCountedPayload49Runtime* CopyRefCountedPayload49Runtime(
  RefCountedPayload49Runtime* const destination,
  const RefCountedPayload49Runtime* const source
)
{
  if (destination == nullptr || source == nullptr) {
    return destination;
  }

  *destination = *source;
  if (destination->ref18 != 0u) {
    (void)::InterlockedExchangeAdd(reinterpret_cast<volatile LONG*>(destination->ref18 + 4u), 1);
  }
  if (destination->ref20 != 0u) {
    (void)::InterlockedExchangeAdd(reinterpret_cast<volatile LONG*>(destination->ref20 + 4u), 1);
  }
  if (destination->ref28 != 0u) {
    (void)::InterlockedExchangeAdd(reinterpret_cast<volatile LONG*>(destination->ref28 + 4u), 1);
  }
  return destination;
}

/**
 * Address: 0x0085FDB0 (FUN_0085FDB0)
 * Address: 0x0085F910 (FUN_0085F910)
 *
 * What it does:
 * Fills `count` contiguous `0x34`-byte lanes by copying one
 * `RefCountedPayload49Runtime` source payload into each lane.
 */
[[maybe_unused]] RefCountedPayload49Runtime* FillStride52RefCountedPayload49LaneRuntime(
  std::uint32_t count,
  Element52Runtime* destination,
  const RefCountedPayload49Runtime* const source
)
{
  RefCountedPayload49Runtime* result = reinterpret_cast<RefCountedPayload49Runtime*>(
    static_cast<std::uintptr_t>(count)
  );

  while (count != 0u) {
    if (destination != nullptr) {
      result = CopyRefCountedPayload49Runtime(
        reinterpret_cast<RefCountedPayload49Runtime*>(destination),
        source
      );
      ++destination;
    }
    --count;
  }

  return result;
}

namespace
{
  [[nodiscard]] Element52Runtime* CopyStride52RefCountedPayload49RangeRuntimeImpl(
    Element52Runtime* destination,
    const Element52Runtime* sourceBegin,
    const Element52Runtime* const sourceEnd
  ) noexcept
  {
    std::uintptr_t destinationCursor = reinterpret_cast<std::uintptr_t>(destination);

    while (sourceBegin != sourceEnd) {
      if (destinationCursor != 0u) {
        (void)CopyRefCountedPayload49Runtime(
          reinterpret_cast<RefCountedPayload49Runtime*>(destinationCursor),
          reinterpret_cast<const RefCountedPayload49Runtime*>(sourceBegin)
        );
      }

      ++sourceBegin;
      destinationCursor += sizeof(Element52Runtime);
    }

    return reinterpret_cast<Element52Runtime*>(destinationCursor);
  }
} // namespace

/**
 * Address: 0x0085FFB0 (FUN_0085FFB0)
 *
 * What it does:
 * Copies one half-open range of `0x34`-byte refcounted payload lanes from
 * `[sourceBegin, sourceEnd)` into `destination`.
 */
[[maybe_unused]] Element52Runtime* CopyStride52RefCountedPayload49RangeRuntimeA(
  Element52Runtime* const destination,
  const Element52Runtime* sourceBegin,
  const Element52Runtime* const sourceEnd
) noexcept
{
  return CopyStride52RefCountedPayload49RangeRuntimeImpl(destination, sourceBegin, sourceEnd);
}

/**
 * Address: 0x0085FFE0 (FUN_0085FFE0)
 *
 * What it does:
 * Alternate register-shape entry that copies one half-open `0x34`-byte
 * refcounted payload range into `destination`.
 */
[[maybe_unused]] Element52Runtime* CopyStride52RefCountedPayload49RangeRuntimeB(
  Element52Runtime* const destination,
  const Element52Runtime* sourceBegin,
  const Element52Runtime* const sourceEnd
) noexcept
{
  return CopyStride52RefCountedPayload49RangeRuntimeImpl(destination, sourceBegin, sourceEnd);
}

/**
 * Address: 0x0085F870 (FUN_0085F870)
 *
 * What it does:
 * Calling-convention adapter lane that forwards one `0x34`-stride half-open
 * range copy into `CopyStride52RefCountedPayload49RangeRuntimeA`.
 */
[[maybe_unused]] Element52Runtime* CopyStride52RefCountedPayload49RangeRuntimeAdapterA(
  const Element52Runtime* const sourceBegin,
  const Element52Runtime* const sourceEnd,
  Element52Runtime* const destination
) noexcept
{
  return CopyStride52RefCountedPayload49RangeRuntimeA(destination, sourceBegin, sourceEnd);
}

/**
 * Address: 0x0085FD10 (FUN_0085FD10)
 *
 * What it does:
 * Alternate calling-convention adapter lane that forwards one `0x34`-stride
 * half-open range copy into `CopyStride52RefCountedPayload49RangeRuntimeA`.
 */
[[maybe_unused]] Element52Runtime* CopyStride52RefCountedPayload49RangeRuntimeAdapterB(
  const Element52Runtime* const sourceBegin,
  const Element52Runtime* const sourceEnd,
  Element52Runtime* const destination
) noexcept
{
  return CopyStride52RefCountedPayload49RangeRuntimeA(destination, sourceBegin, sourceEnd);
}

/**
 * Address: 0x0085FEA0 (FUN_0085FEA0)
 *
 * What it does:
 * Third calling-convention adapter lane that forwards one `0x34`-stride
 * half-open range copy into `CopyStride52RefCountedPayload49RangeRuntimeA`.
 */
[[maybe_unused]] Element52Runtime* CopyStride52RefCountedPayload49RangeRuntimeAdapterC(
  const Element52Runtime* const sourceBegin,
  const Element52Runtime* const sourceEnd,
  Element52Runtime* const destination
) noexcept
{
  return CopyStride52RefCountedPayload49RangeRuntimeA(destination, sourceBegin, sourceEnd);
}

/**
 * Address: 0x00899940 (FUN_00899940)
 *
 * What it does:
 * Advances one RB-tree iterator lane using sentinel flag offset `+0x2D`.
 */
[[maybe_unused]] void AdvanceTreeIteratorFlag45RuntimeC(
  RbNodeFlag45Runtime** const iteratorLane
)
{
  (void)AdvanceRbIteratorRuntime<RbNodeFlag45Runtime, 0x2Du>(iteratorLane);
}

/**
 * Address: 0x007B4BE0 (FUN_007B4BE0)
 *
 * What it does:
 * Moves one RB-tree iterator lane backward using sentinel flag offset `+0x1D`.
 */
[[maybe_unused]] RbNodeFlag29Runtime* RetreatTreeIteratorFlag29RuntimeA(
  const std::uint32_t /*unused*/,
  RbNodeFlag29Runtime** const iteratorLane
)
{
  return RetreatRbIteratorRuntime<RbNodeFlag29Runtime, 0x1Du>(iteratorLane);
}

/**
 * Address: 0x007B3BC0 (FUN_007B3BC0)
 * Address: 0x007B4580 (FUN_007B4580)
 *
 * What it does:
 * Adapts one nil-29 iterator retreat through `RetreatTreeIteratorFlag29RuntimeA`
 * and returns the caller iterator-slot pointer.
 */
[[maybe_unused]] [[nodiscard]] RbNodeFlag29Runtime** RetreatTreeIteratorFlag29RuntimeASlotAdapter(
  const std::uint32_t laneTag,
  RbNodeFlag29Runtime** const iteratorLane
)
{
  (void)RetreatTreeIteratorFlag29RuntimeA(laneTag, iteratorLane);
  return iteratorLane;
}

/**
 * Address: 0x007CB230 (FUN_007CB230)
 *
 * What it does:
 * Advances one set/map iterator lane using sentinel flag offset `+0x0E`.
 */
[[maybe_unused]] SetCharNodeNil14Runtime* AdvanceTreeIteratorFlag14Runtime(
  const std::uint32_t /*unused*/,
  SetCharNodeNil14Runtime** const iteratorLane
)
{
  return AdvanceRbIteratorRuntime<SetCharNodeNil14Runtime, 0x0Eu>(iteratorLane);
}

/**
 * Address: 0x007CCEB0 (FUN_007CCEB0)
 *
 * What it does:
 * Writes one repeated 4-dword payload lane into `count` contiguous slots.
 */
[[maybe_unused]] std::uint32_t* FillStride4DwordLaneRuntimeA(
  std::uint32_t* destination,
  const std::uint32_t* const source,
  std::uint32_t count
)
{
  while (count != 0u) {
    if (destination != nullptr) {
      destination[0] = source[0];
      destination[1] = source[1];
      destination[2] = source[2];
      destination[3] = source[3];
      destination += 4;
    }
    --count;
  }
  return destination;
}

/**
 * Address: 0x007CCEF0 (FUN_007CCEF0)
 * Address: 0x007CBF00 (FUN_007CBF00)
 *
 * What it does:
 * Initializes `count` contiguous 0x18-byte lanes by copying one source
 * dword lane and copy-constructing one `LuaObject` lane from the same source.
 */
[[maybe_unused]] LuaPlus::LuaObject* FillStride24WordLuaObjectLaneRuntime(
  std::uint32_t count,
  Element24WordLuaObjectRuntime* destination,
  const Element24WordLuaObjectRuntime* const source
)
{
  LuaPlus::LuaObject* lastConstructed = reinterpret_cast<LuaPlus::LuaObject*>(
    static_cast<std::uintptr_t>(count)
  );

  while (count != 0u) {
    if (destination != nullptr) {
      destination->lane00 = source->lane00;
      lastConstructed = ::new (&destination->lane04) LuaPlus::LuaObject(source->lane04);
      ++destination;
    }
    --count;
  }

  return lastConstructed;
}

/**
 * Address: 0x007CBEE0 (FUN_007CBEE0)
 *
 * What it does:
 * Forwards one 4-dword lane fill into `FillStride4DwordLaneRuntimeA` while
 * preserving the legacy null-source adapter semantics.
 */
[[maybe_unused]] std::uint32_t* FillStride4DwordLaneRuntimeANullSourceAdapter(
  std::uint32_t* const destination,
  const std::uint32_t count
)
{
  return FillStride4DwordLaneRuntimeA(destination, nullptr, count);
}

/**
 * Address: 0x007E5100 (FUN_007E5100)
 *
 * What it does:
 * Advances one RB-tree iterator lane using sentinel flag offset `+0x25`.
 */
[[maybe_unused]] PairNodeRuntime* AdvanceTreeIteratorFlag37Runtime(
  const std::uint32_t /*unused*/,
  PairNodeRuntime** const iteratorLane
)
{
  return AdvanceRbIteratorRuntime<PairNodeRuntime, 0x25u>(iteratorLane);
}

/**
 * Address: 0x007F30B0 (FUN_007F30B0)
 *
 * What it does:
 * Moves one RB-tree iterator lane backward using sentinel flag offset `+0x2D`.
 */
[[maybe_unused]] RbNodeFlag45Runtime* RetreatTreeIteratorFlag45RuntimeA(
  const std::uint32_t /*unused*/,
  RbNodeFlag45Runtime** const iteratorLane
)
{
  return RetreatRbIteratorRuntime<RbNodeFlag45Runtime, 0x2Du>(iteratorLane);
}

/**
 * Address: 0x007F3110 (FUN_007F3110)
 *
 * What it does:
 * Moves one RB-tree iterator lane backward using sentinel flag offset `+0xB9`.
 */
[[maybe_unused]] RbNodeLinksRuntime* RetreatTreeIteratorFlag185Runtime(
  const std::uint32_t /*unused*/,
  RbNodeLinksRuntime** const iteratorLane
)
{
  return RetreatRbIteratorRuntime<RbNodeLinksRuntime, 0xB9u>(iteratorLane);
}

/**
 * Address: 0x008309D0 (FUN_008309D0)
 *
 * What it does:
 * Moves one RB-tree iterator lane backward using sentinel flag offset `+0x25`.
 */
[[maybe_unused]] PairNodeRuntime* RetreatTreeIteratorFlag37Runtime(
  const std::uint32_t /*unused*/,
  PairNodeRuntime** const iteratorLane
)
{
  return RetreatRbIteratorRuntime<PairNodeRuntime, 0x25u>(iteratorLane);
}

/**
 * Address: 0x0083C400 (FUN_0083C400)
 *
 * What it does:
 * Moves one RB-tree iterator lane backward using sentinel flag offset `+0x15`.
 */
[[maybe_unused]] RbNodeFlag21Runtime* RetreatTreeIteratorFlag21RuntimeA(
  const std::uint32_t /*unused*/,
  RbNodeFlag21Runtime** const iteratorLane
)
{
  return RetreatRbIteratorRuntime<RbNodeFlag21Runtime, 0x15u>(iteratorLane);
}

/**
 * Address: 0x0083C460 (FUN_0083C460)
 *
 * What it does:
 * Moves one RB-tree iterator lane backward using sentinel flag offset `+0x2D`.
 */
[[maybe_unused]] RbNodeFlag45Runtime* RetreatTreeIteratorFlag45RuntimeB(
  const std::uint32_t /*unused*/,
  RbNodeFlag45Runtime** const iteratorLane
)
{
  return RetreatRbIteratorRuntime<RbNodeFlag45Runtime, 0x2Du>(iteratorLane);
}

[[maybe_unused]] std::uint32_t* FillStride3DwordLaneRuntime(
  std::uint32_t* destination,
  const std::uint32_t* const source,
  std::uint32_t count
);

/**
 * Address: 0x00848DA0 (FUN_00848DA0)
 *
 * What it does:
 * Writes `count` zeroed 12-byte lanes and returns one-past-the-last written
 * lane.
 */
[[maybe_unused]] Element12Runtime* ConstructElement12LaneRangeFromZeroRuntimeB(
  Element12Runtime* const destination,
  const std::uint32_t count
)
{
  if (destination == nullptr) {
    return nullptr;
  }

  const Element12Runtime zeroLane{};
  return reinterpret_cast<Element12Runtime*>(
    FillStride3DwordLaneRuntime(reinterpret_cast<std::uint32_t*>(destination), &zeroLane.lane0, count)
  );
}

/**
 * Address: 0x00849D90 (FUN_00849D90)
 *
 * What it does:
 * Descends repeatedly through `right` links until the flag-57 sentinel is
 * reached and returns the last non-sentinel node.
 */
[[maybe_unused]] RbNodeLinksRuntime* AdvanceTreeIteratorFlag57Runtime(
  const std::uint32_t /*unused*/,
  RbNodeLinksRuntime** const iteratorLane
) noexcept
{
  if (iteratorLane == nullptr) {
    return nullptr;
  }
  return DescendRightUntilSentinelRuntime<RbNodeLinksRuntime, 0x39u>(*iteratorLane);
}

/**
 * Address: 0x0084A510 (FUN_0084A510)
 *
 * What it does:
 * Writes one repeated 3-dword source lane across `[destinationBegin,
 * destinationEnd)`.
 */
[[maybe_unused]] std::uint32_t* FillStride3DwordLaneRuntimeB(
  std::uint32_t* destinationBegin,
  std::uint32_t* const destinationEnd,
  const std::uint32_t* const source
) noexcept
{
  while (destinationBegin != destinationEnd) {
    destinationBegin[0] = source[0];
    destinationBegin[1] = source[1];
    destinationBegin[2] = source[2];
    destinationBegin += 3;
  }
  return destinationBegin;
}

/**
 * Address: 0x0084A530 (FUN_0084A530)
 *
 * What it does:
 * Copies one 3-dword lane range backward from `[sourceBegin, sourceEnd)` into
 * destination lanes ending at `destinationEnd`.
 */
[[maybe_unused]] std::uint32_t* CopyStride3DwordRangeBackwardRuntime(
  std::uint32_t* destinationEnd,
  const std::uint32_t* const sourceBegin,
  const std::uint32_t* sourceEnd
) noexcept
{
  while (sourceEnd != sourceBegin) {
    sourceEnd -= 3;
    destinationEnd -= 3;
    destinationEnd[0] = sourceEnd[0];
    destinationEnd[1] = sourceEnd[1];
    destinationEnd[2] = sourceEnd[2];
  }
  return destinationEnd;
}

[[maybe_unused]] PriorityQueueEntry12Runtime* SiftHeapEntry12ByScoreRuntime(
  std::int32_t insertionIndex,
  std::int32_t lowerBoundIndex,
  PriorityQueueEntry12Runtime* entries,
  std::uint32_t lane00,
  float score,
  std::uint32_t lane08
) noexcept;

/**
 * Address: 0x0084BF30 (FUN_0084BF30)
 *
 * What it does:
 * Sifts one 12-byte heap hole downward across the larger-child lane and then
 * reinserts the pending payload via `SiftHeapEntry12ByScoreRuntime(...)`.
 */
[[maybe_unused]] PriorityQueueEntry12Runtime* SiftHeapHoleDownAndReinsertByScoreRuntime(
  std::int32_t holeIndex,
  const std::int32_t upperBoundIndex,
  PriorityQueueEntry12Runtime* const entries,
  const std::uint32_t lane00,
  const float score,
  const std::uint32_t lane08
) noexcept
{
  const std::int32_t lowerBoundIndex = holeIndex;
  std::int32_t childIndex = (holeIndex * 2) + 2;
  bool hasTrailingLeftChild = (childIndex == upperBoundIndex);

  while (childIndex < upperBoundIndex) {
    if (entries[childIndex - 1].score > entries[childIndex].score) {
      --childIndex;
    }

    entries[holeIndex] = entries[childIndex];
    holeIndex = childIndex;
    childIndex = (childIndex * 2) + 2;
    hasTrailingLeftChild = (childIndex == upperBoundIndex);
  }

  if (hasTrailingLeftChild) {
    entries[holeIndex] = entries[upperBoundIndex - 1];
    holeIndex = upperBoundIndex - 1;
  }

  return SiftHeapEntry12ByScoreRuntime(holeIndex, lowerBoundIndex, entries, lane00, score, lane08);
}

/**
 * Address: 0x0084C280 (FUN_0084C280)
 *
 * What it does:
 * Sifts one 12-byte heap entry up toward `lowerBoundIndex` using only score
 * ordering, then writes the new entry lane.
 */
[[maybe_unused]] PriorityQueueEntry12Runtime* SiftHeapEntry12ByScoreRuntime(
  std::int32_t insertionIndex,
  const std::int32_t lowerBoundIndex,
  PriorityQueueEntry12Runtime* const entries,
  const std::uint32_t lane00,
  const float score,
  const std::uint32_t lane08
) noexcept
{
  if (entries == nullptr) {
    return nullptr;
  }

  std::int32_t parentIndex = ParentHeapIndexRuntime(insertionIndex);
  while (lowerBoundIndex < insertionIndex) {
    const PriorityQueueEntry12Runtime parent = entries[parentIndex];
    if (score <= parent.score) {
      break;
    }

    entries[insertionIndex] = parent;
    insertionIndex = parentIndex;
    parentIndex = ParentHeapIndexRuntime(parentIndex);
  }

  PriorityQueueEntry12Runtime& inserted = entries[insertionIndex];
  inserted.lane00 = lane00;
  inserted.score = score;
  inserted.lane08 = lane08;
  return &inserted;
}

/**
 * Address: 0x0084C460 (FUN_0084C460)
 *
 * What it does:
 * Sifts one 12-byte heap entry up toward `lowerBoundIndex` using
 * `(tieKey,score)` ordering, then writes the new entry lane.
 */
[[maybe_unused]] PriorityQueueEntry12Runtime* SiftHeapEntry12ByScoreAndTieRuntime(
  std::int32_t insertionIndex,
  const std::int32_t lowerBoundIndex,
  PriorityQueueEntry12Runtime* const entries,
  const std::uint32_t lane00,
  const float score,
  const std::int32_t tieKey
) noexcept
{
  if (entries == nullptr) {
    return nullptr;
  }

  std::int32_t parentIndex = ParentHeapIndexRuntime(insertionIndex);
  while (lowerBoundIndex < insertionIndex) {
    const PriorityQueueEntry12Runtime parent = entries[parentIndex];
    const std::int32_t parentTie = static_cast<std::int32_t>(parent.lane08);
    if (parentTie == tieKey) {
      if (score <= parent.score) {
        break;
      }
    } else if (parentTie <= tieKey) {
      break;
    }

    entries[insertionIndex] = parent;
    insertionIndex = parentIndex;
    parentIndex = ParentHeapIndexRuntime(parentIndex);
  }

  PriorityQueueEntry12Runtime& inserted = entries[insertionIndex];
  inserted.lane00 = lane00;
  inserted.score = score;
  inserted.lane08 = static_cast<std::uint32_t>(tieKey);
  return &inserted;
}

/**
 * Address: 0x0084E330 (FUN_0084E330)
 *
 * What it does:
 * Rebinds one intrusive owner-slot node to the owner head slot at
 * `requestedOwner + 0x04`.
 */
[[maybe_unused]] IntrusiveOwnerSlotRuntime* RebindIntrusiveOwnerSlotNodeRuntimeB(
  IntrusiveOwnerSlotRuntime* const node,
  IntrusiveOwnerAnchorRuntime* const requestedOwner
) noexcept
{
  IntrusiveOwnerSlotRuntime** requestedOwnerSlot = nullptr;
  if (requestedOwner != nullptr) {
    requestedOwnerSlot = &requestedOwner->head;
  }
  return RebindIntrusiveOwnerSlotNodeRuntime(node, &requestedOwnerSlot);
}

namespace
{
  [[nodiscard]] std::uint32_t* CopyDwordRangeBackwardByBoundsRuntime(
    const std::uint32_t* const sourceEnd,
    std::uint32_t* const destinationEnd,
    const std::uint32_t* const sourceBegin
  )
  {
    return CopyPointerWordRangeBackwardRuntime(sourceBegin, sourceEnd, destinationEnd);
  }
} // namespace

/**
 * Address: 0x0084AF60 (FUN_0084AF60)
 * Address: 0x0084A440 (FUN_0084A440)
 *
 * What it does:
 * Writes one repeated 3-dword payload lane into `count` contiguous slots.
 */
[[maybe_unused]] std::uint32_t* FillStride3DwordLaneRuntime(
  std::uint32_t* destination,
  const std::uint32_t* const source,
  std::uint32_t count
)
{
  while (count != 0u) {
    if (destination != nullptr) {
      destination[0] = source[0];
      destination[1] = source[1];
      destination[2] = source[2];
      destination += 3;
    }
    --count;
  }
  return destination;
}

[[maybe_unused]] std::uint32_t* FillStride4DwordWithDualRefLaneRuntime(
  std::uint32_t* destination,
  const std::uint32_t* const source,
  std::uint32_t count
);

/**
 * Address: 0x0084F1D0 (FUN_0084F1D0)
 *
 * What it does:
 * Releases one `{begin,end,capacity}` storage triple and resets all three
 * cursor lanes to null.
 */
[[maybe_unused]] void ReleaseLegacyBufferTripleRuntimeB(
  LegacyBufferTripleRuntime* const owner
)
{
  ReleaseLegacyBufferTripleRuntime(owner);
}

/**
 * Address: 0x0084FA10 (FUN_0084FA10)
 *
 * What it does:
 * Allocates one `count` dword storage lane and throws `std::bad_alloc` when
 * the `count * 4` byte request overflows 32-bit allocation arithmetic.
 */
[[maybe_unused]] std::uint32_t* AllocateCheckedDwordStorageRuntime(
  const std::uint32_t count
)
{
  if (count != 0u && (std::numeric_limits<std::uint32_t>::max() / count) < sizeof(std::uint32_t)) {
    throw std::bad_alloc();
  }

  return static_cast<std::uint32_t*>(::operator new(static_cast<std::size_t>(count) * sizeof(std::uint32_t)));
}

/**
 * Address: 0x0084F4D0 (FUN_0084F4D0)
 *
 * What it does:
 * Clones one dword-vector storage triple into `destination`, preserving the
 * allocator cookie lane and strong exception cleanup semantics.
 */
[[maybe_unused]] LegacyVectorStorageRuntime<std::uint32_t>* CloneDwordVectorStorageRuntime(
  const LegacyVectorStorageRuntime<std::uint32_t>* const source,
  LegacyVectorStorageRuntime<std::uint32_t>* const destination
)
{
  const std::uint32_t* const sourceBegin = source->begin;
  const std::uint32_t count = (sourceBegin != nullptr) ? static_cast<std::uint32_t>(source->end - sourceBegin) : 0u;

  destination->begin = nullptr;
  destination->end = nullptr;
  destination->capacity = nullptr;

  if (count == 0u) {
    return destination;
  }

  if (count > 0x3FFFFFFFu) {
    throw std::length_error("vector<T> too long");
  }

  destination->begin = AllocateCheckedDwordStorageRuntime(count);
  destination->end = destination->begin;
  destination->capacity = destination->begin + count;

  try {
    destination->end = CopyPointerWordRangeRuntime(sourceBegin, source->end, destination->begin);
  } catch (...) {
    ReleaseLegacyBufferTripleRuntimeB(reinterpret_cast<LegacyBufferTripleRuntime*>(destination));
    throw;
  }

  return destination;
}

/**
 * Address: 0x0084F980 (FUN_0084F980)
 *
 * What it does:
 * Copies one dword range `[sourceBegin, sourceEnd)` into storage ending at
 * `destinationEnd` and returns the destination begin lane.
 */
[[maybe_unused]] std::uint32_t* CopyDwordRangeBackwardRuntimeB(
  const std::uint32_t* const sourceEnd,
  std::uint32_t* const destinationEnd,
  const std::uint32_t* const sourceBegin
)
{
  return CopyDwordRangeBackwardByBoundsRuntime(sourceEnd, destinationEnd, sourceBegin);
}

/**
 * Address: 0x0084FD30 (FUN_0084FD30)
 *
 * What it does:
 * Swaps trailing three dword lanes (`+0x04/+0x08/+0x0C`) between two 16-byte
 * ranges while iterating backward.
 */
[[maybe_unused]] Element16Runtime* SwapElement16TailLanesBackwardRuntime(
  Element16Runtime* destinationEnd,
  Element16Runtime* sourceEnd,
  Element16Runtime* const sourceBegin
) noexcept
{
  while (sourceEnd != sourceBegin) {
    --sourceEnd;
    --destinationEnd;
    std::swap(destinationEnd->lanes[1], sourceEnd->lanes[1]);
    std::swap(destinationEnd->lanes[2], sourceEnd->lanes[2]);
    std::swap(destinationEnd->lanes[3], sourceEnd->lanes[3]);
  }
  return destinationEnd;
}

/**
 * Address: 0x008500C0 (FUN_008500C0)
 *
 * What it does:
 * Resets one dword-vector logical end to begin while preserving capacity.
 */
[[maybe_unused]] void ResetDwordVectorEndToBeginRuntimeB(
  LegacyVectorStorageRuntime<std::uint32_t>* const vector
)
{
  ResetPointerVectorEndToBeginRuntime(vector);
}

/**
 * Address: 0x008503B0 (FUN_008503B0)
 *
 * What it does:
 * Copies one dword range `[sourceBegin, sourceEnd)` to `destinationBegin` and
 * returns one-past-the-last written destination lane.
 */
[[maybe_unused]] std::uint32_t* CopyDwordRangeForwardRuntimeB(
  const std::uint32_t* const sourceEnd,
  std::uint32_t* const destinationBegin,
  const std::uint32_t* const sourceBegin
)
{
  return CopyPointerWordRangeRuntime(sourceBegin, sourceEnd, destinationBegin);
}

/**
 * Address: 0x00852280 (FUN_00852280)
 *
 * What it does:
 * Returns the logical element count for one 12-byte legacy vector lane.
 */
[[maybe_unused]] std::int32_t CountElement12VectorRuntimeB(
  const LegacyVectorStorageRuntime<Element12Runtime>* const vector
) noexcept
{
  if (vector == nullptr || vector->begin == nullptr) {
    return 0;
  }

  return static_cast<std::int32_t>(vector->end - vector->begin);
}

/**
 * Address: 0x0092BCA0 (FUN_0092BCA0)
 *
 * What it does:
 * Returns the logical element count for one 12-byte legacy vector lane.
 */
[[maybe_unused]] std::int32_t CountElement12VectorRuntimeD(
  const LegacyVectorStorageRuntime<Element12Runtime>* const vector
) noexcept
{
  return CountElement12VectorRuntimeB(vector);
}

/**
 * Address: 0x0092C280 (FUN_0092C280)
 *
 * What it does:
 * Returns the logical element count for one 12-byte legacy vector lane.
 */
[[maybe_unused]] std::int32_t CountElement12VectorRuntimeE(
  const LegacyVectorStorageRuntime<Element12Runtime>* const vector
) noexcept
{
  return CountElement12VectorRuntimeB(vector);
}

/**
 * Address: 0x00852350 (FUN_00852350)
 *
 * What it does:
 * Inserts one 12-byte lane at `insertPosition` and writes the rebased cursor
 * into `outCursor`.
 */
[[maybe_unused]] Element12Runtime** InsertElement12LaneAndStoreRebasedCursorRuntime(
  LegacyVectorStorageRuntime<Element12Runtime>* const vector,
  Element12Runtime** const outCursor,
  Element12Runtime* const insertPosition,
  const Element12Runtime* const valueLane
)
{
  if (vector == nullptr || outCursor == nullptr) {
    return outCursor;
  }

  std::size_t index = 0u;
  if (vector->begin != nullptr && vector->end != nullptr && vector->end > vector->begin && insertPosition != nullptr) {
    index = static_cast<std::size_t>(insertPosition - vector->begin);
  }

  const Element12Runtime copy = valueLane != nullptr ? *valueLane : Element12Runtime{};
  (void)InsertTrivialValueAtPosition(vector, insertPosition, copy);
  *outCursor = vector->begin + index;
  return outCursor;
}

/**
 * Address: 0x00852700 (FUN_00852700)
 *
 * What it does:
 * Writes one repeated 3-float source lane across `[destinationBegin,
 * destinationEnd)`.
 */
[[maybe_unused]] float* FillStride3FloatLaneRuntime(
  float* destinationBegin,
  float* const destinationEnd,
  const float* const source
) noexcept
{
  while (destinationBegin != destinationEnd) {
    destinationBegin[0] = source[0];
    destinationBegin[1] = source[1];
    destinationBegin[2] = source[2];
    destinationBegin += 3;
  }
  return destinationBegin;
}

/**
 * Address: 0x00852720 (FUN_00852720)
 *
 * What it does:
 * Copies one 3-float lane range backward from `[sourceBegin, sourceEnd)` into
 * destination lanes ending at `destinationEnd`.
 */
[[maybe_unused]] float* CopyStride3FloatRangeBackwardRuntime(
  float* destinationEnd,
  const float* const sourceBegin,
  const float* sourceEnd
) noexcept
{
  while (sourceEnd != sourceBegin) {
    sourceEnd -= 3;
    destinationEnd -= 3;
    destinationEnd[0] = sourceEnd[0];
    destinationEnd[1] = sourceEnd[1];
    destinationEnd[2] = sourceEnd[2];
  }
  return destinationEnd;
}

/**
 * Address: 0x00855150 (FUN_00855150)
 *
 * What it does:
 * Appends one dword lane to a legacy vector and returns the appended value.
 */
[[maybe_unused]] std::uint32_t AppendDwordLaneRuntime(
  const std::uint32_t* const valueLane,
  LegacyVectorStorageRuntime<std::uint32_t>* const vector
)
{
  const std::uint32_t value = valueLane != nullptr ? *valueLane : 0u;
  if (vector == nullptr) {
    return value;
  }

  const std::size_t currentSize = VectorSize(*vector);
  if (!ReserveTrivialVector(vector, currentSize + 1u)) {
    return value;
  }

  vector->begin[currentSize] = value;
  vector->end = vector->begin + currentSize + 1u;
  return value;
}

/**
 * Address: 0x00855320 (FUN_00855320)
 *
 * What it does:
 * Finds one exact key match in a flag-25 RB-map and returns the node when
 * present; otherwise returns the map head/sentinel node.
 */
[[maybe_unused]] MapNodeNil25Runtime** FindExactMapNodeFlag25RuntimeA(
  MapNodeNil25Runtime** const outNode,
  LegacyMapStorageRuntime<MapNodeNil25Runtime>* const map,
  const std::uint32_t* const keyLane
) noexcept
{
  if (outNode == nullptr) {
    return nullptr;
  }

  MapNodeNil25Runtime* head = nullptr;
  if (map != nullptr) {
    head = map->head;
  }

  const std::uint32_t key = keyLane != nullptr ? *keyLane : 0u;
  *outNode = FindMapNodeEqualOrHeadByKeyRuntime(head, key);
  return outNode;
}

/**
 * Address: 0x008553A0 (FUN_008553A0)
 *
 * What it does:
 * Returns true when one 204-byte legacy vector lane is empty.
 */
[[maybe_unused]] bool IsElement204VectorEmptyRuntime(
  const LegacyVectorStorageRuntime<Element204Runtime>* const vector
) noexcept
{
  if (vector == nullptr || vector->begin == nullptr) {
    return true;
  }
  return vector->end == vector->begin;
}

/**
 * Address: 0x00855810 (FUN_00855810)
 *
 * What it does:
 * Moves one dword range left within vector storage, updates the vector end,
 * and stores `destination` in `outCursor`.
 */
[[maybe_unused]] std::uint32_t** ShiftDwordRangeLeftAndStoreCursorRuntime(
  LegacyVectorStorageRuntime<std::uint32_t>* const vector,
  std::uint32_t** const outCursor,
  std::uint32_t* const destination,
  const std::uint32_t* const source
)
{
  if (outCursor == nullptr) {
    return nullptr;
  }

  if (vector != nullptr && destination != nullptr && source != nullptr && destination != source && vector->end != nullptr
      && vector->end >= source)
  {
    const std::size_t wordCount = static_cast<std::size_t>(vector->end - source);
    if (wordCount != 0u) {
      std::memmove(destination, source, wordCount * sizeof(std::uint32_t));
    }
    vector->end = destination + wordCount;
  }

  *outCursor = destination;
  return outCursor;
}

/**
 * Address: 0x0092DAD0 (FUN_0092DAD0)
 *
 * What it does:
 * Moves one byte range `[sourceBegin, end)` left to `destination` and commits
 * the updated end cursor.
 */
struct ByteRangeStorageRuntime
{
  std::uint8_t* begin;
  std::uint8_t* end;
  std::uint8_t* capacity;
};
static_assert(sizeof(ByteRangeStorageRuntime) == 0x0C, "ByteRangeStorageRuntime size must be 0x0C");

[[maybe_unused]] std::uint8_t* ShiftByteRangeLeftAndCommitEndRuntime(
  ByteRangeStorageRuntime* const owner,
  std::uint8_t* const destination,
  const std::uint8_t* const sourceBegin
)
{
  if (owner == nullptr || destination == nullptr || sourceBegin == nullptr) {
    return destination;
  }

  std::uint8_t* const currentEnd = owner->end;
  if (sourceBegin != currentEnd) {
    std::memmove(destination, sourceBegin, static_cast<std::size_t>(currentEnd - sourceBegin));
  }
  owner->end = destination + static_cast<std::size_t>(currentEnd - sourceBegin);
  return destination;
}

/**
 * Address: 0x0092DC80 (FUN_0092DC80)
 *
 * What it does:
 * Copies one 12-byte lane range backward from `[sourceBegin, sourceEnd)` into
 * destination lanes ending at `destinationEnd`.
 */
[[maybe_unused]] std::uint32_t* CopyStride3DwordRangeBackwardRuntimeC(
  const std::uint32_t* const sourceBegin,
  const std::uint32_t* const sourceEnd,
  std::uint32_t* const destinationEnd
) noexcept
{
  return CopyStride3DwordRangeBackwardRuntime(destinationEnd, sourceBegin, sourceEnd);
}

/**
 * Address: 0x0092DCB0 (FUN_0092DCB0)
 *
 * What it does:
 * Copies one dword range `[sourceBegin, sourceEnd)` into storage ending at
 * `destinationEnd` and returns the destination begin lane.
 */
[[maybe_unused]] std::uint32_t* CopyDwordRangeBackwardRuntimeG(
  const std::uint32_t* const sourceBegin,
  const std::uint32_t* const sourceEnd,
  std::uint32_t* const destinationEnd
)
{
  return CopyPointerWordRangeBackwardRuntime(sourceBegin, sourceEnd, destinationEnd);
}

/**
 * Address: 0x0092DFC0 (FUN_0092DFC0)
 *
 * What it does:
 * Copies one 12-byte lane range backward from `[sourceBegin, sourceEnd)` into
 * destination lanes ending at `destinationEnd`.
 */
[[maybe_unused]] std::uint32_t* CopyStride3DwordRangeBackwardRuntimeD(
  const std::uint32_t* const sourceBegin,
  const std::uint32_t* const sourceEnd,
  std::uint32_t* const destinationEnd
) noexcept
{
  return CopyStride3DwordRangeBackwardRuntime(destinationEnd, sourceBegin, sourceEnd);
}

/**
 * Address: 0x0092EA10 (FUN_0092EA10)
 *
 * What it does:
 * Moves one dword range `[sourceBegin, end)` left within vector storage,
 * commits the new end cursor, and stores `destination` in `outCursor`.
 */
[[maybe_unused]] std::uint32_t** ShiftDwordRangeLeftAndStoreCursorRuntimeB(
  LegacyVectorStorageRuntime<std::uint32_t>* const vector,
  std::uint32_t** const outCursor,
  std::uint32_t* const destination,
  const std::uint32_t* const sourceBegin
)
{
  return ShiftDwordRangeLeftAndStoreCursorRuntime(vector, outCursor, destination, sourceBegin);
}

/**
 * Address: 0x00932940 (FUN_00932940)
 *
 * What it does:
 * Copies one dword range `[sourceBegin, sourceEnd)` into storage ending at
 * `destinationEnd` and returns the destination begin lane.
 */
[[maybe_unused]] std::uint32_t* CopyDwordRangeBackwardRuntimeH(
  const std::uint32_t* const sourceBegin,
  const std::uint32_t* const sourceEnd,
  std::uint32_t* const destinationEnd
)
{
  return CopyPointerWordRangeBackwardRuntime(sourceBegin, sourceEnd, destinationEnd);
}

/**
 * Address: 0x00932970 (FUN_00932970)
 *
 * What it does:
 * Copies one dword range `[sourceBegin, sourceEnd)` into storage ending at
 * `destinationEnd` and returns the destination begin lane.
 */
[[maybe_unused]] std::uint32_t* CopyDwordRangeBackwardRuntimeI(
  const std::uint32_t* const sourceBegin,
  const std::uint32_t* const sourceEnd,
  std::uint32_t* const destinationEnd
)
{
  return CopyPointerWordRangeBackwardRuntime(sourceBegin, sourceEnd, destinationEnd);
}

/**
 * Address: 0x00933180 (FUN_00933180)
 *
 * What it does:
 * Moves one dword range `[sourceBegin, end)` left within vector storage,
 * commits the new end cursor, and stores `destination` in `outCursor`.
 */
[[maybe_unused]] std::uint32_t** ShiftDwordRangeLeftAndStoreCursorRuntimeC(
  LegacyVectorStorageRuntime<std::uint32_t>* const vector,
  std::uint32_t** const outCursor,
  std::uint32_t* const destination,
  const std::uint32_t* const sourceBegin
)
{
  return ShiftDwordRangeLeftAndStoreCursorRuntime(vector, outCursor, destination, sourceBegin);
}

/**
 * Address: 0x009331C0 (FUN_009331C0)
 *
 * What it does:
 * Moves one dword range `[sourceBegin, end)` left within vector storage,
 * commits the new end cursor, and stores `destination` in `outCursor`.
 */
[[maybe_unused]] std::uint32_t** ShiftDwordRangeLeftAndStoreCursorRuntimeD(
  LegacyVectorStorageRuntime<std::uint32_t>* const vector,
  std::uint32_t** const outCursor,
  std::uint32_t* const destination,
  const std::uint32_t* const sourceBegin
)
{
  return ShiftDwordRangeLeftAndStoreCursorRuntime(vector, outCursor, destination, sourceBegin);
}

/**
 * Address: 0x00856810 (FUN_00856810)
 *
 * What it does:
 * Descends repeatedly through `left` links until the flag-21 sentinel is
 * reached and returns the last non-sentinel node.
 */
[[maybe_unused]] RbNodeFlag21Runtime* DescendLeftUntilFlag21SentinelRuntime(
  const std::uint32_t /*unused*/,
  RbNodeFlag21Runtime** const iteratorLane
) noexcept
{
  if (iteratorLane == nullptr) {
    return nullptr;
  }
  return DescendLeftUntilSentinelRuntime<RbNodeFlag21Runtime, 0x15u>(*iteratorLane);
}

/**
 * Address: 0x00856D20 (FUN_00856D20)
 *
 * What it does:
 * Descends repeatedly through `right` links until the flag-25 sentinel is
 * reached and returns the last non-sentinel node.
 */
[[maybe_unused]] MapNodeNil25Runtime* DescendRightUntilFlag25SentinelRuntime(
  const std::uint32_t /*unused*/,
  MapNodeNil25Runtime** const iteratorLane
) noexcept
{
  if (iteratorLane == nullptr) {
    return nullptr;
  }
  return DescendRightUntilSentinelRuntime<MapNodeNil25Runtime, 0x19u>(*iteratorLane);
}

/**
 * Address: 0x00856D40 (FUN_00856D40)
 *
 * What it does:
 * Descends repeatedly through `left` links until the flag-25 sentinel is
 * reached and returns the last non-sentinel node.
 */
[[maybe_unused]] MapNodeNil25Runtime* DescendLeftUntilFlag25SentinelRuntime(
  const std::uint32_t /*unused*/,
  MapNodeNil25Runtime** const iteratorLane
) noexcept
{
  if (iteratorLane == nullptr) {
    return nullptr;
  }
  return DescendLeftUntilSentinelRuntime<MapNodeNil25Runtime, 0x19u>(*iteratorLane);
}

/**
 * Address: 0x0085EEA0 (FUN_0085EEA0)
 *
 * What it does:
 * Returns the logical element count for one 52-byte legacy vector lane.
 */
[[maybe_unused]] std::int32_t CountElement52VectorRuntime(
  const LegacyVectorStorageRuntime<Element52Runtime>* const vector
) noexcept
{
  if (vector == nullptr || vector->begin == nullptr) {
    return 0;
  }
  return static_cast<std::int32_t>(vector->end - vector->begin);
}

/**
 * Address: 0x00857300 (FUN_00857300)
 *
 * What it does:
 * Copies one dword range `[sourceBegin, sourceEnd)` into storage ending at
 * `destinationEnd` and returns the destination begin lane.
 */
[[maybe_unused]] std::uint32_t* CopyDwordRangeBackwardRuntimeC(
  const std::uint32_t* const sourceEnd,
  std::uint32_t* const destinationEnd,
  const std::uint32_t* const sourceBegin
)
{
  return CopyDwordRangeBackwardByBoundsRuntime(sourceEnd, destinationEnd, sourceBegin);
}

/**
 * Address: 0x0085A250 (FUN_0085A250)
 *
 * What it does:
 * Writes `count` zeroed 16-byte lanes and returns one-past-the-last written
 * lane.
 */
[[maybe_unused]] Element16Runtime* ConstructElement16LaneRangeFromZeroRuntime(
  Element16Runtime* const destination,
  const std::uint32_t count
)
{
  if (destination == nullptr) {
    return nullptr;
  }

  const Element16Runtime zeroLane{};
  return reinterpret_cast<Element16Runtime*>(
    FillStride4DwordWithDualRefLaneRuntime(
      reinterpret_cast<std::uint32_t*>(destination),
      zeroLane.lanes,
      count
    )
  );
}

/**
 * Address: 0x0086A0F0 (FUN_0086A0F0)
 *
 * What it does:
 * Copies one dword range `[sourceBegin, sourceEnd)` into storage ending at
 * `destinationEnd` and returns the destination begin lane.
 */
[[maybe_unused]] std::uint32_t* CopyDwordRangeBackwardRuntimeD(
  const std::uint32_t* const sourceEnd,
  std::uint32_t* const destinationEnd,
  const std::uint32_t* const sourceBegin
)
{
  return CopyDwordRangeBackwardByBoundsRuntime(sourceEnd, destinationEnd, sourceBegin);
}

/**
 * Address: 0x008F67E0 (FUN_008F67E0)
 *
 * What it does:
 * Releases one `{begin,end,capacity}` storage triple and resets all three
 * cursor lanes to null.
 */
[[maybe_unused]] void ReleaseLegacyBufferTripleRuntimeC(
  LegacyBufferTripleRuntime* const owner
)
{
  ReleaseLegacyBufferTripleRuntime(owner);
}

/**
 * Address: 0x008F6FB0 (FUN_008F6FB0)
 *
 * What it does:
 * Inserts one 28-byte lane at `insertPosition` and writes the rebased cursor
 * lane into `outCursor`.
 */
[[maybe_unused]] Element28Runtime** InsertElement28LaneAndStoreRebasedCursorRuntime(
  LegacyVectorStorageRuntime<Element28Runtime>* const vector,
  Element28Runtime** const outCursor,
  Element28Runtime* const insertPosition,
  const Element28Runtime* const valueLane
)
{
  if (vector == nullptr || outCursor == nullptr) {
    return outCursor;
  }

  std::size_t index = 0u;
  if (vector->begin != nullptr && vector->end != nullptr && vector->end > vector->begin && insertPosition != nullptr) {
    index = static_cast<std::size_t>(insertPosition - vector->begin);
  }

  const Element28Runtime copy = valueLane != nullptr ? *valueLane : Element28Runtime{};
  (void)InsertTrivialValueAtPosition(vector, insertPosition, copy);
  *outCursor = vector->begin + index;
  return outCursor;
}

/**
 * Address: 0x008FA5C0 (FUN_008FA5C0)
 *
 * What it does:
 * Copies one dword range `[sourceBegin, sourceEnd)` into storage ending at
 * `destinationEnd` and returns the destination begin lane.
 */
[[maybe_unused]] std::uint32_t* CopyDwordRangeBackwardRuntimeE(
  const std::uint32_t* const sourceEnd,
  std::uint32_t* const destinationEnd,
  const std::uint32_t* const sourceBegin
)
{
  return CopyDwordRangeBackwardByBoundsRuntime(sourceEnd, destinationEnd, sourceBegin);
}

/**
 * Address: 0x00900960 (FUN_00900960)
 *
 * What it does:
 * Inserts one 0x13C-byte lane at `insertPosition` and writes the rebased
 * cursor lane into `outCursor`.
 */
[[maybe_unused]] Element316Runtime** InsertElement316LaneAndStoreRebasedCursorRuntime(
  LegacyVectorStorageRuntime<Element316Runtime>* const vector,
  Element316Runtime** const outCursor,
  Element316Runtime* const insertPosition,
  const Element316Runtime* const valueLane
)
{
  if (vector == nullptr || outCursor == nullptr) {
    return outCursor;
  }

  std::size_t index = 0u;
  if (vector->begin != nullptr && vector->end != nullptr && vector->end > vector->begin && insertPosition != nullptr) {
    index = static_cast<std::size_t>(insertPosition - vector->begin);
  }

  const Element316Runtime copy = valueLane != nullptr ? *valueLane : Element316Runtime{};
  (void)InsertTrivialValueAtPosition(vector, insertPosition, copy);
  *outCursor = vector->begin + index;
  return outCursor;
}

/**
 * Address: 0x0092DB40 (FUN_0092DB40)
 *
 * What it does:
 * Clears one intrusive-node list by unlinking all nodes from the sentinel and
 * releasing each node lane.
 */
[[maybe_unused]] IntrusiveNodeRuntime* ClearIntrusiveNodeListRuntimeA(
  IntrusiveNodeListRuntime* const list
)
{
  if (list == nullptr || list->sentinel == nullptr) {
    return nullptr;
  }

  IntrusiveNodeRuntime* const sentinel = list->sentinel;
  IntrusiveNodeRuntime* node = sentinel->next;
  sentinel->next = sentinel;
  sentinel->prev = sentinel;
  list->size = 0u;

  while (node != sentinel) {
    IntrusiveNodeRuntime* const next = node->next;
    ::operator delete(node);
    node = next;
  }
  return node;
}

/**
 * Address: 0x0092E640 (FUN_0092E640)
 *
 * What it does:
 * Erases one intrusive-node half-open range `[first,last)` from the list;
 * when the range spans the whole list, it delegates to full-list clear.
 */
[[maybe_unused]] IntrusiveNodeRuntime** EraseIntrusiveNodeRangeAndStoreCursorRuntimeA(
  IntrusiveNodeListRuntime* const list,
  IntrusiveNodeRuntime** const outCursor,
  IntrusiveNodeRuntime* first,
  IntrusiveNodeRuntime* const last
)
{
  IntrusiveNodeRuntime* const sentinel = (list != nullptr) ? list->sentinel : nullptr;
  if (list != nullptr && sentinel != nullptr && first == sentinel->next && last == sentinel) {
    (void)ClearIntrusiveNodeListRuntimeA(list);
    if (outCursor != nullptr) {
      *outCursor = sentinel;
    }
    return outCursor;
  }

  while (first != last) {
    IntrusiveNodeRuntime* const next = first->next;
    if (list != nullptr && first != sentinel) {
      first->prev->next = next;
      next->prev = first->prev;
      ::operator delete(first);
      if (list->size != 0u) {
        --list->size;
      }
    }
    first = next;
  }

  if (outCursor != nullptr) {
    *outCursor = last;
  }
  return outCursor;
}

/**
 * Address: 0x0092DE90 (FUN_0092DE90)
 *
 * What it does:
 * Erases one intrusive-node list lane, writes its successor into `outNext`,
 * and decrements list size.
 */
[[maybe_unused]] IntrusiveNodeRuntime** EraseIntrusiveNodeAndStoreNextRuntimeA(
  IntrusiveNodeListRuntime* const list,
  IntrusiveNodeRuntime** const outNext,
  IntrusiveNodeRuntime* const node
)
{
  IntrusiveNodeRuntime* next = node != nullptr ? node->next : nullptr;
  if (list != nullptr && node != nullptr && node != list->sentinel) {
    node->prev->next = next;
    next->prev = node->prev;
    ::operator delete(node);
    if (list->size != 0u) {
      --list->size;
    }
  }

  if (outNext != nullptr) {
    *outNext = next;
  }
  return outNext;
}

/**
 * Address: 0x0092ECF0 (FUN_0092ECF0)
 *
 * What it does:
 * Releases one `{begin,end,capacity}` storage triple and resets all three
 * cursor lanes to null.
 */
[[maybe_unused]] void ReleaseLegacyBufferTripleRuntimeD(
  LegacyBufferTripleRuntime* const owner
)
{
  ReleaseLegacyBufferTripleRuntime(owner);
}

/**
 * Address: 0x0092FCD0 (FUN_0092FCD0)
 *
 * What it does:
 * Inserts one 12-byte lane at `insertPosition` and writes the rebased cursor
 * lane into `outCursor`.
 */
[[maybe_unused]] Element12Runtime** InsertElement12LaneAndStoreRebasedCursorRuntimeB(
  LegacyVectorStorageRuntime<Element12Runtime>* const vector,
  Element12Runtime** const outCursor,
  Element12Runtime* const insertPosition,
  const Element12Runtime* const valueLane
)
{
  if (vector == nullptr || outCursor == nullptr) {
    return outCursor;
  }

  std::size_t index = 0u;
  if (vector->begin != nullptr && vector->end != nullptr && vector->end > vector->begin && insertPosition != nullptr) {
    index = static_cast<std::size_t>(insertPosition - vector->begin);
  }

  const Element12Runtime copy = valueLane != nullptr ? *valueLane : Element12Runtime{};
  (void)InsertTrivialValueAtPosition(vector, insertPosition, copy);
  *outCursor = vector->begin + index;
  return outCursor;
}

/**
 * Address: 0x0092FD40 (FUN_0092FD40)
 *
 * What it does:
 * Allocates one 40-byte intrusive payload node, inserts it before
 * `insertBefore`, and increments the owning list size lane.
 */
[[maybe_unused]] std::int32_t InsertNode32BeforeAndGrowListRuntime(
  IntrusivePayloadListRuntime* const list,
  IntrusivePayloadNode32Runtime* const insertBefore,
  const std::uint32_t* const payloadWords
)
{
  IntrusivePayloadNode32Runtime* const node = AllocateIntrusivePayloadNode32(insertBefore, insertBefore->prev, payloadWords);
  const std::uint32_t size = IncrementIntrusivePayloadListSizeWithBound(list, 0x07FFFFFFu);
  insertBefore->prev = node;
  node->prev->next = node;
  return static_cast<std::int32_t>(size);
}

/**
 * Address: 0x00930000 (FUN_00930000)
 *
 * What it does:
 * Inserts one 12-byte lane at `insertPosition` and writes the rebased cursor
 * lane into `outCursor`.
 */
[[maybe_unused]] Element12Runtime** InsertElement12LaneAndStoreRebasedCursorRuntimeC(
  LegacyVectorStorageRuntime<Element12Runtime>* const vector,
  Element12Runtime** const outCursor,
  Element12Runtime* const insertPosition,
  const Element12Runtime* const valueLane
)
{
  return InsertElement12LaneAndStoreRebasedCursorRuntimeB(vector, outCursor, insertPosition, valueLane);
}

/**
 * Address: 0x00930070 (FUN_00930070)
 *
 * What it does:
 * Resets one 16-bit vector storage lane, optionally allocates `count` entries,
 * and sets `{begin,end,capacity}` to the allocated range.
 */
[[maybe_unused]] bool InitializeWordVectorStorageRuntime(
  LegacyVectorStorageRuntime<std::uint16_t>* const vector,
  const std::uint32_t count
)
{
  vector->begin = nullptr;
  vector->end = nullptr;
  vector->capacity = nullptr;

  if (count == 0u) {
    return false;
  }

  if (count > 0x7FFFFFFFu) {
    throw std::length_error("vector<T> too long");
  }

  auto* const storage = static_cast<std::uint16_t*>(::operator new(static_cast<std::size_t>(count) * sizeof(std::uint16_t)));
  vector->begin = storage;
  vector->end = storage;
  vector->capacity = storage + count;
  return true;
}

/**
 * Address: 0x00930220 (FUN_00930220)
 *
 * What it does:
 * Allocates one 40-byte intrusive payload node, inserts it before
 * `insertBefore`, increments list size, and stores the inserted-node cursor.
 */
[[maybe_unused]] IntrusivePayloadNode32Runtime** InsertNode32BeforeAndGrowListStoreCursorRuntime(
  IntrusivePayloadListRuntime* const list,
  IntrusivePayloadNode32Runtime** const outCursor,
  IntrusivePayloadNode32Runtime* const insertBefore,
  const std::uint32_t* const payloadWords
)
{
  IntrusivePayloadNode32Runtime* const node = AllocateIntrusivePayloadNode32(insertBefore, insertBefore->prev, payloadWords);
  (void)IncrementIntrusivePayloadListSizeWithBound(list, 0x07FFFFFFu);
  insertBefore->prev = node;
  node->prev->next = node;
  *outCursor = insertBefore->prev;
  return outCursor;
}

/**
 * Address: 0x00930440 (FUN_00930440)
 *
 * What it does:
 * Acquires one slot id from a free-list lane when available; otherwise appends
 * one new pointer lane and returns its index.
 */
[[maybe_unused]] std::int32_t AcquireOrReusePointerSlotRuntime(
  std::int32_t* const freeHead,
  LegacyVectorStorageRuntime<std::int32_t*>* const vector,
  std::int32_t* const value
)
{
  if (freeHead == nullptr || vector == nullptr) {
    return -1;
  }

  if (*freeHead == -1) {
    const std::int32_t index = static_cast<std::int32_t>(VectorSize(*vector));
    (void)AppendTrivialValue(vector, value);
    return index;
  }

  const std::int32_t reusedIndex = *freeHead;
  if (vector->begin == nullptr || reusedIndex < 0) {
    return -1;
  }

  *freeHead = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(vector->begin[reusedIndex]));
  vector->begin[reusedIndex] = value;
  return reusedIndex;
}

/**
 * Address: 0x00932760 (FUN_00932760)
 *
 * What it does:
 * Clears one intrusive-node list by unlinking all nodes from the sentinel and
 * releasing each node lane.
 */
[[maybe_unused]] IntrusiveNodeRuntime* ClearIntrusiveNodeListRuntimeB(
  IntrusiveNodeListRuntime* const list
)
{
  return ClearIntrusiveNodeListRuntimeA(list);
}

/**
 * Address: 0x00932D40 (FUN_00932D40)
 *
 * What it does:
 * Erases one intrusive-node half-open range `[first,last)` from the list;
 * when the range spans the whole list, it delegates to full-list clear.
 */
[[maybe_unused]] IntrusiveNodeRuntime** EraseIntrusiveNodeRangeAndStoreCursorRuntimeB(
  IntrusiveNodeListRuntime* const list,
  IntrusiveNodeRuntime** const outCursor,
  IntrusiveNodeRuntime* first,
  IntrusiveNodeRuntime* const last
)
{
  IntrusiveNodeRuntime* const sentinel = (list != nullptr) ? list->sentinel : nullptr;
  if (list != nullptr && sentinel != nullptr && first == sentinel->next && last == sentinel) {
    (void)ClearIntrusiveNodeListRuntimeB(list);
    if (outCursor != nullptr) {
      *outCursor = sentinel;
    }
    return outCursor;
  }

  while (first != last) {
    IntrusiveNodeRuntime* const next = first->next;
    if (list != nullptr && first != sentinel) {
      first->prev->next = next;
      next->prev = first->prev;
      ::operator delete(first);
      if (list->size != 0u) {
        --list->size;
      }
    }
    first = next;
  }

  if (outCursor != nullptr) {
    *outCursor = last;
  }
  return outCursor;
}

/**
 * Address: 0x00932880 (FUN_00932880)
 *
 * What it does:
 * Erases one intrusive-node list lane, writes its successor into `outNext`,
 * and decrements list size.
 */
[[maybe_unused]] IntrusiveNodeRuntime** EraseIntrusiveNodeAndStoreNextRuntimeB(
  IntrusiveNodeListRuntime* const list,
  IntrusiveNodeRuntime** const outNext,
  IntrusiveNodeRuntime* const node
)
{
  return EraseIntrusiveNodeAndStoreNextRuntimeA(list, outNext, node);
}

/**
 * Address: 0x00933120 (FUN_00933120)
 *
 * What it does:
 * Releases one `{begin,end,capacity}` storage triple and resets all three
 * cursor lanes to null.
 */
[[maybe_unused]] void ReleaseLegacyBufferTripleRuntimeE(
  LegacyBufferTripleRuntime* const owner
)
{
  ReleaseLegacyBufferTripleRuntime(owner);
}

/**
 * Address: 0x00933150 (FUN_00933150)
 *
 * What it does:
 * Releases one `{begin,end,capacity}` storage triple and resets all three
 * cursor lanes to null.
 */
[[maybe_unused]] void ReleaseLegacyBufferTripleRuntimeF(
  LegacyBufferTripleRuntime* const owner
)
{
  ReleaseLegacyBufferTripleRuntime(owner);
}

/**
 * Address: 0x00933600 (FUN_00933600)
 *
 * What it does:
 * Allocates one 32-byte intrusive payload node, inserts it before
 * `insertBefore`, and increments the owning list size lane.
 */
[[maybe_unused]] std::int32_t InsertNode24BeforeAndGrowListRuntime(
  IntrusivePayloadListRuntime* const list,
  IntrusivePayloadNode24Runtime* const insertBefore,
  const std::uint32_t* const payloadWords
)
{
  IntrusivePayloadNode24Runtime* const node = AllocateIntrusivePayloadNode24(insertBefore, insertBefore->prev, payloadWords);
  const std::uint32_t size = IncrementIntrusivePayloadListSizeWithBound(list, 178956970u);
  insertBefore->prev = node;
  node->prev->next = node;
  return static_cast<std::int32_t>(size);
}

/**
 * Address: 0x00934040 (FUN_00934040)
 *
 * What it does:
 * Allocates one 32-byte intrusive payload node, inserts it before
 * `insertBefore`, increments list size, and stores the inserted-node cursor.
 */
[[maybe_unused]] IntrusivePayloadNode24Runtime** InsertNode24BeforeAndGrowListStoreCursorRuntime(
  IntrusivePayloadListRuntime* const list,
  IntrusivePayloadNode24Runtime** const outCursor,
  IntrusivePayloadNode24Runtime* const insertBefore,
  const std::uint32_t* const payloadWords
)
{
  IntrusivePayloadNode24Runtime* const node = AllocateIntrusivePayloadNode24(insertBefore, insertBefore->prev, payloadWords);
  (void)IncrementIntrusivePayloadListSizeWithBound(list, 178956970u);
  insertBefore->prev = node;
  node->prev->next = node;
  *outCursor = insertBefore->prev;
  return outCursor;
}

/**
 * Address: 0x00936330 (FUN_00936330)
 *
 * What it does:
 * Copies one dword range `[sourceBegin, sourceEnd)` into storage ending at
 * `destinationEnd` and returns the destination begin lane.
 */
[[maybe_unused]] std::uint32_t* CopyDwordRangeBackwardRuntimeF(
  const std::uint32_t* const sourceEnd,
  std::uint32_t* const destinationEnd,
  const std::uint32_t* const sourceBegin
)
{
  return CopyDwordRangeBackwardByBoundsRuntime(sourceEnd, destinationEnd, sourceBegin);
}

/**
 * Address: 0x009401C0 (FUN_009401C0)
 *
 * What it does:
 * Inserts one 60-byte lane at `insertPosition` and writes the rebased cursor
 * lane into `outCursor`.
 */
[[maybe_unused]] Element60Runtime** InsertElement60LaneAndStoreRebasedCursorRuntime(
  LegacyVectorStorageRuntime<Element60Runtime>* const vector,
  Element60Runtime** const outCursor,
  Element60Runtime* const insertPosition,
  const Element60Runtime* const valueLane
)
{
  if (vector == nullptr || outCursor == nullptr) {
    return outCursor;
  }

  std::size_t index = 0u;
  if (vector->begin != nullptr && vector->end != nullptr && vector->end > vector->begin && insertPosition != nullptr) {
    index = static_cast<std::size_t>(insertPosition - vector->begin);
  }

  const Element60Runtime copy = valueLane != nullptr ? *valueLane : Element60Runtime{};
  (void)InsertTrivialValueAtPosition(vector, insertPosition, copy);
  *outCursor = vector->begin + index;
  return outCursor;
}

/**
 * Address: 0x0085A920 (FUN_0085A920)
 *
 * What it does:
 * Writes one repeated 4-dword payload lane and retains two intrusive weak-count
 * lanes (`+0x04`, `+0x0C`) in each destination record.
 */
[[maybe_unused]] std::uint32_t* FillStride4DwordWithDualRefLaneRuntime(
  std::uint32_t* destination,
  const std::uint32_t* const source,
  std::uint32_t count
)
{
  while (count != 0u) {
    if (destination != nullptr) {
      destination[0] = source[0];
      destination[1] = source[1];
      if (destination[1] != 0u) {
        (void)::InterlockedExchangeAdd(reinterpret_cast<volatile LONG*>(destination[1] + 4u), 1);
      }

      destination[2] = source[2];
      destination[3] = source[3];
      if (destination[3] != 0u) {
        (void)::InterlockedExchangeAdd(reinterpret_cast<volatile LONG*>(destination[3] + 4u), 1);
      }
      destination += 4;
    }
    --count;
  }
  return destination;
}

/**
 * Address: 0x0085A7C0 (FUN_0085A7C0)
 *
 * What it does:
 * Compatibility adapter lane that forwards one null-source, zero-count
 * dispatch into `FillStride4DwordWithDualRefLaneRuntime(...)`.
 */
[[maybe_unused]] std::uint32_t* FillStride4DwordWithDualRefLaneRuntimeNullAdapter(
  [[maybe_unused]] const std::uint32_t* const unusedSourceLane,
  std::uint32_t* const destination
)
{
  return FillStride4DwordWithDualRefLaneRuntime(destination, nullptr, 0u);
}

/**
 * Address: 0x00861D10 (FUN_00861D10)
 *
 * What it does:
 * Moves one RB-tree iterator lane forward using sentinel flag offset
 * `+0x0C49`.
 */
[[maybe_unused]] RbNodeLinksRuntime* AdvanceTreeIteratorFlag3145Runtime(
  const std::uint32_t /*unused*/,
  RbNodeLinksRuntime** const iteratorLane
)
{
  return AdvanceRbIteratorRuntime<RbNodeLinksRuntime, 0x0C49u>(iteratorLane);
}

/**
 * Address: 0x00861FA0 (FUN_00861FA0)
 *
 * What it does:
 * Moves one RB-tree iterator lane backward using sentinel flag offset `+0x0C49`.
 */
[[maybe_unused]] RbNodeLinksRuntime* RetreatTreeIteratorFlag3145Runtime(
  const std::uint32_t /*unused*/,
  RbNodeLinksRuntime** const iteratorLane
)
{
  return RetreatRbIteratorRuntime<RbNodeLinksRuntime, 0x0C49u>(iteratorLane);
}

/**
 * Address: 0x00861C70 (FUN_00861C70)
 *
 * What it does:
 * Walks the global flag-3145 RB-tree and returns the lower-bound node address
 * for `*keyLane`; returns the sentinel owner lane when no candidate is found.
 */
[[maybe_unused]] std::uintptr_t FindLowerBoundInGlobalFlag3145TreeRuntime(
  const std::uintptr_t /*unusedOwner*/,
  const std::uint32_t* const keyLane
) noexcept
{
  std::uintptr_t result = reinterpret_cast<std::uintptr_t>(gFlag3145TreeSentinelRuntime);
  if (gFlag3145TreeSentinelRuntime == nullptr || keyLane == nullptr) {
    return result;
  }

  RbNodeKeyFlag3145Runtime* node = gFlag3145TreeSentinelRuntime->root;
  if (node == nullptr || node->isNil3145 != 0u) {
    return result;
  }

  const std::uint32_t key = *keyLane;
  do {
    if (node->key >= key) {
      result = reinterpret_cast<std::uintptr_t>(node);
      node = node->left;
    } else {
      node = node->right;
    }
  } while (node != nullptr && node->isNil3145 == 0u);

  return result;
}

/**
 * Address: 0x008616B0 (FUN_008616B0)
 *
 * What it does:
 * Descends repeatedly through `right` links until the flag-3145 sentinel is
 * reached and returns the last non-sentinel node.
 */
[[maybe_unused]] RbNodeLinksRuntime* DescendRightUntilFlag3145SentinelRuntime(
  const std::uint32_t /*unused*/,
  RbNodeLinksRuntime** const iteratorLane
) noexcept
{
  if (iteratorLane == nullptr) {
    return nullptr;
  }
  return DescendRightUntilSentinelRuntime<RbNodeLinksRuntime, 0x0C49u>(*iteratorLane);
}

/**
 * Address: 0x008616D0 (FUN_008616D0)
 *
 * What it does:
 * Descends repeatedly through `left` links until the flag-3145 sentinel is
 * reached and returns the last non-sentinel node.
 */
[[maybe_unused]] RbNodeLinksRuntime* DescendLeftUntilFlag3145SentinelRuntime(
  const std::uint32_t /*unused*/,
  RbNodeLinksRuntime** const iteratorLane
) noexcept
{
  if (iteratorLane == nullptr) {
    return nullptr;
  }
  return DescendLeftUntilSentinelRuntime<RbNodeLinksRuntime, 0x0C49u>(*iteratorLane);
}

/**
 * Address: 0x008678E0 (FUN_008678E0)
 *
 * What it does:
 * Returns the logical element count for one 12-byte legacy vector lane.
 */
[[maybe_unused]] std::int32_t CountElement12VectorRuntimeC(
  const LegacyVectorStorageRuntime<Element12Runtime>* const vector
) noexcept
{
  return CountElement12VectorRuntimeB(vector);
}

/**
 * Address: 0x00867E90 (FUN_00867E90)
 * Address: 0x008B3130 (FUN_008B3130)
 *
 * What it does:
 * Resolves one equal-range pair in a flag-25 RB-map:
 * `outPair[0] = lower_bound(key)`, `outPair[1] = upper_bound(key)`.
 */
[[maybe_unused]] MapNodeNil25Runtime** FindMapEqualRangeFlag25Runtime(
  MapNodeNil25Runtime** const outPair,
  LegacyMapStorageRuntime<MapNodeNil25Runtime>* const map,
  const std::uint32_t* const keyLane
) noexcept
{
  if (outPair == nullptr) {
    return nullptr;
  }

  MapNodeNil25Runtime* head = nullptr;
  if (map != nullptr) {
    head = map->head;
  }

  const std::uint32_t key = keyLane != nullptr ? *keyLane : 0u;
  FindMapEqualRangeByKeyRuntime(head, key, &outPair[0], &outPair[1]);
  return outPair;
}

/**
 * Address: 0x0086DB30 (FUN_0086DB30)
 *
 * What it does:
 * Resolves one owner pointer from an assisting-unit owner-slot lane
 * (`ownerLinkSlot - 8`), returning null when no slot is linked.
 */
[[maybe_unused]] void* ResolveAssistingUnitOwnerRuntime(
  const AssistingUnitListOwnerRuntime* const owner
) noexcept
{
  if (owner == nullptr || owner->ownerLinkSlot == nullptr) {
    return nullptr;
  }
  return static_cast<void*>(static_cast<std::byte*>(owner->ownerLinkSlot) - 8u);
}

/**
 * Address: 0x00873810 (FUN_00873810)
 *
 * What it does:
 * Rebinds one intrusive owner-slot node to the owner head slot at
 * `requestedOwner + 0x04`.
 */
[[maybe_unused]] IntrusiveOwnerSlotRuntime* RebindIntrusiveOwnerSlotNodeRuntimeC(
  IntrusiveOwnerSlotRuntime* const node,
  IntrusiveOwnerAnchorRuntime* const requestedOwner
) noexcept
{
  return RebindIntrusiveOwnerSlotNodeRuntimeB(node, requestedOwner);
}

/**
 * Address: 0x008792A0 (FUN_008792A0)
 *
 * What it does:
 * Finds one exact key match in a flag-21 RB-map and returns the node when
 * present; otherwise returns the map head/sentinel node.
 */
[[maybe_unused]] MapNodeNil21Runtime** FindExactMapNodeFlag21RuntimeA(
  MapNodeNil21Runtime** const outNode,
  LegacyMapStorageRuntime<MapNodeNil21Runtime>* const map,
  const std::uint32_t* const keyLane
) noexcept
{
  if (outNode == nullptr) {
    return nullptr;
  }

  MapNodeNil21Runtime* head = nullptr;
  if (map != nullptr) {
    head = map->head;
  }

  const std::uint32_t key = keyLane != nullptr ? *keyLane : 0u;
  *outNode = FindMapNodeEqualOrHeadByKeyRuntime(head, key);
  return outNode;
}

/**
 * Address: 0x008795D0 (FUN_008795D0)
 *
 * What it does:
 * Finds one exact key match in a flag-21 RB-map and returns the node when
 * present; otherwise returns the map head/sentinel node.
 */
[[maybe_unused]] MapNodeNil21Runtime** FindExactMapNodeFlag21RuntimeB(
  MapNodeNil21Runtime** const outNode,
  LegacyMapStorageRuntime<MapNodeNil21Runtime>* const map,
  const std::uint32_t* const keyLane
) noexcept
{
  return FindExactMapNodeFlag21RuntimeA(outNode, map, keyLane);
}

/**
 * Address: 0x00879D50 (FUN_00879D50)
 *
 * What it does:
 * Resolves one equal-range pair in a flag-21 RB-map:
 * `outPair[0] = lower_bound(key)`, `outPair[1] = upper_bound(key)`.
 */
[[maybe_unused]] MapNodeNil21Runtime** FindMapEqualRangeFlag21RuntimeA(
  MapNodeNil21Runtime** const outPair,
  LegacyMapStorageRuntime<MapNodeNil21Runtime>* const map,
  const std::uint32_t* const keyLane
) noexcept
{
  if (outPair == nullptr) {
    return nullptr;
  }

  MapNodeNil21Runtime* head = nullptr;
  if (map != nullptr) {
    head = map->head;
  }

  const std::uint32_t key = keyLane != nullptr ? *keyLane : 0u;
  FindMapEqualRangeByKeyRuntime(head, key, &outPair[0], &outPair[1]);
  return outPair;
}

/**
 * Address: 0x0087A1A0 (FUN_0087A1A0)
 *
 * What it does:
 * Resolves one equal-range pair in a flag-21 RB-map:
 * `outPair[0] = lower_bound(key)`, `outPair[1] = upper_bound(key)`.
 */
[[maybe_unused]] MapNodeNil21Runtime** FindMapEqualRangeFlag21RuntimeB(
  MapNodeNil21Runtime** const outPair,
  LegacyMapStorageRuntime<MapNodeNil21Runtime>* const map,
  const std::uint32_t* const keyLane
) noexcept
{
  return FindMapEqualRangeFlag21RuntimeA(outPair, map, keyLane);
}

/**
 * Address: 0x0087C2E0 (FUN_0087C2E0)
 *
 * What it does:
 * Descends repeatedly through `right` links until the flag-21 sentinel is
 * reached and returns the last non-sentinel node.
 */
[[maybe_unused]] RbNodeFlag21Runtime* DescendRightUntilFlag21SentinelRuntimeA(
  const std::uint32_t /*unused*/,
  RbNodeFlag21Runtime** const iteratorLane
) noexcept
{
  if (iteratorLane == nullptr) {
    return nullptr;
  }
  return DescendRightUntilSentinelRuntime<RbNodeFlag21Runtime, 0x15u>(*iteratorLane);
}

/**
 * Address: 0x0087C300 (FUN_0087C300)
 *
 * What it does:
 * Descends repeatedly through `left` links until the flag-21 sentinel is
 * reached and returns the last non-sentinel node.
 */
[[maybe_unused]] RbNodeFlag21Runtime* DescendLeftUntilFlag21SentinelRuntimeA(
  const std::uint32_t /*unused*/,
  RbNodeFlag21Runtime** const iteratorLane
) noexcept
{
  if (iteratorLane == nullptr) {
    return nullptr;
  }
  return DescendLeftUntilSentinelRuntime<RbNodeFlag21Runtime, 0x15u>(*iteratorLane);
}

/**
 * Address: 0x0087C520 (FUN_0087C520)
 *
 * What it does:
 * Descends repeatedly through `right` links until the flag-21 sentinel is
 * reached and returns the last non-sentinel node.
 */
[[maybe_unused]] RbNodeFlag21Runtime* DescendRightUntilFlag21SentinelRuntimeB(
  const std::uint32_t /*unused*/,
  RbNodeFlag21Runtime** const iteratorLane
) noexcept
{
  return DescendRightUntilFlag21SentinelRuntimeA(0u, iteratorLane);
}

/**
 * Address: 0x0087C540 (FUN_0087C540)
 *
 * What it does:
 * Descends repeatedly through `left` links until the flag-21 sentinel is
 * reached and returns the last non-sentinel node.
 */
[[maybe_unused]] RbNodeFlag21Runtime* DescendLeftUntilFlag21SentinelRuntimeB(
  const std::uint32_t /*unused*/,
  RbNodeFlag21Runtime** const iteratorLane
) noexcept
{
  return DescendLeftUntilFlag21SentinelRuntimeA(0u, iteratorLane);
}

/**
 * Address: 0x0087CCB0 (FUN_0087CCB0)
 *
 * What it does:
 * Moves one RB-tree iterator lane backward using sentinel flag offset `+0x15`.
 */
[[maybe_unused]] RbNodeFlag21Runtime* RetreatTreeIteratorFlag21RuntimeB(
  const std::uint32_t /*unused*/,
  RbNodeFlag21Runtime** const iteratorLane
)
{
  return RetreatRbIteratorRuntime<RbNodeFlag21Runtime, 0x15u>(iteratorLane);
}

/**
 * Address: 0x0087CD70 (FUN_0087CD70)
 *
 * What it does:
 * Moves one RB-tree iterator lane backward using sentinel flag offset `+0x15`.
 */
[[maybe_unused]] RbNodeFlag21Runtime* RetreatTreeIteratorFlag21RuntimeC(
  const std::uint32_t /*unused*/,
  RbNodeFlag21Runtime** const iteratorLane
)
{
  return RetreatRbIteratorRuntime<RbNodeFlag21Runtime, 0x15u>(iteratorLane);
}

/**
 * Address: 0x0087CEC0 (FUN_0087CEC0)
 *
 * What it does:
 * Advances one RB-tree iterator lane using sentinel flag offset `+0x11`.
 */
[[maybe_unused]] MapNodeNil17Runtime* AdvanceTreeIteratorFlag17RuntimeA(
  const std::uint32_t /*unused*/,
  MapNodeNil17Runtime** const iteratorLane
)
{
  return AdvanceRbIteratorRuntime<MapNodeNil17Runtime, 0x11u>(iteratorLane);
}

/**
 * Address: 0x008A9720 (FUN_008A9720)
 *
 * What it does:
 * Moves one RB-tree iterator lane backward using sentinel flag offset `+0x4D`.
 */
[[maybe_unused]] RbNodeLinksRuntime* RetreatTreeIteratorFlag77Runtime(
  const std::uint32_t /*unused*/,
  RbNodeLinksRuntime** const iteratorLane
)
{
  return RetreatRbIteratorRuntime<RbNodeLinksRuntime, 0x4Du>(iteratorLane);
}

/**
 * Address: 0x008AF6A0 (FUN_008AF6A0)
 *
 * What it does:
 * Advances one RB-tree iterator lane using sentinel flag offset `+0x11`.
 */
[[maybe_unused]] MapNodeNil17Runtime* AdvanceTreeIteratorFlag17RuntimeB(
  const std::uint32_t /*unused*/,
  MapNodeNil17Runtime** const iteratorLane
)
{
  return AdvanceRbIteratorRuntime<MapNodeNil17Runtime, 0x11u>(iteratorLane);
}

/**
 * Address: 0x008B3870 (FUN_008B3870)
 *
 * What it does:
 * Rebinds a contiguous lane of intrusive owner-slot nodes so each destination
 * node is linked at the head of the source owner slot.
 */
[[maybe_unused]] std::uint32_t* RebindIntrusiveOwnerSlotRangeRuntime(
  std::uint32_t* destination,
  const std::uint32_t* sourceBegin,
  const std::uint32_t* const sourceEnd
)
{
  while (sourceBegin != sourceEnd) {
    auto* const destinationNode = reinterpret_cast<IntrusiveOwnerSlotRuntime*>(destination);
    const auto* const sourceNode = reinterpret_cast<const IntrusiveOwnerSlotRuntime*>(sourceBegin);
    if (destinationNode->ownerSlot != sourceNode->ownerSlot) {
      if (destinationNode->ownerSlot != nullptr) {
        IntrusiveOwnerSlotRuntime** cursor = destinationNode->ownerSlot;
        while (*cursor != destinationNode) {
          cursor = &(*cursor)->next;
        }
        *cursor = destinationNode->next;
      }

      destinationNode->ownerSlot = sourceNode->ownerSlot;
      if (sourceNode->ownerSlot == nullptr) {
        destinationNode->next = nullptr;
      } else {
        destinationNode->next = *sourceNode->ownerSlot;
        *sourceNode->ownerSlot = destinationNode;
      }
    }

    destination += 2;
    sourceBegin += 2;
  }

  return destination;
}

/**
 * Address: 0x008B35F0 (FUN_008B35F0)
 * Address: 0x008B7F80 (FUN_008B7F80)
 *
 * What it does:
 * Register-order adapter that forwards intrusive owner-slot range rebinding
 * into `RebindIntrusiveOwnerSlotRangeRuntime`.
 */
[[maybe_unused]] std::uint32_t* RebindIntrusiveOwnerSlotRangeSourceFirstAdapter(
  const std::uint32_t* const sourceBegin,
  const std::uint32_t* const sourceEnd,
  std::uint32_t* const destination
)
{
  return RebindIntrusiveOwnerSlotRangeRuntime(destination, sourceBegin, sourceEnd);
}

/**
 * Address: 0x008CBEC0 (FUN_008CBEC0)
 *
 * What it does:
 * Moves one RB-tree iterator lane backward using sentinel flag offset `+0x39`.
 */
[[maybe_unused]] RbNodeLinksRuntime* RetreatTreeIteratorFlag57Runtime(
  const std::uint32_t /*unused*/,
  RbNodeLinksRuntime** const iteratorLane
)
{
  return RetreatRbIteratorRuntime<RbNodeLinksRuntime, 0x39u>(iteratorLane);
}

/**
 * Address: 0x008D6C90 (FUN_008D6C90)
 *
 * What it does:
 * Advances one RB-tree iterator lane using sentinel flag offset `+0x1D`.
 */
[[maybe_unused]] MapNodeNil29Runtime* AdvanceTreeIteratorFlag29RuntimeA(
  const std::uint32_t /*unused*/,
  MapNodeNil29Runtime** const iteratorLane
)
{
  return AdvanceRbIteratorRuntime<MapNodeNil29Runtime, 0x1Du>(iteratorLane);
}

/**
 * Address: 0x008D8E50 (FUN_008D8E50)
 *
 * What it does:
 * Moves one map iterator lane backward using sentinel flag offset `+0x15`.
 */
[[maybe_unused]] RbNodeFlag21Runtime* RetreatMapIteratorFlag21RuntimeA(
  RbNodeFlag21Runtime** const iteratorLane
)
{
  return RetreatRbIteratorRuntime<RbNodeFlag21Runtime, 0x15u>(iteratorLane);
}

/**
 * Address: 0x008D99F0 (FUN_008D99F0)
 *
 * What it does:
 * Advances one map iterator lane using sentinel flag offset `+0x15`.
 */
[[maybe_unused]] RbNodeFlag21Runtime* AdvanceMapIteratorFlag21RuntimeC(
  RbNodeFlag21Runtime** const iteratorLane
)
{
  return AdvanceRbIteratorRuntime<RbNodeFlag21Runtime, 0x15u>(iteratorLane);
}

/**
 * Address: 0x00948870 (FUN_00948870)
 *
 * What it does:
 * Moves one map iterator lane backward using sentinel flag offset `+0x15`.
 */
[[maybe_unused]] RbNodeFlag21Runtime* RetreatMapIteratorFlag21RuntimeB(
  RbNodeFlag21Runtime** const iteratorLane
)
{
  return RetreatRbIteratorRuntime<RbNodeFlag21Runtime, 0x15u>(iteratorLane);
}

/**
 * Address: 0x00948BA0 (FUN_00948BA0)
 *
 * What it does:
 * Preserves one `thiscall` adapter lane that retreats a flag-21 map iterator
 * and then returns the original owner pointer.
 */
[[maybe_unused]] [[nodiscard]] void* RetreatMapIteratorFlag21OwnerAdapterLaneA(
  void* const iteratorOwner
)
{
  (void)RetreatRbIteratorRuntime<RbNodeFlag21Runtime, 0x15u>(
    reinterpret_cast<RbNodeFlag21Runtime**>(iteratorOwner)
  );
  return iteratorOwner;
}

/**
 * Address: 0x00948BB0 (FUN_00948BB0)
 *
 * What it does:
 * Preserves one `thiscall` adapter lane that retreats a flag-21 map iterator
 * and then returns the original owner pointer.
 */
[[maybe_unused]] [[nodiscard]] void* RetreatMapIteratorFlag21OwnerAdapterLaneB(
  void* const iteratorOwner
)
{
  (void)RetreatRbIteratorRuntime<RbNodeFlag21Runtime, 0x15u>(
    reinterpret_cast<RbNodeFlag21Runtime**>(iteratorOwner)
  );
  return iteratorOwner;
}

/**
 * Address: 0x00948BC0 (FUN_00948BC0)
 *
 * What it does:
 * Preserves one `thiscall` adapter lane that retreats a flag-21 map iterator
 * and then returns the original owner pointer.
 */
[[maybe_unused]] [[nodiscard]] void* RetreatMapIteratorFlag21OwnerAdapterLaneC(
  void* const iteratorOwner
)
{
  (void)RetreatRbIteratorRuntime<RbNodeFlag21Runtime, 0x15u>(
    reinterpret_cast<RbNodeFlag21Runtime**>(iteratorOwner)
  );
  return iteratorOwner;
}

/**
 * Address: 0x00948C90 (FUN_00948C90)
 *
 * What it does:
 * Preserves one `thiscall` adapter lane that retreats a flag-21 map iterator
 * and then returns the original owner pointer.
 */
[[maybe_unused]] [[nodiscard]] void* RetreatMapIteratorFlag21OwnerAdapterLaneD(
  void* const iteratorOwner
)
{
  (void)RetreatRbIteratorRuntime<RbNodeFlag21Runtime, 0x15u>(
    reinterpret_cast<RbNodeFlag21Runtime**>(iteratorOwner)
  );
  return iteratorOwner;
}

/**
 * Address: 0x00948CA0 (FUN_00948CA0)
 *
 * What it does:
 * Preserves one `thiscall` adapter lane that retreats a flag-21 map iterator
 * and then returns the original owner pointer.
 */
[[maybe_unused]] [[nodiscard]] void* RetreatMapIteratorFlag21OwnerAdapterLaneE(
  void* const iteratorOwner
)
{
  (void)RetreatRbIteratorRuntime<RbNodeFlag21Runtime, 0x15u>(
    reinterpret_cast<RbNodeFlag21Runtime**>(iteratorOwner)
  );
  return iteratorOwner;
}

/**
 * Address: 0x00948CB0 (FUN_00948CB0)
 *
 * What it does:
 * Preserves one `thiscall` adapter lane that retreats a flag-21 map iterator
 * and then returns the original owner pointer.
 */
[[maybe_unused]] [[nodiscard]] void* RetreatMapIteratorFlag21OwnerAdapterLaneF(
  void* const iteratorOwner
)
{
  (void)RetreatRbIteratorRuntime<RbNodeFlag21Runtime, 0x15u>(
    reinterpret_cast<RbNodeFlag21Runtime**>(iteratorOwner)
  );
  return iteratorOwner;
}

/**
 * Address: 0x009A8550 (FUN_009A8550)
 *
 * What it does:
 * Finds one integer value lane in a runtime array either forward or reverse.
 */
[[maybe_unused]] int FindIntArrayIndexRuntime(
  const IntArrayLookupRuntime* const runtime,
  const int value,
  const bool reverseSearch
)
{
  if (runtime == nullptr || runtime->values == nullptr || runtime->count == 0u) {
    return -1;
  }

  if (reverseSearch) {
    for (int index = static_cast<int>(runtime->count) - 1; index >= 0; --index) {
      if (runtime->values[index] == value) {
        return index;
      }
    }
    return -1;
  }

  for (std::uint32_t index = 0; index < runtime->count; ++index) {
    if (runtime->values[index] == value) {
      return static_cast<int>(index);
    }
  }
  return -1;
}

/**
 * Address: 0x00A0D5A0 (FUN_00A0D5A0)
 *
 * What it does:
 * Thunk lane that forwards one integer-array lookup request into
 * `FUN_009A8550`.
 */
[[maybe_unused]] int FindIntArrayIndexRuntimeAdapterLaneB(
  const IntArrayLookupRuntime* const runtime,
  const int value,
  const bool reverseSearch
)
{
  return FindIntArrayIndexRuntime(runtime, value, reverseSearch);
}

/**
 * Address: 0x009F0050 (FUN_009F0050)
 *
 * What it does:
 * Thunk lane that forwards one integer-array lookup request into
 * `FUN_009A8550`.
 */
[[maybe_unused]] int FindIntArrayIndexRuntimeAdapter(
  const IntArrayLookupRuntime* const runtime,
  const int value,
  const bool reverseSearch
)
{
  return FindIntArrayIndexRuntime(runtime, value, reverseSearch);
}

/**
 * Address: 0x009B36D0 (FUN_009B36D0)
 *
 * What it does:
 * Dispatches virtual slot `+0x2C` on one polymorphic runtime object.
 */
[[maybe_unused]] int DispatchVirtualSlot44Runtime(
  VirtualDispatch44Runtime* const runtime
)
{
  if (runtime == nullptr || runtime->vtable == nullptr) {
    return 0;
  }

  using SlotFn = int (__thiscall*)(void*);
  const auto fn = reinterpret_cast<SlotFn>(runtime->vtable[11]);
  return fn != nullptr ? fn(runtime) : 0;
}

/**
 * Address: 0x00A6D420 (FUN_00A6D420)
 *
 * What it does:
 * Snapshots one 2x2 float basis lane into outputs and resets the live basis to
 * identity.
 */
[[maybe_unused]] std::uint32_t SnapshotAndResetBasis2fRuntime(
  BasisPointerResetRuntimeF* const runtime
)
{
  if (runtime == nullptr || runtime->basisPair == nullptr || runtime->outputPrimary == nullptr || runtime->outputSecondary == nullptr) {
    return 0u;
  }

  float* const basis0 = runtime->basisPair[0];
  float* const basis1 = runtime->basisPair[1];
  if (basis0 == nullptr || basis1 == nullptr) {
    return 0u;
  }

  runtime->outputPrimary[0] = basis0[0];
  runtime->outputPrimary[1] = basis1[1];
  runtime->outputSecondary[0] = basis0[1];
  runtime->outputSecondary[1] = 0.0f;

  basis0[0] = 1.0f;
  basis0[1] = 0.0f;
  basis1[0] = 0.0f;
  basis1[1] = 1.0f;
  runtime->wasReset = 1u;
  return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(runtime->basisPair));
}

/**
 * Address: 0x00A6EF10 (FUN_00A6EF10)
 *
 * What it does:
 * Snapshots one 2x2 double basis lane into outputs and resets the live basis
 * to identity.
 */
[[maybe_unused]] std::uint32_t SnapshotAndResetBasis2dRuntime(
  BasisPointerResetRuntimeD* const runtime
)
{
  if (runtime == nullptr || runtime->basisPair == nullptr || runtime->outputPrimary == nullptr || runtime->outputSecondary == nullptr) {
    return 0u;
  }

  double* const basis0 = runtime->basisPair[0];
  double* const basis1 = runtime->basisPair[1];
  if (basis0 == nullptr || basis1 == nullptr) {
    return 0u;
  }

  runtime->outputPrimary[0] = basis0[0];
  runtime->outputPrimary[1] = basis1[1];
  runtime->outputSecondary[0] = basis0[1];
  runtime->outputSecondary[1] = 0.0;

  basis0[0] = 1.0;
  basis0[1] = 0.0;
  basis1[0] = 0.0;
  basis1[1] = 1.0;
  runtime->wasReset = 1u;
  return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(runtime->basisPair));
}

/**
 * Address: 0x00AA7C48 (FUN_00AA7C48)
 *
 * What it does:
 * Returns the IEEE-754 exponent-mask lane for one double, or full high dword
 * when the value is NaN/Inf-class.
 */
[[maybe_unused]] std::uint32_t ClassifyDoubleExponentMaskRuntime(
  const double value
)
{
  const std::uint64_t bits = std::bit_cast<std::uint64_t>(value);
  const std::uint32_t highWord = static_cast<std::uint32_t>(bits >> 32u);
  const std::uint32_t exponentMask = highWord & 0x7FF00000u;
  return exponentMask == 0x7FF00000u ? highWord : exponentMask;
}

/**
 * Address: 0x00549AD0 (FUN_00549AD0)
 *
 * What it does:
 * Copies one `[source, end)` lane sequence of 5-dword records into
 * destination.
 */
[[maybe_unused]] std::uint32_t* CopyStride5DwordRangeRuntime(
  std::uint32_t* destination,
  const std::uint32_t* const sourceEnd,
  const std::uint32_t* source
)
{
  while (source != sourceEnd) {
    if (destination != nullptr) {
      destination[0] = source[0];
      destination[1] = source[1];
      destination[2] = source[2];
      destination[3] = source[3];
      destination[4] = source[4];
    }
    source += 5;
    if (destination != nullptr) {
      destination += 5;
    }
  }
  return destination;
}

/**
 * Address: 0x00548AF0 (FUN_00548AF0)
 *
 * What it does:
 * Adapts one register-lane caller shape into the canonical 5-dword stride
 * copy helper.
 */
[[maybe_unused]] std::uint32_t* CopyStride5DwordRangeRegisterAdapterLaneA(
  const std::uint32_t* const sourceBegin,
  const std::uint32_t* const sourceEnd,
  std::uint32_t* const destinationBegin
)
{
  return CopyStride5DwordRangeRuntime(destinationBegin, sourceEnd, sourceBegin);
}

/**
 * Address: 0x00549780 (FUN_00549780)
 *
 * What it does:
 * Adapts one register-lane caller shape into the canonical 5-dword stride
 * copy helper.
 */
[[maybe_unused]] std::uint32_t* CopyStride5DwordRangeRegisterAdapterLaneB(
  const std::uint32_t* const sourceBegin,
  const std::uint32_t* const sourceEnd,
  std::uint32_t* const destinationBegin
)
{
  return CopyStride5DwordRangeRuntime(destinationBegin, sourceEnd, sourceBegin);
}

/**
 * Address: 0x005494C0 (FUN_005494C0)
 *
 * What it does:
 * Adapts one register-lane caller shape into an empty-range 5-dword copy
 * dispatch (`sourceBegin == sourceEnd`), preserving destination passthrough.
 */
[[maybe_unused]] std::uint32_t* CopyStride5DwordRangeEmptyAdapterLaneA(
  std::uint32_t* const destinationBegin,
  const std::uint32_t* const sourceLane
)
{
  return CopyStride5DwordRangeRuntime(destinationBegin, sourceLane, sourceLane);
}

/**
 * Address: 0x00549920 (FUN_00549920)
 *
 * What it does:
 * Secondary register-lane adapter for empty-range 5-dword copy dispatch.
 */
[[maybe_unused]] std::uint32_t* CopyStride5DwordRangeEmptyAdapterLaneB(
  std::uint32_t* const destinationBegin,
  const std::uint32_t* const sourceLane
)
{
  return CopyStride5DwordRangeRuntime(destinationBegin, sourceLane, sourceLane);
}

/**
 * Address: 0x00549970 (FUN_00549970)
 *
 * What it does:
 * `this`-shape adapter for empty-range 5-dword copy dispatch.
 */
[[maybe_unused]] std::uint32_t* CopyStride5DwordRangeEmptyAdapterLaneC(
  std::uint32_t* const destinationBegin,
  const std::uint32_t* const sourceLane
)
{
  return CopyStride5DwordRangeRuntime(destinationBegin, sourceLane, sourceLane);
}

/**
 * Address: 0x0057EA30 (FUN_0057EA30)
 *
 * What it does:
 * Unlinks one dual back-reference lane by patching both owner chains rooted at
 * `+0x08` and `+0x10`.
 */
[[maybe_unused]] std::uint32_t* UnlinkDualBackReferenceRuntime(
  const std::uint32_t nodeAddress
)
{
  auto* const link = reinterpret_cast<LinkPatchRuntime*>(static_cast<std::uintptr_t>(nodeAddress + 8u));
  if (link == nullptr) {
    return nullptr;
  }

  std::uint32_t* result = reinterpret_cast<std::uint32_t*>(static_cast<std::uintptr_t>(link->lane08));

  if (link->lane10 != 0u) {
    auto* cursor = reinterpret_cast<std::uint32_t*>(static_cast<std::uintptr_t>(link->lane10));
    const std::uintptr_t target = reinterpret_cast<std::uintptr_t>(&link->lane10);
    std::uint32_t guard = 0u;
    while (cursor != nullptr && guard < 0x100000u) {
      if (*cursor == static_cast<std::uint32_t>(target)) {
        *cursor = link->lane14;
        break;
      }
      cursor = reinterpret_cast<std::uint32_t*>(static_cast<std::uintptr_t>(*cursor + 4u));
      ++guard;
    }
  }

  if (link->lane08 != 0u) {
    result = reinterpret_cast<std::uint32_t*>(static_cast<std::uintptr_t>(link->lane08));
    const std::uintptr_t target = reinterpret_cast<std::uintptr_t>(&link->lane08);
    std::uint32_t guard = 0u;
    while (result != nullptr && guard < 0x100000u) {
      if (*result == static_cast<std::uint32_t>(target)) {
        *result = link->lane0C;
        break;
      }
      result = reinterpret_cast<std::uint32_t*>(static_cast<std::uintptr_t>(*result + 4u));
      ++guard;
    }
  }

  return result;
}

/**
 * Address: 0x00584920 (FUN_00584920)
 *
 * What it does:
 * Copies one `[source, sourceEnd)` sequence of 6-float lanes into destination.
 */
[[maybe_unused]] float* CopyStride6FloatRangeRuntime(
  float* destination,
  const float* source,
  const float* const sourceEnd
)
{
  while (source != sourceEnd) {
    if (destination != nullptr) {
      destination[0] = source[0];
      destination[1] = source[1];
      destination[2] = source[2];
      destination[3] = source[3];
      destination[4] = source[4];
      destination[5] = source[5];
      destination += 6;
    }
    source += 6;
  }
  return destination;
}

/**
 * Address: 0x005836B0 (FUN_005836B0)
 *
 * What it does:
 * Register-shape adapter that forwards one float6 range-copy lane into the
 * canonical stride-6 helper.
 */
[[maybe_unused]] float* CopyStride6FloatRangeRegisterAdapterA(
  const float* const sourceBegin,
  const float* const sourceEnd,
  float* const destination
)
{
  return CopyStride6FloatRangeRuntime(destination, sourceBegin, sourceEnd);
}

/**
 * Address: 0x00584200 (FUN_00584200)
 *
 * What it does:
 * Duplicate register-shape adapter of the float6 range-copy lane.
 */
[[maybe_unused]] float* CopyStride6FloatRangeRegisterAdapterB(
  const float* const sourceBegin,
  const float* const sourceEnd,
  float* const destination
)
{
  return CopyStride6FloatRangeRuntime(destination, sourceBegin, sourceEnd);
}

/**
 * Address: 0x00584420 (FUN_00584420)
 *
 * What it does:
 * Duplicate adapter lane that forwards one float6 range copy to the canonical
 * helper.
 */
[[maybe_unused]] float* CopyStride6FloatRangeRegisterAdapterC(
  const float* const sourceBegin,
  const float* const sourceEnd,
  float* const destination
)
{
  return CopyStride6FloatRangeRuntime(destination, sourceBegin, sourceEnd);
}

/**
 * Address: 0x00582180 (FUN_00582180)
 *
 * What it does:
 * Register-shape thunk that forwards one float6 range-copy lane into the
 * canonical stride-6 helper.
 */
[[maybe_unused]] float* CopyStride6FloatRangeRegisterAdapterD(
  const float* const sourceBegin,
  const float* const sourceEnd,
  float* const destination
)
{
  return CopyStride6FloatRangeRuntime(destination, sourceBegin, sourceEnd);
}

/**
 * Address: 0x00583960 (FUN_00583960)
 *
 * What it does:
 * Duplicate register-shape thunk that forwards one float6 range copy into
 * the canonical helper.
 */
[[maybe_unused]] float* CopyStride6FloatRangeRegisterAdapterE(
  const float* const sourceBegin,
  const float* const sourceEnd,
  float* const destination
)
{
  return CopyStride6FloatRangeRuntime(destination, sourceBegin, sourceEnd);
}

/**
 * Address: 0x00962B30 (FUN_00962B30)
 *
 * What it does:
 * Rebinds one wx object lane to `wxObject` vtable and drops the shared
 * reference.
 */
[[maybe_unused]] void ResetWxObjectAndUnrefForCloseRuntime(
  WxObjectRuntime* const object,
  void* const wxObjectVtable,
  const WxUnrefFn unrefFn
)
{
  if (object == nullptr) {
    return;
  }

  object->vtable = wxObjectVtable;
  if (unrefFn != nullptr) {
    unrefFn(object);
  }
}

/**
 * Address: 0x00962CA0 (FUN_00962CA0)
 *
 * What it does:
 * Rebinds one wx object lane to `wxObject` vtable and drops the shared
 * reference.
 */
[[maybe_unused]] void ResetWxObjectAndUnrefForQueryEndSessionRuntime(
  WxObjectRuntime* const object,
  void* const wxObjectVtable,
  const WxUnrefFn unrefFn
)
{
  if (object == nullptr) {
    return;
  }

  object->vtable = wxObjectVtable;
  if (unrefFn != nullptr) {
    unrefFn(object);
  }
}

/**
 * Address: 0x00966CC0 (FUN_00966CC0)
 *
 * What it does:
 * Rebinds one wx object lane to `wxObject` vtable and drops the shared
 * reference.
 */
[[maybe_unused]] void ResetWxObjectAndUnrefForEndSessionRuntime(
  WxObjectRuntime* const object,
  void* const wxObjectVtable,
  const WxUnrefFn unrefFn
)
{
  if (object == nullptr) {
    return;
  }

  object->vtable = wxObjectVtable;
  if (unrefFn != nullptr) {
    unrefFn(object);
  }
}

/**
 * Address: 0x0096E0D0 (FUN_0096E0D0)
 *
 * What it does:
 * Initializes one wx font-descriptor lane using caller values and falls back
 * to the normal-font point size when input size is `-1`.
 */
[[maybe_unused]] int InitializeWxFontDescriptorRuntime(
  WxFontDescriptorRuntime* const descriptor,
  std::int32_t pointSize,
  const std::int32_t family,
  const std::int32_t style,
  const std::int32_t weight,
  const std::uint8_t underlined,
  const void* const faceName,
  const std::int32_t encoding,
  const WxGetDefaultPointSizeFn getDefaultPointSizeFn,
  const WxStringAssignFn assignStringFn
)
{
  if (descriptor == nullptr) {
    return 0;
  }

  descriptor->style = style;
  if (pointSize == -1 && getDefaultPointSizeFn != nullptr) {
    pointSize = getDefaultPointSizeFn();
  }

  descriptor->pointSize = pointSize;
  descriptor->family = family;
  descriptor->weight = weight;
  descriptor->style = style;
  descriptor->underlined = underlined;
  if (assignStringFn != nullptr) {
    assignStringFn(descriptor->faceNameStorage, faceName);
  }
  descriptor->encoding = encoding;
  descriptor->lane24 = 0;
  descriptor->lane84 = 0;
  return 0;
}

/**
 * Address: 0x009EE1C0 (FUN_009EE1C0)
 *
 * What it does:
 * Rebinds one wx spin-button lane to its own vtable and forwards destruction
 * to `wxControl`.
 */
[[maybe_unused]] int DestroyWxSpinButtonRuntime(
  WxObjectRuntime* const spinButton,
  void* const wxSpinButtonVtable,
  const WxControlDtorFn wxControlDtorFn
)
{
  if (spinButton == nullptr) {
    return 0;
  }

  spinButton->vtable = wxSpinButtonVtable;
  return wxControlDtorFn != nullptr ? wxControlDtorFn(spinButton) : 0;
}

/**
 * Address: 0x009F7700 (FUN_009F7700)
 *
 * What it does:
 * Releases four wx shared-string lanes in destruction order (`+0x20`, `+0x0C`,
 * `+0x08`, `+0x04`).
 */
[[maybe_unused]] void ReleaseWxSharedStringBundleRuntime(
  WxSharedStringOwnerRuntime* const owner
)
{
  if (owner == nullptr) {
    return;
  }

  ReleaseSharedWxStringLane(owner->stringLane20);
  ReleaseSharedWxStringLane(owner->stringLane0C);
  ReleaseSharedWxStringLane(owner->stringLane08);
  ReleaseSharedWxStringLane(owner->stringLane04);
}

/**
 * Address: 0x00A0E4C0 (FUN_00A0E4C0)
 *
 * What it does:
 * Runs one protocol-base constructor on `this` and immediately rebinds the
 * instance vtable to the wx-file-protocol lane.
 */
[[maybe_unused]] VtableOnlyRuntime* InitializeWxFileProtoRuntime(
  VtableOnlyRuntime* const fileProto,
  void* const wxFileProtoVtable,
  const WxProtocolCtorFn protocolCtorFn
)
{
  (void)protocolCtorFn(fileProto);
  fileProto->vtable = wxFileProtoVtable;
  return fileProto;
}

/**
 * Address: 0x00A0E5D0 (FUN_00A0E5D0)
 *
 * What it does:
 * Runs one socket-input-stream constructor for the given handle, stores the
 * same socket handle at `+0x1C`, then rebinds the vtable to wxHTTPStream.
 */
[[maybe_unused]] WxHttpStreamRuntime* InitializeWxHttpStreamRuntime(
  WxHttpStreamRuntime* const stream,
  const std::int32_t socketHandle,
  void* const wxHttpStreamVtable,
  const WxSocketInputCtorFn socketInputCtorFn
)
{
  (void)socketInputCtorFn(reinterpret_cast<WxSocketInputStreamRuntime*>(stream), socketHandle);
  stream->socketHandle = socketHandle;
  stream->vtable = wxHttpStreamVtable;
  return stream;
}

/**
 * Address: 0x00A2B590 (FUN_00A2B590)
 *
 * What it does:
 * Clears one global hash-cleanup active flag, destroys all bucket chains via
 * callback, and resets owner lane `+0x08` to zero.
 */
[[maybe_unused]] void* ResetHashBucketCleanupOwnerRuntime(
  HashBucketCleanupOwnerRuntime* const owner,
  std::uint8_t* const globalCleanupActiveFlag,
  const HashBucketDestroyFn destroyNodeFn,
  const HashBucketClearFn clearFn
)
{
  *globalCleanupActiveFlag = 0u;
  void* const result = clearFn(owner->bucketCount, owner->bucketHeads, destroyNodeFn);
  owner->lane08 = 0u;
  return result;
}

/**
 * Address: 0x00A16360 (FUN_00A16360)
 *
 * What it does:
 * Reads one pair lane from lookup source at `+0x6C` and stores both values
 * scaled down by 10 into `+0x0C/+0x10`.
 */
[[maybe_unused]] void UpdatePairTenthsFromLookupRuntime(
  Div10PairOwnerRuntime* const owner,
  const PairLookupFn lookupFn
)
{
  if (owner == nullptr || lookupFn == nullptr) {
    return;
  }

  std::int32_t pair[2] = {0, 0};
  lookupFn(pair, owner->sourceLane6C);
  owner->lane0C = pair[0] / 10;
  owner->lane10 = pair[1] / 10;
}

/**
 * Address: 0x00A2F550 (FUN_00A2F550)
 *
 * What it does:
 * Runs wx-protocol base initialization with lane `0` and installs the
 * protocol vtable token.
 */
[[maybe_unused]] VtableOnlyRuntime* InitializeWxProtocolRuntime(
  VtableOnlyRuntime* const protocol,
  void* const wxProtocolVtable,
  const WxProtocolInitializeFn initializeFn
)
{
  if (initializeFn != nullptr) {
    initializeFn(0);
  }

  if (protocol != nullptr) {
    protocol->vtable = wxProtocolVtable;
  }
  return protocol;
}

/**
 * Address: 0x00A2F9C0 (FUN_00A2F9C0)
 *
 * What it does:
 * Constructs one wx socket-output stream lane, stores the socket handle, and
 * binds the stream vtable.
 */
[[maybe_unused]] WxSocketOutputStreamRuntime* InitializeWxSocketOutputStreamRuntime(
  WxSocketOutputStreamRuntime* const stream,
  const std::int32_t socketHandle,
  void* const wxSocketOutputStreamVtable,
  const WxSocketOutputBaseCtorFn baseCtorFn
)
{
  if (stream == nullptr) {
    return nullptr;
  }

  if (baseCtorFn != nullptr) {
    baseCtorFn(stream);
  }

  stream->socketHandle = socketHandle;
  stream->vtable = wxSocketOutputStreamVtable;
  return stream;
}

/**
 * Address: 0x00A2FA20 (FUN_00A2FA20)
 *
 * What it does:
 * Constructs one wx socket-input stream lane, stores the socket handle at
 * `+0x18`, and binds the input-stream vtable.
 */
[[maybe_unused]] WxSocketInputStreamRuntime* InitializeWxSocketInputStreamRuntime(
  WxSocketInputStreamRuntime* const stream,
  const std::int32_t socketHandle,
  void* const wxSocketInputStreamVtable,
  const WxInputStreamCtorFn baseCtorFn
)
{
  if (stream == nullptr) {
    return nullptr;
  }

  if (baseCtorFn != nullptr) {
    baseCtorFn(stream);
  }

  stream->socketHandle = socketHandle;
  stream->vtable = wxSocketInputStreamVtable;
  return stream;
}

/**
 * Alias of FUN_00A2FA80.
 *
 * What it does:
 * Provides a generalized helper form that runs socket-input/socket-output
 * constructor callbacks over a combined wx-socket-stream runtime object, then
 * applies caller-provided primary/output-adjusted vtable lanes.
 */
[[maybe_unused]] WxSocketStreamRuntime* InitializeWxSocketStreamRuntime(
  WxSocketStreamRuntime* const stream,
  const std::int32_t socketHandle,
  void* const wxSocketStreamVtable,
  void* const wxSocketStreamOutputAdjustedVtable,
  const WxSocketInputCtorFn socketInputCtorFn,
  const WxSocketOutputCtorFn socketOutputCtorFn
)
{
  (void)socketInputCtorFn(&stream->inputBase, socketHandle);
  (void)socketOutputCtorFn(&stream->outputBase, socketHandle);
  stream->inputBase.vtable = wxSocketStreamVtable;
  stream->outputBase.vtable = wxSocketStreamOutputAdjustedVtable;
  return stream;
}

/**
 * Address: 0x00AC14D3 (FUN_00AC14D3)
 *
 * What it does:
 * Normalizes one packed 32-bit float lane represented as two 16-bit words and
 * returns the signed exponent delta produced by normalization.
 */
[[maybe_unused]] std::int32_t NormalizePackedFloatWordsRuntime(
  std::uint16_t* const words
) noexcept
{
  if (words == nullptr) {
    return 0;
  }

  const std::uint16_t sign = static_cast<std::uint16_t>(words[1] & 0x8000u);
  std::int32_t exponentDelta = 1;
  std::uint16_t high = static_cast<std::uint16_t>(words[1] & 0x007Fu);
  std::uint16_t low = words[0];

  if (high == 0u) {
    if (low == 0u) {
      words[1] = sign;
      return exponentDelta;
    }

    high = low;
    low = 0u;
    exponentDelta = -15;
  }

  while (high < 0x80u) {
    const std::uint32_t combined = (static_cast<std::uint32_t>(high) << 16u) | low;
    const std::uint32_t shifted = combined << 1u;
    high = static_cast<std::uint16_t>((shifted >> 16u) & 0xFFFFu);
    low = static_cast<std::uint16_t>(shifted & 0xFFFFu);
    --exponentDelta;
  }

  while (high >= 0x100u) {
    const std::uint32_t combined = (static_cast<std::uint32_t>(high) << 16u) | low;
    const std::uint32_t shifted = combined >> 1u;
    high = static_cast<std::uint16_t>((shifted >> 16u) & 0xFFFFu);
    low = static_cast<std::uint16_t>(shifted & 0xFFFFu);
    ++exponentDelta;
  }

  words[0] = low;
  words[1] = static_cast<std::uint16_t>((high & 0x007Fu) | sign);
  return exponentDelta;
}

/**
 * Address: 0x00AC1677 (FUN_00AC1677)
 *
 * What it does:
 * Normalizes one packed 64-bit float lane represented as four 16-bit words
 * and returns the signed exponent delta produced by normalization.
 */
[[maybe_unused]] std::int16_t NormalizePackedDoubleMantissaWordsRuntime(
  std::uint16_t* const words
) noexcept
{
  if (words == nullptr) {
    return 0;
  }

  const std::uint16_t sign = static_cast<std::uint16_t>(words[3] & 0x8000u);
  std::int16_t exponentDelta = 1;
  words[3] = static_cast<std::uint16_t>(words[3] & 0x000Fu);

  if (words[3] == 0u) {
    if (words[2] == 0u && words[1] == 0u && words[0] == 0u) {
      words[3] = sign;
      return exponentDelta;
    }

    do {
      words[3] = words[2];
      words[2] = words[1];
      words[1] = words[0];
      words[0] = 0u;
      exponentDelta = static_cast<std::int16_t>(exponentDelta - 16);
    } while (words[3] == 0u);
  }

  while (words[3] < 0x10u) {
    const std::uint16_t oldW3 = words[3];
    const std::uint16_t oldW2 = words[2];
    const std::uint16_t oldW1 = words[1];
    const std::uint16_t oldW0 = words[0];

    words[3] = static_cast<std::uint16_t>((static_cast<std::uint32_t>(oldW3) << 1u) | (oldW2 >> 15u));
    words[2] = static_cast<std::uint16_t>((static_cast<std::uint32_t>(oldW2) << 1u) | (oldW1 >> 15u));
    words[1] = static_cast<std::uint16_t>((static_cast<std::uint32_t>(oldW1) << 1u) | (oldW0 >> 15u));
    words[0] = static_cast<std::uint16_t>(static_cast<std::uint32_t>(oldW0) << 1u);
    --exponentDelta;
  }

  while (words[3] >= 0x20u) {
    const std::uint16_t oldW3 = words[3];
    const std::uint16_t oldW2 = words[2];
    const std::uint16_t oldW1 = words[1];
    const std::uint16_t oldW0 = words[0];

    words[0] = static_cast<std::uint16_t>((oldW0 >> 1u) | (static_cast<std::uint32_t>(oldW1) << 15u));
    words[1] = static_cast<std::uint16_t>((oldW1 >> 1u) | (static_cast<std::uint32_t>(oldW2) << 15u));
    words[2] = static_cast<std::uint16_t>((oldW2 >> 1u) | (static_cast<std::uint32_t>(oldW3) << 15u));
    words[3] = static_cast<std::uint16_t>(oldW3 >> 1u);
    ++exponentDelta;
  }

  words[3] = static_cast<std::uint16_t>((words[3] & 0x000Fu) | sign);
  return exponentDelta;
}

/**
 * Address: 0x00AC1138 (FUN_00AC1138)
 *
 * What it does:
 * Scales one packed 64-bit floating-point lane (represented as four 16-bit
 * words) by a signed exponent delta and returns the CRT classification code.
 */
[[maybe_unused]] std::int16_t ScalePackedDoubleWordsRuntime(
  std::uint16_t* const words,
  const int exponentDelta,
  const NormalizePackedDoubleFn normalizeFn,
  const double overflowMagnitude
)
{
  if (words == nullptr) {
    return 0;
  }

  const std::uint16_t highWord = words[3];
  std::int16_t exponent = static_cast<std::int16_t>((highWord >> 4u) & 0x7FFu);
  if (exponent == 0x07FF) {
    if ((highWord & 0x000Fu) != 0u || words[2] != 0u || words[1] != 0u || words[0] != 0u) {
      return 2;
    }
    return 1;
  }

  if (exponent == 0) {
    if (normalizeFn == nullptr) {
      return 0;
    }

    exponent = normalizeFn(words);
    if (exponent > 0) {
      return 0;
    }
  }

  if (exponentDelta > 0 && (0x07FF - exponent) <= exponentDelta) {
    double saturated = overflowMagnitude;
    if ((words[3] & 0x8000u) != 0u) {
      saturated = -saturated;
    }
    std::memcpy(words, &saturated, sizeof(saturated));
    return 1;
  }

  if (-exponent < exponentDelta) {
    const std::int32_t adjustedExponent = exponent + exponentDelta;
    const std::uint16_t preserved = static_cast<std::uint16_t>(words[3] & 0x800Fu);
    words[3] = static_cast<std::uint16_t>(preserved | ((adjustedExponent << 4) & 0x7FF0));
    return -1;
  }

  const std::uint16_t sign = static_cast<std::uint16_t>(words[3] & 0x8000u);
  std::uint16_t normalizedHigh = static_cast<std::uint16_t>((words[3] & 0x000Fu) | 0x0010u);
  words[3] = normalizedHigh;

  int shift = exponentDelta + exponent - 1;
  if (static_cast<unsigned int>(shift + 53) > 0x34u) {
    words[3] = sign;
    words[2] = 0u;
    words[1] = 0u;
    words[0] = 0u;
    return 0;
  }

  std::uint16_t sticky = 0u;
  if (shift <= -16) {
    std::uint16_t w2 = words[2];
    std::uint16_t w1 = words[1];
    const int iterations = ((-16 - shift) >> 4) + 1;
    std::uint16_t w3 = normalizedHigh;
    std::uint16_t w0 = words[0];
    const int shifted = shift + (iterations * 16);

    for (int i = 0; i < iterations; ++i) {
      const std::uint16_t nextSticky = static_cast<std::uint16_t>(w0 | (sticky != 0u ? 1u : 0u));
      w0 = w1;
      w1 = w2;
      w2 = w3;
      w3 = 0u;
      sticky = nextSticky;
    }

    words[3] = 0u;
    words[2] = w2;
    words[1] = w1;
    words[0] = w0;
    shift = shifted;
  }

  if (shift != 0) {
    const int rightShift = -shift;
    const int leftShift = shift + 16;
    const std::uint32_t w0 = words[0];
    const std::uint32_t w1 = words[1];
    const std::uint32_t w2 = words[2];
    const std::uint32_t w3 = words[3];

    sticky = static_cast<std::uint16_t>((sticky != 0u ? 1u : 0u) | static_cast<std::uint16_t>((w0 << leftShift) & 0xFFFFu));
    words[0] = static_cast<std::uint16_t>(((w1 << leftShift) | (w0 >> rightShift)) & 0xFFFFu);
    words[1] = static_cast<std::uint16_t>(((w2 << leftShift) | (w1 >> rightShift)) & 0xFFFFu);
    words[2] = static_cast<std::uint16_t>(((w3 << leftShift) | (w2 >> rightShift)) & 0xFFFFu);
    words[3] = static_cast<std::uint16_t>((w3 >> rightShift) & 0xFFFFu);
  }

  words[3] = static_cast<std::uint16_t>(words[3] | sign);
  const std::uint16_t mergedHigh = words[3];
  if ((sticky > 0x8000u || (sticky == 0x8000u && (words[0] & 1u) != 0u))
      && ++words[0] == 0u
      && ++words[1] == 0u
      && ++words[2] == 0u) {
    words[3] = static_cast<std::uint16_t>(mergedHigh + 1u);
    return -1;
  }

  if (mergedHigh != sign || words[2] != 0u || words[1] != 0u || words[0] != 0u) {
    return -1;
  }

  return 0;
}

/**
 * Address: 0x00AC14CE (FUN_00AC14CE)
 *
 * What it does:
 * Tail-forwards one packed-double scaling thunk lane into
 * `ScalePackedDoubleWordsRuntime`.
 */
[[maybe_unused]] std::int16_t ScalePackedDoubleWordsRuntimeAdapter(
  std::uint16_t* const words,
  const int exponentDelta,
  const NormalizePackedDoubleFn normalizeFn,
  const double overflowMagnitude
)
{
  return ScalePackedDoubleWordsRuntime(words, exponentDelta, normalizeFn, overflowMagnitude);
}

/**
 * Address: 0x007D4380 (FUN_007D4380)
 *
 * What it does:
 * Clears one intrusive cartographic-decal list lane and destroys each dynamic
 * node after rebinding its vtable token.
 */
[[maybe_unused]] CartographicDecalNodeRuntime* ClearCartographicDecalListRuntime(
  CartographicDecalListRuntime* const list,
  void* const cartographicDecalVtable
)
{
  if (list == nullptr || list->sentinel == nullptr) {
    return nullptr;
  }

  CartographicDecalNodeRuntime* const sentinel = list->sentinel;
  CartographicDecalNodeRuntime* node = sentinel->next;
  sentinel->next = sentinel;
  sentinel->prev = sentinel;
  list->size = 0u;

  while (node != nullptr && node != sentinel) {
    CartographicDecalNodeRuntime* const next = node->next;
    node->vtable = cartographicDecalVtable;
    ::operator delete(node);
    node = next;
  }

  return node;
}

/**
 * Address: 0x00886FB0 (FUN_00886FB0)
 *
 * What it does:
 * Releases both legacy string lanes in one wave-parameters object and resets
 * them to empty-inline form.
 */
[[maybe_unused]] void ResetWaveParametersStringsRuntime(
  WaveParametersRuntime* const parameters,
  void* const waveParametersVtable
)
{
  if (parameters == nullptr) {
    return;
  }

  parameters->vtable = waveParametersVtable;
  parameters->lane20Text.tidy(true, 0U);
  parameters->lane04Text.tidy(true, 0U);
}

/**
 * Address: 0x0088B2A0 (FUN_0088B2A0)
 *
 * What it does:
 * Copies both wave-parameter string lanes and all scalar parameter lanes
 * (`+0x3C..+0x84`) from source to destination.
 */
[[maybe_unused]] [[nodiscard]] WaveParametersRuntime* CopyWaveParametersPayloadRuntime(
  const WaveParametersRuntime* const source,
  WaveParametersRuntime* const destination
)
{
  destination->lane04Text.assign(source->lane04Text, 0u, msvc8::string::npos);
  destination->lane20Text.assign(source->lane20Text, 0u, msvc8::string::npos);

  destination->lane3C = source->lane3C;
  destination->lane40 = source->lane40;
  destination->lane44 = source->lane44;
  destination->lane48 = source->lane48;
  destination->lane4C = source->lane4C;
  destination->lane50 = source->lane50;
  destination->lane54 = source->lane54;
  destination->lane58 = source->lane58;
  destination->lane5C = source->lane5C;
  destination->lane60 = source->lane60;
  destination->lane64 = source->lane64;
  destination->lane68 = source->lane68;
  destination->lane6C = source->lane6C;
  destination->lane70 = source->lane70;
  destination->lane74 = source->lane74;
  destination->lane78 = source->lane78;
  destination->lane7C = source->lane7C;
  destination->lane80 = source->lane80;
  destination->lane84 = source->lane84;
  return destination;
}

/**
 * Address: 0x0088AB00 (FUN_0088AB00)
 *
 * What it does:
 * Copy-constructs one wave-parameters object by rebinding its vtable lane,
 * default-constructing both embedded string lanes, and copying payload lanes.
 */
[[maybe_unused]] [[nodiscard]] WaveParametersRuntime* CopyConstructWaveParametersRuntime(
  const WaveParametersRuntime* const source,
  WaveParametersRuntime* const destination
)
{
  destination->vtable = source->vtable;
  ::new (static_cast<void*>(&destination->lane04Text)) msvc8::string();
  ::new (static_cast<void*>(&destination->lane20Text)) msvc8::string();
  return CopyWaveParametersPayloadRuntime(source, destination);
}

/**
 * Address: 0x0088AD60 (FUN_0088AD60)
 *
 * What it does:
 * Forward-copies one half-open wave-parameters range `[sourceBegin,sourceEnd)`
 * into destination storage and returns the destination end pointer.
 */
[[maybe_unused]] [[nodiscard]] WaveParametersRuntime* CopyWaveParametersRangeForwardRuntime(
  const WaveParametersRuntime* sourceBegin,
  WaveParametersRuntime* destinationBegin,
  const WaveParametersRuntime* const sourceEnd
)
{
  while (sourceBegin != sourceEnd) {
    (void)CopyWaveParametersPayloadRuntime(sourceBegin, destinationBegin);
    ++sourceBegin;
    ++destinationBegin;
  }

  return destinationBegin;
}

/**
 * Address: 0x0088E6D0 (FUN_0088E6D0)
 *
 * What it does:
 * When one sim-driver instance is active, requests its client-manager lane
 * and runs the manager debug dump callback.
 */
[[maybe_unused]] void SimDriverDebugClientManagerRuntime()
{
  moho::ISTIDriver* const driver = moho::SIM_GetActiveDriver();
  if (driver == nullptr) {
    return;
  }

  moho::CClientManagerImpl* const clientManager = driver->GetClientManager();
  if (clientManager != nullptr) {
    clientManager->Debug();
  }
}

/**
 * Address: 0x009A4AA0 (FUN_009A4AA0)
 *
 * What it does:
 * Rebinds one wx button lane to its own vtable and forwards destruction to
 * `wxControl`.
 */
[[maybe_unused]] int DestroyWxButtonRuntime(
  WxObjectRuntime* const button,
  void* const wxButtonVtable,
  const WxControlDtorFn wxControlDtorFn
)
{
  if (button == nullptr) {
    return 0;
  }

  button->vtable = wxButtonVtable;
  return wxControlDtorFn != nullptr ? wxControlDtorFn(button) : 0;
}

/**
 * Address: 0x004EAA50 (FUN_004EAA50)
 *
 * What it does:
 * Initializes one shared NaN word-pair lane once and returns the pair base.
 */
[[maybe_unused]] std::uint32_t* GetOrInitializeNaNWordPairRuntime(
  const std::uint32_t nanWord
)
{
  static std::uint32_t initializationFlags = 0u;
  static std::uint32_t nanWords[2] = {0u, 0u};

  if ((initializationFlags & 1u) == 0u) {
    initializationFlags |= 1u;
    nanWords[0] = nanWord;
    nanWords[1] = nanWord;
  }

  return nanWords;
}

/**
 * Address: 0x00967FE0 (FUN_00967FE0)
 *
 * What it does:
 * Maps wx input/style bitflags into output style bits used by the caller lane.
 */
[[maybe_unused]] int MapWxStyleFlagsRuntime(
  const int flags,
  const bool skipExtendedMappings
)
{
  int result = 0;
  if ((flags & 0x00100000) != 0) {
    result = 0x20;
  }

  if (!skipExtendedMappings) {
    if ((flags & 0x08000000) != 0) {
      result |= 0x200;
    }
    if ((flags & 0x10000000) != 0) {
      result |= 0x1;
    }
    if ((flags & 0x04000000) != 0) {
      result |= 0x1;
    }
    if ((flags & 0x01000000) != 0) {
      result |= 0x20000;
    }
  }
  return result;
}

/**
 * Address: 0x0096B530 (FUN_0096B530)
 *
 * What it does:
 * Reads one window text-metric lane from its HWND and writes into the caller
 * output structure.
 */
[[maybe_unused]] TEXTMETRICW* ReadWindowTextMetricsRuntime(
  const WindowTextMetricOwnerRuntime* const owner,
  TEXTMETRICW* const outMetrics
)
{
  if (owner == nullptr || outMetrics == nullptr || owner->windowHandle == nullptr) {
    return outMetrics;
  }

  HDC const deviceContext = ::GetDC(owner->windowHandle);
  if (deviceContext == nullptr) {
    return outMetrics;
  }

  ::GetTextMetricsW(deviceContext, outMetrics);
  ::ReleaseDC(owner->windowHandle, deviceContext);
  return outMetrics;
}

/**
 * Address: 0x0097C070 (FUN_0097C070)
 *
 * What it does:
 * Writes region bounding-box coordinates (`left`, `top`, `width`, `height`)
 * when region data is present, otherwise zeroes all outputs.
 */
[[maybe_unused]] LONG* GetRegionBoundsRuntime(
  const RegionOwnerRuntime* const owner,
  LONG* const outLeft,
  LONG* const outTop,
  LONG* const outWidth,
  LONG* const outHeight
)
{
  if (owner == nullptr || owner->node == nullptr || owner->node->regionHandle == nullptr) {
    if (outHeight != nullptr) {
      *outHeight = 0;
    }
    if (outWidth != nullptr) {
      *outWidth = 0;
    }
    if (outTop != nullptr) {
      *outTop = 0;
    }
    if (outLeft != nullptr) {
      *outLeft = 0;
    }
    return outTop;
  }

  RECT box{};
  ::GetRgnBox(owner->node->regionHandle, &box);
  const LONG left = box.left;
  const LONG top = box.top;

  if (outLeft != nullptr) {
    *outLeft = left;
  }
  if (outTop != nullptr) {
    *outTop = top;
  }
  if (outWidth != nullptr) {
    *outWidth = box.right - left;
  }
  if (outHeight != nullptr) {
    *outHeight = box.bottom - top;
  }
  return outHeight;
}

/**
 * Address: 0x0097C1C0 (FUN_0097C1C0)
 *
 * What it does:
 * Tests whether one rectangle lane intersects the stored region; returns `2`
 * on hit and `0` otherwise.
 */
[[maybe_unused]] int TestRectangleInRegionRuntime(
  const RegionOwnerRuntime* const owner,
  const LONG left,
  const LONG top,
  const int width,
  const int height
)
{
  if (owner == nullptr || owner->node == nullptr || owner->node->regionHandle == nullptr) {
    return 0;
  }

  RECT rectangle{};
  rectangle.left = left;
  rectangle.right = left + width;
  rectangle.top = top;
  rectangle.bottom = top + height;
  return ::RectInRegion(owner->node->regionHandle, &rectangle) != FALSE ? 2 : 0;
}

/**
 * Address: 0x00518370 (FUN_00518370)
 *
 * What it does:
 * Copies one `[source, sourceEnd)` range of emitter-curve key lanes and
 * assigns the key vtable token for each destination lane.
 */
[[maybe_unused]] EmitterCurveKeyRuntime* CopyEmitterCurveKeyRangeRuntime(
  EmitterCurveKeyRuntime* destination,
  const EmitterCurveKeyRuntime* source,
  const EmitterCurveKeyRuntime* const sourceEnd,
  void* const emitterCurveKeyVtable
)
{
  while (source != sourceEnd) {
    if (destination != nullptr) {
      destination->vtable = emitterCurveKeyVtable;
      destination->lane04 = source->lane04;
      destination->lane08 = source->lane08;
      destination->lane0C = source->lane0C;
      ++destination;
    }
    ++source;
  }
  return destination;
}

/**
 * Address: 0x00A2FE30 (FUN_00A2FE30)
 *
 * What it does:
 * Splits one millisecond lane into whole seconds (`+0x24`) and microseconds
 * remainder (`+0x28`).
 */
[[maybe_unused]] TimeSplitRuntime* SplitMillisecondsToTimeRuntime(
  TimeSplitRuntime* const destination,
  const std::uint32_t milliseconds
)
{
  if (destination == nullptr) {
    return nullptr;
  }

  destination->seconds = DivideBy1000Fast(milliseconds);
  destination->microseconds = (milliseconds - (destination->seconds * 1000u)) * 1000u;
  return destination;
}

/**
 * Address: 0x00A2E440 (FUN_00A2E440)
 *
 * What it does:
 * Stores one seconds lane at owner `+0x24` and, when `owner+0x08` is present,
 * updates that target split-time lane from `seconds*1000` milliseconds.
 */
[[maybe_unused]] std::uintptr_t UpdateOwnerSecondsAndSplitTimeRuntime(
  TimeSplitOwnerRuntime* const owner,
  const std::int32_t seconds
)
{
  const auto secondsLane = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(seconds));
  owner->lane24 = seconds;
  TimeSplitRuntime* const splitTime = owner->splitTime;
  if (splitTime == nullptr) {
    return secondsLane;
  }

  const std::uint32_t milliseconds = static_cast<std::uint32_t>(seconds) * 1000u;
  return reinterpret_cast<std::uintptr_t>(SplitMillisecondsToTimeRuntime(splitTime, milliseconds));
}

/**
 * Address: 0x00A38620 (FUN_00A38620)
 *
 * What it does:
 * Rebinds one distance-lane object to the `Distance<float, Vector2<float>>`
 * vtable token.
 */
[[maybe_unused]] void ResetDistanceFloat2VtableRuntime(
  VtableOnlyRuntime* const distance
)
{
  static std::uint8_t sDistanceFloat2RuntimeVtableTag = 0;
  if (distance != nullptr) {
    distance->vtable = &sDistanceFloat2RuntimeVtableTag;
  }
}

/**
 * Address: 0x00A4E5B0 (FUN_00A4E5B0)
 *
 * What it does:
 * Rebinds one distance-lane object through the canonical
 * `Distance<float, Vector2<float>>` vtable reset helper.
 */
[[maybe_unused]] VtableOnlyRuntime* ResetDistanceFloat2VtableRuntimeAdapter(
  VtableOnlyRuntime* const distance
) noexcept
{
  ResetDistanceFloat2VtableRuntime(distance);
  return distance;
}

/**
 * Address: 0x00A39260 (FUN_00A39260)
 *
 * What it does:
 * Rebinds one distance-lane object to the `Distance<double, Vector2<double>>`
 * vtable token.
 */
[[maybe_unused]] void ResetDistanceDouble2VtableRuntime(
  VtableOnlyRuntime* const distance
)
{
  static std::uint8_t sDistanceDouble2RuntimeVtableTag = 0;
  if (distance != nullptr) {
    distance->vtable = &sDistanceDouble2RuntimeVtableTag;
  }
}

/**
 * Address: 0x00A4E5C0 (FUN_00A4E5C0)
 *
 * What it does:
 * Rebinds one distance-lane object through the canonical
 * `Distance<double, Vector2<double>>` vtable reset helper.
 */
[[maybe_unused]] VtableOnlyRuntime* ResetDistanceDouble2VtableRuntimeAdapter(
  VtableOnlyRuntime* const distance
) noexcept
{
  ResetDistanceDouble2VtableRuntime(distance);
  return distance;
}

[[maybe_unused]] void ResetDistanceFloat3VtableRuntime(
  VtableOnlyRuntime* const distance
)
{
  static std::uint8_t sDistanceFloat3RuntimeVtableTag = 0;
  if (distance != nullptr) {
    distance->vtable = &sDistanceFloat3RuntimeVtableTag;
  }
}

[[maybe_unused]] void ResetDistanceDouble3VtableRuntime(
  VtableOnlyRuntime* const distance
)
{
  static std::uint8_t sDistanceDouble3RuntimeVtableTag = 0;
  if (distance != nullptr) {
    distance->vtable = &sDistanceDouble3RuntimeVtableTag;
  }
}

/**
 * Address: 0x00A39E40 (FUN_00A39E40)
 *
 * What it does:
 * Runs one deleting-dtor thunk lane for the `Distance<float, Vector2<float>>`
 * base runtime object.
 */
[[maybe_unused]] void* ResetDistanceFloat2BaseVtableWithFlagRuntime(
  void* const distanceRuntime,
  const std::uint8_t deleteFlags
) noexcept
{
  auto* const distance = static_cast<VtableOnlyRuntime*>(distanceRuntime);
  ResetDistanceFloat2VtableRuntime(distance);
  if ((deleteFlags & 1u) != 0u) {
    ::operator delete(distance);
  }
  return distance;
}

/**
 * Address: 0x00A39E60 (FUN_00A39E60)
 *
 * What it does:
 * Runs one deleting-dtor thunk lane for the `Distance<float, Vector3<float>>`
 * base runtime object.
 */
[[maybe_unused]] void* ResetDistanceFloat3BaseVtableWithFlagRuntime(
  void* const distanceRuntime,
  const std::uint8_t deleteFlags
) noexcept
{
  auto* const distance = static_cast<VtableOnlyRuntime*>(distanceRuntime);
  ResetDistanceFloat3VtableRuntime(distance);
  if ((deleteFlags & 1u) != 0u) {
    ::operator delete(distance);
  }
  return distance;
}

/**
 * Address: 0x00A39E80 (FUN_00A39E80)
 *
 * What it does:
 * Runs one deleting-dtor thunk lane for the `Distance<double, Vector2<double>>`
 * base runtime object.
 */
[[maybe_unused]] void* ResetDistanceDouble2BaseVtableWithFlagRuntime(
  void* const distanceRuntime,
  const std::uint8_t deleteFlags
) noexcept
{
  auto* const distance = static_cast<VtableOnlyRuntime*>(distanceRuntime);
  ResetDistanceDouble2VtableRuntime(distance);
  if ((deleteFlags & 1u) != 0u) {
    ::operator delete(distance);
  }
  return distance;
}

/**
 * Address: 0x00A39EA0 (FUN_00A39EA0)
 *
 * What it does:
 * Runs one deleting-dtor thunk lane for the `Distance<double, Vector3<double>>`
 * base runtime object.
 */
[[maybe_unused]] void* ResetDistanceDouble3BaseVtableWithFlagRuntime(
  void* const distanceRuntime,
  const std::uint8_t deleteFlags
) noexcept
{
  auto* const distance = static_cast<VtableOnlyRuntime*>(distanceRuntime);
  ResetDistanceDouble3VtableRuntime(distance);
  if ((deleteFlags & 1u) != 0u) {
    ::operator delete(distance);
  }
  return distance;
}

/**
 * Address: 0x00A6C5E0 (FUN_00A6C5E0)
 *
 * What it does:
 * Initializes one `DistVector2Box2<float>` runtime lane by seeding the
 * `Distance<float, Vector2<float>>` base state, binding object pointers, and
 * rebinding the derived vtable lane.
 */
[[maybe_unused]] DistVector2Box2fRuntime* InitializeDistVector2Box2fRuntime(
  DistVector2Box2fRuntime* const runtime,
  const void* const vector2Runtime,
  const void* const box2Runtime
)
{
  static std::uint8_t sDistVector2Box2fRuntimeVtableTag = 0;
  if (runtime == nullptr) {
    return nullptr;
  }

  (void)InitializeDistanceVector2fRuntime(runtime, &sDistVector2Box2fRuntimeVtableTag);
  runtime->vector2Runtime = vector2Runtime;
  runtime->box2Runtime = box2Runtime;
  return runtime;
}

/**
 * Address: 0x00A6C630 (FUN_00A6C630)
 *
 * What it does:
 * Initializes one `DistVector2Box2<double>` runtime lane by seeding the
 * `Distance<double, Vector2<double>>` base state, binding object pointers, and
 * rebinding the derived vtable lane.
 */
[[maybe_unused]] DistVector2Box2dRuntime* InitializeDistVector2Box2dRuntime(
  DistVector2Box2dRuntime* const runtime,
  const void* const vector2Runtime,
  const void* const box2Runtime
)
{
  static std::uint8_t sDistVector2Box2dRuntimeVtableTag = 0;
  if (runtime == nullptr) {
    return nullptr;
  }

  (void)InitializeDistanceVector2dRuntime(runtime, &sDistVector2Box2dRuntimeVtableTag);
  runtime->vector2Runtime = vector2Runtime;
  runtime->box2Runtime = box2Runtime;
  return runtime;
}

/**
 * Address: 0x00A6C6B0 (FUN_00A6C6B0)
 *
 * What it does:
 * Runs one deleting-dtor thunk lane for the float distance-vector2 runtime
 * object by rebinding base vtable state and scalar-deleting when requested.
 */
[[maybe_unused]] void* ResetDistanceFloat2VtableWithFlagRuntime(
  void* const distanceRuntime,
  const std::uint8_t deleteFlags
) noexcept
{
  auto* const distance = static_cast<VtableOnlyRuntime*>(distanceRuntime);
  ResetDistanceFloat2VtableRuntime(distance);
  if ((deleteFlags & 1u) != 0u) {
    ::operator delete(distance);
  }
  return distance;
}

/**
 * Address: 0x00A6C6D0 (FUN_00A6C6D0)
 *
 * What it does:
 * Runs one deleting-dtor thunk lane for the double distance-vector2 runtime
 * object by rebinding base vtable state and scalar-deleting when requested.
 */
[[maybe_unused]] void* ResetDistanceDouble2VtableWithFlagRuntime(
  void* const distanceRuntime,
  const std::uint8_t deleteFlags
) noexcept
{
  auto* const distance = static_cast<VtableOnlyRuntime*>(distanceRuntime);
  ResetDistanceDouble2VtableRuntime(distance);
  if ((deleteFlags & 1u) != 0u) {
    ::operator delete(distance);
  }
  return distance;
}

/**
 * Address: 0x00A9A890 (FUN_00A9A890)
 *
 * What it does:
 * Returns MXCSR when compatibility mode is enabled; otherwise returns zero.
 */
[[maybe_unused]] int ReadMxcsrWhenCompatEnabledRuntime(
  const bool compatibilityEnabled
)
{
  return compatibilityEnabled ? static_cast<int>(_mm_getcsr()) : 0;
}

/**
 * Address: 0x00AA3B35 (FUN_00AA3B35)
 *
 * What it does:
 * Captures one runtime-frame context lane into global scratch words and
 * returns the original result lane.
 */
[[maybe_unused]] int CaptureRuntimeFrameContextRuntime(
  const int result,
  const int frameBase,
  const int arg3,
  std::uint32_t* const contextWords
)
{
  if (contextWords != nullptr) {
    contextWords[2] = static_cast<std::uint32_t>(arg3);
    contextWords[1] = static_cast<std::uint32_t>(result);
    contextWords[3] = static_cast<std::uint32_t>(frameBase);
  }
  return result;
}

/**
 * Address: 0x0076D150 (FUN_0076D150)
 *
 * What it does:
 * Writes `count` copies of one occupy-source binding payload into destination
 * storage and installs the occupy-source binding vtable lane on each record.
 */
[[maybe_unused]] OccupySourceBindingRuntime* FillOccupySourceBindingRangeRuntime(
  OccupySourceBindingRuntime* destination,
  const OccupySourceBindingRuntime* const sourcePrototype,
  std::uint32_t count,
  void* const occupySourceBindingVtable
)
{
  while (count != 0u) {
    if (destination != nullptr && sourcePrototype != nullptr) {
      destination->vtable = occupySourceBindingVtable;
      destination->lane04 = sourcePrototype->lane04;
      destination->lane08 = sourcePrototype->lane08;
      ++destination;
    }
    --count;
  }
  return destination;
}

/**
 * Address: 0x0076D300 (FUN_0076D300)
 *
 * What it does:
 * Copies one `[source, sourceEnd)` range of occupy-source bindings, installing
 * the binding vtable token for each copied lane.
 */
[[maybe_unused]] OccupySourceBindingRuntime* CopyOccupySourceBindingRangeRuntime(
  OccupySourceBindingRuntime* destination,
  const OccupySourceBindingRuntime* source,
  const OccupySourceBindingRuntime* const sourceEnd,
  void* const occupySourceBindingVtable
)
{
  while (source != sourceEnd) {
    if (destination != nullptr) {
      destination->vtable = occupySourceBindingVtable;
      destination->lane04 = source->lane04;
      destination->lane08 = source->lane08;
      ++destination;
    }
    ++source;
  }
  return destination;
}

/**
 * Address: 0x0076D290 (FUN_0076D290)
 * Address: 0x00579230 (FUN_00579230)
 *
 * What it does:
 * Register-shape adapter that forwards one occupy-source binding copy lane
 * into `CopyOccupySourceBindingRangeRuntime` using a zero-length source range.
 */
[[maybe_unused]] OccupySourceBindingRuntime* CopyOccupySourceBindingRangeRuntimeAdapterZeroSource(
  OccupySourceBindingRuntime* const destination,
  void* const occupySourceBindingVtable
)
{
  return CopyOccupySourceBindingRangeRuntime(destination, nullptr, nullptr, occupySourceBindingVtable);
}

/**
 * Address: 0x0076CD00 (FUN_0076CD00)
 *
 * What it does:
 * Register-shape adapter that copies one occupy-source binding tail range into
 * a destination lane, with `sourceEnd` carried by the caller register lane.
 */
[[maybe_unused]] OccupySourceBindingRuntime* CopyOccupySourceBindingRangeRuntimeTailAdapterLaneA(
  const OccupySourceBindingRuntime* const sourceBegin,
  OccupySourceBindingRuntime* const destinationBegin,
  const OccupySourceBindingRuntime* const sourceEndRegisterLane
)
{
  void* const occupySourceBindingVtable = (sourceBegin != nullptr) ? sourceBegin->vtable : nullptr;
  return CopyOccupySourceBindingRangeRuntime(
    destinationBegin,
    sourceBegin,
    sourceEndRegisterLane,
    occupySourceBindingVtable
  );
}

/**
 * Address: 0x0076CEE0 (FUN_0076CEE0)
 *
 * What it does:
 * Fastcall-shape adapter for occupy-source fill, forwarding destination/source
 * plus count lanes into the canonical fill helper.
 */
[[maybe_unused]] OccupySourceBindingRuntime* FillOccupySourceBindingRangeRuntimeAdapterLaneA(
  OccupySourceBindingRuntime* const destinationBegin,
  const OccupySourceBindingRuntime* const sourcePrototype,
  const std::uint32_t count
)
{
  void* const occupySourceBindingVtable = (sourcePrototype != nullptr) ? sourcePrototype->vtable : nullptr;
  return FillOccupySourceBindingRangeRuntime(
    destinationBegin,
    sourcePrototype,
    count,
    occupySourceBindingVtable
  );
}

/**
 * Address: 0x0076D000 (FUN_0076D000)
 *
 * What it does:
 * Secondary register-shape adapter for occupy-source tail-range copy.
 */
[[maybe_unused]] OccupySourceBindingRuntime* CopyOccupySourceBindingRangeRuntimeTailAdapterLaneB(
  const OccupySourceBindingRuntime* const sourceBegin,
  OccupySourceBindingRuntime* const destinationBegin,
  const OccupySourceBindingRuntime* const sourceEndRegisterLane
)
{
  void* const occupySourceBindingVtable = (sourceBegin != nullptr) ? sourceBegin->vtable : nullptr;
  return CopyOccupySourceBindingRangeRuntime(
    destinationBegin,
    sourceBegin,
    sourceEndRegisterLane,
    occupySourceBindingVtable
  );
}

/**
 * Address: 0x0076D1C0 (FUN_0076D1C0)
 * Address: 0x005181D0 (FUN_005181D0)
 *
 * What it does:
 * Third register-shape adapter for occupy-source tail-range copy.
 */
[[maybe_unused]] OccupySourceBindingRuntime* CopyOccupySourceBindingRangeRuntimeTailAdapterLaneC(
  const OccupySourceBindingRuntime* const sourceBegin,
  OccupySourceBindingRuntime* const destinationBegin,
  const OccupySourceBindingRuntime* const sourceEndRegisterLane
)
{
  void* const occupySourceBindingVtable = (sourceBegin != nullptr) ? sourceBegin->vtable : nullptr;
  return CopyOccupySourceBindingRangeRuntime(
    destinationBegin,
    sourceBegin,
    sourceEndRegisterLane,
    occupySourceBindingVtable
  );
}

/**
 * Address: 0x007D9B40 (FUN_007D9B40)
 *
 * What it does:
 * Copies one `[source, sourceEnd)` range of clutter seed lanes, installing the
 * seed vtable token for each copied lane.
 */
[[maybe_unused]] ClutterSeedRuntime* CopyClutterSeedRangeRuntime(
  ClutterSeedRuntime* destination,
  const ClutterSeedRuntime* source,
  const ClutterSeedRuntime* const sourceEnd,
  void* const clutterSeedVtable
)
{
  while (source != sourceEnd) {
    if (destination != nullptr) {
      destination->vtable = clutterSeedVtable;
      destination->lane04 = source->lane04;
      destination->lane08 = source->lane08;
      destination->lane0C = source->lane0C;
      ++destination;
    }
    ++source;
  }
  return destination;
}

/**
 * Address: 0x007D99C0 (FUN_007D99C0)
 *
 * What it does:
 * Register-shape adapter that forwards one clutter-seed range copy into
 * `CopyClutterSeedRangeRuntime`, deriving the vtable token from source lane.
 */
[[maybe_unused]] ClutterSeedRuntime* CopyClutterSeedRangeRuntimeAdapterA(
  ClutterSeedRuntime* const destination,
  const ClutterSeedRuntime* const source,
  const ClutterSeedRuntime* const sourceEnd
)
{
  void* const clutterSeedVtable = (source != nullptr) ? source->vtable : nullptr;
  return CopyClutterSeedRangeRuntime(destination, source, sourceEnd, clutterSeedVtable);
}

/**
 * Address: 0x007D9AA0 (FUN_007D9AA0)
 *
 * What it does:
 * Secondary register-shape adapter for clutter-seed range copy.
 */
[[maybe_unused]] ClutterSeedRuntime* CopyClutterSeedRangeRuntimeAdapterB(
  ClutterSeedRuntime* const destination,
  const ClutterSeedRuntime* const source,
  const ClutterSeedRuntime* const sourceEnd
)
{
  void* const clutterSeedVtable = (source != nullptr) ? source->vtable : nullptr;
  return CopyClutterSeedRangeRuntime(destination, source, sourceEnd, clutterSeedVtable);
}

/**
 * Address: 0x007D9B20 (FUN_007D9B20)
 *
 * What it does:
 * Third register-shape adapter for clutter-seed range copy.
 */
[[maybe_unused]] ClutterSeedRuntime* CopyClutterSeedRangeRuntimeAdapterC(
  ClutterSeedRuntime* const destination,
  const ClutterSeedRuntime* const source,
  const ClutterSeedRuntime* const sourceEnd
)
{
  void* const clutterSeedVtable = (source != nullptr) ? source->vtable : nullptr;
  return CopyClutterSeedRangeRuntime(destination, source, sourceEnd, clutterSeedVtable);
}

/**
 * Address: 0x004F7CF0 (FUN_004F7CF0)
 *
 * What it does:
 * Rebinds wios/ostream/istream subobject lanes to teardown vtables and invokes
 * `ios_base` final destruction on the `+0x0C` subobject lane.
 */
[[maybe_unused]] void DestroyWideIoStreamBaseRuntime(
  std::byte* const completeObject,
  const WideIoStreamOffsetsRuntime& offsets,
  void* const wiosVtable,
  void* const wostreamVtable,
  void* const wistreamVtable,
  void* const iosBaseVtable,
  const IosBaseDtorFn iosBaseDtorFn
)
{
  if (completeObject == nullptr || iosBaseDtorFn == nullptr) {
    return;
  }

  *reinterpret_cast<void**>(completeObject + offsets.wiosOffset) = wiosVtable;
  *reinterpret_cast<void**>(completeObject + offsets.iosbOffset) = wostreamVtable;
  *reinterpret_cast<void**>(completeObject + offsets.wistreamOffset) = wistreamVtable;

  std::byte* const iosBaseLane = completeObject + 12;
  *reinterpret_cast<void**>(iosBaseLane) = iosBaseVtable;
  iosBaseDtorFn(iosBaseLane);
}

/**
 * Address: 0x004F7CB0 (FUN_004F7CB0)
 *
 * What it does:
 * Rebinds one wide-ostream teardown lane (`iosb`/`ios_base` subobject) and
 * invokes `ios_base` destruction for the `+0x04` subobject path.
 */
[[maybe_unused]] void DestroyWideOstreamIosBaseLaneRuntime(
  std::byte* const completeObject,
  void* const wostreamIosbVtable,
  void* const iosBaseVtable,
  const IosBaseDtorFn iosBaseDtorFn
) noexcept
{
  if (completeObject == nullptr || iosBaseDtorFn == nullptr) {
    return;
  }

  auto** const completeVtable = *reinterpret_cast<void***>(completeObject);
  const std::ptrdiff_t vbaseAdjust = static_cast<std::ptrdiff_t>(
    reinterpret_cast<std::intptr_t>(completeVtable[1])
  );

  std::byte* const iosBaseLane = completeObject + 0x04;
  *reinterpret_cast<void**>(iosBaseLane + vbaseAdjust - 0x04) = wostreamIosbVtable;
  *reinterpret_cast<void**>(iosBaseLane) = iosBaseVtable;
  iosBaseDtorFn(iosBaseLane);
}

/**
 * Address: 0x004F7CD0 (FUN_004F7CD0)
 *
 * What it does:
 * Rebinds one wide-istream teardown lane (`wios`/`ios_base` subobject) and
 * invokes `ios_base` destruction for the `+0x08` subobject path.
 */
[[maybe_unused]] void DestroyWideIstreamIosBaseLaneRuntime(
  std::byte* const completeObject,
  void* const wistreamWiosVtable,
  void* const iosBaseVtable,
  const IosBaseDtorFn iosBaseDtorFn
) noexcept
{
  if (completeObject == nullptr || iosBaseDtorFn == nullptr) {
    return;
  }

  auto** const completeVtable = *reinterpret_cast<void***>(completeObject);
  const std::ptrdiff_t vbaseAdjust = static_cast<std::ptrdiff_t>(
    reinterpret_cast<std::intptr_t>(completeVtable[1])
  );

  std::byte* const iosBaseLane = completeObject + 0x08;
  *reinterpret_cast<void**>(iosBaseLane + vbaseAdjust - 0x08) = wistreamWiosVtable;
  *reinterpret_cast<void**>(iosBaseLane) = iosBaseVtable;
  iosBaseDtorFn(iosBaseLane);
}

/**
 * Address: 0x004F8240 (FUN_004F8240)
 *
 * What it does:
 * Forwards one runtime-failure lane to the core dispatcher and never returns.
 */
[[maybe_unused]] [[noreturn]] void DispatchRuntimeFailureAndTerminateRuntime(
  const int arg0,
  const int arg1,
  const RuntimeFailureDispatchFn dispatchFn
)
{
  if (dispatchFn != nullptr) {
    dispatchFn(arg0, arg1);
  }
  std::terminate();
}

/**
 * Address: 0x00837750 (FUN_00837750)
 *
 * What it does:
 * Compares one 48-byte-stride build-queue snapshot against the current queue
 * and reports equality when comparator output reaches the snapshot end.
 */
[[maybe_unused]] BOOL CompareBuildQueueSnapshotRuntime(
  const BuildQueueSnapshotRuntime* const snapshot,
  const BuildQueueRangeRuntime* const currentQueue,
  const BuildQueueCompareFn compareFn
)
{
  if (snapshot == nullptr || currentQueue == nullptr || compareFn == nullptr) {
    return FALSE;
  }

  const std::ptrdiff_t snapshotCount = CountStride48Elements(snapshot->begin, snapshot->end);
  const std::ptrdiff_t currentCount = CountStride48Elements(currentQueue->start, currentQueue->end);
  if (snapshotCount != currentCount) {
    return FALSE;
  }

  BuildQueueCompareStateRuntime state{};
  auto* const compareResult = compareFn(&state, snapshot->begin, snapshot->end, currentQueue->start, 0u, 0u);
  return (compareResult != nullptr && compareResult->cursor == snapshot->end) ? TRUE : FALSE;
}

/**
 * Address: 0x007B2560 (FUN_007B2560)
 *
 * What it does:
 * Clears one RB-tree storage lane, frees the storage block, and resets owner
 * pointers/count.
 */
[[maybe_unused]] int ClearTreeStorageLaneA17Runtime(
  TreeStorageOwnerRuntime* const owner,
  const TreeClearFn clearFn
)
{
  if (owner == nullptr) {
    return 0;
  }

  std::uint32_t scratch = 0u;
  if (owner->treeStorage != nullptr && clearFn != nullptr) {
    void* const root = *reinterpret_cast<void**>(owner->treeStorage);
    clearFn(&scratch, root, owner->treeStorage);
  }

  ::operator delete(owner->treeStorage);
  owner->treeStorage = nullptr;
  owner->size = 0u;
  return 0;
}

/**
 * Address: 0x007B2590 (FUN_007B2590)
 *
 * What it does:
 * Clears one map-backed tree storage lane, frees the storage block, and
 * resets owner pointers/count.
 */
[[maybe_unused]] int ClearTreeStorageLaneB17Runtime(
  TreeStorageOwnerRuntime* const owner,
  const TreeClearFn clearFn
)
{
  if (owner == nullptr) {
    return 0;
  }

  std::uint32_t scratch = 0u;
  if (owner->treeStorage != nullptr && clearFn != nullptr) {
    void* const root = *reinterpret_cast<void**>(owner->treeStorage);
    clearFn(&scratch, root, owner->treeStorage);
  }

  ::operator delete(owner->treeStorage);
  owner->treeStorage = nullptr;
  owner->size = 0u;
  return 0;
}

/**
 * Address: 0x007B26B0 (FUN_007B26B0)
 *
 * What it does:
 * Finds-or-inserts one `uint` key in an RB-tree lane whose nil flag lives at
 * `+0x11`, returning `(node, inserted)`.
 */
[[maybe_unused]] MapInsertStatusRuntime* FindOrInsertMapNodeNil17Runtime(
  LegacyMapStorageRuntime<MapNodeNil17Runtime>* const map,
  const std::uint32_t* const key,
  MapInsertStatusRuntime* const outResult
)
{
  return FindOrInsertMapNodeByKey(map, key, outResult);
}

namespace
{
  struct OwnerSlotNodeRuntime
  {
    std::uint32_t lane00;
    std::uint32_t lane04;
    std::uint32_t lane08;
    std::uint32_t lane0C;
    void* ownerLinkSlot; // +0x10
  };

  struct OwnerSlotIndexRuntime
  {
    std::uint32_t lane00;
    OwnerSlotNodeRuntime* node; // +0x04
  };

  static_assert(offsetof(OwnerSlotNodeRuntime, ownerLinkSlot) == 0x10, "OwnerSlotNodeRuntime::ownerLinkSlot offset must be 0x10");
  static_assert(offsetof(OwnerSlotIndexRuntime, node) == 0x04, "OwnerSlotIndexRuntime::node offset must be 0x04");
}

/**
 * Address: 0x007B2920 (FUN_007B2920)
 *
 * What it does:
 * Resolves one owner pointer from an index node's weak-owner slot lane
 * (`ownerLinkSlot - 8`), returning null when no owner slot is linked.
 */
[[maybe_unused]] void* ResolveOwnerFromIndexWeakSlotRuntime(
  const OwnerSlotIndexRuntime* const index
) noexcept
{
  if (index == nullptr || index->node == nullptr || index->node->ownerLinkSlot == nullptr) {
    return nullptr;
  }

  return static_cast<void*>(reinterpret_cast<std::byte*>(index->node->ownerLinkSlot) - 8u);
}

/**
 * Address: 0x007B2940 (FUN_007B2940)
 *
 * What it does:
 * Clears one RB-tree storage lane, frees the storage block, and resets owner
 * pointers/count.
 */
[[maybe_unused]] int ClearTreeStorageLaneC21Runtime(
  TreeStorageOwnerRuntime* const owner,
  const TreeClearFn clearFn
)
{
  if (owner == nullptr) {
    return 0;
  }

  std::uint32_t scratch = 0u;
  if (owner->treeStorage != nullptr && clearFn != nullptr) {
    void* const root = *reinterpret_cast<void**>(owner->treeStorage);
    clearFn(&scratch, root, owner->treeStorage);
  }

  ::operator delete(owner->treeStorage);
  owner->treeStorage = nullptr;
  owner->size = 0u;
  return 0;
}

/**
 * Address: 0x007B2970 (FUN_007B2970)
 *
 * What it does:
 * Clears one embedded secondary RB-tree lane at owner offset `+0x08`, frees
 * its storage block, and resets owner pointers/count.
 */
[[maybe_unused]] int ClearEmbeddedSecondaryTreeLaneRuntime(
  std::byte* const ownerBytes,
  const TreeClearFn clearFn
)
{
  if (ownerBytes == nullptr) {
    return 0;
  }

  auto* const embeddedOwner = reinterpret_cast<TreeStorageOwnerRuntime*>(ownerBytes + 4u);
  std::uint32_t scratch = 0u;
  if (embeddedOwner->treeStorage != nullptr && clearFn != nullptr) {
    void* const root = *reinterpret_cast<void**>(embeddedOwner->treeStorage);
    clearFn(&scratch, root, embeddedOwner->treeStorage);
  }

  ::operator delete(embeddedOwner->treeStorage);
  embeddedOwner->treeStorage = nullptr;
  embeddedOwner->size = 0u;
  return 0;
}

/**
 * Address: 0x007B36A0 (FUN_007B36A0)
 *
 * What it does:
 * Clears one RB-tree storage lane, frees the storage block, and resets owner
 * pointers/count.
 */
[[maybe_unused]] int ClearTreeStorageLaneD21Runtime(
  TreeStorageOwnerRuntime* const owner,
  const TreeClearFn clearFn
)
{
  if (owner == nullptr) {
    return 0;
  }

  std::uint32_t scratch = 0u;
  if (owner->treeStorage != nullptr && clearFn != nullptr) {
    void* const root = *reinterpret_cast<void**>(owner->treeStorage);
    clearFn(&scratch, root, owner->treeStorage);
  }

  ::operator delete(owner->treeStorage);
  owner->treeStorage = nullptr;
  owner->size = 0u;
  return 0;
}

/**
 * Address: 0x007B3760 (FUN_007B3760)
 *
 * What it does:
 * Finds-or-inserts one `uint` key in an RB-tree lane whose nil flag lives at
 * `+0x1D`, returning `(node, inserted)`.
 */
[[maybe_unused]] MapInsertStatusRuntime* FindOrInsertMapNodeNil29Runtime(
  LegacyMapStorageRuntime<MapNodeNil29Runtime>* const map,
  const std::uint32_t* const key,
  MapInsertStatusRuntime* const outResult
)
{
  return FindOrInsertMapNodeByKey(map, key, outResult);
}

/**
 * Address: 0x007BE3B0 (FUN_007BE3B0)
 *
 * What it does:
 * Copies records from wrapped pointer arrays while walking source/destination
 * cursors backward.
 */
[[maybe_unused]] WrappedArrayCursorRuntime* CopyWrappedRecordRangeReverseRuntime(
  WrappedArrayCursorRuntime* const outCursor,
  const WrappedArrayCursorRuntime stopCursor,
  WrappedArrayCursorRuntime sourceCursor,
  WrappedArrayCursorRuntime destinationCursor,
  const NetCommandRecordCopyFn copyRecordFn
)
{
  if (outCursor == nullptr) {
    return nullptr;
  }

  while (stopCursor.owner != sourceCursor.owner || stopCursor.logicalIndex != sourceCursor.logicalIndex) {
    --sourceCursor.logicalIndex;
    const auto sourceWord = ResolveWrappedPointerWord(sourceCursor.owner, sourceCursor.logicalIndex);
    auto* const sourceRecord = reinterpret_cast<const NetCommandRecordRuntime*>(static_cast<std::uintptr_t>(sourceWord));

    --destinationCursor.logicalIndex;
    const auto destinationWord = ResolveWrappedPointerWord(destinationCursor.owner, destinationCursor.logicalIndex);
    auto* const destinationRecord = reinterpret_cast<NetCommandRecordRuntime*>(static_cast<std::uintptr_t>(destinationWord));

    if (copyRecordFn != nullptr && destinationRecord != nullptr && sourceRecord != nullptr) {
      copyRecordFn(destinationRecord, sourceRecord);
    }
  }

  outCursor->owner = destinationCursor.owner;
  outCursor->logicalIndex = destinationCursor.logicalIndex;
  return outCursor;
}

/**
 * Address: 0x007BE430 (FUN_007BE430)
 *
 * What it does:
 * Copies records from wrapped pointer arrays while walking source/destination
 * cursors forward.
 */
[[maybe_unused]] WrappedArrayCursorRuntime* CopyWrappedRecordRangeForwardRuntime(
  WrappedArrayCursorRuntime* const outCursor,
  const WrappedArrayCursorRuntime stopCursor,
  WrappedArrayCursorRuntime sourceCursor,
  WrappedArrayCursorRuntime destinationCursor,
  const NetCommandRecordCopyFn copyRecordFn
)
{
  if (outCursor == nullptr) {
    return nullptr;
  }

  while (sourceCursor.owner != stopCursor.owner || sourceCursor.logicalIndex != stopCursor.logicalIndex) {
    const auto sourceWord = ResolveWrappedPointerWord(sourceCursor.owner, sourceCursor.logicalIndex);
    auto* const sourceRecord = reinterpret_cast<const NetCommandRecordRuntime*>(static_cast<std::uintptr_t>(sourceWord));
    const auto destinationWord = ResolveWrappedPointerWord(destinationCursor.owner, destinationCursor.logicalIndex);
    auto* const destinationRecord = reinterpret_cast<NetCommandRecordRuntime*>(static_cast<std::uintptr_t>(destinationWord));

    if (copyRecordFn != nullptr && destinationRecord != nullptr && sourceRecord != nullptr) {
      copyRecordFn(destinationRecord, sourceRecord);
    }

    ++sourceCursor.logicalIndex;
    ++destinationCursor.logicalIndex;
  }

  outCursor->owner = destinationCursor.owner;
  outCursor->logicalIndex = destinationCursor.logicalIndex;
  return outCursor;
}

/**
 * Address: 0x007C87E0 (FUN_007C87E0)
 *
 * What it does:
 * Appends one 16-byte lane in-place when capacity remains, otherwise routes
 * through the vector growth path.
 */
[[maybe_unused]] int Append16ByteLaneWithGrowRuntime(
  const std::uint32_t inputWord,
  Vector16ByteOwnerRuntime* const owner,
  const Vector16ConstructFn constructFn,
  const Vector16GrowFn growFn
)
{
  if (owner == nullptr) {
    return 0;
  }

  const std::ptrdiff_t size = (owner->begin != nullptr && owner->end != nullptr) ? ((owner->end - owner->begin) >> 4) : 0;
  const std::ptrdiff_t capacity = (owner->begin != nullptr && owner->capacity != nullptr) ? ((owner->capacity - owner->begin) >> 4) : 0;
  if (owner->begin == nullptr || size >= capacity) {
    return growFn != nullptr ? growFn(owner, owner->end, inputWord) : 0;
  }

  std::byte* const tail = owner->end;
  const int result = constructFn != nullptr ? constructFn(tail, 0u, 0u) : 0;
  owner->end = tail + 16;
  return result;
}

/**
 * Address: 0x007C9010 (FUN_007C9010)
 *
 * What it does:
 * Clears one owner-coupled tree storage lane via the 4-argument clear helper,
 * frees storage, and resets owner pointers/count.
 */
[[maybe_unused]] int ClearOwnedTreeStorageLaneARuntime(
  TreeStorageOwnerRuntime* const owner,
  const TreeClearWithOwnerFn clearFn
)
{
  if (owner == nullptr) {
    return 0;
  }

  std::uint32_t scratch = 0u;
  if (owner->treeStorage != nullptr && clearFn != nullptr) {
    void* const root = *reinterpret_cast<void**>(owner->treeStorage);
    clearFn(owner, &scratch, root, owner->treeStorage);
  }

  ::operator delete(owner->treeStorage);
  owner->treeStorage = nullptr;
  owner->size = 0u;
  return 0;
}

/**
 * Address: 0x007C9950 (FUN_007C9950)
 *
 * What it does:
 * Clears one owner-coupled tree storage lane via the 4-argument clear helper,
 * frees storage, and resets owner pointers/count.
 */
[[maybe_unused]] int ClearOwnedTreeStorageLaneBRuntime(
  TreeStorageOwnerRuntime* const owner,
  const TreeClearWithOwnerFn clearFn
)
{
  if (owner == nullptr) {
    return 0;
  }

  std::uint32_t scratch = 0u;
  if (owner->treeStorage != nullptr && clearFn != nullptr) {
    void* const root = *reinterpret_cast<void**>(owner->treeStorage);
    clearFn(owner, &scratch, root, owner->treeStorage);
  }

  ::operator delete(owner->treeStorage);
  owner->treeStorage = nullptr;
  owner->size = 0u;
  return 0;
}

/**
 * Address: 0x007CDED0 (FUN_007CDED0)
 *
 * What it does:
 * Finds-or-inserts one `char` key in a set-style RB-tree lane whose nil flag
 * lives at `+0x0E`, returning `(node, inserted)`.
 */
[[maybe_unused]] MapInsertStatusRuntime* FindOrInsertSetCharNodeRuntime(
  LegacyMapStorageRuntime<SetCharNodeNil14Runtime>* const setStorage,
  const std::int8_t* const key,
  MapInsertStatusRuntime* const outResult
)
{
  if (outResult == nullptr) {
    return nullptr;
  }

  outResult->node = nullptr;
  outResult->inserted = 0u;
  outResult->reserved[0] = 0u;
  outResult->reserved[1] = 0u;
  outResult->reserved[2] = 0u;
  if (setStorage == nullptr || key == nullptr) {
    return outResult;
  }

  SetCharNodeNil14Runtime* head = setStorage->head;
  if (head == nullptr) {
    head = static_cast<SetCharNodeNil14Runtime*>(::operator new(sizeof(SetCharNodeNil14Runtime), std::nothrow));
    if (head == nullptr) {
      return outResult;
    }

    std::memset(head, 0, sizeof(SetCharNodeNil14Runtime));
    head->left = head;
    head->parent = head;
    head->right = head;
    head->isNil = 1u;
    setStorage->head = head;
    setStorage->size = 0u;
  }

  SetCharNodeNil14Runtime* parent = head;
  SetCharNodeNil14Runtime* cursor = head->parent;
  bool goLeft = true;
  while (cursor != nullptr && cursor != head && cursor->isNil == 0u) {
    parent = cursor;
    if (*key < cursor->value) {
      goLeft = true;
      cursor = cursor->left;
    } else if (cursor->value < *key) {
      goLeft = false;
      cursor = cursor->right;
    } else {
      outResult->node = cursor;
      return outResult;
    }
  }

  auto* const inserted = static_cast<SetCharNodeNil14Runtime*>(::operator new(sizeof(SetCharNodeNil14Runtime), std::nothrow));
  if (inserted == nullptr) {
    return outResult;
  }

  std::memset(inserted, 0, sizeof(SetCharNodeNil14Runtime));
  inserted->left = head;
  inserted->right = head;
  inserted->parent = (parent != nullptr) ? parent : head;
  inserted->value = *key;
  inserted->color = 0u;
  inserted->isNil = 0u;

  if (parent == nullptr || parent == head || parent->isNil != 0u) {
    head->parent = inserted;
    head->left = inserted;
    head->right = inserted;
  } else if (goLeft) {
    parent->left = inserted;
    if (head->left == parent || head->left == head) {
      head->left = inserted;
    }
  } else {
    parent->right = inserted;
    if (head->right == parent || head->right == head) {
      head->right = inserted;
    }
  }

  ++setStorage->size;
  outResult->node = inserted;
  outResult->inserted = 1u;
  return outResult;
}

/**
 * Address: 0x007CEDB0 (FUN_007CEDB0)
 *
 * What it does:
 * Performs upward heap insertion for one `(priority, LuaObject)` lane in a
 * 24-byte stride heap array.
 */
[[maybe_unused]] void InsertLuaHeapPairRuntime(
  std::int32_t insertIndex,
  const std::int32_t firstIndex,
  std::byte* const heapStorage,
  const std::int32_t priority,
  LuaPlus::LuaObject value
)
{
  if (heapStorage == nullptr) {
    return;
  }

  std::int32_t parent = (insertIndex - 1) / 2;
  while (firstIndex < insertIndex) {
    std::byte* const parentEntry = heapStorage + (static_cast<std::size_t>(parent) * 24u);
    const auto parentPriority = *reinterpret_cast<std::int32_t*>(parentEntry);
    if (parentPriority >= priority) {
      break;
    }

    std::byte* const targetEntry = heapStorage + (static_cast<std::size_t>(insertIndex) * 24u);
    *reinterpret_cast<std::int32_t*>(targetEntry) = parentPriority;
    *reinterpret_cast<LuaPlus::LuaObject*>(targetEntry + 4u) = *reinterpret_cast<LuaPlus::LuaObject*>(parentEntry + 4u);
    insertIndex = parent;
    parent = (parent - 1) / 2;
  }

  std::byte* const insertEntry = heapStorage + (static_cast<std::size_t>(insertIndex) * 24u);
  *reinterpret_cast<std::int32_t*>(insertEntry) = priority;
  *reinterpret_cast<LuaPlus::LuaObject*>(insertEntry + 4u) = value;
}

/**
 * Address: 0x007CF8C0 (FUN_007CF8C0)
 *
 * What it does:
 * Clears one owner-coupled tree storage lane via the 4-argument clear helper,
 * frees storage, and resets owner pointers/count.
 */
[[maybe_unused]] TreeStorageOwnerRuntime* ClearOwnedTreeStorageLaneAndReturnOwnerRuntime(
  TreeStorageOwnerRuntime* const owner,
  const TreeClearWithOwnerFn clearFn
)
{
  if (owner == nullptr) {
    return nullptr;
  }

  std::uint32_t scratch = 0u;
  if (owner->treeStorage != nullptr && clearFn != nullptr) {
    void* const root = *reinterpret_cast<void**>(owner->treeStorage);
    clearFn(owner, &scratch, root, owner->treeStorage);
  }

  ::operator delete(owner->treeStorage);
  owner->treeStorage = nullptr;
  owner->size = 0u;
  return owner;
}

/**
 * Address: 0x007D4320 (FUN_007D4320)
 *
 * What it does:
 * Clears one cartographic-decal owner lane via its list clear routine, frees
 * list storage, and resets the storage pointer.
 */
[[maybe_unused]] void ClearAndReleaseCartographicDecalOwnerRuntime(
  TreeStorageOwnerRuntime* const owner,
  const OwnerTreeClearFn clearOwnerFn
)
{
  if (owner == nullptr) {
    return;
  }

  if (clearOwnerFn != nullptr) {
    clearOwnerFn(owner);
  }

  ::operator delete(owner->treeStorage);
  owner->treeStorage = nullptr;
}

/**
 * Address: 0x007E2E60 (FUN_007E2E60)
 *
 * What it does:
 * Finds one lookup node by text key and returns either the matched node or the
 * owner sentinel when append-to-sink fails.
 */
[[maybe_unused]] void** FindLookupNodeAndAppendTextRuntime(
  void* const textSink,
  void** const outNode,
  void* const owner,
  const void* const key,
  const LookupNodeByTextFn lookupFn,
  const AppendLookupTextFn appendFn
)
{
  if (outNode == nullptr) {
    return nullptr;
  }

  void* sentinel = nullptr;
  if (owner != nullptr) {
    sentinel = *reinterpret_cast<void**>(static_cast<std::byte*>(owner) + 4u);
  }

  void* node = sentinel;
  if (lookupFn != nullptr) {
    node = lookupFn(owner, key);
  }

  if (node == sentinel || appendFn == nullptr || appendFn(textSink, node) < 0) {
    *outNode = sentinel;
    return outNode;
  }

  *outNode = node;
  return outNode;
}

/**
 * Address: 0x007E5170 (FUN_007E5170)
 *
 * What it does:
 * Initializes a shared-ref pair from one object lane, enables
 * shared-from-this, then releases the previous counter lane.
 */
[[maybe_unused]] void AssignSharedRefWithEnableRuntime(
  void* const object,
  SharedRefRuntime* const destination,
  const InitSharedRefFn initFn,
  const EnableSharedFromThisFn enableFn
)
{
  if (destination == nullptr) {
    return;
  }

  SharedRefInitRuntime temporary{object, nullptr};
  if (initFn != nullptr) {
    initFn(&temporary, object);
  }
  if (enableFn != nullptr) {
    enableFn(&temporary, object, object);
  }

  void* const previousCounter = destination->counter;
  destination->object = object;
  destination->counter = temporary.counter;
  ReleaseSharedCounterRuntime(previousCounter);
}

/**
 * Address: 0x007E5B20 (FUN_007E5B20)
 *
 * What it does:
 * Finds-or-inserts one 2-word key in a pair-key RB-tree lane whose nil flag
 * lives at `+0x25`, returning `(node, inserted)`.
 */
[[maybe_unused]] MapInsertStatusRuntime* FindOrInsertPairKeyNodeRuntime(
  const PairKeyRuntime* const key,
  LegacyMapStorageRuntime<PairKeyNodeNil37Runtime>* const map,
  MapInsertStatusRuntime* const outResult
)
{
  if (outResult == nullptr) {
    return nullptr;
  }

  outResult->node = nullptr;
  outResult->inserted = 0u;
  outResult->reserved[0] = 0u;
  outResult->reserved[1] = 0u;
  outResult->reserved[2] = 0u;
  if (map == nullptr || key == nullptr) {
    return outResult;
  }

  PairKeyNodeNil37Runtime* const head = EnsurePairMapHeadRuntime(map);
  if (head == nullptr) {
    return outResult;
  }

  PairKeyNodeNil37Runtime* parent = head;
  PairKeyNodeNil37Runtime* cursor = head->parent;
  bool goLeft = true;
  while (cursor != nullptr && cursor != head && cursor->isNil == 0u) {
    parent = cursor;
    const PairKeyRuntime cursorKey{cursor->keyHigh, cursor->keyLow};
    if (PairKeyLessRuntime(*key, cursorKey)) {
      goLeft = true;
      cursor = cursor->left;
    } else if (PairKeyLessRuntime(cursorKey, *key)) {
      goLeft = false;
      cursor = cursor->right;
    } else {
      outResult->node = cursor;
      return outResult;
    }
  }

  auto* const inserted = static_cast<PairKeyNodeNil37Runtime*>(::operator new(sizeof(PairKeyNodeNil37Runtime), std::nothrow));
  if (inserted == nullptr) {
    return outResult;
  }

  std::memset(inserted, 0, sizeof(PairKeyNodeNil37Runtime));
  inserted->left = head;
  inserted->right = head;
  inserted->parent = (parent != nullptr) ? parent : head;
  inserted->keyHigh = key->high;
  inserted->keyLow = key->low;
  inserted->isNil = 0u;

  if (parent == nullptr || parent == head || parent->isNil != 0u) {
    head->parent = inserted;
    head->left = inserted;
    head->right = inserted;
  } else if (goLeft) {
    parent->left = inserted;
    if (head->left == parent || head->left == head) {
      head->left = inserted;
    }
  } else {
    parent->right = inserted;
    if (head->right == parent || head->right == head) {
      head->right = inserted;
    }
  }

  ++map->size;
  outResult->node = inserted;
  outResult->inserted = 1u;
  return outResult;
}

/**
 * Address: 0x007E6090 (FUN_007E6090)
 *
 * What it does:
 * Allocates one pair-key map node lane, writes keys/payload, and clears
 * color/nil state bytes.
 */
[[maybe_unused]] PairNodeRuntime* AllocatePairNodeRuntime(
  const std::int32_t keyHigh,
  const std::int32_t keyLow,
  const std::int32_t keyExtra,
  const std::int32_t payloadSource,
  const PairNodeAllocFn allocFn,
  const PairNodePayloadInitFn initPayloadFn
)
{
  if (allocFn == nullptr) {
    return nullptr;
  }

  PairNodeRuntime* const node = allocFn(1u);
  if (node == nullptr) {
    return nullptr;
  }

  node->lane00 = keyHigh;
  node->lane04 = keyLow;
  node->lane08 = keyExtra;
  if (initPayloadFn != nullptr) {
    initPayloadFn(node->payload0C, payloadSource);
  }
  node->color = 0u;
  node->isNil = 0u;
  return node;
}

/**
 * Address: 0x007E6180 (FUN_007E6180)
 *
 * What it does:
 * Copy-constructs one 24-byte pair-node payload lane with MeshKey-shaped
 * storage and retains shared/weak control counters for copied owner lanes.
 */
[[maybe_unused]] PairNodeMeshKeyPayloadRuntime* CopyPairNodeMeshKeyPayloadWithRetainedOwnersRuntime(
  PairNodeMeshKeyPayloadRuntime* const destination,
  const PairNodeMeshKeyPayloadRuntime* const source
) noexcept
{
  if (destination == nullptr || source == nullptr) {
    return destination;
  }

  destination->vtable = &gPairNodeMeshKeyPayloadRuntimeVTableTag;
  destination->lane04 = source->lane04;
  destination->sharedObjectLane08 = source->sharedObjectLane08;

  destination->sharedControlLane0C = source->sharedControlLane0C;
  if (destination->sharedControlLane0C != nullptr) {
    (void)::InterlockedExchangeAdd(
      reinterpret_cast<volatile LONG*>(reinterpret_cast<std::uint8_t*>(destination->sharedControlLane0C) + 4u),
      1
    );
  }

  destination->weakObjectLane10 = source->weakObjectLane10;
  destination->weakControlLane14 = source->weakControlLane14;
  if (destination->weakControlLane14 != nullptr) {
    (void)::InterlockedExchangeAdd(
      reinterpret_cast<volatile LONG*>(reinterpret_cast<std::uint8_t*>(destination->weakControlLane14) + 8u),
      1
    );
  }

  return destination;
}

/**
 * Address: 0x007E6AD0 (FUN_007E6AD0)
 *
 * What it does:
 * Runs one pre-delete hook for an object lane, then frees the object storage.
 */
[[maybe_unused]] void RunCleanupThenDeleteObjectRuntime(
  void* const object,
  const ObjectPreDeleteFn preDeleteFn
)
{
  if (object == nullptr) {
    return;
  }

  if (preDeleteFn != nullptr) {
    preDeleteFn(object);
  }
  ::operator delete(object);
}

/**
 * Address: 0x00739D80 (FUN_00739D80)
 *
 * What it does:
 * Erases one intrusive-list node (except sentinel head), relinks neighbor
 * lanes, releases node storage, decrements list size, and returns the next
 * node through `outNext`.
 */
[[maybe_unused]] IntrusiveListNodeRuntime** EraseIntrusiveListNodeRuntime(
  IntrusiveListNodeRuntime** const outNext,
  IntrusiveListRuntime* const owner,
  IntrusiveListNodeRuntime* const node
)
{
  if (outNext == nullptr || owner == nullptr || node == nullptr) {
    return outNext;
  }

  IntrusiveListNodeRuntime* const next = node->next;
  if (node != owner->head) {
    if (node->prev != nullptr) {
      node->prev->next = node->next;
    }
    if (node->next != nullptr) {
      node->next->prev = node->prev;
    }

    ::operator delete(node);
    --owner->size;
  }

  *outNext = next;
  return outNext;
}

/**
 * Address: 0x007EB4F0 (FUN_007EB4F0)
 *
 * What it does:
 * Replaces one destination intrusive-list lane with source contents when the
 * lists differ, then clears the source list.
 */
[[maybe_unused]] std::size_t TransferListContentAndClearSourceRuntime(
  IntrusiveListRuntime* const destination,
  std::byte* const sourceOwnerBytes,
  const ListClearFn clearFn,
  const ListSpliceFn spliceFn
)
{
  if (destination == nullptr || sourceOwnerBytes == nullptr || clearFn == nullptr) {
    return 0u;
  }

  auto* const source = reinterpret_cast<IntrusiveListRuntime*>(sourceOwnerBytes + 0x30);
  if (destination != source && source->head != nullptr && spliceFn != nullptr) {
    IntrusiveListNodeRuntime* const sourceHead = source->head;
    IntrusiveListNodeRuntime* const first = sourceHead->next;
    clearFn(destination);
    if (destination->head != nullptr) {
      spliceFn(destination, destination->head->next, first, sourceHead, first);
    }
  }

  clearFn(source);
  return static_cast<std::size_t>(destination->size);
}

/**
 * Address: 0x007EB5B0 (FUN_007EB5B0)
 *
 * What it does:
 * Copies one camera-snapshot lane and updates the weak-counted pointer lane
 * with retain/release semantics.
 */
[[maybe_unused]] void* CopyCameraSnapshotAndWeakCounterRuntime(
  const void* const source,
  void* const destination,
  const CameraCopyFn copyCameraFn,
  const WeakReleaseFn weakReleaseFn
)
{
  if (source == nullptr || destination == nullptr) {
    return destination;
  }

  const CameraSnapshotViewRuntime srcView(source);
  const CameraSnapshotViewRuntime dstView(destination);
  dstView.lane08() = srcView.lane08();
  if (copyCameraFn != nullptr) {
    copyCameraFn(dstView.cameraStorage(), srcView.cameraStorage());
  }

  dstView.lane2D8() = srcView.lane2D8();
  dstView.lane2DC() = srcView.lane2DC();
  dstView.lane2E0() = srcView.lane2E0();
  dstView.lane2E4() = srcView.lane2E4();
  dstView.lane2E8() = srcView.lane2E8();
  dstView.lane2EC() = srcView.lane2EC();
  dstView.lane2F0() = srcView.lane2F0();
  dstView.lane2F4() = srcView.lane2F4();
  dstView.lane2F8() = srcView.lane2F8();
  dstView.lane2FC() = srcView.lane2FC();
  dstView.lane300() = srcView.lane300();

  void* const incomingCounter = srcView.weakCounter304();
  if (incomingCounter != dstView.weakCounter304()) {
    if (incomingCounter != nullptr) {
      auto* const strong = reinterpret_cast<volatile LONG*>(static_cast<std::byte*>(incomingCounter) + 4u);
      (void)::InterlockedExchangeAdd(strong, 1);
    }

    void* const previousCounter = dstView.weakCounter304();
    if (previousCounter != nullptr && weakReleaseFn != nullptr) {
      weakReleaseFn(previousCounter);
    }
    dstView.weakCounter304() = incomingCounter;
  }

  return destination;
}

/**
 * Address: 0x007EBB20 (FUN_007EBB20)
 *
 * What it does:
 * Erases one mesh-thumbnail intrusive-list node (except sentinel), destroys
 * payload, and decrements list size.
 */
[[maybe_unused]] MeshThumbnailListNodeRuntime** EraseMeshThumbnailListNodeRuntime(
  MeshThumbnailListNodeRuntime** const outNext,
  TreeStorageOwnerRuntime* const listOwner,
  MeshThumbnailListNodeRuntime* const node,
  const MeshThumbnailDtorFn thumbnailDtorFn
)
{
  if (outNext == nullptr || listOwner == nullptr || node == nullptr) {
    return outNext;
  }

  auto* const sentinel = reinterpret_cast<MeshThumbnailListNodeRuntime*>(listOwner->treeStorage);
  MeshThumbnailListNodeRuntime* const next = node->next;
  if (node != sentinel) {
    if (node->prev != nullptr) {
      node->prev->next = node->next;
    }
    if (node->next != nullptr) {
      node->next->prev = node->prev;
    }

    if (thumbnailDtorFn != nullptr) {
      thumbnailDtorFn(node->thumbnailStorage);
    }
    ::operator delete(node);
    --listOwner->size;
  }

  *outNext = next;
  return outNext;
}

/**
 * Address: 0x007EF1C0 (FUN_007EF1C0)
 *
 * What it does:
 * Builds one current-selection range lane and, when valid, submits an
 * axis-aligned quad derived from selected entry bounds.
 */
[[maybe_unused]] int UpdateSelectedEntryBoundsRuntime(
  void* const owner,
  const void* const selectionState,
  const BuildSelectionRangeFn buildRangeFn,
  const SubmitSelectionQuadFn submitQuadFn
)
{
  if (owner == nullptr || selectionState == nullptr) {
    return 0;
  }

  auto* const ownerBytes = static_cast<std::byte*>(owner);
  void* const begin = *reinterpret_cast<void**>(ownerBytes + 4u);
  void* const end = *reinterpret_cast<void**>(ownerBytes + 8u);
  std::uint32_t rangeState[2]{};
  if (buildRangeFn != nullptr) {
    buildRangeFn(rangeState, owner, begin, end);
  }

  const UnitSelectionStateViewRuntime stateView(selectionState);
  int result = stateView.selectedIndex();
  if (result < 0) {
    return result;
  }

  void* const* const entries = stateView.entries();
  if (entries == nullptr) {
    return result;
  }

  const auto entryWord = reinterpret_cast<std::uintptr_t>(entries[result]);
  result = static_cast<int>(entryWord);
  if (entryWord == 0u) {
    return result;
  }

  const UnitSelectionEntryViewRuntime entryView(reinterpret_cast<const void*>(entryWord));
  if (entryView.sampleCount() <= 0) {
    return result;
  }

  float quad[4]{};
  quad[0] = entryView.minX() + entryView.extX();
  quad[1] = entryView.minY() + entryView.extY();
  quad[2] = 0.0f;
  quad[3] = entryView.minZ();
  return submitQuadFn != nullptr ? submitQuadFn(quad, owner) : result;
}

/**
 * Address: 0x007EFFA0 (FUN_007EFFA0)
 *
 * What it does:
 * Appends one 136-byte lane in-place when capacity remains, otherwise routes
 * through vector growth/reallocation path.
 */
[[maybe_unused]] void AppendOrGrowStride136VectorRuntime(
  Stride136VectorRuntime* const vector,
  void* const source,
  const ConstructStride136Fn constructFn,
  const GrowStride136Fn growFn
)
{
  if (vector == nullptr) {
    return;
  }

  const std::ptrdiff_t size = CountStride136Elements(vector->begin, vector->end);
  const std::ptrdiff_t capacity = CountStride136Elements(vector->begin, vector->capacity);
  if (vector->begin != nullptr && size < capacity) {
    std::byte* const tail = vector->end;
    if (constructFn != nullptr) {
      constructFn(tail, 1u, 0u, 0u);
    }
    vector->end = tail + 136u;
    return;
  }

  std::uint32_t scratch = 0u;
  if (growFn != nullptr) {
    growFn(vector, &scratch, vector->end, source);
  }
}

/**
 * Address: 0x007F2DA0 (FUN_007F2DA0)
 *
 * What it does:
 * Clones one tree storage lane when source root differs from current token and
 * swaps the owner root pointer to the new clone.
 */
[[maybe_unused]] void* CloneTreeStorageIntoOwnerRuntime(
  void* const currentToken,
  TreeStorageOwnerRuntime* const owner,
  void* const sourceRoot,
  const CloneTreeStorageFn cloneStorageFn,
  const CloneTreePayloadFn clonePayloadFn
)
{
  if (owner == nullptr) {
    return sourceRoot;
  }

  if (sourceRoot != currentToken && cloneStorageFn != nullptr) {
    void* const previousRoot = owner->treeStorage;
    void* const clonedRoot = cloneStorageFn(0u, 0u, 0u, sourceRoot);
    if (clonedRoot != nullptr) {
      if (clonePayloadFn != nullptr) {
        clonePayloadFn(clonedRoot, previousRoot);
      }
      owner->treeStorage = clonedRoot;
    }
  }
  return sourceRoot;
}

/**
 * Address: 0x007FC250 (FUN_007FC250)
 *
 * What it does:
 * Destroys one D3D texture-batcher lane and frees its storage.
 */
[[maybe_unused]] void DestroyTextureBatcherObjectRuntime(
  void* const batcher,
  const SimpleDtorFn destructorFn
)
{
  if (batcher == nullptr) {
    return;
  }

  if (destructorFn != nullptr) {
    destructorFn(batcher);
  }
  ::operator delete(batcher);
}

/**
 * Address: 0x007FC270 (FUN_007FC270)
 *
 * What it does:
 * Destroys one D3D prim-batcher lane and frees its storage.
 */
[[maybe_unused]] void DestroyPrimBatcherObjectRuntime(
  void* const batcher,
  const SimpleDtorFn destructorFn
)
{
  if (batcher == nullptr) {
    return;
  }

  if (destructorFn != nullptr) {
    destructorFn(batcher);
  }
  ::operator delete(batcher);
}

/**
 * Address: 0x0080D8B0 (FUN_0080D8B0)
 *
 * What it does:
 * Quantizes three float coordinates into ceil-rounded unsigned 16-bit lanes
 * and stores homogeneous `w=1`.
 */
[[maybe_unused]] std::uint16_t* QuantizeFloatTripletToWord4Runtime(
  std::uint16_t* const outWord4,
  const float x,
  const float y,
  const float z
)
{
  outWord4[0] = static_cast<std::uint16_t>(std::ceil(static_cast<double>(x)));
  outWord4[1] = static_cast<std::uint16_t>(std::ceil(static_cast<double>(y)));
  outWord4[2] = static_cast<std::uint16_t>(std::ceil(static_cast<double>(z)));
  outWord4[3] = 1u;
  return outWord4;
}

/**
 * Address: 0x0080DE80 (FUN_0080DE80)
 *
 * What it does:
 * Reads a 3x3 index neighborhood from the tesselator and emits 8 triangles
 * covering the patch around `(column, rowToken)`.
 */
[[maybe_unused]] void EmitPatchTrianglesFromTesselatorRuntime(
  const std::int32_t column,
  void* const tesselator,
  const std::uint8_t* const rowToken,
  const TesselatorGetIndexFn getIndexFn,
  const TesselatorAddTriangleFn addTriangleFn
)
{
  if (tesselator == nullptr || rowToken == nullptr || getIndexFn == nullptr || addTriangleFn == nullptr) {
    return;
  }

  const std::uint32_t source = getIndexFn(tesselator, 0u, rowToken + 0u, column);
  const std::uint32_t topMid = getIndexFn(tesselator, 0u, rowToken + 1u, column);
  const std::uint32_t topRight = getIndexFn(tesselator, 0u, rowToken + 2u, column);

  const std::uint32_t midLeft = getIndexFn(tesselator, 0u, rowToken + 0u, column + 1);
  const std::uint32_t center = getIndexFn(tesselator, 0u, rowToken + 1u, column + 1);
  const std::uint32_t midRight = getIndexFn(tesselator, 0u, rowToken + 2u, column + 1);

  const std::uint32_t bottomLeft = getIndexFn(tesselator, 0u, rowToken + 0u, column + 2);
  const std::uint32_t bottomMid = getIndexFn(tesselator, 0u, rowToken + 1u, column + 2);
  const std::uint32_t bottomRight = getIndexFn(tesselator, 0u, rowToken + 2u, column + 2);

  addTriangleFn(tesselator, source, topMid, center);
  addTriangleFn(tesselator, source, center, midLeft);
  addTriangleFn(tesselator, topMid, topRight, midRight);
  addTriangleFn(tesselator, topMid, midRight, center);
  addTriangleFn(tesselator, midLeft, center, bottomMid);
  addTriangleFn(tesselator, midLeft, bottomMid, bottomLeft);
  addTriangleFn(tesselator, center, midRight, bottomRight);
  addTriangleFn(tesselator, center, bottomRight, bottomMid);
}

/**
 * Address: 0x007408F0 (FUN_007408F0)
 *
 * What it does:
 * Appends one 32-bit lane into a paged four-slot runtime buffer, allocating a
 * backing page when the destination page has not been materialized yet.
 */
[[maybe_unused]] std::uint32_t* AppendPagedWordRuntime(
  FourLanePagedRuntime<std::uint32_t>* const runtime,
  const std::uint32_t* const value
)
{
  if (runtime == nullptr || value == nullptr) {
    return nullptr;
  }

  const std::uint32_t logicalIndex = runtime->baseIndex + runtime->size;
  std::uint32_t** const pageSlot = EnsurePagedFourLanePage(runtime, logicalIndex);
  if (pageSlot == nullptr || *pageSlot == nullptr) {
    return nullptr;
  }

  std::uint32_t* const lane = *pageSlot + (logicalIndex & 3u);
  *lane = *value;
  ++runtime->size;
  return lane;
}

/**
 * Address: 0x00740A60 (FUN_00740A60)
 *
 * What it does:
 * Releases one 16-byte string-range owner array, destroying each owned string
 * subrange before deleting the backing owner storage.
 */
[[maybe_unused]] void DestroyStringRangeBlock16OwnerRuntime(
  RangeOwnerRuntime<StringRangeBlock16Runtime>* const owner
)
{
  if (owner == nullptr) {
    return;
  }

  if (owner->begin != nullptr) {
    for (StringRangeBlock16Runtime* cursor = owner->begin; cursor != owner->end; ++cursor) {
      if (cursor->begin != nullptr) {
        DestroyRangeAndRelease(cursor->begin, cursor->end);
        ::operator delete(static_cast<void*>(cursor->begin));
      }

      cursor->begin = nullptr;
      cursor->end = nullptr;
      cursor->reserved12 = 0u;
    }

    ::operator delete(static_cast<void*>(owner->begin));
  }

  owner->begin = nullptr;
  owner->end = nullptr;
  owner->reserved12 = 0u;
}

/**
 * Address: 0x00740D50 (FUN_00740D50)
 *
 * What it does:
 * Destroys one `SDecalInfo` range and then releases the owning storage block.
 */
[[maybe_unused]] void DestroySDecalInfoRangeOwnerRuntime(
  RangeOwnerRuntime<moho::SDecalInfo>* const owner
)
{
  if (owner == nullptr) {
    return;
  }

  if (owner->begin != nullptr) {
    DestroyRangeAndRelease(owner->begin, owner->end);
    ::operator delete(static_cast<void*>(owner->begin));
  }

  owner->begin = nullptr;
  owner->end = nullptr;
  owner->reserved12 = 0u;
}

/**
 * Address: 0x00740E20 (FUN_00740E20)
 *
 * What it does:
 * Releases one 12-byte shared-control owner range, decrements the embedded
 * control lanes, and deletes the backing storage block.
 */
[[maybe_unused]] void DestroySharedControlRangeOwnerRuntime(
  RangeOwnerRuntime<SharedControlLane12Runtime>* const owner
)
{
  if (owner == nullptr) {
    return;
  }

  if (owner->begin != nullptr) {
    for (SharedControlLane12Runtime* cursor = owner->begin; cursor != owner->end; ++cursor) {
      volatile long* const control = cursor->control;
      if (control != nullptr) {
        if (::InterlockedExchangeAdd(control + 1, -1) == 0) {
          using ReleaseFn = std::intptr_t(__thiscall*)(volatile long*);
          auto* const vtable = reinterpret_cast<ReleaseFn*>(*reinterpret_cast<void**>(const_cast<long*>(control)));
          (void)vtable[1](control);
          if (::InterlockedExchangeAdd(control + 2, -1) == 0) {
            (void)vtable[2](control);
          }
        }
      }
    }

    ::operator delete(static_cast<void*>(owner->begin));
  }

  owner->begin = nullptr;
  owner->end = nullptr;
  owner->reserved12 = 0u;
}

/**
 * Address: 0x00740E90 (FUN_00740E90)
 *
 * What it does:
 * Releases one contiguous `msvc8::string` range and deletes the backing
 * storage block.
 */
[[maybe_unused]] void DestroyStringRangeOwnerRuntime(
  RangeOwnerRuntime<msvc8::string>* const owner
)
{
  if (owner == nullptr) {
    return;
  }

  if (owner->begin != nullptr) {
    DestroyRangeAndRelease(owner->begin, owner->end);
    ::operator delete(static_cast<void*>(owner->begin));
  }

  owner->begin = nullptr;
  owner->end = nullptr;
  owner->reserved12 = 0u;
}

/**
 * Address: 0x00741980 (FUN_00741980)
 *
 * What it does:
 * Destroys every live `SSyncData` pointer in one four-slot paged range.
 */
[[maybe_unused]] void DestroyPagedSyncDataRangeRuntime(
  FourLanePagedRuntime<moho::SSyncData*>* const runtime,
  const std::uint32_t beginIndex,
  const std::uint32_t endIndex
)
{
  if (runtime == nullptr || runtime->pages == nullptr) {
    return;
  }

  for (std::uint32_t logicalIndex = beginIndex; logicalIndex != endIndex; ++logicalIndex) {
    const std::uint32_t pageIndex = logicalIndex >> 2u;
    const std::uint32_t laneIndex = logicalIndex & 3u;
    if (pageIndex >= runtime->pageCount || runtime->pages[pageIndex] == nullptr) {
      continue;
    }

    moho::SSyncData*& queued = runtime->pages[pageIndex][laneIndex];
    if (queued != nullptr) {
      delete queued;
      queued = nullptr;
    }
  }
}

/**
 * Address: 0x007424A0 (FUN_007424A0)
 *
 * What it does:
 * Releases one contiguous `msvc8::string` range owner and deletes the backing
 * storage block.
 */
[[maybe_unused]] void DestroyStringRangeOwnerRuntimeLegacy(
  RangeOwnerRuntime<msvc8::string>* const owner
)
{
  DestroyStringRangeOwnerRuntime(owner);
}

using DeferredSimDriverBindRuntime = boost::_bi::bind_t<
  void,
  boost::_mfi::mf0<void, moho::CSimDriver>,
  boost::_bi::list1<boost::_bi::value<moho::CSimDriver*>>
>;

struct RuntimeDeferredSimDriverCallableVtable
{
  using ManagerFn = void (*)(
    const boost::detail::function::function_buffer*,
    boost::detail::function::function_buffer*,
    boost::detail::function::functor_manager_operation_type
  );
  using InvokerFn = void (*)(boost::detail::function::function_buffer*, moho::CSimDriver*);

  ManagerFn manager = nullptr; // +0x00
  InvokerFn invoker = nullptr; // +0x04
};
static_assert(
  sizeof(RuntimeDeferredSimDriverCallableVtable) == 0x08,
  "RuntimeDeferredSimDriverCallableVtable size must be 0x08"
);

RuntimeDeferredSimDriverCallableVtable gDeferredSimDriverCallableVtable{};

/**
 * Address: 0x00742E20 (FUN_00742E20)
 *
 * What it does:
 * Invokes one deferred thiscall callback lane using the bound object lane at
 * offset `+0x04`; the forwarded `CSimDriver*` argument is not consumed by this
 * invoker shape.
 */
[[maybe_unused]] void InvokeDeferredSimDriverCallback(
  boost::detail::function::function_buffer* const invoker,
  moho::CSimDriver* const /*driver*/
)
{
  using InvokeFn = void(__thiscall*)(void* boundObject);
  reinterpret_cast<InvokeFn>(invoker->obj_ptr)(invoker[1].obj_ptr);
}

/**
 * Address: 0x00742E30 (FUN_00742E30)
 *
 * What it does:
 * Manages one deferred sim-driver callback payload for clone/destroy/type-check
 * and type-query operations.
 */
[[maybe_unused]] void ManageDeferredSimDriverCallbackPayload(
  const boost::detail::function::function_buffer* const sourcePayload,
  boost::detail::function::function_buffer* const targetPayload,
  const boost::detail::function::functor_manager_operation_type operation
)
{
  using Operation = boost::detail::function::functor_manager_operation_type;

  if (targetPayload == nullptr) {
    return;
  }

  if (operation == Operation::get_functor_type_tag) {
    targetPayload->obj_ptr = const_cast<std::type_info*>(&typeid(DeferredSimDriverBindRuntime));
    return;
  }

  if (operation == Operation::clone_functor_tag) {
    if (sourcePayload != nullptr) {
      targetPayload->obj_ptr = sourcePayload->obj_ptr;
      targetPayload[1].obj_ptr = sourcePayload[1].obj_ptr;
    }
    return;
  }

  if (operation == Operation::destroy_functor_tag) {
    return;
  }

  const auto* const checkType = static_cast<const std::type_info*>(targetPayload->obj_ptr);
  targetPayload->obj_ptr =
    (checkType != nullptr && (*checkType == typeid(DeferredSimDriverBindRuntime)))
      ? const_cast<boost::detail::function::function_buffer*>(sourcePayload)
      : nullptr;
}

/**
 * Address: 0x00742B00 (FUN_00742B00)
 * Address: 0x00742DB0 (FUN_00742DB0)
 *
 * What it does:
 * Binds the global deferred sim-driver callable vtable lanes to the canonical
 * invoker/manager handlers.
 */
[[maybe_unused]] void __stdcall BindDeferredSimDriverCallableHandlers(
  const std::uint32_t /*lane0*/,
  const std::uint32_t /*lane1*/
) noexcept
{
  gDeferredSimDriverCallableVtable.invoker = &InvokeDeferredSimDriverCallback;
  gDeferredSimDriverCallableVtable.manager = &ManageDeferredSimDriverCallbackPayload;
}

/**
 * Address: 0x00742540 (FUN_00742540)
 *
 * What it does:
 * Initializes and returns the deferred sim-driver callable vtable singleton.
 */
[[maybe_unused]] RuntimeDeferredSimDriverCallableVtable* InitializeDeferredSimDriverCallableVtable(
  const std::uint32_t /*lane0*/,
  const std::uint32_t /*lane1*/
) noexcept
{
  BindDeferredSimDriverCallableHandlers(0u, 0u);
  return &gDeferredSimDriverCallableVtable;
}

/**
 * Address: 0x006E2D60 (FUN_006E2D60)
 *
 * What it does:
 * Copies one 32-bit range backward from `[sourceBegin, sourceEnd)` into
 * destination storage.
 */
[[maybe_unused]] std::uint32_t* CopyWordRangeBackwardRuntime(
  std::uint32_t* destinationEnd,
  const std::uint32_t* const sourceBegin,
  const std::uint32_t* sourceEnd
) noexcept
{
  while (sourceEnd != sourceBegin) {
    --sourceEnd;
    --destinationEnd;
    *destinationEnd = *sourceEnd;
  }
  return destinationEnd;
}

/**
 * Address: 0x006E3580 (FUN_006E3580)
 *
 * What it does:
 * Copies one 32-bit range `[sourceBegin, sourceEnd)` into destination
 * storage.
 */
[[maybe_unused]] std::uint32_t* CopyWordRangeForwardRuntime(
  std::uint32_t* destination,
  const std::uint32_t* sourceBegin,
  const std::uint32_t* const sourceEnd
) noexcept
{
  while (sourceBegin != sourceEnd) {
    *destination = *sourceBegin;
    ++destination;
    ++sourceBegin;
  }
  return destination;
}

struct StrideVectorRuntime
{
  std::uint32_t lane00;
  std::byte* begin;
  std::byte* end;
};
static_assert(sizeof(StrideVectorRuntime) == 0x0C, "StrideVectorRuntime size must be 0x0C");

/**
 * Address: 0x006EA190 (FUN_006EA190)
 *
 * What it does:
 * Returns the element count for one stride-60 vector lane.
 */
[[maybe_unused]] std::int32_t CountStride60ElementsRuntime(const StrideVectorRuntime* const vector) noexcept
{
  if (vector == nullptr || vector->begin == nullptr) {
    return 0;
  }

  return static_cast<std::int32_t>((vector->end - vector->begin) / 60);
}

/**
 * Address: 0x007C8EE0 (FUN_007C8EE0)
 *
 * What it does:
 * Returns whether one 24-byte legacy vector lane has no live elements,
 * treating a null begin lane as empty.
 */
[[maybe_unused]] bool IsElement24VectorEmptyRuntime(
  const LegacyVectorStorageRuntime<Element24Runtime>* const vector
) noexcept
{
  if (vector == nullptr || vector->begin == nullptr) {
    return true;
  }

  return vector->end == vector->begin;
}

/**
 * Address: 0x007C9180 (FUN_007C9180)
 *
 * What it does:
 * Returns the capacity element count for one 36-byte legacy vector lane.
 */
[[maybe_unused]] std::int32_t CountElement36VectorCapacityRuntime(
  const LegacyVectorStorageRuntime<Element36Runtime>* const vector
) noexcept
{
  if (vector == nullptr || vector->begin == nullptr || vector->capacity == nullptr || vector->capacity < vector->begin) {
    return 0;
  }

  return static_cast<std::int32_t>(vector->capacity - vector->begin);
}

/**
 * Address: 0x007C97B0 (FUN_007C97B0)
 *
 * What it does:
 * Returns the capacity element count for one 24-byte legacy vector lane.
 */
[[maybe_unused]] std::int32_t CountElement24VectorCapacityRuntime(
  const LegacyVectorStorageRuntime<Element24Runtime>* const vector
) noexcept
{
  if (vector == nullptr || vector->begin == nullptr || vector->capacity == nullptr || vector->capacity < vector->begin) {
    return 0;
  }

  return static_cast<std::int32_t>(vector->capacity - vector->begin);
}

struct GuardThreatCandidateRuntime
{
  std::uint8_t pad00_97[0x98];
  std::int32_t kind; // +0x98
  std::uint8_t pad9C_E3[0x48];
  std::int32_t value; // +0xE4
};
static_assert(offsetof(GuardThreatCandidateRuntime, kind) == 0x98, "GuardThreatCandidateRuntime::kind offset must be 0x98");
static_assert(
  offsetof(GuardThreatCandidateRuntime, value) == 0xE4, "GuardThreatCandidateRuntime::value offset must be 0xE4"
);

struct GuardThreatSlotRuntime
{
  void* weakOwner;    // +0x00
  std::uint32_t lane; // +0x04
};
static_assert(sizeof(GuardThreatSlotRuntime) == 0x08, "GuardThreatSlotRuntime size must be 0x08");

struct GuardThreatSlotRangeRuntime
{
  std::uint8_t pad00_0F[0x10];
  GuardThreatSlotRuntime* begin; // +0x10
  GuardThreatSlotRuntime* end;   // +0x14
};
static_assert(
  offsetof(GuardThreatSlotRangeRuntime, begin) == 0x10, "GuardThreatSlotRangeRuntime::begin offset must be 0x10"
);
static_assert(offsetof(GuardThreatSlotRangeRuntime, end) == 0x14, "GuardThreatSlotRangeRuntime::end offset must be 0x14");

/**
 * Address: 0x006EE430 (FUN_006EE430)
 *
 * What it does:
 * Sums threat values from kind-7 candidates in one guarded slot range and
 * returns the number of contributing entries.
 */
[[maybe_unused]] std::int32_t AccumulateGuardKind7ThreatRuntime(
  const GuardThreatSlotRangeRuntime* const range,
  std::int32_t* const outSum
) noexcept
{
  if (range == nullptr || outSum == nullptr) {
    return 0;
  }

  std::int32_t count = 0;
  for (GuardThreatSlotRuntime* slot = range->begin; slot != range->end; ++slot) {
    auto* candidate = static_cast<GuardThreatCandidateRuntime*>(slot->weakOwner);
    if (candidate != nullptr) {
      candidate = reinterpret_cast<GuardThreatCandidateRuntime*>(reinterpret_cast<std::byte*>(candidate) - 4);
    }

    if (candidate != nullptr && candidate->kind == 7) {
      *outSum += candidate->value;
      ++count;
    }
  }

  return count;
}

struct WordVectorTailRuntime
{
  std::uint32_t lane00;
  std::uint32_t lane04;
  std::uint32_t* end; // +0x08
};
static_assert(sizeof(WordVectorTailRuntime) == 0x0C, "WordVectorTailRuntime size must be 0x0C");

/**
 * Address: 0x00702730 (FUN_00702730)
 *
 * What it does:
 * Copies one source tail range into destination words and updates the owning
 * vector tail pointer.
 */
[[maybe_unused]] std::uint32_t** CopyTailRangeAndUpdateVectorEndRuntime(
  std::uint32_t** const outBegin,
  WordVectorTailRuntime* const owner,
  std::uint32_t* const destinationBegin,
  const std::uint32_t* sourceBegin
) noexcept
{
  if (outBegin == nullptr || owner == nullptr) {
    return outBegin;
  }

  std::uint32_t* write = destinationBegin;
  if (destinationBegin != sourceBegin) {
    const std::uint32_t* read = sourceBegin;
    const std::uint32_t* const sourceEnd = owner->end;
    while (read != sourceEnd) {
      *write = *read;
      ++write;
      ++read;
    }
    owner->end = write;
  }

  *outBegin = destinationBegin;
  return outBegin;
}

/**
 * Address: 0x00711EC0 (FUN_00711EC0)
 *
 * What it does:
 * Returns the leftmost node reachable from a flag-17 RB-tree head.
 */
[[maybe_unused]] MapNodeNil17Runtime* FindTreeLeftmostNodeFlag17Runtime(MapNodeNil17Runtime* head) noexcept
{
  MapNodeNil17Runtime* cursor = head->left;
  if (cursor->isNil != 0u) {
    return head;
  }

  do {
    head = cursor;
    cursor = head->left;
  } while (cursor->isNil == 0u);
  return head;
}

/**
 * Address: 0x007120D0 (FUN_007120D0)
 *
 * What it does:
 * Returns the rightmost node reachable from a flag-17 RB-tree head.
 */
[[maybe_unused]] MapNodeNil17Runtime* FindTreeRightmostNodeFlag17Runtime(MapNodeNil17Runtime* head) noexcept
{
  MapNodeNil17Runtime* cursor = head->right;
  while (cursor->isNil == 0u) {
    head = cursor;
    cursor = head->right;
  }
  return head;
}

#pragma pack(push, 1)
struct ThreatLaneSourceRuntime
{
  std::uint32_t lane00;
  std::uint32_t lane04;
  std::uint32_t lane08;
  float lane0C;
  float lane10;
  float lane14;
  std::uint32_t lane18;
  std::uint32_t lane1C;
  std::uint8_t lane20;
  std::uint8_t pad21_23[3];
  float lane24;
  float lane28;
  std::uint32_t lane2C;
};

struct ThreatLaneBuildRuntime
{
  std::uint32_t lane00;
  std::uint32_t lane04;
  std::uint32_t lane08;
  std::uint32_t lane0C;
  std::uint32_t lane10;
  std::uint32_t lane14;
  float lane18;
  float lane1C;
  float lane20;
  std::uint32_t lane24;
  std::uint32_t lane28;
  std::uint8_t lane2C;
  std::uint8_t pad2D_2F[3];
  float lane30;
  float lane34;
  std::uint32_t lane38;
  std::uint8_t lane3C;
  std::uint8_t lane3D;
};
#pragma pack(pop)

static_assert(sizeof(ThreatLaneBuildRuntime) == 0x3E, "ThreatLaneBuildRuntime size must be 0x3E");

/**
 * Address: 0x0071C8B0 (FUN_0071C8B0)
 *
 * What it does:
 * Builds one packed threat-lane record from header words and one source lane.
 */
[[maybe_unused]] ThreatLaneBuildRuntime* BuildThreatLaneRecordRuntime(
  ThreatLaneBuildRuntime* const outRecord,
  const std::uint32_t lane00,
  const ThreatLaneSourceRuntime& source,
  const std::uint32_t lane04,
  const std::uint32_t lane08,
  const std::uint8_t state
) noexcept
{
  if (outRecord == nullptr) {
    return nullptr;
  }

  outRecord->lane00 = lane00;
  outRecord->lane04 = lane04;
  outRecord->lane08 = lane08;
  outRecord->lane0C = source.lane00;
  outRecord->lane10 = source.lane04;
  outRecord->lane14 = source.lane08;
  outRecord->lane18 = source.lane0C;
  outRecord->lane1C = source.lane10;
  outRecord->lane20 = source.lane14;
  outRecord->lane24 = source.lane18;
  outRecord->lane28 = source.lane1C;
  outRecord->lane2C = source.lane20;
  outRecord->lane30 = source.lane24;
  outRecord->lane34 = source.lane28;
  outRecord->lane38 = source.lane2C;
  outRecord->lane3C = state;
  outRecord->lane3D = 0u;
  return outRecord;
}

/**
 * Address: 0x00720250 (FUN_00720250)
 *
 * What it does:
 * Inserts one 4-float lane into a min-heap by promoting parents.
 */
[[maybe_unused]] std::int32_t InsertFloat4HeapEntryByPromotingParentsRuntime(
  Float4Runtime* const heap,
  std::int32_t insertionIndex,
  const std::int32_t lowerBoundIndex,
  const std::int32_t lane0,
  const std::int32_t lane1,
  const std::int32_t lane2,
  const float lane3
) noexcept
{
  std::int32_t parentIndex = (insertionIndex - 1) / 2;
  while (lowerBoundIndex < insertionIndex) {
    const Float4Runtime& parent = heap[parentIndex];
    if (parent.lanes[3] <= lane3) {
      break;
    }

    heap[insertionIndex] = parent;
    insertionIndex = parentIndex;
    parentIndex = (parentIndex - 1) / 2;
  }

  heap[insertionIndex].lanes[0] = static_cast<float>(lane0);
  heap[insertionIndex].lanes[1] = static_cast<float>(lane1);
  heap[insertionIndex].lanes[2] = static_cast<float>(lane2);
  heap[insertionIndex].lanes[3] = lane3;
  return parentIndex;
}

/**
 * Address: 0x0074CF40 (FUN_0074CF40)
 *
 * What it does:
 * Returns the element count for one stride-56 vector lane.
 */
[[maybe_unused]] std::int32_t CountStride56ElementsRuntime(const StrideVectorRuntime* const vector) noexcept
{
  if (vector == nullptr || vector->begin == nullptr) {
    return 0;
  }

  return static_cast<std::int32_t>((vector->end - vector->begin) / 56);
}

namespace
{
#pragma pack(push, 1)
  struct BitArraySurfaceDescriptorRuntime
  {
    std::uint32_t descriptorBytes; // +0x00
    std::uint32_t width;           // +0x04
    std::uint32_t height;          // +0x08
    std::uint16_t lane0C;          // +0x0C
    std::uint16_t wordsPerRow;     // +0x0E
    std::uint32_t lane10;          // +0x10
    std::uint32_t storageBytes;    // +0x14
    std::uint32_t lane18;          // +0x18
    std::uint32_t lane1C;          // +0x1C
    std::uint32_t lane20;          // +0x20
    std::uint32_t lane24;          // +0x24
  };
#pragma pack(pop)

  static_assert(sizeof(BitArraySurfaceDescriptorRuntime) == 0x28, "BitArraySurfaceDescriptorRuntime size must be 0x28");
  static_assert(
    offsetof(BitArraySurfaceDescriptorRuntime, wordsPerRow) == 0x0E,
    "BitArraySurfaceDescriptorRuntime::wordsPerRow offset must be 0x0E"
  );
  static_assert(
    offsetof(BitArraySurfaceDescriptorRuntime, storageBytes) == 0x14,
    "BitArraySurfaceDescriptorRuntime::storageBytes offset must be 0x14"
  );

  struct NestedStateRuntime
  {
    std::byte pad00[0x14];
    std::uint32_t lane14;
  };
  static_assert(offsetof(NestedStateRuntime, lane14) == 0x14, "NestedStateRuntime::lane14 offset must be 0x14");

  struct NestedOwnerNodeRuntime
  {
    std::uint32_t lane00;
    NestedStateRuntime* nested; // +0x04
  };
  static_assert(offsetof(NestedOwnerNodeRuntime, nested) == 0x04, "NestedOwnerNodeRuntime::nested offset must be 0x04");

  struct NestedOwnerRuntime
  {
    std::byte pad00[0x134];
    NestedOwnerNodeRuntime* node; // +0x134
  };
  static_assert(offsetof(NestedOwnerRuntime, node) == 0x134, "NestedOwnerRuntime::node offset must be 0x134");

  struct TranscodeOwnerRuntime
  {
    std::byte pad00[0x08];
    const std::uint8_t* lookupBytes; // +0x08
    std::byte pad0C[0x02];
    std::uint8_t passthroughAscii; // +0x0E
  };
  static_assert(
    offsetof(TranscodeOwnerRuntime, passthroughAscii) == 0x0E,
    "TranscodeOwnerRuntime::passthroughAscii offset must be 0x0E"
  );

  struct FlaggedResourceVTableRuntime
  {
    std::byte pad00[0x58];
    void (__thiscall* releaseSlot)(void* self);
  };
  static_assert(
    offsetof(FlaggedResourceVTableRuntime, releaseSlot) == 0x58,
    "FlaggedResourceVTableRuntime::releaseSlot offset must be 0x58"
  );

  struct FlaggedResourceRuntime
  {
    FlaggedResourceVTableRuntime* vtable;
    std::byte pad04_CC[0xC8];
    std::uint8_t flags;
  };
  static_assert(offsetof(FlaggedResourceRuntime, flags) == 0xCC, "FlaggedResourceRuntime::flags offset must be 0xCC");

  struct DispatcherVTableRuntime
  {
    std::byte pad00[0x20];
    int (__thiscall* invokeSlot)(void* self);
  };
  static_assert(
    offsetof(DispatcherVTableRuntime, invokeSlot) == 0x20,
    "DispatcherVTableRuntime::invokeSlot offset must be 0x20"
  );

  struct ResourceDispatchOwnerRuntime
  {
    DispatcherVTableRuntime* vtable;
    std::byte pad04[0x04];
    FlaggedResourceRuntime* primary;   // +0x08
    FlaggedResourceRuntime* secondary; // +0x0C
  };
  static_assert(offsetof(ResourceDispatchOwnerRuntime, primary) == 0x08, "ResourceDispatchOwnerRuntime::primary offset must be 0x08");
  static_assert(
    offsetof(ResourceDispatchOwnerRuntime, secondary) == 0x0C,
    "ResourceDispatchOwnerRuntime::secondary offset must be 0x0C"
  );

  struct CallbackChainVTableRuntime
  {
    std::byte pad00[0x14];
    void (__thiscall* preRunSlot)(void* self);
    int (__thiscall* runSlot)(void* self);
  };
  static_assert(offsetof(CallbackChainVTableRuntime, preRunSlot) == 0x14, "CallbackChainVTableRuntime::preRunSlot offset must be 0x14");
  static_assert(offsetof(CallbackChainVTableRuntime, runSlot) == 0x18, "CallbackChainVTableRuntime::runSlot offset must be 0x18");

  struct CallbackChainNodeRuntime
  {
    CallbackChainVTableRuntime* vtable;
    std::byte pad04_13[0x10];
    std::uint8_t runPreCallback; // +0x14
    std::byte pad15_17[0x03];
    void* runCookie; // +0x18
  };
  static_assert(
    offsetof(CallbackChainNodeRuntime, runPreCallback) == 0x14,
    "CallbackChainNodeRuntime::runPreCallback offset must be 0x14"
  );
  static_assert(offsetof(CallbackChainNodeRuntime, runCookie) == 0x18, "CallbackChainNodeRuntime::runCookie offset must be 0x18");

  struct VTableWord56Runtime
  {
    std::byte pad00[0x38];
    std::int32_t lane38;
  };
  static_assert(offsetof(VTableWord56Runtime, lane38) == 0x38, "VTableWord56Runtime::lane38 offset must be 0x38");

  struct VTableWord56OwnerRuntime
  {
    VTableWord56Runtime* vtable;
  };

  struct VTableInvoke04Runtime
  {
    void* lane00;
    int (__thiscall* invokeSlot)(void* self);
  };
  static_assert(offsetof(VTableInvoke04Runtime, invokeSlot) == 0x04, "VTableInvoke04Runtime::invokeSlot offset must be 0x04");

  struct VTableInvoke04OwnerRuntime
  {
    VTableInvoke04Runtime* vtable;
  };

  struct ExpandedStridePayloadRuntime
  {
    std::byte pad00[0x44];
    std::int32_t extraCount;
  };
  static_assert(
    offsetof(ExpandedStridePayloadRuntime, extraCount) == 0x44,
    "ExpandedStridePayloadRuntime::extraCount offset must be 0x44"
  );

  struct ExpandedStrideNodeRuntime
  {
    std::uint32_t lane00;
    std::uint32_t lane04;
    ExpandedStridePayloadRuntime* payload; // +0x08
    ExpandedStrideNodeRuntime* next;       // +0x0C
  };
  static_assert(
    offsetof(ExpandedStrideNodeRuntime, payload) == 0x08,
    "ExpandedStrideNodeRuntime::payload offset must be 0x08"
  );
  static_assert(offsetof(ExpandedStrideNodeRuntime, next) == 0x0C, "ExpandedStrideNodeRuntime::next offset must be 0x0C");

  struct ExpandedStrideOwnerRuntime
  {
    std::byte pad00[0x10];
    ExpandedStrideNodeRuntime* head; // +0x10
  };
  static_assert(offsetof(ExpandedStrideOwnerRuntime, head) == 0x10, "ExpandedStrideOwnerRuntime::head offset must be 0x10");

  using FindSelectionNodeFn = void* (__thiscall*)(void* self, std::int16_t lane0, std::int16_t lane1);
  using ApplySelectionFn = int (__thiscall*)(void* self, int selectionId);

  struct SelectionOwnerVTableRuntime
  {
    std::byte pad00[0x298];
    FindSelectionNodeFn findSelectionNode; // +0x298
    std::byte pad29C_2A3[0x08];
    ApplySelectionFn applySelection; // +0x2A4
  };
  static_assert(
    offsetof(SelectionOwnerVTableRuntime, findSelectionNode) == 0x298,
    "SelectionOwnerVTableRuntime::findSelectionNode offset must be 0x298"
  );
  static_assert(
    offsetof(SelectionOwnerVTableRuntime, applySelection) == 0x2A4,
    "SelectionOwnerVTableRuntime::applySelection offset must be 0x2A4"
  );

  struct SelectionNodeRuntime
  {
    std::byte pad00[0x10];
    std::int32_t selectionId;
  };
  static_assert(offsetof(SelectionNodeRuntime, selectionId) == 0x10, "SelectionNodeRuntime::selectionId offset must be 0x10");

  struct SelectionOwnerRuntime
  {
    SelectionOwnerVTableRuntime* vtable;
    std::byte pad04_173[0x170];
    SelectionNodeRuntime* activeSelection; // +0x174
  };
  static_assert(
    offsetof(SelectionOwnerRuntime, activeSelection) == 0x174,
    "SelectionOwnerRuntime::activeSelection offset must be 0x174"
  );

  struct FourWordLaneRuntime
  {
    std::uint32_t lane00;
    std::uint32_t lane04;
    std::uint32_t lane08;
    std::uint32_t lane0C;
  };
  static_assert(sizeof(FourWordLaneRuntime) == 0x10, "FourWordLaneRuntime size must be 0x10");

  struct FourWordLaneOwnerRuntime
  {
    std::byte pad00[0x150];
    FourWordLaneRuntime lane; // +0x150
  };
  static_assert(offsetof(FourWordLaneOwnerRuntime, lane) == 0x150, "FourWordLaneOwnerRuntime::lane offset must be 0x150");

  struct TripleWordLaneOwnerRuntime
  {
    std::byte pad00[0x2C];
    std::int32_t lane2C;
    std::int32_t lane30;
    std::int32_t lane34;
  };
  static_assert(offsetof(TripleWordLaneOwnerRuntime, lane2C) == 0x2C, "TripleWordLaneOwnerRuntime::lane2C offset must be 0x2C");
  static_assert(offsetof(TripleWordLaneOwnerRuntime, lane30) == 0x30, "TripleWordLaneOwnerRuntime::lane30 offset must be 0x30");
  static_assert(offsetof(TripleWordLaneOwnerRuntime, lane34) == 0x34, "TripleWordLaneOwnerRuntime::lane34 offset must be 0x34");

  using PushIdLaneFn = int (__thiscall*)(void* self, std::uint32_t value);

  struct PushIdLaneVTableRuntime
  {
    std::byte pad00[0x1C];
    PushIdLaneFn pushIdLane; // +0x1C
  };
  static_assert(offsetof(PushIdLaneVTableRuntime, pushIdLane) == 0x1C, "PushIdLaneVTableRuntime::pushIdLane offset must be 0x1C");

  struct PushIdLaneOwnerRuntime
  {
    PushIdLaneVTableRuntime* vtable;
  };

  struct PushIdLaneHostRuntime
  {
    std::byte pad00[0x130];
    PushIdLaneOwnerRuntime pushLaneOwner;
  };
  static_assert(
    offsetof(PushIdLaneHostRuntime, pushLaneOwner) == 0x130,
    "PushIdLaneHostRuntime::pushLaneOwner offset must be 0x130"
  );

  struct BulkIdDispatchOwnerRuntime
  {
    std::byte pad00[0x170];
    PushIdLaneHostRuntime* host; // +0x170
  };
  static_assert(offsetof(BulkIdDispatchOwnerRuntime, host) == 0x170, "BulkIdDispatchOwnerRuntime::host offset must be 0x170");

  struct DwordArrayLaneRuntime
  {
    std::uint32_t lane00;
    std::uint32_t count;
    const std::uint32_t* values;
  };
  static_assert(offsetof(DwordArrayLaneRuntime, count) == 0x04, "DwordArrayLaneRuntime::count offset must be 0x04");
  static_assert(offsetof(DwordArrayLaneRuntime, values) == 0x08, "DwordArrayLaneRuntime::values offset must be 0x08");

  struct ScoreEntryStride8Runtime
  {
    std::int32_t lanes[8];
  };
  static_assert(sizeof(ScoreEntryStride8Runtime) == 0x20, "ScoreEntryStride8Runtime size must be 0x20");

  struct PaletteIndexOffsetsRuntime
  {
    std::uint32_t rOffset;
    std::uint32_t gOffset;
    std::uint32_t bOffset;
  };
  static_assert(sizeof(PaletteIndexOffsetsRuntime) == 0x0C, "PaletteIndexOffsetsRuntime size must be 0x0C");

  struct HistogramSliceContextRuntime
  {
    std::byte pad00[0x18];
    std::uint16_t** slicesByX;
  };
  static_assert(
    offsetof(HistogramSliceContextRuntime, slicesByX) == 0x18,
    "HistogramSliceContextRuntime::slicesByX offset must be 0x18"
  );

  struct HistogramProjectionOwnerRuntime
  {
    HistogramSliceContextRuntime* sliceContext; // +0x00
    std::uint32_t lane04;                       // +0x04
    PaletteIndexOffsetsRuntime* outputOffsets;  // +0x08
  };
  static_assert(
    offsetof(HistogramProjectionOwnerRuntime, outputOffsets) == 0x08,
    "HistogramProjectionOwnerRuntime::outputOffsets offset must be 0x08"
  );

  struct HistogramBoundsRuntime
  {
    std::int32_t xMin;
    std::int32_t xMax;
    std::int32_t yMin;
    std::int32_t yMax;
    std::int32_t zMin;
    std::int32_t zMax;
  };
  static_assert(sizeof(HistogramBoundsRuntime) == 0x18, "HistogramBoundsRuntime size must be 0x18");

  struct PaletteSampleSourcesRuntime
  {
    const std::uint8_t* r;
    const std::uint8_t* g;
    const std::uint8_t* b;
  };
  static_assert(sizeof(PaletteSampleSourcesRuntime) == 0x0C, "PaletteSampleSourcesRuntime size must be 0x0C");

  struct PaletteSampleOwnerRuntime
  {
    std::byte pad00[0x08];
    const PaletteSampleSourcesRuntime* channels; // +0x08
    std::int32_t count;                          // +0x0C
  };
  static_assert(offsetof(PaletteSampleOwnerRuntime, channels) == 0x08, "PaletteSampleOwnerRuntime::channels offset must be 0x08");
  static_assert(offsetof(PaletteSampleOwnerRuntime, count) == 0x0C, "PaletteSampleOwnerRuntime::count offset must be 0x0C");

  struct ArrayIteratorRuntime
  {
    void* value;
    const void* owner;
  };
  static_assert(sizeof(ArrayIteratorRuntime) == 0x08, "ArrayIteratorRuntime size must be 0x08");

  struct PointerArrayOwnerRuntime
  {
    void** entries;
    std::uint32_t count;
  };
  static_assert(sizeof(PointerArrayOwnerRuntime) == 0x08, "PointerArrayOwnerRuntime size must be 0x08");

  struct RefTicketRuntime
  {
    std::byte pad00[0x0C];
    std::uint32_t ticket; // +0x0C
  };
  static_assert(offsetof(RefTicketRuntime, ticket) == 0x0C, "RefTicketRuntime::ticket offset must be 0x0C");

  struct ReleasableHandleVTableRuntime
  {
    std::byte pad00[0x08];
    int (__stdcall* releaseSlot)(void* handle);
  };
  static_assert(offsetof(ReleasableHandleVTableRuntime, releaseSlot) == 0x08, "ReleasableHandleVTableRuntime::releaseSlot offset must be 0x08");

  struct ReleasableHandleRuntime
  {
    ReleasableHandleVTableRuntime* vtable;
    std::byte pad04_0B[0x08];
    std::uint8_t shutdownFlag; // +0x0C
  };
  static_assert(
    offsetof(ReleasableHandleRuntime, shutdownFlag) == 0x0C,
    "ReleasableHandleRuntime::shutdownFlag offset must be 0x0C"
  );

  struct ReleasableHandleOwnerRuntime
  {
    std::uint32_t lane00;
    ReleasableHandleRuntime* handle; // +0x04
  };
  static_assert(
    offsetof(ReleasableHandleOwnerRuntime, handle) == 0x04,
    "ReleasableHandleOwnerRuntime::handle offset must be 0x04"
  );

  struct ChannelMaskOwnerRuntime
  {
    std::uint32_t lanes[20];
  };
  static_assert(sizeof(ChannelMaskOwnerRuntime) == 0x50, "ChannelMaskOwnerRuntime size must be 0x50");

  struct ManagedPayloadRuntime
  {
    std::byte pad00[0x24];
    std::int32_t id;
  };
  static_assert(offsetof(ManagedPayloadRuntime, id) == 0x24, "ManagedPayloadRuntime::id offset must be 0x24");

  struct ManagedNodeVTableRuntime
  {
    void (__thiscall* releaseSlot)(void* self, int reasonCode);
  };

  struct ManagedNodeRuntime
  {
    ManagedNodeVTableRuntime* vtable;
    std::uint32_t lane04;
    ManagedPayloadRuntime* payload;
    ManagedNodeRuntime* next;
  };
  static_assert(offsetof(ManagedNodeRuntime, payload) == 0x08, "ManagedNodeRuntime::payload offset must be 0x08");
  static_assert(offsetof(ManagedNodeRuntime, next) == 0x0C, "ManagedNodeRuntime::next offset must be 0x0C");

  struct ManagedNodeListsOwnerRuntime
  {
    std::byte pad00[0x1C];
    ManagedNodeRuntime* listAt1C;
    ManagedNodeRuntime* listAt20;
  };
  static_assert(
    offsetof(ManagedNodeListsOwnerRuntime, listAt1C) == 0x1C,
    "ManagedNodeListsOwnerRuntime::listAt1C offset must be 0x1C"
  );
  static_assert(
    offsetof(ManagedNodeListsOwnerRuntime, listAt20) == 0x20,
    "ManagedNodeListsOwnerRuntime::listAt20 offset must be 0x20"
  );

  [[nodiscard]] std::int32_t ClampCountToFixedArray(const std::int32_t count, const std::int32_t capacity) noexcept
  {
    if (count <= 0) {
      return 0;
    }
    return count < capacity ? count : capacity;
  }

  [[nodiscard]] std::int32_t ComputeAxisPenaltyPrimary(const std::int32_t sample, const std::int32_t target) noexcept
  {
    const std::int32_t upper = target + 24;
    if (sample < target) {
      const std::int32_t delta = sample - target;
      return (2 * delta) * (2 * delta);
    }
    if (sample > upper) {
      const std::int32_t delta = sample - upper;
      return (2 * delta) * (2 * delta);
    }
    return 0;
  }

  [[nodiscard]] std::int32_t ComputeAxisShapePrimary(const std::int32_t sample, const std::int32_t target) noexcept
  {
    const std::int32_t upper = target + 24;
    const std::int32_t midpoint = ((2 * target) + 24) >> 1;
    if (sample <= midpoint) {
      const std::int32_t delta = sample - upper;
      return (2 * delta) * (2 * delta);
    }
    const std::int32_t delta = sample - upper;
    return (2 * delta) * (2 * delta);
  }

  [[nodiscard]] std::int32_t ComputeAxisPenaltySecondary(
    const std::int32_t sample,
    const std::int32_t target,
    const std::int32_t outsideScale
  ) noexcept
  {
    const std::int32_t upper = target + 28;
    if (sample < target) {
      const std::int32_t delta = sample - target;
      return (outsideScale * delta) * (outsideScale * delta);
    }
    if (sample > upper) {
      const std::int32_t delta = sample - upper;
      return (outsideScale * delta) * (outsideScale * delta);
    }
    return 0;
  }

  [[nodiscard]] std::int32_t ComputeAxisShapeSecondary(
    const std::int32_t sample,
    const std::int32_t target,
    const std::int32_t insideScale
  ) noexcept
  {
    const std::int32_t upper = target + 28;
    const std::int32_t midpoint = ((2 * target) + 28) >> 1;
    const std::int32_t delta = (sample > midpoint) ? (sample - target) : (sample - upper);
    return (insideScale * delta) * (insideScale * delta);
  }

  [[nodiscard]] std::int32_t ComputeAxisPenaltyTertiary(const std::int32_t sample, const std::int32_t target) noexcept
  {
    const std::int32_t upper = target + 24;
    if (sample < target) {
      const std::int32_t delta = sample - target;
      return delta * delta;
    }
    if (sample > upper) {
      const std::int32_t delta = sample - upper;
      return delta * delta;
    }
    return 0;
  }

  [[nodiscard]] std::int32_t ComputeAxisShapeTertiary(const std::int32_t sample, const std::int32_t target) noexcept
  {
    const std::int32_t upper = target + 24;
    const std::int32_t midpoint = ((2 * target) + 24) >> 1;
    const std::int32_t delta = (sample > midpoint) ? (sample - target) : (sample - upper);
    return delta * delta;
  }

  [[nodiscard]] ManagedPayloadRuntime* FindManagedPayloadByIdRuntime(
    ManagedNodeRuntime* node,
    const std::int32_t id
  ) noexcept
  {
    ManagedPayloadRuntime* match = nullptr;
    while (node != nullptr) {
      if (match != nullptr) {
        break;
      }
      if (node->payload != nullptr && node->payload->id == id) {
        match = node->payload;
      } else {
        node = node->next;
      }
    }
    return match;
  }

  [[nodiscard]] std::uint8_t RemoveManagedNodeByIdRuntime(
    ManagedNodeRuntime* node,
    const std::int32_t id
  ) noexcept
  {
    std::uint8_t removed = 0u;
    while (node != nullptr) {
      if (removed != 0u) {
        break;
      }
      if (node->payload != nullptr && node->payload->id == id) {
        removed = 1u;
        if (node->vtable != nullptr && node->vtable->releaseSlot != nullptr) {
          node->vtable->releaseSlot(node, 1);
        }
      } else {
        node = node->next;
      }
    }
    return removed;
  }
} // namespace

/**
 * Address: 0x009EC970 (FUN_009EC970)
 *
 * What it does:
 * Initializes one bit-array surface descriptor from width/height and selector
 * lanes, including computed backing storage bytes.
 */
[[maybe_unused]] BitArraySurfaceDescriptorRuntime* InitializeBitArraySurfaceDescriptorRuntime(
  BitArraySurfaceDescriptorRuntime* const descriptor,
  const std::uint32_t width,
  const std::uint32_t height,
  const std::int32_t selector
) noexcept
{
  if (descriptor == nullptr) {
    return nullptr;
  }

  descriptor->lane0C = 1u;
  descriptor->wordsPerRow = 1u;
  descriptor->lane10 = 0u;
  descriptor->storageBytes = 0u;
  descriptor->lane18 = 0u;
  descriptor->lane1C = 0u;
  descriptor->lane20 = 0u;
  descriptor->lane24 = 0u;

  descriptor->descriptorBytes = 40u;
  descriptor->width = width;
  descriptor->height = height;

  std::uint16_t wordsPerRow = 1u;
  if (selector > 1) {
    if (selector > 4) {
      wordsPerRow = selector > 8 ? 24u : 8u;
    } else {
      wordsPerRow = 4u;
    }
  }
  descriptor->wordsPerRow = wordsPerRow;

  const std::uint32_t bitsPerLine = static_cast<std::uint32_t>(wordsPerRow) * width;
  descriptor->storageBytes = 4u * height * ((bitsPerLine + 31u) >> 5u);
  return descriptor;
}

/**
 * Address: 0x009EDA70 (FUN_009EDA70)
 *
 * What it does:
 * Checks whether one nested owner lane has an active nonzero nested-state
 * marker at offset `+0x14`.
 */
[[maybe_unused]] BOOL HasActiveNestedStateLaneRuntime(
  const NestedOwnerRuntime* const owner
) noexcept
{
  if (owner == nullptr || owner->node == nullptr || owner->node->nested == nullptr) {
    return FALSE;
  }
  return owner->node->nested->lane14 != 0u ? TRUE : FALSE;
}

/**
 * Address: 0x009F03E0 (FUN_009F03E0)
 *
 * What it does:
 * Transcodes one null-terminated narrow string into UTF-16 using either
 * passthrough ASCII lanes or a lookup table lane.
 */
[[maybe_unused]] void ConvertNarrowToWideWithLookupRuntime(
  const TranscodeOwnerRuntime* const owner,
  const char* source,
  std::uint16_t* destination
) noexcept
{
  if (owner == nullptr || source == nullptr || destination == nullptr) {
    return;
  }

  if (owner->passthroughAscii != 0u) {
    while (*source != '\0') {
      *destination = static_cast<std::uint8_t>(*source);
      ++source;
      ++destination;
    }
    *destination = 0u;
    return;
  }

  if (owner->lookupBytes == nullptr) {
    return;
  }

  const auto* const table = reinterpret_cast<const std::uint16_t*>(owner->lookupBytes);
  while (*source != '\0') {
    const auto lane = static_cast<std::uint8_t>(*source);
    *destination = table[lane];
    ++source;
    ++destination;
  }
  *destination = 0u;
}

/**
 * Address: 0x009F0450 (FUN_009F0450)
 *
 * What it does:
 * Transcodes one null-terminated UTF-16 string into narrow bytes using either
 * passthrough ASCII lanes or a lookup table lane.
 */
[[maybe_unused]] void ConvertWideToNarrowWithLookupRuntime(
  const TranscodeOwnerRuntime* const owner,
  const std::uint16_t* source,
  std::uint8_t* destination
) noexcept
{
  if (owner == nullptr || source == nullptr || destination == nullptr) {
    return;
  }

  if (owner->passthroughAscii != 0u) {
    while (*source != 0u) {
      *destination = static_cast<std::uint8_t>(*source);
      ++source;
      ++destination;
    }
    *destination = 0u;
    return;
  }

  if (owner->lookupBytes == nullptr) {
    return;
  }

  while (*source != 0u) {
    const std::uint16_t lane = *source;
    *destination = owner->lookupBytes[2u * lane];
    ++source;
    ++destination;
  }
  *destination = 0u;
}

/**
 * Address: 0x009F12E0 (FUN_009F12E0)
 *
 * What it does:
 * Releases flagged secondary/primary resource lanes when bit-0 is set and then
 * dispatches the owner invoke slot.
 */
[[maybe_unused]] int ReleaseFlaggedResourcesAndDispatchRuntime(
  ResourceDispatchOwnerRuntime* const owner,
  const std::int32_t /*unused*/
)
{
  if (owner == nullptr || owner->vtable == nullptr || owner->vtable->invokeSlot == nullptr) {
    return 0;
  }

  FlaggedResourceRuntime* const primary = owner->primary;
  FlaggedResourceRuntime* const secondary = owner->secondary;
  const bool releasePrimary = (primary != nullptr) && ((primary->flags & 0x1u) != 0u);
  const bool releaseSecondary = (secondary != nullptr) && ((secondary->flags & 0x1u) != 0u);
  if (releasePrimary || releaseSecondary) {
    if (secondary != nullptr && secondary != primary && secondary->vtable != nullptr && secondary->vtable->releaseSlot != nullptr) {
      secondary->vtable->releaseSlot(secondary);
    }
    if (primary != nullptr && primary->vtable != nullptr && primary->vtable->releaseSlot != nullptr) {
      primary->vtable->releaseSlot(primary);
    }
  }

  return owner->vtable->invokeSlot(owner);
}

/**
 * Address: 0x009F2A70 (FUN_009F2A70)
 *
 * What it does:
 * Executes one optional pre-run slot and tail-calls the run slot when a run
 * cookie is present.
 */
[[maybe_unused]] int RunCallbackChainNodeRuntime(
  CallbackChainNodeRuntime* const node
)
{
  if (node == nullptr || node->runCookie == nullptr || node->vtable == nullptr || node->vtable->runSlot == nullptr) {
    return 0;
  }

  if (node->runPreCallback != 0u && node->vtable->preRunSlot != nullptr) {
    node->vtable->preRunSlot(node);
  }
  return node->vtable->runSlot(node);
}

/**
 * Address: 0x009F7CE0 (FUN_009F7CE0)
 *
 * What it does:
 * Returns one vtable word lane at offset `+0x38`.
 */
[[maybe_unused]] std::int32_t ReadVTableWord56Runtime(
  const VTableWord56OwnerRuntime* const owner
) noexcept
{
  if (owner == nullptr || owner->vtable == nullptr) {
    return 0;
  }
  return owner->vtable->lane38;
}

/**
 * Address: 0x009FA470 (FUN_009FA470)
 *
 * What it does:
 * Tail-calls one virtual slot at vtable offset `+0x04`.
 */
[[maybe_unused]] int InvokeVTableSlot04Runtime(
  VTableInvoke04OwnerRuntime* const owner
)
{
  if (owner == nullptr || owner->vtable == nullptr || owner->vtable->invokeSlot == nullptr) {
    return 0;
  }
  return owner->vtable->invokeSlot(owner);
}

/**
 * Address: 0x00A028C0 (FUN_00A028C0)
 *
 * What it does:
 * Returns the `cFileName` lane from one `WIN32_FIND_DATAW` record.
 */
[[maybe_unused]] wchar_t* GetFindDataFileNameRuntime(
  WIN32_FIND_DATAW* const findData
) noexcept
{
  return findData != nullptr ? findData->cFileName : nullptr;
}

/**
 * Address: 0x00A028D0 (FUN_00A028D0)
 *
 * What it does:
 * Returns the file-attribute lane from one `WIN32_FIND_DATAW` record.
 */
[[maybe_unused]] DWORD GetFindDataAttributesRuntime(
  const WIN32_FIND_DATAW* const findData
) noexcept
{
  return findData != nullptr ? findData->dwFileAttributes : 0u;
}

/**
 * Address: 0x00A06200 (FUN_00A06200)
 *
 * What it does:
 * Updates one byte lane at offset `+0x1D` and reports whether it changed.
 */
[[maybe_unused]] std::uint8_t SetOwnerByteAt1DIfChangedRuntime(
  std::uint8_t* const ownerBytes,
  const std::uint8_t value
) noexcept
{
  if (ownerBytes == nullptr) {
    return 0u;
  }

  if (ownerBytes[0x1D] == value) {
    return 0u;
  }
  ownerBytes[0x1D] = value;
  return 1u;
}

/**
 * Address: 0x00A07C50 (FUN_00A07C50)
 *
 * What it does:
 * Walks one linked list and resolves the payload pointer at an expanded index
 * where each node contributes `extraCount + 1` slots.
 */
[[maybe_unused]] ExpandedStridePayloadRuntime* ResolveExpandedStrideNodeByIndexRuntime(
  const ExpandedStrideOwnerRuntime* const owner,
  std::int32_t index
) noexcept
{
  if (owner == nullptr) {
    return nullptr;
  }

  ExpandedStrideNodeRuntime* node = owner->head;
  if (node == nullptr) {
    return nullptr;
  }

  while (index != 0) {
    const ExpandedStridePayloadRuntime* const payload = node->payload;
    const std::int32_t contribution = (payload != nullptr && payload->extraCount != 0) ? (payload->extraCount + 1) : 1;
    node = node->next;
    index -= contribution;
    if (node == nullptr) {
      return nullptr;
    }
  }

  return node->payload;
}

/**
 * Address: 0x00A08280 (FUN_00A08280)
 *
 * What it does:
 * Resolves one selection node from packed 16-bit coordinates and updates the
 * active selection lane through the owner apply-selection slot.
 */
[[maybe_unused]] int ResolveAndApplyPackedSelectionRuntime(
  SelectionOwnerRuntime* const owner,
  const std::int32_t /*unused*/,
  const std::int32_t packedCoords
)
{
  if (owner == nullptr || owner->vtable == nullptr || owner->vtable->findSelectionNode == nullptr
      || owner->vtable->applySelection == nullptr)
  {
    return 0;
  }

  const auto x = static_cast<std::int16_t>(packedCoords & 0xFFFF);
  const auto y = static_cast<std::int16_t>((packedCoords >> 16) & 0xFFFF);
  auto* const resolved = static_cast<SelectionNodeRuntime*>(owner->vtable->findSelectionNode(owner, x, y));
  int result = static_cast<int>(reinterpret_cast<std::uintptr_t>(resolved));
  if (resolved != owner->activeSelection) {
    if (resolved == nullptr) {
      owner->activeSelection = nullptr;
      result = owner->vtable->applySelection(owner, -1);
    }

    if (resolved != owner->activeSelection && resolved != nullptr) {
      owner->activeSelection = resolved;
      return owner->vtable->applySelection(owner, resolved->selectionId);
    }
  }

  return result;
}

/**
 * Address: 0x00A12980 (FUN_00A12980)
 *
 * What it does:
 * Copies one contiguous 4-word lane into owner storage at offset `+0x150`.
 */
[[maybe_unused]] std::uint32_t CopyFourWordLaneToOwnerRuntime(
  FourWordLaneOwnerRuntime* const owner,
  const FourWordLaneRuntime* const sourceLane
) noexcept
{
  if (owner == nullptr || sourceLane == nullptr) {
    return 0u;
  }

  owner->lane = *sourceLane;
  return owner->lane.lane0C;
}

/**
 * Address: 0x00A149A0 (FUN_00A149A0)
 *
 * What it does:
 * Stores three incoming scalar lanes at owner offsets `+0x2C`, `+0x30`,
 * `+0x34` and returns the third argument.
 */
[[maybe_unused]] std::int32_t SetTripleWordLaneRuntime(
  TripleWordLaneOwnerRuntime* const owner,
  const std::int32_t lane2C,
  const std::int32_t lane34,
  const std::int32_t lane30
) noexcept
{
  if (owner == nullptr) {
    return lane34;
  }

  owner->lane2C = lane2C;
  owner->lane30 = lane30;
  owner->lane34 = lane34;
  return lane34;
}

/**
 * Address: 0x00A1E8E0 (FUN_00A1E8E0)
 *
 * What it does:
 * Pushes each dword lane from one array into the owner dispatch lane at
 * `host + 0x130`.
 */
[[maybe_unused]] std::int32_t PushDwordArrayIntoDispatchLaneRuntime(
  BulkIdDispatchOwnerRuntime* const owner,
  const DwordArrayLaneRuntime* const values
)
{
  if (owner == nullptr || owner->host == nullptr || values == nullptr || values->values == nullptr
      || owner->host->pushLaneOwner.vtable == nullptr || owner->host->pushLaneOwner.vtable->pushIdLane == nullptr)
  {
    return 0;
  }

  std::int32_t result = 0;
  for (std::uint32_t index = 0u; index < values->count; ++index) {
    result = owner->host->pushLaneOwner.vtable->pushIdLane(&owner->host->pushLaneOwner, values->values[index]);
  }
  return result;
}

/**
 * Address: 0x00A1F6C0 (FUN_00A1F6C0)
 *
 * What it does:
 * Finds the stride-8 entry with maximal lane-7 value among entries whose
 * lane-6 is positive.
 */
[[maybe_unused]] ScoreEntryStride8Runtime* FindBestScoreEntryWithPositiveGateRuntime(
  ScoreEntryStride8Runtime* const entries,
  const std::int32_t count
) noexcept
{
  std::int32_t bestScore = 0;
  ScoreEntryStride8Runtime* best = nullptr;
  for (std::int32_t index = 0; index < count; ++index) {
    ScoreEntryStride8Runtime& entry = entries[index];
    if (entry.lanes[7] > bestScore && entry.lanes[6] > 0) {
      bestScore = entry.lanes[7];
      best = &entry;
    }
  }
  return best;
}

/**
 * Address: 0x00A1F700 (FUN_00A1F700)
 *
 * What it does:
 * Finds the stride-8 entry with maximal lane-6 value.
 */
[[maybe_unused]] ScoreEntryStride8Runtime* FindBestScoreEntryRuntime(
  ScoreEntryStride8Runtime* const entries,
  const std::int32_t count
) noexcept
{
  std::int32_t bestScore = 0;
  ScoreEntryStride8Runtime* best = nullptr;
  for (std::int32_t index = 0; index < count; ++index) {
    ScoreEntryStride8Runtime& entry = entries[index];
    if (entry.lanes[6] > bestScore) {
      bestScore = entry.lanes[6];
      best = &entry;
    }
  }
  return best;
}

/**
 * Address: 0x00A1FC90 (FUN_00A1FC90)
 *
 * What it does:
 * Computes weighted RGB averages over one bounded 3D histogram range and writes
 * the resulting bytes using owner channel-offset lanes.
 */
[[maybe_unused]] std::int32_t ComputeHistogramWeightedColorRuntime(
  const HistogramProjectionOwnerRuntime* const owner,
  const HistogramBoundsRuntime* const bounds,
  std::uint8_t* const outColor
)
{
  if (owner == nullptr || owner->sliceContext == nullptr || owner->sliceContext->slicesByX == nullptr || owner->outputOffsets == nullptr
      || bounds == nullptr || outColor == nullptr)
  {
    return 0;
  }

  std::int32_t weightedR = 0;
  std::int32_t weightedG = 0;
  std::int32_t weightedB = 0;
  std::int32_t totalWeight = 0;

  for (std::int32_t x = bounds->xMin; x <= bounds->xMax; ++x) {
    const std::int32_t xWeight = (8 * x) + 4;
    for (std::int32_t y = bounds->yMin; y <= bounds->yMax; ++y) {
      std::uint16_t* cell = owner->sliceContext->slicesByX[x] + (2 * (bounds->zMin + (32 * y)));
      const std::int32_t yWeight = (4 * y) + 2;
      for (std::int32_t z = bounds->zMin; z <= bounds->zMax; ++z) {
        const std::int32_t weight = *cell++;
        if (weight != 0) {
          weightedR += weight * xWeight;
          weightedG += weight * yWeight;
          weightedB += weight * ((8 * z) + 4);
          totalWeight += weight;
        }
      }
    }
  }

  const std::int32_t half = totalWeight >> 1;
  outColor[owner->outputOffsets->rOffset] = static_cast<std::uint8_t>((weightedR + half) / totalWeight);
  outColor[owner->outputOffsets->gOffset] = static_cast<std::uint8_t>((weightedG + half) / totalWeight);
  const std::int32_t blue = (weightedB + half) / totalWeight;
  outColor[owner->outputOffsets->bOffset] = static_cast<std::uint8_t>(blue);
  return blue;
}

/**
 * Address: 0x00A1FE90 (FUN_00A1FE90)
 *
 * What it does:
 * Scores each palette lane against a target window profile, writes indices with
 * minimal base-penalty threshold, and returns the written index count.
 */
[[maybe_unused]] std::int32_t SelectPaletteIndicesByWindowPenaltyRuntime(
  const PaletteSampleOwnerRuntime* const owner,
  const std::int32_t targetG,
  const std::int32_t targetR,
  const std::int32_t targetB,
  std::uint8_t* const outIndices
) noexcept
{
  if (owner == nullptr || owner->channels == nullptr || owner->channels->r == nullptr || owner->channels->g == nullptr
      || owner->channels->b == nullptr || outIndices == nullptr)
  {
    return 0;
  }

  std::array<std::int32_t, 256> basePenalty{};
  const std::int32_t count = ClampCountToFixedArray(owner->count, static_cast<std::int32_t>(basePenalty.size()));
  const auto* const r = owner->channels->r;
  const auto* const g = owner->channels->g;
  const auto* const b = owner->channels->b;

  std::int32_t bestComposite = std::numeric_limits<std::int32_t>::max();
  for (std::int32_t index = 0; index < count; ++index) {
    const std::int32_t sampleR = r[index];
    const std::int32_t sampleG = g[index];
    const std::int32_t sampleB = b[index];

    std::int32_t outsidePenalty = ComputeAxisPenaltyPrimary(sampleR, targetR);
    outsidePenalty += ComputeAxisPenaltySecondary(sampleG, targetG, 3);
    outsidePenalty += ComputeAxisPenaltyTertiary(sampleB, targetB);

    const std::int32_t shapePenalty = ComputeAxisShapePrimary(sampleR, targetR)
                                    + ComputeAxisShapeSecondary(sampleG, targetG, 3)
                                    + ComputeAxisShapeTertiary(sampleB, targetB);
    basePenalty[index] = outsidePenalty;
    if (shapePenalty < bestComposite) {
      bestComposite = shapePenalty;
    }
  }

  std::int32_t written = 0;
  for (std::int32_t index = 0; index < count; ++index) {
    if (basePenalty[index] <= bestComposite) {
      outIndices[written] = static_cast<std::uint8_t>(index);
      ++written;
    }
  }
  return written;
}

/**
 * Address: 0x00A20060 (FUN_00A20060)
 *
 * What it does:
 * Updates 128 lattice slots with best candidate palette indices based on
 * weighted RGB distance ramps around the target color.
 */
[[maybe_unused]] std::int32_t UpdateBestPaletteIndexLatticeRuntime(
  const PaletteSampleOwnerRuntime* const owner,
  const std::int32_t targetR,
  const std::int32_t targetG,
  const std::int32_t targetB,
  const std::int32_t candidateCount,
  const std::uint8_t* const candidateIndices,
  std::uint8_t* const outLattice
) noexcept
{
  if (owner == nullptr || owner->channels == nullptr || owner->channels->r == nullptr || owner->channels->g == nullptr
      || owner->channels->b == nullptr || candidateIndices == nullptr || outLattice == nullptr)
  {
    return 0;
  }

  std::array<std::int32_t, 128> bestDistance{};
  bestDistance.fill(std::numeric_limits<std::int32_t>::max());
  for (std::int32_t candidate = 0; candidate < candidateCount; ++candidate) {
    const std::uint8_t sampleIndex = candidateIndices[candidate];
    const std::int32_t dR = targetR - owner->channels->r[sampleIndex];
    const std::int32_t dG3 = 3 * (targetG - owner->channels->g[sampleIndex]);
    const std::int32_t dB = targetB - owner->channels->b[sampleIndex];

    std::int32_t base = (2 * dR) * (2 * dR) + (dG3 * dG3) + (dB * dB);
    std::int32_t deltaX = 32 * ((2 * dR) + 8);
    const std::int32_t deltaY0 = 8 * ((3 * dG3) + 18);
    const std::int32_t deltaZ = 16 * (dB + 4);

    std::int32_t lane = 0;
    for (std::int32_t x = 0; x < 4; ++x) {
      std::int32_t value = base;
      std::int32_t deltaY = deltaY0;
      for (std::int32_t y = 0; y < 8; ++y) {
        const std::int32_t value0 = value;
        if (value0 < bestDistance[lane + 0]) {
          bestDistance[lane + 0] = value0;
          outLattice[lane + 0] = sampleIndex;
        }

        const std::int32_t value1 = value0 + deltaZ;
        if (value1 < bestDistance[lane + 1]) {
          bestDistance[lane + 1] = value1;
          outLattice[lane + 1] = sampleIndex;
        }

        const std::int32_t value2 = value1 + (deltaZ + 128);
        if (value2 < bestDistance[lane + 2]) {
          bestDistance[lane + 2] = value2;
          outLattice[lane + 2] = sampleIndex;
        }

        const std::int32_t value3 = value2 + (deltaZ + 256);
        if (value3 < bestDistance[lane + 3]) {
          bestDistance[lane + 3] = value3;
          outLattice[lane + 3] = sampleIndex;
        }

        value += deltaY;
        deltaY += 0x120;
        lane += 4;
      }

      base += deltaX;
      deltaX += 0x200;
    }
  }

  return 0;
}

/**
 * Address: 0x00A27220 (FUN_00A27220)
 *
 * What it does:
 * Builds one iterator pair for the first non-null entry in a pointer array.
 */
[[maybe_unused]] ArrayIteratorRuntime* BeginPointerArrayIteratorRuntime(
  const PointerArrayOwnerRuntime* const owner,
  ArrayIteratorRuntime* const outIterator
) noexcept
{
  if (outIterator == nullptr) {
    return nullptr;
  }

  void* value = nullptr;
  if (owner != nullptr && owner->entries != nullptr) {
    for (std::uint32_t index = 0; index < owner->count; ++index) {
      if (owner->entries[index] != nullptr) {
        value = owner->entries[index];
        break;
      }
    }
  }

  outIterator->value = value;
  outIterator->owner = owner;
  return outIterator;
}

/**
 * Address: 0x00A27760 (FUN_00A27760)
 *
 * What it does:
 * Increments one nonzero ticket lane at `+0x0C`, returning null when the lane
 * is zero.
 */
[[maybe_unused]] RefTicketRuntime* IncrementNonZeroRefTicketRuntime(
  RefTicketRuntime* const owner
) noexcept
{
  if (owner == nullptr || owner->ticket == 0u) {
    return nullptr;
  }
  ++owner->ticket;
  return owner;
}

/**
 * Address: 0x00A2C5B0 (FUN_00A2C5B0)
 *
 * What it does:
 * Returns true when one 16-bit lane is in range `[1, 0x1E]`.
 */
[[maybe_unused]] BOOL IsWordInOneToThirtyRuntime(
  const std::uint16_t* const lane
) noexcept
{
  if (lane == nullptr) {
    return FALSE;
  }
  return (*lane != 0u && *lane < 0x1Fu) ? TRUE : FALSE;
}

/**
 * Address: 0x00A2CE70 (FUN_00A2CE70)
 *
 * What it does:
 * Marks one handle lane for shutdown, calls its release slot, and clears owner
 * handle ownership.
 */
[[maybe_unused]] int ShutdownAndReleaseHandleRuntime(
  ReleasableHandleOwnerRuntime* const owner
)
{
  if (owner == nullptr || owner->handle == nullptr || owner->handle->vtable == nullptr
      || owner->handle->vtable->releaseSlot == nullptr)
  {
    return 0;
  }

  owner->handle->shutdownFlag = 1u;
  const int result = owner->handle->vtable->releaseSlot(owner->handle);
  owner->handle = nullptr;
  return result;
}

/**
 * Address: 0x00A2FEB0 (FUN_00A2FEB0)
 *
 * What it does:
 * Clears channel accumulator/output lane pairs selected by a 4-bit mask.
 */
[[maybe_unused]] ChannelMaskOwnerRuntime* ClearChannelPairsByMaskRuntime(
  ChannelMaskOwnerRuntime* const owner,
  const std::uint8_t mask
) noexcept
{
  if (owner == nullptr) {
    return nullptr;
  }

  if ((mask & 0x1u) != 0u) {
    owner->lanes[12] = 0u;
    owner->lanes[16] = 0u;
  }
  if ((mask & 0x2u) != 0u) {
    owner->lanes[13] = 0u;
    owner->lanes[17] = 0u;
  }
  if ((mask & 0x4u) != 0u) {
    owner->lanes[14] = 0u;
    owner->lanes[18] = 0u;
  }
  if ((mask & 0x8u) != 0u) {
    owner->lanes[15] = 0u;
    owner->lanes[19] = 0u;
  }
  return owner;
}

/**
 * Address: 0x00A31010 (FUN_00A31010)
 *
 * What it does:
 * Finds one payload by id in the owner list at offset `+0x20`.
 */
[[maybe_unused]] ManagedPayloadRuntime* FindPayloadByIdInList20Runtime(
  const ManagedNodeListsOwnerRuntime* const owner,
  const std::int32_t id
) noexcept
{
  if (owner == nullptr) {
    return nullptr;
  }
  return FindManagedPayloadByIdRuntime(owner->listAt20, id);
}

/**
 * Address: 0x00A31040 (FUN_00A31040)
 *
 * What it does:
 * Removes the first node with matching payload id from the owner list at
 * offset `+0x20`.
 */
[[maybe_unused]] std::uint8_t RemovePayloadByIdFromList20Runtime(
  ManagedNodeListsOwnerRuntime* const owner,
  const std::int32_t id
) noexcept
{
  if (owner == nullptr) {
    return 0u;
  }
  return RemoveManagedNodeByIdRuntime(owner->listAt20, id);
}

/**
 * Address: 0x00A311A0 (FUN_00A311A0)
 *
 * What it does:
 * Finds one payload by id in the owner list at offset `+0x1C`.
 */
[[maybe_unused]] ManagedPayloadRuntime* FindPayloadByIdInList1CRuntime(
  const ManagedNodeListsOwnerRuntime* const owner,
  const std::int32_t id
) noexcept
{
  if (owner == nullptr) {
    return nullptr;
  }
  return FindManagedPayloadByIdRuntime(owner->listAt1C, id);
}

/**
 * Address: 0x00A311D0 (FUN_00A311D0)
 *
 * What it does:
 * Removes the first node with matching payload id from the owner list at
 * offset `+0x1C`.
 */
[[maybe_unused]] std::uint8_t RemovePayloadByIdFromList1CRuntime(
  ManagedNodeListsOwnerRuntime* const owner,
  const std::int32_t id
) noexcept
{
  if (owner == nullptr) {
    return 0u;
  }
  return RemoveManagedNodeByIdRuntime(owner->listAt1C, id);
}

struct Float2LaneRuntime
{
  float lane0;
  float lane1;
};
static_assert(sizeof(Float2LaneRuntime) == 0x08, "Float2LaneRuntime size must be 0x08");

struct Float3LaneRuntime
{
  float lane0;
  float lane1;
  float lane2;
};
static_assert(sizeof(Float3LaneRuntime) == 0x0C, "Float3LaneRuntime size must be 0x0C");

struct Float4LaneRuntime
{
  float lane0;
  float lane1;
  float lane2;
  float lane3;
};
static_assert(sizeof(Float4LaneRuntime) == 0x10, "Float4LaneRuntime size must be 0x10");

struct Float5LaneRuntime
{
  float lane0;
  float lane1;
  float lane2;
  float lane3;
  float lane4;
};
static_assert(sizeof(Float5LaneRuntime) == 0x14, "Float5LaneRuntime size must be 0x14");

struct Double3LaneRuntime
{
  double lane0;
  double lane1;
  double lane2;
};
static_assert(sizeof(Double3LaneRuntime) == 0x18, "Double3LaneRuntime size must be 0x18");

struct Dword4LaneRuntime
{
  std::uint32_t lane0;
  std::uint32_t lane1;
  std::uint32_t lane2;
  std::uint32_t lane3;
};
static_assert(sizeof(Dword4LaneRuntime) == 0x10, "Dword4LaneRuntime size must be 0x10");

struct Dword2LaneRuntime
{
  std::uint32_t lane0;
  std::uint32_t lane1;
};
static_assert(sizeof(Dword2LaneRuntime) == 0x08, "Dword2LaneRuntime size must be 0x08");

struct StringRankLaneRuntime
{
  const char* text;
  std::int32_t rank;
};

struct ByteFlushStateRuntime
{
  std::byte pad00[0x08];
  std::uint8_t* outputBuffer; // +0x08
  std::byte pad0C[0x08];
  std::uint32_t outputSize; // +0x14
  std::byte pad18[0x16A0];
  std::uint16_t stagedWord; // +0x16B8
  std::uint16_t stagedHighByte;
  std::uint32_t stagedBitCount; // +0x16BC
};

struct RuntimeDispatchVTable
{
  std::byte pad00[0x08];
  int (__thiscall* dispatch)(void* self, int arg0, int arg1, int arg2, int arg3);
};

struct RuntimeDispatchTarget
{
  RuntimeDispatchVTable* vtable;
};

struct RuntimeDispatchRelayOwner
{
  std::byte pad00[0x08];
  RuntimeDispatchTarget* fallbackTarget; // +0x08
  RuntimeDispatchTarget* localTarget; // +0x0C
  std::uint8_t localDispatchEnabled; // +0x10
};

struct SnapshotPayloadVTableRuntime
{
  std::uint32_t lane00;
  int (__thiscall* release)(void* self, int lane);
};

struct SnapshotPayloadRuntime
{
  SnapshotPayloadVTableRuntime* vtable;
  std::uint32_t lane04;
  std::uint32_t lane08;
  std::uint32_t lane0C;
  std::uint8_t lane10;
  std::byte pad11[3];
  std::uint32_t lane14;
};

struct SnapshotOwnerLinkVTableRuntime
{
  void (__thiscall* release)(void* self, int lane);
};

struct SnapshotOwnerLinkRuntime
{
  SnapshotOwnerLinkVTableRuntime* vtable;
  std::uint32_t lane04;
  SnapshotPayloadRuntime* payload; // +0x08
};

struct SnapshotOwnerRuntime
{
  std::byte pad00[0x10];
  std::uint32_t cachedLane08; // +0x10
  std::byte pad14[0x28];
  SnapshotOwnerLinkRuntime* ownerLink; // +0x3C
  std::byte pad40[0x1C];
  std::uint32_t cachedLane14; // +0x5C
  std::uint8_t cachedLane10; // +0x60
  std::byte pad61[3];
  std::uint32_t cachedLane0C; // +0x64
};

struct SelectionSpanOwnerRuntime
{
  std::byte pad00[0x13C];
  std::byte* begin; // +0x13C
  std::byte* end; // +0x140
  std::uint32_t lane144;
  std::int32_t selectedIndex; // +0x148
};

struct CacheResolverVTableRuntime
{
  std::uint32_t lane00;
  std::uint32_t lane04;
  std::uint32_t lane08;
  int (__thiscall* resolve)(void* self, int key, int base0, int base1);
};

struct CacheResolverRuntime
{
  CacheResolverVTableRuntime* vtable;
};

struct CachedResolvedValueRuntime
{
  std::int32_t base0;
  std::int32_t base1;
  std::byte pad08[0x08];
  std::int32_t cachedValue; // +0x10
  std::int32_t cachedKey; // +0x14
};

struct ViewportQueryVTableRuntime
{
  void* slots00[101];
  void (__thiscall* queryBounds)(void* self, int* outWidth, int* outHeight);
  void* slot198;
  void* slot19C;
  int (__thiscall* applyBounds)(void* self, int left, int top, int width, int height, int flags);
};

struct ViewportQueryRuntime
{
  ViewportQueryVTableRuntime* vtable;
};

struct SharedCounterVTableRuntime
{
  std::uint32_t lane00;
  void (__thiscall* releaseStrong)(void* self);
  int (__thiscall* releaseWeakAndDelete)(void* self);
};

struct SharedCounterRuntime
{
  SharedCounterVTableRuntime* vtable;
  volatile long strongRefBias; // +0x04
  volatile long weakRefBias; // +0x08
};

struct SharedCounterOwnerRuntime
{
  std::uint32_t lane00;
  SharedCounterRuntime* counter; // +0x04
};

struct TripleStateOwnerRuntime
{
  std::byte pad00[0x0C];
  std::int32_t lane0C;
  std::int32_t lane10;
  std::int32_t lane14;
};

struct MatchResetStateRuntime
{
  std::byte pad00[0x08];
  std::int32_t token; // +0x08
  std::int32_t state0C;
  std::int32_t state10;
  std::int32_t state14;
  std::int32_t state18;
  std::int32_t state1C;
  std::int32_t state20;
};

[[nodiscard]] std::uint8_t HexNibbleFromAsciiRuntime(const std::uint8_t character) noexcept
{
  if (character >= static_cast<std::uint8_t>('a')) {
    return static_cast<std::uint8_t>(character - static_cast<std::uint8_t>('a') + 10u);
  }
  if (character >= static_cast<std::uint8_t>('A')) {
    return static_cast<std::uint8_t>(character - static_cast<std::uint8_t>('A') + 10u);
  }
  return static_cast<std::uint8_t>(character - static_cast<std::uint8_t>('0'));
}

template <typename T>
void SwapByValueRuntime(T& lhs, T& rhs) noexcept
{
  T temp = lhs;
  lhs = rhs;
  rhs = temp;
}

[[nodiscard]] bool IsStringRankLessRuntime(
  const StringRankLaneRuntime& lhs,
  const StringRankLaneRuntime& rhs
)
{
  const int cmp = std::strcmp(lhs.text, rhs.text);
  if (cmp != 0) {
    return cmp < 0;
  }
  return lhs.rank < rhs.rank;
}

[[nodiscard]] bool CompareFloat3ByLane2DescTieLane1AscRuntime(
  const Float3LaneRuntime& lhs,
  const Float3LaneRuntime& rhs
) noexcept
{
  if (lhs.lane2 != rhs.lane2) {
    return lhs.lane2 > rhs.lane2;
  }
  return lhs.lane1 < rhs.lane1;
}

[[nodiscard]] double ReadDoubleLane0Runtime(const Dword4LaneRuntime& lanes) noexcept
{
  double result = 0.0;
  std::memcpy(&result, &lanes.lane0, sizeof(double));
  return result;
}

/**
 * Address: 0x0092BE50 (FUN_0092BE50)
 *
 * What it does:
 * Copies one byte range `[first, last)` into an optional destination buffer
 * and returns the destination cursor advanced by copied length.
 */
[[maybe_unused]] std::uint8_t* CopyByteRangeAndAdvanceRuntimeA(
  const std::uint8_t* first,
  const std::uint8_t* last,
  std::uint8_t* output
) noexcept
{
  while (first != last) {
    if (output != nullptr) {
      *output = *first;
    }
    ++first;
    ++output;
  }
  return output;
}

/**
 * Address: 0x00954250 (FUN_00954250)
 *
 * What it does:
 * Copies one byte range `[first, last)` into an optional destination buffer
 * and returns the destination cursor advanced by copied length.
 */
[[maybe_unused]] std::uint8_t* CopyByteRangeAndAdvanceRuntimeB(
  const std::uint8_t* first,
  const std::uint8_t* last,
  std::uint8_t* output
) noexcept
{
  return CopyByteRangeAndAdvanceRuntimeA(first, last, output);
}

/**
 * Address: 0x0095F0C0 (FUN_0095F0C0)
 *
 * What it does:
 * Flushes staged bits to the output byte stream when at least one full byte
 * is pending in the bit accumulator lane.
 */
[[maybe_unused]] ByteFlushStateRuntime* FlushStagedBitsToOutputRuntime(
  ByteFlushStateRuntime* const owner
) noexcept
{
  if (owner == nullptr) {
    return nullptr;
  }

  if (owner->stagedBitCount == 16u) {
    owner->outputBuffer[owner->outputSize++] = static_cast<std::uint8_t>(owner->stagedWord & 0xFFu);
    owner->outputBuffer[owner->outputSize++] = owner->stagedHighByte;
    owner->stagedBitCount = 0u;
    owner->stagedWord = 0u;
    owner->stagedHighByte = 0u;
  } else if (owner->stagedBitCount >= 8u) {
    owner->outputBuffer[owner->outputSize++] = static_cast<std::uint8_t>(owner->stagedWord & 0xFFu);
    owner->stagedBitCount -= 8u;
    owner->stagedWord = owner->stagedHighByte;
    owner->stagedHighByte = 0u;
  }

  return owner;
}

/**
 * Address: 0x009C50A0 (FUN_009C50A0)
 *
 * What it does:
 * Dispatches one event call to an optional local target, then forwards to the
 * fallback target unless it self-points to the owner.
 */
[[maybe_unused]] int RelayDispatchToTargetsRuntime(
  RuntimeDispatchRelayOwner* const owner,
  const int arg0,
  const int arg1,
  const int arg2,
  const int arg3
)
{
  if (owner == nullptr) {
    return 0;
  }

  if (owner->localTarget != nullptr && owner->localDispatchEnabled != 0u) {
    owner->localTarget->vtable->dispatch(owner->localTarget, arg0, arg1, arg2, arg3);
  }

  const int fallbackAsInt = static_cast<int>(reinterpret_cast<std::uintptr_t>(owner->fallbackTarget));
  if (owner->fallbackTarget != nullptr && owner->fallbackTarget != reinterpret_cast<RuntimeDispatchTarget*>(owner)) {
    return owner->fallbackTarget->vtable->dispatch(owner->fallbackTarget, arg0, arg1, arg2, arg3);
  }
  return fallbackAsInt;
}

/**
 * Address: 0x009EA100 (FUN_009EA100)
 *
 * What it does:
 * Decodes two ASCII hex digits into one byte value.
 */
[[maybe_unused]] int DecodeAsciiHexByteRuntime(
  const std::uint8_t highDigit,
  const std::uint8_t lowDigit
) noexcept
{
  const std::uint8_t high = HexNibbleFromAsciiRuntime(highDigit);
  const std::uint8_t low = HexNibbleFromAsciiRuntime(lowDigit);
  return static_cast<int>(low + static_cast<std::uint8_t>(16u * high));
}

/**
 * Address: 0x00A3AB20 (FUN_00A3AB20)
 *
 * What it does:
 * Adds two 3-lane double vectors and writes the result into the destination
 * lane.
 */
[[maybe_unused]] Double3LaneRuntime* AddDouble3LanesRuntime(
  const Double3LaneRuntime* const lhs,
  Double3LaneRuntime* const out,
  const Double3LaneRuntime* const rhs
) noexcept
{
  out->lane0 = rhs->lane0 + lhs->lane0;
  out->lane1 = rhs->lane1 + lhs->lane1;
  out->lane2 = rhs->lane2 + lhs->lane2;
  return out;
}

/**
 * Address: 0x00A8F680 (FUN_00A8F680)
 *
 * What it does:
 * Swaps `byteCount` bytes between two buffers and returns the first cursor
 * advanced by that count.
 */
[[maybe_unused]] std::uint8_t* SwapByteRangesRuntime(
  std::uint8_t* first,
  std::uint32_t byteCount,
  std::uint8_t* second
) noexcept
{
  if (first != second && byteCount != 0u) {
    std::uint32_t remaining = byteCount;
    do {
      const std::uint8_t temp = *first;
      *first = *second;
      *second = temp;
      ++first;
      ++second;
      --remaining;
    } while (remaining != 0u);
  }

  return first;
}

/**
 * Address: 0x007990F0 (FUN_007990F0)
 *
 * What it does:
 * Returns the number of stride-0x1C entries in a contiguous span lane.
 */
[[maybe_unused]] int GetSelectionSpanCountRuntime(
  const SelectionSpanOwnerRuntime* const owner
) noexcept
{
  if (owner == nullptr || owner->begin == nullptr) {
    return 0;
  }
  return static_cast<int>((owner->end - owner->begin) / 0x1C);
}

/**
 * Address: 0x007EED00 (FUN_007EED00)
 *
 * What it does:
 * Emits one triangle index strip over a [start,end) lane, selecting winding
 * order from the `flipWinding` flag and returning the advanced cursor.
 */
[[maybe_unused]] int EmitTriangleStripIndicesRuntime(
  int writeCursor,
  std::uint16_t* const outIndices,
  const int start,
  const int end,
  const int laneOffset,
  const bool flipWinding
) noexcept
{
  std::int16_t pivot = static_cast<std::int16_t>(start);
  int current = start;
  if (start < end) {
    const std::int16_t lane = static_cast<std::int16_t>(laneOffset);
    int secondary = 1 - laneOffset;
    int edge = start + laneOffset;
    while (true) {
      const int candidatePivot = edge + secondary;
      if (candidatePivot != end) {
        pivot = static_cast<std::int16_t>(candidatePivot);
      }

      const std::int16_t pivotPlusLane = static_cast<std::int16_t>(pivot + lane);
      if (flipWinding) {
        outIndices[writeCursor + 0] = static_cast<std::uint16_t>(current);
        outIndices[writeCursor + 1] = static_cast<std::uint16_t>(edge);
        outIndices[writeCursor + 2] = static_cast<std::uint16_t>(pivot);
        outIndices[writeCursor + 3] = static_cast<std::uint16_t>(pivotPlusLane);
        outIndices[writeCursor + 4] = static_cast<std::uint16_t>(pivot);
        outIndices[writeCursor + 5] = static_cast<std::uint16_t>(edge);
      } else {
        outIndices[writeCursor + 0] = static_cast<std::uint16_t>(pivot);
        outIndices[writeCursor + 1] = static_cast<std::uint16_t>(edge);
        outIndices[writeCursor + 2] = static_cast<std::uint16_t>(current);
        outIndices[writeCursor + 3] = static_cast<std::uint16_t>(edge);
        outIndices[writeCursor + 4] = static_cast<std::uint16_t>(pivot);
        outIndices[writeCursor + 5] = static_cast<std::uint16_t>(pivotPlusLane);
      }

      ++current;
      writeCursor += 6;
      ++edge;
      if (current >= end) {
        break;
      }

      secondary = 1 - laneOffset;
      pivot = static_cast<std::int16_t>(start);
    }
  }
  return writeCursor;
}

/**
 * Address: 0x00A2EEB0 (FUN_00A2EEB0)
 *
 * What it does:
 * Copies cached snapshot lanes from the bound payload into owner state and
 * decrements both owner-link and payload reference lanes.
 */
[[maybe_unused]] int CopySnapshotAndReleaseBindingsRuntime(
  SnapshotOwnerRuntime* const owner
)
{
  if (owner == nullptr) {
    return 0;
  }

  SnapshotOwnerLinkRuntime* const link = owner->ownerLink;
  if (link == nullptr) {
    return static_cast<int>(reinterpret_cast<std::uintptr_t>(owner));
  }

  SnapshotPayloadRuntime* const payload = link->payload;
  owner->cachedLane08 = payload->lane08;
  owner->cachedLane10 = payload->lane10;
  owner->cachedLane0C = payload->lane0C;
  owner->cachedLane14 = payload->lane14;
  link->vtable->release(link, 1);
  return payload->vtable->release(payload, 1);
}

/**
 * Address: 0x00AB8E4C (FUN_00AB8E4C)
 *
 * What it does:
 * Returns whether the input lane is nonzero.
 */
[[maybe_unused]] BOOL IsNonZeroBoolLaneRuntime(const int value) noexcept
{
  return (value != 0) ? TRUE : FALSE;
}

/**
 * Address: 0x0054FC70 (FUN_0054FC70)
 *
 * What it does:
 * Sorts three `(string,rank)` lanes ascending by string then rank using a
 * fixed three-comparator network; returns the final swap predicate.
 */
[[maybe_unused]] char SortThreeStringRankLanesRuntime(
  StringRankLaneRuntime* const lane0,
  StringRankLaneRuntime* const lane1,
  StringRankLaneRuntime* const lane2
)
{
  if (IsStringRankLessRuntime(*lane1, *lane0)) {
    SwapByValueRuntime(*lane0, *lane1);
  }

  if (IsStringRankLessRuntime(*lane2, *lane1)) {
    SwapByValueRuntime(*lane1, *lane2);
  }

  const bool lastSwap = IsStringRankLessRuntime(*lane1, *lane0);
  if (lastSwap) {
    SwapByValueRuntime(*lane0, *lane1);
  }
  return lastSwap ? 1 : 0;
}

/**
 * Address: 0x00595D20 (FUN_00595D20)
 *
 * What it does:
 * Sorts three float3 lanes ascending by lane2 and returns the middle lane
 * pointer.
 */
[[maybe_unused]] Float3LaneRuntime* SortThreeFloat3ByLane2AscendingRuntime(
  Float3LaneRuntime* const lane0,
  Float3LaneRuntime* const lane1,
  Float3LaneRuntime* const lane2
) noexcept
{
  if (lane0->lane2 > lane1->lane2) {
    SwapByValueRuntime(*lane0, *lane1);
  }
  if (lane1->lane2 > lane2->lane2) {
    SwapByValueRuntime(*lane1, *lane2);
  }
  if (lane0->lane2 > lane1->lane2) {
    SwapByValueRuntime(*lane0, *lane1);
  }
  return lane1;
}

/**
 * Address: 0x005F01C0 (FUN_005F01C0)
 *
 * What it does:
 * Sorts three float5 lanes ascending by lane4 and returns the middle lane
 * pointer.
 */
[[maybe_unused]] Float5LaneRuntime* SortThreeFloat5ByLane4AscendingRuntime(
  Float5LaneRuntime* const lane0,
  Float5LaneRuntime* const lane1,
  Float5LaneRuntime* const lane2
) noexcept
{
  if (lane0->lane4 > lane1->lane4) {
    SwapByValueRuntime(*lane0, *lane1);
  }
  if (lane1->lane4 > lane2->lane4) {
    SwapByValueRuntime(*lane1, *lane2);
  }
  if (lane0->lane4 > lane1->lane4) {
    SwapByValueRuntime(*lane0, *lane1);
  }
  return lane1;
}

/**
 * Address: 0x0071FEE0 (FUN_0071FEE0)
 *
 * What it does:
 * Sorts three float4 lanes descending by lane3 and returns the middle lane
 * pointer.
 */
[[maybe_unused]] Float4LaneRuntime* SortThreeFloat4ByLane3DescendingRuntime(
  Float4LaneRuntime* const lane0,
  Float4LaneRuntime* const lane1,
  Float4LaneRuntime* const lane2
) noexcept
{
  if (lane1->lane3 > lane0->lane3) {
    SwapByValueRuntime(*lane0, *lane1);
  }
  if (lane2->lane3 > lane1->lane3) {
    SwapByValueRuntime(*lane1, *lane2);
  }
  if (lane1->lane3 > lane0->lane3) {
    SwapByValueRuntime(*lane0, *lane1);
  }
  return lane1;
}

/**
 * Address: 0x007342C0 (FUN_007342C0)
 *
 * What it does:
 * Sorts three float2 lanes ascending by lane1 and returns the middle lane
 * pointer.
 */
[[maybe_unused]] Float2LaneRuntime* SortThreeFloat2ByLane1AscendingRuntime(
  Float2LaneRuntime* const lane0,
  Float2LaneRuntime* const lane1,
  Float2LaneRuntime* const lane2
) noexcept
{
  if (lane0->lane1 > lane1->lane1) {
    SwapByValueRuntime(*lane0, *lane1);
  }
  if (lane1->lane1 > lane2->lane1) {
    SwapByValueRuntime(*lane1, *lane2);
  }
  if (lane0->lane1 > lane1->lane1) {
    SwapByValueRuntime(*lane0, *lane1);
  }
  return lane1;
}

/**
 * Address: 0x00760690 (FUN_00760690)
 *
 * What it does:
 * Sorts three `(id,score)` dword pairs descending by score and returns the
 * middle lane pointer.
 */
[[maybe_unused]] std::uint32_t* SortThreeDwordPairsByScoreDescendingRuntime(
  std::uint32_t* const lane0Raw,
  std::uint32_t* const lane1Raw,
  std::uint32_t* const lane2Raw
) noexcept
{
  auto* const lane0 = reinterpret_cast<Dword2LaneRuntime*>(lane0Raw);
  auto* const lane1 = reinterpret_cast<Dword2LaneRuntime*>(lane1Raw);
  auto* const lane2 = reinterpret_cast<Dword2LaneRuntime*>(lane2Raw);

  if (lane0->lane1 < lane1->lane1) {
    SwapByValueRuntime(*lane0, *lane1);
  }
  if (lane1->lane1 < lane2->lane1) {
    SwapByValueRuntime(*lane1, *lane2);
  }
  if (lane0->lane1 < lane1->lane1) {
    SwapByValueRuntime(*lane0, *lane1);
  }
  return lane1Raw;
}

/**
 * Address: 0x00799A10 (FUN_00799A10)
 *
 * What it does:
 * Selects an in-range stride-0x1C element index or clears selection to `-1`.
 */
[[maybe_unused]] unsigned int SelectSpanEntryByIndexRuntime(
  const unsigned int requestedIndex,
  SelectionSpanOwnerRuntime* const owner
) noexcept
{
  const unsigned int count = static_cast<unsigned int>(GetSelectionSpanCountRuntime(owner));
  if (count != 0u && requestedIndex < count) {
    owner->selectedIndex = static_cast<std::int32_t>(requestedIndex);
  } else {
    owner->selectedIndex = -1;
  }
  return count;
}

/**
 * Address: 0x0084BE60 (FUN_0084BE60)
 *
 * What it does:
 * Sorts three float3 lanes ascending by lane1 and returns the middle lane
 * pointer.
 */
[[maybe_unused]] Float3LaneRuntime* SortThreeFloat3ByLane1AscendingRuntime(
  Float3LaneRuntime* const lane0,
  Float3LaneRuntime* const lane1,
  Float3LaneRuntime* const lane2
) noexcept
{
  if (lane0->lane1 > lane1->lane1) {
    SwapByValueRuntime(*lane0, *lane1);
  }
  if (lane1->lane1 > lane2->lane1) {
    SwapByValueRuntime(*lane1, *lane2);
  }
  if (lane0->lane1 > lane1->lane1) {
    SwapByValueRuntime(*lane0, *lane1);
  }
  return lane1;
}

/**
 * Address: 0x0084C050 (FUN_0084C050)
 *
 * What it does:
 * Sorts three float3 lanes by descending lane2 with ascending lane1 tie-break
 * and returns the middle lane pointer.
 */
[[maybe_unused]] Float3LaneRuntime* SortThreeFloat3ByLane2DescTieLane1AscRuntime(
  Float3LaneRuntime* const lane0,
  Float3LaneRuntime* const lane1,
  Float3LaneRuntime* const lane2
) noexcept
{
  if (CompareFloat3ByLane2DescTieLane1AscRuntime(*lane1, *lane0)) {
    SwapByValueRuntime(*lane0, *lane1);
  }
  if (CompareFloat3ByLane2DescTieLane1AscRuntime(*lane2, *lane1)) {
    SwapByValueRuntime(*lane1, *lane2);
  }
  if (CompareFloat3ByLane2DescTieLane1AscRuntime(*lane1, *lane0)) {
    SwapByValueRuntime(*lane0, *lane1);
  }
  return lane1;
}

/**
 * Address: 0x00A727C0 (FUN_00A727C0)
 *
 * What it does:
 * Sorts three float2 lanes ascending by lane0.
 */
[[maybe_unused]] void SortThreeFloat2ByLane0AscendingRuntime(
  Float2LaneRuntime* const lane0,
  Float2LaneRuntime* const lane1,
  Float2LaneRuntime* const lane2
) noexcept
{
  if (lane0->lane0 > lane1->lane0) {
    SwapByValueRuntime(*lane0, *lane1);
  }
  if (lane1->lane0 > lane2->lane0) {
    SwapByValueRuntime(*lane1, *lane2);
  }
  if (lane0->lane0 > lane1->lane0) {
    SwapByValueRuntime(*lane0, *lane1);
  }
}

/**
 * Address: 0x00A728C0 (FUN_00A728C0)
 *
 * What it does:
 * Sorts three 16-byte lanes ascending by their lane0 double key.
 */
[[maybe_unused]] void SortThreeDword4ByDoubleKeyAscendingRuntime(
  Dword4LaneRuntime* const lane0,
  Dword4LaneRuntime* const lane1,
  Dword4LaneRuntime* const lane2
) noexcept
{
  if (ReadDoubleLane0Runtime(*lane0) > ReadDoubleLane0Runtime(*lane1)) {
    SwapByValueRuntime(*lane0, *lane1);
  }
  if (ReadDoubleLane0Runtime(*lane1) > ReadDoubleLane0Runtime(*lane2)) {
    SwapByValueRuntime(*lane1, *lane2);
  }
  if (ReadDoubleLane0Runtime(*lane0) > ReadDoubleLane0Runtime(*lane1)) {
    SwapByValueRuntime(*lane0, *lane1);
  }
}

/**
 * Address: 0x00A806B0 (FUN_00A806B0)
 *
 * What it does:
 * Updates one cached resolved value when key changes by invoking resolver slot
 * `+0x0C`.
 */
[[maybe_unused]] int UpdateCachedResolvedValueRuntimeA(
  CachedResolvedValueRuntime* const owner,
  const int key,
  CacheResolverRuntime* const resolver
)
{
  if (key != owner->cachedKey) {
    owner->cachedKey = key;
    owner->cachedValue = resolver->vtable->resolve(resolver, key, owner->base0, owner->base1);
  }
  return owner->cachedValue;
}

/**
 * Address: 0x00A807F0 (FUN_00A807F0)
 *
 * What it does:
 * Updates one cached resolved value when key changes by invoking resolver slot
 * `+0x0C`.
 */
[[maybe_unused]] int UpdateCachedResolvedValueRuntimeB(
  CachedResolvedValueRuntime* const owner,
  const int key,
  CacheResolverRuntime* const resolver
)
{
  return UpdateCachedResolvedValueRuntimeA(owner, key, resolver);
}

/**
 * Address: 0x006638B0 (FUN_006638B0)
 *
 * What it does:
 * Queries viewport bounds and applies an updated rectangle with width scaled
 * to one-third.
 */
[[maybe_unused]] int QueryAndApplyViewportThirdWidthRuntime(
  ViewportQueryRuntime* const owner
)
{
  int width = 0;
  int height = 0;
  owner->vtable->queryBounds(owner, &width, &height);
  return owner->vtable->applyBounds(owner, -1, -1, width / 3, height, 0);
}

/**
 * Address: 0x00A4FD90 (FUN_00A4FD90)
 *
 * What it does:
 * Updates one parametric clip interval edge for a half-space inequality and
 * returns whether the interval remains valid.
 */
[[maybe_unused]] bool UpdateClipIntervalLaneRuntime(
  const double denominator,
  const double numerator,
  double* const lower,
  double* const upper
) noexcept
{
  if (denominator <= 0.0) {
    if (denominator >= 0.0) {
      return numerator <= 0.0;
    }

    if (numerator > (*lower * denominator)) {
      return false;
    }
    if ((*upper * denominator) < numerator) {
      *upper = numerator / denominator;
    }
    return true;
  }

  if (numerator > (*upper * denominator)) {
    return false;
  }
  if ((*lower * denominator) < numerator) {
    *lower = numerator / denominator;
  }
  return true;
}

/**
 * Address: 0x00A7D380 (FUN_00A7D380)
 *
 * What it does:
 * Writes three integer state lanes at offsets `+0x0C/+0x10/+0x14`.
 */
[[maybe_unused]] int SetTripleStateLanesRuntimeA(
  TripleStateOwnerRuntime* const owner,
  const int value0C,
  const int value10,
  const int value14
) noexcept
{
  owner->lane0C = value0C;
  owner->lane10 = value10;
  owner->lane14 = value14;
  return value14;
}

/**
 * Address: 0x00A7D460 (FUN_00A7D460)
 *
 * What it does:
 * Writes three integer state lanes at offsets `+0x0C/+0x10/+0x14`.
 */
[[maybe_unused]] int SetTripleStateLanesRuntimeB(
  TripleStateOwnerRuntime* const owner,
  const int value0C,
  const int value10,
  const int value14
) noexcept
{
  return SetTripleStateLanesRuntimeA(owner, value0C, value10, value14);
}

/**
 * Address: 0x009CC030 (FUN_009CC030)
 *
 * What it does:
 * Validates a token lane and resets six state lanes when it matches.
 */
[[maybe_unused]] char ValidateTokenAndResetStateRuntime(
  MatchResetStateRuntime* const owner,
  const int token
) noexcept
{
  if (token != owner->token) {
    return 0;
  }

  owner->state0C = 1;
  owner->state10 = 1;
  owner->state14 = 0;
  owner->state18 = 0;
  owner->state1C = 0;
  owner->state20 = 1;
  owner->token = 0;
  return 1;
}

/**
 * Address: 0x0064DFE0 (FUN_0064DFE0)
 *
 * What it does:
 * Releases one shared-counter owner lane by decrementing strong and weak bias
 * counters and invoking vtable release slots when they transition from zero.
 */
[[maybe_unused]] int ReleaseSharedCounterOwnerRuntime(
  SharedCounterOwnerRuntime* const owner
)
{
  int result = static_cast<int>(reinterpret_cast<std::uintptr_t>(owner));
  SharedCounterRuntime* const counter = (owner != nullptr) ? owner->counter : nullptr;
  if (counter == nullptr) {
    return result;
  }

  if (InterlockedExchangeAdd(&counter->strongRefBias, -1) == 0) {
    counter->vtable->releaseStrong(counter);
    result = static_cast<int>(reinterpret_cast<std::uintptr_t>(&counter->weakRefBias));
    if (InterlockedExchangeAdd(&counter->weakRefBias, -1) == 0) {
      return counter->vtable->releaseWeakAndDelete(counter);
    }
  }
  return result;
}

namespace
{
  using OpaqueCallbackRuntime = void (*)();

  struct LaneConfigOwnerRuntime
  {
    std::byte pad00[0x08];
    std::uint32_t elementBytes; // +0x08
    std::uint32_t enabled; // +0x0C
    std::byte pad10[0x04];
    OpaqueCallbackRuntime callback14; // +0x14
    std::byte pad18[0x04];
    OpaqueCallbackRuntime callback1C; // +0x1C
  };
  static_assert(offsetof(LaneConfigOwnerRuntime, elementBytes) == 0x08, "LaneConfigOwnerRuntime::elementBytes offset must be 0x08");
  static_assert(offsetof(LaneConfigOwnerRuntime, enabled) == 0x0C, "LaneConfigOwnerRuntime::enabled offset must be 0x0C");
  static_assert(offsetof(LaneConfigOwnerRuntime, callback14) == 0x14, "LaneConfigOwnerRuntime::callback14 offset must be 0x14");
  static_assert(offsetof(LaneConfigOwnerRuntime, callback1C) == 0x1C, "LaneConfigOwnerRuntime::callback1C offset must be 0x1C");

  struct TentCallbackProfileOwnerRuntime
  {
    std::byte pad00[0x08];
    std::uint32_t elementBytes; // +0x08
    std::byte pad0C[0x3C];
    OpaqueCallbackRuntime callback48; // +0x48
    OpaqueCallbackRuntime callback4C; // +0x4C
    OpaqueCallbackRuntime destroy50; // +0x50
    OpaqueCallbackRuntime callback54; // +0x54
    OpaqueCallbackRuntime callback58; // +0x58
    std::byte pad5C_5F[0x04];
    std::uint8_t enabled60; // +0x60
  };
  static_assert(
    offsetof(TentCallbackProfileOwnerRuntime, callback48) == 0x48,
    "TentCallbackProfileOwnerRuntime::callback48 offset must be 0x48"
  );
  static_assert(
    offsetof(TentCallbackProfileOwnerRuntime, enabled60) == 0x60,
    "TentCallbackProfileOwnerRuntime::enabled60 offset must be 0x60"
  );

  struct SpanAtOffset4Runtime
  {
    std::byte pad00[0x04];
    std::uint8_t* begin; // +0x04
    std::uint8_t* end; // +0x08
  };
  static_assert(offsetof(SpanAtOffset4Runtime, begin) == 0x04, "SpanAtOffset4Runtime::begin offset must be 0x04");
  static_assert(offsetof(SpanAtOffset4Runtime, end) == 0x08, "SpanAtOffset4Runtime::end offset must be 0x08");

  struct SpanAtOffset0Runtime
  {
    std::uint8_t* begin; // +0x00
    std::uint8_t* end; // +0x04
  };
  static_assert(offsetof(SpanAtOffset0Runtime, begin) == 0x00, "SpanAtOffset0Runtime::begin offset must be 0x00");
  static_assert(offsetof(SpanAtOffset0Runtime, end) == 0x04, "SpanAtOffset0Runtime::end offset must be 0x04");

  struct ReleaseVTableRuntime
  {
    int (__thiscall* release)(void* self, int lane);
  };

  struct ReleaseTargetRuntime
  {
    ReleaseVTableRuntime* vtable;
  };

  struct OptionalReleaseOwnerRuntime
  {
    std::byte pad00[0x0C];
    ReleaseTargetRuntime* target; // +0x0C
  };
  static_assert(
    offsetof(OptionalReleaseOwnerRuntime, target) == 0x0C,
    "OptionalReleaseOwnerRuntime::target offset must be 0x0C"
  );

  struct FirstDwordLaneRuntime
  {
    std::uint32_t lane0;
  };

  [[nodiscard]] char* OptionalThisPlusOffset(char* const self, const std::size_t offset) noexcept
  {
    if (self == nullptr) {
      return nullptr;
    }
    return self + offset;
  }

  void InitializeLaneConfigWithCallbacks(
    LaneConfigOwnerRuntime* const owner,
    const std::uint32_t elementBytes,
    const OpaqueCallbackRuntime callback1C,
    const OpaqueCallbackRuntime callback14
  ) noexcept
  {
    owner->elementBytes = elementBytes;
    owner->enabled = 1u;
    owner->callback1C = callback1C;
    owner->callback14 = callback14;
  }

  void InitializeTentCallbackProfile(
    TentCallbackProfileOwnerRuntime* const owner,
    const OpaqueCallbackRuntime callback48,
    const OpaqueCallbackRuntime callback54,
    const OpaqueCallbackRuntime callback4C,
    const OpaqueCallbackRuntime callback58,
    const OpaqueCallbackRuntime destroy50
  ) noexcept
  {
    owner->enabled60 = 1u;
    owner->elementBytes = 4u;
    owner->callback48 = callback48;
    owner->callback54 = callback54;
    owner->callback4C = callback4C;
    owner->callback58 = callback58;
    owner->destroy50 = destroy50;
  }

  [[nodiscard]] int CountSpanElementsWithStride(
    const std::uint8_t* const begin,
    const std::uint8_t* const end,
    const std::int32_t stride
  ) noexcept
  {
    if (stride == 0) {
      return 0;
    }
    const std::ptrdiff_t byteDelta = end - begin;
    return static_cast<int>(byteDelta / stride);
  }
}

/**
 * Address: 0x006F82D0 (FUN_006F82D0)
 *
 * What it does:
 * Sets one lane element-size field at `+0x08` to 12 bytes.
 */
[[maybe_unused]] void SetLaneElementSize12RuntimeA(LaneConfigOwnerRuntime* const owner) noexcept
{
  owner->elementBytes = 12u;
}

/**
 * Address: 0x00701720 (FUN_00701720)
 *
 * What it does:
 * Initializes one lane config profile with 16-byte elements and two callback
 * slots.
 */
[[maybe_unused]] void InitializeLaneConfig16RuntimeA(
  LaneConfigOwnerRuntime* const owner,
  const OpaqueCallbackRuntime callback1C,
  const OpaqueCallbackRuntime callback14
) noexcept
{
  InitializeLaneConfigWithCallbacks(owner, 16u, callback1C, callback14);
}

/**
 * Address: 0x007017D0 (FUN_007017D0)
 *
 * What it does:
 * Returns `this + 0x64` when `this` is non-null.
 */
[[maybe_unused]] char* GetOptionalInlineLane100RuntimeA(char* const self) noexcept
{
  return OptionalThisPlusOffset(self, 100u);
}

/**
 * Address: 0x007017E0 (FUN_007017E0)
 *
 * What it does:
 * Returns element count from one span lane `(end - begin) / 40`, returning 0
 * when the begin lane is null.
 */
[[maybe_unused]] int CountSpanElementsStride40Runtime(const SpanAtOffset4Runtime* const span) noexcept
{
  if (span->begin == nullptr) {
    return 0;
  }
  return CountSpanElementsWithStride(span->begin, span->end, 40);
}

/**
 * Address: 0x007359F0 (FUN_007359F0)
 *
 * What it does:
 * Returns `this + 0x08`.
 */
[[maybe_unused]] char* GetInlineLane08RuntimeA(char* const self) noexcept
{
  return self + 8;
}

/**
 * Address: 0x00735AD0 (FUN_00735AD0)
 *
 * What it does:
 * Returns `this + 0x08`.
 */
[[maybe_unused]] char* GetInlineLane08RuntimeB(char* const self) noexcept
{
  return self + 8;
}

/**
 * Address: 0x0074CBF0 (FUN_0074CBF0)
 *
 * What it does:
 * Initializes one lane config profile with 16-byte elements and two callback
 * slots.
 */
[[maybe_unused]] void InitializeLaneConfig16RuntimeB(
  LaneConfigOwnerRuntime* const owner,
  const OpaqueCallbackRuntime callback1C,
  const OpaqueCallbackRuntime callback14
) noexcept
{
  InitializeLaneConfigWithCallbacks(owner, 16u, callback1C, callback14);
}

/**
 * Address: 0x0074CCA0 (FUN_0074CCA0)
 *
 * What it does:
 * Returns `this + 0x64` when `this` is non-null.
 */
[[maybe_unused]] char* GetOptionalInlineLane100RuntimeB(char* const self) noexcept
{
  return OptionalThisPlusOffset(self, 100u);
}

/**
 * Address: 0x0074CCB0 (FUN_0074CCB0)
 *
 * What it does:
 * Returns element count from one span lane `(end - begin) / 4`, returning 0
 * when the begin lane is null.
 */
[[maybe_unused]] int CountSpanElementsStride4RuntimeA(const SpanAtOffset4Runtime* const span) noexcept
{
  if (span->begin == nullptr) {
    return 0;
  }
  return CountSpanElementsWithStride(span->begin, span->end, 4);
}

/**
 * Address: 0x0074CDA0 (FUN_0074CDA0)
 *
 * What it does:
 * Initializes one lane config profile with 12-byte elements and two callback
 * slots.
 */
[[maybe_unused]] void InitializeLaneConfig12Runtime(
  LaneConfigOwnerRuntime* const owner,
  const OpaqueCallbackRuntime callback1C,
  const OpaqueCallbackRuntime callback14
) noexcept
{
  InitializeLaneConfigWithCallbacks(owner, 12u, callback1C, callback14);
}

/**
 * Address: 0x0074FEE0 (FUN_0074FEE0)
 *
 * What it does:
 * Initializes one tent callback profile (enabled flag, element size, and five
 * callback lanes including destroy slot).
 */
[[maybe_unused]] void InitializeTentCallbackProfileRuntimeA(
  TentCallbackProfileOwnerRuntime* const owner,
  const OpaqueCallbackRuntime callback48,
  const OpaqueCallbackRuntime callback54,
  const OpaqueCallbackRuntime callback4C,
  const OpaqueCallbackRuntime callback58,
  const OpaqueCallbackRuntime destroy50
) noexcept
{
  InitializeTentCallbackProfile(owner, callback48, callback54, callback4C, callback58, destroy50);
}

/**
 * Address: 0x00750090 (FUN_00750090)
 *
 * What it does:
 * Returns `this + 0x64` when `this` is non-null.
 */
[[maybe_unused]] char* GetOptionalInlineLane100RuntimeC(char* const self) noexcept
{
  return OptionalThisPlusOffset(self, 100u);
}

/**
 * Address: 0x007500A0 (FUN_007500A0)
 *
 * What it does:
 * Returns `this + 0x64` when `this` is non-null.
 */
[[maybe_unused]] char* GetOptionalInlineLane100RuntimeD(char* const self) noexcept
{
  return OptionalThisPlusOffset(self, 100u);
}

/**
 * Address: 0x007500B0 (FUN_007500B0)
 *
 * What it does:
 * Returns whether the first dword lane is nonzero.
 */
[[maybe_unused]] BOOL IsFirstDwordNonZeroRuntimeA(const FirstDwordLaneRuntime* const lane) noexcept
{
  return (lane->lane0 != 0u) ? TRUE : FALSE;
}

/**
 * Address: 0x007502F0 (FUN_007502F0)
 *
 * What it does:
 * Initializes one tent callback profile (enabled flag, element size, and five
 * callback lanes including destroy slot).
 */
[[maybe_unused]] void InitializeTentCallbackProfileRuntimeB(
  TentCallbackProfileOwnerRuntime* const owner,
  const OpaqueCallbackRuntime callback48,
  const OpaqueCallbackRuntime callback54,
  const OpaqueCallbackRuntime callback4C,
  const OpaqueCallbackRuntime callback58,
  const OpaqueCallbackRuntime destroy50
) noexcept
{
  InitializeTentCallbackProfile(owner, callback48, callback54, callback4C, callback58, destroy50);
}

/**
 * Address: 0x007504A0 (FUN_007504A0)
 *
 * What it does:
 * Returns `this + 0x64` when `this` is non-null.
 */
[[maybe_unused]] char* GetOptionalInlineLane100RuntimeE(char* const self) noexcept
{
  return OptionalThisPlusOffset(self, 100u);
}

/**
 * Address: 0x007504B0 (FUN_007504B0)
 *
 * What it does:
 * Returns `this + 0x64` when `this` is non-null.
 */
[[maybe_unused]] char* GetOptionalInlineLane100RuntimeF(char* const self) noexcept
{
  return OptionalThisPlusOffset(self, 100u);
}

/**
 * Address: 0x007504C0 (FUN_007504C0)
 *
 * What it does:
 * Returns whether the first dword lane is nonzero.
 */
[[maybe_unused]] BOOL IsFirstDwordNonZeroRuntimeB(const FirstDwordLaneRuntime* const lane) noexcept
{
  return (lane->lane0 != 0u) ? TRUE : FALSE;
}

/**
 * Address: 0x00755FC0 (FUN_00755FC0)
 *
 * What it does:
 * Calls one optional owned-object release slot with lane argument `1`.
 */
[[maybe_unused]] int ReleaseOptionalOwnedObjectRuntime(OptionalReleaseOwnerRuntime* const owner)
{
  if (owner->target == nullptr || owner->target->vtable == nullptr || owner->target->vtable->release == nullptr) {
    return 0;
  }
  return owner->target->vtable->release(owner->target, 1);
}

/**
 * Address: 0x00761A70 (FUN_00761A70)
 *
 * What it does:
 * Initializes one lane config profile with 16-byte elements and two callback
 * slots.
 */
[[maybe_unused]] void InitializeLaneConfig16RuntimeC(
  LaneConfigOwnerRuntime* const owner,
  const OpaqueCallbackRuntime callback1C,
  const OpaqueCallbackRuntime callback14
) noexcept
{
  InitializeLaneConfigWithCallbacks(owner, 16u, callback1C, callback14);
}

/**
 * Address: 0x00761B20 (FUN_00761B20)
 *
 * What it does:
 * Returns `this + 0x64` when `this` is non-null.
 */
[[maybe_unused]] char* GetOptionalInlineLane100RuntimeG(char* const self) noexcept
{
  return OptionalThisPlusOffset(self, 100u);
}

/**
 * Address: 0x00761B30 (FUN_00761B30)
 *
 * What it does:
 * Returns element count from one span lane `(end - begin) / 28`.
 */
[[maybe_unused]] int CountSpanElementsStride28Runtime(const SpanAtOffset0Runtime* const span) noexcept
{
  return CountSpanElementsWithStride(span->begin, span->end, 28);
}

/**
 * Address: 0x00763480 (FUN_00763480)
 *
 * What it does:
 * Initializes one lane config profile with 16-byte elements and two callback
 * slots.
 */
[[maybe_unused]] void InitializeLaneConfig16RuntimeD(
  LaneConfigOwnerRuntime* const owner,
  const OpaqueCallbackRuntime callback1C,
  const OpaqueCallbackRuntime callback14
) noexcept
{
  InitializeLaneConfigWithCallbacks(owner, 16u, callback1C, callback14);
}

/**
 * Address: 0x00763530 (FUN_00763530)
 *
 * What it does:
 * Returns `this + 0x64` when `this` is non-null.
 */
[[maybe_unused]] char* GetOptionalInlineLane100RuntimeH(char* const self) noexcept
{
  return OptionalThisPlusOffset(self, 100u);
}

/**
 * Address: 0x00763540 (FUN_00763540)
 *
 * What it does:
 * Returns element count from one span lane `(end - begin) / 4`, returning 0
 * when the begin lane is null.
 */
[[maybe_unused]] int CountSpanElementsStride4RuntimeB(const SpanAtOffset4Runtime* const span) noexcept
{
  if (span->begin == nullptr) {
    return 0;
  }
  return CountSpanElementsWithStride(span->begin, span->end, 4);
}

/**
 * Address: 0x00763660 (FUN_00763660)
 *
 * What it does:
 * Initializes one lane config profile with 8-byte elements and two callback
 * slots.
 */
[[maybe_unused]] void InitializeLaneConfig8Runtime(
  LaneConfigOwnerRuntime* const owner,
  const OpaqueCallbackRuntime callback1C,
  const OpaqueCallbackRuntime callback14
) noexcept
{
  InitializeLaneConfigWithCallbacks(owner, 8u, callback1C, callback14);
}

/**
 * Address: 0x00763720 (FUN_00763720)
 *
 * What it does:
 * Sets one lane element-size field at `+0x08` to 12 bytes.
 */
[[maybe_unused]] void SetLaneElementSize12RuntimeB(LaneConfigOwnerRuntime* const owner) noexcept
{
  owner->elementBytes = 12u;
}

/**
 * Address: 0x0077EC10 (FUN_0077EC10)
 *
 * What it does:
 * Initializes one tent callback profile (enabled flag, element size, and five
 * callback lanes including destroy slot).
 */
[[maybe_unused]] void InitializeTentCallbackProfileRuntimeC(
  TentCallbackProfileOwnerRuntime* const owner,
  const OpaqueCallbackRuntime callback48,
  const OpaqueCallbackRuntime callback54,
  const OpaqueCallbackRuntime callback4C,
  const OpaqueCallbackRuntime callback58,
  const OpaqueCallbackRuntime destroy50
) noexcept
{
  InitializeTentCallbackProfile(owner, callback48, callback54, callback4C, callback58, destroy50);
}

/**
 * Address: 0x0077EDC0 (FUN_0077EDC0)
 *
 * What it does:
 * Returns `this + 0x64` when `this` is non-null.
 */
[[maybe_unused]] char* GetOptionalInlineLane100RuntimeI(char* const self) noexcept
{
  return OptionalThisPlusOffset(self, 100u);
}

/**
 * Address: 0x0077EDD0 (FUN_0077EDD0)
 *
 * What it does:
 * Returns `this + 0x64` when `this` is non-null.
 */
[[maybe_unused]] char* GetOptionalInlineLane100RuntimeJ(char* const self) noexcept
{
  return OptionalThisPlusOffset(self, 100u);
}

namespace
{
  struct StringPayloadArrayOwnerRuntime
  {
    std::byte pad00[0x10];
    std::uint32_t count; // +0x10
    const char** payloadPointers; // +0x14
  };
  static_assert(offsetof(StringPayloadArrayOwnerRuntime, count) == 0x10, "StringPayloadArrayOwnerRuntime::count offset must be 0x10");
  static_assert(
    offsetof(StringPayloadArrayOwnerRuntime, payloadPointers) == 0x14,
    "StringPayloadArrayOwnerRuntime::payloadPointers offset must be 0x14"
  );

  struct TripleDoubleLaneRuntime
  {
    double lane0;
    double lane1;
    double lane2;
  };
  static_assert(sizeof(TripleDoubleLaneRuntime) == 0x18, "TripleDoubleLaneRuntime size must be 0x18");

  struct DoublePairLaneRuntime
  {
    double lane0;
    double lane1;
  };
  static_assert(sizeof(DoublePairLaneRuntime) == 0x10, "DoublePairLaneRuntime size must be 0x10");

  struct ByteAtOffset8Runtime
  {
    std::byte pad00[0x08];
    std::uint8_t lane08;
  };
  static_assert(offsetof(ByteAtOffset8Runtime, lane08) == 0x08, "ByteAtOffset8Runtime::lane08 offset must be 0x08");

  struct TailByteBufferOwnerRuntime
  {
    std::byte pad00[0x08];
    const std::uint8_t* bytes; // +0x08
    std::uint32_t size; // +0x0C
  };
  static_assert(offsetof(TailByteBufferOwnerRuntime, bytes) == 0x08, "TailByteBufferOwnerRuntime::bytes offset must be 0x08");
  static_assert(offsetof(TailByteBufferOwnerRuntime, size) == 0x0C, "TailByteBufferOwnerRuntime::size offset must be 0x0C");

  struct InlineOffsetVectorRuntime
  {
    std::byte* begin; // +0x00
    std::byte* end; // +0x04
    std::byte* capacity; // +0x08
    std::byte* inlineStorage; // +0x0C
    std::byte inlineBytes[0x98]; // +0x10
  };
  static_assert(offsetof(InlineOffsetVectorRuntime, inlineStorage) == 0x0C, "InlineOffsetVectorRuntime::inlineStorage offset must be 0x0C");
  static_assert(offsetof(InlineOffsetVectorRuntime, inlineBytes) == 0x10, "InlineOffsetVectorRuntime::inlineBytes offset must be 0x10");

  using DestinationWriterRuntime = int (__thiscall*)(std::uintptr_t destination, const void* payload);
  using UnaryPayloadCallbackRuntime = int (__cdecl*)(const void* payload);
  using BinaryPayloadCallbackRuntime = void (__cdecl*)(const void* payload, void* callbackState);

  struct SsoPayloadDispatchRuntime
  {
    DestinationWriterRuntime writeFn; // +0x00
    std::uint32_t lane04;
    std::uint32_t lane08;
    std::uint32_t lane0C;
    union
    {
      const void* heapPayload;
      std::byte inlinePayload[0x10];
    } storage; // +0x10
    std::byte pad20_23[0x04];
    std::uint32_t payloadLength; // +0x24
  };
  static_assert(offsetof(SsoPayloadDispatchRuntime, storage) == 0x10, "SsoPayloadDispatchRuntime::storage offset must be 0x10");
  static_assert(
    offsetof(SsoPayloadDispatchRuntime, payloadLength) == 0x24,
    "SsoPayloadDispatchRuntime::payloadLength offset must be 0x24"
  );

  struct SsoPayloadDispatchHandleRuntime
  {
    SsoPayloadDispatchRuntime* object;
  };

  struct SsoUnaryCallbackRuntime
  {
    UnaryPayloadCallbackRuntime callback; // +0x00
    std::uint32_t lane04;
    union
    {
      const void* heapPayload;
      std::byte inlinePayload[0x14];
    } storage; // +0x08
    std::uint32_t payloadLength; // +0x1C
  };
  static_assert(offsetof(SsoUnaryCallbackRuntime, storage) == 0x08, "SsoUnaryCallbackRuntime::storage offset must be 0x08");
  static_assert(
    offsetof(SsoUnaryCallbackRuntime, payloadLength) == 0x1C,
    "SsoUnaryCallbackRuntime::payloadLength offset must be 0x1C"
  );

  struct SsoUnaryCallbackHandleRuntime
  {
    SsoUnaryCallbackRuntime* object;
  };

  struct SsoBinaryCallbackRuntime
  {
    BinaryPayloadCallbackRuntime callback; // +0x00
    std::uint32_t lane04;
    union
    {
      const void* heapPayload;
      std::byte inlinePayload[0x14];
    } storage; // +0x08
    std::uint32_t payloadLength; // +0x1C
    void* callbackState; // +0x20
  };
  static_assert(
    offsetof(SsoBinaryCallbackRuntime, callbackState) == 0x20,
    "SsoBinaryCallbackRuntime::callbackState offset must be 0x20"
  );

  struct SsoBinaryCallbackHandleRuntime
  {
    SsoBinaryCallbackRuntime* object;
  };

  struct SlotD8VTableRuntime
  {
    std::byte pad00[0xD8];
    int (__thiscall* invokeSlotD8)(void* self);
  };
  static_assert(offsetof(SlotD8VTableRuntime, invokeSlotD8) == 0xD8, "SlotD8VTableRuntime::invokeSlotD8 offset must be 0xD8");

  struct SlotD8OwnerRuntime
  {
    SlotD8VTableRuntime* vtable;
  };

  struct Slot198VTableRuntime
  {
    std::byte pad00[0x198];
    int (__thiscall* invokeSlot198)(void* self, int arg0, int arg1);
  };
  static_assert(
    offsetof(Slot198VTableRuntime, invokeSlot198) == 0x198,
    "Slot198VTableRuntime::invokeSlot198 offset must be 0x198"
  );

  struct Slot198TargetRuntime
  {
    Slot198VTableRuntime* vtable;
  };

  struct Slot198ForwardOwnerRuntime
  {
    std::byte pad00[0xE8];
    Slot198TargetRuntime* target; // +0xE8
  };
  static_assert(
    offsetof(Slot198ForwardOwnerRuntime, target) == 0xE8,
    "Slot198ForwardOwnerRuntime::target offset must be 0xE8"
  );

  struct LookupNodeReleaseVTableRuntime
  {
    std::uint32_t lane00;
    void (__thiscall* release)(void* self, int lane);
  };

  struct LookupNodeReleaseRuntime
  {
    LookupNodeReleaseVTableRuntime* vtable;
    std::byte pad04[0x0C];
    std::uint32_t lane10;
  };
  static_assert(offsetof(LookupNodeReleaseRuntime, lane10) == 0x10, "LookupNodeReleaseRuntime::lane10 offset must be 0x10");

  struct LookupOwnerVTableRuntime
  {
    std::byte pad00[0x50];
    LookupNodeReleaseRuntime* (__thiscall* lookupNode)(void* self, int key);
  };
  static_assert(offsetof(LookupOwnerVTableRuntime, lookupNode) == 0x50, "LookupOwnerVTableRuntime::lookupNode offset must be 0x50");

  struct LookupOwnerRuntime
  {
    LookupOwnerVTableRuntime* vtable;
  };

  struct PairLaneRuntime
  {
    std::uint32_t lane0;
    std::uint32_t lane1;
  };

  struct PairSourceOwnerRuntime
  {
    std::byte pad00[0x14C];
    PairLaneRuntime primaryPair; // +0x14C
    std::byte pad154[0x08];
    std::uint32_t lane15C; // +0x15C
    std::uint32_t lane160; // +0x160
    PairLaneRuntime secondaryPair; // +0x164
  };
  static_assert(offsetof(PairSourceOwnerRuntime, primaryPair) == 0x14C, "PairSourceOwnerRuntime::primaryPair offset must be 0x14C");
  static_assert(
    offsetof(PairSourceOwnerRuntime, secondaryPair) == 0x164,
    "PairSourceOwnerRuntime::secondaryPair offset must be 0x164"
  );

  struct DwordAt2CWriterRuntime
  {
    std::byte pad00[0x2C];
    std::uint32_t lane2C;
  };
  static_assert(offsetof(DwordAt2CWriterRuntime, lane2C) == 0x2C, "DwordAt2CWriterRuntime::lane2C offset must be 0x2C");

  struct DwordAtOffset8Runtime
  {
    std::byte pad00[0x08];
    std::uint32_t lane08;
  };
  static_assert(offsetof(DwordAtOffset8Runtime, lane08) == 0x08, "DwordAtOffset8Runtime::lane08 offset must be 0x08");

  struct StreamLikeVTableRuntime
  {
    std::byte pad00[0x14];
    void (__thiscall* readSlot)(void* self, void* outBuffer, int byteCount);
    std::byte pad18[0x0C];
    void (__thiscall* seekSlot)(void* self, int position, int mode);
    int (__thiscall* tellSlot)(void* self);
  };
  static_assert(offsetof(StreamLikeVTableRuntime, readSlot) == 0x14, "StreamLikeVTableRuntime::readSlot offset must be 0x14");
  static_assert(offsetof(StreamLikeVTableRuntime, seekSlot) == 0x24, "StreamLikeVTableRuntime::seekSlot offset must be 0x24");
  static_assert(offsetof(StreamLikeVTableRuntime, tellSlot) == 0x28, "StreamLikeVTableRuntime::tellSlot offset must be 0x28");

  struct StreamLikeRuntime
  {
    StreamLikeVTableRuntime* vtable;
  };

  struct ForwardDispatchVTableRuntime
  {
    std::byte pad00[0x20];
    int (__thiscall* dispatchSlot)(void* self, int arg0, StreamLikeRuntime* stream, int arg2, int arg3);
  };
  static_assert(
    offsetof(ForwardDispatchVTableRuntime, dispatchSlot) == 0x20,
    "ForwardDispatchVTableRuntime::dispatchSlot offset must be 0x20"
  );

  struct ForwardDispatchOwnerRuntime
  {
    ForwardDispatchVTableRuntime* vtable;
  };

  struct OwnerVTable21CRuntime
  {
    std::byte pad00[0x21C];
    int (__thiscall* invokeSlot21C)(void* self, int arg0, int arg1);
  };
  static_assert(
    offsetof(OwnerVTable21CRuntime, invokeSlot21C) == 0x21C,
    "OwnerVTable21CRuntime::invokeSlot21C offset must be 0x21C"
  );

  struct OwnerHeadRuntime
  {
    OwnerVTable21CRuntime* vtable;
  };

  struct CachedDispatchVTableRuntime
  {
    std::byte pad00[0x218];
    int (__thiscall* invokeSlot218)(void* self, std::uint32_t cached, int a2, int a3, int a4, int a5, int a6, int a7, int a8, int a9);
    std::byte pad21C_21F[0x04];
    int (__thiscall* invokeSlot220)(void* self, std::uint32_t cached, int value);
  };
  static_assert(
    offsetof(CachedDispatchVTableRuntime, invokeSlot218) == 0x218,
    "CachedDispatchVTableRuntime::invokeSlot218 offset must be 0x218"
  );
  static_assert(
    offsetof(CachedDispatchVTableRuntime, invokeSlot220) == 0x220,
    "CachedDispatchVTableRuntime::invokeSlot220 offset must be 0x220"
  );

  struct CachedDispatchOwnerRuntime
  {
    CachedDispatchVTableRuntime* vtable;
    std::byte pad04[0x134];
    std::uint32_t cachedLane138; // +0x138
  };
  static_assert(
    offsetof(CachedDispatchOwnerRuntime, cachedLane138) == 0x138,
    "CachedDispatchOwnerRuntime::cachedLane138 offset must be 0x138"
  );

  struct FpuStatusLaneRuntime
  {
    std::uint8_t flags;
    std::uint8_t statusCode;
  };

  [[nodiscard]] std::uint32_t LoadPrefixedStringPayloadLength(const char* const payload) noexcept
  {
    return *reinterpret_cast<const std::uint32_t*>(reinterpret_cast<const std::byte*>(payload) - 8u);
  }

  [[nodiscard]] const void* ResolveSsoPayloadPointer(
    const void* const heapPayload,
    const std::byte* const inlinePayload,
    const std::uint32_t payloadLength
  ) noexcept
  {
    if (payloadLength < 16u) {
      return inlinePayload;
    }
    return heapPayload;
  }
}

/**
 * Address: 0x00A2D0F0 (FUN_00A2D0F0)
 *
 * What it does:
 * Computes one packed payload byte estimate from a counted array of
 * string-payload pointers (`len prefix at -8`), with base cost `0x15`.
 */
[[maybe_unused]] int ComputePrefixedStringPayloadBudgetRuntime(
  const StringPayloadArrayOwnerRuntime* const owner
) noexcept
{
  if (owner == nullptr || owner->count == 0u) {
    return 0;
  }

  int budget = 0x15;
  for (std::uint32_t index = 0; index < owner->count; ++index) {
    budget += static_cast<int>(LoadPrefixedStringPayloadLength(owner->payloadPointers[index]) + 1u);
  }
  return budget;
}

/**
 * Address: 0x00A2D7B0 (FUN_00A2D7B0)
 *
 * What it does:
 * Writes `strlen(input)` into the output dword lane and returns the input
 * pointer.
 */
[[maybe_unused]] const char* CaptureCStringLengthRuntime(
  const char* const input,
  std::uint32_t* const outLength,
  const int /*unused*/
) noexcept
{
  *outLength = static_cast<std::uint32_t>(std::strlen(input));
  return input;
}

/**
 * Address: 0x00A2D7E0 (FUN_00A2D7E0)
 *
 * What it does:
 * Returns the first argument unchanged.
 */
[[maybe_unused]] int ReturnFirstStdcallArgumentRuntime(
  const int arg0,
  const int /*arg1*/,
  const int /*arg2*/
) noexcept
{
  return arg0;
}

/**
 * Address: 0x00A30EE0 (FUN_00A30EE0)
 *
 * What it does:
 * Calls the optional release slot (`+0x04`) with lane `1` and reports success.
 */
[[maybe_unused]] char ReleaseOptionalObjectAndReturnTrueRuntime(
  void* const object
)
{
  if (object != nullptr) {
    auto* const vtable = *reinterpret_cast<void***>(object);
    auto* const release = reinterpret_cast<void(__thiscall*)(void*, int)>(vtable[1]);
    release(object, 1);
  }
  return 1;
}

/**
 * Address: 0x00A3A290 (FUN_00A3A290)
 *
 * What it does:
 * Copies one 3-double lane into destination and returns destination.
 */
[[maybe_unused]] TripleDoubleLaneRuntime* CopyTripleDoubleLaneRuntime(
  TripleDoubleLaneRuntime* const destination,
  const TripleDoubleLaneRuntime* const source
) noexcept
{
  *destination = *source;
  return destination;
}

/**
 * Address: 0x00A67FF0 (FUN_00A67FF0)
 *
 * What it does:
 * Copies one 2-double lane into destination and returns destination.
 */
[[maybe_unused]] DoublePairLaneRuntime* CopyDoublePairLaneRuntime(
  DoublePairLaneRuntime* const destination,
  const DoublePairLaneRuntime* const source
) noexcept
{
  *destination = *source;
  return destination;
}

/**
 * Address: 0x00AA1C81 (FUN_00AA1C81)
 *
 * What it does:
 * Returns true when the referenced double lane is non-negative.
 */
[[maybe_unused]] BOOL IsDoubleLaneNonNegativeRuntime(const double* const value) noexcept
{
  return (*value >= 0.0) ? TRUE : FALSE;
}

/**
 * Address: 0x00AA7AF7 (FUN_00AA7AF7)
 *
 * What it does:
 * Updates one FPU status lane from flag bit `0x40` and returns the sum of two
 * source lanes.
 */
[[maybe_unused]] double AddDoublePairAndUpdateFpuStatusRuntime(
  FpuStatusLaneRuntime* const state,
  const double first,
  const double second
) noexcept
{
  state->statusCode = ((state->flags & 0x40u) != 0u) ? 7u : 1u;
  return first + second;
}

/**
 * Address: 0x00AB12B4 (FUN_00AB12B4)
 *
 * What it does:
 * Returns one byte lane stored at offset `+0x08`.
 */
[[maybe_unused]] char ReadByteLane08Runtime(const ByteAtOffset8Runtime* const owner) noexcept
{
  return static_cast<char>(owner->lane08);
}

/**
 * Address: 0x00AB12B8 (FUN_00AB12B8)
 *
 * What it does:
 * Writes the stored byte lane (`+0x08`) to output when output pointer and
 * length are both nonzero.
 */
[[maybe_unused]] std::uint8_t* WriteByteLane08ToBufferRuntime(
  const ByteAtOffset8Runtime* const owner,
  std::uint8_t* const output,
  const int outputSize
) noexcept
{
  if (output == nullptr || outputSize == 0) {
    return nullptr;
  }

  *output = owner->lane08;
  return output;
}

/**
 * Address: 0x00AB17D7 (FUN_00AB17D7)
 *
 * What it does:
 * Returns the tail byte of one byte-buffer lane, or zero when empty.
 */
[[maybe_unused]] char ReadTailByteOrZeroRuntime(const TailByteBufferOwnerRuntime* const owner) noexcept
{
  if (owner->size == 0u) {
    return 0;
  }
  return static_cast<char>(owner->bytes[owner->size - 1u]);
}

/**
 * Address: 0x0056B4B0 (FUN_0056B4B0)
 *
 * What it does:
 * Resets one inline offset-vector lane to empty, pointing begin/end/original
 * to embedded storage and capacity to storage+0x98.
 */
[[maybe_unused]] InlineOffsetVectorRuntime* ResetInlineOffsetVectorStorageRuntime(
  InlineOffsetVectorRuntime* const owner
) noexcept
{
  owner->begin = owner->inlineBytes;
  owner->end = owner->inlineBytes;
  owner->capacity = owner->inlineBytes + 0x98;
  owner->inlineStorage = owner->inlineBytes;
  return owner;
}

/**
 * Address: 0x007BEEB0 (FUN_007BEEB0)
 *
 * What it does:
 * Dispatches one payload pointer to the destination writer, selecting inline
 * or heap storage based on payload length `< 16`.
 */
[[maybe_unused]] int DispatchSsoPayloadToDestinationRuntime(
  const SsoPayloadDispatchHandleRuntime* const handle
)
{
  const SsoPayloadDispatchRuntime* const object = handle->object;
  const void* const payload = ResolveSsoPayloadPointer(object->storage.heapPayload, object->storage.inlinePayload, object->payloadLength);
  const std::uintptr_t destination = static_cast<std::uintptr_t>(object->lane04 + object->lane08);
  return object->writeFn(destination, payload);
}

/**
 * Address: 0x0088FBA0 (FUN_0088FBA0)
 *
 * What it does:
 * Invokes one unary callback with SSO payload selection (`inline` for len<16,
 * heap pointer otherwise).
 */
[[maybe_unused]] int InvokeUnarySsoPayloadCallbackRuntime(
  const SsoUnaryCallbackHandleRuntime* const handle
)
{
  const SsoUnaryCallbackRuntime* const object = handle->object;
  const void* const payload = ResolveSsoPayloadPointer(object->storage.heapPayload, object->storage.inlinePayload, object->payloadLength);
  return object->callback(payload);
}

/**
 * Address: 0x0088FC40 (FUN_0088FC40)
 *
 * What it does:
 * Invokes one binary callback with selected SSO payload and callback-state lane
 * at offset `+0x20`.
 */
[[maybe_unused]] void InvokeBinarySsoPayloadCallbackRuntime(
  const SsoBinaryCallbackHandleRuntime* const handle
) noexcept
{
  const SsoBinaryCallbackRuntime* const object = handle->object;
  const void* const payload = ResolveSsoPayloadPointer(object->storage.heapPayload, object->storage.inlinePayload, object->payloadLength);
  object->callback(payload, object->callbackState);
}

/**
 * Address: 0x00964A10 (FUN_00964A10)
 *
 * What it does:
 * Forwards to virtual slot `+0xD8`, ignoring the forwarded stack argument.
 */
[[maybe_unused]] int InvokeSlotD8IgnoringArgumentRuntime(
  SlotD8OwnerRuntime* const owner,
  const int /*unused*/
)
{
  return owner->vtable->invokeSlotD8(owner);
}

/**
 * Address: 0x0097DD60 (FUN_0097DD60)
 *
 * What it does:
 * Forwards to child virtual slot `+0x198` when child target at `+0xE8` exists.
 */
[[maybe_unused]] int ForwardToChildSlot198Runtime(
  Slot198ForwardOwnerRuntime* const owner,
  const int arg0,
  const int arg1
)
{
  if (owner->target == nullptr) {
    return 0;
  }
  return owner->target->vtable->invokeSlot198(owner->target, arg0, arg1);
}

/**
 * Address: 0x009A0630 (FUN_009A0630)
 *
 * What it does:
 * Looks up one node by key via slot `+0x50`, clears node lane `+0x10`, then
 * releases it with lane `1`.
 */
[[maybe_unused]] char LookupClearLane10AndReleaseRuntime(
  LookupOwnerRuntime* const owner,
  const int key
)
{
  LookupNodeReleaseRuntime* const node = owner->vtable->lookupNode(owner, key);
  if (node == nullptr) {
    return 0;
  }

  node->lane10 = 0u;
  node->vtable->release(node, 1);
  return 1;
}

/**
 * Address: 0x009A0680 (FUN_009A0680)
 *
 * What it does:
 * Looks up one node by key via slot `+0x50` and releases it with lane `1`.
 */
[[maybe_unused]] char LookupAndReleaseRuntime(
  LookupOwnerRuntime* const owner,
  const int key
)
{
  LookupNodeReleaseRuntime* const node = owner->vtable->lookupNode(owner, key);
  if (node == nullptr) {
    return 0;
  }

  node->vtable->release(node, 1);
  return 1;
}

/**
 * Address: 0x009A8E50 (FUN_009A8E50)
 *
 * What it does:
 * Writes one dword lane at offset `+0x15C`.
 */
[[maybe_unused]] int SetLane15CRuntime(PairSourceOwnerRuntime* const owner, const int value) noexcept
{
  owner->lane15C = static_cast<std::uint32_t>(value);
  return value;
}

/**
 * Address: 0x009A8E60 (FUN_009A8E60)
 *
 * What it does:
 * Writes one dword lane at offset `+0x160`.
 */
[[maybe_unused]] int SetLane160Runtime(PairSourceOwnerRuntime* const owner, const int value) noexcept
{
  owner->lane160 = static_cast<std::uint32_t>(value);
  return value;
}

/**
 * Address: 0x009A8E70 (FUN_009A8E70)
 *
 * What it does:
 * Copies owner pair lanes from offsets `+0x14C/+0x150` into output.
 */
[[maybe_unused]] PairLaneRuntime* CopyPrimaryPairLaneRuntime(
  const PairSourceOwnerRuntime* const owner,
  PairLaneRuntime* const outPair
) noexcept
{
  *outPair = owner->primaryPair;
  return outPair;
}

/**
 * Address: 0x009A8EB0 (FUN_009A8EB0)
 *
 * What it does:
 * Copies owner pair lanes from offsets `+0x164/+0x168` into output.
 */
[[maybe_unused]] PairLaneRuntime* CopySecondaryPairLaneRuntime(
  const PairSourceOwnerRuntime* const owner,
  PairLaneRuntime* const outPair
) noexcept
{
  *outPair = owner->secondaryPair;
  return outPair;
}

/**
 * Address: 0x009CE8B0 (FUN_009CE8B0)
 *
 * What it does:
 * Writes one dword lane at offset `+0x2C` and returns success.
 */
[[maybe_unused]] char WriteLane2CAndReturnTrueRuntime(
  DwordAt2CWriterRuntime* const owner,
  const int value
) noexcept
{
  owner->lane2C = static_cast<std::uint32_t>(value);
  return 1;
}

/**
 * Address: 0x009D9FB0 (FUN_009D9FB0)
 *
 * What it does:
 * Resets stream position/mode lanes to zero, then forwards to owner dispatch
 * slot `+0x20`.
 */
[[maybe_unused]] int ResetStreamAndForwardDispatchRuntime(
  ForwardDispatchOwnerRuntime* const owner,
  const int arg0,
  StreamLikeRuntime* const stream,
  const int arg2,
  const int arg3
)
{
  stream->vtable->seekSlot(stream, 0, 0);
  return owner->vtable->dispatchSlot(owner, arg0, stream, arg2, arg3);
}

/**
 * Address: 0x009DA250 (FUN_009DA250)
 *
 * What it does:
 * Saves current stream position, seeks to start, reads 6 bytes, returns the
 * trailing 16-bit lane, and restores previous stream position.
 */
[[maybe_unused]] int ReadTrailingWordFromStreamHeaderRuntime(StreamLikeRuntime* const stream)
{
  const int previousPosition = stream->vtable->tellSlot(stream);
  stream->vtable->seekSlot(stream, 0, 0);

  std::array<std::byte, 6> header{};
  stream->vtable->readSlot(stream, header.data(), static_cast<int>(header.size()));
  std::uint16_t trailingWord = 0u;
  std::memcpy(&trailingWord, header.data() + 4, sizeof(trailingWord));

  stream->vtable->seekSlot(stream, previousPosition, 0);
  return static_cast<int>(trailingWord);
}

/**
 * Address: 0x009EE690 (FUN_009EE690)
 *
 * What it does:
 * Forwards from a subobject lane at `+0x130` back to owner slot `+0x21C` with
 * fixed second argument `1`.
 */
[[maybe_unused]] int ForwardSubobjectToOwnerSlot21CRuntime(
  void* const subobjectAt130,
  const int arg0
)
{
  auto* const owner = reinterpret_cast<OwnerHeadRuntime*>(reinterpret_cast<std::byte*>(subobjectAt130) - 0x130);
  return owner->vtable->invokeSlot21C(owner, arg0, 1);
}

/**
 * Address: 0x00A06410 (FUN_00A06410)
 *
 * What it does:
 * Writes one dword lane at offset `+0x08`.
 */
[[maybe_unused]] int SetLane08AndReturnRuntime(
  DwordAtOffset8Runtime* const owner,
  const int value
) noexcept
{
  owner->lane08 = static_cast<std::uint32_t>(value);
  return value;
}

/**
 * Address: 0x00A06500 (FUN_00A06500)
 *
 * What it does:
 * Dispatches via slot `+0x218` using cached owner lane `+0x138` and the first
 * eight forwarded arguments.
 */
[[maybe_unused]] int DispatchWithCachedLane218Runtime(
  CachedDispatchOwnerRuntime* const owner,
  const int a2,
  const int a3,
  const int a4,
  const int a5,
  const int a6,
  const int a7,
  const int a8,
  const int a9,
  const int /*a10_unused*/,
  const int /*a11_unused*/
)
{
  return owner->vtable->invokeSlot218(owner, owner->cachedLane138, a2, a3, a4, a5, a6, a7, a8, a9);
}

/**
 * Address: 0x00A065D0 (FUN_00A065D0)
 *
 * What it does:
 * Dispatches via slot `+0x220` using cached owner lane `+0x138`.
 */
[[maybe_unused]] int DispatchWithCachedLane220Runtime(
  CachedDispatchOwnerRuntime* const owner,
  const int value
)
{
  return owner->vtable->invokeSlot220(owner, owner->cachedLane138, value);
}

namespace
{
  struct ThiscallContextUnaryThunkRuntime
  {
    int (__thiscall* invoke)(void* context, int arg0);
    void* context;
  };

  struct CdeclBinaryThunkRuntime
  {
    int (__cdecl* invoke)(void* arg0, void* arg1);
    void* arg0;
    void* arg1;
  };

  struct CdeclUnaryThunkRuntime
  {
    int (__cdecl* invoke)(int arg0);
  };

  struct IntrusiveLinkNodeRuntime
  {
    IntrusiveLinkNodeRuntime* next;
    IntrusiveLinkNodeRuntime* prev;
  };
  static_assert(sizeof(IntrusiveLinkNodeRuntime) == 0x08, "IntrusiveLinkNodeRuntime size must be 0x08");

  struct BoolLane18OwnerRuntime
  {
    std::byte pad00[0x18];
    std::uint32_t lane18;
  };
  static_assert(offsetof(BoolLane18OwnerRuntime, lane18) == 0x18, "BoolLane18OwnerRuntime::lane18 offset must be 0x18");

  struct Slot08VTableRuntime
  {
    std::byte pad00[0x08];
    int (__thiscall* slot08)(void* self);
  };
  static_assert(offsetof(Slot08VTableRuntime, slot08) == 0x08, "Slot08VTableRuntime::slot08 offset must be 0x08");

  struct Slot08OwnerRuntime
  {
    Slot08VTableRuntime* vtable;
  };

  struct WordLaneOwnerRuntime
  {
    std::uint16_t value;
  };
  static_assert(sizeof(WordLaneOwnerRuntime) == 0x02, "WordLaneOwnerRuntime size must be 0x02");

  struct ViewScaleTargetVTableRuntime
  {
    std::byte pad00[0x60];
    void (__thiscall* setViewportRect)(void* self, int width, int height, int laneC, int laneD);
    std::byte pad64[0x0C];
    int (__thiscall* applyViewportRect)(void* self, int width, int height);
    std::byte pad74[0x7C];
    int (__thiscall* setOverlayState)(void* self, int enabled, void* payload);
  };
  static_assert(
    offsetof(ViewScaleTargetVTableRuntime, setViewportRect) == 0x60,
    "ViewScaleTargetVTableRuntime::setViewportRect offset must be 0x60"
  );
  static_assert(
    offsetof(ViewScaleTargetVTableRuntime, applyViewportRect) == 0x70,
    "ViewScaleTargetVTableRuntime::applyViewportRect offset must be 0x70"
  );
  static_assert(
    offsetof(ViewScaleTargetVTableRuntime, setOverlayState) == 0xF0,
    "ViewScaleTargetVTableRuntime::setOverlayState offset must be 0xF0"
  );

  struct ViewScaleTargetRuntime
  {
    ViewScaleTargetVTableRuntime* vtable;
  };

  struct ViewScaleOwnerVTableRuntime
  {
    std::byte pad00[0x1C];
    void (__thiscall* resolveClampedExtents)(void* self, int gridX, int gridY, int* inoutGridY, int* outGridX);
    int (__thiscall* syncSecondaryTarget)(void* self);
  };
  static_assert(
    offsetof(ViewScaleOwnerVTableRuntime, resolveClampedExtents) == 0x1C,
    "ViewScaleOwnerVTableRuntime::resolveClampedExtents offset must be 0x1C"
  );
  static_assert(
    offsetof(ViewScaleOwnerVTableRuntime, syncSecondaryTarget) == 0x20,
    "ViewScaleOwnerVTableRuntime::syncSecondaryTarget offset must be 0x20"
  );

  struct ViewScaleOwnerRuntime
  {
    ViewScaleOwnerVTableRuntime* vtable; // +0x00
    std::byte pad04[0x04];
    ViewScaleTargetRuntime* primaryTarget; // +0x08
    ViewScaleTargetRuntime* activeTarget; // +0x0C
    std::byte overlayPayload[0x08]; // +0x10
    std::uint32_t hasOverlayPayload; // +0x18
    std::byte pad1C[0x08];
    std::int32_t scaleX; // +0x24
    std::int32_t scaleY; // +0x28
    std::int32_t gridX; // +0x2C
    std::int32_t gridY; // +0x30
    std::int32_t maxGridX; // +0x34
    std::int32_t maxGridY; // +0x38
    std::byte pad3C[0x08];
    std::uint8_t lane44;
    std::uint8_t lane45;
    std::byte pad46[0x02];
    double worldOffsetX; // +0x48
    double worldOffsetY; // +0x50
  };
  static_assert(offsetof(ViewScaleOwnerRuntime, scaleX) == 0x24, "ViewScaleOwnerRuntime::scaleX offset must be 0x24");
  static_assert(offsetof(ViewScaleOwnerRuntime, gridY) == 0x30, "ViewScaleOwnerRuntime::gridY offset must be 0x30");
  static_assert(offsetof(ViewScaleOwnerRuntime, lane44) == 0x44, "ViewScaleOwnerRuntime::lane44 offset must be 0x44");
  static_assert(
    offsetof(ViewScaleOwnerRuntime, worldOffsetX) == 0x48,
    "ViewScaleOwnerRuntime::worldOffsetX offset must be 0x48"
  );

  struct ViewportConsumerVTableRuntime
  {
    std::byte pad00[0x80];
    int (__thiscall* setWorldOffset)(void* self, double worldX, double worldY);
    std::byte pad84[0x0C];
    void (__thiscall* setPixelOrigin)(void* self, int originX, int originY);
    std::byte pad94[0x78];
    void (__thiscall* queryPixelOrigin)(void* self, int* outX, int* outY);
  };
  static_assert(
    offsetof(ViewportConsumerVTableRuntime, setWorldOffset) == 0x80,
    "ViewportConsumerVTableRuntime::setWorldOffset offset must be 0x80"
  );
  static_assert(
    offsetof(ViewportConsumerVTableRuntime, setPixelOrigin) == 0x90,
    "ViewportConsumerVTableRuntime::setPixelOrigin offset must be 0x90"
  );
  static_assert(
    offsetof(ViewportConsumerVTableRuntime, queryPixelOrigin) == 0x10C,
    "ViewportConsumerVTableRuntime::queryPixelOrigin offset must be 0x10C"
  );

  struct ViewportConsumerRuntime
  {
    ViewportConsumerVTableRuntime* vtable;
  };

  struct LookupOutVTableRuntime
  {
    std::byte pad00[0x4C];
    std::uint8_t (__thiscall* resolveByKey)(void* self, int key, void** outValue);
    std::byte pad50[0x10];
    void* slot60;
  };
  static_assert(offsetof(LookupOutVTableRuntime, resolveByKey) == 0x4C, "LookupOutVTableRuntime::resolveByKey offset must be 0x4C");
  static_assert(offsetof(LookupOutVTableRuntime, slot60) == 0x60, "LookupOutVTableRuntime::slot60 offset must be 0x60");

  struct LookupOutOwnerRuntime
  {
    LookupOutVTableRuntime* vtable;
  };

  struct WordAtOffset8OwnerRuntime
  {
    std::byte pad00[0x08];
    std::uint16_t lane08;
  };
  static_assert(
    offsetof(WordAtOffset8OwnerRuntime, lane08) == 0x08,
    "WordAtOffset8OwnerRuntime::lane08 offset must be 0x08"
  );

  struct Slot104VTableRuntime
  {
    std::byte pad00[0x104];
    int (__thiscall* slot104)(void* self);
  };
  static_assert(offsetof(Slot104VTableRuntime, slot104) == 0x104, "Slot104VTableRuntime::slot104 offset must be 0x104");

  struct Slot104OwnerRuntime
  {
    Slot104VTableRuntime* vtable;
  };

  struct NotifyOnChangeVTableRuntime
  {
    std::byte pad00[0x78];
    int (__stdcall* notifyChanged)(int callbackContext);
  };
  static_assert(
    offsetof(NotifyOnChangeVTableRuntime, notifyChanged) == 0x78,
    "NotifyOnChangeVTableRuntime::notifyChanged offset must be 0x78"
  );

  struct NotifyOnChangeOwnerRuntime
  {
    NotifyOnChangeVTableRuntime* vtable;
    std::byte pad04[0x1C];
    double lane20;
    double lane28;
    double lane30;
    double lane38;
    double lane40;
    double lane48;
    std::int32_t lane50;
    std::int32_t lane54;
    std::byte pad58[0x28];
    int callbackContext; // +0x80
  };
  static_assert(offsetof(NotifyOnChangeOwnerRuntime, lane30) == 0x30, "NotifyOnChangeOwnerRuntime::lane30 offset must be 0x30");
  static_assert(
    offsetof(NotifyOnChangeOwnerRuntime, callbackContext) == 0x80,
    "NotifyOnChangeOwnerRuntime::callbackContext offset must be 0x80"
  );

  struct Slot0CVTableRuntime
  {
    std::byte pad00[0x0C];
    int (__thiscall* slot0C)(void* self);
  };
  static_assert(offsetof(Slot0CVTableRuntime, slot0C) == 0x0C, "Slot0CVTableRuntime::slot0C offset must be 0x0C");

  struct Slot0COwnerRuntime
  {
    Slot0CVTableRuntime* vtable;
  };
}

/**
 * Address: 0x00886B00 (FUN_00886B00)
 *
 * What it does:
 * Invokes one context-bound callback thunk with a forwarded integer argument.
 */
[[maybe_unused]] int InvokeContextUnaryThunkRuntime(
  const ThiscallContextUnaryThunkRuntime* const thunk,
  const int arg0
)
{
  return thunk->invoke(thunk->context, arg0);
}

/**
 * Address: 0x0088FCE0 (FUN_0088FCE0)
 *
 * What it does:
 * Invokes one cdecl binary thunk with two stored payload lanes.
 */
[[maybe_unused]] int InvokeStoredBinaryCdeclThunkRuntime(const CdeclBinaryThunkRuntime* const thunk)
{
  return thunk->invoke(thunk->arg0, thunk->arg1);
}

/**
 * Address: 0x00935DB0 (FUN_00935DB0)
 *
 * What it does:
 * Invokes one unary cdecl thunk with a forwarded integer argument.
 */
[[maybe_unused]] int InvokeUnaryCdeclThunkRuntime(
  const CdeclUnaryThunkRuntime* const thunk,
  const int arg0
)
{
  return thunk->invoke(arg0);
}

/**
 * Address: 0x00954960 (FUN_00954960)
 *
 * What it does:
 * Unlinks one intrusive node from its current list and resets it as a
 * self-linked singleton.
 */
[[maybe_unused]] void ResetIntrusiveLinkNodeRuntime(IntrusiveLinkNodeRuntime* const node) noexcept
{
  node->next->prev = node->prev;
  node->prev->next = node->next;
  node->prev = node;
  node->next = node;
}

/**
 * Address: 0x00983300 (FUN_00983300)
 *
 * What it does:
 * Returns whether lane `+0x18` is nonzero.
 */
[[maybe_unused]] BOOL HasLane18ValueRuntime(const BoolLane18OwnerRuntime* const owner) noexcept
{
  return (owner->lane18 != 0u) ? TRUE : FALSE;
}

/**
 * Address: 0x009D2EE0 (FUN_009D2EE0)
 *
 * What it does:
 * Forwards to virtual slot `+0x08`.
 */
[[maybe_unused]] int InvokeSlot08Runtime(Slot08OwnerRuntime* const owner)
{
  return owner->vtable->slot08(owner);
}

/**
 * Address: 0x009D31B0 (FUN_009D31B0)
 *
 * What it does:
 * Clears one 16-bit lane to zero.
 */
[[maybe_unused]] void ZeroWordLaneRuntime(WordLaneOwnerRuntime* const owner) noexcept
{
  owner->value = 0u;
}

/**
 * Address: 0x009F0CA0 (FUN_009F0CA0)
 *
 * What it does:
 * Recomputes clamped viewport bounds, updates active scale/grid lanes, applies
 * target viewport changes, and optionally refreshes overlay state.
 */
[[maybe_unused]] int UpdateViewportScaleStateRuntime(
  ViewScaleOwnerRuntime* const owner,
  const int scaleX,
  const int scaleY,
  const int maxGridX,
  const int maxGridY,
  const int gridX,
  const int gridY,
  const std::uint8_t skipOverlayRefresh
)
{
  int resolvedGridY = gridY;
  int resolvedGridX = 0;
  owner->vtable->resolveClampedExtents(owner, gridX, gridY, &resolvedGridY, &resolvedGridX);

  const bool needsRefresh = (maxGridX != 0 && owner->maxGridX == 0)
                         || (maxGridX < owner->maxGridX && resolvedGridY > (maxGridX * scaleX))
                         || (maxGridY != 0 && owner->maxGridY == 0)
                         || (maxGridY < owner->maxGridY && resolvedGridX > (maxGridY * scaleY))
                         || (gridX != owner->gridX)
                         || (gridY != owner->gridY);

  owner->scaleX = scaleX;
  owner->scaleY = scaleY;
  owner->gridY = gridY;
  owner->gridX = gridX;

  const int widthPixels = maxGridX * scaleX;
  const int heightPixels = maxGridY * scaleY;
  owner->activeTarget->vtable->setViewportRect(owner->activeTarget, widthPixels, heightPixels, -1, -1);
  int result = owner->activeTarget->vtable->applyViewportRect(owner->activeTarget, widthPixels, heightPixels);

  if (needsRefresh && skipOverlayRefresh == 0u) {
    void* payload = nullptr;
    if (owner->hasOverlayPayload != 0u) {
      payload = owner->overlayPayload;
    }
    result = owner->activeTarget->vtable->setOverlayState(owner->activeTarget, 1, payload);
  }

  if (owner->activeTarget != owner->primaryTarget) {
    return owner->vtable->syncSecondaryTarget(owner);
  }
  return result;
}

/**
 * Address: 0x009F0F60 (FUN_009F0F60)
 *
 * What it does:
 * Queries current viewport origin, applies tile-scaled translation, and writes
 * current world offsets to the target viewport consumer.
 */
[[maybe_unused]] int ApplyViewportTransformRuntime(
  const ViewScaleOwnerRuntime* const owner,
  ViewportConsumerRuntime* const target
)
{
  int originY = 0;
  int originX = 0;
  target->vtable->queryPixelOrigin(target, &originX, &originY);

  const int translatedX = originX - (owner->gridX * owner->scaleX);
  const int translatedY = originY - (owner->gridY * owner->scaleY);
  target->vtable->setPixelOrigin(target, translatedX, translatedY);
  return target->vtable->setWorldOffset(target, owner->worldOffsetX, owner->worldOffsetY);
}

/**
 * Address: 0x009F1060 (FUN_009F1060)
 *
 * What it does:
 * Exports scale lanes at `+0x24/+0x28` into optional output pointers.
 */
[[maybe_unused]] std::int32_t* GetScalePairRuntime(
  const ViewScaleOwnerRuntime* const owner,
  std::int32_t* const outScaleX,
  std::int32_t* const outScaleY
) noexcept
{
  if (outScaleX != nullptr) {
    *outScaleX = owner->scaleX;
  }
  if (outScaleY != nullptr) {
    *outScaleY = owner->scaleY;
  }
  return outScaleY;
}

/**
 * Address: 0x009F1230 (FUN_009F1230)
 *
 * What it does:
 * Writes two byte lanes at `+0x44/+0x45`.
 */
[[maybe_unused]] char SetByteLanes44And45Runtime(
  ViewScaleOwnerRuntime* const owner,
  const std::uint8_t lane44,
  const std::uint8_t lane45
) noexcept
{
  owner->lane44 = lane44;
  owner->lane45 = lane45;
  return static_cast<char>(lane44);
}

/**
 * Address: 0x009F1250 (FUN_009F1250)
 *
 * What it does:
 * Exports grid lanes at `+0x2C/+0x30` into optional output pointers.
 */
[[maybe_unused]] std::int32_t* GetGridPairRuntime(
  const ViewScaleOwnerRuntime* const owner,
  std::int32_t* const outGridX,
  std::int32_t* const outGridY
) noexcept
{
  if (outGridX != nullptr) {
    *outGridX = owner->gridX;
  }
  if (outGridY != nullptr) {
    *outGridY = owner->gridY;
  }
  return outGridY;
}

/**
 * Address: 0x009F1270 (FUN_009F1270)
 *
 * What it does:
 * Converts absolute pixel coordinates to local coordinates using
 * `grid * scale` subtraction.
 */
[[maybe_unused]] std::int32_t* ConvertToLocalCoordinatesRuntime(
  const ViewScaleOwnerRuntime* const owner,
  const int absoluteX,
  const int absoluteY,
  std::int32_t* const outLocalX,
  std::int32_t* const outLocalY
) noexcept
{
  if (outLocalX != nullptr) {
    *outLocalX = absoluteX - (owner->gridX * owner->scaleX);
  }
  if (outLocalY != nullptr) {
    *outLocalY = absoluteY - (owner->gridY * owner->scaleY);
  }
  return outLocalY;
}

/**
 * Address: 0x009F12B0 (FUN_009F12B0)
 *
 * What it does:
 * Converts local coordinates to absolute pixel coordinates using
 * `grid * scale` addition.
 */
[[maybe_unused]] std::int32_t* ConvertToAbsoluteCoordinatesRuntime(
  const ViewScaleOwnerRuntime* const owner,
  const int localX,
  const int localY,
  std::int32_t* const outAbsoluteX,
  std::int32_t* const outAbsoluteY
) noexcept
{
  if (outAbsoluteX != nullptr) {
    *outAbsoluteX = localX + (owner->gridX * owner->scaleX);
  }
  if (outAbsoluteY != nullptr) {
    *outAbsoluteY = localY + (owner->gridY * owner->scaleY);
  }
  return outAbsoluteY;
}

/**
 * Address: 0x00A09840 (FUN_00A09840)
 *
 * What it does:
 * Resolves one keyed pointer value via slot `+0x4C` and writes it to the
 * output lane.
 */
[[maybe_unused]] char TryResolvePointerByKeyRuntime(
  LookupOutOwnerRuntime* const owner,
  const int key,
  void** const outValue
)
{
  if (outValue == nullptr) {
    return 0;
  }

  void* resolved = *outValue;
  if (owner->vtable->resolveByKey(owner, key, &resolved) == 0u) {
    return 0;
  }
  *outValue = resolved;
  return 1;
}

/**
 * Address: 0x00A09870 (FUN_00A09870)
 *
 * What it does:
 * Resolves one keyed pointer via slot `+0x4C` and writes `true` when the
 * resolved lane is non-null.
 */
[[maybe_unused]] char TryResolvePresenceByKeyRuntime(
  LookupOutOwnerRuntime* const owner,
  const int key,
  bool* const outPresent
)
{
  if (outPresent == nullptr) {
    return 0;
  }

  void* resolved = nullptr;
  if (owner->vtable->resolveByKey(owner, key, &resolved) == 0u) {
    return 0;
  }
  *outPresent = (resolved != nullptr);
  return 1;
}

/**
 * Address: 0x00A09950 (FUN_00A09950)
 *
 * What it does:
 * Forwards directly to virtual slot `+0x60`.
 */
[[maybe_unused]] int InvokeSlot60NoArgsRuntime(LookupOutOwnerRuntime* const owner)
{
  const auto slot60 = reinterpret_cast<int(__thiscall*)(LookupOutOwnerRuntime*)>(owner->vtable->slot60);
  return slot60(owner);
}

/**
 * Address: 0x00A09960 (FUN_00A09960)
 *
 * What it does:
 * Forwards to virtual slot `+0x60` after normalizing the byte flag argument to
 * an integer boolean.
 */
[[maybe_unused]] int InvokeSlot60WithBoolRuntime(
  LookupOutOwnerRuntime* const owner,
  const int arg0,
  const std::uint8_t arg1
)
{
  const auto slot60 = reinterpret_cast<int(__thiscall*)(LookupOutOwnerRuntime*, int, int)>(owner->vtable->slot60);
  return slot60(owner, arg0, (arg1 != 0u) ? 1 : 0);
}

/**
 * Address: 0x00AA7ACF (FUN_00AA7ACF)
 *
 * What it does:
 * Sets one FPU status byte from flag bit `0x40` and returns the sum of two
 * source double lanes.
 */
[[maybe_unused]] double AddDoubleAndUpdateFpuStatusRuntime(
  FpuStatusLaneRuntime* const state,
  const double lhs,
  const double rhs
) noexcept
{
  state->statusCode = ((state->flags & 0x40u) != 0u) ? 7u : 1u;
  return rhs + lhs;
}

/**
 * Address: 0x00A19210 (FUN_00A19210)
 *
 * What it does:
 * Copies the 16-bit lane at `+0x08` into output and returns the output pointer.
 */
[[maybe_unused]] std::uint16_t* CopyWordLane08ToOutputRuntime(
  const WordAtOffset8OwnerRuntime* const owner,
  std::uint16_t* const outValue,
  const int /*unused*/
) noexcept
{
  *outValue = owner->lane08;
  return outValue;
}

/**
 * Address: 0x00A19230 (FUN_00A19230)
 *
 * What it does:
 * Copies the 16-bit lane at `+0x08` into output and returns that value.
 */
[[maybe_unused]] std::uint16_t CopyWordLane08ToOutputAndReturnRuntime(
  const WordAtOffset8OwnerRuntime* const owner,
  std::uint16_t* const outValue,
  const int /*unused*/
) noexcept
{
  const std::uint16_t value = owner->lane08;
  *outValue = value;
  return value;
}

/**
 * Address: 0x00A2CEA0 (FUN_00A2CEA0)
 *
 * What it does:
 * Copies one dword from source to destination and advances the source cursor by
 * one dword.
 */
[[maybe_unused]] std::uint32_t* CopyDwordAndAdvanceSourceRuntime(
  const std::uint32_t* const source,
  std::uint32_t* const destination,
  const int /*unused*/
) noexcept
{
  *destination = *source;
  return const_cast<std::uint32_t*>(source + 1);
}

/**
 * Address: 0x00A2CEC0 (FUN_00A2CEC0)
 *
 * What it does:
 * Writes one dword value and advances destination cursor by one dword.
 */
[[maybe_unused]] std::uint32_t* WriteDwordAndAdvanceDestinationRuntime(
  std::uint32_t* const destination,
  const std::uint32_t value,
  const int /*unused*/
) noexcept
{
  *destination = value;
  return destination + 1;
}

/**
 * Address: 0x00967130 (FUN_00967130)
 *
 * What it does:
 * Forwards to virtual slot `+0x104`.
 */
[[maybe_unused]] int InvokeSlot104Runtime(Slot104OwnerRuntime* const owner)
{
  return owner->vtable->slot104(owner);
}

/**
 * Address: 0x009C9F00 (FUN_009C9F00)
 *
 * What it does:
 * Updates double lanes `+0x30/+0x38` and notifies callback slot `+0x78` only
 * when either lane changes.
 */
[[maybe_unused]] void SetPrimaryDoublePairAndNotifyRuntime(
  NotifyOnChangeOwnerRuntime* const owner,
  const double value0,
  const double value1
)
{
  if (owner->lane30 != value0 || owner->lane38 != value1) {
    owner->lane30 = value0;
    owner->lane38 = value1;
    owner->vtable->notifyChanged(owner->callbackContext);
  }
}

/**
 * Address: 0x009C9F50 (FUN_009C9F50)
 *
 * What it does:
 * Converts two byte flags to sign lanes (`+1/-1`), updates lanes `+0x50/+0x54`
 * on change, and notifies callback slot `+0x78`.
 */
[[maybe_unused]] int SetSignedFlagPairAndNotifyRuntime(
  NotifyOnChangeOwnerRuntime* const owner,
  const std::uint8_t flag0,
  const std::uint8_t flag1
)
{
  const int lane50 = 2 * ((flag0 != 0u) ? 1 : 0) - 1;
  const int lane54 = 2 * ((flag1 == 0u) ? 1 : 0) - 1;
  if (lane50 != owner->lane50 || lane54 != owner->lane54) {
    owner->lane50 = lane50;
    owner->lane54 = lane54;
    return owner->vtable->notifyChanged(owner->callbackContext);
  }
  return lane50;
}

/**
 * Address: 0x009C9F90 (FUN_009C9F90)
 *
 * What it does:
 * Updates double lanes `+0x40/+0x48` and notifies callback slot `+0x78` only
 * when either lane changes.
 */
[[maybe_unused]] void SetSecondaryDoublePairAndNotifyRuntime(
  NotifyOnChangeOwnerRuntime* const owner,
  const double value0,
  const double value1
)
{
  if (owner->lane40 != value0 || owner->lane48 != value1) {
    owner->lane40 = value0;
    owner->lane48 = value1;
    owner->vtable->notifyChanged(owner->callbackContext);
  }
}

/**
 * Address: 0x009CA1D0 (FUN_009CA1D0)
 *
 * What it does:
 * Sets base double lanes `+0x20/+0x28`.
 */
[[maybe_unused]] void SetBaseDoublePairRuntime(
  NotifyOnChangeOwnerRuntime* const owner,
  const double value0,
  const double value1
) noexcept
{
  owner->lane20 = value0;
  owner->lane28 = value1;
}

/**
 * Address: 0x009DD340 (FUN_009DD340)
 *
 * What it does:
 * Forwards to virtual slot `+0x0C`.
 */
[[maybe_unused]] int InvokeSlot0CRuntime(Slot0COwnerRuntime* const owner)
{
  return owner->vtable->slot0C(owner);
}

/**
 * Address: 0x009DD350 (FUN_009DD350)
 *
 * What it does:
 * Forwards to virtual slot `+0x08`.
 */
[[maybe_unused]] int InvokeSlot08RuntimeB(Slot08OwnerRuntime* const owner)
{
  return owner->vtable->slot08(owner);
}
