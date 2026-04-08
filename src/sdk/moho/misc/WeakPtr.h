#pragma once

#include <cstddef>
#include <cstdint>
#include <new>

// Windows GDI headers define `GetObject` as an ANSI/Unicode macro alias.
// Undefine it so intrusive weak-pointer accessors keep their intended name.
#ifdef GetObject
#undef GetObject
#endif

namespace msvc8
{
  template <class T>
  class vector;
}

namespace gpg
{
  class RType;
}

namespace moho
{
  class UnitWeapon;

  template <class T>
  struct WeakPtrOwnerLinkOffset
  {
    static constexpr std::uintptr_t value = sizeof(void*);
  };

#ifndef MOHO_WEAKPTR_OWNER_LINK_OFFSET_UNITWEAPON_DEFINED
#define MOHO_WEAKPTR_OWNER_LINK_OFFSET_UNITWEAPON_DEFINED
  template <>
  struct WeakPtrOwnerLinkOffset<UnitWeapon>
  {
    static constexpr std::uintptr_t value = 0x14;
  };
#endif

  /**
   * Recovered intrusive weak-pointer node layout used by Moho reflection helpers.
   *
   * Binary evidence:
   * - Weak-pointer set path (`sub_1012F320` / FA `sub_541320`) updates two dwords:
   *   [0] owner link slot pointer, [1] next node pointer in owner chain.
   */
  template <class T>
  struct WeakPtr
  {
    inline static gpg::RType* sType = nullptr;

    // Owner link points at the owner's intrusive weak-link head slot.
    // Most owners use +sizeof(void*), but some recovered types have different
    // owner-link slot offsets (specialized via WeakPtrOwnerLinkOffset<T>).
    static constexpr std::uintptr_t kOwnerLinkOffset = WeakPtrOwnerLinkOffset<T>::value;

    void* ownerLinkSlot;     // points to owner weak-link slot (owner + kOwnerLinkOffset) or nullptr/sentinel
    WeakPtr<T>* nextInOwner; // intrusive next node in owner chain

    [[nodiscard]] static bool IsSentinelSlot(void* slot) noexcept
    {
      return reinterpret_cast<std::uintptr_t>(slot) == kOwnerLinkOffset;
    }

    [[nodiscard]] static void* EncodeOwnerLinkSlot(T* object) noexcept
    {
      if (!object) {
        return nullptr;
      }
      return reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) + kOwnerLinkOffset);
    }

    [[nodiscard]] static T* DecodeOwnerObject(void* slot) noexcept
    {
      if (!slot || IsSentinelSlot(slot)) {
        return nullptr;
      }
      const auto raw = reinterpret_cast<std::uintptr_t>(slot);
      return reinterpret_cast<T*>(raw - kOwnerLinkOffset);
    }

    [[nodiscard]] bool IsSentinel() const noexcept
    {
      return IsSentinelSlot(ownerLinkSlot);
    }

    [[nodiscard]] bool HasValue() const noexcept
    {
      return ownerLinkSlot != nullptr && !IsSentinel();
    }

    [[nodiscard]] T* GetObjectPtr() const noexcept
    {
      return DecodeOwnerObject(ownerLinkSlot);
    }

    [[nodiscard]] bool IsLinkedInOwnerChain() const noexcept
    {
      return ownerLinkSlot != nullptr && !IsSentinel();
    }

#if !defined(GetObject)
    [[nodiscard]] T* GetObject() const noexcept
    {
      return GetObjectPtr();
    }
#endif

    [[nodiscard]] bool ReplaceInOwnerChain(WeakPtr<T>* replacement) noexcept
    {
      if (!IsLinkedInOwnerChain()) {
        return false;
      }

      auto** slot = reinterpret_cast<WeakPtr<T>**>(ownerLinkSlot);
      while (*slot && *slot != this) {
        slot = &(*slot)->nextInOwner;
      }

      if (*slot != this) {
        return false;
      }

      *slot = replacement;
      return true;
    }

    void UnlinkFromOwnerChain() noexcept
    {
      if (!IsLinkedInOwnerChain()) {
        return;
      }

      if (ReplaceInOwnerChain(nextInOwner)) {
        ownerLinkSlot = nullptr;
        nextInOwner = nullptr;
      }
    }

    void ClearLinkState() noexcept
    {
      ownerLinkSlot = nullptr;
      nextInOwner = nullptr;
    }

    /**
     * Binds an encoded owner-link slot without inserting into the owner's chain.
     *
     * Use this when a node payload is copied/staged first and linked later by
     * explicit insertion logic.
     */
    void BindOwnerLinkSlotUnlinked(void* encodedOwnerLinkSlot) noexcept
    {
      ownerLinkSlot = encodedOwnerLinkSlot;
      nextInOwner = nullptr;
    }

    /**
     * Binds this weak node to an object owner slot without linking into the chain.
     */
    void BindObjectUnlinked(T* object) noexcept
    {
      BindOwnerLinkSlotUnlinked(EncodeOwnerLinkSlot(object));
    }

    /**
     * Inserts this node at the owner-chain head.
     *
     * Precondition: node is currently unlinked from the owner chain.
     */
    [[nodiscard]] bool LinkIntoOwnerChainHeadUnlinked() noexcept
    {
      if (!HasValue()) {
        nextInOwner = nullptr;
        return false;
      }

      auto** const head = reinterpret_cast<WeakPtr<T>**>(ownerLinkSlot);
      nextInOwner = *head;
      *head = this;
      return true;
    }

    void ResetFromOwnerLinkSlot(void* newOwnerLinkSlot) noexcept
    {
      if (newOwnerLinkSlot == ownerLinkSlot) {
        return;
      }

      // Detach from current owner chain.
      if (ownerLinkSlot && !IsSentinel()) {
        auto** cursor = reinterpret_cast<WeakPtr<T>**>(ownerLinkSlot);
        while (*cursor && *cursor != this) {
          cursor = reinterpret_cast<WeakPtr<T>**>(
            reinterpret_cast<std::uintptr_t>(*cursor) + offsetof(WeakPtr<T>, nextInOwner)
          );
        }
        if (*cursor == this) {
          *cursor = nextInOwner;
        }
      }

      ownerLinkSlot = newOwnerLinkSlot;
      if (newOwnerLinkSlot && !IsSentinelSlot(newOwnerLinkSlot)) {
        auto** const head = reinterpret_cast<WeakPtr<T>**>(newOwnerLinkSlot);
        nextInOwner = *head;
        *head = this;
      } else {
        nextInOwner = nullptr;
      }
    }

    void ResetFromObject(T* object) noexcept
    {
      ResetFromOwnerLinkSlot(EncodeOwnerLinkSlot(object));
    }
  };
  static_assert(sizeof(WeakPtr<void>) == 0x08, "WeakPtr<T> must be 8 bytes");
  static_assert(WeakPtr<void>::kOwnerLinkOffset == 0x4, "WeakPtr ABI expects owner-link offset 0x4");
  static_assert(offsetof(WeakPtr<void>, ownerLinkSlot) == 0x00, "WeakPtr<T>::ownerLinkSlot offset must be 0x00");
  static_assert(offsetof(WeakPtr<void>, nextInOwner) == 0x04, "WeakPtr<T>::nextInOwner offset must be 0x04");

  template <class T>
  struct WeakPtrVectorStorage
  {
    WeakPtr<T>* begin;
    WeakPtr<T>* end;
    WeakPtr<T>* capacityEnd;
  };
  static_assert(sizeof(WeakPtrVectorStorage<void>) == 0x0C, "WeakPtrVectorStorage<T> must be 12 bytes");

  template <class T>
  struct WeakPtrVectorRuntimeView
  {
    void* proxy;
    WeakPtr<T>* begin;
    WeakPtr<T>* end;
    WeakPtr<T>* capacityEnd;
  };
  static_assert(sizeof(WeakPtrVectorRuntimeView<void>) == 0x10, "WeakPtrVectorRuntimeView<T> must be 16 bytes");
  static_assert(
    offsetof(WeakPtrVectorRuntimeView<void>, begin) == 0x04,
    "WeakPtrVectorRuntimeView<T>::begin offset must be 0x04"
  );
  static_assert(
    offsetof(WeakPtrVectorRuntimeView<void>, end) == 0x08,
    "WeakPtrVectorRuntimeView<T>::end offset must be 0x08"
  );
  static_assert(
    offsetof(WeakPtrVectorRuntimeView<void>, capacityEnd) == 0x0C,
    "WeakPtrVectorRuntimeView<T>::capacityEnd offset must be 0x0C"
  );

  template <class T>
  [[nodiscard]] WeakPtrVectorRuntimeView<T>& AsWeakPtrVectorRuntimeView(msvc8::vector<WeakPtr<T>>& weakVector) noexcept
  {
    return *reinterpret_cast<WeakPtrVectorRuntimeView<T>*>(&weakVector);
  }

  template <class T>
  [[nodiscard]] const WeakPtrVectorRuntimeView<T>&
  AsWeakPtrVectorRuntimeView(const msvc8::vector<WeakPtr<T>>& weakVector) noexcept
  {
    return *reinterpret_cast<const WeakPtrVectorRuntimeView<T>*>(&weakVector);
  }

  template <class T>
  void EnsureWeakPtrVectorCapacity(msvc8::vector<WeakPtr<T>>& weakVector, const std::size_t requiredCount)
  {
    auto& view = AsWeakPtrVectorRuntimeView(weakVector);

    const std::size_t size = view.begin ? static_cast<std::size_t>(view.end - view.begin) : 0u;
    const std::size_t capacity = view.begin ? static_cast<std::size_t>(view.capacityEnd - view.begin) : 0u;
    if (requiredCount <= capacity) {
      return;
    }

    std::size_t newCapacity = capacity != 0 ? capacity : 4u;
    while (newCapacity < requiredCount) {
      newCapacity *= 2u;
    }

    auto* const newBegin = static_cast<WeakPtr<T>*>(::operator new(sizeof(WeakPtr<T>) * newCapacity));
    for (std::size_t i = 0; i < newCapacity; ++i) {
      newBegin[i].ownerLinkSlot = nullptr;
      newBegin[i].nextInOwner = nullptr;
    }

    for (std::size_t i = 0; i < size; ++i) {
      newBegin[i].ResetFromOwnerLinkSlot(view.begin[i].ownerLinkSlot);
      view.begin[i].ResetFromObject(nullptr);
    }

    ::operator delete(view.begin);
    view.begin = newBegin;
    view.end = newBegin + size;
    view.capacityEnd = newBegin + newCapacity;
  }

  template <class T>
  [[nodiscard]] std::size_t
  NormalizeWeakPtrVectorInsertIndex(const msvc8::vector<WeakPtr<T>>& weakVector, int index) noexcept
  {
    const auto& view = AsWeakPtrVectorRuntimeView(weakVector);
    const std::size_t size = view.begin ? static_cast<std::size_t>(view.end - view.begin) : 0u;

    int normalized = index;
    if (normalized < 0) {
      normalized += static_cast<int>(size) + 1;
    }
    if (normalized < 0) {
      normalized = 0;
    }

    std::size_t result = static_cast<std::size_t>(normalized);
    if (result > size) {
      result = size;
    }
    return result;
  }

  template <class T>
  void InsertWeakPtrVectorObjectAt(
    msvc8::vector<WeakPtr<T>>& weakVector, T* object, const std::size_t index
  )
  {
    auto& view = AsWeakPtrVectorRuntimeView(weakVector);
    const std::size_t size = view.begin ? static_cast<std::size_t>(view.end - view.begin) : 0u;
    const std::size_t clampedIndex = index <= size ? index : size;

    EnsureWeakPtrVectorCapacity(weakVector, size + 1u);

    for (std::size_t i = size; i > clampedIndex; --i) {
      view.begin[i].ResetFromOwnerLinkSlot(view.begin[i - 1].ownerLinkSlot);
      view.begin[i - 1].ResetFromObject(nullptr);
    }

    view.begin[clampedIndex].ResetFromObject(object);
    view.end = view.begin + size + 1u;
  }

  template <class T>
  [[nodiscard]] bool RemoveWeakPtrVectorObject(msvc8::vector<WeakPtr<T>>& weakVector, const T* object)
  {
    if (!object) {
      return false;
    }

    auto& view = AsWeakPtrVectorRuntimeView(weakVector);
    const std::size_t size = view.begin ? static_cast<std::size_t>(view.end - view.begin) : 0u;
    if (!view.begin || size == 0u) {
      return false;
    }

    for (std::size_t i = 0; i < size; ++i) {
      if (view.begin[i].GetObjectPtr() != object) {
        continue;
      }

      view.begin[i].ResetFromObject(nullptr);
      for (std::size_t j = i + 1; j < size; ++j) {
        view.begin[j - 1].ResetFromOwnerLinkSlot(view.begin[j].ownerLinkSlot);
        view.begin[j].ResetFromObject(nullptr);
      }

      view.end = view.begin + size - 1u;
      return true;
    }

    return false;
  }

  /**
   * Removes one intrusive weak-pointer entry from a contiguous weak-pointer container.
   *
   * The container is expected to expose `size()`, `operator[]`, and `pop_back()`
   * with elements matching `WeakPtr<T>` semantics.
   */
  template <class TWeakVector>
  void EraseWeakVectorEntry(TWeakVector& weakVector, const std::size_t index) noexcept
  {
    const std::size_t count = weakVector.size();
    if (index >= count) {
      return;
    }

    weakVector[index].ResetFromObject(nullptr);
    for (std::size_t i = index + 1; i < count; ++i) {
      weakVector[i - 1].ResetFromOwnerLinkSlot(weakVector[i].ownerLinkSlot);
      weakVector[i].ResetFromObject(nullptr);
    }
    weakVector.pop_back();
  }
} // namespace moho
