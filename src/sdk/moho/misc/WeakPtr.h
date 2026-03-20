#pragma once

#include <cstddef>
#include <cstdint>

// Windows GDI headers define `GetObject` as an ANSI/Unicode macro alias.
// Undefine it so intrusive weak-pointer accessors keep their intended name.
#ifdef GetObject
#undef GetObject
#endif

namespace moho
{
  template <class T>
  struct WeakPtrOwnerLinkOffset
  {
    static constexpr std::uintptr_t value = sizeof(void*);
  };

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

#if !defined(GetObject)
    [[nodiscard]] T* GetObject() const noexcept
    {
      return GetObjectPtr();
    }
#endif

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
} // namespace moho
