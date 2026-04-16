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
  class Unit;
  class IUnit;
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

    WeakPtr() noexcept
      : ownerLinkSlot(nullptr)
      , nextInOwner(nullptr)
    {}

    /**
     * Address: 0x0056AA00 (FUN_0056AA00, Moho::WeakPtr_IUnit::WeakPtr_IUnit)
     * Address: 0x005A6DB0 (FUN_005A6DB0)
     * Address: 0x0057D560 (FUN_0057D560)
     *
     * What it does:
     * Initializes one weak-pointer node from an owner object pointer and links
     * it at the head of the owner's intrusive weak-link chain.
     */
    explicit WeakPtr(T* object) noexcept
      : ownerLinkSlot(nullptr)
      , nextInOwner(nullptr)
    {
      BindObjectUnlinked(object);
      (void)LinkIntoOwnerChainHeadUnlinked();
    }

    // Recovered aggregate-like initialization lane used by serializer/runtime
    // wrappers that materialize weak nodes from raw intrusive fields.
    WeakPtr(void* encodedOwnerLinkSlot, WeakPtr<T>* nextNode) noexcept
      : ownerLinkSlot(encodedOwnerLinkSlot)
      , nextInOwner(nextNode)
    {}

    ~WeakPtr() noexcept;

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

    /**
     * Address: 0x0057D540 (FUN_0057D540)
     *
     * What it does:
     * Decodes one weak owner-link slot back to the owning object pointer
     * (`slot - kOwnerLinkOffset`), returning null for empty/sentinel lanes.
     */
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
     * Inserts one weak node at the current owner-chain head without first
     * scanning for/removing an existing link.
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

    /**
     * Address: 0x0057D610 (FUN_0057D610)
     * Address: 0x005419A0 (FUN_005419A0)
     * Address: 0x005DB430 (FUN_005DB430)
     * Address: 0x0057D4B0 (FUN_0057D4B0)
     *
     * What it does:
     * Rebinds this weak-pointer node to a new owner-link slot, detaches the
     * node from its previous intrusive owner chain when needed, and inserts it
     * at the head of the new owner chain.
     */
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

    void Set(T* object) noexcept
    {
      ResetFromObject(object);
    }
  };

  static_assert(sizeof(WeakPtr<void>) == 0x08, "WeakPtr<T> must be 8 bytes");
  static_assert(WeakPtr<void>::kOwnerLinkOffset == 0x4, "WeakPtr ABI expects owner-link offset 0x4");
  static_assert(offsetof(WeakPtr<void>, ownerLinkSlot) == 0x00, "WeakPtr<T>::ownerLinkSlot offset must be 0x00");
  static_assert(offsetof(WeakPtr<void>, nextInOwner) == 0x04, "WeakPtr<T>::nextInOwner offset must be 0x04");

  template <class PayloadT>
  struct WeakPtrPayloadLane
  {
    WeakPtr<void> weak;
    PayloadT payload;
  };

  static_assert(sizeof(WeakPtrPayloadLane<std::uint32_t>) == 0x0C, "WeakPtrPayloadLane<uint32_t> size must be 0x0C");
  static_assert(sizeof(WeakPtrPayloadLane<float>) == 0x0C, "WeakPtrPayloadLane<float> size must be 0x0C");

  template <class PayloadT>
  [[nodiscard]] inline WeakPtrPayloadLane<PayloadT>* CopyWeakPtrPayloadRangeCore(
    WeakPtrPayloadLane<PayloadT>* destination,
    const WeakPtrPayloadLane<PayloadT>* sourceEnd,
    const WeakPtrPayloadLane<PayloadT>* sourceBegin
  ) noexcept
  {
    for (const WeakPtrPayloadLane<PayloadT>* source = sourceBegin; source != sourceEnd; ++source, ++destination) {
      if (destination == nullptr) {
        continue;
      }

      destination->weak.ownerLinkSlot = source->weak.ownerLinkSlot;
      if (source->weak.ownerLinkSlot == nullptr) {
        destination->weak.nextInOwner = nullptr;
      } else {
        auto** const ownerHead = reinterpret_cast<WeakPtr<void>**>(source->weak.ownerLinkSlot);
        destination->weak.nextInOwner = *ownerHead;
        *ownerHead = &destination->weak;
      }
      destination->payload = source->payload;
    }
    return destination;
  }

  /**
   * Address: 0x00629F40 (FUN_00629F40)
   * Address: 0x00628FB0 (FUN_00628FB0)
   *
   * What it does:
   * Copies `[sourceBegin, sourceEnd)` weak-link lanes with one trailing float
   * payload per element and relinks each copied node into the source owner
   * chain head.
   */
  [[nodiscard]] inline WeakPtrPayloadLane<float>* CopyWeakPtrFloatPayloadRange(
    WeakPtrPayloadLane<float>* destination,
    const WeakPtrPayloadLane<float>* sourceEnd,
    const WeakPtrPayloadLane<float>* sourceBegin
  ) noexcept
  {
    return CopyWeakPtrPayloadRangeCore(destination, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x00628200 (FUN_00628200)
   *
   * What it does:
   * Register-shape adapter lane that forwards one weak-float payload range
   * copy into `CopyWeakPtrFloatPayloadRange`.
   */
  [[maybe_unused]] [[nodiscard]] inline WeakPtrPayloadLane<float>* CopyWeakPtrFloatPayloadRangeAdapterA(
    WeakPtrPayloadLane<float>* destination,
    const WeakPtrPayloadLane<float>* sourceEnd,
    const WeakPtrPayloadLane<float>* sourceBegin
  ) noexcept
  {
    return CopyWeakPtrFloatPayloadRange(destination, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x00628B50 (FUN_00628B50)
   *
   * What it does:
   * Mirrored register-shape adapter lane that forwards one weak-float payload
   * range copy into `CopyWeakPtrFloatPayloadRange`.
   */
  [[maybe_unused]] [[nodiscard]] inline WeakPtrPayloadLane<float>* CopyWeakPtrFloatPayloadRangeAdapterB(
    WeakPtrPayloadLane<float>* destination,
    const WeakPtrPayloadLane<float>* sourceEnd,
    const WeakPtrPayloadLane<float>* sourceBegin
  ) noexcept
  {
    return CopyWeakPtrFloatPayloadRange(destination, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x00629A50 (FUN_00629A50)
   *
   * What it does:
   * Third register-shape adapter lane that forwards one weak-float payload
   * range copy into `CopyWeakPtrFloatPayloadRange`.
   */
  [[maybe_unused]] [[nodiscard]] inline WeakPtrPayloadLane<float>* CopyWeakPtrFloatPayloadRangeAdapterC(
    WeakPtrPayloadLane<float>* destination,
    const WeakPtrPayloadLane<float>* sourceEnd,
    const WeakPtrPayloadLane<float>* sourceBegin
  ) noexcept
  {
    return CopyWeakPtrFloatPayloadRange(destination, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x0062A400 (FUN_0062A400)
   *
   * What it does:
   * Copies one contiguous weak-link + float-payload range
   * `[sourceBegin, sourceEnd)` into destination storage and relinks each copied
   * weak node into the source owner-chain head.
   */
  [[nodiscard]] inline WeakPtrPayloadLane<float>* CopyWeakPtrFloatPayloadRangeStdOrder(
    WeakPtrPayloadLane<float>* destination,
    const WeakPtrPayloadLane<float>* sourceBegin,
    const WeakPtrPayloadLane<float>* sourceEnd
  ) noexcept
  {
    return CopyWeakPtrPayloadRangeCore(destination, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x006281D0 (FUN_006281D0)
   *
   * What it does:
   * Register-shape adapter that forwards one source-first weak-float payload
   * copy range through `FUN_0062A400`.
   */
  [[maybe_unused]] [[nodiscard]] inline WeakPtrPayloadLane<float>* CopyWeakPtrFloatPayloadRangeStdOrderAdapterA(
    const WeakPtrPayloadLane<float>* sourceBegin,
    const WeakPtrPayloadLane<float>* sourceEnd,
    WeakPtrPayloadLane<float>* destination
  ) noexcept
  {
    return CopyWeakPtrFloatPayloadRangeStdOrder(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x00628B20 (FUN_00628B20)
   *
   * What it does:
   * Mirrored register-shape adapter for source-first weak-float payload range
   * copies through `FUN_0062A400`.
   */
  [[maybe_unused]] [[nodiscard]] inline WeakPtrPayloadLane<float>* CopyWeakPtrFloatPayloadRangeStdOrderAdapterB(
    const WeakPtrPayloadLane<float>* sourceBegin,
    const WeakPtrPayloadLane<float>* sourceEnd,
    WeakPtrPayloadLane<float>* destination
  ) noexcept
  {
    return CopyWeakPtrFloatPayloadRangeStdOrder(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x00629A20 (FUN_00629A20)
   *
   * What it does:
   * Mirrored register-shape adapter for source-first weak-float payload range
   * copies through `FUN_0062A400`.
   */
  [[maybe_unused]] [[nodiscard]] inline WeakPtrPayloadLane<float>* CopyWeakPtrFloatPayloadRangeStdOrderAdapterC(
    const WeakPtrPayloadLane<float>* sourceBegin,
    const WeakPtrPayloadLane<float>* sourceEnd,
    WeakPtrPayloadLane<float>* destination
  ) noexcept
  {
    return CopyWeakPtrFloatPayloadRangeStdOrder(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x00629EC0 (FUN_00629EC0)
   *
   * What it does:
   * Mirrored register-shape adapter for source-first weak-float payload range
   * copies through `FUN_0062A400`.
   */
  [[maybe_unused]] [[nodiscard]] inline WeakPtrPayloadLane<float>* CopyWeakPtrFloatPayloadRangeStdOrderAdapterD(
    const WeakPtrPayloadLane<float>* sourceBegin,
    const WeakPtrPayloadLane<float>* sourceEnd,
    WeakPtrPayloadLane<float>* destination
  ) noexcept
  {
    return CopyWeakPtrFloatPayloadRangeStdOrder(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x006E01A0 (FUN_006E01A0)
   * Address: 0x006DDD10 (FUN_006DDD10)
   * Address: 0x006DEFC0 (FUN_006DEFC0)
   *
   * What it does:
   * Copies `[sourceBegin, sourceEnd)` weak-link lanes with one trailing
   * 32-bit payload per element and relinks each copied node into the source
   * owner chain head.
   */
  [[nodiscard]] inline WeakPtrPayloadLane<std::uint32_t>* CopyWeakPtrDwordPayloadRange(
    WeakPtrPayloadLane<std::uint32_t>* destination,
    const WeakPtrPayloadLane<std::uint32_t>* sourceEnd,
    const WeakPtrPayloadLane<std::uint32_t>* sourceBegin
  ) noexcept
  {
    return CopyWeakPtrPayloadRangeCore(destination, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x006DEC90 (FUN_006DEC90)
   *
   * What it does:
   * Register-shape adapter lane that forwards one dword-payload weak range
   * copy into `CopyWeakPtrDwordPayloadRange`.
   */
  [[nodiscard]] inline WeakPtrPayloadLane<std::uint32_t>* CopyWeakPtrDwordPayloadRangeAdapterA(
    WeakPtrPayloadLane<std::uint32_t>* destination,
    const WeakPtrPayloadLane<std::uint32_t>* sourceEnd,
    const WeakPtrPayloadLane<std::uint32_t>* sourceBegin
  ) noexcept
  {
    return CopyWeakPtrDwordPayloadRange(destination, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x006DFB40 (FUN_006DFB40)
   *
   * What it does:
   * Register-shape adapter lane that forwards one dword-payload weak range
   * copy into `CopyWeakPtrDwordPayloadRange`.
   */
  [[nodiscard]] inline WeakPtrPayloadLane<std::uint32_t>* CopyWeakPtrDwordPayloadRangeAdapterB(
    WeakPtrPayloadLane<std::uint32_t>* destination,
    const WeakPtrPayloadLane<std::uint32_t>* sourceEnd,
    const WeakPtrPayloadLane<std::uint32_t>* sourceBegin
  ) noexcept
  {
    return CopyWeakPtrDwordPayloadRange(destination, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x006E04C0 (FUN_006E04C0)
   *
   * What it does:
   * Copies one contiguous weak-link + dword-payload range
   * `[sourceBegin, sourceEnd)` into destination storage and relinks each copied
   * weak node into the source owner-chain head.
   */
  [[nodiscard]] inline WeakPtrPayloadLane<std::uint32_t>* CopyWeakPtrDwordPayloadRangeStdOrder(
    WeakPtrPayloadLane<std::uint32_t>* destination,
    const WeakPtrPayloadLane<std::uint32_t>* sourceBegin,
    const WeakPtrPayloadLane<std::uint32_t>* sourceEnd
  ) noexcept
  {
    return CopyWeakPtrPayloadRangeCore(destination, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x006DEC60 (FUN_006DEC60)
   *
   * What it does:
   * Register-shape adapter lane that forwards one standard-order dword-payload
   * weak range copy into `CopyWeakPtrDwordPayloadRangeStdOrder`.
   */
  [[nodiscard]] inline WeakPtrPayloadLane<std::uint32_t>* CopyWeakPtrDwordPayloadRangeStdOrderAdapterA(
    WeakPtrPayloadLane<std::uint32_t>* destination,
    const WeakPtrPayloadLane<std::uint32_t>* sourceBegin,
    const WeakPtrPayloadLane<std::uint32_t>* sourceEnd
  ) noexcept
  {
    return CopyWeakPtrDwordPayloadRangeStdOrder(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x006DFB10 (FUN_006DFB10)
   *
   * What it does:
   * Register-shape adapter lane that forwards one standard-order dword-payload
   * weak range copy into `CopyWeakPtrDwordPayloadRangeStdOrder`.
   */
  [[nodiscard]] inline WeakPtrPayloadLane<std::uint32_t>* CopyWeakPtrDwordPayloadRangeStdOrderAdapterB(
    WeakPtrPayloadLane<std::uint32_t>* destination,
    const WeakPtrPayloadLane<std::uint32_t>* sourceBegin,
    const WeakPtrPayloadLane<std::uint32_t>* sourceEnd
  ) noexcept
  {
    return CopyWeakPtrDwordPayloadRangeStdOrder(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x006DFFB0 (FUN_006DFFB0)
   *
   * What it does:
   * Register-shape adapter lane that forwards one standard-order dword-payload
   * weak range copy into `CopyWeakPtrDwordPayloadRangeStdOrder`.
   */
  [[nodiscard]] inline WeakPtrPayloadLane<std::uint32_t>* CopyWeakPtrDwordPayloadRangeStdOrderAdapterC(
    WeakPtrPayloadLane<std::uint32_t>* destination,
    const WeakPtrPayloadLane<std::uint32_t>* sourceBegin,
    const WeakPtrPayloadLane<std::uint32_t>* sourceEnd
  ) noexcept
  {
    return CopyWeakPtrDwordPayloadRangeStdOrder(destination, sourceBegin, sourceEnd);
  }

  inline void AssignWeakPtrLaneWithRelink(WeakPtr<void>& destination, const WeakPtr<void>& source) noexcept
  {
    if (source.ownerLinkSlot != destination.ownerLinkSlot) {
      if (destination.ownerLinkSlot != nullptr) {
        auto** cursor = reinterpret_cast<WeakPtr<void>**>(destination.ownerLinkSlot);
        while (*cursor != &destination) {
          cursor = &(*cursor)->nextInOwner;
        }
        *cursor = destination.nextInOwner;
      }

      destination.ownerLinkSlot = source.ownerLinkSlot;
      if (source.ownerLinkSlot != nullptr) {
        auto** const ownerHead = reinterpret_cast<WeakPtr<void>**>(source.ownerLinkSlot);
        destination.nextInOwner = *ownerHead;
        *ownerHead = &destination;
      } else {
        destination.nextInOwner = nullptr;
      }
    }
  }

  /**
   * Address: 0x004FAF20 (FUN_004FAF20)
   * Address: 0x005725A0 (FUN_005725A0)
   * Address: 0x00573140 (FUN_00573140)
   * Address: 0x006B2400 (FUN_006B2400)
   * Address: 0x006EC520 (FUN_006EC520)
   * Address: 0x006EB810 (FUN_006EB810)
   * Address: 0x007A5EB0 (FUN_007A5EB0)
   * Address: 0x007A6030 (FUN_007A6030)
   *
   * What it does:
   * Copy-assigns one contiguous weak-link pair range in forward order and
   * preserves intrusive owner-chain links for each destination lane.
   */
  [[nodiscard]] inline WeakPtr<void>* AssignWeakPtrRangeForward(
    WeakPtr<void>* destination,
    const WeakPtr<void>* sourceBegin,
    const WeakPtr<void>* sourceEnd
  ) noexcept
  {
    for (; sourceBegin != sourceEnd; ++sourceBegin, ++destination) {
      AssignWeakPtrLaneWithRelink(*destination, *sourceBegin);
    }
    return destination;
  }

  /**
   * Address: 0x004FA7A0 (FUN_004FA7A0)
   *
   * What it does:
   * Adapter lane that forwards one forward weak-link range assignment into
   * the canonical `AssignWeakPtrRangeForward` helper.
   */
  [[nodiscard]] inline WeakPtr<void>* AssignWeakPtrRangeForwardAdapterA(
    WeakPtr<void>* destination,
    const WeakPtr<void>* sourceBegin,
    const WeakPtr<void>* sourceEnd
  ) noexcept
  {
    return AssignWeakPtrRangeForward(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x006B13D0 (FUN_006B13D0)
   *
   * What it does:
   * Register-shape adapter lane that forwards one forward weak-link range
   * assignment into `AssignWeakPtrRangeForward`.
   */
  [[maybe_unused]] [[nodiscard]] inline WeakPtr<void>* AssignWeakPtrRangeForwardAdapterB(
    WeakPtr<void>* destination,
    const WeakPtr<void>* sourceBegin,
    const WeakPtr<void>* sourceEnd
  ) noexcept
  {
    return AssignWeakPtrRangeForward(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x004FB240 (FUN_004FB240)
   * Address: 0x008B3B90 (FUN_008B3B90)
   * Address: 0x008B81B0 (FUN_008B81B0)
   * Address: 0x008B8200 (FUN_008B8200)
   * Address: 0x004FB2B0 (FUN_004FB2B0)
   * Address: 0x005724E0 (FUN_005724E0)
   * Address: 0x00572550 (FUN_00572550)
   * Address: 0x0061CE90 (FUN_0061CE90)
   * Address: 0x0061CF00 (FUN_0061CF00)
   * Address: 0x006ED0F0 (FUN_006ED0F0)
   * Address: 0x006EC580 (FUN_006EC580)
   * Address: 0x007A6090 (FUN_007A6090)
   * Address: 0x007A6120 (FUN_007A6120)
   *
   * What it does:
   * Copy-assigns one contiguous weak-link pair range in backward order and
   * preserves intrusive owner-chain links for each destination lane.
   */
  [[nodiscard]] inline WeakPtr<void>* AssignWeakPtrRangeBackward(
    WeakPtr<void>* destinationEnd,
    const WeakPtr<void>* sourceBegin,
    const WeakPtr<void>* sourceEnd
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      --sourceEnd;
      --destinationEnd;
      AssignWeakPtrLaneWithRelink(*destinationEnd, *sourceEnd);
    }
    return destinationEnd;
  }

  /**
   * Address: 0x00628FD0 (FUN_00628FD0)
   *
   * What it does:
   * Copy-assigns one weak-link + float payload lane while preserving
   * intrusive owner-chain links for the embedded weak node.
   */
  [[nodiscard]] inline WeakPtrPayloadLane<float>* AssignWeakPtrFloatPayloadLaneWithRelink(
    WeakPtrPayloadLane<float>* const destination,
    const WeakPtrPayloadLane<float>* const source
  ) noexcept
  {
    AssignWeakPtrLaneWithRelink(destination->weak, source->weak);
    destination->payload = source->payload;
    return destination;
  }

  /**
   * Address: 0x00628B70 (FUN_00628B70)
   * Address: 0x006DECB0 (FUN_006DECB0)
   *
   * What it does:
   * Copy-assigns one contiguous weak-link + float payload range in forward
   * order and preserves intrusive owner-chain links for each destination lane.
   */
  [[nodiscard]] inline WeakPtrPayloadLane<float>* AssignWeakPtrFloatPayloadRangeForward(
    WeakPtrPayloadLane<float>* destination,
    const WeakPtrPayloadLane<float>* sourceBegin,
    const WeakPtrPayloadLane<float>* sourceEnd
  ) noexcept
  {
    for (; sourceBegin != sourceEnd; ++sourceBegin, ++destination) {
      (void)AssignWeakPtrFloatPayloadLaneWithRelink(destination, sourceBegin);
    }
    return destination;
  }

  /**
   * Address: 0x006DDD30 (FUN_006DDD30)
   * Address: 0x006807A0 (FUN_006807A0)
   *
   * What it does:
   * Jump-thunk alias for forward weak-float payload range assignment.
   */
  [[maybe_unused]] [[nodiscard]] inline WeakPtrPayloadLane<float>* AssignWeakPtrFloatPayloadRangeForwardThunk(
    WeakPtrPayloadLane<float>* destination,
    const WeakPtrPayloadLane<float>* sourceBegin,
    const WeakPtrPayloadLane<float>* sourceEnd
  ) noexcept
  {
    return AssignWeakPtrFloatPayloadRangeForward(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x00628220 (FUN_00628220)
   *
   * What it does:
   * Jump-thunk adapter that forwards one float-payload weak range assignment
   * lane to `FUN_00628B70`.
   */
  [[maybe_unused]] [[nodiscard]] inline WeakPtrPayloadLane<float>* AssignWeakPtrFloatPayloadRangeForwardAdapterA(
    WeakPtrPayloadLane<float>* destination,
    const WeakPtrPayloadLane<float>* sourceBegin,
    const WeakPtrPayloadLane<float>* sourceEnd
  ) noexcept
  {
    return AssignWeakPtrFloatPayloadRangeForward(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x00629A70 (FUN_00629A70)
   * Address: 0x006DFB60 (FUN_006DFB60)
   *
   * What it does:
   * Copy-assigns one contiguous weak-link + float payload range in backward
   * order and preserves intrusive owner-chain links for each destination lane.
   */
  [[nodiscard]] inline WeakPtrPayloadLane<float>* AssignWeakPtrFloatPayloadRangeBackward(
    WeakPtrPayloadLane<float>* destinationEnd,
    const WeakPtrPayloadLane<float>* sourceBegin,
    const WeakPtrPayloadLane<float>* sourceEnd
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      --sourceEnd;
      --destinationEnd;
      (void)AssignWeakPtrFloatPayloadLaneWithRelink(destinationEnd, sourceEnd);
    }
    return destinationEnd;
  }

  /**
   * Address: 0x0061CC40 (FUN_0061CC40)
   *
   * What it does:
   * Register-shape adapter lane that forwards one backward weak-link range
   * assignment into `AssignWeakPtrRangeBackward`.
   */
  [[maybe_unused]] [[nodiscard]] inline WeakPtr<void>* AssignWeakPtrRangeBackwardAdapterA(
    WeakPtr<void>* destinationEnd,
    const WeakPtr<void>* sourceBegin,
    const WeakPtr<void>* sourceEnd
  ) noexcept
  {
    return AssignWeakPtrRangeBackward(destinationEnd, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x0061CC70 (FUN_0061CC70)
   *
   * What it does:
   * Mirrored register-shape adapter lane that forwards one backward weak-link
   * range assignment into `AssignWeakPtrRangeBackward`.
   */
  [[maybe_unused]] [[nodiscard]] inline WeakPtr<void>* AssignWeakPtrRangeBackwardAdapterB(
    WeakPtr<void>* destinationEnd,
    const WeakPtr<void>* sourceBegin,
    const WeakPtr<void>* sourceEnd
  ) noexcept
  {
    return AssignWeakPtrRangeBackward(destinationEnd, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x006DDD40 (FUN_006DDD40)
   *
   * What it does:
   * Register-shape adapter lane that forwards one backward weak-float payload
   * assignment range into `AssignWeakPtrFloatPayloadRangeBackward`.
   */
  [[nodiscard]] inline WeakPtrPayloadLane<float>* AssignWeakPtrFloatPayloadRangeBackwardAdapterA(
    WeakPtrPayloadLane<float>* destinationEnd,
    const WeakPtrPayloadLane<float>* sourceBegin,
    const WeakPtrPayloadLane<float>* sourceEnd
  ) noexcept
  {
    return AssignWeakPtrFloatPayloadRangeBackward(destinationEnd, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x006DED10 (FUN_006DED10)
   *
   * What it does:
   * Register-shape adapter lane that forwards one backward weak-float payload
   * assignment range into `AssignWeakPtrFloatPayloadRangeBackward`.
   */
  [[nodiscard]] inline WeakPtrPayloadLane<float>* AssignWeakPtrFloatPayloadRangeBackwardAdapterB(
    WeakPtrPayloadLane<float>* destinationEnd,
    const WeakPtrPayloadLane<float>* sourceBegin,
    const WeakPtrPayloadLane<float>* sourceEnd
  ) noexcept
  {
    return AssignWeakPtrFloatPayloadRangeBackward(destinationEnd, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x00628230 (FUN_00628230)
   *
   * What it does:
   * Register-shape adapter lane that forwards one backward weak-float payload
   * assignment range into `AssignWeakPtrFloatPayloadRangeBackward`.
   */
  [[nodiscard]] inline WeakPtrPayloadLane<float>* AssignWeakPtrFloatPayloadRangeBackwardAdapterC(
    WeakPtrPayloadLane<float>* destinationEnd,
    const WeakPtrPayloadLane<float>* sourceBegin,
    const WeakPtrPayloadLane<float>* sourceEnd
  ) noexcept
  {
    return AssignWeakPtrFloatPayloadRangeBackward(destinationEnd, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x00628BD0 (FUN_00628BD0)
   *
   * What it does:
   * Mirrored register-shape adapter lane that forwards one backward weak-float
   * payload assignment range into `AssignWeakPtrFloatPayloadRangeBackward`.
   */
  [[nodiscard]] inline WeakPtrPayloadLane<float>* AssignWeakPtrFloatPayloadRangeBackwardAdapterD(
    WeakPtrPayloadLane<float>* destinationEnd,
    const WeakPtrPayloadLane<float>* sourceBegin,
    const WeakPtrPayloadLane<float>* sourceEnd
  ) noexcept
  {
    return AssignWeakPtrFloatPayloadRangeBackward(destinationEnd, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x006ED8E0 (FUN_006ED8E0)
   * Address: 0x006EBC10 (FUN_006EBC10)
   * Address: 0x006EC950 (FUN_006EC950)
   * Address: 0x006ED260 (FUN_006ED260)
   *
   * What it does:
   * Copies one contiguous weak-link range `[sourceBegin, sourceEnd)` into
   * destination storage and relinks each copied node into the source owner
   * chain head.
   */
  [[nodiscard]] inline WeakPtr<void>* CopyWeakPtrRangeStdOrder(
    WeakPtr<void>* destination,
    const WeakPtr<void>* sourceBegin,
    const WeakPtr<void>* sourceEnd
  ) noexcept
  {
    for (const WeakPtr<void>* source = sourceBegin; source != sourceEnd; ++source, ++destination) {
      if (destination == nullptr) {
        continue;
      }

      destination->ownerLinkSlot = source->ownerLinkSlot;
      if (source->ownerLinkSlot == nullptr) {
        destination->nextInOwner = nullptr;
      } else {
        auto** const ownerHead = reinterpret_cast<WeakPtr<void>**>(source->ownerLinkSlot);
        destination->nextInOwner = *ownerHead;
        *ownerHead = destination;
      }
    }
    return destination;
  }

  /**
   * Address: 0x006ED580 (FUN_006ED580)
   *
   * What it does:
   * Thin forwarding lane that preserves a distinct call ABI shape while
   * delegating weak-pointer range copy semantics to `FUN_006ED8E0`.
   */
  [[maybe_unused]] [[nodiscard]] inline WeakPtr<void>* CopyWeakPtrRangeStdOrderAdapter(
    WeakPtr<void>* destination,
    const WeakPtr<void>* sourceBegin,
    const WeakPtr<void>* sourceEnd
  ) noexcept
  {
    return CopyWeakPtrRangeStdOrder(destination, sourceBegin, sourceEnd);
  }

  struct PrefixedWeakPtrDwordPayloadLane
  {
    std::uint32_t prefix0;
    std::uint32_t prefix1;
    WeakPtr<void> weak;
    std::uint32_t payload;
  };

  static_assert(sizeof(PrefixedWeakPtrDwordPayloadLane) == 0x14, "PrefixedWeakPtrDwordPayloadLane size must be 0x14");

  /**
   * Address: 0x00687A70 (FUN_00687A70)
   *
   * What it does:
   * Copy-assigns one 20-byte payload lane with two leading dwords, one
   * embedded weak-link node, and one trailing dword while preserving intrusive
   * weak-owner chain semantics.
   */
  [[nodiscard]] inline PrefixedWeakPtrDwordPayloadLane* CopyPrefixedWeakPtrDwordPayloadLane(
    PrefixedWeakPtrDwordPayloadLane* const destination,
    const PrefixedWeakPtrDwordPayloadLane* const source
  ) noexcept
  {
    if (destination == nullptr || source == nullptr) {
      return destination;
    }

    destination->prefix0 = source->prefix0;
    destination->prefix1 = source->prefix1;

    if (source->weak.ownerLinkSlot != destination->weak.ownerLinkSlot) {
      if (destination->weak.ownerLinkSlot != nullptr) {
        auto** cursor = reinterpret_cast<WeakPtr<void>**>(destination->weak.ownerLinkSlot);
        while (*cursor != &destination->weak) {
          cursor = &(*cursor)->nextInOwner;
        }
        *cursor = destination->weak.nextInOwner;
      }

      destination->weak.ownerLinkSlot = source->weak.ownerLinkSlot;
      if (source->weak.ownerLinkSlot != nullptr) {
        auto** const ownerHead = reinterpret_cast<WeakPtr<void>**>(source->weak.ownerLinkSlot);
        destination->weak.nextInOwner = *ownerHead;
        *ownerHead = &destination->weak;
      } else {
        destination->weak.nextInOwner = nullptr;
      }
    }

    destination->payload = source->payload;
    return destination;
  }

  /**
   * Address: 0x00689520 (FUN_00689520)
   *
   * What it does:
   * Copies one fixed prefixed weak-payload lane into every destination lane in
   * `[destinationBegin, destinationEnd)` and returns the last written lane
   * pointer (or `sourceLane` when destination range is empty).
   */
  [[maybe_unused]] [[nodiscard]] inline PrefixedWeakPtrDwordPayloadLane* FillPrefixedWeakPtrDwordPayloadRangeFromSingleLane(
    PrefixedWeakPtrDwordPayloadLane* sourceLane,
    PrefixedWeakPtrDwordPayloadLane* destinationBegin,
    PrefixedWeakPtrDwordPayloadLane* destinationEnd
  ) noexcept
  {
    PrefixedWeakPtrDwordPayloadLane* result = sourceLane;
    for (PrefixedWeakPtrDwordPayloadLane* destination = destinationBegin; destination != destinationEnd; ++destination) {
      result = CopyPrefixedWeakPtrDwordPayloadLane(destination, sourceLane);
    }
    return result;
  }

  [[nodiscard]] inline PrefixedWeakPtrDwordPayloadLane* CopyPrefixedWeakPtrDwordPayloadRangeBackwardCore(
    PrefixedWeakPtrDwordPayloadLane* destinationEnd,
    const PrefixedWeakPtrDwordPayloadLane* sourceEnd,
    const PrefixedWeakPtrDwordPayloadLane* sourceBegin
  ) noexcept
  {
    auto* destination = destinationEnd;
    const PrefixedWeakPtrDwordPayloadLane* source = sourceEnd;
    while (source != sourceBegin) {
      --destination;
      --source;
      (void)CopyPrefixedWeakPtrDwordPayloadLane(destination, source);
    }
    return destination;
  }

  /**
   * Address: 0x00689570 (FUN_00689570)
   *
   * What it does:
   * Register-shape adapter lane for backward prefixed weak-payload range copy
   * into destination tail storage.
   */
  [[maybe_unused]] [[nodiscard]] inline PrefixedWeakPtrDwordPayloadLane* CopyPrefixedWeakPtrDwordPayloadRangeBackwardAdapterA(
    const PrefixedWeakPtrDwordPayloadLane* sourceEnd,
    PrefixedWeakPtrDwordPayloadLane* destinationEnd,
    const PrefixedWeakPtrDwordPayloadLane* sourceBegin
  ) noexcept
  {
    return CopyPrefixedWeakPtrDwordPayloadRangeBackwardCore(destinationEnd, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x006898B0 (FUN_006898B0)
   *
   * What it does:
   * Mirrored register-shape adapter lane for backward prefixed weak-payload
   * range copy into destination tail storage.
   */
  [[maybe_unused]] [[nodiscard]] inline PrefixedWeakPtrDwordPayloadLane* CopyPrefixedWeakPtrDwordPayloadRangeBackwardAdapterB(
    PrefixedWeakPtrDwordPayloadLane* destinationEnd,
    const PrefixedWeakPtrDwordPayloadLane* sourceEnd,
    const PrefixedWeakPtrDwordPayloadLane* sourceBegin
  ) noexcept
  {
    return CopyPrefixedWeakPtrDwordPayloadRangeBackwardCore(destinationEnd, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x007A5FB0 (FUN_007A5FB0)
   *
   * What it does:
   * Unlinks every weak node in `[begin, end)` from its owner chain without
   * mutating the unlinked nodes' local storage lanes.
   */
  inline void UnlinkWeakPtrRangeWithoutClearing(WeakPtr<void>* begin, WeakPtr<void>* end) noexcept
  {
    for (; begin != end; ++begin) {
      if (begin->ownerLinkSlot == nullptr) {
        continue;
      }

      auto** cursor = reinterpret_cast<WeakPtr<void>**>(begin->ownerLinkSlot);
      while (*cursor != begin) {
        cursor = &(*cursor)->nextInOwner;
      }
      *cursor = begin->nextInOwner;
    }
  }

  template <class T>
  inline WeakPtr<T>::~WeakPtr() noexcept = default;

  /**
   * Address: 0x0056AA50 (FUN_0056AA50, Moho::WeakPtr_IUnit::~WeakPtr_IUnit)
   *
   * What it does:
   * Unlinks one `WeakPtr<IUnit>` node from its owner's intrusive weak-link
   * chain without mutating the local node storage lanes.
   */
  template <>
  inline WeakPtr<IUnit>::~WeakPtr() noexcept
  {
    if (ownerLinkSlot == nullptr) {
      return;
    }

    auto** cursor = reinterpret_cast<WeakPtr<IUnit>**>(ownerLinkSlot);
    while (*cursor != this) {
      cursor = &(*cursor)->nextInOwner;
    }
    *cursor = nextInOwner;
  }

  /**
   * Address: 0x0057D4F0 (FUN_0057D4F0, Moho::WeakPtr_Unit::Set)
   *
   * What it does:
   * Rebinds one weak-unit node by unlinking from its current owner chain and
   * inserting at the head of the new owner's weak-link list.
   */
  template <>
  inline void WeakPtr<Unit>::Set(Unit* object) noexcept
  {
    void* const targetOwnerLinkSlot = EncodeOwnerLinkSlot(object);
    if (ownerLinkSlot == targetOwnerLinkSlot) {
      return;
    }

    if (ownerLinkSlot != nullptr) {
      auto** existing = reinterpret_cast<WeakPtr<Unit>**>(ownerLinkSlot);
      while (*existing != this) {
        existing = &(*existing)->nextInOwner;
      }
      *existing = nextInOwner;
    }

    ownerLinkSlot = targetOwnerLinkSlot;
    if (targetOwnerLinkSlot != nullptr) {
      auto** const ownerHead = reinterpret_cast<WeakPtr<Unit>**>(targetOwnerLinkSlot);
      nextInOwner = *ownerHead;
      *ownerHead = this;
    } else {
      nextInOwner = nullptr;
    }
  }

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

  /**
   * Address: 0x0056D3C0 (FUN_0056D3C0, sub_56D3C0)
   * Address: 0x0061CA70 (FUN_0061CA70)
   *
   * What it does:
   * Unlinks each `WeakPtr<Unit>` in [`begin`, `end`) from its owner chain by
   * replacing owner-chain references to each node with that node's `nextInOwner`.
   */
  inline void UnlinkWeakPtrUnitRange(WeakPtr<Unit>* begin, WeakPtr<Unit>* end) noexcept
  {
    while (begin != end) {
      begin->UnlinkFromOwnerChain();
      ++begin;
    }
  }

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
  /**
   * Address: 0x006EC170 (FUN_006EC170)
   *
   * What it does:
   * Finds one weak-pointer lane in `[begin, end)` whose bound object pointer
   * equals `object`, returning `end` when no match is present.
   */
  [[nodiscard]] WeakPtr<T>* FindWeakPtrObjectRange(
    WeakPtr<T>* begin,
    WeakPtr<T>* end,
    const T* object
  ) noexcept
  {
    for (WeakPtr<T>* cursor = begin; cursor != end; ++cursor) {
      if (cursor->GetObjectPtr() == object) {
        return cursor;
      }
    }
    return end;
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

    WeakPtr<T>* const match = FindWeakPtrObjectRange(view.begin, view.begin + size, object);
    if (match == view.begin + size) {
      return false;
    }

    const std::size_t index = static_cast<std::size_t>(match - view.begin);
    view.begin[index].ResetFromObject(nullptr);
    for (std::size_t j = index + 1; j < size; ++j) {
        view.begin[j - 1].ResetFromOwnerLinkSlot(view.begin[j].ownerLinkSlot);
        view.begin[j].ResetFromObject(nullptr);
    }

    view.end = view.begin + size - 1u;
    return true;
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
