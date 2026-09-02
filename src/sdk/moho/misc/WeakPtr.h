#pragma once

#include <cstddef>
#include <cstdint>
#include <new>

#include "legacy/containers/Vector.h"

// Windows GDI headers define `GetObject` as an ANSI/Unicode macro alias.
// Undefine it so intrusive weak-pointer accessors keep their intended name.
#ifdef GetObject
#undef GetObject
#endif

namespace gpg
{
  class RType;
}

namespace moho
{
  class Unit;
  class IUnit;
  class UnitWeapon;
  class UserEntity;
  class UserUnit;

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
   * `UserEntity`'s weak-link head is its `WeakObject` base's `weakLinkHead_`,
   * which sits at +0x08 because the class carries a vtable at +0x00 and the
   * IUnit-chain head at +0x04. Every avatar/creator lane in the binary decodes
   * these nodes with a literal `lea reg, [slot-8]` (0x008B2340 in the army
   * avatar scan, 0x008C0870 in `UserUnit::UpdateUnitData`).
   *
   * `UserUnit` derives from `UserEntity` at offset zero, so it shares the
   * offset.
   */
  template <>
  struct WeakPtrOwnerLinkOffset<UserEntity>
  {
    static constexpr std::uintptr_t value = 0x08;
  };

  template <>
  struct WeakPtrOwnerLinkOffset<UserUnit>
  {
    static constexpr std::uintptr_t value = 0x08;
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
    /**
     * Address: 0x006EC5B0 (FUN_006EC5B0, `FillConstructWeakPtrCUnitCommandLanes`
     * in CUnitCommandWeakPtrReflection.h/.cpp -- the `WeakPtr<CUnitCommand>`-typed
     * sibling emission of this same body)
     * Address: 0x007A5FE0 (FUN_007A5FE0, ICF twin, identical `function_sha256`
     * to FUN_006EC5B0. Reached from `GrowAndInsertInputCaptureWeakRef`
     * (`FUN_007A5A70`, UiRuntimeTypes.cpp): the reallocation branch fill-
     * constructs the staged insert value into the freshly copied buffer's
     * gap, and the in-place append-at-end branch fill-constructs it directly
     * at the old `_Mylast`.)
     * Address: 0x008B39A0 (FUN_008B39A0, `WeakPtr<UserUnit>`-typed sibling
     * emission -- `.c` decompile matches this body exactly, re-reading the
     * fixed `source.ownerLinkSlot` storage fresh every iteration and never
     * advancing the source pointer. Moved off the anonymous-namespace
     * `CopyIntrusiveLinkRangeFromOwnerSlotLane` free function in
     * `moho/containers/LegacyContainerFillLanes.cpp`, a RULE ONE reach-in
     * duplicate over an `IntrusiveLinkRuntimeView***` triple pointer that
     * modeled this exact same shape without naming `moho::WeakPtr<T>`.
     * Reached from `msvc8::vector<WeakPtr<UserUnit>>::insert`'s in-place
     * tail-shift branch -- `InsertWeakPtrVectorObjectAt` (`FUN_008B2770`)
     * and `EnsureWeakPtrVectorCapacity` (`FUN_008B2B70`) above both already
     * cite this address in their own evidence chains -- via the
     * source-first adapter below.)
     *
     * IDA signature:
     * void *__fastcall sub_7A5FE0(WeakPtr<T> *destination@<eax>,
     *                              int count@<edx>, WeakPtr<T> *source@<edi>);
     *
     * What it does:
     * Fill-constructs `count` lanes starting at `destination`, all copying
     * the same `source` node's owner-link slot and relinking each filled
     * lane at the owner-chain head. Unlike `AssignFillRange` below, this
     * assumes the destination lanes are uninitialized (no prior chain
     * membership to detach) -- the construct-into-fresh-storage half of the
     * canonical VC8 `_Insert_n`/fill-lane pair.
     */
    static WeakPtr<T>* FillConstructRange(
      WeakPtr<T>* destination, std::int32_t count, const WeakPtr<T>& source
    ) noexcept
    {
      for (; count > 0; --count, ++destination) {
        if (destination == nullptr) {
          continue;
        }

        void* const ownerLinkSlot = source.ownerLinkSlot;
        destination->ownerLinkSlot = ownerLinkSlot;
        if (ownerLinkSlot == nullptr) {
          destination->nextInOwner = nullptr;
        } else {
          auto** const ownerHead = reinterpret_cast<WeakPtr<T>**>(ownerLinkSlot);
          destination->nextInOwner = *ownerHead;
          *ownerHead = destination;
        }
      }
      return destination;
    }

    /**
     * Address: 0x008B2E20 (FUN_008B2E20)
     *
     * IDA signature:
     * void *__usercall sub_8B2E20@<eax>(void *destination@<ebx>,
     *                                    WeakPtr<T> **ownerSlotLane@<edi>,
     *                                    int count@<esi>);
     *
     * What it does:
     * Source-first register-shape adapter: forwards to `FillConstructRange`
     * above with `count` and `source` swapped back into canonical order,
     * then returns the advanced destination cursor `destination + count`
     * (the binary computes this as `&destination[2 * count]`, i.e. `count`
     * `WeakPtr<T>` elements). Moved off the anonymous-namespace
     * `CopyIntrusiveLinkRangeFromOwnerSlotLaneSourceFirstAdapterA` free
     * function in `moho/containers/LegacyContainerFillLanes.cpp`.
     */
    static WeakPtr<T>* FillConstructSourceFirstAdapterA(
      WeakPtr<T>* const destination, const WeakPtr<T>& source, const std::int32_t count
    ) noexcept
    {
      (void)FillConstructRange(destination, count, source);
      return destination + count;
    }

    /**
     * Address: 0x007A6030 (FUN_007A6030, moved off `AssignWeakPtrRangeForward`
     * in this file -- that citation was wrong. `FUN_007A6030`'s own
     * disassembly (`cmp eax,esi` / `jz done`; the loop body re-reads `[edx]`
     * for the source lane every iteration without ever advancing `edx`;
     * `eax` advances by 8 and is compared against the fixed `esi` bound) is
     * a single-source *fill*, not a two-range copy -- the source never
     * moves, only the destination does. Reached from
     * `GrowAndInsertInputCaptureWeakRef` (`FUN_007A5A70`, UiRuntimeTypes.cpp)
     * to assign the staged insert value into the single-slot gap opened by
     * that function's in-place tail-shift branch; the reallocation branch
     * and the append-at-end branch both pass an empty
     * `[destination,destinationEnd)` range here, making the call a
     * documented no-op in those two paths.
     *
     * What it does:
     * Assign-fills every lane in `[destination, destinationEnd)` from the
     * same single `source` lane via `ResetFromOwnerLinkSlot`, which detaches
     * each destination lane's previous chain membership first when it
     * differs from source's -- the assign-into-live-storage counterpart to
     * `FillConstructRange` above.
     */
    static WeakPtr<T>* AssignFillRange(
      WeakPtr<T>* destination, WeakPtr<T>* const destinationEnd, const WeakPtr<T>& source
    ) noexcept
    {
      for (; destination != destinationEnd; ++destination) {
        destination->ResetFromOwnerLinkSlot(source.ownerLinkSlot);
      }
      return destination;
    }

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

    /**
     * @warning This faults today once projectile impact scripts actually run.
     * `ownerLinkSlot` is `owner + kOwnerLinkOffset`, so a node whose owner was
     * freed without being drained dereferences into released memory here --
     * observed reading 0xF2B8458D from
     * `Projectile::~Projectile` -> `CAiTarget::~CAiTarget` ->
     * `CAiTarget::UnlinkEntityTargetRef` -> `UnlinkFromOwnerChain` -> here.
     * See [[project_onimpact_shape_and_weakptr_crash]] for the trigger.
     *
     * What is already ruled out: the drain itself is correct, and it does run.
     * `CScriptObject::~CScriptObject` calls `ClearWeakObjectChain`, whose body
     * walks the chain nulling each node's `ownerLinkSlot`/`nextInOwner` exactly
     * as `WeakObject::DetachAllWeakReferences` does. A node that had been
     * drained would leave `IsLinkedInOwnerChain()` false and return above.
     *
     * The open lead is **which** `WeakObject` subobject was drained. Entity
     * carries one at RTTI mdisp=4 inside `CScriptObject`, and `Unit.cpp:13838`
     * calls a second, duplicate `ClearWeakObjectChain` on a *different* one --
     * `static_cast<WeakObject&>(static_cast<IUnit&>(*this))`. A `WeakPtr` bound
     * to one subobject's head is not drained by the destructor that drains the
     * other, which would leave exactly this dangling slot. Confirm which head
     * `CAiTarget`'s entity ref binds to before changing anything here.
     */
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
     * Address: 0x005A6E00 (FUN_005A6E00, Moho::WeakPtr_Entity::Set)
     *
     * The compiler emits this body once per instantiation and the linker
     * leaves the copies distinct; all of the addresses above are byte-identical
     * emissions of this one function, so they resolve here rather than to
     * separate recoveries.
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
   * Address: 0x00628AE0 (FUN_00628AE0, `SPickUpInfo`'s `uninit_fill_n` --
   * repeats a SINGLE fixed source lane `count` times into destination,
   * relinking each copied node into that same source's owner chain head.
   * Reached from `PushBackSPickUpInfoWithRelink`'s `storage.push_back(element)`
   * (SPickUpInfoVectorReflection.cpp) via `msvc8::vector<SPickUpInfo>::
   * push_back`'s single-element uninit_fill_n(dst, 1, value) grow lane.
   * Unlike the range-copy sibling below, `source` never advances -- proven
   * by the fixed `a3` register across every loop iteration in the binary.)
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
   * Address: 0x007F3B90 (FUN_007F3B90, ICF twin of FUN_005725A0/FUN_00573140/
   *          FUN_006B2400 above -- identical `function_sha256`. Direct
   *          callers are `FUN_007F20E0` (`AssignCameraFrustumWeakRefRange`,
   *          RangeRenderer.cpp) and `FUN_007F35E0` (a genuinely-unreferenced
   *          ICF-twin fragment, `skip`, zero callers of its own).)
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
   * Address: 0x006EB820 (FUN_006EB820) - __cdecl calling-convention
   *          trampoline into 0x006ED0F0; no separate logic of its own.
   * Address: 0x006EC580 (FUN_006EC580)
   * Address: 0x007A6090 (FUN_007A6090)
   * Address: 0x007A6120 (FUN_007A6120)
   * Address: 0x007A5EC0 (FUN_007A5EC0) - __cdecl calling-convention
   *          trampoline into 0x007A6120; no separate logic of its own.
   * Address: 0x007B1740 (FUN_007B1740, ICF twin of FUN_004FB240 -- identical
   *          `function_sha256` in the namespace callgraph index. Direct
   *          callers are `FUN_007AF0B0` (`InsertUserEntityRangeIntoCameraFrustumLane`,
   *          CameraImpl.cpp) and `FUN_007B1070` (a genuinely-orphaned
   *          default-arg forwarder, zero callers of its own -- `skip`).
   *          Reached from the camera frustum lane insert's in-place
   *          tail-shift step, both branches.)
   * Address: 0x007B17B0 (FUN_007B17B0, ICF twin of FUN_004FB240 -- identical
   *          `function_sha256`. Direct callers are `FUN_007AF0B0` (same
   *          insert dispatcher as above) and `FUN_007B10A0` (sibling
   *          register-shape adapter). Reached from the same in-place
   *          tail-shift step as FUN_007B1740, a different call site within
   *          `FUN_007AF0B0`.)
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
   * Address: 0x008B7DA0 (FUN_008B7DA0, sibling emission for the
   * `UserCommandQueueEntry` instantiation -- reached from
   * `CopyQueueLinkRangeWithOwnerRelink` in UserUnit.cpp)
   * Address: 0x007A61F0 (FUN_007A61F0, separate non-ICF-folded emission of
   * the same body -- direct callers are `FUN_007A5A70` (still `blocked`,
   * two call sites) and `FUN_007A5E90`. `FUN_007A6010`/`FUN_007A6100`/
   * `FUN_007A61E1` also call it, all still `skip`/unclassified fragments in
   * the same address neighborhood.)
   * Address: 0x007A5E90 (FUN_007A5E90) - same-register-shape trampoline into
   *          0x007A61F0 immediately above; no separate logic of its own.
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
   * Address: 0x00689310 (FUN_00689310)
   *
   * What it does:
   * Constructs `count` prefixed weak-payload records from one repeated
   * source record, relinking each written record's embedded weak pointer
   * into the source's owner chain via `CopyPrefixedWeakPtrDwordPayloadLane`.
   * Count-based sibling of `FillPrefixedWeakPtrDwordPayloadRangeFromSingleLane`
   * (0x00689520 below), which takes an end-pointer instead of a count.
   */
  [[nodiscard]] inline PrefixedWeakPtrDwordPayloadLane* ConstructPrefixedWeakPtrDwordPayloadRepeated(
    PrefixedWeakPtrDwordPayloadLane* destination,
    std::uint32_t count,
    const PrefixedWeakPtrDwordPayloadLane* const source
  ) noexcept
  {
    for (; count != 0u; --count, ++destination) {
      if (destination == nullptr) {
        continue;
      }
      (void)CopyPrefixedWeakPtrDwordPayloadLane(destination, source);
    }
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
   * Address: 0x00689D70 (FUN_00689D70)
   *
   * IDA signature:
   * void *__usercall sub_689D70@<eax>(void *result@<eax>, const void *sourceBegin@<ecx>, const void *sourceEnd@<edi>);
   *
   * What it does:
   * Forward counterpart of `CopyPrefixedWeakPtrDwordPayloadRangeBackwardCore`
   * above: walks `[sourceBegin, sourceEnd)` in ascending order, copying each
   * lane into the matching destination slot via
   * `CopyPrefixedWeakPtrDwordPayloadLane` and preserving intrusive
   * weak-owner chain semantics per element exactly like that member.
   * `.asm`-confirmed field-for-field: prefix0/prefix1 direct copy, the
   * owner-chain splice (relink into the owner's weak-observer chain when
   * non-null, else clear), then the trailing payload dword -- the same
   * per-element shape `CopyPrefixedWeakPtrDwordPayloadLane` already
   * expresses, just looped. The binary carries a `destination != nullptr`
   * guard around the whole per-element body (absent from the
   * already-recovered backward core above -- different call site,
   * different codegen, not a contradiction); preserved here for binary
   * fidelity.
   *
   * Real instantiation: this exact 20-byte shape (4-byte prefix0/prefix1,
   * an embedded `WeakPtr<T>`, 4-byte trailing payload) is, field-for-field,
   * `moho::CEntityDbBoundedPropQueueNode` in `moho/entity/EntityDb.cpp`
   * (`mPriority`/`mBoundedTick`/`mOwnerLink`(`WeakPtr<Prop>`)/`mHandleId` at
   * the same four offsets as `prefix0`/`prefix1`/`weak`/`payload`) -- see
   * `Vector.h`'s `insert(const_iterator, const T&)` citation for
   * `FUN_006882E0` (`msvc8::vector<CEntityDbBoundedPropQueueNode>::insert`,
   * this function's real caller) for the full evidence chain. This file's
   * generic, less-specifically-typed `PrefixedWeakPtrDwordPayloadLane` and
   * `EntityDb.cpp`'s properly-typed `CEntityDbBoundedPropQueueNode` are two
   * independently-recovered names for the same binary object -- a
   * `Duplicate layout contract` violation predating this citation, flagged
   * here rather than silently carried forward; a dedicated pass should
   * either retype this whole `PrefixedWeakPtrDwordPayloadLane` family onto
   * `CEntityDbBoundedPropQueueNode` directly or confirm a second, distinct
   * owner actually needs the generic name kept.
   */
  [[nodiscard]] inline PrefixedWeakPtrDwordPayloadLane* CopyPrefixedWeakPtrDwordPayloadRangeForwardCore(
    PrefixedWeakPtrDwordPayloadLane* destinationBegin,
    const PrefixedWeakPtrDwordPayloadLane* sourceBegin,
    const PrefixedWeakPtrDwordPayloadLane* sourceEnd
  ) noexcept
  {
    auto* destination = destinationBegin;
    for (const PrefixedWeakPtrDwordPayloadLane* source = sourceBegin; source != sourceEnd; ++source, ++destination) {
      if (destination != nullptr) {
        (void)CopyPrefixedWeakPtrDwordPayloadLane(destination, source);
      }
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

  /**
   * Address: 0x008B2B70 (FUN_008B2B70, msvc8::vector<Moho::WeakPtr<UserUnit>>
   * ::insert(pos, 1, value) for the 8-byte `WeakPtr<T>` element -- the real
   * `_Insert_n` shape: max_size guard (`0x1FFFFFFF`), in-place tail-shift
   * when capacity allows (`sub_8B39A0`), else VC8's real 1.5x growth
   * (`(cap>>1)+cap`, floored to `size+1` when that's not enough --
   * `msvc8::vector<T>::recommended_capacity()`'s own formula, reused below
   * rather than re-derived, since this element's move-with-relink semantics
   * don't go through `Vector.h`'s generic `reallocate_to`) followed by an
   * allocate (`sub_8B3700`), head/gap/tail relocate
   * (`sub_8B39A0`/`sub_8B3D30`), and old-block release. The capacity-growth
   * divergence this citation caught (this function was doubling from a
   * capacity-4 floor; the binary grows 1.5x from an exact-fit-at-1 floor,
   * matching every other `_Insert_n` in this codebase) is fixed below by
   * calling `recommended_capacity()` directly instead of re-deriving the
   * formula. Reached from `Moho::AddArmyAvatar` (FUN_008B2300,
   * UserUnit.cpp) via `InsertWeakPtrVectorObjectAt`.
   */
  template <class T>
  void EnsureWeakPtrVectorCapacity(msvc8::vector<WeakPtr<T>>& weakVector, const std::size_t requiredCount)
  {
    auto& view = AsWeakPtrVectorRuntimeView(weakVector);

    const std::size_t size = view.begin ? static_cast<std::size_t>(view.end - view.begin) : 0u;
    const std::size_t capacity = view.begin ? static_cast<std::size_t>(view.capacityEnd - view.begin) : 0u;
    if (requiredCount <= capacity) {
      return;
    }

    const std::size_t newCapacity = weakVector.recommended_capacity(requiredCount);

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

  /**
   * Address: 0x00599530 (FUN_00599530, msvc8::vector<WeakPtr<CUnitCommand>>::size)
   *
   * What it does:
   * `(view.end - view.begin) / sizeof(WeakPtr<T>)` - the binary emits this
   * out of line for `WeakPtr<CUnitCommand>` and calls it from
   * `CUnitCommand::AddUnit` by way of this helper; the same
   * `view.end - view.begin` computation is inlined at each of this file's
   * other `WeakPtrVectorRuntimeView` accessors (`EnsureWeakPtrVectorCapacity`,
   * `InsertWeakPtrVectorObjectAt`, `RemoveWeakPtrVectorObject`) rather than
   * calling a shared helper.
   */
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

  /**
   * Address: 0x008B2770 (FUN_008B2770, msvc8::vector<Moho::WeakPtr<UserUnit>>
   * ::push_back's fast-path append -- the sibling emission of the grow lane
   * described above (FUN_008B2B70); AddArmyAvatar's InsertWeakPtrVectorObjectAt
   * call below covers this address's index==size() behavior byte-for-byte.
   *
   * Re-verified directly from FUN_008B2770.asm and FUN_008B2B70.asm (its
   * general insert(pos,1,value), in-place/capacity-sufficient branch at
   * loc_8B2D40) to resolve a divergence a prior pass flagged but did not fix:
   *   - append (pos==end): both FUN_008B2770's fast path and FUN_008B2B70's
   *     own tailCount==0 fallback construct the slot via FUN_008B39A0 -- an
   *     unconditional 2-word write, no read of the slot's prior contents.
   *   - mid-insert (pos!=end, tailCount>=1): FUN_008B3630 -> FUN_008B3D30
   *     fill-*constructs* the freshly-grown tail slot begin[size] from
   *     begin[size-1] (same no-read-before-write shape as FUN_008B39A0;
   *     confirmed from FUN_008B3D30.asm -- `mov ecx,[edx]; mov [eax],ecx`
   *     writes the destination unconditionally and never reads
   *     [eax]/[eax+4] first). FUN_008B3660 -> FUN_008B3B90 then
   *     back-shift-*assigns* [pos,size-1) into [pos+1,size) --
   *     FUN_008B3B90.asm DOES read [eax-8] before decrementing/overwriting,
   *     matching `AssignWeakPtrRangeBackward`'s detach-before-relink shape,
   *     correctly, since those destinations are live elements, not raw
   *     storage. FUN_008B3910 finally assigns the new value into the
   *     vacated gap at pos, matching `AssignFillRange`'s single-element
   *     read-before-write shape.
   *
   * The manual shift loop below used to run the read-before-write
   * `ResetFromOwnerLinkSlot` on the newly-grown tail slot too (loop
   * iteration i==size), and the final assign-into-clampedIndex line ran
   * unconditionally even for the append case, where clampedIndex names that
   * same uninitialized tail slot. Both are now split out as
   * `FillConstructRange` calls to match FUN_008B39A0/FUN_008B3D30; the
   * middle-shift loop and the mid-insert gap-assign already matched
   * FUN_008B3B90/FUN_008B3910's read-before-write shape and are unchanged.
   */
  template <class T>
  void InsertWeakPtrVectorObjectAt(
    msvc8::vector<WeakPtr<T>>& weakVector, T* object, const std::size_t index
  )
  {
    auto& view = AsWeakPtrVectorRuntimeView(weakVector);
    const std::size_t size = view.begin ? static_cast<std::size_t>(view.end - view.begin) : 0u;
    const std::size_t clampedIndex = index <= size ? index : size;

    EnsureWeakPtrVectorCapacity(weakVector, size + 1u);

    if (clampedIndex < size) {
      // begin[size] is freshly-grown capacity, not a live element yet:
      // fill-construct it from the current last element first (FUN_008B3D30
      // shape), then back-shift-assign the rest into place (FUN_008B3B90
      // shape, unchanged).
      (void)WeakPtr<T>::FillConstructRange(view.begin + size, 1, view.begin[size - 1]);

      for (std::size_t i = size - 1; i > clampedIndex; --i) {
        view.begin[i].ResetFromOwnerLinkSlot(view.begin[i - 1].ownerLinkSlot);
        view.begin[i - 1].ResetFromObject(nullptr);
      }

      // The vacated gap at clampedIndex is still a live (if logically
      // superseded) element, so the new value is assigned into it,
      // detaching whatever it was previously holding (FUN_008B3910 shape).
      view.begin[clampedIndex].ResetFromObject(object);
    } else {
      // Appending at the end: begin[clampedIndex] (== begin[size]) is
      // uninitialized capacity, so the new value is constructed directly,
      // matching FUN_008B2770's fast path and FUN_008B2B70's own
      // tailCount==0 fallback (both call FUN_008B39A0).
      const WeakPtr<T> stagedValue(WeakPtr<T>::EncodeOwnerLinkSlot(object), nullptr);
      (void)WeakPtr<T>::FillConstructRange(view.begin + clampedIndex, 1, stagedValue);
    }

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
