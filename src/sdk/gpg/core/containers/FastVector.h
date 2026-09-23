#pragma once

#include <algorithm>
#include <cstddef> // std::ptrdiff_t
#include <cstdint>
#include <cstring>
#include <iterator> // reverse_iterator
#include <memory>
#include <new>
#include <type_traits>

namespace gpg::core
{
  namespace detail
  {
    /**
     * Address: 0x00581270 (FUN_00581270, gpg::fastvector_Entity copy helper lane)
     * Address: 0x00822990 (FUN_00822990, gpg::fastvector_UserUnit copy helper lane)
     *
     * What it does:
     * Copies one dword lane range `[sourceBegin, sourceEnd)` into `destination`
     * and returns the advanced destination pointer. When destination is null, it
     * only advances the pointer lane.
     */
    [[nodiscard]] inline std::uint32_t* CopyDwordRangeForward(
      std::uint32_t* destination,
      const std::uint32_t* sourceBegin,
      const std::uint32_t* sourceEnd
    ) noexcept
    {
      std::uintptr_t destinationAddress = reinterpret_cast<std::uintptr_t>(destination);
      for (const std::uint32_t* source = sourceBegin; source != sourceEnd; ++source) {
        if (destinationAddress != 0u) {
          *reinterpret_cast<std::uint32_t*>(destinationAddress) = *source;
        }
        destinationAddress += sizeof(std::uint32_t);
      }
      return reinterpret_cast<std::uint32_t*>(destinationAddress);
    }
  } // namespace detail

  /**
   * Element-type trait selecting the intrusive weak-ref relink lane of
   * `FastVectorN` (see the `FUN_0061C5E0` push_back / `FUN_0061C750` grow family).
   *
   * The default is `false`: ordinary trivially-relocatable and deep-copy element
   * types keep their existing `push_back` / `InsertAt` / `GrowInsert` branches
   * (byte blit or element-wise construct-assign). Only element types whose value
   * is an 8-byte intrusive weak-owner slot `{ownerLinkSlot, nextInOwner}` — where
   * appending / relocating an element must splice the slot into (or out of) the
   * pointed-at weak object's use-list rather than raw-copy the two words —
   * specialize this to `true`. `moho::SWeakRefSlot` is the sole specialization,
   * declared next to that type (see `Unit.h`).
   *
   * The trait exists because such a slot IS trivially copyable at the C++ type
   * level (two `void*`), so `std::is_trivially_copyable_v<T>` alone would route it
   * through the wrong (memmove) branch and drop the intrusive owner-chain fixups
   * the binary performs.
   */
  template <class T>
  struct IsIntrusiveWeakRefSlot : std::false_type
  {};

  // Compile-time gate for the lanes that move elements WITHOUT relinking.
  //
  // An intrusive weak-ref slot is not a value: it is a node that the owner's
  // weak-link chain points *at* by address. Copying or relocating one is only
  // correct if the node is spliced out of the chain it left and into the chain
  // at its new address -- which is why the binary emits a dedicated relinking
  // body for every operation this element type supports, and no memcpy lane at
  // all: `push_back` (FUN_0061C5E0), `InsertAt` (FUN_0061C750), the reallocate
  // arm (FUN_0061C940), `_Ucopy` (FUN_0061CA20), `_Copy_backward`
  // (FUN_0061CE90/FUN_0061CF00) and the range unlink (FUN_0061CA70). Those six
  // are the only lanes the shipped image has for this element type.
  //
  // A raw-copy lane applied to such a slot leaves the destination claiming an
  // owner whose chain never contained it. Nothing faults at that moment; the
  // damage surfaces later, in whichever unrelated walk of that owner's chain
  // runs off the end -- `moho::UnlinkWeakPtrRangeWithoutClearing` being the
  // usual victim, since its loop is the binary's own unguarded
  // `mov eax,[eax]; add eax,4; cmp [eax],ecx` (0x007A5FC0) and so cannot defend
  // itself. Diagnosing that from the crash site is near-impossible, so reject it
  // here instead: route through the relinking lane, or add the missing lane to
  // this container if the binary has an emission the template lacks -- never a
  // per-element-type copy outside the container homes (RULE ONE).

  /**
   * Typed view over an 8-byte intrusive weak-owner slot. This mirrors the
   * `moho::WeakPtr<void>` / `moho::SWeakRefSlot` layout exactly:
   *   +0x00 ownerLinkSlot : pointer to the owner object's weak-link head slot
   *                         (or null when the slot holds no live target)
   *   +0x04 nextInOwner   : intrusive next node in that owner's weak-link chain
   *
   * Using a named two-field view (rather than raw `void**` arithmetic) keeps the
   * intrusive relink lane free of offset magic while still matching the binary's
   * `*slot = target; slot[1] = *target; *target = slot` splice sequence.
   */
  struct IntrusiveWeakLinkNode
  {
    void* ownerLinkSlot;
    void* nextInOwner;
  };
  static_assert(sizeof(IntrusiveWeakLinkNode) == 0x08, "IntrusiveWeakLinkNode must be 8 bytes");

  namespace detail
  {
    /**
     * Address: 0x0061CA20 (FUN_0061CA20, weak-ref slot copy-construct + relink lane)
     *
     * What it does:
     * Copy-CONSTRUCTS the intrusive weak-ref slot range `[sourceBegin, sourceEnd)`
     * into raw storage at `destination`, relinking each freshly written slot into
     * its target's weak-owner chain head. Mirrors the binary's per-slot sequence
     * `*dst = *src; if (*src) { dst[1] = *(*src); *(*src) = dst; } else dst[1] = 0`
     * with an 8-byte element stride. Advances without writing when
     * `destination == nullptr`, matching the binary's null-guarded lane. This is
     * the `_Ucopy` analogue used by the weak-ref grow path (FUN_0061C940).
     */
    inline IntrusiveWeakLinkNode* CopyIntrusiveWeakRefRangeRelink(
      IntrusiveWeakLinkNode* destination,
      const IntrusiveWeakLinkNode* sourceBegin,
      const IntrusiveWeakLinkNode* sourceEnd
    ) noexcept
    {
      for (const IntrusiveWeakLinkNode* source = sourceBegin; source != sourceEnd; ++source, ++destination) {
        if (destination == nullptr) {
          continue;
        }

        void* const ownerLinkSlot = source->ownerLinkSlot;
        destination->ownerLinkSlot = ownerLinkSlot;
        if (ownerLinkSlot == nullptr) {
          destination->nextInOwner = nullptr;
        } else {
          auto** const ownerHead = reinterpret_cast<IntrusiveWeakLinkNode**>(ownerLinkSlot);
          destination->nextInOwner = *ownerHead;
          *ownerHead = destination;
        }
      }
      return destination;
    }

    /**
     * Address: 0x0061CE90 (FUN_0061CE90, weak-ref slot assign-over-live + relink, backward)
     * Address: 0x0061CF00 (FUN_0061CF00, ICF twin of FUN_0061CE90)
     *
     * What it does:
     * Copy-ASSIGNS the intrusive weak-ref slot range `[sourceBegin, sourceEnd)`
     * into destination slots that already hold live nodes, walking backward so an
     * overlapping upward shift stays correct. For each slot whose target changes,
     * it first splices the destination's old node out of its previous owner chain,
     * then relinks the new target at that owner's head. Mirrors the binary's
     * `std::_Copy_backward`-shaped relink loop. (These two addresses are shared
     * with `moho::AssignWeakPtrRangeBackward`; the body is identical.)
     */
    inline IntrusiveWeakLinkNode* AssignIntrusiveWeakRefRangeBackwardRelink(
      IntrusiveWeakLinkNode* destinationEnd,
      const IntrusiveWeakLinkNode* sourceBegin,
      const IntrusiveWeakLinkNode* sourceEnd
    ) noexcept
    {
      while (sourceBegin != sourceEnd) {
        --sourceEnd;
        --destinationEnd;

        void* const newOwnerLinkSlot = sourceEnd->ownerLinkSlot;
        if (destinationEnd->ownerLinkSlot != newOwnerLinkSlot) {
          if (destinationEnd->ownerLinkSlot != nullptr) {
            auto** cursor = reinterpret_cast<IntrusiveWeakLinkNode**>(destinationEnd->ownerLinkSlot);
            while (*cursor != destinationEnd) {
              cursor = reinterpret_cast<IntrusiveWeakLinkNode**>(&(*cursor)->nextInOwner);
            }
            *cursor = static_cast<IntrusiveWeakLinkNode*>(destinationEnd->nextInOwner);
          }

          destinationEnd->ownerLinkSlot = newOwnerLinkSlot;
          if (newOwnerLinkSlot == nullptr) {
            destinationEnd->nextInOwner = nullptr;
          } else {
            auto** const ownerHead = reinterpret_cast<IntrusiveWeakLinkNode**>(newOwnerLinkSlot);
            destinationEnd->nextInOwner = *ownerHead;
            *ownerHead = destinationEnd;
          }
        }
      }
      return destinationEnd;
    }

    /**
     * Address: 0x0061CA70 (FUN_0061CA70, weak-ref slot range unlink lane)
     * Address: 0x007AF240 (FUN_007AF240, the same body emitted for
     *          `moho::CameraUserEntityWeakRef`, used by the camera's three
     *          frustum lanes)
     * Address: inlined at 0x007EEB21..0x007EEB40 in `RangeRenderer::Render`
     *          (FUN_007EEA00), where it is the unlink half of the stack
     *          snapshot lane's destructor
     *
     * What it does:
     * Unlinks every intrusive weak-ref slot in `[begin, end)` from its owner's
     * weak-link chain by replacing the owner-chain reference to each node with
     * that node's `nextInOwner`, WITHOUT clearing the unlinked node's own storage.
     * Mirrors the binary's `mov [eax], [ecx+4]` splice loop. (Shared with
     * `moho::UnlinkWeakPtrUnitRange`.)
     */
    inline void UnlinkIntrusiveWeakRefRange(IntrusiveWeakLinkNode* begin, IntrusiveWeakLinkNode* end) noexcept
    {
      for (; begin != end; ++begin) {
        if (begin->ownerLinkSlot == nullptr) {
          continue;
        }

        auto** cursor = reinterpret_cast<IntrusiveWeakLinkNode**>(begin->ownerLinkSlot);
        while (*cursor != begin) {
          cursor = reinterpret_cast<IntrusiveWeakLinkNode**>(&(*cursor)->nextInOwner);
        }
        *cursor = static_cast<IntrusiveWeakLinkNode*>(begin->nextInOwner);
      }
    }

    /**
     * Address: 0x00562A80 (FUN_00562A80, _Copy_backward for a 152-byte element)
     *
     * IDA signature:
     * int __usercall sub_562A80@<eax>(int a1@<eax>, int a2@<ecx>, int a3@<ebx>);
     *
     * What it does:
     * Copy-assigns `[first, last)` backward into the range ending at
     * `resultLast`, returning the lowest destination written. Backward order is
     * what makes an overlapping right-shift safe.
     *
     * Assignment, not construction: the destination slots already hold live
     * objects. The 0x00562A80 emission is for `T = Moho::UnitWeaponInfo` and
     * calls its operator= (0x0055F210) per element, which is why a byte-wise
     * move is wrong for that T - it owns two msvc8::string members.
     */
    template <class T>
    T* CopyBackwardAssign(const T* last, T* resultLast, const T* first)
    {
      while (last != first) {
        --last;
        --resultLast;
        *resultLast = *last;
      }
      return resultLast;
    }

    /**
     * Element-lifetime primitives shared by `FastVector`, `FastVectorN` and the
     * runtime-view helpers below.
     *
     * The shipped `gpg::fastvector` keeps only `[start_, end_)` as live objects:
     * storage comes from a plain `operator new(count * sizeof(T))`, appended
     * elements are copy-constructed in place (`_Ucopy`), dropped elements are
     * destroyed (`_Destroy_range`) and the block goes back through
     * `operator delete`. That is what lets a non-trivial element -- a
     * `WeakPtr<T>` that splices itself into its target's chain, an
     * `SOffsetInfo` that owns a map -- live in the container with no
     * per-element bookkeeping at the call site: construction links, destruction
     * unlinks, and nothing outside `[start_, end_)` is ever an object.
     *
     * Every allocation and release in this header goes through these two
     * helpers so the block is always paired with the deallocation function it
     * came from; never mix in `new T[]` / `delete[]`, which for a non-trivially
     * destructible `T` hides an element-count cookie in front of the block.
     */
    template <class T>
    [[nodiscard]] inline T* AllocateElements(const std::size_t count)
    {
      return static_cast<T*>(::operator new(count * sizeof(T)));
    }

    template <class T>
    inline void FreeElements(T* const block) noexcept
    {
      ::operator delete(static_cast<void*>(block));
    }

    /**
     * Address: 0x0056D620 (FUN_0056D620, `_Destroy_range` for
     * `gpg::fastvector_n<Moho::SOffsetInfo, 2>` -- walks the 0x4C-byte
     * elements forward calling `~SOffsetInfo` (0x00568360) on each; reached
     * from that vector's destructor, `ResetStorageToInline` and the grow
     * lane's old-range teardown)
     * Address: 0x0056D3C0 (FUN_0056D3C0, `_Destroy_range` for
     * `gpg::fastvector_n<Moho::WeakPtr<Moho::IUnit>, 4>` -- per element the
     * inlined `~WeakPtr` splice-out of the owner chain; reached from every
     * scope exit of `CFormationInstance::PreRunScript`/`Setup`/
     * `UpdateFormation` and `CFormation::Finalize`, and from `~CFormationInstance`
     * for `mUnits`)
     *
     * What it does:
     * Destroys `[first, last)` in forward order. Nothing to do for a trivially
     * destructible element, which is the shape every POD lane compiles to.
     */
    /**
     * Address: 0x00711B80 (FUN_00711B80 -- `_Destroy_range` for `gpg::fastvector_n<moho::SCondition, 2>` (`STrigger::mConditions`, element 0x38): each `~SCondition` releases the category set's word storage; reached from `~STrigger` (0x00711A90) through `ResetStorageToInline`.)
     * Address: 0x0065F750 (FUN_0065F750 -- `_Destroy_range` for
     * `gpg::fastvector_n<moho::SEfxCurve, 21>` (`CEfxEmitter::mCurves`, element
     * 0x38): per element the inlined `~SEfxCurve`, which is `mKeys`'
     * `ResetInline_` at `+0x10` -- free when `start_ != originalVec_`, restore
     * `capacity_` from the saved sentinel, then `end_ = start_`. Reached from
     * `~CEfxEmitter` (0x0065DE4B) and from both emitter constructors'
     * `resize(21, value)`. Previously tagged `external_dependency` as an
     * "all-external-callees thunk"; its one external callee is
     * `::operator delete`, and the body is this template.)
     */
    template <class T>
    inline void DestroyRange(T* first, T* const last) noexcept
    {
      if constexpr (!std::is_trivially_destructible_v<T>) {
        for (; first != last; ++first) {
          first->~T();
        }
      }
    }

    /**
     * Address: 0x00402C20 (FUN_00402C20)
     * Address: 0x00710F70 (FUN_00710F70, the `moho::SCondition` emission --
     * emitted transitively via the insert lane from the CArmyStats
     * trigger-condition append)
     * Address: 0x0054D790 (FUN_0054D790, the `Moho::CAniPoseBone` emission --
     * that element has a user-declared copy ctor, so the reallocate path
     * copy-constructs rather than relocating bitwise)
     * Address: 0x0054DF50 (FUN_0054DF50, the forward copy-assign range lane for
     * the same element, used to rewind mLast after a shrink)
     * Address: 0x005625D0 (FUN_005625D0, the generic 4-byte emission for
     * `fastvector<WeakPtr<CUnitCommand>>`, reached from the reallocate-insert
     * instantiation cited on `FastVectorInline<T>::ReallocateInsert_` at
     * 0x00562350)
     *
     * Copy-constructs `[first, last)` into the raw storage at `dest` and returns
     * the advanced cursor (`_Ucopy`). Advances without writing when `dest` is
     * null, matching the binary's null-guarded lanes.
     *
     * This is the *uninitialised*-copy lane: every call site writes past `end_`,
     * or into storage `ReallocateInsert_` has just allocated. The destination
     * has therefore never run a constructor, so the elements must be constructed
     * here and never assigned. The `SCondition` emission (FUN_00710F70) shows
     * this explicitly -- it self-links the destination's inline sentinel
     * (`[dst+0x18..0x24] = dst+0x28`) before copying into it. Assigning instead
     * would run `BVIntSet::operator=` over garbage and `delete[]` an
     * uninitialised pointer.
     *
     * For trivially-copyable `T` this collapses to the same plain element store
     * the generic 4-byte emission (FUN_00402C20) performs.
     */
    template <class T>
    inline T* ConstructRangeForward(T* dest, const T* first, const T* const last)
    {
      for (; first != last; ++first) {
        if (dest != nullptr) {
          ::new (static_cast<void*>(dest)) T(*first);
        }
        ++dest;
      }
      return dest;
    }
  } // namespace detail

  /**
   * Three-pointer vector with raw ownership. Size math is done in bytes to avoid
   * compiler quirks and to support T=void (elem size is 1 in that case).
   */
  template <class T>
  class FastVector
  {
  protected:
    // Element size in bytes; for void treat as 1 to allow math in bytes.
    static constexpr size_t elem_ = std::is_void_v<T> ? 1 : sizeof(T);

    static size_t index_of(const T* base, const T* p) noexcept
    {
      const auto b = reinterpret_cast<const std::byte*>(base);
      const auto q = reinterpret_cast<const std::byte*>(p);
      return static_cast<size_t>(q - b) / elem_;
    }
    static T* ptr_at(T* base, const size_t idx) noexcept
    {
      auto b = reinterpret_cast<std::byte*>(base);
      return reinterpret_cast<T*>(b + idx * elem_);
    }

    /**
     * Overwrite the first `count` already-live slots from `source`. VC8 emits a
     * block move for a POD lane and an element-wise assignment loop for a value
     * type that owns storage; both shapes appear in the copy-assign emissions
     * (0x004028E0 for the 4-byte lane, 0x00553370 for 8-byte `Moho::SOCellPos`).
     */
    void AssignOverExistingPrefix_(const T* const source, const size_t count) noexcept(
      std::is_trivially_copyable_v<T>
    )
    {
      if (count == 0) {
        return;
      }
      if constexpr (std::is_trivially_copyable_v<T>) {
        std::memmove(start_, source, count * elem_);
      } else {
        for (size_t i = 0; i < count; ++i) {
          start_[i] = source[i];
        }
      }
    }

  public:
    using value_type = T;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using reference = T&;
    using const_reference = const T&;
    using pointer = T*;
    using const_pointer = const T*;
    using iterator = T*;
    using const_iterator = const T*;
    using reverse_iterator = std::reverse_iterator<iterator>;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

    T* start_{nullptr};
    T* end_{nullptr};
    T* capacity_{nullptr};

    FastVector() = default;

    /**
     * Destroys the live range and releases the block. `FastVectorN` nulls the
     * three lanes before this runs, since its block may be the inline buffer.
     */
    ~FastVector()
    {
      // See ~FastVectorInline: an intrusive weak-ref slot has to leave its
      // target's chain before its storage goes away, and DestroyRange cannot do
      // it because the slot is trivially destructible.
      if constexpr (IsIntrusiveWeakRefSlot<T>::value) {
        detail::UnlinkIntrusiveWeakRefRange(
          reinterpret_cast<IntrusiveWeakLinkNode*>(start_), reinterpret_cast<IntrusiveWeakLinkNode*>(end_)
        );
      }
      detail::DestroyRange(start_, end_);
      detail::FreeElements(start_);
    }

    /**
     * Returns number of elements.
     */
    [[nodiscard]]
    /**
     * Address: 0x00402290 (FUN_00402290, the generic 4-byte emission)
     * Address: 0x006D1A00 (FUN_006D1A00 -- out-of-line `Size()` for an 8-byte element (`(end - begin) / 8`); zero callers, unreachable.)
     * Address: 0x006D1D00 (FUN_006D1D00 -- checked-iterator distance for an 8-byte element; zero callers, unreachable.)
     * Address: 0x006D1DF0 (FUN_006D1DF0 -- a second emission of the 8-byte checked-iterator distance; zero callers, unreachable.)
     */
    size_t Size() const noexcept
    {
      const auto s = reinterpret_cast<const std::byte*>(start_);
      const auto e = reinterpret_cast<const std::byte*>(end_);
      return static_cast<size_t>(e - s) / elem_;
    }

    /**
     * Returns capacity in elements.
     */
    [[nodiscard]]
    /**
     * Address: 0x00402280 (FUN_00402280, the generic `Empty()` emission is the same shape)
     * Address: 0x006D19D0 (FUN_006D19D0 -- out-of-line `Capacity()` for an 8-byte element (`(capacity - begin) / 8`); zero callers, unreachable.)
     */
    size_t Capacity() const noexcept
    {
      const auto s = reinterpret_cast<const std::byte*>(start_);
      const auto c = reinterpret_cast<const std::byte*>(capacity_);
      return static_cast<size_t>(c - s) / elem_;
    }

    /**
     * Returns true if size == 0.
     */
    [[nodiscard]]
    bool Empty() const noexcept
    {
      return start_ == end_;
    }

    /**
     * Address: 0x00402270 (FUN_00402270, the generic 4-byte emission)
     * Address: 0x00402690 (FUN_00402690, the same body reached as the begin lane)
     * Address: 0x00402350 (FUN_00402350, the unchecked element-at lane: `begin + index`)
     * Address: 0x00402360 (FUN_00402360, its const emission)
     *
     * Returns raw data pointer (maybe null if empty and unallocated).
     */
    [[nodiscard]]
    T* Data() noexcept
    {
      return start_;
    }
    [[nodiscard]]
    const T* Data() const noexcept
    {
      return start_;
    }

    /** Random access operators (no bounds checks). */
    T& operator[](const size_t idx) noexcept
    {
      return *ptr_at(start_, idx);
    }
    const T& operator[](const size_t idx) const noexcept
    {
      return *ptr_at(const_cast<T*>(start_), idx);
    }

    /** Front/back (UB if empty; mirrors std::vector behavior without checks). */
    T& Front() noexcept
    {
      return *start_;
    }
    const T& Front() const noexcept
    {
      return *start_;
    }
    T& Back() noexcept
    {
      return *(end_ - 1);
    }
    const T& Back() const noexcept
    {
      return *(end_ - 1);
    }

    /** Iterator accessors. */
    /** begin iterator */
    iterator begin() noexcept
    {
      return start_;
    }
    /** end iterator */
    iterator end() noexcept
    {
      return end_;
    }
    /** const begin iterator */
    const_iterator begin() const noexcept
    {
      return start_;
    }
    /** const end iterator */
    const_iterator end() const noexcept
    {
      return end_;
    }
    /** cbegin iterator */
    const_iterator cbegin() const noexcept
    {
      return start_;
    }
    /** cend iterator */
    const_iterator cend() const noexcept
    {
      return end_;
    }

    /** reverse iterators */
    reverse_iterator rbegin() noexcept
    {
      return reverse_iterator(end_);
    }
    reverse_iterator rend() noexcept
    {
      return reverse_iterator(start_);
    }
    const_reverse_iterator rbegin() const noexcept
    {
      return const_reverse_iterator(end_);
    }
    const_reverse_iterator rend() const noexcept
    {
      return const_reverse_iterator(start_);
    }
    const_reverse_iterator crbegin() const noexcept
    {
      return const_reverse_iterator(end_);
    }
    const_reverse_iterator crend() const noexcept
    {
      return const_reverse_iterator(start_);
    }

    // STL-compatible aliases used by recovered runtime code.
    [[nodiscard]] size_type size() const noexcept
    {
      return Size();
    }
    [[nodiscard]] bool empty() const noexcept
    {
      return Empty();
    }
    [[nodiscard]] pointer data() noexcept
    {
      return Data();
    }
    [[nodiscard]] const_pointer data() const noexcept
    {
      return Data();
    }
    reference front() noexcept
    {
      return Front();
    }
    const_reference front() const noexcept
    {
      return Front();
    }
    reference back() noexcept
    {
      return Back();
    }
    const_reference back() const noexcept
    {
      return Back();
    }

    /**
     * Address: 0x0054CC90 (FUN_0054CC90,
     * gpg::fastvector<Moho::CAniPoseBone>::Reserve -- grows to exactly the
     * requested count through the reallocate-insert lane with a zero-length
     * insert range, so the live elements are preserved 1:1)
     * Address: 0x0067EA30 (FUN_0067EA30, gpg::fastvector<Wm3::Sphere3f>'s
     * old-range-into-new-buffer copy step for this method's 16-byte
     * `Sphere3f` instantiation (center xyz + radius, trivially copyable) --
     * a plain forward per-element 4-float copy loop, the compiled shape
     * `std::memcpy`'s trivially-copyable branch reproduces. Reached from
     * `GrowInsertSphere3fFastVector` (FUN_0067E190, recovered in Entity.cpp)
     * via `spheres.resize(targetCount, fillValue)`'s reallocation path.)
     *
     * Reserve at least n elements; does not shrink.
     */
    void Reserve(size_t n)
    {
      static_assert(
        !IsIntrusiveWeakRefSlot<T>::value,
        "FastVector<T>::Reserve relocates elements without relinking their owner chains; an intrusive "
        "weak-ref slot has to go through the relinking lane instead"
      );
      if (Capacity() >= n)
        return;
      const size_t oldSize = Size();
      T* newBuf = detail::AllocateElements<T>(n);
      // Trivially copyable path
      if constexpr (std::is_trivially_copyable_v<T>) {
        if (oldSize)
          std::memcpy(newBuf, start_, oldSize * elem_);
      } else {
        for (size_t i = 0; i < oldSize; ++i)
          ::new (static_cast<void*>(newBuf + i)) T(std::move(start_[i]));
        detail::DestroyRange(start_, end_);
      }
      detail::FreeElements(start_);
      start_ = newBuf;
      end_ = newBuf + oldSize;
      capacity_ = newBuf + n;
    }

    /**
     * Append by copy; grows capacity exponentially.
     */
    void PushBack(const T& v)
    {
      static_assert(
        !IsIntrusiveWeakRefSlot<T>::value,
        "FastVector<T>::PushBack relocates elements without relinking their owner chains; an intrusive "
        "weak-ref slot has to go through the relinking lane instead"
      );
      if (end_ == capacity_) {
        const size_t newCap = Capacity() ? Capacity() * 2 : 4;
        Reserve(newCap);
      }
      ::new (static_cast<void*>(end_)) T(v);
      ++end_;
    }

    void reserve(const size_t n)
    {
      Reserve(n);
    }
    /**
     * Address: 0x00576C80 (FUN_00576C80,
     * gpg::fastvector_n<Moho::SFormationScriptSlot, 20>::push_back -- the
     * `result.mObjs.push_back(slot)` in `Moho::FORMATION_RunScript`, one call
     * per five-element tuple the formation script returns. Reaches the grow
     * lane at 0x00576D60 when the twenty inline slots are used up.)
     * Address: 0x005B4BB0 (FUN_005B4BB0, gpg::fastvector_n<Moho::CPathPoint, 20>
     * grow lane of `nodes.push_back(point)` in Moho::CAiPathSpline::Generate,
     * element width 0x1C.)
     */
    void push_back(const value_type& v)
    {
      PushBack(v);
    }
    void clear() noexcept
    {
      Clear();
    }

    void resize(const size_t n)
    {
      // Shrinking drops the truncated tail through DestroyRange, which is a
      // no-op for an intrusive weak-ref slot -- so the dropped elements stay
      // linked in their targets' chains while end_ moves out from under them.
      // Same hole as Clear(); see the note there.
      static_assert(
        !IsIntrusiveWeakRefSlot<T>::value,
        "resize() would strand intrusive weak-ref slots in their owners' chains; "
        "unlink the truncated tail first (detail::UnlinkIntrusiveWeakRefRange), as the engine does"
      );
      const size_t current = Size();
      if (n <= current) {
        T* const newEnd = ptr_at(start_, n);
        detail::DestroyRange(newEnd, end_);
        end_ = newEnd;
        return;
      }

      Reserve(n);
      if constexpr (std::is_trivially_constructible_v<T>) {
        std::memset(ptr_at(start_, current), 0, (n - current) * elem_);
      } else {
        for (size_t i = current; i < n; ++i) {
          ::new (static_cast<void*>(start_ + i)) T();
        }
      }
      end_ = ptr_at(start_, n);
    }

    /**
     * Address: 0x00657900 (FUN_00657900 -- `resize(n, fill)` for `moho::CountedPtr<CParticleTexture>` (4-byte refcounted element): shrinking erases the tail through 0x00657DB0 (each slot's destructor releases its texture), growing reserves and copy-constructs `fill` into the new slots (each retaining the texture). Callers: the `RFastVectorType<CountedPtr<CParticleTexture>>` SerLoad 0x0065A4C0 and `SetCount`. Formerly `ResizeFastVectorCountedPtrCParticleTexture` in moho/particles/CParticleTextureCountedPtr.cpp (RULE ONE), removed 2026-09-10.)
     * Address: 0x0067C430 (FUN_0067C430 -- `resize(n, value)` itself -- trim by moving `end_` when shrinking, grow through 0x0067E190 otherwise. Reached from `Entity::GetTerrainCollisionGeom`'s `outSpheres.resize(n, Sphere3f{})` for `gpg::core::FastVector<Wm3::Sphere3f>` (the terrain-collision proxy sphere buffer `Entity::GetTerrainCollisionGeom` fills; the 16-byte element is trivially copyable); callers 0x0067AA50; formerly `ResizeTerrainCollisionSphereBuffer` in moho/entity/Entity.cpp (RULE ONE), removed 2026-09-11.)
     */
    void resize(const size_t n, const value_type& value)
    {
      // See resize(n) above: the shrink arm strands intrusive weak-ref slots.
      static_assert(
        !IsIntrusiveWeakRefSlot<T>::value,
        "resize() would strand intrusive weak-ref slots in their owners' chains; "
        "unlink the truncated tail first (detail::UnlinkIntrusiveWeakRefRange), as the engine does"
      );
      const size_t current = Size();
      if (n <= current) {
        T* const newEnd = ptr_at(start_, n);
        detail::DestroyRange(newEnd, end_);
        end_ = newEnd;
        return;
      }

      Reserve(n);
      for (size_t i = current; i < n; ++i) {
        ::new (static_cast<void*>(start_ + i)) T(value);
      }
      end_ = ptr_at(start_, n);
    }

    /**
     * Address: 0x005E8900 (FUN_005E8900 -- `erase(pos)` -- shift the tail down one slot and rewind `end_`, handing back a cursor on the same index. Reached from `SEntitySetTemplateUnit::RemoveUnit`'s `mVec.erase(it)` for `gpg::core::FastVectorN<moho::Entity*, 4>` (`SEntitySetTemplateUnit::mVec` at +0x08; the 0x10 head sits in front of its own four-slot inline block); callers 0x00608EF0; formerly `EraseEntityVectorSlotAndReturnCursor` in moho/sim/ArmyUnitSet.cpp (RULE ONE), removed 2026-09-11.)
     */
    iterator erase(iterator pos)
    {
      return erase(pos, pos + 1);
    }

    /**
     * Address: 0x0056F0A0 (FUN_0056F0A0 -- `erase(first, last)` for `gpg::fastvector_n<moho::SOffsetInfo, 2>` (`CFormationInstance::mOffsetInfo`, element 0x4C): the assign-forward shift followed by the tail destroy, reached from that vector's shrinking `Resize`.)
     * Address: 0x005716D0 (FUN_005716D0 -- the `std::copy` emission over `SOffsetInfo::operator=` that the shift loop below compiles to for that instantiation.)
     * Address: 0x0072AE40 (FUN_0072AE40 -- tail relocation of `erase` for a 4-byte element; Moves one dword range `[sourceBegin, sourceEnd)` into a destination tail ending at `destinationEnd` and returns the destination begin pointer.)
     * Address: 0x0071D450 (FUN_0071D450 -- tail relocation of `erase` for a 56-byte element (calling-convention bridge); Copies `rangeCount` trailing 56-byte lanes ending at `destinationEnd` into uninitialized storage starting at `destinationEnd`.)
     * Address: 0x00751AF0 (FUN_00751AF0 -- tail relocation of `erase` for a 40-byte element (calling-convention bridge); Copies one 40-byte lane range `[sourceBegin, sourceEnd)` into destination storage starting at `sourceEnd`.)
     * Address: 0x007535B0 (FUN_007535B0 -- tail relocation of `erase` for a 12-byte element; Copies one 12-byte tail range `[sourceCursor, owner.finish)` into `destinationBegin`, updates `owner.finish`, and stores `destinationBegin` through `outBegin`.)
     * Address: 0x00753680 (FUN_00753680 -- tail relocation of `erase` for a 40-byte element; Copies one 40-byte tail range `[sourceCursor, owner.finish)` into `destinationBegin`, updates `owner.finish`, and stores `destinationBegin` through `outBegin`.)
     * Address: 0x007654F0 (FUN_007654F0 -- tail relocation of `erase` for a 4-byte element (calling-convention bridge); Copies one dword lane range `[sourceBegin, sourceEnd)` into destination storage starting at `sourceEnd`.)
     * Address: 0x00658800 (FUN_00658800 -- the shift step of `erase(pos, end())` for `moho::CountedPtr<CParticleTexture>`: per slot a refcounted assignment (release the old texture, retain the new one) rather than a raw copy; its one caller 0x00657DB0 always passes an empty source range. Formerly `RelinkCountedTextureSlotsForward` in moho/particles/CParticleTextureCountedPtr.cpp (RULE ONE), removed 2026-09-10.)
     * Address: 0x00657DB0 (FUN_00657DB0 -- `erase(pos, end())` for `moho::CountedPtr<CParticleTexture>`: shift through 0x00658800 (always empty here), release the vacated tail, drop `end_`; the shrink arm of `resize` 0x00657900.)
     * Address: 0x00954510 (FUN_00954510 -- `FastVector<T>::erase(first, last)` for a 12-char inline-backed lane; zero callers, unreachable; formerly `FastVectorN12CharEraseRange` in gpg/core/algorithms/Cluster.cpp (RULE ONE), removed 2026-09-10.)
     */
    iterator erase(iterator first, iterator last)
    {
      // Worse than the Clear()/resize() hole: the compaction below is a
      // move-assignment per slot, which for an intrusive weak-ref slot is a
      // two-word byte copy that RELOCATES the node without re-splicing it, so
      // the target's chain is left pointing at the vacated address; the tail is
      // then dropped through DestroyRange, which does not unlink either. The
      // binary has no erase lane for this element type -- it has
      // UnlinkIntrusiveWeakRefRange (FUN_0061CA70) and the relinking
      // copy/copy_backward pair (FUN_0061CA20 / FUN_0061CE90) instead.
      static_assert(
        !IsIntrusiveWeakRefSlot<T>::value,
        "erase() would relocate intrusive weak-ref slots without relinking them; "
        "route through the relinking lanes (CopyIntrusiveWeakRefRangeRelink / "
        "AssignIntrusiveWeakRefRangeBackwardRelink) and unlink the vacated tail"
      );
      if (!first || !last || first < start_ || first > end_ || last < first || last > end_) {
        return end_;
      }
      if (first == last) {
        return first;
      }

      iterator write = first;
      iterator read = last;
      while (read != end_) {
        *write++ = std::move(*read++);
      }
      detail::DestroyRange(write, end_);
      end_ = write;
      return first;
    }

    /** Destroys every element; keeps the storage. */
    void Clear() noexcept
    {
      // An intrusive weak-ref slot cannot be dropped by a destructor pass: it
      // is trivially destructible, so `DestroyRange` below is a no-op for it
      // and every element would stay linked in its target's chain while this
      // rewinds `end_` out from under them -- the same silent stranding the
      // destructor carried until it was given an explicit unlink.
      //
      // The engine does not have a clearing lane for this element type; each
      // site open-codes the unlink first and then rewinds, which is why
      // `Unit::GetBlipsInRange` and
      // `CUnitMotion::ProcessSurfaceCollisionFromLastMove` both call
      // `UnlinkWeakPtrRangeWithoutClearing` before `ResetStorageToInline`.
      // Reject the call here rather than corrupt a chain at runtime: unlink the
      // range explicitly, then clear.
      static_assert(
        !IsIntrusiveWeakRefSlot<T>::value,
        "Clear() would strand intrusive weak-ref slots in their owners' chains; "
        "unlink the range first (detail::UnlinkIntrusiveWeakRefRange), as the engine does"
      );
      detail::DestroyRange(start_, end_);
      end_ = start_;
    }

    /**
     * Address: 0x0054C280 (FUN_0054C280,
     * gpg::fastvector<Moho::CAniPoseBone>::Resize -- the release build emits an
     * explicit reserve-to-exact-count (FUN_0054CC90) ahead of the fill on the
     * grow side, and a shrink-side end latch that is a no-op whenever the
     * target already equals mLast, which is every call site. Both fold into
     * this method.)
     * Address: 0x0054CC90 (FUN_0054CC90, that reserve-to-exact-count lane)
     * Address: 0x0054CCC0 (FUN_0054CCC0, that shrink-side end latch --
     * `if (sourceEnd != mLast) mLast = copy_assign_range(...)`)
     * Address: 0x00762120 (FUN_00762120,
     * gpg::fastvector<Moho::SAudioRequest>::Resize -- shrink rebases mLast,
     * grow ensures capacity then fills the appended slots in place)
     * Address: 0x0063C700 (FUN_0063C700, the
     * gpg::fastvector<Moho::SAniManipBinding> emission of the same)
     *
     * Resizes the logical element count, growing storage when needed and
     * filling appended slots with `fill`.
     *
     * The emitted per-element-type bodies are cited on
     * `resize(n, value)`, which is this method's
     * implementation. Only `FastVectorN` had a `Resize` until 2026-08-21,
     * so every base-`FastVector` caller in the engine reached around the
     * container through a runtime-view overlay -- see RULE ONE in
     * CLAUDE.md.
     */
    void Resize(const size_t newSize, const T& fill = T{})
    {
      resize(newSize, fill);
    }

    FastVector(const FastVector&) = delete;

    /**
     * Copy assignment.
     *
     * MSVC emits one out-of-line body per element type; the recovered
     * addresses live on `FastVectorInline<T>::AssignFrom`, whose shape this
     * operator's implementation. The shape is VC8's: when the destination is
     * already at least as long as the source, the elements are overwritten in
     * place and `mLast` is rebased; otherwise capacity is grown, the
     * overlapping prefix is overwritten, and the remainder is appended.
     *
     * This was `= delete` until 2026-08-21, which forced every caller in the
     * engine to reach around the container through
     * a runtime-view overlay -- see RULE ONE in CLAUDE.md.
     */
    FastVector& operator=(const FastVector& other)
    {
      static_assert(
        !IsIntrusiveWeakRefSlot<T>::value,
        "FastVector<T>::operator= relocates elements without relinking their owner chains; an intrusive "
        "weak-ref slot has to go through the relinking lane instead"
      );
      if (this == &other) {
        return *this;
      }

      const size_t destinationSize = Size();
      const size_t sourceSize = other.Size();

      // Fits in place: overwrite the live prefix and drop the surplus tail.
      if (destinationSize >= sourceSize) {
        AssignOverExistingPrefix_(other.start_, sourceSize);
        T* const newEnd = ptr_at(start_, sourceSize);
        detail::DestroyRange(newEnd, end_);
        end_ = newEnd;
        return *this;
      }

      // Grow first, then overwrite the overlapping prefix and copy-construct
      // the remainder into the fresh slots.
      Reserve(sourceSize);
      AssignOverExistingPrefix_(other.start_, destinationSize);
      for (size_t i = destinationSize; i < sourceSize; ++i) {
        ::new (static_cast<void*>(start_ + i)) T(other.start_[i]);
      }
      end_ = ptr_at(start_, sourceSize);
      return *this;
    }

    FastVector(FastVector&& other) noexcept
      : start_(other.start_)
      , end_(other.end_)
      , capacity_(other.capacity_)
    {
      other.start_ = other.end_ = other.capacity_ = nullptr;
    }
    FastVector& operator=(FastVector&& other) noexcept
    {
      if (this != &other) {
        detail::DestroyRange(start_, end_);
        detail::FreeElements(start_);
        start_ = other.start_;
        end_ = other.end_;
        capacity_ = other.capacity_;
        other.start_ = other.end_ = other.capacity_ = nullptr;
      }
      return *this;
    }
  };

  /**
   * The capacity-independent head of an inline-backed fast vector:
   * `{begin, end, capacityEnd, originalVec}`, 0x10 bytes. This is the shape
   * the binary hands to code that does not know `N` -- `SWeakUnitRefList`
   * (`CAiFormationDBImpl::NewFormation` reads it at +0x08 of its argument) and
   * `Unit::GuardedByList` both embed one, with their inline slot run declared
   * by the derived struct.
   *
   * `originalVec_` is the inline anchor: storage is released only when the
   * active buffer is not that anchor, and the first word of the inline window
   * holds the saved capacity sentinel so a lane that spilled to the heap can
   * find its way back. Every growing operation is overridden here because
   * `FastVector<T>`'s own `Reserve` frees `start_` unconditionally, which
   * would hand the inline window to `operator delete`.
   */
  template <class T>
  class FastVectorInline : public FastVector<T>
  {
  public:
    using value_type = T;
    using size_type = std::size_t;
    using iterator = T*;
    using const_iterator = const T*;

    T* originalVec_{nullptr}; // +0x0C

    FastVectorInline() = default;

    /**
     * Address: 0x00401DE0 (FUN_00401DE0, gpg::fastvector_n2_uint::~fastvector_n2_uint)
     *
     * What it does:
     * Destroys the live range, releases the heap block when one is active (the
     * inline buffer is never freed) and nulls the lanes so the base destructor
     * has nothing left to do.
     * Address: 0x0056B4D0 (FUN_0056B4D0 -- the destructor of `gpg::fastvector_n<moho::SOffsetInfo, 2>` (`CFormationInstance::mOffsetInfo`, element 0x4C), the element destructor the `eh vector destructor iterator` runs for `mOffsetInfo[2]` in `~CFormationInstance`.)
     */
    ~FastVectorInline()
    {
      // An intrusive weak-ref slot is a node the target's weak-link chain points
      // AT, so releasing the storage without splicing each slot out leaves the
      // target naming memory that is about to be freed -- and for a vector with
      // live inline storage, that memory is the owning frame. `DestroyRange`
      // cannot do this: the slot is two raw `void*`, hence trivially
      // destructible, so its `is_trivially_destructible_v` branch is a no-op.
      // The binary emits the unlink here for exactly that reason, as
      // `sub_61CA70` immediately before `operator delete[]`.
      if constexpr (IsIntrusiveWeakRefSlot<T>::value) {
        detail::UnlinkIntrusiveWeakRefRange(
          reinterpret_cast<IntrusiveWeakLinkNode*>(this->start_),
          reinterpret_cast<IntrusiveWeakLinkNode*>(this->end_)
        );
      }
      detail::DestroyRange(this->start_, this->end_);
      if (this->start_ && this->start_ != originalVec_) {
        detail::FreeElements(this->start_);
      }
      // Prevent Base dtor from touching inline storage
      this->start_ = this->end_ = this->capacity_ = nullptr;
    }

    FastVectorInline(const FastVectorInline&) = delete;
    FastVectorInline& operator=(const FastVectorInline&) = delete;

    /**
     * Bind the lanes to a caller-owned inline window of `count` slots. The
     * derived struct owns the storage (`FastVectorN<T, N>::inlineVec_`, or the
     * slot run an engine struct declares after this head), so binding is the
     * only thing this level can do about it.
     *
     * Address: 0x004026F0 (FUN_004026F0, the generic emission: binds all four lanes to a
     * caller-owned buffer)
     * Address: 0x0047F500 (FUN_0047F500, the n64<char> fixed-span alias lane)
     * Address: 0x00553430 (FUN_00553430 -- `BindInlineStorage` for `unsigned int`: `lea edx,[ecx+edx*4]` -- base in ECX and the slot count in EDX, the by-count form. Zero callers, unreachable; formerly `BindUIntRuntimeViewToExternalStorageLaneA` in gpg/core/containers/FastVectorUIntReflection.cpp (RULE ONE), removed 2026-09-18.)
     * Address: 0x00553500 (FUN_00553500 -- `BindInlineStorage` for `unsigned int`: an ICF-identical second emission of that by-count form. Zero callers, unreachable; formerly `BindUIntRuntimeViewToExternalStorageLaneB` in gpg/core/containers/FastVectorUIntReflection.cpp (RULE ONE), removed 2026-09-18.)
     * Address: 0x0065A340 (FUN_0065A340 -- `BindInlineStorage` for `unsigned int`: the same body with the count folded to 26 (`lea edx,[ecx+0x68]`). Zero callers, unreachable; formerly `BindDwordVectorHeaderCapacity26` in gpg/core/containers/FastVectorUIntReflection.cpp (RULE ONE), removed 2026-09-18.)
     * Address: 0x0065F380 (FUN_0065F380 -- `BindInlineStorage` for `unsigned int` with the count folded to 294. Zero callers, unreachable; formerly `BindDwordVectorHeaderCapacity294` in moho/render/EmitterTypeTypeInfo.cpp (RULE THREE), removed 2026-09-23.)
     * Address: 0x0065A350 (FUN_0065A350 -- `BindInlineStorage` for `unsigned int`: the same body with the count folded to 2 (`lea edx,[ecx+8]`). Zero callers, unreachable; formerly `BindDwordVectorHeaderCapacity2` in gpg/core/containers/FastVectorUIntReflection.cpp (RULE ONE), removed 2026-09-18.)
     */
    void BindInlineStorage(T* const storage, const size_type count) noexcept
    {
      this->start_ = storage;
      this->end_ = storage;
      this->capacity_ = storage + count;
      originalVec_ = storage;
    }

    /**
     * Returns true while the active buffer is the inline window.
     */
    [[nodiscard]] bool UsesInlineStorage() const noexcept
    {
      return this->start_ == originalVec_;
    }

    /**
     * Address: 0x004021F0 (FUN_004021F0)
     * Address: 0x004022A0 (FUN_004022A0)
     * Address: 0x008969E0 (FUN_008969E0,
     * Moho::CWldSession::ClearBuildTemplates -- the `SBuildTemplateInfo, 16>`
     * instantiation, recovered as `mBuildTemplates.ResetStorageToInline();`
     * at the call site (CWldSession.cpp).)
     * Address: 0x00561D40 (FUN_00561D40,
     * Moho::SSTIUnitVariableData::~SSTIUnitVariableData -- the
     * `UnitWeaponInfo, 1>` instantiation, recovered as
     * `mWeaponInfo.ResetStorageToInline();` at the call site (Unit.cpp).)
     *
     * What it does:
     * if heap-backed -> free heap and restore inline pointers from saved header;
     * otherwise only reset end to start.
     * Address: 0x004021F0 (FUN_004021F0, the same body reached from the clear lane)
     * Address: 0x004022A0 (FUN_004022A0, an alias emission of the same)
     * Address: 0x004E7280 (FUN_004E7280 -- reset to inline storage for a 24-byte element; Resets one 24-byte fastvector lane to its inline origin storage, releasing heap storage when the active lane is not already inline.)
     * Address: 0x0054CCF0 (FUN_0054CCF0 -- reset to inline storage for a ? element; Resets one inline-backed fastvector lane to inline storage and releases heap storage when the active lane is not already inline.)
     * Address: 0x0054D760 (FUN_0054D760 -- reset to inline storage for a ? element; Alias reset lane for the same inline-backed fastvector storage contract.)
     * Address: 0x006FD160 (FUN_006FD160 -- reset to inline storage for a ? element; Resets one inline-backed fastvector lane to inline storage and releases heap storage when the active lane is not already inline.)
     * Address: 0x006FD190 (FUN_006FD190 -- reset to inline storage for a ? element; Alias reset lane for the same inline-backed fastvector storage contract.)
     * Address: 0x0072A440 (FUN_0072A440 -- reset to inline storage for a ? element; Resets one inline-backed fastvector lane to inline storage and frees heap storage when the active lane is not already inline.)
     * Address: 0x0072A970 (FUN_0072A970 -- reset to inline storage for a ? element; Alias reset lane for the same inline-backed fastvector storage contract.)
     * Address: 0x007AE790 (FUN_007AE790 -- reset to inline storage for a ? element; Alias reset lane for the same inline-backed fastvector storage contract.)
     * Address: 0x004C7C70 (FUN_004C7C70 -- `fastvector_n<LuaPlus::LuaObject, N>::clear`: destroy every live `LuaObject`, free the heap block when the active buffer is not the inline one, rebind to the inline buffer using the saved inline capacity. Formerly `ClearAndResetLuaObjectFastVector` in lua/LuaObject.cpp (RULE ONE), removed 2026-09-10.)
     * Address: 0x0056B4B0 (FUN_0056B4B0 -- `FastVectorN<T, N>::ResetStorageToInline` for a 0x98-byte inline block; callers ; formerly `ResetInlineOffsetVectorStorageRuntime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-10.)
     * Address: 0x00954550 (FUN_00954550 -- `FastVectorInline<T>::ResetStorageToInline` for a 12-char inline-backed lane; zero callers, unreachable; formerly `FastVectorN12CharReleaseHeapStorage` in gpg/core/algorithms/Cluster.cpp (RULE ONE), removed 2026-09-10.)
     */
    void ResetStorageToInline() noexcept
    {
      ResetInline_();
    }

    /**
     * Address: 0x0070FAD0 (FUN_0070FAD0, `gpg::fastvector_SCondition::
     * insert_range` -- the ordered insert `Unit::GuardedByList` and the
     * formation weak-ref sets perform; its reallocating branch is
     * 0x00710E90, cited on `ReallocateInsert_`.)
     *
     * What it does:
     * Inserts `[first, last)` at `pos`, growing storage when the run no longer
     * fits and never freeing the inline window. Returns the new end, exactly
     * as the binary body does.
     */
    T* InsertRange(T* const pos, const T* const first, const T* const last)
    {
      static_assert(
        !IsIntrusiveWeakRefSlot<T>::value,
        "FastVectorInline<T>::InsertRange relocates elements without relinking their owner chains; an intrusive "
        "weak-ref slot has to go through the relinking lane instead"
      );
      return InsertRangeImpl_(pos, first, last);
    }

    void PushBack(const T& v)
    {
      static_assert(
        !IsIntrusiveWeakRefSlot<T>::value,
        "FastVectorInline<T>::PushBack relocates elements without relinking their owner chains; an intrusive "
        "weak-ref slot has to go through the relinking lane instead"
      );
      (void)InsertRange(this->end_, &v, &v + 1);
    }

    void push_back(const T& v)
    {
      static_assert(
        !IsIntrusiveWeakRefSlot<T>::value,
        "FastVectorInline<T>::push_back relocates elements without relinking their owner chains; an intrusive "
        "weak-ref slot has to go through the relinking lane instead"
      );
      (void)InsertRange(this->end_, &v, &v + 1);
    }

    /**
     * Address: 0x0092CCF0 (FUN_0092CCF0 -- the reallocate-and-split-copy an insert runs when the inline block is full for `gpg::core::FastVectorInline<T>` (the 0x10 `{start, end, capacity, inline}` head); callers 0x0092DAC5, 0x0092E410; formerly `ReallocateInlineBackedByteVectorWithSplitInsert` in gpg/core/algorithms/Cluster.cpp (RULE ONE), removed 2026-09-10.)
     */
    void Reserve(const size_type n)
    {
      static_assert(
        !IsIntrusiveWeakRefSlot<T>::value,
        "FastVectorInline<T>::Reserve relocates elements without relinking their owner chains; an intrusive "
        "weak-ref slot has to go through the relinking lane instead"
      );
      (void)EnsureCapacity_(n);
    }

    void reserve(const size_type n)
    {
      Reserve(n);
    }

    void resize(const size_type n)
    {
      static_assert(
        !IsIntrusiveWeakRefSlot<T>::value,
        "FastVectorInline<T>::resize relocates elements without relinking their owner chains; an intrusive "
        "weak-ref slot has to go through the relinking lane instead"
      );
      const T zeroFill{};
      ResizeFill_(zeroFill, n);
    }

    /**
     * Address: 0x009545D0 (FUN_009545D0 -- a second emission of `resize(n, value)`, for the reachability flags for `gpg::core::FastVectorInline<T>` (the 0x10 `{start, end, capacity, inline}` head); callers 0x00954650; formerly `FastVectorN12CharResize` in gpg/core/algorithms/Cluster.cpp (RULE ONE), removed 2026-09-10.)
     * Address: 0x0092E410 (FUN_0092E410 -- `resize(n, value)` for `gpg::core::FastVectorInline<T>` (the 0x10 `{start, end, capacity, inline}` head); callers 0x009310E0, 0x00954A40; formerly `ResizeInlineBackedByteVectorWithFill` in gpg/core/algorithms/Cluster.cpp (RULE ONE), removed 2026-09-10.)
     */
    void resize(const size_type n, const T& value)
    {
      static_assert(
        !IsIntrusiveWeakRefSlot<T>::value,
        "FastVectorInline<T>::resize(n, value) relocates elements without relinking their owner chains; an intrusive "
        "weak-ref slot has to go through the relinking lane instead"
      );
      ResizeFill_(value, n);
    }

  protected:
    /**
     * Rebind this container to its inline buffer (like func_Reset_fastvector_n prologue):
     * destroy the live range, release the heap block if one is active and
     * restore the inline window from its saved capacity sentinel.
     */
    void ResetInline_() noexcept
    {
      detail::DestroyRange(this->start_, this->end_);
      if (this->start_ != originalVec_) {
        detail::FreeElements(this->start_);
        this->start_ = originalVec_;
        this->capacity_ = InlineCapacityFromHeader_();
      }
      this->end_ = this->start_;
    }

    /**
     * Save inline capacity in the first pointer-sized slot of inline storage.
     * This mirrors FA/Moho fastvector_n grow helpers that write:
     *   if (start == origin) *origin = capacity;
     */
    void SaveInlineCapacity_() noexcept
    {
      if (!originalVec_) {
        return;
      }
      *reinterpret_cast<T**>(originalVec_) = this->capacity_;
    }

    T* InlineCapacityFromHeader_() const noexcept
    {
      if (!originalVec_) {
        return nullptr;
      }
      return *reinterpret_cast<T* const*>(originalVec_);
    }

    /**
     * Address: 0x004029B0 (FUN_004029B0, func_VecResize)
     * Address: 0x00562350 (FUN_00562350, fastvector<WeakPtr<CUnitCommand>> instantiation)
     * Address: 0x0056D2B0 (FUN_0056D2B0, fastvector<IUnitWeakPtr pair> instantiation)
     * Address: 0x0067E190 (FUN_0067E190, fastvector<Wm3::Sphere3f> instantiation)
     * Address: 0x0063C950 (FUN_0063C950 -- the reallocating insert (buy, copy prefix / inserted run / suffix, stamp the inline capacity sentinel or free the old block, rebase) for `moho::SAniManipBinding` (`IAniManipulator::mWatchBones`, two bindings inline); callers 0x0063C5F0, 0x0063C700, 0x0063C903; formerly `ReallocateWatchBoneStorageForInsert` in moho/animation/IAniManipulator.cpp (RULE ONE), removed 2026-09-10.)
     * Address: 0x00710E90 (FUN_00710E90, the reallocating branch of the
     * `moho::SCondition` instantiation -- sizes the new block with
     * `count * 8 - count` doubled three times, which is `count * 56`, the
     * SCondition stride; reached from `gpg::fastvector_SCondition::insert_range`
     * 0x0070FAD0.)
     * Address: 0x004026C0 (FUN_004026C0, the payload-relocation step -- moves the live
     * range to the new block and rebases `end_`)
     * Address: 0x00553A80 (FUN_00553A80, the `Moho::SOCellPos` instantiation
     * reached from the reflected `SetCount`/`SerLoad` resize at 0x005532F0.)
     *
     * Buy a `newCapacity` block, uninitialized-copy the prefix, the inserted
     * run and the suffix into it, then retire the old storage: when it was the
     * inline window the capacity sentinel is restamped rather than freed
     * (`mov eax,[esi+0xC]; cmp ecx,eax; je` at 0x00553AF8), otherwise the block
     * is released. This is the one step that distinguishes an inline-backed
     * vector from the plain heap-only `FastVector<T>`, which is why it lives
     * here and not on the base.
     */
    std::size_t ReallocateInsert_(
      T* const insertPos, const std::size_t newCapacity, const T* const sourceBegin, const T* const sourceEnd
    )
    {
      static_assert(!std::is_void_v<T>, "ReallocateInsert_ requires a concrete element type");

      T* const oldBegin = this->start_;
      T* const oldEnd = this->end_;
      T* const oldCapacityEnd = this->capacity_;

      T* const newBegin = detail::AllocateElements<T>(newCapacity);
      T* write = newBegin;

      const bool insertInsideOld = oldBegin && insertPos && insertPos >= oldBegin && insertPos <= oldEnd;
      try {
        if (insertInsideOld) {
          write = detail::ConstructRangeForward(write, oldBegin, insertPos);
        }
        write = detail::ConstructRangeForward(write, sourceBegin, sourceEnd);
        if (insertInsideOld) {
          write = detail::ConstructRangeForward(write, insertPos, oldEnd);
        }
      } catch (...) {
        detail::DestroyRange(newBegin, write);
        detail::FreeElements(newBegin);
        throw;
      }

      detail::DestroyRange(oldBegin, oldEnd);
      if (oldBegin == originalVec_) {
        if (originalVec_) {
          *reinterpret_cast<T**>(originalVec_) = oldCapacityEnd;
        }
      } else {
        detail::FreeElements(oldBegin);
      }

      this->start_ = newBegin;
      this->end_ = write;
      this->capacity_ = newBegin + newCapacity;
      return newCapacity;
    }

    /**
     * Address: 0x004026A0 (FUN_004026A0)
     *
     * Grow so at least `requiredCount` values fit, preserving the live range.
     */
    std::size_t EnsureCapacity_(const std::size_t requiredCount)
    {
      if (requiredCount > this->Capacity()) {
        (void)ReallocateInsert_(this->start_, requiredCount, this->start_, this->start_);
      }
      return requiredCount;
    }

    /**
     * Address: 0x004022D0 (FUN_004022D0, gpg::fastvector_uint_resize -- the generic 4-byte emission)
     * Address: 0x0059CE20 (FUN_0059CE20, a separate compiler-emitted inline clone of the same
     * template specialized for 4-byte pointer elements)
     * Address: 0x005532F0 (FUN_005532F0, the `Moho::SOCellPos` emission the
     * reflected `SetCount`, `SerLoad` and `Moho::CDecoder::DecodeCells` all
     * dispatch through)
     * Address: 0x0065ECE0 (FUN_0065ECE0, the 56-byte `moho::SEfxCurve` emission)
     *
     * Shrink by destroying the surplus tail, or grow by appending copies of
     * `fill` one slot at a time, advancing `end_` as each is constructed.
     */
    void ResizeFill_(const T& fill, const std::size_t newSize)
    {
      const std::size_t currentSize = this->Size();
      if (newSize <= currentSize) {
        T* const newEnd = this->start_ + newSize;
        detail::DestroyRange(newEnd, this->end_);
        this->end_ = newEnd;
        return;
      }

      (void)EnsureCapacity_(newSize);
      while (this->end_ != this->start_ + newSize) {
        ::new (static_cast<void*>(this->end_)) T(fill);
        ++this->end_;
      }
    }

    /**
     * Address: 0x004028E0 (FUN_004028E0, the 4-byte lane emission)
     * Address: 0x00561D90 (FUN_00561D90, the `gpg::fastvector_n<Moho::SSTIUnitWeaponInfoSnapshot, 1>`
     * emission -- the 0x98-byte weapon-info snapshot, stride confirmed by the three `/152` size
     * divides at 0x00561DA5/0x00561DB6/0x00561DC8 and the `152 * v3` prefix offset. Reached by
     * name from `moho::CopyFastVectorN(mWeaponInfo, other.mWeaponInfo)` in
     * `SSTIUnitVariableData::AssignFrom` (Unit.cpp).)
     * Address: 0x00553370 (FUN_00553370, the 8-byte `Moho::SOCellPos` emission:
     * element-wise assignment loops where the uint lane uses `memmove`, but the
     * same three branches -- fits-in-place forward copy, reallocating grow, then
     * copy-prefix plus tail insert. Instantiated for `SOCellPos` through
     * `FastVectorN2RebindAndCopy` at the `CopySOCellPosFastVectorN2` call in
     * `Moho::SSTICommandIssueData`'s copy constructor.)
     *
     * Copy `other`'s payload over this one. Public copy assignment stays deleted
     * because an inline-backed vector must not be assigned through a base
     * reference; the rebind helpers call this explicitly instead.
     */
  public:
    void AssignFrom(const FastVectorInline& other)
    {
      if (this == &other) {
        return;
      }

      const std::size_t destinationSize = this->Size();
      const std::size_t sourceSize = other.Size();

      if (destinationSize >= sourceSize) {
        this->AssignOverExistingPrefix_(other.start_, sourceSize);
        T* const newEnd = this->start_ + sourceSize;
        detail::DestroyRange(newEnd, this->end_);
        this->end_ = newEnd;
        return;
      }

      if (sourceSize > this->Capacity()) {
        (void)ReallocateInsert_(this->start_, sourceSize, this->start_, this->start_);
      }
      this->AssignOverExistingPrefix_(other.start_, destinationSize);
      (void)InsertRangeImpl_(this->end_, other.start_ + destinationSize, other.end_);
    }

  protected:
    /**
     * Address: 0x00402B10 (FUN_00402B10)
     * Address: 0x0092DAC5 (FUN_0092DAC5 -- the in-place arm for the byte lane)
     *
     * Insert `[sourceBegin, sourceEnd)` at `insertPos`. When the run no longer
     * fits, growth goes through `ReallocateInsert_` so the inline window is
     * never freed; otherwise the tail is opened in place. The two in-place arms
     * differ by whether the insertion reaches past the old finish, and both
     * write into already-live slots by assignment rather than a byte copy -- a
     * raw move there would duplicate owning members and then double-free them.
     */
    T* InsertRangeImpl_(T* const insertPos, const T* const sourceBegin, const T* const sourceEnd)
    {
      static_assert(!std::is_void_v<T>, "InsertRangeImpl_ requires a concrete element type");

      const std::ptrdiff_t insertCountSigned = sourceEnd - sourceBegin;
      if (insertCountSigned <= 0) {
        return this->end_;
      }

      const std::size_t insertCount = static_cast<std::size_t>(insertCountSigned);
      const std::size_t currentSize = this->Size();
      const std::size_t currentCapacity = this->Capacity();
      const std::size_t required = currentSize + insertCount;

      if (required > currentCapacity) {
        std::size_t newCapacity = currentCapacity * 2u;
        if (newCapacity < required) {
          newCapacity = required;
        }
        (void)ReallocateInsert_(insertPos, newCapacity, sourceBegin, sourceEnd);
        return this->end_;
      }

      T* const oldFinish = this->end_;
      T* const insertEnd = insertPos + insertCount;

      if (insertEnd > oldFinish) {
        // The insertion stretches past the old finish: append the suffix of the
        // inserted run, then the displaced old tail, then assign the remaining
        // source prefix over the vacated live window.
        const std::ptrdiff_t tailCount = oldFinish - insertPos;
        const T* const sourceTailBegin = sourceBegin + tailCount;
        this->end_ = detail::ConstructRangeForward(oldFinish, sourceTailBegin, sourceEnd);
        this->end_ = detail::ConstructRangeForward(this->end_, insertPos, oldFinish);

        const std::ptrdiff_t prefixCount = sourceTailBegin - sourceBegin;
        if (prefixCount > 0) {
          if constexpr (std::is_trivially_copyable_v<T>) {
            std::memmove(oldFinish - prefixCount, sourceBegin, static_cast<std::size_t>(prefixCount) * sizeof(T));
          } else {
            T* write = oldFinish - prefixCount;
            for (std::ptrdiff_t index = 0; index < prefixCount; ++index) {
              write[index] = sourceBegin[index];
            }
          }
        }
        return this->end_;
      }

      // The insertion fits entirely before the old finish: relocate the trailing
      // `insertCount` values into the appended window, shift the middle block
      // right to open the gap, then assign the source into it.
      T* const tailStart = oldFinish - static_cast<std::ptrdiff_t>(insertCount);
      this->end_ = detail::ConstructRangeForward(oldFinish, tailStart, oldFinish);

      const std::ptrdiff_t moveCount = tailStart - insertPos;
      if (moveCount > 0) {
        if constexpr (std::is_trivially_copyable_v<T>) {
          std::memmove(insertPos + insertCount, insertPos, static_cast<std::size_t>(moveCount) * sizeof(T));
        } else {
          // The binary uses a backward element-assign loop here for non-trivial
          // T (0x00562A80 for UnitWeaponInfo, calling its operator=).
          (void)detail::CopyBackwardAssign<T>(
            insertPos + moveCount, insertPos + insertCount + moveCount, insertPos
          );
        }
      }

      if constexpr (std::is_trivially_copyable_v<T>) {
        std::memmove(insertPos, sourceBegin, insertCount * sizeof(T));
      } else {
        for (std::size_t index = 0; index < insertCount; ++index) {
          insertPos[index] = sourceBegin[index];
        }
      }
      return this->end_;
    }
  };

  static_assert(sizeof(FastVectorInline<int>) == 0x10, "FastVectorInline<T> must be 0x10");

  /**
   * Small-buffer optimized vector: `FastVectorInline<T>`'s head plus the
   * inline window it anchors.
   */
  template <class T, size_t N>
  class FastVectorN : public FastVectorInline<T>
  {
    using Base = FastVectorInline<T>;

    // Element size in bytes (void is not a valid element, but keep generic math)
    static constexpr size_t ElemSize = std::is_void_v<T> ? 1 : sizeof(T);

    // Compute index of pointer p relative to base in elements
    static size_t index_of(const T* base, const T* p) noexcept
    {
      auto b = reinterpret_cast<const std::byte*>(base);
      auto q = reinterpret_cast<const std::byte*>(p);
      return static_cast<size_t>(q - b) / ElemSize;
    }

    // Get pointer at element index from base
    static T* ptr_at(T* base, size_t idx) noexcept
    {
      auto b = reinterpret_cast<std::byte*>(base);
      return reinterpret_cast<T*>(b + idx * ElemSize);
    }

  public:
    /**
     * The inline window is raw, suitably aligned storage -- not `T[N]`. Only
     * `[start_, end_)` ever holds objects, exactly as in the shipped container:
     * a slot past `end_` is bytes, whether it sits here or on the heap. That is
     * what makes non-trivial elements (`WeakPtr<T>`, `SOffsetInfo`, strings)
     * safe: an abandoned inline slot after a heap grow is not a live object
     * whose destructor would run a second time.
     */
    alignas(T) std::byte inlineVec_[N * ElemSize];

    [[nodiscard]] T* InlineStorage() noexcept
    {
      return reinterpret_cast<T*>(inlineVec_);
    }
    [[nodiscard]] const T* InlineStorage() const noexcept
    {
      return reinterpret_cast<const T*>(inlineVec_);
    }

    /**
     * Address: 0x0047EF60 (FUN_0047EF60, fastvector_n64_char ctor lane)
     * Address: 0x0047F480 (FUN_0047F480, fastvector_n64_char ctor alias lane)
     *
     * What it does:
     * Initializes vector pointer lanes to the inline storage window and
     * records inline-origin metadata.
     * Address: 0x005FBC10 (FUN_005FBC10 -- `fastvector_n<uint32, 5>` default constructor (inline storage armed); zero callers, no xrefs, unreachable from every seeded root: a linker-retained copy nothing runs.)
     * Address: 0x00605390 (FUN_00605390 -- `fastvector_n<uint32, 15>` default constructor; zero callers, no xrefs, unreachable from every seeded root: a linker-retained copy nothing runs.)
     * Address: 0x00578750 (FUN_00578750 -- `FastVectorN` constructor for a 20-byte element rebinding to a caller-provided block of `count` slots; zero callers, no xrefs, unreachable from every seeded root: a linker-retained copy nothing runs.)
     * Address: 0x005B4680 (FUN_005B4680 -- `FastVectorN` default constructor for a 0x230-byte inline block (at `this + 0x10`, or a caller-provided base); zero callers, no xrefs, unreachable from every seeded root: a linker-retained copy nothing runs.)
     * Address: 0x005B4E30 (FUN_005B4E30 -- `FastVectorN` default constructor for a 0x230-byte inline block (at `this + 0x10`, or a caller-provided base); zero callers, no xrefs, unreachable from every seeded root: a linker-retained copy nothing runs.)
     * Address: 0x0080A290 (FUN_0080A290 -- inline-storage constructor for a ? element; Initializes one inline-backed fastvector runtime view where the inline origin is embedded at `result+0x10` and capacity spans 0x445C0 bytes.)
     * Address: 0x0080EBD0 (FUN_0080EBD0 -- inline-storage constructor for a ? element; Initializes one inline-backed fastvector runtime view where the inline origin is embedded at `result+0x10` and capacity spans 0x7EF40 bytes.)
     * Address: 0x0080ED20 (FUN_0080ED20 -- inline-storage constructor for a ? element; Initializes one inline-backed fastvector runtime view where the inline origin is embedded at `result+0x10` and capacity spans 0x4E200 bytes.)
     * Address: 0x0056B610 (FUN_0056B610 -- inline-storage constructor for a ? element; Initializes one inline-backed fastvector runtime view where the inline origin is embedded at `result+0x10` and capacity spans 0x100 bytes.)
     * Address: 0x0056C5A0 (FUN_0056C5A0 -- inline-storage constructor for a ? element; Initializes one inline-backed fastvector runtime view where the inline origin is embedded at `result+0x10` and capacity spans 0x80 bytes.)
     * Address: 0x0056C740 (FUN_0056C740 -- inline-storage constructor for a ? element; Initializes one inline-backed fastvector runtime view where the inline origin is embedded at `result+0x10` and capacity spans 0x200 bytes.)
     * Address: 0x0056C880 (FUN_0056C880 -- inline-storage constructor for a ? element; Initializes one inline-backed fastvector runtime view where the inline origin is embedded at `result+0x10` and capacity spans 0x480 bytes.)
     * Address: 0x00576C00 (FUN_00576C00 -- inline-storage constructor for a ? element; Initializes one inline-backed fastvector runtime view where the inline origin is embedded at `result+0x10` and capacity spans 0x460 bytes.)
     * Address: 0x00558960 (FUN_00558960 -- inline-storage constructor for a ? element; Initializes one inline-backed fastvector runtime view where the inline origin is embedded at `result+0x10` and capacity spans 0x4 bytes.)
     * Address: 0x00558F40 (FUN_00558F40 -- inline-storage constructor for a ? element; Initializes one fastvector runtime view from caller-provided inline origin storage and sets capacity to `inlineOrigin+0x4`.)
     * Address: 0x005613C0 (FUN_005613C0 -- inline-storage constructor for a ? element; Initializes one fastvector runtime view from caller-provided inline origin storage and sets capacity to `inlineOrigin+0x20`.)
     * Address: 0x0056D260 (FUN_0056D260 -- inline-storage constructor for a ? element; Initializes one fastvector runtime view from caller-provided inline origin storage and sets capacity to `inlineOrigin+0x20`.)
     * Address: 0x00561410 (FUN_00561410 -- inline-storage constructor for a ? element; Initializes one fastvector runtime view from caller-provided inline origin storage and sets capacity to `inlineOrigin+0x98`.)
     * Address: 0x0056D5F0 (FUN_0056D5F0 -- inline-storage constructor for a ? element; Initializes one fastvector runtime view from caller-provided inline origin storage and sets capacity to `inlineOrigin+0x98`.)
     * Address: 0x0056D6E0 (FUN_0056D6E0 -- inline-storage constructor for a ? element; Initializes one fastvector runtime view from caller-provided inline origin storage and sets capacity to `inlineOrigin+0x100`.)
     * Address: 0x0056E3E0 (FUN_0056E3E0 -- inline-storage constructor for a ? element; Initializes one fastvector runtime view from caller-provided inline origin storage and sets capacity to `inlineOrigin+0x80`.)
     * Address: 0x0056E5C0 (FUN_0056E5C0 -- inline-storage constructor for a ? element; Initializes one fastvector runtime view from caller-provided inline origin storage and sets capacity to `inlineOrigin+0x200`.)
     * Address: 0x0056E780 (FUN_0056E780 -- inline-storage constructor for a ? element; Initializes one fastvector runtime view from caller-provided inline origin storage and sets capacity to `inlineOrigin+0x480`.)
     * Address: 0x00576ED0 (FUN_00576ED0 -- inline-storage constructor for a ? element; Initializes one fastvector runtime view from caller-provided inline origin storage and sets capacity to `inlineOrigin+0x460`.)
     * Address: 0x0080F030 (FUN_0080F030 -- inline-storage constructor for a ? element; Initializes one fastvector runtime view from caller-provided inline origin storage and sets capacity to `inlineOrigin+0x7EF40`.)
     * Address: 0x0080F1B0 (FUN_0080F1B0 -- inline-storage constructor for a ? element; Initializes one fastvector runtime view from caller-provided inline origin storage and sets capacity to `inlineOrigin+0x4E200`.)
     * Address: 0x0059C890 (FUN_0059C890 -- `fastvector_n<CAiFormationInstance*, 10>` default constructor. Zero callers, no xrefs, unreachable: the live instantiation is inlined into `CAiFormationDBImpl`'s constructor (visible in `CAiFormationDBImplTypeInfo::NewRef` 0x0059D390). Formerly `InitializeFormationInstanceInlineStorage` in moho/ai/CAiFormationDBImplTypeInfo.cpp (RULE ONE), removed 2026-09-10.)
     * Address: 0x0059CEB0 (FUN_0059CEB0 -- the inline-arming step of that constructor (`start_ = end_ = originalVec_ = inline; capacity_ = inline + 10`). Zero callers, no xrefs, unreachable. Formerly `BindFormationInstanceInlineRuntimeView`, removed 2026-09-10.)
     * Address: 0x00552C40 (FUN_00552C40 -- `FastVectorN<unsigned int, 2>()`: `lea ecx,[eax+0x10]; lea edx,[ecx+8]` -- inline block at this+0x10, capacity 2 words, so `start_ = end_ = originalVec_ = inline` and `capacity_ = inline + N`. Zero callers, unreachable; formerly `InitializeInlineUIntScratchViewLaneA` in gpg/core/containers/FastVectorUIntReflection.cpp (RULE ONE), removed 2026-09-18.)
     * Address: 0x00552CE0 (FUN_00552CE0 -- `FastVectorN<unsigned int, 2>()`: an ICF-identical second emission of the same 2-word constructor, so `start_ = end_ = originalVec_ = inline` and `capacity_ = inline + N`. Zero callers, unreachable; formerly `InitializeInlineUIntScratchViewLaneB` in gpg/core/containers/FastVectorUIntReflection.cpp (RULE ONE), removed 2026-09-18.)
     * Address: 0x00659980 (FUN_00659980 -- `FastVectorN<unsigned int, 26>()`: `lea ecx,[eax+0x10]; lea edx,[ecx+0x68]` -- 0x68 is 26 words, so `start_ = end_ = originalVec_ = inline` and `capacity_ = inline + N`. Zero callers, unreachable; formerly `InitializeInlineDwordVectorHeaderCapacity26` in gpg/core/containers/FastVectorUIntReflection.cpp (RULE ONE), removed 2026-09-18.)
     * Address: 0x006599A0 (FUN_006599A0 -- `FastVectorN<unsigned int, 2>()`: the 2-word emission in that same run, so `start_ = end_ = originalVec_ = inline` and `capacity_ = inline + N`. Zero callers, unreachable; formerly `InitializeInlineDwordVectorHeaderCapacity2` in gpg/core/containers/FastVectorUIntReflection.cpp (RULE ONE), removed 2026-09-18.)
     * Address: 0x0065EC00 (FUN_0065EC00 -- `FastVectorN<unsigned int, 6>()`: the 6-word emission, `start_ = end_ = originalVec_ = inline` and `capacity_ = inline + N`. Zero callers, unreachable; formerly `InitializeInlineDwordVectorHeaderCapacity6` in moho/render/EmitterTypeTypeInfo.cpp (RULE THREE), removed 2026-09-23.)
     * Address: 0x0065EC60 (FUN_0065EC60 -- `FastVectorN<unsigned int, 294>()`: the 294-word emission of the same body. Zero callers, unreachable; formerly `InitializeInlineDwordVectorHeaderCapacity294` in moho/render/EmitterTypeTypeInfo.cpp (RULE THREE), removed 2026-09-23.)
     * Address: 0x006599C0 (FUN_006599C0 -- `FastVectorN<unsigned int, 14>()`: `lea edx,[ecx+0x38]` -- 0x38 is 14 words, so `start_ = end_ = originalVec_ = inline` and `capacity_ = inline + N`. Zero callers, unreachable; formerly `InitializeInlineDwordVectorHeaderCapacity14` in gpg/core/containers/FastVectorUIntReflection.cpp (RULE ONE), removed 2026-09-18.)
     * Address: 0x0063C070 (FUN_0063C070 -- `FastVectorN<T, N>()` -- arm the lane on its inline window for `moho::SAniManipBinding` (`IAniManipulator::mWatchBones`, two bindings inline); zero callers, unreachable; formerly `InitializeWatchBoneStorageInline` in moho/animation/IAniManipulator.cpp (RULE ONE), removed 2026-09-10.)
     * Address: 0x0065DD90 (FUN_0065DD90 -- `moho::SEfxCurve::SEfxCurve()`, whose
     * only non-trivial member is `fastvector_n<Wm3::Vector3f, 2> mKeys` at
     * `+0x10`: `lea ecx,[eax+0x20]; lea edx,[ecx+0x18]` then the four stores at
     * `+0x10/+0x14/+0x18/+0x1C`. Zero callers, no xrefs: every use site inlined
     * it -- `CEfxEmitter`'s two constructors inline it for the stack-built fill
     * value at 0x0065BAE6, and `resize(21, value)` copy-constructs the rest.
     * Formerly `InitializeEmbeddedDwordVectorHeaderOffset10Capacity6` over an
     * `EmbeddedDwordVectorHeaderOffset10RuntimeView` in
     * moho/effects/rendering/CEfxEmitter.cpp (RULE ONE), removed 2026-09-22.)
     *
     * The inline-capacity sentinel is NOT written here. Every emission of this
     * constructor in the binary is exactly four stores plus `ret` -- 0x00552C40
     * and 0x006599A0 (`N=2`), 0x005FBC10 (`N=5`), 0x006599C0 (`N=14`),
     * 0x00659980 (`N=26`), 0x0063C070 and 0x0065DD90 -- and the two inlined
     * copies in `CEfxEmitter`'s constructors (0x0065B9F0, 0x0065BAC7) agree.
     * `capacity_` is already correct while the lane sits on its own window, so
     * the sentinel only has to exist once the lane abandons that window: every
     * grow path writes it on the way out (`if (start_ == originalVec_)
     * SaveInlineCapacity_()`), and `ResetInline_` reads it back only inside the
     * `start_ != originalVec_` arm. Writing it here additionally stamped a
     * pointer over the first four bytes of slot 0 of every inline-backed vector
     * in the engine -- harmless while `end_ == start_`, but not what the
     * shipped container does.
     */
    FastVectorN()
    {
      this->start_ = InlineStorage();
      this->end_ = InlineStorage();
      this->capacity_ = InlineStorage() + N;
      this->originalVec_ = InlineStorage();
    }

    /**
     * Address: 0x006E5720 (FUN_006E5720, gpg::fastvector_n<uint,4>::fastvector_n(unsigned int))
     * Mangled: ??0?$fastvector_n@I$03@gpg@@QAE@I@Z (count ctor lane)
     *
     * IDA signature:
     * gpg::fastvector_n2_uint *__stdcall sub_6E5720(gpg::fastvector_n2_uint *this, unsigned int count);
     *
     * What it does:
     * Binds all four pointer lanes to the inline storage window WITHOUT writing
     * the inline-capacity header (distinct from the default ctor), then resizes
     * the logical element count to `count`, zero-filling appended slots through
     * the shared fastvector_uint_resize helper (FUN_004022D0 =
     * ResizeFill_). This is the emitted constructor the decoder
     * uses to preallocate the raw entity-id scratch buffer.
     */
    explicit FastVectorN(std::size_t count)
    {
      RebindInlineNoFree();
      const T zeroFill{};
      this->ResizeFill_(zeroFill, count);
    }

    /**
     * Address: 0x00401DE0 (FUN_00401DE0, gpg::fastvector_n2_uint::~fastvector_n2_uint)
     *
     * What it does:
     * For `FastVectorN<unsigned int, 2>`, releases heap storage when active and
     * rebinds lanes back to inline storage metadata.
     */
    /**
     * Copies another vector's elements into this one's own storage.
     *
     * The implicitly-generated copy would duplicate the raw pointer lanes and
     * leave the copy aliasing the source's inline buffer, which dangles as
     * soon as the source dies or is relocated. Every inline-storage vector in
     * the binary rebinds to its own buffer instead (`ResetFrom`).
     */
    /**
     * Address: 0x00576C20 (FUN_00576C20,
     * gpg::fastvector_n<Moho::SFormationScriptSlot, 20>'s copy constructor --
     * the lane `Moho::FORMATION_RunScript` (0x00576690) reaches when it
     * returns `SFormationScriptResult` by value. It opens exactly as the
     * `: FastVectorN()` delegation below does, seating the three lanes on
     * `this + 0x10` and the capacity on `this + 0x10 + 0x460` -- 0x460 being
     * twenty slots of 0x38 -- and then rebinds through the uninitialised copy
     * at 0x00576F10, which is `ResetFrom`.)
     * Address: 0x00898E50 (FUN_00898E50,
     * gpg::fastvector_n<Moho::SBuildTemplateInfo, 16>'s copy constructor --
     * `Moho::CWldSession::GetActiveBuildTemplate` (0x00896A40) copy-constructs
     * its hidden-return-slot result through this lane at the true ABI level
     * (`sub_898E50(&this->mBuildTemplate, a4)`, `a4` being raw not-yet-live
     * storage there). Every recovered caller instead declares the
     * destination as an ordinary local first, so by the time
     * `GetActiveBuildTemplate` runs it is already a live, default-constructed
     * object; the recovered body therefore assigns (`*result =
     * mBuildTemplates;`, CWldSession.cpp) rather than placement-constructs,
     * reaching this same `ResetFrom` machinery through `operator=` instead
     * -- identical end state, without constructing over a live object.)
     * Address: 0x0056B200 (FUN_0056B200, sub_56B200 -- the copy constructor of `gpg::fastvector_n<moho::WeakPtr<moho::IUnit>, 4>` (`CFormationInstance::mUnits` and the formation scratch sets, element 0x08): `mUnits(units)` in `CFormationInstance::CFormationInstance` (0x005694B0); each copied `WeakPtr<IUnit>` relinks into its unit's weak chain.)
     * Address: 0x0082E5E0 (FUN_0082E5E0 -- copy constructor for a 4-byte element; Initializes one stack-style inline dword-vector scratch lane and assigns source content into that lane via `AssignDwordVectorRange`.)
     * Address: 0x0057D3F0 (FUN_0057D3F0 -- the copy constructor -- seat the three lanes plus `originalVec_` on the inline block at `this+0x10`, then `AddAll` the source; ten callers, `SEntitySetTemplateUnit`'s own copy constructor 0x00579500 among them for `gpg::core::FastVectorN<moho::Entity*, 4>` (`SEntitySetTemplateUnit::mVec` at +0x08; the 0x10 head sits in front of its own four-slot inline block); callers 0x00579500, 0x005ADC70, 0x005FA790; formerly `CopyEntityInlineVector` in moho/sim/ArmyUnitSet.cpp (RULE ONE), removed 2026-09-11.)
     */
    FastVectorN(const FastVectorN& other)
      : FastVectorN()
    {
      this->ResetFrom(other);
    }

    /**
     * Address: 0x00899790 (FUN_00899790,
     * gpg::fastvector_n<Moho::SBuildTemplateInfo, 16>::operator= -- reached
     * from `Moho::CWldSession::SetActiveBuildTemplate` (0x00896A70), recovered
     * as `mBuildTemplates = templates;` at the call site (CWldSession.cpp).
     * Self-assignment guard, then `ResetFrom` -- destroy/rebind-to-inline,
     * copy the source range.)
     *
     * Copy assignment: self-assignment guard, then reset to inline storage
     * and copy the source range (`ResetFrom`).
     * Address: 0x00752830 (FUN_00752830 -- copy assignment for a 12-byte element; Replaces destination 12-byte fastvector content with source content, reusing storage when possible and reacquiring storage when capacity is insufficient.)
     * Address: 0x00752A70 (FUN_00752A70 -- copy assignment for a 8-byte element; Replaces destination 8-byte fastvector content with source content, reusing storage when possible and reacquiring storage when capacity is insufficient.)
     * Address: 0x0065F240 (FUN_0065F240 -- copy assignment for a 12-byte element; Replaces destination 12-byte fastvector content with source content, reusing capacity when possible and growing when required.)
     * Address: 0x0082D030 (FUN_0082D030 -- copy assignment for a 4-byte element; Replaces destination 4-byte fastvector content with source content, reusing capacity when possible and growing when required.)
     */
    FastVectorN& operator=(const FastVectorN& other)
    {
      if (this != &other) {
        this->ResetFrom(other);
      }
      return *this;
    }

    /**
     * `FastVector<T>` has no move constructor of its own that is safe to
     * inherit here: it has no vtable (must stay the binary's plain
     * `{start_,end_,capacity_}` triple), so `Base(FastVector&&)` is a
     * non-virtual member that unconditionally steals `other.start_` -- for
     * an SBO source still on its OWN inline buffer, that aims this object's
     * `start_` at `other.inlineVec_`, a dangling interior pointer the
     * instant `other` is destroyed, with no allocator involved at all. Only
     * steal the pointer when the source is genuinely heap-backed; otherwise
     * fall back to a real copy (`ResetFrom`, the same machinery the copy
     * constructor above uses) exactly as `std::string`'s own SSO move
     * constructor falls back to a copy when the source is using its small
     * buffer -- there is no cheaper way to "move" data embedded inside
     * another object.
     */
    FastVectorN(FastVectorN&& other) noexcept
      : FastVectorN()
    {
      static_assert(
        !IsIntrusiveWeakRefSlot<T>::value,
        "FastVectorN<T, N>'s move constructor relocates elements without relinking their owner chains; an intrusive "
        "weak-ref slot has to go through the relinking lane instead"
      );
      if (other.start_ != other.originalVec_) {
        this->start_ = other.start_;
        this->end_ = other.end_;
        this->capacity_ = other.capacity_;
        other.RebindInlineNoFree();
      } else {
        this->ResetFrom(other);
        other.ResetInline_();
      }
    }

    /**
     * Same defect as the move constructor above, plus one more:
     * `Base::operator=(FastVector&&)` opens with a bare `delete[] start_`
     * with no check for inline storage, so assigning into an SBO vector
     * still on its own inline buffer through this inherited operator frees
     * that inline buffer -- i.e. corrupts `this` -- before it even looks at
     * `other`. `ResetFrom` already releases any existing heap storage
     * (SBO-aware) before copying, so the inline-source branch needs no
     * separate release step.
     */
    FastVectorN& operator=(FastVectorN&& other) noexcept
    {
      static_assert(
        !IsIntrusiveWeakRefSlot<T>::value,
        "FastVectorN<T, N>'s move assignment relocates elements without relinking their owner chains; an intrusive "
        "weak-ref slot has to go through the relinking lane instead"
      );
      if (this != &other) {
        if (other.start_ != other.originalVec_) {
          detail::DestroyRange(this->start_, this->end_);
          if (this->start_ != this->originalVec_) {
            detail::FreeElements(this->start_);
          }
          this->start_ = other.start_;
          this->end_ = other.end_;
          this->capacity_ = other.capacity_;
          other.RebindInlineNoFree();
        } else {
          this->ResetFrom(other);
          other.ResetInline_();
        }
      }
      return *this;
    }

    /**
     * Address: 0x00576D60 (FUN_00576D60, the grow lane for the 0x38-byte
     * `Moho::SFormationScriptSlot` -- recovers the live element count with the
     * 92492493h magic and `sar 5`, which is a divide by 56, then reads the
     * `{start_, end_, capacity_}` triple and relocates. Reached from both
     * push_back (0x00576C80) and the copy constructor's rebind (0x00576F10).)
     */
    /** Ensure capacity is at least newSize elements. */
    void Grow(size_t newSize)
    {
      if (this->Capacity() >= newSize)
        return;
      GrowToCapacity(newSize);
    }

    /**
     * Address: 0x004C7CC0 (FUN_004C7CC0, gpg::fastvector_n<LuaPlus::LuaObject>::Reserve lane)
     *
     * Reserve is overridden for FastVectorN to avoid Base::Reserve deleting inline storage.
     */
    void Reserve(size_t n)
    {
      if (this->Capacity() >= n)
        return;
      GrowToCapacity(n);
    }

    /**
     * Lower-case aliases, shadowed deliberately.
     *
     * Nothing in `FastVector` is virtual -- the base is the binary's three-word
     * `{start_, end_, capacity_}` triple and must stay layout-compatible, so it
     * has no vptr and `FastVectorN::Reserve` above *shadows* rather than
     * overrides. Name lookup inside a base member body therefore binds to
     * `FastVector::Reserve`, which ends in `delete[] start_`. On a
     * `FastVectorN` whose `start_` is still seated on `inlineVec_` that frees a
     * pointer the allocator never handed out: the array cookie read just below
     * the buffer is whatever the enclosing object happens to hold, so the
     * `eh vector destructor iterator` runs a garbage element count and walks off
     * the end destroying non-elements.
     *
     * `Reserve`, `Resize`, `PushBack`, `push_back`, `InsertAt` and `operator=`
     * were already shadowed. `reserve`, `resize(n)` and `resize(n, value)` were
     * not, so those three were live paths into the base's `delete[]`. Observed:
     * `Unit::Sync`'s `mWeaponInfo.resize(weaponCount, UnitWeaponInfo{})`
     * (Unit.cpp) on a `fastvector_n<UnitWeaponInfo, 1>` -- any unit with two or
     * more weapons exceeds the single inline slot and takes the grow path --
     * faulting in `~UnitWeaponInfo` -> `msvc8::string::tidy` on an unmapped
     * address, via `FastVector::resize` -> `FastVector::Reserve`.
     *
     * These forward to the inline-aware members above, whose semantics match
     * the base versions exactly (shrink rebases `end_`; equal size is a no-op;
     * growth relocates through `GrowInsert`/`GrowToCapacity` instead of
     * `delete[]`, and appended slots are filled with `fill`).
     *
     * `FastVector`'s move constructor and move assignment (the
     * `delete[] start_` at the top of `operator=(FastVector&&)`) had the
     * same defect, and pointer-stealing was wrong for an SBO container
     * regardless -- it would leave `start_` aimed at the moved-from
     * object's `inlineVec_`. Resolved by giving `FastVectorN` its own
     * SBO-aware move constructor and move assignment (below, right after
     * the copy assignment operator): steal the buffer when the source is
     * genuinely heap-backed, fall back to a real copy when it is still on
     * its own inline storage.
     */
    void reserve(const size_t n)
    {
      Reserve(n);
    }

    void resize(const size_t n)
    {
      Resize(n);
    }

    void resize(const size_t n, const T& value)
    {
      Resize(n, value);
    }

    /**
     * Append by copy; grows capacity exponentially.
     * Address: 0x0063C5F0 (FUN_0063C5F0 -- `PushBack` for `moho::SAniManipBinding` (`IAniManipulator::mWatchBones`, two bindings inline); callers 0x0063B6D0, 0x0063C090; formerly `AppendWatchBoneBinding` in moho/animation/IAniManipulator.cpp (RULE ONE), removed 2026-09-10.)
     * Address: 0x0063C090 (FUN_0063C090 -- `PushBack` through a pointer to the value for `moho::SAniManipBinding` (`IAniManipulator::mWatchBones`, two bindings inline); zero callers, unreachable; formerly `AppendWatchBoneBindingFromPointer` in moho/animation/IAniManipulator.cpp (RULE ONE), removed 2026-09-10.)
     */
    void PushBack(const T& v)
    {
      push_back(v);
    }

    /**
     * Address: 0x00515890 (FUN_00515890,
     * gpg::fastvector_n<Wm3::Vector3f, 6>::push_back -- `ecx = end_` (+0x04)
     * tested against `capacity_` (+0x08); when they differ it stores the three
     * floats through `end_` and advances it by 0x0C, otherwise it hands the
     * one-element window to the 12-byte append lane FUN_00515E30
     * (FastVectorInsertLanes.cpp). Reached from moho::ClipEdgeAgainstPlane
     * (CTesselator.cpp), which appends clipped vertices to a
     * FastVectorN<Wm3::Vector3f, 6>&.
     *
     * The +0x04/+0x08 pair is what identifies the container as a fastvector:
     * its layout is {start_, end_, capacity_}, so a last-vs-capacity test lands
     * there, whereas msvc8::vector's {proxy, first, last, end} would put the
     * same test at +0x08/+0x0C.)
     * Address: 0x0059C750 (FUN_0059C750, gpg::fastvector_n64_SAssignedLocInfo::push_back)
     * Address: 0x0061C5E0 (FUN_0061C5E0, gpg::fastvector_n<SWeakRefSlot,20>::push_back —
     *   the mBlipsInRange intrusive weak-ref lane)
     * Address: 0x0056C940 (FUN_0056C940, gpg::fastvector_n<Moho::SFormationRunScriptCandidate,16>::
     *   push_back — the 72-byte "Cand72" candidate local in
     *   CAiFormationInstance::RunScript's phase 6 (`candidates.push_back(candidate)`).
     *   Asm-verified: `ecx=end_` vs `[edi+8]`=capacity_ test at 0x0056C962; full arm
     *   calls `sub_56E620(this, pos=end_, insStart=&value, insEnd=&value+0x48)` —
     *   `InsertAt(this->end_, &value, &value+1)` below; non-full arm calls
     *   `sub_56CB60(dest=end_, src=&value)` — `*end_ = value` (copy-assign into the
     *   already-live inline/heap slot) — then `end_ += 0x48`.)
     *
     * What it does:
     * Appends one element into the active lane. If storage is full, routes
     * through insert-grow lane with a one-element source window; otherwise
     * writes directly at `end_` and advances by one element.
     *
     * For the intrusive weak-ref slot element (`IsIntrusiveWeakRefSlot<T>`), the
     * in-place write is not a raw assignment: the binary (FUN_0061C5E0) links the
     * new slot into its target's weak-owner chain head
     * (`*slot = target; slot[1] = *target; *target = slot`), leaving `slot[1] = 0`
     * when the appended value carries no target. The full-storage arm forwards to
     * the same `InsertAt` grow lane as every other element type.
     *
     * Address: 0x006AD6E0 (FUN_006AD6E0, gpg::fastvector_n<Moho::
     * SExtraUnitDataPair, 1>::push_back for the 8-byte `{key,value}` element --
     * plain in-place `*end_ = value; ++end_;` on the general-element path,
     * grow-full arm forwards to `InsertAt` (0x006AEAD0). Reached from
     * `Moho::Unit::GetExtraData`'s `out->pairs.PushBack(pair)` calls,
     * Unit.cpp.)
     * Address: 0x0056B590 (FUN_0056B590 -- `push_back` for `gpg::fastvector_n<moho::SOffsetInfo, 2>` (`CFormationInstance::mOffsetInfo`, element 0x4C): `mOffsetInfo[layerIndex].push_back(group)` at the end of `CFormationInstance::RunScript`.)
     * Address: 0x0070E8F0 (FUN_0070E8F0 -- `push_back` for `gpg::fastvector_n<moho::SCondition, 2>` (`STrigger::mConditions`, element 0x38): `CArmyStats::AddTriggerCondition`'s `trigger->mConditions.push_back(condition)` (CArmyStats.cpp); the full arm calls the `InsertAt` at 0x0070FAD0.)
     * Address: 0x0080A1A0 (FUN_0080A1A0 -- `push_back` for a 24-byte element; Appends one 24-byte element lane, delegating to range-insert growth when the destination fastvector has no spare capacity.)
     * Address: 0x0080A710 (FUN_0080A710 -- `push_back` for a 24-byte element; Appends one 24-byte element lane, delegating to range-insert growth when the destination fastvector has no spare capacity.)
     * Address: 0x0080A810 (FUN_0080A810 -- `push_back` for a 24-byte element; Appends one 24-byte element lane, delegating to range-insert growth when the destination fastvector has no spare capacity.)
     * Address: 0x00722EC0 (FUN_00722EC0 -- `push_back` for a 24-byte element; Appends one 24-byte element into a collision-result style fastvector lane and grows storage through `AppendRange24ByteLane` when full.)
     * Address: 0x004E72B0 (FUN_004E72B0 -- `push_back` for a 24-byte element; Appends one 24-byte element into the destination fastvector lane and delegates to range-grow insertion when capacity is exhausted.)
     * Address: 0x005477E0 (FUN_005477E0 -- `push_back` for a 20-byte element; Appends one 20-byte element lane and delegates to range-insert growth when the destination fastvector has no spare capacity.)
     * Address: 0x00722F10 (FUN_00722F10 -- `push_back` for a 32-byte element; Appends one 32-byte element lane and delegates to range growth insertion when the destination fastvector has no spare capacity.)
     * Address: 0x0081B6E0 (FUN_0081B6E0 -- `push_back` for a 12-byte element; Appends one 12-byte element lane and delegates to range growth insertion when the destination fastvector has no spare capacity.)
     * Address: 0x008224E0 (FUN_008224E0 -- `push_back` for a ? element; Inserts one `UserUnit*` pointer range into the destination dword lane, preserving the legacy overlap-safe copy/move path and grow semantics.)
     * Address: 0x0072A470 (FUN_0072A470 -- `push_back` for a 4-byte element; Appends one 4-byte element lane and delegates to range growth insertion when the destination fastvector has no spare capacity.)
     * Address: 0x0092E380 (FUN_0092E380 -- `push_back` for a 2-byte element read through a pointer, the `fastvector<Node>` append of `gpg::HaStar::ClusterBuild`'s edge-contact scan (Cluster.cpp).)
     */
    void push_back(const T& value)
    {
      if (this->end_ == this->capacity_) {
        InsertAt(this->end_, &value, &value + 1);
        return;
      }

      if constexpr (IsIntrusiveWeakRefSlot<T>::value) {
        if (this->end_ != nullptr) {
          auto* const destination = reinterpret_cast<IntrusiveWeakLinkNode*>(this->end_);
          const auto* const source = reinterpret_cast<const IntrusiveWeakLinkNode*>(&value);
          void* const ownerLinkSlot = source->ownerLinkSlot;
          destination->ownerLinkSlot = ownerLinkSlot;
          if (ownerLinkSlot != nullptr) {
            auto** const ownerHead = reinterpret_cast<IntrusiveWeakLinkNode**>(ownerLinkSlot);
            destination->nextInOwner = *ownerHead;
            *ownerHead = destination;
          } else {
            destination->nextInOwner = nullptr;
          }
        }
        ++this->end_;
        return;
      }

      if (this->end_ != nullptr) {
        ::new (static_cast<void*>(this->end_)) T(value);
      }
      ++this->end_;
    }

    /**
     * Address: 0x0047C680 (FUN_0047C680, gpg::fastvector_n64_char::Resize char lane)
     * Address: 0x0047EFC0 (FUN_0047EFC0, fastvector_n64_char::Resize zero-fill wrapper lane)
     *
     * What it does:
     * Resizes logical element count, growing storage when needed and filling
     * appended slots with `fill`.
     * Address: 0x0056D500 (FUN_0056D500 -- `Resize` for `gpg::fastvector_n<moho::SOffsetInfo, 2>` (`CFormationInstance::mOffsetInfo`, element 0x4C): `groups.Resize(count, SOffsetInfo())` in `SetFastVectorSOffsetInfoCount`/`LoadFastVectorSOffsetInfo` (CAiFormationInstance.cpp).)
     * Address: 0x0056D650 (FUN_0056D650 -- `Resize` for `gpg::fastvector_n<moho::SAssignedLocInfo, 16>` (`CFormationInstance::mSlots`, element 0x10): `slots.Resize(count, SAssignedLocInfo{})` in `SetFastVectorSAssignedLocInfoCount`/`LoadFastVectorSAssignedLocInfo`; the trivially-copyable 0x10 element is filled as four raw dwords (0x0056D67F-0x0056D691).)
     * Address: 0x005836D0 (FUN_005836D0 -- resize/fill for a 24-byte element; Writes one repeated 24-byte source lane into destination slots in `[destinationBegin, destinationEnd)`.)
     * Address: 0x005821B0 (FUN_005821B0 -- resize/fill for a 24-byte element (calling-convention bridge); Register-shape adapter that forwards one repeated 24-byte fill lane into the canonical range-fill helper.)
     * Address: 0x00548B20 (FUN_00548B20 -- resize/fill for a 20-byte element; Writes one repeated 20-byte source lane into destination slots in `[destinationBegin, destinationEnd)`.)
     * Address: 0x00540C00 (FUN_00540C00 -- resize/fill for a 8-byte element; Writes one repeated 8-byte source lane into destination slots in `[destinationBegin, destinationEnd)` and returns `destinationEnd`.)
     * Address: 0x0054E170 (FUN_0054E170 -- resize/fill for a 8-byte element; Writes one repeated 8-byte source lane into destination slots in `[destinationBegin, destinationEnd)` and returns `destinationEnd`.)
     * Address: 0x0075FD20 (FUN_0075FD20 -- resize/fill for a 8-byte element; Writes one repeated 8-byte source lane into destination slots in `[destinationBegin, destinationEnd)` and returns `destinationEnd`.)
     * Address: 0x00760020 (FUN_00760020 -- resize/fill for a 8-byte element; Writes one repeated 8-byte source lane into destination slots in `[destinationBegin, destinationEnd)` and returns `destinationEnd`.)
     * Address: 0x006D2770 (FUN_006D2770 -- resize/fill for a 8-byte element (calling-convention bridge); Fills one 8-byte destination range with a repeated single 8-byte source lane and returns the destination end pointer.)
     * Address: 0x008F63C0 (FUN_008F63C0 -- resize/fill for a 28-byte element; Writes one repeated 28-byte source lane into destination slots in `[destinationBegin, destinationEnd)`.)
     * Address: 0x00693260 (FUN_00693260 -- resize/fill for a 28-byte element; Writes one repeated 28-byte source lane into destination slots in `[destinationBegin, destinationEnd)`.)
     * Address: 0x00693140 (FUN_00693140 -- resize/fill for a 28-byte element (calling-convention bridge); Tail-thunk alias that forwards 28-byte repeated-fill lanes into the shared fill body.)
     * Address: 0x0064F7C0 (FUN_0064F7C0 -- resize/fill for a 52-byte element (calling-convention bridge); Tail-thunk alias that forwards 52-byte repeated-fill lanes into the shared fill body.)
     * Address: 0x0064FB10 (FUN_0064FB10 -- resize/fill for a 52-byte element; Writes one repeated 52-byte source lane into destination slots in `[destinationBegin, destinationEnd)`.)
     */
    void Resize(size_t newSize, const T& fill = T{})
    {
      // See Clear(): the shrink arm below drops the tail through DestroyRange,
      // which never unlinks an intrusive weak-ref slot.
      static_assert(
        !IsIntrusiveWeakRefSlot<T>::value,
        "Resize() would strand intrusive weak-ref slots in their owners' chains; "
        "unlink the truncated tail first (detail::UnlinkIntrusiveWeakRefRange), as the engine does"
      );
      const size_t sz = this->Size();
      if (newSize < sz) {
        T* const newEnd = this->start_ + newSize;
        detail::DestroyRange(newEnd, this->end_);
        this->end_ = newEnd;
        return;
      }
      if (newSize == sz) {
        return;
      }
      if (this->Capacity() < newSize) {
        // Binary char lane (FUN_0047C680) grows through GrowInsert(start, size, start, start).
        GrowInsert(this->start_, newSize, this->start_, this->start_);
      }
      T* const targetEnd = this->start_ + newSize;
      while (this->end_ != targetEnd) {
        T* const slot = this->end_;
        this->end_ = slot + 1;
        if (slot) {
          if constexpr (std::is_copy_constructible_v<T>) {
            ::new (static_cast<void*>(slot)) T(fill);
          } else {
            ::new (static_cast<void*>(slot)) T();
          }
        }
      }
    }

    /**
     * Address: 0x0047C590 (FUN_0047C590, gpg::fastvector_n64_char::InsertAt char lane)
     * Address: 0x004C7EB0 (FUN_004C7EB0, gpg::fastvector_n<LuaPlus::LuaObject>::InsertAt lane)
     * Address: 0x0057FE30 (FUN_0057FE30, gpg::fastvector_Entity::InsertAt)
     * Address: 0x005050A0 (FUN_005050A0, gpg::fastvector_UserEntity::InsertAt)
     * Address: 0x004FD860 (FUN_004FD860, gpg::fastvector_CollisionShapeBase::insert_range
     * -- asm-verified against FUN_004FD860.c: identical fits-in-tail /
     * spills-past-end / grow branch structure to the trivially-copyable
     * pointer-element lane above; a 4-byte pointer element compiles to the
     * same body as the Entity* / UserEntity* lanes. Confirmed real code-callers per the
     * callgraph: `FUN_004FD200`/`MarchLineAndGatherCollisionSpans` and
     * `FUN_004FD000`, both operating on a `FastVectorN<pointer, 20>`-shaped
     * span/shape vector that reaches this template's grow-capacity path via
     * `push_back`/`InsertAt` under the same call convention as the other
     * pointer-element lanes cited above)
     * Address: 0x0059CC10 (FUN_0059CC10, gpg::fastvector_n64_SAssignedLocInfo::InsertAt)
     * Address: 0x0056B2F0 (FUN_0056B2F0, gpg::fastvector_n<Moho::WeakPtr<Moho::IUnit>, 4>::InsertAt --
     * the `push_back` grow arm of `CFormationInstance::mUnits` and of the
     * transient unit sets `PreRunScript`/`UpdateFormation`/`NewFormation`
     * build; its per-element copies are the relinking `WeakPtr` copy
     * constructor, so it takes the deep-copy path below)
     * Address: 0x0084E570 (FUN_0084E570, gpg::fastvector_n<boost::shared_ptr<Moho::CMauiFrame>, 2>::InsertAt)
     * Address: 0x0083B6F0 (FUN_0083B6F0, gpg::fastvector_n<msvc8::string, 4>::InsertAt)
     * Address: 0x00767370 (FUN_00767370, gpg::fastvector_n<Moho::PathQueueNeighbour, 200>::InsertAt)
     * Address: 0x008489D0 (FUN_008489D0,
     * gpg::fastvector_n<Moho::SBuildTemplateInfo, 16>::InsertAt -- the
     * deep-copy lane (44-byte element owning an `msvc8::string`). Confirmed
     * via `sub_899790`'s IDA-typed call `sub_8489D0(result, result->finish, v7,
     * v2->finish)` (`gpg::fastvector_n16_SBuildTemplateInfo *result`), and via
     * its own asm: `(a4-a3)/44` insert-count division, `requiredSize >
     * currentCapacity` grow test with the doubling clamp, then either the
     * `posAfter <= end` in-place tail-shift branch or the `posAfter > end`
     * spill-past-end branch -- the same three-way shape as every other
     * deep-copy `InsertAt` instantiation above. Reached from
     * `Moho::AssignBuildTemplateBuffer`'s emission (`operator=` above) and
     * from `std::vector_BuildTemplate::append` (0x00848540,
     * `external_dependency` -- an ICF-shared STL body, not engine code).)
     * Address: 0x00570590 (FUN_00570590, the per-element 4-DWORD copy-loop
     * form of the SAssignedLocInfo blit step -- sizeof(SAssignedLocInfo)==
     * 0x10 confirmed via its own static_assert. Reached from the InsertAt
     * instantiation already cited at 0x0059CC10 above.)
     * Address: 0x0056E620 (FUN_0056E620, gpg::fastvector_n<Moho::
     * SFormationRunScriptCandidate,16>::InsertAt -- the deep-copy lane for the
     * 72-byte "Cand72" candidate (`EntityCategorySet mCategory` owns a nested
     * `fastvector_n<uint,2>`, so the element is non-trivially-copyable). Only
     * reached from `push_back` with `pos == end_` (see 0x0056C940 above), so
     * always takes the "spills past end" branch. Asm-verified against
     * FUN_0056E620.asm: element-count division by 0x48 via the 0x38E38E39
     * magic + `sar 4`, `requiredSize > currentCapacity` grow test with the
     * doubling clamp calling `sub_56FAB0` (`GrowInsertDeepCopy` below) when
     * exceeded, else the non-grow "spills past end" copy-construct dance
     * calling `sub_56FB90` (`UninitializedCopyForward` below) directly.)
     *
     * What it does:
     * Inserts one element range `[insStart, insEnd)` before `pos`, growing
     * storage when required.
     *
     * Two distinct emissions share this template, gated on element triviality:
     *  - Trivially-relocatable T (char @0x0047C590; the pointer lanes Entity ptr
     *    @0x0057FE30 and UserEntity ptr @0x005050A0; and the POD structs
     *    SAssignedLocInfo @0x0059CC10) blit
     *    the tail with memcpy/memmove (the fast path below).
     *  - Deep-copy T (msvc8::string @0x0083B6F0, LuaPlus::LuaObject @0x004C7EB0,
     *    boost::shared_ptr<CMauiFrame> @0x0084E570, SFormationRunScriptCandidate
     *    @0x0056E620, WeakPtr<IUnit> @0x0056B2F0, SOffsetInfo @0x0056D3F0) must
     *    NOT relocate raw bytes
     *    (that would shallow-copy owned heap pointers and double-free). Those
     *    emissions shift elements one at a time via copy-construct
     *    (UninitializedCopyForward, binary _Ucopy) into the freshly grown tail
     *    and copy-assign (CopyBackwardAssign, binary std::_Copy_backward) over
     *    live slots, mirroring std::vector::insert on a non-trivial value type.
     *    The branch structure (fits-in-tail vs. spills-past-end vs. grow) is
     *    identical across both emissions; only the per-element operation differs.
     * Address: 0x0056D3F0 (FUN_0056D3F0 -- `InsertAt` for `gpg::fastvector_n<moho::SOffsetInfo, 2>` (`CFormationInstance::mOffsetInfo`, element 0x4C), the grow arm of its `push_back`/`Resize`; deep-copy path.)
     * Address: 0x0070FAD0 (FUN_0070FAD0 -- `insert_range` for `gpg::fastvector_n<moho::SCondition, 2>` (`STrigger::mConditions`, element 0x38), the grow arm of `push_back` 0x0070E8F0; its tail shift is the `_Copy_backward` at 0x00714850.)
     * Address: 0x0080A340 (FUN_0080A340 -- `insert_range`/`InsertAt` for a 28-byte element; Inserts one 28-byte range before `insertPosition`, growing storage when capacity is insufficient.)
     * Address: 0x0080A8C0 (FUN_0080A8C0 -- `insert_range`/`InsertAt` for a 24-byte element; Inserts one 24-byte range before `insertPosition`, growing storage when capacity is insufficient.)
     * Address: 0x0080ACB0 (FUN_0080ACB0 -- `insert_range`/`InsertAt` for a 24-byte element; Inserts one 24-byte range before `insertPosition`, growing storage when capacity is insufficient.)
     * Address: 0x0080AE70 (FUN_0080AE70 -- `insert_range`/`InsertAt` for a 24-byte element; Inserts one 24-byte range before `insertPosition`, growing storage when capacity is insufficient.)
     * Address: 0x004E7460 (FUN_004E7460 -- `insert_range`/`InsertAt` for a 24-byte element; Inserts one 24-byte range before `insertPosition`, growing storage when capacity is insufficient.)
     * Address: 0x00547C70 (FUN_00547C70 -- `insert_range`/`InsertAt` for a 20-byte element; Inserts one 20-byte range before `insertPosition`, growing storage when capacity is insufficient.)
     * Address: 0x0080EF20 (FUN_0080EF20 -- `insert_range`/`InsertAt` for a 8-byte element; Inserts one 8-byte range before `insertPosition`, growing storage when capacity is insufficient.)
     * Address: 0x007A24B0 (FUN_007A24B0 -- `insert_range`/`InsertAt` for a 8-byte element; Inserts one 8-byte range before `insertPosition`, growing storage when capacity is insufficient.)
     * Address: 0x0080F0A0 (FUN_0080F0A0 -- `insert_range`/`InsertAt` for a 32-byte element; Inserts one 32-byte range before `insertPosition`, growing storage when capacity is insufficient.)
     * Address: 0x0056E4A0 (FUN_0056E4A0 -- `insert_range`/`InsertAt` for a 32-byte element; Inserts one 32-byte range before `insertPosition`, growing storage when capacity is insufficient.)
     * Address: 0x00723200 (FUN_00723200 -- `insert_range`/`InsertAt` for a 32-byte element; Inserts one 32-byte range before `insertPosition`, growing storage when capacity is insufficient.)
     * Address: 0x0081B830 (FUN_0081B830 -- `insert_range`/`InsertAt` for a 12-byte element; Inserts one 12-byte range before `insertPosition`, growing storage when capacity is insufficient.)
     * Address: 0x00515E30 (FUN_00515E30 -- `insert_range`/`InsertAt` for a 12-byte element; Inserts one 12-byte range before `insertPosition`, growing storage when capacity is insufficient.)
     * Address: 0x006C0DE0 (FUN_006C0DE0 -- `insert_range`/`InsertAt` for a 16-byte element; Inserts one 16-byte range before `insertPosition`, growing storage when capacity is insufficient.)
     * Address: 0x0092D9B0 (FUN_0092D9B0 -- `insert_range`/`InsertAt` for a 2-byte element; Inserts one 2-byte range before `insertPosition`, growing storage when capacity is insufficient.)
     * Address: 0x0080F210 (FUN_0080F210 -- `insert_range`/`InsertAt` for a 4-byte element; Inserts one 4-byte range before `insertPosition`, growing storage when capacity is insufficient.)
     * Address: 0x0082CF20 (FUN_0082CF20 -- `insert_range`/`InsertAt` for a 4-byte element; Inserts one 4-byte range before `insertPosition`, growing storage when capacity is insufficient.)
     * Address: 0x0084E740 (FUN_0084E740 -- `insert_range`/`InsertAt` for a 4-byte element; Inserts one 4-byte range before `insertPosition`, growing storage when capacity is insufficient.)
     * Address: 0x00867D40 (FUN_00867D40 -- `insert_range`/`InsertAt` for a 4-byte element; Inserts one 4-byte range before `insertPosition`, growing storage when capacity is insufficient.)
     * Address: 0x00540130 (FUN_00540130 -- `insert_range`/`InsertAt` for a 4-byte element; Inserts one 4-byte range before `insertPosition`, growing storage when capacity is insufficient.)
     * Address: 0x0059CD10 (FUN_0059CD10 -- `insert_range`/`InsertAt` for a 4-byte element; Inserts one 4-byte range before `insertPosition`, growing storage when capacity is insufficient.)
     * Address: 0x005C5270 (FUN_005C5270 -- `insert_range`/`InsertAt` for a 4-byte element; Inserts one 4-byte range before `insertPosition`, growing storage when capacity is insufficient.)
     * Address: 0x005D4020 (FUN_005D4020 -- `insert_range`/`InsertAt` for a 4-byte element; Inserts one 4-byte range before `insertPosition`, growing storage when capacity is insufficient.)
     * Address: 0x006FBC40 (FUN_006FBC40 -- `insert_range`/`InsertAt` for a 4-byte element; Inserts one 4-byte range before `insertPosition`, growing storage when capacity is insufficient.)
     * Address: 0x00702330 (FUN_00702330 -- `insert_range`/`InsertAt` for a 4-byte element; Inserts one 4-byte range before `insertPosition`, growing storage when capacity is insufficient.)
     * Address: 0x0072A850 (FUN_0072A850 -- `insert_range`/`InsertAt` for a 4-byte element; Inserts one 4-byte range before `insertPosition`, growing storage when capacity is insufficient.)
     * Address: 0x00774000 (FUN_00774000 -- `insert_range`/`InsertAt` for a 4-byte element; Inserts one 4-byte range before `insertPosition`, growing storage when capacity is insufficient.)
     * Address: 0x006AEAD0 (FUN_006AEAD0 -- `insert_range`/`InsertAt` for a 8-byte element; Inserts one 8-byte source range before `insertPosition`, growing storage when required and preserving overlap-safe lane movement semantics.)
     */
    void InsertAt(T* pos, const T* insStart, const T* insEnd)
    {
      const size_t insertCount = static_cast<size_t>(insEnd - insStart);
      if (!insertCount)
        return;

      if constexpr (IsIntrusiveWeakRefSlot<T>::value) {
        // Intrusive weak-ref slot grow/insert lane (FUN_0061C750 dispatch +
        // FUN_0061C940 reallocate). A slot value is an 8-byte weak-owner node, so
        // relocating it must re-splice the node into its target's use-list rather
        // than blit two words. All per-element work routes through the relink
        // helpers (CopyIntrusiveWeakRefRangeRelink = FUN_0061CA20,
        // AssignIntrusiveWeakRefRangeBackwardRelink = FUN_0061CE90/CF00,
        // UnlinkIntrusiveWeakRefRange = FUN_0061CA70).
        T* const start = this->start_;
        T* const end = this->end_;
        const std::size_t requiredSize = static_cast<std::size_t>(end - start) + insertCount;
        const std::size_t currentCapacity = static_cast<std::size_t>(this->capacity_ - start);
        if (requiredSize > currentCapacity) {
          std::size_t growTo = requiredSize;
          const std::size_t doubledCapacity = currentCapacity * 2u;
          if (growTo < doubledCapacity) {
            growTo = doubledCapacity;
          }
          GrowInsertIntrusiveWeakRef(pos, growTo, insStart, insEnd);
          return;
        }

        auto* const posNode = reinterpret_cast<IntrusiveWeakLinkNode*>(pos);
        auto* const endNode = reinterpret_cast<IntrusiveWeakLinkNode*>(end);
        const auto* const insStartNode = reinterpret_cast<const IntrusiveWeakLinkNode*>(insStart);
        const auto* const insEndNode = reinterpret_cast<const IntrusiveWeakLinkNode*>(insEnd);

        if (posNode + insertCount <= endNode) {
          // Branch A: inserted range fits within the live tail.
          IntrusiveWeakLinkNode* const tailStart = endNode - insertCount;
          this->end_ = reinterpret_cast<T*>(detail::CopyIntrusiveWeakRefRangeRelink(endNode, tailStart, endNode));
          detail::AssignIntrusiveWeakRefRangeBackwardRelink(posNode + insertCount, posNode, tailStart);
          detail::AssignIntrusiveWeakRefRangeBackwardRelink(posNode + insertCount, insStartNode, insEndNode);
          return;
        }

        // Branch B: inserted range spills past the current end.
        const std::size_t prefixCount = static_cast<std::size_t>(endNode - posNode);
        IntrusiveWeakLinkNode* write =
          detail::CopyIntrusiveWeakRefRangeRelink(endNode, insStartNode + prefixCount, insEndNode);
        write = detail::CopyIntrusiveWeakRefRangeRelink(write, posNode, endNode);
        this->end_ = reinterpret_cast<T*>(write);
        detail::AssignIntrusiveWeakRefRangeBackwardRelink(endNode, insStartNode, insStartNode + prefixCount);
        return;
      } else if constexpr (!std::is_trivially_copyable_v<T>) {
        // Deep-copy lane (FUN_0083B6F0 / FUN_004C7EB0 / FUN_0084E570): element-wise
        // construct + assign; never memmove a value type that owns storage.
        T* const start = this->start_;
        T* const end = this->end_;
        const size_t requiredSize = static_cast<size_t>(end - start) + insertCount;
        const size_t currentCapacity = static_cast<size_t>(this->capacity_ - start);
        if (requiredSize > currentCapacity) {
          size_t growTo = requiredSize;
          const size_t doubledCapacity = currentCapacity * 2;
          if (growTo < doubledCapacity) {
            growTo = doubledCapacity;
          }
          GrowInsertDeepCopy(pos, growTo, insStart, insEnd);
          return;
        }

        // posAfter = pos + insertCount (address translated, matches the
        // binary's `(char*)pos + ElemSize*insertCount`).
        T* const posAfter = pos + insertCount;
        if (posAfter <= end) {
          // Branch A: the inserted range fits within the current live tail.
          // 1. Extend by copy-constructing the trailing `insertCount` slots
          //    past end (binary `_Ucopy(end-insertCount, end, end)`).
          T* const tailStart = end - insertCount;
          this->end_ = UninitializedCopyForward(end, tailStart, end);
          // 2. Assign-shift the middle block [pos, tailStart) up by insertCount
          //    (binary `std::_Copy_backward(pos, tailStart, end)`).
          CopyBackwardAssign(tailStart, end, pos);
          // 3. Assign the inserted values into [pos, pos+insertCount)
          //    (binary `std::_Copy_backward(insStart, insEnd, posAfter)`).
          CopyBackwardAssign(insEnd, posAfter, insStart);
          return;
        }

        // Branch B: the inserted range spills past the current end.
        // 1. Copy-construct the overflow suffix of the insert range past end
        //    (binary `_Ucopy(insStart + (end-pos), insEnd, end)`).
        const size_t prefixCount = static_cast<size_t>(end - pos);
        T* write = UninitializedCopyForward(end, insStart + prefixCount, insEnd);
        this->end_ = write;
        // 2. Copy-construct the displaced old tail [pos, end) after the overflow
        //    (binary `_Ucopy(pos, end, write)`).
        this->end_ = UninitializedCopyForward(write, pos, end);
        // 3. Assign the insert prefix over the vacated original [pos, end)
        //    (binary `std::_Copy_backward(insStart, insStart+prefixCount, end)`).
        CopyBackwardAssign(insStart + prefixCount, end, insStart);
        return;
      } else {
        T* const start = this->start_;
        T* const end = this->end_;
        std::size_t requiredSize = static_cast<std::size_t>(end - start) + insertCount;
        const std::size_t currentCapacity = static_cast<std::size_t>(this->capacity_ - start);
        if (requiredSize > currentCapacity) {
          const std::size_t doubledCapacity = currentCapacity * 2;
          if (requiredSize < doubledCapacity) {
            requiredSize = doubledCapacity;
          }
          GrowInsert(pos, requiredSize, insStart, insEnd);
          return;
        }

        const std::uintptr_t posAddress = reinterpret_cast<std::uintptr_t>(pos);
        const std::uintptr_t insStartAddress = reinterpret_cast<std::uintptr_t>(insStart);
        const std::uintptr_t insEndAddress = reinterpret_cast<std::uintptr_t>(insEnd);
        T* const translatedInsertEnd = reinterpret_cast<T*>(insEndAddress + (posAddress - insStartAddress));
        if (translatedInsertEnd <= end) {
          T* const tailStart = end - insertCount;
          this->end_ = CopyRangeForward(end, tailStart, end);

          const std::ptrdiff_t middleCount = tailStart - pos;
          if (middleCount > 0) {
            std::memmove(end - middleCount, pos, static_cast<std::size_t>(middleCount) * ElemSize);
          }
          if (insertCount > 0) {
            std::memmove(translatedInsertEnd - insertCount, insStart, insertCount * ElemSize);
          }
          return;
        }

        T* write = CopyRangeForward(end, insStart + (end - pos), insEnd);
        this->end_ = CopyRangeForward(write, pos, end);
        const std::ptrdiff_t prefixCount = end - pos;
        if (prefixCount > 0) {
          std::memmove(pos, insStart, static_cast<std::size_t>(prefixCount) * ElemSize);
        }
      }
    }

    void Append(T& o)
    {
      if (this->end_ == this->capacity_) {
        this->InsertAt(this->end_, &o, &o + 1);
      } else {
        if (this->end_ != nullptr) {
          ::new (static_cast<void*>(this->end_)) T(o);
        }
        ++this->end_;
      }
    }

    /**
     * Address: 0x0057EB00 (FUN_0057EB00, gpg::fastvector_Entity::AddAll)
     *
     * What it does:
     * Replaces this payload with `source` while preserving inline/heap storage
     * rules and minimizing reallocations when capacity is already sufficient.
     */
    FastVectorN<T, N>* AddAll(const FastVectorN<T, N>* const source)
    {
      if (this == source) {
        return this;
      }

      const std::size_t currentCount = static_cast<std::size_t>(this->end_ - this->start_);
      const std::size_t sourceCount = static_cast<std::size_t>(source->end_ - source->start_);

      if constexpr (std::is_trivially_copyable_v<T>) {
        if (currentCount >= sourceCount) {
          if (sourceCount > 0) {
            std::memmove(this->start_, source->start_, sourceCount * ElemSize);
          }
          this->end_ = this->start_ + sourceCount;
          return this;
        }

        const std::size_t activeCapacity = static_cast<std::size_t>(this->capacity_ - this->start_);
        if (sourceCount > activeCapacity) {
          GrowInsert(this->start_, sourceCount, this->start_, this->start_);
        }

        if (currentCount > 0) {
          std::memmove(this->start_, source->start_, currentCount * ElemSize);
        }

        this->InsertAt(this->end_, source->start_ + currentCount, source->end_);
        return this;
      }

      if (sourceCount > this->Capacity()) {
        GrowToCapacity(sourceCount);
      }

      detail::DestroyRange(this->start_, this->end_);
      this->end_ = this->start_;
      for (const T* it = source->start_; it != source->end_; ++it) {
        push_back(*it);
      }

      return this;
    }

    /**
     * Address: 0x00576F10 (FUN_00576F10, the rebind-and-copy lane for the
     * 0x38-byte `Moho::SFormationScriptSlot`. Reached only from that type's
     * fastvector copy constructor at 0x00576C20, and grows through 0x00576D60
     * when the source outruns the twenty inline slots. Copies element-wise
     * rather than by block because each slot carries an `EntityCategorySet`
     * whose word lane has to be rebound to its own inline run.)
     */
    // Reset to inline storage and copy from a plain FastVector view
    /**
     * Address: 0x0065FED0 (FUN_0065FED0 -- the per-element assignment a range copy runs for `gpg::core::FastVector<moho::SEfxCurve>` (the reflected curve vector; the 0x38 element's assignment copies both bound vectors then hands its key vector to `ResetFrom`, which is the emission at 0x0065F240); callers 0x0065F330, 0x0065FA80; formerly `CopyAssignSEfxCurveRangeRuntime` in moho/effects/rendering/SEfxCurve.cpp (RULE ONE), removed 2026-09-11.)
     */
    void ResetFrom(const FastVector<T>& src)
    {
      static_assert(
        !IsIntrusiveWeakRefSlot<T>::value,
        "FastVectorN<T, N>::ResetFrom(FastVector) relocates elements without relinking their owner chains; an intrusive "
        "weak-ref slot has to go through the relinking lane instead"
      );
      this->ResetInline_();
      CopyFromRaw_(src.start_, static_cast<size_t>(src.end_ - src.start_));
    }

    // Reset to inline storage and copy from another FastVectorN
    void ResetFrom(const FastVectorN<T, N>& src)
    {
      static_assert(
        !IsIntrusiveWeakRefSlot<T>::value,
        "FastVectorN<T, N>::ResetFrom(FastVectorN) relocates elements without relinking their owner chains; an intrusive "
        "weak-ref slot has to go through the relinking lane instead"
      );
      this->ResetInline_();
      CopyFromRaw_(src.start_, static_cast<size_t>(src.end_ - src.start_));
    }

    /**
     * Address: 0x004021D0 (FUN_004021D0)
     *
     * What it does:
     * Rebind this lane to inline storage without touching/freeing prior memory.
     *
     * Binary-style rebind helper:
     * reset to inline storage without touching/freeing previous storage.
     * Mirrors raw layout initialization paths like FUN_00701B70.
     */
    void RebindInlineNoFree() noexcept
    {
      this->originalVec_ = InlineStorage();
      this->start_ = InlineStorage();
      this->end_ = InlineStorage();
      this->capacity_ = InlineStorage() + N;
    }

    /**
     * Address: 0x00402220 (FUN_00402220)
     *
     * What it does:
     * Initializes this fastvector_n lane to inline storage and copies source elements.
     */
    void InitInlineAndCopyFrom(const FastVector<T>& src)
    {
      RebindInlineNoFree();
      ResetFrom(src);
    }

    /**
     * Returns true when active storage is the inline buffer.
     */
    [[nodiscard]]
    bool UsingInlineStorage() const noexcept
    {
      return this->start_ == this->originalVec_;
    }

    /**
     * Save inline capacity pointer into inline header word.
     */
    void SaveInlineCapacityHeader() noexcept
    {
      this->SaveInlineCapacity_();
    }

    /**
     * Adopt raw storage pointers without allocating/freeing.
     * Intended for recovered ABI helpers that manage storage externally.
     */
    void AdoptRawBufferNoFree(T* begin, size_t size, size_t capacity) noexcept
    {
      this->start_ = begin;
      this->end_ = begin + size;
      this->capacity_ = begin + capacity;
    }

    /**
     * Set logical size without constructing/destroying elements.
     */
    void SetSizeUnchecked(size_t size) noexcept
    {
      this->end_ = this->start_ + size;
    }

  private:
    /**
     * Address: 0x0047C9D0 (FUN_0047C9D0, memcpy_1 char lane)
     *
     * What it does:
     * Copies `[copyBegin, copyEnd)` forward into `dest` and returns the
     * advanced destination pointer. If `dest == nullptr`, only advances.
     */
    /**
     * Address: 0x00577450 (FUN_00577450, the forward element copy for the
     * 0x38-byte `Moho::SFormationScriptSlot`. Per slot it moves the 8-byte
     * `mOffset`, the category's universe handle and first-word index, then the
     * word lane through `gpg::fastvector_uint::cpy`, then `mWeight` -- which is
     * the element's own assignment operator inlined into the loop. Walks up,
     * `add 38h` on each cursor.)
     * Address: 0x005774B0 (FUN_005774B0, the same body emitted a second time --
     * 36 instructions and 92 bytes each, identical mnemonics and the same call
     * target. This build did not fold identical COMDATs, so both survive.)
     * Address: 0x008AFB90 (FUN_008AFB90, gpg::fastvector_n<moho::SoundHandleRecord,
     * 256>'s per-element forward copy, called three times from `GrowInsert`'s
     * FUN_008AF760 instantiation (see the citation there) for the
     * `[start,pos)+[insStart,insEnd)+[pos,end)` slices. Per element the binary
     * calls `FUN_008AECF0` (`if (dest) sub_8AECF0(source++, dest); ++dest;`) --
     * a splice-into-owner-chain-head-and-reset-tracked-entity-tree copy, not a
     * plain field copy. `RebuildSoundHandleOwnerChains` and
     * `RefreshTrackedEntitySetAfterRelocation` (CUserSoundManager.cpp) already
     * reproduce those two per-element effects as aggregate caller-side passes
     * run once after the whole `.Resize()` completes, which is what makes this
     * method's plain `*dest = *cur` shape the correct substrate here: it
     * carries every other field (owner handle, cue, params, angle/loop index,
     * playing-seconds) verbatim, exactly as the binary's per-element copy also
     * does for those same fields.)
     * Address: 0x00762530 (FUN_00762530 -- copy-forward (`_Ucopy`/`_Copy`) for a 28-byte element; Copies 28-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x0080ABE0 (FUN_0080ABE0 -- copy-forward (`_Ucopy`/`_Copy`) for a 28-byte element; Copies 28-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x00693430 (FUN_00693430 -- copy-forward (`_Ucopy`/`_Copy`) for a 28-byte element; Copies 28-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x00693110 (FUN_00693110 -- copy-forward (`_Ucopy`/`_Copy`) for a 28-byte element; Copies 28-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x00762850 (FUN_00762850 -- copy-forward (`_Ucopy`/`_Copy`) for a 28-byte element; Copies 28-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x00561E60 (FUN_00561E60 -- copy-forward (`_Ucopy`/`_Copy`) for a 28-byte element; Copies 28-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x005B5250 (FUN_005B5250 -- copy-forward (`_Ucopy`/`_Copy`) for a 28-byte element; Copies 28-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x00754740 (FUN_00754740 -- copy-forward (`_Ucopy`/`_Copy`) for a 28-byte element; Copies 28-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x00693240 (FUN_00693240 -- copy-forward (`_Ucopy`/`_Copy`) for a 28-byte element (calling-convention bridge); Register-shape adapter that forwards one forward 28-byte range copy lane.)
     * Address: 0x00693370 (FUN_00693370 -- copy-forward (`_Ucopy`/`_Copy`) for a 28-byte element (calling-convention bridge); Secondary register-shape adapter that forwards one forward 28-byte range copy lane.)
     * Address: 0x00693410 (FUN_00693410 -- copy-forward (`_Ucopy`/`_Copy`) for a 28-byte element (calling-convention bridge); Third register-shape adapter that forwards one forward 28-byte range copy lane.)
     * Address: 0x006D2880 (FUN_006D2880 -- copy-forward (`_Ucopy`/`_Copy`) for a 28-byte element (calling-convention bridge); Third register-shape adapter that forwards one forward 28-byte range copy lane.)
     * Address: 0x0080B150 (FUN_0080B150 -- copy-forward (`_Ucopy`/`_Copy`) for a 24-byte element; Copies 24-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x0080B2B0 (FUN_0080B2B0 -- copy-forward (`_Ucopy`/`_Copy`) for a 24-byte element; Copies 24-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x0080B3E0 (FUN_0080B3E0 -- copy-forward (`_Ucopy`/`_Copy`) for a 24-byte element; Copies 24-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x004E7740 (FUN_004E7740 -- copy-forward (`_Ucopy`/`_Copy`) for a 24-byte element; Copies 24-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x00548460 (FUN_00548460 -- copy-forward (`_Ucopy`/`_Copy`) for a 20-byte element; Copies 20-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x0080F460 (FUN_0080F460 -- copy-forward (`_Ucopy`/`_Copy`) for a 8-byte element; Copies 8-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x006D28A0 (FUN_006D28A0 -- copy-forward (`_Ucopy`/`_Copy`) for a 8-byte element; Copies 8-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x006D2530 (FUN_006D2530 -- copy-forward (`_Ucopy`/`_Copy`) for a 8-byte element; Copies 8-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x006D2560 (FUN_006D2560 -- copy-forward (`_Ucopy`/`_Copy`) for a 8-byte element; Copies 8-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x007A26D0 (FUN_007A26D0 -- copy-forward (`_Ucopy`/`_Copy`) for a 8-byte element; Copies 8-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x006AF7B0 (FUN_006AF7B0 -- copy-forward (`_Ucopy`/`_Copy`) for a 8-byte element; Copies 8-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x007678A0 (FUN_007678A0 -- copy-forward (`_Ucopy`/`_Copy`) for a 8-byte element; Copies 8-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x006D2750 (FUN_006D2750 -- copy-forward (`_Ucopy`/`_Copy`) for a 8-byte element (calling-convention bridge); Register-shape adapter that forwards one 8-byte forward range copy lane into the canonical null-tolerant copy helper.)
     * Address: 0x006D2820 (FUN_006D2820 -- copy-forward (`_Ucopy`/`_Copy`) for a 8-byte element (calling-convention bridge); Register-shape adapter that forwards one 8-byte forward range copy lane into the canonical null-tolerant copy helper.)
     * Address: 0x00754850 (FUN_00754850 -- copy-forward (`_Ucopy`/`_Copy`) for a 8-byte element (calling-convention bridge); Bridges one 8-byte source-first copy lane where the source-end bound was supplied through a hidden register lane in the original call shape.)
     * Address: 0x0080F550 (FUN_0080F550 -- copy-forward (`_Ucopy`/`_Copy`) for a 32-byte element; Copies 32-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x0056FA10 (FUN_0056FA10 -- copy-forward (`_Ucopy`/`_Copy`) for a 32-byte element; Copies 32-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x00723530 (FUN_00723530 -- copy-forward (`_Ucopy`/`_Copy`) for a 32-byte element; Copies 32-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x0081BC90 (FUN_0081BC90 -- copy-forward (`_Ucopy`/`_Copy`) for a 12-byte element; Copies 12-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x0065FA50 (FUN_0065FA50 -- copy-forward (`_Ucopy`/`_Copy`) for a 12-byte element; Copies 12-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x006A0F70 (FUN_006A0F70 -- copy-forward (`_Ucopy`/`_Copy`) for a 12-byte element; Copies 12-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x006828B0 (FUN_006828B0 -- copy-forward (`_Ucopy`/`_Copy`) for a 12-byte element; Copies 12-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x0069FA60 (FUN_0069FA60 -- copy-forward (`_Ucopy`/`_Copy`) for a 12-byte element; Copies 12-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x0069FA90 (FUN_0069FA90 -- copy-forward (`_Ucopy`/`_Copy`) for a 12-byte element; Copies 12-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x0067F950 (FUN_0067F950 -- copy-forward (`_Ucopy`/`_Copy`) for a 12-byte element; Copies 12-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x00516670 (FUN_00516670 -- copy-forward (`_Ucopy`/`_Copy`) for a 12-byte element; Copies 12-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x0067F920 (FUN_0067F920 -- copy-forward (`_Ucopy`/`_Copy`) for a 12-byte element (calling-convention bridge); Register-shape adapter that forwards one 12-byte forward range copy lane into the canonical null-tolerant copy helper.)
     * Address: 0x00680B10 (FUN_00680B10 -- copy-forward (`_Ucopy`/`_Copy`) for a 12-byte element (calling-convention bridge); Register-shape adapter that forwards one 12-byte forward range copy lane into the canonical null-tolerant copy helper.)
     * Address: 0x00681C20 (FUN_00681C20 -- copy-forward (`_Ucopy`/`_Copy`) for a 12-byte element (calling-convention bridge); Register-shape adapter that forwards one 12-byte forward range copy lane into the canonical null-tolerant copy helper.)
     * Address: 0x00682340 (FUN_00682340 -- copy-forward (`_Ucopy`/`_Copy`) for a 12-byte element (calling-convention bridge); Register-shape adapter that forwards one 12-byte forward range copy lane into the canonical null-tolerant copy helper.)
     * Address: 0x006A02A0 (FUN_006A02A0 -- copy-forward (`_Ucopy`/`_Copy`) for a 12-byte element (calling-convention bridge); Register-shape adapter that forwards one 12-byte forward range copy lane into the canonical null-tolerant copy helper.)
     * Address: 0x006A0CF0 (FUN_006A0CF0 -- copy-forward (`_Ucopy`/`_Copy`) for a 12-byte element (calling-convention bridge); Register-shape adapter that forwards one 12-byte forward range copy lane into the canonical null-tolerant copy helper.)
     * Address: 0x006A0E70 (FUN_006A0E70 -- copy-forward (`_Ucopy`/`_Copy`) for a 12-byte element (calling-convention bridge); Register-shape adapter that forwards one 12-byte forward range copy lane into the canonical null-tolerant copy helper.)
     * Address: 0x006C1030 (FUN_006C1030 -- copy-forward (`_Ucopy`/`_Copy`) for a 16-byte element; Copies 16-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x007F0C50 (FUN_007F0C50 -- copy-forward (`_Ucopy`/`_Copy`) for a 16-byte element; Copies 16-byte elements from `[sourceBegin, rangeEnd)` into `destination`, stores the copied begin in `outBegin`, and advances `rangeEnd` to the copied tail.)
     * Address: 0x0067F8F0 (FUN_0067F8F0 -- copy-forward (`_Ucopy`/`_Copy`) for a 16-byte element; Copies 16-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x00517200 (FUN_00517200 -- copy-forward (`_Ucopy`/`_Copy`) for a 16-byte element; Copies 16-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x007E96A0 (FUN_007E96A0 -- copy-forward (`_Ucopy`/`_Copy`) for a 16-byte element; Copies 16-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x0056F2A0 (FUN_0056F2A0 -- copy-forward (`_Ucopy`/`_Copy`) for a 16-byte element; Copies 16-byte lanes from `[sourceBegin, vectorView.finish)` into `destinationBegin`, advances `vectorView.finish`, and returns `destinationBegin`.)
     * Address: 0x0092BD70 (FUN_0092BD70 -- copy-forward (`_Ucopy`/`_Copy`) for a 2-byte element; Copies 2-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x0080F660 (FUN_0080F660 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element; Copies 4-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x0082E7A0 (FUN_0082E7A0 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element; Copies 4-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x0084ED40 (FUN_0084ED40 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element; Copies 4-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x00868500 (FUN_00868500 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element; Copies 4-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x005407F0 (FUN_005407F0 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element; Copies 4-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x0059D370 (FUN_0059D370 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element; Copies 4-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x005C6CF0 (FUN_005C6CF0 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element; Copies 4-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x005D44A0 (FUN_005D44A0 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element; Copies 4-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x006FBE40 (FUN_006FBE40 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element; Copies 4-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x00702E40 (FUN_00702E40 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element; Copies 4-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x0072AB30 (FUN_0072AB30 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element; Copies 4-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x00774260 (FUN_00774260 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element; Copies 4-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x006E3ED0 (FUN_006E3ED0 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element; Copies 4-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x00706080 (FUN_00706080 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element; Copies 4-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x006E2D10 (FUN_006E2D10 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element; Copies 4-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x006E35A0 (FUN_006E35A0 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element; Copies 4-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x00704270 (FUN_00704270 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element; Copies 4-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x00658470 (FUN_00658470 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element; Copies 4-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x00559270 (FUN_00559270 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element; Copies 4-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x00553C70 (FUN_00553C70 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element; Copies 4-byte elements from `[sourceBegin, sourceEnd)` into `destination` and returns the advanced destination lane.)
     * Address: 0x007052D0 (FUN_007052D0 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element (calling-convention bridge); Register-order adapter that forwards one 4-byte range copy lane to `CopyForwardDwordLane`.)
     * Address: 0x007655C0 (FUN_007655C0 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element (calling-convention bridge); Register-order adapter that forwards one 4-byte range copy lane to `CopyForwardDwordLane`.)
     * Address: 0x007656E0 (FUN_007656E0 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element (calling-convention bridge); Register-order adapter that forwards one 4-byte range copy lane to `CopyForwardDwordLane`.)
     * Address: 0x006E34C0 (FUN_006E34C0 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element (calling-convention bridge); Register-shape forwarding lane for one dword copy range into `CopyForwardDwordLane`.)
     * Address: 0x006E3D10 (FUN_006E3D10 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element (calling-convention bridge); Mirrored register-shape forwarding lane for one dword copy range into `CopyForwardDwordLane`.)
     * Address: 0x008D8190 (FUN_008D8190 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element; Copies 4-byte elements from `[sourceBegin, sourceEnd)` into `destination` when the source range is provided first.)
     * Address: 0x008D81C0 (FUN_008D81C0 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element; Copies 4-byte elements from `[sourceBegin, sourceEnd)` into `destination` when the source range is provided first.)
     * Address: 0x008D7DF0 (FUN_008D7DF0 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element (calling-convention bridge); Forwards one source-first 4-byte lane copy through the shared `FUN_008D8190` dword source-first copy lane.)
     * Address: 0x008D7E50 (FUN_008D7E50 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element (calling-convention bridge); Forwards one source-first 4-byte lane copy through the shared `FUN_008D81C0` dword source-first copy lane.)
     * Address: 0x008EA850 (FUN_008EA850 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element (calling-convention bridge); Forwards one source-first 4-byte lane copy through the shared `FUN_008D8190` dword source-first copy lane.)
     * Address: 0x008EA880 (FUN_008EA880 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element (calling-convention bridge); Forwards one source-first 4-byte lane copy through the shared `FUN_008D81C0` dword source-first copy lane.)
     * Address: 0x008EA450 (FUN_008EA450 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element (calling-convention bridge); Adapter lane forwarding one source-first 4-byte copy range through `CopyForwardDwordLaneSourceFirst`.)
     * Address: 0x008EA470 (FUN_008EA470 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element (calling-convention bridge); Secondary adapter lane forwarding one source-first 4-byte copy range through `CopyForwardDwordLaneSourceFirst`.)
     * Address: 0x008EA660 (FUN_008EA660 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element (calling-convention bridge); Third adapter lane forwarding one source-first 4-byte copy range through `CopyForwardDwordLaneSourceFirst`.)
     * Address: 0x008EA690 (FUN_008EA690 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element (calling-convention bridge); Fourth adapter lane forwarding one source-first 4-byte copy range through `CopyForwardDwordLaneSourceFirst`.)
     * Address: 0x008D7F90 (FUN_008D7F90 -- copy-forward (`_Ucopy`/`_Copy`) for a 12-byte element (calling-convention bridge); Forwards one source-first 12-byte lane copy through the shared `FUN_008D8150` 12-byte source-first copy lane.)
     * Address: 0x008D8000 (FUN_008D8000 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element (calling-convention bridge); Forwards one source-first 4-byte lane copy through the shared `FUN_008D8190` dword source-first copy lane.)
     * Address: 0x008D8070 (FUN_008D8070 -- copy-forward (`_Ucopy`/`_Copy`) for a 4-byte element (calling-convention bridge); Forwards one source-first 4-byte lane copy through the shared `FUN_008D81C0` dword source-first copy lane.)
     * Address: 0x008D8150 (FUN_008D8150 -- copy-forward (`_Ucopy`/`_Copy`) for a 12-byte element; Copies 12-byte elements from `[sourceBegin, sourceEnd)` into `destination` when the source range is provided first.)
     * Address: 0x007547D0 (FUN_007547D0 -- copy-forward (`_Ucopy`/`_Copy`) for a 12-byte element (calling-convention bridge); Bridges one 12-byte source-first copy lane where the source-end bound was supplied through a hidden register lane in the original call shape.)
     * Address: 0x008EA820 (FUN_008EA820 -- copy-forward (`_Ucopy`/`_Copy`) for a 12-byte element (calling-convention bridge); Forwards one source-first 12-byte lane copy through the shared `FUN_008D8150` 12-byte source-first copy lane.)
     * Address: 0x008EA430 (FUN_008EA430 -- copy-forward (`_Ucopy`/`_Copy`) for a 12-byte element (calling-convention bridge); Adapter lane forwarding one source-first 12-byte copy range through `CopyForward12ByteLaneSourceFirst`.)
     * Address: 0x008EA630 (FUN_008EA630 -- copy-forward (`_Ucopy`/`_Copy`) for a 12-byte element (calling-convention bridge); Secondary adapter lane forwarding one source-first 12-byte copy range through `CopyForward12ByteLaneSourceFirst`.)
     * Address: 0x008F64A0 (FUN_008F64A0 -- copy-forward (`_Ucopy`/`_Copy`) for a 28-byte element; Copies 28-byte elements from `[sourceBegin, sourceEnd)` into `destination` when the source range is provided first.)
     * Address: 0x008F64D0 (FUN_008F64D0 -- copy-forward (`_Ucopy`/`_Copy`) for a 28-byte element; Copies 28-byte elements from `[sourceBegin, sourceEnd)` into `destination` when the source range is provided first.)
     * Address: 0x008F6810 (FUN_008F6810 -- copy-forward (`_Ucopy`/`_Copy`) for a 28-byte element; Copies 28-byte elements from `[sourceBegin, sourceEnd)` into `destination` when the source range is provided first.)
     * Address: 0x008F6620 (FUN_008F6620 -- copy-forward (`_Ucopy`/`_Copy`) for a 28-byte element (calling-convention bridge); Forwarding lane that routes one source-first 28-byte range copy into `FUN_008F64D0`.)
     * Address: 0x008F66C0 (FUN_008F66C0 -- copy-forward (`_Ucopy`/`_Copy`) for a 28-byte element (calling-convention bridge); Secondary forwarding lane that routes one source-first 28-byte range copy into `FUN_008F64D0`.)
     * Address: 0x008F6760 (FUN_008F6760 -- copy-forward (`_Ucopy`/`_Copy`) for a 28-byte element (calling-convention bridge); Tertiary forwarding lane that routes one source-first 28-byte range copy into `FUN_008F64D0`.)
     * Address: 0x008F66E0 (FUN_008F66E0 -- copy-forward (`_Ucopy`/`_Copy`) for a 28-byte element (calling-convention bridge); Forwards one source-first 28-byte lane copy through the shared `FUN_008F64D0` 28-byte source-first copy lane.)
     * Address: 0x00756990 (FUN_00756990 -- copy-forward (`_Ucopy`/`_Copy`) for a 40-byte element; Copies 40-byte elements from `[sourceBegin, sourceEnd)` into `destination` when the source range is provided first.)
     * Address: 0x00753D60 (FUN_00753D60 -- copy-forward (`_Ucopy`/`_Copy`) for a 40-byte element; Copies 40-byte elements from `[sourceBegin, sourceEnd)` into `destination` when the source range is provided first.)
     * Address: 0x00751B20 (FUN_00751B20 -- copy-forward (`_Ucopy`/`_Copy`) for a 40-byte element (calling-convention bridge); Tail-jump adapter lane that forwards one 40-byte source-first copy range into `FUN_00753D60`.)
     * Address: 0x00753D40 (FUN_00753D40 -- copy-forward (`_Ucopy`/`_Copy`) for a 40-byte element (calling-convention bridge); Source-first forwarding adapter lane that routes one 40-byte range copy into `FUN_00756990` while discarding one zero scratch lane.)
     * Address: 0x00755950 (FUN_00755950 -- copy-forward (`_Ucopy`/`_Copy`) for a 40-byte element (calling-convention bridge); Duplicate source-first forwarding adapter lane for one 40-byte range copy into `FUN_00756990`.)
     * Address: 0x00755D90 (FUN_00755D90 -- copy-forward (`_Ucopy`/`_Copy`) for a 40-byte element (calling-convention bridge); Third source-first forwarding adapter lane for one 40-byte range copy into `FUN_00756990`.)
     * Address: 0x0071D700 (FUN_0071D700 -- copy-forward (`_Ucopy`/`_Copy`) for a 56-byte element; Copies 56-byte elements from `[sourceBegin, sourceEnd)` into `destination` when the source range is provided first.)
     * Address: 0x0071FC60 (FUN_0071FC60 -- copy-forward (`_Ucopy`/`_Copy`) for a 56-byte element; Copies 56-byte elements from `[sourceBegin, sourceEnd)` into `destination` when the source range is provided first.)
     * Address: 0x0071E950 (FUN_0071E950 -- copy-forward (`_Ucopy`/`_Copy`) for a 56-byte element; Copies 56-byte elements from `[sourceBegin, sourceEnd)` into `destination` when the source range is provided first.)
     * Address: 0x0071F510 (FUN_0071F510 -- copy-forward (`_Ucopy`/`_Copy`) for a 56-byte element; Copies 56-byte elements from `[sourceBegin, sourceEnd)` into `destination` when the source range is provided first.)
     * Address: 0x0071F6D0 (FUN_0071F6D0 -- copy-forward (`_Ucopy`/`_Copy`) for a 56-byte element; Copies 56-byte elements from `[sourceBegin, sourceEnd)` into `destination` when the source range is provided first.)
     * Address: 0x0071EC30 (FUN_0071EC30 -- copy-forward (`_Ucopy`/`_Copy`) for a 56-byte element; Copies 56-byte elements from `[sourceBegin, sourceEnd)` into `destination` when the source range is provided first.)
     * Address: 0x0071EC90 (FUN_0071EC90 -- copy-forward (`_Ucopy`/`_Copy`) for a 56-byte element (calling-convention bridge); Register-shape adapter lane that forwards one 56-byte source-first copy into `CopyForward56ByteLaneSourceFirst`.)
     * Address: 0x00754830 (FUN_00754830 -- forward copy for an 8-byte element (eax=dest, edx=end, ecx=begin register convention), the copy step of `fastvector::operator=` 0x00752A70; formerly `CopyDwordPairRangeLaneA` in moho/containers/LegacyContainerFillLanesB.cpp (RULE ONE), removed 2026-09-10.)
     * Address: 0x007547A0 (FUN_007547A0 -- forward copy for a 12-byte element, the copy step of `fastvector::operator=` 0x00752830; formerly `CopyDwordTripleRangeLaneA`, removed.)
     * Address: 0x0063CA20 (FUN_0063CA20 -- `CopyRangeForward` for `moho::SAniManipBinding` (`IAniManipulator::mWatchBones`, two bindings inline); callers 0x0063C5F0, 0x0063C950; formerly `CopyBindingRange` in moho/animation/IAniManipulator.cpp (RULE ONE), removed 2026-09-10.)
     */
    static T* CopyRangeForward(T* dest, const T* copyBegin, const T* copyEnd)
    {
      if constexpr (std::is_trivially_copyable_v<T> && ElemSize == sizeof(std::uint32_t)) {
        auto* const destWords = reinterpret_cast<std::uint32_t*>(dest);
        auto* const beginWords = reinterpret_cast<const std::uint32_t*>(copyBegin);
        auto* const endWords = reinterpret_cast<const std::uint32_t*>(copyEnd);
        return reinterpret_cast<T*>(detail::CopyDwordRangeForward(destWords, beginWords, endWords));
      }

      std::uintptr_t destinationAddress = reinterpret_cast<std::uintptr_t>(dest);
      for (const T* cur = copyBegin; cur != copyEnd; ++cur) {
        if (destinationAddress != 0u) {
          *reinterpret_cast<T*>(destinationAddress) = *cur;
        }
        destinationAddress += ElemSize;
      }
      return reinterpret_cast<T*>(destinationAddress);
    }

    /**
     * Address: 0x006584C0 (FUN_006584C0, std::_Uninit_copy<std::string> lane == _Ucopy)
     * Address: 0x00849030 (FUN_00849030,
     * gpg::fastvector_n<Moho::SBuildTemplateInfo, 16>'s per-element
     * copy-construct-forward lane -- reached from both `InsertAt`'s grow arm
     * (FUN_00848F50) and its in-place Branch A/B tail relocation. The binary
     * inlines `SBuildTemplateInfo`'s copy constructor into the loop: floats
     * `mPos` and dword `mBuildOrder` are copied directly, `mBlueprintId`'s SSO
     * header is stamped empty (`myRes=15, mySize=0, buf[0]=0`) and then
     * `std::string::assign`ed from the source -- the same
     * copy-construct-then-assign shape this method expresses generically.)
     * Address: 0x0084EC30 (FUN_0084EC30,
     * gpg::fastvector_n<boost::shared_ptr<Moho::CMauiFrame>, 2>'s
     * per-element copy-construct-forward lane -- per slot, the `{px,pn}`
     * pair is copied verbatim and, when `pn` is non-null, its refcount word
     * at `pn+4` is atomically incremented (`_InterlockedExchangeAdd`),
     * exactly `boost::shared_ptr`'s copy constructor placement-newed in
     * place. Reached from the `InsertAt` deep-copy lane `FUN_0084E570`
     * (already recovered, cited above), which shifts elements one at a time
     * via this member for the non-trivially-relocatable `shared_ptr<
     * CMauiFrame>` element.)
     * Address: 0x0056FB90 (FUN_0056FB90, gpg::fastvector_n<Moho::
     * SFormationRunScriptCandidate,16>'s per-element copy-construct-forward
     * lane for the 72-byte "Cand72" candidate -- per slot, copies the two
     * `Vec3f` lanes and the sort-key/weight floats directly, then calls
     * `gpg::fastvector_uint::cpy` for the nested `EntityCategorySet::mWords`
     * word buffer (`mCategory` is not trivially copyable, so this is a real
     * per-field deep copy, not a memcpy). Reached from two places for this
     * instantiation: `InsertAt`'s (0x0056E620) own non-grow branches A/B
     * below, and -- for `push_back`'s always-full grow call specifically --
     * from *inside* `GrowInsertDeepCopy` (0x0056FAB0), which calls this same
     * address three times for the `[start,pos)+[insStart,insEnd)+[pos,end)`
     * slices. This typed reconstruction reaches that second call site through
     * `CopyRangeForward` (assignment into an already-default-constructed
     * `new T[]` slot) rather than through this method directly, per
     * `GrowInsertDeepCopy`'s own documented construct-then-assign divergence
     * from the binary's raw-storage `operator new` + `_Ucopy` shape -- both
     * produce the same per-element deep copy this address performs.)
     *
     * What it does:
     * Copy-CONSTRUCTS `[copyBegin, copyEnd)` into raw storage at `dest` and
     * returns the advanced destination pointer. Mirrors the binary helper that
     * default-initializes each destination slot (`_Myres=15,_Mysize=0`) and then
     * `assign`s the source string; expressed here as placement-new copy so
     * owned heap buffers are deep-copied, never aliased. Advances without
     * writing when `dest == nullptr`, matching the binary's null-guarded lane.
     * Address: 0x0056F1F0 (FUN_0056F1F0 -- `_Ucopy` for `gpg::fastvector_n<moho::SOffsetInfo, 2>` (`CFormationInstance::mOffsetInfo`, element 0x4C), the copy-construct step of its `GrowInsertDeepCopy`/`InsertAt`.)
     * Address: 0x0056D390 (FUN_0056D390 -- `_Ucopy` for `gpg::fastvector_n<moho::WeakPtr<moho::IUnit>, 4>` (`CFormationInstance::mUnits` and the formation scratch sets, element 0x08), the relinking copy-construct step of its `InsertAt` (0x0056B2F0).)
     */
    static T* UninitializedCopyForward(T* dest, const T* copyBegin, const T* copyEnd)
    {
      std::uintptr_t destinationAddress = reinterpret_cast<std::uintptr_t>(dest);
      for (const T* cur = copyBegin; cur != copyEnd; ++cur) {
        if (destinationAddress != 0u) {
          ::new (reinterpret_cast<void*>(destinationAddress)) T(*cur);
        }
        destinationAddress += ElemSize;
      }
      return reinterpret_cast<T*>(destinationAddress);
    }

    /**
     * Address: 0x0083C5C0 (FUN_0083C5C0, std::_Copy_backward<std::string> lane)
     * Address: 0x0083C5F0 (FUN_0083C5F0, std::_Copy_backward<std::string> twin)
     *
     * What it does:
     * Copy-ASSIGNS `[first, last)` into the range ending at `resultLast`,
     * walking backward so overlapping shifts toward higher addresses stay
     * correct (binary `std::_Copy_backward`). Destination slots already hold
     * live objects, so this is assignment (not construction). Returns the
     * final (lowest) destination pointer written.
     */
    /**
     * Address: 0x00577350 (FUN_00577350, the matching backward copy for
     * `Moho::SFormationScriptSlot` -- the same per-element assignment as
     * 0x00577450 but walked down, `sub 38h` on each cursor, so an overlapping
     * shift cannot clobber the tail. 38 instructions to the forward pair's 36.)
     * Address: 0x00573000 (FUN_00573000, gpg::fastvector_n<Moho::
     * SFormationRunScriptCandidate,16>'s backward per-element copy-assign lane
     * for the 72-byte "Cand72" candidate -- walks `[first,last)` backward
     * (`sub esi/ebx/eax, 0x48` each step, asm-verified), assigning the two
     * `Vec3f` lanes and sort-key/weight floats directly, then calling
     * `gpg::fastvector_uint::cpy` for `mCategory.mWords` per element, exactly
     * mirroring the forward per-element copy above. Reached from `InsertAt`'s
     * (0x0056E620) Branch B (spills-past-end) for this instantiation; not
     * reached by `RunScript`'s specific `candidates.push_back(...)` call
     * (`push_back` only invokes `InsertAt` when already full, which always
     * takes the grow branch to `GrowInsertDeepCopy` instead) but is still
     * part of `InsertAt`'s one compiled body for this element type, which
     * this template reproduces branch-for-branch.)
     * Address: 0x00571150 (FUN_00571150 -- `_Copy_backward` for `gpg::fastvector_n<moho::SOffsetInfo, 2>` (`CFormationInstance::mOffsetInfo`, element 0x4C), the in-place tail shift of its `InsertAt`.)
     * Address: 0x00571180 (FUN_00571180 -- a second, byte-identical emission of the same `_Copy_backward` the linker kept distinct.)
     * Address: 0x00714850 (FUN_00714850 -- `_Copy_backward` for `gpg::fastvector_n<moho::SCondition, 2>` (`STrigger::mConditions`, element 0x38), the in-place tail shift of `InsertAt` 0x0070FAD0; element `operator=` copies `mItem`, `mOp`, `mCat` and `mVal`.)
     * Address: 0x00713950 (FUN_00713950 -- a second emission of the same `SCondition` `_Copy_backward`.)
     * Address: 0x00712840 (FUN_00712840 -- jump thunk into the `SCondition` `_Copy_backward`; zero callers.)
     * Address: 0x00712870 (FUN_00712870 -- jump thunk into the `SCondition` `_Copy_backward`; zero callers.)
     * Address: 0x00762590 (FUN_00762590 -- `_Copy_backward` for a 28-byte element; Copies 28-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane.)
     * Address: 0x007625C0 (FUN_007625C0 -- `_Copy_backward` for a 28-byte element; Copies 28-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane.)
     * Address: 0x0080B670 (FUN_0080B670 -- `_Copy_backward` for a 28-byte element; Copies 28-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane.)
     * Address: 0x0080B6E0 (FUN_0080B6E0 -- `_Copy_backward` for a 28-byte element; Copies 28-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane.)
     * Address: 0x005B5C50 (FUN_005B5C50 -- `_Copy_backward` for a 28-byte element; Copies 28-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane.)
     * Address: 0x005B5CC0 (FUN_005B5CC0 -- `_Copy_backward` for a 28-byte element; Copies 28-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane.)
     * Address: 0x00693390 (FUN_00693390 -- `_Copy_backward` for a 28-byte element; Copies 28-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane.)
     * Address: 0x00762A30 (FUN_00762A30 -- `_Copy_backward` for a 28-byte element; Copies 28-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane.)
     * Address: 0x00762A90 (FUN_00762A90 -- `_Copy_backward` for a 28-byte element; Copies 28-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane.)
     * Address: 0x006932C0 (FUN_006932C0 -- `_Copy_backward` for a 28-byte element (calling-convention bridge); Register-shape adapter that forwards one backward 28-byte range copy lane.)
     * Address: 0x005B5740 (FUN_005B5740 -- `_Copy_backward` for a 28-byte element (calling-convention bridge); Register-shape adapter that forwards one source-first backward 28-byte lane copy through `FUN_005B5C50`.)
     * Address: 0x005B5770 (FUN_005B5770 -- `_Copy_backward` for a 28-byte element (calling-convention bridge); Secondary register-shape adapter for source-first backward 28-byte lane copy, forwarding to `FUN_005B5CC0`.)
     * Address: 0x0080B4A0 (FUN_0080B4A0 -- `_Copy_backward` for a 28-byte element (calling-convention bridge); Tertiary source-first delegate for one backward 28-byte range-copy lane.)
     * Address: 0x0080B4D0 (FUN_0080B4D0 -- `_Copy_backward` for a 28-byte element (calling-convention bridge); Quaternary source-first delegate for one backward 28-byte range-copy lane.)
     * Address: 0x0080B750 (FUN_0080B750 -- `_Copy_backward` for a 24-byte element; Copies 24-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane.)
     * Address: 0x0080B7B0 (FUN_0080B7B0 -- `_Copy_backward` for a 24-byte element; Copies 24-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane.)
     * Address: 0x0080B810 (FUN_0080B810 -- `_Copy_backward` for a 24-byte element; Copies 24-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane.)
     * Address: 0x0080B870 (FUN_0080B870 -- `_Copy_backward` for a 24-byte element; Copies 24-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane.)
     * Address: 0x0080B8D0 (FUN_0080B8D0 -- `_Copy_backward` for a 24-byte element; Copies 24-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane.)
     * Address: 0x0080B930 (FUN_0080B930 -- `_Copy_backward` for a 24-byte element; Copies 24-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane.)
     * Address: 0x004E7AA0 (FUN_004E7AA0 -- `_Copy_backward` for a 24-byte element; Copies 24-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane.)
     * Address: 0x00584220 (FUN_00584220 -- `_Copy_backward` for a 24-byte element; Copies 24-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane.)
     * Address: 0x004E7B00 (FUN_004E7B00 -- `_Copy_backward` for a 24-byte element (calling-convention bridge); Alias lane of `CopyBackward24ByteLane` used by one adjacent VC8 vector helper instantiation.)
     * Address: 0x004E7890 (FUN_004E7890 -- `_Copy_backward` for a 24-byte element (calling-convention bridge); Adapts one register-lane caller shape into the canonical backward 24-byte range-copy helper.)
     * Address: 0x004E78C0 (FUN_004E78C0 -- `_Copy_backward` for a 24-byte element (calling-convention bridge); Second register-lane adapter for backward 24-byte range-copy dispatch.)
     * Address: 0x005821C0 (FUN_005821C0 -- `_Copy_backward` for a 24-byte element (calling-convention bridge); Third register-shape adapter for backward 24-byte range-copy dispatch.)
     * Address: 0x00583720 (FUN_00583720 -- `_Copy_backward` for a 24-byte element (calling-convention bridge); Third register-shape adapter for backward 24-byte range-copy dispatch.)
     * Address: 0x0080B500 (FUN_0080B500 -- `_Copy_backward` for a 24-byte element (calling-convention bridge); Forwards one source-first backward 24-byte range-copy lane through the shared canonical helper.)
     * Address: 0x0080B530 (FUN_0080B530 -- `_Copy_backward` for a 24-byte element (calling-convention bridge); Secondary source-first delegate for one backward 24-byte range-copy lane.)
     * Address: 0x0080B560 (FUN_0080B560 -- `_Copy_backward` for a 24-byte element (calling-convention bridge); Tertiary source-first delegate for one backward 24-byte range-copy lane.)
     * Address: 0x0080B590 (FUN_0080B590 -- `_Copy_backward` for a 24-byte element (calling-convention bridge); Quaternary source-first delegate for one backward 24-byte range-copy lane.)
     * Address: 0x0080B5C0 (FUN_0080B5C0 -- `_Copy_backward` for a 24-byte element (calling-convention bridge); Quinary source-first delegate for one backward 24-byte range-copy lane.)
     * Address: 0x0080B5F0 (FUN_0080B5F0 -- `_Copy_backward` for a 24-byte element (calling-convention bridge); Senary source-first delegate for one backward 24-byte range-copy lane.)
     * Address: 0x005EF7D0 (FUN_005EF7D0 -- `_Copy_backward` for a 20-byte element; Copies 20-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane.)
     * Address: 0x00548A50 (FUN_00548A50 -- `_Copy_backward` for a 20-byte element; Copies 20-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane.)
     * Address: 0x00548A80 (FUN_00548A80 -- `_Copy_backward` for a 20-byte element; Copies 20-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane.)
     * Address: 0x00548B50 (FUN_00548B50 -- `_Copy_backward` for a 20-byte element; Copies 20-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane.)
     * Address: 0x00760065 (FUN_00760065 -- `_Copy_backward` for a 8-byte element; Copies 8-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane and returns the destination begin.)
     * Address: 0x007A2830 (FUN_007A2830 -- `_Copy_backward` for a 8-byte element; Copies 8-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane and returns the destination begin.)
     * Address: 0x00540C20 (FUN_00540C20 -- `_Copy_backward` for a 8-byte element; Copies 8-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane and returns the destination begin.)
     * Address: 0x0054E190 (FUN_0054E190 -- `_Copy_backward` for a 8-byte element; Copies 8-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane and returns the destination begin.)
     * Address: 0x006D2580 (FUN_006D2580 -- `_Copy_backward` for a 8-byte element; Copies 8-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane and returns the destination begin.)
     * Address: 0x0075FD40 (FUN_0075FD40 -- `_Copy_backward` for a 8-byte element; Copies 8-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane and returns the destination begin.)
     * Address: 0x007A2860 (FUN_007A2860 -- `_Copy_backward` for a 8-byte element; Copies 8-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane and returns the destination begin.)
     * Address: 0x006D27B0 (FUN_006D27B0 -- `_Copy_backward` for a 8-byte element (calling-convention bridge); Alias lane for backward 8-byte range copy.)
     * Address: 0x006D2840 (FUN_006D2840 -- `_Copy_backward` for a 8-byte element (calling-convention bridge); Alias lane for backward 8-byte range copy.)
     * Address: 0x00572F80 (FUN_00572F80 -- `_Copy_backward` for a 32-byte element; Copies 32-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane.)
     * Address: 0x00572F20 (FUN_00572F20 -- `_Copy_backward` for a 32-byte element; Copies 32-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane.)
     * Address: 0x00723850 (FUN_00723850 -- `_Copy_backward` for a 32-byte element; Copies 32-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane.)
     * Address: 0x007238D0 (FUN_007238D0 -- `_Copy_backward` for a 32-byte element; Copies 32-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane.)
     * Address: 0x005715D0 (FUN_005715D0 -- `_Copy_backward` for a 32-byte element (calling-convention bridge); Adapts one source-first 32-byte backward copy lane through `FUN_00572F20`.)
     * Address: 0x00571600 (FUN_00571600 -- `_Copy_backward` for a 32-byte element (calling-convention bridge); Secondary source-first adapter lane for the 32-byte backward copy dispatcher via `FUN_00572F80`.)
     * Address: 0x00723670 (FUN_00723670 -- `_Copy_backward` for a 32-byte element (calling-convention bridge); Tiny adapter lane that forwards destination-only dispatch to the canonical backward 32-byte copy helper with an empty source range.)
     * Address: 0x007236A0 (FUN_007236A0 -- `_Copy_backward` for a 32-byte element (calling-convention bridge); Secondary destination-only adapter that forwards an empty source range to the canonical backward 32-byte copy helper.)
     * Address: 0x007BEBE0 (FUN_007BEBE0 -- `_Copy_backward` for a 32-byte element (calling-convention bridge); Secondary destination-only adapter that forwards an empty source range to the canonical backward 32-byte copy helper.)
     * Address: 0x00517090 (FUN_00517090 -- `_Copy_backward` for a 12-byte element; Copies 12-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane.)
     * Address: 0x005170C0 (FUN_005170C0 -- `_Copy_backward` for a 12-byte element; Copies 12-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane.)
     * Address: 0x0069FAB0 (FUN_0069FAB0 -- `_Copy_backward` for a 12-byte element; Copies 12-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane.)
     * Address: 0x0067F970 (FUN_0067F970 -- `_Copy_backward` for a 12-byte element; Copies 12-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane.)
     * Address: 0x0059DC60 (FUN_0059DC60 -- `_Copy_backward` for a 16-byte element; Copies 16-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane and returns the destination begin.)
     * Address: 0x006C1170 (FUN_006C1170 -- `_Copy_backward` for a 16-byte element; Copies 16-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane and returns the destination begin.)
     * Address: 0x006C11B0 (FUN_006C11B0 -- `_Copy_backward` for a 16-byte element; Copies 16-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane and returns the destination begin.)
     * Address: 0x0065004D (FUN_0065004D -- `_Copy_backward` for a 52-byte element (calling-convention bridge); Debug-trap adapter lane that breaks into debugger and then forwards to the shared 52-byte backward-copy helper.)
     * Address: 0x00650050 (FUN_00650050 -- `_Copy_backward` for a 52-byte element; Copies 52-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane.)
     * Address: 0x0064FB90 (FUN_0064FB90 -- `_Copy_backward` for a 52-byte element (calling-convention bridge); Adapts one legacy register/stack caller shape into the canonical backward 52-byte range-copy helper.)
     * Address: 0x00755970 (FUN_00755970 -- `_Copy_backward` for a 40-byte element; Copies 40-byte elements backward from `[sourceBegin, sourceEnd)` into the destination tail lane when caller lanes are provided as source-first.)
     * Address: 0x00753DD0 (FUN_00753DD0 -- `_Copy_backward` for a 40-byte element (calling-convention bridge); Source-first forwarding adapter lane that routes one 40-byte backward copy into `FUN_00755970` while discarding one zero scratch lane.)
     * Address: 0x00751B30 (FUN_00751B30 -- `_Copy_backward` for a 40-byte element (calling-convention bridge); Duplicate source-first forwarding adapter lane that routes one 40-byte backward copy into `FUN_00755970` while discarding one zero scratch lane.)
     */
    static T* CopyBackwardAssign(const T* last, T* resultLast, const T* first)
    {
      return detail::CopyBackwardAssign<T>(last, resultLast, first);
    }

    /**
     * Address: 0x0061C940 (FUN_0061C940, weak-ref slot reallocate-grow-insert lane)
     *
     * What it does:
     * Reallocate arm of the intrusive weak-ref slot grow path (the target of
     * FUN_0061C750 when `requiredSize > capacity`). Allocates a `newCapacity`
     * buffer and copy-CONSTRUCTS-with-relink the three slices
     * `[start, pos) + [insStart, insEnd) + [pos, end)` into it via
     * `CopyIntrusiveWeakRefRangeRelink` (FUN_0061CA20) — each moved node is spliced
     * into its target's owner chain in the new storage. The OLD range is then
     * unlinked from its owner chains (`UnlinkIntrusiveWeakRefRange` =
     * FUN_0061CA70) before the old buffer is released (or the inline-capacity
     * sentinel is restamped when the old storage was the inline window), matching
     * the binary's `sub_61CA70` + `operator delete[]` / inline-restore tail.
     */
    void GrowInsertIntrusiveWeakRef(T* pos, const std::size_t newCapacity, const T* insStart, const T* insEnd)
    {
      T* const oldStart = this->start_;
      T* const oldEnd = this->end_;

      T* const newBuffer = detail::AllocateElements<T>(newCapacity);

      auto* const newBegin = reinterpret_cast<IntrusiveWeakLinkNode*>(newBuffer);
      const auto* const oldStartNode = reinterpret_cast<const IntrusiveWeakLinkNode*>(oldStart);
      const auto* const posNode = reinterpret_cast<const IntrusiveWeakLinkNode*>(pos);
      const auto* const oldEndNode = reinterpret_cast<const IntrusiveWeakLinkNode*>(oldEnd);
      const auto* const insStartNode = reinterpret_cast<const IntrusiveWeakLinkNode*>(insStart);
      const auto* const insEndNode = reinterpret_cast<const IntrusiveWeakLinkNode*>(insEnd);

      IntrusiveWeakLinkNode* write = detail::CopyIntrusiveWeakRefRangeRelink(newBegin, oldStartNode, posNode);
      write = detail::CopyIntrusiveWeakRefRangeRelink(write, insStartNode, insEndNode);
      write = detail::CopyIntrusiveWeakRefRangeRelink(write, posNode, oldEndNode);

      // Unlink every node that lived in the old storage from its owner chains
      // (their owner-chain entries currently point at the freed-to-be old slots).
      detail::UnlinkIntrusiveWeakRefRange(
        reinterpret_cast<IntrusiveWeakLinkNode*>(oldStart), reinterpret_cast<IntrusiveWeakLinkNode*>(oldEnd)
      );

      if (oldStart == this->originalVec_) {
        this->SaveInlineCapacity_();
      } else {
        detail::FreeElements(oldStart);
      }

      this->start_ = newBuffer;
      this->end_ = reinterpret_cast<T*>(write);
      this->capacity_ = newBuffer + newCapacity;
    }

    /**
     * Address: 0x00658200 (FUN_00658200, std::vector<std::string>::_Insert_n grow lane)
     * Address: 0x00848F50 (FUN_00848F50,
     * gpg::fastvector_n<Moho::SBuildTemplateInfo, 16>::GrowInsert lane -- the
     * reallocate arm of `InsertAt` (FUN_008489D0) for this element. The binary
     * allocates raw storage (`operator new(44 * newCapacity)`, not a typed
     * array-new) and placement-constructs only the live three-slice union into
     * it via the per-element copy-construct lane (FUN_00849030, cited on
     * `UninitializedCopyForward` above), leaving any slack capacity past that
     * union genuinely uninitialized. This method instead performs a typed
     * `new T[newCapacity]` (default-constructing every slot, slack included)
     * and then copy-*assigns* the three slices over it via `CopyRangeForward`
     * -- a construct-then-assign shape rather than the binary's
     * construct-once-into-raw-storage shape. Both leave the same observable
     * `[start_, end_)` element values; the divergence is memory-footprint
     * only (slack slots hold default-constructed values instead of being
     * genuinely unallocated) and is the same accepted trade-off already made
     * for every other deep-copy element type on this method
     * (`msvc8::string`, `LuaPlus::LuaObject`, `boost::shared_ptr<CMauiFrame>`).)
     * Address: 0x0056FAB0 (FUN_0056FAB0, gpg::fastvector_n<Moho::
     * SFormationRunScriptCandidate,16>::GrowInsert lane -- the reallocate arm
     * of `InsertAt` (0x0056E620) for the 72-byte "Cand72" candidate, and the
     * only branch `RunScript`'s `candidates.push_back(candidate)` actually
     * reaches (push_back only calls InsertAt when already full, so
     * requiredSize always exceeds currentCapacity here). Asm-verified:
     * `operator new(newCapacity*0x48)`, then three calls to `sub_56FB90`
     * (cited on `UninitializedCopyForward` above) for the
     * `[start,pos)+[insStart,insEnd)+[pos,end)` slices into the fresh raw
     * buffer, then `sub_56E7E0` (per-element destroy of the old range) and a
     * conditional `operator delete[]` of the old buffer (skipped when it was
     * the inline window) -- the exact shape this method already implements,
     * modulo the same typed-`new T[]`-then-assign divergence documented above
     * for every other instantiation.)
     *
     * What it does:
     * Deep-copy grow-and-insert for non-trivially-relocatable T (the reallocate
     * arm of FUN_0083B6F0 / FUN_004C7EB0 / FUN_0084E570). Exactly the shipped
     * shape: raw `operator new(newCapacity * sizeof(T))`, the three slices
     * `[start, pos) + [insStart, insEnd) + [pos, end)` copy-CONSTRUCTED into it
     * (`_Ucopy`), the old live range destroyed (`_Destroy_range`), and the old
     * block released -- or, when the old range was the inline window, its
     * capacity sentinel restamped. Should a copy throw, the elements already
     * built in the new block are torn down, the block is freed and the vector
     * is left untouched.
     * Address: 0x0056F100 (FUN_0056F100 -- the reallocating insert for `gpg::fastvector_n<moho::SOffsetInfo, 2>` (`CFormationInstance::mOffsetInfo`, element 0x4C): three `_Ucopy` passes (0x0056F1F0) into the new block, destroy of the old range (0x0056D620) and the inline-capacity save.)
     */
    void GrowInsertDeepCopy(T* pos, const std::size_t newCapacity, const T* insStart, const T* insEnd)
    {
      static_assert(
        !IsIntrusiveWeakRefSlot<T>::value,
        "FastVectorN<T, N>::GrowInsertDeepCopy relocates elements without relinking their owner chains; an intrusive "
        "weak-ref slot has to go through the relinking lane instead"
      );
      T* const oldStart = this->start_;
      T* const oldEnd = this->end_;

      T* const newBuffer = detail::AllocateElements<T>(newCapacity);
      T* write = newBuffer;
      try {
        write = UninitializedCopyForward(write, oldStart, pos);
        write = UninitializedCopyForward(write, insStart, insEnd);
        write = UninitializedCopyForward(write, pos, oldEnd);
      } catch (...) {
        detail::DestroyRange(newBuffer, write);
        detail::FreeElements(newBuffer);
        throw;
      }

      detail::DestroyRange(oldStart, oldEnd);
      if (oldStart == this->originalVec_) {
        this->SaveInlineCapacity_();
      } else {
        detail::FreeElements(oldStart);
      }

      this->start_ = newBuffer;
      this->end_ = write;
      this->capacity_ = newBuffer + newCapacity;
    }

    /**
     * Address: 0x0047C910 (FUN_0047C910, gpg::fastvector_n64_char::GrowInsert)
     * Address: 0x004C7FD0 (FUN_004C7FD0, gpg::fastvector_n<LuaPlus::LuaObject>::GrowInsert lane)
     * Address: 0x005811A0 (FUN_005811A0, gpg::fastvector_Entity::GrowInsert)
     * Address: 0x00505BA0 (FUN_00505BA0, gpg::fastvector_UserEntity::GrowInsert)
     * Address: 0x00723340 (FUN_00723340, gpg::fastvector_n<moho::CollisionResult, 10>::GrowInsert lane)
     * Address: 0x007677D0 (FUN_007677D0, gpg::fastvector_n<Moho::PathQueueNeighbour, 200>::GrowInsert lane)
     * Address: 0x004FDC60 (FUN_004FDC60, gpg::fastvector_EntityOccupation::insert_new_range
     * -- the real binary's per-type "allocate new buffer, copy prefix +
     * inserted range + suffix" growth helper for the trivially-copyable
     * pointer-element lane, called from `FUN_004FD860`'s grow branch; this
     * modern `GrowInsert` consolidates every per-type growth helper (see the
     * other addresses on this block) into one template, same as the other
     * lanes)
     * Address: 0x008AF760 (FUN_008AF760, gpg::fastvector_n<moho::SoundHandleRecord,
     * 256>::GrowInsert -- the 40-byte (0x28) `SoundHandleRecord` element lane
     * reached from `FastVectorN::Resize`'s "Binary char lane grows through
     * GrowInsert(start, size, start, start)" call, itself reached from
     * `moho::EnsureSoundHandleStorage`'s `mSoundHandles.Resize(...)`
     * (CUserSoundManager.cpp). Asm-verified against FUN_008AF760.asm: `operator
     * new(40 * newCapacity)`, three `sub_8AFB90` (CopyRangeForward) calls for
     * the `[start,pos)+[insStart,insEnd)+[pos,end)` slices -- always the
     * degenerate zero-length-insert form at this call site, since `pos ==
     * insStart == insEnd == start` -- then the inline-vs-heap old-buffer
     * release (`+0x0C` origin compare, matching `originalVec_`/
     * `SaveInlineCapacity_`) and the `start_`/`end_`/`capacity_` field swap.
     * One divergence this template does not itself model: right after the
     * copy, for every element carried over from the OLD range specifically
     * (not the empty insert range), FUN_008AF760 also calls `FUN_008AB160`
     * per relocated element (0x008AF7E2 loop, stride 0x28) before releasing
     * the old buffer -- releasing the tracked-entity RB-tree each relocated
     * `SoundHandleRecord` still shares (by raw pointer value) with its
     * about-to-be-freed old-storage origin, and FUN_008AECF0/FUN_008AEE40
     * (reached the same way for brand-new slots) install a fresh empty
     * sentinel rather than carry the old tree forward. That is
     * `SoundHandleRecord`-specific business logic, not generic vector
     * mechanics, so it is NOT folded into this shared template (see RULE ONE,
     * CLAUDE.md) -- it is modeled as the caller-side
     * `RefreshTrackedEntitySetAfterRelocation` step `EnsureSoundHandleStorage`
     * runs over `[0, currentCount)` whenever this grow lane actually fires
     * (CUserSoundManager.cpp), the same "manager-level step wrapping the
     * generic Resize() call" idiom that file already uses for
     * `InitializeSoundHandleRecordRuntime` and `RebuildSoundHandleOwnerChains`.)
     *
     * What it does:
     * Allocates `newCapacity` elements and materializes
     * `[start, pos) + [insStart, insEnd) + [pos, end)` in the new storage.
     * A non-trivially-copyable element takes the construct-and-destroy lane
     * (`GrowInsertDeepCopy`); the bitwise relocation below is the POD emission.
     * Address: 0x0080AB00 (FUN_0080AB00 -- reallocating grow-insert for a 28-byte element; Allocates replacement storage for one 28-byte fastvector lane and materializes prefix/insert/suffix slices into the new storage.)
     * Address: 0x00561460 (FUN_00561460 -- reallocating grow-insert for a 28-byte element; Allocates replacement storage for one 28-byte fastvector lane and materializes prefix/insert/suffix slices into the new storage.)
     * Address: 0x005B5170 (FUN_005B5170 -- reallocating grow-insert for a 28-byte element; Allocates replacement storage for one 28-byte fastvector lane and materializes prefix/insert/suffix slices into the new storage.)
     * Address: 0x0080B080 (FUN_0080B080 -- reallocating grow-insert for a 24-byte element; Allocates replacement storage for one 24-byte fastvector lane and materializes prefix/insert/suffix slices into the new storage.)
     * Address: 0x0080B1E0 (FUN_0080B1E0 -- reallocating grow-insert for a 24-byte element; Allocates replacement storage for one 24-byte fastvector lane and materializes prefix/insert/suffix slices into the new storage.)
     * Address: 0x0080B310 (FUN_0080B310 -- reallocating grow-insert for a 24-byte element; Allocates replacement storage for one 24-byte fastvector lane and materializes prefix/insert/suffix slices into the new storage.)
     * Address: 0x004E7670 (FUN_004E7670 -- reallocating grow-insert for a 24-byte element; Allocates replacement storage for one 24-byte fastvector lane and materializes prefix/insert/suffix slices into the new storage.)
     * Address: 0x00548390 (FUN_00548390 -- reallocating grow-insert for a 20-byte element; Allocates replacement storage for one 20-byte fastvector lane and materializes prefix/insert/suffix slices into the new storage.)
     * Address: 0x0080F390 (FUN_0080F390 -- reallocating grow-insert for a 8-byte element; Allocates replacement storage for one 8-byte fastvector lane and materializes prefix/insert/suffix slices into the new storage.)
     * Address: 0x007A2600 (FUN_007A2600 -- reallocating grow-insert for a 8-byte element; Allocates replacement storage for one 8-byte fastvector lane and materializes prefix/insert/suffix slices into the new storage.)
     * Address: 0x0080F490 (FUN_0080F490 -- reallocating grow-insert for a 32-byte element; Allocates replacement storage for one 32-byte fastvector lane and materializes prefix/insert/suffix slices into the new storage.)
     * Address: 0x0081BBC0 (FUN_0081BBC0 -- reallocating grow-insert for a 12-byte element; Allocates replacement storage for one 12-byte fastvector lane and materializes prefix/insert/suffix slices into the new storage.)
     * Address: 0x005165A0 (FUN_005165A0 -- reallocating grow-insert for a 12-byte element; Allocates replacement storage for one 12-byte fastvector lane and materializes prefix/insert/suffix slices into the new storage.)
     * Address: 0x006C0F70 (FUN_006C0F70 -- reallocating grow-insert for a 16-byte element; 16-byte-stride specialization of the fastvector `_Insert_n_grow` reallocation path.)
     * Address: 0x0092CBF0 (FUN_0092CBF0 -- reallocating grow-insert for a 2-byte element; Allocates replacement storage for one 2-byte fastvector lane and materializes prefix/insert/suffix slices into the new storage.)
     * Address: 0x0080F590 (FUN_0080F590 -- reallocating grow-insert for a 4-byte element; Allocates replacement storage for one 4-byte fastvector lane and materializes prefix/insert/suffix slices into the new storage.)
     * Address: 0x0082E6D0 (FUN_0082E6D0 -- reallocating grow-insert for a 4-byte element; Allocates replacement storage for one 4-byte fastvector lane and materializes prefix/insert/suffix slices into the new storage.)
     * Address: 0x0084EC70 (FUN_0084EC70 -- reallocating grow-insert for a 4-byte element; Allocates replacement storage for one 4-byte fastvector lane and materializes prefix/insert/suffix slices into the new storage.)
     * Address: 0x00868430 (FUN_00868430 -- reallocating grow-insert for a 4-byte element; Allocates replacement storage for one 4-byte fastvector lane and materializes prefix/insert/suffix slices into the new storage.)
     * Address: 0x00540720 (FUN_00540720 -- reallocating grow-insert for a 4-byte element; Allocates replacement storage for one 4-byte fastvector lane and materializes prefix/insert/suffix slices into the new storage.)
     * Address: 0x0059D2A0 (FUN_0059D2A0 -- reallocating grow-insert for a 4-byte element; Allocates replacement storage for one 4-byte fastvector lane and materializes prefix/insert/suffix slices into the new storage.)
     * Address: 0x005C6C20 (FUN_005C6C20 -- reallocating grow-insert for a 4-byte element; Allocates replacement storage for one 4-byte fastvector lane and materializes prefix/insert/suffix slices into the new storage.)
     * Address: 0x005D43D0 (FUN_005D43D0 -- reallocating grow-insert for a 4-byte element; Allocates replacement storage for one 4-byte fastvector lane and materializes prefix/insert/suffix slices into the new storage.)
     * Address: 0x006FBD70 (FUN_006FBD70 -- reallocating grow-insert for a 4-byte element; Allocates replacement storage for one 4-byte fastvector lane and materializes prefix/insert/suffix slices into the new storage.)
     * Address: 0x00702D70 (FUN_00702D70 -- reallocating grow-insert for a 4-byte element; Allocates replacement storage for one 4-byte fastvector lane and materializes prefix/insert/suffix slices into the new storage.)
     * Address: 0x0072AA60 (FUN_0072AA60 -- reallocating grow-insert for a 4-byte element; Allocates replacement storage for one 4-byte fastvector lane and materializes prefix/insert/suffix slices into the new storage.)
     * Address: 0x00774190 (FUN_00774190 -- reallocating grow-insert for a 4-byte element; Allocates replacement storage for one 4-byte fastvector lane and materializes prefix/insert/suffix slices into the new storage.)
     * Address: 0x00553B90 (FUN_00553B90 -- reallocating grow-insert for a 4-byte element; Allocates replacement storage for one 4-byte fastvector lane and materializes prefix/insert/suffix slices into the new storage.)
     * Address: 0x00559190 (FUN_00559190 -- reallocating grow-insert for a 4-byte element; Allocates replacement storage for one 4-byte fastvector lane and materializes prefix/insert/suffix slices into the new storage.)
     * Address: 0x00657F60 (FUN_00657F60 -- reallocating grow-insert for a 4-byte element; Allocates replacement storage for one 4-byte fastvector lane and materializes prefix/insert/suffix slices into the new storage.)
     * Address: 0x008228C0 (FUN_008228C0 -- reallocating grow-insert for a 4-byte element; Allocates replacement storage for one 4-byte fastvector lane and materializes prefix/insert/suffix slices into the new storage.)
     * Address: 0x006AF6E0 (FUN_006AF6E0 -- reallocating grow-insert for a 8-byte element; Grows one 8-byte fastvector lane to `requestedCapacity` and materializes prefix/insert/suffix slices into the replacement storage, returning the requested element count lane.)
     */
    void GrowInsert(T* pos, const std::size_t newCapacity, const T* insStart, const T* insEnd)
    {
      static_assert(
        !IsIntrusiveWeakRefSlot<T>::value,
        "FastVectorN<T, N>::GrowInsert relocates elements without relinking their owner chains; an intrusive "
        "weak-ref slot has to go through the relinking lane instead"
      );
      if constexpr (!std::is_trivially_copyable_v<T>) {
        GrowInsertDeepCopy(pos, newCapacity, insStart, insEnd);
        return;
      } else {
        T* const newBuffer = detail::AllocateElements<T>(newCapacity);
        T* write = CopyRangeForward(newBuffer, this->start_, pos);
        write = CopyRangeForward(write, insStart, insEnd);
        write = CopyRangeForward(write, pos, this->end_);

        if (this->start_ == this->originalVec_) {
          this->SaveInlineCapacity_();
        } else {
          detail::FreeElements(this->start_);
        }

        this->start_ = newBuffer;
        this->end_ = write;
        this->capacity_ = newBuffer + newCapacity;
      }
    }

    /**
     * Copy 'count' elements from raw memory; expand to exact-fit heap if count > N
     */
    /**
     * Address: 0x00577220 (FUN_00577220, the `SFormationScriptSlot`
     * instantiation. It copies the incoming range forward through 0x005774B0
     * -- one of the twins cited on `CopyRangeForward` -- then hands the old
     * range to `ReleaseFormationScriptSlotCategoryStorage` (0x00570390) to
     * free each slot's category word lane, and only then rebases `end_`.
     *
     * The destroy-after-copy order matters and is why this is one body rather
     * than two: the source range may alias the destination when a vector is
     * rebound to its own inline buffer, so the old slots cannot be released
     * until their contents have been read out.
     *
     * Address: 0x00577010 (FUN_00577010, the same member's heap branch for that
 * element -- taken when the incoming count exceeds the inline capacity. It
 * sizes the block as `count * 8 - count` doubled three times, i.e.
 * `count * 0x38`, calls `operator new`, fills it through 0x005770F0 and then
 * releases the old range.)
 * Address: 0x005770F0 (FUN_005770F0, the uninitialised copy that fills it.
 * Per slot it copies the offset, universe handle and first-word index, then
 * *constructs* the embedded `fastvector_n` in place -- seating all four of
 * its lanes on the fresh inline buffer at `+0x18` -- before copying the words
 * and `mWeight`. That in-place construction is what distinguishes it from the
 * assigning copy at 0x00577450.)
 *
 * Reached only from `ResetFrom` (0x00576F10).
     *
     * Address: 0x00750A80 (FUN_00750A80, `gpg::core::FastVectorN<
     * moho::SExtraUnitDataPair, 1>::CopyFromRaw_` -- `pairs` sub-vector of
     * `moho::SExtraUnitData`, the element of `Sim::mSyncSerializeGroup2`.
     * Observed only ever called on a destination that was just reset to
     * inline (`ResetInline_`-equivalent, i.e. `count`/`capacity` start at
     * 0/1), under which condition its real 4-branch "reuse-or-grow assign"
     * shape (`destinationCount>=sourceCount` no-op-grow / `sourceCount>
     * destinationCapacity` grow-to-exactly-`sourceCount` / copy) collapses
     * to exactly this method's 2-branch "fits inline vs. `new T[count]`"
     * shape: `.c`-confirmed count<=1 assigns directly into the existing
     * (inline) `start_`, else calls `sub_74DBA0` to buy an exact
     * `count`-element block (`allocate_slots_checked`-guarded, matching
     * `new T[count]`) and copies into it. Reached from `msvc8::vector<
     * moho::SExtraUnitData>::vector(const vector&)` (`FUN_00753020`) and
     * its `uninit_fill_n`/`uninit_copy_n` element-construction emissions
     * (`FUN_00753AF0`, `FUN_00756A00` and siblings, `legacy/containers/
     * Vector.h`) via `SExtraUnitData`'s compiler-generated copy
     * constructor. Migrated off `Assign8ByteVectorRange` in
     * `gpg/core/containers/FastVectorInsertLanes.cpp` -- a RULE ONE
     * hand-rolled duplicate under a generic-looking name; see `Vector.h`'s
     * `push_back` citation for the full evidence chain.)
     */
    void CopyFromRaw_(const T* src, size_t count)
    {
      static_assert(
        !IsIntrusiveWeakRefSlot<T>::value,
        "FastVectorN<T, N>::CopyFromRaw_ relocates elements without relinking their owner chains; an intrusive "
        "weak-ref slot has to go through the relinking lane instead"
      );
      if (count == 0 || src == nullptr) {
        return;
      }

      // Callers reach here straight after `this->ResetInline_()`, so the live range is
      // empty and every slot written below is raw storage to construct into.
      if (count <= N) {
        if constexpr (std::is_trivially_copyable_v<T>) {
          std::memcpy(this->start_, src, count * ElemSize);
        } else {
          (void)detail::ConstructRangeForward(this->start_, src, src + count);
        }
        this->end_ = this->start_ + count;
        return;
      }

      // Need heap buffer of exact count (matches engine's "capacity_ = start_ + count")
      T* p = detail::AllocateElements<T>(count);
      if constexpr (std::is_trivially_copyable_v<T>) {
        std::memcpy(p, src, count * ElemSize);
      } else {
        try {
          (void)detail::ConstructRangeForward(p, src, src + count);
        } catch (...) {
          detail::FreeElements(p);
          throw;
        }
      }

      // Free previous heap buffer only if not using inline storage
      if (this->start_ && this->start_ != this->originalVec_) {
        detail::FreeElements(this->start_);
      } else if (this->start_ == this->originalVec_) {
        this->SaveInlineCapacity_();
      }

      this->start_ = p;
      this->end_ = p + count;
      this->capacity_ = p + count;
    }

    /** Reallocate to exactly newCap elements; preserve contents. */
    void GrowToCapacity(size_t newCap)
    {
      static_assert(
        !IsIntrusiveWeakRefSlot<T>::value,
        "FastVectorN<T, N>::GrowToCapacity relocates elements without relinking their owner chains; an intrusive "
        "weak-ref slot has to go through the relinking lane instead"
      );
      const size_t sz = this->Size();
      T* newBuf = detail::AllocateElements<T>(newCap);

      if constexpr (std::is_trivially_copyable_v<T>) {
        if (sz)
          std::memcpy(newBuf, this->start_, sz * ElemSize);
      } else {
        for (size_t i = 0; i < sz; ++i)
          ::new (static_cast<void*>(newBuf + i)) T(std::move(this->start_[i]));
        detail::DestroyRange(this->start_, this->end_);
      }

      if (this->start_ != this->originalVec_) {
        detail::FreeElements(this->start_);
      } else {
        this->SaveInlineCapacity_();
      }

      this->start_ = newBuf;
      this->end_ = newBuf + sz;
      this->capacity_ = newBuf + newCap;
    }
  };

  namespace legacy
  {
    template <class T>
    [[nodiscard]] inline FastVector<T>& CopyFrom(FastVector<T>& dst, const FastVector<T>& src, T* inlineOrigin);

    /**
     * Address: 0x00402C20 (FUN_00402C20, fastvector_uint copy-range helper)
     *
     * What it does:
     * Copies `[srcBegin, srcEnd)` into `out` and returns the advanced output pointer.
     * Matches the legacy helper shape that also advances when `out == nullptr`.
     */
    template <class T>
    [[nodiscard]] inline T* CopyRangeForward(T* out, const T* srcBegin, const T* srcEnd) noexcept
    {
      if constexpr (std::is_trivially_copyable_v<T> && sizeof(T) == sizeof(std::uint32_t)) {
        auto* const outWords = reinterpret_cast<std::uint32_t*>(out);
        auto* const beginWords = reinterpret_cast<const std::uint32_t*>(srcBegin);
        auto* const endWords = reinterpret_cast<const std::uint32_t*>(srcEnd);
        return reinterpret_cast<T*>(detail::CopyDwordRangeForward(outWords, beginWords, endWords));
      }

      std::uintptr_t outAddress = reinterpret_cast<std::uintptr_t>(out);
      for (const T* cur = srcBegin; cur != srcEnd; ++cur) {
        if (outAddress != 0u) {
          *reinterpret_cast<T*>(outAddress) = *cur;
        }
        outAddress += sizeof(T);
      }
      return reinterpret_cast<T*>(outAddress);
    }

    /**
     * Address: 0x004021D0 (FUN_004021D0, fastvector_n2<uint> inline init)
     *
     * What it does:
     * Rebinds `fastvector_n` state to its inline buffer and marks that buffer as origin.
     */
    template <class T, std::size_t N>
    [[nodiscard]] inline FastVectorN<T, N>& InitializeInlineStorage(FastVectorN<T, N>& vec) noexcept
    {
      vec.originalVec_ = vec.InlineStorage();
      vec.start_ = vec.InlineStorage();
      vec.end_ = vec.InlineStorage();
      vec.capacity_ = vec.InlineStorage() + N;
      return vec;
    }

    /**
     * Address: 0x004021F0 (FUN_004021F0)
     * Address: 0x004022A0 (FUN_004022A0)
     * Address: 0x007423F0 (FUN_007423F0, `gpg::core::FastVectorN<
     * moho::SExtraUnitDataPair, 1>::ResetStorageToInline` -- `pairs`
     * sub-vector of `moho::SExtraUnitData` (`Unit.h`), the element of
     * `Sim::mSyncSerializeGroup2`. Byte-for-byte match: `if (start ==
     * originalVec_) { end_ = start_; return; } operator delete[](start_);
     * start_ = originalVec_; capacity_ = *reinterpret_cast<T**>(start_);
     * end_ = start_;` -- exactly this free function's body. Called per
     * element, inlined into a range loop, by `msvc8::vector<
     * moho::SExtraUnitData>::destroy_range` (`FUN_00742170`,
     * `legacy/containers/Vector.h`) when the outer vector destroys or
     * reallocates its elements. Migrated off
     * `ResetInlineQwordVectorStorage` in
     * `gpg/core/containers/FastVectorInsertLanes.cpp` -- a RULE ONE
     * hand-rolled duplicate of this exact free function under a raw-offset
     * `InlineQwordVectorWithTagRuntimeView` struct name; see
     * `Vector.h`'s `push_back` citation for the full evidence chain.
     *
     * The cited binary match is byte-identical only because
     * `SExtraUnitDataPair` is a trivially-destructible 8-byte POD -- for a
     * trivial T, `delete[] p` and a raw `operator delete[](p)` call compile
     * to the same instructions, so the two forms are indistinguishable in
     * the decompile. They stop being equivalent the moment this template is
     * instantiated with a non-trivially-destructible T: `new T[n]` then
     * writes a 4-byte element-count cookie before the returned pointer, and
     * only the `delete[]` expression knows to back up over that cookie
     * before calling the deallocation function. A raw
     * `operator delete[](vec.start_)` call frees `vec.start_` itself --
     * base+4 relative to the true allocation -- corrupting the free list and
     * later handing out a block that overlaps a live one. This exact shape
     * (a raw `::operator delete[]` call freeing a `new T[]`'d buffer of a
     * non-trivial-dtor T) is the confirmed root cause of a wild-free heap
     * corruption traced and fixed elsewhere in the engine (`Unit.cpp`,
     * `ClearWeaponInfoVectorAndRebindInline`, commit 3cd159aa). Delegating
     * to the member `ResetStorageToInline()` (which already uses the
     * `delete[]` expression via `ResetInline_()`) keeps this free function
     * correct for every instantiation instead of only the one currently
     * exercised.)
     *
     * What it does:
     * Releases heap-backed storage (if any) and restores inline storage pointers.
     */
    template <class T, std::size_t N>
    inline void ResetStorageToInline(FastVectorN<T, N>& vec) noexcept
    {
      vec.ResetStorageToInline();
    }

    /**
     * Address: 0x00402220 (FUN_00402220, gpg::fastvector_uint::resize helper lane)
     *
     * What it does:
     * Rebinds destination `fastvector_n` to inline storage without freeing and copies
     * source vector content into it.
     */
    template <class T, std::size_t N>
    [[nodiscard]] inline FastVectorN<T, N>& RebindInlineAndCopy(FastVectorN<T, N>& dst, const FastVector<T>& src)
    {
      InitializeInlineStorage(dst);
      CopyFrom(static_cast<FastVector<T>&>(dst), src, dst.originalVec_);
      return dst;
    }

    /**
     * Address: 0x00402270 (FUN_00402270)
     *
     * What it does:
     * Returns raw begin pointer for legacy fastvector storage.
     */
    template <class T>
    [[nodiscard]] inline T* BeginPtr(FastVector<T>& vec) noexcept
    {
      return vec.start_;
    }

    /**
     * Address: 0x00402280 (FUN_00402280)
     *
     * What it does:
     * Returns true when begin == end.
     */
    template <class T>
    [[nodiscard]] inline bool IsEmpty(const FastVector<T>& vec) noexcept
    {
      return vec.start_ == vec.end_;
    }

    /**
     * Address: 0x00402290 (FUN_00402290)
     *
     * What it does:
     * Returns element count from pointer distance.
     */
    template <class T>
    [[nodiscard]] inline std::size_t Count(const FastVector<T>& vec) noexcept
    {
      return static_cast<std::size_t>(vec.end_ - vec.start_);
    }

    /**
     * Address: 0x004028D0 (FUN_004028D0)
     *
     * What it does:
     * Returns total addressable element slots (`capacity - begin`).
     */
    template <class T>
    [[nodiscard]] inline std::size_t CapacityCount(const FastVector<T>& vec) noexcept
    {
      return static_cast<std::size_t>(vec.capacity_ - vec.start_);
    }

    /**
     * Address: 0x00402350 (FUN_00402350)
     * Address: 0x00402360 (FUN_00402360)
     *
     * What it does:
     * Returns pointer to indexed element slot from begin pointer.
     */
    template <class T>
    [[nodiscard]] inline T* IndexPtr(FastVector<T>& vec, const std::size_t index) noexcept
    {
      return vec.start_ + index;
    }

    /**
     * Address: 0x004026F0 (FUN_004026F0)
     *
     * What it does:
     * Binds vector pointers to an external buffer window.
     */
    template <class T>
    [[nodiscard]] inline FastVector<T>&
    BindExternalWindow(FastVector<T>& vec, const std::size_t capacity, T* buffer, T*& metadataPtr) noexcept
    {
      vec.start_ = buffer;
      vec.end_ = buffer;
      vec.capacity_ = buffer + capacity;
      metadataPtr = buffer;
      return vec;
    }

    /**
     * Address: 0x004029B0 (FUN_004029B0, func_VecResize)
     *
     * What it does:
     * Allocates exact-capacity storage, copies prefix/insert/suffix slices, then
     * swaps vector storage preserving inline-origin semantics.
     */
    template <class T>
    [[nodiscard]] inline std::size_t ReallocateForInsert(
      FastVector<T>& vec,
      std::size_t requestedCapacity,
      T* splitPos,
      const T* insertBegin,
      const T* insertEnd,
      T* inlineOrigin = nullptr
    )
    {
      static_assert(
        std::is_trivially_copyable_v<T>, "Legacy fastvector ABI helpers require trivially copyable element types."
      );

      auto* const newStart = detail::AllocateElements<T>(requestedCapacity);
      T* cursor = newStart;
      cursor = CopyRangeForward(cursor, vec.start_, splitPos);
      cursor = CopyRangeForward(cursor, insertBegin, insertEnd);
      cursor = CopyRangeForward(cursor, splitPos, vec.end_);

      if (inlineOrigin && vec.start_ == inlineOrigin) {
        *reinterpret_cast<T**>(inlineOrigin) = vec.capacity_;
      } else if (vec.start_) {
        detail::FreeElements(vec.start_);
      }

      vec.start_ = newStart;
      vec.end_ = cursor;
      vec.capacity_ = newStart + requestedCapacity;
      return requestedCapacity;
    }

    /**
     * Address: 0x00402B10 (FUN_00402B10)
     *
     * What it does:
     * Inserts `[sourceBegin, sourceEnd)` before `insertPos`, growing storage when needed.
     */
    template <class T>
    [[nodiscard]] inline T*
    InsertRange(FastVector<T>& vec, T* insertPos, const T* sourceBegin, const T* sourceEnd, T* inlineOrigin = nullptr)
    {
      static_assert(
        std::is_trivially_copyable_v<T>, "Legacy fastvector ABI helpers require trivially copyable element types."
      );

      const std::size_t insertCount = static_cast<std::size_t>(sourceEnd - sourceBegin);
      if (insertCount == 0u) {
        return vec.end_;
      }

      const std::size_t currentSize = static_cast<std::size_t>(vec.end_ - vec.start_);
      std::size_t requiredSize = currentSize + insertCount;
      const std::size_t currentCapacity = static_cast<std::size_t>(vec.capacity_ - vec.start_);
      if (requiredSize > currentCapacity) {
        const std::size_t doubledCapacity = currentCapacity * 2u;
        if (requiredSize < doubledCapacity) {
          requiredSize = doubledCapacity;
        }
        ReallocateForInsert(vec, requiredSize, insertPos, sourceBegin, sourceEnd, inlineOrigin);
        return vec.end_;
      }

      T* const oldFinish = vec.end_;
      if (insertPos + insertCount > oldFinish) {
        const std::size_t tailCount = static_cast<std::size_t>(oldFinish - insertPos);
        const T* const overflowSource = sourceBegin + tailCount;

        vec.end_ = CopyRangeForward(oldFinish, overflowSource, sourceEnd);
        vec.end_ = CopyRangeForward(vec.end_, insertPos, oldFinish);
        if (tailCount != 0u) {
          std::memmove(insertPos, sourceBegin, tailCount * sizeof(T));
        }
        return vec.end_;
      }

      T* const tailCopyBegin = oldFinish - insertCount;
      vec.end_ = CopyRangeForward(oldFinish, tailCopyBegin, oldFinish);

      const std::size_t middleCount = static_cast<std::size_t>(tailCopyBegin - insertPos);
      if (middleCount != 0u) {
        std::memmove(oldFinish - middleCount, insertPos, middleCount * sizeof(T));
      }
      std::memmove(insertPos, sourceBegin, insertCount * sizeof(T));
      return vec.end_;
    }

    /**
     * Address: 0x004028E0 (FUN_004028E0, gpg::fastvector_uint::cpy)
     *
     * What it does:
     * Copies source vector data into destination while preserving legacy growth and
     * append-path behavior.
     */
    template <class T>
    [[nodiscard]] inline FastVector<T>&
    CopyFrom(FastVector<T>& dst, const FastVector<T>& src, T* inlineOrigin = nullptr)
    {
      static_assert(
        std::is_trivially_copyable_v<T>, "Legacy fastvector ABI helpers require trivially copyable element types."
      );

      if (&dst == &src) {
        return dst;
      }

      const std::size_t currentSize = static_cast<std::size_t>(dst.end_ - dst.start_);
      const std::size_t sourceSize = static_cast<std::size_t>(src.end_ - src.start_);
      if (currentSize >= sourceSize) {
        if (sourceSize != 0u) {
          std::memmove(dst.start_, src.start_, sourceSize * sizeof(T));
        }
        dst.end_ = dst.start_ + sourceSize;
        return dst;
      }

      const std::size_t capacity = static_cast<std::size_t>(dst.capacity_ - dst.start_);
      if (sourceSize > capacity) {
        ReallocateForInsert(dst, sourceSize, dst.start_, dst.start_, dst.start_, inlineOrigin);
      }

      if (currentSize != 0u) {
        std::memmove(dst.start_, src.start_, currentSize * sizeof(T));
      }
      InsertRange(dst, dst.end_, src.start_ + currentSize, src.end_, inlineOrigin);
      return dst;
    }

    /**
     * Address: 0x00402690 (FUN_00402690)
     *
     * What it does:
     * Thin wrapper for legacy vector copy path.
     */
    template <class T>
    [[nodiscard]] inline FastVector<T>&
    CopyFromWrapper(FastVector<T>& dst, const FastVector<T>& src, T* inlineOrigin = nullptr)
    {
      return CopyFrom(dst, src, inlineOrigin);
    }

    /**
     * Address: 0x004026A0 (FUN_004026A0)
     *
     * What it does:
     * Ensures vector capacity for `minCapacity` elements via legacy reallocation path.
     */
    template <class T>
    [[nodiscard]] inline std::size_t
    EnsureCapacity(FastVector<T>& vec, const std::size_t minCapacity, T* inlineOrigin = nullptr)
    {
      const std::size_t currentCapacity = static_cast<std::size_t>(vec.capacity_ - vec.start_);
      if (minCapacity > currentCapacity) {
        return ReallocateForInsert(vec, minCapacity, vec.start_, vec.start_, vec.start_, inlineOrigin);
      }
      return minCapacity;
    }

    /**
     * Address: 0x004026C0 (FUN_004026C0)
     *
     * What it does:
     * Moves prefix data from `sourceBegin` to `destBegin` and updates finish pointer.
     */
    template <class T>
    [[nodiscard]] inline T* MovePrefixAndSetEnd(FastVector<T>& vec, T* sourceBegin, T* destBegin)
    {
      static_assert(
        std::is_trivially_copyable_v<T>, "Legacy fastvector ABI helpers require trivially copyable element types."
      );

      if (destBegin != sourceBegin) {
        const std::size_t count = static_cast<std::size_t>(vec.end_ - sourceBegin);
        T* const newFinish = destBegin + count;
        if (count != 0u) {
          std::memmove(destBegin, sourceBegin, count * sizeof(T));
        }
        vec.end_ = newFinish;
      }
      return destBegin;
    }
  } // namespace legacy

  static_assert(sizeof(FastVector<int>) == 0x0C, "FastVector<int> must be 0x0C (start/end/cap)");
  static_assert(sizeof(FastVectorN<int, 4>) == 0x20, "FastVectorN<int,4> must be 0x20");
  static_assert(
    sizeof(FastVectorN<std::uint32_t, 4>) == 0x20,
    "FastVectorN<uint,4> must be 0x20 (start/end/cap/originalVec + 4 inline uints; FUN_006E5720 ctor lane)"
  );
  static_assert(sizeof(FastVectorN<char, 64>) == 0x50, "FastVectorN<char,64> must be 0x50");

  // Sibling-safety proof for the intrusive weak-ref relink gate: the trait is
  // opt-in (default std::false_type) and specialized true only for
  // moho::SWeakRefSlot (see Unit.h). Every other FastVector(N) element type —
  // the trivially-relocatable char / pointer / POD lanes (FUN_0047C590,
  // FUN_0057FE30, FUN_005050A0, FUN_0059CC10, FUN_0056B2F0) and the deep-copy
  // lanes (msvc8::string FUN_0083B6F0, LuaObject FUN_004C7EB0,
  // boost::shared_ptr FUN_0084E570) — keeps its existing InsertAt / push_back
  // branch because IsIntrusiveWeakRefSlot<T>::value stays false. Prove it for the
  // representative element categories nameable here; the moho POD/deep-copy
  // element proofs live with those types.
  static_assert(!IsIntrusiveWeakRefSlot<char>::value, "char must not take the intrusive relink lane");
  static_assert(!IsIntrusiveWeakRefSlot<int>::value, "int must not take the intrusive relink lane");
  static_assert(!IsIntrusiveWeakRefSlot<std::uint32_t>::value, "uint must not take the intrusive relink lane");
  static_assert(!IsIntrusiveWeakRefSlot<void*>::value, "raw pointer lanes must not take the intrusive relink lane");
  static_assert(
    !IsIntrusiveWeakRefSlot<IntrusiveWeakLinkNode>::value,
    "the untyped node view itself must not opt into the relink lane"
  );
} // namespace gpg::core

namespace gpg
{
  // Binary symbols use gpg::fastvector / gpg::fastvector_n.
  template <class T>
  using fastvector = core::FastVector<T>;

  template <class T, std::size_t N>
  using fastvector_n = core::FastVectorN<T, N>;

  /**
   * Address: 0x004021D0 (FUN_004021D0)
   *
   * What it does:
   * Initializes a `fastvector_n<T,2>` lane to inline storage without
   * mutating inline-capacity sentinel words.
   */
  template <class T>
  [[nodiscard]] inline fastvector_n<T, 2>& FastVectorN2InitInlineNoHeader(fastvector_n<T, 2>& storage) noexcept
  {
    storage.start_ = storage.InlineStorage();
    storage.end_ = storage.InlineStorage();
    storage.capacity_ = storage.InlineStorage() + 2;
    storage.originalVec_ = storage.InlineStorage();
    return storage;
  }

  /**
   * Address: 0x00402220 (FUN_00402220, gpg::fastvector_uint::resize helper)
   *
   * What it does:
   * Rebinds destination fastvector_n2 to inline storage and copies source
   * runtime content into it.
   */
  template <class T>
  [[nodiscard]] inline fastvector_n<T, 2>*
  FastVectorN2RebindAndCopy(fastvector_n<T, 2>* destination, const fastvector_n<T, 2>* source)
  {
    if (!destination || !source) {
      return destination;
    }

    FastVectorN2InitInlineNoHeader(*destination);
    destination->AssignFrom(*source);
    return destination;
  }

} // namespace gpg
