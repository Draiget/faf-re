#pragma once

#include <algorithm>
#include <cstddef> // std::ptrdiff_t
#include <cstdint>
#include <cstring>
#include <iterator> // reverse_iterator
#include <memory>
#include <new>
#include <type_traits>

namespace gpg
{
  // Forward declarations so gpg::core::FastVectorN's inline members can name the
  // runtime-view resize helpers (defined later in this header, in namespace gpg).
  template <class T>
  struct fastvector_runtime_view;

  template <class T>
  fastvector_runtime_view<T>& AsFastVectorRuntimeView(void* object) noexcept;

  template <class T>
  void FastVectorRuntimeResizeFill(const T* fillValue, const unsigned int newSize, fastvector_runtime_view<T>& view);

  template <class T>
  [[nodiscard]] const fastvector_runtime_view<T>& AsFastVectorRuntimeView(const void* object) noexcept;

  template <class T>
  fastvector_runtime_view<T>*
  FastVectorRuntimeCopyAssign(fastvector_runtime_view<T>& destination, const fastvector_runtime_view<T>& source);
} // namespace gpg

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

    ~FastVector()
    {
      delete[] start_;
    }

    /**
     * Returns number of elements.
     */
    [[nodiscard]]
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
     *
     * Reserve at least n elements; does not shrink.
     */
    void Reserve(size_t n)
    {
      if (Capacity() >= n)
        return;
      const size_t oldSize = Size();
      T* newBuf = new T[n];
      // Trivially copyable path
      if constexpr (std::is_trivially_copyable_v<T>) {
        if (oldSize)
          std::memcpy(newBuf, start_, oldSize * elem_);
      } else {
        for (size_t i = 0; i < oldSize; ++i)
          newBuf[i] = std::move(start_[i]);
      }
      delete[] start_;
      start_ = newBuf;
      end_ = newBuf + oldSize;
      capacity_ = newBuf + n;
    }

    /**
     * Append by copy; grows capacity exponentially.
     */
    void PushBack(const T& v)
    {
      if (end_ == capacity_) {
        const size_t newCap = Capacity() ? Capacity() * 2 : 4;
        Reserve(newCap);
      }
      *end_++ = v;
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
      const size_t current = Size();
      if (n <= current) {
        end_ = ptr_at(start_, n);
        return;
      }

      Reserve(n);
      if constexpr (std::is_trivially_constructible_v<T>) {
        std::memset(ptr_at(start_, current), 0, (n - current) * elem_);
      } else {
        for (size_t i = current; i < n; ++i) {
          start_[i] = T{};
        }
      }
      end_ = ptr_at(start_, n);
    }

    void resize(const size_t n, const value_type& value)
    {
      const size_t current = Size();
      if (n <= current) {
        end_ = ptr_at(start_, n);
        return;
      }

      Reserve(n);
      for (size_t i = current; i < n; ++i) {
        start_[i] = value;
      }
      end_ = ptr_at(start_, n);
    }

    iterator erase(iterator pos)
    {
      return erase(pos, pos + 1);
    }

    iterator erase(iterator first, iterator last)
    {
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
      end_ = write;
      return first;
    }

    /** Clears size to zero without releasing memory. */
    void Clear() noexcept
    {
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
     * `gpg::FastVectorRuntimeResizeFill`, which is this method's
     * implementation. Only `FastVectorN` had a `Resize` until 2026-08-21,
     * so every base-`FastVector` caller in the engine reached around the
     * container through `AsFastVectorRuntimeView` -- see RULE ONE in
     * CLAUDE.md.
     */
    void Resize(const size_t newSize, const T& fill = T{})
    {
      gpg::FastVectorRuntimeResizeFill<T>(
        &fill, static_cast<unsigned int>(newSize), gpg::AsFastVectorRuntimeView<T>(this)
      );
    }

    FastVector(const FastVector&) = delete;

    /**
     * Copy assignment.
     *
     * MSVC emits one out-of-line body per element type; the recovered
     * addresses live on `FastVectorRuntimeCopyAssign` below, which is this
     * operator's implementation. The shape is VC8's: when the destination is
     * already at least as long as the source, the elements are overwritten in
     * place and `mLast` is rebased; otherwise capacity is grown, the
     * overlapping prefix is overwritten, and the remainder is appended.
     *
     * This was `= delete` until 2026-08-21, which forced every caller in the
     * engine to reach around the container through
     * `AsFastVectorRuntimeView` -- see RULE ONE in CLAUDE.md.
     */
    FastVector& operator=(const FastVector& other)
    {
      if (this != &other) {
        (void)gpg::FastVectorRuntimeCopyAssign<T>(
          gpg::AsFastVectorRuntimeView<T>(this), gpg::AsFastVectorRuntimeView<T>(&other)
        );
      }
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
        delete[] start_;
        start_ = other.start_;
        end_ = other.end_;
        capacity_ = other.capacity_;
        other.start_ = other.end_ = other.capacity_ = nullptr;
      }
      return *this;
    }
  };

  /**
   * Small-buffer optimized vector based on FastVector.
   * No dependency on Base internals (has its own byte helpers).
   */
  template <class T, size_t N>
  class FastVectorN : public FastVector<T>
  {
    using Base = FastVector<T>;

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
    T* originalVec_{};
    alignas(T) T inlineVec_[N];

    /**
     * Address: 0x0047EF60 (FUN_0047EF60, fastvector_n64_char ctor lane)
     * Address: 0x0047F480 (FUN_0047F480, fastvector_n64_char ctor alias lane)
     *
     * What it does:
     * Initializes vector pointer lanes to the inline storage window and
     * records inline-origin metadata.
     */
    FastVectorN()
    {
      this->start_ = inlineVec_;
      this->end_ = inlineVec_;
      this->capacity_ = inlineVec_ + N;
      originalVec_ = inlineVec_;
      SaveInlineCapacity_();
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
     * FastVectorRuntimeResizeFill). This is the emitted constructor the decoder
     * uses to preallocate the raw entity-id scratch buffer.
     */
    explicit FastVectorN(std::size_t count)
    {
      RebindInlineNoFree();
      const T zeroFill{};
      gpg::FastVectorRuntimeResizeFill<T>(
        &zeroFill, static_cast<unsigned int>(count), gpg::AsFastVectorRuntimeView<T>(this)
      );
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
     */
    FastVectorN(const FastVectorN& other)
      : FastVectorN()
    {
      this->ResetFrom(other);
    }

    FastVectorN& operator=(const FastVectorN& other)
    {
      if (this != &other) {
        this->ResetFrom(other);
      }
      return *this;
    }

    ~FastVectorN()
    {
      // Free heap only; inline buffer must not be freed
      if (this->start_ && this->start_ != originalVec_) {
        delete[] this->start_;
      }
      // Prevent Base dtor from touching inline storage
      this->start_ = this->end_ = this->capacity_ = nullptr;
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
     * Append by copy; grows capacity exponentially.
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
        *this->end_ = value;
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
     */
    void Resize(size_t newSize, const T& fill = T{})
    {
      const size_t sz = this->Size();
      if (newSize < sz) {
        this->end_ = this->start_ + newSize;
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
          if constexpr (std::is_copy_assignable_v<T>) {
            *slot = fill;
          } else if constexpr (std::is_copy_constructible_v<T>) {
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
     * Address: 0x0056B2F0 (FUN_0056B2F0, gpg::fastvector_n<Moho::SFormationLinkedUnitRef, 4>::InsertAt)
     * Address: 0x0084E570 (FUN_0084E570, gpg::fastvector_n<boost::shared_ptr<Moho::CMauiFrame>, 2>::InsertAt)
     * Address: 0x0083B6F0 (FUN_0083B6F0, gpg::fastvector_n<msvc8::string, 4>::InsertAt)
     * Address: 0x00767370 (FUN_00767370, gpg::fastvector_n<Moho::PathQueueNeighbour, 200>::InsertAt)
     *
     * What it does:
     * Inserts one element range `[insStart, insEnd)` before `pos`, growing
     * storage when required.
     *
     * Two distinct emissions share this template, gated on element triviality:
     *  - Trivially-relocatable T (char @0x0047C590; the pointer lanes Entity ptr
     *    @0x0057FE30 and UserEntity ptr @0x005050A0; and the POD structs
     *    SAssignedLocInfo @0x0059CC10, SFormationLinkedUnitRef @0x0056B2F0) blit
     *    the tail with memcpy/memmove (the fast path below).
     *  - Deep-copy T (msvc8::string @0x0083B6F0, LuaPlus::LuaObject @0x004C7EB0,
     *    boost::shared_ptr<CMauiFrame> @0x0084E570) must NOT relocate raw bytes
     *    (that would shallow-copy owned heap pointers and double-free). Those
     *    emissions shift elements one at a time via copy-construct
     *    (UninitializedCopyForward, binary _Ucopy) into the freshly grown tail
     *    and copy-assign (CopyBackwardAssign, binary std::_Copy_backward) over
     *    live slots, mirroring std::vector::insert on a non-trivial value type.
     *    The branch structure (fits-in-tail vs. spills-past-end vs. grow) is
     *    identical across both emissions; only the per-element operation differs.
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
      }

      if constexpr (!std::is_trivially_copyable_v<T>) {
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
      }

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

    void Append(T& o)
    {
      if (this->end_ == this->capacity_) {
        this->InsertAt(this->end_, &o, &o + 1);
      } else {
        if (this->end_ != nullptr) {
          *this->end_ = o;
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
    void ResetFrom(const FastVector<T>& src)
    {
      ResetInline_();
      CopyFromRaw_(src.start_, static_cast<size_t>(src.end_ - src.start_));
    }

    // Reset to inline storage and copy from another FastVectorN
    void ResetFrom(const FastVectorN<T, N>& src)
    {
      ResetInline_();
      CopyFromRaw_(src.start_, static_cast<size_t>(src.end_ - src.start_));
    }

    /**
     * Address: 0x004021F0 (FUN_004021F0)
     * Address: 0x004022A0 (FUN_004022A0)
     *
     * What it does:
     * if heap-backed -> free heap and restore inline pointers from saved header;
     * otherwise only reset end to start.
     */
    void ResetStorageToInline() noexcept
    {
      ResetInline_();
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
      originalVec_ = inlineVec_;
      this->start_ = inlineVec_;
      this->end_ = inlineVec_;
      this->capacity_ = inlineVec_ + N;
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
      return this->start_ == originalVec_;
    }

    /**
     * Save inline capacity pointer into inline header word.
     */
    void SaveInlineCapacityHeader() noexcept
    {
      SaveInlineCapacity_();
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
     *
     * What it does:
     * Copy-CONSTRUCTS `[copyBegin, copyEnd)` into raw storage at `dest` and
     * returns the advanced destination pointer. Mirrors the binary helper that
     * default-initializes each destination slot (`_Myres=15,_Mysize=0`) and then
     * `assign`s the source string; expressed here as placement-new copy so
     * owned heap buffers are deep-copied, never aliased. Advances without
     * writing when `dest == nullptr`, matching the binary's null-guarded lane.
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

      T* const newBuffer = new T[newCapacity];

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

      if (oldStart == originalVec_) {
        SaveInlineCapacity_();
      } else {
        delete[] oldStart;
      }

      this->start_ = newBuffer;
      this->end_ = reinterpret_cast<T*>(write);
      this->capacity_ = newBuffer + newCapacity;
    }

    /**
     * Address: 0x00658200 (FUN_00658200, std::vector<std::string>::_Insert_n grow lane)
     *
     * What it does:
     * Deep-copy grow-and-insert for non-trivially-relocatable T (the reallocate
     * arm of FUN_0083B6F0 / FUN_004C7EB0 / FUN_0084E570). Allocates a typed
     * `newCapacity` buffer and copy-ASSIGNS the three slices
     * `[start, pos) + [insStart, insEnd) + [pos, end)` into it, so each element's
     * owned storage is deep-copied (never aliased). The binary emits raw
     * `operator new` + `_Ucopy` (construct) + `_Destroy_range`; in this typed
      * reconstruction the `new T[]` slots are default-constructed and then
      * copy-assigned. The old live range is destroyed immediately after the
      * copies succeed (including inline-origin elements), matching the binary's
      * `_Destroy_range`; inline C++ subobjects are reconstructed empty so the
      * enclosing array remains safely destructible. A `unique_ptr` owns the
      * replacement through every throwing copy, preserving unwind cleanup and
      * leaving the vector unchanged until all copies complete.
     */
    void GrowInsertDeepCopy(T* pos, const std::size_t newCapacity, const T* insStart, const T* insEnd)
    {
      T* const oldStart = this->start_;
      T* const oldEnd = this->end_;

      std::unique_ptr<T[]> replacement{new T[newCapacity]};
      T* const newBuffer = replacement.get();
      T* write = CopyRangeForward(newBuffer, oldStart, pos);
      write = CopyRangeForward(write, insStart, insEnd);
      write = CopyRangeForward(write, pos, oldEnd);

      if (oldStart == originalVec_) {
        // The inline array remains a live C++ subobject after switching to heap
        // storage. Destroy the displaced values now, exactly where the binary's
        // `_Destroy_range` runs, then reconstruct empty slots so the enclosing
        // array can still be destroyed safely at scope exit.
        for (T* value = oldStart; value != oldEnd; ++value) {
          value->~T();
          ::new (static_cast<void*>(value)) T();
        }
      } else {
        delete[] oldStart;
      }

      this->start_ = newBuffer;
      this->end_ = write;
      this->capacity_ = newBuffer + newCapacity;
      (void)replacement.release();
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
     *
     * What it does:
     * Allocates `newCapacity` elements and materializes
     * `[start, pos) + [insStart, insEnd) + [pos, end)` in the new storage.
     */
    void GrowInsert(T* pos, const std::size_t newCapacity, const T* insStart, const T* insEnd)
    {
      T* const newBuffer = new T[newCapacity];
      T* write = CopyRangeForward(newBuffer, this->start_, pos);
      write = CopyRangeForward(write, insStart, insEnd);
      write = CopyRangeForward(write, pos, this->end_);

      if (this->start_ == originalVec_) {
        SaveInlineCapacity_();
      } else {
        delete[] this->start_;
      }

      this->start_ = newBuffer;
      this->end_ = write;
      this->capacity_ = newBuffer + newCapacity;
    }

    /**
     * Rebind this container to its inline buffer (like func_Reset_fastvector_n prologue)
     */
    void ResetInline_() noexcept
    {
      if (this->start_ != originalVec_) {
        delete[] this->start_;
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
     * Copy 'count' elements from raw memory; expand to exact-fit heap if count > N
     */
    void CopyFromRaw_(const T* src, size_t count)
    {
      if (count == 0 || src == nullptr) {
        return;
      }

      if (count <= N) {
        if constexpr (std::is_trivially_copyable_v<T>) {
          std::memcpy(this->start_, src, count * ElemSize);
        } else {
          for (size_t i = 0; i < count; ++i)
            this->start_[i] = src[i];
        }
        this->end_ = this->start_ + count;
        return;
      }

      // Need heap buffer of exact count (matches engine's "capacity_ = start_ + count")
      T* p = new T[count];
      if constexpr (std::is_trivially_copyable_v<T>) {
        std::memcpy(p, src, count * ElemSize);
      } else {
        for (size_t i = 0; i < count; ++i)
          p[i] = src[i];
      }

      // Free previous heap buffer only if not using inline storage
      if (this->start_ && this->start_ != originalVec_) {
        delete[] this->start_;
      } else if (this->start_ == originalVec_) {
        SaveInlineCapacity_();
      }

      this->start_ = p;
      this->end_ = p + count;
      this->capacity_ = p + count;
    }

    /** Reallocate to exactly newCap elements; preserve contents. */
    void GrowToCapacity(size_t newCap)
    {
      const size_t sz = this->Size();
      T* newBuf = new T[newCap];

      if constexpr (std::is_trivially_copyable_v<T>) {
        if (sz)
          std::memcpy(newBuf, this->start_, sz * ElemSize);
      } else {
        for (size_t i = 0; i < sz; ++i)
          newBuf[i] = std::move(this->start_[i]);
      }

      if (this->start_ != originalVec_) {
        delete[] this->start_;
      } else {
        SaveInlineCapacity_();
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
      vec.originalVec_ = vec.inlineVec_;
      vec.start_ = vec.inlineVec_;
      vec.end_ = vec.inlineVec_;
      vec.capacity_ = vec.inlineVec_ + N;
      return vec;
    }

    /**
     * Address: 0x004021F0 (FUN_004021F0)
     * Address: 0x004022A0 (FUN_004022A0)
     *
     * What it does:
     * Releases heap-backed storage (if any) and restores inline storage pointers.
     */
    template <class T, std::size_t N>
    inline void ResetStorageToInline(FastVectorN<T, N>& vec) noexcept
    {
      if (vec.start_ == vec.originalVec_) {
        vec.end_ = vec.start_;
        return;
      }

      if (vec.start_) {
        ::operator delete[](vec.start_);
      }
      vec.start_ = vec.originalVec_;
      vec.capacity_ = *reinterpret_cast<T**>(vec.start_);
      vec.end_ = vec.start_;
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

      auto* const newStart = new T[requestedCapacity];
      T* cursor = newStart;
      cursor = CopyRangeForward(cursor, vec.start_, splitPos);
      cursor = CopyRangeForward(cursor, insertBegin, insertEnd);
      cursor = CopyRangeForward(cursor, splitPos, vec.end_);

      if (inlineOrigin && vec.start_ == inlineOrigin) {
        *reinterpret_cast<T**>(inlineOrigin) = vec.capacity_;
      } else if (vec.start_) {
        ::operator delete[](vec.start_);
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
   * Runtime view used by reflected fastvector lanes that keep one extra
   * unresolved metadata word after the pointer triplet.
   *
   * Layout:
   *   +0x00 begin
   *   +0x04 end
   *   +0x08 capacity end
   *   +0x0C metadata/owner lane (unresolved)
   */
  template <class T>
  struct fastvector_runtime_view
  {
    T* begin;
    T* end;
    T* capacityEnd;
    void* metadata;

    /**
     * Address: 0x00402270 (FUN_00402270)
     */
    [[nodiscard]] T* Data() noexcept
    {
      return begin;
    }

    /**
     * Address: 0x00402270 (FUN_00402270)
     */
    [[nodiscard]] const T* Data() const noexcept
    {
      return begin;
    }

    /**
     * Address: 0x00402280 (FUN_00402280)
     */
    [[nodiscard]] bool Empty() const noexcept
    {
      return begin == end;
    }

    /**
     * Address: 0x00402290 (FUN_00402290)
     */
    [[nodiscard]] std::size_t Size() const noexcept
    {
      return static_cast<std::size_t>(end - begin);
    }

    /**
     * Address: 0x00402350 (FUN_00402350)
     */
    [[nodiscard]] T* ElementAtUnchecked(const std::size_t index) noexcept
    {
      return begin + index;
    }

    /**
     * Address: 0x00402360 (FUN_00402360)
     */
    [[nodiscard]] const T* ElementAtUnchecked(const std::size_t index) const noexcept
    {
      return begin + index;
    }
  };
  static_assert(sizeof(fastvector_runtime_view<void>) == 0x10, "fastvector_runtime_view<T> must be 0x10");
  static_assert(
    offsetof(fastvector_runtime_view<void>, begin) == 0x00, "fastvector_runtime_view<T>::begin offset must be 0x00"
  );
  static_assert(
    offsetof(fastvector_runtime_view<void>, end) == 0x04, "fastvector_runtime_view<T>::end offset must be 0x04"
  );
  static_assert(
    offsetof(fastvector_runtime_view<void>, capacityEnd) == 0x08,
    "fastvector_runtime_view<T>::capacityEnd offset must be 0x08"
  );
  static_assert(
    offsetof(fastvector_runtime_view<void>, metadata) == 0x0C,
    "fastvector_runtime_view<T>::metadata offset must be 0x0C"
  );

  template <class T>
  [[nodiscard]] inline fastvector_runtime_view<T>& AsFastVectorRuntimeView(void* object) noexcept
  {
    return *reinterpret_cast<fastvector_runtime_view<T>*>(object);
  }

  template <class T>
  [[nodiscard]] inline const fastvector_runtime_view<T>& AsFastVectorRuntimeView(const void* object) noexcept
  {
    return *reinterpret_cast<const fastvector_runtime_view<T>*>(object);
  }

  /**
   * Address: 0x00402C20 (FUN_00402C20)
   * Address: 0x00710F70 (FUN_00710F70, gpg::FastVectorRuntimeCopyRange<moho::SCondition> —
   * emitted transitively via InsertRange<SCondition> from CArmyStats trigger-condition append)
   * Address: 0x0054D790 (FUN_0054D790, the `Moho::CAniPoseBone` emission —
   * that element has a user-declared copy ctor, so the reallocate path
   * copy-constructs rather than relocating bitwise)
   * Address: 0x0054DF50 (FUN_0054DF50, the forward copy-assign range lane for
   * the same element, used to rewind mLast after a shrink)
   *
   * What it does:
   * Copy-constructs [sourceBegin, sourceEnd) into `destination` and returns the
   * first element after the copied range.
   *
   * This is the *uninitialised*-copy lane: every call site writes past the
   * view's `end`, or into storage `FastVectorRuntimeReallocateInsert` has just
   * allocated. The destination has therefore never run a constructor, so the
   * elements must be constructed here and never assigned. The `SCondition`
   * emission (FUN_00710F70) shows this explicitly - it self-links the
   * destination's inline `FastVectorN` sentinel (`[dst+0x18..0x24] = dst+0x28`)
   * before calling `fastvector_uint::cpy` into it. Assigning instead would run
   * `BVIntSet::operator=` over garbage and `delete[]` an uninitialised pointer.
   *
   * For trivially-copyable `T` this collapses to the same plain element store
   * the generic 4-byte emission (FUN_00402C20) performs.
   */
  template <class T>
  [[nodiscard]] inline T* FastVectorRuntimeCopyRange(T* destination, const T* sourceBegin, const T* sourceEnd) noexcept
  {
    for (; sourceBegin != sourceEnd; ++destination) {
      if (destination) {
        if constexpr (std::is_copy_constructible_v<T>) {
          ::new (static_cast<void*>(destination)) T(*sourceBegin);
        } else {
          ::new (static_cast<void*>(destination)) T();
        }
      }
      ++sourceBegin;
    }
    return destination;
  }

  /**
   * Address: 0x004029B0 (FUN_004029B0, func_VecResize)
   * Address: 0x00562350 (FUN_00562350, fastvector<WeakPtr<CUnitCommand>> instantiation)
   * Address: 0x0056D2B0 (FUN_0056D2B0, fastvector<IUnitWeakPtr pair> instantiation)
   * Address: 0x0067E190 (FUN_0067E190, fastvector<Wm3::Sphere3f> instantiation)
   *
   * What it does:
   * Reallocates runtime-view storage to `newCapacity` and inserts
   * [sourceBegin, sourceEnd) at `insertPos`.
   *
   * The secondary addresses above are distinct MSVC8 template instantiations
   * of this same helper for different element types (`WeakPtr<CUnitCommand>`
   * @ size 4, IUnitWeakPtr intrusive-pair @ size 8, `Wm3::Sphere3f` @ size
   * 16). The instantiated bodies are binary-equivalent to the template
   * expansion below once the element-size constant folds into the pointer
   * arithmetic; the address lines are kept here so the binary-to-source
   * map stays one-to-one for each FUN_ token.
   */
  template <class T>
  inline std::size_t FastVectorRuntimeReallocateInsert(
    fastvector_runtime_view<T>& view,
    T* insertPos,
    const std::size_t newCapacity,
    const T* sourceBegin,
    const T* sourceEnd
  )
  {
    static_assert(!std::is_void_v<T>, "FastVectorRuntimeReallocateInsert requires a concrete element type");

    T* const oldBegin = view.begin;
    T* const oldEnd = view.end;
    T* const oldCapacityEnd = view.capacityEnd;

    T* const newBegin = new T[newCapacity];
    T* write = newBegin;

    if (oldBegin && insertPos && insertPos >= oldBegin && insertPos <= oldEnd) {
      write = FastVectorRuntimeCopyRange(write, oldBegin, insertPos);
    }
    write = FastVectorRuntimeCopyRange(write, sourceBegin, sourceEnd);
    if (oldBegin && insertPos && insertPos >= oldBegin && insertPos <= oldEnd) {
      write = FastVectorRuntimeCopyRange(write, insertPos, oldEnd);
    }

    T* const inlineBegin = reinterpret_cast<T*>(view.metadata);
    if (oldBegin == inlineBegin) {
      // Binary path stores prior inline-capacity sentinel before rebinding.
      if (inlineBegin) {
        *reinterpret_cast<T**>(inlineBegin) = oldCapacityEnd;
      }
    } else {
      delete[] oldBegin;
    }

    view.begin = newBegin;
    view.end = write;
    view.capacityEnd = newBegin + newCapacity;
    return newCapacity;
  }

  /**
   * Address: 0x00402B10 (FUN_00402B10)
   *
   * What it does:
   * Inserts [sourceBegin, sourceEnd) at `insertPos`, growing runtime-view
   * storage when needed.
   */
  template <class T>
  [[nodiscard]] inline T*
  FastVectorRuntimeInsertRange(fastvector_runtime_view<T>& view, T* insertPos, const T* sourceBegin, const T* sourceEnd)
  {
    static_assert(!std::is_void_v<T>, "FastVectorRuntimeInsertRange requires a concrete element type");

    const std::ptrdiff_t insertCountSigned = sourceEnd - sourceBegin;
    if (insertCountSigned <= 0) {
      return view.end;
    }

    const std::size_t insertCount = static_cast<std::size_t>(insertCountSigned);
    const std::size_t currentSize = (view.begin && view.end) ? static_cast<std::size_t>(view.end - view.begin) : 0u;
    const std::size_t currentCapacity =
      (view.begin && view.capacityEnd) ? static_cast<std::size_t>(view.capacityEnd - view.begin) : 0u;
    const std::size_t required = currentSize + insertCount;

    if (required > currentCapacity) {
      std::size_t newCapacity = currentCapacity * 2u;
      if (newCapacity < required) {
        newCapacity = required;
      }
      FastVectorRuntimeReallocateInsert(view, insertPos, newCapacity, sourceBegin, sourceEnd);
      return view.end;
    }

    T* const oldFinish = view.end;
    T* const insertEnd = insertPos + insertCount;

    if (insertEnd > oldFinish) {
      // Insertion stretches beyond old finish: copy suffix of inserted range,
      // then old tail, then source prefix into the vacated prefix window.
      const std::ptrdiff_t tailCount = oldFinish - insertPos;
      const T* const sourceTailBegin = sourceBegin + tailCount;
      view.end = FastVectorRuntimeCopyRange(oldFinish, sourceTailBegin, sourceEnd);
      view.end = FastVectorRuntimeCopyRange(view.end, insertPos, oldFinish);

      const std::ptrdiff_t prefixCount = sourceTailBegin - sourceBegin;
      if (prefixCount > 0) {
        // This window is inside the *old* constructed range, so the elements
        // there are live: assign over them rather than byte-copying, which
        // would duplicate owning members (see the backward-shift note below).
        if constexpr (std::is_trivially_copyable_v<T>) {
          std::memmove(oldFinish - prefixCount, sourceBegin, static_cast<std::size_t>(prefixCount) * sizeof(T));
        } else {
          T* write = oldFinish - prefixCount;
          for (std::ptrdiff_t index = 0; index < prefixCount; ++index) {
            write[index] = sourceBegin[index];
          }
        }
      }
      return view.end;
    }

    // Insertion fits entirely before old finish: move trailing `insertCount`
    // values to the appended tail window, shift middle block, then copy source.
    T* const tailStart = oldFinish - static_cast<std::ptrdiff_t>(insertCount);
    view.end = FastVectorRuntimeCopyRange(oldFinish, tailStart, oldFinish);

    // Shift the middle block right by exactly `insertCount` to open the gap.
    // `view.end` has already been advanced to `oldFinish + insertCount`, so
    // `view.end - moveCount` lands at `insertPos + 2 * insertCount` and would
    // overwrite the tail copied just above.
    const std::ptrdiff_t moveCount = tailStart - insertPos;
    if (moveCount > 0) {
      if constexpr (std::is_trivially_copyable_v<T>) {
        std::memmove(
          insertPos + insertCount, insertPos, static_cast<std::size_t>(moveCount) * sizeof(T)
        );
      } else {
        // The binary uses a backward element-assign loop here for non-trivial
        // T (0x00562A80 for UnitWeaponInfo, calling its operator=). A byte-wise
        // move would duplicate owning members - UnitWeaponInfo holds two
        // msvc8::string lanes - and then double-free them.
        (void)core::detail::CopyBackwardAssign<T>(
          insertPos + moveCount, insertPos + insertCount + moveCount, insertPos
        );
      }
    }

    // The gap now holds live elements shifted out of the way, so the source
    // goes in by assignment for the same reason as the backward shift above.
    if constexpr (std::is_trivially_copyable_v<T>) {
      std::memmove(insertPos, sourceBegin, insertCount * sizeof(T));
    } else {
      for (std::size_t index = 0; index < insertCount; ++index) {
        insertPos[index] = sourceBegin[index];
      }
    }
    return view.end;
  }

  /**
   * Address: 0x004028E0 (FUN_004028E0, gpg::fastvector_uint::cpy)
   * Address: 0x00553370 (FUN_00553370, gpg::fastvector<Moho::SOCellPos>::cpy)
   * Address: 0x00561D90 (FUN_00561D90, gpg::fastvector_n<Moho::SSTIUnitWeaponInfoSnapshot, 1>::cpy
   * — the 0x98-byte weapon-info snapshot emission, stride confirmed by the three
   * `/152` size divides at 0x00561DA5/0x00561DB6/0x00561DC8 and the
   * `152 * v3` prefix offset. Reached by name from
   * `moho::CopyFastVectorN(mWeaponInfo, other.mWeaponInfo)` in
   * `SSTIUnitVariableData::AssignFrom` (Unit.cpp), which forwards to this
   * template through `AsFastVectorRuntimeView`.)
   *
   * What it does:
   * Copies source contents into destination runtime view.
   *
   * The 0x00553370 entry is the same template body specialized for
   * 8-byte `Moho::SOCellPos` elements: the compiler emits element-wise
   * assignment loops instead of the 4-byte `memmove` seen in the uint
   * (0x004028E0) emission, but the three branches are identical
   * (fits-in-place forward copy; reallocate-insert via
   * `FastVectorRuntimeReallocateInsert`; copy-prefix + tail
   * `FastVectorRuntimeInsertRange`). Instantiated for `SOCellPos`
   * through `FastVectorN2RebindAndCopy` at the `CopySOCellPosFastVectorN2`
   * call in `Moho::SSTICommandIssueData`'s copy constructor.
   */
  template <class T>
  [[nodiscard]] inline fastvector_runtime_view<T>*
  FastVectorRuntimeCopyAssign(fastvector_runtime_view<T>& destination, const fastvector_runtime_view<T>& source)
  {
    static_assert(!std::is_void_v<T>, "FastVectorRuntimeCopyAssign requires a concrete element type");

    if (&destination == &source) {
      return &destination;
    }

    const std::size_t destinationSize =
      (destination.begin && destination.end) ? static_cast<std::size_t>(destination.end - destination.begin) : 0u;
    const std::size_t sourceSize =
      (source.begin && source.end) ? static_cast<std::size_t>(source.end - source.begin) : 0u;

    if (destinationSize >= sourceSize) {
      if (sourceSize > 0) {
        std::memmove(destination.begin, source.begin, sourceSize * sizeof(T));
      }
      destination.end = destination.begin + sourceSize;
      return &destination;
    }

    const std::size_t destinationCapacity = (destination.begin && destination.capacityEnd)
      ? static_cast<std::size_t>(destination.capacityEnd - destination.begin)
      : 0u;
    if (sourceSize > destinationCapacity) {
      FastVectorRuntimeReallocateInsert(
        destination, destination.begin, sourceSize, destination.begin, destination.begin
      );
    }

    if (destinationSize > 0) {
      std::memmove(destination.begin, source.begin, destinationSize * sizeof(T));
    }

    FastVectorRuntimeInsertRange(
      destination, destination.end, source.begin + static_cast<std::ptrdiff_t>(destinationSize), source.end
    );
    return &destination;
  }

  /**
   * Address: 0x004026A0 (FUN_004026A0)
   *
   * What it does:
   * Ensures runtime-view capacity can hold at least `requiredCount` values.
   */
  template <class T>
  [[nodiscard]] inline std::size_t
  FastVectorRuntimeEnsureCapacity(const std::size_t requiredCount, fastvector_runtime_view<T>& view)
  {
    const std::size_t currentCapacity =
      (view.begin && view.capacityEnd) ? static_cast<std::size_t>(view.capacityEnd - view.begin) : 0u;
    if (requiredCount > currentCapacity) {
      FastVectorRuntimeReallocateInsert(view, view.begin, requiredCount, view.begin, view.begin);
    }
    return requiredCount;
  }

  /**
   * Address: 0x004026C0 (FUN_004026C0)
   *
   * What it does:
   * Moves current [oldBegin, end) payload to `newBegin` and updates end.
   */
  template <class T>
  [[nodiscard]] inline T*
  FastVectorRuntimeMoveRangeAndSetEnd(const T* oldBegin, fastvector_runtime_view<T>& view, T* newBegin)
  {
    if (newBegin != oldBegin) {
      const std::ptrdiff_t count = view.end - oldBegin;
      T* const newEnd = newBegin + count;
      if (count > 0) {
        std::memmove(newBegin, oldBegin, static_cast<std::size_t>(count) * sizeof(T));
      }
      view.end = newEnd;
    }
    return newBegin;
  }

  /**
   * Address: 0x004026F0 (FUN_004026F0)
   * Address: 0x0047F500 (FUN_0047F500, n64<char> fixed-span alias lane)
   *
   * What it does:
   * Binds runtime-view pointers to a caller-owned buffer.
   */
  template <class T>
  [[nodiscard]] inline fastvector_runtime_view<T>&
  FastVectorRuntimeAdoptBuffer(fastvector_runtime_view<T>& view, const std::size_t count, T* begin) noexcept
  {
    view.begin = begin;
    view.end = begin;
    view.capacityEnd = begin + count;
    view.metadata = begin;
    return view;
  }

  /**
   * Address: 0x004021F0 (FUN_004021F0)
   * Address: 0x004022A0 (FUN_004022A0)
   *
   * What it does:
   * Resets runtime-view storage back to metadata/inline storage.
   */
  template <class T>
  inline void FastVectorRuntimeResetToInline(fastvector_runtime_view<T>& view)
  {
    T* const currentBegin = view.begin;
    T* const inlineBegin = reinterpret_cast<T*>(view.metadata);
    if (currentBegin == inlineBegin) {
      view.end = currentBegin;
      return;
    }

    delete[] currentBegin;
    view.begin = inlineBegin;
    view.capacityEnd = inlineBegin ? *reinterpret_cast<T* const*>(inlineBegin) : nullptr;
    view.end = view.begin;
  }

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
    storage.start_ = storage.inlineVec_;
    storage.end_ = storage.inlineVec_;
    storage.capacity_ = storage.inlineVec_ + 2;
    storage.originalVec_ = storage.inlineVec_;
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
    auto& destinationView = AsFastVectorRuntimeView<T>(destination);
    const auto& sourceView = AsFastVectorRuntimeView<T>(source);
    FastVectorRuntimeCopyAssign(destinationView, sourceView);
    return destination;
  }

  /**
   * Address: 0x004022D0 (FUN_004022D0, gpg::fastvector_uint_resize)
   * Address: 0x0059CE20 (FUN_0059CE20, pointer-element inline clone used by
   * `RFastVectorType_IFormationInstance_P::SetCount` and its internal
   * reflect/resize shim)
   * Address: 0x0065ECE0 (FUN_0065ECE0, gpg::FastVectorRuntimeResizeFill<moho::SEfxCurve> — 56-byte element resize-fill)
   *
   * What it does:
   * Resizes runtime-view storage and fills appended values with `*fillValue`.
   * The 0x0059CE20 address is a separate compiler-emitted inline clone of
   * this template specialized for 4-byte pointer elements; both entries
   * share identical behavior (shrink-to-size, preserve-on-equal, ensure
   * capacity and fill on grow). All pointer-fastvector resize callers route
   * through this single template body.
   */
  template <class T>
  inline void
  FastVectorRuntimeResizeFill(const T* fillValue, const unsigned int newSize, fastvector_runtime_view<T>& view)
  {
    const T fill = fillValue ? *fillValue : T{};
    const std::size_t currentSize = view.begin ? static_cast<std::size_t>(view.end - view.begin) : 0u;

    if (newSize < currentSize) {
      view.end = view.begin + newSize;
      return;
    }

    if (newSize == currentSize) {
      return;
    }

    (void)FastVectorRuntimeEnsureCapacity(static_cast<std::size_t>(newSize), view);
    while (view.end != view.begin + newSize) {
      T* const slot = view.end;
      view.end = slot + 1;
      if (slot) {
        if constexpr (std::is_copy_assignable_v<T>) {
          *slot = fill;
        } else if constexpr (std::is_copy_constructible_v<T>) {
          ::new (static_cast<void*>(slot)) T(fill);
        } else {
          ::new (static_cast<void*>(slot)) T();
        }
      }
    }
  }

  /**
   * Address: 0x00402270 (FUN_00402270)
   */
  template <class T>
  [[nodiscard]] inline T* FastVectorRuntimeBegin(const fastvector_runtime_view<T>& view) noexcept
  {
    return view.begin;
  }

  /**
   * Address: 0x00402280 (FUN_00402280)
   */
  template <class T>
  [[nodiscard]] inline bool FastVectorRuntimeEmpty(const fastvector_runtime_view<T>& view) noexcept
  {
    return view.begin == view.end;
  }

  /**
   * Address: 0x00402290 (FUN_00402290)
   */
  template <class T>
  [[nodiscard]] inline std::size_t FastVectorRuntimeCount(const fastvector_runtime_view<T>& view) noexcept
  {
    return view.begin ? static_cast<std::size_t>(view.end - view.begin) : 0u;
  }

  /**
   * Address: 0x00402350 (FUN_00402350)
   * Address: 0x00402360 (FUN_00402360)
   */
  template <class T>
  [[nodiscard]] inline T* FastVectorRuntimeAt(const fastvector_runtime_view<T>& view, const std::size_t index) noexcept
  {
    return view.begin + index;
  }

  /**
   * Address: 0x00402690 (FUN_00402690)
   *
   * What it does:
   * Thin wrapper used by binary helpers to copy one runtime view into another.
   */
  template <class T>
  [[nodiscard]] inline fastvector_runtime_view<T>*
  FastVectorRuntimeCopyAssignAlias(fastvector_runtime_view<T>& destination, const fastvector_runtime_view<T>& source)
  {
    return FastVectorRuntimeCopyAssign(destination, source);
  }
} // namespace gpg
