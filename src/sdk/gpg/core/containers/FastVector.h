#pragma once

#include <algorithm>
#include <cstddef> // std::ptrdiff_t
#include <cstdint>
#include <cstring>
#include <iterator> // reverse_iterator
#include <new>
#include <type_traits>

namespace gpg::core
{
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
    void push_back(const value_type& v)
    {
      PushBack(v);
    }
    void clear() noexcept
    {
      Clear();
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

    FastVector(const FastVector&) = delete;
    FastVector& operator=(const FastVector&) = delete;

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
     * Address: 0x00401DE0 (FUN_00401DE0, gpg::fastvector_n2_uint::~fastvector_n2_uint)
     *
     * What it does:
     * For `FastVectorN<unsigned int, 2>`, releases heap storage when active and
     * rebinds lanes back to inline storage metadata.
     */
    ~FastVectorN()
    {
      // Free heap only; inline buffer must not be freed
      if (this->start_ && this->start_ != originalVec_) {
        delete[] this->start_;
      }
      // Prevent Base dtor from touching inline storage
      this->start_ = this->end_ = this->capacity_ = nullptr;
    }

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
      if (this->end_ == this->capacity_) {
        const size_t newCap = this->Capacity() ? this->Capacity() * 2 : N;
        Reserve(newCap);
      }
      *this->end_++ = v;
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
     *
     * What it does:
     * Inserts one element range `[insStart, insEnd)` before `pos`, growing
     * storage when required.
     */
    void InsertAt(T* pos, const T* insStart, const T* insEnd)
    {
      const size_t insertCount = static_cast<size_t>(insEnd - insStart);
      if (!insertCount)
        return;

      if constexpr (!std::is_trivially_copyable_v<T>) {
        const size_t sz = this->Size();
        const size_t cap = this->Capacity();
        size_t posIndex = index_of(this->start_, pos);
        if (sz + insertCount > cap) {
          size_t newCap = cap ? cap * 2 : N;
          if (newCap < sz + insertCount)
            newCap = sz + insertCount;
          GrowToCapacity(newCap);
        }
        pos = ptr_at(this->start_, posIndex);
        const size_t tailCount = static_cast<size_t>(this->end_ - pos);
        if (tailCount) {
          std::memmove(pos + insertCount, pos, tailCount * ElemSize);
        }
        for (size_t i = 0; i < insertCount; ++i) {
          pos[i] = insStart[i];
        }
        this->end_ += insertCount;
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
    static T* CopyRangeForward(T* dest, const T* copyBegin, const T* copyEnd) noexcept
    {
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
     * Address: 0x0047C910 (FUN_0047C910, gpg::fastvector_n64_char::GrowInsert)
     * Address: 0x004C7FD0 (FUN_004C7FD0, gpg::fastvector_n<LuaPlus::LuaObject>::GrowInsert lane)
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
  static_assert(sizeof(FastVectorN<char, 64>) == 0x50, "FastVectorN<char,64> must be 0x50");
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
   *
   * What it does:
   * Copies [sourceBegin, sourceEnd) into `destination` and returns the first
   * element after the copied range.
   */
  template <class T>
  [[nodiscard]] inline T* FastVectorRuntimeCopyRange(T* destination, const T* sourceBegin, const T* sourceEnd) noexcept
  {
    for (; sourceBegin != sourceEnd; ++destination) {
      if (destination) {
        if constexpr (std::is_copy_assignable_v<T>) {
          *destination = *sourceBegin;
        } else if constexpr (std::is_copy_constructible_v<T>) {
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
   *
   * What it does:
   * Reallocates runtime-view storage to `newCapacity` and inserts
   * [sourceBegin, sourceEnd) at `insertPos`.
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
        std::memmove(oldFinish - prefixCount, sourceBegin, static_cast<std::size_t>(prefixCount) * sizeof(T));
      }
      return view.end;
    }

    // Insertion fits entirely before old finish: move trailing `insertCount`
    // values to the appended tail window, shift middle block, then copy source.
    T* const tailStart = oldFinish - static_cast<std::ptrdiff_t>(insertCount);
    view.end = FastVectorRuntimeCopyRange(oldFinish, tailStart, oldFinish);

    const std::ptrdiff_t moveCount = tailStart - insertPos;
    if (moveCount > 0) {
      std::memmove(view.end - moveCount, insertPos, static_cast<std::size_t>(moveCount) * sizeof(T));
    }

    std::memmove(insertPos, sourceBegin, insertCount * sizeof(T));
    return view.end;
  }

  /**
   * Address: 0x004028E0 (FUN_004028E0, gpg::fastvector_uint::cpy)
   *
   * What it does:
   * Copies source contents into destination runtime view.
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
   *
   * What it does:
   * Resizes runtime-view storage and fills appended values with `*fillValue`.
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

    FastVectorRuntimeEnsureCapacity(static_cast<std::size_t>(newSize), view);
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
