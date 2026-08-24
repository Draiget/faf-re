#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <stdexcept>
#include <cassert>
#include <utility>

#ifndef MSVC8_DEQUE_DISABLE_FREE
#define MSVC8_DEQUE_DISABLE_FREE 0
#endif

namespace msvc8
{
    /**
     * MSVC8-compatible deque (x86) with strict 0x14-bytes layout:
     *   +0x00: void*   _Myproxy
     *   +0x04: T**     _Map
     *   +0x08: size_t  _Mapsize      (number of map slots)
     *   +0x0C: size_t  _Myoff        (offset of begin in elements, modulo capacity)
     *   +0x10: size_t  _Mysize       (current size in elements)
     *
     * Nodes are fixed-size blocks; the map is a circular array of pointers to nodes.
     * Iterators are synthesized from (_Myoff, _Mysize).
     */
    template<class T, class Alloc = std::allocator<T>>
    class deque
    {
        static_assert(sizeof(void*) == 4, "This layout targets 32-bit x86.");
        static_assert(sizeof(std::size_t) == 4, "This layout targets 32-bit x86.");

    public:
        using value_type = T;
        using allocator_type = Alloc;
        using size_type = std::size_t;
        using difference_type = std::ptrdiff_t;
        using reference = T&;
        using const_reference = const T&;

        /**
         * Elements-per-node follows the classic Dinkumware/MSVC8 `_DEQUESIZ`
         * stepped policy, confirmed against two real emissions with
         * different element sizes: `FUN_0067B870` (`std::deque<Entity*>`,
         * sizeof(T)==4, block index math uses `>> 2`/`& 3` i.e. block size
         * 4) and `FUN_007BB920`/`FUN_007BB400` (`std::deque<SNetCommand>`,
         * sizeof(T)==0x30, block index is the raw node index with no
         * intra-node math at all, i.e. block size 1). This is NOT a
         * flat "512-byte chunk" division -- that formula gives block size
         * 128 for a 4-byte element and 10 for a 0x30-byte element, neither
         * of which matches the binary.
         */
        static constexpr size_type kBlockSize =
          sizeof(T) <= 1 ? 16 :
          sizeof(T) <= 2 ? 8 :
          sizeof(T) <= 4 ? 4 :
          sizeof(T) <= 8 ? 2 : 1;

        /**
         * Growth-map fallback slot count used by `grow_map()` when doubling
         * from an empty or near-empty map (`max(mapsize / 2, kMinGrowSlots)`).
         * Not a pre-allocation size -- the default-constructed deque holds
         * no map at all (see the ctor below).
         */
        static constexpr size_type kMinGrowSlots = 8;

        /**
         * Map-slot ceiling before `grow_map()` throws `length_error`.
         * Dinkumware derives this from the allocator's `max_size()` in
         * elements (`SIZE_MAX / sizeof(T)`) further divided down to whole
         * nodes. Confirmed against two real emissions with different
         * element sizes: `FUN_007BB920` (`deque<SNetCommand>`, sizeof(T)==
         * 0x30, kBlockSize==1) computes 0x05555555, and `FUN_00741030`
         * (`deque<SSyncData*>` / 4-byte T, kBlockSize==4) computes
         * 0x0FFFFFFF -- both match `(SIZE_MAX / sizeof(T)) / kBlockSize`
         * exactly, so the ceiling is data-dependent and must not be
         * hardcoded to either emission's constant.
         */
        static constexpr size_type kMaxSlots =
          (static_cast<size_type>(-1) / sizeof(T)) / kBlockSize;

        /** Random-access iterator synthesized from container + logical offset. */
        struct iterator
        {
            deque* cont{};
            size_type off{}; // offset from begin(), in elements

            iterator() = default;
            iterator(deque* c, size_type o) : cont(c), off(o) {}

            reference operator*() const { return *cont->ptr_at(off); }
            T* operator->() const { return  cont->ptr_at(off); }

            iterator& operator++() { ++off; return *this; }
            iterator  operator++(int) { iterator t = *this; ++(*this); return t; }
            iterator& operator--() { --off; return *this; }
            iterator  operator--(int) { iterator t = *this; --(*this); return t; }

            iterator& operator+=(difference_type n) { off = static_cast<size_type>(off + n); return *this; }
            iterator& operator-=(difference_type n) { off = static_cast<size_type>(off - n); return *this; }

            friend iterator operator+(iterator it, difference_type n) { it += n; return it; }
            friend iterator operator+(difference_type n, iterator it) { it += n; return it; }
            friend iterator operator-(iterator it, difference_type n) { it -= n; return it; }
            friend difference_type operator-(const iterator& a, const iterator& b)
            {
                assert(a.cont == b.cont);
                return static_cast<difference_type>(a.off) - static_cast<difference_type>(b.off);
            }

            friend bool operator==(const iterator& a, const iterator& b) { return a.cont == b.cont && a.off == b.off; }
            friend bool operator!=(const iterator& a, const iterator& b) { return !(a == b); }
            friend bool operator<(const iterator& a, const iterator& b) { assert(a.cont == b.cont); return a.off < b.off; }
            friend bool operator<=(const iterator& a, const iterator& b) { assert(a.cont == b.cont); return a.off <= b.off; }
            friend bool operator>(const iterator& a, const iterator& b) { assert(a.cont == b.cont); return a.off > b.off; }
            friend bool operator>=(const iterator& a, const iterator& b) { assert(a.cont == b.cont); return a.off >= b.off; }
        };

        /**
         * Address: 0x0073B570 (FUN_0073B570, `Moho::CSimDriver::CSimDriver`)
         *
         * What it does:
         * Confirms the real default-construction state for a deque member:
         * the ctor writes `_Map = 0; _Mapsize = 0; _Myoff = 0; _Mysize = 0;`
         * directly (`this->mSyncdat._Map = 0` etc. in the decompiler export)
         * with no call into any node/map-allocating helper. The map is
         * built lazily by `grow_map()` on first insert, matching
         * Dinkumware's own lazy-empty `deque` state -- there is no eager
         * `kInitMapSlots`-sized pre-allocation.
         */
        deque()
            : _Myproxy(nullptr), _Map(nullptr), _Mapsize(0), _Myoff(0), _Mysize(0)
        {
        }

        ~deque()
        {
            clear();
#if !MSVC8_DEQUE_DISABLE_FREE
            release_all();
#endif
        }

        deque(const deque&) = delete;
        deque& operator=(const deque&) = delete;

        // ---- Capacity / state ----
        size_type size()     const noexcept { return _Mysize; }
        bool      empty()    const noexcept { return _Mysize == 0; }
        size_type capacity() const noexcept { return _Mapsize * kBlockSize; }

        // ---- Element access ----
        reference       operator[](size_type n) { return *ptr_at(n); }
        const_reference operator[](size_type n) const { return *ptr_at(n); }

        reference at(size_type n)
        {
            if (n >= _Mysize) throw std::out_of_range("deque::at");
            return (*this)[n];
        }
        const_reference at(size_type n) const
        {
            if (n >= _Mysize) throw std::out_of_range("deque::at");
            return (*this)[n];
        }

        reference       front() { assert(!empty()); return *ptr_at(0); }
        const_reference front() const { assert(!empty()); return *ptr_at(0); }

        reference       back() { assert(!empty()); return *ptr_at(_Mysize - 1); }
        const_reference back()  const { assert(!empty()); return *ptr_at(_Mysize - 1); }

        // ---- Iterators ----
        iterator begin() { return iterator{ this, 0 }; }
        iterator end() { return iterator{ this, _Mysize }; }

        // ---- Modifiers (minimal set) ----
        /**
         * Address: 0x007411A0 (FUN_007411A0, bookkeeping half of
         * `deque<SSyncData*>::~deque` reached via `SSyncDataQueue::
         * ~SSyncDataQueue` / `Moho::CSimDriver` teardown)
         *
         * What it does:
         * The binary's size-drain loop destroys nothing itself (element
         * destruction for a pointer-typed deque is a no-op) -- it just
         * decrements `_Mysize` to 0 and resets `_Myoff` to 0 once it gets
         * there, exactly mirroring `pop_back()`/`pop_front()`'s "empty
         * resets offset" convention. Element dtors still run here for
         * non-trivial T so this stays real `clear()` semantics; only the
         * offset reset was missing before this citation.
         */
        void clear()
        {
            // Destroy all elements in logical order
            for (size_type i = 0; i < _Mysize; ++i)
            {
                ptr_at(i)->~T();
            }
            _Mysize = 0;
            _Myoff = 0;
            // Keep nodes and map for capacity, as Dinkumware typically did
        }

        /**
         * Address: 0x0067B870 (FUN_0067B870, msvc8::deque<void*>::push_back
         * specialization for `Moho::Sim::mDeletionQueue`) — grows the node map
         * when the write slot's map index wraps onto a full map (`_Growmap`),
         * lazily allocates the target node if unset, then constructs the value
         * at the computed slot and bumps `_Mysize`. Emitted via
         * SimulationRef->mDeletionQueue.push_back(this) in Entity::Destroy
         * (Entity.cpp:4559).
         */
        void push_back(const T& v)
        {
            grow_if_full(1);
            ensure_node_for_write(_Mysize); // element at logical index = size()
            T* p = ptr_at(_Mysize);
            ::new (static_cast<void*>(p)) T(v);
            ++_Mysize;
        }

        void push_front(const T& v)
        {
            grow_if_full(1);
            // Move begin one step left in the circular space
            if (_Myoff == 0)
                _Myoff = capacity();
            --_Myoff; // now begin() shifts left by one element

            ensure_node_for_write(0);
            T* p = ptr_at(0);
            ::new (static_cast<void*>(p)) T(v);
            ++_Mysize;
        }

        /**
         * Address: 0x007BC110 (FUN_007BC110, msvc8::deque<Moho::SNetCommand>::pop_back)
         *
         * What it does:
         * Destroys the back element and decrements size, additionally
         * resetting the begin offset back to 0 when the deque becomes
         * empty (the binary does this so a fully-drained deque restarts
         * writes at map slot 0 instead of wherever the last element
         * happened to sit).
         */
        void pop_back()
        {
            assert(!empty());
            T* p = ptr_at(_Mysize - 1);
            p->~T();
            --_Mysize;
            if (_Mysize == 0)
                _Myoff = 0;
        }

        /**
         * Address: 0x007BB400 (FUN_007BB400, msvc8::deque<Moho::SNetCommand>::pop_front)
         *
         * What it does:
         * Destroys the front element, advances the begin offset (wrapping
         * at `capacity()`), decrements size, and resets the begin offset
         * back to 0 when the deque becomes empty.
         */
        void pop_front()
        {
            assert(!empty());
            T* p = ptr_at(0);
            p->~T();
            ++_Myoff;
            if (_Myoff >= capacity())
                _Myoff = 0;
            --_Mysize;
            if (_Mysize == 0)
                _Myoff = 0;
        }

        /**
         * Address: 0x007BCF50 (FUN_007BCF50, msvc8::deque<Moho::SNetCommand>::swap)
         * Address: 0x007BC5B0 (FUN_007BC5B0) - linker-emitted thunk that
         *          tail-calls 0x007BCF50 directly (IDA marks it
         *          `attributes: thunk`); no separate body to recover.
         *
         * What it does:
         * Swaps the map/mapsize/offset/size storage lanes with another
         * deque of the same type, leaving each object's debug proxy
         * pointer untouched.
         */
        void swap(deque& other) noexcept
        {
            std::swap(_Map, other._Map);
            std::swap(_Mapsize, other._Mapsize);
            std::swap(_Myoff, other._Myoff);
            std::swap(_Mysize, other._Mysize);
        }

        allocator_type get_allocator() const { return allocator_type(); }

        // Debug-proxy passthrough (opaque)
        void* get_debug_proxy() const { return _Myproxy; }
        void  set_debug_proxy(void* p) { _Myproxy = p; }

    private:
        // ---- Exact layout (keep order!) ----
        void* _Myproxy;   // +0x00
        T** _Map;       // +0x04
        size_type _Mapsize;   // +0x08
        size_type _Myoff;     // +0x0C
        size_type _Mysize;    // +0x10

        // ---- Helpers ----
        static size_type node_index_from_global(size_type global, size_type mapsize) noexcept
        {
            const size_type node = (global / kBlockSize) % mapsize;
            return node;
        }

        static size_type in_node_index_from_global(size_type global) noexcept
        {
            return global % kBlockSize;
        }

        // Returns a pointer to element for logical index n (0.._Mysize), assumes node exists for read.
        T* ptr_at(size_type logical_index) const
        {
            const size_type global = _Myoff + logical_index;
            const size_type node_idx = node_index_from_global(global, _Mapsize);
            const size_type within = in_node_index_from_global(global);
            T* base = _Map[node_idx];
            assert(base != nullptr && "node must exist for ptr_at()");
            return base + within;
        }

        // Ensures node for write at logical index exists (allocates node storage if needed).
        void ensure_node_for_write(size_type logical_index)
        {
            const size_type global = _Myoff + logical_index;
            const size_type node_idx = node_index_from_global(global, _Mapsize);
            if (_Map[node_idx] == nullptr)
                _Map[node_idx] = allocate_node();
        }

        T* allocate_node()
        {
            // Raw uninitialized storage for kBlockSize elements
            return static_cast<T*>(::operator new(sizeof(T) * kBlockSize));
        }

        void deallocate_node(T* p)
        {
#if !MSVC8_DEQUE_DISABLE_FREE
            ::operator delete(static_cast<void*>(p));
#else
            (void)p;
#endif
        }

        void release_all()
        {
            if (_Map)
            {
                for (size_type i = 0; i < _Mapsize; ++i)
                {
                    if (_Map[i])
                    {
                        deallocate_node(_Map[i]);
                        _Map[i] = nullptr;
                    }
                }
                ::operator delete(static_cast<void*>(_Map));
                _Map = nullptr;
                _Mapsize = 0;
            }
            _Myoff = _Mysize = 0;
        }

        // Grow map capacity if total elements would exceed capacity.
        void grow_if_full(size_type to_add)
        {
            const size_type need = _Mysize + to_add;
            if (need <= capacity())
                return;

            grow_map();
        }

        /**
         * Address: 0x007BB920 (FUN_007BB920, msvc8::deque<Moho::SNetCommand>::_Growmap)
         * Address: 0x00741030 (FUN_00741030, msvc8::deque<Moho::SSyncData*>::
         *          _Growmap -- confirms the same body for a 4-byte T /
         *          kBlockSize==4 instantiation; sole caller is
         *          `FUN_007408F0` = `push_back`, called from
         *          `SSyncDataQueue::PushBack` guard `FUN_0073F940`)
         *
         * What it does:
         * Classic Dinkumware `_Growmap`: grows the node map by
         * `max(mapsize / 2, kMinGrowSlots)` slots (falling back to 1 slot
         * when that would overflow the `kMaxSlots`-slot ceiling, which
         * itself throws `length_error` once actually reached), then
         * reshuffles existing node pointers with three `memmove`-shaped
         * ranges so the new, empty slots land contiguously right after the
         * map's previous end (wrapping around slot 0) instead of
         * recentering the whole map. The begin node index (`_Myoff /
         * kBlockSize`) is provably unchanged by this reshuffle -- the
         * "tail" range `[beginNode, oldMapSize)` always maps to itself --
         * so `_Myoff` itself is left untouched, matching the binary (which
         * never writes `view.mOffset` in this function).
         */
        void grow_map()
        {
            if (_Mapsize == kMaxSlots)
                throw std::length_error("deque<T> too long");

            size_type growth = 1;
            const size_type half = _Mapsize >> 1;
            if (half >= kMinGrowSlots)
                growth = half;
            else
                growth = kMinGrowSlots;
            if (_Mapsize > kMaxSlots - growth)
                growth = 1;

            const size_type oldMapSize = _Mapsize;
            const size_type beginNode = _Myoff / kBlockSize;
            T** const oldMap = _Map;

            const size_type newMapSize = oldMapSize + growth;
            T** const newMap = static_cast<T**>(::operator new(sizeof(T*) * newMapSize));
            std::memset(newMap, 0, sizeof(T*) * newMapSize);

            if (oldMap != nullptr && oldMapSize != 0)
            {
                const size_type tailCount = beginNode < oldMapSize ? oldMapSize - beginNode : 0;
                if (tailCount != 0)
                    std::memmove(newMap + beginNode, oldMap + beginNode, tailCount * sizeof(T*));

                if (beginNode > growth)
                {
                    const size_type prefixCount = growth;
                    if (prefixCount != 0)
                        std::memmove(newMap + oldMapSize, oldMap, prefixCount * sizeof(T*));

                    const size_type middleCount = beginNode - growth;
                    if (middleCount != 0)
                        std::memmove(newMap, oldMap + growth, middleCount * sizeof(T*));
                }
                else
                {
                    const size_type copiedCount = beginNode;
                    if (copiedCount != 0)
                        std::memmove(newMap + oldMapSize, oldMap, copiedCount * sizeof(T*));

                    if (growth > copiedCount)
                        std::memset(newMap + oldMapSize + copiedCount, 0, (growth - copiedCount) * sizeof(T*));
                }
            }

#if !MSVC8_DEQUE_DISABLE_FREE
            if (oldMap != nullptr)
                ::operator delete(static_cast<void*>(oldMap));
#endif
            _Map = newMap;
            _Mapsize = newMapSize;
        }
    };

    static_assert(sizeof(deque<int>) == 0x14, "msvc8::deque must be 20 bytes on x86.");
    static_assert(sizeof(deque<void*>) == 0x14, "msvc8::deque must be 20 bytes on x86.");
} // namespace msvc8
