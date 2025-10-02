#pragma once
#include <cstddef>
#include <cstdint>
#include <new>
#include <stdexcept>
#include <cassert>

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

        /** Elements-per-node follows classic 512-byte chunks. */
        static constexpr size_type kBlockBytes = 512;
        static constexpr size_type kBlockSize = (sizeof(T) < kBlockBytes ? (kBlockBytes / (sizeof(T) ? sizeof(T) : 1)) : 1);

        /** Minimal initial map slots (power-of-two not required). */
        static constexpr size_type kInitMapSlots = 8;

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

        // ---- Ctors / Dtor ----
        deque()
            : _Myproxy(nullptr), _Map(nullptr), _Mapsize(0), _Myoff(0), _Mysize(0)
        {
            init_empty();
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
        void clear()
        {
            // Destroy all elements in logical order
            for (size_type i = 0; i < _Mysize; ++i)
            {
                ptr_at(i)->~T();
            }
            _Mysize = 0;
            // Keep nodes and map for capacity, as Dinkumware typically did
        }

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

        void pop_back()
        {
            assert(!empty());
            T* p = ptr_at(_Mysize - 1);
            p->~T();
            --_Mysize;
        }

        void pop_front()
        {
            assert(!empty());
            T* p = ptr_at(0);
            p->~T();
            ++_Myoff;
            if (_Myoff == capacity())
                _Myoff = 0;
            --_Mysize;
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
        void init_empty()
        {
            allocate_map(kInitMapSlots);
            // Center begin offset to allow both-end growth without remap
            _Myoff = (_Mapsize / 2) * kBlockSize;
            _Mysize = 0;
        }

        void allocate_map(size_type slots)
        {
            if (slots < 2) slots = 2;
            _Map = static_cast<T**>(::operator new(sizeof(T*) * slots));
            _Mapsize = slots;
            for (size_type i = 0; i < _Mapsize; ++i) _Map[i] = nullptr;
        }

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

            // Determine new map size (simple doubling strategy).
            size_type new_slots = _Mapsize ? _Mapsize * 2 : kInitMapSlots;
            while (need > new_slots * kBlockSize)
                new_slots *= 2;

            remap_preserving_data(new_slots);
        }

        void remap_preserving_data(size_type new_slots)
        {
            // Compute used node span in old map
            const size_type old_slots = _Mapsize;
            T** old_map = _Map;

            // Choose a centered new begin offset
            const size_type new_begin_node = new_slots / 2;
            const size_type new_off = new_begin_node * kBlockSize + (_Myoff % kBlockSize);

            // Allocate new map and clear
            T** new_map = static_cast<T**>(::operator new(sizeof(T*) * new_slots));
            for (size_type i = 0; i < new_slots; ++i) new_map[i] = nullptr;

            if (_Mysize)
            {
                // Determine the first and last global element indices (half-open)
                const size_type first_global = _Myoff;
                const size_type last_global = _Myoff + _Mysize;

                const size_type first_node = first_global / kBlockSize;
                const size_type last_node = (last_global + kBlockSize - 1) / kBlockSize; // one past

                const size_type used_nodes = last_node - first_node;

                // Copy node pointers in order so elements keep their storage
                for (size_type i = 0; i < used_nodes; ++i)
                {
                    const size_type old_node_idx = (first_node + i) % old_slots;
                    const size_type new_node_idx = (new_begin_node + i) % new_slots;
                    new_map[new_node_idx] = old_map[old_node_idx];
                }
            }

            // Install new map
#if !MSVC8_DEQUE_DISABLE_FREE
            ::operator delete(static_cast<void*>(_Map));
#endif
            _Map = new_map;
            _Mapsize = new_slots;
            _Myoff = new_off;
        }
    };

    static_assert(sizeof(deque<int>) == 0x14, "msvc8::deque must be 20 bytes on x86.");
    static_assert(sizeof(deque<void*>) == 0x14, "msvc8::deque must be 20 bytes on x86.");
} // namespace msvc8
