#pragma once
#include <cstddef>
#include <stdexcept>
#include <new>

namespace msvc8
{

    /**
     * Deque compatible layout for MSVC8-era Dinkumware on x86.
     * - First member is a debug proxy pointer (as with vector) to match _SECURE_SCL.
     * - Memory organization follows SGI-style: a map of node pointers, each node is a fixed-size block.
     * - Start/Finish are full iterators with (cur, first, last, node).
     *
     * Layout (x86):
     *   +0x00: void*      _Myproxy
     *   +0x04: T**        _Map
     *   +0x08: size_t     _Mapsize
     *   +0x0C: iterator   _Start   (4*4 = 16 bytes)
     *   +0x1C: iterator   _Finish  (16 bytes)
     * Total: 0x2C (44 bytes), not accounting for padding rules (none needed on x86).
     *
     * NOTE: This is a clean-room reconstruction for RE, not the original header.
     */
    template<class T, class Alloc = std::allocator<T>>
    class deque {
        static_assert(sizeof(void*) == 4, "This layout targets 32-bit x86.");

    public:
        /** Iterator over segmented storage: keeps current element and node frame. */
        struct iterator {
            T* cur;   // current element within the node
            T* first; // first element address of the node
            T* last;  // one-past-last element address of the node
            T** node;  // pointer into the map pointing to this node

            /** Default constructs a singular iterator. */
            iterator() : cur(nullptr), first(nullptr), last(nullptr), node(nullptr) {}

            /** Difference (random access): counts elements across nodes. */
            std::ptrdiff_t operator-(const iterator& rhs) const {
                // Both singular? define as 0.
                if (node == nullptr && rhs.node == nullptr) return 0;
                // Fast path: same node.
                if (node == rhs.node) return cur - rhs.cur;

                // Cross-node computation.
                std::ptrdiff_t diff = 0;
                const T** n = rhs.node;
                if (n == nullptr) return 0;

                // accumulate from rhs to end of its node
                diff += rhs.last - rhs.cur;

                // full nodes between rhs.node+1 .. node-1
                for (const T** it = rhs.node + 1; it < node; ++it) {
                    const T* f = *it;
                    const T* l = f + (rhs.last - rhs.first); // same block size everywhere
                    diff += (l - f);
                }

                // and from start of this node to cur
                diff += (cur - first);

                return diff;
            }

            /** Increment to next element (spill to next node when needed). */
            iterator& operator++() {
                ++cur;
                if (cur == last) {
                    // move to next node
                    ++node;
                    first = *node;
                    // block size is preserved across nodes
                    last = first + (last - first);
                    cur = first;
                }
                return *this;
            }
            iterator operator++(int) { iterator tmp = *this; ++(*this); return tmp; }

            /** Decrement to previous element (spill to previous node when needed). */
            iterator& operator--() {
                if (cur == first) {
                    // move to prev node
                    --node;
                    first = *node;
                    last = first + (last - first);
                    cur = last - 1;
                } else {
                    --cur;
                }
                return *this;
            }
            iterator operator--(int) { iterator tmp = *this; --(*this); return tmp; }

            T& operator*()  const { return *cur; }
            T* operator->() const { return  cur; }

            bool operator==(const iterator& rhs) const { return cur == rhs.cur && node == rhs.node; }
            bool operator!=(const iterator& rhs) const { return !(*this == rhs); }
        };

        using value_type = T;
        using allocator_type = Alloc;
        using size_type = std::size_t;
        using difference_type = std::ptrdiff_t;
        using reference = T&;
        using const_reference = const T&;

        /** Number of elements stored per node (Dinkumware used 512-byte chunks). */
        static constexpr size_type kBlockBytes = 512;
        static constexpr size_type block_size_for(size_type elem_size) {
            return elem_size ? (kBlockBytes / elem_size > 0 ? kBlockBytes / elem_size : 1u) : 1u;
        }

        /** Constructor: empty deque with initial map of few nodes. */
        deque()
            : _Myproxy(nullptr),
            _Map(nullptr),
            _Mapsize(0)
        {
            init_empty();
        }

        /** Destructor: destroys elements and releases nodes and map. */
        ~deque() {
            clear();
            release_all_nodes_and_map();
        }

        /** Disable copying for safety in this RE scaffold; add if you need it. */
        deque(const deque&) = delete;
        deque& operator=(const deque&) = delete;

        /** Returns the number of elements. */
        size_type size() const {
            return static_cast<size_type>(_Finish - _Start);
        }

        /** True if no elements are stored. */
        bool empty() const { return _Start.cur == _Finish.cur && _Start.node == _Finish.node; }

        /** Random access by index (unchecked). */
        reference operator[](size_type n) {
            return *index_to_iterator(n).cur;
        }
        const_reference operator[](size_type n) const {
            return *index_to_iterator(n).cur;
        }

        /** Random access by index (checked). */
        reference at(size_type n) {
            if (n >= size()) throw std::out_of_range("deque::at");
            return (*this)[n];
        }
        const_reference at(size_type n) const {
            if (n >= size()) throw std::out_of_range("deque::at");
            return (*this)[n];
        }

        /** Front/Back access. */
        reference front() { return *(_Start.cur); }
        const_reference front() const { return *(_Start.cur); }
        reference back() { iterator it = _Finish; --it; return *it.cur; }
        const_reference back() const { iterator it = _Finish; --it; return *it.cur; }

        /** Begin/End iterators (non-const for brevity). */
        iterator begin() { return _Start; }
        iterator end() { return _Finish; }

        /**
         * Pushes an element at the end.
         * Uses in-place new on current node; spills to a new node if needed.
         */
        void push_back(const T& v) {
            if (_Finish.cur != _Finish.last) {
                new (static_cast<void*>(_Finish.cur)) T(v);
                ++_Finish;
            } else {
                push_back_aux(v);
            }
        }

        /** Pushes an element at the front. */
        void push_front(const T& v) {
            if (_Start.cur != _Start.first) {
                --_Start;
                new (static_cast<void*>(_Start.cur)) T(v);
            } else {
                push_front_aux(v);
            }
        }

        /**
         * Pops the last element (calls destructor).
         * Assumes non-empty.
         */
        void pop_back() {
            iterator it = _Finish;
            --it;
            it.cur->~T();
            _Finish = it;
            if (_Finish.cur == _Finish.first) {
                // last element in node removed; if more nodes present, move finish to previous node end
                if (_Finish.node > _Start.node) {
                    // release the currently unused tail node (optional)
                    // keep nodes to avoid churn, as Dinkumware often did
                }
            }
        }

        /** Pops the first element. Assumes non-empty. */
        void pop_front() {
            _Start.cur->~T();
            ++_Start;
            if (_Start.cur == _Start.last) {
                // node became empty; move to next node
                // (we keep nodes allocated to minimize reallocations)
            }
        }

        /**
         * Destroys all elements. Keeps allocated nodes and map around.
         * This mirrors the common Dinkumware approach to retain capacity.
         */
        void clear() {
            // Destroy elements across nodes
            for (iterator it = _Start; it != _Finish; ++it) {
                it.cur->~T();
            }
            _Finish = _Start;
        }

        /** Returns the allocator (trivial pass-through here). */
        allocator_type get_allocator() const { return allocator_type(); }

        // ---- Debug proxy API (no-op placeholder) ----
        void* get_debug_proxy() const { return _Myproxy; }
        void  set_debug_proxy(void* p) { _Myproxy = p; }

    private:
        // --- Internal types and constants ---
        static constexpr size_type kBlockSize = block_size_for(sizeof(T));
        static constexpr size_type kInitMapNodes = 8; // room to grow both ends without re-map

        // --- Members (keep exact order for layout!) ---
        void* _Myproxy;   // +0x00 : _SECURE_SCL proxy
        T** _Map;       // +0x04 : array of node pointers
        size_type _Mapsize;  // +0x08 : number of T* slots in _Map
        iterator _Start;     // +0x0C
        iterator _Finish;    // +0x1C

        // If your binary shows a stored size, enable and position it carefully:
        // #if MOHO_MSVC8_DEQUE_HAS_MYSIZE
        // size_type _Mysize; // must be placed where your binary expects it
        // #endif

        /** Initialize an empty deque with a fresh map and a single centered node. */
        void init_empty() {
            allocate_map(kInitMapNodes);
            // center start/finish on the middle node, empty range
            const size_type center = _Mapsize / 2;
            ensure_node(center);
            T* first = _Map[center];
            _Start = make_iter(first, center, 0);
            _Finish = _Start;
        }

        /** Convert logical index to iterator (unchecked). */
        iterator index_to_iterator(size_type n) const {
            iterator it = _Start;
            // Advance across nodes by full blocks
            size_type offset = n;
            while (offset) {
                size_type block_rem = static_cast<size_type>(it.last - it.cur);
                if (offset < block_rem) {
                    it.cur += static_cast<std::ptrdiff_t>(offset);
                    return it;
                }
                // jump to next node
                offset -= block_rem;
                ++it;
            }
            return it;
        }

        /** Allocates the map (array of T*), uninitialized nodes. */
        void allocate_map(size_type map_nodes) {
            // align to at least 2
            if (map_nodes < 2) map_nodes = 2;
            _Mapsize = map_nodes;
            _Map = static_cast<T**>(::operator new(sizeof(T*) * _Mapsize));
            // zero-init entries
            for (size_type i = 0; i < _Mapsize; ++i) _Map[i] = nullptr;
        }

        /** Ensures node at index exists (allocates block if needed). */
        void ensure_node(size_type idx) {
            if (_Map[idx] == nullptr) {
                _Map[idx] = allocate_node();
            }
        }

        /** Allocates a node (block of kBlockSize elements, raw storage). */
        T* allocate_node() {
            // raw uninitialized storage for T[kBlockSize]
            T* mem = static_cast<T*>(::operator new(sizeof(T) * kBlockSize));
            return mem;
        }

        /** Deallocates a node (no element dtors here!). */
        void deallocate_node(T* p) {
            ::operator delete(static_cast<void*>(p));
        }

        /** Releases all nodes and the map (no element dtors; call clear() first). */
        void release_all_nodes_and_map() {
            if (_Map) {
                for (size_type i = 0; i < _Mapsize; ++i) {
                    if (_Map[i]) {
                        deallocate_node(_Map[i]);
                        _Map[i] = nullptr;
                    }
                }
                ::operator delete(static_cast<void*>(_Map));
                _Map = nullptr;
                _Mapsize = 0;
            }
            _Start = iterator{};
            _Finish = iterator{};
        }

        /** Re-maps: grow map and recenter nodes to keep amortized O(1) at ends. */
        void grow_map(size_type extra_front_nodes, size_type extra_back_nodes) {
            const size_type new_size = _Mapsize + extra_front_nodes + extra_back_nodes + kInitMapNodes;
            T** new_map = static_cast<T**>(::operator new(sizeof(T*) * new_size));
            for (size_type i = 0; i < new_size; ++i) new_map[i] = nullptr;

            // current range of nodes used
            const size_type start_idx = static_cast<size_type>(_Start.node - _Map);
            const size_type finish_idx = static_cast<size_type>(_Finish.node - _Map);
            const size_type used_nodes = (start_idx == finish_idx && _Start.cur == _Finish.cur)
                ? 1u
                : (finish_idx - start_idx + 1u);

            // place used nodes centered after extra_front_nodes
            const size_type new_start_idx = (new_size - used_nodes) / 2;
            for (size_type i = 0; i < used_nodes; ++i) {
                new_map[new_start_idx + i] = _Map[start_idx + i];
            }

            // fix iterators
            const std::ptrdiff_t block_bytes = (_Start.last - _Start.first);
            iterator oldS = _Start;
            iterator oldF = _Finish;

            _Start.node = new_map + new_start_idx;
            _Start.first = *_Start.node;
            _Start.last = _Start.first + block_bytes;
            _Start.cur = _Start.first + (oldS.cur - oldS.first);

            _Finish.node = _Start.node + (oldF.node - oldS.node);
            _Finish.first = *_Finish.node;
            _Finish.last = _Finish.first + block_bytes;
            _Finish.cur = _Finish.first + (oldF.cur - oldF.first);

            // old map goes away
            ::operator delete(static_cast<void*>(_Map));
            _Map = new_map;
            _Mapsize = new_size;
        }

        /** Build iterator for node index with current offset inside node. */
        iterator make_iter(T* node_first, size_type node_idx, size_type offset_in_node) const {
            iterator it;
            it.first = node_first;
            it.last = it.first + kBlockSize;
            it.node = _Map + node_idx;
            it.cur = it.first + static_cast<std::ptrdiff_t>(offset_in_node);
            return it;
        }

        /** Append with node spill handling. */
        void push_back_aux(const T& v) {
            // need a new node at _Finish.node + 1
            size_type finish_idx = static_cast<size_type>(_Finish.node - _Map);
            if (finish_idx + 1 >= _Mapsize) {
                grow_map(0, 1);
                finish_idx = static_cast<size_type>(_Finish.node - _Map);
            }
            const size_type next_idx = finish_idx + 1;
            ensure_node(next_idx);

            // move finish to next node's beginning and emplace value
            _Finish.node = _Map + next_idx;
            _Finish.first = *_Finish.node;
            _Finish.last = _Finish.first + kBlockSize;
            _Finish.cur = _Finish.first;
            new (static_cast<void*>(_Finish.cur)) T(v);
            ++_Finish;
        }

        /** Prepend with node spill handling. */
        void push_front_aux(const T& v) {
            // need a new node before _Start.node
            size_type start_idx = static_cast<size_type>(_Start.node - _Map);
            if (start_idx == 0) {
                grow_map(1, 0);
                start_idx = static_cast<size_type>(_Start.node - _Map);
            }
            const size_type prev_idx = start_idx - 1;
            ensure_node(prev_idx);

            // move start to previous node's end and emplace value just before end
            _Start.node = _Map + prev_idx;
            _Start.first = *_Start.node;
            _Start.last = _Start.first + kBlockSize;
            _Start.cur = _Start.last; // one past last
            --_Start;
            new (static_cast<void*>(_Start.cur)) T(v);
        }
    };

} // namespace msvc8
