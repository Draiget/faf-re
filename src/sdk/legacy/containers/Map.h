#pragma once
#include <cstddef>
#include <cstdint>
#include <utility>
#include <functional>
#include <iterator>
#include <type_traits>
#include <cassert>

namespace msvc8
{
    /**
     * \brief Minimal, debug-checked, read-only facade of MSVC8 std::map layout.
     *
     * This is a layout-compatible RB-tree view for reverse-engineering:
     * - header sentinel node at _Myhead, used as end() iterator
     * - _Myhead->_Parent = root (or _Myhead if empty)
     * - _Myhead->_Left   = leftmost (min) (or _Myhead if empty)
     * - _Myhead->_Right  = rightmost (max) (or _Myhead if empty)
     *
     * The container never allocates or mutates memory. It only traverses what's already built.
     * Use adopt(...) to wrap an in-memory tree from the game.
     */
    template<class Key, class T, class Less = std::less<Key>>
    class map
    {
    public:
        using key_type = Key;
        using mapped_type = T;
        using value_type = std::pair<const Key, T>;
        using key_compare = Less;
        using size_type = std::size_t;
        using difference_type = std::ptrdiff_t;

    private:
#pragma pack(push, 4)
        /** Node layout as in VC8: left/parent/right pointers, color byte, then value. */
        struct _Node {
            _Node* _Left;    // left child or _Myhead
            _Node* _Parent;  // parent or _Myhead
            _Node* _Right;   // right child or _Myhead
            char        _Color;   // 0 = Red, 1 = Black (header is Black)
            char        _Pad[3];  // keep 4-byte alignment before value
            value_type  _Value;   // pair<const Key, T>
        };
#pragma pack(pop)

        /** Owner cookie/allocator slot (debug-era field; not used in this facade). */
        void* _Alval = nullptr;

        /** Header sentinel node pointer (points to a node in target address space). */
        _Node* _Myhead = nullptr;

        /** Number of elements in the tree (debug stores it in container, not header). */
        size_type  _Mysize = 0;

        /** Key comparator. */
        key_compare _Keycomp{};

        /** Debug assertion helper. */
        static void _DbgAssert(bool cond, const char* msg) {
#if !defined(NDEBUG)
            assert((cond) && msg);
#else
            (void)cond; (void)msg;
#endif
        }

        /** Helper: treat header as end() marker. */
        [[nodiscard]] bool _Is_header(const _Node* p) const noexcept {
            return p == _Myhead;
        }

        /** Helper: is the tree empty? */
        [[nodiscard]] bool _Is_empty() const noexcept {
            return !_Myhead || _Myhead->_Parent == _Myhead;
        }

        /** Helper: root pointer (or header if empty). */
        [[nodiscard]] _Node* _Root() const noexcept {
            return _Myhead ? _Myhead->_Parent : nullptr;
        }

        /** Helper: leftmost (min) node (or header if empty). */
        [[nodiscard]] _Node* _Leftmost() const noexcept {
            return _Myhead ? _Myhead->_Left : nullptr;
        }

        /** Helper: rightmost (max) node (or header if empty). */
        [[nodiscard]] _Node* _Rightmost() const noexcept {
            return _Myhead ? _Myhead->_Right : nullptr;
        }

        /** In-order successor of node x (header-aware). */
        static _Node* _Inc(_Node* x, _Node* header) noexcept {
            // If right child exists (not header), go to right then all the way left.
            if (x->_Right != header) {
                x = x->_Right;
                while (x->_Left != header) x = x->_Left;
                return x;
            }
            // Else climb up until we come from a left child.
            _Node* p = x->_Parent;
            while (x == p->_Right) {
                x = p;
                p = p->_Parent;
            }
            // If we hit header from rightmost, p is header (== end()).
            return p;
        }

        /** In-order predecessor of node x (header-aware). */
        static _Node* _Dec(_Node* x, _Node* header) noexcept {
            // If at header (end), predecessor is rightmost.
            if (x == header) return header->_Right;

            // If left child exists (not header), go left then all the way right.
            if (x->_Left != header) {
                x = x->_Left;
                while (x->_Right != header) x = x->_Right;
                return x;
            }
            // Else climb up until we come from a right child.
            _Node* p = x->_Parent;
            while (x == p->_Left) {
                x = p;
                p = p->_Parent;
            }
            return p;
        }

    public:
        /**
         * \brief Bidirectional iterator with VC8-like owner pointer.
         * Stores container owner for debug-checked iterators (similar to _Mycont).
         */
        class iterator
        {
            friend class map;
        public:
            using iterator_category = std::bidirectional_iterator_tag;
            using value_type = map::value_type;
            using difference_type = map::difference_type;
            using pointer = value_type*;
            using reference = value_type&;

            /** Default ctor: null iterator (invalid until assigned). */
            iterator() noexcept = default;

            /** Dereference to value. */
            reference operator*() const noexcept {
                _DbgAssert(_Owner && _Ptr, "msvc8::map::iterator: null dereference");
                return _Ptr->_Value;
            }
            pointer operator->() const noexcept { return std::addressof(**this); }

            /** Pre-increment (next in-order). */
            iterator& operator++() noexcept {
                _DbgAssert(_Owner && _Ptr, "msvc8::map::iterator: ++ on null");
                _Ptr = map::_Inc(_Ptr, _Owner->_Myhead);
                return *this;
            }
            /** Post-increment. */
            iterator operator++(int) noexcept { auto c = *this; ++*this; return c; }

            /** Pre-decrement (prev in-order). */
            iterator& operator--() noexcept {
                _DbgAssert(_Owner && _Ptr, "msvc8::map::iterator: -- on null");
                _Ptr = map::_Dec(_Ptr, _Owner->_Myhead);
                return *this;
            }
            /** Post-decrement. */
            iterator operator--(int) noexcept { auto c = *this; --*this; return c; }

            friend bool operator==(const iterator& a, const iterator& b) noexcept {
                return a._Ptr == b._Ptr;
            }
            friend bool operator!=(const iterator& a, const iterator& b) noexcept {
                return !(a == b);
            }

        private:
            iterator(map* owner, _Node* p) noexcept : _Owner(owner), _Ptr(p) {}

            map* _Owner = nullptr;
            _Node* _Ptr = nullptr;
        };

        /** Const-iterator (same layout, const view). */
        class const_iterator
        {
            friend class map;
        public:
            using iterator_category = std::bidirectional_iterator_tag;
            using value_type = map::value_type;
            using difference_type = map::difference_type;
            using pointer = const value_type*;
            using reference = const value_type&;

            const_iterator() noexcept = default;
            const_iterator(const iterator& it) noexcept : _Owner(it._Owner), _Ptr(it._Ptr) {}

            reference operator*() const noexcept {
                _DbgAssert(_Owner && _Ptr, "msvc8::map::const_iterator: null dereference");
                return _Ptr->_Value;
            }
            pointer operator->() const noexcept { return std::addressof(**this); }

            const_iterator& operator++() noexcept {
                _DbgAssert(_Owner && _Ptr, "msvc8::map::const_iterator: ++ on null");
                _Ptr = map::_Inc(_Ptr, _Owner->_Myhead);
                return *this;
            }
            const_iterator operator++(int) noexcept { auto c = *this; ++*this; return c; }

            const_iterator& operator--() noexcept {
                _DbgAssert(_Owner && _Ptr, "msvc8::map::const_iterator: -- on null");
                _Ptr = map::_Dec(_Ptr, _Owner->_Myhead);
                return *this;
            }
            const_iterator operator--(int) noexcept { auto c = *this; --*this; return c; }

            friend bool operator==(const const_iterator& a, const const_iterator& b) noexcept {
                return a._Ptr == b._Ptr;
            }
            friend bool operator!=(const const_iterator& a, const const_iterator& b) noexcept {
                return !(a == b);
            }

        private:
            const_iterator(const map* owner, _Node* p) noexcept : _Owner(owner), _Ptr(p) {}

            const map* _Owner = nullptr;
            _Node* _Ptr = nullptr;
        };

        // ---- Ctors / adoption -------------------------------------------------

        /**
         * \brief Default-construct an empty view (no header).
         */
        map() noexcept = default;

        /**
         * \brief Adopt an existing VC8 map tree from memory.
         * \param myhead Pointer to header sentinel node in the foreign tree.
         * \param size   Number of elements (debug-era stored in container).
         * \param comp   Comparator (must match original ordering).
         * \param alval  Optional allocator/debug cookie for symmetry with VC8 layout.
         */
        map(_Node* myhead, size_type size, key_compare comp = {}, void* alval = nullptr) noexcept
            : _Alval(alval), _Myhead(myhead), _Mysize(size), _Keycomp(comp)
        {
            _DbgAssert(_Myhead != nullptr, "msvc8::map: _Myhead must not be null");
            // Basic sanity: header should reference itself on empty trees.
            if (_Myhead) {
                if (_Myhead->_Parent == nullptr) {
                    // Some builds may zero header in raw images; we still allow it.
                }
            }
        }

        // ---- Observers --------------------------------------------------------

        /** Returns comparator. */
        [[nodiscard]] key_compare key_comp() const noexcept { return _Keycomp; }

        /** Number of elements (as reported by debug-era container). */
        [[nodiscard]] size_type size() const noexcept { return _Mysize; }

        /** True if size() == 0. */
        [[nodiscard]] bool empty() const noexcept { return size() == 0; }

        /** Header pointer (for low-level diagnostics). */
        [[nodiscard]] const void* header_ptr() const noexcept { return _Myhead; }

        // ---- Iteration --------------------------------------------------------

        /**
         * \brief begin(): in-order first element (leftmost node).
         */
        [[nodiscard]] iterator begin() noexcept {
            return iterator(this, _Is_empty() ? _Myhead : _Leftmost());
        }
        [[nodiscard]] const_iterator begin() const noexcept {
            return const_iterator(this, _Is_empty() ? _Myhead : _Leftmost());
        }
        [[nodiscard]] const_iterator cbegin() const noexcept { return begin(); }

        /**
         * \brief end(): header sentinel (one past the last).
         */
        [[nodiscard]] iterator end() noexcept { return iterator(this, _Myhead); }
        [[nodiscard]] const_iterator end() const noexcept { return const_iterator(this, _Myhead); }
        [[nodiscard]] const_iterator cend() const noexcept { return end(); }

        // ---- Lookup -----------------------------------------------------------

        /**
         * \brief Find node with given key; returns end() if not found.
         */
        iterator find(const key_type& k) noexcept {
            return iterator(this, _Find_node(k));
        }
        const_iterator find(const key_type& k) const noexcept {
            return const_iterator(this, _Find_node(k));
        }

        /**
         * \brief Returns 1 if key exists, 0 otherwise.
         */
        size_type count(const key_type& k) const noexcept {
            return _Find_node(k) == _Myhead ? 0u : 1u;
        }

        /**
         * \brief lower_bound: first element whose key is not less than k.
         */
        iterator lower_bound(const key_type& k) noexcept {
            return iterator(this, _Lower_bound_node(k));
        }
        const_iterator lower_bound(const key_type& k) const noexcept {
            return const_iterator(this, _Lower_bound_node(k));
        }

        /**
         * \brief upper_bound: first element whose key is greater than k.
         */
        iterator upper_bound(const key_type& k) noexcept {
            return iterator(this, _Upper_bound_node(k));
        }
        const_iterator upper_bound(const key_type& k) const noexcept {
            return const_iterator(this, _Upper_bound_node(k));
        }

        /**
         * \brief equal_range: [lower_bound(k), upper_bound(k)).
         */
        std::pair<iterator, iterator> equal_range(const key_type& k) noexcept {
            return { lower_bound(k), upper_bound(k) };
        }
        std::pair<const_iterator, const_iterator> equal_range(const key_type& k) const noexcept {
            return { lower_bound(k), upper_bound(k) };
        }

        /**
         * \brief at(): read-only reference to mapped value; asserts if key is missing.
         */
        const mapped_type& at(const key_type& k) const {
            _Node* n = _Find_node(k);
            _DbgAssert(n != _Myhead, "msvc8::map::at: key not found");
            return n->_Value.second;
        }

        /**
         * \brief Try-get mapped value pointer; returns nullptr if not found.
         */
        const mapped_type* try_get(const key_type& k) const noexcept {
            _Node* n = _Find_node(k);
            return (n == _Myhead) ? nullptr : std::addressof(n->_Value.second);
        }

        // ---- Non-modifying diagnostics ---------------------------------------

        /**
         * \brief Check minimal header invariants (non-exhaustive).
         */
        [[nodiscard]] bool basic_sanity() const noexcept {
            if (!_Myhead) return false;
            // Header is its own parent when empty (common VC8 pattern), but not guaranteed in all dumps.
            // Accept both: empty (Parent==Left==Right==_Myhead) or non-empty with Parent!=_Myhead.
            const bool emptyTree =
                _Myhead->_Parent == _Myhead &&
                _Myhead->_Left == _Myhead &&
                _Myhead->_Right == _Myhead;
            const bool nonEmpty = _Myhead->_Parent != _Myhead;
            return emptyTree || nonEmpty;
        }

        /**
         * Clear view (debug-friendly).
         * By default, does NOT mutate foreign memory; it detaches to a local empty header.
         * Define MSVC8_MAP_MUTATE_ON_CLEAR=1 to patch header links in-place.
         */
        void clear() noexcept {
            // Always reset logical size first.
            _Mysize = 0;

            if (!_Myhead) {
                // Nothing to mutate; switch to local empty header.
                _Myhead = _Empty_header();
                return;
            }

#if MSVC8_MAP_MUTATE_ON_CLEAR
            // In-place header rewire: header points to itself => empty tree.
            _Myhead->_Parent = _Myhead;
            _Myhead->_Left = _Myhead;
            _Myhead->_Right = _Myhead;
            _Myhead->_Color = 1; // Black (matches VC8 header convention)
            // Keep _Myhead as-is (foreign header).
#else
            // Non-mutating: detach this facade from foreign tree and use local empty header.
            _Myhead = _Empty_header();
#endif
        }
    private:
        /** Raw root (or header if empty). */
        [[nodiscard]] _Node* _Root_nonnull_header() const noexcept {
            return _Myhead ? _Myhead->_Parent : nullptr;
        }

        /** Tree search; returns _Myhead if not found. */
        _Node* _Find_node(const key_type& k) const noexcept {
            _DbgAssert(_Myhead != nullptr, "msvc8::map::_Find_node: header is null");
            _Node* cur = _Root_nonnull_header();
            while (cur && cur != _Myhead) {
                const key_type& ck = cur->_Value.first;
                if (_Keycomp(k, ck)) {
                    cur = cur->_Left;
                } else if (_Keycomp(ck, k)) {
                    cur = cur->_Right;
                } else {
                    return cur; // equal
                }
            }
            return _Myhead;
        }

        /** lower_bound search. */
        _Node* _Lower_bound_node(const key_type& k) const noexcept {
            _DbgAssert(_Myhead != nullptr, "msvc8::map::_Lower_bound_node: header is null");
            _Node* cur = _Root_nonnull_header();
            _Node* res = _Myhead; // default to end()
            while (cur && cur != _Myhead) {
                const key_type& ck = cur->_Value.first;
                if (!_Keycomp(ck, k)) { // !(ck < k)  => ck >= k  => candidate
                    res = cur;
                    cur = cur->_Left;
                } else {
                    cur = cur->_Right;
                }
            }
            return res;
        }

        /** upper_bound search. */
        _Node* _Upper_bound_node(const key_type& k) const noexcept {
            _DbgAssert(_Myhead != nullptr, "msvc8::map::_Upper_bound_node: header is null");
            _Node* cur = _Root_nonnull_header();
            _Node* res = _Myhead; // default to end()
            while (cur && cur != _Myhead) {
                const key_type& ck = cur->_Value.first;
                if (_Keycomp(k, ck)) { // k < ck  => candidate
                    res = cur;
                    cur = cur->_Left;
                } else {
                    cur = cur->_Right;
                }
            }
            return res;
        }

        /** Obtain an in-process empty header sentinel without constructing value_type. */
        static _Node* _Empty_header() noexcept {
            // Raw storage with proper alignment; value payload remains unconstructed.
            static typename std::aligned_storage<sizeof(_Node), alignof(_Node)>::type s_storage;
            _Node* h = reinterpret_cast<_Node*>(&s_storage);
            h->_Left = h;
            h->_Right = h;
            h->_Parent = h;
            h->_Color = 1; // Black
            return h;
        }
    public:
        // ---- Factory: adopt from raw pieces ----------------------------------

        /**
         * \brief Factory to adopt a tree using raw header pointer and size.
         *
         * Usage:
         *   auto v = msvc8::map<K,V>::adopt(headerPtr, sz);
         *
         * The header node must follow VC8 invariant:
         *   - header->_Parent == root (or header if empty)
         *   - header->_Left   == leftmost (or header if empty)
         *   - header->_Right  == rightmost (or header if empty)
         */
        static map adopt(void* header, size_type sz, key_compare comp = {}, void* alval = nullptr) noexcept {
            return map(reinterpret_cast<_Node*>(header), sz, comp, alval);
        }
    };

    // --------- Convenience: ensure 32-bit pointer size assumed ----------
    static_assert(sizeof(map<void*, void*>) == 0x10, "msvc8::map size should be 0x10");

} // namespace msvc8
