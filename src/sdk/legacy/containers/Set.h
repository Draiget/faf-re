#pragma once
#include <cstddef>
#include <cstdint>
#include <utility>
#include <type_traits>
#include <new>
#include <cassert>
#include <functional>

#ifndef MSVC8_SET_DISABLE_FREE
#define MSVC8_SET_DISABLE_FREE 0
#endif

#ifndef MSVC8_SET_NOEXCEPT
#  define MSVC8_SET_NOEXCEPT noexcept
#endif

#pragma pack(push, 4)

namespace msvc8
{
    // Minimal stub to match MSVC8 containers ABI when needed.
    struct _Container_proxy { void* _Myfirstiter; };

    template<class Key, class Less = std::less<Key>>
    class set
    {
        // -------- RB-tree node/sentinel layout (Dinkumware-like) --------
        struct rb_base {
            rb_base* left;    // +0
            rb_base* parent;  // +4 (root when this is header)
            rb_base* right;   // +8
            std::uint8_t color;    // +12 (packed by compiler; kept as byte)
            std::uint8_t isHeader; // +13 (1 for header)
            std::uint16_t pad;     // +14 (keep 4-byte alignment for x86)
        };

        struct rb_node : rb_base {
            Key value; // follows base
            template<class...Args>
            explicit rb_node(Args&&...args) : rb_base{}, value(std::forward<Args>(args)...) {
                this->color = 0;      // red by default
                this->isHeader = 0;   // regular node
                this->left = this->right = nullptr; // will be set to header on link
                this->parent = nullptr;
                this->pad = 0;
            }
        };

    public:
        // -------- public aliases --------
        using key_type = Key;
        using value_type = Key;
        using size_type = std::uint32_t;
        using difference_type = std::ptrdiff_t;
        using key_compare = Less;
        using value_compare = Less;
        using reference = const value_type&;
        using const_reference = const value_type&;

        class const_iterator
        {
            friend class set;
            rb_base* cur_{};
            rb_base* head_{};
            static const Key& value_of(rb_base* b) { return static_cast<rb_node*>(b)->value; }

            explicit const_iterator(rb_base* c, rb_base* h) : cur_(c), head_(h) {}

        public:
            using iterator_category = std::bidirectional_iterator_tag;
            using value_type = Key;
            using difference_type = std::ptrdiff_t;
            using pointer = const Key*;
            using reference = const Key&;

            const_iterator() = default;

            reference operator*()  const { assert(cur_ && !cur_->isHeader); return value_of(cur_); }
            pointer   operator->() const { return std::addressof(operator*()); }

            bool operator==(const const_iterator& o) const { return cur_ == o.cur_ && head_ == o.head_; }
            bool operator!=(const const_iterator& o) const { return !(*this == o); }

            const_iterator& operator++() { increment_(); return *this; }
            const_iterator  operator++(int) { auto t = *this; increment_(); return t; }

            const_iterator& operator--() { decrement_(); return *this; }
            const_iterator  operator--(int) { auto t = *this; decrement_(); return t; }

        private:
            void increment_() {
                assert(cur_ && head_);
                if (cur_->right != head_) {
                    cur_ = cur_->right;
                    while (cur_->left != head_) cur_ = cur_->left;
                } else {
                    rb_base* p = cur_->parent;
                    while (cur_ == p->right) { cur_ = p; p = p->parent; }
                    cur_ = p;
                }
            }
            void decrement_() {
                assert(head_);
                if (cur_ == head_) { // end()-- -> rightmost
                    cur_ = head_->right;
                    return;
                }
                if (cur_->left != head_) {
                    cur_ = cur_->left;
                    while (cur_->right != head_) cur_ = cur_->right;
                } else {
                    rb_base* p = cur_->parent;
                    while (cur_ == p->left) { cur_ = p; p = p->parent; }
                    cur_ = p;
                }
            }
        };

        using iterator = const_iterator;

        // -------- ctor/dtor --------
        set() MSVC8_SET_NOEXCEPT
            : _Myproxy(nullptr), _Myhead(alloc_header_()), _Mysize(0), _Tag(nullptr)
        {
            init_header_(_Myhead);
        }

        ~set() MSVC8_SET_NOEXCEPT {
#if !MSVC8_SET_DISABLE_FREE
            clear();
            free_header_(_Myhead);
#endif
            _Myhead = nullptr;
        }

        set(const set&) = delete;
        set& operator=(const set&) = delete;
        set(set&& o) MSVC8_SET_NOEXCEPT { steal_from_(o); }
        set& operator=(set&& o) MSVC8_SET_NOEXCEPT {
            if (this != &o) { this->~set(); steal_from_(o); }
            return *this;
        }

        // -------- iterators --------
        iterator begin() const MSVC8_SET_NOEXCEPT {
            return _Mysize ? iterator(_Myhead->left, _Myhead) : end();
        }
        iterator end() const MSVC8_SET_NOEXCEPT {
            return iterator(_Myhead, _Myhead);
        }
        iterator cbegin() const MSVC8_SET_NOEXCEPT { return begin(); }
        iterator cend()   const MSVC8_SET_NOEXCEPT { return end(); }

        // -------- capacity --------
        bool empty() const MSVC8_SET_NOEXCEPT { return _Mysize == 0; }
        size_type size() const MSVC8_SET_NOEXCEPT { return _Mysize; }

        // Optional: expose the 4th slot for engine-like policy
        void set_reserved_tag(void* tag) MSVC8_SET_NOEXCEPT { _Tag = tag; }
        void* reserved_tag() const MSVC8_SET_NOEXCEPT { return _Tag; }

        // -------- lookup --------
        iterator find(const key_type& k) const {
            rb_base* x = _Myhead->parent; // root
            while (x != _Myhead) {
                if (!Less{}(static_cast<rb_node*>(x)->value, k)) {
                    if (!Less{}(k, static_cast<rb_node*>(x)->value)) return iterator(x, _Myhead);
                    x = x->left;
                } else {
                    x = x->right;
                }
            }
            return end();
        }

        size_type count(const key_type& k) const { return find(k) != end() ? 1u : 0u; }

        iterator lower_bound(const key_type& k) const {
            rb_base* x = _Myhead->parent; // root
            rb_base* y = _Myhead;
            while (x != _Myhead) {
                if (!Less{}(static_cast<rb_node*>(x)->value, k)) { y = x; x = x->left; } else { x = x->right; }
            }
            return iterator(y, _Myhead);
        }

        iterator upper_bound(const key_type& k) const {
            rb_base* x = _Myhead->parent; // root
            rb_base* y = _Myhead;
            while (x != _Myhead) {
                if (Less{}(k, static_cast<rb_node*>(x)->value)) { y = x; x = x->left; } else { x = x->right; }
            }
            return iterator(y, _Myhead);
        }

        std::pair<iterator, iterator> equal_range(const key_type& k) const {
            return { lower_bound(k), upper_bound(k) };
        }

        // -------- modifiers --------
        void clear() MSVC8_SET_NOEXCEPT {
#if !MSVC8_SET_DISABLE_FREE
            // post-order delete
            rb_base* r = _Myhead->parent;
            if (r != _Myhead) post_delete_(r);
#endif
            // reset header
            init_header_(_Myhead);
            _Mysize = 0;
        }

        std::pair<iterator, bool> insert(const value_type& v) { return emplace(v); }
        std::pair<iterator, bool> insert(value_type&& v) { return emplace(std::move(v)); }

        template<class...Args>
        std::pair<iterator, bool> emplace(Args&&...args) {
            // Unique insert (Dinkumware-style)
            rb_base* y = _Myhead;
            rb_base* x = _Myhead->parent; // root
            bool goLeft = true;

            // Probing
            rb_node probe(std::forward<Args>(args)...);
            const Key& k = probe.value;
            while (x != _Myhead) {
                y = x;
                goLeft = Less{}(k, static_cast<rb_node*>(x)->value);
                if (!goLeft && !Less{}(static_cast<rb_node*>(x)->value, k)) {
                    // equal key -> already present
                    return { iterator(x, _Myhead), false };
                }
                x = goLeft ? x->left : x->right;
            }

            // Allocate and link new node
            rb_node* z = alloc_node_(std::forward<Args>(args)...);
            z->left = z->right = _Myhead;
            z->parent = (y == _Myhead) ? nullptr : y;

            if (y == _Myhead) {
                _Myhead->parent = z; // root
                _Myhead->left = z;   // leftmost
                _Myhead->right = z;  // rightmost
            } else if (goLeft) {
                y->left = z;
                if (y == _Myhead->left) _Myhead->left = z;
            } else {
                y->right = z;
                if (y == _Myhead->right) _Myhead->right = z;
            }

            insert_fixup_(z);
            ++_Mysize;
            return { iterator(z, _Myhead), true };
        }

        iterator erase(iterator pos) {
            assert(pos.head_ == _Myhead && "foreign iterator");
            rb_base* n = pos.cur_;
            iterator ret = pos; ++ret;
            erase_node_(n);
            --_Mysize;
            return ret;
        }

        size_type erase(const key_type& k) {
            auto it = find(k);
            if (it == end()) return 0;
            erase(it);
            return 1;
        }

        iterator erase(iterator first, iterator last) {
            while (first != last) first = erase(first);
            return last;
        }

        void swap(set& other) MSVC8_SET_NOEXCEPT {
            if (this == &other) return;
            std::swap(_Myproxy, other._Myproxy);
            std::swap(_Myhead, other._Myhead);
            std::swap(_Mysize, other._Mysize);
            std::swap(_Tag, other._Tag);
        }

    private:
        // -------- helpers: header management --------
        static rb_base* alloc_header_() {
            // allocate header as rb_base
            void* p = ::operator new(sizeof(rb_base));
            return static_cast<rb_base*>(p);
        }
        static void free_header_(rb_base* h) MSVC8_SET_NOEXCEPT {
#if !MSVC8_SET_DISABLE_FREE
            ::operator delete(h);
#endif
        }
        static void init_header_(rb_base* h) MSVC8_SET_NOEXCEPT {
            h->left = h; h->right = h; h->parent = h;
            h->color = 1; // black
            h->isHeader = 1;
            h->pad = 0;
        }

        template<class...Args>
        static rb_node* alloc_node_(Args&&...args) {
            void* mem = ::operator new(sizeof(rb_node));
            try {
                return new (mem) rb_node(std::forward<Args>(args)...);
            } catch (...) {
                ::operator delete(mem);
                throw;
            }
        }
        static void free_node_(rb_node* n) MSVC8_SET_NOEXCEPT {
#if !MSVC8_SET_DISABLE_FREE
            n->~rb_node();
            ::operator delete(n);
#endif
        }

        static rb_base* tree_min_(rb_base* x, rb_base* head) MSVC8_SET_NOEXCEPT { while (x->left != head) x = x->left;  return x; }
        static rb_base* tree_max_(rb_base* x, rb_base* head) MSVC8_SET_NOEXCEPT { while (x->right != head) x = x->right; return x; }

        void left_rotate_(rb_base* x) {
            rb_base* y = x->right;
            x->right = y->left;
            if (y->left != _Myhead) y->left->parent = x;
            y->parent = x->parent;
            if (x->parent == nullptr)        _Myhead->parent = y;
            else if (x == x->parent->left)   x->parent->left = y;
            else                              x->parent->right = y;
            y->left = x;
            x->parent = y;
            if (_Myhead->left == x && x->left == _Myhead)   _Myhead->left = y;
            if (_Myhead->right == y && y->right == _Myhead) _Myhead->right = x;
        }

        void right_rotate_(rb_base* x) {
            rb_base* y = x->left;
            x->left = y->right;
            if (y->right != _Myhead) y->right->parent = x;
            y->parent = x->parent;
            if (x->parent == nullptr)         _Myhead->parent = y;
            else if (x == x->parent->right)   x->parent->right = y;
            else                               x->parent->left = y;
            y->right = x;
            x->parent = y;
            if (_Myhead->right == x && x->right == _Myhead) _Myhead->right = y;
            if (_Myhead->left == y && y->left == _Myhead)   _Myhead->left = x;
        }

        void insert_fixup_(rb_base* z_) {
            // z_ is rb_node*, but we only use base links/colors here
            rb_base* z = z_;
            while (z->parent && z->parent->color == 0) { // parent is red
                rb_base* gp = z->parent->parent;
                if (z->parent == gp->left) {
                    rb_base* y = gp->right; // uncle
                    if (y != _Myhead && y->color == 0) { // red uncle
                        z->parent->color = 1;
                        y->color = 1;
                        gp->color = 0;
                        z = gp;
                    } else {
                        if (z == z->parent->right) {
                            z = z->parent;
                            left_rotate_(z);
                        }
                        z->parent->color = 1;
                        gp->color = 0;
                        right_rotate_(gp);
                    }
                } else {
                    rb_base* y = gp->left;
                    if (y != _Myhead && y->color == 0) {
                        z->parent->color = 1;
                        y->color = 1;
                        gp->color = 0;
                        z = gp;
                    } else {
                        if (z == z->parent->left) {
                            z = z->parent;
                            right_rotate_(z);
                        }
                        z->parent->color = 1;
                        gp->color = 0;
                        left_rotate_(gp);
                    }
                }
                if (z == _Myhead->parent) break;
            }
            _Myhead->parent->color = 1; // root is black
        }

        void transplant_(rb_base* u, rb_base* v) {
            if (u->parent == nullptr)                 _Myhead->parent = v;
            else if (u == u->parent->left)            u->parent->left = v;
            else                                      u->parent->right = v;
            if (v != _Myhead) v->parent = u->parent;
        }

        void erase_node_(rb_base* z) {
            rb_base* y = z;
            std::uint8_t y_orig = y->color;
            rb_base* x = _Myhead;
            rb_base* x_parent = nullptr;

            if (z->left == _Myhead) {
                x = z->right;
                x_parent = z->parent;
                transplant_(z, z->right);
            } else if (z->right == _Myhead) {
                x = z->left;
                x_parent = z->parent;
                transplant_(z, z->left);
            } else {
                y = tree_min_(z->right, _Myhead);
                y_orig = y->color;
                x = y->right;
                if (y->parent == z) {
                    x_parent = y;
                    if (x != _Myhead) x->parent = y;
                } else {
                    transplant_(y, y->right);
                    y->right = z->right; y->right->parent = y;
                    x_parent = y->parent;
                }
                transplant_(z, y);
                y->left = z->left; y->left->parent = y;
                y->color = z->color;
            }

            // header extremes maintenance
            if (_Myhead->left == z)  _Myhead->left = (z->left != _Myhead) ? tree_max_(z->left, _Myhead) : (z->parent ? z->parent : _Myhead);
            if (_Myhead->right == z) _Myhead->right = (z->right != _Myhead) ? tree_min_(z->right, _Myhead) : (z->parent ? z->parent : _Myhead);

            free_node_(static_cast<rb_node*>(z));

            if (y_orig == 1) // if removed black
                erase_fixup_(x, x_parent);
        }

        void erase_fixup_(rb_base* x, rb_base* parent) {
            rb_base* p = (x != _Myhead) ? x->parent : parent;
            while ((x != _Myhead->parent) && (x == _Myhead || x->color == 1)) {
                if (x == (p ? p->left : nullptr)) {
                    rb_base* w = p ? p->right : _Myhead;
                    if (w == _Myhead) break;
                    if (w->color == 0) {
                        w->color = 1; p->color = 0;
                        left_rotate_(p);
                        w = p->right;
                    }
                    if ((w->left == _Myhead || w->left->color == 1) &&
                        (w->right == _Myhead || w->right->color == 1)) {
                        w->color = 0;
                        x = p; p = x ? x->parent : nullptr;
                    } else {
                        if (w->right == _Myhead || w->right->color == 1) {
                            if (w->left != _Myhead) w->left->color = 1;
                            w->color = 0;
                            right_rotate_(w);
                            w = p->right;
                        }
                        w->color = p ? p->color : 1;
                        if (p) p->color = 1;
                        if (w->right != _Myhead) w->right->color = 1;
                        if (p) left_rotate_(p);
                        x = _Myhead->parent;
                        break;
                    }
                } else {
                    rb_base* w = p ? p->left : _Myhead;
                    if (w == _Myhead) break;
                    if (w->color == 0) {
                        w->color = 1; p->color = 0;
                        right_rotate_(p);
                        w = p->left;
                    }
                    if ((w->right == _Myhead || w->right->color == 1) &&
                        (w->left == _Myhead || w->left->color == 1)) {
                        w->color = 0;
                        x = p; p = x ? x->parent : nullptr;
                    } else {
                        if (w->left == _Myhead || w->left->color == 1) {
                            if (w->right != _Myhead) w->right->color = 1;
                            w->color = 0;
                            left_rotate_(w);
                            w = p->left;
                        }
                        w->color = p ? p->color : 1;
                        if (p) p->color = 1;
                        if (w->left != _Myhead) w->left->color = 1;
                        if (p) right_rotate_(p);
                        x = _Myhead->parent;
                        break;
                    }
                }
            }
            if (x != _Myhead) x->color = 1;
        }

        void post_delete_(rb_base* r) {
            // non-recursive post-order delete
            rb_base* cur = r;
            rb_base* last = _Myhead;
            while (cur != _Myhead) {
                if (last == cur->parent) {
                    last = cur;
                    if (cur->left != _Myhead) { cur = cur->left; continue; }
                }
                if (last == cur->left) {
                    last = cur;
                    if (cur->right != _Myhead) { cur = cur->right; continue; }
                }
                rb_base* parent = cur->parent ? cur->parent : _Myhead;
                free_node_(static_cast<rb_node*>(cur));
                if (parent == _Myhead) break;
                last = cur; cur = parent;
            }
        }

        void steal_from_(set& o) MSVC8_SET_NOEXCEPT {
            _Myproxy = o._Myproxy;  o._Myproxy = nullptr;
            _Myhead = o._Myhead;   o._Myhead = alloc_header_(); init_header_(o._Myhead);
            _Mysize = o._Mysize;   o._Mysize = 0;
            _Tag = o._Tag;      o._Tag = nullptr;
        }

    private:
        // -------- fixed 16-byte payload (x86) --------
        _Container_proxy* _Myproxy; // 0x0
        rb_base* _Myhead;  // 0x4 (sentinel)
        size_type         _Mysize;  // 0x8
        void* _Tag;     // 0xC (reserved/policy)
    };

    // Size check (x86)
    static_assert(sizeof(set<int>) == 16, "msvc8::set must be 16 bytes on x86");

} // namespace msvc8

#pragma pack(pop)
