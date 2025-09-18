#pragma once
#include <cstddef>
#include <iterator>
#include <type_traits>

namespace moho
{
    /**
     * Intrusive list node (prev/next only). No payload.
     * T is the *declared* owner type for RTTI/signatures; layout is two pointers.
     */
    template<class T, class U>
    struct TDatListItem
    {
        using item_t = TDatListItem<T, U>;

        item_t* mPrev;
        item_t* mNext;

        /**
         * Construct self-linked node.
         */
        TDatListItem() : mPrev{ this }, mNext{ this } {}

        /**
         * Unlink this node and return next.
         */
        item_t* ListUnlink() noexcept
        {
            item_t* const nxt = mNext;
            mPrev->mNext = mNext;
            mNext->mPrev = mPrev;
            mNext = this;
            mPrev = this;
            return nxt;
        }

        /**
         * Link this node after the given node (that).
         */
        item_t* ListLinkAfter(item_t* that) noexcept
        {
            // detach self
            mPrev->mNext = mNext;
            mNext->mPrev = mPrev;
            mPrev = this;
            mNext = this;

            // insert after 'that'
            item_t* const next = that->mNext;
            mPrev = that;
            mNext = next;
            next->mPrev = this;
            that->mNext = this;
            return mPrev;
        }

        /**
         * Link this node before the given node (that).
         */
        item_t* ListLinkBefore(item_t* that) noexcept
        {
            // detach self
            mPrev->mNext = mNext;
            mNext->mPrev = mPrev;
            mPrev = this;
            mNext = this;

            // insert before 'that'
            item_t* const prev = that->mPrev;
            mPrev = prev;
            mNext = that;
            prev->mNext = this;
            that->mPrev = this;
            return mPrev;
        }
    };

    /**
     * Intrusive list "head" type. Derives from node, no extra fields.
     * You may use it both as a real head (sentinel object) and as a node inside an element.
     */
    template<class T, class U>
    struct TDatList : TDatListItem<T, U>
    {
        using item_t = TDatListItem<T, U>;
        using base = item_t;

        /**
         * Bidirectional iterator over nodes (yields item_t*).
         */
        template<bool IsConst>
        struct Iterator
        {
            using node_type = std::conditional_t<IsConst, const item_t, item_t>;
            using pointer = node_type*;      // node*
            using reference = node_type&;      // node&
            using difference_type = std::ptrdiff_t;
            using iterator_category = std::bidirectional_iterator_tag;

            pointer pos{ nullptr };

            Iterator& operator++() noexcept { pos = pos->mNext; return *this; }
            Iterator& operator--() noexcept { pos = pos->mPrev; return *this; }
            reference operator*()  const noexcept { return *pos; }
            pointer   operator->() const noexcept { return pos; }
            pointer   node()       const noexcept { return pos; }
            bool operator==(const Iterator& r) const noexcept { return pos == r.pos; }
            bool operator!=(const Iterator& r) const noexcept { return pos != r.pos; }

            Iterator() = default;
            explicit Iterator(pointer p) : pos{ p } {}
        };

        using iterator = Iterator<false>;
        using const_iterator = Iterator<true>;

        /**
         * Construct empty head (self-linked).
         */
        TDatList() : base{} {}

        /**
         * Begin/end as node iterators.
         */
        iterator       begin()       noexcept { return iterator{ this->mNext }; }
        iterator       end()         noexcept { return iterator{ this }; }
        const_iterator begin() const noexcept { return const_iterator{ this->mNext }; }
        const_iterator end()   const noexcept { return const_iterator{ const_cast<item_t*>(static_cast<const item_t*>(this)) }; }

        /**
         * Return true if empty.
         */
        bool empty() const noexcept { return this->mNext == this; }

        /**
         * Erase at iterator (unlink node); return iterator to next.
         */
        iterator erase(iterator it) noexcept
        {
            item_t* const next = it.pos->mNext;
            it.pos->ListUnlink();
            return iterator{ next };
        }

        /**
         * Push NODE front/back (node must be unlinked).
         */
        void push_front(item_t* node) noexcept { node->ListLinkAfter(this); }
        void push_back(item_t* node) noexcept { node->ListLinkBefore(this); }

        /**
         * Pop front/back node; nullptr if empty.
         */
        item_t* pop_front() noexcept
        {
            if (empty()) return nullptr;
            item_t* n = this->mNext;
            n->ListUnlink();
            return n;
        }

        item_t* pop_back() noexcept
        {
            if (empty()) return nullptr;
            item_t* p = this->mPrev;
            p->ListUnlink();
            return p;
        }
    };

    /**
     * Compute runtime offset of Base subobject and 'Hook' member within Owner.
     * Works with multiple/diamond inheritance like in MSVC layout for non-virtual bases.
     */
    template<class Owner, class Base, class HookNode>
    inline std::ptrdiff_t offset_of_member_in_owner(HookNode Base::* Hook) noexcept
    {
        Owner* o = reinterpret_cast<Owner*>(0x1000);
        Base* b = static_cast<Base*>(o); // may add base offset
        HookNode* mem = &(b->*Hook);
        return reinterpret_cast<char*>(mem) - reinterpret_cast<char*>(o);
    }

    /**
     * Convert node pointer (pointing at Base::Hook) back to Owner*.
     * HookNode must be TDatList<Base,U> or TDatListItem<Base,U> (layout-compatible).
     */
    template<class Owner, class Base, class U, class HookNode>
    inline Owner* owner_from_node_with_base(TDatListItem<Base, U>* n, HookNode Base::* Hook) noexcept
    {
        const std::ptrdiff_t off = offset_of_member_in_owner<Owner, Base>(Hook);
        return reinterpret_cast<Owner*>(reinterpret_cast<char*>(n) - off);
    }

    /**
     * Get node pointer (Base::Hook) from Owner*.
     * HookNode may be TDatList<Base,U> or TDatListItem<Base,U>.
     */
    template<class Owner, class Base, class U, class HookNode>
    inline TDatListItem<Base, U>* node_from_owner_with_base(Owner* o, HookNode Base::* Hook) noexcept
    {
        Base* b = static_cast<Base*>(o);
        HookNode* m = &(b->*Hook);
        return static_cast<TDatListItem<Base, U>*>(m); // HookNode derives from TDatListItem
    }

    /**
     * Two-pointer head (start/end) for lists whose node lives in Base as member Hook.
     * Owner: most-derived element type (SPacket)
     * Base:  base class that contains Hook (SPacketHeader)
     * U:     tag
     * Hook:  pointer-to-member in Base of type TDatList<Owner,U>
     */
    template<
        class Owner,
        class Base,
        class U,
        TDatList<Owner, U> Base::* Hook
    >
    struct TPairList
    {
        typedef TDatListItem<Owner, U> node_t;

        Owner* start; // acts as first sentinel address
        Owner* end;   // acts as second sentinel address

        /**
         * Construct empty (uninitialized); call init_empty() before use.
         */
        TPairList() : start(0), end(0) {}

        /**
         * Initialize empty state exactly like in PE: start == &end; link sentinels.
         */
        void init_empty() noexcept
        {
            end_node()->mNext = start_node();
            start_node()->mPrev = end_node();
            start = reinterpret_cast<Owner*>(&end);
            end = reinterpret_cast<Owner*>(&end);
        }

        /**
         * Return true if empty (start points to &end).
         */
        bool empty() const noexcept
        {
            return reinterpret_cast<const void*>(start) ==
                reinterpret_cast<const void*>(&end);
        }

        /**
         * Access sentinel nodes placed over &start / &end.
         */
        node_t* start_node()       noexcept { return reinterpret_cast<node_t*>(&start); }
        const node_t* start_node() const noexcept { return reinterpret_cast<const node_t*>(&start); }
        node_t* end_node()         noexcept { return reinterpret_cast<node_t*>(&end); }
        const node_t* end_node()   const noexcept { return reinterpret_cast<const node_t*>(&end); }

        /**
         * Node from owner (Owner* -> node_t*) via Base::Hook.
         */
        static node_t* node_from_owner(Owner* o) noexcept
        {
            Base* b = static_cast<Base*>(o);
            TDatList<Owner, U>* m = &(b->*Hook);
            return static_cast<node_t*>(m); // first base of TDatList is node_t
        }

        /**
         * Owner from node (node_t* -> Owner*) using Base::Hook offset inside Owner.
         */
        static Owner* owner_from_node(node_t* n) noexcept
        {
            // compute offset of Base::Hook within Owner
            Owner* dummy = reinterpret_cast<Owner*>(0x1000);
            Base* db = static_cast<Base*>(dummy);                    // base offset
            TDatList<Owner, U>* dm = &(db->*Hook);                        // member addr
            std::ptrdiff_t off = reinterpret_cast<char*>(dm) - reinterpret_cast<char*>(dummy);
            return reinterpret_cast<Owner*>(reinterpret_cast<char*>(n) - off);
        }

        /**
         * Iterator over nodes between sentinels.
         */
        template<bool IsConst>
        struct Iterator
        {
            typedef typename std::conditional<IsConst, const node_t, node_t>::type node_type;
            node_type* pos;
            Iterator& operator++() noexcept { pos = pos->mNext; return *this; }
            Iterator& operator--() noexcept { pos = pos->mPrev; return *this; }
            node_type& operator*()  const noexcept { return *pos; }
            node_type* operator->() const noexcept { return pos; }
            node_type* node()       const noexcept { return pos; }
            bool operator==(const Iterator& r) const noexcept { return pos == r.pos; }
            bool operator!=(const Iterator& r) const noexcept { return pos != r.pos; }
            Iterator() : pos(0) {}
            explicit Iterator(node_type* p) : pos(p) {}
        };

        typedef Iterator<false> iterator;
        typedef Iterator<true>  const_iterator;

        iterator       begin()       noexcept { return iterator{ start_node()->mNext }; }
        iterator       endit()       noexcept { return iterator{ end_node() }; }
        const_iterator begin() const noexcept { return const_iterator{ start_node()->mNext }; }
        const_iterator endit() const noexcept { return const_iterator{ end_node() }; }

        /**
         * Push element at front/back (owner pointer), element must be unlinked.
         */
        void push_front(Owner* o) noexcept { node_from_owner(o)->ListLinkAfter(start_node()); }
        void push_back(Owner* o) noexcept { node_from_owner(o)->ListLinkBefore(end_node()); }

        /**
         * Erase node at iterator; return iterator to next.
         */
        iterator erase(iterator it) noexcept
        {
            node_t* const next = it.pos->mNext;
            it.pos->ListUnlink();
            return iterator{ next };
        }
    };
}
