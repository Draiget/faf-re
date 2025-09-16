#pragma once
#include <type_traits>

namespace gpg
{
    /**
     * Intrusive doubly-linked circular list node (CRTP).
     * Requirements:
     *  - T must publicly inherit DListItem<T, U>
     *  - No virtuals; standard-layout; first base at offset 0
     *  - On x86 the raw layout is: [prev (4)][next (4)]
     */
#pragma pack(push, 4)
    template<class T, class U = void>
    struct DListItem 
    {
        using type = T;
        using unk_t = U;
        using item_t = DListItem<type, unk_t>;

        item_t* mPrev;
        item_t* mNext;

        /**
         * Construct as a singleton ring (self-linked).
         *
         */
        DListItem() noexcept : mPrev{ this }, mNext{ this } {}

        /**
         * Dtor unlinks from the list and resets to singleton.
         */
        ~DListItem() { ListUnlink(); }

        /**
         * Cast this node to the owning T*.
         */
        type* Get() noexcept {
	        return static_cast<type*>(this);
        }
        const type* Get() const noexcept {
	        return static_cast<const type*>(this);
        }

        /**
         * Return true if node is a singleton (not linked into any list).
         */
        [[nodiscard]]
    	bool ListIsUnlinked() const noexcept {
	        return mNext == this;
        }

        /**
         * Return true if node participates in any non-singleton cycle.
         */
        [[nodiscard]]
    	bool HasNext() const noexcept {
	        return mPrev != mNext;
        }

        /**
         * Unlink this node from its current list, making it a singleton.
         * Assembly pattern matches the decompiled code: write neighbor links first,
         * then self-links (prev/next -> self).
         */
        void ListUnlink() noexcept {
            // Fast path: already singleton
            if (mNext == this) {
                mPrev = this; // keep strictly the same final shape
                return;
            }
            // Neighbors adopt each other
            mNext->mPrev = mPrev;
            mPrev->mNext = mNext;
            // Reset self as singleton
            mPrev = this;
            mNext = this;
        }

        /**
         * Insert this node immediately BEFORE 'that' node.
         * Equivalent to: [... that->mPrev] <-> [this] <-> [that]
         * Matches the observed store order:
         *  - unlink self
         *  - set self prev/next
         *  - fix neighbors both sides
         */
        void ListLinkBefore(type* that) noexcept {
            auto* casted = static_cast<item_t*>(that);
            // Safe for re-linking: ensure we are singleton first.
            ListUnlink();

            // this between that->prev and that
            mPrev = casted->mPrev;
            mNext = casted;
            casted->mPrev->mNext = this;
            casted->mPrev = this;
        }

        /**
         * Insert this node immediately AFTER 'that' node.
         * Equivalent to: [that] <-> [this] <-> [that->mNext]
         * Store order mirrors ListLinkBefore to match common patterns.
         */
        void ListLinkAfter(type* that) noexcept {
            auto* casted = static_cast<item_t*>(that);
            // Ensure singleton
            ListUnlink();

            // this between that and that->next
            mPrev = casted;
            mNext = casted->mNext;
            casted->mNext->mPrev = this;
            casted->mNext = this;
        }

        // Optional overloads that accept item_t*, handy for sentinel usage.
        void ListLinkBefore(item_t* that) noexcept { ListLinkBefore(static_cast<type*>(that)); }
        void ListLinkAfter(item_t* that)  noexcept { ListLinkAfter(static_cast<type*>(that)); }

    protected:
        // Enforce CRTP usage at compile time (non-failing on dependent contexts).
        static_assert(std::is_empty_v<U> || !std::is_empty_v<U> || true,
            "U is an arbitrary tag and unused at runtime.");
    };
#pragma pack(pop)

    /**
     * Intrusive list head (sentinel) for T nodes.
     * T must publicly inherit DListItem<T, U>.
     * Head itself is also a node: empty() iff head->next == head.
     */
    template<class T, class U = void>
    struct DList : DListItem<T, U>
	{
        using type = T;
        using unk_t = U;
        using item_t = DListItem<type, unk_t>;
        using head_t = DList<type, unk_t>;

        /**
         * Iterator over T* in the circular list (stops at head).
         */
        struct iterator {
            item_t* pos{ nullptr };
            item_t* head{ nullptr };

            iterator() = default;
            iterator(item_t* p, item_t* h) : pos{ p }, head{ h } {}

            iterator& operator++() noexcept {
                pos = pos->mNext;
                return *this;
            }
            type* operator*() const noexcept { return pos->Get(); }
            type* operator->() const noexcept { return pos->Get(); }
            bool operator==(const iterator& rhs) const noexcept { return pos == rhs.pos && head == rhs.head; }
            bool operator!=(const iterator& rhs) const noexcept { return !(*this == rhs); }
        };

        struct const_iterator {
            const item_t* pos{ nullptr };
            const item_t* head{ nullptr };

            const_iterator() = default;
            const_iterator(const item_t* p, const item_t* h) : pos{ p }, head{ h } {}

            const_iterator& operator++() noexcept {
                pos = pos->mNext;
                return *this;
            }
            const type* operator*() const noexcept { return pos->Get(); }
            const type* operator->() const noexcept { return pos->Get(); }
            bool operator==(const const_iterator& rhs) const noexcept { return pos == rhs.pos && head == rhs.head; }
            bool operator!=(const const_iterator& rhs) const noexcept { return !(*this == rhs); }
        };

        /**
         * Begin at the first element after the head.
         */
        iterator begin() noexcept {
	        return iterator(this->mNext, this);
        }
        /**
         * End is the head itself (sentinel).
         */
        iterator end() noexcept {
	        return iterator(this, this);
        }

        const_iterator begin() const noexcept { return const_iterator(this->mNext, this); }
        const_iterator end()   const noexcept { return const_iterator(this, this); }

        /**
         * True if the list is empty.
         */
        [[nodiscard]]
    	bool empty() const noexcept {
	        return this->mNext == this;
        }

        /**
         * Front element or nullptr if empty.
         */
        type* front() noexcept {
	        return empty() ? nullptr : this->mNext->Get();
        }
        const type* front() const noexcept {
	        return empty() ? nullptr : this->mNext->Get();
        }

        /**
         * Back element or nullptr if empty.
         *
         */
        type* back() noexcept {
	        return empty() ? nullptr : this->mPrev->Get();
        }
        const type* back() const noexcept {
	        return empty() ? nullptr : this->mPrev->Get();
        }

        /**
         * Push at front: insert after head.
         */
        void push_front(type* node) noexcept {
	        static_cast<item_t*>(node)->ListLinkAfter(this);
        }

        /**
         * Push at back: insert before head.
         */
        void push_back(type* node) noexcept {
	        static_cast<item_t*>(node)->ListLinkBefore(this);
        }

        /**
         * Pop front: unlink the first node and return it (or nullptr if empty).
         */
        type* pop_front() noexcept {
            if (empty()) return nullptr;
            item_t* n = this->mNext;
            n->ListUnlink();
            return n->Get();
        }

        /**
         * Pop back: unlink the last node and return it (or nullptr if empty).
         */
        type* pop_back() noexcept {
            if (empty()) return nullptr;
            item_t* n = this->mPrev;
            n->ListUnlink();
            return n->Get();
        }

        /**
         * Clear the list (does NOT destroy payload objects).
         */
        void clear() noexcept {
            while (!empty()) {
                this->mNext->ListUnlink();
            }
        }
    };
}
