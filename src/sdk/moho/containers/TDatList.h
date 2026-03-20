#pragma once
#include <assert.h>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <type_traits>

namespace moho
{
  /**
   * Intrusive list node (prev/next only). No payload.
   * T is the *declared* owner type for RTTI/signatures; layout is two pointers.
   */
  template <class T, class U>
  struct TDatListItem
  {
    using type = T;
    using item_t = TDatListItem<type, U>;

    item_t* mPrev;
    item_t* mNext;

    /**
     * Construct self-linked node.
     */
    TDatListItem()
      : mPrev{this}
      , mNext{this}
    {}

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
      ListUnlink();

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
      ListUnlink();

      // insert before 'that'
      item_t* const prev = that->mPrev;
      mPrev = prev;
      mNext = that;
      prev->mNext = this;
      that->mPrev = this;
      return mPrev;
    }

    /**
     * Return owner object for next node.
     */
    type* ListGetNext() noexcept
    {
      return static_cast<type*>(this->mNext);
    }

    /**
     * Return owner object for prev node.
     */
    type* ListGetPrev() noexcept
    {
      return static_cast<type*>(this->mPrev);
    }

    /**
     * Is this node unlinked (self-linked)?
     */
    [[nodiscard]]
    bool ListIsSingleton() const noexcept
    {
      return mNext == this && mPrev == this;
    }

    /**
     * Move this node to be the first after head (MRU push).
     */
    void ListMoveToFront(item_t* head) noexcept
    {
      ListLinkAfter(head);
    }

    /**
     * Move this node to be right before head (LRU push).
     */
    void ListMoveToBack(item_t* head) noexcept
    {
      ListLinkBefore(head);
    }
  };

  /**
   * Intrusive list "head" type. Derives from node, no extra fields.
   * You may use it both as a real head (sentinel object) and as a node inside an element.
   */
  template <class T, class U>
  struct TDatList : TDatListItem<T, U>
  {
    using item_t = TDatListItem<T, U>;
    using base = item_t;

    /**
     * Bidirectional iterator over nodes (yields item_t*).
     */
    template <bool IsConst>
    struct Iterator
    {
      using node_type = std::conditional_t<IsConst, const item_t, item_t>;
      using pointer = node_type*;   // node*
      using reference = node_type&; // node&
      using difference_type = std::ptrdiff_t;
      using iterator_category = std::bidirectional_iterator_tag;

      pointer pos{nullptr};

      Iterator& operator++() noexcept
      {
        pos = pos->mNext;
        return *this;
      }
      Iterator& operator--() noexcept
      {
        pos = pos->mPrev;
        return *this;
      }
      reference operator*() const noexcept
      {
        return *pos;
      }
      pointer operator->() const noexcept
      {
        return pos;
      }
      pointer node() const noexcept
      {
        return pos;
      }
      bool operator==(const Iterator& r) const noexcept
      {
        return pos == r.pos;
      }
      bool operator!=(const Iterator& r) const noexcept
      {
        return pos != r.pos;
      }

      Iterator() = default;
      explicit Iterator(pointer p)
        : pos{p}
      {}
    };

    using iterator = Iterator<false>;
    using const_iterator = Iterator<true>;

    /**
     * Construct empty head (self-linked).
     */
    TDatList()
      : base{}
    {}

    /**
     * Begin/end as node iterators.
     */
    iterator begin() noexcept
    {
      return iterator{this->mNext};
    }
    iterator end() noexcept
    {
      return iterator{this};
    }
    const_iterator begin() const noexcept
    {
      return const_iterator{this->mNext};
    }
    const_iterator end() const noexcept
    {
      return const_iterator{const_cast<item_t*>(static_cast<const item_t*>(this))};
    }

    /**
     * Return true if empty.
     */
    bool empty() const noexcept
    {
      return this->mNext == this;
    }

    /**
     * Erase at iterator (unlink node); return iterator to next.
     */
    iterator erase(iterator it) noexcept
    {
      item_t* const next = it.pos->mNext;
      it.pos->ListUnlink();
      return iterator{next};
    }

    /**
     * Push NODE front/back (node must be unlinked).
     */
    void push_front(item_t* node) noexcept
    {
      node->ListLinkAfter(this);
    }
    void push_back(item_t* node) noexcept
    {
      node->ListLinkBefore(this);
    }

    /**
     * Pop front/back node; nullptr if empty.
     */
    item_t* pop_front() noexcept
    {
      if (empty())
        return nullptr;
      item_t* n = this->mNext;
      n->ListUnlink();
      return n;
    }

    item_t* pop_back() noexcept
    {
      if (empty())
        return nullptr;
      item_t* p = this->mPrev;
      p->ListUnlink();
      return p;
    }

    /**
     * Iterator that yields owner (T*) instead of node.
     */
    struct owner_iterator
    {
      item_t* pos{nullptr};

      owner_iterator& operator++() noexcept
      {
        pos = pos->mNext;
        return *this;
      }
      owner_iterator& operator--() noexcept
      {
        pos = pos->mPrev;
        return *this;
      }

      T* operator*() const noexcept
      {
#ifndef NDEBUG
        // Debug-time sanity roundtrip: node -> owner -> node
        auto* d = static_cast<T*>(pos);
        assert(static_cast<item_t*>(d) == pos);
#endif
        return static_cast<T*>(pos); // centralized downcast
      }
      T* operator->() const noexcept
      {
        return **this;
      }

      bool operator==(const owner_iterator& r) const noexcept
      {
        return pos == r.pos;
      }
      bool operator!=(const owner_iterator& r) const noexcept
      {
        return pos != r.pos;
      }
    };

    struct owner_range
    {
      owner_iterator b, e;
      owner_iterator begin() const noexcept
      {
        return b;
      }
      owner_iterator end() const noexcept
      {
        return e;
      }
    };

    owner_range owners() noexcept
    {
      return {owner_iterator{this->mNext}, owner_iterator{static_cast<item_t*>(this)}};
    }
    owner_range owners() const noexcept
    {
      // const-версию можно сделать отдельно, если нужен const T*
      return {
        owner_iterator{const_cast<item_t*>(this->mNext)},
        owner_iterator{const_cast<item_t*>(static_cast<const item_t*>(this))}
      };
    }

    /**
     * Iterator/range variant that is safe when current node can unlink/delete itself
     * during loop body execution. It snapshots mNext in operator*().
     */
    struct owner_safe_iterator
    {
      item_t* pos{nullptr};
      item_t* next{nullptr};

      owner_safe_iterator& operator++() noexcept
      {
        if (next == nullptr && pos != nullptr) {
          next = pos->mNext;
        }
        pos = next;
        next = nullptr;
        return *this;
      }
      owner_safe_iterator& operator--() noexcept
      {
        pos = pos->mPrev;
        next = nullptr;
        return *this;
      }

      T* operator*() noexcept
      {
#ifndef NDEBUG
        auto* d = static_cast<T*>(pos);
        assert(static_cast<item_t*>(d) == pos);
#endif
        next = pos->mNext;
        return static_cast<T*>(pos);
      }
      T* operator->() noexcept
      {
        return **this;
      }

      bool operator==(const owner_safe_iterator& r) const noexcept
      {
        return pos == r.pos;
      }
      bool operator!=(const owner_safe_iterator& r) const noexcept
      {
        return pos != r.pos;
      }
    };

    struct owner_safe_range
    {
      owner_safe_iterator b, e;
      owner_safe_iterator begin() const noexcept
      {
        return b;
      }
      owner_safe_iterator end() const noexcept
      {
        return e;
      }
    };

    owner_safe_range owners_safe() noexcept
    {
      return {owner_safe_iterator{this->mNext}, owner_safe_iterator{static_cast<item_t*>(this)}};
    }

    owner_safe_range owners_safe() const noexcept
    {
      return {
        owner_safe_iterator{const_cast<item_t*>(this->mNext)},
        owner_safe_iterator{const_cast<item_t*>(static_cast<const item_t*>(this))}
      };
    }

    template <class Owner, item_t Owner::* Member>
    static Owner* owner_from_member_node(item_t* node) noexcept
    {
      const auto* const memberPtr = &(reinterpret_cast<Owner const volatile*>(0)->*Member);
      const auto memberOffset = static_cast<std::ptrdiff_t>(reinterpret_cast<std::uintptr_t>(memberPtr));
      return reinterpret_cast<Owner*>(reinterpret_cast<char*>(node) - memberOffset);
    }

    template <class Owner, item_t Owner::* Member>
    static const Owner* owner_from_member_node(const item_t* node) noexcept
    {
      return owner_from_member_node<Owner, Member>(const_cast<item_t*>(node));
    }

    template <class Owner, item_t Owner::* Member, bool IsConst>
    struct member_owner_iterator
    {
      using node_type = std::conditional_t<IsConst, const item_t, item_t>;
      using owner_type = std::conditional_t<IsConst, const Owner, Owner>;
      using difference_type = std::ptrdiff_t;
      using iterator_category = std::bidirectional_iterator_tag;

      node_type* pos{nullptr};

      member_owner_iterator& operator++() noexcept
      {
        pos = pos->mNext;
        return *this;
      }
      member_owner_iterator& operator--() noexcept
      {
        pos = pos->mPrev;
        return *this;
      }

      owner_type* operator*() const noexcept
      {
        if constexpr (IsConst) {
          return owner_from_member_node<Owner, Member>(pos);
        }
        return owner_from_member_node<Owner, Member>(const_cast<item_t*>(pos));
      }

      owner_type* operator->() const noexcept
      {
        return **this;
      }

      bool operator==(const member_owner_iterator& r) const noexcept
      {
        return pos == r.pos;
      }
      bool operator!=(const member_owner_iterator& r) const noexcept
      {
        return pos != r.pos;
      }
    };

    template <class Owner, item_t Owner::* Member, bool IsConst>
    struct member_owner_range
    {
      using iterator = member_owner_iterator<Owner, Member, IsConst>;

      iterator b;
      iterator e;

      iterator begin() const noexcept
      {
        return b;
      }
      iterator end() const noexcept
      {
        return e;
      }
    };

    template <class Owner, item_t Owner::* Member>
    member_owner_range<Owner, Member, false> owners_member() noexcept
    {
      return {
        member_owner_iterator<Owner, Member, false>{this->mNext},
        member_owner_iterator<Owner, Member, false>{static_cast<item_t*>(this)}
      };
    }

    template <class Owner, item_t Owner::* Member>
    member_owner_range<Owner, Member, true> owners_member() const noexcept
    {
      return {
        member_owner_iterator<Owner, Member, true>{this->mNext},
        member_owner_iterator<Owner, Member, true>{static_cast<const item_t*>(this)}
      };
    }
  };
} // namespace moho
