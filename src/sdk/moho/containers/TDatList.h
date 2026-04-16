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
     * Address: 0x00442DA0 (FUN_00442DA0)
     * Address: 0x00443020 (FUN_00443020)
     * Address: 0x00443230 (FUN_00443230)
     * Address: 0x0063C060 (FUN_0063C060, typed-instantiation lane)
     * Address: 0x004856F0 (FUN_004856F0, typed-instantiation lane)
     * Address: 0x00485780 (FUN_00485780, typed-instantiation lane)
     *
     * What it does:
     * Resets one intrusive node to a self-linked singleton state.
     */
    void ListResetLinks() noexcept
    {
      mNext = this;
      mPrev = this;
    }

    /**
     * Address: 0x00443A50 (FUN_00443A50)
     * Address: 0x00443AA0 (FUN_00443AA0)
     * Address: 0x00443AC0 (FUN_00443AC0)
     * Address: 0x00443AE0 (FUN_00443AE0)
     * Address: 0x00443B00 (FUN_00443B00)
     * Address: 0x00443B60 (FUN_00443B60)
     * Address: 0x0047C260 (FUN_0047C260, typed-instantiation lane)
     * Address: 0x0047C540 (FUN_0047C540, typed-instantiation lane)
     * Address: 0x0047CA00 (FUN_0047CA00, typed-instantiation lane)
     * Address: 0x0047CA60 (FUN_0047CA60, typed-instantiation lane)
     * Address: 0x0047FA20 (FUN_0047FA20, typed-instantiation lane)
     * Address: 0x00480910 (FUN_00480910, typed-instantiation lane)
     *
     * What it does:
     * Unlinks this node from its current ring and resets it to singleton state.
     */
    item_t* ListUnlink() noexcept
    {
      item_t* const nxt = mNext;
      mPrev->mNext = mNext;
      mNext->mPrev = mPrev;
      ListResetLinks();
      return nxt;
    }

    /**
     * Address: 0x00632BC0 (FUN_00632BC0)
     * Address: 0x00565CE0 (FUN_00565CE0)
     * Address: 0x00565D00 (FUN_00565D00)
     * Address: 0x005A2D70 (FUN_005A2D70)
     * Address: 0x005A2D90 (FUN_005A2D90)
     * Address: 0x005D5800 (FUN_005D5800)
     * Address: 0x005E3CD0 (FUN_005E3CD0)
     * Address: 0x00599840 (FUN_00599840)
     * Address: 0x00760F20 (FUN_00760F20)
     * Address: 0x00765B70 (FUN_00765B70)
     * Address: 0x00786A80 (FUN_00786A80)
     * Address: 0x00779220 (FUN_00779220)
     *
     * What it does:
     * Unlinks this node from its current ring and returns this node after
     * restoring singleton self-links.
     */
    item_t* ListUnlinkSelf() noexcept
    {
      mPrev->mNext = mNext;
      mNext->mPrev = mPrev;
      ListResetLinks();
      return this;
    }

    /**
     * Address: 0x00442D60 (FUN_00442D60)
     * Address: 0x00442DD0 (FUN_00442DD0)
     * Address: 0x00442E40 (FUN_00442E40)
     * Address: 0x00442ED0 (FUN_00442ED0)
     * Address: 0x00443050 (FUN_00443050)
     * Address: 0x00480930 (FUN_00480930, typed-instantiation lane)
     * Address: 0x00485730 (FUN_00485730, offset+0x410 member-node lane)
     * Address: 0x004857B0 (FUN_004857B0, typed-instantiation lane)
     *
     * What it does:
     * Unlinks this node from its current ring and inserts it directly after `that`.
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
     * Address: 0x00443260 (FUN_00443260, offset+0x04 member-node lane)
     * Address: 0x00443A70 (FUN_00443A70)
     *
     * What it does:
     * Unlinks this node from its current ring and inserts it directly before `that`.
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
     * Address: 0x004439F0 (FUN_004439F0)
     * Address: 0x00443A10 (FUN_00443A10)
     * Address: 0x00443A30 (FUN_00443A30)
     * Address: 0x00443B20 (FUN_00443B20)
     * Address: 0x00443B40 (FUN_00443B40)
     *
     * What it does:
     * Swaps one node's intrusive link lanes (`mPrev`, `mNext`) with another node.
     */
    item_t* SwapLinks(item_t* that) noexcept
    {
      item_t* const prev = mPrev;
      mPrev = that->mPrev;
      that->mPrev = prev;

      item_t* const next = mNext;
      mNext = that->mNext;
      that->mNext = next;
      return that;
    }

    /**
     * Address: 0x00443240 (FUN_00443240)
     * Address: 0x00626DF0 (FUN_00626DF0)
     * Address: 0x00628700 (FUN_00628700)
     * Address: 0x0063C000 (FUN_0063C000)
     * Address: 0x0064C230 (FUN_0064C230)
     * Address: 0x00651ED0 (FUN_00651ED0)
     * Address: 0x00651F30 (FUN_00651F30)
     * Address: 0x006521C0 (FUN_006521C0)
     * Address: 0x0066A100 (FUN_0066A100)
     * Address: 0x0066A540 (FUN_0066A540)
     * Address: 0x0067CCF0 (FUN_0067CCF0)
     * Address: 0x0067D080 (FUN_0067D080)
     * Address: 0x0067D650 (FUN_0067D650)
     * Address: 0x00680350 (FUN_00680350)
     * Address: 0x00685890 (FUN_00685890)
     * Address: 0x006858B0 (FUN_006858B0)
     * Address: 0x006870C0 (FUN_006870C0)
     * Address: 0x006874D0 (FUN_006874D0)
     * Address: 0x00688280 (FUN_00688280)
     *
     * What it does:
     * Returns the `mNext` node lane from one intrusive list node.
     */
    static item_t* NextNode(item_t* node) noexcept
    {
      return node->mNext;
    }

    /**
     * Address: 0x00443250 (FUN_00443250)
     * Address: 0x00444140 (FUN_00444140)
     * Address: 0x00444150 (FUN_00444150)
     *
     * What it does:
     * Returns the same node pointer unchanged.
     */
    static item_t* IdentityNode(item_t* node) noexcept
    {
      return node;
    }

    /**
     * Address: 0x00443880 (FUN_00443880)
     *
     * What it does:
     * Advances one node-pointer cursor to `cursor->mNext`.
     */
    static item_t** AdvanceCursor(item_t** cursor) noexcept
    {
      *cursor = (*cursor)->mNext;
      return cursor;
    }

    /**
     * Address: 0x0047C560 (FUN_0047C560, typed-instantiation lane)
     *
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
     * Address: 0x00485720 (FUN_00485720, typed-instantiation lane)
     *
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

      /**
       * Address: 0x00443880 (FUN_00443880)
       *
       * What it does:
       * Advances node cursor to `mNext`.
       */
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

      /**
       * Address: 0x00443250 (FUN_00443250)
       * Address: 0x0063C0C0 (FUN_0063C0C0, typed-instantiation lane)
       *
       * What it does:
       * Initializes one iterator cursor from a raw node pointer.
       */
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
    /**
     * Address: 0x00443240 (FUN_00443240)
     * Address: 0x00485700 (FUN_00485700, typed-instantiation lane)
     * Address: 0x00485790 (FUN_00485790, typed-instantiation lane)
     *
     * What it does:
     * Builds node-iterator begin cursor from head `mNext`.
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

    /**
     * Address: 0x00485710 (FUN_00485710, typed-instantiation lane)
     * Address: 0x004857A0 (FUN_004857A0, typed-instantiation lane)
     *
     * What it does:
     * Builds node-iterator end cursor from the head sentinel.
     */
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
     * Move all nodes from this list head into pending and reset this head.
     * The destination head is unlinked/reset first.
     */
    void move_nodes_to(TDatList& pending) noexcept
    {
      pending.ListResetLinks();
      if (this->ListIsSingleton()) {
        return;
      }

      pending.mPrev = this->mPrev;
      pending.mNext = this->mNext;
      pending.mPrev->mNext = &pending;
      pending.mNext->mPrev = &pending;
      this->ListResetLinks();
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

    template <class Owner, class MemberNode, MemberNode Owner::* Member>
    /**
     * Address: 0x00442D90 (FUN_00442D90)
     * Address: 0x00442E00 (FUN_00442E00)
     * Address: 0x00442E70 (FUN_00442E70)
     * Address: 0x00442F00 (FUN_00442F00)
     * Address: 0x00443080 (FUN_00443080)
     * Address: 0x00443890 (FUN_00443890)
     * Address: 0x004438A0 (FUN_004438A0)
     * Address: 0x00485770 (FUN_00485770, offset+0x410 member-node lane)
     *
     * What it does:
     * Converts one intrusive-member pointer back to the owning object pointer.
     * The listed codegen lanes match offset-`0x04` member ownership recovery.
     */
    static Owner* owner_from_member(MemberNode* node) noexcept
    {
      static_assert(std::is_base_of_v<item_t, MemberNode>, "MemberNode must derive from TDatList item_t");
      if (!node) {
        return nullptr;
      }

      const auto* const memberPtr = &(reinterpret_cast<Owner const volatile*>(0)->*Member);
      const auto memberOffset = static_cast<std::ptrdiff_t>(reinterpret_cast<std::uintptr_t>(memberPtr));
      return reinterpret_cast<Owner*>(reinterpret_cast<char*>(node) - memberOffset);
    }

    template <class Owner, class MemberNode, MemberNode Owner::* Member>
    static const Owner* owner_from_member(const MemberNode* node) noexcept
    {
      static_assert(std::is_base_of_v<item_t, MemberNode>, "MemberNode must derive from TDatList item_t");
      if (!node) {
        return nullptr;
      }
      return owner_from_member<Owner, MemberNode, Member>(const_cast<MemberNode*>(node));
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
