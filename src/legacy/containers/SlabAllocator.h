#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <type_traits>
#include <utility>

namespace fa
{
  /**
   * Engine addition: whether 64-bit trees take their nodes from per-tree slabs (`local_slab_allocator`).
   * `/treeslabs 0` on the command line or FAF_TREESLABS=0 turns it off; read once, at the first tree.
   * Each allocator keeps the value it was constructed with, so a tree never mixes slab and heap nodes.
   */
  [[nodiscard]] bool TreeSlabsEnabled() noexcept;

  /**
   * Per-tree node allocator: nodes come from slabs of `SlabSize` nodes that this allocator owns, and a
   * freed node goes to this allocator's free list for the next insert into the same tree. A tree's nodes
   * therefore sit close together in memory, which saves cache misses on large trees.
   *
   * The first single-object allocation (the tree's head sentinel) comes from the heap, so an empty tree
   * costs what it costs with `std::allocator`. Array allocations (n != 1) always go to the heap.
   *
   * Copies get a fresh, empty pool, and two allocators compare equal only when they are the same object:
   * a node can only be freed by the allocator that handed it out. `rb_tree` moves and swaps the allocator
   * together with its nodes (propagate on move and swap) and never assumes copies are equal.
   */
  template <class T, std::size_t SlabSize = 32>
  class local_slab_allocator
  {
    static_assert(SlabSize > 0);

    struct FreeNode
    {
      FreeNode* next;
    };

    struct Slab
    {
      Slab* next;
      alignas(T) std::byte data[SlabSize * sizeof(T)];
    };

    static_assert(sizeof(T) >= sizeof(FreeNode), "a free node is stored in the node's own memory");

  public:
    using value_type = T;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using pointer = T*;
    using const_pointer = const T*;
    using reference = T&;
    using const_reference = const T&;

    using propagate_on_container_copy_assignment = std::false_type;
    using propagate_on_container_move_assignment = std::true_type;
    using propagate_on_container_swap = std::true_type;
    using is_always_equal = std::false_type;

    template <class U>
    struct rebind
    {
      using other = local_slab_allocator<U, SlabSize>;
    };

    local_slab_allocator() noexcept
      : slabsOn_(TreeSlabsEnabled())
    {}

    local_slab_allocator(
      const local_slab_allocator&
    ) noexcept
      : local_slab_allocator()
    {}

    template <class U>
    local_slab_allocator(
      const local_slab_allocator<U, SlabSize>&
    ) noexcept
      : local_slab_allocator()
    {}

    local_slab_allocator(
      local_slab_allocator&& other
    ) noexcept
    {
      take(other);
    }

    local_slab_allocator& operator=(
      const local_slab_allocator&
    ) noexcept
    {
      return *this;
    }

    local_slab_allocator& operator=(
      local_slab_allocator&& other
    ) noexcept
    {
      if (this != &other) {
        purge();
        take(other);
      }
      return *this;
    }

    ~local_slab_allocator()
    {
      purge();
    }

    [[nodiscard]] pointer allocate(
      const size_type n
    )
    {
      if (n != 1 || !slabsOn_) {
        return static_cast<pointer>(::operator new(n * sizeof(T)));
      }
      if (head_ == nullptr && slabs_ == nullptr) {
        head_ = static_cast<pointer>(::operator new(sizeof(T)));
        ++live_;
        return head_;
      }
      if (freeList_ == nullptr) {
        auto* const slab = static_cast<Slab*>(::operator new(sizeof(Slab)));
        slab->next = slabs_;
        slabs_ = slab;
        T* const elements = reinterpret_cast<T*>(slab->data);
        for (std::size_t i = SlabSize; i-- > 0;) {
          freeList_ = ::new (static_cast<void*>(&elements[i])) FreeNode{freeList_};
        }
      }
      FreeNode* const node = freeList_;
      freeList_ = node->next;
      ++live_;
      return reinterpret_cast<pointer>(node);
    }

    void deallocate(
      const pointer p,
      const size_type n
    ) noexcept
    {
      if (p == nullptr) {
        return;
      }
      if (n != 1 || !slabsOn_) {
        ::operator delete(p);
        return;
      }
      --live_;
      if (p == head_) {
        ::operator delete(p);
        head_ = nullptr;
        return;
      }
      freeList_ = ::new (static_cast<void*>(p)) FreeNode{freeList_};
    }

    /** Slabs this allocator holds (walks the list; for tests). */
    [[nodiscard]] std::size_t total_slabs() const noexcept
    {
      std::size_t count = 0;
      for (const Slab* slab = slabs_; slab != nullptr; slab = slab->next) {
        ++count;
      }
      return count;
    }

    /** Single objects handed out and not yet freed, the head included. */
    [[nodiscard]] std::size_t active_allocations() const noexcept
    {
      return live_;
    }

    [[nodiscard]] bool slabs_on() const noexcept
    {
      return slabsOn_;
    }

    void purge() noexcept
    {
      while (slabs_ != nullptr) {
        Slab* const next = slabs_->next;
        ::operator delete(slabs_);
        slabs_ = next;
      }
      if (head_ != nullptr) {
        ::operator delete(head_);
        head_ = nullptr;
      }
      freeList_ = nullptr;
      live_ = 0;
    }

    friend void swap(
      local_slab_allocator& lhs,
      local_slab_allocator& rhs
    ) noexcept
    {
      local_slab_allocator tmp(std::move(lhs));
      lhs = std::move(rhs);
      rhs = std::move(tmp);
    }

    template <class U, std::size_t S>
    friend bool operator==(
      const local_slab_allocator& lhs,
      const local_slab_allocator<U, S>& rhs
    ) noexcept
    {
      return static_cast<const void*>(&lhs) == static_cast<const void*>(&rhs);
    }

    template <class U, std::size_t S>
    friend bool operator!=(
      const local_slab_allocator& lhs,
      const local_slab_allocator<U, S>& rhs
    ) noexcept
    {
      return !(lhs == rhs);
    }

  private:
    void take(
      local_slab_allocator& other
    ) noexcept
    {
      slabs_ = std::exchange(other.slabs_, nullptr);
      freeList_ = std::exchange(other.freeList_, nullptr);
      head_ = std::exchange(other.head_, nullptr);
      live_ = std::exchange(other.live_, 0u);
      slabsOn_ = other.slabsOn_;
    }

    Slab* slabs_ = nullptr;
    FreeNode* freeList_ = nullptr;
    pointer head_ = nullptr;
    std::uint32_t live_ = 0;
    bool slabsOn_ = true;
  };

#if FAFRE_ARCH_64BIT
  /** 64-bit trees use per-tree slabs (switch: `TreeSlabsEnabled`). */
  template <class T>
  using default_rb_allocator = local_slab_allocator<T, 32>;
#else
  /** 32-bit trees keep the retail allocator and layout. */
  template <class T>
  using default_rb_allocator = std::allocator<T>;
#endif

} // namespace fa
