#pragma once

#include <cstddef>
#include <cstdint>
#include <new>
#include <type_traits>
#include <utility>

namespace fa
{
  /**
   * Per-instance slab allocator where slabs are owned by the allocator instance itself.
   * Allocates T in slabs of SlabSize elements.
   */
  template <class T, std::size_t SlabSize = 32>
  class local_slab_allocator
  {
    struct FreeNode { FreeNode* next; };
    struct Slab { Slab* next; alignas(T) std::byte data[SlabSize * sizeof(T)]; };

    Slab* slabs_ = nullptr;
    FreeNode* free_list_ = nullptr;
    std::size_t total_slabs_ = 0;
    std::size_t active_allocations_ = 0;

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
    struct rebind { using other = local_slab_allocator<U, SlabSize>; };

    local_slab_allocator() = default;
    /*
    local_slab_allocator() : slabs_(nullptr), free_list_(nullptr), total_slabs_(0), active_allocations_(0) {}
    */


    // Fresh allocator instance on copy (standard allocator behavior)
    local_slab_allocator(const local_slab_allocator&) noexcept : local_slab_allocator() {}

    // Template constructor to rebind to different type (creates a fresh, independent pool)
    template <class U>
    local_slab_allocator(const local_slab_allocator<U, SlabSize>&) noexcept
      : local_slab_allocator()
    {}

    // Move transfers state
    local_slab_allocator(local_slab_allocator&& other) noexcept
      : slabs_(other.slabs_), free_list_(other.free_list_),
        total_slabs_(other.total_slabs_), active_allocations_(other.active_allocations_)
    {
      other.slabs_ = nullptr;
      other.free_list_ = nullptr;
      other.total_slabs_ = 0;
      other.active_allocations_ = 0;
    }

    local_slab_allocator& operator=(const local_slab_allocator&) noexcept { return *this; }
    
    local_slab_allocator& operator=(local_slab_allocator&& other) noexcept
    {
      if (this != &other) {
        purge();
        slabs_ = other.slabs_;
        free_list_ = other.free_list_;
        total_slabs_ = other.total_slabs_;
        active_allocations_ = other.active_allocations_;
        other.slabs_ = nullptr;
        other.free_list_ = nullptr;
        other.total_slabs_ = 0;
        other.active_allocations_ = 0;
      }
      return *this;
    }

    ~local_slab_allocator() { purge(); }

    [[nodiscard]] pointer allocate(size_type n)
    {
      if (n != 1) {
        return static_cast<pointer>(::operator new(n * sizeof(T)));
      }
      if (!free_list_) {
        Slab* slab = static_cast<Slab*>(::operator new(sizeof(Slab)));
        slab->next = slabs_;
        slabs_ = slab;
        ++total_slabs_;

        T* elements = reinterpret_cast<T*>(slab->data);
        for (std::size_t i = 0; i < SlabSize; ++i) {
          FreeNode* node = reinterpret_cast<FreeNode*>(&elements[i]);
          node->next = free_list_;
          free_list_ = node;
        }
      }
      FreeNode* node = free_list_;
      free_list_ = node->next;
      ++active_allocations_;
      return reinterpret_cast<pointer>(node);
    }

    void deallocate(pointer p, size_type n) noexcept
    {
      if (!p) return;
      if (n != 1) {
        ::operator delete(p);
        return;
      }
      FreeNode* node = reinterpret_cast<FreeNode*>(p);
      node->next = free_list_;
      free_list_ = node;
      --active_allocations_;
    }

    [[nodiscard]] std::size_t total_slabs() const noexcept { return total_slabs_; }
    [[nodiscard]] std::size_t active_allocations() const noexcept { return active_allocations_; }

    void purge() noexcept
    {
      while (slabs_) {
        Slab* next = slabs_->next;
        ::operator delete(slabs_);
        slabs_ = next;
      }
      free_list_ = nullptr;
      total_slabs_ = 0;
      active_allocations_ = 0;
    }

    friend void swap(local_slab_allocator& lhs, local_slab_allocator& rhs) noexcept
    {
      std::swap(lhs.slabs_, rhs.slabs_);
      std::swap(lhs.free_list_, rhs.free_list_);
      std::swap(lhs.total_slabs_, rhs.total_slabs_);
      std::swap(lhs.active_allocations_, rhs.active_allocations_);
    }

    template <class U, std::size_t S>
    friend bool operator==(const local_slab_allocator&, const local_slab_allocator<U, S>&) noexcept { return false; }
    template <class U, std::size_t S>
    friend bool operator!=(const local_slab_allocator&, const local_slab_allocator<U, S>&) noexcept { return true; }
  };

#if defined(_M_X64) || defined(__x86_64__)
  template <class T>
  using default_rb_allocator = local_slab_allocator<T, 32>;
#else
  template <class T>
  using default_rb_allocator = std::allocator<T>;
#endif

} // namespace fa
