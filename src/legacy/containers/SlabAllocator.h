#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <new>
#include <type_traits>
#include <unordered_map>
#include <utility>

namespace fa
{
  namespace detail
  {
    class local_pool_state
    {
      struct FreeNode
      {
        FreeNode* next;
      };

      struct SlabHeader
      {
        SlabHeader* next;
      };

      struct PoolForSize
      {
        SlabHeader* slabs = nullptr;
        FreeNode* free_list = nullptr;
        std::size_t total_slabs = 0;
        std::size_t active_allocations = 0;

        ~PoolForSize()
        {
          while (slabs) {
            SlabHeader* next = slabs->next;
            ::operator delete(slabs);
            slabs = next;
          }
        }
      };

      std::mutex mutex_;
      std::unordered_map<std::size_t, PoolForSize> pools_;

    public:
      local_pool_state() = default;
      ~local_pool_state() = default;
      local_pool_state(const local_pool_state&) = delete;
      local_pool_state& operator=(const local_pool_state&) = delete;

      void* allocate(
        std::size_t elem_size,
        std::size_t slab_count,
        std::size_t elem_align = alignof(std::max_align_t)
      )
      {
        std::lock_guard<std::mutex> lock(mutex_);
        const std::size_t min_size = sizeof(FreeNode);
        std::size_t slot_size = elem_size < min_size ? min_size : elem_size;
        if (elem_align > 0) {
          slot_size = (slot_size + elem_align - 1) & ~(elem_align - 1);
        }
        auto& pool = pools_[slot_size];
        if (!pool.free_list) {
          std::size_t header_size = sizeof(SlabHeader);
          if (elem_align > 0) {
            header_size = (header_size + elem_align - 1) & ~(elem_align - 1);
          }
          const std::size_t slab_bytes = header_size + slab_count * slot_size;
          void* raw = ::operator new(slab_bytes);
          SlabHeader* slab = static_cast<SlabHeader*>(raw);
          slab->next = pool.slabs;
          pool.slabs = slab;
          ++pool.total_slabs;

          char* slots_start = reinterpret_cast<char*>(raw) + header_size;
          for (std::size_t i = 0; i < slab_count; ++i) {
            FreeNode* node = reinterpret_cast<FreeNode*>(slots_start + i * slot_size);
            node->next = pool.free_list;
            pool.free_list = node;
          }
        }
        FreeNode* node = pool.free_list;
        pool.free_list = node->next;
        ++pool.active_allocations;
        return node;
      }

      void deallocate(
        void* ptr,
        std::size_t elem_size,
        std::size_t elem_align = alignof(std::max_align_t)
      ) noexcept
      {
        if (!ptr) {
          return;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        const std::size_t min_size = sizeof(FreeNode);
        std::size_t slot_size = elem_size < min_size ? min_size : elem_size;
        if (elem_align > 0) {
          slot_size = (slot_size + elem_align - 1) & ~(elem_align - 1);
        }
        auto it = pools_.find(slot_size);
        if (it != pools_.end()) {
          FreeNode* node = reinterpret_cast<FreeNode*>(ptr);
          node->next = it->second.free_list;
          it->second.free_list = node;
          if (it->second.active_allocations > 0) {
            --it->second.active_allocations;
          }
        }
      }

      [[nodiscard]] std::size_t total_slabs() noexcept
      {
        std::lock_guard<std::mutex> lock(mutex_);
        std::size_t total = 0;
        for (const auto& [_, pool] : pools_) {
          total += pool.total_slabs;
        }
        return total;
      }

      [[nodiscard]] std::size_t active_allocations() noexcept
      {
        std::lock_guard<std::mutex> lock(mutex_);
        std::size_t total = 0;
        for (const auto& [_, pool] : pools_) {
          total += pool.active_allocations;
        }
        return total;
      }

      void purge() noexcept
      {
        std::lock_guard<std::mutex> lock(mutex_);
        pools_.clear();
      }
    };
  } // namespace detail

  /**
   * Per-instance slab allocator where slabs are owned by the allocator instance (and shared among rebound copies).
   */
  template <class T, std::size_t SlabSize = 32>
  class local_slab_allocator
  {
    std::shared_ptr<detail::local_pool_state> state_;

  public:
    using value_type = T;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using pointer = T*;
    using const_pointer = const T*;
    using reference = T&;
    using const_reference = const T&;

    using propagate_on_container_copy_assignment = std::true_type;
    using propagate_on_container_move_assignment = std::true_type;
    using propagate_on_container_swap = std::true_type;
    using is_always_equal = std::false_type;

    template <class U>
    struct rebind
    {
      using other = local_slab_allocator<U, SlabSize>;
    };

    local_slab_allocator()
      : state_(std::make_shared<detail::local_pool_state>())
    {}

    local_slab_allocator(const local_slab_allocator&) noexcept = default;
    local_slab_allocator& operator=(const local_slab_allocator&) noexcept = default;
    local_slab_allocator(local_slab_allocator&&) noexcept = default;
    local_slab_allocator& operator=(local_slab_allocator&&) noexcept = default;

    template <class U>
    local_slab_allocator(const local_slab_allocator<U, SlabSize>& other) noexcept
      : state_(other.state_)
    {}

    template <class U>
    local_slab_allocator(local_slab_allocator<U, SlabSize>&& other) noexcept
      : state_(std::move(other.state_))
    {}

    template <class U>
    local_slab_allocator& operator=(const local_slab_allocator<U, SlabSize>& other) noexcept
    {
      state_ = other.state_;
      return *this;
    }

    template <class U>
    local_slab_allocator& operator=(local_slab_allocator<U, SlabSize>&& other) noexcept
    {
      state_ = std::move(other.state_);
      return *this;
    }

    ~local_slab_allocator() = default;

    [[nodiscard]] pointer allocate(size_type n)
    {
      if (n != 1) {
        return static_cast<pointer>(::operator new(n * sizeof(T)));
      }
      if (!state_) {
        state_ = std::make_shared<detail::local_pool_state>();
      }
      return static_cast<pointer>(state_->allocate(sizeof(T), SlabSize, alignof(T)));
    }

    void deallocate(pointer p, size_type n) noexcept
    {
      if (!p) {
        return;
      }
      if (n != 1) {
        ::operator delete(p);
        return;
      }
      if (state_) {
        state_->deallocate(p, sizeof(T), alignof(T));
      }
    }

    [[nodiscard]] std::size_t total_slabs() const noexcept
    {
      return state_ ? state_->total_slabs() : 0;
    }

    [[nodiscard]] std::size_t active_allocations() const noexcept
    {
      return state_ ? state_->active_allocations() : 0;
    }

    void purge() noexcept
    {
      if (state_) {
        state_->purge();
      }
    }

    template <class U, std::size_t S>
    friend class local_slab_allocator;

    template <class U, std::size_t S>
    friend bool operator==(const local_slab_allocator& lhs, const local_slab_allocator<U, S>& rhs) noexcept
    {
      return lhs.state_ == rhs.state_;
    }

    template <class U, std::size_t S>
    friend bool operator!=(const local_slab_allocator& lhs, const local_slab_allocator<U, S>& rhs) noexcept
    {
      return lhs.state_ != rhs.state_;
    }

    friend void swap(local_slab_allocator& lhs, local_slab_allocator& rhs) noexcept
    {
      std::swap(lhs.state_, rhs.state_);
    }
  };

  /**
   * Default tree allocator policy:
   * - x86: std::allocator<T> (allocates one item at a time via new/delete, preserves 12-byte retail layout via EBO)
   * - x64: local_slab_allocator<T, 32> (allocates in slabs of 32 items with per-container local slab pool)
   */
#if defined(_M_X64) || defined(__x86_64__)
  template <class T>
  using default_rb_allocator = local_slab_allocator<T, 32>;
#else
  template <class T>
  using default_rb_allocator = std::allocator<T>;
#endif

} // namespace fa
