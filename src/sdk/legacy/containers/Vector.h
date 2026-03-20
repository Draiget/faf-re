#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <type_traits>
#include <vector>

#ifndef MSVC8_VECTOR_DISABLE_FREE
#define MSVC8_VECTOR_DISABLE_FREE 0
#endif

namespace msvc8
{
#ifndef MSVC8_CONTAINER_PROXY_DEFINED
#define MSVC8_CONTAINER_PROXY_DEFINED 1
    struct _Container_proxy
    {
        void* _Myfirstiter;
    };
#endif

    // Base that holds the proxy pointer (debug iterator support footprint)
    struct _Container_base
    {
        _Container_proxy* _Myproxy;

        _Container_base()
            : _Myproxy(0)
        {
        }
    };

    /**
     * MSVC8-compatible vector with fixed ABI (16 bytes).
     * Only pointer fields are stored: proxy (opaque), begin, end, capacity-end.
     * Provides a minimal modern API: reserve/resize/push_back/emplace_back/clear,
     * copy/move, and conversions to/from std::vector<T>.
     *
     * WARNING about ownership: this implementation assumes it owns the memory it allocates.
     * If you map this struct over foreign memory from the original binary, you MUST NOT let
     * it destroy/deallocate that memory. See MSVC8_VECTOR_DISABLE_FREE macro above.
     *
     * Why do we have this `Dbg` in Release? This is common default practice of VS2005,
     * they have `_SECURE_SCL=1` defined in Release, so we can see that debug iterator that
     * aren't used by anything really and just sitting alone there.
     */
    template <class T>
    class vector
	{
        using iterator = T*;
        using const_iterator = const T*;

        void* myProxy_; // +0x0  (opaque _Container_proxy*)
        T* first_;      // +0x4
        T* last_;       // +0x8
        T* end_;        // +0xC

    public:
        /**
         * Default constructor: empty
         */
        vector() noexcept :
    		myProxy_(nullptr),
    		first_(nullptr),
    		last_(nullptr),
    		end_(nullptr)
    	{
        }

        /**
         * Construct with count default-inserted elements
         */
        explicit vector(std::size_t count) : vector() {
            if (count) {
                reserve(count);
                uninit_value_construct_n(first_, count);
                last_ = first_ + count;
            }
        }

        /**
         * Construct from std::vector (copy)
         */
        explicit vector(const std::vector<T>& src) : vector() {
            if (!src.empty()) {
                reserve(src.size());
                uninit_copy_n(src.data(), src.size(), first_);
                last_ = first_ + src.size();
            }
        }

        /**
         * Copy constructor (deep copy)
         */
        vector(const vector& other) : vector() {
            const std::size_t n = other.size();
            if (n) {
                reserve(n);
                uninit_copy_n(other.first_, n, first_);
                last_ = first_ + n;
            }
        }

        /**
         * Move constructor (steals pointers)
         */
        vector(vector&& other) noexcept :
    		myProxy_(other.myProxy_),
			first_(other.first_),
			last_(other.last_),
			end_(other.end_)
    	{
            other.myProxy_ = nullptr;
            other.first_ = other.last_ = other.end_ = nullptr;
        }

        /**
         * Destructor: destroy elements and free storage if allowed
         */
        ~vector() {
            destroy_all();
            deallocate_all();
        }

        /**
         * Copy assignment (strong exception safety)
         */
        vector& operator=(const vector& rhs) {
            if (this == &rhs) return *this;
            assign(rhs.first_, rhs.size());
            return *this;
        }

        /**
         * Move assignment (steals pointers)
         */
        vector& operator=(vector&& rhs) noexcept {
            if (this == &rhs) return *this;
            destroy_all();
            deallocate_all();
            myProxy_ = rhs.myProxy_;
            first_ = rhs.first_;
            last_ = rhs.last_;
            end_ = rhs.end_;
            rhs.myProxy_ = nullptr;
            rhs.first_ = rhs.last_ = rhs.end_ = nullptr;
            return *this;
        }

        T* begin() const noexcept {
	        return first_;
        }
        T* end()   const noexcept {
	        return last_;
        }
        [[nodiscard]] bool empty() const noexcept {
	        return first_ == last_;
        }
        [[nodiscard]] std::size_t size() const noexcept {
	        return static_cast<std::size_t>(last_ - first_);
        }
        [[nodiscard]] std::size_t capacity() const noexcept {
	        return static_cast<std::size_t>(end_ - first_);
        }
        T& operator[](std::size_t i) const noexcept {
	        return first_[i];
        }
        T* data() const noexcept {
	        return first_;
        }

        /**
         * Front element (no check)
         */
        T& front() const noexcept { return *first_; }

        /**
         * Back element (no check)
         */
        T& back() const noexcept { return *(last_ - 1); }

        /**
         * Reserve storage for at least new_cap elements
         */
        void reserve(const std::size_t newCap) {
            if (newCap <= capacity()) {
                return;
            }
            reallocate_to(newCap);
        }

        /**
         * Resize to new_size; value-initialize or fill with 'value' when growing
         */
        void resize(std::size_t newSize) {
            const std::size_t cur = size();
            if (newSize <= cur) {
                destroy_n(first_ + newSize, cur - newSize);
                last_ = first_ + newSize;
                return;
            }
            const std::size_t add = newSize - cur;
            if (newSize > capacity())
                reallocate_to(recommended_capacity(newSize));
            uninit_value_construct_n(last_, add);
            last_ += add;
        }

        /**
         * Resize with fill value for new elements
         */
        void resize(std::size_t newSize, const T& value) {
            const std::size_t cur = size();
            if (newSize <= cur) {
                destroy_n(first_ + newSize, cur - newSize);
                last_ = first_ + newSize;
                return;
            }
            const std::size_t add = newSize - cur;
            if (newSize > capacity())
                reallocate_to(recommended_capacity(newSize));
            uninit_fill_n(last_, add, value);
            last_ += add;
        }

        /**
         * Clear all elements; keep capacity
         */
        void clear() noexcept {
            destroy_all();
            last_ = first_;
        }

        /**
         * Push by const&
         */
        void push_back(const T& value) {
            ensure_grow_for(1);
            new (static_cast<void*>(last_)) T(value);
            ++last_;
        }

        /** Push by rvalue */
        void push_back(T&& value) {
            ensure_grow_for(1);
            ::new (static_cast<void*>(last_)) T(std::move(value));
            ++last_;
        }

        /**
         * Emplace in-place
         */
        template <class... Args>
        T& emplace_back(Args&&... args) {
            ensure_grow_for(1);
            ::new (static_cast<void*>(last_)) T(std::forward<Args>(args)...);
            return *(last_++);
        }

        /**
         * Pop last (no check)
         */
        void pop_back() noexcept {
            --last_;
            last_->~T();
        }

        /**
         * Assign from raw pointer + count (deep copy)
         */
        void assign(const T* src, std::size_t n) {
            if (n <= size()) {
                // Overwrite existing, destroy rest
                copy_or_move_assign(first_, src, n);
                destroy_n(first_ + n, size() - n);
                last_ = first_ + n;
            } else {
                // Grow if needed, overwrite existing, uninitialized-copy tail
                if (n > capacity())
                    reallocate_to(n);
                const std::size_t cur = size();
                copy_or_move_assign(first_, src, cur);
                uninit_copy_n(src + cur, n - cur, first_ + cur);
                last_ = first_ + n;
            }
        }

        /**
         * Assign from std::vector (deep copy)
         */
        void assign(const std::vector<T>& src) {
            assign(src.data(), src.size());
        }

        /**
         * Convert to std::vector<T> (copy)
         */
        [[nodiscard]]
    	std::vector<T> to_std() const {
            std::vector<T> out;
            out.reserve(size());
            out.insert(out.end(), first_, last_);
            return out;
        }

        /**
         * Replace contents from std::vector<T> (copy)
         */
        void from_std(const std::vector<T>& src) {
            assign(src);
        }

        /**
         * Erase one element at position `pos`.
         * Shifts the tail left by 1, destroys the last duplicated slot,
         * and returns iterator to the position of erased element.
         */
        iterator erase(iterator pos) {
            assert(pos >= first_ && pos < last_);
            iterator next = pos + 1;
            const std::size_t tail = static_cast<std::size_t>(last_ - next);
            if (tail) {
                if constexpr (std::is_trivially_copyable_v<T>) {
                    std::memmove(pos, next, tail * sizeof(T));
                } else {
                    for (std::size_t i = 0; i < tail; ++i)
                        pos[i] = std::move(next[i]);
                }
            }
            --last_;
            if constexpr (!std::is_trivially_destructible_v<T>) {
                last_->~T();
            }
            return pos;
        }

        /**
         * Erase a range [first,last). Returns iterator to the position that
         * now contains the element that followed the last erased element.
         */
        iterator erase(iterator first, iterator last) {
            assert(first_ <= first && first <= last && last <= last_);
            const std::size_t count = static_cast<std::size_t>(last - first);
            if (count == 0) return first;

            const std::size_t tail = static_cast<std::size_t>(last_ - last);
            if (tail) {
                if constexpr (std::is_trivially_copyable_v<T>) {
                    std::memmove(first, last, tail * sizeof(T));
                } else {
                    for (std::size_t i = 0; i < tail; ++i)
                        first[i] = std::move(last[i]);
                }
            }
            if constexpr (!std::is_trivially_destructible_v<T>) {
                destroy_range(last_ - count, last_);
            }
            last_ -= count;
            return first;
        }

    private:
        /**
         * Destroy [first,last)
         */
        static void destroy_range(T* first, T* last) noexcept {
            if constexpr (!std::is_trivially_destructible_v<T>) {
                for (; first != last; ++first) first->~T();
            } else {
                (void)first; (void)last;
            }
        }

        /**
         * Destroy N elements starting at p
         */
        static void destroy_n(T* p, std::size_t n) noexcept {
            destroy_range(p, p + n);
        }

        /**
         * Uninitialized copy N from src to dst
         */
        static void uninit_copy_n(const T* src, const std::size_t n, T* dst) {
            if constexpr (std::is_trivially_copyable_v<T>) {
                std::memcpy(dst, src, n * sizeof(T));
            } else {
                std::size_t i = 0;
                try {
                    for (; i < n; ++i) ::new (static_cast<void*>(dst + i)) T(src[i]);
                } catch (...) {
                    destroy_n(dst, i);
                    throw;
                }
            }
        }

        /**
         * Uninitialized fill N with value starting at dst
         */
        static void uninit_fill_n(T* dst, const std::size_t n, const T& value) {
            std::size_t i = 0;
            try {
                for (; i < n; ++i) ::new (static_cast<void*>(dst + i)) T(value);
            } catch (...) {
                destroy_n(dst, i);
                throw;
            }
        }

        /**
         * Uninitialized value-initialize N elements at dst
         */
        static void uninit_value_construct_n(T* dst, const std::size_t n) {
            std::size_t i = 0;
            try {
                for (; i < n; ++i) ::new (static_cast<void*>(dst + i)) T();
            } catch (...) {
                destroy_n(dst, i);
                throw;
            }
        }

        /**
         * Assign n elements from src to dst (dst already constructed)
         */
        static void copy_or_move_assign(T* dst, const T* src, const std::size_t n) {
            if constexpr (std::is_trivially_copy_assignable_v<T>) {
                std::memcpy(dst, src, n * sizeof(T));
            } else {
                for (std::size_t i = 0; i < n; ++i) dst[i] = src[i];
            }
        }

        /**
         * Growth policy: double, but at least new_cap
         */
        [[nodiscard]]
    	static std::size_t recommended_capacity(const std::size_t need) {
		    const std::size_t cur = need > 0 ? need : 1;
            // Try to double from current capacity if possible
            if (need > 0) {
                // Overflow-safe doubling
                const std::size_t doubled = (need > (static_cast<std::size_t>(-1) / 2)) ? need : need * 2;
                return doubled;
            }
            return cur;
        }

        /**
         * Ensure capacity for 'add' more elements
         */
        void ensure_grow_for(const std::size_t add) {
            const std::size_t newSize = size() + add;
            if (newSize > capacity()) {
                const std::size_t target = recommended_capacity(newSize);
                reallocate_to(target);
            }
        }

        /**
         * Destroy all elements
         */
        void destroy_all() noexcept {
            if (first_) destroy_range(first_, last_);
            last_ = first_;
        }

        /**
         * Deallocate buffer if owned/allowed
         */
        void deallocate_all() noexcept {
#if MSVC8_VECTOR_DISABLE_FREE
            first_ = last_ = end_ = nullptr;
#else
            if (first_) {
                ::operator delete(static_cast<void*>(first_));
                first_ = last_ = end_ = nullptr;
            }
#endif
        }

        /**
         * Reallocate to exactly new_cap, preserving elements
         */
        void reallocate_to(std::size_t newCap) {
            assert(newCap >= size());
            T* newBuf = static_cast<T*>(::operator new(sizeof(T) * newCap));
            T* newFirst = newBuf;
            T* newLast;
            const std::size_t n = size();

            // Move or copy existing elements
            if constexpr (std::is_nothrow_move_constructible_v<T> || !std::is_copy_constructible_v<T>) {
                // Prefer move if nothrow or copy is unavailable
                std::size_t i = 0;
                try {
                    for (; i < n; ++i) {
                        ::new (static_cast<void*>(newFirst + i)) T(std::move(first_[i]));
                    }
                    newLast = newFirst + n;
                } catch (...) {
                    destroy_n(newFirst, i);
                    ::operator delete(static_cast<void*>(newBuf));
                    throw;
                }
            } else if constexpr (std::is_trivially_copyable_v<T>) {
                std::memcpy(newFirst, first_, n * sizeof(T));
                newLast = newFirst + n;
            } else {
                std::size_t i = 0;
                try {
                    for (; i < n; ++i) {
                        ::new (static_cast<void*>(newFirst + i)) T(first_[i]);
                    }
                    newLast = newFirst + n;
                } catch (...) {
                    destroy_n(newFirst, i);
                    ::operator delete(static_cast<void*>(newBuf));
                    throw;
                }
            }

            // Destroy old elements and free old buffer
            destroy_all(); // destroys moved-from values too (OK)
#if MSVC8_VECTOR_DISABLE_FREE
            // If freeing disabled, just forget the old buffer
#else
            if (first_) {
                ::operator delete(static_cast<void*>(first_));
            }
#endif

            // Install new buffer
            first_ = newFirst;
            last_ = newLast;
            end_ = newFirst + newCap;
        }
    };
    static_assert(sizeof(vector<int>) == 16, "msvc8::set must be 16 bytes on x86");

    /**
	 * Small-vector with inline storage and heap fallback (non-owning SDK view).
	 *
	 * Layout:
	 *   +0x00: T* first_          // begin
	 *   +0x04: T* last_           // one past last
	 *   +0x08: T* end_            // end of storage (inline or heap)
	 *   +0x0C: T* _InlineMirror   // points to &_Inline[0] (debug/mirror)
	 *   +0x10: T  _Inline[N]      // inline storage (N elements)
	 *
	 * This matches engine containers that keep a small inline buffer and switch
	 * to heap when overflowed. The triad always reflects the active storage.
	 *
	 * NOTE:
	 *  - This is a non-owning view over already-laid-out memory inside engine objects.
	 *  - Safe to use for reads/iteration; do not mutate unless you fully control engine logic.
	 */
    template <class T, std::size_t N>
    struct inline_vector {
        T* first_;         // 0x00
        T* last_;          // 0x04
        T* end_;           // 0x08
        T* _InlineMirror;  // 0x0C (usually == &_Inline[0])
        T   _Inline[N];     // 0x10 .. 0x10 + N*sizeof(T)

        // --- std-like API (read-only friendly) ---
        T* begin() const noexcept { return first_; }
        T* end()   const noexcept { return last_; }
        [[nodiscard]] bool empty() const noexcept { return first_ == last_; }
        [[nodiscard]] std::size_t size() const noexcept { return static_cast<std::size_t>(last_ - first_); }
        [[nodiscard]] std::size_t capacity() const noexcept { return static_cast<std::size_t>(end_ - first_); }
        T& operator[](std::size_t i) const noexcept { return first_[i]; }
        T* data() const noexcept { return first_; }

        // Diagnostics helpers
        [[nodiscard]] T* inline_begin() const noexcept { return const_cast<T*>(&_Inline[0]); }
        [[nodiscard]] T* inlineend_()   const noexcept { return const_cast<T*>(&_Inline[0]) + N; }
        [[nodiscard]] static std::size_t inline_capacity() noexcept { return N; }
        [[nodiscard]] bool using_inline() const noexcept {
            return first_ >= inline_begin() && first_ <= inlineend_();
        }
    };

    template <class T, class Alloc = std::allocator<T> >
    class list : public _Container_base
    {
    public:
        typedef T                value_type;
        typedef Alloc            allocator_type;
        typedef std::size_t      size_type;
        typedef std::ptrdiff_t   difference_type;
        typedef T* pointer;
        typedef const T* const_pointer;
        typedef T& reference;
        typedef const T& const_reference;

    private:
        struct _Node;
        struct _Node_base
        {
            _Node_base* _Next;
            _Node_base* _Prev;
        };

        struct _Node : _Node_base
        {
            value_type _Value;

            _Node()
                : _Node_base()
                , _Value()
            {
                this->_Next = this;
                this->_Prev = this;
            }

            explicit _Node(const value_type& v)
                : _Node_base()
                , _Value(v)
            {
                this->_Next = this;
                this->_Prev = this;
            }
        };

        typedef typename std::allocator_traits<Alloc>::template rebind_alloc<_Node> _Node_alloc_type;
        typedef _Node_base* _Nodeptr;

        _Nodeptr  _Myhead;   // offset +4 from base
        size_type _Mysize;   // offset +8 from base

    public:
        class iterator
        {
            friend class list;
            _Nodeptr _Ptr;

            explicit iterator(_Nodeptr p)
                : _Ptr(p)
            {
            }

        public:
            typedef std::bidirectional_iterator_tag iterator_category;
            typedef value_type        value_type;
            typedef difference_type   difference_type;
            typedef pointer           pointer;
            typedef reference         reference;

            iterator()
                : _Ptr(0)
            {
            }

            reference operator*() const
            {
                return static_cast<_Node*>(_Ptr)->_Value;
            }

            pointer operator->() const
            {
                return &static_cast<_Node*>(_Ptr)->_Value;
            }

            iterator& operator++()
            {
                _Ptr = _Ptr->_Next;
                return *this;
            }

            iterator operator++(int)
            {
                iterator tmp(*this);
                ++(*this);
                return tmp;
            }

            iterator& operator--()
            {
                _Ptr = _Ptr->_Prev;
                return *this;
            }

            iterator operator--(int)
            {
                iterator tmp(*this);
                --(*this);
                return tmp;
            }

            bool operator==(const iterator& other) const
            {
                return _Ptr == other._Ptr;
            }

            bool operator!=(const iterator& other) const
            {
                return _Ptr != other._Ptr;
            }
        };

        class const_iterator
        {
            friend class list;
            _Nodeptr _Ptr;

            explicit const_iterator(_Nodeptr p)
                : _Ptr(p)
            {
            }

        public:
            typedef std::bidirectional_iterator_tag iterator_category;
            typedef value_type        value_type;
            typedef difference_type   difference_type;
            typedef const_pointer     pointer;
            typedef const_reference   reference;

            const_iterator()
                : _Ptr(0)
            {
            }

            const_iterator(const iterator& it)
                : _Ptr(it._Ptr)
            {
            }

            reference operator*() const
            {
                return static_cast<_Node*>(_Ptr)->_Value;
            }

            pointer operator->() const
            {
                return &static_cast<_Node*>(_Ptr)->_Value;
            }

            const_iterator& operator++()
            {
                _Ptr = _Ptr->_Next;
                return *this;
            }

            const_iterator operator++(int)
            {
                const_iterator tmp(*this);
                ++(*this);
                return tmp;
            }

            const_iterator& operator--()
            {
                _Ptr = _Ptr->_Prev;
                return *this;
            }

            const_iterator operator--(int)
            {
                const_iterator tmp(*this);
                --(*this);
                return tmp;
            }

            bool operator==(const const_iterator& other) const
            {
                return _Ptr == other._Ptr;
            }

            bool operator!=(const const_iterator& other) const
            {
                return _Ptr != other._Ptr;
            }
        };

        typedef std::reverse_iterator<iterator>       reverse_iterator;
        typedef std::reverse_iterator<const_iterator> const_reverse_iterator;

        list()
            : _Myhead(0)
            , _Mysize(0)
        {
            _Init();
        }

        explicit list(const allocator_type&)
            : _Myhead(0)
            , _Mysize(0)
        {
            _Init();
        }

        ~list()
        {
            _Tidy();
            _Free_head();
            _Free_proxy();
        }

        bool empty() const
        {
            return _Mysize == 0;
        }

        size_type size() const
        {
            return _Mysize;
        }

        iterator begin()
        {
            return iterator(_Myhead->_Next);
        }

        const_iterator begin() const
        {
            return const_iterator(_Myhead->_Next);
        }

        iterator end()
        {
            return iterator(_Myhead);
        }

        const_iterator end() const
        {
            return const_iterator(_Myhead);
        }

        reverse_iterator rbegin()
        {
            return reverse_iterator(end());
        }

        const_reverse_iterator rbegin() const
        {
            return const_reverse_iterator(end());
        }

        reverse_iterator rend()
        {
            return reverse_iterator(begin());
        }

        const_reverse_iterator rend() const
        {
            return const_reverse_iterator(begin());
        }

        reference front()
        {
            return *begin();
        }

        const_reference front() const
        {
            return *begin();
        }

        reference back()
        {
            iterator it = end();
            --it;
            return *it;
        }

        const_reference back() const
        {
            const_iterator it = end();
            --it;
            return *it;
        }

        void clear()
        {
            _Tidy();
        }

        void push_back(const value_type& v)
        {
            insert(end(), v);
        }

        void push_front(const value_type& v)
        {
            insert(begin(), v);
        }

        iterator insert(const_iterator pos, const value_type& v)
        {
            _Node_alloc_type al;
            _Node* node = al.allocate(1);
            new (node) _Node(v);

            _Nodeptr where = pos._Ptr;
            _Nodeptr prev = where->_Prev;

            node->_Next = where;
            node->_Prev = prev;
            prev->_Next = node;
            where->_Prev = node;

            ++_Mysize;
            return iterator(node);
        }

        iterator erase(const_iterator pos)
        {
            _Nodeptr node = pos._Ptr;
            _Nodeptr next = node->_Next;
            _Nodeptr prev = node->_Prev;

            prev->_Next = next;
            next->_Prev = prev;

            _Node_alloc_type al;
            _Node* ptr = static_cast<_Node*>(node);
            ptr->~_Node();
            al.deallocate(ptr, 1);

            --_Mysize;
            return iterator(next);
        }

    private:
        void _Init()
        {
            _Alloc_proxy();
            _Buy_head();
        }

        void _Alloc_proxy()
        {
            this->_Myproxy = new _Container_proxy();
            this->_Myproxy->_Myfirstiter = 0;
        }

        void _Free_proxy()
        {
            delete this->_Myproxy;
            this->_Myproxy = 0;
        }

        void _Buy_head()
        {
            _Node_alloc_type al;
            _Node* head = al.allocate(1);
            new (head) _Node();      // sentinel
            _Myhead = head;
            _Mysize = 0;
        }

        void _Free_head()
        {
            if (!_Myhead)
                return;

            _Node_alloc_type al;
            _Node* head = static_cast<_Node*>(_Myhead);
            head->~_Node();
            al.deallocate(head, 1);
            _Myhead = 0;
        }

        void _Tidy()
        {
            if (!_Myhead)
                return;

            _Node_alloc_type al;
            _Nodeptr head = _Myhead;
            _Nodeptr cur = head->_Next;

            while (cur != head)
            {
                _Nodeptr next = cur->_Next;
                _Node* node = static_cast<_Node*>(cur);
                node->~_Node();
                al.deallocate(node, 1);
                cur = next;
            }

            head->_Next = head;
            head->_Prev = head;
            _Mysize = 0;
        }
    };
    static_assert(sizeof(list<int>) == 0xC, "list<int> == 0xC");

    template<class T>
	struct linked_list
    {
	    void* head;
    	void* tail;
    };
    static_assert(sizeof(linked_list<int>) == 8, "linked_list<int> == 8");
}
