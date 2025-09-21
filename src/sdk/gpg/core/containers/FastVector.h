#pragma once

#include <algorithm>
#include <cstring>

namespace gpg::core
{
    /**
     * Three-pointer vector with raw ownership. Size math is done in bytes to avoid
     * compiler quirks and to support T=void (elem size is 1 in that case).
	 */
    template<class T>
    class FastVector {
    protected:
        // Element size in bytes; for void treat as 1 to allow math in bytes.
        static constexpr size_t elem_ = std::is_void_v<T> ? 1 : sizeof(T);

        static size_t index_of(const T* base, const T* p) noexcept {
	        const auto b = reinterpret_cast<const std::byte*>(base);
	        const auto q = reinterpret_cast<const std::byte*>(p);
            return static_cast<size_t>(q - b) / elem_;
        }
        static T* ptr_at(T* base, const size_t idx) noexcept {
            auto b = reinterpret_cast<std::byte*>(base);
            return reinterpret_cast<T*>(b + idx * elem_);
        }

    public:
        T* start_{ nullptr };
        T* end_{ nullptr };
        T* capacity_{ nullptr };

        FastVector() = default;

        ~FastVector() {
            delete[] start_;
        }

        [[nodiscard]]
        size_t Size() const noexcept {
	        const auto b = reinterpret_cast<const std::byte*>(start_);
	        const auto e = reinterpret_cast<const std::byte*>(end_);
            return static_cast<size_t>(e - b) / elem_;
        }

        [[nodiscard]]
        size_t Capacity() const noexcept {
	        const auto b = reinterpret_cast<const std::byte*>(start_);
	        const auto c = reinterpret_cast<const std::byte*>(capacity_);
            return static_cast<size_t>(c - b) / elem_;
        }

        T& operator[](const size_t idx) noexcept {
            return *ptr_at(start_, idx);
        }
        const T& operator[](const size_t idx) const noexcept {
            return *ptr_at(const_cast<T*>(start_), idx);
        }

        /**
         * Reserve at least n elements; does not shrink.
         */
        void Reserve(size_t n) {
            if (Capacity() >= n) return;
            const size_t oldSize = Size();
            T* newBuf = new T[n];
            // Trivially copyable path
            if constexpr (std::is_trivially_copyable_v<T>) {
                if (oldSize) std::memcpy(newBuf, start_, oldSize * elem_);
            } else {
                for (size_t i = 0; i < oldSize; ++i) newBuf[i] = std::move(start_[i]);
            }
            delete[] start_;
            start_ = newBuf;
            end_ = newBuf + oldSize;
            capacity_ = newBuf + n;
        }

        void PushBack(const T& v) {
            if (end_ == capacity_) {
	            const size_t newCap = Capacity() ? Capacity() * 2 : 4;
                Reserve(newCap);
            }
            *end_++ = v;
        }

        void Clear() noexcept { end_ = start_; }

        FastVector(const FastVector&) = delete;
        FastVector& operator=(const FastVector&) = delete;

        FastVector(FastVector&& other) noexcept
            : start_(other.start_), end_(other.end_), capacity_(other.capacity_) {
            other.start_ = other.end_ = other.capacity_ = nullptr;
        }
        FastVector& operator=(FastVector&& other) noexcept {
            if (this != &other) {
                delete[] start_;
                start_ = other.start_;
                end_ = other.end_;
                capacity_ = other.capacity_;
                other.start_ = other.end_ = other.capacity_ = nullptr;
            }
            return *this;
        }
    };

    /**
	 * Small-buffer optimized vector based on FastVector.
	 * No dependency on Base internals (has its own byte helpers).
	 */
    template<class T, size_t N>
    class FastVectorN : public FastVector<T> {
        using Base = FastVector<T>;

        // Element size in bytes (void is not a valid element, but keep generic math)
        static constexpr size_t ElemSize = std::is_void_v<T> ? 1 : sizeof(T);

        // Compute index of pointer p relative to base in elements
        static size_t index_of(const T* base, const T* p) noexcept {
            auto b = reinterpret_cast<const std::byte*>(base);
            auto q = reinterpret_cast<const std::byte*>(p);
            return static_cast<size_t>(q - b) / ElemSize;
        }

        // Get pointer at element index from base
        static T* ptr_at(T* base, size_t idx) noexcept {
            auto b = reinterpret_cast<std::byte*>(base);
            return reinterpret_cast<T*>(b + idx * ElemSize);
        }

    public:
        T* originalVec_{};
        alignas(T) T inlineVec_[N];

        FastVectorN() {
            this->start_ = inlineVec_;
            this->end_ = inlineVec_;
            this->capacity_ = inlineVec_ + N;
            originalVec_ = inlineVec_;
        }

        ~FastVectorN() {
            // Free heap only; inline buffer must not be freed
            if (this->start_ && this->start_ != originalVec_) {
                delete[] this->start_;
            }
            // Prevent Base dtor from touching inline storage
            this->start_ = this->end_ = this->capacity_ = nullptr;
        }

        /** Ensure capacity is at least newSize elements. */
        void Grow(size_t newSize) {
            if (this->Capacity() >= newSize) return;
            GrowToCapacity(newSize);
        }

        /** Resize; fill new elements with 'fill' value. */
        void Resize(size_t newSize, const T& fill = T{}) {
            const size_t sz = this->Size();
            if (newSize <= sz) {
                this->end_ = this->start_ + newSize;
                return;
            }
            if (this->Capacity() < newSize) {
                GrowToCapacity(newSize);
            }
            for (size_t i = sz; i < newSize; ++i) {
                this->start_[i] = fill;
            }
            this->end_ = this->start_ + newSize;
        }

        /** Insert range [insStart, insEnd) before 'pos'. */
        void InsertAt(T* pos, const T* insStart, const T* insEnd) {
            const size_t insertCount = static_cast<size_t>(insEnd - insStart);
            if (!insertCount) return;

            const size_t sz = this->Size();
            const size_t cap = this->Capacity();
            size_t posIndex = index_of(this->start_, pos);

            if (sz + insertCount > cap) {
                size_t newCap = cap ? cap * 2 : N;
                if (newCap < sz + insertCount) newCap = sz + insertCount;
                GrowToCapacity(newCap);
            }

            // Recompute 'pos' after potential reallocation
            pos = ptr_at(this->start_, posIndex);

            // Shift tail to make room; memmove handles overlap
            const size_t tailCount = static_cast<size_t>(this->end_ - pos);
            if (tailCount) {
                std::memmove(pos + insertCount, pos, tailCount * ElemSize);
            }

            // Copy new items
            if constexpr (std::is_trivially_copyable_v<T>) {
                std::memcpy(pos, insStart, insertCount * ElemSize);
            } else {
                for (size_t i = 0; i < insertCount; ++i) pos[i] = insStart[i];
            }

            this->end_ += insertCount;
        }

        void Append(T& o) {
            if (this->end_ == this->capacity_) {
                this->InsertAt(this->end_, &o, &o + 1);
            } else {
                if (this->end_ != nullptr) {
                    *this->end_ = o;
                }
                ++this->end_;
            }
        }

    private:
        /** Reallocate to exactly newCap elements; preserve contents. */
        void GrowToCapacity(size_t newCap) {
            const size_t sz = this->Size();
            T* newBuf = new T[newCap];

            if constexpr (std::is_trivially_copyable_v<T>) {
                if (sz) std::memcpy(newBuf, this->start_, sz * ElemSize);
            } else {
                for (size_t i = 0; i < sz; ++i) newBuf[i] = std::move(this->start_[i]);
            }

            if (this->start_ != originalVec_) {
                delete[] this->start_;
            }

            this->start_ = newBuf;
            this->end_ = newBuf + sz;
            this->capacity_ = newBuf + newCap;
        }
    };
}
