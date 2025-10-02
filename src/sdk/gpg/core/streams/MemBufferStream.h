#pragma once

#include <stdexcept>
#include <cstddef>

#include "boost/shared_ptr.h"

namespace gpg
{
    /**
     * Lightweight shared view over a contiguous memory range [mBegin, mEnd).
     * Ownership is kept via boost::shared_ptr<T> (typically allocated as an array).
     * The view itself is non-owning; copying shares ownership of the same buffer.
     */
    template<class T>
    class MemBuffer
    {
        using type = T;

    public:
        boost::shared_ptr<type> mData{};
        type* mBegin{ nullptr };
        type* mEnd{ nullptr };

        /** Default ctor - empty view. */
        MemBuffer() noexcept = default;

        /** Copy ctor - shallow copy (shares ownership). */
        MemBuffer(const MemBuffer& cpy) noexcept = default;

        /** Construct from owner + raw range [begin, end). */
        MemBuffer(boost::shared_ptr<type> ptr, type* begin, type* end) noexcept
            : mData{ ptr }, mBegin{ begin }, mEnd{ end } {
        }

        /** Construct from owner + length (range is [ptr.get(), ptr.get()+len)). */
        MemBuffer(boost::shared_ptr<type> ptr, std::size_t len) noexcept
            : mData{ ptr }, mBegin{ ptr.get() }, mEnd{ ptr.get() + len } {
        }

        /** Get pointer to subrange start with bounds check for [start, start+len). */
        type* GetPtr(std::size_t start, std::size_t len) const
        {
            if (!mBegin && (start || len)) {
                throw std::range_error("MemBuffer::GetPtr: null buffer");
            }
            type* p = mBegin + start;
            if (p < mBegin || p > mEnd || p + len > mEnd) {
                throw std::range_error("Out of bound access in MemBuffer<>::GetPtr()");
            }
            return p;
        }

        /** Create a sub-buffer view [start, start+len). */
        MemBuffer SubBuffer(std::size_t start, std::size_t len) const
        {
            type* b = GetPtr(start, 0);
            type* e = GetPtr(start + len, 0);
            return MemBuffer{ this->mData, b, e };
        }

        /** Reset to empty; releases shared ownership. */
        void Reset() noexcept
        {
            this->mData.reset();
            this->mBegin = nullptr;
            this->mEnd = nullptr;
        }

        /** Size in elements. */
        std::size_t Size() const noexcept
        {
            return static_cast<std::size_t>(mEnd - mBegin);
        }

        /** Copy assignment (shares ownership). */
        MemBuffer& operator=(const MemBuffer&) noexcept = default;

        /** Implicit conversion to raw pointer (begin). */
        operator type* () noexcept { return mBegin; }
        operator const type* () const noexcept { return mBegin; }

        /** Raw data accessors. */
        type* data() noexcept { return mBegin; }
        const type* data() const noexcept { return mBegin; }

        /** STL-like iterators. */
        type* begin() noexcept { return mBegin; }
        const type* begin() const noexcept { return mBegin; }
        type* end() noexcept { return mEnd; }
        const type* end() const noexcept { return mEnd; }

        /** Unchecked element access. */
        type& operator[](std::size_t ind) noexcept { return mBegin[ind]; }
        const type& operator[](std::size_t ind) const noexcept { return mBegin[ind]; }
    };

    /**
     * Address: 0x0094E320
     */
    MemBuffer<char> AllocMemBuffer(std::size_t size);
}
