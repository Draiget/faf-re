#pragma once

#include <stdexcept>
#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "boost/shared_ptr.h"
#include "Stream.h"

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

        /** Converting copy ctor (e.g. MemBuffer<char> -> MemBuffer<const char>). */
        template <class U, std::enable_if_t<std::is_convertible_v<U*, type*>, int> = 0>
        MemBuffer(const MemBuffer<U>& cpy) noexcept
            : mData(cpy.mData),
              mBegin(cpy.mBegin),
              mEnd(cpy.mEnd)
        {
        }

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
            if (mBegin == nullptr) {
                if (start == 0 && len == 0) {
                    return nullptr;
                }
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

        /** Converting assignment (e.g. MemBuffer<char> -> MemBuffer<const char>). */
        template <class U, std::enable_if_t<std::is_convertible_v<U*, type*>, int> = 0>
        MemBuffer& operator=(const MemBuffer<U>& rhs) noexcept
        {
            mData = rhs.mData;
            mBegin = rhs.mBegin;
            mEnd = rhs.mEnd;
            return *this;
        }

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
    static_assert(sizeof(MemBuffer<char>) == 0x10, "MemBuffer<char> size must be 0x10");
    static_assert(sizeof(MemBuffer<const char>) == 0x10, "MemBuffer<const char> size must be 0x10");

    class MemBufferStream : public Stream
    {
    public:
        /**
         * Address: 0x004D3060 (FUN_004D3060)
         * Deleting owner: 0x008E5B80 (FUN_008E5B80)
         * Demangled: gpg::MemBufferStream::dtr
         *
         * What it does:
         * Tears down output/input shared-buffer views, then runs Stream base destructor.
         */
        ~MemBufferStream() override;

        /**
         * Address: 0x008E5AE0 (FUN_008E5AE0)
         *
         * What it does:
         * Initializes a writable in-memory stream with a newly allocated backing buffer.
         */
        explicit MemBufferStream(unsigned int size);

        /**
         * Address: 0x008E5BA0 (FUN_008E5BA0)
         *
         * What it does:
         * Initializes a writable in-memory stream from caller-owned mutable storage and an initial logical length.
         */
        MemBufferStream(const MemBuffer<char>& input, unsigned int initialLength);

        /**
         * Address: 0x008E5CC0 (FUN_008E5CC0)
         * Mangled: ??0MemBufferStream@gpg@@QAE@ABU?$MemBuffer@$$CBD@1@I@Z
         *
         * What it does:
         * Initializes a read-only in-memory stream from caller-owned const storage and an initial logical length.
         */
        MemBufferStream(const MemBuffer<const char>& output, unsigned int initialLength = static_cast<unsigned int>(-1));

        /**
         * Address: 0x008E5DC0 (FUN_008E5DC0)
         *
         * What it does:
         * Returns current read/write offset based on mode (`ModeReceive` or `ModeSend`).
         */
        size_t VirtTell(Mode mode) override;

        /**
         * Address: 0x008E6140 (FUN_008E6140)
         *
         * What it does:
         * Seeks read/write cursors by mode and origin, growing writable storage and zero-filling gaps when needed.
         */
        size_t VirtSeek(Mode mode, SeekOrigin origin, size_t pos) override;

        /**
         * Address: 0x008E5A50 (FUN_008E5A50)
         *
         * What it does:
         * Reads up to `len` bytes from current read cursor and advances the read cursor.
         */
        size_t VirtRead(char* buf, size_t len) override;

        /**
         * Address: 0x008E5E70 (FUN_008E5E70)
         *
         * What it does:
         * Throws when asked to unget beyond the start of the in-memory stream.
         */
        void VirtUnGetByte(int value) override;

        /**
         * Address: 0x008E5AB0 (FUN_008E5AB0)
         *
         * What it does:
         * Returns true when read cursor reaches the logical end.
         */
        bool VirtAtEnd() override;

        /**
         * Address: 0x008E6470 (FUN_008E6470)
         *
         * What it does:
         * Writes bytes to current write cursor, growing writable storage on demand.
         */
        void VirtWrite(const char* data, size_t size) override;

        /**
         * Address: 0x008E5AD0 (FUN_008E5AD0)
         *
         * What it does:
         * Promotes logical read-end to include pending writes.
         */
        void VirtFlush() override;

    private:
        /**
         * Address: 0x008E5EE0 (FUN_008E5EE0)
         *
         * What it does:
         * Grows writable storage to satisfy `size`, preserving read/write cursor offsets.
         */
        void Resize(std::uint64_t size);

        void SyncReadEndWithWriteHead();

    public:
        MemBuffer<char> mInput{};
        MemBuffer<const char> mOutput{};
    };
    static_assert(sizeof(MemBufferStream) == 0x3C, "MemBufferStream size must be 0x3C");

    /**
     * Address: 0x0094E320
     */
    MemBuffer<char> AllocMemBuffer(std::size_t size);

    /**
     * What it does:
     * Creates one owned immutable byte view by copying `size` bytes from `source`.
     */
    MemBuffer<const char> CopyMemBuffer(const void* source, std::size_t size);

    /**
     * What it does:
     * Loads one file into an owned immutable byte view; returns empty view on failure.
     */
    MemBuffer<const char> LoadFileToMemBuffer(const char* path);
}
