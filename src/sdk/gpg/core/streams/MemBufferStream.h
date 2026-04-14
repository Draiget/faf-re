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

        /**
         * Address: 0x00442A70 (FUN_00442A70)
         * Address: 0x00442A90 (FUN_00442A90)
         * Address: 0x00442B00 (FUN_00442B00)
         *
         * What it does:
         * Initializes one mem-buffer view as empty (null owner + null bounds).
         */
        MemBuffer() noexcept = default;

        /**
         * Address: 0x00442B10 (FUN_00442B10)
         *
         * What it does:
         * Performs one shallow copy of the mem-buffer payload lanes.
         */
        MemBuffer(const MemBuffer& cpy) noexcept = default;

        /**
         * Address: 0x0042D1A0 (FUN_0042D1A0, __imp_??1?$MemBuffer@$$CBD@gpg@@QAE@XZ)
         * Address: 0x0042D1E0 (FUN_0042D1E0, __imp_??1?$MemBuffer@D@gpg@@QAE@XZ)
         * Address: 0x004CE280 (FUN_004CE280, gpg::MemBuffer<char const>::~MemBuffer<char const>)
         * Address: 0x004CEE70 (FUN_004CEE70, gpg::MemBuffer<char const>::~MemBuffer<char const> alias)
         *
         * What it does:
         * Releases one shared ownership lane for the buffer/control block.
         */
        ~MemBuffer() noexcept = default;

        /** Converting copy ctor (e.g. MemBuffer<char> -> MemBuffer<const char>). */
        template <class U, std::enable_if_t<std::is_convertible_v<U*, type*>, int> = 0>
        MemBuffer(const MemBuffer<U>& cpy) noexcept
            : mData(cpy.mData),
              mBegin(cpy.mBegin),
              mEnd(cpy.mEnd)
        {
        }

        /**
         * Address: 0x0094E0F0 (FUN_0094E0F0, gpg::MemBuffer<char>::MemBuffer<char>)
         *
         * What it does:
         * Copies one shared owner lane and binds explicit begin/end pointers.
         */
        MemBuffer(boost::shared_ptr<type> ptr, type* begin, type* end) noexcept
            : mData{ ptr }, mBegin{ begin }, mEnd{ end } {
        }

        /**
         * Address: 0x0045B4C0 (FUN_0045B4C0, gpg::MemBuffer<char>::MemBuffer<char>)
         * Address: 0x0046D9D0 (FUN_0046D9D0, gpg::MemBuffer<char const>::MemBuffer<char const>)
         *
         * What it does:
         * Copies one shared owner lane and sets view bounds to
         * `[ptr.get(), ptr.get() + len)`.
         */
        MemBuffer(boost::shared_ptr<type> ptr, std::size_t len) noexcept
            : mData{ ptr }, mBegin{ ptr.get() }, mEnd{ ptr.get() + len } {
        }

        /**
         * Address family:
         * - 0x004313E0 (FUN_004313E0, `MemBuffer<char>::GetPtr`)
         * - 0x00431520 (FUN_00431520, `MemBuffer<const char>::GetPtr`)
         *
         * What it does:
         * Returns `mBegin + start` and throws `std::range_error` when
         * `[start, start + len)` crosses `mEnd`.
         */
        type* GetPtr(std::size_t start, std::size_t len) const
        {
            type* const result = &mBegin[start];
            if (&result[len] > mEnd) {
                throw std::range_error("Out of bound access in MemBuffer<>::GetPtr()");
            }
            return result;
        }

        /**
         * Address: 0x0088E780 (FUN_0088E780, gpg::MemBuffer<char const>::SubBuffer)
         *
         * What it does:
         * Creates one range-checked shared sub-view `[start, start + len)`.
         */
        MemBuffer SubBuffer(std::size_t start, std::size_t len) const
        {
            type* b = GetPtr(start, 0);
            type* e = GetPtr(start + len, 0);
            return MemBuffer{ this->mData, b, e };
        }

        /**
         * Address: 0x00442AB0 (FUN_00442AB0)
         *
         * What it does:
         * Releases one retained shared owner and clears begin/end bounds.
         */
        void Reset() noexcept
        {
            this->mData.reset();
            this->mBegin = nullptr;
            this->mEnd = nullptr;
        }

        /**
         * Address: 0x00442A80 (FUN_00442A80)
         *
         * What it does:
         * Returns the element-count distance between end and begin lanes.
         */
        std::size_t Size() const noexcept
        {
            return static_cast<std::size_t>(mEnd - mBegin);
        }

        /**
         * Address: 0x00539E40 (FUN_00539E40, gpg::MemBuffer::GetSharedPtr)
         *
         * boost::shared_ptr<T>
         *
         * IDA signature:
         * boost::shared_ptr_char * __stdcall
         *   gpg::MemBuffer::GetSharedPtr(gpg::MemBuffer *this, boost::shared_ptr_char *out);
         *
         * What it does:
         * Returns one shared owner that aliases this view's begin pointer while
         * retaining the original control block.
         */
        [[nodiscard]] boost::shared_ptr<type> GetSharedPtr() const
        {
            if (!mData) {
                return {};
            }
            return boost::shared_ptr<type>(mData, mBegin);
        }

        /**
         * Address: 0x004D8E90 (FUN_004D8E90, gpg::MemBuffer<char>::operator=)
         *
         * What it does:
         * Performs one shallow lane copy (shared owner + begin/end bounds).
         */
        MemBuffer& operator=(const MemBuffer& rhs) noexcept
        {
            if (this == &rhs) {
                return *this;
            }

            mData = rhs.mData;
            mBegin = rhs.mBegin;
            mEnd = rhs.mEnd;
            return *this;
        }

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

        /**
         * Address: 0x00442AA0 (FUN_00442AA0)
         *
         * What it does:
         * Returns the begin-lane pointer for direct raw access.
         */
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
        std::uint64_t VirtTell(Mode mode) override;

        /**
         * Address: 0x008E6140 (FUN_008E6140)
         *
         * What it does:
         * Seeks read/write cursors by mode and origin, growing writable storage and zero-filling gaps when needed.
         */
        std::uint64_t VirtSeek(Mode mode, SeekOrigin origin, std::int64_t pos) override;

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

        /**
         * Address: 0x008E59F0 (FUN_008E59F0, gpg::MemBufferStream::GetLength)
         *
         * What it does:
         * Returns the current logical length of the stream from the active
         * write window when present, otherwise from the read window.
         */
        unsigned int GetLength() const;

        /**
         * Address: 0x004CCCD0 (FUN_004CCCD0, gpg::MemBufferStream::GetBuffer)
         *
         * What it does:
         * Returns one mutable buffer view for writable streams and throws on
         * immutable stream instances.
         */
        MemBuffer<char> GetBuffer() const;

        /**
         * Address: 0x0088B7E0 (FUN_0088B7E0, gpg::MemBufferStream::GetConstBuffer)
         *
         * What it does:
         * Returns one immutable shared view over the stream output window.
         */
        MemBuffer<const char> GetConstBuffer() const;

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
     * Address: 0x0094E5D0 (FUN_0094E5D0, ?CopyMemBuffer@gpg@@YA?AU?$MemBuffer@D@1@ABU?$MemBuffer@$$CBD@1@@Z)
     *
     * What it does:
     * Copies one immutable mem-buffer view into a new owned immutable byte view.
     */
    MemBuffer<char> CopyMemBuffer(const MemBuffer<const char>& source);

    /**
     * What it does:
     * Loads one file into an owned immutable byte view; returns empty view on failure.
     */
    MemBuffer<const char> LoadFileToMemBuffer(const char* path);
}
