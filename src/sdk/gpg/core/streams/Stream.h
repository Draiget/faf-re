#pragma once
#include <stdexcept>

#include "gpg/core/containers/FastVector.h"
#include "moho/net/INetConnection.h"

namespace gpg
{
    // 0x00D49658
    class Stream
    {
    public:

        // 0x00D49684
        class UnsupportedOperation : public std::logic_error
        {
        public:
            UnsupportedOperation(); // 0x00956E40
        };

        enum Mode
        {
            ModeNone = 0,
            ModeReceive = 1,
            ModeSend = 2,
            ModeBoth = 3,
        };

        enum SeekOrigin
        {
            OriginBegin = 0,
            OriginCurr = 1,
            OriginEnd = 2,
        };

    public:
        char* mReadStart;
        char* mReadHead;
        char* mReadEnd;
        char* mWriteStart;
        char* mWriteHead;
        char* mWriteEnd;

        /**
         * Address: 0x00956E20
		 * Slot: 0
         */
        virtual ~Stream() = default;

        /**
         * Address: 0x00956DB0
         */
        Stream() = default;

        /**
         * Address: 0x00956F50
		 * Slot: 1
		 *
         * @param mode 
         * @return 
         */
        virtual size_t VirtTell(Mode mode);

        /**
         * Address: 0x00956F90
         * Slot: 2
         * 
         * @param mode 
         * @param orig 
         * @param pos 
         * @return 
         */
        virtual size_t VirtSeek(Mode mode, SeekOrigin orig, size_t pos);

        /**
         * Address: 0x00956FB0
         * Slot: 3
         *
         * @param buff 
         * @param len 
         * @return 
         */
        virtual size_t VirtRead(char* buff, size_t len);

        /**
         * Address: 0x00956DE0
         * Slot: 4
         *
         * @param buf 
         * @param len 
         * @return 
         */
        virtual size_t VirtReadNonBlocking(char* buf, size_t len);

        /**
         * Address: 0x00956FD0
         * Slot: 5
         *
         * @param unknown
         */
        virtual void VirtUnGetByte(int unknown);

        /**
         * Address: 0x00956DF0
         * Slot: 6
         *
         * @return 
         */
        virtual bool VirtAtEnd();

        /**
         * Address: 0x00956FF0
         * Slot: 7
         *
         * @param data 
         * @param size 
         */
        virtual void VirtWrite(const char* data, size_t size);

        /**
         * Address: 0x00956E00
         * Slot: 8
         */
        virtual void VirtFlush();

        /**
         * Address: 0x00956E10
         * Slot: 9
         *
         * @param mode 
         */
        virtual void VirtClose(Mode mode);

        /**
         * NOTE: Inlined
         * @return
         */
        [[nodiscard]]
        bool CanRead() const {
            return mReadEnd != mReadHead;
        }

        /**
         * NOTE: Inlined
         * Bytes pending in the small inline input buffer.
         */
        [[nodiscard]]
        size_t BytesRead() const {
            return mReadEnd - mReadHead;
        }

        /**
         * NOTE: Inlined
         * @return
         */
        [[nodiscard]]
        bool CanWrite() const {
            return this->mWriteEnd != this->mWriteHead;
        }

        /**
         * NOTE: Inlined
         * @return
         */
        [[nodiscard]] 
        size_t LeftToWrite() const {
            return mWriteEnd - mWriteHead;
        }

        /**
         * NOTE: Inlined
         * @return 
         */
        [[nodiscard]]
        size_t BytesWritten() const {
            return mWriteHead - mWriteStart;
        }

        /**
         * Address: 0x006E5A10
         *
         * @param str 
         */
        void Write(const msvc8::string& str);

        /**
         * Address: 0x0043D130
         *
         * @param buf 
         * @param size 
         */
        void Write(const char* buf, size_t size);

        /**
         * Address: 0x004CCD80
         *
         * @param buf 
         */
        void Write(const char* buf); 

        /**
         * Note: Custom function.
         *
         * Write any trivially-copyable non-pointer, non-enum value as raw bytes.
         * Endianness: bytes are emitted as-is (little-endian on x86).
         */
        template <class T>
        std::enable_if_t<
            std::is_trivially_copyable_v<T> &&
            !std::is_pointer_v<T> &&
            !std::is_enum_v<T>,
            void
        >
            Write(const T& value) {
            Write(reinterpret_cast<const char*>(&value), sizeof(T));
        }

        /**
         * Note: Custom function.
         *
         * Write enum by its underlying integral type.
         */
        template <class E>
        std::enable_if_t<std::is_enum_v<E>, void>
            Write(const E value) {
            using U = std::underlying_type_t<E>;
            U tmp = static_cast<U>(value);
            Write(reinterpret_cast<const char*>(&tmp), sizeof(U));
        }

        /**
         * Note: Custom function.
         *
         * Write fixed-size C array (e.g., byte blobs).
         */
        template <class T, std::size_t N>
        std::enable_if_t<std::is_trivially_copyable_v<T>, void>
            Write(const T(&arr)[N]) {
            Write(reinterpret_cast<const char*>(arr), sizeof(arr));
        }

        /**
         * Address: 0x00955760
         *
         * @param access 
         * @return 
         */
        bool Close(Mode access);

        /**
         * Address: 0x0043D100
         *
         * @param buf 
         * @param size 
         * @return 
         */
        size_t Read(char* buf, size_t size); 

        /**
         * NOTE: Inlined (e.g. - 0x0047BF13)
         *
         * @param buf 
         * @param size 
         * @return 
         */
        size_t ReadNonBlocking(char* buf, size_t size);

        /**
         * NOTE: Inlined
         * @param vec 
         */
        void Write(const core::FastVector<char>& vec) {
            Write(vec.start_, vec.Size());
        }

        /**
         * Address: 0x004CCDEC
         *
         * NOTE: Inlined
         * @return byte (int8_t)
         */
        int8_t GetByte();
    };
    static_assert(sizeof(Stream) == 0x1C, "gpg::Stream size must be 0x1C");
}
