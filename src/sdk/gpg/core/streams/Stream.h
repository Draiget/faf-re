#pragma once
#include <stdexcept>

#include "gpg/core/containers/FastVector.h"

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

        virtual ~Stream() = default; // 0x00956E20
        virtual size_t VirtTell(Mode mode); // 0x00956F50
        virtual size_t VirtSeek(Mode mode, SeekOrigin orig, size_t pos); // 0x00956F90
        virtual size_t VirtRead(char* buff, size_t len); // 0x00956FB0
        virtual size_t VirtReadNonBlocking(char* buf, size_t len); // 0x00956DE0
        virtual void VirtUnGetByte(int); // 0x00956FD0
        virtual bool VirtAtEnd(); // 0x00956DF0
        virtual void VirtWrite(const char* data, size_t size); // 0x00956FF0
        virtual void VirtFlush(); // 0x00956E00
        virtual void VirtClose(Mode mode); // 0x00956E10

        Stream() = default; // 0x00956DB0

        int LeftToRead() const {
            return mReadEnd - mReadHead;
        } // inline

        int LeftToWrite() const {
            return mWriteEnd - mWriteHead;
        } // inline

        /**
         * Bytes pending in the small inline input buffer.
         */
        size_t LeftToFlush() const {
            return static_cast<size_t>(mWriteHead - mWriteStart);
        }

        void Write(const char* buf, size_t size); // 0x0043D130

        bool Close(Mode access); // 0x00955760

        size_t Read(char* buf, size_t size); // 0x0043D100

        size_t ReadNonBlocking(char* buf, size_t size) {
            if (size > LeftToRead()) {
                size = VirtReadNonBlocking(buf, size);
            } else if (size) {
                memcpy(buf, mReadHead, size);
                mReadHead += size;
            }
            return size;
        } // inline e.g. 0x0047BF13

        void Write(core::FastVector<char>& vec) {
            Write(vec.start_, vec.Size());
        } // inline
    };
}
