#pragma once

#include "PipeStream.h"
#include "Stream.h"
#include <zlib.h>

namespace gpg
{
    /**
     * VFTABLE: 0x00D496F0
     * COL:     0x00E53D00
     */
    class ZLibOutputFilterStream : public Stream
    {
    public:
        /**
         * Address: 0x00957340
         * Slot: 0
         * Demangled: gpg::ZLibOutputFilterStream::dtr
         */
        ~ZLibOutputFilterStream() override;

        /**
         * Address: 0x00956F50
         * Slot: 1
         * Demangled: protected: virtual uint64_t __thiscall gpg::Stream::VirtTell(enum gpg::Stream::Mode)
         */
        size_t VirtTell(Mode mode) override;

        /**
         * Address: 0x00956F90
         * Slot: 2
         * Demangled: protected: virtual uint64_t __thiscall gpg::Stream::VirtSeek(enum gpg::Stream::Mode,enum gpg::Stream::SeekOrigin,int64_t)
         */
        size_t VirtSeek(Mode mode, SeekOrigin origin, size_t size) override;

        /**
         * Address: 0x00956FB0
         * Slot: 3
         * Demangled: protected: virtual unsigned int __thiscall gpg::Stream::VirtRead(char near *,unsigned int)
         */
        size_t VirtRead(char* buffer, unsigned int size) override;

        /**
         * Address: 0x00956DE0
         * Slot: 4
         * Demangled: protected: virtual unsigned int __thiscall gpg::Stream::VirtReadNonBlocking(char near *,unsigned int)
         */
        size_t VirtReadNonBlocking(char* buffer, unsigned int size) override;

        /**
         * Address: 0x00956FD0
         * Slot: 5
         * Demangled: protected: virtual void __thiscall gpg::Stream::VirtUnGetByte(int)
         */
        void VirtUnGetByte(int size) override;

        /**
         * Address: 0x00956DF0
         * Slot: 6
         * Demangled: protected: virtual bool __thiscall gpg::Stream::VirtAtEnd(void)
         */
        bool VirtAtEnd() override;

        /**
         * Address: 0x00957760
         * Slot: 7
         * Demangled: private: virtual void __thiscall gpg::ZLibOutputFilterStream::VirtWrite(char const near *,unsigned int)
         */
        void VirtWrite(char const* data, size_t size) override;

        /**
         * Address: 0x00957810
         * Slot: 8
         * Demangled: private: virtual void __thiscall gpg::ZLibOutputFilterStream::VirtFlush(void)
         */
        void VirtFlush() override;

        /**
         * Address: 0x009578B0
         * Slot: 9
         * Demangled: private: virtual void __thiscall gpg::ZLibOutputFilterStream::VirtClose(enum gpg::Stream::Mode)
         */
        void VirtClose(Mode mode) override;

        /**
         * Address: 0x00957360
         */
        ZLibOutputFilterStream(PipeStream* str, int operation);

    private:
        /**
         * Core write path used by Write/Flush/Close with a zlib flush code.
         */
        void DoWrite(char const* data, size_t len, int flush);

    public:
        PipeStream* mPipeStream;
        int mOperation{ Z_OK };
        z_stream mZStream{};
        char mBuff[1024]{};
        bool mEnded{ false };
        bool mClosed{ false };

    };
} // namespace gpg
