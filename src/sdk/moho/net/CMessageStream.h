#pragma once

#include "gpg/core/streams/Stream.h"

namespace moho
{
	struct CMessage;

	/**
     * VFTABLE: 0x00E03BEC
     * COL:  0x00E606AC
     */
    class CMessageStream : public gpg::Stream
	{
    public:
        enum class Access
        {
	        kReadOnly,
        	kReadWrite
        };

        /**
         * Address: 0x0047C030
         * Slot: 0
         * Demangled: public: __thiscall Moho::CMessageStream::~CMessageStream()
         */
        ~CMessageStream() override;

        /**
         * Address: 0x00956F50
         * Slot: 1
         * Demangled: protected: virtual unsigned __int64 __thiscall gpg::Stream::VirtTell(enum gpg::Stream::Mode)
         */
        size_t VirtTell(Mode) override;

        /**
         * Address: 0x00956F90
         * Slot: 2
         * Demangled: protected: virtual unsigned __int64 __thiscall gpg::Stream::VirtSeek(enum gpg::Stream::Mode,enum gpg::Stream::SeekOrigin,__int64)
         */
        size_t VirtSeek(Mode mode, SeekOrigin orig, size_t pos) override;

        /**
         * Address: 0x0047C0F0
         * Slot: 3
         * Demangled: gpg::Stream::VirtRead
         */
        size_t VirtRead(char* buff, size_t len) override;

        /**
         * Address: 0x00956DE0
         * Slot: 4
         * Demangled: protected: virtual unsigned int __thiscall gpg::Stream::VirtReadNonBlocking(char near *,unsigned int)
         */
        size_t VirtReadNonBlocking(char* buf, size_t len) override;

        /**
         * Address: 0x00956FD0
         * Slot: 5
         * Demangled: protected: virtual void __thiscall gpg::Stream::VirtUnGetByte(int)
         */
        void VirtUnGetByte(int) override;

        /**
         * Address: 0x0047C120
         * Slot: 6
         * Demangled: gpg::Stream::VirtAtEnd
         */
        bool VirtAtEnd() override;

        /**
         * Address: 0x0047C130
         * Slot: 7
         * Demangled: Moho::CMessageStream::VirtWrite
         */
        void VirtWrite(const char* data, size_t size) override;

        /**
         * Address: 0x00956E00
         * Slot: 8
         * Demangled: protected: virtual void __thiscall gpg::Stream::VirtFlush(void)
         */
        void VirtFlush() override {}

        /**
         * Address: 0x00956E10
         * Slot: 9
         * Demangled: protected: virtual void __thiscall gpg::Stream::VirtClose(enum gpg::Stream::Mode)
         */
        void VirtClose(Mode mode) override {}

        /**
         * Address: 0x0047BFE0
         * NOTE: Could be inlined in binary, example: 0x007C64E7
         *
         * @param msg
         * @param access
         */
        explicit CMessageStream(CMessage& msg, Access access = Access::kReadWrite);

        /**
         * Address: 0x0047C060
         *
         * @param msg
         * @param access
         */
        explicit CMessageStream(CMessage* msg, Access access = Access::kReadOnly);

    private:
        CMessage* msg_ = nullptr;

        /**
         * Compute payload window [start, end) from message buffer.
         */
        static inline std::pair<char*, char*> PayloadWindow(CMessage& m) noexcept;

        /**
         * Rebind read/write windows to message payload, preserving offsets.
         */
        void RebindToMessagePreserve(size_t readOff, size_t writeOffPlus = 0) noexcept;
    };

} 
