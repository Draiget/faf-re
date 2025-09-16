#pragma once
#include <stdexcept>

#include "MemBufferStream.h"
#include "platform/Platform.h"
#include "Stream.h"

namespace gpg
{
	class FileStream : public Stream
	{
    public:
        /**
         * VFTABLE: 0x00D494A8
         * COL:  0x00E53BFC
         */
        class IOError : public std::runtime_error {
        public:
            /**
             * Address: 0x00955940
             * Slot: 0
             * Demangled: gpg::FileStream::IOError::dtr
             */
            virtual ~IOError() = default;
            /**
             * Address: 0x004051D0
             * Slot: 1
             * Demangled: std::runtime_error::what
             */
            virtual const char* what() const noexcept = 0;
        };

    public:
        HANDLE mHandle;
        Mode mAccessKind;
        MemBuffer<char> mBuff;
	};
}
