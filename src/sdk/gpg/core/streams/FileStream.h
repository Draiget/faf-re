#pragma once

#include <stdexcept>
#include <string>

#include "MemBufferStream.h"
#include "platform/Platform.h"
#include "Stream.h"

namespace gpg
{
    class FileStream : public Stream
    {
    public:
        class IOError : public std::runtime_error
        {
        public:
            /**
             * Address: 0x00955890 (FUN_00955890)
             *
             * What it does:
             * Builds a runtime_error payload from a Win32/system error code and stores that code in `mMsg`.
             */
            explicit IOError(DWORD messageId);

            /**
             * Address: 0x00955900 (FUN_00955900)
             * Deleting owner: 0x00955940 (FUN_00955940)
             * Demangled: gpg::FileStream::IOError::dtr
             *
             * What it does:
             * Destroys IOError runtime_error payload.
             */
            ~IOError() noexcept override;

            DWORD mMsg{ 0 };

        private:
            static std::string BuildMessage(DWORD messageId);
        };

        /**
         * Address: 0x009557E0 (FUN_009557E0)
         * Deleting owner: 0x00955870 (FUN_00955870)
         *
         * What it does:
         * Restores FileStream vftable, closes active lanes via Stream close wrapper, then tears down owned buffer state.
         */
        ~FileStream() override;

        /**
         * Address: 0x00955BD0 (FUN_00955BD0)
         *
         * What it does:
         * Constructs FileStream with a freshly allocated internal `MemBuffer<char>` and opens the file.
         */
        FileStream(const char* filename, Mode accessKind, unsigned int attributes, int buffSize);

        /**
         * Address: 0x00955C50 (FUN_00955C50)
         *
         * What it does:
         * Constructs FileStream from a caller-provided `MemBuffer<char>` view and opens the file.
         */
        FileStream(const char* filename, Mode accessKind, unsigned int attributes, const MemBuffer<char>& buffer);

        /**
         * Address: 0x00955CE0 (FUN_00955CE0)
         *
         * What it does:
         * Returns current logical stream position adjusted by unread/read-buffer and pending-write windows.
         */
        size_t VirtTell(Mode mode) override;

        /**
         * Address: 0x00955DF0 (FUN_00955DF0)
         *
         * What it does:
         * Flushes pending write bytes, seeks by origin/mode with read-window compensation, and clears local windows.
         */
        size_t VirtSeek(Mode mode, SeekOrigin orig, size_t pos) override;

        /**
         * Address: 0x00955F80 (FUN_00955F80)
         *
         * What it does:
         * Reads up to `len` bytes using inline read window first, then refill/direct OS reads through DoRead.
         */
        size_t VirtRead(char* buf, size_t len) override;

        /**
         * Address: 0x009560C0 (FUN_009560C0)
         *
         * What it does:
         * Checks end-of-stream by consuming buffered bytes first and issuing one refill read when empty.
         */
        bool VirtAtEnd() override;

        /**
         * Address: 0x00956180 (FUN_00956180)
         *
         * What it does:
         * Writes bytes through inline write window and flushes/direct-writes when needed.
         */
        void VirtWrite(const char* data, size_t size) override;

        /**
         * Address: 0x00956290 (FUN_00956290)
         *
         * What it does:
         * Flushes any pending write-window bytes to the backing file handle.
         */
        void VirtFlush() override;

        /**
         * Address: 0x00956320 (FUN_00956320)
         *
         * What it does:
         * Closes requested read/write lanes, releases the OS handle, and resets owned memory buffer state.
         */
        void VirtClose(Mode mode) override;

    private:
        /**
         * Address: 0x00955990 (FUN_00955990)
         *
         * What it does:
         * Converts UTF-8 path to wide string, opens file handle with attribute-driven Win32 flags, and stores access mode.
         */
        void DoOpen(const char* file, Mode accessKind, unsigned int attributes);

        /**
         * Address: 0x00955A80 (FUN_00955A80)
         *
         * What it does:
         * Flushes pending read-window offset compensation and writes bytes to the file handle.
         */
        void DoWrite(const void* buffer, size_t bytes);

        /**
         * Address: 0x00955B60 (FUN_00955B60)
         *
         * What it does:
         * Flushes pending write window if needed, then reads bytes from file handle into caller buffer.
         */
        size_t DoRead(void* buffer, size_t bytes);

    public:
        HANDLE mHandle{ INVALID_HANDLE_VALUE };
        Mode mAccessKind{ ModeNone };
        MemBuffer<char> mBuff{};
    };

    static_assert(sizeof(FileStream) == 0x34, "FileStream size must be 0x34");
}
