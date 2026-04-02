#pragma once

#include <cstddef>
#include <exception>

#include "legacy/containers/String.h"

namespace gpg
{
    /**
     * Address: 0x00B50FD8 (FUN_00B50FD8)
     *
     * HRESULT
     *
     * What it does:
     * Maps a large set of DirectX/COM HRESULT values to stable engine-facing
     * diagnostic text, returning `"n/a"` for unknown values.
     */
    const char* __stdcall D3DErrorToString(long code);
}

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D42104
     * COL:     0x00E9D59C
     */
    class Error : public std::exception
    {
    public:
        /**
         * Address: 0x009404D0 (FUN_009404D0)
         *
         * What it does:
         * Builds an exception payload from source-file, line, and message strings.
         */
        Error(const msvc8::string& file, int line, const msvc8::string& message);

        /**
         * Address: 0x008A7B10 (FUN_008A7B10)
         *
         * What it does:
         * Owns the scalar-deleting destructor thunk for Error exception objects.
         */
        ~Error() override;

        /**
         * Address: 0x00940460 (FUN_00940460)
         *
         * What it does:
         * Returns a raw pointer to the stored error message payload.
         */
        const char* what() const noexcept override;

        /**
         * Address: 0x00940440 (FUN_00940440)
         *
         * What it does:
         * Returns the stored source line captured for this error payload.
         */
        int GetRuntimeLine() const noexcept;

        /**
         * Address: 0x00940450 (FUN_00940450)
         *
         * What it does:
         * Returns the raw throw-site runtime text pointer (SSO/heap aware).
         */
        const char* GetRuntimeMessage() const noexcept;

    public:
        msvc8::string runtimeMessage_; // +0x0C
        int line_ = 0;                // +0x28
        msvc8::string message_;        // +0x2C
    };

    static_assert(offsetof(Error, runtimeMessage_) == 0x0C, "Error::runtimeMessage_ offset must be 0x0C");
    static_assert(offsetof(Error, line_) == 0x28, "Error::line_ offset must be 0x28");
    static_assert(offsetof(Error, message_) == 0x2C, "Error::message_ offset must be 0x2C");
    static_assert(sizeof(Error) == 0x48, "Error size must be 0x48");
}
