#pragma once

#include <stdexcept>

namespace gpg
{
    /**
     * VFTABLE: 0x00D44AC4
     * COL:  0x00E5CBC8
     */
    class SerializationError : public std::runtime_error
    {
    public:
        /**
         * Address: 0x004066B0 (FUN_004066B0)
         * Mangled: ??0SerializationError@gpg@@Z
         *
         * What it does:
         * Builds the serialization exception payload from a C-string message.
         */
        explicit SerializationError(const char* message);

        explicit SerializationError(const std::runtime_error& error)
            : std::runtime_error(error.what()) {
        }

        /**
         * Address: 0x00406770 (FUN_00406770)
         * Demangled: gpg::SerializationError::dtr
         *
         * What it does:
         * Destroys runtime_error-backed serialization exception state.
         */
        ~SerializationError() noexcept override;
    };
} // namespace gpg
