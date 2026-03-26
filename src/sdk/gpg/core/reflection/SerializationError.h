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
        explicit SerializationError(const char* message)
            : std::runtime_error(message ? message : "") {
        }

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

