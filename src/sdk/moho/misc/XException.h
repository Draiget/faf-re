#pragma once

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>

namespace moho
{
    /**
     * VFTABLE: 0x00E00020
     * COL:  0x00E5C84C
     */
    class XException : public std::runtime_error
    {
    public:
        /**
         * Address: 0x00405240 (FUN_00405240)
         * Deleting owner: 0x00405370 (FUN_00405370)
         *
         * What it does:
         * Releases cached formatted message payload and tears down runtime_error state.
         */
        ~XException() noexcept override;

        /**
         * Address: 0x004052A0 (FUN_004052A0)
         * Mangled: ??0XException@Moho@@QAE@@Z
         *
         * What it does:
         * Builds runtime_error payload and captures current callstack snapshot.
         */
        explicit XException(const char* message);

        /**
         * Address: 0x0040FCD0 (FUN_0040FCD0, sub_40FCD0)
         *
         * What it does:
         * Copies runtime_error payload, callstack lanes, and cached message.
         */
        XException(const XException& other);

        /**
         * Address: 0x00405470 (FUN_00405470)
         * Mangled: ?what@XException@Moho@@UBEPBDXZ
         *
         * What it does:
         * Lazily builds and returns cached error text, appending original callstack text when available.
         */
        [[nodiscard]]
        const char* what() const noexcept override;

    protected:
        XException(const char* message, bool captureCallstack);

        std::array<std::uint32_t, 32> mCallstack{};
        std::uint32_t mTopStack{ 0 };
        mutable std::string mMsg{};
    };
} // namespace moho
