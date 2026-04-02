#pragma once

#include <stdexcept>

namespace gpg
{
    /**
     * VFTABLE: 0x00D41608
     * COL:  0x00E5D0D0
     */
    class BadRefCast : public std::runtime_error
    {
    public:
        /**
         * Address: 0x004089D0 (FUN_004089D0)
         * Mangled: ??0BadRefCast@gpg@@Z
         *
         * What it does:
         * Builds the bad-reference-cast exception payload from a C-string message.
         */
        explicit BadRefCast(const char* message);

        /**
         * Address: 0x008DD300 (FUN_008DD300, ??0BadRefCast@gpg@@QAE@@Z)
         *
         * What it does:
         * Builds one formatted cast failure payload:
         * `prefix_or_default + fromType + " to " + toType`.
         */
        BadRefCast(const char* prefix, const char* fromType, const char* toType);

        /**
         * Address: 0x0040CC30 (FUN_0040CC30)
         * Mangled: ??0BadRefCast@gpg@@QAE@ABVruntime_error@std@@@Z
         *
         * What it does:
         * Clones a runtime_error payload into BadRefCast and restores BadRefCast vftable.
         */
        explicit BadRefCast(const std::runtime_error& error);

        /**
         * Address: 0x00408A70 (FUN_00408A70)
         * Mangled: ??1BadRefCast@gpg@@UAE@XZ
         *
         * What it does:
         * Destroys the bad-reference-cast runtime_error payload.
         */
        ~BadRefCast() noexcept override;
    };
} // namespace gpg
