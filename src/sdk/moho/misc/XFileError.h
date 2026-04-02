#pragma once

#include <cstdint>
#include <string>

#include "XException.h"

namespace moho
{
    /**
     * VFTABLE: 0x00E008D8
     * COL:  0x00E5D6E4
     */
    class XFileError : public XException
    {
    public:
        /**
         * Address: 0x00405390 (FUN_00405390)
         * Mangled: ??0XFileError@Moho@@QAE@ABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@PAII@Z
         *
         * What it does:
         * Builds file-error exception payload and adopts provided callstack snapshot.
         */
        XFileError(const std::string& message, const std::uint32_t* callstack, std::uint32_t frameCount);

        /**
         * Address: 0x0040FCB0 (FUN_0040FCB0, Moho::XFileError::XFileError)
         *
         * What it does:
         * Copy-constructs file error payload and inherited exception lanes.
         */
        XFileError(const XFileError& other);

        /**
         * Address: 0x0040FAE0 (FUN_0040FAE0, Moho::XFileError::~XFileError)
         *
         * What it does:
         * Destroys file-error payload and base exception state.
         */
        ~XFileError() noexcept override;
    };
} // namespace moho
