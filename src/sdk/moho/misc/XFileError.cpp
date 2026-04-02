#include "XFileError.h"

#include <algorithm>
#include <cstring>

using namespace moho;

/**
 * Address: 0x00405390 (FUN_00405390)
 * Mangled: ??0XFileError@Moho@@QAE@ABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@PAII@Z
 *
 * What it does:
 * Builds file-error exception payload and adopts provided callstack snapshot.
 */
XFileError::XFileError(const std::string& message, const std::uint32_t* const callstack, const std::uint32_t frameCount)
    : XException(message.c_str(), false)
{
    mTopStack = frameCount;

    if (mTopStack != 0) {
        const std::uint32_t copyCount =
            std::min<std::uint32_t>(mTopStack, static_cast<std::uint32_t>(mCallstack.size()));
        std::memcpy(mCallstack.data(), callstack, copyCount * sizeof(std::uint32_t));
    }
}

/**
 * Address: 0x0040FCB0 (FUN_0040FCB0, Moho::XFileError::XFileError)
 *
 * What it does:
 * Copy-constructs file-error payload and inherited exception lanes.
 */
XFileError::XFileError(const XFileError& other)
    : XException(other)
{
}

/**
 * Address: 0x0040FAE0 (FUN_0040FAE0, Moho::XFileError::~XFileError)
 *
 * What it does:
 * Destroys file-error payload and base exception state.
 */
XFileError::~XFileError() noexcept = default;
