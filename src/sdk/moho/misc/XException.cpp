#include "XException.h"

#include <cstdint>

#include "legacy/containers/String.h"

namespace moho
{
    std::uint32_t PLAT_GetCallStack(void* contextRecord, std::uint32_t maxFrames, std::uint32_t* outFrames);
    msvc8::string PLAT_FormatCallstack(std::int32_t firstFrame, std::int32_t endFrame, const std::uint32_t* frames);
} // namespace moho

using namespace moho;

XException::XException(const char* const message, const bool captureCallstack)
    : std::runtime_error(message),
      mCallstack{},
      mTopStack(0),
      mMsg()
{
    if (captureCallstack) {
        mTopStack = moho::PLAT_GetCallStack(
            nullptr,
            static_cast<std::uint32_t>(mCallstack.size()),
            mCallstack.data());
    }
}

/**
 * Address: 0x004052A0 (FUN_004052A0)
 * Mangled: ??0XException@Moho@@QAE@@Z
 *
 * What it does:
 * Builds runtime_error payload and captures current callstack snapshot.
 */
XException::XException(const char* const message)
    : XException(message, true)
{
}

/**
 * Address: 0x0040FCD0 (FUN_0040FCD0, sub_40FCD0)
 *
 * What it does:
 * Copies runtime_error payload plus callstack/message lanes.
 */
XException::XException(const XException& other)
    : std::runtime_error(other)
    , mCallstack(other.mCallstack)
    , mTopStack(other.mTopStack)
    , mMsg(other.mMsg)
{
}

/**
 * Address: 0x00405240 (FUN_00405240)
 * Deleting owner: 0x00405370 (FUN_00405370)
 *
 * What it does:
 * Releases cached formatted message payload and tears down runtime_error state.
 */
XException::~XException() noexcept = default;

/**
 * Address: 0x00405470 (FUN_00405470)
 * Mangled: ?what@XException@Moho@@UBEPBDXZ
 *
 * What it does:
 * Lazily builds and returns cached error text, appending original callstack text when available.
 */
const char* XException::what() const noexcept
{
    if (mMsg.empty()) {
        mMsg = std::runtime_error::what();
        if (mTopStack != 0) {
            mMsg.append("\n\nOriginal callstack:\n\n");
            const msvc8::string formatted =
                moho::PLAT_FormatCallstack(0, static_cast<std::int32_t>(mTopStack), mCallstack.data());
            mMsg.append(formatted.c_str());
        }
    }

    return mMsg.c_str();
}
