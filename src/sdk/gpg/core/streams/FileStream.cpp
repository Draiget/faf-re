#include "FileStream.h"

#include <cerrno>
#include <cstring>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"

using namespace gpg;

namespace
{
    constexpr DWORD kCreationDispositionByAttribute[8] = {
        CREATE_ALWAYS,
        CREATE_NEW,
        OPEN_ALWAYS,
        OPEN_EXISTING,
        TRUNCATE_EXISTING,
        0,
        0,
        0,
    };

    constexpr DWORD kSeekMoveMethod[3] = {
        FILE_BEGIN,
        FILE_CURRENT,
        FILE_END,
    };

    constexpr const char* kReadModeError = "Attempt to read from a file that isn't open for input.";
    constexpr const char* kWriteModeError = "Attempt to write to a file that isn't open for output.";
}

/**
 * Address: 0x00955890 (FUN_00955890)
 *
 * What it does:
 * Builds a runtime_error payload from a Win32/system error code and stores that code in `mMsg`.
 */
FileStream::IOError::IOError(const DWORD messageId)
    : std::runtime_error(BuildMessage(messageId)), mMsg(messageId)
{
}

/**
 * Address: 0x00955900 (FUN_00955900)
 * Deleting owner: 0x00955940 (FUN_00955940)
 * Demangled: gpg::FileStream::IOError::dtr
 *
 * What it does:
 * Destroys IOError runtime_error payload.
 */
FileStream::IOError::~IOError() noexcept = default;

/**
 * Address: 0x00957950 (FUN_00957950, gpg::GetWin32ErrorString)
 *
 * What it does:
 * Resolves one Win32 system-message id to UTF-8 text via `FormatMessageW`.
 * Falls back to `"Unknown error 0x%08x"` when lookup fails.
 */
std::string FileStream::IOError::BuildMessage(const DWORD messageId)
{
    LPWSTR systemText = nullptr;
    const DWORD flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER;
    const int length = static_cast<int>(
        ::FormatMessageW(
            flags,
            nullptr,
            messageId,
            0x400u,
            reinterpret_cast<LPWSTR>(&systemText),
            0,
            nullptr));

    if (length <= 0 || systemText == nullptr) {
        const msvc8::string unknownText = gpg::STR_Printf("Unknown error 0x%08x", messageId);
        return std::string(unknownText.c_str());
    }

    const msvc8::string utf8Message = gpg::STR_WideToUtf8(systemText);
    ::LocalFree(systemText);
    return std::string(utf8Message.c_str());
}

/**
 * Address: 0x009557E0 (FUN_009557E0)
 * Deleting owner: 0x00955870 (FUN_00955870)
 *
 * What it does:
 * Restores FileStream vftable, closes active lanes via Stream close wrapper, then tears down owned buffer state.
 */
FileStream::~FileStream()
{
    CloseNoThrow(mAccessKind);
}

/**
 * Address: 0x00955BD0 (FUN_00955BD0)
 *
 * What it does:
 * Constructs FileStream with a freshly allocated internal `MemBuffer<char>` and opens the file.
 */
FileStream::FileStream(const char* const filename, const Mode accessKind, const unsigned int attributes, const int buffSize)
    : Stream(),
      mHandle(nullptr),
      mAccessKind(ModeNone),
      mBuff(AllocMemBuffer(static_cast<unsigned int>(buffSize)))
{
    DoOpen(filename, accessKind, attributes);
}

/**
 * Address: 0x00955C50 (FUN_00955C50)
 *
 * What it does:
 * Constructs FileStream from a caller-provided `MemBuffer<char>` view and opens the file.
 */
FileStream::FileStream(const char* const filename, const Mode accessKind, const unsigned int attributes, const MemBuffer<char>& buffer)
    : Stream(),
      mHandle(nullptr),
      mAccessKind(ModeNone),
      mBuff(buffer)
{
    DoOpen(filename, accessKind, attributes);
}

/**
 * Address: 0x00955990 (FUN_00955990)
 *
 * What it does:
 * Converts UTF-8 path to wide string, opens file handle with attribute-driven Win32 flags, and stores access mode.
 */
void FileStream::DoOpen(const char* const file, const Mode accessKind, const unsigned int attributes)
{
    const std::wstring widePath = STR_Utf8ToWide(file);
    const auto modeValue = static_cast<unsigned int>(accessKind);
    const DWORD desiredAccess = ((modeValue * 4U) | (modeValue & 2U)) << 29;
    const DWORD shareMode = (attributes >> 3U) & 3U;
    const DWORD creation = kCreationDispositionByAttribute[attributes & 7U];
    const DWORD flagsAndAttributes = FILE_ATTRIBUTE_NORMAL | ((attributes & 0x20U) << 21U);

    mHandle = CreateFileW(
        widePath.c_str(),
        desiredAccess,
        shareMode,
        nullptr,
        creation,
        flagsAndAttributes,
        nullptr);

    if (mHandle == INVALID_HANDLE_VALUE) {
        throw IOError(GetLastError());
    }

    mAccessKind = accessKind;
}

/**
 * Address: 0x00955CE0 (FUN_00955CE0)
 *
 * What it does:
 * Returns current logical stream position adjusted by unread/read-buffer and pending-write windows.
 */
std::uint64_t FileStream::VirtTell(const Mode mode)
{
    if ((mode & mAccessKind) == 0) {
        throw std::invalid_argument("Invalid mode for Tell()");
    }

    LARGE_INTEGER distance{};
    LARGE_INTEGER filePointer{};
    if (!SetFilePointerEx(mHandle, distance, &filePointer, FILE_CURRENT)) {
        throw IOError(GetLastError());
    }

    LONGLONG logicalPosition = filePointer.QuadPart;
    if (mReadEnd != mReadHead) {
        logicalPosition -= static_cast<LONGLONG>(mReadEnd - mReadHead);
    }
    if (mWriteHead != mWriteStart) {
        logicalPosition += static_cast<LONGLONG>(mWriteHead - mWriteStart);
    }

    return static_cast<std::uint64_t>(logicalPosition);
}

/**
 * Address: 0x00955DF0 (FUN_00955DF0)
 *
 * What it does:
 * Flushes pending write bytes, seeks by origin/mode with read-window compensation, and clears local windows.
 */
std::uint64_t FileStream::VirtSeek(const Mode mode, const SeekOrigin orig, const std::int64_t pos)
{
    if ((mode & mAccessKind) == 0) {
        throw std::invalid_argument("Invalid mode for Seek()");
    }

    if (orig > OriginEnd) {
        throw std::invalid_argument("Invalid origin for Seek()");
    }

    if (mWriteHead != mWriteStart) {
        DoWrite(mWriteStart, static_cast<size_t>(mWriteHead - mWriteStart));
    }

    LARGE_INTEGER distance{};
    distance.QuadPart = static_cast<LONGLONG>(pos);
    if (mReadHead != mReadEnd && orig == OriginCurr) {
        distance.QuadPart -= static_cast<LONGLONG>(mReadEnd - mReadHead);
    }

    LARGE_INTEGER filePointer{};
    const auto originIndex = static_cast<unsigned int>(orig);
    if (!SetFilePointerEx(mHandle, distance, &filePointer, kSeekMoveMethod[originIndex])) {
        throw IOError(GetLastError());
    }

    mReadStart = nullptr;
    mReadHead = nullptr;
    mReadEnd = nullptr;
    mWriteStart = nullptr;
    mWriteHead = nullptr;
    mWriteEnd = nullptr;

    return static_cast<std::uint64_t>(filePointer.QuadPart);
}

/**
 * Address: 0x00955F80 (FUN_00955F80)
 *
 * What it does:
 * Reads up to `len` bytes using inline read window first, then refill/direct OS reads through DoRead.
 */
size_t FileStream::VirtRead(char* buf, size_t len)
{
    if ((mAccessKind & ModeReceive) == 0) {
        throw std::runtime_error(kReadModeError);
    }

    size_t remaining = len;
    size_t copied = 0;
    size_t available = static_cast<size_t>(mReadEnd - mReadHead);

    if (available >= remaining) {
        std::memcpy(buf, mReadHead, remaining);
        mReadHead += remaining;
        return remaining;
    }

    while (true)
    {
        if (available != 0) {
            std::memcpy(buf, mReadHead, available);
            mReadHead += available;
            copied += available;
            buf += available;
            remaining -= available;
        }

        const size_t capacity = mBuff.Size();
        if (remaining < capacity) {
            const size_t fetched = DoRead(mBuff.begin(), capacity);
            if (fetched == 0) {
                return copied;
            }

            char* const begin = mBuff.begin();
            mReadHead = begin;
            mReadStart = begin;
            mReadEnd = begin + fetched;
            available = static_cast<size_t>(mReadEnd - mReadHead);
            if (available >= remaining) {
                std::memcpy(buf, mReadHead, remaining);
                mReadHead += remaining;
                return copied + remaining;
            }
            continue;
        }

        const size_t directRead = DoRead(buf, remaining);
        if (directRead == 0) {
            return copied;
        }

        copied += directRead;
        buf += directRead;
        remaining -= directRead;
        available = static_cast<size_t>(mReadEnd - mReadHead);
        if (available >= remaining) {
            std::memcpy(buf, mReadHead, remaining);
            mReadHead += remaining;
            return copied + remaining;
        }
    }
}

/**
 * Address: 0x009560C0 (FUN_009560C0)
 *
 * What it does:
 * Checks end-of-stream by consuming buffered bytes first and issuing one refill read when empty.
 */
bool FileStream::VirtAtEnd()
{
    if ((mAccessKind & ModeReceive) == 0) {
        throw std::runtime_error(kReadModeError);
    }

    if (mReadHead != mReadEnd) {
        return false;
    }

    const size_t fetched = DoRead(mBuff.begin(), mBuff.Size());
    char* const begin = mBuff.begin();
    mReadHead = begin;
    mReadStart = begin;
    mReadEnd = begin + fetched;
    return fetched == 0;
}

/**
 * Address: 0x00956180 (FUN_00956180)
 *
 * What it does:
 * Writes bytes through inline write window and flushes/direct-writes when needed.
 */
void FileStream::VirtWrite(const char* data, size_t size)
{
    if ((mAccessKind & ModeSend) == 0) {
        throw std::runtime_error(kWriteModeError);
    }

    char* writeHead = mWriteHead;
    size_t available = static_cast<size_t>(mWriteEnd - writeHead);
    if (size > available) {
        const size_t capacity = mBuff.Size();
        if (available != 0 && (size - available) < capacity) {
            std::memcpy(writeHead, data, available);
            mWriteHead += available;
            data += available;
            size -= available;
        }

        DoWrite(mWriteStart, static_cast<size_t>(mWriteHead - mWriteStart));
        if (size >= capacity) {
            DoWrite(data, size);
            return;
        }

        writeHead = mWriteHead;
    }

    std::memcpy(writeHead, data, size);
    mWriteHead += size;
}

/**
 * Address: 0x00956290 (FUN_00956290)
 *
 * What it does:
 * Flushes any pending write-window bytes to the backing file handle.
 */
void FileStream::VirtFlush()
{
    if ((mAccessKind & ModeSend) == 0) {
        throw std::runtime_error(kWriteModeError);
    }

    if (mWriteHead != mWriteStart) {
        DoWrite(mWriteStart, static_cast<size_t>(mWriteHead - mWriteStart));
    }
}

/**
 * Address: 0x00956320 (FUN_00956320)
 *
 * What it does:
 * Closes requested read/write lanes, releases the OS handle, and resets owned memory buffer state.
 */
void FileStream::VirtClose(const Mode mode)
{
    if ((mAccessKind & mode & ModeSend) != 0) {
        if (mWriteHead != mWriteStart) {
            DoWrite(mWriteStart, static_cast<size_t>(mWriteHead - mWriteStart));
        }

        mAccessKind = static_cast<Mode>(mAccessKind & ~ModeSend);
        mWriteStart = nullptr;
        mWriteHead = nullptr;
        mWriteEnd = nullptr;
    }

    if ((mode & mAccessKind & ModeReceive) != 0) {
        mAccessKind = static_cast<Mode>(mAccessKind & ~ModeReceive);
        mReadStart = nullptr;
        mReadHead = nullptr;
        mReadEnd = nullptr;
    }

    if (mHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(mHandle);
        mHandle = INVALID_HANDLE_VALUE;
        mBuff.Reset();
    }
}

/**
 * Address: 0x00955A80 (FUN_00955A80)
 *
 * What it does:
 * Flushes pending read-window offset compensation and writes bytes to the file handle.
 */
void FileStream::DoWrite(const void* const buffer, const size_t bytes)
{
    if (mReadHead != mReadEnd) {
        LARGE_INTEGER distance{};
        distance.QuadPart = static_cast<LONGLONG>(mReadHead - mReadEnd);
        if (!SetFilePointerEx(mHandle, distance, nullptr, FILE_CURRENT)) {
            throw IOError(GetLastError());
        }
    }

    mReadStart = nullptr;
    mReadHead = nullptr;
    mReadEnd = nullptr;

    const auto expectedBytes = static_cast<DWORD>(bytes);
    if (expectedBytes != 0) {
        DWORD written = 0;
        if (!WriteFile(mHandle, buffer, expectedBytes, &written, nullptr)) {
            int* const runtimeErrno = _errno();
            const DWORD errorCode = runtimeErrno ? static_cast<DWORD>(*runtimeErrno) : GetLastError();
            throw IOError(errorCode);
        }

        if (written != expectedBytes) {
            HandleAssertFailure(
                "written == bytes",
                288,
                "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\streams\\FileStream.cpp");
        }
    }

    char* const begin = mBuff.begin();
    mWriteStart = begin;
    mWriteHead = begin;
    mWriteEnd = mBuff.end();
}

/**
 * Address: 0x00955B60 (FUN_00955B60)
 *
 * What it does:
 * Flushes pending write window if needed, then reads bytes from file handle into caller buffer.
 */
size_t FileStream::DoRead(void* const buffer, const size_t bytes)
{
    if (mWriteHead != mWriteStart) {
        DoWrite(mWriteStart, static_cast<size_t>(mWriteHead - mWriteStart));
    }

    mWriteStart = nullptr;
    mWriteHead = nullptr;
    mWriteEnd = nullptr;

    DWORD read = 0;
    if (!ReadFile(mHandle, buffer, static_cast<DWORD>(bytes), &read, nullptr)) {
        throw IOError(GetLastError());
    }

    return read;
}
