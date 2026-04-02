#include "BinaryReader.h"

#include <cstdint>
#include <cstring>
#include <string>

#include "Stream.h"
using namespace gpg;

/**
 * Address: 0x0043D180 (FUN_0043D180)
 *
 * What it does:
 * Constructs PrematureEOF runtime_error payload ("Premature EOF").
 */
BinaryReader::PrematureEOF::PrematureEOF()
    : std::runtime_error("Premature EOF")
{
}

/**
 * Address: 0x0043D270 (FUN_0043D270)
 * Demangled: gpg::BinaryReader::PrematureEOF::dtr
 *
 * What it does:
 * Destroys PrematureEOF exception payload.
 */
BinaryReader::PrematureEOF::~PrematureEOF() noexcept = default;

/**
 * Address: 0x0043D210 (FUN_0043D210)
 *
 * What it does:
 * Reads exactly `size` bytes or throws PrematureEOF on underrun.
 */
void BinaryReader::Read(char* buf, const size_t size) const
{
    Stream* const stream = mStream;
    const char* const readHead = stream->mReadHead;
    const auto available = static_cast<size_t>(stream->mReadEnd - readHead);

    if (size > available) {
        const size_t got = stream->VirtRead(buf, size);
        if (got != size) {
            throw PrematureEOF();
        }
    } else if (size != 0) {
        std::memcpy(buf, readHead, size);
        stream->mReadHead += size;
    }
}

/**
 * Address: 0x00445590 (FUN_00445590)
 *
 * What it does:
 * Reads one 32-bit integer and returns it by value.
 */
int BinaryReader::ReadInt32() const
{
    int value = 0;
    Read(reinterpret_cast<char*>(&value), sizeof(value));
    return value;
}

/**
 * Address: 0x004CCDD0 (FUN_004CCDD0)
 *
 * What it does:
 * Reads one NUL-terminated string from stream bytes.
 */
void BinaryReader::ReadString(msvc8::string* out) const
{
    std::string ownedValue{};
    Stream* const stream = mStream;

    std::uint8_t nextByte = 0;
    while (true) {
        if (stream->mReadHead == stream->mReadEnd) {
            if (stream->VirtRead(reinterpret_cast<char*>(&nextByte), 1U) < 1U) {
                out->assign_owned(ownedValue);
                return;
            }
        } else {
            nextByte = static_cast<std::uint8_t>(*stream->mReadHead);
            ++stream->mReadHead;
        }

        if (nextByte == 0U) {
            out->assign_owned(ownedValue);
            break;
        }

        ownedValue.push_back(static_cast<char>(nextByte));
    }
}

/**
 * Address: <synthetic host-build helper>
 *
 * What it does:
 * Reads one 32-bit length-prefixed byte string into legacy string storage.
 */
void BinaryReader::ReadLengthPrefixedString(msvc8::string* out) const
{
    if (out == nullptr) {
        return;
    }

    std::int32_t byteCount = 0;
    ReadExact(byteCount);
    if (byteCount < 0) {
        throw std::runtime_error("InvalidFormat");
    }

    std::string ownedValue(static_cast<std::size_t>(byteCount), '\0');
    if (byteCount > 0) {
        Read(ownedValue.data(), static_cast<std::size_t>(byteCount));
    }

    out->assign_owned(ownedValue);
}
