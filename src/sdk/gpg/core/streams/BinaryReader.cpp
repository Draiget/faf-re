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
 * Address: 0x006E58A0 (FUN_006E58A0)
 *
 * What it does:
 * Reads one fixed 12-byte payload lane and returns the destination pointer.
 */
[[maybe_unused]] void* ReadThreeDwordLaneFromBinaryReader(BinaryReader* const reader, void* const out)
{
    reader->Read(static_cast<char*>(out), 12u);
    return out;
}

/**
 * Address: 0x006E5950 (FUN_006E5950)
 *
 * What it does:
 * Reads `wordCount` dwords (`wordCount * 4` bytes) into caller storage.
 */
[[maybe_unused]] void ReadDwordArrayLanePrimary(
    BinaryReader* const reader,
    const int wordCount,
    void* const out
)
{
    reader->Read(static_cast<char*>(out), static_cast<std::size_t>(wordCount) * sizeof(std::uint32_t));
}

/**
 * Address: 0x006E5960 (FUN_006E5960)
 *
 * What it does:
 * Reads one fixed 16-byte payload lane and returns the destination pointer.
 */
[[maybe_unused]] void* ReadFourDwordLaneFromBinaryReader(BinaryReader* const reader, void* const out)
{
    reader->Read(static_cast<char*>(out), 16u);
    return out;
}

/**
 * Address: 0x006E5980 (FUN_006E5980)
 *
 * What it does:
 * Secondary adapter that reads `wordCount` dwords (`wordCount * 4` bytes)
 * into caller storage.
 */
[[maybe_unused]] void ReadDwordArrayLaneSecondary(
    BinaryReader* const reader,
    const int wordCount,
    void* const out
)
{
    reader->Read(static_cast<char*>(out), static_cast<std::size_t>(wordCount) * sizeof(std::uint32_t));
}

/**
 * Address: 0x00540A10 (FUN_00540A10, gpg::BinaryReader::ReadInt)
 *
 * int *
 *
 * IDA signature:
 * int * __usercall gpg::BinaryReader::ReadInt@<eax>(gpg::BinaryReader *this@<eax>, int *outValue@<ecx>);
 *
 * What it does:
 * Reads one 32-bit integer into `outValue`, preferring the stream's resident
 * read window and throwing `PrematureEOF` on short reads.
 */
int* BinaryReader::ReadInt(int* const outValue) const
{
    if (outValue == nullptr) {
        throw PrematureEOF();
    }

    *outValue = 0;

    Stream* const stream = mStream;
    const auto available = static_cast<std::size_t>(stream->mReadEnd - stream->mReadHead);
    if (available < sizeof(*outValue)) {
        const std::size_t readCount = stream->VirtRead(reinterpret_cast<char*>(outValue), sizeof(*outValue));
        if (readCount != sizeof(*outValue)) {
            throw PrematureEOF();
        }
        return outValue;
    }

    std::memcpy(outValue, stream->mReadHead, sizeof(*outValue));
    stream->mReadHead += sizeof(*outValue);
    return outValue;
}

/**
 * Address: 0x00445590 (FUN_00445590)
 *
 * What it does:
 * Reads one 32-bit integer and returns it by value via `ReadInt`.
 */
int BinaryReader::ReadInt32() const
{
    int value = 0;
    (void)ReadInt(&value);
    return value;
}

/**
 * Address: 0x004D4DC0 (FUN_004D4DC0, gpg::BinaryReader::ReadChar)
 *
 * What it does:
 * Reads one byte from stream input and returns it as unsigned char.
 */
std::uint8_t BinaryReader::ReadChar() const
{
    std::uint8_t value = 0;
    Read(reinterpret_cast<char*>(&value), 1U);
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
