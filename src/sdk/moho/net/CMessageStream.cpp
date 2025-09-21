#include "CMessageStream.h"

#include "CMessage.h"
using namespace moho;

CMessageStream::~CMessageStream() = default;

size_t CMessageStream::VirtTell(Mode mode) {
	throw UnsupportedOperation();
}

size_t CMessageStream::VirtSeek(Mode mode, SeekOrigin orig, size_t pos) {
	throw UnsupportedOperation();
}

size_t CMessageStream::VirtRead(char* buff, const size_t len) {
    if (!buff || !mReadHead || !mReadEnd) {
        return 0;
    }

    // Compute available bytes without crossing end
    const size_t avail = static_cast<size_t>(mReadEnd - mReadHead);
    const size_t toCopy = std::min(len, avail);

    // Fast path: nothing to read
    if (toCopy == 0) {
        return 0;
    }

    // Copy and advance head
    std::memcpy(buff, mReadHead, toCopy);
    mReadHead += toCopy;
    return toCopy;
}

size_t CMessageStream::VirtReadNonBlocking(char* buf, const size_t len) {
    if (!buf || len == 0) {
        return 0;
    }
    return VirtRead(buf, len);
}

void CMessageStream::VirtUnGetByte(int i) {
	throw UnsupportedOperation();
}

bool CMessageStream::VirtAtEnd() {
    return mReadHead == mReadEnd;
}

void CMessageStream::VirtWrite(const char* data, const size_t size) {
    if (!mWriteStart) {
        throw std::logic_error("Can't write to a read-only message.");
    }
    if (!data || size == 0) return;

    // In-place write within current window
    const size_t windowLeft = static_cast<size_t>(mWriteEnd - mWriteHead);
    const size_t inPlace = std::min(windowLeft, size);
    if (inPlace) {
        std::memcpy(mWriteHead, data, inPlace);
        mWriteHead += inPlace;
    }

    // Overflow => append + rebind
    const size_t overflow = size - inPlace;
    if (overflow == 0) return;

    // preserve offsets
    const size_t readOff = static_cast<size_t>(mReadHead - mReadStart);
    const size_t writeOff = static_cast<size_t>(mWriteHead - mWriteStart);

    // Append remainder to message (original signature uses (char*, int))
    // Assumes Append updates header size and possibly reallocates mBuf
    msg_->Append(data + inPlace, static_cast<int>(overflow));

    // Rebind to the (possibly) new buffer; write head gets +overflow
    RebindToMessagePreserve(readOff, writeOff + overflow);
}

std::pair<char*, char*> CMessageStream::PayloadWindow(CMessage& m) noexcept {
    // base pointer to entire message buffer
    // safe even for SBO: &mBuf[0] is contiguous storage
    char* base = &m.mBuff[0];

    // total size from header (LE), consistent with your GetSize()
    const unsigned total = m.GetSize();
    const unsigned payload = (total >= 3u) ? (total - 3u) : 0u;

    char* beg = base + 3;
    char* end = beg + payload;
    return { beg, end };
}

void CMessageStream::RebindToMessagePreserve(const size_t readOff, const size_t writeOffPlus) noexcept {
    auto [beg, end] = PayloadWindow(*msg_);

    mReadStart = beg;
    mWriteStart = beg;
    mReadEnd = end;
    mWriteEnd = end;

    // clamp offsets to bounds defensively
    const size_t payloadSize = static_cast<size_t>(end - beg);
    const size_t clampedRead = std::min(readOff, payloadSize);
    const size_t clampedWrite = std::min(writeOffPlus, payloadSize);

    mReadHead = beg + clampedRead;
    mWriteHead = beg + clampedWrite;
}
