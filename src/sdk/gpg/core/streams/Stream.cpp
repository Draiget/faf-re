#include "Stream.h"
using namespace gpg;


// 0x00956E40
Stream::UnsupportedOperation::UnsupportedOperation()
    : std::logic_error{ std::string{"Unsupported stream operation."} }
{}

// 0x00956F50
size_t Stream::VirtTell(Mode) {
    throw UnsupportedOperation{};
}

// 0x00956F90
size_t Stream::VirtSeek(Mode, SeekOrigin, size_t) {
    throw UnsupportedOperation{};
}

// 0x00956FB0
size_t Stream::VirtRead(char*, size_t) {
    throw UnsupportedOperation{};
}

// 0x00956DE0
size_t Stream::VirtReadNonBlocking(char* buf, size_t len) {
    return VirtRead(buf, len);
}

// 0x00956FD0
void Stream::VirtUnGetByte(int unknown) {
    throw UnsupportedOperation{};
}

// 0x00956DF0
bool Stream::VirtAtEnd() {
    return false;
}

// 0x00956FF0
void Stream::VirtWrite(const char* data, size_t size) {
    throw UnsupportedOperation{};
}

// 0x00956E00
void Stream::VirtFlush() {}

// 0x00956E10
void Stream::VirtClose(Mode) {}

void Stream::Write(const msvc8::string& str) {
    Write(str.c_str(), str.size() + 1);
}

// 0x0043D130
void Stream::Write(const char* buf, const size_t size) {
    if (size > LeftToWrite()) {
        VirtWrite(buf, size);
        return;
    }

    memcpy(mWriteHead, buf, size);
    mWriteHead += size;
}

// 0x004CCD80
void Stream::Write(const char* buf) {
    const auto len = strlen(buf) + 1;
    Write(buf, len);
}

// 0x00955760
bool Stream::Close(Mode access) {
    VirtClose(access);
    return true;
}

// 0x0043D100
size_t Stream::Read(char* buf, size_t size) {
    if (size > BytesRead()) {
        size = VirtRead(buf, size);
    } else if (size) {
        memcpy(buf, mReadHead, size);
        mReadHead += size;
    }
    return size;
}

size_t Stream::ReadNonBlocking(char* buf, size_t size) {
    if (size > BytesRead()) {
        size = VirtReadNonBlocking(buf, size);
    } else if (size) {
        memcpy(buf, mReadHead, size);
        mReadHead += size;
    }
    return size;
}

// 0x004CCDEC
int8_t Stream::GetByte() {
    if (mReadHead != mReadEnd) {
        const unsigned char c = static_cast<unsigned char>(*mReadHead);
        ++mReadHead;
        return static_cast<int8_t>(c);
    }

    unsigned char b = 0;
    const size_t got = VirtRead(reinterpret_cast<char*>(&b), 1u);
    if (got == 1u) {
        return static_cast<int8_t>(b);
    }

    return -1;
}
