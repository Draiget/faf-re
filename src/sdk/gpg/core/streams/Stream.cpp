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
    return this->VirtRead(buf, len);
}

// 0x00956FD0
void Stream::VirtUnGetByte(int) {
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

// 0x0043D130
void Stream::Write(const char* buf, size_t size) {
    if (size > this->LeftToWrite()) {
        this->VirtWrite(buf, size);
    } else {
        memcpy(this->mWriteHead, buf, size);
        this->mWriteHead += size;
    }
}

// 0x00955760
bool Stream::Close(Mode access) {
    this->VirtClose(access);
    return true;
}

// 0x0043D100
size_t Stream::Read(char* buf, size_t size) {
    if (size > this->LeftToRead()) {
        size = this->VirtRead(buf, size);
    } else if (size) {
        memcpy(buf, this->mReadHead, size);
        this->mReadHead += size;
    }
    return size;
}
