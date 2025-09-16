#include "CMessage.h"

#include <stdexcept>
#include <string>

#include "gpg/core/streams/Stream.h"
using namespace moho;

CMessage::CMessage(int size, const char type) {
    size += 3;
    constexpr char fill = 0;
    mBuf.Resize(size, fill);
    SetSize(size);
    SetType(type);
}
int CMessage::GetMessageSize() {
    int size = this->GetSize();
    if (size >= 3) {
        size -= 3;
    }
    return size;
}

unsigned int CMessage::Append(const char* ptr, const size_t size) {
    if (this->mBuf.Size() + size > 0x10000) {
        throw std::runtime_error{ std::string{"Message too large"} };
    }

    this->mBuf.InsertAt(this->mBuf.end_, ptr, &ptr[size]);

    const auto targetSize = this->mBuf.Size();
    this->SetSize(targetSize);
    return targetSize;
}

bool CMessage::ReadMessage(gpg::Stream* stream) {
	constexpr char fill = 0;
    this->mBuf.Resize(3, fill);
    if (stream->Read(this->mBuf.start_, 3) != 3) {
        return false;
    }
	const size_t size = this->GetSize();
    if (size < 3) {
        return false;
    }
    if (size == 3) {
        return true;
    }
    this->mBuf.Resize(size - 3, fill);
    return stream->Read(&this->mBuf[3], size - 3) == size - 3;
}

bool CMessage::Read(gpg::Stream* stream) {
    if (!this->HasReadLength()) {
        if (this->mBuf.Size() == 0) {
	        constexpr char fill = 0;
            this->mBuf.Resize(3, fill);
        }
        this->mPos += static_cast<int>(stream->ReadNonBlocking(&this->mBuf[this->mPos], 3 - this->mPos));
        if (!this->HasReadLength()) {
            return false;
        }
    }
    const int newSize = this->GetSize();
    if (newSize < 3) {
        return false;
    }
    if (newSize == this->mPos) {
        return true;
    }
    constexpr char fill = 0;
    this->mBuf.Resize(newSize, fill);
    this->mPos += static_cast<int>(stream->ReadNonBlocking(&this->mBuf[this->mPos], newSize - this->mPos));
    return this->mPos == newSize;
}
