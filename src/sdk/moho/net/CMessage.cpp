#include "CMessage.h"

#include <stdexcept>
#include <string>

#include "gpg/core/streams/Stream.h"
using namespace moho;

CMessage::CMessage(int size, const char type) {
    size += 3;
    constexpr char fill = 0;
    mBuff.Resize(size, fill);
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
    if (this->mBuff.Size() + size > 0x10000) {
        throw std::runtime_error{ std::string{"Message too large"} };
    }

    this->mBuff.InsertAt(this->mBuff.end_, ptr, &ptr[size]);

    const auto targetSize = this->mBuff.Size();
    this->SetSize(targetSize);
    return targetSize;
}

void inline CMessage::Clear() noexcept {
    // If we currently point into heap memory, free it
    if (mBuff.start_ != mBuff.originalVec_) {
        delete[] mBuff.start_;

        // Restore start to inline storage base
        mBuff.start_ = mBuff.originalVec_;

        // Inline header stores capacity pointer at [originalVec]
        // (binary: capacity = *(char**)originalVec)
        mBuff.capacity_ = *reinterpret_cast<char**>(mBuff.originalVec_);
    }

    // Reset logical size to 0 (binary: end = start)
    mBuff.end_ = mBuff.start_;
}

bool CMessage::ReadMessage(gpg::Stream* stream) {
	constexpr char fill = 0;
    this->mBuff.Resize(3, fill);
    if (stream->Read(this->mBuff.start_, 3) != 3) {
        return false;
    }
	const size_t size = this->GetSize();
    if (size < 3) {
        return false;
    }
    if (size == 3) {
        return true;
    }
    this->mBuff.Resize(size - 3, fill);
    return stream->Read(&this->mBuff[3], size - 3) == size - 3;
}

bool CMessage::Read(gpg::Stream* stream) {
    if (!this->HasReadLength()) {
        if (this->mBuff.Size() == 0) {
	        constexpr char fill = 0;
            this->mBuff.Resize(3, fill);
        }
        this->mPos += static_cast<int>(stream->ReadNonBlocking(&this->mBuff[this->mPos], 3 - this->mPos));
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
    this->mBuff.Resize(newSize, fill);
    this->mPos += static_cast<int>(stream->ReadNonBlocking(&this->mBuff[this->mPos], newSize - this->mPos));
    return this->mPos == newSize;
}
