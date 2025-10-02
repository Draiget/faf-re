#include "CMessage.h"

#include <stdexcept>
#include <string>

#include "gpg/core/streams/Stream.h"
using namespace moho;

CMessage::CMessage() {
}

CMessage::CMessage(const MessageType type, size_t size) {
    size += 3;
    constexpr char fill = 0;
    mBuff.Resize(size, fill);
    SetSize(size);
    SetType(type);
}

int CMessage::GetMessageSize() {
    int size = GetSize();
    if (size >= 3) {
        size -= 3;
    }
    return size;
}

unsigned int CMessage::Append(const char* ptr, const size_t size) {
    if (mBuff.Size() + size > 0x10000) {
        throw std::runtime_error{ std::string{"Message too large"} };
    }

    mBuff.InsertAt(mBuff.end_, ptr, &ptr[size]);

    const auto targetSize = mBuff.Size();
    SetSize(targetSize);
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
    mBuff.Resize(3, fill);
    if (stream->Read(mBuff.start_, 3) != 3) {
        return false;
    }
	const size_t size = GetSize();
    if (size < 3) {
        return false;
    }
    if (size == 3) {
        return true;
    }
    mBuff.Resize(size - 3, fill);
    return stream->Read(&mBuff[3], size - 3) == size - 3;
}

bool CMessage::Read(gpg::Stream* stream) {
    if (!HasReadLength()) {
        if (mBuff.Size() == 0) {
	        constexpr char fill = 0;
            mBuff.Resize(3, fill);
        }
        mPos += static_cast<int>(stream->ReadNonBlocking(&mBuff[mPos], 3 - mPos));
        if (!HasReadLength()) {
            return false;
        }
    }
    const int newSize = GetSize();
    if (newSize < 3) {
        return false;
    }
    if (newSize == mPos) {
        return true;
    }
    constexpr char fill = 0;
    mBuff.Resize(newSize, fill);
    mPos += static_cast<int>(stream->ReadNonBlocking(&mBuff[mPos], newSize - mPos));
    return mPos == newSize;
}
