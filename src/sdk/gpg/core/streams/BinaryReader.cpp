#include "BinaryReader.h"

#include "Stream.h"
using namespace gpg;

void BinaryReader::Read(char* buf, const size_t size) const {
    Stream* const stream = mStream;
    const char* const readHead = stream ? stream->mReadHead : nullptr;

    if (size <= 0) {
        return;
    }

    const auto available = static_cast<size_t>(stream ? stream->mReadEnd - readHead : 0);

    if (size > available) {
        const size_t got = stream ? stream->Read(buf, size) : 0;
        if (got != size) {
            throw PrematureEOF();
        }
    } else {
        std::memcpy(buf, readHead, size);
        stream->mReadHead += size;
    }
}

void BinaryReader::ReadString(msvc8::string* out) const {
    if (!out) {
	    return;
    }

    out->clear();
    for (auto i = mStream->GetByte(); i; i = mStream->GetByte()) {
	    if (i == -1) {
            break;
	    }
        out->append(i, 1);
    }
}
