#include "MemBufferStream.h"
using namespace gpg;

MemBuffer<char> gpg::AllocMemBuffer(const size_t size) {
	const auto buff = static_cast<char*>(malloc(size));
    memset(buff, 0, size);
    boost::SharedPtrRaw ptr{ buff, free };
    return MemBuffer{ptr, buff, & buff[size]};
}
