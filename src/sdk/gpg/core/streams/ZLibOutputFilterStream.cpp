// Auto-generated from IDA VFTABLE/RTTI scan.
#include "gpg/core/streams/ZLibOutputFilterStream.h"

#include "gpg/core/utils/Global.h"
using namespace gpg;

ZLibOutputFilterStream::~ZLibOutputFilterStream() {
    try {
        if (!mClosed) {
	        ZLibOutputFilterStream::VirtClose(ModeSend);
        }
    } catch (...) {
        // no-throw
    }

    if (this->mOperation == 0) {
        inflateEnd(&this->mZStream);
    } else if (this->mOperation == 1) {
        deflateEnd(&this->mZStream);
    }
}

size_t ZLibOutputFilterStream::VirtTell(Mode mode) {
    throw UnsupportedOperation{};
}

size_t ZLibOutputFilterStream::VirtSeek(Mode mode, SeekOrigin origin, size_t size) {
    throw UnsupportedOperation{};
}

size_t ZLibOutputFilterStream::VirtRead(char* buffer, unsigned int size) {
    throw UnsupportedOperation{};
}

size_t ZLibOutputFilterStream::VirtReadNonBlocking(char* buffer, const unsigned int size) {
	return Stream::VirtRead(buffer, size);
}

void ZLibOutputFilterStream::VirtUnGetByte(int size) {
    throw UnsupportedOperation{};
}

bool ZLibOutputFilterStream::VirtAtEnd() {
    return false;
}

void ZLibOutputFilterStream::VirtWrite(char const* data, const size_t size) {
    if (mClosed) {
        throw std::runtime_error{ std::string{"ZLibOutputFilterStream: stream closed."} };
    }

    if (this->LeftToFlush()) {
        this->DoWrite(this->mWriteStart, this->LeftToFlush(), Z_NO_FLUSH);
        this->mWriteHead = this->mWriteStart;
    }

    this->DoWrite(data, size, Z_NO_FLUSH);
}

void ZLibOutputFilterStream::VirtFlush() {
    if (mClosed) {
        throw std::runtime_error{ std::string{"ZLibOutputFilterStream: stream closed."} };
    }

    this->DoWrite(this->mWriteStart, this->LeftToFlush(), Z_SYNC_FLUSH);
    this->mWriteStart = this->mWriteHead;
}

void ZLibOutputFilterStream::VirtClose(const Mode mode) {
    if ((mode & ModeSend) && !mClosed) {
        this->DoWrite(this->mWriteStart, this->LeftToFlush(), Z_FINISH);
        if (this->mOperation == 0 && !this->mEnded) {
            this->mClosed = true;
            throw std::runtime_error{
            	std::string{
					"ZLibOutputFilterStream: stream closed before end."
				}
            };
        }
        this->mClosed = true;
    }
}

ZLibOutputFilterStream::ZLibOutputFilterStream(PipeStream* str, const int operation) :
	Stream(),
	mPipeStream(str)
{
	// small inline input cache lives in mBuff
	mWriteHead = mBuff;
	mWriteStart = mBuff;
	mWriteEnd = mBuff + sizeof(mBuff);

	std::memset(&mZStream, 0, sizeof(mZStream));

	// inflateInit2_(&mZStream, -14, "1.2.3", 56);
	// deflateInit2_(&mZStream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -14, 8, 0, "1.2.3", 56);
	if (operation == 0) {
		if (inflateInit2_(&mZStream, -14, "1.2.3", sizeof(z_stream)) != Z_OK) {
			throw std::runtime_error{std::string{"ZLibOutputFilterStream: inflateInit2() failed."}};
		}
	} else if (operation == 1) {
		if (deflateInit2_(&mZStream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -14, 8, 0, "1.2.3", sizeof(z_stream)) != Z_OK) {
			throw std::runtime_error{std::string{"ZLibOutputFilterStream: deflateInit2() failed."}};
		}
	} else {
		throw std::logic_error{std::string{"invalid operation"}};
	}
}

void ZLibOutputFilterStream::DoWrite(const char* data, const size_t len, const int flush) {
	if (mEnded) {
        if (len == 0) {
            return;
        }
        throw std::runtime_error{ std::string{"ZLibOutputFilterStream: excess data after stream end."} };
    }

    mZStream.next_in = reinterpret_cast<unsigned char*>(const_cast<char*>(data));
    mZStream.avail_in = static_cast<uInt>(len);

    while (true) {
	    char out[1024];
	    int res;
        while (true) {
            mZStream.next_out = reinterpret_cast<unsigned char*>(out);
            mZStream.avail_out = sizeof(out);

            res = Z_STREAM_ERROR;
            if (mOperation == 0) {
                res = inflate(&mZStream, flush);
            } else if (mOperation == 1) {
                res = deflate(&mZStream, flush);
            }

            if (res != Z_OK) break;

            // write produced so far
            mPipeStream->Write(out, static_cast<unsigned>(mZStream.next_out
                - reinterpret_cast<unsigned char*>(out)));
        }

        if (res == Z_BUF_ERROR) {
            throw std::runtime_error{ std::string{
                "CDeflateOutputFilter::BufWrite(): call to deflate() failed."
            } };
        }

        if (res == Z_STREAM_END) {
            mEnded = true;
            mPipeStream->Write(out, static_cast<unsigned>(mZStream.next_out
                - reinterpret_cast<unsigned char*>(out)));
            if (mZStream.avail_in != 0) {
                return;
            }
            throw std::runtime_error{ std::string{
                "ZLibOutputFilterStream: Excess data after stream end."
            } };
        }

        if (mZStream.next_out == reinterpret_cast<unsigned char*>(out)) {
            break; // no new output produced
        }

        mPipeStream->Write(out, static_cast<unsigned>(mZStream.next_out
            - reinterpret_cast<unsigned char*>(out)));
    }

    GPG_ASSERT(mZStream.avail_in == 0);
}
