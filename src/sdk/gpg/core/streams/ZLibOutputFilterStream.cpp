#include "gpg/core/streams/ZLibOutputFilterStream.h"

#include <cstring>

#include "gpg/core/utils/Global.h"

using namespace gpg;

namespace
{
    constexpr const char* kClosedStreamMessage = "ZLibOutputFilterStream: stream closed.";
    constexpr const char* kInvalidOperationMessage = "invalid operation";
    constexpr const char* kInflateInitFailedMessage = "ZLibOutputFilterStream: inflateInit2() failed.";
    constexpr const char* kDeflateInitFailedMessage = "ZLibOutputFilterStream: deflateInit2() failed.";
    constexpr const char* kExcessDataAfterEndMessage = "ZLibOutputFilterStream: excess data after stream end.";
    constexpr const char* kExcessDataAfterEndUpperMessage = "ZLibOutputFilterStream: Excess data after stream end.";
    constexpr const char* kClosedBeforeEndMessage = "ZLibOutputFilterStream: stream closed before end.";
    constexpr const char* kDeflateWriteFailedMessage = "CDeflateOutputFilter::BufWrite(): call to deflate() failed.";

    constexpr const char* kAvailInAssertExpr = "mZStream.avail_in == 0";
    constexpr int kAvailInAssertLine = 157;
    constexpr const char* kAvailInAssertSource = "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\streams\\ZLibStream.cpp";
}

/**
 * Address: 0x009572C0 (FUN_009572C0)
 * Deleting owner: 0x00957340 (FUN_00957340)
 * Demangled: gpg::ZLibOutputFilterStream::dtr
 *
 * What it does:
 * Closes send/receive lanes with no-throw semantics, finalizes inflate/deflate state, then tears down Stream base.
 */
ZLibOutputFilterStream::~ZLibOutputFilterStream()
{
    CloseNoThrow(ModeBoth);

    if (mOperation == FLOP_Inflate) {
        inflateEnd(&mZStream);
    } else if (mOperation == FLOP_Deflate) {
        deflateEnd(&mZStream);
    }
}

/**
 * Address: 0x00957360 (FUN_00957360)
 *
 * What it does:
 * Initializes zlib stream state for inflate/deflate mode and configures the 1024-byte inline write buffer.
 */
ZLibOutputFilterStream::ZLibOutputFilterStream(PipeStream* const str, const EFilterOperation operation)
    : Stream(),
      mPipeStream(str),
      mOperation(operation)
{
    mEnded = false;
    mClosed = false;

    mWriteStart = mBuff;
    mWriteHead = mBuff;
    mWriteEnd = mBuff + sizeof(mBuff);

    std::memset(&mZStream, 0, sizeof(mZStream));

    if (operation == FLOP_Inflate) {
        if (inflateInit2_(&mZStream, -14, "1.2.3", sizeof(z_stream)) != Z_OK) {
            throw std::runtime_error(kInflateInitFailedMessage);
        }
        return;
    }

    if (operation == FLOP_Deflate) {
        if (deflateInit2_(&mZStream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -14, 8, 0, "1.2.3", sizeof(z_stream)) != Z_OK) {
            throw std::runtime_error(kDeflateInitFailedMessage);
        }
        return;
    }

    throw std::invalid_argument(kInvalidOperationMessage);
}

/**
 * Address: 0x00957500 (FUN_00957500)
 *
 * What it does:
 * Feeds input into inflate/deflate, forwards produced chunks to `mPipeStream`, and tracks stream-end/error lanes.
 */
void ZLibOutputFilterStream::DoWrite(const char* const data, const size_t len, const int flush)
{
    if (mEnded) {
        if (len == 0) {
            return;
        }
        throw std::runtime_error(kExcessDataAfterEndMessage);
    }

    mZStream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(data));
    mZStream.avail_in = static_cast<uInt>(len);

    for (;;)
    {
        unsigned char out[1024]{};
        int result = Z_STREAM_ERROR;

        for (;;)
        {
            mZStream.next_out = out;
            mZStream.avail_out = static_cast<uInt>(sizeof(out));

            if (mOperation == FLOP_Inflate) {
                result = inflate(&mZStream, flush);
            } else if (mOperation == FLOP_Deflate) {
                result = deflate(&mZStream, flush);
            }

            if (result != Z_OK) {
                break;
            }

            const size_t produced = static_cast<size_t>(mZStream.next_out - out);
            mPipeStream->Write(reinterpret_cast<const char*>(out), produced);
        }

        if (result != Z_BUF_ERROR) {
            if (result == Z_STREAM_END) {
                mEnded = true;
                const size_t produced = static_cast<size_t>(mZStream.next_out - out);
                mPipeStream->Write(reinterpret_cast<const char*>(out), produced);
                if (mZStream.avail_in == 0) {
                    return;
                }
                throw std::runtime_error(kExcessDataAfterEndUpperMessage);
            }
            throw std::runtime_error(kDeflateWriteFailedMessage);
        }

        if (mZStream.next_out == out) {
            break;
        }

        const size_t produced = static_cast<size_t>(mZStream.next_out - out);
        mPipeStream->Write(reinterpret_cast<const char*>(out), produced);
    }

    if (mZStream.avail_in != 0) {
        HandleAssertFailure(kAvailInAssertExpr, kAvailInAssertLine, kAvailInAssertSource);
    }
}

/**
 * Address: 0x00957760 (FUN_00957760)
 *
 * What it does:
 * Rejects closed stream writes, drains pending inline bytes, then sends caller data through zlib pump.
 */
void ZLibOutputFilterStream::VirtWrite(const char* const data, const size_t size)
{
    if (mClosed) {
        throw std::runtime_error(kClosedStreamMessage);
    }

    if (mWriteHead != mWriteStart) {
        DoWrite(mWriteStart, static_cast<size_t>(mWriteHead - mWriteStart), Z_NO_FLUSH);
        mWriteHead = mWriteStart;
    }

    DoWrite(data, size, Z_NO_FLUSH);
}

/**
 * Address: 0x00957810 (FUN_00957810)
 *
 * What it does:
 * Rejects closed stream flushes, pumps buffered bytes with `Z_SYNC_FLUSH`, then resets inline write head.
 */
void ZLibOutputFilterStream::VirtFlush()
{
    if (mClosed) {
        throw std::runtime_error(kClosedStreamMessage);
    }

    DoWrite(mWriteStart, static_cast<size_t>(mWriteHead - mWriteStart), Z_SYNC_FLUSH);
    mWriteHead = mWriteStart;
}

/**
 * Address: 0x009578B0 (FUN_009578B0)
 *
 * What it does:
 * On send close, pumps buffered bytes with `Z_FINISH`, validates inflate-end state, then marks stream closed.
 */
void ZLibOutputFilterStream::VirtClose(const Mode mode)
{
    if ((mode & ModeSend) != 0 && !mClosed) {
        DoWrite(mWriteStart, static_cast<size_t>(mWriteHead - mWriteStart), Z_FINISH);
        if (mOperation == FLOP_Inflate && !mEnded) {
            throw std::runtime_error(kClosedBeforeEndMessage);
        }
        mClosed = true;
    }
}
