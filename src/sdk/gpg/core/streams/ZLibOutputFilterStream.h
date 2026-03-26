#pragma once

#include "PipeStream.h"
#include "Stream.h"
#include <zlib.h>

namespace gpg
{
    enum EFilterOperation
    {
        FLOP_Inflate = 0,
        FLOP_Deflate = 1,
    };

    /**
     * VFTABLE: 0x00D496F0
     * COL:     0x00E53D00
     */
    class ZLibOutputFilterStream : public Stream
    {
    public:
        /**
         * Address: 0x009572C0 (FUN_009572C0)
         * Deleting owner: 0x00957340 (FUN_00957340)
         * Demangled: gpg::ZLibOutputFilterStream::dtr
         *
         * What it does:
         * Closes send/receive lanes with no-throw semantics, finalizes inflate/deflate state, then tears down Stream base.
         */
        ~ZLibOutputFilterStream() override;

        /**
         * Address: 0x00957760 (FUN_00957760)
         *
         * What it does:
         * Rejects closed stream writes, drains pending inline bytes, then sends caller data through zlib pump.
         */
        void VirtWrite(const char* data, size_t size) override;

        /**
         * Address: 0x00957810 (FUN_00957810)
         *
         * What it does:
         * Rejects closed stream flushes, pumps buffered bytes with `Z_SYNC_FLUSH`, then resets inline write head.
         */
        void VirtFlush() override;

        /**
         * Address: 0x009578B0 (FUN_009578B0)
         *
         * What it does:
         * On send close, pumps buffered bytes with `Z_FINISH`, validates inflate-end state, then marks stream closed.
         */
        void VirtClose(Mode mode) override;

        /**
         * Address: 0x00957360 (FUN_00957360)
         *
         * What it does:
         * Initializes zlib stream state for inflate/deflate mode and configures the 1024-byte inline write buffer.
         */
        ZLibOutputFilterStream(PipeStream* str, EFilterOperation operation);

    private:
        /**
         * Address: 0x00957500 (FUN_00957500)
         *
         * What it does:
         * Feeds input into inflate/deflate, forwards produced chunks to `mPipeStream`, and tracks stream-end/error lanes.
         */
        void DoWrite(const char* data, size_t len, int flush);

    public:
        PipeStream* mPipeStream{ nullptr };
        int mOperation{ Z_OK };
        z_stream mZStream{};
        char mBuff[1024]{};
        bool mEnded{ false };
        bool mClosed{ false };
    };

    // 0x00486067
    static_assert(sizeof(ZLibOutputFilterStream) == 0x460, "ZLibOutputFilterStream size must be 0x460");
}
