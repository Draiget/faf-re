#pragma once

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/streams/Stream.h"
#include "platform/Platform.h"

namespace moho
{
    struct CMessage
    {
        gpg::core::FastVectorN<char, 64> mBuf;
        int mPos;

        /**
         * PDB address: 0x00483490
         */
        CMessage(int size, char type);

        /**
         * PDB address: 0x0047BE62
         */
        void SetSize(const size_t size) {
            this->mBuf[1] = LOBYTE(size);
            this->mBuf[2] = HIBYTE(size);
        }

        /**
         * PDB address: 0x0047BF4C
         */
        unsigned short GetSize() {
            // return *(unsigned short *)(&this->mBuf[1]);
            return MAKEWORD(this->mBuf[1], this->mBuf[2]);
        }

        /**
         * PDB address: 0x0047BEE5
         */
        [[nodiscard]]
    	bool HasReadLength() const {
            return this->mPos >= 3;
        }

        /**
         * PDB address: 0x007BFB97
         */
        char GetType() {
            return this->mBuf[0];
        }

        /**
         * PDB address: 0x004834E9
         */
        void SetType(const char type) {
            this->mBuf[0] = type;
        }

        /**
         * PDB address: 0x0047BE90
         */
        int GetMessageSize();

        /**
         * PDB address: 0x0047BD40
         */
        bool ReadMessage(gpg::Stream* stream);

        /**
         * PDB address: 0x0047BEE0
         */
        bool Read(gpg::Stream* stream);

        /**
         * PDB address: 0x0047BDE0
         */
        unsigned int Append(const char* ptr, size_t size);

        /**
         * PDB address: <inlined>
         */
        void inline Clear() noexcept;
    };
}