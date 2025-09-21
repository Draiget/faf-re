#include "SNetPacket.h"

#include "platform/Platform.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"
using namespace moho;

msvc8::string SNetPacket::ToString() const {
    msvc8::string packetState;
	NetPacketStateToStr(header.mState, packetState);

    // Prefix: "l=<size> <state>"
    auto out = gpg::STR_Printf("l=%d %s", mSize, packetState.c_str());

    // For states 0..7: print header fields
    if (header.mState < NATTRAVERSAL) {
        out.append(gpg::STR_Printf(
            " mask=%x ser=%d irt=%d seq=%d expected=%d",
            static_cast<unsigned>(header.mEarlyMask),
            static_cast<int>(header.mSerialNumber),
            static_cast<int>(header.mInResponseTo),
            static_cast<int>(header.mSequenceNumber),
            static_cast<int>(header.mExpectedSequenceNumber)).c_str());
    }
    // For state == 8: hex dump first up to 20 bytes starting at mState
    else if (header.mState == NATTRAVERSAL) {
	    const auto base = reinterpret_cast<const unsigned char*>(&header.mState);
        unsigned max = static_cast<unsigned>(mSize);
        if (max > 20) {
            max = 20;
        }
        for (unsigned i = 0; i < max; ++i) {
            out.append(gpg::STR_Printf(" %02x", static_cast<unsigned>(base[i])).c_str());
        }
        if (static_cast<unsigned>(mSize) > 0x14u) {
            out.append(" ...");
        }
    }

    // For state >=9 and !=8: only the prefix is shown
    return out;
}

void SNetPacket::LogPacket(const char* dirType, const int64_t receiveOrSentTime) const {
    gpg::Logf("      %s %7dusec ago:", dirType, static_cast<int64_t>(receiveOrSentTime - mSentTime));
    gpg::Logf("        length=%d bytes", mSize);
    gpg::Logf("        resend count=%d", mResendCount);

    msvc8::string buf;
    if (header.mState >= NATTRAVERSAL + 1) {
        buf = gpg::STR_Printf("?[%d)", static_cast<uint8_t>(header.mState));
    } else {
        NetPacketStateToStr(header.mState, buf);
    }

    gpg::Logf("        type=%s", buf.c_str());
    gpg::Logf("        early mask=%08x", header.mEarlyMask);
    gpg::Logf("        serial number=%d", header.mSerialNumber);
    gpg::Logf("        in response to=%d", header.mInResponseTo);
    gpg::Logf("        sequence number=%d", header.mSequenceNumber);
    gpg::Logf("        expected sequence number=%d", header.mExpectedSequenceNumber);
    gpg::Logf("        payload length=%d", header.mPayloadLength);
}
