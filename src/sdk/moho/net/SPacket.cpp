#include "SPacket.h"

#include "gpg/core/containers/String.h"
using namespace moho;

const char* sPacketStateString[9]{
    "CONNECT",
    "ANSWER",
    "RESETSERIAL",
    "SERIALRESET",
    "DATA",
    "ACK",
    "KEEPALIVE",
    "GOODBYE",
    "NATTRAVERSAL",
};

msvc8::string SPacket::ToString() const {
    const char* stateStr;

    // Choose state string: known table for <9, otherwise hex like "%02x".
    // Amount of `EPacketState`.
    if (mState < NATTRAVERSAL + 1) {
        stateStr = sPacketStateString[static_cast<uint8_t>(mState)];
    } else {
        stateStr = gpg::STR_Printf("%02x", static_cast<unsigned>(mState)).c_str();
    }

    // Prefix: "l=<size> <state>"
    auto out = gpg::STR_Printf("l=%d %s", mSize, stateStr);

    // For states 0..7: print header fields
    if (mState < NATTRAVERSAL) {
        out.append(gpg::STR_Printf(
            " mask=%x ser=%d irt=%d seq=%d expected=%d",
            static_cast<unsigned>(mEarlyMask),
            static_cast<int>(mSerialNumber),
            static_cast<int>(mInResponseTo),
            static_cast<int>(mSequenceNumber),
            static_cast<int>(mExpectedSequenceNumber)).c_str());
    }
    // For state == 8: hex dump first up to 20 bytes starting at mState
    else if (mState == NATTRAVERSAL) {
	    const auto base = reinterpret_cast<const unsigned char*>(&mState);
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
