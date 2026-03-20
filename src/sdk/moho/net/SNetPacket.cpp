#include "SNetPacket.h"

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"
#include "platform/Platform.h"
using namespace moho;

/**
 * Address: 0x00488BC0 (FUN_00488BC0)
 * Address: 0x100825E0 (sub_100825E0)
 *
 * SNetPacket const &
 *
 * IDA signature (FA):
 * std::string *__usercall Moho::SPacket::ToString@<eax>(Moho::SPacket *a1@<esi>, std::string *a2);
 *
 * IDA signature (MohoEngine):
 * int __usercall sub_100825E0@<eax>(int a1@<esi>, int a2);
 *
 * What it does:
 * Formats packet state as `l=<size> <type>`, appends sequence header fields for
 * non-NAT frames, and dumps first bytes for NAT-traversal packets.
 */
msvc8::string SNetPacket::ToString() const
{
  msvc8::string packetState;
  NetPacketTypeToStr(header.mType, packetState);

  // Prefix: "l=<size> <state>"
  auto out = gpg::STR_Printf("l=%d %s", mSize, packetState.c_str());

  // For states 0..7: print header fields
  if (header.mType < PT_NATTraversal) {
    out.append(
      gpg::STR_Printf(
        " mask=%x ser=%d irt=%d seq=%d expected=%d",
        static_cast<unsigned>(header.mEarlyMask),
        static_cast<int>(header.mSerialNumber),
        static_cast<int>(header.mInResponseTo),
        static_cast<int>(header.mSequenceNumber),
        static_cast<int>(header.mExpectedSequenceNumber)
      )
        .c_str()
    );
  }
  // For type == 8: hex dump first up to 20 bytes starting at mType
  else if (header.mType == PT_NATTraversal) {
    const auto base = reinterpret_cast<const unsigned char*>(&header.mType);
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

/**
 * Address: 0x00487A30 (FUN_00487A30)
 * Address: 0x10081450 (sub_10081450)
 *
 * const char *, __int64
 *
 * IDA signature (FA, unnamed export):
 * int __usercall nullsub_513_0@<eax>(const char *a1@<edx>, int a2@<esi>, __int64 a3);
 *
 * IDA signature (MohoEngine):
 * void __usercall sub_10081450(const char *a1@<edx>, int a2@<esi>, __int64 a3);
 *
 * What it does:
 * Logs packet age, size, resend count, type and sequence/payload header fields.
 */
void SNetPacket::LogPacket(const char* dirType, const int64_t receiveOrSentTime) const
{
  gpg::Logf("      %s %7dusec ago:", dirType, static_cast<int64_t>(receiveOrSentTime - mSentTime));
  gpg::Logf("        length=%d bytes", mSize);
  gpg::Logf("        resend count=%d", mResendCount);

  msvc8::string buf;
  if (header.mType >= PT_NumTypes) {
    buf = gpg::STR_Printf("?[%d)", static_cast<uint8_t>(header.mType));
  } else {
    NetPacketTypeToStr(header.mType, buf);
  }

  gpg::Logf("        type=%s", buf.c_str());
  gpg::Logf("        early mask=%08x", header.mEarlyMask);
  gpg::Logf("        serial number=%d", header.mSerialNumber);
  gpg::Logf("        in response to=%d", header.mInResponseTo);
  gpg::Logf("        sequence number=%d", header.mSequenceNumber);
  gpg::Logf("        expected sequence number=%d", header.mExpectedSequenceNumber);
  gpg::Logf("        payload length=%d", header.mPayloadLength);
}
