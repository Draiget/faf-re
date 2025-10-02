#include "INetConnection.h"
#include "CMessageStream.h"
using namespace moho;

NetDataSpan::NetDataSpan(const CMessageStream& s) noexcept
    : start(reinterpret_cast<std::uint8_t*>(s.mWriteStart))
    , end(reinterpret_cast<std::uint8_t*>(s.mWriteHead))
{
}
