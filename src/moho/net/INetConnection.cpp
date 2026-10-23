#include "INetConnection.h"

#include "CMessage.h"

using namespace moho;

/**
 * Address: <synthetic host-build helper>
 *
 * What it does:
 * Stores a caller-provided byte span [start, end).
 */
NetDataSpan::NetDataSpan(uint8_t* const begin, uint8_t* const finish) noexcept
  : start(begin)
  , end(finish)
{}

/**
 * Address: <synthetic host-build helper>
 *
 * What it does:
 * Creates a span over a message's whole wire buffer [mBuff.start_, mBuff.end_):
 * the 3-byte type/size header followed by the payload.
 */
NetDataSpan::NetDataSpan(const CMessage& message) noexcept
  : start(reinterpret_cast<std::uint8_t*>(message.mBuff.start_))
  , end(reinterpret_cast<std::uint8_t*>(message.mBuff.end_))
{}

/**
 * Address: <synthetic host-build helper>
 *
 * What it does:
 * Returns byte length of [start, end).
 */
size_t NetDataSpan::size() const noexcept
{
  return static_cast<size_t>(end - start);
}

/**
 * Address: <synthetic host-build helper>
 *
 * What it does:
 * Returns span start pointer.
 */
uint8_t* NetDataSpan::data() const noexcept
{
  return start;
}

/**
 * Address: <synthetic host-build helper>
 *
 * What it does:
 * Queues one whole message on the connection. The binary passes the `CMessage`
 * itself to slot 4 (its `mBuff` begins with the {start, end} pair), e.g.
 * `lea edx,[esp+0x6C]; push edx; call [eax+0x10]` at 0x007C5E85 in
 * `CLobby::OnConnectionMade`, so the header travels with the payload.
 */
void INetConnection::Write(const CMessage& message)
{
  NetDataSpan span(message);
  Write(&span);
}
