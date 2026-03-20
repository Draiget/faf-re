#include "INetConnection.h"

#include "CMessageStream.h"

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
 * Creates a span over CMessageStream write window [mWriteStart, mWriteHead).
 */
NetDataSpan::NetDataSpan(const CMessageStream& stream) noexcept
  : start(reinterpret_cast<std::uint8_t*>(stream.mWriteStart))
  , end(reinterpret_cast<std::uint8_t*>(stream.mWriteHead))
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
 * Forwards CMessageStream write window [mWriteStart, mWriteHead) to virtual Write(NetDataSpan*).
 */
void INetConnection::Write(const CMessageStream& stream)
{
  NetDataSpan span(stream);
  Write(&span);
}
