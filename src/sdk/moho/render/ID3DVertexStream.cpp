#include "ID3DVertexStream.h"

namespace moho
{
  /**
   * Address: 0x0043FB00 (FUN_0043FB00, sub_43FB00)
   *
   * What it does:
   * Initializes the base interface vftable lane for derived vertex streams.
   */
  ID3DVertexStream::ID3DVertexStream() = default;

  /**
   * Address: 0x0043CCF0 (FUN_0043CCF0, sub_43CCF0)
   *
   * What it does:
   * Resets base vftable state and owns the deleting-destructor entrypoint.
   */
  ID3DVertexStream::~ID3DVertexStream() = default;
} // namespace moho
