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
   * Address: 0x0043CCE0 (FUN_0043CCE0, ID3DVertexStream dtor body)
   * Address: 0x0043CCF0 (FUN_0043CCF0, sub_43CCF0, scalar deleting destructor thunk)
   *
   * What it does:
   * Defaulted destructor body — compiler emits a 2-insn vtable-set + retn at
   * 0x0043CCE0 and a separate scalar-deleting thunk at 0x0043CCF0.
   */
  ID3DVertexStream::~ID3DVertexStream() = default;
} // namespace moho
