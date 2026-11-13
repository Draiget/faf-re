#include "ID3DVertexSheet.h"

#include <memory>

#include <new>

namespace moho
{

  /**
   * Address: 0x00440020 (FUN_00440020, sub_440020)
   *
   * What it does:
   * Initializes the base interface vftable lane for derived vertex sheets.
   */
  ID3DVertexSheet::ID3DVertexSheet() = default;

  /**
   * Address: 0x0043CD10 (FUN_0043CD10, ID3DVertexSheet dtor body)
   * Address: 0x0043CD20 (FUN_0043CD20, sub_43CD20, scalar deleting destructor thunk)
   *
   * What it does:
   * Defaulted destructor body — compiler emits a 2-insn vtable-set + retn at
   * 0x0043CD10 and a separate scalar-deleting thunk at 0x0043CD20.
   */
  ID3DVertexSheet::~ID3DVertexSheet() = default;
} // namespace moho
