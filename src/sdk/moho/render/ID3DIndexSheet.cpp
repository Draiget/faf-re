#include "ID3DIndexSheet.h"

namespace moho
{
  /**
   * Address: 0x0043F5D0 (FUN_0043F5D0, sub_43F5D0)
   *
   * What it does:
   * Initializes the base interface vftable lane for derived index sheets.
   */
  ID3DIndexSheet::ID3DIndexSheet() = default;

  /**
   * Address: 0x0043CD40 (FUN_0043CD40, ID3DIndexSheet dtor body)
   * Address: 0x0043CD50 (FUN_0043CD50, sub_43CD50, scalar deleting destructor thunk)
   *
   * What it does:
   * Defaulted destructor body — compiler emits a 2-insn vtable-set + retn at
   * 0x0043CD40 and a separate scalar-deleting thunk at 0x0043CD50.
   */
  ID3DIndexSheet::~ID3DIndexSheet() = default;
} // namespace moho
