#include "ID3DTextureSheet.h"

namespace moho
{
  gpg::RType* ID3DTextureSheet::sType = nullptr;

  /**
   * Address: 0x0043CD70 (FUN_0043CD70, ID3DTextureSheet dtor body)
   * Address: 0x0043CD80 (FUN_0043CD80, sub_43CD80, scalar deleting destructor thunk)
   *
   * What it does:
   * Defaulted destructor body — compiler emits a 2-insn vtable-set + retn at
   * 0x0043CD70 and a separate scalar-deleting thunk at 0x0043CD80.
   */
  ID3DTextureSheet::~ID3DTextureSheet() = default;
} // namespace moho
