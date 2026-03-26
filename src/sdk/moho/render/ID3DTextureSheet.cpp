#include "ID3DTextureSheet.h"

namespace moho
{
  gpg::RType* ID3DTextureSheet::sType = nullptr;

  /**
   * Address: 0x0043CD80 (FUN_0043CD80, sub_43CD80)
   *
   * What it does:
   * Resets base vftable state and owns the deleting-destructor entrypoint.
   */
  ID3DTextureSheet::~ID3DTextureSheet() = default;
} // namespace moho
