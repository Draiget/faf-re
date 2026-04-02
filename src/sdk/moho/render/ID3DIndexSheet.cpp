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
   * Address: 0x0043CD50 (FUN_0043CD50, sub_43CD50)
   *
   * What it does:
   * Resets base vftable state and owns the deleting-destructor entrypoint.
   */
  ID3DIndexSheet::~ID3DIndexSheet() = default;
} // namespace moho
