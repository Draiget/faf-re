#include "ID3DVertexSheet.h"

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
   * Address: 0x0043CD20 (FUN_0043CD20, sub_43CD20)
   *
   * What it does:
   * Resets base vftable state and owns the deleting-destructor entrypoint.
   */
  ID3DVertexSheet::~ID3DVertexSheet() = default;
} // namespace moho
