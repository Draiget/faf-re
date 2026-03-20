#include "RBlueprint.h"

namespace moho
{
  gpg::RType* RBlueprint::sPointerType = nullptr;

  /**
   * Address: 0x0050DBA0 (FUN_0050DBA0)
   * Mangled: ?OnInitBlueprint@RBlueprint@Moho@@MAEXXZ
   *
   * What it does:
   * Base blueprint post-load hook; default implementation is empty.
   */
  void RBlueprint::OnInitBlueprint() {}
} // namespace moho
