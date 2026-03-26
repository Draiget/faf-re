#include "moho/path/IPathTraveler.h"

namespace moho
{
  /**
   * Address: 0x005A9C60 (FUN_005A9C60, ?Func7@IPathTraveler@Moho@@UAEXABUNavPath@2@@Z)
   *
   * SNavPath const &
   *
   * IDA signature:
   * void __stdcall Moho::IPathTraveler::Func7(int a1);
   *
   * What it does:
   * Base no-op hook for accepted path payload callbacks.
   */
  void IPathTraveler::OnPathAccepted(const SNavPath&) {}

  /**
   * Address: 0x005A9C70 (FUN_005A9C70, ?Func9@IPathTraveler@Moho@@UAEXXZ)
   *
   * IDA signature:
   * void Moho::IPathTraveler::Func9();
   *
   * What it does:
   * Base no-op hook for search-cancel callbacks.
   */
  void IPathTraveler::OnPathSearchCancelled() {}

  /**
   * Address: 0x005A9C80 (FUN_005A9C80, ?Func10@IPathTraveler@Moho@@UAEXABUNavPath@2@@Z)
   *
   * SNavPath const &
   *
   * IDA signature:
   * void __stdcall Moho::IPathTraveler::Func10(int a1);
   *
   * What it does:
   * Base no-op hook for rejected path payload callbacks.
   */
  void IPathTraveler::OnPathRejected(const SNavPath&) {}
} // namespace moho
