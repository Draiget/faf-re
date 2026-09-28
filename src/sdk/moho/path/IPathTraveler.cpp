#include "moho/path/IPathTraveler.h"

namespace moho
{
  /**
   * Address: 0x007657A0 (FUN_007657A0, `PathPreviewFinder`'s scalar-deleting
   * destructor, `??_7PathPreviewFinder@Moho@@6B@+0x8`)
   *
   * What it does:
   * Unlinks the queue node from whatever path-queue list it is currently
   * threaded into before the derived object's storage is released --
   * `*(mNext_slot+4) = mNext; *mNext = mPrev; self-reset` matches this
   * struct's `ListUnlink()` exactly (offset +0x04 from `this`, i.e.
   * the node at `IPathTraveler+0x04`). That is the `DListItem` base's
   * destructor, so the body is empty. It is what keeps a still-queued
   * traveler (e.g. a `PathPreviewFinder` dropped mid-search) from leaving the
   * path-queue dispatcher holding a dangling node, for every
   * `IPathTraveler`-derived class.
   */
  IPathTraveler::~IPathTraveler() = default;

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
