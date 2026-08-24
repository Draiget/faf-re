#include "moho/path/IPathTraveler.h"

namespace moho
{
  /**
   * Address: 0x005A9F80 (FUN_005A9F80)
   */
  IPathTraveler::IPathTraveler()
  {
    mPathQueueNode.ListUnlinkSelf();
  }

  /**
   * Address: 0x007657A0 (FUN_007657A0, `PathPreviewFinder`'s scalar-deleting
   * destructor, `??_7PathPreviewFinder@Moho@@6B@+0x8`)
   *
   * What it does:
   * Unlinks `mPathQueueNode` from whatever path-queue ring it is currently
   * threaded into before the derived object's storage is released --
   * `*(mNext_slot+4) = mNext; *mNext = mPrev; self-reset` matches this
   * struct's `ListUnlink()` exactly (offset +0x04 from `this`, i.e.
   * `mPathQueueNode` at `IPathTraveler+0x04`). Without this, destroying a
   * still-queued traveler (e.g. a `PathPreviewFinder` dropped mid-search)
   * would leave the path-queue dispatcher holding a dangling node -- this
   * fixes that for every `IPathTraveler`-derived class, not just
   * `PathPreviewFinder`, since the real binary's other derived-class
   * destructors (via `PathPreviewFinder`'s emission, the only one directly
   * observed) chain through this same base unlink.
   */
  IPathTraveler::~IPathTraveler()
  {
    (void)mPathQueueNode.ListUnlink();
  }

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
