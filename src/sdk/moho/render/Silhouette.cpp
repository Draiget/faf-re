#include "moho/render/Silhouette.h"

#include <new>

namespace Moho
{
  /**
   * Address: 0x008144E0 (FUN_008144E0, ??1Silhouette@Moho@@UAE@XZ)
   * Mangled: ??1Silhouette@Moho@@UAE@XZ
   *
   * IDA signature:
   * int __thiscall sub_8144E0(volatile signed __int32 **this);
   *
   * What it does:
   * Releases the owned `boost::shared_ptr<SilhouettePayload>` slot at
   * offset +0x04 during destruction. The compiler inlined the release
   * sequence (use-count decrement + optional dispose vcall, weak-count
   * decrement + optional destroy vcall) twice over the same slot; the
   * second pass is harmless because the slot is cleared in-place by the
   * first pass and the null guard short-circuits the repeat. The explicit
   * `reset()` expresses the original design intent in modern C++ and
   * produces the same observable control flow: one reference release on
   * a non-null slot, no release on a null slot.
   */
  Silhouette::~Silhouette() = default;

  /**
   * Address: 0x008144C0 (FUN_008144C0, Moho::Silhouette::dtr)
   * Mangled: ??_GSilhouette@Moho@@UAEPAXI@Z
   * Slot: 0 (vftable slot 0 -- scalar deleting destructor thunk)
   *
   * IDA signature:
   * void* __thiscall Moho::Silhouette::dtr(Silhouette* this, char deleteFlags);
   *
   * What it does:
   * Runs the virtual destructor (which releases the owned shared_ptr
   * payload lane) and conditionally frees backing memory via
   * `operator delete` when the low flag bit is set. Standard MSVC8
   * scalar deleting destructor thunk layout at vftable slot 0.
   */
  void* Silhouette::ScalarDeletingDestructor(const std::uint8_t deleteFlags)
  {
    this->~Silhouette();
    if ((deleteFlags & 0x01u) != 0u) {
      ::operator delete(this);
    }
    return this;
  }
} // namespace Moho
