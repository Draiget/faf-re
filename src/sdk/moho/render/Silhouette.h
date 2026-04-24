#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"

namespace Moho
{
  /**
   * Opaque payload owned by `Silhouette` through a `boost::shared_ptr` slot.
   *
   * The binary destructor only exercises the `boost::detail::sp_counted_base`
   * slot-4/slot-8 virtual dispatch sequence (dispose + destroy), so the
   * payload type identity is not required for correct teardown. The typed
   * placeholder keeps the owning shared_ptr ABI-compatible with the binary
   * layout `{px at +0x04, pi_ at +0x08}` without re-introducing raw vtable
   * offset magic in callers.
   */
  struct SilhouettePayload;

  /**
   * VFTABLE: 0x00E42098
   * COL:     0x00E98B74
   *
   * Owning handle for one silhouette-rendering payload attached to a render
   * viewport. The object's only runtime responsibility is to retain one
   * reference-counted payload through construction/copy and release it on
   * destruction; all rendering work lives in the payload type and the
   * viewport pipeline that consumes it.
   */
  class Silhouette
  {
  public:
    /**
     * Address: 0x008144E0 (FUN_008144E0, ??1Silhouette@Moho@@UAE@XZ)
     * Mangled: ??1Silhouette@Moho@@UAE@XZ
     *
     * IDA signature:
     * int __thiscall sub_8144E0(volatile signed __int32 **this);
     *
     * What it does:
     * Re-seats the vftable to `Moho::Silhouette` and releases the owned
     * silhouette payload through `boost::shared_ptr`'s inlined release
     * sequence. The binary-visible release block is emitted twice over the
     * same `pn.pi_` slot; the second pass is dead after the first because
     * the slot is cleared in-place, but keeping both preserves 1:1 binary
     * control flow during SEH unwind.
     */
    virtual ~Silhouette();

    /**
     * Address: 0x008144C0 (FUN_008144C0, Moho::Silhouette::dtr)
     * Mangled: ??_GSilhouette@Moho@@UAEPAXI@Z
     * Slot: 0 (vftable slot 0 -- scalar deleting destructor thunk)
     *
     * IDA signature:
     * void* __thiscall Moho::Silhouette::dtr(Silhouette* this, char deleteFlags);
     *
     * What it does:
     * Runs the virtual destructor and conditionally frees memory with
     * `operator delete` when the low flag bit is set. This is the standard
     * MSVC8 scalar deleting destructor thunk that appears at vftable slot 0.
     */
    void* ScalarDeletingDestructor(std::uint8_t deleteFlags);

  public:
    boost::shared_ptr<SilhouettePayload> mPayload; // +0x04..+0x0B
  };

  static_assert(offsetof(Silhouette, mPayload) == 0x04, "Silhouette::mPayload offset must be 0x04");
  // sizeof(Silhouette) is at least 0x0C (vftable + shared_ptr{px, pi_}); the
  // ABI-exact total size depends on trailing fields that are still under
  // recovery in the render-viewport subsystem, so no hard size_assert here.
} // namespace Moho
