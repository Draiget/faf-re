#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"

namespace moho
{
  class GeomCamera3;
  class ID3DVertexSheet;

  /**
   * VFTABLE: 0x00E42098
   * COL:     0x00E98B74
   *
   * Draws the full-screen quad the silhouette pass renders through. The whole
   * object is that one quad: `Init` (0x008145A0) builds a four-vertex sheet
   * sized to the primary head, and the destructor releases it.
   *
   * IDA labels the Init export `Moho::Silohouette::Init`, but the destructor's
   * mangled name (`??1Silhouette@Moho@@UAE@XZ`) spells the class correctly, so
   * that spelling is used here. The namespace is folded to `moho` to match
   * every other recovered type in this tree.
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
     * Re-seats the vftable to `Silhouette` and releases the owned vertex
     * sheet. The compiler inlined the shared_ptr release sequence (use-count
     * decrement + optional dispose vcall, weak-count decrement + optional
     * destroy vcall) twice over the same slot; the second pass is dead
     * because the first clears the slot in place.
     */
    virtual ~Silhouette();

    /**
     * Address: 0x008145A0 (FUN_008145A0, Moho::Silhouette::Init)
     *
     * IDA signature:
     * int __usercall Moho::Silohouette::Init@<eax>(Moho::Silohouette *a1@<eax>);
     *
     * What it does:
     * Rebuilds the silhouette pass's full-screen quad. Drops whatever sheet
     * was held, allocates a fresh four-vertex sheet, and writes a quad scaled
     * to the primary head's pixel size, with texture coordinates scaled by the
     * head's aspect ratio so the shorter axis keeps a 0..1 range.
     *
     * Returns nothing: the binary's `eax` on exit is just whatever the stream
     * Unlock call left there, and its only caller
     * (WRenViewport::D3DWindowOnDeviceInit) discards it.
     */
    void Init();

    /**
     * Address: 0x008144C0 (FUN_008144C0, Moho::Silhouette::dtr)
     * Mangled: ??_GSilhouette@Moho@@UAEPAXI@Z
     * Slot: 0 (vftable slot 0 -- scalar deleting destructor thunk)
     *
     * IDA signature:
     * void* __thiscall Moho::Silhouette::dtr(Silhouette* this, char deleteFlags);
     *
     * What it does:
     * Runs the virtual destructor and conditionally frees backing memory with
     * `operator delete` when the low flag bit is set. Standard MSVC8 scalar
     * deleting destructor thunk at vftable slot 0.
     */
    void* ScalarDeletingDestructor(std::uint8_t deleteFlags);

  public:
    // The quad itself. `Init` assigns through boost::shared_ptr's operator=,
    // which IDA names `boost::shared_ptr_ID3DVertexSheet::operator=` - that
    // label is what pins the pointee type.
    /**
     * Address: 0x00814820 (FUN_00814820, Moho::Silhouette::Render)
     *
     * What it does:
     * Draws the silhouette overlay into one render target and composites it
     * with the frame effect's `TSilhouette` technique.
     */
    void Render(const GeomCamera3& camera, std::int32_t renderTargetIndex);

    boost::shared_ptr<ID3DVertexSheet> mQuadVertexSheet; // +0x04..+0x0B
  };

  static_assert(
    offsetof(Silhouette, mQuadVertexSheet) == 0x04,
    "Silhouette::mQuadVertexSheet offset must be 0x04"
  );
  // sizeof(Silhouette) is at least 0x0C (vftable + shared_ptr{px, pi_}); the
  // ABI-exact total size depends on trailing fields that are still under
  // recovery in the render-viewport subsystem, so no hard size_assert here.
} // namespace moho
