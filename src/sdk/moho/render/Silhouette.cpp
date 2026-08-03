#include "moho/render/Silhouette.h"

#include <new>

#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/ID3DVertexSheet.h"
#include "moho/render/ScreenQuadVertexSheet.h"
#include "moho/render/d3d/CD3DVertexSheet.h"
#include "moho/render/d3d/CD3DDevice.h"

namespace moho
{
  /**
   * Address: 0x008144E0 (FUN_008144E0, ??1Silhouette@Moho@@UAE@XZ)
   * Mangled: ??1Silhouette@Moho@@UAE@XZ
   *
   * IDA signature:
   * int __thiscall sub_8144E0(volatile signed __int32 **this);
   *
   * What it does:
   * Releases the owned vertex sheet at offset +0x04 during destruction. The
   * compiler inlined the release sequence (use-count decrement + optional
   * dispose vcall, weak-count decrement + optional destroy vcall) twice over
   * the same slot; the second pass is harmless because the slot is cleared
   * in-place by the first and the null guard short-circuits the repeat. The
   * member's own destructor expresses the same observable control flow: one
   * reference release on a non-null slot, none on a null slot.
   */
  Silhouette::~Silhouette() = default;

  /**
   * Address: 0x008145A0 (FUN_008145A0, Moho::Silhouette::Init)
   *
   * IDA signature:
   * int __usercall Moho::Silohouette::Init@<eax>(Moho::Silohouette *a1@<eax>);
   *
   * What it does:
   * Rebuilds the silhouette pass's full-screen quad for the current primary
   * head size. Releases the previous sheet, allocates a fresh four-vertex one,
   * and scales the unit quad out to the head's pixel dimensions. The texture
   * coordinates are scaled by the aspect ratio instead: the longer axis keeps
   * its full 0..1 range and the shorter one is reduced by the ratio between
   * them, so the sampled region stays square.
   */
  void Silhouette::Init()
  {
    mQuadVertexSheet.reset();

    CD3DDevice* const device = D3D_GetDevice();
    ID3DDeviceResources* const resources = device->GetResources();

    CD3DVertexFormat* const vertexFormat = resources->GetVertexFormat(kScreenQuadVertexFormatToken);
    mQuadVertexSheet.reset(
      resources->NewVertexSheet(kScreenQuadStreamUsage, kScreenQuadVertexCount, vertexFormat)
    );

    const auto headWidth = static_cast<float>(static_cast<unsigned int>(device->GetHeadWidth(0U)));
    const auto headHeight = static_cast<float>(static_cast<unsigned int>(device->GetHeadHeight(0U)));

    // Only the smaller extent is compressed; the larger one keeps 1.0. Both
    // comparisons are written the way the binary orders them, so a square head
    // takes the division on both lanes and still yields 1.0.
    const float textureScaleU = (headWidth <= headHeight) ? (headWidth / headHeight) : 1.0f;
    const float textureScaleV = (headHeight <= headWidth) ? (headHeight / headWidth) : 1.0f;

    FillScreenQuadVertexSheet(*mQuadVertexSheet, headWidth, headHeight, textureScaleU, textureScaleV);
  }

  /**
   * Address: 0x008144C0 (FUN_008144C0, Moho::Silhouette::dtr)
   * Mangled: ??_GSilhouette@Moho@@UAEPAXI@Z
   * Slot: 0 (vftable slot 0 -- scalar deleting destructor thunk)
   *
   * IDA signature:
   * void* __thiscall Moho::Silhouette::dtr(Silhouette* this, char deleteFlags);
   *
   * What it does:
   * Runs the virtual destructor (which releases the owned vertex sheet) and
   * conditionally frees backing memory via `operator delete` when the low flag
   * bit is set. Standard MSVC8 scalar deleting destructor thunk at vftable
   * slot 0.
   */
  void* Silhouette::ScalarDeletingDestructor(const std::uint8_t deleteFlags)
  {
    this->~Silhouette();
    if ((deleteFlags & 0x01u) != 0u) {
      ::operator delete(this);
    }
    return this;
  }
} // namespace moho
