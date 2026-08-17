#include "moho/render/Silhouette.h"

#include <new>

#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/ID3DVertexSheet.h"
#include "moho/render/ScreenQuadVertexSheet.h"
#include "moho/render/d3d/CD3DVertexSheet.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/mesh/Mesh.h"
#include "moho/render/camera/GeomCamera3.h"

namespace moho
{
  namespace
  {
    constexpr std::int32_t kSilhouetteQuadPrimitiveToken = 5;   // D3DPT_TRIANGLESTRIP
    constexpr std::int32_t kSilhouetteQuadLastVertexIndex = 3;  // four-vertex quad
  } // namespace

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
namespace moho
{
  /**
   * Address: 0x00814820 (FUN_00814820, ?Render@Silhouette@Moho@@QAEXABVGeomCamera3@2@H@Z)
   *
   * IDA signature:
   * int __userpurge Moho::Silhouette::Render@<eax>(
   *     Moho::GeomCamera3 *a1@<edi>, Moho::Silohouette *a2, int a3);
   *
   * What it does:
   * Renders the silhouette overlay into `renderTargetIndex`: binds the target
   * and the camera's viewport rectangle, lets the mesh renderer lay down the
   * occluder and outline passes, then composites the result with the frame
   * effect's `TSilhouette` technique over a fullscreen quad.
   *
   * IDA names `a2` as the instance and puts the camera in `edi`, so `this` is
   * the stack argument here.
   */
  void Silhouette::Render(const GeomCamera3& camera, const std::int32_t renderTargetIndex)
  {
    MeshRenderer* const renderer = MeshRenderer::GetInstance();
    CD3DDevice* const device = D3D_GetDevice();

    // Row 3 of the camera's viewport matrix carries (x, y, width, height).
    const auto& viewportRect = camera.viewport.r[3];

    device->SetRenderTarget2(renderTargetIndex, false, 0, 1.0f, 0);

    Wm3::Vector2i viewportPos{static_cast<int>(viewportRect.x), static_cast<int>(viewportRect.y)};
    Wm3::Vector2i viewportSize{static_cast<int>(viewportRect.z), static_cast<int>(viewportRect.w)};
    device->SetViewport(&viewportPos, &viewportSize, 0.0f, 1.0f);

    renderer->RenderSilhouette(camera);

    device->SelectFxFile("frame");
    device->SelectTechnique("TSilhouette");

    CD3DVertexSheetViewRuntime quadView{};
    quadView.sheet = mQuadVertexSheet.get();
    quadView.startVertex = 0;
    quadView.baseVertex = 0;
    quadView.endVertex = kSilhouetteQuadLastVertexIndex;

    std::int32_t primitiveType = kSilhouetteQuadPrimitiveToken;
    (void)device->DrawPrimitiveList(&quadView, &primitiveType);
  }
} // namespace moho
