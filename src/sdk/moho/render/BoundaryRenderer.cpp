#include "moho/render/BoundaryRenderer.h"

#include <cstdint>

#include "boost/shared_ptr.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/DrawIndexedContext.hpp"
#include "gpg/gal/Head.hpp"
#include "gpg/gal/backends/d3d9/DeviceD3D9.hpp"
#include "gpg/gal/backends/d3d9/EffectD3D9.hpp"
#include "gpg/gal/backends/d3d9/EffectTechniqueD3D9.hpp"
#include "gpg/gal/backends/d3d9/EffectVariableD3D9.hpp"
#include "legacy/containers/String.h"
#include "moho/render/VisionRenderer.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/STIMap.h"
#include "Wm3AxisAlignedBox3.h"
#include "Wm3Vector3.h"

namespace
{
  /**
   * Vertical span the boundary wall is extruded over. Both values are read from
   * rodata by `RenderPlayableBoundary`, not immediates: `movss xmm0,
   * ds:dword_E4F86C` at 0x007D022D is the floor and `movss xmm0, ds:dword_E4F868`
   * at 0x007D0247 is the ceiling.
   */
  constexpr float kBoundaryVolumeFloor = -256.0f;
  constexpr float kBoundaryVolumeCeiling = 250.0f;

  /**
   * Squared world-unit tolerance (`ds:dword_DFF0AC`, compared at 0x007D02D5)
   * under which a playable-rect edge counts as coincident with the map edge.
   */
  constexpr float kBoundaryEdgeMatchToleranceSq = 0.001f;

  /** `D3DPT_TRIANGLELIST`, pushed as the topology token at 0x007D0BA4. */
  constexpr int kTriangleListTopology = 4;

  /** Corner count and index count of the unit box the boundary shader casts. */
  constexpr int kBoundaryBoxVertexCount = 8;
  constexpr int kBoundaryBoxIndexCount = 36;

  [[nodiscard]] bool BoundaryEdgesDiffer(const float mapEdge, const float playableEdge) noexcept
  {
    const float delta = mapEdge - playableEdge;
    return (delta * delta) >= kBoundaryEdgeMatchToleranceSq;
  }

  /**
   * Address: 0x007D08D0 (FUN_007D08D0, sub_7D08D0)
   *
   * IDA signature:
   * void __userpurge sub_7D08D0(_DWORD *a1@<edx>, float *a2@<ecx>, int a3,
   *         unsigned int a4, int a5, int a6);
   *
   * IDA lists four stack arguments but the shipped body is `retn 0Ch`
   * (0x007D0D5F lane) with three, and it aliases the technique-name string and
   * the camera onto the same synthetic `a6`. Decoded from the shipped body:
   * `edx` is the `BoxRenderer` whose `+0x04/+0x0C/+0x14` shared-pointer pairs
   * are bound as the vertex format / vertex buffer / index buffer
   * (0x007D0AD2 / 0x007D0B06 / 0x007D0B40), `ecx` is a six-float
   * min/max corner pair (0x007D09F7..0x007D0A19), the first stack argument is
   * the head index (0x007D0901), the second is the camera whose `+0x5C` view
   * and `+0x1C` projection matrices are pushed at 0x007D0A99 / 0x007D0AA8, and
   * the third is the technique-name string read through its SSO lane at
   * 0x007D092C.
   *
   * What it does:
   * Binds the `"vision"` effect with the named technique, uploads the camera
   * matrices plus the volume's center/half-extent as `boxCenter` / `boxExtent`,
   * and draws the unit box once per technique pass so the shader can stencil the
   * volume.
   */
  void CastBoundaryVolume(
    moho::BoxRenderer& body,
    const Wm3::AxisAlignedBox3f& volume,
    const unsigned int headIndex,
    const moho::GeomCamera3& camera,
    const msvc8::string& techniqueName
  )
  {
    auto* const device = reinterpret_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());

    // 0x007D090B resolves the head and drops the result on the floor - `eax` is
    // overwritten by the effect lookup at 0x007D0914 before it is ever read.
    static_cast<void>(device->GetDeviceContext()->GetHead(headIndex));

    const boost::shared_ptr<gpg::gal::EffectD3D9> effect = moho::AcquireVisionBaseEffect();

    const boost::shared_ptr<gpg::gal::EffectTechniqueD3D9> technique =
      effect->SetTechnique(techniqueName.c_str());
    const boost::shared_ptr<gpg::gal::EffectVariableD3D9> viewMatrix = effect->SetMatrix("viewMatrix");
    const boost::shared_ptr<gpg::gal::EffectVariableD3D9> projMatrix = effect->SetMatrix("projMatrix");
    const boost::shared_ptr<gpg::gal::EffectVariableD3D9> boxCenter = effect->SetMatrix("boxCenter");
    const boost::shared_ptr<gpg::gal::EffectVariableD3D9> boxExtent = effect->SetMatrix("boxExtent");

    const float center[3] = {
      (volume.Min.x + volume.Max.x) * 0.5f,
      (volume.Min.y + volume.Max.y) * 0.5f,
      (volume.Min.z + volume.Max.z) * 0.5f
    };
    const float halfExtent[3] = {
      (volume.Max.x - volume.Min.x) * 0.5f,
      (volume.Max.y - volume.Min.y) * 0.5f,
      (volume.Max.z - volume.Min.z) * 0.5f
    };

    viewMatrix->SetMatrix4x4(&camera.view);
    projMatrix->SetMatrix4x4(&camera.projection);
    boxCenter->SetMem(3u, center);
    boxExtent->SetMem(3u, halfExtent);

    device->SetVertexDeclaration(body.mGeometry.mVertexFormat);
    device->SetVertexBuffer(0u, body.mGeometry.mVertexBuffer, 1, 0);
    device->SetBufferIndices(body.mGeometry.mIndexBuffer);

    const int passCount = technique->BeginTechnique();
    for (int pass = 0; pass < passCount; ++pass) {
      technique->BeginPass(pass);

      const gpg::gal::DrawIndexedContext draw{
        kTriangleListTopology, kBoundaryBoxVertexCount, kBoundaryBoxIndexCount, 0, 0
      };
      static_cast<void>(device->DrawIndexedPrimitive(&draw));

      technique->EndPass();
    }
    technique->EndTechnique();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x007D00A0 (FUN_007D00A0, Moho::BoundaryRenderer::BoundaryRenderer)
   */
  BoundaryRenderer::BoundaryRenderer()
    : mBoundaryRendererBody()
    , mFrame()
  {}

  /**
   * Address: 0x007D0100 (FUN_007D0100, Moho::BoundaryRenderer::dtr)
   * Address: 0x007D0120 (FUN_007D0120, Moho::BoundaryRenderer::~BoundaryRenderer)
   */
  BoundaryRenderer::~BoundaryRenderer() = default;

  /**
   * Address: 0x007D05D0 (FUN_007D05D0, Moho::BoundaryRenderer::Init)
   */
  void BoundaryRenderer::Init(BoxRenderer* const boundaryRendererBody)
  {
    if (!boundaryRendererBody) {
      return;
    }

    boundaryRendererBody->InitializeGeometryResources();
  }

  void BoundaryRenderer::Init()
  {
    Init(&mBoundaryRendererBody);
  }

  /**
   * Address: 0x007D01C0 (FUN_007D01C0, func_RenBoundary)
   *
   * IDA signature:
   * void __thiscall func_RenBoundary(void *this, Moho::BoundaryRenderer *a4, int a3, int _AC);
   *
   * What it does:
   * Renders the playable-area boundary wall for one head, skipping the pass when
   * the playable rect and the terrain bounds coincide on all four horizontal
   * edges.
   */
  void RenderPlayableBoundary(
    const unsigned int headIndex,
    BoundaryRenderer& boundary,
    CWldSession& session,
    const GeomCamera3& camera
  )
  {
    auto* const device = reinterpret_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    const gpg::gal::Head& head = device->GetDeviceContext()->GetHead(headIndex);

    const STIMap* const map = session.GetSTIMap();
    const gpg::Rect2i& playableRect = map->mPlayableRect;

    const float playableMinX = static_cast<float>(playableRect.x0);
    const float playableMinZ = static_cast<float>(playableRect.z0);
    const float playableMaxX = static_cast<float>(playableRect.x1);
    const float playableMaxZ = static_cast<float>(playableRect.z1);

    // The playable volume is the playable rect extruded over the fixed vertical
    // span; the outer volume is the terrain's own bounds extruded the same way
    // (0x007D02AB / 0x007D02B9 overwrite the Y lanes GetBounds3D just produced).
    const Wm3::AxisAlignedBox3f playableVolume{
      Wm3::Vector3f{playableMinX, kBoundaryVolumeFloor, playableMinZ},
      Wm3::Vector3f{playableMaxX, kBoundaryVolumeCeiling, playableMaxZ}
    };

    Wm3::AxisAlignedBox3f mapVolume = map->GetBounds3D();
    mapVolume.Min.y = kBoundaryVolumeFloor;
    mapVolume.Max.y = kBoundaryVolumeCeiling;

    const bool boundaryIsVisible =
      BoundaryEdgesDiffer(mapVolume.Min.x, playableMinX)
      || BoundaryEdgesDiffer(mapVolume.Max.x, playableMaxX)
      || BoundaryEdgesDiffer(mapVolume.Min.z, playableMinZ)
      || BoundaryEdgesDiffer(mapVolume.Max.z, playableMaxZ);
    if (!boundaryIsVisible) {
      return;
    }

    device->Clear(false, false, true, 0xFFFFFFFFu, 1.0f, 0);

    // Outer shell clockwise, playable shell counter-clockwise: the two casts
    // leave exactly the ring between them marked in the stencil buffer.
    const msvc8::string outerTechnique{"CastBoundaryCW"};
    CastBoundaryVolume(boundary.mBoundaryRendererBody, mapVolume, headIndex, camera, outerTechnique);

    const msvc8::string innerTechnique{"CastBoundaryCCW"};
    CastBoundaryVolume(boundary.mBoundaryRendererBody, playableVolume, headIndex, camera, innerTechnique);

    const auto headWidth = static_cast<std::int32_t>(head.mWidth);
    const auto headHeight = static_cast<std::int32_t>(head.mHeight);

    boundary.mFrame.InitTransformedVerts(static_cast<float>(headWidth), static_cast<float>(headHeight));
    // 0x007D042A constructs the name in place over `mFrame.mName`; both labels
    // used here are short enough to stay in the string's inline buffer, so a
    // plain assignment reproduces the resulting state without leaking.
    boundary.mFrame.mName = "Boundary";
    boundary.mFrame.Render(headWidth, headHeight);
  }
} // namespace moho
