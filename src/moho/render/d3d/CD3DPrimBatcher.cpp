#include "CD3DPrimBatcher.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cmath>
#include <cstring>
#include <new>
#include <stdexcept>

#include "gpg/core/utils/BoostWrappers.h"
#include "gpg/gal/EffectVariable.hpp"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/ID3DIndexSheet.h"
#include "moho/render/ID3DTextureSheet.h"
#include "moho/render/ID3DVertexStream.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DIndexSheet.h"
#include "moho/render/d3d/CD3DTextureBatcher.h"
#include "moho/render/d3d/CD3DVertexSheet.h"
#include "moho/render/d3d/ShaderVar.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "moho/render/textures/CD3DDynamicTextureSheet.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/sim/STIMap.h"
#include "moho/ui/CUIManager.h"
#include "moho/ui/UiRuntimeTypes.h"

namespace moho
{
  // Declared in moho/math/QuaternionMath.h; that header is not included here
  // because its header-scope yaw constants would add dynamic initializers to
  // this translation unit.
  Wm3::Vector3f* MultQuadVec(Wm3::Vector3f* dest, const Wm3::Vector3f* vec, const Wm3::Quaternionf* quat);
  Wm3::Quaternionf* QuatCrossAdd(
    Wm3::Quaternionf* dest, Wm3::Vector3f v1, Wm3::Vector3f v2, const Wm3::Vector3f& fallbackAxis
  );
}

namespace
{
  constexpr float kTau = 6.28318530717958647692f;
  // Fixed queue capacity the constructor reserves for both batcher queues
  // (0x00438433/0x0043843B); Draw*/Add* flush before a primitive would
  // overflow it.
  constexpr std::uint32_t kPrimQueueCapacity = 0x8000u;
  constexpr std::uint32_t kAxisColorX = 0xFFFF0000u;
  constexpr std::uint32_t kAxisColorY = 0xFF00FF00u;
  constexpr std::uint32_t kAxisColorZ = 0xFF0000FFu;
  constexpr std::int32_t kMode1PrimitiveType = 1;
  constexpr std::int32_t kLineListPrimitiveType = 2;
  constexpr std::int32_t kTriangleListPrimitiveType = 4;
  constexpr std::uint32_t kRectEdgeSubdivisionCount = 10u;
  constexpr float kRectEdgeSubdivisionStep = 1.0f / 10.0f;
  constexpr float kRectTerrainBias = 0.1f;
  // FAF FA-Binary-Patches (hooks/HDraw.cpp): 48 segments instead of the shipped 20 (0x00455E53 and
  // 0x004561E4 `0x14` -> `0x30`), and the angle step 2*pi/48 (0x00455E30 now loads SEGMENT_RAD
  // instead of the shipped 0.31415927 = 2*pi/20).
  constexpr std::uint32_t kOvalSegmentCount = moho::kDrawOvalSegmentCount;
  constexpr float kOvalAngleStep = 0.1308996939f;
  // FAF FA-Binary-Patches (section/DrawCircleSetColor.cpp, hooks/HDraw.cpp): the colour (shipped
  // as the immediate at 0x004561A8) and the band half width (shipped as 0.5 at 0x00456264 /
  // 0x004562CD) became the globals CIRCLE_COLOR and THICKNESS, which UI_DrawCircle overwrites.
  // They are parameters here; these are the globals' initial values, which the build-assist
  // circle keeps.
  constexpr std::uint32_t kOvalBandColor = 0xFF00D800u;
  constexpr float kOvalBandHalfWidth = 0.1f;
  constexpr std::uint16_t kUnmappedIndexedVertex = 0xFFFFu;

  static_assert(
    sizeof(moho::VMatrix4) == sizeof(gpg::gal::Matrix),
    "CD3DPrimBatcher camera matrix lanes must match VMatrix4 storage"
  );

  [[nodiscard]] moho::Vector3f BuildGlyphCorner(
    const moho::Vector3f& origin,
    const moho::Vector3f& xAxis,
    const float xScale,
    const moho::Vector3f& yAxis,
    const float yScale
  ) noexcept
  {
    return {
      origin.x + (xAxis.x * xScale) + (yAxis.x * yScale),
      origin.y + (xAxis.y * xScale) + (yAxis.y * yScale),
      origin.z + (xAxis.z * xScale) + (yAxis.z * yScale),
    };
  }

  [[nodiscard]] moho::CD3DPrimBatcher::Vertex MakeVertex(
    const moho::Vector3f& position, const std::uint32_t color, const float u, const float v
  ) noexcept
  {
    return {position.x, position.y, position.z, color, u, v};
  }

  void DrawLine(
    moho::CD3DPrimBatcher* const primBatcher,
    const moho::Vector3f& start,
    const moho::Vector3f& end,
    const std::uint32_t color
  )
  {
    if (primBatcher == nullptr) {
      return;
    }

    const moho::CD3DPrimBatcher::Vertex startVertex = MakeVertex(start, color, 0.0f, 0.0f);
    const moho::CD3DPrimBatcher::Vertex endVertex = MakeVertex(end, color, 1.0f, 0.0f);
    primBatcher->DrawLine(startVertex, endVertex);
  }

  // `QuatCrossAdd` used to be duplicated here with the textbook `.w`-scalar
  // field layout (dot product in `.w`, cross terms in `.x/.y/.z`). Ground
  // truth for every caller of this quaternion (`FUN_00453ED0.c` /
  // `Moho::DRAW_WireCircle`, and `Moho::DRAW_Circle`'s own doc comment below)
  // calls the real, already-fixed `Moho::QuatCrossAdd` (0x0044F880, defined
  // in Sim.cpp) directly, so the local duplicate is removed in favor of that
  // canonical definition -- see its doc comment for the scalar-first layout.

  [[nodiscard]] moho::Vector3f RotateByQuaternion(
    const moho::Vector3f& vector, const Wm3::Quaternionf& orientation
  ) noexcept
  {
    moho::Vector3f rotated{};
    moho::MultQuadVec(&rotated, &vector, &orientation);
    return rotated;
  }

  /**
   * Address: 0x007FC1C0 (FUN_007FC1C0)
   *
   * What it does:
   * Disposes one `sp_counted_impl_p<CD3DPrimBatcher>` payload by running
   * non-deleting `CD3DPrimBatcher` teardown and releasing owned storage.
   */
  void DisposeCountedPrimBatcherStorage(
    boost::SpCountedImplStorage<moho::CD3DPrimBatcher>* const countedStorage
  )
  {
    moho::CD3DPrimBatcher* const ownedBatcher = countedStorage->px;
    if (ownedBatcher != nullptr) {
      ownedBatcher->~CD3DPrimBatcher();
      ::operator delete(static_cast<void*>(ownedBatcher));
    }
  }

  [[nodiscard]] moho::CD3DPrimBatcher::Vertex BuildTransformedVertex(
    const moho::CD3DPrimBatcher& runtime,
    const moho::CD3DPrimBatcher::Vertex& source
  ) noexcept
  {
    moho::CD3DPrimBatcher::Vertex transformed = source;
    transformed.mU = runtime.mP2x + (runtime.mP1x * source.mU);
    transformed.mV = runtime.mP2y + (runtime.mP1y * source.mV);
    return transformed;
  }

  [[nodiscard]] float SampleTerrainClampedElevation(
    const moho::CHeightField& heightField,
    const moho::Vector3f& position,
    const float minimumElevation
  )
  {
    return std::max(minimumElevation, heightField.GetElevation(position.x, position.z)) + kRectTerrainBias;
  }

  void AppendPrimitiveIndex(
    moho::CD3DPrimBatcher& runtime,
    const std::uint16_t index
  )
  {
    runtime.mPrimitives.push_back(static_cast<std::int16_t>(index));
  }

  void InitializeIndexedVertexRemap(gpg::fastvector<std::uint16_t>& remap, const std::uint32_t sourceVertexCount)
  {
    remap.Clear();
    remap.Reserve(sourceVertexCount);
    for (std::uint32_t index = 0; index < sourceVertexCount; ++index) {
      remap.PushBack(kUnmappedIndexedVertex);
    }
  }

  void ResetIndexedVertexRemap(gpg::fastvector<std::uint16_t>& remap) noexcept
  {
    const std::size_t remapSize = remap.size();
    for (std::size_t index = 0; index < remapSize; ++index) {
      remap[index] = kUnmappedIndexedVertex;
    }
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00438310 (FUN_00438310, ??0CD3DPrimBatcher@Moho@@QAE@PAVCD3DTextureBatcher@1@@Z)
   *
   * What it does:
   * Initializes one prim-batcher runtime lane, allocates three dynamic vertex
   * sheets and one dynamic index sheet from device resources, and seeds
   * identity view/projection/composite matrices.
   */
  CD3DPrimBatcher::CD3DPrimBatcher(CD3DTextureBatcher* const textureBatcher)
    : mTextureBatcher(textureBatcher)
  {
    auto* const runtime = this;

    const VMatrix4 identity = VMatrix4::Identity();
    runtime->mViewMatrix = identity;
    runtime->mProjectionMatrix = identity;
    runtime->mComposite = identity;

    ID3DDeviceResources* const resources = D3D_GetDevice()->GetResources();
    for (CD3DVertexSheet*& sheet : runtime->mVertexSheets) {
      CD3DVertexFormat* const vertexFormat = resources->GetVertexFormat(6);
      sheet = resources->NewVertexSheet(1u, 0x8000, vertexFormat);
    }

    runtime->mIndexSheet = resources->CreateIndexSheet(true, 0x8000);

    // Binary order (0x00438433 then 0x0043843B): the vertex queue reserve is
    // emitted first (`reserve` body 0x0043A470), then the index queue reserve
    // (0x0043A6C0). Both preallocate the 0x8000-element flush capacity.
    runtime->mVertices.reserve(kPrimQueueCapacity);
    runtime->mPrimitives.reserve(kPrimQueueCapacity);
  }

  /**
   * Address: 0x00438460 (FUN_00438460, Moho::CD3DPrimBatcher::~CD3DPrimBatcher)
   *
   * IDA signature:
   * void __stdcall Moho::CD3DPrimBatcher::~CD3DPrimBatcher(int a1);
   *
   * What it does:
   * Destroys the three vertex sheets and the index sheet through their
   * typed `Destroy` virtuals. The remaining teardown - the batch-texture
   * handle release (+0x48 control block, 0x004384A8), the dynamic-sheet
   * handle release (+0x40, 0x004384DE), then the index and vertex queue
   * vector frees (+0x2C/+0x1C, 0x00438517/0x00438530) - runs in reverse
   * member order and is emitted by the member destructors themselves.
   */
  CD3DPrimBatcher::~CD3DPrimBatcher()
  {
    for (CD3DVertexSheet* const sheet : mVertexSheets) {
      if (sheet != nullptr) {
        sheet->Destroy();
      }
    }

    if (mIndexSheet != nullptr) {
      mIndexSheet->Destroy();
    }
  }

  /**
   * Address: 0x00438560 (FUN_00438560)
   *
   * What it does:
   * Selects one prim-batcher effect file/technique pair and invalidates the
   * currently uploaded composite matrix lane.
   */
  CD3DPrimBatcher* CD3DPrimBatcher::Setup(const char* const techniqueName)
  {
    CD3DDevice* const device = D3D_GetDevice();
    device->SelectFxFile("primbatcher");
    device->SelectTechnique(techniqueName);

    this->mRebuildComposite = 0;
    return this;
  }

  /**
   * Address: 0x004385A0 (?SetViewMatrix@CD3DPrimBatcher@Moho@@QAEXABUVMatrix4@2@@Z)
   *
   * What it does:
   * Flushes queued primitives when needed, then updates the current view matrix
   * and marks the composite matrix lane as dirty.
   */
  void CD3DPrimBatcher::SetViewMatrix(const VMatrix4& matrix)
  {
    auto* const runtime = this;
    if (!runtime->mVertices.empty()) {
      Flush();
    }

    runtime->mViewMatrix = matrix;
    runtime->mResetComposite = 1;
  }

  /**
   * Address: 0x004385F0 (?SetProjectionMatrix@CD3DPrimBatcher@Moho@@QAEXABUVMatrix4@2@@Z)
   *
   * What it does:
   * Flushes queued primitives when needed, then updates the current projection
   * matrix and marks the composite matrix lane as dirty.
   */
  void CD3DPrimBatcher::SetProjectionMatrix(const VMatrix4& matrix)
  {
    auto* const runtime = this;
    if (!runtime->mVertices.empty()) {
      Flush();
    }

    runtime->mProjectionMatrix = matrix;
    runtime->mResetComposite = 1;
  }

  /**
   * Address: 0x00438640 (FUN_00438640)
   *
   * What it does:
   * Flushes queued primitives when needed, then updates both view/projection
   * matrices from one camera payload and marks the composite matrix lane dirty.
   */
  void CD3DPrimBatcher::SetViewProjMatrix(const GeomCamera3& camera)
  {
    auto* const runtime = this;
    if (!runtime->mVertices.empty()) {
      Flush();
    }

    runtime->mViewMatrix = camera.view;
    runtime->mProjectionMatrix = camera.projection;
    runtime->mResetComposite = 1;
  }

  /**
   * Address: 0x0043A8B0 (FUN_0043A8B0)
   * Mangled: ??1WeakPtr_CD3DBatchTexture@Moho@@QAE@@Z
   *          (analyst label; the emitted body is the out-of-line
   *           `boost::shared_ptr<Moho::CD3DBatchTexture>::reset()` instantiation)
   *
   * IDA signature:
   * void __usercall Moho::WeakPtr_CD3DBatchTexture::~WeakPtr_CD3DBatchTexture(
   *     boost::shared_ptr_CD3DBatchTexture *result@<eax>);
   *
   * What it does:
   * Empties one `shared_ptr<CD3DBatchTexture>` lane in place and drops one
   * strong owner reference from the detached control block.
   *
   * The 25-instruction body is `reset()`, not `~shared_ptr()`: it *stores*
   * null into `px` (+0x00) and `pn.pi_` (+0x04) before touching the counters,
   * which is the optimiser's rendering of boost 1.34.1's
   * `this_type().swap(*this)`. A destructor would have no reason to write the
   * lanes at all. The release path (`lock xadd [pi+4], -1` -> vslot +0x04
   * `dispose()` -> `lock xadd [pi+8], -1` -> vslot +0x08 `destroy()`) is
   * `sp_counted_base::release()` with `weak_release()` inlined into it.
   */
  void ResetSharedBatchTextureHandle(boost::shared_ptr<CD3DBatchTexture>& handle) noexcept
  {
    handle.reset();
  }

  /**
   * Address: 0x0043A860 (FUN_0043A860)
   * Mangled: ??1WeakPtr_CD3DDynamicTextureSheet@Moho@@QAE@@Z
   *          (analyst label; the emitted body is the out-of-line
   *           `boost::shared_ptr<Moho::CD3DDynamicTextureSheet>::reset()`
   *           instantiation)
   *
   * IDA signature:
   * void __usercall Moho::WeakPtr_CD3DDynamicTextureSheet::~WeakPtr_CD3DDynamicTextureSheet(
   *     boost::shared_ptr_CD3DDynamicTextureSheet *result@<eax>);
   *
   * What it does:
   * Empties one `shared_ptr<CD3DDynamicTextureSheet>` lane in place and drops
   * one strong owner reference from the detached control block.
   *
   * Byte-identical to `ResetSharedBatchTextureHandle` above (both hash to
   * 597fd943...); the two remain distinct functions because they are distinct
   * template instantiations, and the caller picks them per lane - +0x44 for
   * the batch texture, +0x3C for the sheet.
   */
  void ResetSharedDynamicTextureSheetHandle(boost::shared_ptr<CD3DDynamicTextureSheet>& handle) noexcept
  {
    handle.reset();
  }

  /**
   * Address: 0x004386A0 (?SetTexture@CD3DPrimBatcher@Moho@@QAEXABV?$shared_ptr@VCD3DBatchTexture@Moho@@@boost@@@Z)
   *
   * What it does:
   * Switches between direct-texture and atlas-texture paths, flushing queued
   * primitives on mode changes and updating UV scale/border lanes.
   */
  void CD3DPrimBatcher::SetTexture(const boost::shared_ptr<CD3DBatchTexture>& texture)
  {
    auto* const runtime = this;

    const std::uint32_t atlasHalfWidth = static_cast<std::uint32_t>(runtime->mTextureBatcher->mWidth) >> 1u;
    const std::uint32_t atlasHalfHeight = static_cast<std::uint32_t>(runtime->mTextureBatcher->mHeight) >> 1u;
    const bool useDirectTexture = texture->mWidth >= atlasHalfWidth || texture->mHeight >= atlasHalfHeight;

    if (useDirectTexture) {
      if (!runtime->mVertices.empty() && runtime->mTexture.get() != texture.get()) {
        Flush();
      }

      runtime->mTexture = texture;

      CD3DBatchTexture::TextureSheetHandle textureSheet{};
      Wm3::Vector2f uvScale{};
      Wm3::Vector2f uvBorder{};
      texture->GetTextureSheet(textureSheet, uvScale, uvBorder);

      runtime->mDynamicTexSheet = texture->mTextureSheet;
      runtime->mP1x = uvScale.x;
      runtime->mP1y = uvScale.y;
      runtime->mP2x = uvBorder.x;
      runtime->mP2y = uvBorder.y;
      return;
    }

    if (!runtime->mVertices.empty() && runtime->mDynamicTexSheet) {
      Flush();
    }

    const gpg::Rect2f* uvRect = runtime->mTextureBatcher->AddTexture(texture);
    if (uvRect == nullptr) {
      if (!runtime->mVertices.empty()) {
        Flush();
      }
      runtime->mTextureBatcher->Reset();
      uvRect = runtime->mTextureBatcher->AddTexture(texture);
    }

    // Binary order: 0x00438728 `lea eax, [edi+44h]` -> call 0x0043A8B0 (batch
    // texture lane), then 0x00438730 `lea eax, [edi+3Ch]` -> call 0x0043A860
    // (dynamic sheet lane). Both lanes are dropped before the atlas UV rect is
    // published, so a subsequent Flush takes the composite-atlas branch.
    ResetSharedBatchTextureHandle(runtime->mTexture);
    ResetSharedDynamicTextureSheetHandle(runtime->mDynamicTexSheet);

    runtime->mP2x = uvRect->x0;
    runtime->mP2y = uvRect->z0;
    runtime->mP1x = uvRect->x1 - uvRect->x0;
    runtime->mP1y = uvRect->z1 - uvRect->z0;
  }

  /**
   * Address: 0x00438870 (FUN_00438870, ?SetTexture@CD3DPrimBatcher@Moho@@QAEXV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@@Z)
   *
   * What it does:
   * Binds one retained dynamic texture sheet directly without going through
   * the atlas path. Flushes queued primitives if a different sheet is already
   * bound, releases any held batch-texture handle, assigns the new sheet to
   * the dynamic-sheet handle lane, and resets UV scale/border to the identity
   * rectangle (scale = 1,1; border = 0,0).
   *
   * Parameter is the ID3DTextureSheet base interface, but the runtime
   * invariant across all call sites is that the concrete sheet is always a
   * CD3DDynamicTextureSheet (binary directly stores the derived pointer
   * without a virtual downcast guard).
   */
  void CD3DPrimBatcher::SetTexture(boost::shared_ptr<ID3DTextureSheet> sheet)
  {
    auto* const runtime = this;

    const boost::shared_ptr<CD3DDynamicTextureSheet> derivedSheet =
      boost::static_pointer_cast<CD3DDynamicTextureSheet>(sheet);

    if (!runtime->mVertices.empty() && runtime->mDynamicTexSheet.get() != derivedSheet.get()) {
      Flush();
    }

    // 0x004388C0-0x004388E8 inlines the very same lane reset the atlas path
    // reaches through 0x0043A8B0; expressed here through the named recovery so
    // both emissions share one source body.
    ResetSharedBatchTextureHandle(runtime->mTexture);
    runtime->mDynamicTexSheet = derivedSheet;

    runtime->mP2x = 0.0f;
    runtime->mP2y = 0.0f;
    runtime->mP1x = 1.0f;
    runtime->mP1y = 1.0f;
  }

  /**
   * Address: 0x004389A0 (?DrawQuad@CD3DPrimBatcher@Moho@@QAEXABUVertex@12@000@Z)
   *
   * What it does:
   * Appends one textured quad as 4 transformed vertices + 6 indices and
   * flushes first when primitive mode/capacity lanes would overflow.
   */
  void CD3DPrimBatcher::DrawQuad(
    const Vertex& topLeft,
    const Vertex& topRight,
    const Vertex& bottomRight,
    const Vertex& bottomLeft
  )
  {
    auto* const runtime = this;

    if (!runtime->mVertices.empty()) {
      const std::uint32_t vertexCount = static_cast<std::uint32_t>(runtime->mVertices.size());
      const std::uint32_t primitiveCount = static_cast<std::uint32_t>(runtime->mPrimitives.size());
      if (runtime->mMode != static_cast<std::uint32_t>(kTriangleListPrimitiveType) ||
          (vertexCount + 4u) > kPrimQueueCapacity ||
          (primitiveCount + 6u) > kPrimQueueCapacity) {
        Flush();
      }
    }

    runtime->mMode = static_cast<std::uint32_t>(kTriangleListPrimitiveType);

    const std::uint16_t baseVertexIndex =
      static_cast<std::uint16_t>(runtime->mVertices.size());

    runtime->mVertices.push_back(BuildTransformedVertex(*runtime, topLeft));
    runtime->mVertices.push_back(BuildTransformedVertex(*runtime, topRight));
    runtime->mVertices.push_back(BuildTransformedVertex(*runtime, bottomRight));
    runtime->mVertices.push_back(BuildTransformedVertex(*runtime, bottomLeft));

    AppendPrimitiveIndex(*runtime, baseVertexIndex);
    AppendPrimitiveIndex(*runtime, static_cast<std::uint16_t>(baseVertexIndex + 1u));
    AppendPrimitiveIndex(*runtime, static_cast<std::uint16_t>(baseVertexIndex + 2u));
    AppendPrimitiveIndex(*runtime, static_cast<std::uint16_t>(baseVertexIndex + 2u));
    AppendPrimitiveIndex(*runtime, static_cast<std::uint16_t>(baseVertexIndex + 3u));
    AppendPrimitiveIndex(*runtime, baseVertexIndex);
  }

  /**
   * Address: 0x00438DA0 (?DrawQuad@CD3DPrimBatcher@Moho@@QAEXABV?$Vector3@M@Wm3@@000I@Z)
   *
   * What it does:
   * Builds one unit-UV quad from four position corners and delegates to the
   * vertex-quad path.
   */
  void CD3DPrimBatcher::DrawQuad(
    const Vector3f& topLeft,
    const Vector3f& topRight,
    const Vector3f& bottomRight,
    const Vector3f& bottomLeft,
    const std::uint32_t color
  )
  {
    const Vertex topLeftVertex = MakeVertex(topLeft, color, 0.0f, 0.0f);
    const Vertex topRightVertex = MakeVertex(topRight, color, 1.0f, 0.0f);
    const Vertex bottomRightVertex = MakeVertex(bottomRight, color, 1.0f, 1.0f);
    const Vertex bottomLeftVertex = MakeVertex(bottomLeft, color, 0.0f, 1.0f);
    DrawQuad(topLeftVertex, topRightVertex, bottomRightVertex, bottomLeftVertex);
  }

  void CD3DPrimBatcher::DrawScreenQuads(const ScreenQuad* const quads, const std::size_t quadCount)
  {
    auto* const runtime = this;
    std::size_t done = 0;
    while (done < quadCount) {
      // `DrawQuad`'s flush test, run once per block: each block ends where the next single-quad
      // call would flush, so the batches come out exactly as the per-quad calls make them.
      if (!runtime->mVertices.empty()) {
        const std::uint32_t vertexCount = static_cast<std::uint32_t>(runtime->mVertices.size());
        const std::uint32_t primitiveCount = static_cast<std::uint32_t>(runtime->mPrimitives.size());
        if (runtime->mMode != static_cast<std::uint32_t>(kTriangleListPrimitiveType) ||
            (vertexCount + 4u) > kPrimQueueCapacity ||
            (primitiveCount + 6u) > kPrimQueueCapacity) {
          Flush();
        }
      }
      runtime->mMode = static_cast<std::uint32_t>(kTriangleListPrimitiveType);

      const std::size_t vertexCount = runtime->mVertices.size();
      const std::size_t primitiveCount = runtime->mPrimitives.size();
      const std::size_t fit = std::min(
        (kPrimQueueCapacity - std::min<std::size_t>(vertexCount, kPrimQueueCapacity)) / 4u,
        (kPrimQueueCapacity - std::min<std::size_t>(primitiveCount, kPrimQueueCapacity)) / 6u
      );
      const std::size_t block = std::min(std::max<std::size_t>(fit, 1u), quadCount - done);

      // Built in small stack batches and appended with one range insert each, so the queues are
      // written once per vertex rather than value-filled by a resize first.
      constexpr std::size_t kStagedQuads = 128u;
      Vertex stagedVertices[kStagedQuads * 4u];
      std::int16_t stagedIndices[kStagedQuads * 6u];
      for (std::size_t first = 0; first < block; first += kStagedQuads) {
        const std::size_t count = std::min(kStagedQuads, block - first);
        Vertex* vertices = stagedVertices;
        std::int16_t* indices = stagedIndices;
        for (std::size_t i = 0; i < count; ++i, vertices += 4, indices += 6) {
          const ScreenQuad& quad = quads[done + first + i];
          vertices[0] = BuildTransformedVertex(*runtime, MakeVertex({quad.mLeft, quad.mTop, 0.0f}, quad.mColor, 0.0f, 0.0f));
          vertices[1] = BuildTransformedVertex(*runtime, MakeVertex({quad.mRight, quad.mTop, 0.0f}, quad.mColor, 1.0f, 0.0f));
          vertices[2] =
            BuildTransformedVertex(*runtime, MakeVertex({quad.mRight, quad.mBottom, 0.0f}, quad.mColor, 1.0f, 1.0f));
          vertices[3] =
            BuildTransformedVertex(*runtime, MakeVertex({quad.mLeft, quad.mBottom, 0.0f}, quad.mColor, 0.0f, 1.0f));

          const std::uint16_t base = static_cast<std::uint16_t>(vertexCount + ((first + i) * 4u));
          indices[0] = static_cast<std::int16_t>(base);
          indices[1] = static_cast<std::int16_t>(base + 1u);
          indices[2] = static_cast<std::int16_t>(base + 2u);
          indices[3] = static_cast<std::int16_t>(base + 2u);
          indices[4] = static_cast<std::int16_t>(base + 3u);
          indices[5] = static_cast<std::int16_t>(base);
        }
        runtime->mVertices.insert(runtime->mVertices.end(), stagedVertices, stagedVertices + (count * 4u));
        runtime->mPrimitives.insert(runtime->mPrimitives.end(), stagedIndices, stagedIndices + (count * 6u));
      }
      done += block;
    }
  }

  /**
   * Address: 0x00438EA0 (FUN_00438EA0)
   *
   * What it does:
   * Flushes on primitive-mode mismatch and appends one non-indexed quad batch.
   */
  void CD3DPrimBatcher::DrawQuads(const Vertex* const sourceVertices, const std::uint32_t quadCount)
  {
    if (quadCount == 0u) {
      return;
    }

    auto* const runtime = this;
    if (!runtime->mVertices.empty() && runtime->mMode != static_cast<std::uint32_t>(kTriangleListPrimitiveType)) {
      Flush();
    }

    runtime->mMode = static_cast<std::uint32_t>(kTriangleListPrimitiveType);
    AddVerts(sourceVertices, quadCount, 4u);
  }

  /**
   * Address: 0x00438EF0 (FUN_00438EF0)
   *
   * What it does:
   * Flushes on primitive-mode mismatch and appends one indexed quad batch.
   */
  void CD3DPrimBatcher::DrawIndexedQuads(
    const Vertex* const sourceVertices,
    const std::uint32_t sourceVertexCount,
    const std::uint16_t* const sourceIndices,
    const std::uint32_t quadCount
  )
  {
    if (quadCount == 0u) {
      return;
    }

    auto* const runtime = this;
    if (!runtime->mVertices.empty() && runtime->mMode != static_cast<std::uint32_t>(kTriangleListPrimitiveType)) {
      Flush();
    }

    runtime->mMode = static_cast<std::uint32_t>(kTriangleListPrimitiveType);
    AddIndexedVerts(sourceVertices, sourceVertexCount, sourceIndices, quadCount, 4u);
  }

  /**
   * Address: 0x00438F50 (?DrawTri@CD3DPrimBatcher@Moho@@QAEXABUVertex@12@00@Z)
   *
   * What it does:
   * Emits one textured/color triangle and flushes first when mode/capacity lanes
   * would overflow.
   */
  void CD3DPrimBatcher::DrawTri(const Vertex& v0, const Vertex& v1, const Vertex& v2)
  {
    auto* const runtime = this;

    if (!runtime->mVertices.empty()) {
      const std::uint32_t vertexCount = static_cast<std::uint32_t>(runtime->mVertices.size());
      const std::uint32_t primitiveCount = static_cast<std::uint32_t>(runtime->mPrimitives.size());
      if (runtime->mMode != static_cast<std::uint32_t>(kTriangleListPrimitiveType) ||
          (vertexCount + 3u) > kPrimQueueCapacity ||
          (primitiveCount + 3u) > kPrimQueueCapacity) {
        Flush();
      }
    }

    runtime->mMode = static_cast<std::uint32_t>(kTriangleListPrimitiveType);

    const std::uint16_t baseVertexIndex =
      static_cast<std::uint16_t>(runtime->mVertices.size());

    AddVert(v0);
    AddVert(v1);
    AddVert(v2);

    AppendPrimitiveIndex(*runtime, baseVertexIndex);
    AppendPrimitiveIndex(*runtime, static_cast<std::uint16_t>(baseVertexIndex + 1u));
    AppendPrimitiveIndex(*runtime, static_cast<std::uint16_t>(baseVertexIndex + 2u));
  }

  /**
   * Address: 0x00439210 (FUN_00439210)
   *
   * What it does:
   * Flushes on primitive-mode mismatch and appends one non-indexed triangle
   * batch.
   */
  void CD3DPrimBatcher::DrawTriangles(const Vertex* const sourceVertices, const std::uint32_t triangleCount)
  {
    if (triangleCount == 0u) {
      return;
    }

    auto* const runtime = this;
    if (!runtime->mVertices.empty() && runtime->mMode != static_cast<std::uint32_t>(kTriangleListPrimitiveType)) {
      Flush();
    }

    runtime->mMode = static_cast<std::uint32_t>(kTriangleListPrimitiveType);
    AddVerts(sourceVertices, triangleCount, 3u);
  }

  /**
   * Address: 0x00439260 (FUN_00439260)
   *
   * What it does:
   * Flushes on primitive-mode mismatch and appends one indexed triangle batch.
   */
  void CD3DPrimBatcher::DrawIndexedTriangles(
    const Vertex* const sourceVertices,
    const std::uint32_t sourceVertexCount,
    const std::uint16_t* const sourceIndices,
    const std::uint32_t triangleCount
  )
  {
    if (triangleCount == 0u) {
      return;
    }

    auto* const runtime = this;
    if (!runtime->mVertices.empty() && runtime->mMode != static_cast<std::uint32_t>(kTriangleListPrimitiveType)) {
      Flush();
    }

    runtime->mMode = static_cast<std::uint32_t>(kTriangleListPrimitiveType);
    AddIndexedVerts(sourceVertices, sourceVertexCount, sourceIndices, triangleCount, 3u);
  }

  /**
   * Address: 0x004392C0 (?DrawLine@CD3DPrimBatcher@Moho@@QAEXABUVertex@12@0@Z)
   *
   * What it does:
   * Appends one textured line as 2 transformed vertices + 2 indices and
   * flushes first when primitive mode/capacity lanes would overflow.
   */
  void CD3DPrimBatcher::DrawLine(const Vertex& start, const Vertex& end)
  {
    auto* const runtime = this;

    if (!runtime->mVertices.empty()) {
      const std::uint32_t vertexCount = static_cast<std::uint32_t>(runtime->mVertices.size());
      const std::uint32_t primitiveCount = static_cast<std::uint32_t>(runtime->mPrimitives.size());
      if (runtime->mMode != static_cast<std::uint32_t>(kLineListPrimitiveType) ||
          (vertexCount + 2u) > kPrimQueueCapacity ||
          (primitiveCount + 2u) > kPrimQueueCapacity) {
        Flush();
      }
    }

    runtime->mMode = static_cast<std::uint32_t>(kLineListPrimitiveType);

    const std::uint16_t baseVertexIndex =
      static_cast<std::uint16_t>(runtime->mVertices.size());

    runtime->mVertices.push_back(BuildTransformedVertex(*runtime, start));
    runtime->mVertices.push_back(BuildTransformedVertex(*runtime, end));

    AppendPrimitiveIndex(*runtime, baseVertexIndex);
    AppendPrimitiveIndex(*runtime, static_cast<std::uint16_t>(baseVertexIndex + 1u));
  }

  /**
   * Address: 0x004394D0 (FUN_004394D0)
   *
   * What it does:
   * Flushes on primitive-mode mismatch and appends one non-indexed line batch.
   */
  void CD3DPrimBatcher::DrawLines(const Vertex* const sourceVertices, const std::uint32_t lineCount)
  {
    if (lineCount == 0u) {
      return;
    }

    auto* const runtime = this;
    if (!runtime->mVertices.empty() && runtime->mMode != static_cast<std::uint32_t>(kLineListPrimitiveType)) {
      Flush();
    }

    runtime->mMode = static_cast<std::uint32_t>(kLineListPrimitiveType);
    AddVerts(sourceVertices, lineCount, 2u);
  }

  /**
   * Address: 0x00439520 (FUN_00439520)
   *
   * What it does:
   * Flushes on primitive-mode mismatch and appends one indexed line batch.
   */
  void CD3DPrimBatcher::DrawIndexedLines(
    const Vertex* const sourceVertices,
    const std::uint32_t sourceVertexCount,
    const std::uint16_t* const sourceIndices,
    const std::uint32_t lineCount
  )
  {
    auto* const runtime = this;
    if (!runtime->mVertices.empty() && runtime->mMode != static_cast<std::uint32_t>(kLineListPrimitiveType)) {
      Flush();
    }

    runtime->mMode = static_cast<std::uint32_t>(kLineListPrimitiveType);
    AddIndexedVerts(sourceVertices, sourceVertexCount, sourceIndices, lineCount, 2u);
  }

  /**
   * Address: 0x00439580 (?DrawPoint@CD3DPrimBatcher@Moho@@QAEXABUVertex@12@@Z)
   *
   * What it does:
   * Emits one point entry; preserves original mode gate that flushes unless the
   * queued lane is triangle mode.
   */
  void CD3DPrimBatcher::DrawPoint(const Vertex& vertex)
  {
    auto* const runtime = this;

    if (!runtime->mVertices.empty()) {
      if (runtime->mMode != static_cast<std::uint32_t>(kTriangleListPrimitiveType)) {
        Flush();
      } else {
        const std::uint32_t vertexCount = static_cast<std::uint32_t>(runtime->mVertices.size());
        const std::uint32_t primitiveCount = static_cast<std::uint32_t>(runtime->mPrimitives.size());
        if ((vertexCount + 2u) > kPrimQueueCapacity ||
            (primitiveCount + 2u) > kPrimQueueCapacity) {
          Flush();
        }
      }
    }

    runtime->mMode = static_cast<std::uint32_t>(kLineListPrimitiveType);

    const std::uint16_t baseVertexIndex =
      static_cast<std::uint16_t>(runtime->mVertices.size());
    AddVert(vertex);
    AppendPrimitiveIndex(*runtime, baseVertexIndex);
  }

  /**
   * Address: 0x004396E0 (FUN_004396E0)
   *
   * What it does:
   * Flushes on primitive-mode mismatch and appends one non-indexed mode-1
   * primitive-pair batch.
   */
  void CD3DPrimBatcher::DrawMode1PrimitivePairs(
    const Vertex* const sourceVertices,
    const std::uint32_t primitivePairCount
  )
  {
    if (primitivePairCount == 0u) {
      return;
    }

    auto* const runtime = this;
    if (!runtime->mVertices.empty() && runtime->mMode != static_cast<std::uint32_t>(kMode1PrimitiveType)) {
      Flush();
    }

    runtime->mMode = static_cast<std::uint32_t>(kMode1PrimitiveType);
    AddVerts(sourceVertices, primitivePairCount, 2u);
  }

  /**
   * Address: 0x00439730 (FUN_00439730)
   *
   * What it does:
   * Flushes on primitive-mode mismatch and appends one indexed mode-1
   * primitive-pair batch.
   */
  void CD3DPrimBatcher::DrawIndexedMode1PrimitivePairs(
    const Vertex* const sourceVertices,
    const std::uint32_t sourceVertexCount,
    const std::uint16_t* const sourceIndices,
    const std::uint32_t primitivePairCount
  )
  {
    if (primitivePairCount == 0u) {
      return;
    }

    auto* const runtime = this;
    if (!runtime->mVertices.empty() && runtime->mMode != static_cast<std::uint32_t>(kMode1PrimitiveType)) {
      Flush();
    }

    runtime->mMode = static_cast<std::uint32_t>(kMode1PrimitiveType);
    AddIndexedVerts(sourceVertices, sourceVertexCount, sourceIndices, primitivePairCount, 2u);
  }

  /**
   * Address: 0x00439790 (?AddVerts@CD3DPrimBatcher@Moho@@AAEXPBUVertex@12@II@Z)
   *
   * What it does:
   * Copies transformed source vertices into the batch queue and emits either
   * direct sequential indices or quad-expanded triangle-list indices.
   */
  void CD3DPrimBatcher::AddVerts(
    const Vertex* sourceVertices,
    std::uint32_t primitiveCount,
    const std::uint32_t verticesPerPrimitive
  )
  {
    if (primitiveCount == 0u) {
      return;
    }

    auto* const runtime = this;
    while (primitiveCount != 0u) {
      const std::uint32_t indicesPerPrimitive = (verticesPerPrimitive == 4u) ? 6u : verticesPerPrimitive;
      const std::uint32_t usedPrimitiveIndices = static_cast<std::uint32_t>(runtime->mPrimitives.size());
      const std::uint32_t usedVertices = static_cast<std::uint32_t>(runtime->mVertices.size());

      const std::uint32_t maxByIndices = (kPrimQueueCapacity - usedPrimitiveIndices) / indicesPerPrimitive;
      const std::uint32_t maxByVertices = (kPrimQueueCapacity - usedVertices) / verticesPerPrimitive;
      const std::uint32_t batchPrimitiveCount = std::min(primitiveCount, std::min(maxByIndices, maxByVertices));
      if (batchPrimitiveCount == 0u) {
        Flush();
        continue;
      }

      const std::uint16_t baseVertexIndex = static_cast<std::uint16_t>(usedVertices);
      const std::uint32_t vertexBatchCount = verticesPerPrimitive * batchPrimitiveCount;

      for (std::uint32_t vertexIndex = 0; vertexIndex < vertexBatchCount; ++vertexIndex) {
        runtime->mVertices.push_back(BuildTransformedVertex(*runtime, sourceVertices[vertexIndex]));
      }
      sourceVertices += vertexBatchCount;

      if (verticesPerPrimitive == 4u) {
        std::uint16_t quadBaseVertex = baseVertexIndex;
        for (std::uint32_t quadIndex = 0; quadIndex < batchPrimitiveCount; ++quadIndex) {
          AppendPrimitiveIndex(*runtime, quadBaseVertex);
          AppendPrimitiveIndex(*runtime, static_cast<std::uint16_t>(quadBaseVertex + 1u));
          AppendPrimitiveIndex(*runtime, static_cast<std::uint16_t>(quadBaseVertex + 2u));
          AppendPrimitiveIndex(*runtime, static_cast<std::uint16_t>(quadBaseVertex + 2u));
          AppendPrimitiveIndex(*runtime, static_cast<std::uint16_t>(quadBaseVertex + 3u));
          AppendPrimitiveIndex(*runtime, quadBaseVertex);
          quadBaseVertex = static_cast<std::uint16_t>(quadBaseVertex + 4u);
        }
      } else {
        for (std::uint32_t vertexIndex = 0; vertexIndex < vertexBatchCount; ++vertexIndex) {
          AppendPrimitiveIndex(*runtime, static_cast<std::uint16_t>(baseVertexIndex + vertexIndex));
        }
      }

      primitiveCount -= batchPrimitiveCount;
    }
  }

  /**
   * Address: 0x00439B60 (?AddVert@CD3DPrimBatcher@Moho@@AAEXABUVertex@12@@Z)
   *
   * What it does:
   * Appends one UV-transformed vertex to the queued vertex stream.
   */
  void CD3DPrimBatcher::AddVert(const Vertex& sourceVertex)
  {
    auto* const runtime = this;
    runtime->mVertices.push_back(BuildTransformedVertex(*runtime, sourceVertex));
  }

  /**
   * Address: 0x0043A060 (?AddIndexedVert@CD3DPrimBatcher@Moho@@AAEGGPBUVertex@12@IAAV?$fastvector@G@gpg@@@Z)
   *
   * What it does:
   * Maps one source index through the per-batch remap table and appends one
   * transformed vertex only for unmapped indices.
   */
  std::uint16_t CD3DPrimBatcher::AddIndexedVert(
    const std::uint16_t sourceIndex,
    const Vertex* const sourceVertices,
    gpg::fastvector<std::uint16_t>& remap
  )
  {
    const std::uint16_t cachedIndex = remap[sourceIndex];
    if (cachedIndex != kUnmappedIndexedVertex) {
      return cachedIndex;
    }

    auto* const runtime = this;
    const std::uint16_t mappedIndex = static_cast<std::uint16_t>(runtime->mVertices.size());

    runtime->mVertices.push_back(BuildTransformedVertex(*runtime, sourceVertices[sourceIndex]));

    remap[sourceIndex] = mappedIndex;
    return mappedIndex;
  }

  /**
   * Address: 0x00439BD0 (?AddIndexedVerts@CD3DPrimBatcher@Moho@@AAEXPBUVertex@12@IPBGII@Z)
   *
   * What it does:
   * Appends primitives from indexed source data, preserving remapped-vertex
   * reuse within each flush chunk and resetting remap state after flush.
   */
  void CD3DPrimBatcher::AddIndexedVerts(
    const Vertex* const sourceVertices,
    const std::uint32_t sourceVertexCount,
    const std::uint16_t* sourceIndices,
    std::uint32_t primitiveCount,
    const std::uint32_t verticesPerPrimitive
  )
  {
    gpg::fastvector<std::uint16_t> remap{};
    InitializeIndexedVertexRemap(remap, sourceVertexCount);

    auto* const runtime = this;
    while (primitiveCount != 0u) {
      const std::uint32_t indicesPerPrimitive = (verticesPerPrimitive == 4u) ? 6u : verticesPerPrimitive;
      const std::uint32_t usedPrimitiveIndices = static_cast<std::uint32_t>(runtime->mPrimitives.size());
      const std::uint32_t usedVertices = static_cast<std::uint32_t>(runtime->mVertices.size());

      const std::uint32_t maxByIndices = (kPrimQueueCapacity - usedPrimitiveIndices) / indicesPerPrimitive;
      const std::uint32_t maxByVertices = (kPrimQueueCapacity - usedVertices) / verticesPerPrimitive;
      const std::uint32_t batchPrimitiveCount = std::min(primitiveCount, std::min(maxByIndices, maxByVertices));
      if (batchPrimitiveCount == 0u) {
        Flush();
        ResetIndexedVertexRemap(remap);
        continue;
      }

      const std::uint32_t indexBatchCount = verticesPerPrimitive * batchPrimitiveCount;
      if (verticesPerPrimitive == 4u) {
        const std::uint16_t* quadCursor = sourceIndices + 2;
        for (std::uint32_t quadIndex = 0; quadIndex < batchPrimitiveCount; ++quadIndex, ++quadCursor) {
          const std::uint16_t i0 = AddIndexedVert(quadCursor[-2], sourceVertices, remap);
          const std::uint16_t i1 = AddIndexedVert(quadCursor[-1], sourceVertices, remap);
          const std::uint16_t i2 = AddIndexedVert(quadCursor[0], sourceVertices, remap);
          const std::uint16_t i3 = AddIndexedVert(quadCursor[1], sourceVertices, remap);

          AppendPrimitiveIndex(*runtime, i0);
          AppendPrimitiveIndex(*runtime, i1);
          AppendPrimitiveIndex(*runtime, i2);
          AppendPrimitiveIndex(*runtime, i2);
          AppendPrimitiveIndex(*runtime, i3);
          AppendPrimitiveIndex(*runtime, i0);
        }
      } else {
        for (std::uint32_t indexPos = 0; indexPos < indexBatchCount; ++indexPos) {
          AppendPrimitiveIndex(*runtime, AddIndexedVert(sourceIndices[indexPos], sourceVertices, remap));
        }
      }

      primitiveCount -= batchPrimitiveCount;
      sourceIndices += indexBatchCount;
    }
  }

  /**
   * Address: 0x0043A140 (?Flush@CD3DPrimBatcher@Moho@@QAEXXZ)
   *
   * What it does:
   * Uploads queued vertices/indices, updates prim-batcher shader variables,
   * submits one indexed draw call, and resets queue tails.
   */
  void CD3DPrimBatcher::Flush()
  {
    auto* const runtime = this;
    if (runtime->mVertices.empty()) {
      return;
    }

    if (runtime->mResetComposite != 0u) {
      runtime->mComposite = VMatrix4::Multiply(runtime->mViewMatrix, runtime->mProjectionMatrix);
      runtime->mRebuildComposite = 0;
    }

    if (runtime->mRebuildComposite == 0u) {
      if (shaderVarPrimBatcherCompositeMatrix.Exists()) {
        shaderVarPrimBatcherCompositeMatrix.mEffectVariable->SetMatrix4x4(&runtime->mComposite);
      }
      runtime->mRebuildComposite = 1;
    }

    if (shaderVarPrimBatcherAlphaMultiplier.Exists()) {
      shaderVarPrimBatcherAlphaMultiplier.mEffectVariable->SetFloat(runtime->mAlphaMultiplier);
    }

    if (runtime->mDynamicTexSheet) {
      shaderVarPrimBatcherTexture1.GetTexture(runtime->mDynamicTexSheet);
    } else {
      (void)runtime->mTextureBatcher->GetCompositeTexture();
      shaderVarPrimBatcherTexture1.GetTexture(runtime->mTextureBatcher->mDynTexSheet);
    }

    runtime->mCurVertexSheet = (runtime->mCurVertexSheet + 1) % 3;

    ID3DVertexStream* const vertexStream = runtime->mVertexSheets[runtime->mCurVertexSheet]->GetVertStream(0);
    const std::uint32_t vertexCount = static_cast<std::uint32_t>(runtime->mVertices.size());
    void* const lockedVertices = vertexStream->Lock(0, static_cast<int>(vertexCount), false, true);
    // Raw GPU upload: vertex blob into the locked D3D stream.
    std::copy_n(runtime->mVertices.data(), vertexCount, static_cast<Vertex*>(lockedVertices));
    vertexStream->Unlock();

    const std::uint32_t primitiveCount = static_cast<std::uint32_t>(runtime->mPrimitives.size());
    std::int16_t* const lockedPrimitives = runtime->mIndexSheet->Lock(0, primitiveCount, false, true);
    // Raw GPU upload: index blob into the locked D3D sheet.
    std::copy_n(runtime->mPrimitives.data(), primitiveCount, lockedPrimitives);
    runtime->mIndexSheet->Unlock();

    SD3DIndexRange indexSheetView{};
    indexSheetView.sheet = runtime->mIndexSheet;
    indexSheetView.startIndex = 0;
    indexSheetView.indexCount = static_cast<std::int32_t>(primitiveCount);

    SD3DVertexRange vertexSheetView{};
    vertexSheetView.sheet = runtime->mVertexSheets[runtime->mCurVertexSheet];
    vertexSheetView.startVertex = 0;
    vertexSheetView.baseVertex = 0;
    vertexSheetView.endVertex = static_cast<std::int32_t>(vertexCount) - 1;

    std::int32_t primitiveType = static_cast<std::int32_t>(runtime->mMode);
    CD3DDevice* const device = D3D_GetDevice();
    (void)device->DrawTriangleList(&vertexSheetView, &indexSheetView, &primitiveType);

    runtime->mVertices.clear();
    runtime->mPrimitives.clear();
  }

  /**
   * Address: 0x00426150 (FUN_00426150, Moho::CD3DPrimBatcher::DrawChar)
   *
   * What it does:
   * Emits one glyph quad from cached font extents using caller-supplied basis
   * vectors and origin.
   */
  void CD3DPrimBatcher::DrawChar(
    const Vector3f& xAxis,
    const Vector3f& yAxis,
    const CD3DFontCharInfo& charInfo,
    const Vector3f& origin,
    const std::uint32_t color
  )
  {
    SetTexture(charInfo.mTex);

    const Vector3f topLeftPos = BuildGlyphCorner(origin, xAxis, charInfo.mV2, yAxis, charInfo.mV5);
    const Vector3f topRightPos = BuildGlyphCorner(origin, xAxis, charInfo.mV4, yAxis, charInfo.mV5);
    const Vector3f bottomRightPos = BuildGlyphCorner(origin, xAxis, charInfo.mV4, yAxis, charInfo.mV3);
    const Vector3f bottomLeftPos = BuildGlyphCorner(origin, xAxis, charInfo.mV2, yAxis, charInfo.mV3);

    const Vertex topLeft{topLeftPos.x, topLeftPos.y, topLeftPos.z, color, 0.0f, 0.0f};
    const Vertex topRight{topRightPos.x, topRightPos.y, topRightPos.z, color, 1.0f, 0.0f};
    const Vertex bottomRight{bottomRightPos.x, bottomRightPos.y, bottomRightPos.z, color, 1.0f, 1.0f};
    const Vertex bottomLeft{bottomLeftPos.x, bottomLeftPos.y, bottomLeftPos.z, color, 0.0f, 1.0f};

    DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
  }

  /**
   * Address: 0x00453AB0 (?DRAW_WireOval@Moho@@YAXPAVCD3DPrimBatcher@1@ABV?$Vector3@M@Wm3@@11II@Z)
   *
   * What it does:
   * Emits one wireframe oval polyline using cosine/sine axis vectors.
   */
  void DRAW_WireOval(
    CD3DPrimBatcher* const primBatcher,
    const Vector3f& center,
    const Vector3f& axisCos,
    const Vector3f& axisSin,
    const std::uint32_t color,
    const std::uint32_t precision
  )
  {
    if (primBatcher == nullptr || precision < 2u) {
      return;
    }

    const float stepAngle = kTau / static_cast<float>(precision);
    Vector3f previous = center + axisCos;

    for (std::uint32_t index = 1; index <= precision; ++index) {
      const float angle = stepAngle * static_cast<float>(index);
      const float cosAngle = std::cos(angle);
      const float sinAngle = std::sin(angle);

      const Vector3f current{center + (axisCos * cosAngle) + (axisSin * sinAngle)};

      DrawLine(primBatcher, previous, current, color);
      previous = current;
    }
  }

  /**
   * Address: 0x00453ED0 (?DRAW_WireCircle@Moho@@YAXPAVCD3DPrimBatcher@1@ABV?$Vector3@M@Wm3@@1MII@Z)
   *
   * What it does:
   * Builds tangent oval axes from `normal` and delegates to `DRAW_WireOval`.
   *
   * Ground truth (`FUN_00453ED0.c`) calls the real `Moho::QuatCrossAdd`
   * (0x0044F880) with the hardcoded +Z axis, then rotates both tangent axes
   * via `Moho::MultQuadVec` against that quaternion -- same scalar-first
   * convention as every other `MultQuadVec` consumer in this bug class.
   */
  void DRAW_WireCircle(
    CD3DPrimBatcher* const primBatcher,
    const Vector3f& center,
    const Vector3f& normal,
    const float radius,
    const std::uint32_t color,
    const std::uint32_t precision
  )
  {
    // 0x00453EE3..0x00453F23: v1 = +Z, v2 = `normal`, fallback axis `edi` = +X.
    Wm3::Quaternionf orientation{};
    (void)QuatCrossAdd(&orientation, {0.0f, 0.0f, 1.0f}, normal, {1.0f, 0.0f, 0.0f});

    const Vector3f axisSin = RotateByQuaternion({0.0f, radius, 0.0f}, orientation);
    const Vector3f axisCos = RotateByQuaternion({radius, 0.0f, 0.0f}, orientation);
    DRAW_WireOval(primBatcher, center, axisCos, axisSin, color, precision);
  }

  /**
   * Address: 0x004541F0 (?DRAW_WireCoords@Moho@@YAXPAVCD3DPrimBatcher@1@ABV?$Vector3@M@Wm3@@ABV?$Quaternion@M@4@M@Z)
   *
   * What it does:
   * Draws RGB basis axes transformed by quaternion orientation.
   */
  void DRAW_WireCoords(
    CD3DPrimBatcher* const primBatcher,
    const Vector3f& origin,
    const Wm3::Quaternionf& orientation,
    const float axisLength
  )
  {
    if (primBatcher == nullptr) {
      return;
    }

    const Vector3f xOffset = RotateByQuaternion({axisLength, 0.0f, 0.0f}, orientation);
    const Vector3f yOffset = RotateByQuaternion({0.0f, axisLength, 0.0f}, orientation);
    const Vector3f zOffset = RotateByQuaternion({0.0f, 0.0f, axisLength}, orientation);

    DrawLine(
      primBatcher,
      origin,
      origin + xOffset,
      kAxisColorX
    );
    DrawLine(
      primBatcher,
      origin,
      origin + yOffset,
      kAxisColorY
    );
    DrawLine(
      primBatcher,
      origin,
      origin + zOffset,
      kAxisColorZ
    );
  }

  /**
   * Address: 0x00454430 (?DRAW_WireCoords@Moho@@YAXPAVCD3DPrimBatcher@1@ABUVMatrix4@1@M@Z)
   *
   * What it does:
   * Draws RGB basis axes from one transform matrix (rows 0..2 as basis, row 3 as origin).
   */
  void DRAW_WireCoords(CD3DPrimBatcher* const primBatcher, const VMatrix4& transform, const float axisLength)
  {
    if (primBatcher == nullptr) {
      return;
    }

    const Vector3f origin{transform.r[3].XYZ()};
    const Vector3f axisX{transform.r[0].XYZ()};
    const Vector3f axisY{transform.r[1].XYZ()};
    const Vector3f axisZ{transform.r[2].XYZ()};

    DrawLine(
      primBatcher,
      origin,
      origin + axisX * axisLength,
      kAxisColorX
    );
    DrawLine(
      primBatcher,
      origin,
      origin + axisY * axisLength,
      kAxisColorY
    );
    DrawLine(
      primBatcher,
      origin,
      origin + axisZ * axisLength,
      kAxisColorZ
    );
  }

  /**
   * Address: 0x00454680 (?DRAW_WireBox@Moho@@YAXPAVCD3DPrimBatcher@1@ABV?$Box3@M@Wm3@@I@Z)
   *
   * What it does:
   * Draws a wireframe oriented box from `box` corners and the canonical 12 edge pairs.
   */
  void DRAW_WireBox(CD3DPrimBatcher* const primBatcher, const Wm3::Box3f& box, const std::uint32_t color)
  {
    if (primBatcher == nullptr) {
      return;
    }

    std::array<Vector3f, 8> corners{};
    box.GetCorners(corners.data());

    constexpr std::array<std::array<std::uint8_t, 2>, 12> kEdges{{
      {0, 1},
      {1, 3},
      {3, 2},
      {2, 0},
      {4, 5},
      {5, 7},
      {7, 6},
      {6, 4},
      {0, 4},
      {1, 5},
      {2, 6},
      {3, 7},
    }};

    for (const auto& edge : kEdges) {
      DrawLine(primBatcher, corners[edge[0]], corners[edge[1]], color);
    }
  }

  /**
   * The corner computation at the head of `DRAW_Rect` (0x00455480..0x00455907).
   *
   * What it does:
   * Expands the rectangle `topLeft`, `+widthAxis`, `+widthAxis+heightAxis`,
   * `+heightAxis` by half of `borderWidth` along its two diagonals into an
   * outer and an inner corner ring (each top-left, top-right, bottom-right,
   * bottom-left).
   */
  DrawRectRing DRAW_RectRing(
    const float borderWidth, const Vector3f& heightAxis, const Vector3f& widthAxis, const Vector3f& topLeft
  )
  {
    const float halfBorderWidth = borderWidth * 0.5f;

    const Vector3f outerExpansion = Wm3::Vector3f::NormalizeOrZero(heightAxis + widthAxis) * halfBorderWidth;
    const Vector3f edgeExpansion = Wm3::Vector3f::NormalizeOrZero(heightAxis - widthAxis) * halfBorderWidth;

    DrawRectRing ring{};
    ring.outer[0] = topLeft - outerExpansion;
    ring.outer[1] = topLeft + widthAxis - edgeExpansion;
    ring.outer[2] = topLeft + widthAxis + heightAxis + outerExpansion;
    ring.outer[3] = topLeft + heightAxis + edgeExpansion;

    ring.inner[0] = topLeft + outerExpansion;
    ring.inner[1] = topLeft + widthAxis + edgeExpansion;
    ring.inner[2] = topLeft + widthAxis + heightAxis - outerExpansion;
    ring.inner[3] = topLeft + heightAxis - edgeExpansion;
    return ring;
  }

  /**
   * Address: 0x00455480 (?DRAW_Rect@Moho@@YAXPAVCD3DPrimBatcher@1@MABV?$Vector3@M@Wm3@@11IPBVCHeightField@1@M@Z)
   *
   * What it does:
   * Builds a rectangular border ring from basis vectors and either emits four
   * direct border quads or terrain-clamped subdivided strips per edge.
   */
  void DRAW_Rect(
    CD3DPrimBatcher* const primBatcher,
    const float borderWidth,
    const Vector3f& heightAxis,
    const Vector3f& widthAxis,
    const Vector3f& topLeft,
    const std::uint32_t color,
    const CHeightField* const heightField,
    const float elevation
  )
  {
    if (primBatcher == nullptr) {
      return;
    }

    const DrawRectRing ring = DRAW_RectRing(borderWidth, heightAxis, widthAxis, topLeft);
    const Vector3f& topOuterLeft = ring.outer[0];
    const Vector3f& topOuterRight = ring.outer[1];
    const Vector3f& bottomOuterRight = ring.outer[2];
    const Vector3f& bottomOuterLeft = ring.outer[3];
    const Vector3f& topInnerLeft = ring.inner[0];
    const Vector3f& topInnerRight = ring.inner[1];
    const Vector3f& bottomInnerRight = ring.inner[2];
    const Vector3f& bottomInnerLeft = ring.inner[3];

    if (heightField == nullptr) {
      primBatcher->DrawQuad(topOuterLeft, topInnerLeft, topInnerRight, topOuterRight, color);
      primBatcher->DrawQuad(topOuterRight, topInnerRight, bottomInnerRight, bottomOuterRight, color);
      // 0x00455DD0..0x00455DEB: stack `bottomInnerLeft`, ecx `bottomOuterLeft`, edx `bottomOuterRight`
      // (the previous call's esi), esi `bottomInnerRight` - the corner ring BIL, BOL, BOR, BIR. With
      // the two outer corners swapped the quad folded into a bowtie and the bottom edge drew half
      // covered and half doubled.
      primBatcher->DrawQuad(bottomInnerLeft, bottomOuterLeft, bottomOuterRight, bottomInnerRight, color);
      primBatcher->DrawQuad(topOuterLeft, bottomOuterLeft, bottomInnerLeft, topInnerLeft, color);
      return;
    }

    const std::array<Vector3f, 4>& outerCorners = ring.outer;
    const std::array<Vector3f, 4>& innerCorners = ring.inner;

    for (std::size_t sideIndex = 0; sideIndex < outerCorners.size(); ++sideIndex) {
      const std::size_t nextSideIndex = (sideIndex + 1u) % outerCorners.size();

      const Vector3f& outerStart = outerCorners[sideIndex];
      const Vector3f& outerEnd = outerCorners[nextSideIndex];
      const Vector3f& innerStart = innerCorners[sideIndex];
      const Vector3f& innerEnd = innerCorners[nextSideIndex];

      const float outerStartY = SampleTerrainClampedElevation(*heightField, outerStart, elevation);
      const float outerEndY = SampleTerrainClampedElevation(*heightField, outerEnd, elevation);
      const float innerEndY = SampleTerrainClampedElevation(*heightField, innerEnd, elevation);
      const float innerStartY = SampleTerrainClampedElevation(*heightField, innerStart, elevation);

      const Vector3f outerStep{
        (outerEnd.x - outerStart.x) * kRectEdgeSubdivisionStep,
        (outerEndY - outerStartY) * kRectEdgeSubdivisionStep,
        (outerEnd.z - outerStart.z) * kRectEdgeSubdivisionStep,
      };
      const Vector3f innerStep{
        (innerEnd.x - innerStart.x) * kRectEdgeSubdivisionStep,
        (innerEndY - innerStartY) * kRectEdgeSubdivisionStep,
        (innerEnd.z - innerStart.z) * kRectEdgeSubdivisionStep,
      };

      for (std::uint32_t segment = 0; segment < kRectEdgeSubdivisionCount; ++segment) {
        const float segmentF = static_cast<float>(segment);

        const Vector3f segmentOuterStart{
          outerStart.x + (outerStep.x * segmentF),
          outerStartY + (outerStep.y * segmentF),
          outerStart.z + (outerStep.z * segmentF),
        };
        const Vector3f segmentOuterEnd = segmentOuterStart + outerStep;

        const Vector3f segmentInnerStart{
          innerStart.x + (innerStep.x * segmentF),
          innerStartY + (innerStep.y * segmentF),
          innerStart.z + (innerStep.z * segmentF),
        };
        const Vector3f segmentInnerEnd = segmentInnerStart + innerStep;

        primBatcher->DrawQuad(segmentOuterStart, segmentOuterEnd, segmentInnerEnd, segmentInnerStart, color);
      }
    }
  }

  /**
   * Address: 0x00455E20 (?DRAW_Oval@Moho@@YAXPAVCD3DPrimBatcher@1@ABV?$Vector3@M@Wm3@@1111IIPBVCHeightField@1@_NM@Z)
   *
   * What it does:
   * Draws one filled oval band (48 quads with FAF's segment patch) from
   * inner/outer axis pairs, in `color`.
   *
   * FAF FA-Binary-Patches (hooks/HDraw.cpp, section/DrawCircleSetColor.cpp):
   * the colour is the CIRCLE_COLOR global the patch loads at 0x004561A8 in
   * place of the shipped 0xFF00D800 immediate; it is a parameter here.
   */
  void DRAW_Oval(
    CD3DPrimBatcher* const primBatcher,
    const Vector3f& center,
    const Vector3f& innerSinAxis,
    const Vector3f& outerCosAxis,
    const Vector3f& outerSinAxis,
    const Vector3f& innerCosAxis,
    const std::uint32_t color
  )
  {
    if (primBatcher == nullptr) {
      return;
    }

    for (std::uint32_t segment = 0; segment < kOvalSegmentCount; ++segment) {
      const std::uint32_t nextSegment = (segment + 1u) % kOvalSegmentCount;

      const float currentAngle = DRAW_OvalSegmentAngle(segment);
      const float nextAngle = DRAW_OvalSegmentAngle(nextSegment);

      const float cosCurrent = std::cos(currentAngle);
      const float sinCurrent = std::sin(currentAngle);
      const float cosNext = std::cos(nextAngle);
      const float sinNext = std::sin(nextAngle);

      const Vector3f innerCurrent{center + (innerCosAxis * cosCurrent) + (innerSinAxis * sinCurrent)};
      const Vector3f innerNext{center + (innerCosAxis * cosNext) + (innerSinAxis * sinNext)};
      const Vector3f outerCurrent{center + (outerCosAxis * cosCurrent) + (outerSinAxis * sinCurrent)};
      const Vector3f outerNext{center + (outerCosAxis * cosNext) + (outerSinAxis * sinNext)};

      primBatcher->DrawQuad(innerCurrent, outerCurrent, outerNext, innerNext, color);
    }
  }

  /**
   * Address: 0x00456200 (?DRAW_Circle@Moho@@YAXPAVCD3DPrimBatcher@1@MABV?$Vector3@M@Wm3@@1MIIPBVCHeightField@1@_NM@Z)
   *
   * What it does:
   * Builds rotated inner/outer oval axes around `normal` and delegates to `DRAW_Oval`.
   *
   * The mangled name declares 10 parameters (CD3DPrimBatcher*, float, const Vector3f&,
   * const Vector3f&, float, uint, uint, const CHeightField*, bool, float) but the sole
   * caller in this binary (`Moho::DrawCommandGraph`, 0x00853DC0) was compiled under
   * whole-program optimization against this single call site: it only pushes/loads real
   * values for `primBatcher` (stack), `center` (stack), `normal` (ECX register — a custom
   * `__usercall` promotion, confirmed by the raw .asm) and `radius` (a pre-filled stack
   * slot). The remaining six parameters have no computed values at the call site (one
   * stack slot is written with a leftover register value that is immediately overwritten
   * before use — dead space reservation, not a real argument) and this function's own
   * disassembly never reads them. They are kept in the signature, in mangled-name order,
   * for ABI/name fidelity, and are `[[maybe_unused]]` rather than given invented names.
   *
   * The axes come from `DRAW_CircleAxes`. With FAF's patches the band half
   * width and colour are the THICKNESS / CIRCLE_COLOR globals; the
   * build-assist circle (the only engine caller) draws with their initial
   * values 0.1 and 0xFF00D800. The patch never restores them after
   * UI_DrawCircle, so in the patched exe this circle takes whatever the last
   * UI_DrawCircle used; that leak is not reproduced.
   */
  void DRAW_Circle(
    CD3DPrimBatcher* const primBatcher,
    [[maybe_unused]] const float unusedFloat0,
    const Vector3f& center,
    const Vector3f& normal,
    [[maybe_unused]] const float unusedFloat1,
    [[maybe_unused]] const std::uint32_t unusedUInt0,
    [[maybe_unused]] const std::uint32_t unusedUInt1,
    [[maybe_unused]] const CHeightField* const heightField,
    [[maybe_unused]] const bool unusedBool0,
    const float radius
  )
  {
    DRAW_Circle(primBatcher, center, normal, radius, kOvalBandHalfWidth, kOvalBandColor);
  }

  /**
   * FAF FA-Binary-Patches (hooks/HDraw.cpp, section/DrawFunc.cpp): the body of
   * `DRAW_Circle` (0x00456200) with the band half width (THICKNESS, read at
   * 0x00456264 / 0x004562CD) and the colour (CIRCLE_COLOR, 0x004561A8) as
   * parameters instead of the globals the patch stores before each call.
   *
   * What it does:
   * Draws a `2 * bandHalfWidth` wide ring of `radius` around `center` in the
   * plane whose normal is `normal`.
   */
  void DRAW_Circle(
    CD3DPrimBatcher* const primBatcher,
    const Vector3f& center,
    const Vector3f& normal,
    const float radius,
    const float bandHalfWidth,
    const std::uint32_t color
  )
  {
    if (primBatcher == nullptr) {
      return;
    }

    const DrawOvalAxes axes = DRAW_CircleAxes(normal, radius, bandHalfWidth);
    DRAW_Oval(primBatcher, center, axes.innerSin, axes.outerCos, axes.outerSin, axes.innerCos, color);
  }

  /**
   * The axis computation of `DRAW_Circle` (0x00456200).
   *
   * What it does:
   * `normal` is rotated with a hardcoded +Z axis (0,0,1) via the real
   * `Moho::QuatCrossAdd` (0x0044F880, Sim.cpp), then four points at `radius`
   * +/- `bandHalfWidth` along the local X/Y axes are rotated by that
   * quaternion via `RotateByQuaternion`, i.e. `Moho::MultQuadVec` in the
   * binary, to form the inner/outer cosine/sine axes handed to `DRAW_Oval`.
   */
  DrawOvalAxes DRAW_CircleAxes(const Vector3f& normal, const float radius, const float bandHalfWidth)
  {
    // 0x00456213..0x00456253: v1 = +Z, v2 = `normal`, fallback axis `edi` = +X.
    Wm3::Quaternionf orientation{};
    (void)QuatCrossAdd(&orientation, {0.0f, 0.0f, 1.0f}, normal, {1.0f, 0.0f, 0.0f});

    const float innerRadius = radius - bandHalfWidth;
    const float outerRadius = radius + bandHalfWidth;

    DrawOvalAxes axes{};
    axes.innerSin = RotateByQuaternion({0.0f, innerRadius, 0.0f}, orientation);
    axes.innerCos = RotateByQuaternion({innerRadius, 0.0f, 0.0f}, orientation);
    axes.outerSin = RotateByQuaternion({0.0f, outerRadius, 0.0f}, orientation);
    axes.outerCos = RotateByQuaternion({outerRadius, 0.0f, 0.0f}, orientation);
    return axes;
  }

  /**
   * What it does:
   * The angle of `DRAW_Oval`'s segment `segment` (0x00455E30: the segment
   * index times the angle step).
   */
  float DRAW_OvalSegmentAngle(const std::uint32_t segment) noexcept
  {
    return static_cast<float>(segment) * kOvalAngleStep;
  }

  /**
   * Address: 0x00454E20 (?DRAW_ClippedQuad@Moho@@YAXPAVCD3DPrimBatcher@1@ABV?$Rect2@M@gpg@@11I@Z)
   *
   * What it does:
   * Clips one quad against `clipRect` and remaps UVs to the clipped position.
   */
  void DRAW_ClippedQuad(
    CD3DPrimBatcher* const primBatcher,
    const gpg::Rect2f& quadRect,
    const gpg::Rect2f& uvRect,
    const gpg::Rect2f& clipRect,
    const std::uint32_t color
  )
  {
    if (primBatcher == nullptr) {
      return;
    }

    const float clippedX0 = std::max(quadRect.x0, clipRect.x0);
    const float clippedX1 = std::min(quadRect.x1, clipRect.x1);
    const float clippedZ0 = std::max(quadRect.z0, clipRect.z0);
    const float clippedZ1 = std::min(quadRect.z1, clipRect.z1);

    if (!(clippedX1 > clippedX0 && clippedZ1 > clippedZ0)) {
      return;
    }

    const float quadWidth = quadRect.x1 - quadRect.x0;
    const float quadHeight = quadRect.z1 - quadRect.z0;
    if (quadWidth == 0.0f || quadHeight == 0.0f) {
      return;
    }

    const float uvWidth = uvRect.x1 - uvRect.x0;
    const float uvHeight = uvRect.z1 - uvRect.z0;

    const float u0 = uvRect.x0 + (((clippedX0 - quadRect.x0) / quadWidth) * uvWidth);
    const float u1 = uvRect.x0 + (((clippedX1 - quadRect.x0) / quadWidth) * uvWidth);
    const float v0 = uvRect.z0 + (((clippedZ0 - quadRect.z0) / quadHeight) * uvHeight);
    const float v1 = uvRect.z0 + (((clippedZ1 - quadRect.z0) / quadHeight) * uvHeight);

    const CD3DPrimBatcher::Vertex topLeft = MakeVertex({clippedX0, clippedZ0, 0.0f}, color, u0, v0);
    const CD3DPrimBatcher::Vertex topRight = MakeVertex({clippedX1, clippedZ0, 0.0f}, color, u1, v0);
    const CD3DPrimBatcher::Vertex bottomRight = MakeVertex({clippedX1, clippedZ1, 0.0f}, color, u1, v1);
    const CD3DPrimBatcher::Vertex bottomLeft = MakeVertex({clippedX0, clippedZ1, 0.0f}, color, u0, v1);
    primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
  }

  /**
   * Address: 0x00455150 (?DRAW_TiledQuad@Moho@@YAXPAVCD3DPrimBatcher@1@ABV?$Rect2@M@gpg@@11I@Z)
   *
   * What it does:
   * Splits one tiled destination range into unit tiles and draws each via `DRAW_ClippedQuad`.
   */
  void DRAW_TiledQuad(
    CD3DPrimBatcher* const primBatcher,
    const gpg::Rect2f& clipRect,
    const gpg::Rect2f& tileRect,
    const gpg::Rect2f& outputRect,
    const std::uint32_t color
  )
  {
    if (primBatcher == nullptr) {
      return;
    }

    const float clippedX0 = std::max(clipRect.x0, outputRect.x0);
    const float clippedX1 = std::min(clipRect.x1, outputRect.x1);
    const float clippedZ0 = std::max(clipRect.z0, outputRect.z0);
    const float clippedZ1 = std::min(clipRect.z1, outputRect.z1);
    if (!(clippedX1 > clippedX0 && clippedZ1 > clippedZ0)) {
      return;
    }

    const float tileX0 = std::min(tileRect.x0, tileRect.x1);
    const float tileX1 = std::max(tileRect.x0, tileRect.x1);
    const float tileZ0 = std::min(tileRect.z0, tileRect.z1);
    const float tileZ1 = std::max(tileRect.z0, tileRect.z1);
    if (!(tileX1 > tileX0 && tileZ1 > tileZ0)) {
      return;
    }

    const float firstTileX = static_cast<float>(std::floor(tileX0));
    const float endTileX = static_cast<float>(std::ceil(tileX1));
    const float firstTileZ = static_cast<float>(std::floor(tileZ0));
    const float endTileZ = static_cast<float>(std::ceil(tileZ1));

    constexpr gpg::Rect2f kUnitUv{0.0f, 0.0f, 1.0f, 1.0f};
    const gpg::Rect2f clippedArea{clippedX0, clippedZ0, clippedX1, clippedZ1};

    for (float tileX = firstTileX; tileX < endTileX; tileX += 1.0f) {
      for (float tileZ = firstTileZ; tileZ < endTileZ; tileZ += 1.0f) {
        const float mappedX0 = outputRect.x0 + (((tileX - tileX0) / (tileX1 - tileX0)) * (outputRect.x1 - outputRect.x0));
        const float mappedX1 = outputRect.x0
          + ((((tileX + 1.0f) - tileX0) / (tileX1 - tileX0)) * (outputRect.x1 - outputRect.x0));
        const float mappedZ0 = outputRect.z0 + (((tileZ - tileZ0) / (tileZ1 - tileZ0)) * (outputRect.z1 - outputRect.z0));
        const float mappedZ1 = outputRect.z0
          + ((((tileZ + 1.0f) - tileZ0) / (tileZ1 - tileZ0)) * (outputRect.z1 - outputRect.z0));

        const gpg::Rect2f tileOutput{mappedX0, mappedZ0, mappedX1, mappedZ1};
        DRAW_ClippedQuad(primBatcher, tileOutput, kUnitUv, clippedArea, color);
      }
    }
  }

  /**
   * Address: 0x0084D3E0 (FUN_0084D3E0)
   *
   * What it does:
   * Builds per-head UI orthographic matrices from the input-window client size and
   * applies UI alpha multiplier from the owning CUIManager.
   */
  void CD3DPrimBatcher::SetToViewport(const int head, const CUIManager& manager)
  {
    if (head < 0) {
      return;
    }

    const std::size_t headIndex = static_cast<std::size_t>(head);
    if (headIndex >= manager.mInputWindows.Size()) {
      return;
    }

    wxWindow* const inputWindow = manager.mInputWindows[headIndex];
    if (inputWindow == nullptr) {
      return;
    }

    int width = 0;
    int height = 0;
    inputWindow->GetClientSize(&width, &height);
    if (width <= 0 || height <= 0) {
      return;
    }

    const float widthF = static_cast<float>(width);
    const float heightF = static_cast<float>(height);

    VMatrix4 projection{};
    projection.r[0] = {2.0f / widthF, 0.0f, 0.0f, 0.0f};
    projection.r[1] = {0.0f, 2.0f / (-heightF), 0.0f, 0.0f};
    projection.r[2] = {0.0f, 0.0f, -0.5f, 0.0f};
    projection.r[3] = {
      (widthF / (-widthF)) - (1.0f / widthF),
      (heightF / heightF) + (1.0f / heightF),
      0.5f,
      1.0f,
    };

    SetProjectionMatrix(projection);
    SetViewMatrix(UI_IdentityMatrix());
    this->mAlphaMultiplier = manager.mUIControlsAlpha;
  }
} // namespace moho
