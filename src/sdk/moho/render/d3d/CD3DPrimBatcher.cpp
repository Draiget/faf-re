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
#include "gpg/gal/backends/d3d9/EffectVariableD3D9.hpp"
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

namespace
{
  constexpr float kTau = 6.28318530717958647692f;
  constexpr std::uint32_t kLegacyPrimQueueLimit = 0x8000u;
  constexpr std::uint32_t kAxisColorX = 0xFFFF0000u;
  constexpr std::uint32_t kAxisColorY = 0xFF00FF00u;
  constexpr std::uint32_t kAxisColorZ = 0xFF0000FFu;
  constexpr std::int32_t kMode1PrimitiveType = 1;
  constexpr std::int32_t kLineListPrimitiveType = 2;
  constexpr std::int32_t kTriangleListPrimitiveType = 4;
  constexpr std::uint32_t kRectEdgeSubdivisionCount = 10u;
  constexpr float kRectEdgeSubdivisionStep = 1.0f / 10.0f;
  constexpr float kRectTerrainBias = 0.1f;
  constexpr std::uint32_t kOvalSegmentCount = 0x14u;
  constexpr float kOvalAngleStep = 0.31415927f;
  constexpr std::uint32_t kOvalBandColor = 0xFF00D800u;
  constexpr float kOvalBandHalfWidth = 0.5f;
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

  [[nodiscard]] Wm3::Quaternionf QuatCrossAdd(
    Wm3::Vector3f lhsNormalized, Wm3::Vector3f rhsNormalized
  ) noexcept
  {
    Wm3::Vector3f::Normalize(&lhsNormalized);
    Wm3::Vector3f::Normalize(&rhsNormalized);

    Wm3::Vector3f sum{
      lhsNormalized.x + rhsNormalized.x,
      lhsNormalized.y + rhsNormalized.y,
      lhsNormalized.z + rhsNormalized.z,
    };

    if (Wm3::Vector3f::Normalize(&sum) <= 0.0f) {
      Wm3::Vector3f::Normalize(&lhsNormalized);
      return {0.0f, lhsNormalized.x, lhsNormalized.y, lhsNormalized.z};
    }

    return {
      (sum.x * lhsNormalized.x) + (sum.y * lhsNormalized.y) + (sum.z * lhsNormalized.z),
      (sum.z * lhsNormalized.y) - (lhsNormalized.z * sum.y),
      (lhsNormalized.z * sum.x) - (sum.z * lhsNormalized.x),
      (sum.y * lhsNormalized.x) - (lhsNormalized.y * sum.x),
    };
  }

  [[nodiscard]] moho::Vector3f RotateByQuaternion(
    const moho::Vector3f& vector, const Wm3::Quaternionf& orientation
  ) noexcept
  {
    moho::Vector3f rotated{};
    Wm3::MultiplyQuaternionVector(&rotated, vector, orientation);
    return rotated;
  }

  template <typename TValue>
  [[nodiscard]] std::uint32_t LegacyVectorCount(
    const moho::CD3DPrimBatcherRuntimeView::LegacyVector<TValue>& vector
  ) noexcept
  {
    if (vector.mFirst == nullptr || vector.mLast == nullptr || vector.mLast < vector.mFirst) {
      return 0u;
    }
    return static_cast<std::uint32_t>(vector.mLast - vector.mFirst);
  }

  template <typename TValue>
  [[nodiscard]] std::uint32_t LegacyVectorCapacity(
    const moho::CD3DPrimBatcherRuntimeView::LegacyVector<TValue>& vector
  ) noexcept
  {
    if (vector.mFirst == nullptr || vector.mEnd == nullptr || vector.mEnd < vector.mFirst) {
      return 0u;
    }
    return static_cast<std::uint32_t>(vector.mEnd - vector.mFirst);
  }

  template <typename TValue>
  void EnsureLegacyQueueCapacity(
    moho::CD3DPrimBatcherRuntimeView::LegacyVector<TValue>& vector,
    const std::uint32_t queueLimit
  )
  {
    const std::uint32_t count = LegacyVectorCount(vector);
    const std::uint32_t capacity = LegacyVectorCapacity(vector);
    if (capacity >= queueLimit && vector.mFirst != nullptr) {
      return;
    }

    auto* const newStorage = static_cast<TValue*>(::operator new(sizeof(TValue) * queueLimit));
    if (count != 0u && vector.mFirst != nullptr) {
      std::memcpy(newStorage, vector.mFirst, sizeof(TValue) * count);
    }

    if (vector.mFirst != nullptr) {
      ::operator delete(static_cast<void*>(vector.mFirst));
    }

    vector.mFirst = newStorage;
    vector.mLast = newStorage + count;
    vector.mEnd = newStorage + queueLimit;
  }

  template <typename TValue>
  TValue* PushBackLegacyQueue(
    moho::CD3DPrimBatcherRuntimeView::LegacyVector<TValue>& vector,
    const TValue& value,
    const std::uint32_t queueLimit
  )
  {
    EnsureLegacyQueueCapacity(vector, queueLimit);

    const std::uint32_t count = LegacyVectorCount(vector);
    if (count >= queueLimit) {
      throw std::length_error("vector<T> too long");
    }

    TValue* const slot = vector.mLast;
    *slot = value;
    vector.mLast = slot + 1;
    return slot;
  }

  template <typename TPointee>
  [[nodiscard]] boost::SharedCountPair* AsSharedCountPair(
    moho::CD3DPrimBatcherRuntimeView::LegacyWeakHandle<TPointee>* const weakHandle
  ) noexcept
  {
    return reinterpret_cast<boost::SharedCountPair*>(weakHandle);
  }

  template <typename TPointee>
  [[nodiscard]] const boost::SharedCountPair* AsSharedCountPair(
    const boost::shared_ptr<TPointee>& sharedHandle
  ) noexcept
  {
    static_assert(
      sizeof(boost::shared_ptr<TPointee>) == sizeof(boost::SharedCountPair),
      "boost::shared_ptr<T> layout must match SharedCountPair"
    );
    return reinterpret_cast<const boost::SharedCountPair*>(&sharedHandle);
  }

  template <typename TPointee>
  void AssignLegacyWeakFromShared(
    moho::CD3DPrimBatcherRuntimeView::LegacyWeakHandle<TPointee>& weakHandle,
    const boost::shared_ptr<TPointee>& sharedHandle
  ) noexcept
  {
    (void)boost::AssignWeakPairFromShared(AsSharedCountPair(&weakHandle), AsSharedCountPair(sharedHandle));
  }

  template <typename TPointee>
  void ResetLegacyWeakHandle(
    moho::CD3DPrimBatcherRuntimeView::LegacyWeakHandle<TPointee>& weakHandle
  ) noexcept
  {
    weakHandle.px = nullptr;
    if (weakHandle.pi != nullptr) {
      weakHandle.pi->weak_release();
      weakHandle.pi = nullptr;
    }
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
    const moho::CD3DPrimBatcherRuntimeView& runtime,
    const moho::CD3DPrimBatcher::Vertex& source
  ) noexcept
  {
    moho::CD3DPrimBatcher::Vertex transformed = source;
    transformed.mU = runtime.mP2x + (runtime.mP1x * source.mU);
    transformed.mV = runtime.mP2y + (runtime.mP1y * source.mV);
    return transformed;
  }

  [[nodiscard]] moho::Vector3f AddVector3f(const moho::Vector3f& lhs, const moho::Vector3f& rhs) noexcept
  {
    return {lhs.x + rhs.x, lhs.y + rhs.y, lhs.z + rhs.z};
  }

  [[nodiscard]] moho::Vector3f SubVector3f(const moho::Vector3f& lhs, const moho::Vector3f& rhs) noexcept
  {
    return {lhs.x - rhs.x, lhs.y - rhs.y, lhs.z - rhs.z};
  }

  [[nodiscard]] moho::Vector3f ScaleVector3f(const moho::Vector3f& value, const float scale) noexcept
  {
    return {value.x * scale, value.y * scale, value.z * scale};
  }

  [[nodiscard]] moho::Vector3f NormalizeScaledVector3f(const moho::Vector3f& value, const float scale) noexcept
  {
    moho::Vector3f normalized = value;
    if (Wm3::Vector3f::Normalize(&normalized) <= 0.0f) {
      return {0.0f, 0.0f, 0.0f};
    }
    return ScaleVector3f(normalized, scale);
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
    moho::CD3DPrimBatcherRuntimeView& runtime,
    const std::uint16_t index
  )
  {
    (void)PushBackLegacyQueue(
      runtime.mPrimitives,
      static_cast<std::int16_t>(index),
      kLegacyPrimQueueLimit
    );
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
  {
    CD3DPrimBatcherRuntimeView* const runtime = CD3DPrimBatcherRuntimeView::FromBatcher(this);

    runtime->mTextureBatcher = textureBatcher;
    runtime->mCurVertexSheet = 0;
    runtime->mIndexSheet = nullptr;

    runtime->mVertices.mFirst = nullptr;
    runtime->mVertices.mLast = nullptr;
    runtime->mVertices.mEnd = nullptr;

    runtime->mUnknown028 = 0u;

    runtime->mPrimitives.mFirst = nullptr;
    runtime->mPrimitives.mLast = nullptr;
    runtime->mPrimitives.mEnd = nullptr;

    runtime->mMode = 0u;
    runtime->mDynamicTexSheet.px = nullptr;
    runtime->mDynamicTexSheet.pi = nullptr;
    runtime->mTexture.px = nullptr;
    runtime->mTexture.pi = nullptr;

    runtime->mP2x = 0.0f;
    runtime->mP2y = 0.0f;
    runtime->mP1x = 1.0f;
    runtime->mP1y = 1.0f;

    const VMatrix4 identity = VMatrix4::Identity();
    std::memcpy(&runtime->mViewMatrix, &identity, sizeof(runtime->mViewMatrix));
    std::memcpy(&runtime->mProjectionMatrix, &identity, sizeof(runtime->mProjectionMatrix));
    std::memcpy(&runtime->mComposite, &identity, sizeof(runtime->mComposite));

    runtime->mResetComposite = 0u;
    runtime->mRebuildComposite = 0u;
    runtime->mUnknown11ETo11F[0] = 0u;
    runtime->mUnknown11ETo11F[1] = 0u;
    runtime->mAlphaMultiplier = 1.0f;

    ID3DDeviceResources* const resources = D3D_GetDevice()->GetResources();
    for (CD3DVertexSheet*& sheet : runtime->mVertexSheets) {
      CD3DVertexFormat* const vertexFormat = resources->GetVertexFormat(6);
      sheet = resources->NewVertexSheet(1u, 0x8000, vertexFormat);
    }

    runtime->mIndexSheet = resources->CreateIndexSheet(true, 0x8000);
  }

  /**
   * Address: 0x00438460 (FUN_00438460, Moho::CD3DPrimBatcher::~CD3DPrimBatcher)
   *
   * IDA signature:
   * void __stdcall Moho::CD3DPrimBatcher::~CD3DPrimBatcher(int a1);
   *
   * What it does:
   * Tears down one prim-batcher instance in the binary's original order:
   * destroy the three vertex sheets and the index sheet through their
   * typed `Destroy` virtuals, release shared-control-block references
   * held by the batch-texture and dynamic-texture-sheet weak-style
   * handles, then release the primitive and vertex legacy-vector heap
   * storage and null their tracking pointers.
   */
  CD3DPrimBatcher::~CD3DPrimBatcher()
  {
    CD3DPrimBatcherRuntimeView* const runtime = CD3DPrimBatcherRuntimeView::FromBatcher(this);

    for (CD3DVertexSheet* const sheet : runtime->mVertexSheets) {
      if (sheet != nullptr) {
        sheet->Destroy();
      }
    }

    if (runtime->mIndexSheet != nullptr) {
      runtime->mIndexSheet->Destroy();
    }

    boost::ReleaseSharedControlOnly(AsSharedCountPair(&runtime->mDynamicTexSheet));
    boost::ReleaseSharedControlOnly(AsSharedCountPair(&runtime->mTexture));

    if (runtime->mPrimitives.mFirst != nullptr) {
      ::operator delete(static_cast<void*>(runtime->mPrimitives.mFirst));
    }
    runtime->mPrimitives.mFirst = nullptr;
    runtime->mPrimitives.mLast = nullptr;
    runtime->mPrimitives.mEnd = nullptr;

    if (runtime->mVertices.mFirst != nullptr) {
      ::operator delete(static_cast<void*>(runtime->mVertices.mFirst));
    }
    runtime->mVertices.mFirst = nullptr;
    runtime->mVertices.mLast = nullptr;
    runtime->mVertices.mEnd = nullptr;
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

    CD3DPrimBatcherRuntimeView::FromBatcher(this)->mRebuildComposite = 0;
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
    CD3DPrimBatcherRuntimeView* const runtime = CD3DPrimBatcherRuntimeView::FromBatcher(this);
    if (runtime->mVertices.HasElements()) {
      Flush();
    }

    std::memcpy(&runtime->mViewMatrix, &matrix, sizeof(runtime->mViewMatrix));
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
    CD3DPrimBatcherRuntimeView* const runtime = CD3DPrimBatcherRuntimeView::FromBatcher(this);
    if (runtime->mVertices.HasElements()) {
      Flush();
    }

    std::memcpy(&runtime->mProjectionMatrix, &matrix, sizeof(runtime->mProjectionMatrix));
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
    CD3DPrimBatcherRuntimeView* const runtime = CD3DPrimBatcherRuntimeView::FromBatcher(this);
    if (runtime->mVertices.HasElements()) {
      Flush();
    }

    std::memcpy(&runtime->mViewMatrix, &camera.view, sizeof(runtime->mViewMatrix));
    std::memcpy(&runtime->mProjectionMatrix, &camera.projection, sizeof(runtime->mProjectionMatrix));
    runtime->mResetComposite = 1;
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
    CD3DPrimBatcherRuntimeView* const runtime = CD3DPrimBatcherRuntimeView::FromBatcher(this);

    const std::uint32_t atlasHalfWidth = static_cast<std::uint32_t>(runtime->mTextureBatcher->mWidth) >> 1u;
    const std::uint32_t atlasHalfHeight = static_cast<std::uint32_t>(runtime->mTextureBatcher->mHeight) >> 1u;
    const bool useDirectTexture = texture->mWidth >= atlasHalfWidth || texture->mHeight >= atlasHalfHeight;

    if (useDirectTexture) {
      if (runtime->mVertices.HasElements() && runtime->mTexture.px != texture.get()) {
        Flush();
      }

      AssignLegacyWeakFromShared(runtime->mTexture, texture);

      CD3DBatchTexture::TextureSheetHandle textureSheet{};
      Wm3::Vector2f uvScale{};
      Wm3::Vector2f uvBorder{};
      texture->GetTextureSheet(textureSheet, uvScale, uvBorder);

      AssignLegacyWeakFromShared(runtime->mDynamicTexSheet, texture->mTextureSheet);
      runtime->mP1x = uvScale.x;
      runtime->mP1y = uvScale.y;
      runtime->mP2x = uvBorder.x;
      runtime->mP2y = uvBorder.y;
      return;
    }

    if (runtime->mVertices.HasElements() && runtime->mDynamicTexSheet.px != nullptr) {
      Flush();
    }

    const gpg::Rect2f* uvRect = runtime->mTextureBatcher->AddTexture(texture);
    if (uvRect == nullptr) {
      if (runtime->mVertices.HasElements()) {
        Flush();
      }
      runtime->mTextureBatcher->Reset();
      uvRect = runtime->mTextureBatcher->AddTexture(texture);
    }

    ResetLegacyWeakHandle(runtime->mTexture);
    ResetLegacyWeakHandle(runtime->mDynamicTexSheet);

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
   * the legacy-weak handle lane, and resets UV scale/border to the identity
   * rectangle (scale = 1,1; border = 0,0).
   *
   * Parameter is the ID3DTextureSheet base interface, but the runtime
   * invariant across all call sites is that the concrete sheet is always a
   * CD3DDynamicTextureSheet (binary directly stores the derived pointer
   * without a virtual downcast guard).
   */
  void CD3DPrimBatcher::SetTexture(boost::shared_ptr<ID3DTextureSheet> sheet)
  {
    CD3DPrimBatcherRuntimeView* const runtime = CD3DPrimBatcherRuntimeView::FromBatcher(this);

    const boost::shared_ptr<CD3DDynamicTextureSheet> derivedSheet =
      boost::static_pointer_cast<CD3DDynamicTextureSheet>(sheet);

    if (runtime->mVertices.HasElements() && runtime->mDynamicTexSheet.px != derivedSheet.get()) {
      Flush();
    }

    ResetLegacyWeakHandle(runtime->mTexture);
    AssignLegacyWeakFromShared(runtime->mDynamicTexSheet, derivedSheet);

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
    CD3DPrimBatcherRuntimeView* const runtime = CD3DPrimBatcherRuntimeView::FromBatcher(this);

    if (runtime->mVertices.HasElements()) {
      const std::uint32_t vertexCount = LegacyVectorCount(runtime->mVertices);
      const std::uint32_t primitiveCount = LegacyVectorCount(runtime->mPrimitives);
      if (runtime->mMode != static_cast<std::uint32_t>(kTriangleListPrimitiveType) ||
          (vertexCount + 4u) > kLegacyPrimQueueLimit ||
          (primitiveCount + 6u) > kLegacyPrimQueueLimit) {
        Flush();
      }
    }

    runtime->mMode = static_cast<std::uint32_t>(kTriangleListPrimitiveType);

    const std::uint16_t baseVertexIndex =
      static_cast<std::uint16_t>(LegacyVectorCount(runtime->mVertices));

    (void)PushBackLegacyQueue(runtime->mVertices, BuildTransformedVertex(*runtime, topLeft), kLegacyPrimQueueLimit);
    (void)PushBackLegacyQueue(runtime->mVertices, BuildTransformedVertex(*runtime, topRight), kLegacyPrimQueueLimit);
    (void)PushBackLegacyQueue(runtime->mVertices, BuildTransformedVertex(*runtime, bottomRight), kLegacyPrimQueueLimit);
    (void)PushBackLegacyQueue(runtime->mVertices, BuildTransformedVertex(*runtime, bottomLeft), kLegacyPrimQueueLimit);

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

    CD3DPrimBatcherRuntimeView* const runtime = CD3DPrimBatcherRuntimeView::FromBatcher(this);
    if (runtime->mVertices.HasElements() && runtime->mMode != static_cast<std::uint32_t>(kTriangleListPrimitiveType)) {
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

    CD3DPrimBatcherRuntimeView* const runtime = CD3DPrimBatcherRuntimeView::FromBatcher(this);
    if (runtime->mVertices.HasElements() && runtime->mMode != static_cast<std::uint32_t>(kTriangleListPrimitiveType)) {
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
    CD3DPrimBatcherRuntimeView* const runtime = CD3DPrimBatcherRuntimeView::FromBatcher(this);

    if (runtime->mVertices.HasElements()) {
      const std::uint32_t vertexCount = LegacyVectorCount(runtime->mVertices);
      const std::uint32_t primitiveCount = LegacyVectorCount(runtime->mPrimitives);
      if (runtime->mMode != static_cast<std::uint32_t>(kTriangleListPrimitiveType) ||
          (vertexCount + 3u) > kLegacyPrimQueueLimit ||
          (primitiveCount + 3u) > kLegacyPrimQueueLimit) {
        Flush();
      }
    }

    runtime->mMode = static_cast<std::uint32_t>(kTriangleListPrimitiveType);

    const std::uint16_t baseVertexIndex =
      static_cast<std::uint16_t>(LegacyVectorCount(runtime->mVertices));

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

    CD3DPrimBatcherRuntimeView* const runtime = CD3DPrimBatcherRuntimeView::FromBatcher(this);
    if (runtime->mVertices.HasElements() && runtime->mMode != static_cast<std::uint32_t>(kTriangleListPrimitiveType)) {
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

    CD3DPrimBatcherRuntimeView* const runtime = CD3DPrimBatcherRuntimeView::FromBatcher(this);
    if (runtime->mVertices.HasElements() && runtime->mMode != static_cast<std::uint32_t>(kTriangleListPrimitiveType)) {
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
    CD3DPrimBatcherRuntimeView* const runtime = CD3DPrimBatcherRuntimeView::FromBatcher(this);

    if (runtime->mVertices.HasElements()) {
      const std::uint32_t vertexCount = LegacyVectorCount(runtime->mVertices);
      const std::uint32_t primitiveCount = LegacyVectorCount(runtime->mPrimitives);
      if (runtime->mMode != static_cast<std::uint32_t>(kLineListPrimitiveType) ||
          (vertexCount + 2u) > kLegacyPrimQueueLimit ||
          (primitiveCount + 2u) > kLegacyPrimQueueLimit) {
        Flush();
      }
    }

    runtime->mMode = static_cast<std::uint32_t>(kLineListPrimitiveType);

    const std::uint16_t baseVertexIndex =
      static_cast<std::uint16_t>(LegacyVectorCount(runtime->mVertices));

    (void)PushBackLegacyQueue(runtime->mVertices, BuildTransformedVertex(*runtime, start), kLegacyPrimQueueLimit);
    (void)PushBackLegacyQueue(runtime->mVertices, BuildTransformedVertex(*runtime, end), kLegacyPrimQueueLimit);

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

    CD3DPrimBatcherRuntimeView* const runtime = CD3DPrimBatcherRuntimeView::FromBatcher(this);
    if (runtime->mVertices.HasElements() && runtime->mMode != static_cast<std::uint32_t>(kLineListPrimitiveType)) {
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
    CD3DPrimBatcherRuntimeView* const runtime = CD3DPrimBatcherRuntimeView::FromBatcher(this);
    if (runtime->mVertices.HasElements() && runtime->mMode != static_cast<std::uint32_t>(kLineListPrimitiveType)) {
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
    CD3DPrimBatcherRuntimeView* const runtime = CD3DPrimBatcherRuntimeView::FromBatcher(this);

    if (runtime->mVertices.HasElements()) {
      if (runtime->mMode != static_cast<std::uint32_t>(kTriangleListPrimitiveType)) {
        Flush();
      } else {
        const std::uint32_t vertexCount = LegacyVectorCount(runtime->mVertices);
        const std::uint32_t primitiveCount = LegacyVectorCount(runtime->mPrimitives);
        if ((vertexCount + 2u) > kLegacyPrimQueueLimit ||
            (primitiveCount + 2u) > kLegacyPrimQueueLimit) {
          Flush();
        }
      }
    }

    runtime->mMode = static_cast<std::uint32_t>(kLineListPrimitiveType);

    const std::uint16_t baseVertexIndex =
      static_cast<std::uint16_t>(LegacyVectorCount(runtime->mVertices));
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

    CD3DPrimBatcherRuntimeView* const runtime = CD3DPrimBatcherRuntimeView::FromBatcher(this);
    if (runtime->mVertices.HasElements() && runtime->mMode != static_cast<std::uint32_t>(kMode1PrimitiveType)) {
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

    CD3DPrimBatcherRuntimeView* const runtime = CD3DPrimBatcherRuntimeView::FromBatcher(this);
    if (runtime->mVertices.HasElements() && runtime->mMode != static_cast<std::uint32_t>(kMode1PrimitiveType)) {
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

    CD3DPrimBatcherRuntimeView* const runtime = CD3DPrimBatcherRuntimeView::FromBatcher(this);
    while (primitiveCount != 0u) {
      const std::uint32_t indicesPerPrimitive = (verticesPerPrimitive == 4u) ? 6u : verticesPerPrimitive;
      const std::uint32_t usedPrimitiveIndices = LegacyVectorCount(runtime->mPrimitives);
      const std::uint32_t usedVertices = LegacyVectorCount(runtime->mVertices);

      const std::uint32_t maxByIndices = (kLegacyPrimQueueLimit - usedPrimitiveIndices) / indicesPerPrimitive;
      const std::uint32_t maxByVertices = (kLegacyPrimQueueLimit - usedVertices) / verticesPerPrimitive;
      const std::uint32_t batchPrimitiveCount = std::min(primitiveCount, std::min(maxByIndices, maxByVertices));
      if (batchPrimitiveCount == 0u) {
        Flush();
        continue;
      }

      const std::uint16_t baseVertexIndex = static_cast<std::uint16_t>(usedVertices);
      const std::uint32_t vertexBatchCount = verticesPerPrimitive * batchPrimitiveCount;

      for (std::uint32_t vertexIndex = 0; vertexIndex < vertexBatchCount; ++vertexIndex) {
        (void)PushBackLegacyQueue(
          runtime->mVertices,
          BuildTransformedVertex(*runtime, sourceVertices[vertexIndex]),
          kLegacyPrimQueueLimit
        );
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
    CD3DPrimBatcherRuntimeView* const runtime = CD3DPrimBatcherRuntimeView::FromBatcher(this);
    (void)PushBackLegacyQueue(
      runtime->mVertices,
      BuildTransformedVertex(*runtime, sourceVertex),
      kLegacyPrimQueueLimit
    );
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

    CD3DPrimBatcherRuntimeView* const runtime = CD3DPrimBatcherRuntimeView::FromBatcher(this);
    const std::uint16_t mappedIndex = static_cast<std::uint16_t>(LegacyVectorCount(runtime->mVertices));

    (void)PushBackLegacyQueue(
      runtime->mVertices,
      BuildTransformedVertex(*runtime, sourceVertices[sourceIndex]),
      kLegacyPrimQueueLimit
    );

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

    CD3DPrimBatcherRuntimeView* const runtime = CD3DPrimBatcherRuntimeView::FromBatcher(this);
    while (primitiveCount != 0u) {
      const std::uint32_t indicesPerPrimitive = (verticesPerPrimitive == 4u) ? 6u : verticesPerPrimitive;
      const std::uint32_t usedPrimitiveIndices = LegacyVectorCount(runtime->mPrimitives);
      const std::uint32_t usedVertices = LegacyVectorCount(runtime->mVertices);

      const std::uint32_t maxByIndices = (kLegacyPrimQueueLimit - usedPrimitiveIndices) / indicesPerPrimitive;
      const std::uint32_t maxByVertices = (kLegacyPrimQueueLimit - usedVertices) / verticesPerPrimitive;
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
    CD3DPrimBatcherRuntimeView* const runtime = CD3DPrimBatcherRuntimeView::FromBatcher(this);
    if (!runtime->mVertices.HasElements()) {
      return;
    }

    if (runtime->mResetComposite != 0u) {
      runtime->mComposite = VMatrix4::Multiply(runtime->mViewMatrix, runtime->mProjectionMatrix);
      runtime->mRebuildComposite = 0;
    }

    ShaderVar& compositeMatrixShaderVar = GetPrimBatcherCompositeMatrixShaderVar();
    if (runtime->mRebuildComposite == 0u) {
      if (compositeMatrixShaderVar.Exists()) {
        compositeMatrixShaderVar.mEffectVariable->SetMatrix4x4(&runtime->mComposite);
      }
      runtime->mRebuildComposite = 1;
    }

    ShaderVar& alphaMultiplierShaderVar = GetPrimBatcherAlphaMultiplierShaderVar();
    if (alphaMultiplierShaderVar.Exists()) {
      alphaMultiplierShaderVar.mEffectVariable->SetFloat(runtime->mAlphaMultiplier);
    }

    ShaderVar& textureShaderVar = GetPrimBatcherTexture1ShaderVar();
    if (runtime->mDynamicTexSheet.px != nullptr) {
      const auto& boundDynamicTextureSheet =
        reinterpret_cast<const boost::shared_ptr<CD3DDynamicTextureSheet>&>(runtime->mDynamicTexSheet);
      textureShaderVar.GetTexture(boundDynamicTextureSheet);
    } else {
      (void)runtime->mTextureBatcher->GetCompositeTexture();
      textureShaderVar.GetTexture(runtime->mTextureBatcher->mDynTexSheet);
    }

    runtime->mCurVertexSheet = (runtime->mCurVertexSheet + 1) % 3;

    ID3DVertexStream* const vertexStream = runtime->mVertexSheets[runtime->mCurVertexSheet]->GetVertStream(0);
    const std::uint32_t vertexCount = LegacyVectorCount(runtime->mVertices);
    void* const lockedVertices = vertexStream->Lock(0, static_cast<int>(vertexCount), false, true);
    std::memcpy(lockedVertices, runtime->mVertices.mFirst, sizeof(Vertex) * vertexCount);
    vertexStream->Unlock();

    const std::uint32_t primitiveCount = LegacyVectorCount(runtime->mPrimitives);
    std::int16_t* const lockedPrimitives = runtime->mIndexSheet->Lock(0, primitiveCount, false, true);
    std::memcpy(lockedPrimitives, runtime->mPrimitives.mFirst, sizeof(std::int16_t) * primitiveCount);
    runtime->mIndexSheet->Unlock();

    CD3DIndexSheetViewRuntime indexSheetView{};
    indexSheetView.sheet = runtime->mIndexSheet;
    indexSheetView.startIndex = 0;
    indexSheetView.indexCount = static_cast<std::int32_t>(primitiveCount);

    CD3DVertexSheetViewRuntime vertexSheetView{};
    vertexSheetView.sheet = runtime->mVertexSheets[runtime->mCurVertexSheet];
    vertexSheetView.startVertex = 0;
    vertexSheetView.baseVertex = 0;
    vertexSheetView.endVertex = static_cast<std::int32_t>(vertexCount) - 1;

    std::int32_t primitiveType = static_cast<std::int32_t>(runtime->mMode);
    CD3DDevice* const device = D3D_GetDevice();
    (void)device->DrawTriangleList(&vertexSheetView, &indexSheetView, &primitiveType);

    runtime->mVertices.mLast = runtime->mVertices.mFirst;
    runtime->mPrimitives.mLast = runtime->mPrimitives.mFirst;
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
    Vector3f previous{
      center.x + axisCos.x,
      center.y + axisCos.y,
      center.z + axisCos.z,
    };

    for (std::uint32_t index = 1; index <= precision; ++index) {
      const float angle = stepAngle * static_cast<float>(index);
      const float cosAngle = std::cos(angle);
      const float sinAngle = std::sin(angle);

      const Vector3f current{
        center.x + (axisCos.x * cosAngle) + (axisSin.x * sinAngle),
        center.y + (axisCos.y * cosAngle) + (axisSin.y * sinAngle),
        center.z + (axisCos.z * cosAngle) + (axisSin.z * sinAngle),
      };

      DrawLine(primBatcher, previous, current, color);
      previous = current;
    }
  }

  /**
   * Address: 0x00453ED0 (?DRAW_WireCircle@Moho@@YAXPAVCD3DPrimBatcher@1@ABV?$Vector3@M@Wm3@@1MII@Z)
   *
   * What it does:
   * Builds tangent oval axes from `normal` and delegates to `DRAW_WireOval`.
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
    const Wm3::Quaternionf orientation = QuatCrossAdd({0.0f, 0.0f, 1.0f}, normal);

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
      {origin.x + xOffset.x, origin.y + xOffset.y, origin.z + xOffset.z},
      kAxisColorX
    );
    DrawLine(
      primBatcher,
      origin,
      {origin.x + yOffset.x, origin.y + yOffset.y, origin.z + yOffset.z},
      kAxisColorY
    );
    DrawLine(
      primBatcher,
      origin,
      {origin.x + zOffset.x, origin.y + zOffset.y, origin.z + zOffset.z},
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

    const Vector3f origin{transform.r[3].x, transform.r[3].y, transform.r[3].z};
    const Vector3f axisX{transform.r[0].x, transform.r[0].y, transform.r[0].z};
    const Vector3f axisY{transform.r[1].x, transform.r[1].y, transform.r[1].z};
    const Vector3f axisZ{transform.r[2].x, transform.r[2].y, transform.r[2].z};

    DrawLine(
      primBatcher,
      origin,
      {
        origin.x + (axisX.x * axisLength),
        origin.y + (axisX.y * axisLength),
        origin.z + (axisX.z * axisLength),
      },
      kAxisColorX
    );
    DrawLine(
      primBatcher,
      origin,
      {
        origin.x + (axisY.x * axisLength),
        origin.y + (axisY.y * axisLength),
        origin.z + (axisY.z * axisLength),
      },
      kAxisColorY
    );
    DrawLine(
      primBatcher,
      origin,
      {
        origin.x + (axisZ.x * axisLength),
        origin.y + (axisZ.y * axisLength),
        origin.z + (axisZ.z * axisLength),
      },
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

    const float halfBorderWidth = borderWidth * 0.5f;

    const Vector3f outerExpansion = NormalizeScaledVector3f(AddVector3f(heightAxis, widthAxis), halfBorderWidth);
    const Vector3f edgeExpansion = NormalizeScaledVector3f(SubVector3f(heightAxis, widthAxis), halfBorderWidth);

    const Vector3f topOuterLeft = SubVector3f(topLeft, outerExpansion);
    const Vector3f topOuterRight = SubVector3f(AddVector3f(topLeft, widthAxis), edgeExpansion);
    const Vector3f bottomOuterRight = AddVector3f(AddVector3f(AddVector3f(topLeft, widthAxis), heightAxis), outerExpansion);
    const Vector3f bottomOuterLeft = AddVector3f(AddVector3f(topLeft, heightAxis), edgeExpansion);

    const Vector3f topInnerLeft = AddVector3f(topLeft, outerExpansion);
    const Vector3f topInnerRight = AddVector3f(AddVector3f(topLeft, widthAxis), edgeExpansion);
    const Vector3f bottomInnerRight = SubVector3f(AddVector3f(AddVector3f(topLeft, widthAxis), heightAxis), outerExpansion);
    const Vector3f bottomInnerLeft = SubVector3f(AddVector3f(topLeft, heightAxis), edgeExpansion);

    if (heightField == nullptr) {
      primBatcher->DrawQuad(topOuterLeft, topInnerLeft, topInnerRight, topOuterRight, color);
      primBatcher->DrawQuad(topOuterRight, topInnerRight, bottomInnerRight, bottomOuterRight, color);
      primBatcher->DrawQuad(bottomInnerLeft, bottomOuterRight, bottomOuterLeft, bottomInnerRight, color);
      primBatcher->DrawQuad(topOuterLeft, bottomOuterLeft, bottomInnerLeft, topInnerLeft, color);
      return;
    }

    const std::array<Vector3f, 4> outerCorners{topOuterLeft, topOuterRight, bottomOuterRight, bottomOuterLeft};
    const std::array<Vector3f, 4> innerCorners{topInnerLeft, topInnerRight, bottomInnerRight, bottomInnerLeft};

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
        const Vector3f segmentOuterEnd = AddVector3f(segmentOuterStart, outerStep);

        const Vector3f segmentInnerStart{
          innerStart.x + (innerStep.x * segmentF),
          innerStartY + (innerStep.y * segmentF),
          innerStart.z + (innerStep.z * segmentF),
        };
        const Vector3f segmentInnerEnd = AddVector3f(segmentInnerStart, innerStep);

        primBatcher->DrawQuad(segmentOuterStart, segmentOuterEnd, segmentInnerEnd, segmentInnerStart, color);
      }
    }
  }

  /**
   * Address: 0x00455E20 (?DRAW_Oval@Moho@@YAXPAVCD3DPrimBatcher@1@ABV?$Vector3@M@Wm3@@1111IIPBVCHeightField@1@_NM@Z)
   *
   * What it does:
   * Draws one fixed-color filled oval band (20 quads) from inner/outer axis pairs.
   */
  void DRAW_Oval(
    CD3DPrimBatcher* const primBatcher,
    const Vector3f& center,
    const Vector3f& innerSinAxis,
    const Vector3f& outerCosAxis,
    const Vector3f& outerSinAxis,
    const Vector3f& innerCosAxis
  )
  {
    if (primBatcher == nullptr) {
      return;
    }

    for (std::uint32_t segment = 0; segment < kOvalSegmentCount; ++segment) {
      const std::uint32_t nextSegment = (segment + 1u) % kOvalSegmentCount;

      const float currentAngle = static_cast<float>(segment) * kOvalAngleStep;
      const float nextAngle = static_cast<float>(nextSegment) * kOvalAngleStep;

      const float cosCurrent = std::cos(currentAngle);
      const float sinCurrent = std::sin(currentAngle);
      const float cosNext = std::cos(nextAngle);
      const float sinNext = std::sin(nextAngle);

      const Vector3f innerCurrent{
        center.x + (innerCosAxis.x * cosCurrent) + (innerSinAxis.x * sinCurrent),
        center.y + (innerCosAxis.y * cosCurrent) + (innerSinAxis.y * sinCurrent),
        center.z + (innerCosAxis.z * cosCurrent) + (innerSinAxis.z * sinCurrent),
      };
      const Vector3f innerNext{
        center.x + (innerCosAxis.x * cosNext) + (innerSinAxis.x * sinNext),
        center.y + (innerCosAxis.y * cosNext) + (innerSinAxis.y * sinNext),
        center.z + (innerCosAxis.z * cosNext) + (innerSinAxis.z * sinNext),
      };
      const Vector3f outerCurrent{
        center.x + (outerCosAxis.x * cosCurrent) + (outerSinAxis.x * sinCurrent),
        center.y + (outerCosAxis.y * cosCurrent) + (outerSinAxis.y * sinCurrent),
        center.z + (outerCosAxis.z * cosCurrent) + (outerSinAxis.z * sinCurrent),
      };
      const Vector3f outerNext{
        center.x + (outerCosAxis.x * cosNext) + (outerSinAxis.x * sinNext),
        center.y + (outerCosAxis.y * cosNext) + (outerSinAxis.y * sinNext),
        center.z + (outerCosAxis.z * cosNext) + (outerSinAxis.z * sinNext),
      };

      primBatcher->DrawQuad(innerCurrent, outerCurrent, outerNext, innerNext, kOvalBandColor);
    }
  }

  /**
   * Address: 0x00456200 (?DRAW_Circle@Moho@@YAXPAVCD3DPrimBatcher@1@MABV?$Vector3@M@Wm3@@1MIIPBVCHeightField@1@_NM@Z)
   *
   * What it does:
   * Builds rotated inner/outer oval axes around `normal` and delegates to `DRAW_Oval`.
   */
  void DRAW_Circle(
    CD3DPrimBatcher* const primBatcher,
    const Vector3f& center,
    const Vector3f& normal,
    const float radius
  )
  {
    if (primBatcher == nullptr) {
      return;
    }

    const Wm3::Quaternionf orientation = QuatCrossAdd({0.0f, 0.0f, 1.0f}, normal);

    const float innerRadius = radius - kOvalBandHalfWidth;
    const float outerRadius = radius + kOvalBandHalfWidth;

    const Vector3f innerSinAxis = RotateByQuaternion({0.0f, innerRadius, 0.0f}, orientation);
    const Vector3f innerCosAxis = RotateByQuaternion({innerRadius, 0.0f, 0.0f}, orientation);
    const Vector3f outerSinAxis = RotateByQuaternion({0.0f, outerRadius, 0.0f}, orientation);
    const Vector3f outerCosAxis = RotateByQuaternion({outerRadius, 0.0f, 0.0f}, orientation);

    DRAW_Oval(primBatcher, center, innerSinAxis, outerCosAxis, outerSinAxis, innerCosAxis);
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

    wxWindowBase* const inputWindow = manager.mInputWindows[headIndex];
    if (inputWindow == nullptr) {
      return;
    }

    std::int32_t width = 0;
    std::int32_t height = 0;
    WX_GetClientSize(inputWindow, width, height);
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
    CD3DPrimBatcherRuntimeView::FromBatcher(this)->mAlphaMultiplier = manager.mUIControlsAlpha;
  }
} // namespace moho
