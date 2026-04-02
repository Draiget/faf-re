#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/Rect2.h"
#include "gpg/core/containers/FastVector.h"
#include "boost/shared_ptr.h"
#include "moho/math/VMatrix4.h"
#include "moho/math/Vector3f.h"
#include "moho/render/d3d/CD3DFontTypes.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "wm3/Box3.h"
#include "wm3/Quaternion.h"

namespace moho
{
  class CHeightField;
  class CUIManager;
  struct GeomCamera3;
  class CD3DIndexSheet;
  class CD3DTextureBatcher;
  class CD3DVertexSheet;
  class CD3DDynamicTextureSheet;

  class CD3DPrimBatcher
  {
  public:
    struct Vertex
    {
      float mX;             // +0x00
      float mY;             // +0x04
      float mZ;             // +0x08
      std::uint32_t mColor; // +0x0C
      float mU;             // +0x10
      float mV;             // +0x14
    };

    virtual ~CD3DPrimBatcher() = default;

    /**
     * Address: 0x00438560 (FUN_00438560)
     *
     * What it does:
     * Selects one prim-batcher effect file/technique pair on the active D3D
     * device and invalidates the uploaded composite matrix lane.
     */
    CD3DPrimBatcher* Setup(const char* techniqueName);

    /**
     * Address: 0x004385F0 (?SetProjectionMatrix@CD3DPrimBatcher@Moho@@QAEXABUVMatrix4@2@@Z)
     *
     * What it does:
     * Updates the prim-batcher projection matrix.
     */
    void SetProjectionMatrix(const VMatrix4& matrix);

    /**
     * Address: 0x004385A0 (?SetViewMatrix@CD3DPrimBatcher@Moho@@QAEXABUVMatrix4@2@@Z)
     *
     * What it does:
     * Updates the prim-batcher view matrix.
     */
    void SetViewMatrix(const VMatrix4& matrix);

    /**
     * Address: 0x00438640 (FUN_00438640)
     *
     * What it does:
     * Updates both view and projection matrices from one camera payload and
     * marks the composite matrix lane as dirty.
     */
    void SetViewProjMatrix(const GeomCamera3& camera);

    /**
     * Address: 0x004386A0 (?SetTexture@CD3DPrimBatcher@Moho@@QAEXABV?$shared_ptr@VCD3DBatchTexture@Moho@@@boost@@@Z)
     *
     * What it does:
     * Binds one retained batch texture for subsequent primitive draws.
     */
    void SetTexture(const boost::shared_ptr<CD3DBatchTexture>& texture);

    /**
     * Address: 0x004389A0 (?DrawQuad@CD3DPrimBatcher@Moho@@QAEXABUVertex@12@000@Z)
     *
     * What it does:
     * Emits one colored/UV quad primitive from four prebuilt vertices.
     */
    void DrawQuad(const Vertex& topLeft, const Vertex& topRight, const Vertex& bottomRight, const Vertex& bottomLeft);

    /**
     * Address: 0x00438DA0 (?DrawQuad@CD3DPrimBatcher@Moho@@QAEXABV?$Vector3@M@Wm3@@000I@Z)
     *
     * What it does:
     * Builds one unit-UV quad from four positions and delegates to the vertex overload.
     */
    void DrawQuad(
      const Vector3f& topLeft,
      const Vector3f& topRight,
      const Vector3f& bottomRight,
      const Vector3f& bottomLeft,
      std::uint32_t color
    );

    /**
     * Address: 0x00438EA0 (FUN_00438EA0)
     *
     * What it does:
     * Appends one batch of non-indexed quads.
     */
    void DrawQuads(const Vertex* sourceVertices, std::uint32_t quadCount);

    /**
     * Address: 0x00438EF0 (FUN_00438EF0)
     *
     * What it does:
     * Appends one batch of indexed quads.
     */
    void DrawIndexedQuads(
      const Vertex* sourceVertices,
      std::uint32_t sourceVertexCount,
      const std::uint16_t* sourceIndices,
      std::uint32_t quadCount
    );

    /**
     * Address: 0x00438F50 (?DrawTri@CD3DPrimBatcher@Moho@@QAEXABUVertex@12@00@Z)
     *
     * What it does:
     * Emits one textured/color triangle from three prebuilt vertices.
     */
    void DrawTri(const Vertex& v0, const Vertex& v1, const Vertex& v2);

    /**
     * Address: 0x00439210 (FUN_00439210)
     *
     * What it does:
     * Appends one batch of non-indexed triangles.
     */
    void DrawTriangles(const Vertex* sourceVertices, std::uint32_t triangleCount);

    /**
     * Address: 0x00439260 (FUN_00439260)
     *
     * What it does:
     * Appends one batch of indexed triangles.
     */
    void DrawIndexedTriangles(
      const Vertex* sourceVertices,
      std::uint32_t sourceVertexCount,
      const std::uint16_t* sourceIndices,
      std::uint32_t triangleCount
    );

    /**
     * Address: 0x00426150 (FUN_00426150, Moho::CD3DPrimBatcher::DrawChar)
     *
     * What it does:
     * Emits one glyph quad from cached font extents using caller-supplied basis
     * vectors and origin.
     */
    void DrawChar(
      const Vector3f& xAxis,
      const Vector3f& yAxis,
      const CD3DFontCharInfo& charInfo,
      const Vector3f& origin,
      std::uint32_t color
    );

    /**
     * Address: 0x004392C0 (?DrawLine@CD3DPrimBatcher@Moho@@QAEXABUVertex@12@0@Z)
     *
     * What it does:
     * Emits one colored line primitive from two prebuilt vertices.
     */
    void DrawLine(const Vertex& start, const Vertex& end);

    /**
     * Address: 0x004394D0 (FUN_004394D0)
     *
     * What it does:
     * Appends one batch of non-indexed lines.
     */
    void DrawLines(const Vertex* sourceVertices, std::uint32_t lineCount);

    /**
     * Address: 0x00439520 (FUN_00439520)
     *
     * What it does:
     * Appends one batch of indexed lines.
     */
    void DrawIndexedLines(
      const Vertex* sourceVertices,
      std::uint32_t sourceVertexCount,
      const std::uint16_t* sourceIndices,
      std::uint32_t lineCount
    );

    /**
     * Address: 0x00439580 (?DrawPoint@CD3DPrimBatcher@Moho@@QAEXABUVertex@12@@Z)
     *
     * What it does:
     * Emits one textured/color point vertex and one primitive index entry.
     */
    void DrawPoint(const Vertex& vertex);

    /**
     * Address: 0x004396E0 (FUN_004396E0)
     *
     * What it does:
     * Appends one batch of non-indexed vertex pairs using primitive mode 1.
     */
    void DrawMode1PrimitivePairs(const Vertex* sourceVertices, std::uint32_t primitivePairCount);

    /**
     * Address: 0x00439730 (FUN_00439730)
     *
     * What it does:
     * Appends one batch of indexed vertex pairs using primitive mode 1.
     */
    void DrawIndexedMode1PrimitivePairs(
      const Vertex* sourceVertices,
      std::uint32_t sourceVertexCount,
      const std::uint16_t* sourceIndices,
      std::uint32_t primitivePairCount
    );

    /**
     * Address: 0x0043A140 (?Flush@CD3DPrimBatcher@Moho@@QAEXXZ)
     *
     * What it does:
     * Flushes queued primitives to the current device pipeline.
     */
    void Flush();

    /**
     * Address: 0x0084D3E0 (FUN_0084D3E0)
     *
     * What it does:
     * Builds per-head UI orthographic matrices from the input-window client size and
     * applies UI alpha multiplier from the owning CUIManager.
     */
    void SetToViewport(int head, const CUIManager& manager);

  private:
    /**
     * Address: 0x00439B60 (?AddVert@CD3DPrimBatcher@Moho@@AAEXABUVertex@12@@Z)
     *
     * What it does:
     * Appends one transformed vertex to the queue.
     */
    void AddVert(const Vertex& sourceVertex);

    /**
     * Address: 0x00439790 (?AddVerts@CD3DPrimBatcher@Moho@@AAEXPBUVertex@12@II@Z)
     *
     * What it does:
     * Appends transformed vertices and generated primitive indices in capacity-aware chunks.
     */
    void AddVerts(const Vertex* sourceVertices, std::uint32_t primitiveCount, std::uint32_t verticesPerPrimitive);

    /**
     * Address: 0x0043A060 (?AddIndexedVert@CD3DPrimBatcher@Moho@@AAEGGPBUVertex@12@IAAV?$fastvector@G@gpg@@@Z)
     *
     * What it does:
     * Maps one source vertex index through a remap table, appending transformed vertex data on first use.
     */
    std::uint16_t
      AddIndexedVert(std::uint16_t sourceIndex, const Vertex* sourceVertices, gpg::fastvector<std::uint16_t>& remap);

    /**
     * Address: 0x00439BD0 (?AddIndexedVerts@CD3DPrimBatcher@Moho@@AAEXPBUVertex@12@IPBGII@Z)
     *
     * What it does:
     * Appends indexed primitives with per-chunk remap cache reset across flush boundaries.
     */
    void AddIndexedVerts(
      const Vertex* sourceVertices,
      std::uint32_t sourceVertexCount,
      const std::uint16_t* sourceIndices,
      std::uint32_t primitiveCount,
      std::uint32_t verticesPerPrimitive
    );
  };

  static_assert(sizeof(CD3DPrimBatcher::Vertex) == 0x18, "moho::CD3DPrimBatcher::Vertex size must be 0x18");
  static_assert(offsetof(CD3DPrimBatcher::Vertex, mX) == 0x00, "moho::CD3DPrimBatcher::Vertex::mX offset must be 0x00");
  static_assert(offsetof(CD3DPrimBatcher::Vertex, mY) == 0x04, "moho::CD3DPrimBatcher::Vertex::mY offset must be 0x04");
  static_assert(offsetof(CD3DPrimBatcher::Vertex, mZ) == 0x08, "moho::CD3DPrimBatcher::Vertex::mZ offset must be 0x08");
  static_assert(
    offsetof(CD3DPrimBatcher::Vertex, mColor) == 0x0C, "moho::CD3DPrimBatcher::Vertex::mColor offset must be 0x0C"
  );
  static_assert(offsetof(CD3DPrimBatcher::Vertex, mU) == 0x10, "moho::CD3DPrimBatcher::Vertex::mU offset must be 0x10");
  static_assert(offsetof(CD3DPrimBatcher::Vertex, mV) == 0x14, "moho::CD3DPrimBatcher::Vertex::mV offset must be 0x14");

  struct CD3DPrimBatcherRuntimeView
  {
    template <typename T>
    struct LegacyVector
    {
      T* mFirst;  // +0x00
      T* mLast;   // +0x04
      T* mEnd;    // +0x08

      [[nodiscard]] bool HasElements() const noexcept
      {
        return mFirst != nullptr && mLast != mFirst;
      }
    };

    template <typename T>
    struct LegacyWeakHandle
    {
      T* px;                                 // +0x00
      boost::detail::sp_counted_base* pi;    // +0x04
    };

    void* mVftable = nullptr;                            // +0x00
    CD3DVertexSheet* mVertexSheets[3]{};                // +0x04
    CD3DTextureBatcher* mTextureBatcher = nullptr;      // +0x10
    CD3DIndexSheet* mIndexSheet = nullptr;              // +0x14
    std::int32_t mCurVertexSheet = 0;                   // +0x18
    LegacyVector<CD3DPrimBatcher::Vertex> mVertices{};  // +0x1C
    std::uint32_t mUnknown028 = 0;                      // +0x28
    LegacyVector<std::int16_t> mPrimitives{};           // +0x2C
    std::uint32_t mMode = 0;                            // +0x38
    LegacyWeakHandle<CD3DBatchTexture> mTexture{};      // +0x3C
    LegacyWeakHandle<CD3DDynamicTextureSheet> mDynamicTexSheet{}; // +0x44
    float mP2x = 0.0f;                                  // +0x4C
    float mP2y = 0.0f;                                  // +0x50
    float mP1x = 1.0f;                                  // +0x54
    float mP1y = 1.0f;                                  // +0x58
    VMatrix4 mViewMatrix{};                             // +0x5C
    VMatrix4 mProjectionMatrix{};                       // +0x9C
    VMatrix4 mComposite{};                              // +0xDC
    std::uint8_t mResetComposite = 0;                  // +0x11C
    std::uint8_t mRebuildComposite = 0;                // +0x11D
    std::uint8_t mUnknown11ETo11F[0x02]{};             // +0x11E
    float mAlphaMultiplier = 1.0f;                     // +0x120

    [[nodiscard]] static CD3DPrimBatcherRuntimeView* FromBatcher(CD3DPrimBatcher* batcher) noexcept
    {
      return reinterpret_cast<CD3DPrimBatcherRuntimeView*>(batcher);
    }

    [[nodiscard]] static const CD3DPrimBatcherRuntimeView* FromBatcher(const CD3DPrimBatcher* batcher) noexcept
    {
      return reinterpret_cast<const CD3DPrimBatcherRuntimeView*>(batcher);
    }
  };

  static_assert(
    offsetof(CD3DPrimBatcherRuntimeView, mVertices) == 0x1C,
    "moho::CD3DPrimBatcherRuntimeView::mVertices offset must be 0x1C"
  );
  static_assert(
    offsetof(CD3DPrimBatcherRuntimeView, mPrimitives) == 0x2C,
    "moho::CD3DPrimBatcherRuntimeView::mPrimitives offset must be 0x2C"
  );
  static_assert(
    offsetof(CD3DPrimBatcherRuntimeView, mMode) == 0x38,
    "moho::CD3DPrimBatcherRuntimeView::mMode offset must be 0x38"
  );
  static_assert(
    offsetof(CD3DPrimBatcherRuntimeView, mViewMatrix) == 0x5C,
    "moho::CD3DPrimBatcherRuntimeView::mViewMatrix offset must be 0x5C"
  );
  static_assert(
    offsetof(CD3DPrimBatcherRuntimeView, mProjectionMatrix) == 0x9C,
    "moho::CD3DPrimBatcherRuntimeView::mProjectionMatrix offset must be 0x9C"
  );
  static_assert(
    offsetof(CD3DPrimBatcherRuntimeView, mComposite) == 0xDC,
    "moho::CD3DPrimBatcherRuntimeView::mComposite offset must be 0xDC"
  );
  static_assert(
    offsetof(CD3DPrimBatcherRuntimeView, mResetComposite) == 0x11C,
    "moho::CD3DPrimBatcherRuntimeView::mResetComposite offset must be 0x11C"
  );
  static_assert(
    offsetof(CD3DPrimBatcherRuntimeView, mRebuildComposite) == 0x11D,
    "moho::CD3DPrimBatcherRuntimeView::mRebuildComposite offset must be 0x11D"
  );
  static_assert(
    offsetof(CD3DPrimBatcherRuntimeView, mAlphaMultiplier) == 0x120,
    "moho::CD3DPrimBatcherRuntimeView::mAlphaMultiplier offset must be 0x120"
  );

  /**
   * Address: 0x00453AB0 (?DRAW_WireOval@Moho@@YAXPAVCD3DPrimBatcher@1@ABV?$Vector3@M@Wm3@@11II@Z)
   *
   * What it does:
   * Emits one wireframe oval around `center` using two orthogonal axis vectors.
   */
  void DRAW_WireOval(
    CD3DPrimBatcher* primBatcher,
    const Vector3f& center,
    const Vector3f& axisCos,
    const Vector3f& axisSin,
    std::uint32_t color,
    std::uint32_t precision
  );

  /**
   * Address: 0x00453ED0 (?DRAW_WireCircle@Moho@@YAXPAVCD3DPrimBatcher@1@ABV?$Vector3@M@Wm3@@1MII@Z)
   *
   * What it does:
   * Builds two tangent basis vectors from `normal` and delegates to `DRAW_WireOval`.
   */
  void DRAW_WireCircle(
    CD3DPrimBatcher* primBatcher,
    const Vector3f& center,
    const Vector3f& normal,
    float radius,
    std::uint32_t color,
    std::uint32_t precision
  );

  /**
   * Address: 0x004541F0 (?DRAW_WireCoords@Moho@@YAXPAVCD3DPrimBatcher@1@ABV?$Vector3@M@Wm3@@ABV?$Quaternion@M@4@M@Z)
   *
   * What it does:
   * Draws RGB basis axes at `origin` transformed by quaternion orientation.
   */
  void DRAW_WireCoords(
    CD3DPrimBatcher* primBatcher,
    const Vector3f& origin,
    const Wm3::Quaternionf& orientation,
    float axisLength
  );

  /**
   * Address: 0x00454430 (?DRAW_WireCoords@Moho@@YAXPAVCD3DPrimBatcher@1@ABUVMatrix4@1@M@Z)
   *
   * What it does:
   * Draws RGB basis axes from one transform matrix row-basis and translation.
   */
  void DRAW_WireCoords(CD3DPrimBatcher* primBatcher, const VMatrix4& transform, float axisLength);

  /**
   * Address: 0x00454680 (?DRAW_WireBox@Moho@@YAXPAVCD3DPrimBatcher@1@ABV?$Box3@M@Wm3@@I@Z)
   *
   * What it does:
   * Emits a wireframe oriented box using the standard 12-edge index pattern.
   */
  void DRAW_WireBox(CD3DPrimBatcher* primBatcher, const Wm3::Box3f& box, std::uint32_t color);

  /**
   * Address: 0x00455480 (?DRAW_Rect@Moho@@YAXPAVCD3DPrimBatcher@1@MABV?$Vector3@M@Wm3@@11IPBVCHeightField@1@M@Z)
   *
   * What it does:
   * Draws one rectangle in prim-batcher space using basis axes and top-left anchor.
   */
  void DRAW_Rect(
    CD3DPrimBatcher* primBatcher,
    float borderWidth,
    const Vector3f& heightAxis,
    const Vector3f& widthAxis,
    const Vector3f& topLeft,
    std::uint32_t color,
    const CHeightField* heightField,
    float elevation
  );

  /**
   * Address: 0x00455E20 (?DRAW_Oval@Moho@@YAXPAVCD3DPrimBatcher@1@ABV?$Vector3@M@Wm3@@1111IIPBVCHeightField@1@_NM@Z)
   *
   * What it does:
   * Draws one filled oval band segment strip from inner/outer cosine-sine axes.
   */
  void DRAW_Oval(
    CD3DPrimBatcher* primBatcher,
    const Vector3f& center,
    const Vector3f& innerSinAxis,
    const Vector3f& outerCosAxis,
    const Vector3f& outerSinAxis,
    const Vector3f& innerCosAxis
  );

  /**
   * Address: 0x00456200 (?DRAW_Circle@Moho@@YAXPAVCD3DPrimBatcher@1@MABV?$Vector3@M@Wm3@@1MIIPBVCHeightField@1@_NM@Z)
   *
   * What it does:
   * Builds rotated inner/outer circle axes from `normal` and delegates to `DRAW_Oval`.
   */
  void DRAW_Circle(CD3DPrimBatcher* primBatcher, const Vector3f& center, const Vector3f& normal, float radius);

  /**
   * Address: 0x00454E20 (?DRAW_ClippedQuad@Moho@@YAXPAVCD3DPrimBatcher@1@ABV?$Rect2@M@gpg@@11I@Z)
   *
   * What it does:
   * Draws one textured quad clipped against `clipRect`, remapping UVs to the clipped area.
   */
  void DRAW_ClippedQuad(
    CD3DPrimBatcher* primBatcher,
    const gpg::Rect2f& quadRect,
    const gpg::Rect2f& uvRect,
    const gpg::Rect2f& clipRect,
    std::uint32_t color
  );

  /**
   * Address: 0x00455150 (?DRAW_TiledQuad@Moho@@YAXPAVCD3DPrimBatcher@1@ABV?$Rect2@M@gpg@@11I@Z)
   *
   * What it does:
   * Tiles a unit-UV quad across one source tile range and clips each tile against `clipRect`.
   */
  void DRAW_TiledQuad(
    CD3DPrimBatcher* primBatcher,
    const gpg::Rect2f& clipRect,
    const gpg::Rect2f& tileRect,
    const gpg::Rect2f& outputRect,
    std::uint32_t color
  );
} // namespace moho
