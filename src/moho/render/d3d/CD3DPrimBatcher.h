#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/Rect2.h"
#include "gpg/core/containers/FastVector.h"
#include "legacy/containers/Vector.h"
#include "boost/shared_ptr.h"
#include "moho/math/VMatrix4.h"
#include "moho/math/Vector3f.h"
#include "moho/render/d3d/CD3DFontTypes.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "Wm3Box3.h"
#include "Wm3Quaternion.h"

namespace moho
{
  class CHeightField;
  class CUIManager;
  struct GeomCamera3;
  class CD3DIndexSheet;
  class CD3DTextureBatcher;
  class CD3DVertexSheet;
  class CD3DDynamicTextureSheet;
  class ID3DTextureSheet;

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

    /**
     * Address: 0x00438310 (FUN_00438310, ??0CD3DPrimBatcher@Moho@@QAE@PAVCD3DTextureBatcher@1@@Z)
     *
     * What it does:
     * Initializes one prim-batcher runtime lane, allocates three dynamic
     * vertex sheets and one dynamic index sheet from device resources, and
     * seeds identity view/projection/composite matrices.
     */
    explicit CD3DPrimBatcher(CD3DTextureBatcher* textureBatcher);

    /**
     * Address: 0x00438460 (FUN_00438460, Moho::CD3DPrimBatcher::~CD3DPrimBatcher)
     *
     * What it does:
     * Destroys the three vertex sheets and the index sheet through their
     * virtual `Destroy()` method, then releases the batch-texture and
     * dynamic-texture-sheet `boost::shared_ptr` lanes and the two queue
     * vectors' storage in reverse member order.
     *
     * Not virtual: the class has no vtable. The constructor stores the texture
     * batcher at +0x00, and `sp_counted_impl_p<CD3DPrimBatcher>::dispose`
     * (0x007FC1C0) calls this destructor directly.
     */
    ~CD3DPrimBatcher();

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
     * Address: 0x00438870 (FUN_00438870, ?SetTexture@CD3DPrimBatcher@Moho@@QAEXV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@@Z)
     *
     * What it does:
     * Binds one retained dynamic texture sheet directly (no atlas route),
     * releasing any previously-held batch texture handle and resetting UV
     * scale/border lanes to the identity (0,0)-(1,1). Takes the ID3DTextureSheet
     * base interface; the runtime invariant is that the concrete sheet is
     * always a CD3DDynamicTextureSheet (binary stores the derived pointer).
     */
    void SetTexture(boost::shared_ptr<ID3DTextureSheet> sheet);

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

    /// Engine addition: one axis-aligned screen quad for `DrawScreenQuads`.
    struct ScreenQuad
    {
      float mLeft;
      float mTop;
      float mRight;
      float mBottom;
      std::uint32_t mColor;
    };

    /**
     * Engine addition, not recovered from the binary: for each quad, exactly what
     * `DrawQuad({left,top,0}, {right,top,0}, {right,bottom,0}, {left,bottom,0}, color)` does under
     * the texture set last - the same vertices, indices and flushes - written in blocks instead
     * of four calls per quad. Strategic icons draw tens of thousands of these per frame.
     */
    void DrawScreenQuads(const ScreenQuad* quads, std::size_t quadCount);

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

  public:
    // Offsets proven from the binary:
    //   0x00438331 (constructor) `mov [ebx], eax` stores the texture batcher at +0x00.
    //   0x004383DC (constructor) fills the three vertex sheets from `lea ecx, [ebx+4]`.
    //   0x0043A268 (Flush) advances +0x10 with `idiv` by 3, and 0x0043A26E
    //   indexes the vertex sheets with it (`[ebp+edx*4+4]`).
    //   0x0043A2FF (Flush) loads the index sheet from +0x14 to lock it.
    // The vertex and index queues are VC8 `std::vector`s (debug-iterator
    // layout: proxy dword + {first,last,end} triple): the constructor
    // reserves them at 0x00438433 (`ecx = this + 0x18`) and 0x0043843B
    // (`ecx = this + 0x28`) via the `reserve` emissions 0x0043A470/0x0043A6C0,
    // the append lane is `push_back` at 0x0043A5C0, and the empty() probe is
    // 0x0043A570. The proxy dwords are never read by the binary.
    CD3DTextureBatcher* mTextureBatcher = nullptr;      // +0x00
    CD3DVertexSheet* mVertexSheets[3]{};                // +0x04
    std::int32_t mCurVertexSheet = 0;                   // +0x10
    CD3DIndexSheet* mIndexSheet = nullptr;              // +0x14
    msvc8::vector<Vertex> mVertices{};                  // +0x18
    msvc8::vector<std::int16_t> mPrimitives{};          // +0x28
    std::uint32_t mMode = 0;                            // +0x38
    // Offsets proven from the binary, not from field order:
    //   0x00438870 `cmp [esi+3Ch], ebx` tests the incoming *sheet* pointer, and
    //   0x0043A214 (Flush) `cmp [ebp+3Ch], ebx` / `lea eax, [ebp+3Ch]` hands
    //   +0x3C to the texture shader var as a `shared_ptr<CD3DDynamicTextureSheet>`.
    //   0x004387A5 `mov [edi+44h], edx` stores the incoming CD3DBatchTexture*,
    //   with its control block at +0x48 (`cmp esi, [edi+48h]`).
    // Both handles are strong `boost::shared_ptr<T>` lanes: the rebind at
    // 0x004387A5 stores `px` then `lock xadd [pi+4], 1` (add_ref_copy) and
    // releases the old block through 0x004229B0 (sp_counted_base::release).
    boost::shared_ptr<CD3DDynamicTextureSheet> mDynamicTexSheet{}; // +0x3C
    boost::shared_ptr<CD3DBatchTexture> mTexture{};                // +0x44
    float mP2x = 0.0f;                                  // +0x4C
    float mP2y = 0.0f;                                  // +0x50
    float mP1x = 1.0f;                                  // +0x54
    float mP1y = 1.0f;                                  // +0x58
    VMatrix4 mViewMatrix{};                             // +0x5C
    VMatrix4 mProjectionMatrix{};                       // +0x9C
    VMatrix4 mComposite{};                              // +0xDC
    std::uint8_t mResetComposite = 0;                  // +0x11C
    std::uint8_t mRebuildComposite = 0;                // +0x11D
    float mAlphaMultiplier = 1.0f;                     // +0x120

  };

  static_assert(sizeof(CD3DPrimBatcher) == 0x124, "moho::CD3DPrimBatcher size must be 0x124");
  static_assert(sizeof(CD3DPrimBatcher::Vertex) == 0x18, "moho::CD3DPrimBatcher::Vertex size must be 0x18");
  static_assert(offsetof(CD3DPrimBatcher::Vertex, mX) == 0x00, "moho::CD3DPrimBatcher::Vertex::mX offset must be 0x00");
  static_assert(offsetof(CD3DPrimBatcher::Vertex, mY) == 0x04, "moho::CD3DPrimBatcher::Vertex::mY offset must be 0x04");
  static_assert(offsetof(CD3DPrimBatcher::Vertex, mZ) == 0x08, "moho::CD3DPrimBatcher::Vertex::mZ offset must be 0x08");
  static_assert(
    offsetof(CD3DPrimBatcher::Vertex, mColor) == 0x0C, "moho::CD3DPrimBatcher::Vertex::mColor offset must be 0x0C"
  );
  static_assert(offsetof(CD3DPrimBatcher::Vertex, mU) == 0x10, "moho::CD3DPrimBatcher::Vertex::mU offset must be 0x10");
  static_assert(offsetof(CD3DPrimBatcher::Vertex, mV) == 0x14, "moho::CD3DPrimBatcher::Vertex::mV offset must be 0x14");


  static_assert(
    offsetof(CD3DPrimBatcher, mTextureBatcher) == 0x00,
    "moho::CD3DPrimBatcher::mTextureBatcher offset must be 0x00"
  );
  static_assert(
    offsetof(CD3DPrimBatcher, mVertexSheets) == 0x04,
    "moho::CD3DPrimBatcher::mVertexSheets offset must be 0x04"
  );
  static_assert(
    offsetof(CD3DPrimBatcher, mCurVertexSheet) == 0x10,
    "moho::CD3DPrimBatcher::mCurVertexSheet offset must be 0x10"
  );
  static_assert(
    offsetof(CD3DPrimBatcher, mIndexSheet) == 0x14,
    "moho::CD3DPrimBatcher::mIndexSheet offset must be 0x14"
  );
  static_assert(
    offsetof(CD3DPrimBatcher, mVertices) == 0x18,
    "moho::CD3DPrimBatcher::mVertices offset must be 0x18"
  );
  static_assert(
    offsetof(CD3DPrimBatcher, mPrimitives) == 0x28,
    "moho::CD3DPrimBatcher::mPrimitives offset must be 0x28"
  );
  static_assert(
    offsetof(CD3DPrimBatcher, mMode) == 0x38,
    "moho::CD3DPrimBatcher::mMode offset must be 0x38"
  );
  static_assert(
    offsetof(CD3DPrimBatcher, mDynamicTexSheet) == 0x3C,
    "moho::CD3DPrimBatcher::mDynamicTexSheet offset must be 0x3C"
  );
  static_assert(
    offsetof(CD3DPrimBatcher, mTexture) == 0x44,
    "moho::CD3DPrimBatcher::mTexture offset must be 0x44"
  );
  static_assert(
    offsetof(CD3DPrimBatcher, mViewMatrix) == 0x5C,
    "moho::CD3DPrimBatcher::mViewMatrix offset must be 0x5C"
  );
  static_assert(
    offsetof(CD3DPrimBatcher, mProjectionMatrix) == 0x9C,
    "moho::CD3DPrimBatcher::mProjectionMatrix offset must be 0x9C"
  );
  static_assert(
    offsetof(CD3DPrimBatcher, mComposite) == 0xDC,
    "moho::CD3DPrimBatcher::mComposite offset must be 0xDC"
  );
  static_assert(
    offsetof(CD3DPrimBatcher, mResetComposite) == 0x11C,
    "moho::CD3DPrimBatcher::mResetComposite offset must be 0x11C"
  );
  static_assert(
    offsetof(CD3DPrimBatcher, mRebuildComposite) == 0x11D,
    "moho::CD3DPrimBatcher::mRebuildComposite offset must be 0x11D"
  );
  static_assert(
    offsetof(CD3DPrimBatcher, mAlphaMultiplier) == 0x120,
    "moho::CD3DPrimBatcher::mAlphaMultiplier offset must be 0x120"
  );

  /**
   * Address: 0x0043A8B0 (FUN_0043A8B0)
   * Mangled: ??1WeakPtr_CD3DBatchTexture@Moho@@QAE@@Z
   *          (the IDB label is the analyst's; the emitted body is the
   *           out-of-line `boost::shared_ptr<Moho::CD3DBatchTexture>::reset()`
   *           instantiation - `this_type().swap(*this)` in boost 1.34.1)
   *
   * IDA signature:
   * void __usercall Moho::WeakPtr_CD3DBatchTexture::~WeakPtr_CD3DBatchTexture(
   *     boost::shared_ptr_CD3DBatchTexture *result@<eax>);
   *
   * What it does:
   * Empties one `shared_ptr<CD3DBatchTexture>` lane in place: clears `px`,
   * detaches the control block, then drops one *strong* owner reference from
   * the detached block - disposing the pointee when `use_count_` reaches zero
   * and destroying the block when `weak_count_` follows it to zero.
   */
  void ResetSharedBatchTextureHandle(boost::shared_ptr<CD3DBatchTexture>& handle) noexcept;

  /**
   * Address: 0x0043A860 (FUN_0043A860)
   * Mangled: ??1WeakPtr_CD3DDynamicTextureSheet@Moho@@QAE@@Z
   *          (the IDB label is the analyst's; the emitted body is the
   *           out-of-line
   *           `boost::shared_ptr<Moho::CD3DDynamicTextureSheet>::reset()`
   *           instantiation - `this_type().swap(*this)` in boost 1.34.1)
   *
   * IDA signature:
   * void __usercall Moho::WeakPtr_CD3DDynamicTextureSheet::~WeakPtr_CD3DDynamicTextureSheet(
   *     boost::shared_ptr_CD3DDynamicTextureSheet *result@<eax>);
   *
   * What it does:
   * Empties one `shared_ptr<CD3DDynamicTextureSheet>` lane in place: clears
   * `px`, detaches the control block, then drops one *strong* owner reference
   * from the detached block - disposing the sheet when `use_count_` reaches
   * zero and destroying the block when `weak_count_` follows it to zero.
   */
  void ResetSharedDynamicTextureSheetHandle(boost::shared_ptr<CD3DDynamicTextureSheet>& handle) noexcept;

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

  /** The two corner rings of a `DRAW_Rect` border, each top-left, top-right, bottom-right, bottom-left. */
  struct DrawRectRing
  {
    std::array<Vector3f, 4> outer;
    std::array<Vector3f, 4> inner;
  };

  /**
   * The corner computation at the head of `DRAW_Rect` (0x00455480..0x00455907).
   *
   * What it does:
   * Expands the rectangle spanned from `topLeft` by `widthAxis` and
   * `heightAxis` into the outer and inner corner rings of a border
   * `borderWidth` wide.
   */
  [[nodiscard]] DrawRectRing DRAW_RectRing(
    float borderWidth, const Vector3f& heightAxis, const Vector3f& widthAxis, const Vector3f& topLeft
  );

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
   * Draws one filled oval band segment strip from inner/outer cosine-sine axes
   * in `color` (FAF FA-Binary-Patches (hooks/HDraw.cpp): 48 segments, and the
   * colour the patch reads from CIRCLE_COLOR).
   */
  void DRAW_Oval(
    CD3DPrimBatcher* primBatcher,
    const Vector3f& center,
    const Vector3f& innerSinAxis,
    const Vector3f& outerCosAxis,
    const Vector3f& outerSinAxis,
    const Vector3f& innerCosAxis,
    std::uint32_t color
  );

  /// `DRAW_Oval`'s segment count: 48 with FAF FA-Binary-Patches (hooks/HDraw.cpp), 20 as shipped.
  inline constexpr std::uint32_t kDrawOvalSegmentCount = 0x30U;

  /**
   * What it does:
   * The angle `DRAW_Oval` takes the cosine and sine of for segment `segment`.
   */
  [[nodiscard]] float DRAW_OvalSegmentAngle(std::uint32_t segment) noexcept;

  /** The four axes `DRAW_Circle` hands to `DRAW_Oval`. */
  struct DrawOvalAxes
  {
    Vector3f innerSin;
    Vector3f outerCos;
    Vector3f outerSin;
    Vector3f innerCos;
  };

  /**
   * The axis computation of `DRAW_Circle` (0x00456200).
   *
   * What it does:
   * Rotates the inner (`radius - bandHalfWidth`) and outer
   * (`radius + bandHalfWidth`) X/Y axes into the plane whose normal is
   * `normal`.
   */
  [[nodiscard]] DrawOvalAxes DRAW_CircleAxes(const Vector3f& normal, float radius, float bandHalfWidth);

  /**
   * Address: 0x00456200 (?DRAW_Circle@Moho@@YAXPAVCD3DPrimBatcher@1@MABV?$Vector3@M@Wm3@@1MIIPBVCHeightField@1@_NM@Z)
   *
   * What it does:
   * Builds rotated inner/outer circle axes from `normal` and delegates to `DRAW_Oval`.
   *
   * The mangled name declares 10 parameters; parameter order below follows the mangled
   * signature exactly (`float`/`unsigned int`/`bool` are never back-referenced, so the
   * two `Vector3f` reference parameters are the only compressible/reused type). Only
   * `primBatcher`, `center`, `normal` and `radius` are actually read by this compiled
   * instantiation — the sole caller (`Moho::DrawCommandGraph`, 0x00853DC0) never computes
   * values for the other six, and this function's own compiled body never dereferences or
   * branches on them either. They are kept in the signature for ABI/name fidelity and are
   * marked `[[maybe_unused]]` rather than given invented semantic names.
   */
  void DRAW_Circle(
    CD3DPrimBatcher* primBatcher,
    [[maybe_unused]] float unusedFloat0,
    const Vector3f& center,
    const Vector3f& normal,
    [[maybe_unused]] float unusedFloat1,
    [[maybe_unused]] std::uint32_t unusedUInt0,
    [[maybe_unused]] std::uint32_t unusedUInt1,
    [[maybe_unused]] const CHeightField* heightField,
    [[maybe_unused]] bool unusedBool0,
    float radius
  );

  /**
   * FAF FA-Binary-Patches (hooks/HDraw.cpp, section/DrawFunc.cpp): `DRAW_Circle`
   * with the band half width (the patch's THICKNESS global) and the colour
   * (CIRCLE_COLOR) as parameters.
   *
   * What it does:
   * Draws a ring `2 * bandHalfWidth` wide of `radius` around `center` in the
   * plane whose normal is `normal`.
   */
  void DRAW_Circle(
    CD3DPrimBatcher* primBatcher,
    const Vector3f& center,
    const Vector3f& normal,
    float radius,
    float bandHalfWidth,
    std::uint32_t color
  );

  /**
   * FAF FA-Binary-Patches (section/DrawFunc.cpp `_DrawCircle`, DrawCircleSetColor.cpp):
   * UI_DrawCircle stores its band half width and colour in the THICKNESS and
   * CIRCLE_COLOR globals (initially 0.1 and 0xFF00D800) and never restores them, so
   * the engine's own `DRAW_Circle` (the build-assist circle) draws with the values of
   * the last UI_DrawCircle.
   *
   * What it does:
   * Sets the band half width and colour the 10-parameter `DRAW_Circle` uses.
   */
  void DRAW_SetCircleStyle(float bandHalfWidth, std::uint32_t color);

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
