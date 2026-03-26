#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "moho/math/VMatrix4.h"
#include "moho/math/Vector3f.h"
#include "moho/render/textures/CD3DBatchTexture.h"

namespace moho
{
  class CHeightField;
  class CUIManager;

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
     * Address: 0x004392C0 (?DrawLine@CD3DPrimBatcher@Moho@@QAEXABUVertex@12@0@Z)
     *
     * What it does:
     * Emits one colored line primitive from two prebuilt vertices.
     */
    void DrawLine(const Vertex& start, const Vertex& end);

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
    std::uint8_t mUnknown000To11C[0x11D]{};
    std::uint8_t mRebuildComposite = 0; // +0x11D
    std::uint8_t mUnknown11ETo11F[0x02]{};
    float mAlphaMultiplier = 1.0f; // +0x120

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
    offsetof(CD3DPrimBatcherRuntimeView, mRebuildComposite) == 0x11D,
    "moho::CD3DPrimBatcherRuntimeView::mRebuildComposite offset must be 0x11D"
  );
  static_assert(
    offsetof(CD3DPrimBatcherRuntimeView, mAlphaMultiplier) == 0x120,
    "moho::CD3DPrimBatcherRuntimeView::mAlphaMultiplier offset must be 0x120"
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
} // namespace moho
