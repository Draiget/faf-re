#pragma once

// Engine addition, not in the shipped binary: the interface as one instanced draw (`ren_GpuText`,
// `ren_GpuUiQuads`, issue #307).
//
// Text has to stay in the painter's order with the images around it, or a dialog's text would show through
// the dialog on top of it. So both go in one list: each glyph and each image quad is one 96-byte record in a
// GPU buffer, in the order they were submitted, and the shader pulls six vertices per record. A record with
// a distance range reads the MSDF atlas page and takes coverage from the median of its channels; one without
// reads the prim batcher's atlas. All fonts share that page, so a change of font or size doesn't split the
// draw, and a pass of the interface is one draw unless something else has to draw in the middle of it.
//
// `MSDF_FlushPendingText` draws the list. Everything that could draw after it calls that first: the prim
// batcher's Flush, Setup and matrix setters, the device's draws, effect and technique changes, render targets
// and Refresh. A backend without vertex pulling, Direct3D 9 among them, draws through the prim batcher.

#include <cstddef>
#include <cstdint>
#include <vector>

#include "boost/shared_ptr.h"
#include "moho/math/VMatrix4.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"

namespace gpg::gal
{
  class EffectTechnique;
  class GpuBuffer;
  class GpuProgram;
  class Texture;
} // namespace gpg::gal

namespace moho
{
  class CD3DDynamicTextureSheet;

  /// `ren_GpuText`: draw MSDF text through MsdfTextGpuRenderer when the backend can (-1 auto, 1 force, 0 never).
  extern int ren_GpuText;
  /// `ren_GpuUiQuads`: image quads join the same draw as the text; off, each break between them is a draw.
  extern bool ren_GpuUiQuads;

  /** One quad (`QuadInstance` in the shader). Corners in `DrawQuad` order. */
  struct MsdfUiQuad
  {
    float mX[4] = {};
    float mY[4] = {};
    float mU[4] = {};
    float mV[4] = {};
    std::uint32_t mColor[4] = {}; // ARGB
    float mZ = 0.0f;
    float mPixelRange = 0.0f;     // screen pixels covered by the distance range; 0 for an image quad
    float mUnused[2] = {};
  };
  static_assert(sizeof(MsdfUiQuad) == 96, "MsdfUiQuad must match QuadInstance");

  class MsdfTextGpuRenderer
  {
  public:
    [[nodiscard]] static MsdfTextGpuRenderer& Get();

    /** `ren_GpuText` is on and the backend can draw this path (creates it on first use). */
    [[nodiscard]] bool IsActive();

    /**
     * Starts a string's glyphs from this atlas page, with this batcher's matrices and alpha multiplier.
     * False, having added nothing, when the page has no texture.
     */
    [[nodiscard]] bool BeginString(CD3DPrimBatcher& batcher, const boost::shared_ptr<CD3DDynamicTextureSheet>& page);

    void AddGlyph(const MsdfUiQuad& glyph);

    /**
     * Adds an image quad whose vertices already have their atlas coordinates. False when it has to go
     * through the batcher: the path is off, or the caller draws with a technique other than the UI's.
     */
    [[nodiscard]] bool QueueImageQuad(
      CD3DPrimBatcher& batcher, const CD3DPrimBatcher::Vertex& topLeft, const CD3DPrimBatcher::Vertex& topRight,
      const CD3DPrimBatcher::Vertex& bottomRight, const CD3DPrimBatcher::Vertex& bottomLeft
    );

    /** Draws the pending quads. */
    void Flush();

  private:
    /** Pending quads keep to one batcher and its matrices. */
    void PrepareFor(CD3DPrimBatcher& batcher);
    void Push(const MsdfUiQuad& quad);

    boost::shared_ptr<gpg::gal::GpuProgram> mProgram;
    boost::shared_ptr<gpg::gal::GpuBuffer> mBuffer;
    std::vector<MsdfUiQuad> mPending;
    boost::shared_ptr<gpg::gal::Texture> mPage; // the MSDF atlas page
    CD3DPrimBatcher* mBatcher = nullptr;        // whose atlas and matrices the pending quads use
    VMatrix4 mComposite{};
    float mAlphaMultiplier = 1.0f;
    std::uint32_t mNextQuad = 0u;               // where the next upload goes in the buffer
    // The last technique seen by QueueImageQuad and whether quads may join under it. Selecting a technique
    // makes a new object, so this compares by pointer once and by name only when that changes.
    boost::shared_ptr<gpg::gal::EffectTechnique> mCheckedTechnique;
    bool mCheckedTechniqueAllowsQuads = false;
    bool mInitialized = false;
    bool mSupported = false;
  };

  /** Set while quads are pending, so the calls that have to flush cost one load when none are. */
  extern bool gMsdfTextPending;

  void MSDF_FlushPendingTextSlow();

  inline void MSDF_FlushPendingText()
  {
    if (gMsdfTextPending) {
      MSDF_FlushPendingTextSlow();
    }
  }
} // namespace moho
