#include "moho/render/CRenFrame.h"

#include <cstring>

#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/ID3DRenderTarget.h"
#include "moho/render/ID3DVertexSheet.h"
#include "moho/render/ID3DVertexStream.h"
#include "moho/render/d3d/CD3DVertexSheet.h"
#include "moho/render/d3d/CD3DDevice.h"

namespace moho
{
  namespace
  {
    constexpr int kRenFrameVertexFormatToken = 8;
    constexpr int kRenFrameVertexCountToken = 6;
    constexpr float kHalfPixelOffset = 0.5f;

    struct RenFrameTransformedVertex
    {
      float x;
      float y;
      float z;
      float rhw;
      float u0;
      float v0;
      float u1;
      float v1;
    };

    static_assert(sizeof(RenFrameTransformedVertex) == 0x20, "RenFrameTransformedVertex size must be 0x20");
  } // namespace

  /**
   * Address: 0x007F5C10 (FUN_007F5C10, Moho::CRenFrame::CRenFrame)
   */
  CRenFrame::CRenFrame()
    : mName()
    , mVertexSheet(nullptr)
    , mWidth(0.0f)
    , mHeight(0.0f)
    , mFrameTexture1()
    , mFrameTexture2()
    , mFrameTexture3()
    , mFrameTexture4()
  {}

  /**
   * Address: 0x007F5C80 (FUN_007F5C80, Moho::CRenFrame::~CRenFrame)
   */
  CRenFrame::~CRenFrame()
  {
    ResetTransientResources();
  }

  /**
   * Address: 0x007F5D00 (FUN_007F5D00, Moho::CRenFrame::SetTexture)
   */
  void CRenFrame::SetTexture(const unsigned int textureSlot, boost::shared_ptr<ID3DRenderTarget> texture)
  {
    (void)textureSlot;
    mFrameTexture1 = texture;
  }

  /**
   * Address: 0x007F5DA0 (FUN_007F5DA0, Moho::CRenFrame::InitTransformedVerts)
   *
   * float width, float height
   *
   * What it does:
   * Rebuilds the cached transformed fullscreen-quad vertices used by
   * CRenFrame pass rendering, with a half-pixel screen-space offset.
   */
  void CRenFrame::InitTransformedVerts(const float width, const float height)
  {
    CD3DDevice* const device = D3D_GetDevice();
    ID3DDeviceResources* const resources = device->GetResources();
    CD3DVertexFormat* const vertexFormat = resources->GetVertexFormat(kRenFrameVertexFormatToken);
    if (vertexFormat == nullptr) {
      gpg::Die("CRenFrame::InitVerts: Unable to create vertex format");
    }

    if (mVertexSheet != nullptr) {
      if (mWidth == width && mHeight == height) {
        return;
      }
    } else {
      mVertexSheet = resources->NewVertexSheet(0U, kRenFrameVertexCountToken, vertexFormat);
    }

    if (mVertexSheet == nullptr) {
      gpg::Die("CRenFrame::InitVerts: Unable to create vertex sheet");
    }

    const float maxX = width - kHalfPixelOffset;
    const float maxY = height - kHalfPixelOffset;
    mWidth = width;
    mHeight = height;

    const RenFrameTransformedVertex quadVertices[4] = {
      {-0.5f, -0.5f, 1.0f, 1.0f, 0.0f, 0.0f, 0.0f, 0.0f},
      {maxX, -0.5f, 1.0f, 1.0f, 1.0f, 0.0f, 1.0f, 0.0f},
      {-0.5f, maxY, 1.0f, 1.0f, 0.0f, 1.0f, 0.0f, 1.0f},
      {maxX, maxY, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f},
    };

    ID3DVertexStream* const vertexStream = mVertexSheet->GetVertStream(0U);
    const int vertexCount = mVertexSheet->Func5();
    void* const lockedVertices = vertexStream->Lock(0, vertexCount, false, false);
    std::memcpy(lockedVertices, quadVertices, sizeof(quadVertices));
    mVertexSheet->GetVertStream(0U)->Unlock();
  }

  void CRenFrame::ResetTransientResources() noexcept
  {
    mVertexSheet = nullptr;
  }
} // namespace moho
