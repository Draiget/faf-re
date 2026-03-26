#include "moho/render/CRenFrame.h"

namespace moho
{
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

  void CRenFrame::ResetTransientResources() noexcept
  {
    mVertexSheet = nullptr;
  }
} // namespace moho
