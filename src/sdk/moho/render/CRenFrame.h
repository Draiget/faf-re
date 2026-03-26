#pragma once

#include <cstddef>

#include "boost/shared_ptr.h"
#include "legacy/containers/String.h"

namespace moho
{
  class CRenFrame
  {
  public:
    /**
     * Address: 0x007F5C10 (FUN_007F5C10, Moho::CRenFrame::CRenFrame)
     *
     * What it does:
     * Initializes frame-pass name/state lanes and clears dynamic frame-sheet storage.
     */
    CRenFrame();

    /**
     * Address: 0x007F5C80 (FUN_007F5C80, Moho::CRenFrame::~CRenFrame)
     *
     * What it does:
     * Releases dynamic frame-sheet ownership and destroys frame-pass texture slots.
     */
    ~CRenFrame();

    /**
     * Address: 0x007F5DA0 (FUN_007F5DA0, Moho::CRenFrame::InitTransformedVerts)
     *
     * What it does:
     * Rebuilds the transformed full-screen quad geometry for the requested frame size.
     */
    void InitTransformedVerts(float width, float height);

    /**
     * Address: 0x007F6030 (FUN_007F6030, Moho::CRenFrame::Render)
     *
     * What it does:
     * Binds frame-pass textures/shader variables and issues the full-screen frame draw.
     */
    void Render(int width, int height);

    void ResetTransientResources() noexcept;

  public:
    msvc8::string mName;                   // +0x00
    void* mVertexSheet = nullptr;          // +0x1C
    float mWidth = 0.0f;                   // +0x20
    float mHeight = 0.0f;                  // +0x24
    boost::shared_ptr<void> mFrameTexture1; // +0x28
    boost::shared_ptr<void> mFrameTexture2; // +0x30
    boost::shared_ptr<void> mFrameTexture3; // +0x38
    boost::shared_ptr<void> mFrameTexture4; // +0x40
  };

  static_assert(offsetof(CRenFrame, mName) == 0x00, "CRenFrame::mName offset must be 0x00");
  static_assert(offsetof(CRenFrame, mVertexSheet) == 0x1C, "CRenFrame::mVertexSheet offset must be 0x1C");
  static_assert(offsetof(CRenFrame, mWidth) == 0x20, "CRenFrame::mWidth offset must be 0x20");
  static_assert(offsetof(CRenFrame, mHeight) == 0x24, "CRenFrame::mHeight offset must be 0x24");
  static_assert(offsetof(CRenFrame, mFrameTexture1) == 0x28, "CRenFrame::mFrameTexture1 offset must be 0x28");
  static_assert(offsetof(CRenFrame, mFrameTexture2) == 0x30, "CRenFrame::mFrameTexture2 offset must be 0x30");
  static_assert(offsetof(CRenFrame, mFrameTexture3) == 0x38, "CRenFrame::mFrameTexture3 offset must be 0x38");
  static_assert(offsetof(CRenFrame, mFrameTexture4) == 0x40, "CRenFrame::mFrameTexture4 offset must be 0x40");
  static_assert(sizeof(CRenFrame) == 0x48, "CRenFrame size must be 0x48");
} // namespace moho
