#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/math/Vector3f.h"

namespace moho
{
  class CameraImpl;
  class CGeomSolid3;
  class CWldSession;

  struct SelectionDraggerLink
  {
    SelectionDraggerLink* mOwnerHead = nullptr; // +0x00
    SelectionDraggerLink* mNext = nullptr; // +0x04
  };

  static_assert(sizeof(SelectionDraggerLink) == 0x08, "SelectionDraggerLink size must be 0x08");

  /**
   * Base runtime state shared by 2D/3D selection draggers.
   *
   * This class currently models the recovered constructor layout/state lane.
   * Additional virtual methods are recovered in later passes.
   */
  class SelectionDragger
  {
  public:
    /**
     * Address: 0x008637F0 (FUN_008637F0, ??0SelectionDragger@Moho@@...)
     *
     * What it does:
     * Seeds dragger runtime state from current session cursor world/screen
     * lanes, falling back to the global invalid vector when world cursor data
     * is not available.
     */
    SelectionDragger(CameraImpl* camera, CWldSession* session);

    virtual ~SelectionDragger();

    /**
     * Address: 0x00864000 (FUN_00864000, Moho::SelectionDragger::dtr)
     *
     * What it does:
     * Runs dragger cleanup and conditionally frees this object when bit 0 of
     * `deleteFlags` is set.
     */
    SelectionDragger* DeleteWithFlag(std::uint8_t deleteFlags) noexcept;

  public:
    SelectionDraggerLink* mSelectionListHead; // +0x04
    CWldSession* mSess;       // +0x08
    CameraImpl* mCam;         // +0x0C
    float mX0;                // +0x10
    float mY0;                // +0x14
    Wm3::Vector3f mPos;       // +0x18
  };

  static_assert(offsetof(SelectionDragger, mSelectionListHead) == 0x04,
                "SelectionDragger::mSelectionListHead offset must be 0x04");
  static_assert(offsetof(SelectionDragger, mSess) == 0x08,
                "SelectionDragger::mSess offset must be 0x08");
  static_assert(offsetof(SelectionDragger, mCam) == 0x0C,
                "SelectionDragger::mCam offset must be 0x0C");
  static_assert(offsetof(SelectionDragger, mX0) == 0x10,
                "SelectionDragger::mX0 offset must be 0x10");
  static_assert(offsetof(SelectionDragger, mY0) == 0x14,
                "SelectionDragger::mY0 offset must be 0x14");
  static_assert(offsetof(SelectionDragger, mPos) == 0x18,
                "SelectionDragger::mPos offset must be 0x18");
  static_assert(sizeof(SelectionDragger) == 0x24,
                "SelectionDragger size must be 0x24");

  class SelectionDragger2D : public SelectionDragger
  {
  public:
    /**
     * Address: 0x00864CB0 (FUN_00864CB0, ??0SelectionDragger2D@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes 2D dragger tail state and seeds drag-end screen coordinates
     * to the global invalid-screen sentinel value.
     */
    SelectionDragger2D(CameraImpl* camera, CWldSession* session);

    ~SelectionDragger2D() override = default;

    /**
     * Address: 0x00864FC0 (FUN_00864FC0, Moho::SelectionDragger2D::Func5)
     *
     * What it does:
     * Builds one world-space selection solid by sorting current drag start/end
     * screen coordinates into a canonical rectangle and unprojecting it through
     * the active camera view.
     */
    [[nodiscard]] virtual CGeomSolid3 BuildSelectionSolid() const;

  public:
    std::uint8_t mStretch;   // +0x24
    std::uint8_t pad_0025[3];
    float mX1;               // +0x28
    float mY1;               // +0x2C
  };

  static_assert(offsetof(SelectionDragger2D, mStretch) == 0x24,
                "SelectionDragger2D::mStretch offset must be 0x24");
  static_assert(offsetof(SelectionDragger2D, mX1) == 0x28,
                "SelectionDragger2D::mX1 offset must be 0x28");
  static_assert(offsetof(SelectionDragger2D, mY1) == 0x2C,
                "SelectionDragger2D::mY1 offset must be 0x2C");
  static_assert(sizeof(SelectionDragger2D) == 0x30,
                "SelectionDragger2D size must be 0x30");
} // namespace moho
