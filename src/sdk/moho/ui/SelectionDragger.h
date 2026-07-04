#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/math/Vector3f.h"

namespace moho
{
  class CameraImpl;
  class CGeomSolid3;
  class CWldSession;
  struct SSelectionSetUserEntity;

  // Global selection-bracket weak-set, defined in moho/ui/UiRuntimeTypes.cpp.
  // SelectionDragger2D::~SelectionDragger2D() (0x00864D10) clears it as part of
  // its derived-destructor body.
  extern SSelectionSetUserEntity sSelectionBrackets;

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

    [[nodiscard]] virtual CGeomSolid3 BuildSelectionSolid() const = 0;

    [[nodiscard]] virtual bool HasActiveSelectionDrag() const = 0;

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

    /**
     * Address: 0x00864D10 (FUN_00864D10, ??1SelectionDragger2D@Moho@@UAE@XZ)
     * Mangled: ??1SelectionDragger2D@Moho@@UAE@XZ
     *
     * IDA signature:
     * SelectionDragger_vtbl* __stdcall sub_864D10(SelectionDragger_vtbl** this);
     *
     * What it does:
     * Derived-destructor body for the 2D selection dragger: clears the global
     * `sSelectionBrackets` weak-set via the full-range erase path, then chains
     * into the base `~SelectionDragger()` (which unlinks the intrusive
     * selection-link list and restores the IMauiDragger base vtable).
     */
    ~SelectionDragger2D() override;

    /**
     * Address: 0x00865470 (FUN_00865470, Moho::SelectionDragger2D::Func1)
     *
     * What it does:
     * Scalar-deleting-destructor variant for `SelectionDragger2D` —
     * delegates to the implicit base/derived destructor chain and
     * conditionally releases the object's heap storage when bit 0 of
     * `deleteFlags` is set. Provided as an explicit named bridge so the
     * binary's `??_GSelectionDragger2D@Moho@@UAEPAXI@Z`-style scalar
     * deleting dtor vtable slot has a recovered source counterpart.
     */
    SelectionDragger2D* DeleteWithFlag(std::uint8_t deleteFlags) noexcept;

    /**
     * Address: 0x00864FC0 (FUN_00864FC0, Moho::SelectionDragger2D::Func5)
     *
     * What it does:
     * Builds one world-space selection solid by sorting current drag start/end
     * screen coordinates into a canonical rectangle and unprojecting it through
     * the active camera view.
     */
    [[nodiscard]] CGeomSolid3 BuildSelectionSolid() const override;

    /**
     * Address: 0x00864DA0 (FUN_00864DA0, Moho::SelectionDragger2D::Func6)
     *
     * What it does:
     * Returns whether the drag stretched far enough to produce a selection
     * volume.
     */
    [[nodiscard]] bool HasActiveSelectionDrag() const override;

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

  /**
   * Address: 0x00863F10 (FUN_00863F10)
   *
   * What it does:
   * Builds the selectable user-entity weak-set currently covered by one active
   * selection dragger.
   */
  void CollectSelectionDraggerEntities(SSelectionSetUserEntity& outSelection, SelectionDragger& dragger);
} // namespace moho
