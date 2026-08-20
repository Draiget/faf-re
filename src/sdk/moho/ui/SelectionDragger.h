#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/math/Vector3f.h"
#include "moho/ui/UiRuntimeTypes.h"

namespace moho
{
  class CameraImpl;
  class CD3DPrimBatcher;
  class CGeomSolid3;
  class CWldSession;
  struct SSelectionSetUserEntity;

  // Global selection-bracket weak-set, defined in moho/ui/UiRuntimeTypes.cpp.
  // SelectionDragger2D::~SelectionDragger2D() (0x00864D10) clears it as part of
  // its derived-destructor body.
  extern SSelectionSetUserEntity sSelectionBrackets;

  /**
   * Interface layer between `IMauiDragger` and the concrete selection
   * draggers: a dragger the world view is allowed to draw.
   *
   * RTTI proves the layer exists and where it sits. The complete-object
   * locator at 0x00E9AB4C names `.?AVISelectionDragger@Moho@@` and its
   * base-class array is `{ISelectionDragger mdisp=0, IMauiDragger mdisp=0,
   * WeakObject mdisp=4}`; `SelectionDragger`'s own locator (0x00E9AB60) and
   * both leaves (`SelectionDragger2D` 0x00E9A9B0, `SelectionDragger3D`
   * 0x00E9AA08) list the identical chain with `ISelectionDragger` between
   * them.
   *
   * `??_7ISelectionDragger@Moho@@6B@` sits at 0x00E479F8 and is exactly five
   * dwords wide - one more than `IMauiDragger`'s four, which is the single
   * virtual this layer introduces:
   *   +0x00  0x008640B0  scalar deleting destructor
   *   +0x04  0x0078DB50  `IMauiDragger::DragMove`                (inherited)
   *   +0x08  0x0078DB60  `IMauiDragger::DragRelease`             (inherited)
   *   +0x0C  0x0078DB80  `IMauiDragger::OnCurrentDraggerReplaced`(inherited)
   *   +0x10  0x00A82547  `_purecall`                 -> `Render`
   * (the dword after it, 0x00E47A0C, is the next class's locator, so the table
   * genuinely ends at five slots).
   *
   * The class is abstract, so the binary only ever runs its constructor and
   * destructor as part of a derived object:
   *   0x00864040  mov [eax+4], 0                 ; base weak head cleared
   *               mov [eax], offset ??_7ISelectionDragger@Moho@@6B@
   *   0x008640B0  restores ??_7IMauiDragger@Moho@@6B@, drains the weak chain,
   *               then honours the scalar-delete flag
   * Both are compiler-emitted here.
   */
  class ISelectionDragger : public IMauiDragger
  {
  public:
    /**
     * Vtable slot +0x10 of `??_7ISelectionDragger@Moho@@6B@` (0x00A82547,
     * `_purecall`).
     *
     * What it does:
     * Draws the dragger's on-screen feedback through the shared prim batcher.
     * `SelectionDragger2D` draws the selection rectangle (0x00865050);
     * `SelectionDragger3D`'s override (0x00864C80) is an empty `retn 4`.
     *
     * Dispatched at 0x0086F06D inside `Moho::CUIWorldView::Draw` (0x0086EF40)
     * - `call edx` with `edx = [[esi-4]+0x10]`, `ecx = esi-4`.
     */
    virtual void Render(CD3DPrimBatcher* batcher) = 0;
  };

  static_assert(sizeof(ISelectionDragger) == 0x08, "ISelectionDragger size must be 0x08");

  /**
   * Base runtime state shared by 2D/3D selection draggers.
   *
   * `??_7SelectionDragger@Moho@@6B@` lives at 0x00E479D8 and is written by the
   * constructor at 0x008637F0 (`mov dword ptr [eax], offset
   * ??_7SelectionDragger@Moho@@6B@`, 0x008637F7), so the vtable is
   * constructor-anchored. The instruction right before it, `mov dword ptr
   * [eax+4], 0` at 0x008637F0, is the inlined base constructor clearing the
   * `IMauiDragger`/`WeakObject` head, and the destructor body at 0x00864080
   * restores `??_7IMauiDragger@Moho@@6B@` (0x00E38DC0) before draining that
   * same `[ecx+4]` chain - which is what proves the dragger bases sit at
   * offset 0 and that +0x04 is theirs, not this class's.
   *
   * Slot map of `??_7SelectionDragger@Moho@@6B@` (read from the shipped PE):
   *   +0x00  0x00864000  scalar deleting destructor  -> `DeleteWithFlag`
   *   +0x04  0x0078DB50  `IMauiDragger::DragMove`    (inherited, empty body)
   *   +0x08  0x00863870  `SelectionDragger::DragRelease` (override, NOT YET
   *                      RECOVERED - see the note below)
   *   +0x0C  0x0078DB80  `IMauiDragger::OnCurrentDraggerReplaced` (inherited)
   *   +0x10  0x00A82547  `_purecall` -> `ISelectionDragger::Render`
   *   +0x14  0x00A82547  `_purecall` -> `BuildSelectionSolid`
   *   +0x18  0x00A82547  `_purecall` -> `HasActiveSelectionDrag`
   *
   * Slots +0x04 and +0x0C hold the *same* addresses as the corresponding slots
   * of `??_7IMauiDragger@Moho@@6B@`, so this class overrides neither: no
   * derived-class body is declared for them here.
   *
   * Slot +0x08 (`SelectionDragger::DragRelease`, 0x00863870, 485 instructions)
   * is a genuine override and is still blocked. Its no-modifier branch drives a
   * per-priority `WeakSet<UserEntity>` bucket vector through three helpers that
   * only exist as file-private statics of `moho/sim/CWldSession.cpp`
   * (`CopySelectionSetFromOther` 0x00822210, `FindSelectionNodeByEntityGuarded`
   * 0x00867780, `ReleaseSelectionWeakSetStorageRange` 0x00868CC0) plus the
   * bucket-vector grow helper at 0x00867890, which is not recovered anywhere.
   * Until those are reachable from this translation unit the slot stays pure,
   * inherited from `IMauiDragger`.
   */
  class SelectionDragger : public ISelectionDragger
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

    /**
     * Address: 0x00864080 (inlined destructor body, restores
     *          `??_7IMauiDragger@Moho@@6B@` then drains the intrusive list)
     */
    ~SelectionDragger() override;

    /**
     * Address: 0x00864000 (FUN_00864000, Moho::SelectionDragger::dtr)
     *
     * What it does:
     * Runs dragger cleanup and conditionally frees this object when bit 0 of
     * `deleteFlags` is set.
     */
    SelectionDragger* DeleteWithFlag(std::uint8_t deleteFlags) noexcept;

    /**
     * Vtable slot +0x14 of `??_7SelectionDragger@Moho@@6B@` (0x00A82547,
     * `_purecall`).
     */
    [[nodiscard]] virtual CGeomSolid3 BuildSelectionSolid() const = 0;

    /**
     * Vtable slot +0x18 of `??_7SelectionDragger@Moho@@6B@` (0x00A82547,
     * `_purecall`).
     */
    [[nodiscard]] virtual bool HasActiveSelectionDrag() const = 0;

  public:
    // +0x00 vptr and +0x04 `WeakObject::weakLinkHead_` belong to the
    // `ISelectionDragger`/`IMauiDragger` bases; this class starts at +0x08.
    CWldSession* mSess;       // +0x08
    CameraImpl* mCam;         // +0x0C
    float mX0;                // +0x10
    float mY0;                // +0x14
    Wm3::Vector3f mPos;       // +0x18
  };

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

  /**
   * Rubber-band (screen-rectangle) selection dragger.
   *
   * `??_7SelectionDragger2D@Moho@@6B@` lives at 0x00E47A44 and is written by
   * the constructor at 0x00864CB0 (`mov dword ptr [esi], offset
   * ??_7SelectionDragger2D@Moho@@6B@`, 0x00864CC2), so the vtable is
   * constructor-anchored. Slot map read from the shipped PE:
   *   +0x00  0x00865470  scalar deleting destructor  -> `DeleteWithFlag`
   *   +0x04  0x00864DB0  `DragMove`                  (override)
   *   +0x08  0x00863870  `SelectionDragger::DragRelease` (inherited)
   *   +0x0C  0x0078DB80  `IMauiDragger::OnCurrentDraggerReplaced` (inherited)
   *   +0x10  0x00865050  `Render`                    (override)
   *   +0x14  0x00864FC0  `BuildSelectionSolid`       (override)
   *   +0x18  0x00864DA0  `HasActiveSelectionDrag`    (override)
   */
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
     * Address: 0x00864DB0 (FUN_00864DB0, Moho::SelectionDragger2D::Func2)
     * Mangled: vtable slot +0x04 of ??_7SelectionDragger2D@Moho@@6B@
     *
     * IDA signature:
     * void __thiscall Moho::SelectionDragger2D::Func2(
     *     Moho::SelectionDragger2D *this, int a2);
     *
     * What it does:
     * Tracks one pointer-drag step: stores the current cursor position as the
     * drag-end corner, latches `mStretch` once the drag exceeds the click
     * threshold, then recomputes the highlighted-unit bracket set by collecting
     * everything under the current drag volume into `sSelectionBrackets`.
     */
    void DragMove(const SMauiEventData* eventData) override;

    /**
     * Address: 0x00865050 (FUN_00865050, Moho::SelectionDragger2D::Func4)
     * Mangled: vtable slot +0x10 of ??_7SelectionDragger2D@Moho@@6B@
     *
     * IDA signature:
     * void __thiscall Moho::SelectionDragger2D::Func4(
     *     Moho::SelectionDragger2D *this, Moho::CD3DPrimBatcher *a3);
     *
     * What it does:
     * Draws the rubber-band rectangle: one translucent black fill quad over the
     * canonicalized drag rectangle, then four 2-pixel white border bars around
     * it. Draws nothing until the drag has stretched past the click threshold.
     */
    void Render(CD3DPrimBatcher* batcher) override;

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
