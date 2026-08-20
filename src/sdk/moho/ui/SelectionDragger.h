#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/utils/BoostWrappers.h"
#include "moho/math/Vector3f.h"
#include "moho/ui/UiRuntimeTypes.h"

namespace moho
{
  class CameraImpl;
  class CD3DDynamicTextureSheet;
  class CD3DPrimBatcher;
  class CGeomSolid3;
  class CWldSession;
  class IDecalManager;
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
   *   +0x08  0x00863870  `SelectionDragger::DragRelease` (override, recovered)
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
   * is a genuine override, recovered in SelectionDragger.cpp. Its no-modifier
   * branch drives a per-priority `SSelectionSetUserEntity` bucket vector; the
   * three CWldSession.cpp-local helpers this slot used to depend on
   * (`CopySelectionSetFromOther` 0x00822210, `FindSelectionNodeByEntityGuarded`
   * 0x00867780, `ReleaseSelectionWeakSetStorageRange` 0x00868CC0) are all
   * file-private (anonymous namespace) to that TU, so the recovered body does
   * not call them directly - it reaches the identical observable behavior
   * through the already-public `SSelectionSetUserEntity` API instead (`Find`,
   * `find`, `Add`, `Iterator_inc`, `IsEmptyAfterPrune`, `ReleaseStorage`) plus
   * this file's own `AddSelectionRange`/`DecodeSelectionEntity` helpers. The
   * bucket-vector growth path (0x00867890/0x00867B90/0x00868040, a hand-rolled
   * `vector<WeakEntitySetUserEntity>::resize`) is likewise not ported literally;
   * the recovered body grows an `msvc8::vector<SSelectionSetUserEntity>`
   * through the already-recovered generic `resize()` plus a per-slot
   * `InitializeLocalSelectionSet()` call, matching the binary's per-element
   * defensive-copy-of-an-empty-source semantics without needing the raw
   * 12-byte-stride internals.
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
     * Address: 0x00863870 (FUN_00863870)
     *
     * IDA signature:
     * void __thiscall Moho::SelectionDragger::DragRelease(
     *     Moho::SelectionDragger *this, Moho::SMauiEventData *a2);
     *
     * What it does:
     * Forwards the release event through this dragger's own `DragMove`, then
     * either releases the click-selection path (dragger inactive) or resolves
     * a new session selection from the entities the drag volume covers: with
     * Shift held, merges/toggles the dragged set against the current
     * selection; otherwise groups intersected entities into per-priority
     * buckets (mesh-bounds test against the drag solid, blueprint selection
     * scale/`LOWSELECTPRIO` override) and selects the first non-empty bucket.
     *
     * Invocation: vtable slot +0x08 of `??_7SelectionDragger@Moho@@6B@`,
     * `??_7SelectionDragger2D@Moho@@6B@` and `??_7SelectionDragger3D@Moho@@6B@`
     * (all three data-xref the same body; neither derived class overrides this
     * slot).
     */
    void DragRelease(const SMauiEventData* eventData) override;

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
   * Volumetric (world-space) selection dragger, used whenever
   * `Moho::ui_DragSelect2D` is false. Where `SelectionDragger2D` drags a
   * screen-space rectangle, this class drags a capsule/box between two
   * world-space points and highlights it with terrain decals instead of a
   * screen-space rubber band.
   *
   * `??_7SelectionDragger3D@Moho@@6B@` lives at 0x00E47A24 and is written by
   * both the constructor at 0x008640F0 (`mov dword ptr [esi], offset
   * ??_7SelectionDragger3D@Moho@@6B@`, 0x00864124) and the derived
   * destructor at 0x008641C0, so the vtable is constructor-anchored. Slot
   * map read from the shipped PE:
   *   +0x00  0x00864C90  scalar deleting destructor  -> `DeleteWithFlag`
   *   +0x04  0x00864340  `DragMove`                  (override, NOT YET
   *          recovered here - see the doc note below)
   *   +0x08  0x00863870  `SelectionDragger::DragRelease` (inherited)
   *   +0x0C  0x0078DB80  `IMauiDragger::OnCurrentDraggerReplaced` (inherited)
   *   +0x10  0x00864C80  `Render`                    (override, empty body)
   *   +0x14  0x00864670  `BuildSelectionSolid`       (override)
   *   +0x18  0x00864320  `HasActiveSelectionDrag`    (override)
   *
   * NOT YET RECOVERED: `DragMove` (0x00864340) and the derived destructor
   * body (0x008641C0). Both center on `field_0x34`/`field_0x38` and
   * `field_0x3C`/`field_0x40` below, which the disassembly proves are used
   * two different ways: `DragMove` (0x00864340) writes fresh decal-transform
   * data through them, and the destructor both (a) passes
   * `field_0x34 - 4`/`field_0x3C - 4` to a virtual "destroy" call reached
   * through the cached decal manager, *and* (b) separately walks and unlinks
   * `field_0x34`/`field_0x3C` themselves as intrusive-list node addresses
   * through the exact generic drain helper `SelectionDragger`'s own base
   * destructor uses for its `IMauiDragger` weak head (0x008642A5-0x8642DE
   * mirrors 0x00864090's shape exactly). That dual use is consistent with
   * each pair being a `WeakPtr`-shaped weak reference into a
   * `CWldTerrainDecal`'s own intrusive weak-observer chain (matching this
   * codebase's `WeakObject`/`WeakPtr_*` family), not a pair of independent
   * scalars - but pinning down the exact owning type needs the same
   * `IDecalManager`/decal-lifetime evidence pass `DragMove` needs, so it is
   * deferred together with `DragMove` rather than guessed here.
   *
   * `DragMove` additionally touches an unrecovered
   * `Moho::SelectionDragger3D::SetTextures` and collects entities into the
   * shared `sSelectionBrackets` weak-set through a *second*,
   * still-unrecovered container type the decompiler names
   * `Moho::WeakSet_UserEntity` (distinct from this file's
   * `SSelectionSetUserEntity`) plus three more unrecovered helpers
   * (`FUN_007B08D0`, `FUN_007AF740`, `FUN_007FDAB0`).
   *
   * Until that cluster is resolved, this class declares no destructor of its
   * own (the compiler-generated implicit one runs, which still correctly
   * chains into the base `~SelectionDragger()`) and inherits
   * `IMauiDragger::DragMove`'s empty body. Both are known, documented
   * fidelity gaps - the dragger will not paint/update its 3D highlight
   * decals, and destroying one will not release its two highlight-decal weak
   * references or its highlight-texture shared-pointer lane - not oversights.
   */
  class SelectionDragger3D : public SelectionDragger
  {
  public:
    /**
     * Address: 0x008640F0 (FUN_008640F0, ??0SelectionDragger3D@Moho@@...)
     *
     * What it does:
     * Chains the `SelectionDragger` base constructor, installs this class's
     * own vtable, clears the stretch/active latch and the pending drag-end
     * world position (seeded to the shared invalid-vector sentinel), zeroes
     * the two highlight-decal handle slots and the owned highlight-texture
     * shared-pointer lane, and caches this view's decal manager
     * (`session->mWldMap->mTerrainRes->GetDecalManager()`) for later use by
     * `DragMove`/`~SelectionDragger3D`.
     */
    SelectionDragger3D(CameraImpl* camera, CWldSession* session);

    /**
     * Address: 0x00864C90 (FUN_00864C90, Moho::SelectionDragger3D::Func1)
     *
     * What it does:
     * Scalar-deleting-destructor variant for `SelectionDragger3D` —
     * delegates to the implicit base/derived destructor chain and
     * conditionally releases the object's heap storage when bit 0 of
     * `deleteFlags` is set. Matches `SelectionDragger2D::DeleteWithFlag`'s
     * role for the binary's `??_G` vtable slot.
     *
     * NOTE: the binary's own scalar-deleting destructor (0x00864C90) chains
     * into the full derived destructor body at 0x008641C0, which this
     * recovery does not yet provide (see the class doc comment) - the
     * chained `~SelectionDragger3D()` this calls is therefore the
     * compiler-generated implicit one, not a 1:1 port of 0x008641C0.
     */
    SelectionDragger3D* DeleteWithFlag(std::uint8_t deleteFlags) noexcept;

    /**
     * Address: 0x00864C80 (FUN_00864C80, Moho::SelectionDragger3D::Func4)
     * Mangled: vtable slot +0x10 of ??_7SelectionDragger3D@Moho@@6B@
     *
     * What it does:
     * Empty override (`retn 4` in the binary) - the 3D dragger draws its
     * highlight through terrain decals updated by `DragMove`, not through
     * the shared prim batcher.
     */
    void Render(CD3DPrimBatcher* batcher) override;

    /**
     * Address: 0x00864670 (FUN_00864670, Moho::SelectionDragger3D::Func5)
     *
     * What it does:
     * Builds one oriented world-space capsule/box between the inherited
     * `mPos` (current cursor world position, continuously updated while the
     * drag is live) and `mDragEndPos` (the drag's other endpoint), aligned to
     * the active camera's heading via `COORDS_Orient`/`MultQuadVec`, and
     * wraps it in a `CGeomSolid3`.
     */
    [[nodiscard]] CGeomSolid3 BuildSelectionSolid() const override;

    /**
     * Address: 0x00864320 (FUN_00864320, Moho::SelectionDragger3D::Func6)
     *
     * What it does:
     * Returns whether the drag latched active (`mStretch`) and the current
     * cursor world position is valid.
     */
    [[nodiscard]] bool HasActiveSelectionDrag() const override;

  public:
    std::uint8_t mStretch;     // +0x24
    std::uint8_t pad_0025[3];
    Wm3::Vector3f mDragEndPos; // +0x28

    /**
     * Two highlight-decal weak-reference slots (`field_0x34`/`field_0x38` and
     * `field_0x3C`/`field_0x40`), each zero-initialized here and otherwise
     * only written by the not-yet-recovered `DragMove` (0x00864340) and read
     * by the not-yet-recovered derived destructor (0x008641C0) - see the
     * class doc comment for what the disassembly shows about their shape and
     * why they are not yet typed more precisely than raw dwords.
     */
    std::uint32_t field_0x34; // +0x34
    std::uint32_t field_0x38; // +0x38
    std::uint32_t field_0x3C; // +0x3C
    std::uint32_t field_0x40; // +0x40

    /**
     * Highlight texture shared-pointer lane. Zero-initialized here; released
     * through `boost::SharedPtrRaw<T>::release()` in the binary's derived
     * destructor (0x008641C0, matching its inlined `sp_counted_base::
     * release()`/`weak_release()` chain at 0x0086427B-0x008642A5; see
     * `Moho::WeakPtr_CD3DDynamicTextureSheet::Release`, 0x00422B80, cited
     * from `FUN_008640F0`'s callee list) - not yet recovered here, see the
     * class doc comment.
     */
    boost::SharedPtrRaw<CD3DDynamicTextureSheet> mHighlightTexture; // +0x44

    /**
     * Cached decal manager for this dragger's owning terrain resource
     * (`session->mWldMap->mTerrainRes->GetDecalManager()`), populated once by
     * the constructor and used by (once recovered) `DragMove` and the
     * derived destructor to create/update/destroy the highlight decals
     * above.
     */
    IDecalManager* mDecalManager; // +0x4C
  };

  static_assert(offsetof(SelectionDragger3D, mStretch) == 0x24,
                "SelectionDragger3D::mStretch offset must be 0x24");
  static_assert(offsetof(SelectionDragger3D, mDragEndPos) == 0x28,
                "SelectionDragger3D::mDragEndPos offset must be 0x28");
  static_assert(offsetof(SelectionDragger3D, field_0x34) == 0x34,
                "SelectionDragger3D::field_0x34 offset must be 0x34");
  static_assert(offsetof(SelectionDragger3D, field_0x38) == 0x38,
                "SelectionDragger3D::field_0x38 offset must be 0x38");
  static_assert(offsetof(SelectionDragger3D, field_0x3C) == 0x3C,
                "SelectionDragger3D::field_0x3C offset must be 0x3C");
  static_assert(offsetof(SelectionDragger3D, field_0x40) == 0x40,
                "SelectionDragger3D::field_0x40 offset must be 0x40");
  static_assert(offsetof(SelectionDragger3D, mHighlightTexture) == 0x44,
                "SelectionDragger3D::mHighlightTexture offset must be 0x44");
  static_assert(offsetof(SelectionDragger3D, mDecalManager) == 0x4C,
                "SelectionDragger3D::mDecalManager offset must be 0x4C");
  static_assert(sizeof(SelectionDragger3D) == 0x50,
                "SelectionDragger3D size must be 0x50");

  /**
   * Address: 0x00863F10 (FUN_00863F10)
   *
   * What it does:
   * Builds the selectable user-entity weak-set currently covered by one active
   * selection dragger.
   */
  void CollectSelectionDraggerEntities(SSelectionSetUserEntity& outSelection, SelectionDragger& dragger);
} // namespace moho
