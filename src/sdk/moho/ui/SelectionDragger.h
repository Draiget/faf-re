#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"

#include "gpg/core/utils/BoostWrappers.h"
#include "moho/math/Vector3f.h"
#include "moho/misc/WeakPtr.h"
#include "moho/ui/UiRuntimeTypes.h"

namespace moho
{
  class CameraImpl;
  class CD3DPrimBatcher;
  class CGeomSolid3;
  class CWldSession;
  class CWldTerrainDecal;
  class IDecalManager;
  class RD3DTextureResource;
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
   *   +0x04  0x00864340  `DragMove`                  (override)
   *   +0x08  0x00863870  `SelectionDragger::DragRelease` (inherited)
   *   +0x0C  0x0078DB80  `IMauiDragger::OnCurrentDraggerReplaced` (inherited)
   *   +0x10  0x00864C80  `Render`                    (override, empty body)
   *   +0x14  0x00864670  `BuildSelectionSolid`       (override)
   *   +0x18  0x00864320  `HasActiveSelectionDrag`    (override)
   *
   * The two `WeakPtr<CWldTerrainDecal>` lanes below were previously modelled
   * as four opaque dwords (`field_0x34`..`field_0x40`) because the earlier
   * pass could not tell a weak-reference pair from two independent scalars.
   * `SetTextures` (0x00864950) settles it: every read of `+0x34`/`+0x3C` in
   * both this class's bodies is the `p ? p - 4 : 0` null-checked downcast
   * MSVC emits for a base-subobject-to-derived conversion, and every write
   * goes through 0x008679E0 - a generic node relink that upcasts its
   * argument with `p ? p + 4 : 0`, unlinks the node from its previous
   * owner's chain, and pushes it onto the new owner's head slot. That is
   * exactly `moho::WeakPtr<T>::ResetFromOwnerLinkSlot`, and the +4 owner-link
   * offset is `CWldTerrainDecal::mLinkHead`.
   *
   * STILL NOT RECOVERED: the derived destructor body (0x008641C0), which
   * releases both decals through the cached manager and drains the two weak
   * lanes. The compiler-generated implicit destructor runs instead (it still
   * chains correctly into the base `~SelectionDragger()` and now also runs
   * the two `WeakPtr` and the `boost::shared_ptr` member destructors, which
   * the raw-dword model could not) - so the remaining gap is narrower than
   * before: the two decals are not handed back to the decal manager.
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
     * Address: 0x00864340 (FUN_00864340, Moho::SelectionDragger3D::Func2)
     * Mangled: vtable slot +0x04 of ??_7SelectionDragger3D@Moho@@6B@ (0x00E47A28)
     *
     * IDA signature:
     * void __thiscall Moho::SelectionDragger3D::Func2(
     *     Moho::SelectionDragger3D *this, Moho::SMauiEventData *a2);
     *
     * What it does:
     * Tracks one pointer-drag step of the volumetric selection dragger:
     * latches `mStretch` once the cursor passes the click threshold,
     * unprojects the cursor onto the terrain surface, and - on the first
     * valid sample - anchors `mPos` there; on every later sample it stores
     * the surface point as `mDragEndPos`, refreshes the two highlight decals
     * so they span the heading-aligned box between anchor and cursor, and
     * rebuilds the global `sSelectionBrackets` set from everything the drag
     * volume covers.
     *
     * Invocation: vtable slot +0x04 of `??_7SelectionDragger3D@Moho@@6B@`.
     * The dispatch site is 0x008638A3 (`call edx` with `edx = [[this]+4]`)
     * inside `SelectionDragger::DragRelease` (0x00863870), which forwards
     * the release event through the dragger's own `DragMove` before
     * resolving the selection.
     */
    void DragMove(const SMauiEventData* eventData) override;

    /**
     * Address: 0x00864950 (FUN_00864950, Moho::SelectionDragger3D::SetTextures)
     *
     * IDA signature:
     * void __stdcall Moho::SelectionDragger3D::SetTextures(
     *     Moho::SelectionDragger3D *a1);
     *
     * What it does:
     * Lazily creates this dragger's two terrain highlight decals - one
     * `WldTerrainDecalType_Albedo` for land and one
     * `WldTerrainDecalType_WaterAlbedo` for water, so the highlight paints on
     * both surfaces - binds the shared selection texture to each, disables
     * their flatness optimization and LOD/dissolve cutoffs, and raises both
     * to the front of the manager's draw order. Returns immediately once the
     * decals exist, so repeated `DragMove` calls create them only once.
     */
    void SetTextures();

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
     * `mPos` and `mDragEndPos`, aligned to the active camera's heading via
     * `COORDS_Orient`/`MultQuadVec`, and wraps it in a `CGeomSolid3`.
     *
     * Which endpoint is which is settled by `DragMove` (0x00864340): `mPos`
     * is the *anchor*, latched once at 0x008643F7 by the first drag sample
     * that lands on a valid surface while `mPos` is still the invalid
     * sentinel, and left alone afterwards; `mDragEndPos` is the endpoint
     * rewritten on every later sample (0x00864425). An earlier revision of
     * this comment had the two the other way round.
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
     * The land-surface highlight decal (`WldTerrainDecalType_Albedo`), held
     * weakly: the decal is owned by the decal manager, and this lane is only
     * an observer that the decal's own teardown can blank.
     *
     * `SetTextures` (0x00864950) binds it with 0x008679E0 - the generic weak
     * relink whose `owner + 4` upcast and `slot - 4` downcast identify it as
     * `moho::WeakPtr<T>` over an owner whose weak head sits at +0x04, i.e.
     * `CWldTerrainDecal::mLinkHead`.
     */
    WeakPtr<CWldTerrainDecal> mAlbedoDecal; // +0x34

    /**
     * The water-surface highlight decal (`WldTerrainDecalType_WaterAlbedo`),
     * bound the same way at 0x00864B28-0x00864B53. Both decals carry the same
     * texture and the same transform; only `mType` differs, so the highlight
     * paints over land and water alike.
     */
    WeakPtr<CWldTerrainDecal> mWaterAlbedoDecal; // +0x3C

    /**
     * Highlight texture shared-pointer lane, owned by this dragger.
     *
     * `SetTextures` assigns it from
     * `D3D_GetDevice()->GetResources()->GetTexture(...)` at
     * 0x008649B3-0x008649DC: the returned handle's `px`/`pi` pair is copied
     * into +0x44/+0x48, the new count is `lock xadd`-incremented and the old
     * one released through `sp_counted_base::release()` (0x004229B0) - a
     * plain `boost::shared_ptr` assignment, which is what fixes the element
     * type. The earlier `SharedPtrRaw<CD3DDynamicTextureSheet>` model
     * predates that evidence; `GetTexture`'s return type is
     * `boost::shared_ptr<RD3DTextureResource>` (`ID3DDeviceResources::
     * TextureResourceHandle`). Both models are 8 bytes, so the layout is
     * unchanged.
     */
    boost::shared_ptr<RD3DTextureResource> mHighlightTexture; // +0x44

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
  static_assert(offsetof(SelectionDragger3D, mAlbedoDecal) == 0x34,
                "SelectionDragger3D::mAlbedoDecal offset must be 0x34");
  static_assert(offsetof(SelectionDragger3D, mWaterAlbedoDecal) == 0x3C,
                "SelectionDragger3D::mWaterAlbedoDecal offset must be 0x3C");
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
