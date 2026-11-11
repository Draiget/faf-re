#include "moho/sim/CWldSessionPrivate.h"
#include "moho/sim/PlannedFactoryProxy.h"

/**
 * Session-global ghost list for the formation-placement preview.
 *
 * This is one plain `fa::vector` parked at 0x010C4258, not the three loose
 * pointer globals an earlier pass modelled:
 *   myProxy_ +0x00 -> 0x010C4258   first_ +0x04 -> 0x010C425C
 *   last_    +0x08 -> 0x010C4260   end_   +0x0C -> 0x010C4264
 *
 * That the container head is 0x010C4258 is settled by FUN_0085A280 and
 * FUN_0085A630: both are a bare `mov eax, offset 0x010C4258; retn`, i.e.
 * they hand back the container itself. FUN_00859F70 pins the 0x10-byte
 * element width - it derives both size and capacity by `sar ..., 4` over the
 * same three lanes.
 *
 * `CWldSession::RenderMeshPreviews` (0x008599D0) is the only writer: it
 * clears the vector at the top of every frame and repopulates it.
 */
fa::vector<SFormationPreviewGhost> gFormationPreviews;

// `StrategicIconAux` (the real type) and `gStrategicIconAuxiliary`
// live in the `moho`-scoped anonymous namespace alongside the type's
// definition (see `CWldSession::RenderStrategicIcons`'s callee cluster) -
// a plain forward declaration here would name an unrelated, permanently
// incomplete type in *this* (global-scope) anonymous namespace instead.

// The formation-preview container emissions used to live here as one
// hand-written free function per operation. They are `fa::vector`
// members, so the addresses now sit on the template in
// `legacy/containers/Vector.h` and the call sites just use the container:
//
//   FUN_00859E90  ~SFormationPreviewGhost (implicit, member order)
//   FUN_0085A1D0  destroy_range
//   FUN_0085A9F0  copy_or_move_assign, one slot
//   FUN_0085A130  erase, first..last
//   FUN_00859FE0  pop_back
//   FUN_00859F70  push_back
//   FUN_0085A920  uninit_fill_n / in-place construct, push_back fast path
//   FUN_0085A0E0  reallocate_to + insert, push_back grow path
//
namespace moho
{

  // Projectile strategic-icon CVars. None of these existed in the tree; the
  // addresses come from the store/compare operands in FUN_008621B0.
  float UI_StrategicProjectileLOD = 128.0f; // 0x00F57B20
  bool UI_RenProjectileIcons = true;        // 0x00F57A8F
  bool UI_RenProjectileGlow = true;         // 0x00F57B24
  bool UI_forceWeaponsToYellow = true;      // 0x00F57B25
  float UI_RenProjectileGlowMin = 0.01f;    // 0x00F57B28
  float UI_RenProjectileGlowMax = 0.15f;    // 0x00F57B2C
  float UI_RenProjectileGlowPeriod = 2.0f;  // 0x00F57B30
  float UI_CurGlowTime = 0.0f;              // 0x010A6460

  // Read once per deposit by `CWldSession::RenderResources` (0x00862E68). The
  // 75 is the shipped value: `bin/2025.7.1/ForgedAlliance.exe` holds
  // 0x42960000 at 0x00F57B08, and `func_UI_ResourceLODCutoff_ConVarDef`
  // (0x00BE6010) only binds the console variable to this same storage.
  float UI_ResourceLODCutoff = 75.0f; // 0x00F57B08

  // Strategic-icon and unit-bar console variables. None of these existed in
  // the tree; every address below is the absolute operand of the instruction
  // that reads it, taken from the `.asm` of the five functions that make up
  // the strategic-icon pass (0x0085B6E0, 0x0085CD40, 0x0085D9A0, 0x0085E0A0,
  // 0x0085E3A0). An earlier note here said they all ship zeroed and left the
  // console/UI layer to write them. They do not: every address in this block
  // lands inside `.data`'s raw bytes in bin/2025.7.1/ForgedAlliance.exe and
  // carries a real static initialiser, transcribed below. Shipping them zeroed
  // turned the whole pass off - `ui_RenderIcons` false is the gate at
  // 0x0085C0B1 that drops every collected strategic icon, and a 0.0f
  // `ui_LifebarLOD` can never exceed the current zoom (0x0085BFE8), so no unit
  // bar was ever collected either.
  bool ui_RenderUnitBars = true;                         // 0x00F57B26 (0x0085BFDB)
  bool ui_RenderIcons = true;                            // 0x00F57B27 (0x0085C0B1)
  float ui_lifebarHeight = 0.125f;                       // 0x00F57B6C (0x0085CDCB)
  float ui_LifebarWidth = 1.5f;                          // 0x00F57B70 (0x0085CDB6)
  float ui_LifebarLOD = 200.0f;                          // 0x00F57B74 (0x0085BFE8)
  float ui_LifebarOffset = 0.1f;                         // 0x00F57B78 (0x0085CECE)
  bool ui_NisRenderIcons = true;                         // 0x00F57B7C (0x0085C0A4)
  bool ui_RenderCustomNames = true;                      // 0x00F57B7D (0x0085E0BE)
  bool ui_RenderSelectionSetNames = true;                // 0x00F57B7E (0x0085E3BE)
  std::uint32_t ui_CustomNameColor = 0xFF00AA00u;        // 0x00F57B80 (0x0085E2ED)
  std::int32_t ui_CustomNameFontSize = 12;               // 0x00F57B84 (0x0085E145)
  std::uint32_t ui_SelectionSetNamesColor = 0xFF00AA00u; // 0x00F57B88 (0x0085E72A)
  float ui_StrategicIconBlinkRate = 0.6f;                // 0x00F57B8C (0x0085DC44)
  float ui_FuelEmptyBlinkRate = 0.1f;                    // 0x00F57B90 (0x0085D113)
  float ui_StrategicIconBlinkDuration = 0.5f;            // 0x00F57B94 (0x0085DC22)
  std::uint32_t ui_LifeBarGoodColor = 0xFF00FF00u;       // 0x00F57B98 (0x0085D070)
  std::uint32_t ui_LifeBarMedColor = 0xFFFFFF00u;        // 0x00F57B9C (0x0085D085)
  std::uint32_t ui_LifeBarBadColor = 0xFFFF0000u;        // 0x00F57BA0 (0x0085D065)
  float ui_LifeBarGoodCutoff = 0.75f;                    // 0x00F57BA4 (0x0085D05E)
  float ui_LifeBarBadCutoff = 0.25f;                     // 0x00F57BA8 (0x0085D07C)
  std::uint32_t ui_FuelBarColor = 0xFFF4EC4Du;           // 0x00F57BAC (0x0085D0EE)
  std::uint32_t ui_FuelWarningColor = 0xFFFF0000u;       // 0x00F57BB0 (0x0085D135)
  std::uint32_t ui_ShieldBarColor = 0xFF00C3F7u;         // 0x00F57BB4 (0x0085D0DA)
  std::uint32_t ui_ProgressBarColor = 0xFFFF9900u;       // 0x00F57BB8 (0x0085D14B)
  fa::string ui_CustomNameFont("Arial");                 // 0x00F5B300 (0x0085E124), built "Arial" by FUN_00BE5720
  bool ui_ForceLifbarsOnEnemy = false;                   // 0x010A644A (0x0085C031)
  bool ui_AlwaysRenderStrategicIcons = false;            // 0x010A644B (0x0085C148)

  // FAF FA-Binary-Patches #147 (Scale projectile/deposit/strategic icons): screen-size multipliers
  // of the strategic-view icons. `ui_StrategicIconScale` is FAF's older strategic-icon scale (in the
  // FAF retail exe at 0x01292AC0) that #147 rewrote; the deposit and projectile scales are new in #147.
  float ui_StrategicIconScale = 1.0f;
  float ui_DepositIconScale = 1.0f;
  float ui_ProjectileIconScale = 1.0f;

  TConVar<float> gTConVar_ui_StrategicIconScale(
    "ui_StrategicIconScale",
    "Size multiplier of unit strategic icons and their paused, stunned and underlay overlays (1 = the texture's own "
    "size).",
    &ui_StrategicIconScale
  );
  TConVar<float> gTConVar_ui_DepositIconScale(
    "ui_DepositIconScale",
    "Size multiplier of the mass and hydrocarbon deposit icons of the strategic view (1 = the original size).",
    &ui_DepositIconScale
  );
  TConVar<float> gTConVar_ui_ProjectileIconScale(
    "ui_ProjectileIconScale",
    "Size multiplier of projectile icons, textured or the plain squares (1 = the original size).",
    &ui_ProjectileIconScale
  );

  // Per-army team-color palette, distinct from `StrategicIconAux`'s own
  // Self/Ally/Enemy/Neutral relation colors: `RenderUnitIcon` (0x0085D9A0)
  // indexes this one directly by the icon's owning army's `mArmyIndex`
  // (`mov eax, offset teamcolors` / `mov ecx, [eax+ecx*4]`, FA-Binary-Patches
  // TeamColorModeRenderer). 32 entries, as the patch's `int Colors[32]`
  // (0x012931E0); `TeamColorMode(string)` fills it (cfunc_TeamColorModeL).
  std::uint32_t teamcolors[kTeamColorPaletteSize]{};

  // Entity ids carry their family in the top nibble; 0x1_______ is a projectile.
  constexpr std::uint32_t kEntityFamilyMask = 0xF0000000u;
  constexpr std::uint32_t kEntityFamilyProjectile = 0x10000000u;
  constexpr std::uint32_t kProjectileIconColor = 0xFFFFFFFFu;
  constexpr std::uint32_t kProjectileForcedColor = 0xFFFFFF00u;
  constexpr const char* kProjectileIconTechnique = "TAlphaBlendLinearSampleNoDepth";
  // 0x008624F2 masks the layer with 6 - seabed | sub - to pick the recon grid.
  constexpr std::int32_t kLayerUnderwaterMask = LAYER_Seabed | LAYER_Sub;
  namespace
  {

    // Forward-declared here (rather than defined) because the process-global
    // singleton lane below only ever holds a pointer; `StrategicIconAux`
    // itself is defined later in this same `moho`-scoped anonymous
    // namespace, next to `CWldSession::RenderStrategicIcons`'s callee
    // cluster (0x0085B6E0's lazy-init target, address 0x010C4300).
    struct StrategicIconAux;
    StrategicIconAux* gStrategicIconAuxiliary = nullptr;

    /**
     * Address: 0x0085EFE0 (FUN_0085EFE0)
     *
     * What it does:
     * Returns the global strategic-icon auxiliary object lane.
     */
    [[maybe_unused]] [[nodiscard]] StrategicIconAux* GetStrategicIconAuxiliaryLaneA() noexcept
    {
      return gStrategicIconAuxiliary;
    }

    /**
     * Address: 0x0085EFF0 (FUN_0085EFF0)
     *
     * What it does:
     * Secondary entrypoint returning the strategic-icon auxiliary object lane.
     */
    [[maybe_unused]] [[nodiscard]] StrategicIconAux* GetStrategicIconAuxiliaryLaneB() noexcept
    {
      return gStrategicIconAuxiliary;
    }

    /**
     * Address: 0x0085F000 (FUN_0085F000)
     *
     * What it does:
     * Third entrypoint returning the strategic-icon auxiliary object lane.
     */
    [[maybe_unused]] [[nodiscard]] StrategicIconAux* GetStrategicIconAuxiliaryLaneC() noexcept
    {
      return gStrategicIconAuxiliary;
    }

    /**
     * One classified entity in the strategic-icon pass - `struct_UnitIconData`
     * in the IDB. `CWldSession::RenderStrategicIcons` fills one of these per
     * visible entity, files it into one of the five runs on
     * `StrategicIconAux` below, and the emitters read it back.
     *
     * Layout evidence, all from the binary:
     *  - the copy-assignment at 0x0085CB00 walks every lane in order: two
     *    dwords at `+0`/`+4`, three floats at `+8`/`+12`/`+16`, three
     *    shared-pointer pairs at `+20`/`+24`, `+28`/`+32` and `+36`/`+40`
     *    (each re-seated through the `use_count_`/`weak_release` pair, so each
     *    is a `boost::shared_ptr`), then five single bytes at `+44`..`+48`;
     *  - the destructor at 0x0085CA20 releases exactly the control blocks held
     *    at `+0x18` (`mov esi, [edi+18h]`), `+0x20` and `+0x28`, which pins the
     *    three shared pointers to `+0x14`, `+0x1C` and `+0x24`;
     *  - the element stride is 0x34 in both the vector grow lane
     *    (`add esi, 34h` @ 0x0085EF3A) and the lifebar loop
     *    (`add edi, 34h` @ 0x0085C9C5), and every size computation in the
     *    family divides the byte span by 52.
     *
     * Flag roles come from `RenderUnitIcon` (0x0085D9A0), which is the only
     * reader: `+0x2C` gates the newly-created blink (0x0085DBF6), `+0x2D` the
     * pause overlay quad (0x0085DCD5), `+0x2E` the stunned overlay quad
     * (0x0085DD3C), `+0x2F` suppresses the base icon quad (0x0085DC90) and
     * `+0x30` marks the formation-preview ghost, whose colour is alpha-halved
     * instead of team-coloured (0x0085DBE1).
     *
     * The binary's per-type container and special-member emissions for this
     * struct are all covered by code that already exists, so none of them get
     * a hand-written copy here:
     *  - 0x0085CA20 is the compiler-generated `~UnitIconData` (three
     *    `shared_ptr` releases in reverse declaration order);
     *  - 0x0085CB00 is the compiler-generated `operator=`;
     *  - 0x0085ED70 / 0x0085EED0 / 0x0085F1B0 / 0x0085F290 are
     *    `fa::vector<UnitIconData>`'s `reserve` / `push_back` /
     *    `erase(first,last)` / destructor, and 0x0085F140, 0x0085F930,
     *    0x0085FDB0, 0x0085FFB0 and 0x0085F310 are that same instantiation's
     *    grow, allocate, copy-construct, uninitialised-copy and length-error
     *    lanes. They belong on `fa::vector<T>` in
     *    src/legacy/containers/Vector.h next to the other per-type
     *    emissions listed there, not as a second set of container primitives.
     * Address: 0x0085F740 (FUN_0085F740 -- the implicit copy constructor `UnitIconData(const UnitIconData&)`, emitted
     * out of line for `fa::vector<UnitIconData>`'s placement copies: member-wise in declaration order (the two
     * pointers, the three floats through `fld`/`fstp`, each `shared_ptr` with a `lock xadd` +1 on the non-null control
     * block's `use_count_` at +0x18/+0x20/+0x28, then the five flag bytes up to +0x30), no release, so a construction
     * rather than `operator=` 0x0085CB00; callers 0x0085F414 (`_Insert_n` 0x0085F3F0's `_Tmp = _Val`), 0x0085FDC8
     * (`_Uninit_fill_n` 0x0085FDB0), 0x0085FFC9 (`_Uninit_copy` 0x0085FFB0), 0x0085FFF8 (0x0085FFE0), and the
     * null-guarded tail jumps 0x0085FE64 / 0x0085FF24 (`_Construct` / `allocator::construct`, nothing references them);
     * formerly `CopyRefCountedPayload49Runtime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-30.)
     */
    struct UnitIconData
    {
      UserEntity* mUnit = nullptr;                         // +0x00
      const REntityBlueprint* mBlueprint = nullptr;        // +0x04
      float mWorldX = 0.0f;                                // +0x08
      float mWorldY = 0.0f;                                // +0x0C
      float mWorldZ = 0.0f;                                // +0x10
      boost::shared_ptr<CD3DBatchTexture> mIconTexture;    // +0x14
      boost::shared_ptr<CD3DBatchTexture> mPausedTexture;  // +0x1C
      boost::shared_ptr<CD3DBatchTexture> mStunnedTexture; // +0x24
      /// Own or allied unit: the only ones whose icon blinks while fresh.
      bool mIsFriendly = false; // +0x2C
      /// Draw the pause/toggle-off overlay over the icon.
      bool mShowPausedOverlay = false; // +0x2D
      /// Draw the stunned overlay over the icon.
      bool mShowStunnedOverlay = false; // +0x2E
      /// The unit's mesh is already on screen, so only the overlays are drawn.
      bool mSuppressBaseIcon = false; // +0x2F
      /// Formation-preview ghost rather than a live unit.
      bool mIsFormationGhost = false; // +0x30
      // +0x31..+0x33 is alignment padding, not a member: neither the copy
      // constructor (0x0085F740) nor `operator=` (0x0085CB00) copies it.
    };

    static_assert(sizeof(UnitIconData) == 0x34, "UnitIconData size must be 0x34");
    static_assert(offsetof(UnitIconData, mBlueprint) == 0x04, "UnitIconData::mBlueprint offset must be 0x04");
    static_assert(offsetof(UnitIconData, mWorldX) == 0x08, "UnitIconData::mWorldX offset must be 0x08");
    static_assert(offsetof(UnitIconData, mWorldZ) == 0x10, "UnitIconData::mWorldZ offset must be 0x10");
    static_assert(offsetof(UnitIconData, mIconTexture) == 0x14, "UnitIconData::mIconTexture offset must be 0x14");
    static_assert(offsetof(UnitIconData, mPausedTexture) == 0x1C, "UnitIconData::mPausedTexture offset must be 0x1C");
    static_assert(offsetof(UnitIconData, mStunnedTexture) == 0x24, "UnitIconData::mStunnedTexture offset must be 0x24");
    static_assert(offsetof(UnitIconData, mIsFriendly) == 0x2C, "UnitIconData::mIsFriendly offset must be 0x2C");
    static_assert(
      offsetof(UnitIconData, mIsFormationGhost) == 0x30,
      "UnitIconData::mIsFormationGhost offset must be 0x30"
    );

    /**
     * The strategic-icon pass's per-frame scratch object - `struct_IconAux` in
     * the IDB. `CWldSession::RenderStrategicIcons` lazily allocates exactly one
     * of these into a process-global lane (0x010C4300) on its first frame and
     * reuses it forever after, clearing the five icon runs at the top of each
     * frame rather than reallocating them.
     *
     * Size evidence: the single allocation site pushes 0xACh
     * (`push 0ACh` @ 0x0085B72D) into `operator new` before running the
     * constructor at 0x0085B2A0.
     *
     * Field evidence (constructor 0x0085B2A0 unless noted):
     *  - `+0x00..0x0F` is the camera's viewport rect, copied a float at a time
     *    from `GeomCamera3::viewport.r[3]` (`fld [eax+2B4h]` ->
     *    `fstp [ebp+0]` .. `fld [eax+2C0h]` -> `fstp [ebp+0Ch]`,
     *    0x0085B864..0x0085B88B). It is the one region the constructor leaves
     *    alone, because the render entry rewrites it every frame.
     *  - `+0x10` session (`mov [ebp+10h], edi` @ 0x0085B861), `+0x14` batcher
     *    (`mov [ebp+14h], ebx` @ 0x0085B7C6), `+0x18` camera view
     *    (`mov [ebp+18h], eax` @ 0x0085B7C0).
     *  - `+0x1C` is a float, not the `CWldMap*` the mangled name types into
     *    that argument slot: the render entry stores the incoming slot with
     *    `movss dword ptr [ebp+1Ch], xmm0` (0x0085B85C) after loading it with
     *    `movss xmm0, [esp+argC]`, and the constructor zeroes it with
     *    `movss dword ptr [esi+1Ch], xmm0` (0x0085B2D0) rather than a `mov`.
     *    The lifebar emitter reads it back as the sub-tick interpolant that
     *    drives the fuel-empty blink (`*(float *)(aux+28)` at 0x0085D103).
     *  - `+0x20` the 0xFFFFFFFF solid-colour texture the bar quads are drawn
     *    with (`CD3DBatchTexture::FromSolidColor` @ 0x0085B349, stored at
     *    0x0085B35B/0x0085B38A).
     *  - `+0x28` the generic-icon table: `GetGenericIcons` is handed `aux+0x28`
     *    (`add eax, 28h` @ 0x0085B788) and indexes it as 8-byte elements
     *    (`&_Myfirst[2 * iconType]`), and 0x0085F020 sizes it to exactly 8.
     *  - `+0x38`/`+0x40` the pause and stunned rest textures.
     *  - `+0x48`, `+0x58`, `+0x68`, `+0x78`, `+0x88` the five icon runs, each
     *    a 0x10-byte `fa::vector` header the frame entry clears in turn
     *    (`lea eax, [ebp+48h]` .. `lea eax, [ebp+88h]`,
     *    0x0085B7C3..0x0085B82D) and the constructor reserves at
     *    0x200/0x200/0x40/0x80/0x80 elements.
     *  - `+0x98`, `+0x9C`, `+0xA0`, `+0xA4` the four `GameColors.TeamColorMode`
     *    entries, decoded in source order Self/Ally/Enemy/Neutral but stored
     *    Self/Neutral/Ally/Enemy (`mov [esi+98h], eax` 0x0085B4B1,
     *    `[esi+0A0h]` 0x0085B54C, `[esi+0A4h]` 0x0085B5DF, `[esi+9Ch]`
     *    0x0085B672), and `+0xA8` the unidentified-blip colour
     *    (`mov [esi+0A8h], eax` @ 0x0085B6AD).
     *
     * The five runs are drawn in declaration order, which is why the split
     * matters: ground icons, then air icons on top of them (the classifier
     * picks the second run when `RUnitBlueprint::Air.CanFly`, blueprint+0x368,
     * is set - 0x0085C2E8), then the high-sort-priority icons whose blueprint
     * carries its own texture, then the selected units, and finally the
     * lifebars under their own `TLifeBar` technique.
     */
    struct StrategicIconAux
    {
      float mViewportX = 0.0f;              // +0x00
      float mViewportY = 0.0f;              // +0x04
      float mViewportWidth = 0.0f;          // +0x08
      float mViewportHeight = 0.0f;         // +0x0C
      CWldSession* mSession = nullptr;      // +0x10
      CD3DPrimBatcher* mBatcher = nullptr;  // +0x14
      const GeomCamera3* mCamera = nullptr; // +0x18
      /// Sub-tick interpolant for this frame; see the `+0x1C` note above.
      float mTickFraction = 0.0f;                                    // +0x1C
      boost::shared_ptr<CD3DBatchTexture> mWhiteTexture;             // +0x20
      fa::vector<boost::shared_ptr<CD3DBatchTexture>> mGenericIcons; // +0x28
      boost::shared_ptr<CD3DBatchTexture> mPauseRestTexture;         // +0x38
      boost::shared_ptr<CD3DBatchTexture> mStunnedRestTexture;       // +0x40
      fa::vector<UnitIconData> mGroundIcons;                         // +0x48
      fa::vector<UnitIconData> mAirIcons;                            // +0x58
      fa::vector<UnitIconData> mHighPriorityIcons;                   // +0x68
      fa::vector<UnitIconData> mSelectedIcons;                       // +0x78
      fa::vector<UnitIconData> mLifebarIcons;                        // +0x88
      std::uint32_t mSelfColor = 0u;                                 // +0x98
      std::uint32_t mNeutralColor = 0u;                              // +0x9C
      std::uint32_t mAllyColor = 0u;                                 // +0xA0
      std::uint32_t mEnemyColor = 0u;                                // +0xA4
      std::uint32_t mUnidentifiedColor = 0u;                         // +0xA8

      /**
       * Address: 0x0085B2A0 (FUN_0085B2A0, struct_TeamColors::struct_TeamColors)
       * Mangled: struct_IconAux *__stdcall struct_TeamColors::struct_TeamColors(struct_IconAux *this)
       *
       * What it does:
       * Builds the white solid-colour texture, reserves the five icon runs to
       * their binary-observed capacities (0x200/0x200/0x40/0x80/0x80 for
       * ground/air/high-priority/selected/lifebar), and decodes the four
       * `GameColors.TeamColorMode` entries plus the unidentified-blip colour.
       * `mGenericIcons`/`mPauseRestTexture`/`mStunnedRestTexture` are left
       * empty here - the binary fills them from separate calls
       * (`LoadGenericIcons`/`LoadPauseAndStunnedRestTextures`) right after
       * construction, not from this constructor.
       */
      StrategicIconAux();

      /**
       * Address: 0x0085E7F0 (FUN_0085E7F0, struct_IconAux::GetGenericIcons)
       * Mangled: LuaPlus::LuaObject *__cdecl struct_IconAux::GetGenericIcons(Moho::CWldSession *session, std::vector
       * *target)
       *
       * What it does:
       * Loads `/lua/ui/game/strategicIcons.lua`'s `GenericIcons` table and
       * fills one `mGenericIcons` slot per `EGenericIconType` key with the
       * named batch texture. `mGenericIcons` is sized to exactly 8 first
       * (0x0085F020, the `fa::vector<boost::shared_ptr<CD3DBatchTexture>>`
       * resize lane for this instantiation - a per-type container emission
       * already covered generically by `fa::vector<T>::resize`, the same
       * way the sibling `UnitIconData` instantiation's reserve/push_back/erase
       * lanes are documented above rather than hand-recovered).
       */
      void LoadGenericIcons(CWldSession* session);

      /**
       * Address: 0x0085EA60 (FUN_0085EA60, struct_IconAux::GetStunIcons)
       *
       * What it does:
       * Imports strategic icon Lua tables and refreshes pause/stunned overlay
       * rest textures for one icon-aux runtime object.
       */
      void LoadPauseAndStunnedRestTextures(CWldSession* session);
    };

    static_assert(sizeof(StrategicIconAux) == 0xAC, "StrategicIconAux size must be 0xAC");
    static_assert(
      offsetof(StrategicIconAux, mViewportWidth) == 0x08,
      "StrategicIconAux::mViewportWidth offset must be 0x08"
    );
    static_assert(offsetof(StrategicIconAux, mSession) == 0x10, "StrategicIconAux::mSession offset must be 0x10");
    static_assert(offsetof(StrategicIconAux, mBatcher) == 0x14, "StrategicIconAux::mBatcher offset must be 0x14");
    static_assert(offsetof(StrategicIconAux, mCamera) == 0x18, "StrategicIconAux::mCamera offset must be 0x18");
    static_assert(
      offsetof(StrategicIconAux, mTickFraction) == 0x1C,
      "StrategicIconAux::mTickFraction offset must be 0x1C"
    );
    static_assert(
      offsetof(StrategicIconAux, mWhiteTexture) == 0x20,
      "StrategicIconAux::mWhiteTexture offset must be 0x20"
    );
    static_assert(
      offsetof(StrategicIconAux, mGenericIcons) == 0x28,
      "StrategicIconAux::mGenericIcons offset must be 0x28"
    );
    static_assert(
      offsetof(StrategicIconAux, mPauseRestTexture) == 0x38,
      "StrategicIconAux::mPauseRestTexture offset must be 0x38"
    );
    static_assert(
      offsetof(StrategicIconAux, mStunnedRestTexture) == 0x40,
      "StrategicIconAux::mStunnedRestTexture offset must be 0x40"
    );
    static_assert(
      offsetof(StrategicIconAux, mGroundIcons) == 0x48,
      "StrategicIconAux::mGroundIcons offset must be 0x48"
    );
    static_assert(offsetof(StrategicIconAux, mAirIcons) == 0x58, "StrategicIconAux::mAirIcons offset must be 0x58");
    static_assert(
      offsetof(StrategicIconAux, mHighPriorityIcons) == 0x68,
      "StrategicIconAux::mHighPriorityIcons offset must be 0x68"
    );
    static_assert(
      offsetof(StrategicIconAux, mSelectedIcons) == 0x78,
      "StrategicIconAux::mSelectedIcons offset must be 0x78"
    );
    static_assert(
      offsetof(StrategicIconAux, mLifebarIcons) == 0x88,
      "StrategicIconAux::mLifebarIcons offset must be 0x88"
    );
    static_assert(offsetof(StrategicIconAux, mSelfColor) == 0x98, "StrategicIconAux::mSelfColor offset must be 0x98");
    static_assert(
      offsetof(StrategicIconAux, mUnidentifiedColor) == 0xA8,
      "StrategicIconAux::mUnidentifiedColor offset must be 0xA8"
    );

    /// Engine addition: the run of `StrategicIconAux` a classified unit is stored in.
    enum class EStrategicIconRun : std::uint8_t
    {
      Ground,
      Air,
      HighPriority,
      Selected,
      Lifebar,
      /// The single hovered-unit slot (see `sHoveredStrategicIcon`), drawn after the four runs.
      Hovered,
    };

    /**
     * Engine addition: stores one classified unit in its run, attaching its texture handles: the
     * picked icon, and the paused/stunned overlays its flags ask for. `icon` is null for a lifebar
     * record, which carries no textures. These are the same handles, in the same runs and order,
     * that the serial classification stored directly.
     */
    /**
     * The binary's hovered-unit slot: a `UnitIconData` local of `RenderStrategicIcons`
     * ([esp+0xB0], zeroed at 0x0085B9CE). Classification copies the hovered unit's icon data into
     * it (0x0085C262..0x0085C277, `FUN_0085CB00`) instead of a run - the last hovered entry wins -
     * and the pass draws it after the four runs (0x0085BCB7..0x0085BCCD), so the hovered icon is on
     * top, in its `Over` / `SelectedOver` / highlighted generic texture.
     */
    UnitIconData sHoveredStrategicIcon{};

    void StoreStrategicIcon(
      StrategicIconAux& aux,
      const EStrategicIconRun run,
      const UnitIconData& data,
      const boost::shared_ptr<CD3DBatchTexture>* const icon
    )
    {
      if (run == EStrategicIconRun::Hovered) {
        sHoveredStrategicIcon = data;
        if (icon != nullptr) {
          sHoveredStrategicIcon.mIconTexture = *icon;
          if (sHoveredStrategicIcon.mShowPausedOverlay) {
            sHoveredStrategicIcon.mPausedTexture = aux.mPauseRestTexture;
          }
          if (sHoveredStrategicIcon.mShowStunnedOverlay) {
            sHoveredStrategicIcon.mStunnedTexture = aux.mStunnedRestTexture;
          }
        }
        return;
      }
      fa::vector<UnitIconData>* target = nullptr;
      switch (run) {
      case EStrategicIconRun::Ground:
        target = &aux.mGroundIcons;
        break;
      case EStrategicIconRun::Air:
        target = &aux.mAirIcons;
        break;
      case EStrategicIconRun::HighPriority:
        target = &aux.mHighPriorityIcons;
        break;
      case EStrategicIconRun::Selected:
        target = &aux.mSelectedIcons;
        break;
      case EStrategicIconRun::Lifebar:
        target = &aux.mLifebarIcons;
        break;
      case EStrategicIconRun::Hovered:
        return;
      }

      target->push_back(data);
      if (icon != nullptr) {
        UnitIconData& stored = target->back();
        stored.mIconTexture = *icon;
        if (stored.mShowPausedOverlay) {
          stored.mPausedTexture = aux.mPauseRestTexture;
        }
        if (stored.mShowStunnedOverlay) {
          stored.mStunnedTexture = aux.mStunnedRestTexture;
        }
      }
    }

    /**
     * Engine addition: one unit as a parallel classification chunk records it - the icon record
     * with its texture handles still empty, and where its icon texture comes from - so a worker
     * never touches the reference counts of the textures every unit shares.
     */
    struct StrategicIconCandidate
    {
      UnitIconData mData;
      const boost::shared_ptr<CD3DBatchTexture>* mIcon;
      EStrategicIconRun mRun;
    };

    /// Engine addition: `ui_ParallelIcons`, user-side. Build strategic icons on CUserWorkerPool.
    bool ui_ParallelIcons = true;

    TConVar<bool> gTConVar_ui_ParallelIcons(
      "ui_ParallelIcons",
      "Classify and place strategic icons on user worker threads (see user_Workers). Draws exactly "
      "what the serial pass draws, in the same order.",
      &ui_ParallelIcons
    );

    /// Engine addition: `ui_IconRecords`, user-side. Classify strategic icons from per-entity records.
    bool ui_IconRecords = true;

    TConVar<bool> gTConVar_ui_IconRecords(
      "ui_IconRecords",
      "Classify strategic icons from compact per-unit records refreshed only when a sync beat was "
      "applied or the camera's in-view list was rebuilt, instead of reading every unit each frame. "
      "Draws exactly what the original pass draws, in the same order (the default). 0 reads the units.",
      &ui_IconRecords
    );

    /**
     * Engine addition (`ui_IconRecords`): everything `RenderStrategicIcons`' classifier reads about
     * one unit that only the user-side sync apply can change (or that never changes) - its
     * liveness, intel bits, army relation, overlays, mesh, interpolation endpoints and icon
     * textures - flattened into one record per entry of the camera's in-view list. Every input the
     * classifier reads besides these (selection, hover, zoom, console variables, options, the
     * playable rect) can change between beats and is read per frame, as before.
     */
    struct StrategicIconSource
    {
      enum Flags : std::uint16_t
      {
        kFriendly = 1U << 0U,                ///< no focus army, or an ally of it
        kStunned = 1U << 1U,                 ///< `mShowStunnedOverlay`
        kPaused = 1U << 2U,                  ///< `mShowPausedOverlay`
        kCheckPlayableRect = 1U << 3U,       ///< no focus army, or the focus army's own unit
        kSelectedVariantEligible = 1U << 4U, ///< intel bit 0x08 (or not a unit)
        kLifebarBlueprint = 1U << 5U,        ///< `mLifeBarRender != 0`
        kLifebarUnit = 1U << 6U,             ///< a unit that is not being upgraded and shows lifebars
        kBusy = 1U << 7U,                    ///< `mUnitVarDat.mIsBusy`
        kBeingBuilt = 1U << 8U,              ///< `IsBeingBuilt()`
        kSkipWhenMeshVisible = 1U << 9U,
        kHighPriority = 1U << 10U, ///< sort priority below 'A'
        kAir = 1U << 11U,          ///< a unit whose blueprint can fly
      };

      /// Null when the classifier drops this entry before reading anything per-frame.
      UserEntity* mEntity = nullptr;
      const REntityBlueprint* mBlueprint = nullptr;
      const RMeshBlueprint* mMesh = nullptr;
      /// `GetInterpolatedTransform`'s inputs.
      Wm3::Vector3f mLastPosition{};
      Wm3::Vector3f mCurrentPosition{};
      float mImpact = 0.0f;
      /// The icon `PickUnitStrategicIconTexture` picks for an unhovered unit, unselected and selected.
      const boost::shared_ptr<CD3DBatchTexture>* mIcon = nullptr;
      const boost::shared_ptr<CD3DBatchTexture>* mSelectedIcon = nullptr;
      /// The same for a hovered unit (`Over` / `SelectedOver`, or the highlighted generic icon).
      const boost::shared_ptr<CD3DBatchTexture>* mHoveredIcon = nullptr;
      const boost::shared_ptr<CD3DBatchTexture>* mHoveredSelectedIcon = nullptr;
      std::uint16_t mFlags = 0U;

      [[nodiscard]] bool Has(
        const Flags flag
      ) const noexcept
      {
        return (mFlags & flag) != 0U;
      }
    };

    /// Engine addition (`ui_IconRecords`): one camera's records, valid while its key holds.
    struct StrategicIconSourceSet
    {
      const CameraImpl* mCamera = nullptr;
      const CWldSession* mSession = nullptr;
      std::uint64_t mBeat = ~0ull;
      std::uint64_t mFrustumRebuild = ~0ull;
      const void* mFocusArmy = nullptr;
      bool mTeamColorMode = false;
      std::vector<StrategicIconSource> mSources;

      // Engine addition (`ren_GpuIconClassify`): the GPU form of `mSources`, and the selection as
      // one bit per source. Each version changes whenever its array does.
      std::vector<StrategicIconSourceRecord> mGpuSources;
      std::uint64_t mGpuSourcesVersion = 0U;
      std::vector<std::uint32_t> mSelectionBits;
      std::vector<const UserEntity*> mSelectionSnapshot; // the selection the bits were built from
      std::uint64_t mSelectionVersion = 0U;
      std::uint64_t mSelectionBuiltFor = ~0ull; // `mGpuSourcesVersion` the bits were built for
      const UserEntity* mHoveredEntity = nullptr;
      std::uint32_t mHoveredIndex = 0xFFFFFFFFU;
      std::uint64_t mHoveredBuiltFor = ~0ull;
    };

    // Below this many units the serial pass is cheaper than a dispatch.
    constexpr std::size_t kParallelIconMinUnits = 1024u;
    constexpr std::size_t kParallelIconChunk = 512u;

    [[nodiscard]] bool UseParallelIcons(
      const std::size_t count
    )
    {
      return ui_ParallelIcons && count >= kParallelIconMinUnits && CUserWorkerPool::ConfiguredWorkerCount() != 0u;
    }

    /**
     * Address: 0x0085B2A0 (FUN_0085B2A0, struct_TeamColors::struct_TeamColors)
     *
     * What it does:
     * Builds the white solid-colour texture, reserves the five icon runs to
     * their binary-observed capacities, and decodes the team-color palette.
     * See the class comment above for the full field-by-field evidence.
     */
    StrategicIconAux::StrategicIconAux()
    {
      mWhiteTexture = CD3DBatchTexture::FromSolidColor(0xFFFFFFFFu);

      mGroundIcons.reserve(0x200);
      mAirIcons.reserve(0x200);
      mHighPriorityIcons.reserve(0x40);
      mSelectedIcons.reserve(0x80);
      mLifebarIcons.reserve(0x80);

      // Held until the LuaObjects below are gone: they live in the shared colour LuaState.
      const auto colorLock = moho::LockColorLuaState();
      LuaPlus::LuaObject* const colors = moho::GetColors();
      const LuaPlus::LuaObject gameColors = (*colors)["GameColors"];
      const LuaPlus::LuaObject teamColorMode = gameColors["TeamColorMode"];

      // Decoded in the binary's source order (Self/Ally/Enemy/Neutral); the
      // storage order (Self/Neutral/Ally/Enemy) is just field layout, not a
      // reordering of which key feeds which member.
      mSelfColor = SCR_DecodeColor(fa::string(teamColorMode["Self"].GetString()));
      mAllyColor = SCR_DecodeColor(fa::string(teamColorMode["Ally"].GetString()));
      mEnemyColor = SCR_DecodeColor(fa::string(teamColorMode["Enemy"].GetString()));
      mNeutralColor = SCR_DecodeColor(fa::string(teamColorMode["Neutral"].GetString()));

      mUnidentifiedColor = moho::GetUnidentifiedColor();
    }

    /**
     * Address: 0x0085E7F0 (FUN_0085E7F0, struct_IconAux::GetGenericIcons)
     *
     * What it does:
     * Loads `/lua/ui/game/strategicIcons.lua`'s `GenericIcons` table and
     * fills one `mGenericIcons` slot per `EGenericIconType` key with the
     * named batch texture.
     */
    void StrategicIconAux::LoadGenericIcons(
      CWldSession* const session
    )
    {
      mGenericIcons.resize(8);

      const LuaPlus::LuaObject iconTable = SCR_Import(session->mState, "/lua/ui/game/strategicIcons.lua");
      const LuaPlus::LuaObject genericIcons = iconTable.GetByName("GenericIcons");

      for (LuaPlus::LuaTableIterator iter(genericIcons, 1); iter.IsValid(); iter.Next()) {
        EGenericIconType iconType{};
        gpg::RRef enumRef{};
        enumRef = gpg::MakeRRef<moho::EGenericIconType>(&iconType);
        SCR_GetEnum(session->mState, iter.GetKey().GetString(), enumRef);

        mGenericIcons[static_cast<std::size_t>(iconType)] = CD3DBatchTexture::FromFile(iter.GetValue().GetString(), 0u);
      }
    }

    /**
     * Address: 0x0085EA60 (FUN_0085EA60, struct_IconAux::GetStunIcons)
     *
     * What it does:
     * Imports strategic icon Lua tables and refreshes pause/stunned overlay
     * rest textures for one icon-aux runtime object.
     */
    void StrategicIconAux::LoadPauseAndStunnedRestTextures(
      CWldSession* const session
    )
    {
      LuaPlus::LuaObject iconTable = SCR_Import(session->mState, "/lua/ui/game/strategicIcons.lua");
      LuaPlus::LuaObject pauseIcons = iconTable.GetByName("PauseIcons");
      LuaPlus::LuaObject pauseRest = pauseIcons.GetByName("PauseRest");
      if (pauseRest.IsString()) {
        mPauseRestTexture = CD3DBatchTexture::FromFile(pauseRest.GetString(), 0u);
      }

      iconTable = SCR_Import(session->mState, "/lua/ui/game/strategicIcons.lua");
      LuaPlus::LuaObject stunnedIcons = iconTable.GetByName("StunnedIcons");
      LuaPlus::LuaObject stunnedRest = stunnedIcons.GetByName("StunnedRest");
      if (stunnedRest.IsString()) {
        mStunnedRestTexture = CD3DBatchTexture::FromFile(stunnedRest.GetString(), 0u);
      }
    }

    /**
     * Address: 0x0085CBD0 (FUN_0085CBD0, sub_85CBD0)
     *
     * IDA signature:
     * _DWORD *callcnv_F3 sub_85CBD0@<eax>(_DWORD *a1@<eax>, _DWORD **a2@<ebx>, int a3@<edi>, _DWORD *a4@<esi>, char
     * a5);
     *
     * What it does:
     * Picks the shared "no specific blueprint icon" texture for one unit:
     * a fixed structure icon for immobile blueprints, or a land/naval/air
     * icon looked up by the unit's movement layer for mobile ones, or the
     * plain white texture when the layer doesn't match any of those three.
     * `wantHighlightVariant` selects the `*HL` (highlight) icon set over the
     * plain set - the caller (`PickUnitStrategicIconTexture` below) passes
     * `true` for the mouse-over case and `false` otherwise.
     *
     * Evidence: `iconData->mBlueprint->IsMobile()` is the vtable-slot-4
     * dispatch at 0x0085CBD9/0x0085CBDC (`REntityBlueprint` vftable slot 4,
     * byte-verified against `bin/2025.7.1/ForgedAlliance.exe` at 0x00E0F604
     * == 0x00511B60 == `REntityBlueprint::IsMobile`). The category switch
     * reads `iconData->mUnit->mVariableData.mLayerMask` (UserEntity+0xF0,
     * `cmp .. 0F0h` @ 0x0085CC20/0x0085CC87) and its case labels (1 / 2,4,8 /
     * 16) match `ELayer`'s `LAYER_Land` / `LAYER_Seabed|LAYER_Sub|LAYER_Water`
     * / `LAYER_Air` exactly. Every branch is a plain `boost::shared_ptr`
     * copy (`sub_428340`, itself just `*dst = *src; if (src.pn)
     * ++src.pn->use_count_`) from one of `aux->mGenericIcons`'s eight slots
     * or `aux->mWhiteTexture` - never a weak-to-shared promotion.
     */
    [[nodiscard]] const boost::shared_ptr<CD3DBatchTexture>& PickGenericStrategicIconTexture(
      const StrategicIconAux& aux,
      const UnitIconData& iconData,
      const bool wantHighlightVariant
    )
    {
      // Engine change: returns the persistent handle (an `aux` slot or a blueprint field) by
      // reference, so the parallel icon pass copies it only where it stores it.
      if (!iconData.mBlueprint->IsMobile()) {
        return aux.mGenericIcons[wantHighlightVariant ? GIT_StructureHL : GIT_Structure];
      }

      switch (static_cast<ELayer>(iconData.mUnit->mVariableData.mLayerMask)) {
      case LAYER_Land:
        return aux.mGenericIcons[wantHighlightVariant ? GIT_LandHL : GIT_Land];
      case LAYER_Seabed:
      case LAYER_Sub:
      case LAYER_Water:
        return aux.mGenericIcons[wantHighlightVariant ? GIT_NavalHL : GIT_Naval];
      case LAYER_Air:
        return aux.mGenericIcons[wantHighlightVariant ? GIT_AirHL : GIT_Air];
      default:
        return aux.mWhiteTexture;
      }
    }

    /**
     * Address: 0x0085D880 (FUN_0085D880, sub_85D880)
     *
     * IDA signature:
     * Moho::CAniPose **__usercall sub_85D880@<eax>(Moho::UserEntity **eax0@<eax>,
     *   Moho::CAniPose **a2@<edx>, char a3@<cl>, int a4, char a5, _DWORD *a1);
     *
     * What it does:
     * Picks the strategic-icon texture for one classified unit. A unit that
     * qualifies for a per-blueprint icon (is a real `UserUnit` and its
     * `mIntelStateFlags` "has real blueprint data" bit is set - the same bit
     * `UserEntity.cpp` already names `kSelectionBracketEnemyVisibleMask`) picks
     * one of the blueprint's four cached textures by `(isHovered, isSelected
     * && selectedVariantEligible)`: Rest / Over / Selected / SelectedOver.
     * Everything else (recon blips, wrecks, props, or a unit whose intel
     * doesn't carry full blueprint data) falls back to
     * `PickGenericStrategicIconTexture`.
     *
     * Evidence, all byte-verified in `FUN_0085D880.asm`:
     *  - `mov edx, [eax+0Ch]; call edx` (0x0085D893/0x0085D89E) is vtable
     *    slot 3 on `iconData.mUnit`, i.e. `UserEntity::IsUserUnit()`
     *    (Hex-Rays' "IsUserUnit2" is its own disambiguation of the
     *    const/non-const overload pair, not a distinct virtual).
     *  - `test byte ptr [eax+3E0h], 10h` (0x0085D8AB/0x0085D954) reads bit
     *    0x10 of `UserUnit::mIntelStateFlags` (already documented on that
     *    field: "0x10=has-data").
     *  - The four cached-texture fetches are inlined `boost::shared_ptr`
     *    copies (unconditional `lock xadd`, no expiry check) from
     *    `iconData.mBlueprint`+0x15C/0x164/0x16C/0x174 -
     *    `mStrategicIconRest/Selected/Over/SelectedOver` exactly (see the
     *    retype note on those fields in `REntityBlueprint.h`).
     */
    [[nodiscard]] const boost::shared_ptr<CD3DBatchTexture>& PickUnitStrategicIconTexture(
      const StrategicIconAux& aux,
      const UnitIconData& iconData,
      const bool isSelected,
      const bool selectedVariantEligible,
      const bool isHovered
    )
    {
      // Engine change: returns the persistent handle (an `aux` slot or a blueprint field) by
      // reference, so the parallel icon pass copies it only where it stores it.
      UserUnit* const asUnit = iconData.mUnit->IsUserUnit();
      // Same bit UserEntity.cpp's kSelectionBracketEnemyVisibleMask names on
      // mIntelStateFlags; re-declared locally because that constant is
      // file-private there.
      constexpr std::uint32_t kHasBlueprintIconDataMask = 0x10u;
      const bool usesGenericIcon = asUnit == nullptr || (asUnit->mIntelStateFlags & kHasBlueprintIconDataMask) == 0u;

      if (isHovered) {
        if (usesGenericIcon) {
          return PickGenericStrategicIconTexture(aux, iconData, /*wantHighlightVariant=*/true);
        }
        return (isSelected && selectedVariantEligible) ? iconData.mBlueprint->mStrategicIconSelectedOver
                                                       : iconData.mBlueprint->mStrategicIconOver;
      }

      if (isSelected && selectedVariantEligible) {
        return iconData.mBlueprint->mStrategicIconSelected;
      }
      if (usesGenericIcon) {
        return PickGenericStrategicIconTexture(aux, iconData, /*wantHighlightVariant=*/false);
      }
      return iconData.mBlueprint->mStrategicIconRest;
    }
    /** `TELEPORTBEACON` category the teleport-beacon splat/icon branch tests for (0x00851C5D). */
    const fa::string kCommandSplatTeleportBeaconCategory("TELEPORTBEACON", 14u);

    /** Default (non-teleport) command-splat line colour, `0x80800000` (0x00851D22). */
    constexpr std::uint32_t kCommandSplatDefaultColor = 0x80800000u;

    /** Same-army teleport-beacon command-splat line colour, `0x809040A0` (0x00851CF1). */
    constexpr std::uint32_t kCommandSplatTeleportColor = 0x809040A0u;

    /** Half-width of the beveled command-splat line ribbon, in world units (`0.1`, 0x00851B9E..0x00851BA6). */
    constexpr float kCommandSplatLineHalfWidth = 0.1f;

    /** Half-extent of the flat command-splat icon billboard, in world units (`1.0`, 0x00851E38..0x00851E42). */
    constexpr float kCommandSplatIconHalfExtent = 1.0f;

    /**
     * Resolves the world-space anchor `CWldSession::DrawCommandSplats` draws
     * one command-link line endpoint from/to for `entity`: either its own
     * interpolated position (`boneIndex < 0`, 0x008519D9..0x00851A11) or the
     * composite-transform position of bone `boneIndex` on its freshly
     * refreshed debug pose (0x00851929..0x00851994, the same
     * `MeshInstance::ComputeDebugPose` + `CAniPoseBone::GetCompositeTransform`
     * chain `MeshRenderer::RenderSkeleton` issues for the skeleton-debug
     * overlay). The interpolation alpha is `0.0f`: the incoming stack slot
     * the binary reads for it is never written by the sole call site (which
     * pushes only the session, camera and prim-batcher), so it resolves
     * whatever was left on the caller's frame - the same "phantom
     * interpolant" shape already documented and resolved to a hard `0.0f`
     * on the sibling `DrawEconomyOverlay` above.
     *
     * The binary calls `CAniPoseBone::GetCompositeTransform` unconditionally
     * even when `boneIndex` is out of range for the refreshed pose's bone
     * array, leaving the bone pointer null (0x00851961..0x00851971) - a
     * latent null-dereference crash on out-of-range data. Preserved here as
     * a defensive `false` return instead of reproducing the crash.
     */
    [[nodiscard]] bool ResolveCommandSplatAnchorPosition(
      UserEntity& entity,
      const std::int32_t boneIndex,
      Wm3::Vector3f& outPosition
    )
    {
      if (boneIndex < 0) {
        outPosition = entity.GetInterpolatedTransform(0.0f).pos_;
        return true;
      }

      if (entity.mMeshInstance == nullptr) {
        return false;
      }

      const boost::shared_ptr<CAniPose> pose = entity.mMeshInstance->ComputeDebugPose();
      if (!pose) {
        return false;
      }

      const std::ptrdiff_t boneCount = pose->mBones.end() - pose->mBones.begin();
      if (boneIndex >= boneCount) {
        return false;
      }

      outPosition = pose->mBones.begin()[boneIndex].GetCompositeTransform().pos_;
      return true;
    }

    /**
     * Binds one texture resource by path for the command-splat icon
     * batches, matching 0x00851DB8..0x00851DF1 (attack icon) /
     * 0x00851F3C..0x00851FAA (teleport icon):
     * `CD3DDevice::GetResources()->GetTexture(handle, path, nullptr, true)`
     * followed by `CD3DPrimBatcher::SetTexture` on the dynamic-sheet
     * overload (the resolved `TextureResourceHandle` - a
     * `shared_ptr<RD3DTextureResource>` - upcasts to the
     * `shared_ptr<ID3DTextureSheet>` the overload wants, since
     * `RD3DTextureResource` derives from `ID3DTextureSheet`).
     */
    void BindCommandSplatIconTexture(
      CD3DPrimBatcher& batcher,
      const char* const path
    )
    {
      CD3DDevice* const device = D3D_GetDevice();
      ID3DDeviceResources* const resources = device->GetResources();
      ID3DDeviceResources::TextureResourceHandle textureHandle{};
      (void)resources->GetTexture(textureHandle, path, nullptr, true);
      batcher.SetTexture(boost::shared_ptr<ID3DTextureSheet>(textureHandle));
    }

    /**
     * Draws one flat, ground-aligned 2x2-world-unit icon billboard at
     * `worldPosition` (0x00851E30..0x00851F27 / 0x00851FE0..0x008520D2 -
     * the attack- and teleport-icon batch loops share this exact shape).
     * The `+-1.0` X/Z corner offsets with no Y offset and the opaque-white
     * vertex colour (`-1`, written repeatedly at 0x00851E55..0x00851F19 and
     * its teleport-branch twin) come straight from the binary; the precise
     * corner-to-UV pairing was not independently bit-verified (the source
     * locals the binary reuses for this pass were, earlier in the same
     * function, a `std::string` and two unrelated `Vertex` scratch buffers,
     * which makes a byte-exact reconstruction of just this block
     * impractical) - the standard 0..1 UV wrap used here reproduces the
     * visible quad shape and opaque-white tint and is not expected to read
     * any differently.
     */
    void DrawCommandSplatIcon(
      CD3DPrimBatcher& batcher,
      const Wm3::Vector3f& worldPosition
    )
    {
      constexpr std::uint32_t kIconColor = 0xFFFFFFFFu;

      const CD3DPrimBatcher::Vertex topLeft{
        worldPosition.x - kCommandSplatIconHalfExtent,
        worldPosition.y,
        worldPosition.z + kCommandSplatIconHalfExtent,
        kIconColor,
        0.0f,
        0.0f
      };
      const CD3DPrimBatcher::Vertex topRight{
        worldPosition.x - kCommandSplatIconHalfExtent,
        worldPosition.y,
        worldPosition.z - kCommandSplatIconHalfExtent,
        kIconColor,
        0.0f,
        1.0f
      };
      const CD3DPrimBatcher::Vertex bottomRight{
        worldPosition.x + kCommandSplatIconHalfExtent,
        worldPosition.y,
        worldPosition.z - kCommandSplatIconHalfExtent,
        kIconColor,
        1.0f,
        1.0f
      };
      const CD3DPrimBatcher::Vertex bottomLeft{
        worldPosition.x + kCommandSplatIconHalfExtent,
        worldPosition.y,
        worldPosition.z + kCommandSplatIconHalfExtent,
        kIconColor,
        1.0f,
        0.0f
      };
      batcher.DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
    }
  } // namespace

  /**
   * Address: 0x008515B0 (FUN_008515B0, ?DrawCommandSplats@CWldSession@Moho@@QAEXXZ)
   */
  void CWldSession::DrawCommandSplats(
    GeomCamera3* const camera,
    CD3DPrimBatcher* const primBatcher
  )
  {
    // Walk the selection weak-set and collect the distinct army indices of
    // every live selected unit (0x008515D4..0x00851696, `WeakSet_UserEntity`
    // `find`/`Iterator::inc` over `mSelection`; the per-entity value added to
    // the set is that unit's owning army index).
    BVIntSet selectedArmies{};
    for (UserEntity* const entity : mSelection) {
      if (entity->mArmy != nullptr) {
        (void)selectedArmies.Add(static_cast<unsigned int>(entity->mArmy->mArmyIndex));
      }
    }

    ISTIDriver* const simDriver = sSimDriver.get();
    if (simDriver == nullptr) {
      return;
    }

    // Always publish the selection's army mask to the sync filter, even when
    // the rest of this overlay is not drawn this frame (0x008516A6..0x008516F5).
    simDriver->SetSyncFilterMaskA(selectedArmies);

    // The rest of the overlay only draws while Shift is held with no UI
    // control focused and the game window foreground - `MAUI_KeyIsDown`
    // already implements exactly that gate (0x00851704..0x00851742).
    if (!MAUI_KeyIsDown(MKEY_SHIFT)) {
      return;
    }

    primBatcher->Setup("TAlphaBlendLinearSampleNoDepth");
    primBatcher->SetViewProjMatrix(*camera);
    primBatcher->SetTexture(CD3DBatchTexture::FromSolidColor(0xFFFFFFFFu));

    fa::vector<Wm3::Vector3f> attackIconPositions{};
    fa::vector<Wm3::Vector3f> teleportIconPositions{};

    // `mSyncExtraUnitData` is the per-beat extra-unit-data run
    // `CWldSession::DoBeat` copies wholesale from `beat.mSyncExtraUnitData`
    // (see its declaration above) - this is that lane's reader. Each record
    // is one source unit's queued command-link run: `unitEntityId` holds
    // the source `EntId`, and `pairs` holds `(boneIndex, targetEntId)`
    // records, one per weapon (`Unit::GetExtraData`'s `AiAttacker` branch)
    // or teleport-beacon link (its `key == -1` sentinel branch, 0x006ACB20)
    // (0x008518A4..0x0085189A).
    for (const SExtraUnitData& record : mSyncExtraUnitData) {
      UserEntity* const source = LookupEntityId(record.unitEntityId);
      if (source == nullptr) {
        continue;
      }

      for (const SExtraUnitDataPair& pair : record.pairs) {
        const std::int32_t boneIndex = pair.key;
        const EntId targetId = pair.value;

        UserEntity* const target = LookupEntityId(targetId);
        if (target == nullptr) {
          continue;
        }

        Wm3::Vector3f sourcePosition{};
        if (!ResolveCommandSplatAnchorPosition(*source, boneIndex, sourcePosition)) {
          continue;
        }

        const Wm3::Vector3f targetPosition = target->GetInterpolatedTransform(0.0f).pos_;

        // Direction from source to target, normalized (zero vector when the
        // two points coincide) - 0x00851A37..0x00851AE9.
        Wm3::Vector3f direction{
          targetPosition.x - sourcePosition.x, targetPosition.y - sourcePosition.y, targetPosition.z - sourcePosition.z
        };
        const float distance =
          std::sqrt(direction.x * direction.x + direction.y * direction.y + direction.z * direction.z);
        if (distance > 0.0f) {
          const float inverseDistance = 1.0f / distance;
          direction =
            Wm3::Vector3f{direction.x * inverseDistance, direction.y * inverseDistance, direction.z * inverseDistance};
        } else {
          direction = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
        }

        // Perpendicular bevel offset: the direction rotated 90 degrees
        // about Y, scaled to the ribbon half-width (0x00851B8C..0x00851BA6).
        const Wm3::Vector3f bevel{
          direction.z * kCommandSplatLineHalfWidth, 0.0f, -direction.x * kCommandSplatLineHalfWidth
        };

        // The line ribbon runs from one unit short of the source to one
        // unit short of the target (0x00851AE9..0x00851C50), offset to one
        // side by `bevel`.
        const Wm3::Vector3f nearSource{
          sourcePosition.x + direction.x, sourcePosition.y + direction.y, sourcePosition.z + direction.z
        };
        const Wm3::Vector3f nearTarget{
          targetPosition.x - direction.x, targetPosition.y - direction.y, targetPosition.z - direction.z
        };

        const Wm3::Vector3f topLeft{nearSource.x + bevel.x, nearSource.y + bevel.y, nearSource.z + bevel.z};
        const Wm3::Vector3f& topRight = nearSource;
        const Wm3::Vector3f& bottomRight = nearTarget;
        const Wm3::Vector3f bottomLeft{nearTarget.x + bevel.x, nearTarget.y + bevel.y, nearTarget.z + bevel.z};

        const bool sameArmy = source->mArmy != nullptr && source->mArmy == target->mArmy;
        const bool isTeleportBeacon = sameArmy && target->IsInCategory(kCommandSplatTeleportBeaconCategory);
        const std::uint32_t lineColor = isTeleportBeacon ? kCommandSplatTeleportColor : kCommandSplatDefaultColor;

        primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft, lineColor);

        if (isTeleportBeacon) {
          teleportIconPositions.push_back(targetPosition);
        } else {
          attackIconPositions.push_back(targetPosition);
        }
      }
    }

    BindCommandSplatIconTexture(*primBatcher, "/textures/ui/common/game/waypoints/attack_btn_up.dds");
    for (const Wm3::Vector3f& iconPosition : attackIconPositions) {
      DrawCommandSplatIcon(*primBatcher, iconPosition);
    }

    BindCommandSplatIconTexture(*primBatcher, "/textures/ui/common/game/waypoints/teleport_btn_up.dds");
    for (const Wm3::Vector3f& iconPosition : teleportIconPositions) {
      DrawCommandSplatIcon(*primBatcher, iconPosition);
    }

    primBatcher->Flush();
  }
  namespace
  {
    /**
     * Tint every formation-placement ghost is stamped with, written straight
     * into `MeshInstance::color` at 0x00859E0B as the literal `0D8D8D800h`.
     */
    constexpr std::int32_t kFormationPreviewTint = static_cast<std::int32_t>(0xD8D8D800u);
  } // namespace

  /**
   * Address: 0x008599D0 (FUN_008599D0, ?RenderMeshPreviews@CWldSession@Moho@@QAEHXZ)
   *
   * IDA signature:
   * int __usercall sub_8599D0@<eax>(Moho::CWldSession *this);
   *
   * What it does:
   * Rebuilds this frame's formation-placement ghosts. Last frame's previews are
   * dropped unconditionally; then, only while the pending formation is ready,
   * still has a live instance, and its placement timer has run out, every
   * participant unit gets one translucent copy of its own mesh - reshaded with
   * the "UnitFormationPreview" shader - parked on the terrain at the slot the
   * formation assigned it and turned to face the formation heading.
   */
  void CWldSession::RenderMeshPreviews()
  {
    MeshRenderer* const renderer = MeshRenderer::GetInstance();

    // 0x008599EF..0x00859A0A: the whole-range erase runs before every early-out
    // below, so a formation that is no longer placeable clears its ghosts.
    gFormationPreviews.clear();

    CFormation* const formation = mCurFormation;
    if (!formation->mReady || formation->mCurInstance == nullptr || formation->mTimeLeft > 0.0f) {
      return;
    }

    // 0x00859AB1 / 0x00859AF8 dispatch instance slots 16 and 6, which only
    // `CAiFormationInstance` declares - `mCurInstance` is typed as the bare
    // `IFormationInstance` interface. Same reinterpret_cast the rest of the
    // tree already uses to reach the concrete instance (Unit.cpp).
    CAiFormationInstance* const instance = reinterpret_cast<CAiFormationInstance*>(formation->mCurInstance);
    WeakSet<UserUnit>& participants = formation->mParticipants;

    for (UserUnit* const unit : participants) {
      {
        // The unit's `IUnit` bridge sub-object at +0x148 is what every
        // formation-side call below is handed.
        IUnit* const bridge = GetIUnitBridge(unit);
        Unit* const formationUnit = reinterpret_cast<Unit*>(bridge);

        if (!bridge->IsDead() && instance->Contains(formationUnit, false) && unit->GetAttachmentParent() == nullptr) {
          const RUnitBlueprint* const blueprint = bridge->GetBlueprint();
          const RMeshBlueprint* const meshBlueprint = unit->mVariableData.mMeshBlueprint;
          if (!meshBlueprint->mLods.empty()) {
            SCoordsVec2 slot{};
            instance->GetFormationPosition(&slot, formationUnit, nullptr);

            // 0x00859B12 builds the basis for the formation heading and then
            // never reads it back - a dead local in the 2007 source, kept
            // because the constructor call is a real emission.
            [[maybe_unused]] const VAxes3 heading{formation->mDirection};

            // Park the ghost on the terrain: surface height under the slot,
            // plus the unit's own half-height and its blueprint elevation.
            Wm3::Vec3f position{slot.x, 0.0f, slot.z};
            position.y = GetSTIMap()->GetSurface(position) + blueprint->mSizeY + blueprint->Physics.Elevation;

            gFormationPreviews.push_back(SFormationPreviewGhost{});
            SFormationPreviewGhost& preview = gFormationPreviews.back();

            // Only the top LOD is previewed, and only its three texture lanes -
            // the shader is forced to "UnitFormationPreview" and the lookup and
            // secondary maps are left empty (0x00859C3F..0x00859C71).
            const RMeshBlueprintLOD& lod = *meshBlueprint->mLods.begin();
            preview.mMaterial = MeshMaterial::Create(
              fa::string{"UnitFormationPreview"},
              lod.mAlbedoName,
              lod.mNormalsName,
              lod.mSpecularName,
              fa::string{},
              fa::string{},
              nullptr
            );

            const float uniformScale = blueprint->Display.UniformScale;
            preview.mMesh = boost::shared_ptr<MeshInstance>(renderer->CreateMeshInstance(
              0, 0, meshBlueprint, Wm3::Vec3f{uniformScale, uniformScale, uniformScale}, false, preview.mMaterial
            ));

            if (preview.mMesh) {
              VTransform stance{Wm3::Vec3f{0.0f, 0.0f, 0.0f}, Wm3::Quatf{1.0f, 0.0f, 0.0f, 0.0f}};
              stance.orient_ = formation->mDirection;
              stance.pos_ = position;

              // Start and end stance are the same transform - the ghost does
              // not interpolate.
              //
              // Not reproduced here: 0x00859DE4 zero-fills an 8-byte slot that
              // EH state 5 covers for exactly this call plus the tint store,
              // and 0x00859E1D hands it to the shared-count teardown
              // (FUN_0055B7A0). Both halves are null for its whole lifetime, so
              // the teardown returns on its first branch and the pair is
              // observably a no-op - a default-constructed shared handle the
              // 2007 source declared and never used. Behaviour is identical
              // without it; inventing a variable to carry it would not be.
              preview.mMesh->SetStance(stance, stance);
              preview.mMesh->color = kFormationPreviewTint;
            } else {
              // 0x00859E26: the renderer refused the instance, so the slot
              // that was just appended is retired again.
              gFormationPreviews.pop_back();
            }
          }
        }
      }
    }
  }
  namespace
  {
    /**
     * Gap between two stacked bars, in screen pixels (`flt_DFEB0C` added twice
     * per row at 0x0085D22F / 0x0085D23E).
     */
    constexpr float kLifebarRowGap = 2.0f;

    /** Every bar sits on an opaque black backdrop (`0FF000000h`, 0x0085D285). */
    constexpr std::uint32_t kLifebarBackdropColor = 0xFF000000u;

    /**
     * A filled bar never gets thinner than this even when the bar itself is
     * (`comiss` against `flt_DFEB0C` at 0x0085D55D / 0x0085D581).
     */
    constexpr float kLifebarMinFillHeight = 2.0f;

    /** The drop shadow under a label is offset one pixel down-right (0x0085E2A3). */
    constexpr float kLabelShadowOffset = 1.0f;

    /** Label drop shadow colour (`0FF000000h` pushed at 0x0085E2AB). */
    constexpr std::uint32_t kLabelShadowColor = 0xFF000000u;

    /**
     * Address: 0x004EAA50 (FUN_004EAA50)
     *
     * What it does:
     * Returns the shared "no screen position" sentinel - a `Wm3::Vector2f`
     * whose components are both NaN. The binary keeps it in a
     * function-local static (storage 0x010C7AB4/0x010C7AB8 behind the
     * one-bit init guard at 0x010C7ABC) and both of
     * `DrawUnitCustomNameLabel`'s early-outs hand it back: the first inlines
     * the guard (0x0085E33F), the second calls this body (0x0085E0F5).
     */
    [[nodiscard]] const Wm3::Vector2f& InvalidScreenPoint()
    {
      static const Wm3::Vector2f sentinel{
        std::numeric_limits<float>::quiet_NaN(), std::numeric_limits<float>::quiet_NaN()
      };
      return sentinel;
    }

    /**
     * Address: 0x005657B0 (FUN_005657B0, sub_5657B0)
     *
     * IDA signature:
     * BOOL __usercall sub_5657B0@<eax>(float *a1@<esi>);
     *
     * What it does:
     * Reports whether a screen point carries a real position, i.e. neither
     * component is NaN. This is the read side of `InvalidScreenPoint()`.
     */
    [[nodiscard]] bool IsValidScreenPoint(
      const Wm3::Vector2f& point
    )
    {
      return !std::isnan(point.X()) && !std::isnan(point.Y());
    }

    /**
     * Address: 0x010C4284 (the cached custom-name font)
     *
     * What it does:
     * Returns the process-wide font the custom-name labels render with,
     * creating it on first use from the `ui_CustomNameFont` /
     * `ui_CustomNameFontSize` console variables (0x0085E11B..0x0085E171).
     * The binary keeps exactly one reference for the life of the process -
     * the temporary handle `CD3DFont::Create` returns is assigned into the
     * global and then released - so the static below deliberately never
     * releases either.
     */
    [[nodiscard]] CD3DFont* CustomNameFont()
    {
      static boost::SharedPtrRaw<CD3DFont> font{};
      if (font.px == nullptr) {
        font = CD3DFont::Create(ui_CustomNameFontSize, ui_CustomNameFont.c_str());
      }
      return font.px;
    }

    /**
     * Emits one axis-aligned screen-space bar.
     *
     * All six quads in `DrawUnitLifebars` hand their corners to
     * `CD3DPrimBatcher::DrawQuad` in the same rotation - top-left, down the
     * left edge, across the bottom, back up the right edge - so the corner
     * mechanics are lifted here instead of being open-coded six times. That
     * rotation is the binary's own: at 0x0085D317 the `topLeft` argument
     * (the vector pushed first, read from the callee frame at +8 in
     * 0x00438DD0) is `(left, top)` while `topRight` (the `ecx` argument,
     * read at 0x00438DA3) is `(left, bottom)`.
     */
    void DrawLifebarQuad(
      CD3DPrimBatcher& primBatcher,
      const float left,
      const float top,
      const float right,
      const float bottom,
      const std::uint32_t color
    )
    {
      primBatcher.DrawQuad(
        Wm3::Vector3f(left, top, 0.0f),
        Wm3::Vector3f(left, bottom, 0.0f),
        Wm3::Vector3f(right, bottom, 0.0f),
        Wm3::Vector3f(right, top, 0.0f),
        color
      );
    }

    /**
     * Phase of the shared "empty fuel" blink, in [0,1)
     * (0x0085D107..0x0085D11B and the identical block at
     * 0x0085D18E..0x0085D1A2).
     *
     * Driven by the sim clock rather than the wall clock so every warning bar
     * on screen blinks in step: the whole-tick counter plus this frame's
     * sub-tick interpolant, scaled by the console rate and wrapped.
     */
    [[nodiscard]] float FuelWarningBlinkPhase(
      const StrategicIconAux& aux
    )
    {
      const double simTime = static_cast<double>(aux.mSession->mGameTick) + static_cast<double>(aux.mTickFraction);
      return static_cast<float>(fa::fmod(simTime * static_cast<double>(ui_FuelEmptyBlinkRate), 1.0));
    }

    /**
     * Address: 0x0085CD40 (FUN_0085CD40, sub_85CD40)
     *
     * IDA signature:
     * float *__usercall sub_85CD40@<eax>(UnitIconData *icon@<eax>,
     *   Wm3::Vector2f *labelCursor, struct_IconAux *aux);
     *
     * What it does:
     * Draws one unit's stacked status bars in the strategic view and reports
     * where a text label under them would start.
     *
     * Row one is always the health bar. Row two and three are conditional: a
     * unit with a shield puts the shield on row two and fuel (or, when the
     * unit carries no fuel at all, build progress) on row three; a unit
     * without a shield collapses to a single second row showing whichever of
     * fuel and build progress is further along. Fuel at or below empty - but
     * not the "no fuel lane at all" sentinel of -1 - swaps that bar to the
     * warning colour and fills it completely on alternate blink phases.
     *
     * Each row is an opaque black backdrop with a coloured fill inset one
     * pixel, the fill running `fraction` of the way across.
     *
     * `labelCursor` receives the horizontal centre of the bar stack and the
     * bottom edge of the last row actually drawn, which is what
     * `DrawUnitCustomNameLabel` hangs its text off.
     */
    void DrawUnitLifebars(
      const UnitIconData& icon,
      Wm3::Vector2f& labelCursor,
      const StrategicIconAux& aux
    )
    {
      if (icon.mUnit == nullptr || icon.mUnit->mVariableData.mIsDead != 0 || icon.mUnit->mMarkedForDeletion != 0) {
        return;
      }
      if (IsFactoryPreOrdersEnabled()) {
        if (const UserUnit* const asUnit = icon.mUnit->IsUserUnit()) {
          if (PlannedFactoryManager::Get().IsPlannedProxyUnit(asUnit)) {
            return;
          }
        }
      }

      CD3DPrimBatcher& primBatcher = *aux.mBatcher;
      primBatcher.SetTexture(aux.mWhiteTexture);

      const GeomCamera3& camera = *aux.mCamera;
      const REntityBlueprint& blueprint = *icon.mBlueprint;
      const Wm3::Vector3f worldPosition{icon.mWorldX, icon.mWorldY, icon.mWorldZ};

      // Row 2 of the viewport matrix is the perspective-correct width factor;
      // dividing by it keeps the bar a constant on-screen size as the camera
      // pulls back (0x0085CD6A..0x0085CDAF).
      const float widthScale = camera.viewport.ProjectViewportWidthRow2(worldPosition);

      // A blueprint may override either bar extent; a non-positive value means
      // "use the console default" (0x0085CDA8 / 0x0085CDC6).
      const float barWidthSource = (blueprint.mLifeBarSize > 0.0f) ? blueprint.mLifeBarSize : ui_LifebarWidth;
      const float barHeightSource = (blueprint.mLifeBarHeight > 0.0f) ? blueprint.mLifeBarHeight : ui_lifebarHeight;
      const float barWidth = (1.0f / widthScale) * barWidthSource;
      const float barHeight = (1.0f / widthScale) * barHeightSource;

      // The anchor is not the unit's screen position: the world point is taken
      // into VIEW space first so the stack can be dropped straight down the
      // camera's own up axis by the blueprint's lifebar offset, and only then
      // projected. That is why this cannot go through `GeomCamera3::Project` -
      // the offset is applied mid-pipeline (0x0085CDFF..0x0085CFA1).
      const VMatrix4& view = camera.view;
      const float viewX = (view.r[0].x * worldPosition.X()) + (view.r[1].x * worldPosition.Y()) +
        (view.r[2].x * worldPosition.Z()) + view.r[3].x;
      const float viewY = (view.r[0].y * worldPosition.X()) + (view.r[1].y * worldPosition.Y()) +
        (view.r[2].y * worldPosition.Z()) + view.r[3].y;
      const float viewZ = (view.r[0].z * worldPosition.X()) + (view.r[1].z * worldPosition.Y()) +
        (view.r[2].z * worldPosition.Z()) + view.r[3].z;
      const float viewW = (view.r[0].w * worldPosition.X()) + (view.r[1].w * worldPosition.Y()) +
        (view.r[2].w * worldPosition.Z()) + view.r[3].w;

      const float inverseViewW = 1.0f / viewW;
      const float anchorX = viewX * inverseViewW;
      const float anchorY = (viewY * inverseViewW) - (blueprint.mLifeBarOffset + ui_LifebarOffset);
      const float anchorZ = viewZ * inverseViewW;

      const VMatrix4& projection = camera.projection;
      const float clipX = (projection.r[0].x * anchorX) + (projection.r[1].x * anchorY) +
        (projection.r[2].x * anchorZ) + projection.r[3].x;
      const float clipY = (projection.r[0].y * anchorX) + (projection.r[1].y * anchorY) +
        (projection.r[2].y * anchorZ) + projection.r[3].y;
      const float clipW = (projection.r[0].w * anchorX) + (projection.r[1].w * anchorY) +
        (projection.r[2].w * anchorZ) + projection.r[3].w;

      // NDC to whole pixels, Y flipped, same mapping the resource splats use.
      const float inverseClipW = 1.0f / clipW;
      const float anchorScreenX = std::floor(((clipX * inverseClipW) - -1.0f) * aux.mViewportWidth * 0.5f);
      const float anchorScreenY =
        std::floor(((((clipY * inverseClipW) - -1.0f) * (-0.0f - aux.mViewportHeight)) * 0.5f) + aux.mViewportHeight);

      const float halfBarWidth = barWidth * 0.5f;
      const float barLeft = anchorScreenX - halfBarWidth;
      const float barRight = barLeft + barWidth;
      const float barTop = anchorScreenY - (barHeight * 0.5f);

      const UserEntity& entity = *icon.mUnit;
      float healthFraction = entity.mVariableData.mHealth / entity.mVariableData.mMaxHealth;
      // Written as the binary's inverted compares so a NaN ratio (a unit with
      // zero max health) clamps to full rather than propagating.
      if (!(1.0f > healthFraction)) {
        healthFraction = 1.0f;
      }
      if (0.0f > healthFraction) {
        healthFraction = 0.0f;
      }

      std::uint32_t healthColor = ui_LifeBarBadColor;
      if (healthFraction > ui_LifeBarGoodCutoff) {
        healthColor = ui_LifeBarGoodColor;
      } else if (healthFraction > ui_LifeBarBadCutoff) {
        healthColor = ui_LifeBarMedColor;
      }

      // Rows two and three stay at zero for anything that is not a unit, which
      // is what suppresses them below.
      float secondRowFraction = 0.0f;
      float thirdRowFraction = 0.0f;
      std::uint32_t secondRowColor = 0u;
      std::uint32_t thirdRowColor = 0u;

      // Slot 3 (`[vftable+0x0C]`, the non-const overload) is the one the
      // binary dispatches at 0x0085D091, matching the caller's own test.
      if (const UserUnit* const unit = icon.mUnit->IsUserUnit(); unit != nullptr) {
        const float fuelRatio = unit->mUnitVarDat.mFuelRatio;
        const float shieldRatio = unit->mUnitVarDat.mShieldRatio;
        const float workProgress = unit->mUnitVarDat.mWorkProgress;
        // -1 is the "this unit has no fuel lane" sentinel, distinct from an
        // empty tank at 0 (0x0085D0D3 / 0x0085D180).
        constexpr float kNoFuelLaneSentinel = -1.0f;

        if (shieldRatio > 0.0f) {
          secondRowColor = ui_ShieldBarColor;
          secondRowFraction = shieldRatio;

          if (!(fuelRatio > kNoFuelLaneSentinel)) {
            thirdRowColor = ui_ProgressBarColor;
            thirdRowFraction = workProgress;
          } else {
            thirdRowColor = ui_FuelBarColor;
            thirdRowFraction = fuelRatio;
            if (!(0.0f < fuelRatio) && FuelWarningBlinkPhase(aux) > 0.5f) {
              thirdRowColor = ui_FuelWarningColor;
              thirdRowFraction = 1.0f;
            }
          }
        } else {
          if (fuelRatio > workProgress) {
            secondRowColor = ui_FuelBarColor;
            secondRowFraction = fuelRatio;
          } else {
            secondRowColor = ui_ProgressBarColor;
            secondRowFraction = workProgress;
          }

          if (fuelRatio > kNoFuelLaneSentinel && !(0.0f < fuelRatio) && FuelWarningBlinkPhase(aux) > 0.5f) {
            secondRowColor = ui_FuelWarningColor;
            secondRowFraction = 1.0f;
          }
        }

        if (!(1.0f > secondRowFraction)) {
          secondRowFraction = 1.0f;
        }
        if (0.0f > secondRowFraction) {
          secondRowFraction = 0.0f;
        }
        if (!(1.0f > thirdRowFraction)) {
          thirdRowFraction = 1.0f;
        }
        if (0.0f > thirdRowFraction) {
          thirdRowFraction = 0.0f;
        }
      }

      const float secondRowTop = barTop + (barHeight + kLifebarRowGap);
      const float thirdRowTop = secondRowTop + (barHeight + kLifebarRowGap);

      // Backdrops first, one row at a time, each row gated on the row above
      // having something to show.
      DrawLifebarQuad(primBatcher, barLeft, barTop, barRight, barTop + barHeight, kLifebarBackdropColor);

      float lastRowTop = barTop;
      if (secondRowFraction > 0.0f) {
        DrawLifebarQuad(primBatcher, barLeft, secondRowTop, barRight, secondRowTop + barHeight, kLifebarBackdropColor);
        lastRowTop = secondRowTop;

        if (thirdRowFraction > 0.0f) {
          DrawLifebarQuad(primBatcher, barLeft, thirdRowTop, barRight, thirdRowTop + barHeight, kLifebarBackdropColor);
          lastRowTop = thirdRowTop;
        }
      }

      labelCursor = Wm3::Vector2f(barLeft + halfBarWidth, lastRowTop + barHeight);

      // Then the coloured fills, inset one pixel inside their backdrops.
      const float fillTrackWidth = barWidth - 1.0f;
      const float fillHeight = (barHeight - kLifebarRowGap) + 1.0f;
      const float fillBottomOffset = (fillHeight < kLifebarMinFillHeight) ? kLifebarMinFillHeight : fillHeight;

      DrawLifebarQuad(
        primBatcher,
        barLeft + 1.0f,
        barTop + 1.0f,
        barLeft + (healthFraction * fillTrackWidth),
        barTop + fillBottomOffset,
        healthColor
      );

      if (secondRowFraction > 0.0f) {
        DrawLifebarQuad(
          primBatcher,
          barLeft + 1.0f,
          secondRowTop + 1.0f,
          barLeft + (secondRowFraction * fillTrackWidth),
          secondRowTop + fillBottomOffset,
          secondRowColor
        );

        if (thirdRowFraction > 0.0f) {
          DrawLifebarQuad(
            primBatcher,
            barLeft + 1.0f,
            thirdRowTop + 1.0f,
            barLeft + (thirdRowFraction * fillTrackWidth),
            thirdRowTop + fillBottomOffset,
            thirdRowColor
          );
        }
      }
    }

    /**
     * Address: 0x0085E0A0 (FUN_0085E0A0, sub_85E0A0)
     *
     * IDA signature:
     * Wm3::Vector2f *__cdecl sub_85E0A0(Wm3::Vector2f *result, UnitIconData *icon,
     *   struct_IconAux *aux, Wm3::Vector2f *labelCursor, char isMiniMap);
     *
     * What it does:
     * Draws one unit's player-assigned custom name under its status bars and
     * returns where the text was placed, so the next label down can stack
     * beneath it. Returns `InvalidScreenPoint()` when nothing was drawn -
     * labels are off, this is the minimap, or the unit has no custom name -
     * which is the caller's signal to leave its cursor untouched.
     *
     * The label is centred on `labelCursor` when the bar pass gave it one;
     * otherwise it falls back to projecting the unit itself and applying the
     * same blueprint + console lifebar offset the bars use. Either way the
     * text is snapped to whole pixels and drawn twice, an opaque black copy
     * one pixel down-right first so it stays readable over terrain.
     */
    [[nodiscard]] Wm3::Vector2f DrawUnitCustomNameLabel(
      const UnitIconData& icon,
      const StrategicIconAux& aux,
      const Wm3::Vector2f& labelCursor,
      const bool isMiniMap
    )
    {
      if (!ui_RenderCustomNames || isMiniMap) {
        return InvalidScreenPoint();
      }

      UserUnit* const unit = icon.mUnit->IsUserUnit();

      // `UserUnit::GetCustomName` (vtable slot 24, `[vftable+0x60]`) hands back
      // the address of the unit's `fa::string`, not a C string - the binary
      // reads `_Mysize` at +0x14 and picks the inline buffer or heap pointer off
      // `_Myres` at +0x18. Same reinterpret the console command family uses.
      const auto& customName = *reinterpret_cast<const fa::string*>(unit->GetCustomName());
      if (customName.empty()) {
        return InvalidScreenPoint();
      }

      CD3DFont* const font = CustomNameFont();

      // The second `GetAdvance` argument is not materialised at this call site
      // (0x0085E196 sets up only the string); zero is the neutral flag value.
      const float textWidth = font->GetAdvance(customName.c_str(), 0);
      const float lineHeight = font->mHeight;

      float textLeft = 0.0f;
      float textBaseline = 0.0f;
      if (IsValidScreenPoint(labelCursor)) {
        textLeft = labelCursor.X() - (textWidth * 0.5f);
        textBaseline = labelCursor.Y();
      } else {
        const Wm3::Vector2f projected = aux.mCamera->Project(
          Wm3::Vector3f(icon.mWorldX, icon.mWorldY, icon.mWorldZ), 0.0f, aux.mViewportWidth, aux.mViewportHeight, 0.0f
        );
        textLeft = projected.X() - (textWidth * 0.5f);
        textBaseline = (icon.mBlueprint->mLifeBarOffset + projected.Y()) + ui_LifebarOffset;
      }
      textBaseline += lineHeight;

      const float snappedLeft = std::floor(textLeft);
      const float snappedBaseline = std::floor(textBaseline);

      const Wm3::Vector2f shadowOrigin{snappedLeft + kLabelShadowOffset, snappedBaseline + kLabelShadowOffset};
      const Wm3::Vector2f textOrigin{snappedLeft, snappedBaseline};

      // The trailing glyph-scale / max-advance pair is not passed at either
      // call site - `Render2D` materialises its own axis constants on entry
      // (0x00426583..0x004265AB) - so both draws use the file's established
      // unscaled / unclipped defaults.
      font->Render2D(customName.c_str(), aux.mBatcher, shadowOrigin, kLabelShadowColor, 1.0f, gpg::NaN);
      font->Render2D(customName.c_str(), aux.mBatcher, textOrigin, ui_CustomNameColor, 1.0f, gpg::NaN);

      return textOrigin;
    }

    /**
     * Address: 0x0085E3A0 (FUN_0085E3A0, sub_85E3A0)
     *
     * IDA signature:
     * Wm3::Vector2f *__cdecl sub_85E3A0(Wm3::Vector2f *result, UnitIconData *icon,
     *   struct_IconAux *aux, Wm3::Vector2f *labelCursor, char isMiniMap);
     *
     * What it does:
     * Draws the space-joined list of every named selection set this unit
     * belongs to (`UserUnit::mSelectionSets`), stacked directly under the
     * custom name label, and returns where the text was placed so a
     * still-deferred label could stack under this one in turn. Returns
     * `InvalidScreenPoint()` when nothing was drawn - labels are off, this
     * is the minimap (inlined guard at 0x0085E796, byte-identical to
     * `DrawUnitCustomNameLabel`'s first early-out), or the unit belongs to
     * no selection set (`mSelectionSets.empty()`, 0x0085E3EF calls the
     * shared sentinel body directly) - which is the caller's signal to
     * leave its cursor untouched.
     *
     * Positioning mirrors `DrawUnitCustomNameLabel` exactly: centred on
     * `labelCursor` when the bar/name pass gave it one, otherwise projected
     * from the unit itself through `aux.mCamera->Project` plus the
     * blueprint and console lifebar offsets (0x0085E415..0x0085E48A is the
     * same `viewProjection`-matrix `Project` math, confirmed against
     * `GeomCamera3::viewProjection`'s `+0x9C` offset). Snapped to whole
     * pixels and drawn twice, an opaque black shadow copy one pixel
     * down-right first, same as the custom name label.
     *
     * The joined string is built by walking `unit->mSelectionSets` in its
     * own key order (`fa::set<fa::string>`'s `begin()`/`end()`/
     * `operator++`, i.e. the already-recovered `rb_increment` at
     * FUN_004DDD30 - also reached from `UserUnit::AddToSelectionSet` and
     * `cfunc_UserUnitGetSelectionSetsL`, confirming this is the same
     * `mSelectionSets` instantiation) and appending each name followed by a
     * literal space, including after the last one (0x0085E4A8..0x0085E4C5)
     * - the binary does not trim the trailing separator, so this preserves
     * that exactly rather than "fixing" it.
     */
    [[nodiscard]] Wm3::Vector2f DrawUnitSelectionSetNameLabel(
      const UnitIconData& icon,
      const StrategicIconAux& aux,
      const Wm3::Vector2f& labelCursor,
      const bool isMiniMap
    )
    {
      if (!ui_RenderSelectionSetNames || isMiniMap) {
        return InvalidScreenPoint();
      }

      // Slot 3 (`[vftable+0x0C]`), same dispatch as `DrawUnitLifebars`/
      // `DrawUnitCustomNameLabel` - relies on the lifebar loop above having
      // already proven `icon.mUnit` is a real `UserUnit` this frame, so this
      // is not re-null-checked here either (matches the binary).
      UserUnit* const unit = icon.mUnit->IsUserUnit();
      if (unit->mSelectionSets.empty()) {
        return InvalidScreenPoint();
      }

      CD3DFont* const font = CustomNameFont();

      fa::string joinedNames{};
      for (const fa::string& name : unit->mSelectionSets) {
        joinedNames.append(name.view());
        joinedNames.append(" ", 1);
      }

      // The second `GetAdvance` argument is not materialised at this call
      // site either (0x0085E491), same neutral-flag convention as
      // `DrawUnitCustomNameLabel`.
      const float textWidth = font->GetAdvance(joinedNames.c_str(), 0);
      const float lineHeight = font->mHeight;

      float textLeft = 0.0f;
      float textBaseline = 0.0f;
      if (IsValidScreenPoint(labelCursor)) {
        textLeft = labelCursor.X() - (textWidth * 0.5f);
        textBaseline = labelCursor.Y();
      } else {
        const Wm3::Vector2f projected = aux.mCamera->Project(
          Wm3::Vector3f(icon.mWorldX, icon.mWorldY, icon.mWorldZ), 0.0f, aux.mViewportWidth, aux.mViewportHeight, 0.0f
        );
        textLeft = projected.X() - (textWidth * 0.5f);
        textBaseline = (icon.mBlueprint->mLifeBarOffset + projected.Y()) + ui_LifebarOffset;
      }
      textBaseline += lineHeight;

      const float snappedLeft = std::floor(textLeft);
      const float snappedBaseline = std::floor(textBaseline);

      const Wm3::Vector2f shadowOrigin{snappedLeft + kLabelShadowOffset, snappedBaseline + kLabelShadowOffset};
      const Wm3::Vector2f textOrigin{snappedLeft, snappedBaseline};

      font->Render2D(joinedNames.c_str(), aux.mBatcher, shadowOrigin, kLabelShadowColor, 1.0f, gpg::NaN);
      font->Render2D(joinedNames.c_str(), aux.mBatcher, textOrigin, ui_SelectionSetNamesColor, 1.0f, gpg::NaN);

      return textOrigin;
    }

    /**
     * Draws one centered, screen-aligned strategic-icon quad sized to
     * `texture`'s own pixel dimensions (halved to radii). `RenderUnitIcon`
     * repeats this exact corner-building shape at all four of its
     * quad-draw sites - 0x0085DC96 (identified underlay), 0x0085DDAA (base
     * icon), 0x0085DEA7 (paused overlay), 0x0085DFA3 (stunned overlay) -
     * each computing `texture->mWidth >> 1` / `mHeight >> 1` then the same
     * four corners, so it is lifted here once instead of four times. The
     * radii are scaled by `ui_StrategicIconScale` (FAF FA-Binary-Patches #147).
     */
    void DrawStrategicIconQuad(
      CD3DPrimBatcher& primBatcher,
      const float centerX,
      const float centerY,
      const CD3DBatchTexture& texture,
      const std::uint32_t color
    )
    {
      // FAF FA-Binary-Patches #147 (Scale projectile/deposit/strategic icons): radii times
      // `ui_StrategicIconScale` at all four quad sites (0x0085DCA4, 0x0085DDB6, 0x0085DEB3, 0x0085DFAF).
      const float halfWidth = static_cast<float>(texture.mWidth >> 1) * ui_StrategicIconScale;
      const float halfHeight = static_cast<float>(texture.mHeight >> 1) * ui_StrategicIconScale;

      primBatcher.DrawQuad(
        Wm3::Vector3f(centerX - halfWidth, centerY - halfHeight, 0.0f),
        Wm3::Vector3f(centerX + halfWidth, centerY - halfHeight, 0.0f),
        Wm3::Vector3f(centerX + halfWidth, centerY + halfHeight, 0.0f),
        Wm3::Vector3f(centerX - halfWidth, centerY + halfHeight, 0.0f),
        color
      );
    }

    /**
     * Address: 0x0085DBD9..0x0085DC02 (inline in FUN_0085D9A0)
     *
     * What it does:
     * Halves an ARGB color's R/G/B channels while leaving alpha untouched:
     * each channel's top 7 bits (`channel >> 1`) are repacked into the same
     * byte position with the low bit cleared. Used to darken a strategic
     * icon's tint for units whose intel carries bit 0x40.
     */
    [[nodiscard]] std::uint32_t DarkenRgbPreserveAlpha(
      const std::uint32_t argb
    )
    {
      const std::uint32_t alpha = argb & 0xFF000000u;
      const std::uint32_t red = ((argb >> 16) & 0xFFu) >> 1;
      const std::uint32_t green = ((argb >> 8) & 0xFFu) >> 1;
      const std::uint32_t blue = (argb & 0xFFu) >> 1;
      return alpha | (red << 16) | (green << 8) | blue;
    }

    /**
     * Engine addition: everything `RenderUnitIcon` decides before it touches the batcher - the
     * floored screen point, the resolved tint, whether the icon blinks off this frame and whether
     * the identified underlay goes under it. A pure read of the icon and `aux`, so the placements
     * of a whole run can be computed on workers and then drawn in order.
     */
    struct UnitIconPlacement
    {
      float mScreenX = 0.0f;
      float mScreenY = 0.0f;
      std::uint32_t mColor = 0u;
      bool mVisible = true;
      /// The identified underlay to draw under the icon, or null (the entity's own handle).
      const boost::shared_ptr<CD3DBatchTexture>* mUnderlay = nullptr;
    };

    [[nodiscard]] UnitIconPlacement PlaceUnitIcon(
      const UnitIconData& icon,
      const StrategicIconAux& aux
    )
    {
      UnitIconPlacement placement{};

      const Wm3::Vector2f screenPoint = aux.mCamera->Project(
        Wm3::Vector3f(icon.mWorldX, icon.mWorldY, icon.mWorldZ), 0.0f, aux.mViewportWidth, aux.mViewportHeight, 0.0f
      );
      placement.mScreenX = std::floor(screenPoint.X());
      placement.mScreenY = std::floor(screenPoint.Y());

      const UserUnit* const asUnit = icon.mUnit->IsUserUnit();

      // Same bit `PickUnitStrategicIconTexture` names `kHasBlueprintIconDataMask`
      // on `mIntelStateFlags` ("has-data"); re-declared locally for the same
      // file-private-constant reason noted there.
      constexpr std::uint32_t kHasBlueprintIconDataMask = 0x10u;
      const bool hasIdentifiedOwner = asUnit == nullptr || (asUnit->mIntelStateFlags & kHasBlueprintIconDataMask) != 0u;

      std::uint32_t iconColor;
      if (hasIdentifiedOwner) {
        if (aux.mSession->mTeamColorMode && aux.mSession->GetFocusArmy() != nullptr) {
          iconColor = teamcolors[static_cast<std::size_t>(icon.mUnit->mArmy->mArmyIndex)];
        } else {
          iconColor = icon.mUnit->mArmy->mVarDat.mPlayerColorBgra;
        }
      } else {
        iconColor = aux.mUnidentifiedColor;
      }

      if (icon.mIsFormationGhost) {
        iconColor &= 0x7FFFFFFFu;
      } else {
        constexpr std::uint32_t kDarkenedTintMask = 0x40u;
        if (asUnit != nullptr && (asUnit->mIntelStateFlags & kDarkenedTintMask) != 0u) {
          iconColor = DarkenRgbPreserveAlpha(iconColor);
        }

        if (icon.mIsFriendly) {
          const std::int32_t lastFocusDamageTick = icon.mUnit->mLastFocusDamageGameTick;
          if (lastFocusDamageTick != 0) {
            // `* 10.0f`: 0x0085DC2A.
            constexpr float kBlinkDurationTickScale = 10.0f;
            const float ticksSinceDamage = static_cast<float>(aux.mSession->mGameTick - lastFocusDamageTick);
            if ((ui_StrategicIconBlinkDuration * kBlinkDurationTickScale) > ticksSinceDamage) {
              const double simTime =
                static_cast<double>(aux.mSession->mGameTick) + static_cast<double>(aux.mTickFraction);
              const double blinkPhase = std::fmod(simTime * static_cast<double>(ui_StrategicIconBlinkRate), 1.0);
              if (blinkPhase <= 0.5) {
                placement.mVisible = false;
                return placement;
              }
            }
          }
        }

        // `UserEntity::GetStrategicUnderlayTexture` returns a copy of this handle; the draw only
        // needs to read it.
        const boost::shared_ptr<CD3DBatchTexture>& underlay = icon.mUnit->mVariableData.mUnderlayTexture;
        if (hasIdentifiedOwner && underlay) {
          placement.mUnderlay = &underlay;
        }
      }

      placement.mColor = iconColor;
      return placement;
    }

    /**
     * Engine addition: the batcher half of `RenderUnitIcon` - the quad stack it draws at `placement`,
     * in its order: identified underlay, base icon (tinted), paused overlay, stunned overlay. Each
     * quad goes to `drawQuad(texture, centerX, centerY, color)`.
     */
    template <class DrawQuad>
    void EmitUnitIconQuads(
      const UnitIconData& icon,
      const UnitIconPlacement& placement,
      DrawQuad&& drawQuad
    )
    {
      constexpr std::uint32_t kOverlayNoTintColor = 0xFFFFFFFFu;

      if (!placement.mVisible) {
        return;
      }

      const float screenX = placement.mScreenX;
      const float screenY = placement.mScreenY;

      if (placement.mUnderlay != nullptr) {
        drawQuad(*placement.mUnderlay, screenX, screenY, kOverlayNoTintColor);
      }

      if (!icon.mSuppressBaseIcon) {
        drawQuad(icon.mIconTexture, screenX, screenY, placement.mColor);
      }

      if (icon.mShowPausedOverlay && icon.mPausedTexture) {
        drawQuad(icon.mPausedTexture, screenX, screenY, kOverlayNoTintColor);
      }

      if (icon.mShowStunnedOverlay && icon.mStunnedTexture) {
        drawQuad(icon.mStunnedTexture, screenX, screenY, kOverlayNoTintColor);
      }
    }

    /// Engine addition: `EmitUnitIconQuads` straight into the batcher, one `SetTexture` per quad.
    void EmitUnitIcon(
      const UnitIconData& icon,
      const UnitIconPlacement& placement,
      const StrategicIconAux& aux
    )
    {
      EmitUnitIconQuads(
        icon,
        placement,
        [&](
          const boost::shared_ptr<CD3DBatchTexture>& texture, const float x, const float y, const std::uint32_t color
        ) {
        aux.mBatcher->SetTexture(texture);
        DrawStrategicIconQuad(*aux.mBatcher, x, y, *texture, color);
      }
      );
    }

    /**
     * Engine addition (`ui_ParallelIcons`): the icon emit of the parallel path. Quads collect while
     * the texture stays the same and go to the batcher in one `DrawScreenQuads` call when it
     * changes. A `SetTexture` that repeats the texture set last is skipped: the batcher would look
     * the same texture up again and end in the same state (a flush keeps the atlas and the UV
     * lanes). The batcher receives the same textures, vertices and flushes in the same order as
     * from one `DrawQuad` per quad.
     */
    class StrategicIconBulkEmitter
    {
    public:
      StrategicIconBulkEmitter(
        CD3DPrimBatcher& batcher,
        std::vector<CD3DPrimBatcher::ScreenQuad>& pending
      )
        : mBatcher(batcher)
        , mPending(pending)
      {
        mPending.clear();
      }

      ~StrategicIconBulkEmitter()
      {
        Submit();
      }

      void operator()(
        const boost::shared_ptr<CD3DBatchTexture>& texture,
        const float centerX,
        const float centerY,
        const std::uint32_t color
      )
      {
        if (texture.get() != mLastTexture) {
          Submit();
          mBatcher.SetTexture(texture);
          mLastTexture = texture.get();
        }

        // `DrawStrategicIconQuad`'s corners, scaled the same way (FAF FA-Binary-Patches #147).
        const float halfWidth = static_cast<float>(texture->mWidth >> 1) * ui_StrategicIconScale;
        const float halfHeight = static_cast<float>(texture->mHeight >> 1) * ui_StrategicIconScale;
        mPending.push_back(
          CD3DPrimBatcher::ScreenQuad{
            centerX - halfWidth, centerY - halfHeight, centerX + halfWidth, centerY + halfHeight, color
          }
        );
      }

    private:
      void Submit()
      {
        if (!mPending.empty()) {
          mBatcher.DrawScreenQuads(mPending.data(), mPending.size());
          mPending.clear();
        }
      }

      CD3DPrimBatcher& mBatcher;
      std::vector<CD3DPrimBatcher::ScreenQuad>& mPending;
      const CD3DBatchTexture* mLastTexture = nullptr;
    };

    /**
     * Engine addition (`ren_GpuIcons`): the GPU record of one placed icon - its floored screen
     * point, tint, and the atlas slot of each quad `EmitUnitIconQuads` would draw, in its order
     * (underlay, base, paused, stunned). `slotOf(texture)` names the slot; a layer whose slot it
     * cannot name is left empty and the function returns false, so the caller can rebuild that
     * record once the slot exists.
     */
    template <class SlotOf>
    [[nodiscard]] bool BuildStrategicIconRecord(
      const StrategicIconCandidate& candidate,
      const StrategicIconAux& aux,
      const UnitIconPlacement& placement,
      SlotOf&& slotOf,
      StrategicIconInstance& record
    )
    {
      record = StrategicIconInstance{};
      if (!placement.mVisible) {
        return true;
      }
      record.SetPosition(placement.mScreenX, placement.mScreenY);
      record.mColor = placement.mColor;

      // The textures `StoreStrategicIcon` would attach: the picked icon, and the paused and
      // stunned rest textures when the flags ask for them.
      const UnitIconData& icon = candidate.mData;
      const boost::shared_ptr<CD3DBatchTexture>* layers[StrategicIconInstance::kLayerCount] = {
        placement.mUnderlay,
        icon.mSuppressBaseIcon ? nullptr : candidate.mIcon,
        (icon.mShowPausedOverlay && aux.mPauseRestTexture) ? &aux.mPauseRestTexture : nullptr,
        (icon.mShowStunnedOverlay && aux.mStunnedRestTexture) ? &aux.mStunnedRestTexture : nullptr,
      };
      bool complete = true;
      for (std::uint32_t layer = 0U; layer < StrategicIconInstance::kLayerCount; ++layer) {
        if (layers[layer] == nullptr || !*layers[layer]) {
          continue;
        }
        const std::uint16_t slot = slotOf(*layers[layer]);
        if (slot == StrategicIconInstance::kNoLayer) {
          complete = false;
        }
        record.SetLayer(layer, slot);
      }
      return complete;
    }

    /**
     * Engine addition (`ren_GpuIcons`): phase 3.5 through `StrategicIconRenderer` - every icon of
     * the four runs placed (on workers for large counts) straight from its classification
     * candidate into its GPU record, records whose textures have no atlas slot yet completed on
     * this thread, then one instanced draw. `icons` holds the candidates in draw order. Returns
     * false, having drawn nothing, when the renderer declines (the caller then stores the
     * candidates and draws through the batcher).
     */
    [[nodiscard]] bool DrawStrategicIconsOnGpu(
      StrategicIconRenderer& renderer,
      const StrategicIconAux& aux,
      const void* const viewKey,
      const std::vector<const StrategicIconCandidate*>& icons
    )
    {
      const std::size_t count = icons.size();
      static std::vector<StrategicIconInstance> sRecords;
      static std::vector<UnitIconPlacement> sGpuPlacements;
      static std::vector<std::uint8_t> sIncomplete;
      sRecords.resize(count);
      sGpuPlacements.resize(count);
      sIncomplete.assign(count, 0U);

      const auto findSlot = [&renderer](const boost::shared_ptr<CD3DBatchTexture>& texture) {
        return renderer.FindSlot(texture.get());
      };
      const auto build = [&](const std::size_t begin, const std::size_t end) {
        for (std::size_t i = begin; i < end; ++i) {
          sGpuPlacements[i] = PlaceUnitIcon(icons[i]->mData, aux);
          if (!BuildStrategicIconRecord(*icons[i], aux, sGpuPlacements[i], findSlot, sRecords[i])) {
            sIncomplete[i] = 1U;
          }
        }
      };
      if (UseParallelIcons(count)) {
        CUserWorkerPool::Get().ParallelFor(count, kParallelIconChunk, build);
      } else {
        build(0U, count);
      }

      // Textures seen for the first time get their slot here, on this thread.
      const auto addSlot = [&renderer](const boost::shared_ptr<CD3DBatchTexture>& texture) {
        return renderer.AddSlot(texture);
      };
      for (std::size_t i = 0; i < count; ++i) {
        if (sIncomplete[i] != 0U) {
          (void)BuildStrategicIconRecord(*icons[i], aux, sGpuPlacements[i], addSlot, sRecords[i]);
        }
      }
      return renderer.Draw(*aux.mBatcher, viewKey, std::span<const StrategicIconInstance>(sRecords.data(), count));
    }

    /**
     * Address: 0x0085D9A0 (FUN_0085D9A0, RenderUnitIcon)
     *
     * IDA signature:
     * void __cdecl RenderUnitIcon(struct_UnitIconData *a1, struct_IconAux *a2);
     *
     * What it does:
     * Draws one classified unit's strategic-icon quads. Called once per icon
     * collected into `StrategicIconAux`'s ground/air/high-priority/
     * selected runs by `RenderStrategicIcons`.
     *
     * Projects the icon's world position through the camera to a floored
     * screen point, then resolves a display color: when the unit is either
     * not a real `UserUnit` or its intel carries full blueprint data
     * (`mIntelStateFlags` bit 0x10, the same bit `PickUnitStrategicIconTexture`
     * already names), the icon's owning army's real color - `teamcolors[]`
     * in team-color mode with a focus army active, else the army's own
     * `mVarDat.mPlayerColorBgra`; otherwise the flat `aux.mUnidentifiedColor`
     * placeholder.
     *
     * A formation-preview ghost (`mIsFormationGhost`) short-circuits
     * straight to the quad stack below with that color's sign/alpha-high
     * bit cleared (`& 0x7FFFFFFF`) instead of team-colored, skipping
     * everything else in this function - no darken check, no blink gate, no
     * identified-icon draw. Otherwise, a unit whose intel carries bit 0x40
     * gets its color darkened (`DarkenRgbPreserveAlpha`).
     *
     * A friendly unit (`mIsFriendly`) that was damaged while under the local
     * player's focus within the last `ui_StrategicIconBlinkDuration * 10`
     * ticks (`UserEntity::mLastFocusDamageGameTick`) blinks: on the "off"
     * half of the `ui_StrategicIconBlinkRate` cycle the function returns
     * without drawing anything at all for this icon this frame.
     *
     * When an owning army was resolved, the unit's own strategic-underlay
     * texture (`UserEntity::GetStrategicUnderlayTexture`, itself the
     * recovered form of the `WeakPtr_CD3DBatchTexture` constructor this
     * function calls at 0x0085DC74) draws first, at full opacity with no
     * additional tint. Finally the shared quad stack draws the base icon
     * (unless `mSuppressBaseIcon`), then the paused and stunned overlay
     * badges when present - only the base icon is tinted with the
     * resolved/darkened color; the underlay and both overlays draw at their
     * own native texture color.
     */
    void RenderUnitIcon(
      const UnitIconData& icon,
      const StrategicIconAux& aux
    )
    {
      EmitUnitIcon(icon, PlaceUnitIcon(icon, aux), aux);
    }
    /**
     * Engine diagnostics (`ui_IconRecords`): with FAF_ICON_RECORDS_CHECK=1 in the environment,
     * every frame classifies the in-view list both ways - from the units, as the original pass,
     * and from the records - and compares what each stores (run, unit, position bits, flags,
     * texture), logging the totals every 300 calls and the first few differences.
     */
    template <class FromUnits, class FromRecords>
    void VerifyStrategicIconSources(
      const std::size_t count,
      FromUnits&& fromUnits,
      FromRecords&& fromRecords
    )
    {
      static const bool sEnabled = [] {
        char value[8] = {};
        std::size_t length = 0u;
        return ::getenv_s(&length, value, sizeof(value), "FAF_ICON_RECORDS_CHECK") == 0 && length != 0u &&
          value[0] == '1';
      }();
      if (!sEnabled) {
        return;
      }
      struct Stored
      {
        EStrategicIconRun mRun;
        const UserEntity* mUnit;
        float mX, mY, mZ;
        std::uint8_t mFlags;
        const CD3DBatchTexture* mTexture;
        [[nodiscard]] bool operator==(
          const Stored& other
        ) const noexcept
        {
          return mRun == other.mRun && mUnit == other.mUnit && std::memcmp(&mX, &other.mX, sizeof(float) * 3u) == 0 &&
            mFlags == other.mFlags && mTexture == other.mTexture;
        }
      };
      static std::vector<Stored> sA;
      static std::vector<Stored> sB;
      static std::uint64_t sCalls = 0u;
      static std::uint64_t sCompared = 0u;
      static std::uint64_t sMismatches = 0u;
      static int sReported = 0;
      const auto recorder = [](std::vector<Stored>& out) {
        return
          [&out](
            const EStrategicIconRun run, const UnitIconData& data, const boost::shared_ptr<CD3DBatchTexture>* const icon
          ) {
          out.push_back(
            Stored{
              run,
              data.mUnit,
              data.mWorldX,
              data.mWorldY,
              data.mWorldZ,
              static_cast<std::uint8_t>(
                data.mIsFriendly | (data.mShowPausedOverlay << 1) | (data.mShowStunnedOverlay << 2) |
                (data.mSuppressBaseIcon << 3)
              ),
              icon != nullptr ? icon->get() : nullptr
            }
          );
        };
      };
      for (std::size_t i = 0; i < count; ++i) {
        sA.clear();
        sB.clear();
        fromUnits(i, recorder(sA));
        fromRecords(i, recorder(sB));
        ++sCompared;
        if (sA != sB) {
          ++sMismatches;
          if (sReported < 8) {
            ++sReported;
            gpg::Warnf(
              "icon record check: entry %zu differs (units stored %zu, records stored %zu; first run %d/%d, pos "
              "%g,%g,%g / %g,%g,%g)",
              i,
              sA.size(),
              sB.size(),
              sA.empty() ? -1 : static_cast<int>(sA[0].mRun),
              sB.empty() ? -1 : static_cast<int>(sB[0].mRun),
              sA.empty() ? 0.0 : sA[0].mX,
              sA.empty() ? 0.0 : sA[0].mY,
              sA.empty() ? 0.0 : sA[0].mZ,
              sB.empty() ? 0.0 : sB[0].mX,
              sB.empty() ? 0.0 : sB[0].mY,
              sB.empty() ? 0.0 : sB[0].mZ
            );
          }
        }
      }
      if (++sCalls % 300u == 0u) {
        gpg::Logf("icon record check: %llu entries compared, %llu differ", sCompared, sMismatches);
      }
    }

    /**
     * Engine diagnostics (`ren_GpuIconClassify`): with FAF_ICON_GPU_CHECK=<n> in the environment,
     * every n-th GPU-classified draw of a view also classifies that frame on the CPU, builds the
     * records the CPU path would draw, reads back what the GPU drew, and compares the two - count
     * and every record, bit for bit. Returns 0 when off.
     */
    [[nodiscard]] std::uint32_t StrategicIconGpuCheckInterval()
    {
      static const std::uint32_t sInterval = [] {
        char value[16] = {};
        std::size_t length = 0u;
        if (::getenv_s(&length, value, sizeof(value), "FAF_ICON_GPU_CHECK") != 0 || length == 0u) {
          return 0u;
        }
        return static_cast<std::uint32_t>(std::max(0, std::atoi(value)));
      }();
      return sInterval;
    }

    void CompareClassifiedStrategicIcons(
      const std::vector<StrategicIconInstance>& expected,
      const std::vector<StrategicIconInstance>& drawn,
      const bool miniMap
    )
    {
      static std::uint64_t sChecks = 0u;
      static std::uint64_t sMiniMapChecks = 0u;
      static std::uint64_t sRecords = 0u;
      static std::uint64_t sDiffering = 0u;
      static std::uint64_t sCountMismatches = 0u;
      static int sReported = 0;
      ++sChecks;
      if (miniMap) {
        ++sMiniMapChecks;
      }
      if (expected.size() != drawn.size()) {
        ++sCountMismatches;
      }
      const std::size_t common = std::min(expected.size(), drawn.size());
      std::size_t differing = 0u;
      for (std::size_t i = 0; i < common; ++i) {
        if (std::memcmp(&expected[i], &drawn[i], sizeof(StrategicIconInstance)) == 0) {
          continue;
        }
        ++differing;
        if (sReported < 16) {
          ++sReported;
          const StrategicIconInstance& a = expected[i];
          const StrategicIconInstance& b = drawn[i];
          gpg::Warnf(
            "icon GPU check (%s): record %zu differs: cpu {pos %08X color %08X layers %08X %08X} gpu {pos %08X color "
            "%08X layers %08X %08X}",
            miniMap ? "minimap" : "view",
            i,
            a.mPosition,
            a.mColor,
            a.mLayers01,
            a.mLayers23,
            b.mPosition,
            b.mColor,
            b.mLayers01,
            b.mLayers23
          );
        }
      }
      sRecords += common;
      sDiffering += differing;
      if (expected.size() != drawn.size() || differing != 0u || sChecks % 20u == 0u) {
        gpg::Logf(
          "icon GPU check (%s): %zu records on the CPU, %zu drawn by the GPU, %zu differ; totals: %llu checks (%llu "
          "minimap), "
          "%llu records, %llu differ, %llu count mismatches",
          miniMap ? "minimap" : "view",
          expected.size(),
          drawn.size(),
          differing,
          sChecks,
          sMiniMapChecks,
          sRecords,
          sDiffering,
          sCountMismatches
        );
      }
    }
  } // namespace

  namespace
  {
    /**
     * One frame of `CWldSession::RenderStrategicIcons`: what its phases share. Lives for that call.
     */
    struct StrategicIconFrame
    {
      CWldSession& session;
      StrategicIconAux& aux;
      CameraImpl* const camera;
      const GeomCamera3& view;
      CD3DPrimBatcher* const primBatcher;
      const float tickFraction;
      const bool isMiniMap;
      const bool showAttachedUnitLifebars;
      const float currentZoomValue;
      UserArmy* const focusArmy;
      gpg::core::FastVectorInline<WeakPtr<UserEntity>>& frustumUnits;
      const std::size_t frustumUnitCount;
      StrategicIconRenderer& gpuIcons;
      const UserEntity* const hoveredEntity;
      const float maxZoomFade;
      const bool classifyOnGpu;
      const StrategicIconSource* iconSources = nullptr;
      StrategicIconSourceSet* activeSourceSet = nullptr;

      // Engine addition (`ui_ParallelIcons`): the classification below reads each entity and writes
      // only that entity's interpolation cache and its own icon record, so chunks of the frustum list
      // run on CUserWorkerPool and are merged back in list order, which keeps every run - and so the
      // draw order - exactly as the serial walk builds it.
      template <class Store>
      void Classify(
        const WeakPtr<UserEntity>& ref,
        Store&& store
      )
      {
        UserEntity* const entity = ref.GetObjectPtr();
        if (entity == nullptr || entity->mVariableData.mIsDead) {
          return;
        }

        UserUnit* const asUnit = entity->IsUserUnit();

        // `mIntelStateFlags` bit 0x20: this unit renders through some other
        // path already and its strategic icon is suppressed outright
        // (`(v26->mSelectionMaskUsed & 0x20) == 0` gates entry at 0x0085BAC3).
        constexpr std::uint32_t kStrategicIconEntitySuppressedMask = 0x20u;
        if (asUnit != nullptr && (asUnit->mIntelStateFlags & kStrategicIconEntitySuppressedMask) != 0u) {
          return;
        }

        // Planned factory proxies skip lifebars and strategic icons:
        if (asUnit != nullptr && IsFactoryPreOrdersEnabled() && PlannedFactoryManager::Get().IsPlannedProxyUnit(asUnit)) {
          return;
        }

        const REntityBlueprint* const blueprint = entity->mParams.mBlueprint;
        if (blueprint == nullptr || blueprint->mStrategicIconName.empty()) {
          return;
        }

        UnitIconData iconData{};
        iconData.mUnit = entity;
        iconData.mBlueprint = blueprint;

        const VTransform interpolated = entity->GetInterpolatedTransform(tickFraction);
        iconData.mWorldX = interpolated.pos_.x;
        iconData.mWorldY = interpolated.pos_.y;
        iconData.mWorldZ = interpolated.pos_.z;

        // `mIntelStateFlags` bit 0x08 ("health-valid") / bit 0x10
        // ("has-data"): both default true for non-`UserUnit` entities
        // (wrecks, props, ...), matching `isBusy_60`/`v49`'s init at
        // 0x0085BB60..0x0085BB74.
        constexpr std::uint32_t kIntelHealthValidMask = 0x08u;
        constexpr std::uint32_t kHasBlueprintIconDataMask = 0x10u;
        const bool selectedVariantEligible =
          asUnit == nullptr || (asUnit->mIntelStateFlags & kIntelHealthValidMask) != 0u;
        const bool hasFullBlueprintIconData =
          asUnit == nullptr || (asUnit->mIntelStateFlags & kHasBlueprintIconDataMask) != 0u;

        iconData.mIsFriendly =
          focusArmy == nullptr || focusArmy->IsAlly(static_cast<std::uint32_t>(entity->mArmy->mArmyIndex));

        iconData.mShowStunnedOverlay = asUnit != nullptr && asUnit->mUnitVarDat.mStunTicks != 0;
        if (iconData.mIsFriendly && asUnit != nullptr) {
          const std::uint32_t toggleCaps = asUnit->GetAttributes().toggleCapsMask;
          // Script-bit indices from 0x0085BE51..0x0085BEFA. Shield uses
          // the opposite polarity; weapon and special toggles are excluded.
          iconData.mShowPausedOverlay = ((toggleCaps & RULEUTC_ShieldToggle) != 0u && !asUnit->HasScriptBit(0)) ||
            ((toggleCaps & RULEUTC_JammingToggle) != 0u && asUnit->HasScriptBit(2)) ||
            ((toggleCaps & RULEUTC_IntelToggle) != 0u && asUnit->HasScriptBit(3)) ||
            ((toggleCaps & RULEUTC_ProductionToggle) != 0u && asUnit->HasScriptBit(4)) ||
            ((toggleCaps & RULEUTC_StealthToggle) != 0u && asUnit->HasScriptBit(5)) ||
            ((toggleCaps & RULEUTC_GenericToggle) != 0u && asUnit->HasScriptBit(6)) ||
            ((toggleCaps & RULEUTC_CloakToggle) != 0u && asUnit->HasScriptBit(8)) || asUnit->mUnitVarDat.mIsPaused;
        }

        if (focusArmy == nullptr || entity->mArmy == focusArmy) {
          if (
            session.mWldMap != nullptr && session.mWldMap->mTerrainRes != nullptr &&
            !session.mWldMap->mTerrainRes->IsInPlayableRect(interpolated.pos_)
          ) {
            return;
          }
        }

        if (iconData.mIsFriendly) {
          UserEntity* const attachmentParent = entity->GetAttachmentParent();
          if (attachmentParent != nullptr && attachmentParent->IsInCategory(fa::string("CARRIER"))) {
            return;
          }
        } else if (asUnit != nullptr && asUnit->mUnitVarDat.mIsBusy && asUnit->GetBlueprint()->Air.CanFly) {
          return;
        }

        // --- Lifebar collection gate (0x0085BFDB..0x0085C09F) -------------
        // The one producer of `mLifebarIcons`. Everything below is read in the
        // binary's own order; each early-out lands on the same 0x0085C0A4
        // continue as the icon test that follows.
        if (
          ui_RenderUnitBars && ui_LifebarLOD > currentZoomValue && !entity->mVariableData.mIsDead &&
          blueprint->mLifeBarRender != 0
        ) {
          // Enemy units only get bars when their health is actually known
          // (`selectedVariantEligible`, intel bit 0x08), and then only if the
          // player forced enemy bars on or is hovering this unit. Friendly units
          // skip all three tests.
          bool eligible = iconData.mIsFriendly;
          if (!eligible && selectedVariantEligible) {
            eligible = ui_ForceLifbarsOnEnemy || entity == session.GetHoveredUserEntity();
          }

          if (eligible && asUnit != nullptr) {
            // A unit mid-upgrade is drawn by the upgrade progress UI instead
            // (slot 15, dispatched with `push 25h` at 0x0085C06B).
            const IUnit* const unitBridge = GetIUnitBridge(asUnit);
            const bool attachedAndHidden = !showAttachedUnitLifebars && asUnit->mUnitVarDat.mIsBusy;
            if (
              !unitBridge->IsUnitState(UNITSTATE_BeingUpgraded) && !attachedAndHidden &&
              unitBridge->GetBlueprint()->Display.HideLifebars == 0
            ) {
              store(EStrategicIconRun::Lifebar, iconData, nullptr);
            }
          }
        }

        if (!ui_NisRenderIcons || (!ui_RenderIcons && !iconData.mShowPausedOverlay) || entity->IsBeingBuilt()) {
          return;
        }

        // When the unit's own mesh is already close enough to be visible
        // without help, skip the icon entirely for units that have full
        // intel data (or belong to an immobile blueprint under a focus
        // army) and aren't paused - everyone else still gets an icon.
        const bool skipWhenMeshVisible =
          (hasFullBlueprintIconData || (focusArmy != nullptr && !blueprint->IsMobile())) &&
          !iconData.mShowPausedOverlay;

        const RMeshBlueprint* const mesh = entity->mVariableData.mMeshBlueprint;
        if (mesh != nullptr && !ui_AlwaysRenderStrategicIcons) {
          const float fadeThreshold = std::min(mesh->mIconFadeInZoom, camera->GetMaxZoom() * 0.89f);
          if (fadeThreshold > currentZoomValue) {
            if (skipWhenMeshVisible) {
              return;
            }
            iconData.mSuppressBaseIcon = iconData.mShowPausedOverlay || iconData.mShowStunnedOverlay;
          }
        }

        const bool isHovered = entity == session.GetHoveredUserEntity();

        const bool isSelected = session.mSelection.Find(entity) != session.mSelection.end();

        // The texture handles are attached where the record is stored (`StoreStrategicIcon`).
        const boost::shared_ptr<CD3DBatchTexture>& icon =
          PickUnitStrategicIconTexture(aux, iconData, isSelected, selectedVariantEligible, isHovered);
        if (!icon) {
          return;
        }

        // 0x0085C262..0x0085C28E: the hovered unit goes to the one hovered slot, not to a run.
        if (isHovered) {
          store(EStrategicIconRun::Hovered, iconData, &icon);
          return;
        }

        if (isSelected) {
          store(EStrategicIconRun::Selected, iconData, &icon);
          return;
        }

        // Sort-priority byte < 'A' always wins the high-priority run
        // (0x0085C2C0..0x0085C2C7). At/above 'A' the binary default-
        // constructs a `WeakPtr_CD3DBatchTexture` and tests it - a
        // no-argument constructor is unconditionally empty, so that branch
        // is provably always false and always falls through to ground/air.
        if (blueprint->mStrategicIconSortPriority < static_cast<std::uint8_t>('A')) {
          store(EStrategicIconRun::HighPriority, iconData, &icon);
          return;
        }

        if (asUnit != nullptr && asUnit->GetBlueprint()->Air.CanFly) {
          store(EStrategicIconRun::Air, iconData, &icon);
        } else {
          store(EStrategicIconRun::Ground, iconData, &icon);
        }
      }

      // Engine addition (`ui_IconRecords`): `classify` split in two. `describe` reads, once per
      // entry of the in-view list, every input that only the sync apply changes; the records stay
      // valid until a beat is applied, the list is rebuilt or the focus army changes (all on this
      // thread, before rendering). `classifySource` then does `classify`'s per-frame work from the
      // record, with the same tests in the same order.
      void Describe(
        const WeakPtr<UserEntity>& ref,
        StrategicIconSource& source
      )
      {
        source = StrategicIconSource{};
        UserEntity* const entity = ref.GetObjectPtr();
        if (entity == nullptr || entity->mVariableData.mIsDead) {
          return;
        }
        UserUnit* const asUnit = entity->IsUserUnit();
        constexpr std::uint32_t kStrategicIconEntitySuppressedMask = 0x20u;
        if (asUnit != nullptr && (asUnit->mIntelStateFlags & kStrategicIconEntitySuppressedMask) != 0u) {
          return;
        }
        const REntityBlueprint* const blueprint = entity->mParams.mBlueprint;
        if (blueprint == nullptr || blueprint->mStrategicIconName.empty()) {
          return;
        }

        constexpr std::uint32_t kIntelHealthValidMask = 0x08u;
        constexpr std::uint32_t kHasBlueprintIconDataMask = 0x10u;
        const bool selectedVariantEligible =
          asUnit == nullptr || (asUnit->mIntelStateFlags & kIntelHealthValidMask) != 0u;
        const bool hasFullBlueprintIconData =
          asUnit == nullptr || (asUnit->mIntelStateFlags & kHasBlueprintIconDataMask) != 0u;
        const bool friendly =
          focusArmy == nullptr || focusArmy->IsAlly(static_cast<std::uint32_t>(entity->mArmy->mArmyIndex));

        // `classify`'s two unconditional early-outs that read only beat data.
        if (friendly) {
          UserEntity* const attachmentParent = entity->GetAttachmentParent();
          if (attachmentParent != nullptr && attachmentParent->IsInCategory(fa::string("CARRIER"))) {
            return;
          }
        } else if (asUnit != nullptr && asUnit->mUnitVarDat.mIsBusy && asUnit->GetBlueprint()->Air.CanFly) {
          return;
        }

        bool paused = false;
        if (friendly && asUnit != nullptr) {
          const std::uint32_t toggleCaps = asUnit->GetAttributes().toggleCapsMask;
          paused = ((toggleCaps & RULEUTC_ShieldToggle) != 0u && !asUnit->HasScriptBit(0)) ||
            ((toggleCaps & RULEUTC_JammingToggle) != 0u && asUnit->HasScriptBit(2)) ||
            ((toggleCaps & RULEUTC_IntelToggle) != 0u && asUnit->HasScriptBit(3)) ||
            ((toggleCaps & RULEUTC_ProductionToggle) != 0u && asUnit->HasScriptBit(4)) ||
            ((toggleCaps & RULEUTC_StealthToggle) != 0u && asUnit->HasScriptBit(5)) ||
            ((toggleCaps & RULEUTC_GenericToggle) != 0u && asUnit->HasScriptBit(6)) ||
            ((toggleCaps & RULEUTC_CloakToggle) != 0u && asUnit->HasScriptBit(8)) || asUnit->mUnitVarDat.mIsPaused;
        }

        std::uint16_t flags = 0U;
        const auto set = [&flags](const bool condition, const StrategicIconSource::Flags flag) {
          if (condition) {
            flags = static_cast<std::uint16_t>(flags | flag);
          }
        };
        set(friendly, StrategicIconSource::kFriendly);
        set(asUnit != nullptr && asUnit->mUnitVarDat.mStunTicks != 0, StrategicIconSource::kStunned);
        set(paused, StrategicIconSource::kPaused);
        set(focusArmy == nullptr || entity->mArmy == focusArmy, StrategicIconSource::kCheckPlayableRect);
        set(selectedVariantEligible, StrategicIconSource::kSelectedVariantEligible);
        set(blueprint->mLifeBarRender != 0, StrategicIconSource::kLifebarBlueprint);
        if (asUnit != nullptr) {
          const IUnit* const unitBridge = GetIUnitBridge(asUnit);
          set(
            !unitBridge->IsUnitState(UNITSTATE_BeingUpgraded) && unitBridge->GetBlueprint()->Display.HideLifebars == 0,
            StrategicIconSource::kLifebarUnit
          );
          set(asUnit->mUnitVarDat.mIsBusy, StrategicIconSource::kBusy);
          set(asUnit->GetBlueprint()->Air.CanFly, StrategicIconSource::kAir);
        }
        set(entity->IsBeingBuilt(), StrategicIconSource::kBeingBuilt);
        set(
          (hasFullBlueprintIconData || (focusArmy != nullptr && !blueprint->IsMobile())) && !paused,
          StrategicIconSource::kSkipWhenMeshVisible
        );
        set(blueprint->mStrategicIconSortPriority < static_cast<std::uint8_t>('A'), StrategicIconSource::kHighPriority);

        source.mEntity = entity;
        source.mBlueprint = blueprint;
        source.mMesh = entity->mVariableData.mMeshBlueprint;
        source.mLastPosition = entity->mVariableData.mLastTransform.pos_;
        source.mCurrentPosition = entity->mVariableData.mCurTransform.pos_;
        source.mImpact = entity->mVariableData.mCurImpactValue;
        source.mFlags = flags;

        // `PickUnitStrategicIconTexture` for an unhovered unit; a hovered one never gets a run.
        UnitIconData probe{};
        probe.mUnit = entity;
        probe.mBlueprint = blueprint;
        source.mIcon = &PickUnitStrategicIconTexture(aux, probe, false, selectedVariantEligible, false);
        source.mSelectedIcon = &PickUnitStrategicIconTexture(aux, probe, true, selectedVariantEligible, false);
        source.mHoveredIcon = &PickUnitStrategicIconTexture(aux, probe, false, selectedVariantEligible, true);
        source.mHoveredSelectedIcon = &PickUnitStrategicIconTexture(aux, probe, true, selectedVariantEligible, true);
      }

      // Engine addition (`ren_GpuIconClassify`): the GPU form of one record - `describe`'s flags and
      // endpoints, `PlaceUnitIcon`'s colour up to the blink test, the identified underlay, the focus
      // damage tick and the atlas slots. `FindSlot` only reads, so workers may call it; a texture
      // without a slot yet sets `needsSlot` and gets one on this thread afterwards. The selected icon
      // gets its slot when the unit is first selected.
      void DescribeGpu(
        const StrategicIconSource& source,
        StrategicIconSourceRecord& record,
        std::uint8_t& needsSlot
      )
      {
        record = StrategicIconSourceRecord{};
        needsSlot = 0U;
        UserEntity* const entity = source.mEntity;
        if (entity == nullptr) {
          return;
        }
        using Gpu = StrategicIconSourceRecord;
        std::uint32_t flags = Gpu::kValid;
        const auto map = [&](const StrategicIconSource::Flags from, const Gpu::Flags to) {
          if (source.Has(from)) {
            flags |= to;
          }
        };
        map(StrategicIconSource::kFriendly, Gpu::kFriendly);
        map(StrategicIconSource::kStunned, Gpu::kStunned);
        map(StrategicIconSource::kPaused, Gpu::kPaused);
        map(StrategicIconSource::kCheckPlayableRect, Gpu::kCheckPlayableRect);
        map(StrategicIconSource::kBeingBuilt, Gpu::kBeingBuilt);
        map(StrategicIconSource::kSkipWhenMeshVisible, Gpu::kSkipWhenMeshVisible);
        map(StrategicIconSource::kHighPriority, Gpu::kHighPriority);
        map(StrategicIconSource::kAir, Gpu::kAir);
        if (source.mMesh != nullptr) {
          flags |= Gpu::kHasMesh;
          record.mIconFadeInZoom = source.mMesh->mIconFadeInZoom;
        }
        record.mFlags = flags;
        record.mLastPosition[0] = source.mLastPosition.x;
        record.mLastPosition[1] = source.mLastPosition.y;
        record.mLastPosition[2] = source.mLastPosition.z;
        record.mCurrentPosition[0] = source.mCurrentPosition.x;
        record.mCurrentPosition[1] = source.mCurrentPosition.y;
        record.mCurrentPosition[2] = source.mCurrentPosition.z;
        record.mImpact = source.mImpact;

        // `PlaceUnitIcon`'s colour, everything before its blink test.
        const UserUnit* const asUnit = entity->IsUserUnit();
        constexpr std::uint32_t kHasBlueprintIconDataMask = 0x10u;
        constexpr std::uint32_t kDarkenedTintMask = 0x40u;
        const bool hasIdentifiedOwner =
          asUnit == nullptr || (asUnit->mIntelStateFlags & kHasBlueprintIconDataMask) != 0u;
        std::uint32_t iconColor;
        if (hasIdentifiedOwner) {
          if (session.mTeamColorMode && focusArmy != nullptr) {
            iconColor = teamcolors[static_cast<std::size_t>(entity->mArmy->mArmyIndex)];
          } else {
            iconColor = entity->mArmy->mVarDat.mPlayerColorBgra;
          }
        } else {
          iconColor = aux.mUnidentifiedColor;
        }
        if (asUnit != nullptr && (asUnit->mIntelStateFlags & kDarkenedTintMask) != 0u) {
          iconColor = DarkenRgbPreserveAlpha(iconColor);
        }
        record.mColor = iconColor;
        record.mLastFocusDamageTick = entity->mLastFocusDamageGameTick;

        const auto findSlot = [this](const boost::shared_ptr<CD3DBatchTexture>* const texture) -> std::uint32_t {
          return (texture != nullptr && *texture) ? gpuIcons.FindSlot(texture->get()) : StrategicIconInstance::kNoLayer;
        };
        const std::uint32_t iconSlot = findSlot(source.mIcon);
        if (iconSlot == StrategicIconInstance::kNoLayer && source.mIcon != nullptr && *source.mIcon) {
          needsSlot = 1U;
        }
        record.mIconSlots = iconSlot | (findSlot(source.mSelectedIcon) << 16U);
        // The hovered textures get their slots when the unit is first hovered.
        record.mHoveredIconSlots = findSlot(source.mHoveredIcon) | (findSlot(source.mHoveredSelectedIcon) << 16U);
        const boost::shared_ptr<CD3DBatchTexture>& underlay = entity->mVariableData.mUnderlayTexture;
        if (hasIdentifiedOwner && underlay) {
          const std::uint32_t underlaySlot = gpuIcons.FindSlot(underlay.get());
          if (underlaySlot == StrategicIconInstance::kNoLayer) {
            needsSlot = 1U;
          } else {
            record.mUnderlaySlotOrNone = static_cast<std::int32_t>(underlaySlot);
          }
        }
      }

      template <class Store>
      void ClassifySource(
        const StrategicIconSource& source,
        Store&& store
      )
      {
        UserEntity* const entity = source.mEntity;
        if (entity == nullptr || entity->mVariableData.mIsDead != 0 || entity->mMarkedForDeletion != 0) {
          return;
        }
        if (IsFactoryPreOrdersEnabled()) {
          if (const UserUnit* const asUnit = entity->IsUserUnit()) {
            if (PlannedFactoryManager::Get().IsPlannedProxyUnit(asUnit)) {
              return;
            }
          }
        }

        // `GetInterpolatedTransform`'s position, from the endpoints the record holds.
        const float alpha = std::clamp(source.mImpact * tickFraction, 0.0f, 1.0f);
        Wm3::Vector3f position;
        position.x = source.mLastPosition.x + (source.mCurrentPosition.x - source.mLastPosition.x) * alpha;
        position.y = source.mLastPosition.y + (source.mCurrentPosition.y - source.mLastPosition.y) * alpha;
        position.z = source.mLastPosition.z + (source.mCurrentPosition.z - source.mLastPosition.z) * alpha;

        UnitIconData iconData{};
        iconData.mUnit = entity;
        iconData.mBlueprint = source.mBlueprint;
        iconData.mWorldX = position.x;
        iconData.mWorldY = position.y;
        iconData.mWorldZ = position.z;
        iconData.mIsFriendly = source.Has(StrategicIconSource::kFriendly);
        iconData.mShowStunnedOverlay = source.Has(StrategicIconSource::kStunned);
        iconData.mShowPausedOverlay = source.Has(StrategicIconSource::kPaused);

        if (source.Has(StrategicIconSource::kCheckPlayableRect)) {
          if (
            session.mWldMap != nullptr && session.mWldMap->mTerrainRes != nullptr &&
            !session.mWldMap->mTerrainRes->IsInPlayableRect(position)
          ) {
            return;
          }
        }

        if (
          ui_RenderUnitBars && ui_LifebarLOD > currentZoomValue && source.Has(StrategicIconSource::kLifebarBlueprint)
        ) {
          bool eligible = iconData.mIsFriendly;
          if (!eligible && source.Has(StrategicIconSource::kSelectedVariantEligible)) {
            eligible = ui_ForceLifbarsOnEnemy || entity == hoveredEntity;
          }
          if (eligible && source.Has(StrategicIconSource::kLifebarUnit)) {
            const bool attachedAndHidden = !showAttachedUnitLifebars && source.Has(StrategicIconSource::kBusy);
            if (!attachedAndHidden) {
              store(EStrategicIconRun::Lifebar, iconData, nullptr);
            }
          }
        }

        if (
          !ui_NisRenderIcons || (!ui_RenderIcons && !iconData.mShowPausedOverlay) ||
          source.Has(StrategicIconSource::kBeingBuilt)
        ) {
          return;
        }

        if (source.mMesh != nullptr && !ui_AlwaysRenderStrategicIcons) {
          const float fadeThreshold = std::min(source.mMesh->mIconFadeInZoom, maxZoomFade);
          if (fadeThreshold > currentZoomValue) {
            if (source.Has(StrategicIconSource::kSkipWhenMeshVisible)) {
              return;
            }
            iconData.mSuppressBaseIcon = iconData.mShowPausedOverlay || iconData.mShowStunnedOverlay;
          }
        }

        const bool isSelected = session.mSelection.Find(entity) != session.mSelection.end();
        if (entity == hoveredEntity) {
          const boost::shared_ptr<CD3DBatchTexture>* const hoveredIcon =
            isSelected ? source.mHoveredSelectedIcon : source.mHoveredIcon;
          if (hoveredIcon != nullptr && *hoveredIcon) {
            store(EStrategicIconRun::Hovered, iconData, hoveredIcon);
          }
          return;
        }
        const boost::shared_ptr<CD3DBatchTexture>* const icon = isSelected ? source.mSelectedIcon : source.mIcon;
        if (icon == nullptr || !*icon) {
          return;
        }
        if (isSelected) {
          store(EStrategicIconRun::Selected, iconData, icon);
        } else if (source.Has(StrategicIconSource::kHighPriority)) {
          store(EStrategicIconRun::HighPriority, iconData, icon);
        } else if (source.Has(StrategicIconSource::kAir)) {
          store(EStrategicIconRun::Air, iconData, icon);
        } else {
          store(EStrategicIconRun::Ground, iconData, icon);
        }
      }

      // Engine addition (`ui_IconRecords`): brings this view's records up to date.
      void UpdateSources()
      {
        static std::vector<StrategicIconSourceSet> sSourceSets;
        StrategicIconSourceSet* sourceSet = nullptr;
        for (StrategicIconSourceSet& candidate : sSourceSets) {
          if (candidate.mCamera == camera) {
            sourceSet = &candidate;
          }
        }
        if (sourceSet == nullptr) {
          sourceSet = &sSourceSets.emplace_back();
          sourceSet->mCamera = camera;
        }
        const std::uint64_t frustumRebuild = CAM_FrustumUnitsRebuildCount();
        if (
          sourceSet->mSession != &session || sourceSet->mBeat != gUserSyncBeats ||
          sourceSet->mFrustumRebuild != frustumRebuild || sourceSet->mFocusArmy != focusArmy ||
          sourceSet->mTeamColorMode != session.mTeamColorMode || sourceSet->mSources.size() != frustumUnitCount ||
          (classifyOnGpu && sourceSet->mGpuSources.size() != frustumUnitCount)
        ) {
          sourceSet->mSession = &session;
          sourceSet->mBeat = gUserSyncBeats;
          sourceSet->mFrustumRebuild = frustumRebuild;
          sourceSet->mFocusArmy = focusArmy;
          sourceSet->mTeamColorMode = session.mTeamColorMode;
          sourceSet->mSources.resize(frustumUnitCount);
          static std::vector<std::uint8_t> sNeedsSlot;
          if (classifyOnGpu) {
            sourceSet->mGpuSources.resize(frustumUnitCount);
            sNeedsSlot.resize(frustumUnitCount);
          } else {
            sourceSet->mGpuSources.clear();
          }
          const auto describeRange = [&](const std::size_t begin, const std::size_t end) {
            for (std::size_t i = begin; i < end; ++i) {
              Describe(frustumUnits[i], sourceSet->mSources[i]);
              if (classifyOnGpu) {
                DescribeGpu(sourceSet->mSources[i], sourceSet->mGpuSources[i], sNeedsSlot[i]);
              }
            }
          };
          if (UseParallelIcons(frustumUnitCount)) {
            CUserWorkerPool::Get().ParallelFor(frustumUnitCount, kParallelIconChunk, describeRange);
          } else {
            describeRange(0u, frustumUnitCount);
          }
          if (classifyOnGpu) {
            // Textures seen for the first time get their slot here, on this thread.
            for (std::size_t i = 0; i < frustumUnitCount; ++i) {
              if (sNeedsSlot[i] == 0U) {
                continue;
              }
              const StrategicIconSource& source = sourceSet->mSources[i];
              StrategicIconSourceRecord& record = sourceSet->mGpuSources[i];
              if (source.mIcon != nullptr && *source.mIcon) {
                record.mIconSlots = (record.mIconSlots & 0xFFFF0000u) | gpuIcons.AddSlot(*source.mIcon);
              }
              const boost::shared_ptr<CD3DBatchTexture>& underlay = source.mEntity->mVariableData.mUnderlayTexture;
              const UserUnit* const asUnit = source.mEntity->IsUserUnit();
              constexpr std::uint32_t kHasBlueprintIconDataMask = 0x10u;
              if (underlay && (asUnit == nullptr || (asUnit->mIntelStateFlags & kHasBlueprintIconDataMask) != 0u)) {
                const std::uint16_t slot = gpuIcons.AddSlot(underlay);
                record.mUnderlaySlotOrNone =
                  slot == StrategicIconInstance::kNoLayer ? -1 : static_cast<std::int32_t>(slot);
              }
            }
            ++sourceSet->mGpuSourcesVersion;
          }
        }
        activeSourceSet = sourceSet;
        iconSources = sourceSet->mSources.data();
        VerifyStrategicIconSources(frustumUnitCount, [&](const std::size_t i, auto&& store) {
          Classify(frustumUnits[i], store);
        }, [&](const std::size_t i, auto&& store) {
          ClassifySource(iconSources[i], store);
        });
      }

      // `classify` or, with `ui_IconRecords`, its record-based form, for entry `i` of the list.
      template <class Store>
      void ClassifyAt(
        const std::size_t i,
        Store&& store
      )
      {
        if (iconSources != nullptr) {
          ClassifySource(iconSources[i], store);
        } else {
          Classify(frustumUnits[i], store);
        }
      }

      // Engine addition (`ren_GpuIconClassify`): the four icon runs classified, placed and drawn on
      // the GPU (StrategicIconClassifyShader.h) from the records' GPU form. The CPU keeps the lifebar
      // run, which exists only zoomed in, and per frame only gathers the selection, the hovered unit
      // and the constants. If the renderer declines, the CPU path below runs as before.
      // Returns false if the renderer declined.
      bool DrawClassifiedOnGpu(
        std::optional<gpg::gal::RenderProfileScope>& profilePhase
      )
      {
        bool drawnByClassifier = false;
        StrategicIconSourceSet& sourceSet = *activeSourceSet;
        if (ui_RenderUnitBars && ui_LifebarLOD > currentZoomValue) {
          const auto storeLifebar = [this](
                                      const EStrategicIconRun run,
                                      const UnitIconData& data,
                                      const boost::shared_ptr<CD3DBatchTexture>* const icon
                                    ) {
            if (run == EStrategicIconRun::Lifebar) {
              StoreStrategicIcon(aux, run, data, icon);
            }
          };
          for (std::size_t i = 0; i < frustumUnitCount; ++i) {
            ClassifySource(iconSources[i], storeLifebar);
          }
        }

        // The selection as one bit per record, rebuilt when the selection or the records change.
        static std::vector<const UserEntity*> sSelection;
        sSelection.clear();
        for (UserEntity* const selected : session.mSelection) {
          sSelection.push_back(selected);
        }
        if (
          sourceSet.mSelectionBuiltFor != sourceSet.mGpuSourcesVersion || sSelection != sourceSet.mSelectionSnapshot
        ) {
          sourceSet.mSelectionSnapshot = sSelection;
          ++sourceSet.mSelectionVersion;
          sourceSet.mSelectionBits.assign((frustumUnitCount + 31u) / 32u, 0u);
          bool recordsChanged = false;
          if (!sSelection.empty()) {
            // The live selected objects, sorted: what `mSelection.Find` finds, searched without
            // touching the set, so workers can do it. A chunk is a whole number of bit words.
            static std::vector<const UserEntity*> sSorted;
            sSorted.assign(sSelection.begin(), sSelection.end());
            std::sort(sSorted.begin(), sSorted.end());
            static_assert(kParallelIconChunk % 32u == 0u, "a chunk must own whole selection words");
            const auto markRange = [&](const std::size_t begin, const std::size_t end) {
              for (std::size_t i = begin; i < end; ++i) {
                const UserEntity* const entity = iconSources[i].mEntity;
                if (entity != nullptr && std::binary_search(sSorted.begin(), sSorted.end(), entity)) {
                  sourceSet.mSelectionBits[i >> 5u] |= 1u << (i & 31u);
                }
              }
            };
            if (UseParallelIcons(frustumUnitCount)) {
              CUserWorkerPool::Get().ParallelFor(frustumUnitCount, kParallelIconChunk, markRange);
            } else {
              markRange(0u, frustumUnitCount);
            }
            // A selected icon gets its atlas slot the first time it is needed.
            for (std::size_t word = 0; word < sourceSet.mSelectionBits.size(); ++word) {
              for (std::uint32_t bits = sourceSet.mSelectionBits[word]; bits != 0u; bits &= bits - 1u) {
                const std::size_t i = word * 32u + static_cast<std::size_t>(std::countr_zero(bits));
                StrategicIconSourceRecord& record = sourceSet.mGpuSources[i];
                const boost::shared_ptr<CD3DBatchTexture>* const selectedIcon = iconSources[i].mSelectedIcon;
                if (
                  (record.mIconSlots >> 16u) == StrategicIconInstance::kNoLayer && selectedIcon != nullptr &&
                  *selectedIcon
                ) {
                  record.mIconSlots = (record.mIconSlots & 0xFFFFu) |
                    (static_cast<std::uint32_t>(gpuIcons.AddSlot(*selectedIcon)) << 16u);
                  recordsChanged = true;
                }
              }
            }
          }
          if (recordsChanged) {
            ++sourceSet.mGpuSourcesVersion;
          }
          sourceSet.mSelectionBuiltFor = sourceSet.mGpuSourcesVersion;
        }

        if (sourceSet.mHoveredBuiltFor != sourceSet.mGpuSourcesVersion || sourceSet.mHoveredEntity != hoveredEntity) {
          sourceSet.mHoveredBuiltFor = sourceSet.mGpuSourcesVersion;
          sourceSet.mHoveredEntity = hoveredEntity;
          sourceSet.mHoveredIndex = 0xFFFFFFFFU;
          for (std::size_t i = 0; hoveredEntity != nullptr && i < frustumUnitCount; ++i) {
            if (iconSources[i].mEntity == hoveredEntity) {
              sourceSet.mHoveredIndex = static_cast<std::uint32_t>(i);
            }
          }
          // The hovered unit's textures get their atlas slots the first time they are needed. The
          // last matching entry is the binary's: its hovered slot keeps the last one stored.
          if (sourceSet.mHoveredIndex != 0xFFFFFFFFU) {
            const StrategicIconSource& source = iconSources[sourceSet.mHoveredIndex];
            StrategicIconSourceRecord& record = sourceSet.mGpuSources[sourceSet.mHoveredIndex];
            std::uint32_t slots = record.mHoveredIconSlots;
            const auto ensure =
              [this](const boost::shared_ptr<CD3DBatchTexture>* const texture, const std::uint32_t slot) {
              return (slot == StrategicIconInstance::kNoLayer && texture != nullptr && *texture)
                ? gpuIcons.AddSlot(*texture)
                : slot;
            };
            slots =
              ensure(source.mHoveredIcon, slots & 0xFFFFu) | (ensure(source.mHoveredSelectedIcon, slots >> 16U) << 16U);
            if (slots != record.mHoveredIconSlots) {
              record.mHoveredIconSlots = slots;
              const bool selectionCurrent = sourceSet.mSelectionBuiltFor == sourceSet.mGpuSourcesVersion;
              ++sourceSet.mGpuSourcesVersion;
              if (selectionCurrent) {
                sourceSet.mSelectionBuiltFor = sourceSet.mGpuSourcesVersion;
              }
            }
          }
          sourceSet.mHoveredBuiltFor = sourceSet.mGpuSourcesVersion;
        }

        using Constants = StrategicIconClassifyConstants;
        Constants constants{};
        for (std::size_t row = 0; row < 4u; ++row) {
          constants.mViewProjection[row * 4u + 0u] = view.viewProjection.r[row].x;
          constants.mViewProjection[row * 4u + 1u] = view.viewProjection.r[row].y;
          constants.mViewProjection[row * 4u + 2u] = view.viewProjection.r[row].z;
          constants.mViewProjection[row * 4u + 3u] = view.viewProjection.r[row].w;
        }
        // `PlaceUnitIcon`'s `Project(world, 0, width, height, 0)`.
        constants.mViewport[0] = 0.0f;
        constants.mViewport[1] = aux.mViewportWidth;
        constants.mViewport[2] = aux.mViewportHeight;
        constants.mViewport[3] = 0.0f;
        std::uint32_t frameFlags = 0u;
        if (
          session.mWldMap != nullptr && session.mWldMap->mTerrainRes != nullptr &&
          session.mWldMap->mTerrainRes->mMap != nullptr
        ) {
          // `CWldTerrainRes::IsInPlayableRect`'s bounds.
          const gpg::Rect2i& playableRect = session.mWldMap->mTerrainRes->mMap->mPlayableRect;
          constants.mPlayableRect[0] = static_cast<float>(playableRect.x0);
          constants.mPlayableRect[1] = static_cast<float>(playableRect.z0);
          constants.mPlayableRect[2] = static_cast<float>(playableRect.x1);
          constants.mPlayableRect[3] = static_cast<float>(playableRect.z1);
          frameFlags |= Constants::kHasPlayableRect;
        }
        constants.mTickFraction = tickFraction;
        constants.mCurrentZoom = currentZoomValue;
        constants.mMaxZoomFade = maxZoomFade;
        // `PlaceUnitIcon`'s blink test: the phase is the same for every unit.
        constexpr float kBlinkDurationTickScale = 10.0f;
        constants.mBlinkTicks = ui_StrategicIconBlinkDuration * kBlinkDurationTickScale;
        const double simTime = static_cast<double>(session.mGameTick) + static_cast<double>(aux.mTickFraction);
        if (std::fmod(simTime * static_cast<double>(ui_StrategicIconBlinkRate), 1.0) <= 0.5) {
          frameFlags |= Constants::kBlinkHidden;
        }
        if (ui_NisRenderIcons) {
          frameFlags |= Constants::kNisRenderIcons;
        }
        if (ui_RenderIcons) {
          frameFlags |= Constants::kRenderIcons;
        }
        if (ui_AlwaysRenderStrategicIcons) {
          frameFlags |= Constants::kAlwaysRenderIcons;
        }
        constants.mFlags = frameFlags;
        constants.mHovered = sourceSet.mHoveredIndex;
        constants.mGameTick = session.mGameTick;
        constants.mPausedSlot =
          aux.mPauseRestTexture ? gpuIcons.AddSlot(aux.mPauseRestTexture) : StrategicIconInstance::kNoLayer;
        constants.mStunnedSlot =
          aux.mStunnedRestTexture ? gpuIcons.AddSlot(aux.mStunnedRestTexture) : StrategicIconInstance::kNoLayer;

        profilePhase.reset();
        profilePhase.emplace("IconDraw");
        (void)primBatcher->Setup("TStrategicIcon");
        drawnByClassifier = gpuIcons.DrawClassified(
          *primBatcher,
          camera,
          std::span<const StrategicIconSourceRecord>(sourceSet.mGpuSources),
          sourceSet.mGpuSourcesVersion,
          std::span<const std::uint32_t>(sourceSet.mSelectionBits),
          sourceSet.mSelectionVersion,
          constants
        );

        static std::uint64_t sClassifiedDraws[2] = {}; // per kind of view, so both get checked
        const std::uint32_t checkInterval = StrategicIconGpuCheckInterval();
        if (drawnByClassifier && checkInterval != 0u && ++sClassifiedDraws[isMiniMap ? 1 : 0] % checkInterval == 0u) {
          // What the CPU path would have drawn this frame: classify, runs in draw order, place, build.
          std::vector<StrategicIconCandidate> candidates;
          const auto record = [&candidates](
                                const EStrategicIconRun run,
                                const UnitIconData& data,
                                const boost::shared_ptr<CD3DBatchTexture>* const icon
                              ) {
            if (run != EStrategicIconRun::Lifebar) {
              candidates.push_back(StrategicIconCandidate{data, icon, run});
            }
          };
          for (std::size_t i = 0; i < frustumUnitCount; ++i) {
            ClassifySource(iconSources[i], record);
          }
          std::vector<StrategicIconInstance> expected;
          expected.reserve(candidates.size());
          const auto findSlot = [this](const boost::shared_ptr<CD3DBatchTexture>& texture) {
            return gpuIcons.FindSlot(texture.get());
          };
          for (const EStrategicIconRun run :
               {EStrategicIconRun::Ground,
                EStrategicIconRun::Air,
                EStrategicIconRun::HighPriority,
                EStrategicIconRun::Selected}) {
            for (const StrategicIconCandidate& candidate : candidates) {
              if (candidate.mRun == run) {
                (void)BuildStrategicIconRecord(
                  candidate, aux, PlaceUnitIcon(candidate.mData, aux), findSlot, expected.emplace_back()
                );
              }
            }
          }
          // The hovered slot: the last hovered candidate.
          for (auto it = candidates.rbegin(); it != candidates.rend(); ++it) {
            if (it->mRun == EStrategicIconRun::Hovered) {
              (void)BuildStrategicIconRecord(
                *it, aux, PlaceUnitIcon(it->mData, aux), findSlot, expected.emplace_back()
              );
              break;
            }
          }
          std::vector<StrategicIconInstance> drawn;
          if (gpuIcons.ReadBackClassified(drawn)) {
            CompareClassifiedStrategicIcons(expected, drawn, isMiniMap);
          }
        }

        if (!drawnByClassifier) {
          // The CPU path classifies again, lifebars included.
          aux.mLifebarIcons.clear();
          profilePhase.reset();
          profilePhase.emplace("IconClassify");
        }
        return drawnByClassifier;
      }

      // The CPU path: classifies the frustum list and draws the icon quads.
      void ClassifyAndDraw(
        std::optional<gpg::gal::RenderProfileScope>& profilePhase
      )
      {
        // Main-thread scratch, kept across frames so the chunk lists keep their capacity.
        static std::vector<std::vector<StrategicIconCandidate>> sChunks;
        // Engine addition (`ren_GpuIcons`): the candidates of the four icon runs in draw order.
        static std::vector<const StrategicIconCandidate*> sGpuIcons;
        const bool gpuIconsActive = gpuIcons.IsActive();
        sGpuIcons.clear();
        if (gpuIconsActive) {
          // Engine addition (`ren_GpuIcons`): classify into candidates as the parallel path does
          // (one chunk when the count is small), but keep the icon runs as candidates instead of
          // copying them into `aux`: the GPU records are built from them directly. Lifebar records
          // are stored as before, in the same order.
          const std::size_t chunkCount =
            std::max<std::size_t>(1u, (frustumUnitCount + kParallelIconChunk - 1u) / kParallelIconChunk);
          if (sChunks.size() < chunkCount) {
            sChunks.resize(chunkCount);
          }
          const auto classifyChunk = [&](const std::size_t begin, const std::size_t end) {
            std::vector<StrategicIconCandidate>& chunk = sChunks[begin / kParallelIconChunk];
            chunk.clear();
            const auto record = [&chunk](
                                  const EStrategicIconRun run,
                                  const UnitIconData& data,
                                  const boost::shared_ptr<CD3DBatchTexture>* const icon
                                ) {
              chunk.push_back(StrategicIconCandidate{data, icon, run});
            };
            for (std::size_t i = begin; i < end; ++i) {
              ClassifyAt(i, record);
            }
          };
          if (UseParallelIcons(frustumUnitCount)) {
            CUserWorkerPool::Get().ParallelFor(frustumUnitCount, kParallelIconChunk, classifyChunk);
          } else {
            classifyChunk(0u, frustumUnitCount);
            for (std::size_t c = 1; c < chunkCount; ++c) {
              sChunks[c].clear();
            }
          }
          // Runs in draw order (ground, air, high priority, selected), each in classification order,
          // then the hovered slot (the last hovered candidate, as the binary overwrites its slot).
          std::size_t runCounts[4] = {};
          const StrategicIconCandidate* hoveredCandidate = nullptr;
          for (std::size_t c = 0; c < chunkCount; ++c) {
            for (const StrategicIconCandidate& candidate : sChunks[c]) {
              if (candidate.mRun == EStrategicIconRun::Lifebar) {
                StoreStrategicIcon(aux, candidate.mRun, candidate.mData, candidate.mIcon);
              } else if (candidate.mRun == EStrategicIconRun::Hovered) {
                hoveredCandidate = &candidate;
              } else {
                ++runCounts[static_cast<std::size_t>(candidate.mRun)];
              }
            }
          }
          std::size_t runCursor[4] = {
            0u, runCounts[0], runCounts[0] + runCounts[1], runCounts[0] + runCounts[1] + runCounts[2]
          };
          sGpuIcons.resize(runCursor[3] + runCounts[3]);
          for (std::size_t c = 0; c < chunkCount; ++c) {
            for (const StrategicIconCandidate& candidate : sChunks[c]) {
              if (candidate.mRun != EStrategicIconRun::Lifebar && candidate.mRun != EStrategicIconRun::Hovered) {
                sGpuIcons[runCursor[static_cast<std::size_t>(candidate.mRun)]++] = &candidate;
              }
            }
          }
          if (hoveredCandidate != nullptr) {
            sGpuIcons.push_back(hoveredCandidate);
          }
        } else if (!UseParallelIcons(frustumUnitCount)) {
          const auto storeInAux = [this](
                                    const EStrategicIconRun run,
                                    const UnitIconData& data,
                                    const boost::shared_ptr<CD3DBatchTexture>* const icon
                                  ) {
            StoreStrategicIcon(aux, run, data, icon);
          };
          for (std::size_t i = 0; i < frustumUnitCount; ++i) {
            ClassifyAt(i, storeInAux);
          }
        } else {
          const std::size_t chunkCount = (frustumUnitCount + kParallelIconChunk - 1u) / kParallelIconChunk;
          if (sChunks.size() < chunkCount) {
            sChunks.resize(chunkCount);
          }
          CUserWorkerPool::Get().ParallelFor(
            frustumUnitCount, kParallelIconChunk, [&](const std::size_t begin, const std::size_t end) {
            std::vector<StrategicIconCandidate>& chunk = sChunks[begin / kParallelIconChunk];
            chunk.clear();
            const auto record = [&chunk](
                                  const EStrategicIconRun run,
                                  const UnitIconData& data,
                                  const boost::shared_ptr<CD3DBatchTexture>* const icon
                                ) {
              chunk.push_back(StrategicIconCandidate{data, icon, run});
            };
            for (std::size_t i = begin; i < end; ++i) {
              ClassifyAt(i, record);
            }
          }
          );
          for (std::size_t c = 0; c < chunkCount; ++c) {
            for (const StrategicIconCandidate& candidate : sChunks[c]) {
              StoreStrategicIcon(aux, candidate.mRun, candidate.mData, candidate.mIcon);
            }
            sChunks[c].clear();
          }
        }

        // --- Phase 3.5: draw the classified icon quads -----------------------
        // The four runs collected above, each drawn through `RenderUnitIcon`
        // (0x0085D9A0) under its own technique (0x0085B79D..0x0085BCCD in the
        // binary). This runs before the lifebar pass below, matching the
        // binary's own SetTexture/DrawQuad-then-Flush ordering (0x0085BBE9..
        // 0x0085BCCD then Flush at 0x0085BFA9). The formation-preview icons
        // follow in phase 3.75.
        profilePhase.reset();
        profilePhase.emplace("IconDraw");
        (void)primBatcher->Setup("TStrategicIcon");

        // Engine addition (`ren_GpuIcons`): one instanced draw from per-icon GPU records when the
        // backend can; the batcher path below otherwise. If the GPU path declines, the candidates go
        // into the runs exactly as the batcher path stores them.
        bool drawnOnGpu = false;
        if (gpuIconsActive) {
          drawnOnGpu = DrawStrategicIconsOnGpu(gpuIcons, aux, camera, sGpuIcons);
          if (!drawnOnGpu) {
            for (const StrategicIconCandidate* const candidate : sGpuIcons) {
              StoreStrategicIcon(aux, candidate->mRun, candidate->mData, candidate->mIcon);
            }
          }
        }
        const std::size_t drawnIconCount =
          aux.mGroundIcons.size() + aux.mAirIcons.size() + aux.mHighPriorityIcons.size() + aux.mSelectedIcons.size();
        if (drawnOnGpu) {
          // Drawn: nothing left for the batcher.
        } else if (!UseParallelIcons(drawnIconCount)) {
          for (UnitIconData& groundIcon : aux.mGroundIcons) {
            RenderUnitIcon(groundIcon, aux);
          }
          for (UnitIconData& airIcon : aux.mAirIcons) {
            RenderUnitIcon(airIcon, aux);
          }
          for (UnitIconData& highPriorityIcon : aux.mHighPriorityIcons) {
            RenderUnitIcon(highPriorityIcon, aux);
          }
          for (UnitIconData& selectedIcon : aux.mSelectedIcons) {
            RenderUnitIcon(selectedIcon, aux);
          }
          if (sHoveredStrategicIcon.mUnit != nullptr) {
            RenderUnitIcon(sHoveredStrategicIcon, aux);
          }
        } else {
          // Engine addition (`ui_ParallelIcons`): place every icon of the four runs on workers, then
          // draw them on this thread in the serial order (ground, air, high priority, selected).
          const UnitIconData* const runStarts[4] = {
            aux.mGroundIcons.data(), aux.mAirIcons.data(), aux.mHighPriorityIcons.data(), aux.mSelectedIcons.data()
          };
          const std::size_t runEnds[4] = {
            aux.mGroundIcons.size(),
            aux.mGroundIcons.size() + aux.mAirIcons.size(),
            aux.mGroundIcons.size() + aux.mAirIcons.size() + aux.mHighPriorityIcons.size(),
            drawnIconCount
          };
          const auto iconAt = [&](const std::size_t index) -> const UnitIconData& {
            std::size_t run = 0;
            while (index >= runEnds[run]) {
              ++run;
            }
            return runStarts[run][index - (run == 0 ? 0 : runEnds[run - 1])];
          };

          static std::vector<UnitIconPlacement> sPlacements;
          sPlacements.resize(drawnIconCount);
          CUserWorkerPool::Get().ParallelFor(
            drawnIconCount, kParallelIconChunk, [&](const std::size_t begin, const std::size_t end) {
            for (std::size_t i = begin; i < end; ++i) {
              sPlacements[i] = PlaceUnitIcon(iconAt(i), aux);
            }
          }
          );
          static std::vector<CD3DPrimBatcher::ScreenQuad> sPendingQuads;
          StrategicIconBulkEmitter emit(*aux.mBatcher, sPendingQuads);
          for (std::size_t i = 0; i < drawnIconCount; ++i) {
            EmitUnitIconQuads(iconAt(i), sPlacements[i], emit);
          }
          if (sHoveredStrategicIcon.mUnit != nullptr) {
            EmitUnitIconQuads(sHoveredStrategicIcon, PlaceUnitIcon(sHoveredStrategicIcon, aux), emit);
          }
        }
      }

      // --- Phase 3.75: formation-preview icons (0x0085C3C2..0x0085C859) -------
      // While a formation is being placed, every participant's strategic icon is
      // drawn at the slot the formation assigned it, as a ghost under its own
      // technique. The gates and the slot height are the ones
      // `RenderMeshPreviews` uses for the matching mesh ghosts.
      void DrawFormationPreviews()
      {
        CFormation* const formation = session.mCurFormation;
        // 0x0085C3E7 `comiss 0, mTimeLeft; jb`: only once the placement timer
        // has run out.
        if (formation->mReady && formation->mCurInstance != nullptr && formation->mTimeLeft <= 0.0f) {
          (void)primBatcher->Setup("TStrategicFormationIcon");

          // Same reinterpret_cast as `RenderMeshPreviews`: `Contains` (slot 16,
          // 0x0085C4D9) and `GetFormationPosition` (slot 6, 0x0085C5C8) are
          // declared on the concrete instance only.
          CAiFormationInstance* const instance = reinterpret_cast<CAiFormationInstance*>(formation->mCurInstance);
          for (UserUnit* const unit : formation->mParticipants) {
            IUnit* const bridge = GetIUnitBridge(unit);
            Unit* const formationUnit = reinterpret_cast<Unit*>(bridge);
            // 0x0085C4E9..0x0085C51B is `GetAttachmentParent()` inlined.
            if (
              bridge->IsDead() || !instance->Contains(formationUnit, false) || unit->GetAttachmentParent() != nullptr
            ) {
              continue;
            }

            UnitIconData iconData{};
            iconData.mUnit = session.LookupEntityId(bridge->GetEntityId());
            iconData.mBlueprint = bridge->GetBlueprint();
            // +0x150 is the size word of `mStrategicIconName` (0x0085C5AC).
            if (iconData.mBlueprint->mStrategicIconName.empty()) {
              continue;
            }

            SCoordsVec2 slot{};
            instance->GetFormationPosition(&slot, formationUnit, nullptr);
            const RUnitBlueprint* const blueprint = bridge->GetBlueprint();
            iconData.mWorldX = slot.x;
            iconData.mWorldY =
              (blueprint->mSizeY + session.GetSTIMap()->GetSurface(slot.x, slot.z)) + blueprint->Physics.Elevation;
            iconData.mWorldZ = slot.z;

            // The camera-distance test of the main pass, without its
            // `GetMaxZoom() * 0.89` clamp (0x0085C6A1..0x0085C6E0).
            const auto& lodRow = aux.mCamera->viewport.r[1];
            const float zoom = ((iconData.mWorldZ * lodRow.z) + (iconData.mWorldY * lodRow.y)) +
              (lodRow.x * iconData.mWorldX) + lodRow.w;
            if (iconData.mUnit->mVariableData.mMeshBlueprint->mIconFadeInZoom > zoom) {
              continue;
            }

            // Not selected, selected variant eligible, hovered (0x0085C6E6..0x0085C6EF):
            // the ghosts show the highlighted icon.
            iconData.mIconTexture = PickUnitStrategicIconTexture(aux, iconData, false, true, true);
            if (iconData.mIconTexture) {
              iconData.mIsFormationGhost = true;
              RenderUnitIcon(iconData, aux);
            }
          }
        }
      }
    };
  } // namespace

  /**
   * Address: 0x0085B6E0 (FUN_0085B6E0,
   * ?RenderStrategicIcons@CWldSession@Moho@@QAEXPAVCameraImpl@2@PAVCD3DPrimBatcher@2@PAVCWldMap@2@@Z)
   *
   * What it does:
   * Lazily builds the process-global icon-aux singleton, re-seats its
   * per-frame camera/batcher state and screen projection, then walks every
   * unit `CameraImpl::GetAllUnitsInFrustum()` currently sees and classifies
   * each one carrying a strategic-icon name into one of four runs (ground /
   * air / high-priority / selected), picking its icon texture through
   * `PickUnitStrategicIconTexture`.
   *
   * Blockers this pass resolved (see cited evidence at each site):
   *  - `CameraImpl` vtable slot mixup: the dispatch at 0x0085BA71 (byte
   *    offset 0xA0 from the vtable head) is slot 40 = `GetAllUnitsInFrustum`,
   *    not `GetArmyUnitsInFrustum` (slot 41, +0xA4) as an earlier pass's
   *    comment guessed - confirmed by reading the shipped vtable directly
   *    out of `bin/2025.7.1/ForgedAlliance.exe` (see `CameraImpl.h`).
   *  - `REntityBlueprint::mStrategicIconSortPriority` retyped from a 32-bit
   *    `mStrategicIconRuntimeWord` to the real single byte the classifier
   *    compares against `'A'`.
   *  - `CWldSession`'s `EntId -> UserEntity*` map was already modelled
   *    (`SessionEntityMap` / `LookupEntityId`) by a prior pass - no new work
   *    needed there.
   *  - `StrategicIconAux`'s constructor and `LoadGenericIcons` recovered
   *    (0x0085B2A0 / 0x0085E7F0); `gStrategicIconAuxiliary` retyped from a
   *    never-defined `StrategicIconAux` forward declaration to
   *    the real, complete type.
   *  - `PickUnitStrategicIconTexture` / `PickGenericStrategicIconTexture`
   *    recovered (0x0085D880 / 0x0085CBD0), which required retyping
   *    `REntityBlueprint`'s four cached icon fields from `boost::weak_ptr`
   *    to `boost::shared_ptr` (see the evidence note on those fields).
   *  - The selection-set name label (`DrawUnitSelectionSetNameLabel`,
   *    0x0085E3A0), which stacks under the custom name using the same
   *    cursor protocol, is now wired into phase 4 below.
   *  - The icon-quad draw itself (`RenderUnitIcon`, 0x0085D9A0) is now
   *    recovered and wired into phase 3.5 below, for all four of the
   *    ground/air/high-priority/selected runs: world-to-screen projection,
   *    the `Moho::teamcolors` per-army palette (`+0x0128F1C0`, read when
   *    `mTeamColorMode` is on) vs. the flat unidentified color, the
   *    formation-ghost alpha-clear and intel-bit darken tints, the
   *    recently-focus-damaged blink timer, and the identified-icon
   *    underlay / base icon / paused / stunned quad stack.
   *
   * Deferred to a follow-up pass - not drawn by this function yet:
   *  - The single dedicated "hovered unit" slot (this function's local
   *    `v148.playableRectX1` in the original binary - hovered units are
   *    excluded from all four runs below, matching the binary, but nothing
   *    collects or consumes that slot's own icon data yet).
   *
   * The formation-preview icons ("TStrategicFormationIcon", 0x0085C3C2..
   * 0x0085C859) draw in phase 3.75.
   */
  void CWldSession::RenderStrategicIcons(
    CameraImpl* const camera,
    CD3DPrimBatcher* const primBatcher,
    const float tickFraction,
    const bool isMiniMap
  )
  {
    // Read once per frame, before the singleton is even built (0x0085B719).
    // An "attached" unit - one riding a transport or docked - normally has its
    // lifebar suppressed; this option puts it back.
    const bool showAttachedUnitLifebars = OPTIONS_GetBool("show_attached_unit_lifebars");
    const gpg::gal::RenderProfileScope profileIcons("StrategicIcons"); // FAF instrumentation

    // --- Phase 1: lazy singleton build --------------------------------
    if (gStrategicIconAuxiliary == nullptr) {
      gStrategicIconAuxiliary = new StrategicIconAux();
      gStrategicIconAuxiliary->LoadGenericIcons(this);
      gStrategicIconAuxiliary->LoadPauseAndStunnedRestTextures(this);
    }
    StrategicIconAux& aux = *gStrategicIconAuxiliary;

    // --- Phase 2: re-seat per-frame camera/batcher state, clear the four
    // implemented runs, push the pixel-exact screen projection ----------
    const GeomCamera3& view = camera->CameraGetView();
    aux.mViewportX = view.viewport.r[3].x;
    aux.mViewportY = view.viewport.r[3].y;
    aux.mViewportWidth = view.viewport.r[3].z;
    aux.mViewportHeight = view.viewport.r[3].w;
    aux.mSession = this;
    aux.mBatcher = primBatcher;
    aux.mCamera = &view;
    // aux.mTickFraction re-seat deferred alongside the lifebar pass, its
    // only reader - see the class comment above `mTickFraction`.

    aux.mGroundIcons.clear();
    aux.mAirIcons.clear();
    aux.mHighPriorityIcons.clear();
    aux.mSelectedIcons.clear();
    // The lifebar run is collected below whether or not the draw pass that
    // consumes it is wired yet, so it has to be cleared here with the other
    // four. Leaving it out made it grow by every visible unit every frame.
    aux.mLifebarIcons.clear();
    sHoveredStrategicIcon = UnitIconData{};

    primBatcher->SetProjectionMatrix(MakeViewportPixelProjection(view));
    primBatcher->SetViewMatrix(VMatrix4::Identity());

    // "Current zoom" scalar used below as the mesh-fade-in comparison
    // baseline: the camera target position projected through row 1 of the
    // viewport matrix (0x0085BA1E..0x0085BA93 in the binary).
    const Wm3::Vector3f targetPosition = camera->GetTargetPosition();
    const float currentZoomValue = (view.viewport.r[1].x * targetPosition.x) +
      (view.viewport.r[1].y * targetPosition.y) + (view.viewport.r[1].z * targetPosition.z) + view.viewport.r[1].w;

    // --- Phase 3: classify every unit in frustum ------------------------
    UserArmy* const focusArmy = GetFocusArmy();
    gpg::core::FastVectorInline<WeakPtr<UserEntity>>& frustumUnits = *camera->GetAllUnitsInFrustum();
    const std::size_t frustumUnitCount = frustumUnits.size();
    StrategicIconRenderer& gpuIcons = StrategicIconRenderer::Get();
    const UserEntity* const hoveredEntity = GetHoveredUserEntity();
    const float maxZoomFade = camera->GetMaxZoom() * 0.89f;
    // Engine addition (`ren_GpuIconClassify`): classify on the GPU, from the records.
    const bool classifyOnGpu = ui_IconRecords && gpuIcons.IsClassifyActive();
    StrategicIconFrame frame{
      *this,
      aux,
      camera,
      view,
      primBatcher,
      tickFraction,
      isMiniMap,
      showAttachedUnitLifebars,
      currentZoomValue,
      focusArmy,
      frustumUnits,
      frustumUnitCount,
      gpuIcons,
      hoveredEntity,
      maxZoomFade,
      classifyOnGpu
    };
    if (ui_IconRecords) {
      frame.UpdateSources();
    }
    std::optional<gpg::gal::RenderProfileScope> profilePhase(std::in_place, "IconClassify"); // FAF instrumentation

    bool drawnByClassifier = false;
    if (
      classifyOnGpu && frame.activeSourceSet != nullptr && frame.activeSourceSet->mGpuSources.size() == frustumUnitCount
    ) {
      drawnByClassifier = frame.DrawClassifiedOnGpu(profilePhase);
    }
    if (!drawnByClassifier) {
      frame.ClassifyAndDraw(profilePhase);
    }

    primBatcher->Flush();

    frame.DrawFormationPreviews();
    primBatcher->Flush();

    profilePhase.reset();
    profilePhase.emplace("Lifebars");

    // --- Phase 4: draw the lifebar / label stack ------------------------
    // The icon-quad runs collected above are drawn by phase 3.5's
    // `RenderUnitIcon` pass just above; this is the bar-and-label stack
    // that follows it in the binary (0x0085C890..0x0085C9DB).
    (void)primBatcher->Setup("TLifeBar");

    for (UnitIconData& lifebarIcon : aux.mLifebarIcons) {
      if (lifebarIcon.mUnit == nullptr || lifebarIcon.mUnit->mVariableData.mIsDead != 0 ||
          lifebarIcon.mUnit->mMarkedForDeletion != 0) {
        continue;
      }
      if (IsFactoryPreOrdersEnabled()) {
        if (const UserUnit* const asUnit = lifebarIcon.mUnit->IsUserUnit()) {
          if (PlannedFactoryManager::Get().IsPlannedProxyUnit(asUnit)) {
            continue;
          }
        }
      }

      // The bar pass always writes both components before returning, on every
      // path; it is the label pass that may decline.
      Wm3::Vector2f labelCursor{};
      DrawUnitLifebars(lifebarIcon, labelCursor, aux);

      // Props and wrecks get bars but never labels - only a real unit can
      // carry a custom name or belong to a named selection set
      // (0x0085C915..0x0085C923).
      if (lifebarIcon.mUnit->IsUserUnit() == nullptr) {
        continue;
      }

      // A label that declined to draw returns the NaN sentinel, which leaves
      // the cursor where the bars left it so the next label still stacks
      // correctly (the caller-side isnan pair at 0x0085C973/0x0085C989).
      const Wm3::Vector2f afterCustomName = DrawUnitCustomNameLabel(lifebarIcon, aux, labelCursor, isMiniMap);
      if (IsValidScreenPoint(afterCustomName)) {
        labelCursor = afterCustomName;
      }

      // The selection-set name label stacks under the custom name label,
      // same cursor protocol (0x0085C990..0x0085C9DB).
      const Wm3::Vector2f afterSelectionSetNames =
        DrawUnitSelectionSetNameLabel(lifebarIcon, aux, labelCursor, isMiniMap);
      if (IsValidScreenPoint(afterSelectionSetNames)) {
        labelCursor = afterSelectionSetNames;
      }
    }

    primBatcher->Flush();
  }

  /**
   * Address: 0x008621B0 (FUN_008621B0, CWldSession::RenderProjectileIcons)
   *
   * What it does:
   * Draws a screen-space icon at every visible projectile and advances the
   * shared icon glow timer.
   *
   * The two floats are not interchangeable: the icon position is interpolated
   * with `tickFraction` (`movss xmm1, [ebp+0Ch]` at 0x00862491, the argument
   * of `GetInterpolatedTransform` at 0x0086249F) and the glow timer advances
   * by `frameSeconds` (`addss xmm2, [ebp+10h]` at 0x008628A6). Reading the
   * frame time for both, as this used to, placed every icon a frame-length
   * fraction past the previous tick instead of where the projectile is.
   */
  void CWldSession::RenderProjectileIcons(
    CameraImpl* const camera,
    CD3DPrimBatcher* const primBatcher,
    const float tickFraction,
    const float frameSeconds
  )
  {
    const GeomCamera3& view = camera->CameraGetView();

    // Zoomed in past the strategic threshold the projectiles are drawn as real
    // meshes, so the icon pass is skipped entirely.
    if (camera->CameraGetTargetZoom() < UI_StrategicProjectileLOD) {
      return;
    }

    const float viewportWidth = static_cast<float>(static_cast<std::int32_t>(view.viewport.r[3].z));
    const float viewportHeight = static_cast<float>(static_cast<std::int32_t>(view.viewport.r[3].w));

    primBatcher->SetProjectionMatrix(MakeViewportPixelProjection(view));
    primBatcher->SetViewMatrix(VMatrix4::Identity());

    CD3DDevice* const device = D3D_GetDevice();
    device->SelectFxFile("primbatcher");
    device->SelectTechnique(kProjectileIconTechnique);
    primBatcher->mRebuildComposite = 0;

    const EntityCategorySet* const projectileCategory = mRules->GetEntityCategory("PROJECTILE");
    UserArmy* const focusArmy = GetFocusArmy();

    // Engine addition (`ren_GpuProjectileIcons`): the plain icon quads go to one instanced draw
    // instead of the batcher, in the same order. A projectile drawn with its glow pass flushes
    // the instanced icons first and is drawn as before; after one, the batcher is left on the
    // glow technique, so the rest of the pass stays on the batcher as in the original.
    ProjectileIconRenderer& gpuIcons = ProjectileIconRenderer::Get();
    bool iconsOnGpu = gpuIcons.IsActive();
    if (iconsOnGpu) {
      gpuIcons.Begin(camera);
    }
    // The solid-colour icons this pass has looked up, by colour.
    std::vector<std::pair<std::uint32_t, boost::shared_ptr<CD3DBatchTexture>>> solidIcons;
    const auto flushGpuIcons = [&]() {
      if (iconsOnGpu && !gpuIcons.Flush(*primBatcher)) {
        gpuIcons.DrawWithBatcher(*primBatcher);
      }
    };

    // The binary collects into a stack fastvector with a large inline buffer;
    // the heap-backed lane is behaviourally identical for a scratch list.
    gpg::fastvector<UserEntity*> visibleEntities{};
    auto* const spatialStorage = GetEntitySpatialDbStorage();
    // 0x008623E1: `push 0x400`, the projectile bucket.
    (void)spatialStorage->CollectInView(const_cast<GeomCamera3*>(&view), visibleEntities, ENTITYTYPE_Projectile);

    // The per-projectile tests that read only the entity and the recon grids: whether it gets an
    // icon at all, and where. Engine addition (`ren_GpuProjectileIcons`): with the GPU path and
    // many projectiles they run on workers first; the loop below reads their results in order.
    struct ProjectileIconTest
    {
      const RProjectileBlueprint* mBlueprint = nullptr; // null: no icon
      Wm3::Vec3f mPosition{};
    };
    const auto testProjectile = [&](UserEntity* const entity, ProjectileIconTest& out) {
      out = ProjectileIconTest{};
      if (entity == nullptr || entity->mVariableData.mIsDead) {
        return;
      }

      // Entity ids are family-tagged in their top nibble; only the projectile
      // family gets an icon, which is cheaper than a category test per entity.
      if ((entity->mParams.mEntityId & kEntityFamilyMask) != kEntityFamilyProjectile) {
        return;
      }

      const auto* const blueprint = reinterpret_cast<const RProjectileBlueprint*>(entity->mParams.mBlueprint);
      if (blueprint == nullptr) {
        return;
      }
      if (projectileCategory == nullptr || !projectileCategory->mBits.Contains(blueprint->mCategoryBitIndex)) {
        return;
      }

      const Wm3::Vec3f worldPosition = entity->GetInterpolatedTransform(tickFraction).pos_;

      // Own and allied projectiles are always drawn; everyone else's have to be
      // under recon cover, and an underwater projectile is checked against the
      // fog grid rather than the explored grid.
      if (
        focusArmy != nullptr && !focusArmy->IsAlly(static_cast<std::uint32_t>(entity->mArmy->mArmyIndex)) &&
        !focusArmy->CanSeePoint(
          worldPosition,
          (entity->mVariableData.mLayerMask & kLayerUnderwaterMask) != 0 ? UserArmy::EReconGridMask::Fog
                                                                         : UserArmy::EReconGridMask::Explored
        )
      ) {
        return;
      }
      out.mBlueprint = blueprint;
      out.mPosition = worldPosition;
    };
    static std::vector<ProjectileIconTest> sProjectileTests;
    constexpr std::size_t kParallelProjectileMin = 1024U;
    constexpr std::size_t kParallelProjectileChunk = 512U;
    const bool testedAhead =
      iconsOnGpu && visibleEntities.size() >= kParallelProjectileMin && CUserWorkerPool::ConfiguredWorkerCount() != 0U;
    if (testedAhead) {
      sProjectileTests.resize(visibleEntities.size());
      CUserWorkerPool::Get().ParallelFor(
        visibleEntities.size(), kParallelProjectileChunk, [&](const std::size_t begin, const std::size_t end) {
        for (std::size_t i = begin; i < end; ++i) {
          testProjectile(visibleEntities[i], sProjectileTests[i]);
        }
      }
      );
    }

    for (std::size_t entityIndex = 0; entityIndex < visibleEntities.size(); ++entityIndex) {
      UserEntity* const entity = visibleEntities[entityIndex];
      ProjectileIconTest tested{};
      if (testedAhead) {
        tested = sProjectileTests[entityIndex];
      } else {
        testProjectile(entity, tested);
      }
      if (tested.mBlueprint == nullptr) {
        continue;
      }
      const RProjectileBlueprint* const blueprint = tested.mBlueprint;
      const Wm3::Vec3f worldPosition = tested.mPosition;

      boost::shared_ptr<CD3DBatchTexture> icon{};
      float halfWidth = 0.0f;
      float halfHeight = 0.0f;
      bool usesIconTexture = false;

      if (!blueprint->mStrategicIconName.empty()) {
        if (!UI_RenProjectileIcons) {
          continue;
        }
        icon = CD3DBatchTexture::FromFile(blueprint->mStrategicIconName.c_str(), 0u);
        if (!icon) {
          continue;
        }
        // Sized from the texture itself, so an icon is drawn at its authored
        // pixel size regardless of zoom, times `ui_ProjectileIconScale` (FAF
        // FA-Binary-Patches #147, 0x008625A3).
        halfWidth = static_cast<float>(icon->mWidth >> 1u) * ui_ProjectileIconScale;
        halfHeight = static_cast<float>(icon->mHeight >> 1u) * ui_ProjectileIconScale;
        usesIconTexture = true;
        if (UI_RenProjectileGlow) {
          primBatcher->Flush();
          (void)primBatcher->Setup(kProjectileIconTechnique);
        }
      } else {
        UserArmy* const owningArmy = entity->mArmy;
        if (owningArmy == nullptr) {
          continue;
        }
        // Engine change: `FromSolidColor` returns the one cached texture of a colour, so the pass
        // keeps the handles it already asked for instead of asking again per projectile.
        const std::uint32_t solidColor =
          UI_forceWeaponsToYellow ? kProjectileForcedColor : owningArmy->mVarDat.mPlayerColorBgra;
        const auto cached = std::find_if(solidIcons.begin(), solidIcons.end(), [solidColor](const auto& entry) {
          return entry.first == solidColor;
        });
        if (cached != solidIcons.end()) {
          icon = cached->second;
        } else {
          icon = CD3DBatchTexture::FromSolidColor(solidColor);
          solidIcons.emplace_back(solidColor, icon);
        }
        if (!icon) {
          continue;
        }
        // FAF FA-Binary-Patches #147: times `ui_ProjectileIconScale` (0x0086269C).
        halfWidth = blueprint->Display.StrategicIconSize * 0.5f * ui_ProjectileIconScale;
        halfHeight = halfWidth;
      }

      const bool drawsGlow = usesIconTexture && UI_RenProjectileGlow;
      if (iconsOnGpu && !drawsGlow) {
        const Wm3::Vector2f projected = view.Project(worldPosition, 0.0f, viewportWidth, viewportHeight, 0.0f);
        gpuIcons.Add(icon, std::floor(projected.x), std::floor(projected.y), halfWidth, halfHeight);
        continue;
      }
      if (iconsOnGpu) {
        // This one draws through the batcher, after the icons collected so far.
        flushGpuIcons();
      }

      primBatcher->SetTexture(icon);

      const Wm3::Vector2f projected = view.Project(worldPosition, 0.0f, viewportWidth, viewportHeight, 0.0f);
      // Snapped to whole pixels so the icon samples its texels 1:1.
      const float centerX = std::floor(projected.x);
      const float centerY = std::floor(projected.y);

      const float left = centerX - halfWidth;
      const float right = centerX + halfWidth;
      const float top = centerY - halfHeight;
      const float bottom = centerY + halfHeight;

      const CD3DPrimBatcher::Vertex topLeft{left, top, 1.0f, kProjectileIconColor, 0.0f, 1.0f};
      const CD3DPrimBatcher::Vertex topRight{left, bottom, 1.0f, kProjectileIconColor, 0.0f, 0.0f};
      const CD3DPrimBatcher::Vertex bottomRight{right, bottom, 1.0f, kProjectileIconColor, 1.0f, 0.0f};
      const CD3DPrimBatcher::Vertex bottomLeft{right, top, 1.0f, kProjectileIconColor, 1.0f, 1.0f};
      primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);

      if (!usesIconTexture || !UI_RenProjectileGlow) {
        continue;
      }

      // Glow pass: a second quad over the icon whose alpha pulses on a shared
      // global timer, so every projectile icon on screen pulses in step.
      primBatcher->Flush();
      (void)primBatcher->Setup("TCommandGlow");

      UI_CurGlowTime = (UI_CurGlowTime <= UI_RenProjectileGlowPeriod) ? UI_CurGlowTime + frameSeconds : 0.0f;

      const float halfPeriod = UI_RenProjectileGlowPeriod * 0.5f;
      float glowFrom = UI_RenProjectileGlowMax;
      float glowTo = UI_RenProjectileGlowMin;
      float glowElapsed = UI_CurGlowTime;
      if (glowElapsed > halfPeriod) {
        glowFrom = UI_RenProjectileGlowMin;
        glowTo = UI_RenProjectileGlowMax;
        glowElapsed -= halfPeriod;
      }

      const float glow = (((glowFrom - glowTo) / halfPeriod) * glowElapsed) + glowTo;
      const std::uint32_t glowColor = static_cast<std::uint32_t>(static_cast<std::uint8_t>(glow * 255.0f)) << 24u;

      const CD3DPrimBatcher::Vertex glowTopLeft{right, top, 1.0f, glowColor, 1.0f, 1.0f};
      const CD3DPrimBatcher::Vertex glowTopRight{left, top, 1.0f, glowColor, 0.0f, 1.0f};
      const CD3DPrimBatcher::Vertex glowBottomRight{left, bottom, 1.0f, glowColor, 0.0f, 0.0f};
      const CD3DPrimBatcher::Vertex glowBottomLeft{right, bottom, 1.0f, glowColor, 1.0f, 0.0f};
      primBatcher->DrawQuad(glowTopLeft, glowTopRight, glowBottomRight, glowBottomLeft);
      primBatcher->Flush();
      // The batcher stays on TCommandGlow for the rest of the pass.
      iconsOnGpu = false;
    }

    flushGpuIcons();
    primBatcher->Flush();
  }
  namespace
  {
    /** "/env/common/splats/mass_strategic.dds" - literal at 0x00E47488. */
    constexpr const char* kMassStrategicSplat = "/env/common/splats/mass_strategic.dds";

    /** "/env/common/splats/hydrocarbon_strategic.dds" - literal at 0x00E474B0. */
    constexpr const char* kHydrocarbonStrategicSplat = "/env/common/splats/hydrocarbon_strategic.dds";

    /**
     * Splat quads are drawn unmodulated (`or eax, 0FFFFFFFFh` at 0x00862F63 /
     * 0x00863361 feeds all four vertex colour lanes); the tint lives in the
     * texture.
     */
    constexpr std::uint32_t kResourceSplatColor = 0xFFFFFFFFu;

    /**
     * A splat quad is half the texture's pixel size: both extents are the
     * dimension shifted right by two, i.e. width/4 either side of the centre
     * (`shr eax, 2` at 0x0086309D / 0x008630B9, and again at 0x00863298 /
     * 0x008632B4). The `fild` + negative fixup around each shift is the
     * unsigned-to-float conversion of the `std::uint32_t` dimension.
     */
    constexpr std::uint32_t kResourceSplatHalfExtentShift = 2u;

    /**
     * Address: 0x0086309A..0x0086325A (mass splat run, inlined)
     * Address: 0x00863295..0x00863455 (hydrocarbon splat run, inlined)
     *
     * What it does:
     * Binds one strategic-resource splat texture and emits one screen-space
     * quad per collected deposit centre. The compiler emitted this twice, once
     * per resource kind, from what was plainly one helper: both runs compute
     * the same half-extents, bind through the same `SetTexture` overload and
     * build the same four vertices, differing only in which stack slots the
     * scheduler picked for them.
     *
     * A missing texture skips the whole run (`test ecx, ecx` / `jz` at
     * 0x00863092 and 0x0086328D), but an empty point list still binds the
     * texture - the count test comes after `SetTexture` in both runs.
     */
    void DrawResourceSplats(
      CD3DPrimBatcher& primBatcher,
      const boost::shared_ptr<CD3DBatchTexture>& splat,
      const gpg::fastvector<Wm3::Vector2f>& screenPoints
    )
    {
      if (!splat) {
        return;
      }

      // FAF FA-Binary-Patches #147 (Scale projectile/deposit/strategic icons): times
      // `ui_DepositIconScale` (0x008630A0 mass, 0x0086329D hydrocarbon).
      const float halfWidth = static_cast<float>(splat->mWidth >> kResourceSplatHalfExtentShift) * ui_DepositIconScale;
      const float halfHeight =
        static_cast<float>(splat->mHeight >> kResourceSplatHalfExtentShift) * ui_DepositIconScale;
      primBatcher.SetTexture(splat);

      for (const Wm3::Vector2f& centre : screenPoints) {
        const float left = centre.X() - halfWidth;
        const float right = centre.X() + halfWidth;
        const float top = centre.Y() - halfHeight;
        const float bottom = centre.Y() + halfHeight;

        const CD3DPrimBatcher::Vertex topLeft{left, top, 0.0f, kResourceSplatColor, 0.0f, 0.0f};
        const CD3DPrimBatcher::Vertex bottomLeft{left, bottom, 0.0f, kResourceSplatColor, 0.0f, 1.0f};
        const CD3DPrimBatcher::Vertex bottomRight{right, bottom, 0.0f, kResourceSplatColor, 1.0f, 1.0f};
        const CD3DPrimBatcher::Vertex topRight{right, top, 0.0f, kResourceSplatColor, 1.0f, 0.0f};
        primBatcher.DrawQuad(topLeft, bottomLeft, bottomRight, topRight);
      }
    }
  } // namespace

  /**
   * Address: 0x00862A80 (FUN_00862A80, ?RenderResources@CWldSession@Moho@@QAEXPAVGeomCamera3@2@PAVCD3DPrimBatcher@2@@Z)
   *
   * IDA signature:
   * void __usercall Moho::CWldSession::RenderResources(Moho::CWldSession *this,
   *   Moho::GeomCamera3 *camera@<ecx>, Moho::CD3DPrimBatcher *primBatcher);
   *
   * What it does:
   * Draws the strategic-view mass and hydrocarbon splats. Binds the
   * `TResourceIcon` technique of the `primbatcher` effect, pushes the wall
   * clock into that effect's `time` variable, switches the batcher to the
   * pixel-exact screen projection, then asks the sim's resource registry for
   * every deposit whose terrain AABB intersects the camera's second frustum
   * solid. Each deposit that lies wholly inside the playable rect and whose
   * terrain-height centre is nearer than `UI_ResourceLODCutoff` is projected
   * to a whole screen pixel and bucketed by resource kind; the two buckets are
   * then drawn with their respective splat textures and flushed.
   *
   * Locals map, from the frame slots the disassembly actually uses (IDA's own
   * frame naming past 0x00862D3A is shifted 0x10 low because it does not model
   * the indirect `DepositCollides` call's argument purge, which is why the
   * decompile aliases unrelated slots onto one another):
   *   ebp-0x7F8 `gpg::fastvector_n<Wm3::Vector2f, 16>` hydrocarbon points
   *             (inline window ebp-0x7E8 .. ebp-0x768 = 0x80 bytes)
   *   ebp-0x768 `gpg::fastvector_n<Wm3::Vector2f, 64>` mass points
   *             (inline window ebp-0x758 .. ebp-0x558 = 0x200 bytes)
   *   ebp-0x558 `gpg::fastvector_n<ResourceDeposit, 64>` query output
   *             (inline window ebp-0x548 .. ebp-0x48  = 0x500 bytes)
   *   ebp-0x898 .. ebp-0x88C  the playable rect, copied out of `STIMap`
   *   ebp-0x8B0 .. ebp-0x8A8  the deposit centre (x, terrain height, z)
   *   ebp-0x8B8 / ebp-0x8B4   the floored screen pixel
   *   ebp-0x848 / ebp-0x850   the mass / hydrocarbon splat handles
   */
  void CWldSession::RenderResources(
    GeomCamera3* const camera,
    CD3DPrimBatcher* const primBatcher
  )
  {
    // 0x00862AA6..0x00862ACC: `D3D_GetDevice()->SelectFxFile("primbatcher")`,
    // `SelectTechnique("TResourceIcon")` and the composite-matrix invalidation
    // are `CD3DPrimBatcher::Setup` (0x00438560) inlined verbatim.
    (void)primBatcher->Setup("TResourceIcon");

    // The resource-icon shader animates off the process wall clock, not off a
    // sim tick - `gpg::time::GetSystemTimer().ElapsedSeconds()` at
    // 0x00862AD3/0x00862ADA.
    const float shaderTime = gpg::time::GetSystemTimer().ElapsedSeconds();
    if (shaderVarPrimBatcherTime.Exists()) {
      shaderVarPrimBatcherTime.SetFloat(shaderTime);
    }

    // Raw viewport extents, not the whole-pixel truncation the projection
    // matrix below uses: 0x00862B18/0x00862B20 keep the untruncated floats and
    // 0x00862F42/0x00862F56 map NDC onto them.
    const float viewportWidth = camera->viewport.r[3].z;
    const float viewportHeight = camera->viewport.r[3].w;

    // `mWldMap->mTerrainRes` + 0x04 is the active `STIMap`; its playable rect
    // sits at +0x08 (0x00862B09..0x00862B4D reads all four bounds).
    const VisibilityRect& playableRect = VisibilityRect::FromRect2i(mWldMap->mTerrainRes->mMap->mPlayableRect);

    primBatcher->SetProjectionMatrix(MakeViewportPixelProjection(*camera));
    primBatcher->SetViewMatrix(VMatrix4::Identity());

    IResources* const resources = mSimResources.px;
    CHeightField* const heightField = mWldMap->mTerrainRes->GetHeightField();

    // Declaration order is the binary's: the tail destroys the query output
    // first (0x008634DB), then the hydrocarbon bucket (0x00863512), then the
    // mass bucket (0x00863549).
    gpg::fastvector_n<Wm3::Vector2f, 64> massPoints;
    gpg::fastvector_n<Wm3::Vector2f, 16> hydrocarbonPoints;

    // The binary hands `DepositCollides` a 64-deposit inline fastvector. This
    // tree's `CSimResources::DepositCollides` takes the plain
    // `gpg::fastvector<T>` base and appends through that base's `PushBack`,
    // whose grow path frees `start_` unconditionally, so an inline window
    // cannot be handed across the call - heap-backed on purpose, same as the
    // projectile-arc `Collect` site.
    gpg::fastvector<ResourceDeposit> deposits;

    // Virtual dispatch through `IResources` slot 7 (`[vftable+0x1C]` at
    // 0x00862D2D..0x00862D3A). `kNone` asks for every deposit kind.
    resources->DepositCollides(&camera->solid2, heightField, &deposits, kNone);

    for (const ResourceDeposit& deposit : deposits) {
      const gpg::Rect2i& footprint = deposit.footprintRect;

      // Centre of the integer footprint, computed the binary's way: the extent
      // is differenced in integers first, then halved and re-based
      // (0x00862D8A..0x00862DC5).
      const float centreX = (static_cast<float>(footprint.x1 - footprint.x0) * 0.5f) + static_cast<float>(footprint.x0);
      const float centreZ = (static_cast<float>(footprint.z1 - footprint.z0) * 0.5f) + static_cast<float>(footprint.z0);

      // A deposit that pokes out of the playable rect is dropped whole, not
      // clipped (four signed compares at 0x00862DB1..0x00862DF4).
      if (
        footprint.x0 < playableRect.minX || playableRect.maxX < footprint.x1 || footprint.z0 < playableRect.minZ ||
        playableRect.maxZ < footprint.z1
      ) {
        continue;
      }

      const Wm3::Vector3f centre{centreX, heightField->GetElevation(centreX, centreZ), centreZ};

      // Row 1 of the viewport matrix carries the renderer's LOD depth; splats
      // stop drawing past the cutoff (0x00862E15..0x00862E6F).
      if (camera->viewport.ProjectViewportDepthRow1(centre) <= UI_ResourceLODCutoff) {
        continue;
      }

      // 0x00862E75..0x00862F5F is `GeomCamera3::Project` (0x00470F60) inlined
      // over a viewport anchored at the origin with a flipped Y axis: x maps
      // onto [0, width] and y onto [height, -0]. The two zero terms fold away
      // in the emission, which is why no `sub`/`add` against them survives.
      const Wm3::Vector2f projected = camera->Project(centre, 0.0f, viewportWidth, viewportHeight, -0.0f);

      // Splats snap to whole pixels so the texture samples 1:1 (two `floor`
      // calls at 0x00862F81 / 0x00862F91).
      const Wm3::Vector2f screenPoint{std::floor(projected.X()), std::floor(projected.Y())};

      if (deposit.depositType == kMass) {
        massPoints.push_back(screenPoint);
      } else {
        hydrocarbonPoints.push_back(screenPoint);
      }
    }

    // Both handles stay alive until after the flush - the binary releases the
    // hydrocarbon one at 0x00863469 and the mass one at 0x008634A6, both past
    // `Flush`. The `1` border argument asks `FromFile` for a one-texel guard
    // band so the atlas neighbours cannot bleed into the splat.
    const boost::shared_ptr<CD3DBatchTexture> massSplat = CD3DBatchTexture::FromFile(kMassStrategicSplat, 1u);
    DrawResourceSplats(*primBatcher, massSplat, massPoints);

    const boost::shared_ptr<CD3DBatchTexture> hydrocarbonSplat =
      CD3DBatchTexture::FromFile(kHydrocarbonStrategicSplat, 1u);
    DrawResourceSplats(*primBatcher, hydrocarbonSplat, hydrocarbonPoints);

    primBatcher->Flush();
  }
  namespace
  {
    // The economy lanes below are per-tick rates and the overlay shows them per
    // second; the sim runs ten ticks a second (0x00DFF31C).
    constexpr float kEconOverlayTicksPerSecond = 10.0f;

    // Inside this magnitude the rate is printed with one decimal, outside it as
    // a whole number (0x008591FA / 0x0085927B against 0x00DFF31C / 0x00E4F910).
    constexpr float kEconOverlayDecimalCutoff = 10.0f;

    // Opaque black - the drop-shadow pass (pushed at 0x008597B9 / 0x008598A8).
    constexpr std::uint32_t kEconOverlayShadowColor = 0xFF000000u;

    // Unmodulated white - the bar slices carry their own texture colour.
    constexpr std::uint32_t kEconOverlayBarColor = 0xFFFFFFFFu;

    // The shadow pass is offset one pixel right and down (0x00DFEC20 == 1.0f).
    constexpr float kEconOverlayShadowOffset = 1.0f;

    // `/lua/ui/game/econoverlayparams.lua` lanes, in the order the import reads
    // them. Each is left at its previous value when the key is absent, so the
    // initial values are the ones the shipped .data holds.
    std::uint32_t gEconOverlayPositiveColor = 0xFF00D800u;          // 0x00F57C00
    std::uint32_t gEconOverlayNegativeColor = 0xFFD80000u;          // 0x00F57BFC
    boost::shared_ptr<CD3DBatchTexture> gEconOverlayLeftTexture{};  // 0x010C4230
    boost::shared_ptr<CD3DBatchTexture> gEconOverlayRightTexture{}; // 0x010C4238
    boost::shared_ptr<CD3DBatchTexture> gEconOverlayMidTexture{};   // 0x010C4244
    fa::string gEconOverlayFontName{};                              // 0x00F5B210
    std::int32_t gEconOverlayFontSize = 12;                         // 0x00F57C04
    float gEconOverlayEnergyTopOffset = 0.0f;                       // 0x010A6458
    float gEconOverlayMassTopOffset = 14.0f;                        // 0x00F57C08

    bool gEconOverlayParamsImported = false; // 0x010A6449
    CD3DFont* gEconOverlayFont = nullptr;    // 0x010C4228

    /**
     * Address: 0x00858850 (FUN_00858850, Moho::func_ImportEconOverlayParams)
     *
     * IDA signature:
     * void __cdecl func_ImportEconOverlayParams();
     *
     * What it does:
     * Imports `/lua/ui/game/econoverlayparams.lua` and copies the nine optional
     * `EconOverlayParams` fields into the lanes above. Every field is looked up
     * twice exactly as the binary does it: once for an `IsNil` probe on a
     * throwaway object, and again to read the value, so a missing key leaves
     * the previous value untouched.
     */
    void ImportEconOverlayParams()
    {
      LuaPlus::LuaState* const state = static_cast<CUIManager*>(UI_GetManager())->mLuaState;

      LuaPlus::LuaObject module = SCR_Import(state, "/lua/ui/game/econoverlayparams.lua");
      if (module.IsNil()) {
        return;
      }

      LuaPlus::LuaObject params = module["EconOverlayParams"];
      if (!params.IsTable()) {
        return;
      }

      if (!params["positiveColor"].IsNil()) {
        gEconOverlayPositiveColor = SCR_DecodeColor(state, params["positiveColor"]);
      }
      if (!params["negativeColor"].IsNil()) {
        gEconOverlayNegativeColor = SCR_DecodeColor(state, params["negativeColor"]);
      }
      if (!params["leftTexture"].IsNil()) {
        gEconOverlayLeftTexture = CD3DBatchTexture::FromFile(params["leftTexture"].GetString(), 1u);
      }
      if (!params["midTexture"].IsNil()) {
        gEconOverlayMidTexture = CD3DBatchTexture::FromFile(params["midTexture"].GetString(), 1u);
      }
      if (!params["rightTexture"].IsNil()) {
        gEconOverlayRightTexture = CD3DBatchTexture::FromFile(params["rightTexture"].GetString(), 1u);
      }
      if (!params["fontName"].IsNil()) {
        const char* const fontName = params["fontName"].GetString();
        (void)gEconOverlayFontName.assign(fontName, std::strlen(fontName));
      }
      if (!params["fontSize"].IsNil()) {
        gEconOverlayFontSize = static_cast<std::int32_t>(params["fontSize"].GetNumber());
      }
      if (!params["energyTopOffset"].IsNil()) {
        gEconOverlayEnergyTopOffset = static_cast<float>(params["energyTopOffset"].GetNumber());
      }
      if (!params["massTopOffset"].IsNil()) {
        gEconOverlayMassTopOffset = static_cast<float>(params["massTopOffset"].GetNumber());
      }
    }

    /**
     * What it does:
     * Formats one per-second resource rate into `out` the way the overlay does
     * it at 0x008591E3 and 0x00859275: one decimal while the magnitude stays
     * inside +/-10, a whole number outside it. NaN takes the whole-number path,
     * because the binary branches on an unordered `comiss`.
     *
     * The binary prints into a temporary and then assigns that temporary into
     * the caller's string; kept in that shape so the temporary's storage is
     * released before the draw, as in the binary.
     */
    void FormatEconomyRateInto(
      fa::string& out,
      const float ratePerSecond,
      const char* const wholeFormat,
      const char* const decimalFormat
    )
    {
      const bool useDecimals = kEconOverlayDecimalCutoff > ratePerSecond && ratePerSecond > -kEconOverlayDecimalCutoff;
      const fa::string formatted = useDecimals ? gpg::STR_Printf(decimalFormat, static_cast<double>(ratePerSecond))
                                               : gpg::STR_Printf(wholeFormat, static_cast<std::int32_t>(ratePerSecond));
      (void)out.assign(formatted, 0, fa::string::npos);
    }

    /**
     * What it does:
     * Emits one axis-aligned, fully-mapped quad of the economy bar. The three
     * slice draws at 0x0085952E, 0x00859659 and 0x0085977F write byte-identical
     * vertex blocks apart from the x range, so they share this helper.
     */
    void DrawEconomyOverlaySlice(
      CD3DPrimBatcher& primBatcher,
      const float x0,
      const float y0,
      const float x1,
      const float y1
    )
    {
      const CD3DPrimBatcher::Vertex topLeft{x0, y0, 0.0f, kEconOverlayBarColor, 0.0f, 0.0f};
      const CD3DPrimBatcher::Vertex topRight{x1, y0, 0.0f, kEconOverlayBarColor, 1.0f, 0.0f};
      const CD3DPrimBatcher::Vertex bottomRight{x1, y1, 0.0f, kEconOverlayBarColor, 1.0f, 1.0f};
      const CD3DPrimBatcher::Vertex bottomLeft{x0, y1, 0.0f, kEconOverlayBarColor, 0.0f, 1.0f};
      primBatcher.DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
    }

    /**
     * What it does:
     * Draws one economy number. `Render2D`'s two trailing floats are not
     * materialised at the binary's call sites (0x008597FB, 0x00859877,
     * 0x008598E5 and 0x00859961 push only this/text/colour and hand the origin
     * over in `eax`), and the recovered `Render2D` ignores `maxAdvance` while
     * `Render` ignores `glyphScale`, so both are passed as zero here.
     */
    void DrawEconomyOverlayLabel(
      CD3DFont& font,
      CD3DPrimBatcher& primBatcher,
      const fa::string& text,
      const float x,
      const float y,
      const std::uint32_t color
    )
    {
      const Wm3::Vector2f origin{x, y};
      font.Render2D(text.c_str(), &primBatcher, origin, color, 0.0f, 0.0f);
    }
  } // namespace

  /**
   * Address: 0x00858D80 (FUN_00858D80, Moho::CWldSession::DrawEconomyOverlay)
   *
   * IDA signature:
   * void __usercall Moho::CWldSession::DrawEconomyOverlay(
   *   CWldSession *session, CD3DPrimBatcher *batcher, CWldMap *map,
   *   CameraImpl *camera@<ecx>);
   *
   * What it does:
   * Draws the net energy/mass rate readout over every army unit in the camera
   * frustum - see the header for the full description.
   */
  void CWldSession::DrawEconomyOverlay(
    CameraImpl* const camera,
    CD3DPrimBatcher* const primBatcher,
    [[maybe_unused]] const float tickFraction
  )
  {
    if (!DisplayEconomyOverlay) {
      return;
    }

    if (!gEconOverlayParamsImported) {
      ImportEconOverlayParams();
      gEconOverlayParamsImported = true;
    }

    if (gEconOverlayFont == nullptr) {
      // `Create` hands back a borrowed shared lane; the overlay keeps its own
      // intrusive reference on the font and releases the lane straight away.
      boost::SharedPtrRaw<CD3DFont> created = CD3DFont::Create(gEconOverlayFontSize, gEconOverlayFontName.c_str());
      CD3DFont* const font = created.px;
      if (gEconOverlayFont != font) {
        if (gEconOverlayFont != nullptr) {
          (void)gEconOverlayFont->ReleaseReference();
        }
        gEconOverlayFont = font;
        if (font != nullptr) {
          font->AddReference();
        }
      }
      created.release();
    }

    (void)primBatcher->Setup("TAlphaBlendLinearSampleNoDepth");

    const GeomCamera3& view = camera->CameraGetView();

    // The binary inlines the same pixel-exact screen projection here that
    // RenderProjectileArcs inlines at 0x0086010B; it lives on GeomCamera3 now.
    const float viewportWidth = static_cast<float>(static_cast<std::int32_t>(view.viewport.r[3].z));
    const float viewportHeight = static_cast<float>(static_cast<std::int32_t>(view.viewport.r[3].w));

    primBatcher->SetProjectionMatrix(MakeViewportPixelProjection(view));
    primBatcher->SetViewMatrix(VMatrix4::Identity()); // 0x00858FE6 (sIdentity)

    for (const WeakPtr<UserEntity>& weakRef : *camera->GetArmyUnitsInFrustum()) {
      UserEntity* const entity = weakRef.GetObjectPtr();
      if (entity == nullptr) {
        continue;
      }

      UserUnit* const unit = entity->IsUserUnit();
      if (unit == nullptr) {
        continue;
      }

      IUnit* const unitBridge = GetIUnitBridge(unit);
      if (unitBridge->IsDead() || unitBridge->DestroyQueued()) {
        continue;
      }

      // Only units still drawn as meshes get the readout: past the mesh's
      // icon-fade-in depth the unit is a strategic icon and the bar would
      // clutter the map.
      const RMeshBlueprint* const meshBlueprint = unit->mVariableData.mMeshBlueprint;
      if (meshBlueprint == nullptr) {
        continue;
      }
      if (view.viewport.ProjectViewportDepthRow1(unitBridge->GetPosition()) >= meshBlueprint->mIconFadeInZoom) {
        continue;
      }

      // The binary dispatches through the blueprint accessor here and discards
      // the result (0x008590CF); kept because the virtual call is observable.
      (void)unitBridge->GetBlueprint();

      const SSTIUnitEconomyPair& produced = unit->mUnitVarDat.mProduced;
      const SSTIUnitEconomyPair& upkeep = unit->mUnitVarDat.mMaintainenceCost;
      const float energyRate = produced.ENERGY - upkeep.ENERGY;
      const float massRate = produced.MASS - upkeep.MASS;
      if (energyRate == 0.0f && massRate == 0.0f) {
        continue;
      }

      const float energyPerSecond = energyRate * kEconOverlayTicksPerSecond;
      const float massPerSecond = massRate * kEconOverlayTicksPerSecond;

      // Not a parameter: the binary reads a frame local at -4 that is stored
      // once from a zeroed ebx (0x00858DAF -> 0x00858E0E) and never rewritten,
      // so the overlay always samples the untick-interpolated position.
      const Wm3::Vector3f worldPosition = entity->GetInterpolatedPosition(0.0f);
      const Wm3::Vector2f screenPosition = view.Project(worldPosition, 0.0f, viewportWidth, viewportHeight, 0.0f);

      fa::string energyText{};
      fa::string massText{};
      FormatEconomyRateInto(energyText, energyPerSecond, "%+4i ", "%+4.1f ");
      FormatEconomyRateInto(massText, massPerSecond, "%+4i", "%+4.1f");

      // The bar is as wide as the wider of the two numbers and as tall as the
      // middle slice, centred on the projected position and snapped to whole
      // pixels.
      const float energyAdvance = gEconOverlayFont->GetAdvance(energyText.c_str(), 0);
      const float massAdvance = gEconOverlayFont->GetAdvance(massText.c_str(), 0);
      const float barWidth = massAdvance > energyAdvance ? massAdvance : energyAdvance;
      const float barHeight = static_cast<float>(gEconOverlayMidTexture->mHeight);

      const float barLeft = std::floor(screenPosition.x - (barWidth * 0.5f));
      const float barTop = std::floor(screenPosition.y - (barHeight * 0.5f));
      const float barRight = barLeft + barWidth;
      const float barBottom = barTop + barHeight;

      primBatcher->SetTexture(gEconOverlayMidTexture);
      DrawEconomyOverlaySlice(*primBatcher, barLeft, barTop, barRight, barBottom);

      primBatcher->SetTexture(gEconOverlayLeftTexture);
      const float leftCapWidth = static_cast<float>(gEconOverlayLeftTexture->mWidth);
      DrawEconomyOverlaySlice(*primBatcher, barLeft - leftCapWidth, barTop, barLeft, barBottom);

      primBatcher->SetTexture(gEconOverlayRightTexture);
      const float rightCapWidth = static_cast<float>(gEconOverlayRightTexture->mWidth);
      DrawEconomyOverlaySlice(*primBatcher, barRight, barTop, barRight + rightCapWidth, barBottom);

      // Each number is drawn twice: an opaque black shadow one pixel down and
      // right, then the value itself in the sign colour.
      const float fontHeight = gEconOverlayFont->mHeight;
      const float energyBaseline = std::floor(gEconOverlayEnergyTopOffset) + fontHeight + barTop;
      const float massBaseline = std::floor(gEconOverlayMassTopOffset) + fontHeight + barTop;
      const std::uint32_t energyColor = energyPerSecond < 0.0f ? gEconOverlayNegativeColor : gEconOverlayPositiveColor;
      const std::uint32_t massColor = massPerSecond < 0.0f ? gEconOverlayNegativeColor : gEconOverlayPositiveColor;

      DrawEconomyOverlayLabel(
        *gEconOverlayFont,
        *primBatcher,
        energyText,
        barLeft + kEconOverlayShadowOffset,
        energyBaseline + kEconOverlayShadowOffset,
        kEconOverlayShadowColor
      );
      DrawEconomyOverlayLabel(*gEconOverlayFont, *primBatcher, energyText, barLeft, energyBaseline, energyColor);
      DrawEconomyOverlayLabel(
        *gEconOverlayFont,
        *primBatcher,
        massText,
        barLeft + kEconOverlayShadowOffset,
        massBaseline + kEconOverlayShadowOffset,
        kEconOverlayShadowColor
      );
      DrawEconomyOverlayLabel(*gEconOverlayFont, *primBatcher, massText, barLeft, massBaseline, massColor);
    }

    primBatcher->Flush();
  }
} // namespace moho
