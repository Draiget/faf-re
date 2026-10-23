#include "moho/render/RangeRendererStartupRegistrations.h"

#include "moho/console/CConCommand.h"

namespace moho
{
  // Byte-verified defaults from `bin/external/ForgedAlliance.exe`.
  //
  // The four range flags sit past the end of `.data`'s raw image (the
  // zero-initialised `.bss` tail at VA 0x010A640A..0x010A6415), so the loader
  // zeroes them: every range-ring pass is off until the console or a profile
  // turns it on. `ren_Ranges` and the two thickness coefficients live in real
  // `.data` and carry initialisers - 0x00F57E4F reads `01`, and both
  // coefficients read `00 00 80 3A` == 0.0009765625f (1/1024).
  bool range_RenderSelected = false;
  bool range_RenderHighlighted = false;
  bool range_RenderBuild = false;
  bool range_Fill = false;
  float range_InnerThicknessCoeff = 0.0009765625f;
  float range_OuterThicknessCoeff = 0.0009765625f;
  bool ren_Ranges = true;

  // NOT IN THE ORIGINAL BINARY - see the header. Additive, defaults off.
  bool range_RenderSelectedAtCursor = false;

  // NOT IN THE ORIGINAL BINARY - see the header. Additive, defaults off.
  bool range_RenderReclaimAtCursor = false;

  // NOT IN THE ORIGINAL BINARY - see the header. Additive, defaults off.
  bool range_RenderHoveredAttack = false;
} // namespace moho

namespace
{
  // The binary's console-variable objects are statically constructed globals
  // whose name/description lanes are baked into `.data` and whose vftable and
  // value pointer are patched in by the `register_*` static initialisers below
  // (see 0x00BE0AD0: `mov <obj>.__vftable, offset TConVar<bool>::vftable`
  // followed by `mov <obj>.mValue, offset <global>`).
  //
  // Every description pointer in this family resolves to the empty string in
  // the image, so the recovered objects pass "" rather than inventing help
  // text that the shipped binary does not carry.
  constexpr const char* kRangeConVarNoDescription = "";

  /**
   * Address: 0x00BE0AD0 (FUN_00BE0AD0, dynamic initializer for `gTConVar_range_RenderSelected`)
   * Address: 0x00C03F50 (FUN_00C03F50, dynamic atexit destructor for `gTConVar_range_RenderSelected`)
   *
   * Console object: 0x00F5A810.
   */
  moho::TConVar<bool> gTConVar_range_RenderSelected(
    "range_RenderSelected",
    kRangeConVarNoDescription,
    &moho::range_RenderSelected
  );

  /**
   * Address: 0x00BE0B10 (FUN_00BE0B10, dynamic initializer for `gTConVar_range_RenderHighlighted`)
   * Address: 0x00C03F80 (FUN_00C03F80, dynamic atexit destructor for `gTConVar_range_RenderHighlighted`)
   *
   * Console object: 0x00F5A820.
   */
  moho::TConVar<bool> gTConVar_range_RenderHighlighted(
    "range_RenderHighlighted",
    kRangeConVarNoDescription,
    &moho::range_RenderHighlighted
  );

  /**
   * Address: 0x00BE0B50 (FUN_00BE0B50, dynamic initializer for `gTConVar_range_RenderBuild`)
   * Address: 0x00C03FB0 (FUN_00C03FB0, dynamic atexit destructor for `gTConVar_range_RenderBuild`)
   *
   * Console object: 0x00F5A830.
   */
  moho::TConVar<bool> gTConVar_range_RenderBuild(
    "range_RenderBuild",
    kRangeConVarNoDescription,
    &moho::range_RenderBuild
  );

  /**
   * NOT IN THE ORIGINAL BINARY - no console object exists for this in the
   * image, so there is no address to cite. Registered the same way as the
   * recovered family so a mod can drive it with `ConExecute`.
   */
  moho::TConVar<bool> gTConVar_range_RenderSelectedAtCursor(
    "range_RenderSelectedAtCursor",
    kRangeConVarNoDescription,
    &moho::range_RenderSelectedAtCursor
  );

  /**
   * NOT IN THE ORIGINAL BINARY - additive extension, see the header. No
   * console object for this exists in the shipped image, so there is no
   * address to cite. Registered the same way as the recovered family so a mod
   * can drive it with `ConExecute`.
   */
  moho::TConVar<bool> gTConVar_range_RenderReclaimAtCursor(
    "range_RenderReclaimAtCursor",
    kRangeConVarNoDescription,
    &moho::range_RenderReclaimAtCursor
  );

  /**
   * NOT IN THE ORIGINAL BINARY - additive extension, see the header. No
   * console object for this exists in the shipped image, so there is no
   * address to cite. Registered the same way as the recovered family so a mod
   * can drive it with `ConExecute`.
   */
  moho::TConVar<bool> gTConVar_range_RenderHoveredAttack(
    "range_RenderHoveredAttack",
    kRangeConVarNoDescription,
    &moho::range_RenderHoveredAttack
  );

  /**
   * Address: 0x00BE0B90 (FUN_00BE0B90, dynamic initializer for `gTConVar_range_Fill`)
   * Address: 0x00C03FE0 (FUN_00C03FE0, dynamic atexit destructor for `gTConVar_range_Fill`)
   *
   * Console object: 0x00F5A840.
   */
  moho::TConVar<bool> gTConVar_range_Fill(
    "range_Fill",
    kRangeConVarNoDescription,
    &moho::range_Fill
  );

  /**
   * Address: 0x00BE0BD0 (FUN_00BE0BD0, dynamic initializer for `gTConVar_range_InnerThicknessCoeff`)
   * Address: 0x00C04010 (FUN_00C04010, dynamic atexit destructor for `gTConVar_range_InnerThicknessCoeff`)
   *
   * Console object: 0x00F5A850.
   */
  moho::TConVar<float> gTConVar_range_InnerThicknessCoeff(
    "range_InnerThicknessCoeff",
    kRangeConVarNoDescription,
    &moho::range_InnerThicknessCoeff
  );

  /**
   * Address: 0x00BE0C10 (FUN_00BE0C10, dynamic initializer for `gTConVar_range_OuterThicknessCoeff`)
   * Address: 0x00C04040 (FUN_00C04040, dynamic atexit destructor for `gTConVar_range_OuterThicknessCoeff`)
   *
   * Console object: 0x00F5A860.
   */
  moho::TConVar<float> gTConVar_range_OuterThicknessCoeff(
    "range_OuterThicknessCoeff",
    kRangeConVarNoDescription,
    &moho::range_OuterThicknessCoeff
  );

  /**
   * Address: 0x00BE1690 (FUN_00BE1690, dynamic initializer for `gTConVar_ren_Ranges`)
   * Address: 0x00C046F0 (FUN_00C046F0, dynamic atexit destructor for `gTConVar_ren_Ranges`)
   *
   * Console object: 0x00F5A9F8.
   */
  moho::TConVar<bool> gTConVar_ren_Ranges(
    "ren_Ranges",
    kRangeConVarNoDescription,
    &moho::ren_Ranges
  );
} // namespace
