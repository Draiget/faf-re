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

  /** Console object: 0x00F5A810. */
  moho::TConVar<bool> gTConVar_range_RenderSelected(
    "range_RenderSelected",
    kRangeConVarNoDescription,
    &moho::range_RenderSelected
  );

  /** Console object: 0x00F5A820. */
  moho::TConVar<bool> gTConVar_range_RenderHighlighted(
    "range_RenderHighlighted",
    kRangeConVarNoDescription,
    &moho::range_RenderHighlighted
  );

  /** Console object: 0x00F5A830. */
  moho::TConVar<bool> gTConVar_range_RenderBuild(
    "range_RenderBuild",
    kRangeConVarNoDescription,
    &moho::range_RenderBuild
  );

  /** Console object: 0x00F5A840. */
  moho::TConVar<bool> gTConVar_range_Fill(
    "range_Fill",
    kRangeConVarNoDescription,
    &moho::range_Fill
  );

  /** Console object: 0x00F5A850. */
  moho::TConVar<float> gTConVar_range_InnerThicknessCoeff(
    "range_InnerThicknessCoeff",
    kRangeConVarNoDescription,
    &moho::range_InnerThicknessCoeff
  );

  /** Console object: 0x00F5A860. */
  moho::TConVar<float> gTConVar_range_OuterThicknessCoeff(
    "range_OuterThicknessCoeff",
    kRangeConVarNoDescription,
    &moho::range_OuterThicknessCoeff
  );

  /** Console object: 0x00F5A9F8. */
  moho::TConVar<bool> gTConVar_ren_Ranges(
    "ren_Ranges",
    kRangeConVarNoDescription,
    &moho::ren_Ranges
  );
} // namespace

namespace moho
{
  /**
   * Address: 0x00C03F50 (FUN_00C03F50, ??1TConVar_range_RenderSelected@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `range_RenderSelected`.
   */
  void cleanup_TConVar_range_RenderSelected()
  {
    CleanupStartupConCommand(gTConVar_range_RenderSelected);
  }

  /**
   * Address: 0x00BE0AD0 (FUN_00BE0AD0, register_TConVar_range_RenderSelected)
   *
   * What it does:
   * Registers the selected-unit range-ring toggle into the process-global
   * console command map and schedules its teardown lane at exit.
   */
  void register_TConVar_range_RenderSelected()
  {
    RegisterStartupConVar(gTConVar_range_RenderSelected, &cleanup_TConVar_range_RenderSelected);
  }

  /**
   * Address: 0x00C03F80 (FUN_00C03F80, ??1TConVar_range_RenderHighlighted@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `range_RenderHighlighted`.
   */
  void cleanup_TConVar_range_RenderHighlighted()
  {
    CleanupStartupConCommand(gTConVar_range_RenderHighlighted);
  }

  /**
   * Address: 0x00BE0B10 (FUN_00BE0B10, register_TConVar_range_RenderHighlighted)
   *
   * What it does:
   * Registers the highlighted-unit range-ring toggle into the process-global
   * console command map and schedules its teardown lane at exit.
   */
  void register_TConVar_range_RenderHighlighted()
  {
    RegisterStartupConVar(gTConVar_range_RenderHighlighted, &cleanup_TConVar_range_RenderHighlighted);
  }

  /**
   * Address: 0x00C03FB0 (FUN_00C03FB0, ??1TConVar_range_RenderBuild@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `range_RenderBuild`.
   */
  void cleanup_TConVar_range_RenderBuild()
  {
    CleanupStartupConCommand(gTConVar_range_RenderBuild);
  }

  /**
   * Address: 0x00BE0B50 (FUN_00BE0B50, register_TConVar_range_RenderBuild)
   *
   * What it does:
   * Registers the build-placement range-ring toggle into the process-global
   * console command map and schedules its teardown lane at exit.
   */
  void register_TConVar_range_RenderBuild()
  {
    RegisterStartupConVar(gTConVar_range_RenderBuild, &cleanup_TConVar_range_RenderBuild);
  }

  /**
   * Address: 0x00C03FE0 (FUN_00C03FE0, ??1TConVar_range_Fill@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `range_Fill`.
   */
  void cleanup_TConVar_range_Fill()
  {
    CleanupStartupConCommand(gTConVar_range_Fill);
  }

  /**
   * Address: 0x00BE0B90 (FUN_00BE0B90, register_TConVar_range_Fill)
   *
   * What it does:
   * Registers the ring interior-fill toggle into the process-global console
   * command map and schedules its teardown lane at exit.
   */
  void register_TConVar_range_Fill()
  {
    RegisterStartupConVar(gTConVar_range_Fill, &cleanup_TConVar_range_Fill);
  }

  /**
   * Address: 0x00C04010 (FUN_00C04010, ??1TConVar_range_InnerThicknessCoeff@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `range_InnerThicknessCoeff`.
   */
  void cleanup_TConVar_range_InnerThicknessCoeff()
  {
    CleanupStartupConCommand(gTConVar_range_InnerThicknessCoeff);
  }

  /**
   * Address: 0x00BE0BD0 (FUN_00BE0BD0, register_TConVar_range_InnerThicknessCoeff)
   *
   * What it does:
   * Registers the inner ring thickness coefficient into the process-global
   * console command map and schedules its teardown lane at exit.
   */
  void register_TConVar_range_InnerThicknessCoeff()
  {
    RegisterStartupConVar(gTConVar_range_InnerThicknessCoeff, &cleanup_TConVar_range_InnerThicknessCoeff);
  }

  /**
   * Address: 0x00C04040 (FUN_00C04040, ??1TConVar_range_OuterThicknessCoeff@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `range_OuterThicknessCoeff`.
   */
  void cleanup_TConVar_range_OuterThicknessCoeff()
  {
    CleanupStartupConCommand(gTConVar_range_OuterThicknessCoeff);
  }

  /**
   * Address: 0x00BE0C10 (FUN_00BE0C10, register_TConVar_range_OuterThicknessCoeff)
   *
   * What it does:
   * Registers the outer ring thickness coefficient into the process-global
   * console command map and schedules its teardown lane at exit.
   */
  void register_TConVar_range_OuterThicknessCoeff()
  {
    RegisterStartupConVar(gTConVar_range_OuterThicknessCoeff, &cleanup_TConVar_range_OuterThicknessCoeff);
  }

  /**
   * Address: 0x00C046F0 (FUN_00C046F0, ??1TConVar_ren_Ranges@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_Ranges`.
   */
  void cleanup_TConVar_ren_Ranges()
  {
    CleanupStartupConCommand(gTConVar_ren_Ranges);
  }

  /**
   * Address: 0x00BE1690 (FUN_00BE1690, register_TConVar_ren_Ranges)
   *
   * What it does:
   * Registers the master range-ring viewport-pass enable into the
   * process-global console command map and schedules its teardown lane at exit.
   */
  void register_TConVar_ren_Ranges()
  {
    RegisterStartupConVar(gTConVar_ren_Ranges, &cleanup_TConVar_ren_Ranges);
  }
} // namespace moho

namespace
{
  /**
   * Static-initialiser dispatch for the range-ring console family.
   *
   * The binary reaches each `register_TConVar_range_*` through its `__xc_a`
   * static-initialiser array entry; this constructor is the recovered
   * equivalent and is what keeps the seven registration bodies linked in.
   */
  struct RangeRendererConsoleStartupRegistrations
  {
    RangeRendererConsoleStartupRegistrations()
    {
      moho::register_TConVar_range_RenderSelected();
      moho::register_TConVar_range_RenderHighlighted();
      moho::register_TConVar_range_RenderBuild();
      moho::register_TConVar_range_Fill();
      moho::register_TConVar_range_InnerThicknessCoeff();
      moho::register_TConVar_range_OuterThicknessCoeff();
      moho::register_TConVar_ren_Ranges();
    }
  };

  [[maybe_unused]] RangeRendererConsoleStartupRegistrations gRangeRendererConsoleStartupRegistrations;
} // namespace
