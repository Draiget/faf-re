#include "moho/sim/SimDebugCommandRegistrations.h"

#include "moho/console/CConAlias.h"
#include "moho/sim/CSimConFunc.h"
#include "moho/sim/CSimConVarBase.h"
#include "moho/sim/Sim.h"

namespace
{
  /**
   * Address: 0x00BCE420 (FUN_00BCE420, dynamic initializer for `gTConVar_ren_Steering`)
   * Address: 0x00BF80A0 (FUN_00BF80A0, dynamic atexit destructor for `gTConVar_ren_Steering`)
   */
  moho::TConVar<bool> gTConVar_ren_Steering("ren_Steering", "", reinterpret_cast<bool*>(&moho::ren_Steering));
} // namespace

namespace moho
{
  /**
   * Address: 0x00BDB130 (FUN_00BDB130, dynamic initializer for `gConAlias_sim_TestVarBool`)
   * Address: 0x00C00670 (FUN_00C00670, dynamic atexit destructor for `gConAlias_sim_TestVarBool`)
   */
  moho::CConAlias gConAlias_sim_TestVarBool("sim_TestVarBool", "Test variable - not used.", "DoSimCommand sim_TestVarBool");

  /**
   * Address: 0x00BDB160 (FUN_00BDB160, dynamic initializer for `gSimConVar_sim_TestVarBool`)
   * Address: 0x00C006C0 (FUN_00C006C0, dynamic atexit destructor for `gSimConVar_sim_TestVarBool`)
   */
  TSimConVar<bool> gSimConVar_sim_TestVarBool(false, "sim_TestVarBool", false);

  /**
   * Address: 0x00BDB1B0 (FUN_00BDB1B0, dynamic initializer for `gConAlias_sim_TestVar`)
   * Address: 0x00C006D0 (FUN_00C006D0, dynamic atexit destructor for `gConAlias_sim_TestVar`)
   */
  moho::CConAlias gConAlias_sim_TestVar("sim_TestVar", "Test variable - not used.", "DoSimCommand sim_TestVar");

  /**
   * Address: 0x00BDB1E0 (FUN_00BDB1E0, dynamic initializer for `gSimConVar_sim_TestVar`)
   * Address: 0x00C00720 (FUN_00C00720, dynamic atexit destructor for `gSimConVar_sim_TestVar`)
   */
  TSimConVar<int> gSimConVar_sim_TestVar(false, "sim_TestVar", 0);

  /**
   * Address: 0x00BDB230 (FUN_00BDB230, dynamic initializer for `gConAlias_sim_TestVarUByte`)
   * Address: 0x00C00730 (FUN_00C00730, dynamic atexit destructor for `gConAlias_sim_TestVarUByte`)
   */
  moho::CConAlias gConAlias_sim_TestVarUByte("sim_TestVarUByte", "Test variable - not used.", "DoSimCommand sim_TestVarUByte");

  /**
   * Address: 0x00BDB260 (FUN_00BDB260, dynamic initializer for `gSimConVar_sim_TestVarUByte`)
   * Address: 0x00C00780 (FUN_00C00780, dynamic atexit destructor for `gSimConVar_sim_TestVarUByte`)
   * Address: 0x007353C0 (FUN_007353C0, a copy of the TSimConVar<uint8_t> constructor with
   *   `this` bound to this global; no callers)
   */
  TSimConVar<std::uint8_t> gSimConVar_sim_TestVarUByte(false, "sim_TestVarUByte", 0);

  /**
   * Address: 0x00BDB2B0 (FUN_00BDB2B0, dynamic initializer for `gConAlias_sim_TestVarFloat`)
   * Address: 0x00C00790 (FUN_00C00790, dynamic atexit destructor for `gConAlias_sim_TestVarFloat`)
   */
  moho::CConAlias gConAlias_sim_TestVarFloat("sim_TestVarFloat", "Test variable - not used.", "DoSimCommand sim_TestVarFloat");

  /**
   * Address: 0x00BDB2E0 (FUN_00BDB2E0, dynamic initializer for `gSimConVar_sim_TestVarFloat`)
   * Address: 0x00C007E0 (FUN_00C007E0, dynamic atexit destructor for `gSimConVar_sim_TestVarFloat`)
   */
  TSimConVar<float> gSimConVar_sim_TestVarFloat(false, "sim_TestVarFloat", 0.0f);

  /**
   * Address: 0x00BDB330 (FUN_00BDB330, dynamic initializer for `gConAlias_sim_TestVarStr`)
   * Address: 0x00C007F0 (FUN_00C007F0, dynamic atexit destructor for `gConAlias_sim_TestVarStr`)
   */
  moho::CConAlias gConAlias_sim_TestVarStr("sim_TestVarStr", "Test variable - not used.", "DoSimCommand sim_TestVarStr");

  /**
   * Address: 0x00BDB360 (FUN_00BDB360, dynamic initializer for `gSimConVar_sim_TestVarStr`)
   * Address: 0x00C00840 (FUN_00C00840, dynamic atexit destructor for `gSimConVar_sim_TestVarStr`)
   * Address: 0x00735430 (FUN_00735430, the TSimConVar<string> constructor the initializer calls,
   *   cloned with `this` bound to this global and the default passed by value)
   */
  TSimConVar<msvc8::string> gSimConVar_sim_TestVarStr(false, "sim_TestVarStr", msvc8::string("yea!"));

  /**
   * Address: 0x00BDB3A0 (FUN_00BDB3A0, dynamic initializer for `gConAlias_sim_TestFunc`)
   * Address: 0x00C00880 (FUN_00C00880, dynamic atexit destructor for `gConAlias_sim_TestFunc`)
   */
  moho::CConAlias gConAlias_sim_TestFunc("sim_TestFunc", "Test function - not used.", "DoSimCommand sim_TestFunc");

  /**
   * Address: 0x00BDB3D0 (FUN_00BDB3D0, dynamic initializer for `gSimConFunc_sim_TestFunc`)
   * Address: 0x00C008D0 (FUN_00C008D0, dynamic atexit destructor for `gSimConFunc_sim_TestFunc`)
   */
  CSimConFunc gSimConFunc_sim_TestFunc(false, "sim_TestFunc", &Sim::sim_TestFunc);

  /**
   * Address: 0x00BDB410 (FUN_00BDB410, dynamic initializer for `gConAlias_SimLog`)
   * Address: 0x00C008E0 (FUN_00C008E0, dynamic atexit destructor for `gConAlias_SimLog`)
   */
  moho::CConAlias gConAlias_SimLog("SimLog", "Log a string (for debugging purposes)", "DoSimCommand SimLog");

  /**
   * Address: 0x00BDB440 (FUN_00BDB440, dynamic initializer for `gSimConFunc_SimLog`)
   * Address: 0x00C00930 (FUN_00C00930, dynamic atexit destructor for `gSimConFunc_SimLog`)
   */
  CSimConFunc gSimConFunc_SimLog(false, "SimLog", &Sim::Log);

  /**
   * Address: 0x00BDB480 (FUN_00BDB480, dynamic initializer for `gConAlias_SimWarn`)
   * Address: 0x00C00940 (FUN_00C00940, dynamic atexit destructor for `gConAlias_SimWarn`)
   */
  moho::CConAlias gConAlias_SimWarn("SimWarn", "Log a warning string (for debugging purposes)", "DoSimCommand SimWarn");

  /**
   * Address: 0x00BDB4B0 (FUN_00BDB4B0, dynamic initializer for `gSimConFunc_SimWarn`)
   * Address: 0x00C00990 (FUN_00C00990, dynamic atexit destructor for `gSimConFunc_SimWarn`)
   */
  CSimConFunc gSimConFunc_SimWarn(false, "SimWarn", &Sim::SimWarn);

  /**
   * Address: 0x00BDB4F0 (FUN_00BDB4F0, dynamic initializer for `gConAlias_SimError`)
   * Address: 0x00C009A0 (FUN_00C009A0, dynamic atexit destructor for `gConAlias_SimError`)
   */
  moho::CConAlias gConAlias_SimError("SimError", "Log an error string (for debugging purposes)", "DoSimCommand SimError");

  /**
   * Address: 0x00BDB520 (FUN_00BDB520, dynamic initializer for `gSimConFunc_SimError`)
   * Address: 0x00C009F0 (FUN_00C009F0, dynamic atexit destructor for `gSimConFunc_SimError`)
   */
  CSimConFunc gSimConFunc_SimError(false, "SimError", &Sim::SimError);

  /**
   * Address: 0x00BDB560 (FUN_00BDB560, dynamic initializer for `gConAlias_SimAssert`)
   * Address: 0x00C00A00 (FUN_00C00A00, dynamic atexit destructor for `gConAlias_SimAssert`)
   */
  moho::CConAlias gConAlias_SimAssert("SimAssert", "Fail an assertion (for debugging purposes)", "DoSimCommand SimAssert");

  /**
   * Address: 0x00BDB590 (FUN_00BDB590, dynamic initializer for `gSimConFunc_SimAssert`)
   * Address: 0x00C00A50 (FUN_00C00A50, dynamic atexit destructor for `gSimConFunc_SimAssert`)
   */
  CSimConFunc gSimConFunc_SimAssert(false, "SimAssert", &Sim::SimAssert);

  /**
   * Address: 0x00BDB5D0 (FUN_00BDB5D0, dynamic initializer for `gConAlias_SimCrash`)
   * Address: 0x00C00A60 (FUN_00C00A60, dynamic atexit destructor for `gConAlias_SimCrash`)
   */
  moho::CConAlias gConAlias_SimCrash("SimCrash", "Cause a crash (for debugging purposes)", "DoSimCommand SimCrash");

  /**
   * Address: 0x00BDB600 (FUN_00BDB600, dynamic initializer for `gSimConFunc_SimCrash`)
   * Address: 0x00C00AB0 (FUN_00C00AB0, dynamic atexit destructor for `gSimConFunc_SimCrash`)
   */
  CSimConFunc gSimConFunc_SimCrash(false, "SimCrash", &Sim::SimCrash);

  /**
   * Address: 0x00BDBAD0 (FUN_00BDBAD0, dynamic initializer for `gConAlias_path_BackgroundUpdate`)
   * Address: 0x00C00D40 (FUN_00C00D40, dynamic atexit destructor for `gConAlias_path_BackgroundUpdate`)
   */
  moho::CConAlias gConAlias_path_BackgroundUpdate("path_BackgroundUpdate", "Update pathfinding tables in background", "DoSimCommand path_BackgroundUpdate");

  /**
   * Address: 0x00BDBB00 (FUN_00BDBB00, dynamic initializer for `gSimConVar_path_BackgroundUpdate`)
   * Address: 0x00C00D90 (FUN_00C00D90, dynamic atexit destructor for `gSimConVar_path_BackgroundUpdate`)
   */
  TSimConVar<bool> gSimConVar_path_BackgroundUpdate(false, "path_BackgroundUpdate", true);

  /**
   * Address: 0x00BDBB50 (FUN_00BDBB50, dynamic initializer for `gConAlias_path_BackgroundBudget`)
   * Address: 0x00C00DA0 (FUN_00C00DA0, dynamic atexit destructor for `gConAlias_path_BackgroundBudget`)
   */
  moho::CConAlias gConAlias_path_BackgroundBudget("path_BackgroundBudget", "Maximum number of steps to run pathfinder in background", "DoSimCommand path_BackgroundBudget");

  /**
   * Address: 0x00BDBB80 (FUN_00BDBB80, dynamic initializer for `gSimConVar_path_BackgroundBudget`)
   * Address: 0x00C00DF0 (FUN_00C00DF0, dynamic atexit destructor for `gSimConVar_path_BackgroundBudget`)
   */
  TSimConVar<int> gSimConVar_path_BackgroundBudget(false, "path_BackgroundBudget", 1000);

  /**
   * Address: 0x00BDBBD0 (FUN_00BDBBD0, dynamic initializer for `gConAlias_sim_ChecksumPeriod`)
   * Address: 0x00C00E00 (FUN_00C00E00, dynamic atexit destructor for `gConAlias_sim_ChecksumPeriod`)
   */
  moho::CConAlias gConAlias_sim_ChecksumPeriod("sim_ChecksumPeriod", "How many beats between checksums.", "DoSimCommand sim_ChecksumPeriod");

  /**
   * Address: 0x00BDBC00 (FUN_00BDBC00, dynamic initializer for `gSimConVar_sim_ChecksumPeriod`)
   * Address: 0x00C00E50 (FUN_00C00E50, dynamic atexit destructor for `gSimConVar_sim_ChecksumPeriod`)
   */
  TSimConVar<int> gSimConVar_sim_ChecksumPeriod(false, "sim_ChecksumPeriod", 50);

  /**
   * Address: 0x00BDBD50 (FUN_00BDBD50, dynamic initializer for `gConAlias_sim_DebugCrash`)
   * Address: 0x00C00F50 (FUN_00C00F50, dynamic atexit destructor for `gConAlias_sim_DebugCrash`)
   */
  moho::CConAlias gConAlias_sim_DebugCrash("sim_DebugCrash", "Crash the sim.", "DoSimCommand sim_DebugCrash");

  /**
   * Address: 0x00BDBD80 (FUN_00BDBD80, dynamic initializer for `gSimConFunc_sim_DebugCrash`)
   * Address: 0x00C00FA0 (FUN_00C00FA0, dynamic atexit destructor for `gSimConFunc_sim_DebugCrash`)
   */
  CSimConFunc gSimConFunc_sim_DebugCrash(false, "sim_DebugCrash", &Sim::sim_DebugCrash);

  /**
   * Address: 0x00BDBF10 (FUN_00BDBF10, dynamic initializer for `gConAlias_SimLua`)
   * Address: 0x00C01210 (FUN_00C01210, dynamic atexit destructor for `gConAlias_SimLua`)
   */
  moho::CConAlias gConAlias_SimLua("SimLua", "Run some lua code in the sim's Lua.", "DoSimCommand SimLua");

  /**
   * Address: 0x00BDBF40 (FUN_00BDBF40, dynamic initializer for `gSimConFunc_SimLua`)
   * Address: 0x00C01260 (FUN_00C01260, dynamic atexit destructor for `gSimConFunc_SimLua`)
   */
  CSimConFunc gSimConFunc_SimLua(false, "SimLua", &Sim::SimLua);

  /**
   * Address: 0x00BDC220 (FUN_00BDC220, dynamic initializer for `gConAlias_DebugMoveCamera`)
   * Address: 0x00C01330 (FUN_00C01330, dynamic atexit destructor for `gConAlias_DebugMoveCamera`)
   */
  moho::CConAlias gConAlias_DebugMoveCamera("DebugMoveCamera", "Debug function for moving the camera in sim script.", "DoSimCommand DebugMoveCamera");

  /**
   * Address: 0x00BDC250 (FUN_00BDC250, dynamic initializer for `gSimConFunc_DebugMoveCamera`)
   * Address: 0x00C01380 (FUN_00C01380, dynamic atexit destructor for `gSimConFunc_DebugMoveCamera`)
   */
  CSimConFunc gSimConFunc_DebugMoveCamera(false, "DebugMoveCamera", &Sim::DebugMoveCamera);

  /**
   * Address: 0x00BDC7A0 (FUN_00BDC7A0, dynamic initializer for `gConAlias_path_TimeoutPreview`)
   * Address: 0x00C01970 (FUN_00C01970, dynamic atexit destructor for `gConAlias_path_TimeoutPreview`)
   */
  moho::CConAlias gConAlias_path_TimeoutPreview("path_TimeoutPreview", "Maximum number of ticks to allow pathfinder preview to take", "DoSimCommand path_TimeoutPreview");

  /**
   * Address: 0x00BDC7D0 (FUN_00BDC7D0, dynamic initializer for `gSimConVar_path_TimeoutPreview`)
   * Address: 0x00C019C0 (FUN_00C019C0, dynamic atexit destructor for `gSimConVar_path_TimeoutPreview`)
   */
  TSimConVar<int> gSimConVar_path_TimeoutPreview(false, "path_TimeoutPreview", 1000);

  /**
   * Address: 0x00BDC820 (FUN_00BDC820, dynamic initializer for `gConAlias_path_GeneratePreview`)
   * Address: 0x00C019D0 (FUN_00C019D0, dynamic atexit destructor for `gConAlias_path_GeneratePreview`)
   */
  moho::CConAlias gConAlias_path_GeneratePreview("path_GeneratePreview", "Do a pathfind for the UI preview", "DoSimCommand path_GeneratePreview");

  /**
   * Address: 0x00BDC850 (FUN_00BDC850, dynamic initializer for `gSimConFunc_path_GeneratePreview`)
   * Address: 0x00C01A20 (FUN_00C01A20, dynamic atexit destructor for `gSimConFunc_path_GeneratePreview`)
   */
  CSimConFunc gSimConFunc_path_GeneratePreview(true, "path_GeneratePreview", &Sim::path_GeneratePreview);

  /**
   * Address: 0x00BD3D80 (FUN_00BD3D80, dynamic initializer for `gConAlias_dbg`)
   * Address: 0x00BFB7D0 (FUN_00BFB7D0, dynamic atexit destructor for `gConAlias_dbg`)
   */
  moho::CConAlias gConAlias_dbg("dbg", "Enable/Disable debug overlay", "DoSimCommand dbg");

  /**
   * Address: 0x00BD3DB0 (FUN_00BD3DB0, dynamic initializer for `gSimConFunc_dbg`)
   * Address: 0x00BFB820 (FUN_00BFB820, dynamic atexit destructor for `gSimConFunc_dbg`)
   */
  CSimConFunc gSimConFunc_dbg(false, "dbg", &Sim::dbg);

  /**
   * Address: 0x00BD3890 (FUN_00BD3890, dynamic initializer for `gConAlias_SallyShears`)
   * Address: 0x00BFB470 (FUN_00BFB470, dynamic atexit destructor for `gConAlias_SallyShears`)
   */
  moho::CConAlias gConAlias_SallyShears("SallyShears", "Reveal entire map.", "DoSimCommand SallyShears");

  /**
   * Address: 0x00BD38C0 (FUN_00BD38C0, dynamic initializer for `gSimConFunc_SallyShears`)
   * Address: 0x00BFB4C0 (FUN_00BFB4C0, dynamic atexit destructor for `gSimConFunc_SallyShears`)
   */
  CSimConFunc gSimConFunc_SallyShears(false, "SallyShears", &Sim::SallyShears);

  /**
   * Address: 0x00BD3900 (FUN_00BD3900, dynamic initializer for `gConAlias_BlingBling`)
   * Address: 0x00BFB4D0 (FUN_00BFB4D0, dynamic atexit destructor for `gConAlias_BlingBling`)
   */
  moho::CConAlias gConAlias_BlingBling("BlingBling", "Cash money yo", "DoSimCommand BlingBling");

  /**
   * Address: 0x00BD3930 (FUN_00BD3930, dynamic initializer for `gSimConFunc_BlingBling`)
   * Address: 0x00BFB520 (FUN_00BFB520, dynamic atexit destructor for `gSimConFunc_BlingBling`)
   */
  CSimConFunc gSimConFunc_BlingBling(false, "BlingBling", &Sim::BlingBling);

  /**
   * Address: 0x00BD3970 (FUN_00BD3970, dynamic initializer for `gConAlias_ZeroExtraStorage`)
   * Address: 0x00BFB530 (FUN_00BFB530, dynamic atexit destructor for `gConAlias_ZeroExtraStorage`)
   */
  moho::CConAlias gConAlias_ZeroExtraStorage("ZeroExtraStorage", "Set energy and mass extra storage to 0", "DoSimCommand ZeroExtraStorage");

  /**
   * Address: 0x00BD39A0 (FUN_00BD39A0, dynamic initializer for `gSimConFunc_ZeroExtraStorage`)
   * Address: 0x00BFB580 (FUN_00BFB580, dynamic atexit destructor for `gSimConFunc_ZeroExtraStorage`)
   */
  CSimConFunc gSimConFunc_ZeroExtraStorage(false, "ZeroExtraStorage", &Sim::ZeroExtraStorage);

  /**
   * Address: 0x00BD39E0 (FUN_00BD39E0, dynamic initializer for `gConAlias_DamageUnit`)
   * Address: 0x00BFB590 (FUN_00BFB590, dynamic atexit destructor for `gConAlias_DamageUnit`)
   */
  moho::CConAlias gConAlias_DamageUnit("DamageUnit", "Damage the selected unit (negative values heal)", "DoSimCommand DamageUnit");

  /**
   * Address: 0x00BD3A10 (FUN_00BD3A10, dynamic initializer for `gSimConFunc_DamageUnit`)
   * Address: 0x00BFB5E0 (FUN_00BFB5E0, dynamic atexit destructor for `gSimConFunc_DamageUnit`)
   */
  CSimConFunc gSimConFunc_DamageUnit(false, "DamageUnit", &Sim::DamageUnit);

  /**
   * Address: 0x00BD3A50 (FUN_00BD3A50, dynamic initializer for `gConAlias_AddImpulse`)
   * Address: 0x00BFB5F0 (FUN_00BFB5F0, dynamic atexit destructor for `gConAlias_AddImpulse`)
   */
  moho::CConAlias gConAlias_AddImpulse("AddImpulse", "AddImpulse (x,y,z)", "DoSimCommand AddImpulse");

  /**
   * Address: 0x00BD3A80 (FUN_00BD3A80, dynamic initializer for `gSimConFunc_AddImpulse`)
   * Address: 0x00BFB640 (FUN_00BFB640, dynamic atexit destructor for `gSimConFunc_AddImpulse`)
   */
  CSimConFunc gSimConFunc_AddImpulse(false, "AddImpulse", &Sim::AddImpulse);

  /**
   * Address: 0x00BD1F60 (FUN_00BD1F60, dynamic initializer for `gConAlias_NeedRefuelThresholdRatio`)
   * Address: 0x00BFA720 (FUN_00BFA720, dynamic atexit destructor for `gConAlias_NeedRefuelThresholdRatio`)
   */
  moho::CConAlias gConAlias_NeedRefuelThresholdRatio("NeedRefuelThresholdRatio", "Start looking for refueling platform when fuel ratio drops below this point", "DoSimCommand NeedRefuelThresholdRatio");

  /**
   * Address: 0x00BD1F90 (FUN_00BD1F90, dynamic initializer for `gSimConVar_NeedRefuelThresholdRatio`)
   * Address: 0x00BFA770 (FUN_00BFA770, dynamic atexit destructor for `gSimConVar_NeedRefuelThresholdRatio`)
   */
  TSimConVar<float> gSimConVar_NeedRefuelThresholdRatio(false, "NeedRefuelThresholdRatio", 0.2f);

  /**
   * Address: 0x00BD1FE0 (FUN_00BD1FE0, dynamic initializer for `gConAlias_NeedRepairThresholdRatio`)
   * Address: 0x00BFA780 (FUN_00BFA780, dynamic atexit destructor for `gConAlias_NeedRepairThresholdRatio`)
   */
  moho::CConAlias gConAlias_NeedRepairThresholdRatio("NeedRepairThresholdRatio", "Start looking for refueling platform when health ratio drops below this point", "DoSimCommand NeedRepairThresholdRatio");

  /**
   * Address: 0x00BD2010 (FUN_00BD2010, dynamic initializer for `gSimConVar_NeedRepairThresholdRatio`)
   * Address: 0x00BFA7D0 (FUN_00BFA7D0, dynamic atexit destructor for `gSimConVar_NeedRepairThresholdRatio`)
   */
  TSimConVar<float> gSimConVar_NeedRepairThresholdRatio(false, "NeedRepairThresholdRatio", 0.75f);

  /**
   * Address: 0x00BD4E80 (FUN_00BD4E80, dynamic initializer for `gConAlias_NoDamage`)
   * Address: 0x00BFC630 (FUN_00BFC630, dynamic atexit destructor for `gConAlias_NoDamage`)
   */
  moho::CConAlias gConAlias_NoDamage("NoDamage", "Disables all damage to units when set.", "DoSimCommand NoDamage");

  /**
   * Address: 0x00BD4EB0 (FUN_00BD4EB0, dynamic initializer for `gSimConVar_NoDamage`)
   * Address: 0x00BFC680 (FUN_00BFC680, dynamic atexit destructor for `gSimConVar_NoDamage`)
   */
  TSimConVar<bool> gSimConVar_NoDamage(false, "NoDamage", false);

  /**
   * Address: 0x00BCB050 (FUN_00BCB050, dynamic initializer for `gConAlias_AI_RunOpponentAI`)
   * Address: 0x00BF5F80 (FUN_00BF5F80, dynamic atexit destructor for `gConAlias_AI_RunOpponentAI`)
   */
  moho::CConAlias gConAlias_AI_RunOpponentAI("AI_RunOpponentAI", "Turns on or off Opponent AI", "DoSimCommand AI_RunOpponentAI");

  /**
   * Address: 0x00BCB080 (FUN_00BCB080, dynamic initializer for `gSimConVar_AI_RunOpponentAI`)
   * Address: 0x00BF5FD0 (FUN_00BF5FD0, dynamic atexit destructor for `gSimConVar_AI_RunOpponentAI`)
   */
  TSimConVar<bool> gSimConVar_AI_RunOpponentAI(true, "AI_RunOpponentAI", true);

  /**
   * Address: 0x00BCB0D0 (FUN_00BCB0D0, dynamic initializer for `gConAlias_AI_DebugArmyIndex`)
   * Address: 0x00BF5FE0 (FUN_00BF5FE0, dynamic atexit destructor for `gConAlias_AI_DebugArmyIndex`)
   */
  moho::CConAlias gConAlias_AI_DebugArmyIndex("AI_DebugArmyIndex", "Set up a army index for debugging purposes", "DoSimCommand AI_DebugArmyIndex");

  /**
   * Address: 0x00BCB100 (FUN_00BCB100, dynamic initializer for `gSimConVar_AI_DebugArmyIndex`)
   * Address: 0x00BF6030 (FUN_00BF6030, dynamic atexit destructor for `gSimConVar_AI_DebugArmyIndex`)
   */
  TSimConVar<int> gSimConVar_AI_DebugArmyIndex(true, "AI_DebugArmyIndex", -1);

  /**
   * Address: 0x00BCB150 (FUN_00BCB150, dynamic initializer for `gConAlias_AI_RenderDebugAttackVectors`)
   * Address: 0x00BF6040 (FUN_00BF6040, dynamic atexit destructor for `gConAlias_AI_RenderDebugAttackVectors`)
   */
  moho::CConAlias gConAlias_AI_RenderDebugAttackVectors("AI_RenderDebugAttackVectors", "Toggle on/off rendering of debug base attack vectors", "DoSimCommand AI_RenderDebugAttackVectors");

  /**
   * Address: 0x00BCB180 (FUN_00BCB180, dynamic initializer for `gSimConVar_AI_RenderDebugAttackVectors`)
   * Address: 0x00BF6090 (FUN_00BF6090, dynamic atexit destructor for `gSimConVar_AI_RenderDebugAttackVectors`)
   */
  TSimConVar<bool> gSimConVar_AI_RenderDebugAttackVectors(true, "AI_RenderDebugAttackVectors", false);

  /**
   * Address: 0x00BCB1D0 (FUN_00BCB1D0, dynamic initializer for `gConAlias_AI_RenderDebugPlayableRect`)
   * Address: 0x00BF60A0 (FUN_00BF60A0, dynamic atexit destructor for `gConAlias_AI_RenderDebugPlayableRect`)
   */
  moho::CConAlias gConAlias_AI_RenderDebugPlayableRect("AI_RenderDebugPlayableRect", "Toggle on/off rendering of debug playable rect", "DoSimCommand AI_RenderDebugPlayableRect");

  /**
   * Address: 0x00BCB200 (FUN_00BCB200, dynamic initializer for `gSimConVar_AI_RenderDebugPlayableRect`)
   * Address: 0x00BF60F0 (FUN_00BF60F0, dynamic atexit destructor for `gSimConVar_AI_RenderDebugPlayableRect`)
   */
  TSimConVar<bool> gSimConVar_AI_RenderDebugPlayableRect(true, "AI_RenderDebugPlayableRect", false);

  /**
   * Address: 0x00BCB250 (FUN_00BCB250, dynamic initializer for `gConAlias_AI_DebugCollision`)
   * Address: 0x00BF6100 (FUN_00BF6100, dynamic atexit destructor for `gConAlias_AI_DebugCollision`)
   */
  moho::CConAlias gConAlias_AI_DebugCollision("AI_DebugCollision", "Toggle on/off collision detection", "DoSimCommand AI_DebugCollision");

  /**
   * Address: 0x00BCB280 (FUN_00BCB280, dynamic initializer for `gSimConVar_AI_DebugCollision`)
   * Address: 0x00BF6150 (FUN_00BF6150, dynamic atexit destructor for `gSimConVar_AI_DebugCollision`)
   */
  TSimConVar<bool> gSimConVar_AI_DebugCollision(false, "AI_DebugCollision", false);

  /**
   * Address: 0x00BCB2D0 (FUN_00BCB2D0, dynamic initializer for `gConAlias_AI_DebugIgnorePlayableRect`)
   * Address: 0x00BF6160 (FUN_00BF6160, dynamic atexit destructor for `gConAlias_AI_DebugIgnorePlayableRect`)
   */
  moho::CConAlias gConAlias_AI_DebugIgnorePlayableRect("AI_DebugIgnorePlayableRect", "Toggle on/off ignore playable rect", "DoSimCommand AI_DebugIgnorePlayableRect");

  /**
   * Address: 0x00BCB300 (FUN_00BCB300, dynamic initializer for `gSimConVar_AI_DebugIgnorePlayableRect`)
   * Address: 0x00BF61B0 (FUN_00BF61B0, dynamic atexit destructor for `gSimConVar_AI_DebugIgnorePlayableRect`)
   */
  TSimConVar<bool> gSimConVar_AI_DebugIgnorePlayableRect(false, "AI_DebugIgnorePlayableRect", false);

  /**
   * Address: 0x00BCF710 (FUN_00BCF710, dynamic initializer for `gConAlias_ai_InstaBuild`)
   * Address: 0x00BF9180 (FUN_00BF9180, dynamic atexit destructor for `gConAlias_ai_InstaBuild`)
   */
  moho::CConAlias gConAlias_ai_InstaBuild("ai_InstaBuild", "Units build instantly.", "DoSimCommand ai_InstaBuild");

  /**
   * Address: 0x00BCF740 (FUN_00BCF740, dynamic initializer for `gSimConVar_ai_InstaBuild`)
   * Address: 0x00BF91D0 (FUN_00BF91D0, dynamic atexit destructor for `gSimConVar_ai_InstaBuild`)
   */
  TSimConVar<bool> gSimConVar_ai_InstaBuild(false, "ai_InstaBuild", false);

  /**
   * Address: 0x00BCF790 (FUN_00BCF790, dynamic initializer for `gConAlias_ai_FreeBuild`)
   * Address: 0x00BF91E0 (FUN_00BF91E0, dynamic atexit destructor for `gConAlias_ai_FreeBuild`)
   */
  moho::CConAlias gConAlias_ai_FreeBuild("ai_FreeBuild", "Unit build costs are 0", "DoSimCommand ai_FreeBuild");

  /**
   * Address: 0x00BCF7C0 (FUN_00BCF7C0, dynamic initializer for `gSimConVar_ai_FreeBuild`)
   * Address: 0x00BF9230 (FUN_00BF9230, dynamic atexit destructor for `gSimConVar_ai_FreeBuild`)
   */
  TSimConVar<bool> gSimConVar_ai_FreeBuild(false, "ai_FreeBuild", false);

  /**
   * Address: 0x00BCE3A0 (FUN_00BCE3A0, dynamic initializer for `gConAlias_ai_SteeringAirTolerance`)
   * Address: 0x00BF8040 (FUN_00BF8040, dynamic atexit destructor for `gConAlias_ai_SteeringAirTolerance`)
   */
  moho::CConAlias gConAlias_ai_SteeringAirTolerance("ai_SteeringAirTolerance", "Tolerance used to detect whether an aircraft has reached its destination.", "DoSimCommand ai_SteeringAirTolerance");

  /**
   * Address: 0x00BCE3D0 (FUN_00BCE3D0, dynamic initializer for `gSimConVar_ai_SteeringAirTolerance`)
   * Address: 0x00BF8090 (FUN_00BF8090, dynamic atexit destructor for `gSimConVar_ai_SteeringAirTolerance`)
   */
  TSimConVar<float> gSimConVar_ai_SteeringAirTolerance(false, "ai_SteeringAirTolerance", 4.0f);

  /**
   * Address: 0x00BCE6D0 (FUN_00BCE6D0, dynamic initializer for `gConAlias_WeaponTerrainBlockageTest`)
   * Address: 0x00BF81E0 (FUN_00BF81E0, dynamic atexit destructor for `gConAlias_WeaponTerrainBlockageTest`)
   */
  moho::CConAlias gConAlias_WeaponTerrainBlockageTest("WeaponTerrainBlockageTest", "Toggle on/off wepaon collision tests against terrain blockages", "DoSimCommand WeaponTerrainBlockageTest");

  /**
   * Address: 0x00BCE700 (FUN_00BCE700, dynamic initializer for `gSimConVar_WeaponTerrainBlockageTest`)
   * Address: 0x00BF8230 (FUN_00BF8230, dynamic atexit destructor for `gSimConVar_WeaponTerrainBlockageTest`)
   */
  TSimConVar<bool> gSimConVar_WeaponTerrainBlockageTest(false, "WeaponTerrainBlockageTest", true);

  /**
   * Address: 0x00BD8380 (FUN_00BD8380, dynamic initializer for `gConAlias_DebugAIStatesOff`)
   * Address: 0x00BFE370 (FUN_00BFE370, dynamic atexit destructor for `gConAlias_DebugAIStatesOff`)
   */
  moho::CConAlias gConAlias_DebugAIStatesOff("DebugAIStatesOff", "debug function to show some AI states", "DoSimCommand DebugAIStatesOff");

  /**
   * Address: 0x00BD83B0 (FUN_00BD83B0, dynamic initializer for `gSimConFunc_DebugAIStatesOff`)
   * Address: 0x00BFE3C0 (FUN_00BFE3C0, dynamic atexit destructor for `gSimConFunc_DebugAIStatesOff`)
   */
  CSimConFunc gSimConFunc_DebugAIStatesOff(false, "DebugAIStatesOff", &Sim::DebugAIStatesOff);

  /**
   * Address: 0x00BD8310 (FUN_00BD8310, dynamic initializer for `gConAlias_DebugAIStatesOn`)
   * Address: 0x00BFE310 (FUN_00BFE310, dynamic atexit destructor for `gConAlias_DebugAIStatesOn`)
   */
  moho::CConAlias gConAlias_DebugAIStatesOn("DebugAIStatesOn", "debug function to show some AI states", "DoSimCommand DebugAIStatesOn");

  /**
   * Address: 0x00BD8340 (FUN_00BD8340, dynamic initializer for `gSimConFunc_DebugAIStatesOn`)
   * Address: 0x00BFE360 (FUN_00BFE360, dynamic atexit destructor for `gSimConFunc_DebugAIStatesOn`)
   */
  CSimConFunc gSimConFunc_DebugAIStatesOn(false, "DebugAIStatesOn", &Sim::DebugAIStatesOn);

  /**
   * Address: 0x00BDC350 (FUN_00BDC350, dynamic initializer for `gConAlias_TrackStats`)
   * Address: 0x00C01390 (FUN_00C01390, dynamic atexit destructor for `gConAlias_TrackStats`)
   */
  moho::CConAlias gConAlias_TrackStats("TrackStats", "Begin/End tracking stats of selected units.", "DoSimCommand TrackStats");

  /**
   * Address: 0x00BDC380 (FUN_00BDC380, dynamic initializer for `gSimConFunc_TrackStats`)
   * Address: 0x00C013E0 (FUN_00C013E0, dynamic atexit destructor for `gSimConFunc_TrackStats`)
   */
  CSimConFunc gSimConFunc_TrackStats(false, "TrackStats", &Sim::TrackStats);

  /**
   * Address: 0x00BDC3C0 (FUN_00BDC3C0, dynamic initializer for `gConAlias_DumpUnits`)
   * Address: 0x00C013F0 (FUN_00C013F0, dynamic atexit destructor for `gConAlias_DumpUnits`)
   */
  moho::CConAlias gConAlias_DumpUnits("DumpUnits", "Print out units in play", "DoSimCommand DumpUnits");

  /**
   * Address: 0x00BDC3F0 (FUN_00BDC3F0, dynamic initializer for `gSimConFunc_DumpUnits`)
   * Address: 0x00C01440 (FUN_00C01440, dynamic atexit destructor for `gSimConFunc_DumpUnits`)
   */
  CSimConFunc gSimConFunc_DumpUnits(false, "DumpUnits", &Sim::DumpUnits);

  /**
   * Address: 0x00BDC140 (FUN_00BDC140, dynamic initializer for `gConAlias_DebugSetPlayableRect`)
   * Address: 0x00C01270 (FUN_00C01270, dynamic atexit destructor for `gConAlias_DebugSetPlayableRect`)
   */
  moho::CConAlias gConAlias_DebugSetPlayableRect("DebugSetPlayableRect", "Set the playable rect of the map (minX, minZ, maxX, maxZ).", "DoSimCommand DebugSetPlayableRect");

  /**
   * Address: 0x00BDC170 (FUN_00BDC170, dynamic initializer for `gSimConFunc_DebugSetPlayableRect`)
   * Address: 0x00C012C0 (FUN_00C012C0, dynamic atexit destructor for `gSimConFunc_DebugSetPlayableRect`)
   */
  CSimConFunc gSimConFunc_DebugSetPlayableRect(false, "DebugSetPlayableRect", &Sim::DebugSetPlayableRect);

  /**
   * Address: 0x00BDC1B0 (FUN_00BDC1B0, dynamic initializer for `gConAlias_DebugDumpArmyStats`)
   * Address: 0x00C012D0 (FUN_00C012D0, dynamic atexit destructor for `gConAlias_DebugDumpArmyStats`)
   */
  moho::CConAlias gConAlias_DebugDumpArmyStats("DebugDumpArmyStats", "Dump current stats for army index.", "DoSimCommand DebugDumpArmyStats");

  /**
   * Address: 0x00BDC1E0 (FUN_00BDC1E0, dynamic initializer for `gSimConFunc_DebugDumpArmyStats`)
   * Address: 0x00C01320 (FUN_00C01320, dynamic atexit destructor for `gSimConFunc_DebugDumpArmyStats`)
   */
  CSimConFunc gSimConFunc_DebugDumpArmyStats(false, "DebugDumpArmyStats", &Sim::DebugDumpArmyStats);

  /**
   * Address: 0x00BD82A0 (FUN_00BD82A0, dynamic initializer for `gConAlias_DebugSetProductionInActive`)
   * Address: 0x00BFE2B0 (FUN_00BFE2B0, dynamic atexit destructor for `gConAlias_DebugSetProductionInActive`)
   */
  moho::CConAlias gConAlias_DebugSetProductionInActive("DebugSetProductionInActive", "debug function to turn selected units production of resources into inactive state", "DoSimCommand DebugSetProductionInActive");

  /**
   * Address: 0x00BD82D0 (FUN_00BD82D0, dynamic initializer for `gSimConFunc_DebugSetProductionInActive`)
   * Address: 0x00BFE300 (FUN_00BFE300, dynamic atexit destructor for `gSimConFunc_DebugSetProductionInActive`)
   */
  CSimConFunc gSimConFunc_DebugSetProductionInActive(false, "DebugSetProductionInActive", &Sim::DebugSetProductionInActive);

  /**
   * Address: 0x00BD8230 (FUN_00BD8230, dynamic initializer for `gConAlias_DebugSetProductionActive`)
   * Address: 0x00BFE250 (FUN_00BFE250, dynamic atexit destructor for `gConAlias_DebugSetProductionActive`)
   */
  moho::CConAlias gConAlias_DebugSetProductionActive("DebugSetProductionActive", "debug function to turn selected units production of resources into active state", "DoSimCommand DebugSetProductionActive");

  /**
   * Address: 0x00BD8260 (FUN_00BD8260, dynamic initializer for `gSimConFunc_DebugSetProductionActive`)
   * Address: 0x00BFE2A0 (FUN_00BFE2A0, dynamic atexit destructor for `gSimConFunc_DebugSetProductionActive`)
   */
  CSimConFunc gSimConFunc_DebugSetProductionActive(false, "DebugSetProductionActive", &Sim::DebugSetProductionActive);

  /**
   * Address: 0x00BD81C0 (FUN_00BD81C0, dynamic initializer for `gConAlias_DebugSetConsumptionInActive`)
   * Address: 0x00BFE1F0 (FUN_00BFE1F0, dynamic atexit destructor for `gConAlias_DebugSetConsumptionInActive`)
   */
  moho::CConAlias gConAlias_DebugSetConsumptionInActive("DebugSetConsumptionInActive", "debug function to turn selected units consumption of resources into inactive state", "DoSimCommand DebugSetConsumptionInActive");

  /**
   * Address: 0x00BD81F0 (FUN_00BD81F0, dynamic initializer for `gSimConFunc_DebugSetConsumptionInActive`)
   * Address: 0x00BFE240 (FUN_00BFE240, dynamic atexit destructor for `gSimConFunc_DebugSetConsumptionInActive`)
   */
  CSimConFunc gSimConFunc_DebugSetConsumptionInActive(false, "DebugSetConsumptionInActive", &Sim::DebugSetConsumptionInActive);

  /**
   * Address: 0x00BD8150 (FUN_00BD8150, dynamic initializer for `gConAlias_DebugSetConsumptionActive`)
   * Address: 0x00BFE190 (FUN_00BFE190, dynamic atexit destructor for `gConAlias_DebugSetConsumptionActive`)
   */
  moho::CConAlias gConAlias_DebugSetConsumptionActive("DebugSetConsumptionActive", "debug function to turn selected units consumption of resources into active state", "DoSimCommand DebugSetConsumptionActive");

  /**
   * Address: 0x00BD8180 (FUN_00BD8180, dynamic initializer for `gSimConFunc_DebugSetConsumptionActive`)
   * Address: 0x00BFE1E0 (FUN_00BFE1E0, dynamic atexit destructor for `gSimConFunc_DebugSetConsumptionActive`)
   */
  CSimConFunc gSimConFunc_DebugSetConsumptionActive(false, "DebugSetConsumptionActive", &Sim::DebugSetConsumptionActive);

  /**
   * Address: 0x00BD51E0 (FUN_00BD51E0, dynamic initializer for `gConAlias_Purge`)
   * Address: 0x00BFCB00 (FUN_00BFCB00, dynamic atexit destructor for `gConAlias_Purge`)
   */
  moho::CConAlias gConAlias_Purge("Purge", "Purge all entities of a specified type <shield|projectile|unit|all>.  If any optional army indices are supplied, destroy those army's entities.", "DoSimCommand Purge");

  /**
   * Address: 0x00BD5210 (FUN_00BD5210, dynamic initializer for `gSimConFunc_Purge`)
   * Address: 0x00BFCB50 (FUN_00BFCB50, dynamic atexit destructor for `gSimConFunc_Purge`)
   */
  CSimConFunc gSimConFunc_Purge(false, "Purge", &Sim::Purge);

  /**
   * Address: 0x00BD6C90 (FUN_00BD6C90, dynamic initializer for `gConAlias_KillAll`)
   * Address: 0x00BFDD50 (FUN_00BFDD50, dynamic atexit destructor for `gConAlias_KillAll`)
   */
  moho::CConAlias gConAlias_KillAll("KillAll", "Kill all units", "DoSimCommand KillAll");

  /**
   * Address: 0x00BD6CC0 (FUN_00BD6CC0, dynamic initializer for `gSimConFunc_KillAll`)
   * Address: 0x00BFDDA0 (FUN_00BFDDA0, dynamic atexit destructor for `gSimConFunc_KillAll`)
   */
  CSimConFunc gSimConFunc_KillAll(false, "KillAll", &Sim::KillAll);

  /**
   * Address: 0x00BD6D00 (FUN_00BD6D00, dynamic initializer for `gConAlias_DestroyAll`)
   * Address: 0x00BFDDB0 (FUN_00BFDDB0, dynamic atexit destructor for `gConAlias_DestroyAll`)
   */
  moho::CConAlias gConAlias_DestroyAll("DestroyAll", "Destroy all units.  If any optional army indices are supplied, destroy those army's units.", "DoSimCommand DestroyAll");

  /**
   * Address: 0x00BD6D30 (FUN_00BD6D30, dynamic initializer for `gSimConFunc_DestroyAll`)
   * Address: 0x00BFDE00 (FUN_00BFDE00, dynamic atexit destructor for `gSimConFunc_DestroyAll`)
   */
  CSimConFunc gSimConFunc_DestroyAll(false, "DestroyAll", &Sim::DestroyAll);

} // namespace moho
