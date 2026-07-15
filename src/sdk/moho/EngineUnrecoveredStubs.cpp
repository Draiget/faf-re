// SPDX: faf engine recovery
//
// EngineUnrecoveredStubs.cpp
//
// Linker stubs for engine free functions whose recovered source is not yet
// available. Each stub satisfies the link with a no-op default return.
//
// Class methods, constructors, and methods with reference returns are NOT
// stubbed here (they need type-correct implementations and member init).
// Those remain as TODO recovery items; see decomp/recovery/disasm/.

// Forward declarations for types referenced in stubbed signatures.
class wxWindowBase;
struct wxSize;
namespace gpg
{
  class RType;
  class ReadArchive;
  class WriteArchive;
  class RRef;
  namespace core { template<class T, int N> class FastVectorN; }
}
namespace Wm3 { template<class T> class Vector3; }
namespace msvc8 { struct string; }
namespace moho
{
  struct SOCellPos;
  class COGrid;
  class Unit;
  struct SCoordsVec2;
  struct RUnitBlueprint;
  class Sim;
  class CUnitCommand;
  class CAiBrain;
  class IWldTerrainRes;
  struct UnitWeaponInfo;
  struct WD3DViewport;
  class CDamage;
}

namespace moho
{
  // ===== Unrecovered free functions =====
  // REMOVED: preregister_SSTIUnitVariableDataTypeInfo and
  // preregister_UnitWeaponInfoTypeInfo were here as stubs returning nullptr,
  // shadowing the real recovered RTTI registration in moho/unit/core/Unit.cpp.
  // The real definitions there were at file scope (not inside namespace moho)
  // so the linker couldn't reach them; that has been fixed by wrapping them
  // in `namespace moho { ... }`. Same fix applied to
  // InitializeSSTIUnitWeaponInfoVector (FUN_005C3850) — the real body in
  // moho/unit/core/Unit.cpp is now wrapped in `namespace moho { ... }`
  // matching the Unit.h:485 declaration, so the no-op stub here is gone.
  class moho::IWldTerrainRes * WLD_CreateTerrainRes(void) { return nullptr; }
  // REN_CreateGameViewport now recovered in src/sdk/moho/app/WxRuntimeTypes.cpp
  // (FUN_007FA230). Replaces the no-op stub.
  // moho::-namespace duplicates of the gpg::Save... stubs have been
  // dropped — no caller in src/sdk/** references the moho-qualified
  // versions; callers use the gpg::-qualified symbols which now resolve
  // either to real trampolines (Save{Owned,Unowned}RawPointer*) or to
  // the remaining gpg-namespace stubs (LoadAndBroadcast...,
  // SaveBroadcasterListener...) below.
  // CON_WxInputBox now recovered in src/sdk/moho/app/WxRuntimeTypes.cpp
  // (FUN_004FC900). Replaces the no-op stub.
  // SIM_Damage now recovered in src/sdk/moho/sim/CDamage.cpp
  // (FUN_00737E60) along with its mMethod==0 callee
  // SIM_DoDamagePoint (FUN_00737140). Replaces the no-op stub.
  // SIM_DoDamageArea (FUN_00737680, mMethod==1) and func_DoDamageRing
  // (FUN_00737B30, mMethod==2) are still blocked; their stubs live here
  // so the SIM_Damage dispatcher links until those bodies are recovered.
}

// REMOVED: ADXM_WaitVsync, mpvcdec_InitDct C++-mangled stubs. Their C-linkage
// counterparts come from the real recovered SofdecRuntime translation-unit
// assembly; CMovie.cpp / MPVDecoder.cpp callers were updated to declare the
// forward decls inside `extern "C"` so they hit the real bodies.

// ===== Misc unrecovered free functions =====
// RuntimeToLowerWideWithCurrentLocale recovered in CrtRuntimeHelpers.cpp at
// file scope (was previously hidden inside that file's anonymous
// namespace, which fell back to this no-op stub at link time).

namespace gpg
{
  // ===== Unrecovered serialization helpers =====
  //
  // SaveOwnedRawPointerFromCArmyStatItemOwnerFieldLane1 and
  // SaveUnownedRawPointerFromManyToOneListener_EProjectileImpactEventIntrusiveHeadLane1
  // have file-scope `gpg::` trampolines at the bottom of
  // src/sdk/gpg/core/containers/ArchiveSerialization.cpp that forward
  // into the anon-namespace real bodies. The stubs that used to live
  // here have been removed; the linker now resolves the cross-TU
  // `gpg::Save...` lookups (SConditionTriggerReflection.cpp,
  // ProjectileStartupRegistrations.cpp) to the real bodies.
  //
  // LoadAndBroadcastManyToOneListenerEProjectileImpactEvent and
  // SaveBroadcasterListenerChainEUnitCommandQueueStatus remain as
  // no-op stubs because their real bodies are not yet recovered in
  // src/sdk/**. Save/load for those reflection lanes is still lossy.
  void LoadAndBroadcastManyToOneListenerEProjectileImpactEvent(
      gpg::ReadArchive*, int, int, gpg::RRef*) {}
  void SaveBroadcasterListenerChainEUnitCommandQueueStatus(
      gpg::WriteArchive*, int) {}
}

namespace moho
{
  struct CommandModeData;
  struct MouseInfo;
  class CWldSession;
}

// Linker error references this at global scope (no namespace):
// `?func_GetRightMouseButtonAction@@YA...` — keep here, NOT inside namespace moho.
moho::CommandModeData* func_GetRightMouseButtonAction(
    moho::CommandModeData* out, moho::MouseInfo*, int, moho::CWldSession*) { return out; }

// ===== Free wxRuntime helper =====
// wxDestroyListNoDeleteRuntime recovered in src/sdk/moho/app/WxRuntimeTypes.cpp
// — the anonymous-namespace body (`wxDestroyListNoDeleteRuntimeImpl`) is now
// wrapped by a file-scope trampoline so the global symbol resolves to the
// real wxList vtable-rebind + base-teardown body instead of falling back to
// a no-op (was leaking the embedded list at WxSocketBase+0x28).

