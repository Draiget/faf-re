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
  bool COORDS_CanMoveAt(struct moho::SOCellPos *,class moho::COGrid *,class moho::Unit *,bool,class moho::Unit *) { return false; }
  bool TryBuildStructureAt(struct moho::SCoordsVec2 *,struct moho::RUnitBlueprint const *,class moho::Sim *,int,bool,bool,bool) { return false; }
  // REMOVED: preregister_SSTIUnitVariableDataTypeInfo and
  // preregister_UnitWeaponInfoTypeInfo were here as stubs returning nullptr,
  // shadowing the real recovered RTTI registration in moho/unit/core/Unit.cpp.
  // The real definitions there were at file scope (not inside namespace moho)
  // so the linker couldn't reach them; that has been fixed by wrapping them
  // in `namespace moho { ... }`.
  class gpg::core::FastVectorN<struct moho::UnitWeaponInfo,1> * InitializeSSTIUnitWeaponInfoVector(class gpg::core::FastVectorN<struct moho::UnitWeaponInfo,1> *) { return nullptr; }
  class moho::CUnitCommand * func_OrderBuildStructure(class Wm3::Vector3<float> *,class moho::CAiBrain *,class moho::Unit *,char const *,class Wm3::Vector3<float> *,float) { return nullptr; }
  class moho::IWldTerrainRes * WLD_CreateTerrainRes(void) { return nullptr; }
  struct moho::WD3DViewport * REN_CreateGameViewport(class wxWindowBase *,char const *,struct wxSize const &,bool) { return nullptr; }
  void LoadAndBroadcastManyToOneListenerEProjectileImpactEvent(class gpg::ReadArchive *,int,int,class gpg::RRef *) {}
  void SaveBroadcasterListenerChainEUnitCommandQueueStatus(class gpg::WriteArchive *,int) {}
  void SaveOwnedRawPointerFromCArmyStatItemOwnerFieldLane1(class gpg::WriteArchive *,int) {}
  void SaveUnownedRawPointerFromManyToOneListener_EProjectileImpactEventIntrusiveHeadLane1(class gpg::WriteArchive *,unsigned int *) {}
  void CON_WxInputBox(void *) {}
  void SIM_Damage(class moho::Sim *,class moho::CDamage const &) {}
}

// REMOVED: ADXM_WaitVsync, mpvcdec_InitDct C++-mangled stubs. Their C-linkage
// counterparts come from the real recovered SofdecRuntime translation-unit
// assembly; CMovie.cpp / MPVDecoder.cpp callers were updated to declare the
// forward decls inside `extern "C"` so they hit the real bodies.

// ===== Misc unrecovered free functions =====
int RuntimeToLowerWideWithCurrentLocale(wchar_t) { return 0; }

namespace gpg
{
  // ===== Unrecovered serialization helpers =====
  //
  // TODO(recovery): SaveOwnedRawPointerFromCArmyStatItemOwnerFieldLane1 and
  // SaveUnownedRawPointerFromManyToOneListener_EProjectileImpactEventIntrusiveHeadLane1
  // both have REAL recovered bodies in src/sdk/gpg/core/containers/ArchiveSerialization.cpp
  // (around line 6526 and 8596 respectively), but they live inside an
  // anonymous namespace at file scope, giving them internal linkage. The call
  // sites (SConditionTriggerReflection.cpp, ProjectileStartupRegistrations.cpp)
  // reference them as `gpg::Save...`, so the linker can't reach the real
  // implementations and falls back to these no-op stubs. Save/load for these
  // specific reflection lanes will be lossy until the originals are moved out
  // of the anon namespace and into `namespace gpg { ... }`.
  void LoadAndBroadcastManyToOneListenerEProjectileImpactEvent(
      gpg::ReadArchive*, int, int, gpg::RRef*) {}
  void SaveBroadcasterListenerChainEUnitCommandQueueStatus(
      gpg::WriteArchive*, int) {}
  void SaveOwnedRawPointerFromCArmyStatItemOwnerFieldLane1(
      gpg::WriteArchive*, int) {}
  void SaveUnownedRawPointerFromManyToOneListener_EProjectileImpactEventIntrusiveHeadLane1(
      gpg::WriteArchive*, unsigned int*) {}
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
//
// TODO(recovery): wxDestroyListNoDeleteRuntime DOES have a recovered body in
// src/sdk/moho/app/WxRuntimeTypes.cpp:75655, but it lives inside an anonymous
// namespace (lines 75463-76408) so it has internal linkage and the file-scope
// caller `wxDestroySocketBaseNoDeleteRuntime` (line 59506) cannot reach it.
// This no-op stub provides a file-scope definition that satisfies the link;
// the embedded list at WxSocketBase+0x28 is therefore not torn down. To use
// the real recovery the wxList runtime helpers around line 75611-75665 need
// to be lifted out of the anonymous namespace into file scope.
void wxDestroyListNoDeleteRuntime(void* const) {}

