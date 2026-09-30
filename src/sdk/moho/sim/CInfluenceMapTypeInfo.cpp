#include "moho/sim/CInfluenceMapTypeInfo.h"

#include <typeinfo>

#include "moho/sim/CInfluenceMap.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  moho::CInfluenceMapTypeInfo gCInfluenceMapTypeInfo;
  moho::EThreatTypeTypeInfo gEThreatTypeTypeInfo;

  // Address: 0x010B9448 -- process-global `PrimitiveSerHelper<EThreatType,int>`
  // singleton (constructed by FUN_00BDA3A0; see CInfluenceMapTypeInfo.h for
  // the dead-duplicate-ctor and dead-sibling-writer evidence).
  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::EThreatType,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EThreatType@Moho@@H@gpg'`):
   * `FUN_00BDA3A0` (real, `__xc_a`-reachable) vs. a dead zero-xref duplicate
   * at `FUN_007188D0`. A third writer for the same global's storage address,
   * `FUN_00719FF0` (demangled `gpg::SerSaveLoadHelper<Moho::EThreatType>`),
   * is itself zero-xref/unreachable -- same sibling-writer pattern already
   * documented for `EAlliance`/`ELayer`/`EVisibilityMode`/`ESquadClass` on
   * the template itself (see `Reflection.h`). There is no real
   * `SerSaveLoadHelper<EThreatType>` instance in this binary; only the
   * `PrimitiveSerHelper` instantiation is ever constructed.
   *
   * The real ctor's tail pushes plain, unmangled `FUN_00BFFCA0` as its
   * `atexit` target (bare unlink-then-self-link shape, matching
   * the helper node's unlink (`gpg::DListItem::ListUnlink`)) -- modeled by the template's own real
   * destructor, no explicit `atexit` call needed. `FUN_007156F0`/
   * `FUN_00715720` are dead, zero-xref duplicate-emission twins of that
   * exact `FUN_00BFFCA0` body (function_sha256-confirmed), formerly modeled
   * in `moho/containers/LegacyContainerFillLanes.cpp` as
   * `gGlobalIntrusiveSentinelLaneAY` and its two reset thunks; removed in
   * favor of this citation.
   *
   * Previously a hand-rolled `{ void* mVtable; SerHelperBase*, SerHelperBase*;
   * ...}` mimic named `EThreatTypeSerializerHelperStorage` lived in
   * SThreatSerializer.cpp, entirely disconnected from this real global
   * (`dword_10B9448`/`Moho__PrimitiveSerHelper<EThreatType,int>`): its own
   * storage was a separate anonymous-namespace static, its two
   * "initializer" functions had no real caller beyond a local bootstrap in
   * that file, and its one real address citation (0x007188D0) actually
   * pointed at the dead duplicate ctor, not this real one. Removed as
   * fabricated/orphaned; this alias is the correct, evidence-backed
   * recovery.
   */
  gpg::PrimitiveSerHelper<moho::EThreatType, int> gEThreatTypeSerializer;
}

namespace moho
{
  /**
   * Address: 0x00717490 (FUN_00717490, sub_717490)
   *
   * IDA signature:
   * gpg::RType *sub_717490();
   */
  CInfluenceMapTypeInfo::CInfluenceMapTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CInfluenceMap), this);
  }

  /**
   * Address: 0x00BDA660 (FUN_00BDA660, sub_BDA660)
   *
   * What it does:
   * Forces CInfluenceMap RTTI preregistration bootstrap.
   */
  void register_CInfluenceMapTypeInfo()
  {
    (void)gCInfluenceMapTypeInfo;
  }

  /**
   * What it does:
   * Forces EThreatType enum-type reflection preregistration storage.
   */
  void register_EThreatTypeTypeInfo()
  {
    (void)gEThreatTypeTypeInfo;
  }

  /**
   * Address: 0x00717520 (FUN_00717520, Moho::CInfluenceMapTypeInfo::dtr)
   */
  CInfluenceMapTypeInfo::~CInfluenceMapTypeInfo() = default;

  /**
   * Address: 0x00717510 (FUN_00717510, Moho::CInfluenceMapTypeInfo::GetName)
   */
  const char* CInfluenceMapTypeInfo::GetName() const
  {
    return "CInfluenceMap";
  }

  /**
   * Address: 0x007174F0 (FUN_007174F0, Moho::CInfluenceMapTypeInfo::Init)
   *
   * IDA signature:
   * void __thiscall Moho::CInfluenceMapTypeInfo::Init(gpg::RType *this);
   */
  void CInfluenceMapTypeInfo::Init()
  {
    size_ = sizeof(CInfluenceMap);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x007154D0 (FUN_007154D0, Moho::EThreatTypeTypeInfo::EThreatTypeTypeInfo)
   */
  EThreatTypeTypeInfo::EThreatTypeTypeInfo()
    : gpg::REnumType()
  {
    gpg::PreRegisterRType(typeid(EThreatType), this);
  }

  /**
   * Address: 0x00715560 (FUN_00715560, vtable-slot-2 scalar deleting
   * destructor: tail-calls `gpg::REnumType::~REnumType(this)` then
   * conditionally frees the object -- ordinary C++ `delete` semantics, not
   * modeled as a separate function here)
   */
  EThreatTypeTypeInfo::~EThreatTypeTypeInfo() = default;

  /**
   * Address: 0x00715550 (FUN_00715550, Moho::EThreatTypeTypeInfo::GetName)
   */
  const char* EThreatTypeTypeInfo::GetName() const
  {
    return "EThreatType";
  }

  /**
   * Address: 0x00715530 (FUN_00715530, Moho::EThreatTypeTypeInfo::Init)
   */
  void EThreatTypeTypeInfo::Init()
  {
    size_ = sizeof(EThreatType);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x00715590 (FUN_00715590, Moho::EThreatTypeTypeInfo::AddEnums)
   */
  void EThreatTypeTypeInfo::AddEnums()
  {
    mPrefix = "THREATTYPE_";
    AddEnum(StripPrefix("THREATTYPE_Overall"), static_cast<std::int32_t>(THREATTYPE_Overall));
    AddEnum(StripPrefix("THREATTYPE_OverallNotAssigned"), static_cast<std::int32_t>(THREATTYPE_OverallNotAssigned));
    AddEnum(StripPrefix("THREATTYPE_StructuresNotMex"), static_cast<std::int32_t>(THREATTYPE_StructuresNotMex));
    AddEnum(StripPrefix("THREATTYPE_Structures"), static_cast<std::int32_t>(THREATTYPE_Structures));
    AddEnum(StripPrefix("THREATTYPE_Naval"), static_cast<std::int32_t>(THREATTYPE_Naval));
    AddEnum(StripPrefix("THREATTYPE_Air"), static_cast<std::int32_t>(THREATTYPE_Air));
    AddEnum(StripPrefix("THREATTYPE_Land"), static_cast<std::int32_t>(THREATTYPE_Land));
    AddEnum(StripPrefix("THREATTYPE_Experimental"), static_cast<std::int32_t>(THREATTYPE_Experimental));
    AddEnum(StripPrefix("THREATTYPE_Commander"), static_cast<std::int32_t>(THREATTYPE_Commander));
    AddEnum(StripPrefix("THREATTYPE_Artillery"), static_cast<std::int32_t>(THREATTYPE_Artillery));
    AddEnum(StripPrefix("THREATTYPE_AntiAir"), static_cast<std::int32_t>(THREATTYPE_AntiAir));
    AddEnum(StripPrefix("THREATTYPE_AntiSurface"), static_cast<std::int32_t>(THREATTYPE_AntiSurface));
    AddEnum(StripPrefix("THREATTYPE_AntiSub"), static_cast<std::int32_t>(THREATTYPE_AntiSub));
    AddEnum(StripPrefix("THREATTYPE_Economy"), static_cast<std::int32_t>(THREATTYPE_Economy));
    AddEnum(StripPrefix("THREATTYPE_Unknown"), static_cast<std::int32_t>(THREATTYPE_Unknown));
  }
} // namespace moho

namespace
{
  struct CInfluenceMapTypeInfoBootstrap
  {
    CInfluenceMapTypeInfoBootstrap()
    {
      moho::register_CInfluenceMapTypeInfo();
      moho::register_EThreatTypeTypeInfo();
    }
  };

  CInfluenceMapTypeInfoBootstrap gCInfluenceMapTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CInfluenceMapTypeInfo_50df3b, moho::register_CInfluenceMapTypeInfo)
GPG_PREREGISTER_INIT(register_EThreatTypeTypeInfo_50df3b, moho::register_EThreatTypeTypeInfo)
