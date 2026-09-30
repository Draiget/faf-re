#include "moho/sim/ESquadClassTypeInfo.h"

#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  /**
   * Address: 0x00723B10 (FUN_00723B10, ESquadClassTypeInfo construct/register lane)
   * Address: 0x00C00430 (FUN_00C00430, atexit destructor of the ESquadClassTypeInfo object; registered by 0x00BDAB60)
   *
   * What it does:
   * Constructs one static `ESquadClassTypeInfo` object and pre-registers RTTI
   * ownership for `ESquadClass`.
   */
  [[maybe_unused]] gpg::REnumType* ConstructESquadClassTypeInfo()
  {
    static moho::ESquadClassTypeInfo sInstance;
    gpg::PreRegisterRType(typeid(moho::ESquadClass), &sInstance);
    return &sInstance;
  }

  // Address: 0x010B9804 -- process-global `PrimitiveSerHelper<ESquadClass,int>`
  // singleton (constructed by FUN_00BDAB80; see ESquadClassTypeInfo.h for the
  // dead-duplicate-ctor and dead-sibling-writer evidence).
  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::ESquadClass,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4ESquadClass@Moho@@H@gpg'`):
   * `FUN_00BDAB80` (real, `__xc_a`-reachable) vs. a dead zero-xref duplicate
   * at `FUN_0072A4A0`. A third writer for the same global's storage address,
   * `FUN_0072A9F0` (demangled `gpg::SerSaveLoadHelper<Moho::ESquadClass>`),
   * is itself zero-xref/unreachable -- same sibling-writer pattern already
   * documented for `EAlliance`/`ELayer`/`EVisibilityMode` on the template
   * itself (see `Reflection.h`). There is no real `SerSaveLoadHelper<
   * ESquadClass>` instance in this binary; only the `PrimitiveSerHelper`
   * instantiation is ever constructed.
   *
   * The real ctor's tail pushes plain, unmangled `FUN_00C00440` as its
   * `atexit` target (bare unlink-then-self-link shape, matching
   * the helper node's unlink (`gpg::DListItem::ListUnlink`)) -- modeled by the template's own real
   * destructor, no explicit `atexit` call needed. `FUN_00723C60`/
   * `FUN_00723C90` are dead, zero-xref duplicate-emission twins of that
   * exact `FUN_00C00440` body (function_sha256-confirmed), formerly modeled
   * in `moho/containers/LegacyContainerFillLanes.cpp` as
   * `gGlobalIntrusiveSentinelLaneBD` and its two reset thunks; removed in
   * favor of this citation.
   */
  gpg::PrimitiveSerHelper<moho::ESquadClass, int> gESquadClassSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x00723BA0 (FUN_00723BA0, Moho::ESquadClassTypeInfo::dtr, scalar
   * deleting destructor -- calls `gpg::REnumType::~REnumType()` then
   * conditionally `operator delete`s `this`)
   * Also emitted at: 0x00723BC0 (FUN_00723BC0, complete-object destructor --
   * `ESquadClassTypeInfo` adds no members of its own beyond `REnumType`, so
   * this non-deleting variant is a bare 5-byte `jmp gpg::REnumType::~REnumType`
   * tail-call, not a distinct body. It has zero callsite evidence anywhere in
   * the binary (no code caller, no data/vtable xref, unreachable per the
   * enriched callgraph index); the static object's own atexit destructor
   * (0x00C00430) destroys it.
   * Compiler-emitted glue for the `= default` destructor below, corresponding
   * to no source line of its own -- RULE ONE.
   */
  ESquadClassTypeInfo::~ESquadClassTypeInfo() = default;

  /**
   * Address: 0x00723B90 (FUN_00723B90, Moho::ESquadClassTypeInfo::GetName)
   */
  const char* ESquadClassTypeInfo::GetName() const
  {
    return "ESquadClass";
  }

  /**
   * Address: 0x00723B70 (FUN_00723B70, Moho::ESquadClassTypeInfo::Init)
   */
  void ESquadClassTypeInfo::Init()
  {
    size_ = sizeof(ESquadClass);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x00723BD0 (FUN_00723BD0, Moho::ESquadClassTypeInfo::AddEnums)
   */
  void ESquadClassTypeInfo::AddEnums()
  {
    mPrefix = "SQUADCLASS_";
    AddEnum(StripPrefix("SQUADCLASS_Unassigned"), static_cast<std::int32_t>(ESquadClass::Unassigned));
    AddEnum(StripPrefix("SQUADCLASS_Attack"), static_cast<std::int32_t>(ESquadClass::Attack));
    AddEnum(StripPrefix("SQUADCLASS_Artillery"), static_cast<std::int32_t>(ESquadClass::Artillery));
    AddEnum(StripPrefix("SQUADCLASS_Guard"), static_cast<std::int32_t>(ESquadClass::Guard));
    AddEnum(StripPrefix("SQUADCLASS_Support"), static_cast<std::int32_t>(ESquadClass::Support));
    AddEnum(StripPrefix("SQUADCLASS_Scout"), static_cast<std::int32_t>(ESquadClass::Scout));
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(ConstructESquadClassTypeInfo_542e07, ConstructESquadClassTypeInfo)
