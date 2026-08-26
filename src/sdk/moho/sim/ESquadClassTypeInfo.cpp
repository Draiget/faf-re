#include "moho/sim/ESquadClassTypeInfo.h"

#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  alignas(moho::ESquadClassTypeInfo) unsigned char gESquadClassTypeInfoStorage[sizeof(moho::ESquadClassTypeInfo)]{};
  bool gESquadClassTypeInfoConstructed = false;

  /**
   * Address: 0x00723B10 (FUN_00723B10, ESquadClassTypeInfo construct/register lane)
   *
   * What it does:
   * Constructs one static `ESquadClassTypeInfo` object and pre-registers RTTI
   * ownership for `ESquadClass`.
   */
  [[maybe_unused]] gpg::REnumType* ConstructESquadClassTypeInfo()
  {
    if (!gESquadClassTypeInfoConstructed) {
      new (gESquadClassTypeInfoStorage) moho::ESquadClassTypeInfo();
      gESquadClassTypeInfoConstructed = true;
    }

    auto* const typeInfo = reinterpret_cast<moho::ESquadClassTypeInfo*>(gESquadClassTypeInfoStorage);
    gpg::PreRegisterRType(typeid(moho::ESquadClass), typeInfo);
    return typeInfo;
  }

  // Address: 0x010B9804 -- process-global `PrimitiveSerHelper<ESquadClass,int>`
  // singleton (constructed by FUN_00BDAB80; see ESquadClassTypeInfo.h for the
  // dead-duplicate-ctor and dead-sibling-writer evidence).
  moho::ESquadClassPrimitiveSerializer gESquadClassSerializer;
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
   * enriched callgraph index) -- unlike its `EAllianceTypeInfo`/
   * `EImpactTypeTypeInfo` siblings, `ESquadClassTypeInfo` has no
   * `cleanup_*`/`atexit` teardown registered at all (see
   * `ConstructESquadClassTypeInfo` above), so there is no plausible explicit
   * `->~ESquadClassTypeInfo()` call site in this binary in the first place.
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
