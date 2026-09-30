#include "moho/sim/EAllianceTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  bool gEAllianceTypeInfoPreregistered = false;

  /**
   * Address: 0x00BF1F10 (FUN_00BF1F10, atexit destructor of the EAllianceTypeInfo object)
   */
  [[nodiscard]] moho::EAllianceTypeInfo* AcquireEAllianceTypeInfo()
  {
    static moho::EAllianceTypeInfo sInstance;
    return &sInstance;
  }

  /**
   * Address: 0x00BC7A30 (FUN_00BC7A30, dynamic initializer for the global
   * `PrimitiveSerHelper<EAlliance,int>` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields (vtable slot 0 `Init()` dispatched later by
   * `gpg::SerHelperBase::InitNewHelpers`). The previous raw-struct stand-in
   * for this helper required an explicit
   * `register_EAlliancePrimitiveSerializer()` call from a bootstrap struct
   * to run its equivalent logic; the real binary never does that -- the
   * global's own dynamic initializer is the entire registration.
   *
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::EAlliance,int>
   * VFTABLE: never constructed prior to this recovery -- see the ctor
   * Doxygen block on `gpg::PrimitiveSerHelper` in Reflection.h.
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EAlliance@Moho@@H@gpg'`):
   * `FUN_00BC7A30` (real, `__xc_a`-reachable) vs. a dead zero-xref duplicate
   * at 0x0050A600 (compiler/linker artifact, no source line -- see the
   * class-level Doxygen block on `gpg::PrimitiveSerHelper` in Reflection.h).
   *
   * The previous raw-struct recovery of this instantiation also modeled a
   * "secondary" startup thunk at 0x0050A960 as if it were a duplicate
   * emission of this same ctor. It is not: per `vtable_writers`, 0x0050A960
   * is the (itself dead, zero-xref) ctor of the unrelated template
   * instantiation `gpg::SerSaveLoadHelper<Moho::EAlliance>`
   * (`class_name='?$SerSaveLoadHelper@W4EAlliance@Moho@@@gpg'`), a distinct
   * ~50-instantiation template family (see `ArchiveSerialization.cpp` and
   * friends) that has not been canonicalized and is out of scope here.
   */
  gpg::PrimitiveSerHelper<moho::EAlliance, int> gEAlliancePrimitiveSerializer;

  /**
   * Address: 0x00509D60 (FUN_00509D60, EAllianceTypeInfo construct/register lane)
   *
   * What it does:
   * Constructs one static `EAllianceTypeInfo` instance and pre-registers RTTI
   * ownership for `EAlliance`.
   */
  [[maybe_unused]] gpg::REnumType* ConstructEAllianceTypeInfoInternal()
  {
    auto* const typeInfo = AcquireEAllianceTypeInfo();
    if (!gEAllianceTypeInfoPreregistered) {
      gpg::PreRegisterRType(typeid(moho::EAlliance), typeInfo);
      gEAllianceTypeInfoPreregistered = true;
    }
    return typeInfo;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00509DF0 (FUN_00509DF0, Moho::EAllianceTypeInfo::dtr, scalar
   * deleting destructor -- calls `gpg::REnumType::~REnumType()` then
   * conditionally `operator delete`s `this`)
   * Also emitted at: 0x00509E10 (FUN_00509E10, complete-object destructor --
   * `EAllianceTypeInfo` adds no members of its own beyond `REnumType`, so
   * this non-deleting variant is a bare 5-byte `jmp gpg::REnumType::~REnumType`
   * tail-call, not a distinct body. It has zero callsite evidence anywhere
   * in the binary (no code caller, no data/vtable xref, unreachable per the
   * enriched callgraph index): the one plausible caller, the atexit
   * destructor of the `EAllianceTypeInfo` object (0x00BF1F10), was
   * independently verified to itself `jmp` directly into
   * `gpg::REnumType::~REnumType`
   * (`mov ecx, offset <object>; jmp ??1REnumType@gpg@@QAE@@Z`),
   * bypassing this address entirely. Compiler-emitted glue for the
   * `= default` destructor below, corresponding to no source line of its
   * own -- RULE ONE.
   */
  EAllianceTypeInfo::~EAllianceTypeInfo() = default;

  /**
   * Address: 0x00509DE0 (FUN_00509DE0, Moho::EAllianceTypeInfo::GetName)
   */
  const char* EAllianceTypeInfo::GetName() const
  {
    return "EAlliance";
  }

  /**
   * Address: 0x00509DC0 (FUN_00509DC0, Moho::EAllianceTypeInfo::Init)
   */
  void EAllianceTypeInfo::Init()
  {
    size_ = sizeof(EAlliance);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x00509E20 (FUN_00509E20, Moho::EAllianceTypeInfo::AddEnums)
   */
  void EAllianceTypeInfo::AddEnums()
  {
    mPrefix = "ALLIANCE_";
    AddEnum(StripPrefix("ALLIANCE_Neutral"), static_cast<std::int32_t>(ALLIANCE_Neutral));
    AddEnum(StripPrefix("ALLIANCE_Ally"), static_cast<std::int32_t>(ALLIANCE_Ally));
    AddEnum(StripPrefix("ALLIANCE_Enemy"), static_cast<std::int32_t>(ALLIANCE_Enemy));
  }

  /**
   * Address: 0x00BC7A10 (FUN_00BC7A10, register_EAllianceTypeInfo)
   */
  void register_EAllianceTypeInfo()
  {
    (void)ConstructEAllianceTypeInfoInternal();
  }
} // namespace moho

namespace
{
  struct EAllianceTypeInfoBootstrap
  {
    EAllianceTypeInfoBootstrap()
    {
      (void)moho::register_EAllianceTypeInfo();
    }
  };

  [[maybe_unused]] EAllianceTypeInfoBootstrap gEAllianceTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EAllianceTypeInfo_90bbef, moho::register_EAllianceTypeInfo)

GPG_PREREGISTER_INIT(ConstructEAllianceTypeInfoInternal_90bbef, ConstructEAllianceTypeInfoInternal)
