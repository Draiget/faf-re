#include "moho/ai/EEconResourceTypeInfo.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  /**
   * Address: 0x00BCA810 (FUN_00BCA810, dynamic initializer for the global
   * `PrimitiveSerHelper<EEconResource,int>` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields (vtable slot 0 `Init()` dispatched later by
   * `gpg::SerHelperBase::InitNewHelpers`). Prior to this recovery, nothing
   * in `src/sdk` ever constructed this helper at all, so `EEconResource`'s
   * serialize/deserialize callbacks were never installed.
   *
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::EEconResource,int>
   * VFTABLE: never constructed prior to this recovery -- see the ctor
   * Doxygen block on `gpg::PrimitiveSerHelper` in Reflection.h.
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EEconResource@Moho@@H@gpg'`):
   * `FUN_00BCA810` (real, `__xc_a`-reachable) vs. a dead zero-xref duplicate
   * at a lower address in the same instantiation family.
   *
   * `~PrimitiveSerHelper()`'s compiler-emitted static-destructor
   * registration for this instantiation is `FUN_00BF5630` (atexit target
   * pushed by the real ctor above); `FUN_00563AB0`/`FUN_00563AE0` are dead,
   * zero-xref duplicate-emission twins of that exact body
   * (function_sha256-confirmed), formerly modeled in
   * `moho/containers/LegacyContainerFillLanes.cpp` as
   * `gGlobalIntrusiveSentinelLaneK` and its two reset thunks; removed in
   * favor of this citation.
   */
  gpg::PrimitiveSerHelper<moho::EEconResource, int> gEEconResourcePrimitiveSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x00563980 (FUN_00563980, static-init lane)
   * Address: 0x00BF5620 (FUN_00BF5620, atexit destructor of the EEconResourceTypeInfo object; registered by 0x00BCA7F0)
   *
   * What it does:
   * Constructs the static descriptor on first call; the constructor is what
   * performs the `PreRegisterRType`, so one construction is the whole
   * registration.
   */
  gpg::REnumType* preregister_EEconResourceTypeInfo()
  {
    static moho::EEconResourceTypeInfo sInstance;
    return &sInstance;
  }

  /**
   * Address: 0x00563980 (FUN_00563980, Moho::EEconResourceTypeInfo::EEconResourceTypeInfo)
   *
   * What it does:
   * Preregisters the enum type descriptor for `EEconResource` with the reflection registry.
   */
  EEconResourceTypeInfo::EEconResourceTypeInfo()
    : gpg::REnumType()
  {
    gpg::PreRegisterRType(typeid(EEconResource), this);
  }

  /**
   * Address: 0x00563A40 (FUN_00563A40, Moho::EEconResourceTypeInfo::dtr)
   */
  EEconResourceTypeInfo::~EEconResourceTypeInfo() = default;

  /**
   * Address: 0x00563A30 (FUN_00563A30, Moho::EEconResourceTypeInfo::GetName)
   */
  const char* EEconResourceTypeInfo::GetName() const
  {
    return "EEconResource";
  }

  /**
   * Address: 0x005639E0 (FUN_005639E0, Moho::EEconResourceTypeInfo::Init)
   */
  void EEconResourceTypeInfo::Init()
  {
    size_ = sizeof(EEconResource);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x00563A70 (FUN_00563A70, Moho::EEconResourceTypeInfo::AddEnums)
   */
  void EEconResourceTypeInfo::AddEnums()
  {
    mPrefix = "ECON_";

    AddEnum(StripPrefix("ECON_ENERGY"), static_cast<std::int32_t>(ECON_ENERGY));
    AddEnum(StripPrefix("ECON_MASS"), static_cast<std::int32_t>(ECON_MASS));
  }
} // namespace moho

// Phase-1 pre-registration: gEEconResourcePrimitiveSerializer's Init() (run
// later, from InitNewHelpers) calls gpg::LookupRType(typeid(EEconResource)),
// so the descriptor must exist first. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_EEconResourceTypeInfo_563980, moho::preregister_EEconResourceTypeInfo)
