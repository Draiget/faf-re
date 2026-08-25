#include "moho/ai/EEconResourceTypeInfo.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/StaticTypeInfoStorage.h"

namespace
{
  gpg::StaticTypeInfoStorage<moho::EEconResourceTypeInfo> gEEconResourceTypeInfoStorage{};

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
   */
  moho::EEconResourcePrimitiveSerializer gEEconResourcePrimitiveSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x00563980 (FUN_00563980, static-init lane)
   *
   * What it does:
   * Constructs the static descriptor on first call; the constructor is what
   * performs the `PreRegisterRType`, so one construction is the whole
   * registration.
   */
  gpg::REnumType* preregister_EEconResourceTypeInfo()
  {
    return &gEEconResourceTypeInfoStorage.Ensure();
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
