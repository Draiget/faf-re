#include "moho/unit/core/EFireStateTypeInfo.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/StaticTypeInfoStorage.h"

namespace
{
  gpg::StaticTypeInfoStorage<moho::EFireStateTypeInfo> gEFireStateTypeInfoStorage{};

  /**
   * Address: 0x00BCA4C0 (FUN_00BCA4C0, dynamic initializer for the global
   * `PrimitiveSerHelper<EFireState,int>` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields (vtable slot 0 `Init()` dispatched later by
   * `gpg::SerHelperBase::InitNewHelpers`). This is an independent `__xc_a`
   * static initializer, separate from `EFireStateTypeInfo`'s own
   * initializer above.
   */
  moho::EFireStatePrimitiveSerializer gEFireStatePrimitiveSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x0055B990 (FUN_0055B990, static-init lane)
   *
   * What it does:
   * Constructs the static descriptor on first call; the constructor is what
   * performs the `PreRegisterRType`, so one construction is the whole
   * registration.
   */
  gpg::REnumType* preregister_EFireStateTypeInfo()
  {
    return &gEFireStateTypeInfoStorage.Ensure();
  }

  /**
   * Address: 0x0055B990 (FUN_0055B990, Moho::EFireStateTypeInfo::EFireStateTypeInfo)
   *
   * What it does:
   * Preregisters the enum type descriptor for `EFireState` with the reflection registry.
   */
  EFireStateTypeInfo::EFireStateTypeInfo()
    : gpg::REnumType()
  {
    gpg::PreRegisterRType(typeid(EFireState), this);
  }

  /**
   * Address: 0x0055BA20 (FUN_0055BA20, Moho::EFireStateTypeInfo::dtr)
   */
  EFireStateTypeInfo::~EFireStateTypeInfo() = default;

  /**
   * Address: 0x0055BA10 (FUN_0055BA10, Moho::EFireStateTypeInfo::GetName)
   */
  const char* EFireStateTypeInfo::GetName() const
  {
    return "EFireState";
  }

  /**
   * Address: 0x0055B9F0 (FUN_0055B9F0, Moho::EFireStateTypeInfo::Init)
   */
  void EFireStateTypeInfo::Init()
  {
    size_ = sizeof(EFireState);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x0055BA50 (FUN_0055BA50, Moho::EFireStateTypeInfo::AddEnums)
   */
  void EFireStateTypeInfo::AddEnums()
  {
    mPrefix = "FIRESTATE_";

    AddEnum(StripPrefix("FIRESTATE_Mix"), static_cast<std::int32_t>(FIRESTATE_Mix));
    AddEnum(StripPrefix("FIRESTATE_ReturnFire"), static_cast<std::int32_t>(FIRESTATE_ReturnFire));
    AddEnum(StripPrefix("FIRESTATE_HoldFire"), static_cast<std::int32_t>(FIRESTATE_HoldFire));
    AddEnum(StripPrefix("FIRESTATE_HoldGround"), static_cast<std::int32_t>(FIRESTATE_HoldGround));
  }

} // namespace moho

// Phase-1 pre-registration: RegisterSerializeFunctions above is a consumer
// that calls gpg::LookupRType, so the descriptor must exist first. See
// StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_EFireStateTypeInfo_55b990, moho::preregister_EFireStateTypeInfo)
