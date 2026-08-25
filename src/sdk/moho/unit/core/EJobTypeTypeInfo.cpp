#include "moho/unit/core/EJobTypeTypeInfo.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/StaticTypeInfoStorage.h"

namespace
{
  gpg::StaticTypeInfoStorage<moho::EJobTypeTypeInfo> gEJobTypeTypeInfoStorage{};

  /**
   * Address: 0x00BCA460 (FUN_00BCA460, dynamic initializer for the global
   * `PrimitiveSerHelper<EJobType,int>` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields (vtable slot 0 `Init()` dispatched later by
   * `gpg::SerHelperBase::InitNewHelpers`). This is an independent `__xc_a`
   * static initializer, separate from `EJobTypeTypeInfo`'s own initializer
   * above.
   */
  moho::EJobTypePrimitiveSerializer gEJobTypePrimitiveSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x0055B810 (FUN_0055B810, static-init lane)
   *
   * What it does:
   * Constructs the static descriptor on first call; the constructor is what
   * performs the `PreRegisterRType`, so one construction is the whole
   * registration.
   */
  gpg::REnumType* preregister_EJobTypeTypeInfo()
  {
    return &gEJobTypeTypeInfoStorage.Ensure();
  }

  /**
   * Address: 0x0055B810 (FUN_0055B810, Moho::EJobTypeTypeInfo::EJobTypeTypeInfo)
   *
   * What it does:
   * Preregisters the enum type descriptor for `EJobType` with the reflection registry.
   */
  EJobTypeTypeInfo::EJobTypeTypeInfo()
    : gpg::REnumType()
  {
    gpg::PreRegisterRType(typeid(EJobType), this);
  }

  /**
   * Address: 0x0055B8A0 (FUN_0055B8A0, Moho::EJobTypeTypeInfo::dtr)
   */
  EJobTypeTypeInfo::~EJobTypeTypeInfo() = default;

  /**
   * Address: 0x0055B890 (FUN_0055B890, Moho::EJobTypeTypeInfo::GetName)
   */
  const char* EJobTypeTypeInfo::GetName() const
  {
    return "EJobType";
  }

  /**
   * Address: 0x0055B870 (FUN_0055B870, Moho::EJobTypeTypeInfo::Init)
   */
  void EJobTypeTypeInfo::Init()
  {
    size_ = sizeof(EJobType);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x0055B8D0 (FUN_0055B8D0, Moho::EJobTypeTypeInfo::AddEnums)
   */
  void EJobTypeTypeInfo::AddEnums()
  {
    mPrefix = "JOB_";

    AddEnum(StripPrefix("JOB_None"), static_cast<std::int32_t>(JOB_None));
    AddEnum(StripPrefix("JOB_Build"), static_cast<std::int32_t>(JOB_Build));
    AddEnum(StripPrefix("JOB_Repair"), static_cast<std::int32_t>(JOB_Repair));
    AddEnum(StripPrefix("JOB_Reclaim"), static_cast<std::int32_t>(JOB_Reclaim));
  }

} // namespace moho

// Phase-1 pre-registration: RegisterSerializeFunctions above is a consumer
// that calls gpg::LookupRType, so the descriptor must exist first. See
// StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_EJobTypeTypeInfo_55b810, moho::preregister_EJobTypeTypeInfo)
