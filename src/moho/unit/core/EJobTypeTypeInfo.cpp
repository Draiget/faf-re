#include "moho/unit/core/EJobTypeTypeInfo.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
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
   *
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::EJobType,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EJobType@Moho@@H@gpg'`):
   * `FUN_00BCA460` (real, `__xc_a`-reachable; no dead duplicate found for
   * this instantiation). `Init()` confirmed at `FUN_0055C860` via the RTTI
   * vftable dump (`vftable@0xE186DC` slot 0) -- previously mis-cited in
   * `ArchiveSerialization.cpp` as a generic
   * `InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::EJobType")`
   * dispatch; the real body does a direct `typeid`/`sType`-cache lookup and
   * hardcoded callback install, matching this template's `Init()` exactly
   * (same mis-citation family already caught this session for
   * ESTITargetType/EResourceType/EUnitCommandType/CAniPose/CAniPoseBone).
   * `Deserialize`/`Serialize` at 0x0055D370/0x0055D390 already matched this
   * template's generic bodies exactly (no fabricated null-check).
   *
   * `~PrimitiveSerHelper()`'s compiler-emitted static-destructor
   * registration for this instantiation is `FUN_00BF51F0` (atexit target
   * pushed by the real ctor above); `FUN_0055B930`/`FUN_0055B960` are dead,
   * zero-xref duplicate-emission twins of that exact body
   * (function_sha256-confirmed), formerly modeled in
   * `moho/containers/LegacyContainerFillLanes.cpp` as
   * `gGlobalIntrusiveSentinelLaneH` and its two reset thunks; removed in
   * favor of this citation.
   */
  gpg::PrimitiveSerHelper<moho::EJobType, int> gEJobTypePrimitiveSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x0055B810 (FUN_0055B810, static-init lane)
   * Address: 0x00BF51E0 (FUN_00BF51E0, atexit destructor of the EJobTypeTypeInfo object; registered by 0x00BCA440)
   *
   * What it does:
   * Constructs the static descriptor on first call; the constructor is what
   * performs the `PreRegisterRType`, so one construction is the whole
   * registration.
   */
  gpg::REnumType* preregister_EJobTypeTypeInfo()
  {
    static moho::EJobTypeTypeInfo sInstance;
    return &sInstance;
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
