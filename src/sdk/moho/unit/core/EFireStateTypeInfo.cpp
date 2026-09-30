#include "moho/unit/core/EFireStateTypeInfo.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
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
   *
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::EFireState,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EFireState@Moho@@H@gpg'`):
   * `FUN_00BCA4C0` (real, `__xc_a`-reachable; no dead duplicate found for
   * this instantiation). `Init()` confirmed at `FUN_0055C900` via the RTTI
   * vftable dump (`vftable@0xE1871C` slot 0) -- previously mis-cited in
   * `ArchiveSerialization.cpp` as a generic
   * `InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::EFireState")`
   * dispatch; the real body does a direct `typeid`/`sType`-cache lookup and
   * hardcoded callback install, matching this template's `Init()` exactly
   * (same mis-citation family already caught this session for
   * ESTITargetType/EResourceType/EUnitCommandType/CAniPose/CAniPoseBone).
   * `Deserialize`/`Serialize` at 0x0055D3E0/0x0055D400 already matched this
   * template's generic bodies exactly (no fabricated null-check).
   *
   * `~PrimitiveSerHelper()`'s compiler-emitted static-destructor
   * registration for this instantiation is `FUN_00BF5230` (atexit target
   * pushed by the real ctor above); `FUN_0055BAB0`/`FUN_0055BAE0` are dead,
   * zero-xref duplicate-emission twins of that exact body
   * (function_sha256-confirmed), formerly modeled in
   * `moho/containers/LegacyContainerFillLanes.cpp` as
   * `gGlobalIntrusiveSentinelLaneI` and its two reset thunks; removed in
   * favor of this citation.
   */
  gpg::PrimitiveSerHelper<moho::EFireState, int> gEFireStatePrimitiveSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x0055B990 (FUN_0055B990, static-init lane)
   * Address: 0x00BF5220 (FUN_00BF5220, atexit destructor of the EFireStateTypeInfo object; registered by 0x00BCA4A0)
   *
   * What it does:
   * Constructs the static descriptor on first call; the constructor is what
   * performs the `PreRegisterRType`, so one construction is the whole
   * registration.
   */
  gpg::REnumType* preregister_EFireStateTypeInfo()
  {
    static moho::EFireStateTypeInfo sInstance;
    return &sInstance;
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
