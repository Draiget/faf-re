#include "moho/entity/EVisibilityModeTypeInfo.h"

#include <cstdint>
#include <typeinfo>
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  bool gEVisibilityModeTypeInfoPreregistered = false;

  /**
   * Address: 0x00BF1F90 (FUN_00BF1F90, atexit destructor of the EVisibilityModeTypeInfo object)
   */
  [[nodiscard]] moho::EVisibilityModeTypeInfo* AcquireEVisibilityModeTypeInfo()
  {
    static moho::EVisibilityModeTypeInfo sInstance;
    return &sInstance;
  }

  /**
   * Address: 0x00BC7AF0 (FUN_00BC7AF0, dynamic initializer for the global
   * `PrimitiveSerHelper<EVisibilityMode,int>` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base (which self-links this
   * helper onto the process-global pending-helper list) and binds the
   * load/save callback fields; `Init()` is dispatched later, from
   * `gpg::SerHelperBase::InitNewHelpers`. Prior to this recovery, this
   * global was a hand-rolled POD that never actually inherited
   * `SerHelperBase`, so `EVisibilityMode`'s serialize/deserialize callbacks
   * were never installed under any code path.
   */
  moho::EVisibilityModePrimitiveSerializer gEVisibilityModePrimitiveSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x0050A190 (FUN_0050A190, Moho::EVisibilityModeTypeInfo::dtr,
   * vtable-slot-2 scalar deleting destructor: tail-calls
   * `gpg::REnumType::~REnumType(this)` then conditionally frees the object --
   * ordinary C++ `delete` semantics, not modeled as a separate function here)
   */
  EVisibilityModeTypeInfo::~EVisibilityModeTypeInfo() = default;

  /**
   * Address: 0x0050A0D0 (FUN_0050A0D0, Moho::EVisibilityModeTypeInfo::GetName)
   */
  const char* EVisibilityModeTypeInfo::GetName() const
  {
    return "EVisibilityMode";
  }

  /**
   * Address: 0x0050A160 (FUN_0050A160, Moho::EVisibilityModeTypeInfo::Init)
   */
  void EVisibilityModeTypeInfo::Init()
  {
    size_ = sizeof(EVisibilityMode);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x0050A1C0 (FUN_0050A1C0, Moho::EVisibilityModeTypeInfo::AddEnums)
   */
  void EVisibilityModeTypeInfo::AddEnums()
  {
    mPrefix = "VIZMODE_";
    AddEnum(StripPrefix("VIZMODE_Always"), VIZMODE_Always);
    AddEnum(StripPrefix("VIZMODE_Never"), VIZMODE_Never);
    AddEnum(StripPrefix("VIZMODE_Intel"), VIZMODE_Intel);
  }

  /**
   * Address: 0x0050A100 (FUN_0050A100, preregister_EVisibilityModeTypeInfo)
   */
  gpg::REnumType* preregister_EVisibilityModeTypeInfo()
  {
    auto* const typeInfo = AcquireEVisibilityModeTypeInfo();
    if (!gEVisibilityModeTypeInfoPreregistered) {
      gpg::PreRegisterRType(typeid(moho::EVisibilityMode), typeInfo);
      gEVisibilityModeTypeInfoPreregistered = true;
    }

    return typeInfo;
  }

  /**
   * Address: 0x00BC7AD0 (FUN_00BC7AD0, register_EVisibilityModeTypeInfo)
   */
  void register_EVisibilityModeTypeInfo()
  {
    (void)preregister_EVisibilityModeTypeInfo();
  }
} // namespace moho

namespace
{
  struct EVisibilityModeTypeInfoBootstrap
  {
    EVisibilityModeTypeInfoBootstrap()
    {
      (void)moho::register_EVisibilityModeTypeInfo();
    }
  };

  [[maybe_unused]] EVisibilityModeTypeInfoBootstrap gEVisibilityModeTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EVisibilityModeTypeInfo_700154, moho::register_EVisibilityModeTypeInfo)

GPG_PREREGISTER_INIT(preregister_EVisibilityModeTypeInfo_700154, moho::preregister_EVisibilityModeTypeInfo)
