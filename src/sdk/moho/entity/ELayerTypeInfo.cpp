#include "moho/entity/ELayerTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  alignas(moho::ELayerTypeInfo) unsigned char gELayerTypeInfoStorage[sizeof(moho::ELayerTypeInfo)]{};
  bool gELayerTypeInfoConstructed = false;
  bool gELayerTypeInfoPreregistered = false;

  gpg::RType* gELayerCachedType = nullptr;

  [[nodiscard]] moho::ELayerTypeInfo* AcquireELayerTypeInfo()
  {
    if (!gELayerTypeInfoConstructed) {
      new (gELayerTypeInfoStorage) moho::ELayerTypeInfo();
      gELayerTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::ELayerTypeInfo*>(gELayerTypeInfoStorage);
  }

  /**
   * Address: 0x00BC7C80 (FUN_00BC7C80, dynamic initializer for the global
   * `PrimitiveSerHelper<ELayer,int>` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base (which self-links this
   * helper onto the process-global pending-helper list) and binds the
   * load/save callback fields; `Init()` is dispatched later, from
   * `gpg::SerHelperBase::InitNewHelpers`. Prior to this recovery, this
   * global was a hand-rolled POD that never actually inherited
   * `SerHelperBase`, so `ELayer`'s serialize/deserialize callbacks were
   * never installed under any code path.
   */
  moho::ELayerPrimitiveSerializer gELayerPrimitiveSerializer;

  /**
   * Address: 0x00BF2070 (FUN_00BF2070, cleanup_ELayerTypeInfo)
   */
  void cleanup_ELayerTypeInfo()
  {
    if (!gELayerTypeInfoConstructed) {
      return;
    }

    AcquireELayerTypeInfo()->~ELayerTypeInfo();
    gELayerTypeInfoConstructed = false;
    gELayerTypeInfoPreregistered = false;
    gELayerCachedType = nullptr;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BF2070 (FUN_00BF2070, Moho::ELayerTypeInfo::dtr)
   * Address: 0x0050BA80 (FUN_0050BA80, vtable-slot-2 scalar deleting
   * destructor: tail-calls `gpg::REnumType::~REnumType(this)` then
   * conditionally frees the object -- ordinary C++ `delete` semantics, not
   * modeled as a separate function here)
   */
  ELayerTypeInfo::~ELayerTypeInfo() = default;

  /**
   * Address: 0x0050BA70 (FUN_0050BA70, Moho::ELayerTypeInfo::GetName)
   */
  const char* ELayerTypeInfo::GetName() const
  {
    return "ELayer";
  }

  /**
   * Address: 0x0050BA50 (FUN_0050BA50, Moho::ELayerTypeInfo::Init)
   */
  void ELayerTypeInfo::Init()
  {
    size_ = sizeof(ELayer);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x0050BAB0 (FUN_0050BAB0, Moho::ELayerTypeInfo::AddEnums)
   */
  void ELayerTypeInfo::AddEnums()
  {
    mPrefix = "LAYER_";
    AddEnum(StripPrefix("LAYER_None"), LAYER_None);
    AddEnum(StripPrefix("LAYER_Land"), LAYER_Land);
    AddEnum(StripPrefix("LAYER_Seabed"), LAYER_Seabed);
    AddEnum(StripPrefix("LAYER_Sub"), LAYER_Sub);
    AddEnum(StripPrefix("LAYER_Water"), LAYER_Water);
    AddEnum(StripPrefix("LAYER_Air"), LAYER_Air);
    AddEnum(StripPrefix("LAYER_Orbit"), LAYER_Orbit);
    AddEnum(StripPrefix("LAYER_All"), 127);
  }

  /**
   * Address: 0x0050B9F0 (FUN_0050B9F0, preregister_ELayerTypeInfo)
   */
  gpg::REnumType* preregister_ELayerTypeInfo()
  {
    auto* const typeInfo = AcquireELayerTypeInfo();
    if (!gELayerTypeInfoPreregistered) {
      gpg::PreRegisterRType(typeid(ELayer), typeInfo);
      gELayerTypeInfoPreregistered = true;
    }

    gELayerCachedType = typeInfo;
    return typeInfo;
  }

  /**
   * Address: 0x00BC7C60 (FUN_00BC7C60, register_ELayerTypeInfo)
   */
  int register_ELayerTypeInfo()
  {
    (void)preregister_ELayerTypeInfo();
    return std::atexit(&cleanup_ELayerTypeInfo);
  }
} // namespace moho

namespace
{
  struct ELayerTypeInfoBootstrap
  {
    ELayerTypeInfoBootstrap()
    {
      (void)moho::register_ELayerTypeInfo();
    }
  };

  [[maybe_unused]] ELayerTypeInfoBootstrap gELayerTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_ELayerTypeInfo_b64bda, moho::register_ELayerTypeInfo)

GPG_PREREGISTER_INIT(preregister_ELayerTypeInfo_b64bda, moho::preregister_ELayerTypeInfo)
