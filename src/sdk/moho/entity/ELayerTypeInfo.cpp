#include "moho/entity/ELayerTypeInfo.h"

#include <cstdint>
#include <typeinfo>
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  bool gELayerTypeInfoPreregistered = false;

  /**
   * Address: 0x00BF2070 (FUN_00BF2070, atexit destructor of the ELayerTypeInfo object)
   */
  [[nodiscard]] moho::ELayerTypeInfo* AcquireELayerTypeInfo()
  {
    static moho::ELayerTypeInfo sInstance;
    return &sInstance;
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
   *
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::ELayer,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4ELayer@Moho@@H@gpg'`):
   * `FUN_00BC7C80` (real, `__xc_a`-reachable) vs. a dead zero-xref duplicate
   * at `FUN_0050C660` in the same instantiation family. Previously modeled
   * in this file as a hand-rolled `{ void* mVtable; SerHelperBase*
   * mHelperNext, mHelperPrev; ... }` POD plus manual
   * `InitializeSerializerNode`/`UnlinkSerializerNode` splicing and an eager
   * `register_ELayerPrimitiveSerializer()` bootstrap call -- none of which
   * the real binary does; `SerHelperBase`'s own ctor performs the real
   * self-registration onto the pending-helper list.
   *
   * A second, unrelated writer shares this global's storage address
   * (`FUN_0050CA60`, demangled `gpg::SerSaveLoadHelper<enum Moho::ELayer>`)
   * but is itself zero-xref/unreachable too -- a separate, still-unrecovered
   * template family, not modeled here.
   */
  gpg::PrimitiveSerHelper<moho::ELayer, int> gELayerPrimitiveSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x0050BA80 (FUN_0050BA80, Moho::ELayerTypeInfo::dtr,
   * vtable-slot-2 scalar deleting destructor: tail-calls
   * `gpg::REnumType::~REnumType(this)` then conditionally frees the object --
   * ordinary C++ `delete` semantics, not modeled as a separate function here)
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

    return typeInfo;
  }

  /**
   * Address: 0x00BC7C60 (FUN_00BC7C60, register_ELayerTypeInfo)
   */
  void register_ELayerTypeInfo()
  {
    (void)preregister_ELayerTypeInfo();
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
