#include "moho/resource/EResourceTypeTypeInfo.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  /**
   * Address: 0x00BF4190 (FUN_00BF4190, atexit destructor of the EResourceTypeTypeInfo object)
   */
  [[nodiscard]] moho::EResourceTypeTypeInfo& AcquireEResourceTypeTypeInfo()
  {
    static moho::EResourceTypeTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BC9610 (FUN_00BC9610, dynamic initializer for the global
   * `PrimitiveSerHelper<EResourceType,int>` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base (which self-links this
   * helper onto the process-global pending-helper list) and binds the
   * load/save callback fields; `Init()` is dispatched later, from
   * `gpg::SerHelperBase::InitNewHelpers`. Prior to this recovery, this
   * global's only wiring function was `[[maybe_unused]]` and never called
   * from anywhere, so `EResourceType`'s serialize/deserialize callbacks
   * were never installed under any code path at all.
   *
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::EResourceType,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EResourceType@Moho@@H@gpg'`):
   * `FUN_00BC9610` (real, `__xc_a`-reachable) vs. a dead zero-xref duplicate
   * at `FUN_00547380` in the same instantiation family. `FUN_00BC9610` was
   * wrongly tagged `external_dependency` in progress tracking before this
   * recovery -- it is the same SerHelperBase-ctor/field-set/vtable-install/
   * atexit shape as every other confirmed instantiation, not an OS/CRT/
   * library import.
   *
   * Previously modeled in this file as a hand-rolled `{ void* mVtable;
   * SerHelperBase* mHelperNext, mHelperPrev; ... }` POD. Worse than the
   * sibling conversions in this same pass: its only wiring function,
   * `InitializeEResourceTypePrimitiveSerializerStartupThunk` (citing the
   * dead `FUN_00547380` address, not the real one), was `[[maybe_unused]]`
   * and genuinely never called from anywhere -- not even from an eager
   * bootstrap struct like the others had -- so `EResourceType`'s
   * serialize/deserialize callbacks were never installed under any code
   * path at all. `SerHelperBase`'s own ctor now performs the real
   * self-registration onto the pending-helper list.
   *
   * `~PrimitiveSerHelper()`'s compiler-emitted static-destructor
   * registration for this instantiation is `FUN_00BF41A0` (atexit target
   * pushed by the real ctor at 0x00BC9610); `FUN_00545B70`/`FUN_00545BA0`
   * are dead, zero-xref duplicate-emission twins of that exact body
   * (function_sha256-confirmed), formerly modeled in
   * `moho/containers/LegacyContainerFillLanes.cpp` as
   * `gGlobalIntrusiveSentinelLaneC` and its two reset thunks; removed in
   * favor of this citation. See `gpg::PrimitiveSerHelper<T,IntType>`'s
   * per-instantiation address list in `Reflection.h`.
   */
  gpg::PrimitiveSerHelper<moho::EResourceType, int> gEResourceTypePrimitiveSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x00545A50 (FUN_00545A50, Moho::EResourceTypeTypeInfo::EResourceTypeTypeInfo)
   *
   * What it does:
   * Preregisters this type descriptor under `typeid(EResourceType)` so
   * `gpg::LookupRType` can resolve it later. The base `REnumType`/`RType`
   * subobject and vtable install are handled by the compiler-generated base
   * ctor chain; this constructor's only own work is the preregistration
   * call.
   */
  EResourceTypeTypeInfo::EResourceTypeTypeInfo()
  {
    gpg::PreRegisterRType(typeid(EResourceType), this);
  }

  /**
   * Address: 0x00545AE0 (FUN_00545AE0, vtable-slot-2 scalar deleting
   * destructor: tail-calls `gpg::REnumType::~REnumType(this)` then
   * conditionally frees the object -- ordinary C++ `delete` semantics, not
   * modeled as a separate function here)
   *
   * The vtable-slot-0 deleting-destructor thunk (FUN_00545AE0, `this,
   * deleteFlags` shape: runs this destructor then conditionally frees the
   * object) is the compiler-generated override the `override` destructor
   * below already emits -- no separate hand-written body needed.
   */
  EResourceTypeTypeInfo::~EResourceTypeTypeInfo() = default;

  /**
   * Address: 0x00545AD0 (FUN_00545AD0, Moho::EResourceTypeTypeInfo::GetName)
   */
  const char* EResourceTypeTypeInfo::GetName() const
  {
    return "EResourceType";
  }

  /**
   * Address: 0x00545AB0 (FUN_00545AB0, Moho::EResourceTypeTypeInfo::Init)
   */
  void EResourceTypeTypeInfo::Init()
  {
    size_ = sizeof(EResourceType);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x00545B10 (FUN_00545B10, Moho::EResourceTypeTypeInfo::AddEnums)
   */
  void EResourceTypeTypeInfo::AddEnums()
  {
    mPrefix = "RESTYPE_";

    AddEnum(StripPrefix("RESTYPE_None"), static_cast<std::int32_t>(RESTYPE_None));
    AddEnum(StripPrefix("RESTYPE_Mass"), static_cast<std::int32_t>(RESTYPE_Mass));
    AddEnum(StripPrefix("RESTYPE_Hydrocarbon"), static_cast<std::int32_t>(RESTYPE_Hydrocarbon));
    AddEnum(StripPrefix("RESTYPE_Max"), static_cast<std::int32_t>(RESTYPE_Max));
  }

  /**
   * Address: 0x00BC95F0 (FUN_00BC95F0, register_EResourceTypeTypeInfo)
   *
   * What it does:
   * Constructs the global `EResourceTypeTypeInfo` descriptor (preregistering
   * it under `typeid(EResourceType)` as a side effect of its constructor).
   */
  void register_EResourceTypeTypeInfo()
  {
    (void)AcquireEResourceTypeTypeInfo();
  }
} // namespace moho

namespace
{
  struct EResourceTypeTypeInfoBootstrap
  {
    EResourceTypeTypeInfoBootstrap()
    {
      moho::register_EResourceTypeTypeInfo();
    }
  };

  [[maybe_unused]] EResourceTypeTypeInfoBootstrap gEResourceTypeTypeInfoBootstrap;
} // namespace

// Phase-1 pre-registration: run this descriptor registration ahead of every
// consumer that calls gpg::LookupRType(typeid(EResourceType)). See
// StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EResourceTypeTypeInfo_bc95f0, moho::register_EResourceTypeTypeInfo)
