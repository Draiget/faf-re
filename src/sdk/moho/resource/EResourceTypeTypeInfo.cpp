#include "moho/resource/EResourceTypeTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  alignas(moho::EResourceTypeTypeInfo) unsigned char gEResourceTypeTypeInfoStorage[sizeof(moho::EResourceTypeTypeInfo)];

  void CleanupEResourceTypeTypeInfoAtexit()
  {
    reinterpret_cast<moho::EResourceTypeTypeInfo*>(gEResourceTypeTypeInfoStorage)->~EResourceTypeTypeInfo();
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
   */
  moho::EResourceTypePrimitiveSerializer gEResourceTypePrimitiveSerializer;
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
   * Address: 0x00BF4190 (FUN_00BF4190, Moho::EResourceTypeTypeInfo::~EResourceTypeTypeInfo)
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
   * it under `typeid(EResourceType)` as a side effect of its constructor)
   * and schedules its teardown at process exit.
   */
  void register_EResourceTypeTypeInfo()
  {
    new (gEResourceTypeTypeInfoStorage) EResourceTypeTypeInfo();
    (void)std::atexit(&CleanupEResourceTypeTypeInfoAtexit);
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
