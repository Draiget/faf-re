#include "moho/ai/CAiBrainTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiBrain.h"
#include "moho/script/CScriptObject.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  alignas(CAiBrainTypeInfo) unsigned char gCAiBrainTypeInfoStorage[sizeof(CAiBrainTypeInfo)];
  bool gCAiBrainTypeInfoConstructed = false;

  [[nodiscard]] CAiBrainTypeInfo& AcquireCAiBrainTypeInfo()
  {
    if (!gCAiBrainTypeInfoConstructed) {
      new (gCAiBrainTypeInfoStorage) CAiBrainTypeInfo();
      gCAiBrainTypeInfoConstructed = true;
    }

    return *reinterpret_cast<CAiBrainTypeInfo*>(gCAiBrainTypeInfoStorage);
  }

  [[nodiscard]] CAiBrainTypeInfo* PeekCAiBrainTypeInfo() noexcept
  {
    if (!gCAiBrainTypeInfoConstructed) {
      return nullptr;
    }

    return reinterpret_cast<CAiBrainTypeInfo*>(gCAiBrainTypeInfoStorage);
  }

  [[nodiscard]] gpg::RType* CachedCScriptObjectType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CScriptObject));
    }
    return cached;
  }

  /**
   * Address: 0x00581830 (FUN_00581830)
   *
   * What it does:
   * Registers `CScriptObject` as one reflected base lane for `CAiBrain` at
   * offset `+0x00`.
   */
  void AddCScriptObjectBaseToCAiBrainType(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedCScriptObjectType();
    if (!baseType) {
      return;
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  // Address: 0x00581890 (FUN_00581890, sub_581890) -- generic, type-erased
  // "delete this reflected object" callback: reads the object's own vtable
  // slot 2 (`+0x08`) and calls it with the scalar-delete flag hardcoded to
  // 1. One of a 36-way ICF-identical `delete_func_t` thunk family
  // (canonical twin `FUN_00510AA0`). This exact address's own real
  // registration site (`moho::CAiBrainConstruct::mDeleteCallback`,
  // instruction 0x00BCB409 in CAiBrainConstruct.cpp) is already served by
  // the typed `DeleteConstructedCAiBrain` specialization there -- see its
  // doc comment for the vtable-slot equivalence proof
  // (`CAiBrain::~CAiBrain()`'s own scalar-deleting-destructor thunk,
  // `FUN_00579F30`, sits at the identical slot 2 of `CAiBrain`'s vtable).
  // No registration site anywhere in this binary needs the raw generic
  // dispatcher as its own named function: recovering it as
  // `delete static_cast<gpg::RObject*>(object)` behind a `void*` parameter
  // would be exactly the raw vtable-slot-magic this project's
  // reconstruction-fidelity contract forbids, and nothing in `src/sdk/**`
  // has a source-level call to it (RULE ONE / no-orphan-helper rule) --
  // so this address intentionally has no dedicated recovered function here.

  void cleanup_CAiBrainTypeInfoStartup()
  {
    CAiBrainTypeInfo* const typeInfo = PeekCAiBrainTypeInfo();
    if (!typeInfo) {
      return;
    }

    typeInfo->fields_ = msvc8::vector<gpg::RField>{};
    typeInfo->bases_ = msvc8::vector<gpg::RField>{};
  }

  struct CAiBrainTypeInfoStartupBootstrap
  {
    CAiBrainTypeInfoStartupBootstrap()
    {
      moho::register_CAiBrainTypeInfoStartup();
    }
  };

  CAiBrainTypeInfoStartupBootstrap gCAiBrainTypeInfoStartupBootstrap;
} // namespace

/**
 * Address: 0x00579B20 (FUN_00579B20, ??0CAiBrainTypeInfo@Moho@@QAE@XZ)
 *
 * What it does:
 * Preregisters `CAiBrain` RTTI for this type-info helper.
 */
CAiBrainTypeInfo::CAiBrainTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CAiBrain), this);
}

/**
 * Address: 0x00579BB0 (FUN_00579BB0, scalar deleting thunk)
 */
CAiBrainTypeInfo::~CAiBrainTypeInfo() = default;

/**
 * Address: 0x00579BA0 (FUN_00579BA0, ?GetName@CAiBrainTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CAiBrainTypeInfo::GetName() const
{
  return "CAiBrain";
}

/**
 * Address: 0x00579B80 (FUN_00579B80, ?Init@CAiBrainTypeInfo@Moho@@UAEXXZ)
 */
void CAiBrainTypeInfo::Init()
{
  size_ = sizeof(CAiBrain);
  gpg::RType::Init();
  AddCScriptObjectBaseToCAiBrainType(this);
  Finish();
}

/**
 * Address: 0x00BCB3D0 (FUN_00BCB3D0, register_Moho::CAiBrainTypeInfo)
 *
 * What it does:
 * Ensures startup construction of `CAiBrainTypeInfo` and installs process-exit cleanup.
 */
void moho::register_CAiBrainTypeInfoStartup()
{
  (void)AcquireCAiBrainTypeInfo();
  (void)std::atexit(&cleanup_CAiBrainTypeInfoStartup);
}


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CAiBrainTypeInfoStartup_776a4f, moho::register_CAiBrainTypeInfoStartup)
