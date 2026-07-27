#include "moho/sim/CPlatoonTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/script/CScriptObject.h"
#include "moho/sim/CPlatoon.h"
#include "gpg/core/reflection/StaticInitPhase.h"

// CPlatoon registration runs from the earliest C++ initializer segment (binary
// __xc_a) so the descriptor is preregistered before default-segment bootstrap
// objects query CPlatoon RTTI during static initialization.
namespace
{
  alignas(moho::CPlatoonTypeInfo) unsigned char gCPlatoonTypeInfoStorage[sizeof(moho::CPlatoonTypeInfo)];
  bool gCPlatoonTypeInfoConstructed = false;

  [[nodiscard]] moho::CPlatoonTypeInfo* AcquireCPlatoonTypeInfo()
  {
    if (!gCPlatoonTypeInfoConstructed) {
      new (gCPlatoonTypeInfoStorage) moho::CPlatoonTypeInfo();
      gCPlatoonTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::CPlatoonTypeInfo*>(gCPlatoonTypeInfoStorage);
  }

  /**
   * Address: 0x00C00530 (FUN_00C00530)
   *
   * What it does:
   * Runs startup-registered teardown for the global `CPlatoon` descriptor,
   * releasing its reflected field/base lanes.
   */
  void cleanup_CPlatoonTypeInfo()
  {
    if (!gCPlatoonTypeInfoConstructed) {
      return;
    }

    AcquireCPlatoonTypeInfo()->~CPlatoonTypeInfo();
    gCPlatoonTypeInfoConstructed = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00724A60 (FUN_00724A60, construct-and-preregister worker)
   *
   * What it does:
   * Preregisters `CPlatoon` RTTI so lookup resolves to this type helper.
   */
  CPlatoonTypeInfo::CPlatoonTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CPlatoon), this);
  }

  /**
   * Address: 0x00724AF0 (FUN_00724AF0, scalar deleting thunk)
   */
  CPlatoonTypeInfo::~CPlatoonTypeInfo() = default;

  /**
   * Address: 0x00724AE0 (FUN_00724AE0)
   *
   * What it does:
   * Returns the reflection type name literal for CPlatoon.
   */
  const char* CPlatoonTypeInfo::GetName() const
  {
    return "CPlatoon";
  }

  /**
   * Address: 0x0072ABD0 (FUN_0072ABD0,
   * ?AddBase_CSCcriptObject@CPlatoonTypeInfo@Moho@@ — the retail symbol
   * carries the doubled-C typo)
   *
   * What it does:
   * Resolves (and caches) the `CScriptObject` reflection type, then appends it
   * as a zero-offset reflected base of this descriptor.
   */
  void CPlatoonTypeInfo::AddBaseCScriptObject()
  {
    if (CScriptObject::sType == nullptr) {
      CScriptObject::sType = gpg::LookupRType(typeid(CScriptObject));
    }

    gpg::RType* const baseType = CScriptObject::sType;
    const gpg::RField base(baseType->GetName(), baseType, 0);
    AddBase(base);
  }

  /**
   * Address: 0x00724AC0 (FUN_00724AC0)
   *
   * What it does:
   * Writes `size_` for CPlatoon, runs base-init, registers the `CScriptObject`
   * reflected base, then finalizes the descriptor.
   */
  void CPlatoonTypeInfo::Init()
  {
    size_ = sizeof(CPlatoon);
    gpg::RType::Init();
    AddBaseCScriptObject();
    Finish();
  }

  /**
   * Address: 0x00BDAC60 (FUN_00BDAC60, register_CPlatoonTypeInfo)
   *
   * What it does:
   * Registers the `CPlatoon` type-info object and installs process-exit cleanup.
   */
  int register_CPlatoonTypeInfo()
  {
    (void)AcquireCPlatoonTypeInfo();
    return std::atexit(&cleanup_CPlatoonTypeInfo);
  }
} // namespace moho

namespace
{
  struct CPlatoonTypeInfoRegistration
  {
    CPlatoonTypeInfoRegistration()
    {
      (void)moho::register_CPlatoonTypeInfo();
    }
  };

  [[maybe_unused]] CPlatoonTypeInfoRegistration gCPlatoonTypeInfoRegistration;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CPlatoonTypeInfo_007b24, moho::register_CPlatoonTypeInfo)
