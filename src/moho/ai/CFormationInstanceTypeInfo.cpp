#include "moho/ai/CFormationInstanceTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiFormationInstance.h"
#include "moho/ai/IFormationInstance.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x00570F10 (FUN_00570F10)
   *
   * What it does:
   * Registers `IFormationInstance` as one reflected base lane for
   * `CFormationInstance` at offset `+0x00`.
   */
  void AddIFormationInstanceBaseToCFormationInstanceType(gpg::RType* const typeInfo)
  {
    if (!IFormationInstance::sType) {
      IFormationInstance::sType = gpg::LookupRType(typeid(IFormationInstance));
    }

    typeInfo->AddBase(gpg::RField{IFormationInstance::sType->GetName(), IFormationInstance::sType, 0});
  }

  /**
   * Address: 0x00BF5A40 (FUN_00BF5A40, atexit destructor of the CFormationInstanceTypeInfo object)
   */
  [[nodiscard]] CFormationInstanceTypeInfo& CFormationInstanceTypeInfoSingleton()
  {
    static CFormationInstanceTypeInfo sInstance;
    return sInstance;
  }
} // namespace

/**
 * Address: 0x0056A720 (FUN_0056A720, ctor lane)
 */
CFormationInstanceTypeInfo::CFormationInstanceTypeInfo()
{
  gpg::PreRegisterRType(typeid(CFormationInstance), this);
}

/**
 * Address: 0x0056A7A0 (FUN_0056A7A0, Moho::CFormationInstanceTypeInfo::GetName)
 */
const char* CFormationInstanceTypeInfo::GetName() const
{
  return "CFormationInstance";
}

/**
 * Address: 0x0056A780 (FUN_0056A780, Moho::CFormationInstanceTypeInfo::Init)
 */
void CFormationInstanceTypeInfo::Init()
{
  size_ = sizeof(CFormationInstance);
  gpg::RType::Init();
  AddIFormationInstanceBaseToCFormationInstanceType(this);
  Finish();
}

/**
 * Address: 0x00BCAC20 (FUN_00BCAC20, register_CFormationInstanceTypeInfo)
 */
void moho::register_CFormationInstanceTypeInfo()
{
  (void)CFormationInstanceTypeInfoSingleton();
}

// Phase-1 pre-registration: run this descriptor registration ahead of every
// consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CFormationInstanceTypeInfo_4a1f9d, moho::register_CFormationInstanceTypeInfo)
