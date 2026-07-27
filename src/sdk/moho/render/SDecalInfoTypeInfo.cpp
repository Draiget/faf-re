#include "moho/render/SDecalInfoTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/render/CDecalTypes.h"
#include "gpg/core/reflection/StaticInitPhase.h"

// SDecalInfo registration runs from the earliest C++ initializer segment (binary
// __xc_a) so the descriptor is preregistered before default-segment bootstrap
// objects query SDecalInfo RTTI during static initialization.
namespace
{
  alignas(moho::SDecalInfoTypeInfo) unsigned char gSDecalInfoTypeInfoStorage[sizeof(moho::SDecalInfoTypeInfo)];
  bool gSDecalInfoTypeInfoConstructed = false;

  [[nodiscard]] moho::SDecalInfoTypeInfo* AcquireSDecalInfoTypeInfo()
  {
    if (!gSDecalInfoTypeInfoConstructed) {
      new (gSDecalInfoTypeInfoStorage) moho::SDecalInfoTypeInfo();
      gSDecalInfoTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::SDecalInfoTypeInfo*>(gSDecalInfoTypeInfoStorage);
  }

  /**
   * Address: 0x00C027C0 (FUN_00C027C0)
   *
   * What it does:
   * Runs startup-registered teardown for the global `SDecalInfo` descriptor,
   * releasing its reflected field/base lanes.
   */
  void cleanup_SDecalInfoTypeInfo()
  {
    if (!gSDecalInfoTypeInfoConstructed) {
      return;
    }

    AcquireSDecalInfoTypeInfo()->~SDecalInfoTypeInfo();
    gSDecalInfoTypeInfoConstructed = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00778CD0 (FUN_00778CD0, construct-and-preregister worker)
   *
   * What it does:
   * Preregisters `SDecalInfo` RTTI so lookup resolves to this type helper.
   */
  SDecalInfoTypeInfo::SDecalInfoTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(SDecalInfo), this);
  }

  /**
   * Address: 0x00778D60 (FUN_00778D60, scalar deleting thunk)
   */
  SDecalInfoTypeInfo::~SDecalInfoTypeInfo() = default;

  /**
   * Address: 0x00778D50 (FUN_00778D50)
   *
   * What it does:
   * Returns the reflection type name literal for SDecalInfo.
   */
  const char* SDecalInfoTypeInfo::GetName() const
  {
    return "SDecalInfo";
  }

  /**
   * Address: 0x00778D30 (FUN_00778D30)
   *
   * What it does:
   * Writes `size_` for SDecalInfo, then performs base-init/finalization.
   */
  void SDecalInfoTypeInfo::Init()
  {
    size_ = sizeof(SDecalInfo);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BDD800 (FUN_00BDD800, register_SDecalInfoTypeInfo)
   *
   * What it does:
   * Registers the `SDecalInfo` type-info object and installs process-exit cleanup.
   */
  int register_SDecalInfoTypeInfo()
  {
    (void)AcquireSDecalInfoTypeInfo();
    return std::atexit(&cleanup_SDecalInfoTypeInfo);
  }
} // namespace moho

namespace
{
  struct SDecalInfoTypeInfoRegistration
  {
    SDecalInfoTypeInfoRegistration()
    {
      (void)moho::register_SDecalInfoTypeInfo();
    }
  };

  [[maybe_unused]] SDecalInfoTypeInfoRegistration gSDecalInfoTypeInfoRegistration;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_SDecalInfoTypeInfo_e40ec1, moho::register_SDecalInfoTypeInfo)
