#include "moho/sim/CSquadTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/sim/CSquad.h"
#include "gpg/core/reflection/StaticInitPhase.h"

// CSquad registration runs from the earliest C++ initializer segment (binary
// __xc_a) so the descriptor is preregistered before default-segment bootstrap
// objects query CSquad RTTI during static initialization.
namespace
{
  /**
   * Address: 0x00C00470 (FUN_00C00470, atexit destructor of the moho::CSquadTypeInfo object)
   */
  [[nodiscard]] moho::CSquadTypeInfo* AcquireCSquadTypeInfo()
  {
    static moho::CSquadTypeInfo sInstance;
    return &sInstance;
  }

} // namespace

namespace moho
{
  /**
   * Address: 0x00723CC0 (FUN_00723CC0, construct-and-preregister worker)
   *
   * What it does:
   * Preregisters `CSquad` RTTI so lookup resolves to this type helper.
   */
  CSquadTypeInfo::CSquadTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CSquad), this);
  }

  /**
   * Address: 0x00723D50 (FUN_00723D50, scalar deleting thunk)
   */
  CSquadTypeInfo::~CSquadTypeInfo() = default;

  /**
   * Address: 0x00723D40 (FUN_00723D40)
   *
   * What it does:
   * Returns the reflection type name literal for CSquad.
   */
  const char* CSquadTypeInfo::GetName() const
  {
    return "CSquad";
  }

  /**
   * Address: 0x00723D20 (FUN_00723D20)
   *
   * What it does:
   * Writes `size_` for CSquad, then performs base-init/finalization.
   */
  void CSquadTypeInfo::Init()
  {
    size_ = sizeof(CSquad);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BDABC0 (FUN_00BDABC0, register_CSquadTypeInfo)
   *
   * What it does:
   * Registers the `CSquad` type-info object and installs process-exit cleanup.
   */
  void register_CSquadTypeInfo()
  {
    (void)AcquireCSquadTypeInfo();
  }
} // namespace moho

namespace
{
  struct CSquadTypeInfoRegistration
  {
    CSquadTypeInfoRegistration()
    {
      (void)moho::register_CSquadTypeInfo();
    }
  };

  [[maybe_unused]] CSquadTypeInfoRegistration gCSquadTypeInfoRegistration;
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CSquadTypeInfo_e03500, moho::register_CSquadTypeInfo)
