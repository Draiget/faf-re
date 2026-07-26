#include "moho/sim/CSquadTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/sim/CSquad.h"

// CSquad registration runs from the earliest C++ initializer segment (binary
// __xc_a) so the descriptor is preregistered before default-segment bootstrap
// objects query CSquad RTTI during static initialization.
#pragma init_seg(lib)

namespace
{
  alignas(moho::CSquadTypeInfo) unsigned char gCSquadTypeInfoStorage[sizeof(moho::CSquadTypeInfo)];
  bool gCSquadTypeInfoConstructed = false;

  [[nodiscard]] moho::CSquadTypeInfo* AcquireCSquadTypeInfo()
  {
    if (!gCSquadTypeInfoConstructed) {
      new (gCSquadTypeInfoStorage) moho::CSquadTypeInfo();
      gCSquadTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::CSquadTypeInfo*>(gCSquadTypeInfoStorage);
  }

  /**
   * Address: 0x00C00470 (FUN_00C00470)
   *
   * What it does:
   * Runs startup-registered teardown for the global `CSquad` descriptor,
   * releasing its reflected field/base lanes.
   */
  void cleanup_CSquadTypeInfo()
  {
    if (!gCSquadTypeInfoConstructed) {
      return;
    }

    AcquireCSquadTypeInfo()->~CSquadTypeInfo();
    gCSquadTypeInfoConstructed = false;
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
  int register_CSquadTypeInfo()
  {
    (void)AcquireCSquadTypeInfo();
    return std::atexit(&cleanup_CSquadTypeInfo);
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
