#include "moho/sim/IArmyTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/sim/IArmy.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  bool gIArmyTypeInfoPreregistered = false;

  /**
   * Address: 0x00BF48A0 (FUN_00BF48A0, atexit destructor of the IArmyTypeInfo object)
   */
  [[nodiscard]] moho::IArmyTypeInfo* AcquireIArmyTypeInfo()
  {
    static moho::IArmyTypeInfo sInstance;
    return &sInstance;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00550B50 (FUN_00550B50, Moho::IArmyTypeInfo::dtr)
   */
  IArmyTypeInfo::~IArmyTypeInfo() = default;

  /**
   * Address: 0x00550B40 (FUN_00550B40, Moho::IArmyTypeInfo::GetName)
   */
  const char* IArmyTypeInfo::GetName() const
  {
    return "IArmy";
  }

  /**
   * Address: 0x00550B20 (FUN_00550B20, Moho::IArmyTypeInfo::Init)
   */
  void IArmyTypeInfo::Init()
  {
    size_ = 0x1E0;
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00550AC0 (FUN_00550AC0, preregister_IArmyTypeInfo)
   *
   * What it does:
   * Constructs/preregisters startup-owned RTTI descriptor storage for `IArmy`.
   */
  gpg::RType* preregister_IArmyTypeInfo()
  {
    auto* const typeInfo = AcquireIArmyTypeInfo();
    if (!gIArmyTypeInfoPreregistered) {
      gpg::PreRegisterRType(typeid(IArmy), typeInfo);
      gIArmyTypeInfoPreregistered = true;
    }

    IArmy::sType = typeInfo;
    return typeInfo;
  }

  /**
   * Address: 0x00BC9B50 (FUN_00BC9B50, register_IArmyTypeInfo)
   *
   * What it does:
   * Runs `IArmy` typeinfo preregistration.
   */
  void register_IArmyTypeInfo()
  {
    (void)preregister_IArmyTypeInfo();
  }
} // namespace moho

namespace
{
  struct IArmyTypeInfoBootstrap
  {
    IArmyTypeInfoBootstrap()
    {
      (void)moho::register_IArmyTypeInfo();
    }
  };

  [[maybe_unused]] IArmyTypeInfoBootstrap gIArmyTypeInfoBootstrap;
} // namespace



// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_IArmyTypeInfo_0717a0, moho::register_IArmyTypeInfo)

GPG_PREREGISTER_INIT(preregister_IArmyTypeInfo_0717a0, moho::preregister_IArmyTypeInfo)
