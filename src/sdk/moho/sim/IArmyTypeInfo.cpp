#include "moho/sim/IArmyTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/sim/IArmy.h"

namespace
{
  alignas(moho::IArmyTypeInfo) unsigned char gIArmyTypeInfoStorage[sizeof(moho::IArmyTypeInfo)];
  bool gIArmyTypeInfoConstructed = false;
  bool gIArmyTypeInfoPreregistered = false;

  [[nodiscard]] moho::IArmyTypeInfo* AcquireIArmyTypeInfo()
  {
    if (!gIArmyTypeInfoConstructed) {
      new (gIArmyTypeInfoStorage) moho::IArmyTypeInfo();
      gIArmyTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::IArmyTypeInfo*>(gIArmyTypeInfoStorage);
  }

  /**
   * Address: 0x00BF48A0 (FUN_00BF48A0, cleanup_IArmyTypeInfo)
   */
  void cleanup_IArmyTypeInfo()
  {
    if (!gIArmyTypeInfoConstructed) {
      return;
    }

    AcquireIArmyTypeInfo()->~IArmyTypeInfo();
    gIArmyTypeInfoConstructed = false;
    gIArmyTypeInfoPreregistered = false;
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
   * Runs `IArmy` typeinfo preregistration and installs process-exit cleanup.
   */
  int register_IArmyTypeInfo()
  {
    (void)preregister_IArmyTypeInfo();
    return std::atexit(&cleanup_IArmyTypeInfo);
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

