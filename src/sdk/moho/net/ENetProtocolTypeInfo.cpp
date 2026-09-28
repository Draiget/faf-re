#include "moho/net/ENetProtocolTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "moho/net/NetTransportEnums.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  /**
   * Address: 0x00BEF9E0 (FUN_00BEF9E0, atexit destructor of the moho::ENetProtocolTypeInfo object)
   */
  [[nodiscard]] moho::ENetProtocolTypeInfo& GetENetProtocolTypeInfo() noexcept
  {
    static moho::ENetProtocolTypeInfo sInstance;
    return sInstance;
  }

} // namespace

namespace moho
{
  /**
   * Address: 0x0047EE20 (FUN_0047EE20, ENetProtocolTypeInfo::ENetProtocolTypeInfo)
   */
  ENetProtocolTypeInfo::ENetProtocolTypeInfo()
    : gpg::REnumType()
  {
    gpg::PreRegisterRType(typeid(ENetProtocolType), this);
  }

  /**
   * Address: 0x0047EEB0 (FUN_0047EEB0, ENetProtocolTypeInfo::dtr)
   */
  ENetProtocolTypeInfo::~ENetProtocolTypeInfo() = default;

  /**
   * Address: 0x0047EEA0 (FUN_0047EEA0, ENetProtocolTypeInfo::GetName)
   */
  const char* ENetProtocolTypeInfo::GetName() const
  {
    return "ENetProtocol";
  }

  /**
   * Address: 0x0047EE80 (FUN_0047EE80, ENetProtocolTypeInfo::Init)
   */
  void ENetProtocolTypeInfo::Init()
  {
    size_ = sizeof(ENetProtocolType);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x0047EEE0 (FUN_0047EEE0, ENetProtocolTypeInfo::AddEnums)
   */
  void ENetProtocolTypeInfo::AddEnums()
  {
    mPrefix = "NETPROTO_";
    AddEnum(StripPrefix("NETPROTO_None"), static_cast<std::int32_t>(ENetProtocolType::kNone));
    AddEnum(StripPrefix("NETPROTO_TCP"), static_cast<std::int32_t>(ENetProtocolType::kTcp));
    AddEnum(StripPrefix("NETPROTO_UDP"), static_cast<std::int32_t>(ENetProtocolType::kUdp));
  }

  /**
   * Address: 0x00BC4D50 (FUN_00BC4D50, register_ENetProtocolTypeInfo)
   */
  void register_ENetProtocolTypeInfo()
  {
    (void)GetENetProtocolTypeInfo();
  }
} // namespace moho

namespace
{
  struct ENetProtocolTypeInfoBootstrap
  {
    ENetProtocolTypeInfoBootstrap()
    {
      moho::register_ENetProtocolTypeInfo();
    }
  };

  ENetProtocolTypeInfoBootstrap gENetProtocolTypeInfoBootstrap;
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_ENetProtocolTypeInfo_691d12, moho::register_ENetProtocolTypeInfo)
