#include "moho/net/ENetProtocolTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "moho/net/NetTransportEnums.h"

namespace
{
  alignas(moho::ENetProtocolTypeInfo) unsigned char gENetProtocolTypeInfoStorage[sizeof(moho::ENetProtocolTypeInfo)];
  bool gENetProtocolTypeInfoConstructed = false;

  [[nodiscard]] moho::ENetProtocolTypeInfo& GetENetProtocolTypeInfo() noexcept
  {
    if (!gENetProtocolTypeInfoConstructed) {
      new (gENetProtocolTypeInfoStorage) moho::ENetProtocolTypeInfo();
      gENetProtocolTypeInfoConstructed = true;
    }

    return *reinterpret_cast<moho::ENetProtocolTypeInfo*>(gENetProtocolTypeInfoStorage);
  }

  /**
   * Address: 0x00BEF9E0 (??1ENetProtocolTypeInfo@Moho@@QAE@@Z)
   *
   * What it does:
   * Runs process-exit teardown for recovered ENetProtocol type-info singleton.
   */
  void cleanup_ENetProtocolTypeInfo()
  {
    if (!gENetProtocolTypeInfoConstructed) {
      return;
    }

    GetENetProtocolTypeInfo().~ENetProtocolTypeInfo();
    gENetProtocolTypeInfoConstructed = false;
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
    (void)std::atexit(&cleanup_ENetProtocolTypeInfo);
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

