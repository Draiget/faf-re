#include "moho/net/INetNATTraversalProviderTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/net/INetNATTraversalProvider.h"

namespace
{
  alignas(moho::INetNATTraversalProviderTypeInfo)
  unsigned char gINetNATTraversalProviderTypeInfoStorage[sizeof(moho::INetNATTraversalProviderTypeInfo)];
  bool gINetNATTraversalProviderTypeInfoConstructed = false;

  [[nodiscard]] moho::INetNATTraversalProviderTypeInfo& GetINetNATTraversalProviderTypeInfo() noexcept
  {
    if (!gINetNATTraversalProviderTypeInfoConstructed) {
      new (gINetNATTraversalProviderTypeInfoStorage) moho::INetNATTraversalProviderTypeInfo();
      gINetNATTraversalProviderTypeInfoConstructed = true;
    }

    return *reinterpret_cast<moho::INetNATTraversalProviderTypeInfo*>(gINetNATTraversalProviderTypeInfoStorage);
  }

  void cleanup_INetNATTraversalProviderTypeInfo()
  {
    if (!gINetNATTraversalProviderTypeInfoConstructed) {
      return;
    }

    GetINetNATTraversalProviderTypeInfo().~INetNATTraversalProviderTypeInfo();
    gINetNATTraversalProviderTypeInfoConstructed = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x004818C0 (FUN_004818C0, Moho::INetNATTraversalProviderTypeInfo::INetNATTraversalProviderTypeInfo)
   */
  INetNATTraversalProviderTypeInfo::INetNATTraversalProviderTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(INetNATTraversalProvider), this);
  }

  /**
   * Address: 0x00481950 (FUN_00481950, Moho::INetNATTraversalProviderTypeInfo::dtr)
   */
  INetNATTraversalProviderTypeInfo::~INetNATTraversalProviderTypeInfo() = default;

  /**
   * Address: 0x00481940 (FUN_00481940, Moho::INetNATTraversalProviderTypeInfo::GetName)
   *
   * IDA signature:
   * const char *sub_481940();
   */
  const char* INetNATTraversalProviderTypeInfo::GetName() const
  {
    return "INetNATTraversalProvider";
  }

  /**
   * Address: 0x00481920 (FUN_00481920, Moho::INetNATTraversalProviderTypeInfo::Init)
   *
   * IDA signature:
   * int __thiscall sub_481920(_DWORD *this);
   */
  void INetNATTraversalProviderTypeInfo::Init()
  {
    size_ = sizeof(INetNATTraversalProvider);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BC4D70 (FUN_00BC4D70, register_INetNATTraversalProviderTypeInfo)
   */
  void register_INetNATTraversalProviderTypeInfo()
  {
    (void)GetINetNATTraversalProviderTypeInfo();
    (void)std::atexit(&cleanup_INetNATTraversalProviderTypeInfo);
  }
} // namespace moho

namespace
{
  struct INetNATTraversalProviderTypeInfoBootstrap
  {
    INetNATTraversalProviderTypeInfoBootstrap()
    {
      moho::register_INetNATTraversalProviderTypeInfo();
    }
  };

  INetNATTraversalProviderTypeInfoBootstrap gINetNATTraversalProviderTypeInfoBootstrap;
} // namespace
