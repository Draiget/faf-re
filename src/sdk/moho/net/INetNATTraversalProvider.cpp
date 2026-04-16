#include "moho/net/INetNATTraversalProvider.h"

#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"

namespace
{
  class INetNATTraversalProviderVtableProbe final : public moho::INetNATTraversalProvider
  {
  public:
    void SetTraversalHandler(int /*port*/, boost::shared_ptr<moho::INetNATTraversalHandler>* /*handler*/) override
    {
    }

    void ReceivePacket(u_long /*address*/, u_short /*port*/, const char* /*dat*/, size_t /*size*/) override
    {
    }
  };

  struct INetNATTraversalProviderRuntimeView
  {
    void* vtable; // +0x00
  };

  [[nodiscard]] void* INetNATTraversalProviderVtableToken() noexcept
  {
    static INetNATTraversalProviderVtableProbe probe{};
    return *reinterpret_cast<void**>(&probe);
  }
} // namespace

namespace moho
{
  gpg::RType* INetNATTraversalProvider::sType = nullptr;

  /**
   * Address: 0x007B64F0 (FUN_007B64F0, ??0INetNATTraversalProvider@Moho@@QAE@XZ)
   *
   * What it does:
   * Initializes one NAT traversal provider base interface object.
   */
  INetNATTraversalProvider::INetNATTraversalProvider() = default;

  /**
   * Address: 0x007B68F0 (FUN_007B68F0)
   *
   * What it does:
   * Rebinds one NAT traversal provider runtime lane to the recovered
   * interface vtable token.
   */
  [[maybe_unused]] INetNATTraversalProvider* InitializeINetNATTraversalProviderBaseVtable(
    INetNATTraversalProvider* const provider
  ) noexcept
  {
    if (provider == nullptr) {
      return nullptr;
    }

    auto* const runtime = reinterpret_cast<INetNATTraversalProviderRuntimeView*>(provider);
    runtime->vtable = INetNATTraversalProviderVtableToken();
    return provider;
  }

  gpg::RType* INetNATTraversalProvider::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(INetNATTraversalProvider));
    }
    return sType;
  }
} // namespace moho
