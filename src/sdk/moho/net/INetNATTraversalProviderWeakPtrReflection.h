#pragma once

#include "boost/weak_ptr.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/net/INetNATTraversalProvider.h"

namespace gpg
{
  template <class T>
  class RWeakPointerType;

  /**
   * VFTABLE: 0x00E04304
   * COL: 0x00E60948
   *
   * What it is:
   * Reflection adapter for `boost::weak_ptr<moho::INetNATTraversalProvider>`.
   */
  template <>
  class RWeakPointerType<moho::INetNATTraversalProvider> final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00482350 (FUN_00482350)
     */
    ~RWeakPointerType() override;

    /**
     * Address: 0x00481A00 (FUN_00481A00, gpg::RWeakPointerType_INetNATTraversalProvider::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00481AE0 (FUN_00481AE0)
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x00481AA0 (FUN_00481AA0)
     */
    void Init() override;
  };

  static_assert(
    sizeof(RWeakPointerType<moho::INetNATTraversalProvider>) == 0x64,
    "RWeakPointerType<INetNATTraversalProvider> size must be 0x64"
  );

  [[nodiscard]] RType* ResolveWeakPtrINetNATTraversalProviderType();
} // namespace gpg
