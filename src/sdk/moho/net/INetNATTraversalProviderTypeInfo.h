#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E042D4
   * COL: 0x00E60998
   */
  class INetNATTraversalProviderTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x004818C0 (FUN_004818C0, Moho::INetNATTraversalProviderTypeInfo::INetNATTraversalProviderTypeInfo)
     *
     * What it does:
     * Constructs and preregisters reflection metadata for
     * `INetNATTraversalProvider`.
     */
    INetNATTraversalProviderTypeInfo();

    /**
     * Address: 0x00481950 (FUN_00481950, Moho::INetNATTraversalProviderTypeInfo::dtr)
     *
     * What it does:
     * Scalar deleting destructor thunk for INetNATTraversalProviderTypeInfo.
     */
    ~INetNATTraversalProviderTypeInfo() override;

    /**
     * Address: 0x00481940 (FUN_00481940, Moho::INetNATTraversalProviderTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflection type label for INetNATTraversalProvider.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00481920 (FUN_00481920, Moho::INetNATTraversalProviderTypeInfo::Init)
     *
     * What it does:
     * Sets INetNATTraversalProvider object size metadata and finalizes type
     * initialization.
     */
    void Init() override;
  };

  static_assert(
    sizeof(INetNATTraversalProviderTypeInfo) == 0x64, "INetNATTraversalProviderTypeInfo size must be 0x64"
  );

  /**
   * Address: 0x00BC4D70 (FUN_00BC4D70, register_INetNATTraversalProviderTypeInfo)
   *
   * What it does:
   * Ensures INetNATTraversalProvider type-info singleton construction and
   * registers process-exit teardown.
   */
  void register_INetNATTraversalProviderTypeInfo();
} // namespace moho
