#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E03D20
   * COL: 0x00E60848
   *
   * What it does:
   * Owns reflected enum descriptor for `ENetProtocolType`.
   */
  class ENetProtocolTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x0047EE20 (FUN_0047EE20, ENetProtocolTypeInfo::ENetProtocolTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the `ENetProtocolType` enum descriptor.
     */
    ENetProtocolTypeInfo();

    /**
     * Address: 0x0047EEB0 (FUN_0047EEB0, ENetProtocolTypeInfo::dtr)
     *
     * What it does:
     * Scalar deleting-destructor lane for enum type descriptor.
     */
    ~ENetProtocolTypeInfo() override;

    /**
     * Address: 0x0047EEA0 (FUN_0047EEA0, ENetProtocolTypeInfo::GetName)
     *
     * What it does:
     * Returns reflected enum type label.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0047EE80 (FUN_0047EE80, ENetProtocolTypeInfo::Init)
     *
     * What it does:
     * Writes enum width, installs enum labels, and finalizes type metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x0047EEE0 (FUN_0047EEE0, ENetProtocolTypeInfo::AddEnums)
     *
     * What it does:
     * Adds `NETPROTO_`-prefixed enum labels (`None`, `TCP`, `UDP`).
     */
    void AddEnums();
  };

  static_assert(sizeof(ENetProtocolTypeInfo) == 0x78, "ENetProtocolTypeInfo size must be 0x78");

  /**
   * Address: 0x00BC4D50 (FUN_00BC4D50, register_ENetProtocolTypeInfo)
   *
   * What it does:
   * Ensures `ENetProtocolTypeInfo` is constructed and registers teardown at
   * process exit.
   */
  void register_ENetProtocolTypeInfo();
} // namespace moho

