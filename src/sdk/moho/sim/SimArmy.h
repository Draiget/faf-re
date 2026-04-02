#pragma once

#include "IArmy.h"

namespace moho
{
  class SimArmy : public IArmy
  {
  public:
    static gpg::RType* sType;
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x00703EA0 (FUN_00703EA0, Moho::SimArmy::MemberDeserialize)
     *
     * What it does:
     * Deserializes the `IArmy` base-subobject (offset +0x08) through reflected RTTI.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x00703EF0 (FUN_00703EF0, Moho::SimArmy::MemberSerialize)
     *
     * What it does:
     * Serializes the `IArmy` base-subobject (offset +0x08) through reflected RTTI.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x006FDAD0 (FUN_006FDAD0, Moho::SimArmy::~SimArmy)
     *
     * What it does:
     * Restores the SimArmy vtable and tears down the +0x08 IArmy subobject.
     * Calls helper Address: 0x006FDB00 (FUN_006FDB00), which then calls Address: 0x006FD570.
     */
    ~SimArmy() override;
  };
} // namespace moho
