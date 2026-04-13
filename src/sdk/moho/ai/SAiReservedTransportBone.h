#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/Vector.h"
#include "moho/misc/WeakPtr.h"

namespace gpg
{
  class RType;
  class ReadArchive;
  class WriteArchive;
}

namespace moho
{
  class Unit;

  /**
   * Transport attach-slot reservation payload.
   *
   * Evidence:
   * - Type-info init writes size 0x20 (FUN_005E3FC0).
   * - RVectorType helper uses 0x20 element stride (FUN_005E9140/FUN_005E9170).
   * - Reserve/unreserve helper chain:
   *   - FUN_005E3ED0 initializes dwords +0x00/+0x04 and weak-link at +0x08.
   *   - FUN_005EE360 unlinks weak-link at +0x08 and clears vector<int> at +0x14.
   */
  struct SAiReservedTransportBone
  {
    static gpg::RType* sType;

    /**
     * Address: 0x005EB860 (FUN_005EB860, Moho::SAiReservedTransportBone::MemberDeserialize)
     *
     * What it does:
     * Loads transport/attach indices, reserved unit weak link, and reserved
     * attach-bone list from one archive payload.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x005EB8F0 (FUN_005EB8F0, Moho::SAiReservedTransportBone::MemberSerialize)
     *
     * What it does:
     * Saves transport/attach indices, reserved unit weak link, and reserved
     * attach-bone list into one archive payload.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    std::uint32_t transportBoneIndex; // +0x00
    std::uint32_t attachBoneIndex;    // +0x04
    WeakPtr<Unit> reservedUnit;       // +0x08
    msvc8::vector<int> reservedBones; // +0x10
  };

  static_assert(sizeof(SAiReservedTransportBone) == 0x20, "SAiReservedTransportBone size must be 0x20");
  static_assert(
    offsetof(SAiReservedTransportBone, transportBoneIndex) == 0x00,
    "SAiReservedTransportBone::transportBoneIndex offset must be 0x00"
  );
  static_assert(offsetof(SAiReservedTransportBone, attachBoneIndex) == 0x04, "SAiReservedTransportBone::attachBoneIndex offset must be 0x04");
  static_assert(offsetof(SAiReservedTransportBone, reservedUnit) == 0x08, "SAiReservedTransportBone::reservedUnit offset must be 0x08");
  static_assert(offsetof(SAiReservedTransportBone, reservedBones) == 0x10, "SAiReservedTransportBone::reservedBones offset must be 0x10");
} // namespace moho
