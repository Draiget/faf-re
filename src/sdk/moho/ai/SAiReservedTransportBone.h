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

    SAiReservedTransportBone() = default;

    /**
     * Address: 0x005EAC50 (FUN_005EAC50,
     * Moho::SAiReservedTransportBone::SAiReservedTransportBone(const SAiReservedTransportBone&))
     *
     * What it does:
     * The copy constructor: copies both bone indices, links `reservedUnit`
     * into the owner chain `other.reservedUnit` sits in, and copy-constructs
     * `reservedBones`. It is the element constructor that
     * `msvc8::vector<SAiReservedTransportBone>`'s `_Uninit_copy`
     * (0x005EFF70, cited on `uninit_copy_n` in Vector.h) and its
     * `resize`/`_Insert_n` paths (0x005EA590, cited on `resize`) run per
     * element; an earlier `Vector.cpp` transcription had folded it into a
     * default-construct-then-assign helper (`CopyAssignReservedTransportBoneLane`).
     */
    SAiReservedTransportBone(const SAiReservedTransportBone& other);

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

    /**
     * Address: 0x005EE740 (FUN_005EE740, Moho::SAiReservedTransportBone::operator=)
     *
     * IDA signature:
     * SAiReservedTransportBone *__usercall
     *     SAiReservedTransportBone::operator=@<eax>(
     *         const SAiReservedTransportBone *other@<edx>, SAiReservedTransportBone *this@<esi>);
     *
     * What it does:
     * Copies the transport/attach bone indices directly, relinks the
     * `reservedUnit` weak-pointer node onto the source's owner-chain slot
     * (unlinking it from its previous owner chain first when the slot
     * differs), and assigns the nested `reservedBones` vector via its own
     * `operator=` (tail call into `msvc8::vector<int>::operator=`,
     * 0x005ED190). Used by the erase-and-shift loop
     * (`EraseReservedTransportBoneAndAdvance`) and by the vector's own
     * `operator=` whenever `vector<SAiReservedTransportBone>` needs to assign
     * one already-constructed element from another.
     */
    SAiReservedTransportBone& operator=(const SAiReservedTransportBone& other);

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

  /**
   * Address: 0x005E8230 (FUN_005E8230, Moho::SAiReservedTransportBone::~SAiReservedTransportBone)
   *
   * The implicit destructor: `reservedBones`' `_Tidy` frees the block and
   * nulls its lanes, then `~WeakPtr<Unit>` walks the owner chain to this node
   * and unlinks it. Eleven callers -- every erase, tidy and range destroy of
   * the vector that holds one. The two jump-only alias lanes at 0x005EE820
   * and 0x005EF8B0 are dead: zero data_refs and zero call_edges for both, and
   * no source-level caller anywhere in `src/sdk/**`.
   */
} // namespace moho
