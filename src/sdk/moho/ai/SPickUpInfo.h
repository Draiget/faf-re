#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/misc/WeakPtr.h"

namespace gpg
{
  class RRef;
  class RType;
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class Unit;

  /**
   * Unit pickup candidate entry used by transport-load task selection.
   *
   * Layout evidence:
   * - Type-info init sets `sizeof(SPickUpInfo) == 0x0C` (FUN_00624730).
   * - Vector serializers use 12-byte element stride (FUN_006270E0/FUN_00627240).
   */
  struct SPickUpInfo
  {
    static gpg::RType* sType;

    SPickUpInfo() noexcept = default;

    /**
     * Address: 0x006246A0 (FUN_006246A0)
     *
     * What it does:
     * Links `mUnit` at the head of `unit`'s weak chain (`unit + 4`, or a null
     * slot for a null unit) and stores the squared distance. Emitted out of
     * line, the entry in EAX, the unit in ECX, the distance in XMM0; caller
     * `CUnitLoadUnits::DoTask` (0x00625110), one per pickup candidate.
     */
    SPickUpInfo(Unit* unit, float distanceSquared) noexcept;

    SPickUpInfo(const SPickUpInfo&) noexcept = default;

    /**
     * Address: 0x00628FD0 (FUN_00628FD0 -- the implicit assignment emitted out
     * of line, the destination in EAX and the source in EDX: `mUnit`'s
     * `operator=` (relink only when the two slots differ), then the distance.
     * No self-assignment test; equal slots make it a no-op. Callers: the
     * pickup-queue sort's `iter_swap` 0x0062A130 and `_Pop_heap` 0x0062A7F0
     * (legacy/algorithms/Sort.h). Formerly
     * `AssignWeakPtrFloatPayloadLaneWithRelink` over a `WeakPtrPayloadLane<float>`
     * look-alike in moho/misc/WeakPtr.h (RULE ONE), removed 2026-09-30.)
     */
    SPickUpInfo& operator=(const SPickUpInfo&) noexcept = default;

    /**
     * Address: 0x00624AA0 (FUN_00624AA0 -- the destructor emitted out of line,
     * `this` in ECX: `mUnit` walks the unit's weak chain to itself and splices
     * itself out. Callers include the comparator 0x006248D0 (its by-value
     * operands), `CUnitLoadUnits::DoTask` 0x00625110, `SerLoad` 0x006270E0 and
     * the vector's `_Insert_n` 0x00627800. Formerly the hand-written
     * `UnlinkWeakUnitLane`, removed 2026-09-30.)
     */
    ~SPickUpInfo() = default;

    /**
     * Address: 0x00627EB0 (FUN_00627EB0)
     *
     * What it does:
     * Deserializes one pickup entry by reading weak-unit lane then distance.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x00627F00 (FUN_00627F00)
     *
     * What it does:
     * Serializes one pickup entry by writing weak-unit lane then distance.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    // Out of line: decoding the weak link is the cast from the unit's
    // `WeakObject`, which needs `Unit` complete.
    [[nodiscard]] Unit* GetUnit() const noexcept;

    WeakPtr<Unit> mUnit;     // +0x00
    float mDistanceSq = 0.0f; // +0x08
  };

  static_assert(sizeof(SPickUpInfo) == 0x0C, "SPickUpInfo size must be 0x0C");
  static_assert(offsetof(SPickUpInfo, mUnit) == 0x00, "SPickUpInfo::mUnit offset must be 0x00");
  static_assert(offsetof(SPickUpInfo, mDistanceSq) == 0x08, "SPickUpInfo::mDistanceSq offset must be 0x08");

} // namespace moho

namespace gpg
{
  /**
   * Address: 0x00628090 (FUN_00628090)
   *
   * What it does:
   * Wrapper lane that materializes one temporary `RRef_SPickUpInfo` and
   * copies object/type fields into the destination reference record.
   */
  gpg::RRef* AssignSPickUpInfoRef(gpg::RRef* outRef, moho::SPickUpInfo* value);
} // namespace gpg
