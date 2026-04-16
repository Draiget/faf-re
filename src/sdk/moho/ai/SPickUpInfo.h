#pragma once

#include <cstddef>

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

    SPickUpInfo() noexcept;
    SPickUpInfo(Unit* unit, float distanceSquared) noexcept;
    SPickUpInfo(const SPickUpInfo& source) noexcept;
    SPickUpInfo& operator=(const SPickUpInfo& source) noexcept;
    ~SPickUpInfo();

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

    [[nodiscard]] Unit* GetUnit() const noexcept
    {
      return mUnit.GetObjectPtr();
    }

  private:
    /**
     * Address: 0x006246A0 (FUN_006246A0)
     *
     * What it does:
     * Binds this entry's weak-unit link from `unit` and stores the provided
     * distance-squared lane.
     */
    void BindUnitAndDistanceSquared(Unit* unit, float distanceSquared) noexcept;

    /**
     * Address: 0x00624AA0 (FUN_00624AA0)
     *
     * What it does:
     * Unlinks this entry from the current unit weak-owner intrusive chain.
     */
    void UnlinkWeakUnitLane() noexcept;

  public:
    WeakPtr<Unit> mUnit; // +0x00
    float mDistanceSq;   // +0x08
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
