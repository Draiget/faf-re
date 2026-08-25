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

  /**
   * Serializer helper for `SPickUpInfo`.
   *
   * Address: 0x00BD1C50 (FUN_00BD1C50, dynamic initializer for the global
   * `SPickUpInfoSerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
   * splices it into the process-global `sNewHelpers` pending list), then
   * binds the load/save callback fields. Confirmed from raw disassembly:
   * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
   * `??_7SPickUpInfoSerializer@Moho@@6B@` -- no eager `Init()` call exists
   * here. The previous recovery modeled this helper as an anonymous,
   * non-virtual `SPickUpInfoSerializerStartupNode` struct that never wrote
   * a vtable slot at all and never touched the real `gpg::SerHelperBase`
   * base, so it was never actually spliced into `sNewHelpers`.
   */
  class SPickUpInfoSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00624810 (FUN_00624810, Moho::SPickUpInfoSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `SPickUpInfo::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00624820 (FUN_00624820, Moho::SPickUpInfoSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `SPickUpInfo::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    SPickUpInfoSerializer();

    /**
     * Address: 0x00BFA520 (FUN_00BFA520, ??1SPickUpInfoSerializer@Moho@@QAE@@Z)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~SPickUpInfoSerializer();

    /**
     * What it does:
     * Binds the `SPickUpInfo` serializer callbacks into reflected RTTI.
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper
     * is drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoad; // +0x0C
    gpg::RType::save_func_t mSave; // +0x10
  };

  static_assert(offsetof(SPickUpInfoSerializer, mLoad) == 0x0C, "SPickUpInfoSerializer::mLoad offset must be 0x0C");
  static_assert(offsetof(SPickUpInfoSerializer, mSave) == 0x10, "SPickUpInfoSerializer::mSave offset must be 0x10");
  static_assert(sizeof(SPickUpInfoSerializer) == 0x14, "SPickUpInfoSerializer size must be 0x14");
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
