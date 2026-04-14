#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/misc/CEconomyEvent.h"

namespace gpg
{
  class ReadArchive;
  struct RRef;
  class SerConstructResult;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class CEconomy;

  class CEconStorage
  {
  public:
    /**
     * Address: 0x00773500 (FUN_00773500, Moho::CEconStorage::MemberConstruct)
     *
     * What it does:
     * Allocates one `CEconStorage`, zero-initializes owner/value lanes, and
     * publishes the object as an unowned construct result.
     */
    static void MemberConstruct(gpg::ReadArchive& archive, int version, const gpg::RRef& ownerRef, gpg::SerConstructResult& result);

    /**
     * Address: 0x007732C0 (FUN_007732C0, Moho::CEconStorage::Chng)
     *
     * What it does:
     * Applies this storage lane as a signed delta (`direction` is typically
     * `+1` or `-1`) into owning economy max-storage counters.
     */
    std::int64_t Chng(std::int32_t direction);

    /**
     * Address: 0x00774990 (FUN_00774990, Moho::CEconStorage::MemberDeserialize)
     *
     * What it does:
     * Deserializes referenced economy owner pointer, then reads one reflected
     * `SEconValue` payload lane.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x007749F0 (FUN_007749F0, Moho::CEconStorage::MemberSerialize)
     *
     * What it does:
     * Serializes referenced economy owner as an unowned pointer, then writes
     * one reflected `SEconValue` payload lane.
     */
    void MemberSerialize(gpg::WriteArchive* archive);

  public:
    CEconomy* mEconomy; // +0x00
    SEconValue mAmt;    // +0x04
  };

  static_assert(offsetof(CEconStorage, mEconomy) == 0x00, "CEconStorage::mEconomy offset must be 0x00");
  static_assert(offsetof(CEconStorage, mAmt) == 0x04, "CEconStorage::mAmt offset must be 0x04");
  static_assert(sizeof(CEconStorage) == 0x0C, "CEconStorage size must be 0x0C");
} // namespace moho
