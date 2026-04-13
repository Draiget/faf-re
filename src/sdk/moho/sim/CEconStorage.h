#pragma once

#include <cstddef>

#include "moho/misc/CEconomyEvent.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class CEconomy;

  class CEconStorage
  {
  public:
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
