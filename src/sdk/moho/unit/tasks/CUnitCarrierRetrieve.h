#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/sim/ArmyUnitSet.h"
#include "moho/task/CCommandTask.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
}

namespace moho
{
  /**
   * Task lane used by carrier transport retrieval command flow.
   */
  class CUnitCarrierRetrieve : public CCommandTask
  {
  public:
    /**
     * Address: 0x00608630 (FUN_00608630, Moho::CUnitCarrierRetrieve::MemberSerialize)
     *
     * What it does:
     * Serializes one retrieve-task payload: base `CCommandTask` state,
     * retrieval-complete flag, and tracked transport-unit set.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x006085A0 (FUN_006085A0, Moho::CUnitCarrierRetrieve::MemberDeserialize)
     *
     * What it does:
     * Deserializes one retrieve-task payload: base `CCommandTask` state,
     * retrieval-complete flag, and tracked transport-unit set.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

  public:
    bool mRetrievalComplete;             // 0x30
    std::uint8_t mPad31_37[0x07];        // 0x31
    SEntitySetTemplateUnit mTrackedUnits; // 0x38
  };

  static_assert(sizeof(CUnitCarrierRetrieve) == 0x60, "CUnitCarrierRetrieve size must be 0x60");
  static_assert(
    offsetof(CUnitCarrierRetrieve, mRetrievalComplete) == 0x30,
    "CUnitCarrierRetrieve::mRetrievalComplete offset must be 0x30"
  );
  static_assert(
    offsetof(CUnitCarrierRetrieve, mTrackedUnits) == 0x38,
    "CUnitCarrierRetrieve::mTrackedUnits offset must be 0x38"
  );
} // namespace moho
