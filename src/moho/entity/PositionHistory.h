#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/render/camera/VTransform.h"

namespace gpg
{
  class RType;
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  /**
   * The rolling 25-tick transform ring an entity keeps once
   * `Entity::InitPositionHistory` (0x00678800) allocates it; `Entity::
   * AdvanceCoords` (0x00678F10) records into it and `Entity::GetPositionHistory`
   * (0x006794F0) reads it back. Reflected as `PositionHistory`
   * (`PositionHistoryTypeInfo::Init`, 0x00676FA0).
   *
   * The default constructor is implicit: MSVC emits it inline as the
   * `eh vector constructor iterator` over `VTransform::VTransform`
   * (0x006770F0) plus `cursor = 0` (0x00678800, 0x0067DEE0, 0x0067E020), and
   * the copy constructor as the vector copy iterator over `VTransform`'s copy
   * constructor (0x004FFE40 with 0x0046FC90).
   */
  struct PositionHistory
  {
    static constexpr std::int32_t kSampleCount = 25;

    inline static gpg::RType* sType = nullptr;

    VTransform samples[kSampleCount];
    std::int32_t cursor = 0;

    /**
     * Address: 0x0067EE60 (FUN_0067EE60, Moho::PositionHistory::MemberDeserialize)
     *
     * What it does:
     * Deserializes 25 sampled transforms and the active cursor index.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x0067EED0 (FUN_0067EED0, Moho::PositionHistory::MemberSerialize)
     *
     * What it does:
     * Serializes 25 sampled transforms and the active cursor index.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;
  };

  static_assert(offsetof(PositionHistory, samples) == 0x00, "PositionHistory::samples offset must be 0x00");
  static_assert(offsetof(PositionHistory, cursor) == 0x2BC, "PositionHistory::cursor offset must be 0x2BC");
  static_assert(sizeof(PositionHistory) == 0x2C0, "PositionHistory size must be 0x2C0");
} // namespace moho
