#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/containers/SCoordsVec2.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  /**
   * 12-byte structure holding a coordinate position plus a mass value.
   * Serialized as: SCoordsVec2 (position) + float (mVal).
   */
  struct SMassInfo
  {
    SCoordsVec2 mPosition{}; // +0x00 (8 bytes)
    float mVal = 0.0f;       // +0x08

    /**
     * Address: 0x00593030 (FUN_00593030, Moho::SMassInfo::MemberDeserialize)
     *
     * What it does:
     * Reads the SCoordsVec2 position and float value from archive.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x00593080 (FUN_00593080, Moho::SMassInfo::MemberSerialize)
     *
     * What it does:
     * Writes the SCoordsVec2 position and float value to archive.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;
  };

  static_assert(sizeof(SMassInfo) == 0x0C, "SMassInfo size must be 0x0C");
  static_assert(offsetof(SMassInfo, mPosition) == 0x00, "SMassInfo::mPosition offset must be 0x00");
  static_assert(offsetof(SMassInfo, mVal) == 0x08, "SMassInfo::mVal offset must be 0x08");
} // namespace moho
