#pragma once

#include "Wm3Vector3.h"

namespace gpg
{
  class RType;
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  struct SPhysConstants
  {
    /**
     * Address: 0x00699A90 (FUN_00699A90, Moho::SPhysConstants::SPhysConstants)
     *
     * What it does:
     * Initializes gravity constants to `(0.0f, -4.9f, 0.0f)`.
     */
    SPhysConstants() noexcept;

    /**
     * Address: 0x00699C10 (FUN_00699C10, Moho::SPhysConstantsSerializer::Deserialize)
     *
     * What it does:
     * Loads the reflected `mGravity` vector.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x00699C50 (FUN_00699C50, Moho::SPhysConstantsSerializer::Serialize)
     *
     * What it does:
     * Saves the reflected `mGravity` vector.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    static gpg::RType* sType;

    Wm3::Vec3f mGravity;
  };

  static_assert(sizeof(SPhysConstants) == 0x0C, "SPhysConstants size must be 0x0C");
} // namespace moho
