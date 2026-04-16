#pragma once
#include <cstddef>
#include <cstdint>

#include "moho/ai/EAiTargetType.h"
#include "Wm3Vector3.h"

namespace gpg
{
  class RType;
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  struct SSTITarget
  {
    /**
     * Address: 0x0055B3A0 (FUN_0055B3A0, Moho::SSTITarget::MemberDeserialize)
     *
     * What it does:
     * Reads target-kind enum, then conditionally deserializes either entity-id
     * payload or ground-position payload.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x0055B460 (FUN_0055B460, Moho::SSTITarget::MemberSerialize)
     *
     * What it does:
     * Writes target-kind enum, then conditionally serializes either entity-id
     * payload or ground-position payload.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    EAiTargetType mType; // +0x00
    union
    {
      std::uint32_t mEntityId; // +0x04 (serialized raw id for AITARGET_Entity)
      std::uint32_t mEnt;      // legacy alias used by recovered callsites
    };
    Wm3::Vec3f mPos; // +0x08
  };

  static_assert(offsetof(SSTITarget, mType) == 0x00, "SSTITarget::mType offset must be 0x00");
  static_assert(offsetof(SSTITarget, mEntityId) == 0x04, "SSTITarget::mEntityId offset must be 0x04");
  static_assert(offsetof(SSTITarget, mPos) == 0x08, "SSTITarget::mPos offset must be 0x08");
  static_assert(sizeof(SSTITarget) == 0x14, "SSTITarget size must be 0x14");

  /**
   * Address: 0x00557DB0 (FUN_00557DB0, preregister_EntIdTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `EntId`.
   */
  [[nodiscard]] gpg::RType* preregister_EntIdTypeInfo();

  /**
   * Address: 0x0055AFE0 (FUN_0055AFE0, preregister_SSTITargetTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SSTITarget`.
   */
  [[nodiscard]] gpg::RType* preregister_SSTITargetTypeInfo();
} // namespace moho
