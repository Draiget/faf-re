#pragma once

#include <cstddef>
#include <cstdint>

namespace gpg
{
  class RType;
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  struct REntityBlueprint;

  struct SSTIEntityConstantData
  {
    /**
     * Address: 0x00559990 (FUN_00559990, Moho::SSTIEntityConstantData::MemberDeserialize)
     *
     * What it does:
     * Deserializes entity id, unowned entity-blueprint pointer, and creation tick.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x00559A00 (FUN_00559A00, Moho::SSTIEntityConstantData::MemberSerialize)
     *
     * What it does:
     * Serializes entity id, unowned entity-blueprint pointer, and creation tick.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    std::int32_t mEntityId; // +0x00
    REntityBlueprint* mBlueprint; // +0x04
    std::uint32_t mTickCreated; // +0x08
  };

  static_assert(offsetof(SSTIEntityConstantData, mEntityId) == 0x00, "SSTIEntityConstantData::mEntityId offset must be 0x00");
  static_assert(offsetof(SSTIEntityConstantData, mBlueprint) == 0x04, "SSTIEntityConstantData::mBlueprint offset must be 0x04");
  static_assert(offsetof(SSTIEntityConstantData, mTickCreated) == 0x08, "SSTIEntityConstantData::mTickCreated offset must be 0x08");
  static_assert(sizeof(SSTIEntityConstantData) == 0x0C, "SSTIEntityConstantData size must be 0x0C");

  /**
   * Address: 0x00557FC0 (FUN_00557FC0, preregister_SSTIEntityConstantDataTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SSTIEntityConstantData`.
   */
  [[nodiscard]] gpg::RType* preregister_SSTIEntityConstantDataTypeInfo();
} // namespace moho
