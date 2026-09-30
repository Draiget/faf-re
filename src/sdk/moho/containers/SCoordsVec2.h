#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  struct SCoordsVec2
  {
    static gpg::RType* sType;

    /**
     * What it does:
     * Reads `x`, `z`. Inlined into `gpg::SerSaveLoadHelper<SCoordsVec2>::Deserialize` 0x0050BD10.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * What it does:
     * Writes `x`, `z`. Inlined into `gpg::SerSaveLoadHelper<SCoordsVec2>::Serialize` 0x0050BD40.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    float x;
    float z;
  };

  /**
   * Owns reflected metadata for `SCoordsVec2`.
   */
  class SCoordsVec2TypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0050BBD0 (FUN_0050BBD0, Moho::SCoordsVec2TypeInfo::SCoordsVec2TypeInfo)
     *
     * What it does:
     * Preregisters the `SCoordsVec2` RTTI descriptor with the reflection map.
     */
    SCoordsVec2TypeInfo();

    /**
     * What it does:
     * Releases the reflected field and base vector storage. Its deleting
     * destructor (vtable slot 2) is one of the `gpg::RType` teardown COMDAT
     * clones cited on `gpg::RType::~RType`.
     */
    ~SCoordsVec2TypeInfo() override;

    /**
     * Address: 0x0050BC50 (FUN_0050BC50, Moho::SCoordsVec2TypeInfo::GetName)
     *
     * What it does:
     * Returns the reflected type label for `SCoordsVec2`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0050BC30 (FUN_0050BC30, Moho::SCoordsVec2TypeInfo::Init)
     *
     * What it does:
     * Sets the reflected size and finalizes the type.
     */
    void Init() override;
  };

  static_assert(sizeof(SCoordsVec2TypeInfo) == 0x64, "SCoordsVec2TypeInfo size must be 0x64");
  static_assert(sizeof(SCoordsVec2) == 0x08, "SCoordsVec2 size must be 0x08");
  static_assert(offsetof(SCoordsVec2, x) == 0x00, "SCoordsVec2::x offset must be 0x00");
  static_assert(offsetof(SCoordsVec2, z) == 0x04, "SCoordsVec2::z offset must be 0x04");

  /**
   * Address: 0x00BC7CC0 (FUN_00BC7CC0, register_SCoordsVec2TypeInfo)
   *
   * What it does:
   * Constructs the static `SCoordsVec2TypeInfo` instance.
   */
  void register_SCoordsVec2TypeInfo();
} // namespace moho
