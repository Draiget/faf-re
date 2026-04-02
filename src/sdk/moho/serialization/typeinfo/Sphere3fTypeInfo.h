#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "wm3/Sphere3.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E038CC
   * COL: 0x00E601AC
   */
  class Sphere3fTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00472EB0 (FUN_00472EB0, Moho::Sphere3fTypeInfo::Sphere3fTypeInfo)
     *
     * What it does:
     * Constructs and preregisters reflection metadata for `Wm3::Sphere3<float>`.
     */
    Sphere3fTypeInfo();

    /**
     * Address: 0x00472F40 (FUN_00472F40, Moho::Sphere3fTypeInfo::~Sphere3fTypeInfo)
     *
     * What it does:
     * Releases dynamic field/base reflection metadata storage.
     */
    ~Sphere3fTypeInfo() override;

    /**
     * Address: 0x00472F30 (FUN_00472F30, Moho::Sphere3fTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflection type name string for Sphere3f.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00472F10 (FUN_00472F10, Moho::Sphere3fTypeInfo::Init)
     *
     * What it does:
     * Sets runtime reflection size and finalizes base `RType` initialization.
     */
    void Init() override;
  };

  static_assert(sizeof(Sphere3fTypeInfo) == 0x64, "Sphere3fTypeInfo size must be 0x64");

  /**
   * Address: 0x00BC4950 (FUN_00BC4950, register_Sphere3fTypeInfo)
   *
   * What it does:
   * Constructs startup-owned Sphere3f type metadata and installs process-exit
   * teardown.
   */
  int register_Sphere3fTypeInfo();
} // namespace moho
