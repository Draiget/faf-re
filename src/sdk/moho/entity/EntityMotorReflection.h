#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/entity/EntityMotor.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  class MotorTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00694800 (FUN_00694800, Moho::MotorTypeInfo::MotorTypeInfo)
     *
     * What it does:
     * Constructs and preregisters RTTI metadata for `moho::Motor`.
     */
    MotorTypeInfo();

    /**
     * Address: 0x00BFCF00 (FUN_00BFCF00, Moho::MotorTypeInfo::~MotorTypeInfo)
     *
     * What it does:
     * Releases reflected base/field vectors for `moho::Motor` type info.
     */
    ~MotorTypeInfo() override;

    /**
     * Address: 0x00694880 (FUN_00694880, Moho::MotorTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflection name literal for `moho::Motor`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00694860 (FUN_00694860, Moho::MotorTypeInfo::Init)
     *
     * What it does:
     * Sets reflected size metadata and finalizes the `moho::Motor` type.
     */
    void Init() override;
  };

  static_assert(sizeof(MotorTypeInfo) == 0x64, "MotorTypeInfo size must be 0x64");

  /**
   * VFTABLE: 0x00E28F64
   *
   * Demangled: gpg::SerSaveLoadHelper<class Moho::Motor>
   *
   * Per-instantiation addresses (one compiler-emitted body per `T`; see the
   * template's class-level comment in Reflection.h for the general shape):
   *  - ctor / compiler dynamic-initializer (`register_MotorSerializer`):
   *    0x00BD5930 (__xc_a-reachable; dead zero-xref COMDAT duplicate:
   *    0x006949F0)
   *  - dtor: 0x00BFCF60 (no recovered mangled name; body confirmed via raw
   *    asm to just call `ResetLinks()`, same as every other instantiation's
   *    real destructor)
   *  - Init(): 0x00694A20
   *  - Deserialize(): 0x00694940
   *  - Serialize(): 0x00694950
   */
  using MotorSerializer = gpg::SerSaveLoadHelper<EntityMotor>;

  /**
   * Address: 0x00BD5910 (FUN_00BD5910, register_MotorTypeInfo)
   *
   * What it does:
   * Initializes global `MotorTypeInfo` storage and schedules exit cleanup.
   */
  void register_MotorTypeInfo();

  /**
   * Address: 0x00BD5930 (FUN_00BD5930, register_MotorSerializer)
   *
   * What it does:
   * Forces this translation unit's global `MotorSerializer` instance to link
   * into the reflection bootstrap sequence. The ctor/vtable-install/
   * atexit-dtor-registration sequence this address decompiles to is MSVC's
   * own compiler-generated dynamic initializer for that global, not
   * hand-written source -- see `gpg::SerSaveLoadHelper<T>` in Reflection.h.
   */
  void register_MotorSerializer();
} // namespace moho


