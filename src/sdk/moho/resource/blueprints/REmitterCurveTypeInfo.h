#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class REmitterBlueprintCurveTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00515400 (FUN_00515400, Moho::REmitterBlueprintCurveTypeInfo::REmitterBlueprintCurveTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `REmitterBlueprintCurve`.
     */
    REmitterBlueprintCurveTypeInfo();

    /**
     * Address: 0x005154E0 (FUN_005154E0, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~REmitterBlueprintCurveTypeInfo() override;

    /**
     * Address: 0x005154D0 (FUN_005154D0)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00515460 (FUN_00515460)
     * Slot: 9
     *
     * What it does:
     * Sets curve type metadata, binds object lifetime callbacks, and publishes
     * `XRange`/`Keys` reflection fields.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00516EC0 (FUN_00516EC0)
     */
    static void AddBaseRObject(gpg::RType* typeInfo);

    /**
     * Address: 0x00516F20 (FUN_00516F20)
     */
    static void AddFields(gpg::RType* typeInfo);
  };

  class REmitterCurveKeyTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005155C0 (FUN_005155C0, Moho::REmitterCurveKeyTypeInfo::REmitterCurveKeyTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `REmitterCurveKey`.
     */
    REmitterCurveKeyTypeInfo();

    /**
     * Address: 0x00515680 (FUN_00515680, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~REmitterCurveKeyTypeInfo() override;

    /**
     * Address: 0x00515670 (FUN_00515670)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00515620 (FUN_00515620)
     * Slot: 9
     *
     * What it does:
     * Sets curve-key metadata, binds object lifetime callbacks, and publishes
     * `x/y/z` reflection fields.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00516FA0 (FUN_00516FA0)
     */
    static void AddBaseRObject(gpg::RType* typeInfo);

    /**
     * Address: 0x00515720 (FUN_00515720)
     */
    static void AddFields(gpg::RType* typeInfo);
  };

  /**
   * Address: 0x00BC8480 (FUN_00BC8480, register_REmitterBlueprintCurveTypeInfo)
   */
  int register_REmitterBlueprintCurveTypeInfo();

  /**
   * Address: 0x00BC84A0 (FUN_00BC84A0, register_REmitterCurveKeyTypeInfo)
   */
  int register_REmitterCurveKeyTypeInfo();

  /**
   * Address: 0x00517420 (FUN_00517420, preregister_VectorREmitterCurveKeyType)
   *
   * What it does:
   * Constructs/preregisters RTTI for `vector<REmitterCurveKey>`.
   */
  gpg::RType* preregister_VectorREmitterCurveKeyType();

  /**
   * Address: 0x00BC84E0 (FUN_00BC84E0, register_VectorREmitterCurveKeyTypeAtexit)
   *
   * What it does:
   * Registers `vector<REmitterCurveKey>` reflection and installs `atexit`
   * teardown.
   */
  int register_VectorREmitterCurveKeyTypeAtexit();

  static_assert(sizeof(REmitterBlueprintCurveTypeInfo) == 0x64, "REmitterBlueprintCurveTypeInfo size must be 0x64");
  static_assert(sizeof(REmitterCurveKeyTypeInfo) == 0x64, "REmitterCurveKeyTypeInfo size must be 0x64");
} // namespace moho

