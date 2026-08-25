#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1F18C
   * COL:  0x00E76CC0
   */
  class EAiTransportEventTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x005E3D10 (FUN_005E3D10, Moho::EAiTransportEventTypeInfo::EAiTransportEventTypeInfo)
     *
     * What it does:
     * Preregisters `EAiTransportEvent` enum metadata with the reflection runtime.
     */
    EAiTransportEventTypeInfo();

    /**
     * Address: 0x005E3DA0 (FUN_005E3DA0, scalar deleting thunk)
     */
    ~EAiTransportEventTypeInfo() override;

    /**
     * Address: 0x005E3D90 (FUN_005E3D90)
     *
     * What it does:
     * Returns the reflection type name literal for EAiTransportEvent.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005E3D70 (FUN_005E3D70)
     *
     * What it does:
     * Writes enum width, registers enum values, then finalizes metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x005E3DD0 (FUN_005E3DD0)
     *
     * What it does:
     * Registers EAiTransportEvent enum option names/values.
     */
    void AddEnums();
  };

  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::EAiTransportEvent,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EAiTransportEvent@Moho@@H@gpg'`):
   * `FUN_00BCED30` (real, `__xc_a`-reachable). Confirmed via raw asm:
   * default-constructs `gpg::SerHelperBase`, binds `mLoadCallback`/
   * `mSaveCallback` to `FUN_005E9DD0`/`FUN_005E9DF0`, installs the
   * `PrimitiveSerHelper<EAiTransportEvent,int>` vtable, and pushes plain
   * unmangled `FUN_00BF8970` (bare unlink-then-self-link shape, matching
   * `SerHelperBase::ResetLinks()`) as its `atexit` target -- modeled by the
   * template's own real destructor, no explicit `atexit` call needed.
   *
   * Unlike the other AI enum serializers in this cluster, this global has
   * TWO dead zero-caller/zero-xref duplicate ctors sharing its storage
   * address (both write the same fields, neither calls `atexit`, so
   * neither is ever live): `FUN_005E8B60` and `FUN_005E9E10`. The previous
   * recovery wrongly modeled `FUN_005E9E10` as a helper function CALLED BY
   * `register_EAiTransportEventPrimitiveSerializer()` -- the real ctor's
   * disassembly sets its fields inline and calls no such helper. Both dead
   * duplicates marked `skip`.
   *
   * The previous recovery also modeled this as a hand-rolled raw-struct
   * mimic of `SerHelperBase` plus a fabricated
   * `register_EAiTransportEventPrimitiveSerializer()` free function eagerly
   * invoked a second time from `IAiTransport.cpp`'s
   * `IAiTransportReflectionBootstrap` constructor -- absent from the real
   * ctor's disassembly; removed from both files.
   */
  using EAiTransportEventPrimitiveSerializer = gpg::PrimitiveSerHelper<EAiTransportEvent, int>;

  /**
   * Address: 0x00BCED10 (FUN_00BCED10, register_EAiTransportEventTypeInfo)
   *
   * What it does:
   * Registers `EAiTransportEvent` enum type-info and installs process-exit
   * cleanup.
   */
  int register_EAiTransportEventTypeInfo();

  static_assert(sizeof(EAiTransportEventTypeInfo) == 0x78, "EAiTransportEventTypeInfo size must be 0x78");
} // namespace moho
