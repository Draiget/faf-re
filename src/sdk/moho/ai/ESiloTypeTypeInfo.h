#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/IAiSiloBuild.h"

namespace moho
{
  class ESiloTypeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x00BF1FD0 (FUN_00BF1FD0, Moho::ESiloTypeTypeInfo::dtr)
     */
    ~ESiloTypeTypeInfo() override;

    /**
     * Address: 0x0050A2F0 (FUN_0050A2F0, Moho::ESiloTypeTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0050A2D0 (FUN_0050A2D0, Moho::ESiloTypeTypeInfo::Init)
     */
    void Init() override;
  };

  static_assert(sizeof(ESiloTypeTypeInfo) == 0x78, "ESiloTypeTypeInfo size must be 0x78");

  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::ESiloType,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4ESiloType@Moho@@H@gpg'`):
   * `FUN_00BC7B50` (real, `__xc_a`-reachable) vs. a dead zero-xref duplicate
   * at `FUN_0050A7E0` (same fields, no `atexit` call -- confirmed via raw
   * asm never live). A third writer for the same global's storage address,
   * `FUN_0050AAB0` (demangled `gpg::SerSaveLoadHelper<Moho::ESiloType>`), is
   * itself zero-xref/unreachable too -- same "dead sibling-writer" pattern
   * already documented for `EAlliance`/`ELayer`/`EVisibilityMode`/
   * `ESquadClass`/`EThreatType` on the `PrimitiveSerHelper` template itself
   * (see `Reflection.h`); already corrected to `skip` in the progress DB by
   * an earlier pass this session. There is no real
   * `SerSaveLoadHelper<ESiloType>` instance in this binary.
   *
   * Confirmed via raw asm: the real ctor default-constructs
   * `gpg::SerHelperBase`, binds `mDeserialize`/`mSerialize` to
   * `FUN_0050AA70`/`FUN_0050AA90`, installs the
   * `PrimitiveSerHelper<ESiloType,int>` vtable, and pushes plain unmangled
   * `FUN_00BF1FE0` (bare unlink-then-self-link shape, matching
   * `SerHelperBase::ResetLinks()`) as its `atexit` target -- modeled by the
   * template's own real destructor, no explicit `atexit` call needed.
   *
   * The previous recovery modeled this as a hand-rolled raw-struct mimic of
   * `SerHelperBase` plus a fabricated `register_ESiloTypePrimitiveSerializer()`
   * free function eagerly invoked a second time from this file's own
   * `ESiloTypeTypeInfoBootstrap` constructor -- absent from the real ctor's
   * disassembly; removed.
   */
  using ESiloTypePrimitiveSerializer = gpg::PrimitiveSerHelper<ESiloType, int>;

  /**
   * Address: 0x0050A270 (FUN_0050A270, preregister_ESiloTypeTypeInfo)
   *
   * What it does:
   * Constructs/preregisters startup-owned RTTI descriptor storage for
   * `ESiloType`.
   */
  [[nodiscard]] gpg::REnumType* preregister_ESiloTypeTypeInfo();

  /**
   * Address: 0x00BC7B30 (FUN_00BC7B30, register_ESiloTypeTypeInfo)
   *
   * What it does:
   * Runs `ESiloType` typeinfo preregistration and installs process-exit
   * cleanup.
   */
  int register_ESiloTypeTypeInfo();
} // namespace moho
