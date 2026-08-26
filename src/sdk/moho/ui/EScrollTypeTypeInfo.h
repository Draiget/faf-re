#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  enum EScrollType : std::int32_t
  {
    SCROLLTYPE_None = 0,
    SCROLLTYPE_PingPong = 1,
    SCROLLTYPE_Manual = 2,
    SCROLLTYPE_MotionDerived = 3,
  };

  static_assert(sizeof(EScrollType) == 0x4, "EScrollType size must be 0x4");

  class EScrollTypeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x007771B0 (FUN_007771B0, Moho::EScrollTypeTypeInfo::ctor)
     *
     * What it does:
     * Preregisters the reflected `EScrollType` enum metadata.
     */
    EScrollTypeTypeInfo();

    /**
     * Address: 0x00777240 (FUN_00777240, Moho::EScrollTypeTypeInfo::dtr)
     */
    ~EScrollTypeTypeInfo() override;

    /**
     * Address: 0x00777230 (FUN_00777230, Moho::EScrollTypeTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00777210 (FUN_00777210, Moho::EScrollTypeTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x00777270 (FUN_00777270, Moho::EScrollTypeTypeInfo::AddEnums)
     */
    void AddEnums();
  };

  static_assert(sizeof(EScrollTypeTypeInfo) == 0x78, "EScrollTypeTypeInfo size must be 0x78");

  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::EScrollType,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EScrollType@Moho@@H@gpg'`):
   * `FUN_00BDD690` (real, `__xc_a`-reachable at depth 0, sole writer to
   * global storage 0x010BBB6C -- no dead duplicate ctor found). Confirmed
   * via raw asm: default-constructs `gpg::SerHelperBase`, binds
   * `mLoadCallback`/`mSaveCallback` to `FUN_00777FF0`/`FUN_00778010`,
   * installs the `PrimitiveSerHelper<EScrollType,int>` vtable, and pushes
   * plain unmangled `FUN_00C02650` (bare unlink-then-self-link shape,
   * matching `SerHelperBase::ResetLinks()`) as its `atexit` target --
   * modeled by the template's own real destructor, no explicit `atexit`
   * call needed.
   *
   * `FUN_00777FF0`/`FUN_00778010` decompile byte-identically to this
   * template's own generic `Deserialize`/`Serialize` (archive->ReadInt /
   * WriteInt through vtable slot 9 / offset 0x24 on a plain `int` lane), so
   * this instantiation needs no per-type override -- the template alone
   * reproduces the binary.
   *
   * `FUN_00777E20` -- previously cited in `ArchiveSerialization.cpp` as
   * `InstallMohoEScrollTypeSerializerCallbacks`, modeled there as a generic
   * `InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::EScrollType")`
   * by-name dispatch -- is actually this template's own `Init()` body
   * (confirmed via raw asm: thiscall on the helper, reads `this+0x0C`/
   * `this+0x10`, writes the looked-up `EScrollType` RType's
   * `serLoadFunc_`/`serSaveFunc_`, same shared-body pattern documented on
   * `PrimitiveSerHelper` above for ESTITargetType/EResourceType). It is a
   * vtable-slot-0 target shared by both the real `PrimitiveSerHelper<
   * EScrollType,int>` vtable and the dead, zero-writer `SerSaveLoadHelper<
   * EScrollType>` sibling vtable, same pattern as ESquadClass/EThreatType.
   * The `ArchiveSerialization.cpp` free function wrapped around that address
   * has zero source-level callers in `src/sdk/**` (2026-08-26
   * ArchiveSerialization dead-duplicate audit) and is left untouched, out of
   * scope for this pass -- it does not compete with this instantiation, it
   * is simply an orphaned, mis-shaped model of the same underlying `Init()`.
   *
   * The previous recovery here modeled the whole mechanism as a hand-rolled
   * `EScrollTypePrimitiveSerializerHelper` raw-struct mimic (a bare
   * `void* mVtable` + `moho::TDatListItem` pair, deliberately not deriving
   * `gpg::SerHelperBase`) plus file-local `DeserializeEScrollTypeSerializerCallback`/
   * `SerializeEScrollTypeSerializerCallback` bodies, reasoning that the
   * ArchiveSerialization.cpp free function above was the real binder and a
   * second `Init()`-based binder here would double-register. That free
   * function has zero real callers (see above) -- it never ran. This
   * self-registering template instantiation is the actual, live wiring.
   */
  using EScrollTypePrimitiveSerializer = gpg::PrimitiveSerHelper<EScrollType, int>;

  /**
   * Address: 0x007771B0 (FUN_007771B0, static-init lane)
   *
   * IDA signature:
   * gpg::REnumType *sub_7771B0();
   *
   * What it does:
   * Constructs the static `EScrollTypeTypeInfo` descriptor (`stru_10BBC78` in
   * the binary) in place and returns it; construction preregisters
   * `EScrollType` with the reflection registry. Called from the CRT
   * static-initializer array via FUN_00BDD670.
   */
  [[nodiscard]] gpg::REnumType* preregister_EScrollTypeTypeInfo();
} // namespace moho
