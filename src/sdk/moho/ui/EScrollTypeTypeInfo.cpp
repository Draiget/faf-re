#include "moho/ui/EScrollTypeTypeInfo.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
} // namespace

namespace moho
{
  /**
   * Address: 0x007771B0 (FUN_007771B0, static-init lane)
   * Address: 0x00C02640 (FUN_00C02640, atexit destructor of the EScrollTypeTypeInfo object; registered by 0x00BDD670)
   *
   * What it does:
   * Constructs the static descriptor on first call; the constructor is what
   * performs the `PreRegisterRType`, so one construction is the whole
   * registration.
   */
  gpg::REnumType* preregister_EScrollTypeTypeInfo()
  {
    static moho::EScrollTypeTypeInfo sInstance;
    return &sInstance;
  }

  /**
   * Address: 0x007771B0 (FUN_007771B0, Moho::EScrollTypeTypeInfo::ctor)
   *
   * What it does:
   * Preregisters the reflected `EScrollType` enum metadata.
   */
  EScrollTypeTypeInfo::EScrollTypeTypeInfo()
  {
    gpg::PreRegisterRType(typeid(EScrollType), this);
  }

  /**
   * Address: 0x00777240 (FUN_00777240, Moho::EScrollTypeTypeInfo::dtr)
   */
  EScrollTypeTypeInfo::~EScrollTypeTypeInfo() = default;

  /**
   * Address: 0x00777230 (FUN_00777230, Moho::EScrollTypeTypeInfo::GetName)
   */
  const char* EScrollTypeTypeInfo::GetName() const
  {
    return "EScrollType";
  }

  /**
   * Address: 0x00777210 (FUN_00777210, Moho::EScrollTypeTypeInfo::Init)
   */
  void EScrollTypeTypeInfo::Init()
  {
    size_ = sizeof(EScrollType);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x00777270 (FUN_00777270, Moho::EScrollTypeTypeInfo::AddEnums)
   */
  void EScrollTypeTypeInfo::AddEnums()
  {
    mPrefix = "SCROLLTYPE_";

    AddEnum(StripPrefix("SCROLLTYPE_None"), static_cast<std::int32_t>(SCROLLTYPE_None));
    AddEnum(StripPrefix("SCROLLTYPE_PingPong"), static_cast<std::int32_t>(SCROLLTYPE_PingPong));
    AddEnum(StripPrefix("SCROLLTYPE_Manual"), static_cast<std::int32_t>(SCROLLTYPE_Manual));
    AddEnum(StripPrefix("SCROLLTYPE_MotionDerived"), static_cast<std::int32_t>(SCROLLTYPE_MotionDerived));
  }
} // namespace moho

namespace
{
  // Address: 0x010BBB6C -- process-global `gpg::PrimitiveSerHelper<
  // Moho::EScrollType,int>` singleton (constructed by FUN_00BDD690,
  // self-registering via `__xc_a`; see EScrollTypeTypeInfo.h for the full
  // real-ctor/Init/atexit-target evidence, including why the address
  // previously cited here as a separate "real binder",
  // `InstallMohoEScrollTypeSerializerCallbacks` (0x00777E20), is actually
  // this same template's `Init()` body, not a competing mechanism).
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
   * matching the helper node's unlink (`gpg::DListItem::ListUnlink`)) as its `atexit` target --
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
   *
   * `FUN_007772D0`/`FUN_00777300` are dead, zero-xref duplicate-emission
   * twins of the real `FUN_00C02650` atexit body above
   * (function_sha256-confirmed), formerly modeled in
   * `moho/containers/LegacyContainerFillLanes.cpp` as
   * `gGlobalIntrusiveSentinelLaneBO` and its two reset thunks; removed in
   * favor of this citation.
   */
  gpg::PrimitiveSerHelper<moho::EScrollType, int> gEScrollTypePrimitiveSerializer;
} // namespace

// Phase-1 pre-registration: CTextureScroller caches the reflected EScrollType
// through gpg::LookupRType, so the descriptor must exist before that consumer
// runs. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_EScrollTypeTypeInfo_7771b0, moho::preregister_EScrollTypeTypeInfo)
