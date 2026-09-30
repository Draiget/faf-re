#include "moho/ai/ESiloBuildStageTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x00BF7E00 (FUN_00BF7E00, atexit destructor of the ESiloBuildStageTypeInfo object)
   */
  [[nodiscard]] ESiloBuildStageTypeInfo* AcquireESiloBuildStageTypeInfo()
  {
    static ESiloBuildStageTypeInfo sInstance;
    return &sInstance;
  }

  /**
   * Address: 0x005CE9F0 (FUN_005CE9F0, sub_5CE9F0)
   *
   * What it does:
   * Constructs and preregisters the static `ESiloBuildStageTypeInfo` instance.
   */
  [[nodiscard]] gpg::REnumType* preregister_ESiloBuildStageTypeInfo()
  {
    ESiloBuildStageTypeInfo* const typeInfo = AcquireESiloBuildStageTypeInfo();
    gpg::PreRegisterRType(typeid(ESiloBuildStage), typeInfo);
    return typeInfo;
  }

  // Address: 0x010AFBBC -- process-global `PrimitiveSerHelper<ESiloBuildStage,int>`
  // singleton (constructed by FUN_00BCE050, self-registering via `__xc_a`; see
  // ESiloBuildStageTypeInfo.h for the real-ctor/atexit-target evidence).
  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::ESiloBuildStage,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4ESiloBuildStage@Moho@@H@gpg'`):
   * `FUN_00BCE050` (real, `__xc_a`-reachable, sole writer -- no dead
   * duplicate ctor found). Confirmed via raw asm: default-constructs
   * `gpg::SerHelperBase`, binds `mLoadCallback`/`mSaveCallback` to
   * `FUN_005CFFB0`/`FUN_005CFFD0`, installs the
   * `PrimitiveSerHelper<ESiloBuildStage,int>` vtable, and pushes plain
   * unmangled `FUN_00BF7E10` (bare unlink-then-self-link shape, matching
   * the helper node's unlink (`gpg::DListItem::ListUnlink`)) as its `atexit` target -- modeled by the
   * template's own real destructor, no explicit `atexit` call needed.
   *
   * The previous recovery modeled this as a hand-rolled raw-struct mimic of
   * `SerHelperBase` plus a fabricated `register_ESiloBuildStagePrimitiveSerializer()`
   * free function eagerly invoked a second time from this file's own
   * `ESiloBuildStageReflectionBootstrap` constructor -- absent from the
   * real ctor's disassembly; removed.
   */
  gpg::PrimitiveSerHelper<moho::ESiloBuildStage, int> gESiloBuildStagePrimitiveSerializer;
} // namespace

/**
 * Address: 0x005CEA80 (FUN_005CEA80, scalar deleting thunk)
 */
ESiloBuildStageTypeInfo::~ESiloBuildStageTypeInfo() = default;

/**
 * Address: 0x005CEA70 (FUN_005CEA70, ?GetName@ESiloBuildStageTypeInfo@Moho@@UBEPBDXZ)
 */
const char* ESiloBuildStageTypeInfo::GetName() const
{
  return "ESiloBuildStage";
}

/**
 * Address: 0x005CEA50 (FUN_005CEA50, ?Init@ESiloBuildStageTypeInfo@Moho@@UAEXXZ)
 */
void ESiloBuildStageTypeInfo::Init()
{
  size_ = sizeof(ESiloBuildStage);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BCE030 (FUN_00BCE030, register_ESiloBuildStageTypeInfo)
 *
 * What it does:
 * Registers `ESiloBuildStage` enum type-info.
 */
void moho::register_ESiloBuildStageTypeInfo()
{
  (void)preregister_ESiloBuildStageTypeInfo();
}

namespace
{
  struct ESiloBuildStageReflectionBootstrap
  {
    ESiloBuildStageReflectionBootstrap()
    {
      moho::register_ESiloBuildStageTypeInfo();
    }
  };

  [[maybe_unused]] ESiloBuildStageReflectionBootstrap gESiloBuildStageReflectionBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_ESiloBuildStageTypeInfo_ea41ff, moho::register_ESiloBuildStageTypeInfo)

GPG_PREREGISTER_INIT(AcquireESiloBuildStageTypeInfo_ea41ff, AcquireESiloBuildStageTypeInfo)
