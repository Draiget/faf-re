#include "moho/ai/ESiloTypeTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  /**
   * Address: 0x00BF1FD0 (FUN_00BF1FD0, atexit destructor of the ESiloTypeTypeInfo object)
   */
  [[nodiscard]] moho::ESiloTypeTypeInfo* AcquireESiloTypeTypeInfo()
  {
    static moho::ESiloTypeTypeInfo sInstance;
    return &sInstance;
  }

  // Address: 0x010AA0FC -- process-global `PrimitiveSerHelper<ESiloType,int>`
  // singleton (constructed by FUN_00BC7B50, self-registering via `__xc_a`; see
  // ESiloTypeTypeInfo.h for the real-ctor/atexit-target/dead-duplicate
  // evidence).
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
   * the helper node's unlink (`gpg::DListItem::ListUnlink`)) as its `atexit` target -- modeled by the
   * template's own real destructor, no explicit `atexit` call needed.
   *
   * The previous recovery modeled this as a hand-rolled raw-struct mimic of
   * `SerHelperBase` plus a fabricated `register_ESiloTypePrimitiveSerializer()`
   * free function eagerly invoked a second time from this file's own
   * `ESiloTypeTypeInfoBootstrap` constructor -- absent from the real ctor's
   * disassembly; removed.
   */
  gpg::PrimitiveSerHelper<moho::ESiloType, int> gESiloTypePrimitiveSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x0050A300 (FUN_0050A300, vtable-slot-2 scalar deleting
   * destructor: tail-calls `gpg::REnumType::~REnumType(this)` then
   * conditionally frees the object -- ordinary C++ `delete` semantics, not
   * modeled as a separate function here)
   */
  ESiloTypeTypeInfo::~ESiloTypeTypeInfo() = default;

  /**
   * Address: 0x0050A2F0 (FUN_0050A2F0, Moho::ESiloTypeTypeInfo::GetName)
   */
  const char* ESiloTypeTypeInfo::GetName() const
  {
    return "ESiloType";
  }

  /**
   * Address: 0x0050A2D0 (FUN_0050A2D0, Moho::ESiloTypeTypeInfo::Init)
   */
  void ESiloTypeTypeInfo::Init()
  {
    size_ = sizeof(ESiloType);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x0050A270 (FUN_0050A270, preregister_ESiloTypeTypeInfo)
   */
  gpg::REnumType* preregister_ESiloTypeTypeInfo()
  {
    ESiloTypeTypeInfo* const typeInfo = AcquireESiloTypeTypeInfo();
    gpg::PreRegisterRType(typeid(ESiloType), typeInfo);
    return typeInfo;
  }

  /**
   * Address: 0x00BC7B30 (FUN_00BC7B30, register_ESiloTypeTypeInfo)
   */
  void register_ESiloTypeTypeInfo()
  {
    (void)preregister_ESiloTypeTypeInfo();
  }
} // namespace moho

namespace
{
  struct ESiloTypeTypeInfoBootstrap
  {
    ESiloTypeTypeInfoBootstrap()
    {
      moho::register_ESiloTypeTypeInfo();
    }
  };

  [[maybe_unused]] ESiloTypeTypeInfoBootstrap gESiloTypeTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_ESiloTypeTypeInfo_9672e7, moho::register_ESiloTypeTypeInfo)

GPG_PREREGISTER_INIT(preregister_ESiloTypeTypeInfo_9672e7, moho::preregister_ESiloTypeTypeInfo)
