#include "moho/unit/ECommandEventTypeInfo.h"

#include <cstdlib>
#include <typeinfo>

#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/StaticTypeInfoStorage.h"

namespace
{
  gpg::StaticTypeInfoStorage<moho::ECommandEventTypeInfo> gECommandEventTypeInfoStorage{};

  /**
   * Address: 0x00BFEB40 (FUN_00BFEB40, sub_BFEB40)
   *
   * What it does:
   * Tears down the recovered `ECommandEvent` enum descriptor at process exit.
   */
  void cleanup_ECommandEventTypeInfo()
  {
    gECommandEventTypeInfoStorage.Destroy();
  }

  /**
   * Address: 0x00BD8EF0 (FUN_00BD8EF0, dynamic initializer for the global
   * `PrimitiveSerHelper<ECommandEvent,int>` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields (vtable slot 0 `Init()` dispatched later by
   * `gpg::SerHelperBase::InitNewHelpers`). This is an independent `__xc_a`
   * static initializer, separate from `ECommandEventTypeInfo`'s own
   * initializer below -- the prior recovery wrongly coupled both into one
   * shared bootstrap struct.
   */
  moho::ECommandEventPrimitiveSerializer gECommandEventPrimitiveSerializer;
} // namespace

namespace moho
{
  ECommandEventTypeInfo::ECommandEventTypeInfo()
    : gpg::REnumType()
  {
    gpg::PreRegisterRType(typeid(ECommandEvent), this);
  }

  /**
   * Address: 0x006E7DF0 (FUN_006E7DF0, vtable-slot-2 scalar deleting
   * destructor: tail-calls `gpg::REnumType::~REnumType(this)` then
   * conditionally frees the object -- ordinary C++ `delete` semantics, not
   * modeled as a separate function here)
   */
  ECommandEventTypeInfo::~ECommandEventTypeInfo() = default;

  const char* ECommandEventTypeInfo::GetName() const
  {
    return "ECommandEvent";
  }

  void ECommandEventTypeInfo::Init()
  {
    size_ = sizeof(ECommandEvent);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BD8ED0 (FUN_00BD8ED0, sub_BD8ED0)
   *
   * What it does:
   * Ensures `ECommandEvent` type-info is registered and schedules teardown.
   */
  int register_ECommandEventTypeInfo()
  {
    (void)gECommandEventTypeInfoStorage.Ensure();
    return std::atexit(&cleanup_ECommandEventTypeInfo);
  }
} // namespace moho

// Phase-1 pre-registration: run this descriptor registration ahead of every
// consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_ECommandEventTypeInfo_a42648, moho::register_ECommandEventTypeInfo)
