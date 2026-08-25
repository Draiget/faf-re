#include "moho/unit/UnitMotionEnumTypeInfo.h"

#include <cstdlib>
#include <typeinfo>

#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/StaticTypeInfoStorage.h"
#include "moho/ai/EAirCombatState.h"
#include "moho/ai/EAirCombatStateTypeInfo.h"
#include "moho/unit/CUnitMotion.h"

namespace
{
  /**
   * `gpg::PrimitiveSerHelper<T,int>` aliases for the five `EUnitMotion*`
   * enums. Kept file-local (not exposed in UnitMotionEnumTypeInfo.h) since
   * `EUnitMotionVertEvent` is declared in CUnitMotion.h rather than the
   * shared EUnitMotionEnums.h, and this .cpp already includes CUnitMotion.h
   * for CUnitMotion::MemberDeserialize/MemberSerialize elsewhere in the
   * translation unit -- pulling that header into UnitMotionEnumTypeInfo.h
   * just for one alias would add unwanted weight to every includer. Matches
   * the original file's own architecture, where the hand-rolled
   * EnumPrimitiveSerializer<TEnum> template mimic was likewise anonymous-
   * namespace-local, never declared in the header.
   */
  using EUnitMotionStatePrimitiveSerializer = gpg::PrimitiveSerHelper<moho::EUnitMotionState, int>;
  using EUnitMotionCarrierEventPrimitiveSerializer = gpg::PrimitiveSerHelper<moho::EUnitMotionCarrierEvent, int>;
  using EUnitMotionHorzEventPrimitiveSerializer = gpg::PrimitiveSerHelper<moho::EUnitMotionHorzEvent, int>;
  using EUnitMotionVertEventPrimitiveSerializer = gpg::PrimitiveSerHelper<moho::EUnitMotionVertEvent, int>;
  using EUnitMotionTurnEventPrimitiveSerializer = gpg::PrimitiveSerHelper<moho::EUnitMotionTurnEvent, int>;

  gpg::StaticTypeInfoStorage<moho::EUnitMotionStateTypeInfo> gEUnitMotionStateTypeInfoStorage{};
  gpg::StaticTypeInfoStorage<moho::EUnitMotionCarrierEventTypeInfo> gEUnitMotionCarrierEventTypeInfoStorage{};
  gpg::StaticTypeInfoStorage<moho::EUnitMotionHorzEventTypeInfo> gEUnitMotionHorzEventTypeInfoStorage{};
  gpg::StaticTypeInfoStorage<moho::EUnitMotionVertEventTypeInfo> gEUnitMotionVertEventTypeInfoStorage{};
  gpg::StaticTypeInfoStorage<moho::EUnitMotionTurnEventTypeInfo> gEUnitMotionTurnEventTypeInfoStorage{};
  gpg::StaticTypeInfoStorage<moho::EAirCombatStateTypeInfo> gEAirCombatStateTypeInfoStorage{};

  /**
   * Address: 0x00BFDE90 (FUN_00BFDE90)
   */
  void cleanup_EUnitMotionStateTypeInfo()
  {
    gEUnitMotionStateTypeInfoStorage.Destroy();
  }

  /**
   * Address: 0x00BFDED0 (FUN_00BFDED0)
   */
  void cleanup_EUnitMotionCarrierEventTypeInfo()
  {
    gEUnitMotionCarrierEventTypeInfoStorage.Destroy();
  }

  /**
   * Address: 0x00BFDF10 (FUN_00BFDF10)
   */
  void cleanup_EUnitMotionHorzEventTypeInfo()
  {
    gEUnitMotionHorzEventTypeInfoStorage.Destroy();
  }

  /**
   * Address: 0x00BFDF50 (FUN_00BFDF50)
   */
  void cleanup_EUnitMotionVertEventTypeInfo()
  {
    gEUnitMotionVertEventTypeInfoStorage.Destroy();
  }

  /**
   * Address: 0x00BFDF90 (FUN_00BFDF90)
   */
  void cleanup_EUnitMotionTurnEventTypeInfo()
  {
    gEUnitMotionTurnEventTypeInfoStorage.Destroy();
  }

  /**
   * Address: 0x00BFDFD0 (FUN_00BFDFD0)
   */
  void cleanup_EAirCombatStateTypeInfo()
  {
    gEAirCombatStateTypeInfoStorage.Destroy();
  }

  /**
   * Per-instantiation `gpg::PrimitiveSerHelper<T,int>` dynamic-initializer
   * addresses (one compiler-emitted ctor per enum; no dead low-address
   * duplicate found for any of the six):
   *   - T=Moho::EUnitMotionState: 0x00BD7000 (Init 0x006BA420)
   *   - T=Moho::EUnitMotionCarrierEvent: 0x00BD7060 (Init 0x006BA4C0)
   *   - T=Moho::EUnitMotionHorzEvent: 0x00BD70C0 (Init 0x006BA560)
   *   - T=Moho::EUnitMotionVertEvent: 0x00BD7120 (Init 0x006BA600)
   *   - T=Moho::EUnitMotionTurnEvent: 0x00BD7180 (Init 0x006BA6A0)
   *   - T=Moho::EAirCombatState: 0x00BD71E0 (Init 0x006BA740)
   * All six Init() bodies were previously mis-homed in
   * ArchiveSerialization.cpp as a generic
   * InstallSerSaveLoadHelperCallbacksByTypeName dispatch (same mis-citation
   * family already caught this session for several other classes); the
   * real bodies cache on this template's own `sCachedType` static, matching
   * `gpg::PrimitiveSerHelper<T,int>::Init()` exactly. Real destructors
   * (0x00BFDEA0/0x00BFDEE0/0x00BFDF20/0x00BFDF60/0x00BFDFA0/0x00BFDFE0) are
   * now implicit via the template's declared destructor -- no explicit
   * register_/cleanup_ pair is needed.
   */
  EUnitMotionStatePrimitiveSerializer gEUnitMotionStatePrimitiveSerializer;
  EUnitMotionCarrierEventPrimitiveSerializer gEUnitMotionCarrierEventPrimitiveSerializer;
  EUnitMotionHorzEventPrimitiveSerializer gEUnitMotionHorzEventPrimitiveSerializer;
  EUnitMotionVertEventPrimitiveSerializer gEUnitMotionVertEventPrimitiveSerializer;
  EUnitMotionTurnEventPrimitiveSerializer gEUnitMotionTurnEventPrimitiveSerializer;
  moho::EAirCombatStatePrimitiveSerializer gEAirCombatStatePrimitiveSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x006B7110 (FUN_006B7110, scalar deleting thunk)
   */
  EUnitMotionStateTypeInfo::~EUnitMotionStateTypeInfo() = default;

  /**
   * Address: 0x006B7100 (FUN_006B7100)
   */
  const char* EUnitMotionStateTypeInfo::GetName() const
  {
    return "EUnitMotionState";
  }

  /**
   * Address: 0x006B70E0 (FUN_006B70E0)
   */
  void EUnitMotionStateTypeInfo::Init()
  {
    size_ = sizeof(EUnitMotionState);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x006B7240 (FUN_006B7240, scalar deleting thunk)
   */
  EUnitMotionCarrierEventTypeInfo::~EUnitMotionCarrierEventTypeInfo() = default;

  /**
   * Address: 0x006B7230 (FUN_006B7230)
   */
  const char* EUnitMotionCarrierEventTypeInfo::GetName() const
  {
    return "EUnitMotionCarrierEvent";
  }

  /**
   * Address: 0x006B7210 (FUN_006B7210)
   */
  void EUnitMotionCarrierEventTypeInfo::Init()
  {
    size_ = sizeof(EUnitMotionCarrierEvent);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x006B7370 (FUN_006B7370, scalar deleting thunk)
   */
  EUnitMotionHorzEventTypeInfo::~EUnitMotionHorzEventTypeInfo() = default;

  /**
   * Address: 0x006B7360 (FUN_006B7360)
   */
  const char* EUnitMotionHorzEventTypeInfo::GetName() const
  {
    return "EUnitMotionHorzEvent";
  }

  /**
   * Address: 0x006B7340 (FUN_006B7340)
   */
  void EUnitMotionHorzEventTypeInfo::Init()
  {
    size_ = sizeof(EUnitMotionHorzEvent);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x006B74A0 (FUN_006B74A0, scalar deleting thunk)
   */
  EUnitMotionVertEventTypeInfo::~EUnitMotionVertEventTypeInfo() = default;

  /**
   * Address: 0x006B7490 (FUN_006B7490)
   */
  const char* EUnitMotionVertEventTypeInfo::GetName() const
  {
    return "EUnitMotionVertEvent";
  }

  /**
   * Address: 0x006B7470 (FUN_006B7470)
   */
  void EUnitMotionVertEventTypeInfo::Init()
  {
    size_ = sizeof(EUnitMotionVertEvent);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x006B75D0 (FUN_006B75D0, scalar deleting thunk)
   */
  EUnitMotionTurnEventTypeInfo::~EUnitMotionTurnEventTypeInfo() = default;

  /**
   * Address: 0x006B75C0 (FUN_006B75C0)
   */
  const char* EUnitMotionTurnEventTypeInfo::GetName() const
  {
    return "EUnitMotionTurnEvent";
  }

  /**
   * Address: 0x006B75A0 (FUN_006B75A0)
   */
  void EUnitMotionTurnEventTypeInfo::Init()
  {
    size_ = sizeof(EUnitMotionTurnEvent);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x006B7080 (FUN_006B7080, construct_EUnitMotionStateTypeInfo)
   */
  gpg::REnumType* construct_EUnitMotionStateTypeInfo()
  {
    return &gEUnitMotionStateTypeInfoStorage.Ensure();
  }

  /**
   * Address: 0x006B71B0 (FUN_006B71B0, construct_EUnitMotionCarrierEventTypeInfo)
   */
  gpg::REnumType* construct_EUnitMotionCarrierEventTypeInfo()
  {
    return &gEUnitMotionCarrierEventTypeInfoStorage.Ensure();
  }

  /**
   * Address: 0x006B72E0 (FUN_006B72E0, construct_EUnitMotionHorzEventTypeInfo)
   */
  gpg::REnumType* construct_EUnitMotionHorzEventTypeInfo()
  {
    return &gEUnitMotionHorzEventTypeInfoStorage.Ensure();
  }

  /**
   * Address: 0x006B7410 (FUN_006B7410, construct_EUnitMotionVertEventTypeInfo)
   */
  gpg::REnumType* construct_EUnitMotionVertEventTypeInfo()
  {
    return &gEUnitMotionVertEventTypeInfoStorage.Ensure();
  }

  /**
   * Address: 0x006B7540 (FUN_006B7540, construct_EUnitMotionTurnEventTypeInfo)
   */
  gpg::REnumType* construct_EUnitMotionTurnEventTypeInfo()
  {
    return &gEUnitMotionTurnEventTypeInfoStorage.Ensure();
  }

  /**
   * Address: 0x006B7670 (FUN_006B7670, construct_EAirCombatStateTypeInfo)
   */
  gpg::REnumType* construct_EAirCombatStateTypeInfo()
  {
    return &gEAirCombatStateTypeInfoStorage.Ensure();
  }

  /**
   * Address: 0x00BD6FE0 (FUN_00BD6FE0, register_EUnitMotionStateTypeInfo)
   */
  int register_EUnitMotionStateTypeInfo()
  {
    (void)construct_EUnitMotionStateTypeInfo();
    return std::atexit(&cleanup_EUnitMotionStateTypeInfo);
  }

  /**
   * Address: 0x00BD7040 (FUN_00BD7040, register_EUnitMotionCarrierEventTypeInfo)
   */
  int register_EUnitMotionCarrierEventTypeInfo()
  {
    (void)construct_EUnitMotionCarrierEventTypeInfo();
    return std::atexit(&cleanup_EUnitMotionCarrierEventTypeInfo);
  }

  /**
   * Address: 0x00BD70A0 (FUN_00BD70A0, register_EUnitMotionHorzEventTypeInfo)
   */
  int register_EUnitMotionHorzEventTypeInfo()
  {
    (void)construct_EUnitMotionHorzEventTypeInfo();
    return std::atexit(&cleanup_EUnitMotionHorzEventTypeInfo);
  }

  /**
   * Address: 0x00BD7100 (FUN_00BD7100, register_EUnitMotionVertEventTypeInfo)
   */
  int register_EUnitMotionVertEventTypeInfo()
  {
    (void)construct_EUnitMotionVertEventTypeInfo();
    return std::atexit(&cleanup_EUnitMotionVertEventTypeInfo);
  }

  /**
   * Address: 0x00BD7160 (FUN_00BD7160, register_EUnitMotionTurnEventTypeInfo)
   */
  int register_EUnitMotionTurnEventTypeInfo()
  {
    (void)construct_EUnitMotionTurnEventTypeInfo();
    return std::atexit(&cleanup_EUnitMotionTurnEventTypeInfo);
  }

  /**
   * Address: 0x00BD71C0 (FUN_00BD71C0, register_EAirCombatStateTypeInfo)
   */
  int register_EAirCombatStateTypeInfo()
  {
    (void)construct_EAirCombatStateTypeInfo();
    return std::atexit(&cleanup_EAirCombatStateTypeInfo);
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EUnitMotionStateTypeInfo_ddfe48, moho::register_EUnitMotionStateTypeInfo)
GPG_PREREGISTER_INIT(register_EUnitMotionCarrierEventTypeInfo_ddfe48, moho::register_EUnitMotionCarrierEventTypeInfo)
GPG_PREREGISTER_INIT(register_EUnitMotionHorzEventTypeInfo_ddfe48, moho::register_EUnitMotionHorzEventTypeInfo)
GPG_PREREGISTER_INIT(register_EUnitMotionVertEventTypeInfo_ddfe48, moho::register_EUnitMotionVertEventTypeInfo)
GPG_PREREGISTER_INIT(register_EUnitMotionTurnEventTypeInfo_ddfe48, moho::register_EUnitMotionTurnEventTypeInfo)
GPG_PREREGISTER_INIT(register_EAirCombatStateTypeInfo_ddfe48, moho::register_EAirCombatStateTypeInfo)
