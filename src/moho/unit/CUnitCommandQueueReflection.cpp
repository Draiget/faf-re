#include "moho/unit/CUnitCommandQueueReflection.h"

#include <typeinfo>

#include "moho/unit/Broadcaster.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  /**
   * Address: 0x00BFEEB0 (FUN_00BFEEB0, atexit destructor of the CUnitCommandQueueTypeInfo object)
   */
  [[nodiscard]] moho::CUnitCommandQueueTypeInfo* AcquireCUnitCommandQueueTypeInfo()
  {
    static moho::CUnitCommandQueueTypeInfo sInstance;
    return &sInstance;
  }

} // namespace

namespace moho
{
  /**
   * Address: 0x006EDAA0 (FUN_006EDAA0, ??0CUnitCommandQueueTypeInfo@Moho@@QAE@@Z)
   */
  CUnitCommandQueueTypeInfo::CUnitCommandQueueTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CUnitCommandQueue), this);
  }

  /**
   * Address: 0x006EDB30 (FUN_006EDB30, Moho::CUnitCommandQueueTypeInfo::dtr)
   */
  CUnitCommandQueueTypeInfo::~CUnitCommandQueueTypeInfo() = default;

  /**
   * Address: 0x006EDB20 (FUN_006EDB20, Moho::CUnitCommandQueueTypeInfo::GetName)
   */
  const char* CUnitCommandQueueTypeInfo::GetName() const
  {
    return "CUnitCommandQueue";
  }

  /**
   * Address: 0x006EDB00 (FUN_006EDB00, Moho::CUnitCommandQueueTypeInfo::Init)
   */
  void CUnitCommandQueueTypeInfo::Init()
  {
    size_ = sizeof(CUnitCommandQueue);
    gpg::RType::Init();
    AddBase_Broadcaster_EUnitCommandQueueStatus(this);
    Finish();
  }

  /**
   * Address: 0x006F8C50 (FUN_006F8C50, Moho::CUnitCommandQueueTypeInfo::AddBase_Broadcaster_EUnitCommandQueueStatus)
   */
  void CUnitCommandQueueTypeInfo::AddBase_Broadcaster_EUnitCommandQueueStatus(gpg::RType* const typeInfo)
  {
    gpg::RType* baseType = register_Broadcaster_EUnitCommandQueueStatus_RType();
    if (baseType == nullptr) {
      baseType = gpg::LookupRType(typeid(Broadcaster<EUnitCommandQueueStatus>));
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.mFlags = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00BD9280 (FUN_00BD9280, register_CUnitCommandQueueTypeInfo)
   */
  void register_CUnitCommandQueueTypeInfo()
  {
    (void)AcquireCUnitCommandQueueTypeInfo();
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CUnitCommandQueueTypeInfo_856820, moho::register_CUnitCommandQueueTypeInfo)

namespace moho
{
  /**
   * `gpg::SerConstructHelper<CUnitCommandQueue>`, vtable 0x00E2F234.
   *
   * Address: 0x00BD92D0 (FUN_00BD92D0 -- constructs the global and registers its destructor.)
   * Address: 0x00BFEF40 (FUN_00BFEF40 -- the global's destructor.)
   * Address: 0x006F84A0 (FUN_006F84A0 -- `Init`.)
   * Address: 0x006EEAA0 (FUN_006EEAA0 -- `Construct`, a forward to `MemberConstruct`.)
   * Address: 0x006F8D00 (FUN_006F8D00 -- `Delete`.)
   */
  struct CUnitCommandQueueConstruct : gpg::SerConstructHelper<CUnitCommandQueue>
  {};

  /**
   * `gpg::SerSaveConstructHelper<CUnitCommandQueue>`, vtable 0x00E2F224.
   *
   * Address: 0x00BD92A0 (FUN_00BD92A0 -- constructs the global and registers its destructor.)
   * Address: 0x00BFEF10 (FUN_00BFEF10 -- the global's destructor.)
   * Address: 0x006F8420 (FUN_006F8420 -- `Init`.)
   * Address: 0x006EE8C0 (FUN_006EE8C0 -- `SaveConstructArgs`, `MemberSaveConstructArgs` inlined.)
   */
  struct CUnitCommandQueueSaveConstruct : gpg::SerSaveConstructHelper<CUnitCommandQueue>
  {};

  /**
   * `gpg::SerSaveLoadHelper<CUnitCommandQueue>`, vtable 0x00E2F244.
   *
   * Address: 0x00BD9310 (FUN_00BD9310 -- constructs the global and registers its destructor.)
   * Address: 0x00BFEF70 (FUN_00BFEF70 -- the global's destructor.)
   * Address: 0x006F8520 (FUN_006F8520 -- `Init`.)
   * Address: 0x006EEB70 (FUN_006EEB70 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x006EEB90 (FUN_006EEB90 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct CUnitCommandQueueSerializer : gpg::SerSaveLoadHelper<CUnitCommandQueue>
  {};
} // namespace moho

namespace
{
  // Address: 0x010B7FE8 -- process-global `CUnitCommandQueueConstruct` singleton.
  moho::CUnitCommandQueueConstruct gCUnitCommandQueueConstruct;

  // Address: 0x010B85F8 -- process-global `CUnitCommandQueueSaveConstruct` singleton.
  moho::CUnitCommandQueueSaveConstruct gCUnitCommandQueueSaveConstruct;

  // Address: 0x010B7FFC -- process-global `CUnitCommandQueueSerializer` singleton.
  moho::CUnitCommandQueueSerializer gCUnitCommandQueueSerializer;
} // namespace
