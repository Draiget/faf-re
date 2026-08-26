#include "moho/unit/CUnitCommandQueueReflection.h"

#include <cstdlib>
#include <typeinfo>

#include "moho/unit/Broadcaster.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };

  class SerSaveConstructArgsResult
  {
  public:
    void SetUnowned(unsigned int value);
  };
} // namespace gpg

namespace
{
  moho::CUnitCommandQueueTypeInfo gCUnitCommandQueueTypeInfo;

  // Address: 0x00BD92A0 -- dynamic initializer for the global
  // CUnitCommandQueueSaveConstruct singleton (base-ctor -> field-set ->
  // vtable-install -> atexit, no eager RegisterSaveConstructArgsFunction()
  // dispatch, confirmed via raw asm).
  moho::CUnitCommandQueueSaveConstruct gCUnitCommandQueueSaveConstruct;

  // Address: 0x00BD92D0 -- dynamic initializer for the global
  // CUnitCommandQueueConstruct singleton, same shape, independent __xc_a
  // static initializer.
  moho::CUnitCommandQueueConstruct gCUnitCommandQueueConstruct;

  // Address: 0x00BD9310 -- dynamic initializer for the global
  // CUnitCommandQueueSerializer singleton, same shape, independent __xc_a
  // static initializer.
  moho::CUnitCommandQueueSerializer gCUnitCommandQueueSerializer;

  template <class TTypeInfo>
  void ResetTypeInfoVectors(TTypeInfo& typeInfo) noexcept
  {
    typeInfo.fields_ = msvc8::vector<gpg::RField>{};
    typeInfo.bases_ = msvc8::vector<gpg::RField>{};
  }

  /**
   * Address: 0x00BFEEB0 (FUN_00BFEEB0, sub_BFEEB0)
   *
   * What it does:
   * Releases CUnitCommandQueue type-info field/base storage lanes.
   */
  void cleanup_CUnitCommandQueueTypeInfo()
  {
    ResetTypeInfoVectors(gCUnitCommandQueueTypeInfo);
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
      baseType = gpg::LookupRType(typeid(Broadcaster));
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00BD92A0 (FUN_00BD92A0, register_CUnitCommandQueueSaveConstruct)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * save-construct-args callback field.
   */
  CUnitCommandQueueSaveConstruct::CUnitCommandQueueSaveConstruct()
    : mSaveConstructArgsCallback(
        reinterpret_cast<gpg::RType::save_construct_args_func_t>(&CUnitCommandQueueSaveConstruct::SaveConstructArgs)
      )
  {}

  /**
   * Address: 0x00BFEF10 (FUN_00BFEF10, sub_BFEF10)
   *
   * `FUN_006EE910` and `FUN_006EE940` are duplicate-emission twins of this
   * exact unlink/reset lane (same `ResetLinks()` shape, folded to separate
   * addresses); they have no distinct source-level body of their own.
   */
  CUnitCommandQueueSaveConstruct::~CUnitCommandQueueSaveConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x006EE9C0 (FUN_006EE9C0, save-construct callback thunk)
   */
  void CUnitCommandQueueSaveConstruct::SaveConstructArgs(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const queue = reinterpret_cast<CUnitCommandQueue*>(objectPtr);
    if (archive == nullptr || queue == nullptr || result == nullptr) {
      return;
    }

    queue->MemberSaveConstructArgs(*archive, version, gpg::RRef{}, *result);
  }

  /**
   * Address: 0x006F8420 (FUN_006F8420, Moho::CUnitCommandQueueSaveConstruct::RegisterSaveConstructArgsFunction)
   */
  void CUnitCommandQueueSaveConstruct::Init()
  {
    gpg::RType* type = CUnitCommandQueue::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(CUnitCommandQueue));
      CUnitCommandQueue::sType = type;
    }

    GPG_ASSERT(type->serSaveConstructArgsFunc_ == nullptr);
    type->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }

  /**
   * Address: 0x00BD92D0 (FUN_00BD92D0, register_CUnitCommandQueueConstruct)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * construct/delete callback fields.
   */
  CUnitCommandQueueConstruct::CUnitCommandQueueConstruct()
    : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&CUnitCommandQueueConstruct::Construct))
    , mDeconstructCallback(&CUnitCommandQueueConstruct::Deconstruct)
  {}

  /**
   * Address: 0x00BFEF40 (FUN_00BFEF40, Moho::CUnitCommandQueueConstruct::~CUnitCommandQueueConstruct)
   */
  CUnitCommandQueueConstruct::~CUnitCommandQueueConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x006EEAA0 (FUN_006EEAA0, Moho::CUnitCommandQueueConstruct::Construct)
   */
  void CUnitCommandQueueConstruct::Construct(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::SerConstructResult* const result
  )
  {
    if (archive == nullptr || result == nullptr) {
      return;
    }

    CUnitCommandQueue::MemberConstruct(*archive, version, gpg::RRef{}, *result);
    (void)objectPtr;
  }

  /**
   * Address: 0x006F8D00 (FUN_006F8D00, Moho::CUnitCommandQueueConstruct::Deconstruct)
   */
  void CUnitCommandQueueConstruct::Deconstruct(void* const objectPtr)
  {
    auto* const queue = static_cast<CUnitCommandQueue*>(objectPtr);
    if (queue == nullptr) {
      return;
    }

    queue->~CUnitCommandQueue();
    ::operator delete(queue);
  }

  /**
   * Address: 0x006F84A0 (FUN_006F84A0, Moho::CUnitCommandQueueConstruct::RegisterConstructFunction)
   */
  void CUnitCommandQueueConstruct::Init()
  {
    gpg::RType* type = CUnitCommandQueue::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(CUnitCommandQueue));
      CUnitCommandQueue::sType = type;
    }

    GPG_ASSERT(type->serConstructFunc_ == nullptr);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeconstructCallback;
  }

  /**
   * Address: 0x00BD9310 (FUN_00BD9310, register_CUnitCommandQueueSerializer)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  CUnitCommandQueueSerializer::CUnitCommandQueueSerializer()
    : mDeserialize(reinterpret_cast<gpg::RType::load_func_t>(&CUnitCommandQueueSerializer::Deserialize))
    , mSerialize(reinterpret_cast<gpg::RType::save_func_t>(&CUnitCommandQueueSerializer::Serialize))
  {}

  /**
   * Address: 0x00BFEF70 (FUN_00BFEF70, sub_BFEF70)
   */
  CUnitCommandQueueSerializer::~CUnitCommandQueueSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x006EEB70 (FUN_006EEB70, Moho::CUnitCommandQueueSerializer::Deserialize)
   */
  void CUnitCommandQueueSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    auto* const queue = reinterpret_cast<CUnitCommandQueue*>(objectPtr);
    if (archive == nullptr || queue == nullptr) {
      return;
    }

    queue->MemberDeserialize(*archive);
  }

  /**
   * Address: 0x006EEB90 (FUN_006EEB90, Moho::CUnitCommandQueueSerializer::Serialize)
   */
  void CUnitCommandQueueSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    auto* const queue = reinterpret_cast<CUnitCommandQueue*>(objectPtr);
    if (archive == nullptr || queue == nullptr) {
      return;
    }

    queue->MemberSerialize(*archive);
  }

  /**
   * Address: 0x006F8520 (FUN_006F8520, gpg::SerSaveLoadHelper<Moho::CUnitCommandQueue>::Init)
   *
   * What it does:
   * Binds `CUnitCommandQueue` load/save callbacks onto its reflected type
   * metadata; asserts neither slot is already claimed before installing them.
   */
  void CUnitCommandQueueSerializer::Init()
  {
    gpg::RType* const type = CUnitCommandQueue::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BD9280 (FUN_00BD9280, register_CUnitCommandQueueTypeInfo)
   */
  void register_CUnitCommandQueueTypeInfo()
  {
    (void)gCUnitCommandQueueTypeInfo;
    (void)std::atexit(&cleanup_CUnitCommandQueueTypeInfo);
  }
} // namespace moho


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CUnitCommandQueueTypeInfo_856820, moho::register_CUnitCommandQueueTypeInfo)
