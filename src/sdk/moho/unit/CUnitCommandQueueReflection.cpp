#include "moho/unit/CUnitCommandQueueReflection.h"

#include <cstdlib>
#include <typeinfo>

#include "moho/unit/Broadcaster.h"
#include "moho/unit/CUnitCommandQueue.h"

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
  moho::CUnitCommandQueueSaveConstruct gCUnitCommandQueueSaveConstruct;
  moho::CUnitCommandQueueConstruct gCUnitCommandQueueConstruct;
  moho::CUnitCommandQueueSerializer gCUnitCommandQueueSerializer;

  template <class THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  template <class THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
  }

  template <class THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    if (helper.mHelperNext != nullptr && helper.mHelperPrev != nullptr) {
      helper.mHelperNext->mPrev = helper.mHelperPrev;
      helper.mHelperPrev->mNext = helper.mHelperNext;
    }

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperPrev = self;
    helper.mHelperNext = self;
    return self;
  }

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

  /**
   * Address: 0x00BFEF10 (FUN_00BFEF10, sub_BFEF10)
   *
   * What it does:
   * Unlinks the CUnitCommandQueue save-construct helper node.
   */
  gpg::SerHelperBase* cleanup_CUnitCommandQueueSaveConstruct()
  {
    return UnlinkHelperNode(gCUnitCommandQueueSaveConstruct);
  }

  /**
   * Address: 0x00BFEF40 (FUN_00BFEF40, Moho::CUnitCommandQueueConstruct::~CUnitCommandQueueConstruct)
   *
   * What it does:
   * Unlinks the CUnitCommandQueue construct helper node.
   */
  gpg::SerHelperBase* cleanup_CUnitCommandQueueConstruct()
  {
    return UnlinkHelperNode(gCUnitCommandQueueConstruct);
  }

  /**
   * Address: 0x00BFEF70 (FUN_00BFEF70, sub_BFEF70)
   *
   * What it does:
   * Unlinks the CUnitCommandQueue serializer helper node.
   */
  gpg::SerHelperBase* cleanup_CUnitCommandQueueSerializer()
  {
    return UnlinkHelperNode(gCUnitCommandQueueSerializer);
  }

  void CleanupSaveConstructAtexit()
  {
    (void)cleanup_CUnitCommandQueueSaveConstruct();
  }

  void CleanupConstructAtexit()
  {
    (void)cleanup_CUnitCommandQueueConstruct();
  }

  void CleanupSerializerAtexit()
  {
    (void)cleanup_CUnitCommandQueueSerializer();
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
   * Address: 0x006EDBD0 (FUN_006EDBD0)
   *
   * What it does:
   * Wrapper lane that forwards one base-registration dispatch to
   * `AddBase_Broadcaster_EUnitCommandQueueStatus`.
   */
  void CUnitCommandQueueTypeInfo::AddBase_Broadcaster_EUnitCommandQueueStatusAdapter(gpg::RType* const typeInfo)
  {
    AddBase_Broadcaster_EUnitCommandQueueStatus(typeInfo);
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
  void CUnitCommandQueueSaveConstruct::RegisterSaveConstructArgsFunction()
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
  void CUnitCommandQueueConstruct::RegisterConstructFunction()
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
   * Address: 0x006EEBE0 (FUN_006EEBE0, helper Init)
   */
  void CUnitCommandQueueSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CUnitCommandQueue::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
    type->serLoadFunc_ = mDeserialize;
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

  /**
   * Address: 0x00BD92A0 (FUN_00BD92A0, sub_BD92A0)
   */
  void register_CUnitCommandQueueSaveConstruct()
  {
    InitializeHelperNode(gCUnitCommandQueueSaveConstruct);
    gCUnitCommandQueueSaveConstruct.mSaveConstructArgsCallback =
      reinterpret_cast<gpg::RType::save_construct_args_func_t>(&CUnitCommandQueueSaveConstruct::SaveConstructArgs);
    gCUnitCommandQueueSaveConstruct.RegisterSaveConstructArgsFunction();
    (void)std::atexit(&CleanupSaveConstructAtexit);
  }

  /**
   * Address: 0x00BD92D0 (FUN_00BD92D0, register_CUnitCommandQueueConstruct)
   */
  void register_CUnitCommandQueueConstruct()
  {
    InitializeHelperNode(gCUnitCommandQueueConstruct);
    gCUnitCommandQueueConstruct.mConstructCallback =
      reinterpret_cast<gpg::RType::construct_func_t>(&CUnitCommandQueueConstruct::Construct);
    gCUnitCommandQueueConstruct.mDeconstructCallback = &CUnitCommandQueueConstruct::Deconstruct;
    gCUnitCommandQueueConstruct.RegisterConstructFunction();
    (void)std::atexit(&CleanupConstructAtexit);
  }

  /**
   * Address: 0x00BD9310 (FUN_00BD9310, register_CUnitCommandQueueSerializer)
   */
  void register_CUnitCommandQueueSerializer()
  {
    InitializeHelperNode(gCUnitCommandQueueSerializer);
    gCUnitCommandQueueSerializer.mDeserialize = reinterpret_cast<gpg::RType::load_func_t>(&CUnitCommandQueueSerializer::Deserialize);
    gCUnitCommandQueueSerializer.mSerialize = reinterpret_cast<gpg::RType::save_func_t>(&CUnitCommandQueueSerializer::Serialize);
    (void)std::atexit(&CleanupSerializerAtexit);
  }

  /**
   * Address: 0x006EEA70 (FUN_006EEA70)
   *
   * What it does:
   * Duplicated teardown lane that unlinks `CUnitCommandQueueConstruct` helper
   * links and self-links the node.
   */
  gpg::SerHelperBase* cleanup_CUnitCommandQueueConstruct_variant()
  {
    return cleanup_CUnitCommandQueueConstruct();
  }

  /**
   * Address: 0x006EEC10 (FUN_006EEC10)
   *
   * What it does:
   * Duplicated teardown lane that unlinks `CUnitCommandQueueSerializer` helper
   * links and self-links the node.
   */
  gpg::SerHelperBase* cleanup_CUnitCommandQueueSerializer_variant()
  {
    return cleanup_CUnitCommandQueueSerializer();
  }
} // namespace moho

namespace
{
  struct CUnitCommandQueueReflectionBootstrap
  {
    CUnitCommandQueueReflectionBootstrap()
    {
      moho::register_CUnitCommandQueueTypeInfo();
      moho::register_CUnitCommandQueueSaveConstruct();
      moho::register_CUnitCommandQueueConstruct();
      moho::register_CUnitCommandQueueSerializer();
    }
  };

  CUnitCommandQueueReflectionBootstrap gCUnitCommandQueueReflectionBootstrap;
} // namespace
