#include "moho/unit/CUnitCommandSerHelpers.h"

#include <cstdlib>

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

namespace
{
  moho::CUnitCommandConstruct gCUnitCommandConstruct;
  moho::CUnitCommandSerializer gCUnitCommandSerializer;

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
  }

  template <typename THelper>
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

  void CleanupCUnitCommandConstructAtexit()
  {
    (void)moho::cleanup_CUnitCommandConstruct();
  }

  void CleanupCUnitCommandSerializerAtexit()
  {
    (void)moho::cleanup_CUnitCommandSerializer();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BFEBE0 (FUN_00BFEBE0, Moho::CUnitCommandConstruct::~CUnitCommandConstruct)
   *
   * What it does:
   * Unlinks the construct helper from the intrusive helper list.
   */
  gpg::SerHelperBase* cleanup_CUnitCommandConstruct()
  {
    return UnlinkHelperNode(gCUnitCommandConstruct);
  }

  /**
   * Address: 0x00BFEC10 (FUN_00BFEC10, Moho::CUnitCommandSerializer::~CUnitCommandSerializer)
   *
   * What it does:
   * Unlinks the serializer helper from the intrusive helper list.
   */
  gpg::SerHelperBase* cleanup_CUnitCommandSerializer()
  {
    return UnlinkHelperNode(gCUnitCommandSerializer);
  }

  /**
   * Address: 0x006E91B0 (FUN_006E91B0, Moho::CUnitCommandConstruct::Construct)
   *
   * What it does:
   * Forwards construct callback flow to `CUnitCommand::MemberConstruct`.
   */
  void CUnitCommandConstruct::Construct(
    gpg::ReadArchive* const,
    const int,
    const int,
    gpg::SerConstructResult* const result
  )
  {
    if (result == nullptr) {
      return;
    }

    CUnitCommand::MemberConstruct(result);
  }

  /**
   * Address: 0x006EB710 (FUN_006EB710, Moho::CUnitCommandConstruct::Deconstruct)
   *
   * What it does:
   * Runs deleting-dtor teardown for one `CUnitCommand`.
   */
  void CUnitCommandConstruct::Deconstruct(void* const objectPtr)
  {
    auto* const command = static_cast<CUnitCommand*>(objectPtr);
    if (command == nullptr) {
      return;
    }

    delete command;
  }

  /**
   * Address: 0x006E9250 (FUN_006E9250, Moho::CUnitCommandSerializer::Deserialize)
   *
   * What it does:
   * Loads the serialized `CUnitCommand` payload lanes.
   */
  void CUnitCommandSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef*
  )
  {
    auto* const command = reinterpret_cast<CUnitCommand*>(objectPtr);
    if (archive == nullptr || command == nullptr) {
      return;
    }

    CUnitCommand::MemberDeserialize(archive, command, version);
  }

  /**
   * Address: 0x006E9270 (FUN_006E9270, Moho::CUnitCommandSerializer::Serialize)
   *
   * What it does:
   * Saves the serialized `CUnitCommand` payload lanes.
   */
  void CUnitCommandSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef*
  )
  {
    auto* const command = reinterpret_cast<CUnitCommand*>(objectPtr);
    if (archive == nullptr || command == nullptr) {
      return;
    }

    CUnitCommand::MemberSerialize(command, archive, version);
  }

  /**
   * Address: 0x00BD8F50 (FUN_00BD8F50, register_CUnitCommandConstruct)
   *
   * What it does:
   * Binds `CUnitCommand` construct/delete callbacks into RTTI and schedules
   * helper cleanup at process exit.
   */
  void CUnitCommandConstruct::RegisterConstructFunction()
  {
    gpg::RType* const type = CUnitCommand::StaticGetClass();
    GPG_ASSERT(type->serConstructFunc_ == nullptr || type->serConstructFunc_ == mConstructCallback);
    GPG_ASSERT(type->deleteFunc_ == nullptr || type->deleteFunc_ == mDeconstructCallback);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeconstructCallback;
  }

  /**
   * Address: 0x00BD8F90 (FUN_00BD8F90, register_CUnitCommandSerializer)
   *
   * What it does:
   * Binds `CUnitCommand` load/save callbacks into RTTI and schedules helper
   * cleanup at process exit.
   */
  void CUnitCommandSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CUnitCommand::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
    type->serLoadFunc_ = mDeserialize;
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BD8F50 (FUN_00BD8F50, register_CUnitCommandConstruct)
   *
   * What it does:
   * Initializes and registers the `CUnitCommand` construct helper.
   */
  void register_CUnitCommandConstruct()
  {
    InitializeHelperNode(gCUnitCommandConstruct);
    gCUnitCommandConstruct.mConstructCallback =
      reinterpret_cast<gpg::RType::construct_func_t>(&CUnitCommandConstruct::Construct);
    gCUnitCommandConstruct.mDeconstructCallback = &CUnitCommandConstruct::Deconstruct;
    gCUnitCommandConstruct.RegisterConstructFunction();
    (void)std::atexit(&CleanupCUnitCommandConstructAtexit);
  }

  /**
   * Address: 0x00BD8F90 (FUN_00BD8F90, register_CUnitCommandSerializer)
   *
   * What it does:
   * Initializes and registers the `CUnitCommand` serializer helper.
   */
  void register_CUnitCommandSerializer()
  {
    InitializeHelperNode(gCUnitCommandSerializer);
    gCUnitCommandSerializer.mDeserialize = reinterpret_cast<gpg::RType::load_func_t>(&CUnitCommandSerializer::Deserialize);
    gCUnitCommandSerializer.mSerialize = reinterpret_cast<gpg::RType::save_func_t>(&CUnitCommandSerializer::Serialize);
    gCUnitCommandSerializer.RegisterSerializeFunctions();
    (void)std::atexit(&CleanupCUnitCommandSerializerAtexit);
  }
} // namespace moho

namespace
{
  struct CUnitCommandSerHelpersBootstrap
  {
    CUnitCommandSerHelpersBootstrap()
    {
      moho::register_CUnitCommandConstruct();
      moho::register_CUnitCommandSerializer();
    }
  };

  CUnitCommandSerHelpersBootstrap gCUnitCommandSerHelpersBootstrap;
} // namespace
