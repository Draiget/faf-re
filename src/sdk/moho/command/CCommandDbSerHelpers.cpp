#include "moho/command/CCommandDbSerHelpers.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/utils/Global.h"
#include "moho/command/CCommandDb.h"
#include "moho/sim/Sim.h"

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
  gpg::RType* gSimType = nullptr;
  gpg::RType* gCommandDbType = nullptr;
  moho::CCommandDBSaveConstruct gCCommandDBSaveConstruct;
  moho::CCommandDBConstruct gCCommandDBConstruct;
  moho::CCommandDBSerializer gCCommandDBSerializer;

  template <typename TObject>
  [[nodiscard]] gpg::RType* ResolveCachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

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

  [[nodiscard]] moho::Sim* ReadSimOwner(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return nullptr;
    }

    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, gpg::RRef{});
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, ResolveCachedType<moho::Sim>(gSimType));
    return static_cast<moho::Sim*>(upcast.mObj);
  }

  [[nodiscard]] gpg::RRef MakeCCommandDbRef(moho::CCommandDb* const object) noexcept
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = object ? ResolveCachedType<moho::CCommandDb>(gCommandDbType) : nullptr;
    return ref;
  }

  gpg::SerHelperBase* cleanup_CCommandDBSaveConstruct_00BFE9A0_Impl()
  {
    return UnlinkHelperNode(gCCommandDBSaveConstruct);
  }

  gpg::SerHelperBase* cleanup_CCommandDBConstruct_00BFE9D0_Impl()
  {
    return UnlinkHelperNode(gCCommandDBConstruct);
  }

  gpg::SerHelperBase* cleanup_CCommandDBSerializer_00BFEA00_Impl()
  {
    return UnlinkHelperNode(gCCommandDBSerializer);
  }

  void DeleteConstructedCCommandDb(void* const objectPtr)
  {
    auto* const commandDb = static_cast<moho::CCommandDb*>(objectPtr);
    if (!commandDb) {
      return;
    }

    ::operator delete(commandDb);
  }

  void CleanupSaveConstructAtexit()
  {
    (void)cleanup_CCommandDBSaveConstruct_00BFE9A0_Impl();
  }

  void CleanupConstructAtexit()
  {
    (void)cleanup_CCommandDBConstruct_00BFE9D0_Impl();
  }

  void CleanupSerializerAtexit()
  {
    (void)cleanup_CCommandDBSerializer_00BFEA00_Impl();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BFE9A0 (FUN_00BFE9A0, sub_BFE9A0)
   *
   * What it does:
   * Unlinks the `CCommandDBSaveConstruct` helper node from the intrusive list.
   */
  gpg::SerHelperBase* cleanup_CCommandDBSaveConstruct()
  {
    return cleanup_CCommandDBSaveConstruct_00BFE9A0_Impl();
  }

  /**
   * Address: 0x00BFE9D0 (FUN_00BFE9D0, sub_BFE9D0)
   *
   * What it does:
   * Unlinks the `CCommandDBConstruct` helper node from the intrusive list.
   */
  gpg::SerHelperBase* cleanup_CCommandDBConstruct()
  {
    return cleanup_CCommandDBConstruct_00BFE9D0_Impl();
  }

  /**
   * Address: 0x00BFEA00 (FUN_00BFEA00, sub_BFEA00)
   *
   * What it does:
   * Unlinks the `CCommandDBSerializer` helper node from the intrusive list.
   */
  gpg::SerHelperBase* cleanup_CCommandDBSerializer()
  {
    return cleanup_CCommandDBSerializer_00BFEA00_Impl();
  }

  /**
   * Address: 0x006E1040 (FUN_006E1040, sub_6E1040)
   *
   * IDA signature:
   * void __cdecl sub_6E1040(BinaryWriteArchive *a1, Moho::Sim **a2, int a3, gpg::SerSaveConstructArgsResult *a4)
   *
   * What it does:
   * Serializes the owning `Sim` pointer for `CCommandDb` as an unowned tracked pointer.
   */
  void CCommandDBSaveConstruct::SaveConstructArgs(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const commandDb = reinterpret_cast<moho::CCommandDb*>(objectPtr);
    if (!archive || !commandDb) {
      return;
    }

    gpg::RRef ownerRef{};
    ownerRef.mObj = commandDb->sim;
    ownerRef.mType = commandDb->sim ? ResolveCachedType<moho::Sim>(gSimType) : nullptr;
    gpg::WriteRawPointer(archive, ownerRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});

    if (result) {
      result->SetUnowned(0u);
    }
  }

  /**
   * Address: 0x006E1220 (FUN_006E1220, sub_6E1220)
   *
   * IDA signature:
   * void __cdecl sub_6E1220(gpg::ReadArchive *arg0, int _34, int _38, gpg::SerConstructResult *a4)
   *
   * What it does:
   * Reads the owning `Sim` pointer, allocates `CCommandDb`, and returns it as unowned.
   */
  void CCommandDBConstruct::Construct(
    gpg::ReadArchive* const archive, const int, const int, gpg::SerConstructResult* const result
  )
  {
    moho::Sim* const ownerSim = ReadSimOwner(archive);
    moho::CCommandDb* const object = new (std::nothrow) moho::CCommandDb(ownerSim);

    if (!result) {
      return;
    }

    const gpg::RRef objectRef = MakeCCommandDbRef(object);
    result->SetUnowned(objectRef, 0u);
  }

  /**
   * Address: 0x006E12E0 (FUN_006E12E0, Moho::CCommandDBSerializer::Deserialize)
   *
   * What it does:
   * Forwards archive load into `CCommandDb::MemberDeserialize`.
   */
  void CCommandDBSerializer::Deserialize(
    gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*
  )
  {
    auto* const commandDb = reinterpret_cast<moho::CCommandDb*>(objectPtr);
    if (!archive || !commandDb) {
      return;
    }

    commandDb->MemberDeserialize(archive);
  }

  /**
   * Address: 0x006E12F0 (FUN_006E12F0, Moho::CCommandDBSerializer::Serialize)
   *
   * What it does:
   * Forwards archive save into `CCommandDb::MemberSerialize`.
   */
  void CCommandDBSerializer::Serialize(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*
  )
  {
    auto* const commandDb = reinterpret_cast<moho::CCommandDb*>(objectPtr);
    if (!archive || !commandDb) {
      return;
    }

    commandDb->MemberSerialize(archive);
  }

  /**
   * Address: 0x006E1B20 (FUN_006E1B20, Moho::CCommandDBSaveConstruct::RegisterSaveConstructArgsFunction)
   *
   * What it does:
   * Binds `CCommandDb` save-construct-args callback into the reflected RTTI slot.
   */
  void CCommandDBSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* const type = ResolveCachedType<CCommandDb>(gCommandDbType);
    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serSaveConstructArgsFunc_ == nullptr || type->serSaveConstructArgsFunc_ == mSaveConstructArgsCallback);
    type->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }

  /**
   * Address: 0x006E1BA0 (FUN_006E1BA0, Moho::CCommandDBConstruct::RegisterConstructFunction)
   *
   * What it does:
   * Binds `CCommandDb` construct/delete callbacks into the reflected RTTI slot.
   */
  void CCommandDBConstruct::RegisterConstructFunction()
  {
    gpg::RType* const type = ResolveCachedType<CCommandDb>(gCommandDbType);
    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serConstructFunc_ == nullptr || type->serConstructFunc_ == mConstructCallback);
    GPG_ASSERT(type->deleteFunc_ == nullptr || type->deleteFunc_ == mDeconstructCallback);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeconstructCallback;
  }

  /**
   * Address: 0x006E1C20 (FUN_006E1C20, Moho::CCommandDBSerializer::RegisterSerializeFunctions)
   *
   * What it does:
   * Binds `CCommandDb` load/save callbacks into the reflected RTTI slot.
   */
  void CCommandDBSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = ResolveCachedType<CCommandDb>(gCommandDbType);
    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
    type->serLoadFunc_ = mDeserialize;
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BD8C60 (FUN_00BD8C60, sub_BD8C60)
   *
   * What it does:
   * Initializes `CCommandDBSaveConstruct` helper callback slots and registers them.
   */
  void register_CCommandDBSaveConstruct()
  {
    InitializeHelperNode(gCCommandDBSaveConstruct);
    gCCommandDBSaveConstruct.mSaveConstructArgsCallback =
      reinterpret_cast<gpg::RType::save_construct_args_func_t>(&CCommandDBSaveConstruct::SaveConstructArgs);
    gCCommandDBSaveConstruct.RegisterSaveConstructArgsFunction();
    (void)std::atexit(&CleanupSaveConstructAtexit);
  }

  /**
   * Address: 0x00BD8C90 (FUN_00BD8C90, sub_BD8C90)
   *
   * What it does:
   * Initializes `CCommandDBConstruct` helper callback slots and registers them.
   */
  void register_CCommandDBConstruct()
  {
    InitializeHelperNode(gCCommandDBConstruct);
    gCCommandDBConstruct.mConstructCallback =
      reinterpret_cast<gpg::RType::construct_func_t>(&CCommandDBConstruct::Construct);
    gCCommandDBConstruct.mDeconstructCallback = &DeleteConstructedCCommandDb;
    gCCommandDBConstruct.RegisterConstructFunction();
    (void)std::atexit(&CleanupConstructAtexit);
  }

  /**
   * Address: 0x00BD8CD0 (FUN_00BD8CD0, register_CCommandDBSerializer)
   *
   * What it does:
   * Initializes `CCommandDBSerializer` helper callback slots and registers them.
   */
  void register_CCommandDBSerializer()
  {
    InitializeHelperNode(gCCommandDBSerializer);
    gCCommandDBSerializer.mDeserialize = reinterpret_cast<gpg::RType::load_func_t>(&CCommandDBSerializer::Deserialize);
    gCCommandDBSerializer.mSerialize = reinterpret_cast<gpg::RType::save_func_t>(&CCommandDBSerializer::Serialize);
    gCCommandDBSerializer.RegisterSerializeFunctions();
    (void)std::atexit(&CleanupSerializerAtexit);
  }
} // namespace moho

namespace
{
  struct CCommandDbSerHelpersBootstrap
  {
    CCommandDbSerHelpersBootstrap()
    {
      moho::register_CCommandDBSaveConstruct();
      moho::register_CCommandDBConstruct();
      moho::register_CCommandDBSerializer();
    }
  };

  CCommandDbSerHelpersBootstrap gCCommandDbSerHelpersBootstrap;
} // namespace
