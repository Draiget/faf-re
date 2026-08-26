#include "moho/command/CCommandDbSerHelpers.h"

#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/reflection/Reflection.h"
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

  template <typename TObject>
  [[nodiscard]] gpg::RType* ResolveCachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
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

  /**
   * Address: 0x006E2A90 (FUN_006E2A90, Moho::CommandDatabase::operator delete)
   *
   * What it does:
   * Destroys and frees a heap-allocated `CCommandDb` reached only through a
   * type-erased `void*`. Matches the binary's null-checked
   * destructor-then-global-`operator delete` sequence exactly; the prior
   * recovery of this callback freed the raw storage without ever calling
   * the destructor, leaking every `CCommandDb`'s owned map/id-pool state.
   */
  void DeleteConstructedCCommandDb(void* const objectPtr)
  {
    delete static_cast<moho::CCommandDb*>(objectPtr);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BD8C60 (FUN_00BD8C60, dynamic initializer for the global
   * `CCommandDBSaveConstruct` singleton)
   */
  CCommandDBSaveConstruct::CCommandDBSaveConstruct()
    : mSaveConstructArgsCallback(
        reinterpret_cast<gpg::RType::save_construct_args_func_t>(&CCommandDBSaveConstruct::SaveConstructArgs)
      )
  {}

  /**
   * Address: 0x00BFE9A0 (FUN_00BFE9A0, plain unlink thunk pushed as this
   * class's atexit target)
   *
   * `FUN_006E1090` and `FUN_006E10C0` are duplicate-emission twins of this
   * exact unlink/reset lane (same `ResetLinks()` shape, folded to separate
   * addresses); they have no distinct source-level body of their own.
   */
  CCommandDBSaveConstruct::~CCommandDBSaveConstruct()
  {
    ResetLinks();
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
   * Address: 0x006E1B20 (FUN_006E1B20, Moho::CCommandDBSaveConstruct::RegisterSaveConstructArgsFunction)
   *
   * What it does:
   * Binds `CCommandDb` save-construct-args callback into the reflected RTTI slot.
   */
  void CCommandDBSaveConstruct::Init()
  {
    gpg::RType* const type = ResolveCachedType<CCommandDb>(gCommandDbType);
    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serSaveConstructArgsFunc_ == nullptr || type->serSaveConstructArgsFunc_ == mSaveConstructArgsCallback);
    type->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }

  /**
   * Address: 0x00BD8C90 (FUN_00BD8C90, dynamic initializer for the global
   * `CCommandDBConstruct` singleton)
   */
  CCommandDBConstruct::CCommandDBConstruct()
    : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&CCommandDBConstruct::Construct))
    , mDeconstructCallback(&DeleteConstructedCCommandDb)
  {}

  /**
   * Address: 0x00BFE9D0 (FUN_00BFE9D0, plain unlink thunk pushed as this
   * class's atexit target)
   *
   * `FUN_006E11C0` and `FUN_006E11F0` are duplicate-emission twins of this
   * exact unlink/reset lane (same `ResetLinks()` shape, folded to separate
   * addresses); they have no distinct source-level body of their own.
   */
  CCommandDBConstruct::~CCommandDBConstruct()
  {
    ResetLinks();
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
   * Address: 0x006E1BA0 (FUN_006E1BA0, Moho::CCommandDBConstruct::RegisterConstructFunction)
   *
   * What it does:
   * Binds `CCommandDb` construct/delete callbacks into the reflected RTTI slot.
   */
  void CCommandDBConstruct::Init()
  {
    gpg::RType* const type = ResolveCachedType<CCommandDb>(gCommandDbType);
    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serConstructFunc_ == nullptr || type->serConstructFunc_ == mConstructCallback);
    GPG_ASSERT(type->deleteFunc_ == nullptr || type->deleteFunc_ == mDeconstructCallback);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeconstructCallback;
  }

  /**
   * Address: 0x00BD8CD0 (FUN_00BD8CD0, dynamic initializer for the global
   * `CCommandDBSerializer` singleton)
   */
  CCommandDBSerializer::CCommandDBSerializer()
    : mDeserialize(&CCommandDBSerializer::Deserialize)
    , mSerialize(&CCommandDBSerializer::Serialize)
  {}

  /**
   * Address: 0x00BFEA00 (FUN_00BFEA00, Moho::CCommandDBSerializer::~CCommandDBSerializer)
   */
  CCommandDBSerializer::~CCommandDBSerializer()
  {
    ResetLinks();
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
   * Address: 0x006E1C20 (FUN_006E1C20, Moho::CCommandDBSerializer::RegisterSerializeFunctions)
   *
   * What it does:
   * Binds `CCommandDb` load/save callbacks into the reflected RTTI slot.
   */
  void CCommandDBSerializer::Init()
  {
    gpg::RType* const type = ResolveCachedType<CCommandDb>(gCommandDbType);
    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
    type->serLoadFunc_ = mDeserialize;
    type->serSaveFunc_ = mSerialize;
  }
} // namespace moho

namespace
{
  // Address: 0x010B7E68 -- process-global `CCommandDBSaveConstruct` singleton.
  moho::CCommandDBSaveConstruct gCCommandDBSaveConstruct;

  // Address: 0x010B7E4C -- process-global `CCommandDBConstruct` singleton.
  moho::CCommandDBConstruct gCCommandDBConstruct;

  // Address: 0x010B7DD4 -- process-global `CCommandDBSerializer` singleton.
  moho::CCommandDBSerializer gCCommandDBSerializer;
} // namespace
