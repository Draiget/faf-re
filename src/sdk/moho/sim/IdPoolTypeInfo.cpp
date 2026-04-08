#include "moho/sim/IdPoolTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/sim/IdPool.h"

#pragma init_seg(lib)

namespace moho
{
  void register_IdPoolTypeInfo();
}

namespace
{
  moho::IdPoolTypeInfo gIdPoolTypeInfo;

  template <class TObject>
  [[nodiscard]] gpg::RRef MakeReflectionRef(TObject* const object, gpg::RType* const type)
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = type;
    return ref;
  }

  [[nodiscard]] gpg::RType* CachedIdPoolType()
  {
    gpg::RType* type = moho::IdPool::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::IdPool));
      moho::IdPool::sType = type;
    }
    GPG_ASSERT(type != nullptr);
    return type;
  }

  void DestroyIdPoolMembers(moho::IdPool& pool)
  {
    pool.mSubRes2.Reset();
    pool.mReleasedLows.mWords.ResetStorageToInline();
  }

  /**
   * Address: 0x00BEE000 (FUN_00BEE000, ??1IdPoolTypeInfo@Moho@@QAE@@Z)
   *
   * What it does:
   * Process-exit cleanup for global `IdPoolTypeInfo` dynamic field/base lanes.
   */
  void cleanup_IdPoolTypeInfo()
  {
    gIdPoolTypeInfo.fields_.clear();
    gIdPoolTypeInfo.bases_.clear();
  }

  struct IdPoolTypeInfoRegistration
  {
    IdPoolTypeInfoRegistration()
    {
      moho::register_IdPoolTypeInfo();
    }
  };

  IdPoolTypeInfoRegistration gIdPoolTypeInfoRegistration;
} // namespace

namespace moho
{
  /**
   * Address: 0x00BC2D80 (FUN_00BC2D80, register_IdPoolTypeInfo)
   *
   * What it does:
   * Materializes startup `IdPoolTypeInfo` storage and registers process-exit
   * teardown.
   */
  void register_IdPoolTypeInfo()
  {
    (void)gIdPoolTypeInfo;
    (void)std::atexit(&cleanup_IdPoolTypeInfo);
  }

  /**
   * Address: 0x004037C0 (FUN_004037C0, Moho::IdPoolTypeInfo::IdPoolTypeInfo)
   */
  IdPoolTypeInfo::IdPoolTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(IdPool), this);
  }

  /**
   * Address: 0x00403870 (FUN_00403870, deleting dtor lane)
   */
  IdPoolTypeInfo::~IdPoolTypeInfo() = default;

  /**
   * Address: 0x00403860 (FUN_00403860, Moho::IdPoolTypeInfo::GetName)
   */
  const char* IdPoolTypeInfo::GetName() const
  {
    return "IdPool";
  }

  /**
   * Address: 0x00403820 (FUN_00403820, Moho::IdPoolTypeInfo::Init)
   */
  void IdPoolTypeInfo::Init()
  {
    size_ = sizeof(IdPool);
    newRefFunc_ = &IdPoolTypeInfo::NewRef;
    ctorRefFunc_ = &IdPoolTypeInfo::CtrRef;
    deleteFunc_ = &IdPoolTypeInfo::Delete;
    dtrFunc_ = &IdPoolTypeInfo::Destruct;
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00403F40 (FUN_00403F40, Moho::IdPoolTypeInfo::NewRef)
   */
  gpg::RRef IdPoolTypeInfo::NewRef()
  {
    IdPool* const object = new (std::nothrow) IdPool();
    return MakeReflectionRef(object, CachedIdPoolType());
  }

  /**
   * Address: 0x00404000 (FUN_00404000, Moho::IdPoolTypeInfo::CtrRef)
   */
  gpg::RRef IdPoolTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const object = reinterpret_cast<IdPool*>(objectStorage);
    if (object) {
      new (object) IdPool();
    }
    return MakeReflectionRef(object, CachedIdPoolType());
  }

  /**
   * Address: 0x00403FC0 (FUN_00403FC0, Moho::IdPoolTypeInfo::Delete)
   */
  void IdPoolTypeInfo::Delete(void* const objectStorage)
  {
    auto* const object = reinterpret_cast<IdPool*>(objectStorage);
    if (!object) {
      return;
    }

    DestroyIdPoolMembers(*object);
    ::operator delete(object);
  }

  /**
   * Address: 0x00404070 (FUN_00404070, Moho::IdPoolTypeInfo::Destruct)
   */
  void IdPoolTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const object = reinterpret_cast<IdPool*>(objectStorage);
    if (!object) {
      return;
    }

    DestroyIdPoolMembers(*object);
  }
} // namespace moho
