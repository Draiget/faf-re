#include "moho/sim/SPhysConstantsTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/sim/SPhysConstants.h"

#pragma init_seg(lib)

namespace
{
  using TypeInfo = moho::SPhysConstantsTypeInfo;

  alignas(TypeInfo) unsigned char gSPhysConstantsTypeInfoStorage[sizeof(TypeInfo)];
  bool gSPhysConstantsTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& GetSPhysConstantsTypeInfo() noexcept
  {
    if (!gSPhysConstantsTypeInfoConstructed) {
      new (gSPhysConstantsTypeInfoStorage) TypeInfo();
      gSPhysConstantsTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gSPhysConstantsTypeInfoStorage);
  }

  [[nodiscard]] gpg::RType* CachedSPhysConstantsType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::SPhysConstants));
    }

    GPG_ASSERT(cached != nullptr);
    return cached;
  }

  [[nodiscard]] gpg::RRef MakeSPhysConstantsRef(moho::SPhysConstants* const object)
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = CachedSPhysConstantsType();
    return ref;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00699AB0 (FUN_00699AB0, Moho::SPhysConstantsTypeInfo::SPhysConstantsTypeInfo)
   */
  SPhysConstantsTypeInfo::SPhysConstantsTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(SPhysConstants), this);
  }

  /**
   * Address: 0x00699B60 (FUN_00699B60, Moho::SPhysConstantsTypeInfo::dtr)
   */
  SPhysConstantsTypeInfo::~SPhysConstantsTypeInfo()
  {
    fields_ = {};
    bases_ = {};
  }

  /**
   * Address: 0x00699B50 (FUN_00699B50, Moho::SPhysConstantsTypeInfo::GetName)
   */
  const char* SPhysConstantsTypeInfo::GetName() const
  {
    return "SPhysConstants";
  }

  /**
   * Address: 0x00699B10 (FUN_00699B10, Moho::SPhysConstantsTypeInfo::Init)
   */
  void SPhysConstantsTypeInfo::Init()
  {
    size_ = sizeof(SPhysConstants);
    newRefFunc_ = &SPhysConstantsTypeInfo::NewRef;
    ctorRefFunc_ = &SPhysConstantsTypeInfo::CtrRef;
    deleteFunc_ = &SPhysConstantsTypeInfo::Delete;
    dtrFunc_ = &SPhysConstantsTypeInfo::Destruct;
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00699F60 (FUN_00699F60, Moho::SPhysConstantsTypeInfo::NewRef)
   */
  gpg::RRef SPhysConstantsTypeInfo::NewRef()
  {
    auto* const object = new (std::nothrow) SPhysConstants;
    if (object) {
      object->mGravity.x = 0.0f;
      object->mGravity.y = -4.9f;
      object->mGravity.z = 0.0f;
    }

    return MakeSPhysConstantsRef(object);
  }

  /**
   * Address: 0x00699FC0 (FUN_00699FC0, Moho::SPhysConstantsTypeInfo::CtrRef)
   */
  gpg::RRef SPhysConstantsTypeInfo::CtrRef(void* const objectPtr)
  {
    auto* const object = static_cast<SPhysConstants*>(objectPtr);
    if (object) {
      object->mGravity.x = 0.0f;
      object->mGravity.y = -4.9f;
      object->mGravity.z = 0.0f;
    }

    return MakeSPhysConstantsRef(object);
  }

  /**
   * Address: 0x00699FB0 (FUN_00699FB0, Moho::SPhysConstantsTypeInfo::Delete)
   */
  void SPhysConstantsTypeInfo::Delete(void* const objectPtr)
  {
    ::operator delete(objectPtr);
  }

  /**
   * Address: 0x0069A010 (FUN_0069A010, Moho::SPhysConstantsTypeInfo::Destruct)
   */
  void SPhysConstantsTypeInfo::Destruct(void*)
  {}

  /**
   * Address: 0x00BFD400 (FUN_00BFD400, cleanup_SPhysConstantsTypeInfo)
   */
  void cleanup_SPhysConstantsTypeInfo()
  {
    if (!gSPhysConstantsTypeInfoConstructed) {
      return;
    }

    GetSPhysConstantsTypeInfo().~SPhysConstantsTypeInfo();
    gSPhysConstantsTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BD6030 (FUN_00BD6030, register_SPhysConstantsTypeInfo)
   */
  void register_SPhysConstantsTypeInfo()
  {
    (void)GetSPhysConstantsTypeInfo();
    (void)std::atexit(&cleanup_SPhysConstantsTypeInfo);
  }
} // namespace moho

namespace
{
  struct SPhysConstantsTypeInfoBootstrap
  {
    SPhysConstantsTypeInfoBootstrap()
    {
      moho::register_SPhysConstantsTypeInfo();
    }
  };

  [[maybe_unused]] SPhysConstantsTypeInfoBootstrap gSPhysConstantsTypeInfoBootstrap;
} // namespace
