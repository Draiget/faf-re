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

  gpg::RType* gSPhysConstantsPrimaryType = nullptr;
  gpg::RType* gSPhysConstantsSecondaryType = nullptr;

  /**
   * Address: 0x00698A40 (FUN_00698A40)
   *
   * What it does:
   * Resolves and caches the primary RTTI lane for `SPhysConstants`.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* ResolveSPhysConstantsPrimaryType()
  {
    gpg::RType* type = gSPhysConstantsPrimaryType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SPhysConstants));
      gSPhysConstantsPrimaryType = type;
    }
    return type;
  }

  /**
   * Address: 0x00698F20 (FUN_00698F20)
   *
   * What it does:
   * Resolves and caches the secondary RTTI lane for `SPhysConstants`.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* ResolveSPhysConstantsSecondaryType()
  {
    gpg::RType* type = gSPhysConstantsSecondaryType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SPhysConstants));
      gSPhysConstantsSecondaryType = type;
    }
    return type;
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

  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Vector3f));
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

  /**
   * Address: 0x0069A020 (FUN_0069A020)
   *
   * What it does:
   * Deserializes one `Vector3f` object lane using one local null-owner
   * reference.
   */
  void ReadVector3fArchiveObjectWithNullOwnerVariantA(gpg::ReadArchive* const archive, void* const object)
  {
    gpg::RRef ownerRef{};
    archive->Read(CachedVector3fType(), object, ownerRef);
  }

  /**
   * Address: 0x0069A060 (FUN_0069A060)
   *
   * What it does:
   * Serializes one `Vector3f` object lane using one local null-owner
   * reference.
   */
  void WriteVector3fArchiveObjectWithNullOwnerVariantA(gpg::WriteArchive* const archive, void** const objectSlot)
  {
    const gpg::RRef ownerRef{};
    archive->Write(CachedVector3fType(), objectSlot, ownerRef);
  }

  /**
   * Address: 0x0069A0D0 (FUN_0069A0D0)
   *
   * What it does:
   * Secondary deserialization lane for one `Vector3f` object using one local
   * null-owner reference.
   */
  void ReadVector3fArchiveObjectWithNullOwnerVariantB(gpg::ReadArchive* const archive, void* const object)
  {
    gpg::RRef ownerRef{};
    archive->Read(CachedVector3fType(), object, ownerRef);
  }

  /**
   * Address: 0x0069A110 (FUN_0069A110)
   *
   * What it does:
   * Secondary serialization lane for one `Vector3f` object using one local
   * null-owner reference.
   */
  void WriteVector3fArchiveObjectWithNullOwnerVariantB(gpg::WriteArchive* const archive, void** const objectSlot)
  {
    const gpg::RRef ownerRef{};
    archive->Write(CachedVector3fType(), objectSlot, ownerRef);
  }

  /**
   * Address: 0x0069A150 (FUN_0069A150)
   *
   * What it does:
   * Stdcall bridge that deserializes one `Vector3f` object lane using one
   * local null-owner reference.
   */
  void ReadVector3fArchiveObjectWithNullOwnerStdCall(void* const object, gpg::ReadArchive* const archive)
  {
    gpg::RRef ownerRef{};
    archive->Read(CachedVector3fType(), object, ownerRef);
  }

  /**
   * Address: 0x0069A190 (FUN_0069A190)
   *
   * What it does:
   * Stdcall bridge that serializes one `Vector3f` object lane using one local
   * null-owner reference.
   */
  void WriteVector3fArchiveObjectWithNullOwnerStdCall(void** const objectSlot, gpg::WriteArchive* const archive)
  {
    const gpg::RRef ownerRef{};
    archive->Write(CachedVector3fType(), objectSlot, ownerRef);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00699A90 (FUN_00699A90, Moho::SPhysConstants::SPhysConstants)
   *
   * What it does:
   * Initializes gravity constants to `(0.0f, -4.9f, 0.0f)`.
   */
  SPhysConstants::SPhysConstants() noexcept
    : mGravity(0.0f, -4.9f, 0.0f)
  {
  }

  /**
   * Address: 0x00699AB0 (FUN_00699AB0, Moho::SPhysConstantsTypeInfo::SPhysConstantsTypeInfo)
   */
  SPhysConstantsTypeInfo::SPhysConstantsTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(SPhysConstants), this);
  }

  /**
   * Address: 0x00699BC0 (FUN_00699BC0, SPhysConstantsTypeInfo non-deleting cleanup body)
   *
   * What it does:
   * Clears reflected base/field vector lanes for one `SPhysConstantsTypeInfo`
   * instance while preserving outer storage ownership.
   */
  [[maybe_unused]] void DestroySPhysConstantsTypeInfoBody(SPhysConstantsTypeInfo* const typeInfo) noexcept
  {
    if (typeInfo == nullptr) {
      return;
    }

    typeInfo->fields_ = {};
    typeInfo->bases_ = {};
  }

  /**
   * Address: 0x00699B60 (FUN_00699B60, Moho::SPhysConstantsTypeInfo::dtr)
   */
  SPhysConstantsTypeInfo::~SPhysConstantsTypeInfo()
  {
    DestroySPhysConstantsTypeInfoBody(this);
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
    (void)gpg::BindRTypeLifecycleCallbacks(
      this,
      &SPhysConstantsTypeInfo::NewRef,
      &SPhysConstantsTypeInfo::CtrRef,
      &SPhysConstantsTypeInfo::Delete,
      &SPhysConstantsTypeInfo::Destruct
    );
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00699F60 (FUN_00699F60, Moho::SPhysConstantsTypeInfo::NewRef)
   */
  gpg::RRef SPhysConstantsTypeInfo::NewRef()
  {
    auto* const object = new (std::nothrow) SPhysConstants();
    return MakeSPhysConstantsRef(object);
  }

  /**
   * Address: 0x00699FC0 (FUN_00699FC0, Moho::SPhysConstantsTypeInfo::CtrRef)
   */
  gpg::RRef SPhysConstantsTypeInfo::CtrRef(void* const objectPtr)
  {
    auto* const object = static_cast<SPhysConstants*>(objectPtr);
    if (object) {
      ::new (object) SPhysConstants();
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
