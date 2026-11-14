#include "moho/sim/SPhysConstantsTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/sim/SPhysConstants.h"

#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::SPhysConstantsTypeInfo;

  /**
   * Address: 0x00BFD400 (FUN_00BFD400, atexit destructor of the TypeInfo object)
   */
  [[nodiscard]] TypeInfo& GetSPhysConstantsTypeInfo() noexcept
  {
    static TypeInfo sInstance;
    return sInstance;
  }

  [[nodiscard]] gpg::RRef MakeSPhysConstantsRef(
    moho::SPhysConstants* const object
  )
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = gpg::RTypeOf<moho::SPhysConstants>();
    return ref;
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
  {}

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
  [[maybe_unused]] void DestroySPhysConstantsTypeInfoBody(
    SPhysConstantsTypeInfo* const typeInfo
  ) noexcept
  {
    gpg::ClearTypeLists(typeInfo);
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
  gpg::RRef SPhysConstantsTypeInfo::CtrRef(
    void* const objectPtr
  )
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
  void SPhysConstantsTypeInfo::Delete(
    void* const objectPtr
  )
  {
    ::operator delete(objectPtr);
  }

  /**
   * Address: 0x0069A010 (FUN_0069A010, Moho::SPhysConstantsTypeInfo::Destruct)
   */
  void SPhysConstantsTypeInfo::Destruct(
    void*
  )
  {}

  /**
   * Address: 0x00BD6030 (FUN_00BD6030, register_SPhysConstantsTypeInfo)
   */
  void register_SPhysConstantsTypeInfo()
  {
    (void)GetSPhysConstantsTypeInfo();
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

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(
  register_SPhysConstantsTypeInfo_4a719c,
  moho::register_SPhysConstantsTypeInfo
)
