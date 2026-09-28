#include "moho/animation/CAniPoseSharedPtrReflection.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "moho/animation/CAniPose.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  gpg::RType* gCAniPoseSharedPtrPointeeType = nullptr;

  /**
   * Address: 0x00BF5540 (FUN_00BF5540, atexit destructor of the RSharedPointerType<CAniPose> object)
   */
  [[nodiscard]] gpg::RSharedPointerType_CAniPose* AcquireSharedPtrCAniPoseType()
  {
    static gpg::RSharedPointerType_CAniPose sInstance;
    return &sInstance;
  }

  [[nodiscard]] gpg::RType* CachedCAniPoseType()
  {
    if (!gCAniPoseSharedPtrPointeeType) {
      gCAniPoseSharedPtrPointeeType = gpg::LookupRType(typeid(moho::CAniPose));
    }
    return gCAniPoseSharedPtrPointeeType;
  }

  [[nodiscard]] gpg::RRef MakeCAniPoseRef(moho::CAniPose* const pose) noexcept
  {
    return gpg::RRef{pose, CachedCAniPoseType()};
  }
} // namespace

namespace gpg
{
  RSharedPointerType<moho::CAniPose>::~RSharedPointerType() = default;

  /**
   * Address: 0x0055CE20 (FUN_0055CE20, gpg::RSharedPointerType_CAniPose::GetName)
   * Address: 0x00BF54E0 (FUN_00BF54E0, atexit destructor of GetName's cached name)
   *
   * What it does:
   * Builds `boost::shared_ptr<CAniPose>` once from CAniPose RTTI and returns it.
   */
  const char* RSharedPointerType<moho::CAniPose>::GetName() const
  {
    static const msvc8::string sName = gpg::STR_Printf("boost::shared_ptr<%s>", CachedCAniPoseType()->GetName());
    return sName.c_str();
  }

  /**
   * Address: 0x0055CED0 (FUN_0055CED0, gpg::RSharedPointerType_CAniPose::GetLexical)
   *
   * What it does:
   * Returns `"NULL"` for empty shared pointers, otherwise wraps pointee lexical with brackets.
   */
  msvc8::string RSharedPointerType<moho::CAniPose>::GetLexical(const gpg::RRef& ref) const
  {
    const auto* const shared = static_cast<const boost::SharedPtrRaw<moho::CAniPose>*>(ref.mObj);
    if (!shared || !shared->px) {
      return msvc8::string("NULL");
    }

    const msvc8::string inner = MakeCAniPoseRef(shared->px).GetLexical();
    return gpg::STR_Printf("[%s]", inner.c_str());
  }

  /**
   * Address: 0x0055D050 (FUN_0055D050, gpg::RSharedPointerType_CAniPose::IsIndexed)
   */
  const gpg::RIndexed* RSharedPointerType<moho::CAniPose>::IsIndexed() const
  {
    return this;
  }

  /**
   * Address: 0x0055D060 (FUN_0055D060, gpg::RSharedPointerType_CAniPose::IsPointer)
   */
  const gpg::RIndexed* RSharedPointerType<moho::CAniPose>::IsPointer() const
  {
    return this;
  }

  /**
   * Address: 0x0055CEC0 (FUN_0055CEC0, gpg::RSharedPointerType_CAniPose::Init)
   *
   * What it does:
   * Registers one shared-pointer payload size lane (`sizeof(boost::SharedPtrRaw<CAniPose>)`).
   */
  void RSharedPointerType<moho::CAniPose>::Init()
  {
    size_ = sizeof(boost::SharedPtrRaw<moho::CAniPose>);
  }

  /**
   * Address: 0x0055D080 (FUN_0055D080, gpg::RSharedPointerType_CAniPose::SubscriptIndex)
   *
   * What it does:
   * Returns element 0 as `RRef<CAniPose>` (asserts on any other index).
   */
  gpg::RRef RSharedPointerType<moho::CAniPose>::SubscriptIndex(void* const obj, const int ind) const
  {
    GPG_ASSERT(ind == 0);
    const auto* const shared = static_cast<const boost::SharedPtrRaw<moho::CAniPose>*>(obj);
    return MakeCAniPoseRef(shared ? shared->px : nullptr);
  }

  /**
   * Address: 0x0055D070 (FUN_0055D070, gpg::RSharedPointerType_CAniPose::GetCount)
   *
   * What it does:
   * Returns 1 when shared pointer has a non-null pointee, otherwise 0.
   */
  size_t RSharedPointerType<moho::CAniPose>::GetCount(void* const obj) const
  {
    const auto* const shared = static_cast<const boost::SharedPtrRaw<moho::CAniPose>*>(obj);
    return (shared && shared->px) ? 1u : 0u;
  }

  /**
   * Address: 0x0055EA20 (FUN_0055EA20, preregister_SharedPtrCAniPoseTypeStartup)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for
   * `boost::shared_ptr<moho::CAniPose>`.
   */
  gpg::RType* preregister_SharedPtrCAniPoseTypeStartup()
  {
    auto* const typeInfo = AcquireSharedPtrCAniPoseType();
    gpg::PreRegisterRType(typeid(boost::shared_ptr<moho::CAniPose>), typeInfo);
    return typeInfo;
  }
} // namespace gpg

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_SharedPtrCAniPoseTypeStartup_4971d6, gpg::preregister_SharedPtrCAniPoseTypeStartup)
