#include "moho/animation/CAniPoseSharedPtrReflection.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "moho/animation/CAniPose.h"

namespace
{
  alignas(gpg::RSharedPointerType_CAniPose) unsigned char
    gSharedPtrCAniPoseTypeStorage[sizeof(gpg::RSharedPointerType_CAniPose)]{};
  bool gSharedPtrCAniPoseTypeConstructed = false;

  gpg::RType* gCAniPoseSharedPtrPointeeType = nullptr;
  msvc8::string gCAniPoseSharedPtrTypeName;
  bool gCAniPoseSharedPtrTypeNameCleanupRegistered = false;

  [[nodiscard]] gpg::RSharedPointerType_CAniPose* AcquireSharedPtrCAniPoseType()
  {
    if (!gSharedPtrCAniPoseTypeConstructed) {
      ::new (static_cast<void*>(gSharedPtrCAniPoseTypeStorage)) gpg::RSharedPointerType_CAniPose();
      gSharedPtrCAniPoseTypeConstructed = true;
    }

    return reinterpret_cast<gpg::RSharedPointerType_CAniPose*>(gSharedPtrCAniPoseTypeStorage);
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

  void cleanup_CAniPoseSharedPtrTypeName()
  {
    gCAniPoseSharedPtrTypeName.clear();
  }
} // namespace

namespace gpg
{
  /**
   * Address: 0x0055CE20 (FUN_0055CE20, gpg::RSharedPointerType_CAniPose::GetName)
   *
   * What it does:
   * Builds/caches lexical type name `"boost::shared_ptr<%s>"` from CAniPose RTTI.
   */
  const char* RSharedPointerType<moho::CAniPose>::GetName() const
  {
    if (gCAniPoseSharedPtrTypeName.empty()) {
      const gpg::RType* const pointeeType = CachedCAniPoseType();
      const char* const pointeeName = pointeeType ? pointeeType->GetName() : "CAniPose";
      gCAniPoseSharedPtrTypeName = gpg::STR_Printf("boost::shared_ptr<%s>", pointeeName ? pointeeName : "CAniPose");

      if (!gCAniPoseSharedPtrTypeNameCleanupRegistered) {
        gCAniPoseSharedPtrTypeNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_CAniPoseSharedPtrTypeName);
      }
    }

    return gCAniPoseSharedPtrTypeName.c_str();
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
