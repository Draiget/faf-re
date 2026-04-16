#include "moho/resource/CAniResourceSkelConstruct.h"

#include <typeinfo>

#include "moho/animation/CAniSkel.h"
#include "moho/resource/RScmResource.h"
#include "moho/resource/ResourceManager.h"
#include "moho/resource/ResourceReflectionHelpers.h"

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetShared(const boost::shared_ptr<void>& object, gpg::RType* type, unsigned int flags);
  };
} // namespace gpg

namespace
{
  moho::CAniResourceSkelConstruct gCAniResourceSkelConstruct{};

  [[nodiscard]] gpg::SerHelperBase* ResetCAniResourceSkelConstructHelperLinks() noexcept
  {
    gCAniResourceSkelConstruct.mHelperNext->mPrev = gCAniResourceSkelConstruct.mHelperPrev;
    gCAniResourceSkelConstruct.mHelperPrev->mNext = gCAniResourceSkelConstruct.mHelperNext;
    gpg::SerHelperBase* const self = reinterpret_cast<gpg::SerHelperBase*>(&gCAniResourceSkelConstruct.mHelperNext);
    gCAniResourceSkelConstruct.mHelperPrev = self;
    gCAniResourceSkelConstruct.mHelperNext = self;
    return self;
  }

  /**
   * Address: 0x00538860 (FUN_00538860)
   *
   * What it does:
   * Unlinks `CAniResourceSkelConstruct` helper node from the intrusive helper
   * list and restores self-linked sentinel links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupCAniResourceSkelConstructHelperNodePrimary() noexcept
  {
    return ResetCAniResourceSkelConstructHelperLinks();
  }

  /**
   * Address: 0x00538890 (FUN_00538890)
   *
   * What it does:
   * Secondary entrypoint for `CAniResourceSkelConstruct` helper-node
   * unlink/reset.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupCAniResourceSkelConstructHelperNodeSecondary() noexcept
  {
    return ResetCAniResourceSkelConstructHelperLinks();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00539C80 (FUN_00539C80)
   *
   * What it does:
   * Packages one shared `CAniSkel` lane into the construct-result shared
   * payload with resolved `CAniSkel` runtime type metadata.
   */
  void SetConstructResultSharedAniSkel(
    gpg::SerConstructResult* const result,
    const boost::shared_ptr<const CAniSkel>& skeleton
  )
  {
    gpg::RType* skelType = CAniSkel::sType;
    if (skelType == nullptr) {
      skelType = gpg::LookupRType(typeid(CAniSkel));
      CAniSkel::sType = skelType;
    }

    const boost::shared_ptr<void>& sharedAny =
      reinterpret_cast<const boost::shared_ptr<void>&>(skeleton);
    result->SetShared(sharedAny, skelType, 1U);
  }

  /**
   * Address: 0x005388C0 (FUN_005388C0, Moho::CAniResourceSkelConstruct::Construct)
   *
   * What it does:
   * Reads one model path from archive, resolves/loads the SCM resource via the
   * resource manager, pulls its shared skeleton payload, and forwards it into
   * construct-result shared ownership as a `CAniSkel` lane.
   */
  void CAniResourceSkelConstruct::Construct(
    gpg::ReadArchive* const archive, const int, const int, gpg::SerConstructResult* const result
  )
  {
    msvc8::string modelPath{};
    archive->ReadString(&modelPath);

    gpg::RType* resourceType = RScmResource::sType;
    if (resourceType == nullptr) {
      resourceType = gpg::LookupRType(typeid(RScmResource));
      RScmResource::sType = resourceType;
    }

    boost::weak_ptr<RScmResource> modelWeak{};
    (void)RES_GetResource(&modelWeak, modelPath.c_str(), nullptr, resourceType);

    boost::shared_ptr<const CAniSkel> skeleton{};
    if (boost::shared_ptr<RScmResource> modelResource = modelWeak.lock(); modelResource) {
      skeleton = modelResource->GetSkeleton();
    }

    SetConstructResultSharedAniSkel(result, skeleton);
  }

  /**
   * Address: 0x00539580 (FUN_00539580, gpg::SerConstructHelper_CAniResourceSkel::Init)
   *
   * What it does:
   * Resolves `CAniResourceSkel` RTTI and installs construct/delete callbacks.
   */
  void CAniResourceSkelConstruct::RegisterConstructFunction()
  {
    gpg::RType* const typeInfo = resource_reflection::ResolveCAniResourceSkelType();
    resource_reflection::RegisterConstructCallbacks(typeInfo, mConstructCallback, mDeleteCallback);
  }
} // namespace moho
