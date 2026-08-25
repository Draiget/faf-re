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
  struct ScalarDeleteVTable
  {
    using deleting_dtor_t = int(__thiscall*)(void* self, int deleteFlag);
    deleting_dtor_t mDeletingDtor;
  };

  struct ScalarDeleteObject
  {
    ScalarDeleteVTable* mVTable;
  };
} // namespace

namespace moho
{
  /**
   * Address: 0x00539C80 (FUN_00539C80, sub_539C80)
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
   * Address: 0x00BC90B0 (FUN_00BC90B0, register_CAniResourceSkelConstruct)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
   * into `sNewHelpers`), then binds the construct/delete callback fields.
   */
  CAniResourceSkelConstruct::CAniResourceSkelConstruct()
    : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&CAniResourceSkelConstruct::Construct))
    , mDeleteCallback(&CAniResourceSkelConstruct::Deconstruct)
  {
  }

  /**
   * Address: 0x00BF3BB0 (FUN_00BF3BB0, Moho::CAniResourceSkelConstruct::~CAniResourceSkelConstruct)
   *
   * What it does:
   * Unlinks this helper node from whatever intrusive list it currently sits
   * in and restores a self-linked sentinel state.
   */
  CAniResourceSkelConstruct::~CAniResourceSkelConstruct()
  {
    ResetLinks();
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
   * Address: 0x00539B80 (FUN_00539B80, Moho::CAniResourceSkelConstruct::Deconstruct)
   *
   * What it does:
   * Deleting-teardown callback: dispatches through the runtime object's own
   * vtable slot 0 (scalar deleting destructor) with the deleting flag set,
   * when the object pointer is non-null.
   */
  void CAniResourceSkelConstruct::Deconstruct(void* const objectPtr)
  {
    if (objectPtr == nullptr) {
      return;
    }

    auto* const scalarDeleteObject = static_cast<ScalarDeleteObject*>(objectPtr);
    (void)scalarDeleteObject->mVTable->mDeletingDtor(objectPtr, 1);
  }

  /**
   * Address: 0x00539580 (FUN_00539580, gpg::SerConstructHelper_CAniResourceSkel::Init)
   *
   * What it does:
   * Resolves `CAniResourceSkel` RTTI and installs construct/delete callbacks.
   */
  void CAniResourceSkelConstruct::Init()
  {
    gpg::RType* const typeInfo = resource_reflection::ResolveCAniResourceSkelType();
    resource_reflection::RegisterConstructCallbacks(typeInfo, mConstructCallback, mDeleteCallback);
  }
} // namespace moho

namespace
{
  // Address: 0x010ABBB4 -- process-global `CAniResourceSkelConstruct`
  // singleton. Constructing it runs CAniResourceSkelConstruct::
  // CAniResourceSkelConstruct() (0x00BC90B0), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first
  // ReadArchive/WriteArchive construction. Its destructor
  // (~CAniResourceSkelConstruct, 0x00BF3BB0) runs at normal static-duration
  // teardown, matching the real binary's atexit registration.
  moho::CAniResourceSkelConstruct gCAniResourceSkelConstruct;
} // namespace
