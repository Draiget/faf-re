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
  // No top-level `const` on `result`: MSVC folds it into the decorated name
  // (`QAVSerConstructResult@gpg@@` rather than `PAV...`), and the only other
  // reference is the cross-TU declaration in `CAniDefaultSkelConstruct.cpp`,
  // which spells the parameter without it. The `const` form left this defined
  // but unlinkable.
  void SetConstructResultSharedAniSkel(
    gpg::SerConstructResult* result,
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

    boost::shared_ptr<const CAniSkel> skeleton{};
    if (const boost::shared_ptr<RScmResource> modelResource = GetModel(modelPath.c_str(), nullptr); modelResource) {
      skeleton = modelResource->GetSkeleton();
    }

    SetConstructResultSharedAniSkel(result, skeleton);
  }

  /**
   * Address: 0x00539BA0 (FUN_00539BA0, func_GetModel)
   *
   * IDA signature:
   * boost::shared_ptr<RScmResource> *__cdecl func_GetModel(
   *     boost::shared_ptr<RScmResource> *out, const char *path, int resWatcher);
   *
   * What it does:
   * Lazily resolves the `RScmResource` reflection descriptor (0x00539BC6
   * caches it in `RScmResource::sType`), dispatches one model path through
   * `RES_GetResource` (0x00539BF0), and retains the resolved object into the
   * caller's handle (0x00539BFC) before releasing the manager's temporary.
   * Yields an empty pointer when the lookup produced no live object -- the
   * empty-path case lands there too, via the manager's own
   * `GetResource: Invalid name` rejection.
   */
  boost::shared_ptr<RScmResource> GetModel(const gpg::StrArg path, CResourceWatcher* const resourceWatcher)
  {
    gpg::RType* resourceType = RScmResource::sType;
    if (resourceType == nullptr) {
      resourceType = gpg::LookupRType(typeid(RScmResource));
      RScmResource::sType = resourceType;
    }

    boost::weak_ptr<RScmResource> resolved{};
    (void)RES_GetResource(&resolved, path, resourceWatcher, resourceType);
    return resolved.lock();
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
