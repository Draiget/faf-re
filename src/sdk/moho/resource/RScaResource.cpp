// RScaResource recovered implementation.

#include "moho/resource/RScaResource.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/resource/ResourceManager.h"

#include <cstddef>
#include <cstring>
#include <new>
#include <typeinfo>

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetShared(const boost::shared_ptr<void>& object, gpg::RType* type, unsigned int flags);
  };

  class SerSaveConstructArgsResult
  {
  public:
    void SetShared(unsigned int flags);
  };
} // namespace gpg

namespace moho
{

gpg::RType* RScaResource::sType = nullptr;

namespace
{
  struct SerSaveLoadHelperNodeRuntime
  {
    void* mVtable = nullptr;
    gpg::SerHelperBase* mNext = nullptr;
    gpg::SerHelperBase* mPrev = nullptr;
  };

  static_assert(
    offsetof(SerSaveLoadHelperNodeRuntime, mNext) == 0x04,
    "SerSaveLoadHelperNodeRuntime::mNext offset must be 0x04"
  );
  static_assert(
    offsetof(SerSaveLoadHelperNodeRuntime, mPrev) == 0x08,
    "SerSaveLoadHelperNodeRuntime::mPrev offset must be 0x08"
  );
  static_assert(sizeof(SerSaveLoadHelperNodeRuntime) == 0x0C, "SerSaveLoadHelperNodeRuntime size must be 0x0C");

  [[nodiscard]] gpg::SerHelperBase* UnlinkSerSaveLoadHelperNode(SerSaveLoadHelperNodeRuntime& helper) noexcept
  {
    helper.mNext->mPrev = helper.mPrev;
    helper.mPrev->mNext = helper.mNext;

    gpg::SerHelperBase* const self = reinterpret_cast<gpg::SerHelperBase*>(&helper.mNext);
    helper.mPrev = self;
    helper.mNext = self;
    return self;
  }

  SerSaveLoadHelperNodeRuntime gRScaResourceSaveConstructHelper{};

  class RScaResourceTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "RScaResource";
    }

    void Init() override
    {
      size_ = sizeof(RScaResource);
      gpg::RType::Init();
      Finish();
    }
  };

  [[nodiscard]] CScaResourceFactory& ScaResourceFactorySingleton()
  {
    static CScaResourceFactory sFactory;
    return sFactory;
  }
} // namespace

/**
 * Address: 0x0053A710 (FUN_0053A710)
 *
 * What it does:
 * Unlinks `RScaResource` save-construct helper links and restores the node
 * to self-linked sentinel state.
 */
[[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupRScaResourceSaveConstructHelperPrimary() noexcept
{
  return UnlinkSerSaveLoadHelperNode(gRScaResourceSaveConstructHelper);
}

/**
 * Address: 0x0053A2D0 (FUN_0053A2D0, preregister_RScaResourceTypeInfo)
 *
 * What it does:
 * Constructs/preregisters reflection metadata for `RScaResource`.
 */
[[nodiscard]] gpg::RType* preregister_RScaResourceTypeInfo()
{
  static RScaResourceTypeInfo typeInfo;
  gpg::PreRegisterRType(typeid(RScaResource), &typeInfo);
  return &typeInfo;
}

/**
 * Address: 0x0053B2A0 (FUN_0053B2A0, boost::shared_ptr_RScaResource::shared_ptr_RScaResource)
 *
 * What it does:
 * Constructs one `shared_ptr<RScaResource>` from one raw resource pointer lane.
 */
boost::shared_ptr<RScaResource>* ConstructSharedRScaResourceFromRaw(
  boost::shared_ptr<RScaResource>* const outResource,
  RScaResource* const resource
)
{
  return ::new (outResource) boost::shared_ptr<RScaResource>(resource);
}

/**
 * Address: 0x0053B3B0 (FUN_0053B3B0)
 *
 * What it does:
 * Constructs one `boost::detail::sp_counted_impl_p<RScaResource>` control
 * block in caller-provided storage with both initial reference counters set to
 * `1` and payload pointer bound to `resource`.
 */
boost::detail::sp_counted_impl_p<RScaResource>* ConstructRScaSharedCountedImpl(
  boost::detail::sp_counted_impl_p<RScaResource>* const outControlBlock,
  RScaResource* const resource
)
{
  return ::new (outControlBlock) boost::detail::sp_counted_impl_p<RScaResource>(resource);
}

/**
 * Address: 0x0053B1E0 (FUN_0053B1E0)
 *
 * What it does:
 * Packages one shared `RScaResource` lane into construct-result shared
 * payload with resolved `RScaResource` runtime type metadata.
 */
void SetConstructResultSharedScaResource(
  gpg::SerConstructResult* const result,
  const boost::shared_ptr<RScaResource>& resource
)
{
  gpg::RType* resourceType = RScaResource::sType;
  if (resourceType == nullptr) {
    resourceType = gpg::LookupRType(typeid(RScaResource));
    RScaResource::sType = resourceType;
  }

  const boost::shared_ptr<void>& sharedAny =
    reinterpret_cast<const boost::shared_ptr<void>&>(resource);
  result->SetShared(sharedAny, resourceType, 1u);
}

/**
 * Address: 0x0053A8C0 (FUN_0053A8C0)
 *
 * What it does:
 * Reads one animation path from archive, resolves/loads the referenced SCA
 * resource, and forwards it into construct-result shared ownership.
 */
void Construct_RScaResource(
  gpg::ReadArchive* const archive,
  const int,
  const int,
  gpg::SerConstructResult* const result
)
{
  msvc8::string resourcePath{};
  archive->ReadString(&resourcePath);

  gpg::RType* resourceType = RScaResource::sType;
  if (resourceType == nullptr) {
    resourceType = gpg::LookupRType(typeid(RScaResource));
    RScaResource::sType = resourceType;
  }

  boost::weak_ptr<RScaResource> weakResource{};
  (void)RES_GetResource(&weakResource, resourcePath.c_str(), nullptr, resourceType);
  const boost::shared_ptr<RScaResource> sharedResource = weakResource.lock();
  SetConstructResultSharedScaResource(result, sharedResource);
}

/**
 * Address: 0x0053A770 (FUN_0053A770)
 *
 * What it does:
 * Writes one mounted-path string save-construct arg for one `RScaResource`
 * and marks the construct-result ownership lane as shared.
 */
void SaveConstructArgs_RScaResource(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const,
  gpg::SerSaveConstructArgsResult* const result
)
{
  const auto* const resource = reinterpret_cast<const RScaResource*>(static_cast<std::uintptr_t>(objectPtr));

  msvc8::string mountedPath{};
  (void)FILE_ToMountedPath(&mountedPath, resource->mFilename.c_str());
  archive->WriteString(&mountedPath);
  result->SetShared(1u);
}

/**
 * Address: 0x0053A6F0 (FUN_0053A6F0)
 *
 * What it does:
 * Thin callback thunk forwarding save-construct arg serialization for one
 * `RScaResource`.
 */
void SaveConstructArgs_RScaResourceThunk(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int version,
  gpg::RRef* const ownerRef,
  gpg::SerSaveConstructArgsResult* const result
)
{
  SaveConstructArgs_RScaResource(archive, objectPtr, version, ownerRef, result);
}

/**
 * Address: 0x0053AA40 (FUN_0053AA40)
 *
 * What it does:
 * Ensures the resource-manager singleton, attaches process-lifetime SCA
 * factory registration, and returns the attached factory object.
 */
CScaResourceFactory* construct_CScaResourceFactoryPreload()
{
  RES_EnsureResourceManager();

  ResourceManager* const manager = RES_GetResourceManager();
  CScaResourceFactory& factory = ScaResourceFactorySingleton();
  if (manager != nullptr) {
    manager->AttachFactory(&factory);
  }

  return &factory;
}

/**
 * Address: 0x0053AD00 (FUN_0053AD00, Moho::ResourceFactory_RScaResource::Init)
 *
 * What it does:
 * Resolves cached `RScaResource` RTTI and updates the prefetch/resource
 * type lanes used by factory virtual dispatch.
 */
void CScaResourceFactory::Init()
{
  (void)preregister_RScaResourceTypeInfo();

  gpg::RType* firstResolvedType = RScaResource::sType;
  if (firstResolvedType == nullptr) {
    firstResolvedType = gpg::LookupRType(typeid(RScaResource));
    RScaResource::sType = firstResolvedType;
  }

  gpg::RType* resolvedType = firstResolvedType;
  if (resolvedType == nullptr) {
    resolvedType = gpg::LookupRType(typeid(RScaResource));
    RScaResource::sType = resolvedType;
  }

  mPrefetchType = firstResolvedType;
  mResourceType = resolvedType;
}

/**
 * Address: 0x0053A4D0 (FUN_0053A4D0)
 *
 * IDA signature:
 * char __userpurge Moho::RScaResource::LoadScaFile@<al>(
 *   Moho::RScaResource *res@<edi>, const char *filename);
 *
 * What it does:
 * Reads an SCA animation file from disk via DISK_ReadFile, copies the
 * buffer into the resource, and applies a quaternion rotation fixup for
 * files with version < 5. Returns true on success, false if the file
 * could not be loaded.
 */
bool RScaResource::LoadScaFile(const char* filename)
{
  gpg::MemBuffer<char> fileData = DISK_ReadFile(filename);

  if (!fileData.mBegin) {
    return false;
  }

  // Store filename and take ownership of the file data buffer.
  new (&mFilename) msvc8::string(filename, std::strlen(filename));
  mMem = fileData;

  // Parse header pointers.
  auto* header = reinterpret_cast<SScaHeader*>(fileData.mBegin);
  mStart = fileData.mBegin;
  mEnd = fileData.mBegin + header->animDataOffset;

  // Apply quaternion rotation fixup for version < 5 files.
  // Old versions stored quaternions as [w, x, y, z]; the fixup rotates
  // them to [x, w, y, z] by cycling the four components.
  if (header->version < 5u) {
    // Fix up the animation data section header quaternion.
    auto* animHeader = reinterpret_cast<SScaAnimDataHeader*>(mEnd);
    float w = animHeader->rotation[0];
    float x = animHeader->rotation[1];
    float y = animHeader->rotation[2];
    float z = animHeader->rotation[3];
    animHeader->rotation[0] = z;
    animHeader->rotation[1] = w;
    animHeader->rotation[2] = x;
    animHeader->rotation[3] = y;

    // Fix up each per-bone key quaternion.
    const std::uint32_t boneCount = header->boneCount;
    const std::uint32_t keysPerBone = header->keysPerBone;
    // Stride per bone: 8-byte bone header + keysPerBone * 28-byte keys.
    const std::uint32_t boneStride = 8u + keysPerBone * sizeof(SScaAnimKey);

    for (std::uint32_t bone = 0; bone < boneCount; ++bone) {
      char* boneBase = mEnd + sizeof(SScaAnimDataHeader) + bone * boneStride;

      for (std::uint32_t key = 0; key < keysPerBone; ++key) {
        auto* animKey = reinterpret_cast<SScaAnimKey*>(
          boneBase + 8u + key * sizeof(SScaAnimKey)
        );
        float kw = animKey->rotation[0];
        float kx = animKey->rotation[1];
        float ky = animKey->rotation[2];
        float kz = animKey->rotation[3];
        animKey->rotation[0] = kz;
        animKey->rotation[1] = kw;
        animKey->rotation[2] = kx;
        animKey->rotation[3] = ky;
      }
    }
  }

  return true;
}

/**
 * Address: 0x0053AAD0 (FUN_0053AAD0)
 * Mangled: ?Load@CScaResourceFactory@Moho@@UAEAAV?$shared_ptr@VRScaResource@Moho@@@boost@@AAV34@PBD@Z
 *
 * IDA signature:
 * boost::shared_ptr<Moho::RScaResource>* __thiscall
 * Moho::CScaResourceFactory::Load(
 *   Moho::CScaResourceFactory *this,
 *   boost::shared_ptr<Moho::RScaResource>* outResource,
 *   const char* path);
 *
 * What it does:
 * Allocates a fresh `RScaResource`, parses the SCA file via `LoadScaFile`,
 * and resets the out handle to null when parsing fails.
 */
CScaResourceFactory::ResourceHandle&
CScaResourceFactory::Load(ResourceHandle& outResource, const char* const path)
{
  auto* const rawResource = new (std::nothrow) RScaResource();
  outResource.reset(rawResource);

  if (rawResource == nullptr) {
    return outResource;
  }

  if (!rawResource->LoadScaFile(path)) {
    outResource.reset();
  }

  return outResource;
}

/**
 * Address: 0x0053AF60 (FUN_0053AF60, Moho::ResourceFactory_RScaResource::LoadFrom)
 *
 * What it does:
 * Clones prefetch handle lane, forwards into `LoadFromImpl`, and copies the
 * resulting resource handle into `outResource`.
 */
CScaResourceFactory::ResourceHandle&
CScaResourceFactory::LoadFrom(ResourceHandle& outResource, const char* const path, ResourceHandle prefetchData)
{
  ResourceHandle prefetchCopy = prefetchData;
  ResourceHandle loadedResource{};
  (void)LoadFromImpl(loadedResource, path, prefetchCopy);
  outResource = loadedResource;
  return outResource;
}

/**
 * Address: 0x0053B100 (FUN_0053B100)
 *
 * IDA signature:
 * gpg::RRef* __cdecl Moho::func_GetScaResource(gpg::RRef* outRef, const char* path);
 *
 * What it does:
 * Resolves the cached `RScaResource` reflection type, fetches a weak handle
 * via `RES_GetResource`, packages it as a typed `gpg::RRef` into `outRef`,
 * then drops the temporary weak-ptr reference count.
 */
gpg::RRef* GetScaResource(gpg::RRef* const outRef, const char* const path)
{
  gpg::RType* resourceType = RScaResource::sType;
  if (resourceType == nullptr) {
    resourceType = gpg::LookupRType(typeid(RScaResource));
    RScaResource::sType = resourceType;
  }

  boost::weak_ptr<RScaResource> weakResource{};
  (void)RES_GetResource(&weakResource, path, nullptr, resourceType);

  // The binary packages the live referent and reflected type into the RRef
  // and then releases the temporary weak count when `weakResource` falls out
  // of scope. The locked shared_ptr's referent is the same pointer the binary
  // read directly from the weak_ptr `px` lane.
  if (const boost::shared_ptr<RScaResource> liveResource = weakResource.lock(); liveResource) {
    outRef->mObj = liveResource.get();
  } else {
    outRef->mObj = nullptr;
  }
  outRef->mType = resourceType;
  return outRef;
}

} // namespace moho
