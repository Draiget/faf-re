// RScaResource recovered implementation.

#include "moho/resource/RScaResource.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/resource/ResourceManager.h"

#include <cstring>
#include <new>
#include <typeinfo>

namespace moho
{

gpg::RType* RScaResource::sType = nullptr;

/**
 * Address: 0x0053AD00 (FUN_0053AD00, Moho::ResourceFactory_RScaResource::Init)
 *
 * What it does:
 * Resolves cached `RScaResource` RTTI and updates the prefetch/resource
 * type lanes used by factory virtual dispatch.
 */
void CScaResourceFactory::Init()
{
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
