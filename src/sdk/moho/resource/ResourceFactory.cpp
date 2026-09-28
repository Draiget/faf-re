#include "moho/resource/ResourceFactory.h"

#include <cstdlib>
#include <cstring>
#include <new>

#include "moho/misc/FileWaitHandleSet.h"
#include "moho/resource/RScmResource.h"
#include "moho/resource/ResourceManager.h"
#include "moho/resource/SScmFile.h"

namespace
{
  void DeleteScmFileBuffer(const moho::SScmFile* const scmFile) noexcept
  {
    delete[] reinterpret_cast<const char*>(scmFile);
  }

  /**
   * Address: 0x00BC9180 (FUN_00BC9180, dynamic initializer for `sScmResourceFactory`)
   * Address: 0x00BF3CA0 (FUN_00BF3CA0, dynamic atexit destructor for `sScmResourceFactory`)
   *
   * What it does:
   * The process-lifetime `.scm` factory; constructing it attaches it to the
   * resource manager and destroying it detaches it.
   */
  moho::CScmResourceFactory sScmResourceFactory;
} // namespace

namespace moho
{
  ResourceFactoryBase::ResourceFactoryBase()
  {
    RES_GetResourceManager()->AttachFactory(this);
  }

  ResourceFactoryBase::~ResourceFactoryBase()
  {
    RES_GetResourceManager()->DetachFactory(this);
  }

  /**
   * Address: 0x005396F0 (FUN_005396F0, Moho::ResourceFactory_RScmResource::Init)
   *
   * What it does:
   * Resolves cached `RScmResource` RTTI and updates the prefetch/resource
   * type lanes used by factory virtual dispatch.
   */
  void CScmResourceFactory::Init()
  {
    gpg::RType* firstResolvedType = RScmResource::sType;
    if (firstResolvedType == nullptr) {
      firstResolvedType = gpg::LookupRType(typeid(RScmResource));
      RScmResource::sType = firstResolvedType;
    }

    gpg::RType* resolvedType = firstResolvedType;
    if (resolvedType == nullptr) {
      resolvedType = gpg::LookupRType(typeid(RScmResource));
      RScmResource::sType = resolvedType;
    }

    mPrefetchType = firstResolvedType;
    mResourceType = resolvedType;
  }

  /**
   * Address: 0x00539290 (FUN_00539290) -- vtable slot 4, the pure slot
   * `ResourceFactory<RScmResource>` declares. Slots 1..3 stay the
   * template's own `Load`/`Preload`/`LoadFrom` in both vftables.
   *
   * What it does:
   * Reads one SCM payload from disk, validates minimum byte length, then
   * materializes one `RScmResource` bound to aliased file bytes.
   */
  CScmResourceFactory::ResourceHandle&
  CScmResourceFactory::LoadImpl(ResourceHandle& outResource, const char* const path)
  {
    outResource.reset();

    gpg::MemBuffer<char> fileBytes = DISK_ReadFile(path);
    if (fileBytes.mBegin == nullptr) {
      return outResource;
    }

    const std::size_t byteCount = static_cast<std::size_t>(fileBytes.mEnd - fileBytes.mBegin);
    if (byteCount < 0x30u) {
      return outResource;
    }

    auto* const scmBytes = new (std::nothrow) char[byteCount];
    if (scmBytes == nullptr) {
      return outResource;
    }
    std::memcpy(scmBytes, fileBytes.mBegin, byteCount);

    const boost::shared_ptr<const SScmFile> scmFile(
      reinterpret_cast<const SScmFile*>(scmBytes),
      &DeleteScmFileBuffer
    );

    RScmResource* const rawResource = new (std::nothrow) RScmResource(path, scmFile);
    if (rawResource == nullptr) {
      return outResource;
    }

    ConstructSharedRScmResourceFromRaw(&outResource, rawResource);
    return outResource;
  }

} // namespace moho
