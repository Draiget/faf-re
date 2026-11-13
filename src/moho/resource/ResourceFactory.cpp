#include "moho/resource/ResourceFactory.h"

#include "moho/misc/FileWaitHandleSet.h"
#include "moho/resource/RScmResource.h"
#include "moho/resource/ResourceManager.h"
#include "moho/resource/SScmFile.h"

namespace
{
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
   * Address: 0x00539290 (FUN_00539290)
   *
   * What it does:
   * Reads one SCM file and wraps it in an `RScmResource`; a missing file or
   * one shorter than the 0x30-byte header loads as nothing.
   *
   * The resource shares the file buffer's own owner, as the binary does
   * (0x00539E7A: `px = mBegin`, then the buffer's `pn` retained at 0x00539E93).
   *
   * Address: 0x00539E40 (FUN_00539E40 -- that aliasing `shared_ptr<SScmFile const>`
   * construction from the `MemBuffer<char>`.)
   * Address: 0x0053A100 (FUN_0053A100 -- `shared_count(RScmResource*)`) and
   * 0x00539EC0 (FUN_00539EC0 -- the `shared_ptr<RScmResource>(RScmResource*)`
   * wrapper around it that also binds `enable_shared_from_this`); formerly
   * `ConstructSharedRScmResourceFromRaw` in RScmResource.cpp.
   */
  std::shared_ptr<RScmResource> CScmResourceFactory::LoadImpl(
    const gpg::StrArg path
  )
  {
    const gpg::MemBuffer<char> fileBytes = DISK_ReadFile(path);
    if (fileBytes.mBegin == nullptr) {
      return {};
    }

    const std::size_t byteCount = fileBytes.Size();
    if (byteCount < 0x30u) {
      return {};
    }

    const std::shared_ptr<const SScmFile> scmFile(fileBytes.mData, reinterpret_cast<const SScmFile*>(fileBytes.mBegin));

    const std::shared_ptr<RScmResource> resource(new RScmResource(path, scmFile));
    if (!RScmResource::KeepGeometry()) {
      resource->DropGeometry();
    }
    return resource;
  }
} // namespace moho
