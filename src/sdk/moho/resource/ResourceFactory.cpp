#include "moho/resource/ResourceFactory.h"

#include <cstring>

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
   * Address: 0x00539290 (FUN_00539290)
   *
   * What it does:
   * Reads one SCM file and wraps it in an `RScmResource`; a missing file or
   * one shorter than the 0x30-byte header loads as nothing.
   *
   * The binary hands the file buffer's own control block to the resource
   * (0x00539E40 aliases `mBegin` onto it); this copies the bytes into a buffer
   * the resource owns instead, since boost 1.34 has no aliasing constructor.
   */
  boost::shared_ptr<RScmResource> CScmResourceFactory::LoadImpl(const gpg::StrArg path)
  {
    const gpg::MemBuffer<char> fileBytes = DISK_ReadFile(path);
    if (fileBytes.mBegin == nullptr) {
      return {};
    }

    const std::size_t byteCount = fileBytes.Size();
    if (byteCount < 0x30u) {
      return {};
    }

    auto* const scmBytes = new char[byteCount];
    std::memcpy(scmBytes, fileBytes.mBegin, byteCount);
    const boost::shared_ptr<const SScmFile> scmFile(
      reinterpret_cast<const SScmFile*>(scmBytes), &DeleteScmFileBuffer
    );

    boost::shared_ptr<RScmResource> resource;
    return *ConstructSharedRScmResourceFromRaw(&resource, new RScmResource(path, scmFile));
  }
} // namespace moho
