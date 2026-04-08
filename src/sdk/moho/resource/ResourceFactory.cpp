#include "moho/resource/ResourceFactory.h"

#include <cstdlib>
#include <cstring>
#include <new>

#include "moho/misc/FileWaitHandleSet.h"
#include "moho/resource/RScmResource.h"
#include "moho/resource/ResourceManager.h"
#include "moho/resource/SScmFile.h"

#pragma init_seg(lib)

namespace
{
  void DeleteScmFileBuffer(const moho::SScmFile* const scmFile) noexcept
  {
    delete[] reinterpret_cast<const char*>(scmFile);
  }

  [[nodiscard]] moho::CScmResourceFactory& ScmResourceFactorySingleton()
  {
    static moho::CScmResourceFactory sFactory;
    return sFactory;
  }

  [[nodiscard]] moho::CScmResourceFactory* AttachScmResourceFactory()
  {
    moho::RES_EnsureResourceManager();

    moho::ResourceManager* const manager = moho::RES_GetResourceManager();
    moho::CScmResourceFactory& factory = ScmResourceFactorySingleton();
    if (manager != nullptr) {
      manager->AttachFactory(&factory);
    }

    return &factory;
  }

  void DetachScmResourceFactory()
  {
    moho::RES_EnsureResourceManager();

    moho::ResourceManager* const manager = moho::RES_GetResourceManager();
    moho::CScmResourceFactory& factory = ScmResourceFactorySingleton();
    if (manager != nullptr) {
      manager->DetachFactory(&factory);
    }
  }

  template <void (*Cleanup)()>
  void RegisterExitCleanup() noexcept
  {
    (void)std::atexit(Cleanup);
  }

  struct ScmResourceFactoryStartupBootstrap
  {
    ScmResourceFactoryStartupBootstrap()
    {
      moho::register_CScmResourceFactory();
    }
  };

  [[maybe_unused]] ScmResourceFactoryStartupBootstrap gScmResourceFactoryStartupBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x00539290 (FUN_00539290, Moho::CScmResourceFactory::Load)
   *
   * What it does:
   * Reads one SCM payload from disk, validates minimum byte length, then
   * materializes one `RScmResource` bound to aliased file bytes.
   */
  CScmResourceFactory::ResourceHandle&
  CScmResourceFactory::Load(ResourceHandle& outResource, const char* const path)
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

    outResource.reset(rawResource);
    return outResource;
  }

  CScmResourceFactory::ResourceHandle&
  CScmResourceFactory::LoadImpl(ResourceHandle& outResource, const char* const path)
  {
    return Load(outResource, path);
  }

  /**
   * Address: 0x00539200 (FUN_00539200, Moho::ResourceFactory_RScmResource::ResourceFactory_RScmResource)
   *
   * What it does:
   * Attaches the process-lifetime SCM resource-factory singleton to
   * `ResourceManager` and returns it.
   */
  CScmResourceFactory* construct_CScmResourceFactory()
  {
    return AttachScmResourceFactory();
  }

  /**
   * Address: 0x00BF3CA0 (FUN_00BF3CA0, Moho::CScmResourceFactory::~CScmResourceFactory teardown lane)
   *
   * What it does:
   * Detaches SCM factory startup registration from the resource-manager
   * singleton.
   */
  void cleanup_CScmResourceFactory()
  {
    DetachScmResourceFactory();
  }

  /**
   * Address: 0x00BC9180 (FUN_00BC9180, register_CScmResourceFactory)
   *
   * What it does:
   * Registers SCM factory startup and schedules process-exit cleanup.
   */
  void register_CScmResourceFactory()
  {
    (void)construct_CScmResourceFactory();
    RegisterExitCleanup<&cleanup_CScmResourceFactory>();
  }
} // namespace moho
