#pragma once

#include <typeinfo>

#include "boost/shared_ptr.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "moho/resource/RScmResource.h"

namespace gpg
{
  class RType;
  RType* LookupRType(const std::type_info& typeInfo);
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E07614
   * COL: 0x00E61FA0
   */
  class ResourceFactoryBase
  {
  public:
    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Optional startup hook consumed by `ResourceManager::AttachFactory`.
     */
    virtual void Init() {}

    /**
     * Address: 0x004AA9DE / 0x004AAA09 call lane in FUN_004AA690
     *
     * What it does:
     * Type-erased resource-load dispatch used by `ResourceManager` resolve
     * paths that operate on raw `(px,pi)` pair lanes.
     */
    virtual boost::SharedCountPair* LoadResourcePair(
      boost::SharedCountPair* outResourcePair,
      const char* path,
      gpg::RType* resourceType
    ) = 0;

    /**
     * Address: 0x004AB371 call lane in FUN_004AB180
     *
     * What it does:
     * Type-erased prefetch dispatch used by prefetch-thread resolve lanes.
     */
    virtual boost::SharedCountPair* PreloadResourcePair(
      boost::SharedCountPair* outPrefetchPair,
      const char* path,
      gpg::RType* resourceType
    ) = 0;

    /**
     * Address: 0x004AA845 call lane in FUN_004AA690
     *
     * What it does:
     * Type-erased load-from-prefetched-data dispatch used by manager resolve
     * paths when a prefetch payload is already available.
     */
    virtual boost::SharedCountPair* LoadResourceFromPrefetchPair(
      boost::SharedCountPair* outResourcePair,
      const char* path,
      gpg::RType* resourceType,
      const boost::SharedCountPair* prefetchPair,
      gpg::RType* prefetchType
    ) = 0;

  protected:
    ~ResourceFactoryBase() = default;
  };

  static_assert(sizeof(ResourceFactoryBase) == 0x04, "ResourceFactoryBase size must be 0x04");

  template <typename TResource>
  class ResourceFactory : public ResourceFactoryBase
  {
  public:
    using ResourceHandle = boost::shared_ptr<TResource>;
    using PrefetchHandle = boost::shared_ptr<TResource>;

    /**
     * Address: 0x0044A320 (FUN_0044A320, Moho::ResourceFactory_SBatchTextureData::Init)
     *
     * What it does:
     * Resolves reflected resource type metadata and updates both resource and
     * prefetch type lanes for this factory.
     */
    void Init() override
    {
      gpg::RType* firstResolvedType = TResource::sType;
      if (firstResolvedType == nullptr) {
        firstResolvedType = gpg::LookupRType(typeid(TResource));
        TResource::sType = firstResolvedType;
      }

      gpg::RType* resolvedType = firstResolvedType;
      if (resolvedType == nullptr) {
        resolvedType = gpg::LookupRType(typeid(TResource));
        TResource::sType = resolvedType;
      }

      mPrefetchType = firstResolvedType;
      mResourceType = resolvedType;
    }

    /**
     * Address: 0x0044A420 (FUN_0044A420, Moho::ResourceFactory_SBatchTextureData::Load)
     * Address: 0x005397F0 (FUN_005397F0, Moho::ResourceFactory_RScmResource::Load wrapper)
     * Address: 0x0053AE00 (FUN_0053AE00, Moho::ResourceFactory_RScaResource::Load wrapper)
     *
     * What it does:
     * Forwards load requests into `LoadImpl` using one temporary handle lane.
     */
    virtual ResourceHandle& Load(ResourceHandle& outResource, const char* path)
    {
      ResourceHandle loadedResource;
      LoadImpl(loadedResource, path);
      outResource = loadedResource;
      return outResource;
    }

    /**
     * Address: 0x0044A4D0 (FUN_0044A4D0, Moho::ResourceFactory_SBatchTextureData::Preload)
     * Address: 0x005398A0 (FUN_005398A0, Moho::ResourceFactory_RScmResource::Preload wrapper)
     * Address: 0x0053AEB0 (FUN_0053AEB0, Moho::ResourceFactory_RScaResource::Preload wrapper)
     *
     * What it does:
     * Forwards preload requests into `PreloadImpl` using one temporary handle lane.
     */
    virtual PrefetchHandle& Preload(PrefetchHandle& outPrefetchData, const char* path)
    {
      PrefetchHandle prefetchedData;
      PreloadImpl(prefetchedData, path);
      outPrefetchData = prefetchedData;
      return outPrefetchData;
    }

    /**
     * Address: 0x0044A580 (FUN_0044A580, Moho::ResourceFactory_SBatchTextureData::LoadFrom)
     *
     * What it does:
     * Forwards load-from-prefetch requests into `LoadFromImpl`.
     */
    virtual ResourceHandle& LoadFrom(ResourceHandle& outResource, const char* path, PrefetchHandle prefetchData)
    {
      PrefetchHandle prefetchCopy = prefetchData;
      ResourceHandle loadedResource;
      LoadFromImpl(loadedResource, path, prefetchCopy);
      outResource = loadedResource;
      return outResource;
    }

    /**
     * What it does:
     * Loads one resource instance from `path`.
     */
    virtual ResourceHandle& LoadImpl(ResourceHandle& outResource, const char* path) = 0;

    /**
     * Address: 0x0044A360 (FUN_0044A360, Moho::ResourceFactory_SBatchTextureData::PreloadImpl)
     * Address: 0x00539730 (FUN_00539730, Moho::ResourceFactory_RScmResource::PreloadImpl)
     * Address: 0x0053AD40 (FUN_0053AD40, Moho::ResourceFactory_RScaResource::PreloadImpl)
     *
     * What it does:
     * Default prefetch implementation that reuses `LoadImpl`.
     */
    virtual PrefetchHandle& PreloadImpl(PrefetchHandle& outPrefetchData, const char* path)
    {
      return LoadImpl(outPrefetchData, path);
    }

    /**
     * Address: 0x00539760 (FUN_00539760, Moho::ResourceFactory_RScmResource::LoadFromImpl)
     * Address: 0x0053AD70 (FUN_0053AD70, Moho::ResourceFactory_RScaResource::LoadFromImpl)
     * Address: 0x0044A390 (FUN_0044A390, Moho::ResourceFactory_SBatchTextureData::LoadFromImpl)
     *
     * What it does:
     * Default load-from-prefetch implementation that returns the prefetch lane.
     */
    virtual ResourceHandle& LoadFromImpl(ResourceHandle& outResource, const char* path, PrefetchHandle prefetchData)
    {
      (void)path;
      outResource = prefetchData;
      return outResource;
    }

    /**
     * Address: 0x004AA9DE / 0x004AAA09 call lane in FUN_004AA690
     */
    boost::SharedCountPair* LoadResourcePair(
      boost::SharedCountPair* const outResourcePair,
      const char* const path,
      gpg::RType* const resourceType
    ) override
    {
      (void)resourceType;
      if (outResourcePair == nullptr) {
        return nullptr;
      }

      ResourceHandle loadedResource{};
      (void)Load(loadedResource, path);
      *outResourcePair = SharedPairFromHandleRetained(loadedResource);
      return outResourcePair;
    }

    /**
     * Address: 0x004AB371 call lane in FUN_004AB180
     */
    boost::SharedCountPair* PreloadResourcePair(
      boost::SharedCountPair* const outPrefetchPair,
      const char* const path,
      gpg::RType* const resourceType
    ) override
    {
      (void)resourceType;
      if (outPrefetchPair == nullptr) {
        return nullptr;
      }

      PrefetchHandle prefetchedResource{};
      (void)Preload(prefetchedResource, path);
      *outPrefetchPair = SharedPairFromHandleRetained(prefetchedResource);
      return outPrefetchPair;
    }

    /**
     * Address: 0x004AA845 call lane in FUN_004AA690
     */
    boost::SharedCountPair* LoadResourceFromPrefetchPair(
      boost::SharedCountPair* const outResourcePair,
      const char* const path,
      gpg::RType* const resourceType,
      const boost::SharedCountPair* const prefetchPair,
      gpg::RType* const prefetchType
    ) override
    {
      (void)resourceType;
      (void)prefetchType;
      if (outResourcePair == nullptr) {
        return nullptr;
      }

      const PrefetchHandle prefetchHandle = HandleFromSharedPairRetained<PrefetchHandle>(prefetchPair);
      ResourceHandle loadedResource{};
      (void)LoadFrom(loadedResource, path, prefetchHandle);
      *outResourcePair = SharedPairFromHandleRetained(loadedResource);
      return outResourcePair;
    }

  protected:
    gpg::RType* mResourceType = nullptr; // +0x04
    gpg::RType* mPrefetchType = nullptr; // +0x08

  private:
    template <class HandleT>
    [[nodiscard]] static boost::SharedCountPair SharedPairFromHandleRetained(const HandleT& handle) noexcept
    {
      const boost::SharedPtrRaw<typename HandleT::element_type> raw =
        boost::SharedPtrRawFromSharedBorrow(handle);
      boost::SharedCountPair pair{};
      pair.px = raw.px;
      pair.pi = raw.pi;
      if (pair.pi != nullptr) {
        pair.pi->add_ref_copy();
      }
      return pair;
    }

    template <class HandleT>
    [[nodiscard]] static HandleT HandleFromSharedPairRetained(const boost::SharedCountPair* const pair) noexcept
    {
      HandleT handle{};
      if (pair == nullptr) {
        return handle;
      }

      auto* const layout =
        reinterpret_cast<boost::SharedPtrLayoutView<typename HandleT::element_type>*>(&handle);
      layout->px = static_cast<typename HandleT::element_type*>(pair->px);
      layout->pi = pair->pi;
      if (layout->pi != nullptr) {
        layout->pi->add_ref_copy();
      }
      return handle;
    }
  };

  class CScmResourceFactory final : public ResourceFactory<RScmResource>
  {
  public:
    using ResourceHandle = boost::shared_ptr<RScmResource>;

    /**
     * Address: 0x005396F0 (FUN_005396F0, Moho::ResourceFactory_RScmResource::Init)
     *
     * What it does:
     * Resolves cached `RScmResource` RTTI and updates the prefetch/resource
     * type lanes used by factory virtual dispatch.
     */
    void Init() override;

    /**
     * Address: 0x00539290 (FUN_00539290, Moho::CScmResourceFactory::Load)
     *
     * What it does:
     * Reads one SCM payload from disk, validates minimum byte length, then
     * materializes one `RScmResource` bound to aliased file bytes.
     */
    ResourceHandle& Load(ResourceHandle& outResource, const char* path) override;

    /**
     * Address: 0x00539950 (FUN_00539950, Moho::ResourceFactory_RScmResource::LoadFrom)
     *
     * What it does:
     * Clones prefetch handle lane, forwards into `LoadFromImpl`, and assigns
     * the loaded resource handle to `outResource`.
     */
    ResourceHandle& LoadFrom(ResourceHandle& outResource, const char* path, ResourceHandle prefetchData) override;

    /**
     * What it does:
     * Shares the same SCM load lane as `Load` for base template dispatch.
     */
    ResourceHandle& LoadImpl(ResourceHandle& outResource, const char* path) override;
  };

  /**
   * Address: 0x00539200 (FUN_00539200, Moho::ResourceFactory_RScmResource::ResourceFactory_RScmResource)
   *
   * What it does:
   * Attaches the process-lifetime SCM resource-factory singleton to
   * `ResourceManager` and returns it.
   */
  [[nodiscard]] CScmResourceFactory* construct_CScmResourceFactory();

  /**
   * Address: 0x00BC9180 (FUN_00BC9180, register_CScmResourceFactory)
   *
   * What it does:
   * Registers SCM factory startup and schedules process-exit cleanup.
   */
  void register_CScmResourceFactory();

  /**
   * Address: 0x00BF3CA0 (FUN_00BF3CA0, Moho::CScmResourceFactory::~CScmResourceFactory teardown lane)
   *
   * What it does:
   * Detaches SCM factory startup registration from the resource-manager
   * singleton.
   */
  void cleanup_CScmResourceFactory();

  static_assert(sizeof(CScmResourceFactory) == 0x0C, "CScmResourceFactory size must be 0x0C");
} // namespace moho
