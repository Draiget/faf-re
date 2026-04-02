#pragma once

#include <typeinfo>

#include "boost/shared_ptr.h"
#include "gpg/core/utils/BoostWrappers.h"

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
     *
     * What it does:
     * Default prefetch implementation that reuses `LoadImpl`.
     */
    virtual PrefetchHandle& PreloadImpl(PrefetchHandle& outPrefetchData, const char* path)
    {
      return LoadImpl(outPrefetchData, path);
    }

    /**
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
} // namespace moho
