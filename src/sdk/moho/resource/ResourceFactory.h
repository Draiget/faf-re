#pragma once

#include "boost/noncopyable.hpp"
#include "boost/shared_ptr.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/resource/RScmResource.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E07614
   * COL: 0x00E61FA0
   *
   * The type-erased face of a resource loader. `ResourceManager` keeps its
   * factories keyed on `mResourceType` and drives them through the four slots
   * below; the typed templates underneath forward each one into a typed
   * `*Impl` that a concrete factory fills in.
   */
  class ResourceFactoryBase : private boost::noncopyable
  {
  public:
    /**
     * Address: 0x00A82547 (FUN_00A82547, _purecall slot)
     *
     * What it does:
     * Resolves `mResourceType` / `mPrefetchType`. `ResourceManager::
     * ActivatePendingFactories` (0x004AA090) calls it before registering the
     * factory under `mResourceType`.
     */
    virtual void Init() = 0;

    /**
     * Slot 1. `ResourceManager::LoadRequest` (0x004AAA24) calls it with the
     * request's type when nothing was prefetched.
     */
    virtual boost::shared_ptr<void> Load(gpg::StrArg path, const gpg::RType* type) = 0;

    /**
     * Slot 2. The prefetch thread (0x004AB441) calls it with `mPrefetchType`.
     */
    virtual boost::shared_ptr<void> Preload(gpg::StrArg path, const gpg::RType* type) = 0;

    /**
     * Slot 3. `ResourceManager::LoadRequest` (0x004AA845) calls it when the
     * prefetch thread already produced `prefetchData`.
     */
    virtual boost::shared_ptr<void> LoadFrom(
      gpg::StrArg path, const gpg::RType* type, boost::shared_ptr<void> prefetchData, const gpg::RType* prefetchType
    ) = 0;

    /** What `Load` produces; the manager's registration key (factory +0x04). */
    const gpg::RType* mResourceType = nullptr; // +0x04
    /** What `Preload` produces and `LoadFrom` consumes (factory +0x08). */
    const gpg::RType* mPrefetchType = nullptr; // +0x08

  protected:
    /**
     * What it does:
     * Attaches this factory to the resource manager. Every factory
     * constructor in the binary inlines this: it stores this vftable
     * (0x00E07614), calls `RES_GetResourceManager()->AttachFactory(this)`,
     * then stores the derived vftable.
     */
    ResourceFactoryBase();

    /**
     * What it does:
     * Detaches this factory from the resource manager (inlined into every
     * factory destructor after the base vftable is restored).
     */
    ~ResourceFactoryBase();
  };

  static_assert(sizeof(ResourceFactoryBase) == 0x0C, "ResourceFactoryBase size must be 0x0C");

  /**
   * A factory whose prefetch step produces the resource itself: `Preload`
   * defaults to `LoadImpl` and `LoadFrom` hands the prefetched object straight
   * back, so a concrete factory only supplies `LoadImpl`.
   */
  template <class T>
  class ResourceFactory : public ResourceFactoryBase
  {
  public:
    /**
     * Address: 0x00539200 (FUN_00539200, Moho::ResourceFactory_RScmResource::ResourceFactory_RScmResource)
     * Address: 0x0053AA40 (FUN_0053AA40, Moho::ResourceFactory_RScaResource::ResourceFactory_RScaResource)
     * Address: 0x00448090 (FUN_00448090, Moho::ResourceFactory_SBatchTextureData::ResourceFactory_SBatchTextureData)
     *
     * What it does:
     * Runs the attaching base constructor, then installs this vftable. The
     * binary keeps one out-of-line copy per resource type, each with `this`
     * folded to the one static factory object.
     */
    ResourceFactory() = default;

    /**
     * Address: 0x0044A320 (FUN_0044A320, Moho::ResourceFactory_SBatchTextureData::Init)
     * Address: 0x005396F0 (FUN_005396F0, Moho::ResourceFactory_RScmResource::Init)
     * Address: 0x0053AD00 (FUN_0053AD00, Moho::ResourceFactory_RScaResource::Init)
     *
     * What it does:
     * Both type slots are `T`: the prefetch step produces the resource itself.
     * The binary resolves the cached type twice, prefetch slot first.
     */
    void Init() override
    {
      mPrefetchType = gpg::RTypeOf<T>();
      mResourceType = gpg::RTypeOf<T>();
    }

    /**
     * Address: 0x0044A420 (FUN_0044A420, Moho::ResourceFactory_SBatchTextureData::Load)
     * Address: 0x005397F0 (FUN_005397F0, Moho::ResourceFactory_RScmResource::Load)
     * Address: 0x0053AE00 (FUN_0053AE00, Moho::ResourceFactory_RScaResource::Load)
     */
    boost::shared_ptr<void> Load(const gpg::StrArg path, const gpg::RType*) override
    {
      return LoadImpl(path);
    }

    /**
     * Address: 0x0044A4D0 (FUN_0044A4D0, Moho::ResourceFactory_SBatchTextureData::Preload)
     * Address: 0x005398A0 (FUN_005398A0, Moho::ResourceFactory_RScmResource::Preload)
     * Address: 0x0053AEB0 (FUN_0053AEB0, Moho::ResourceFactory_RScaResource::Preload)
     */
    boost::shared_ptr<void> Preload(const gpg::StrArg path, const gpg::RType*) override
    {
      return PreloadImpl(path);
    }

    /**
     * Address: 0x0044A580 (FUN_0044A580, Moho::ResourceFactory_SBatchTextureData::LoadFrom)
     * Address: 0x00539950 (FUN_00539950, Moho::ResourceFactory_RScmResource::LoadFrom)
     * Address: 0x0053AF60 (FUN_0053AF60, Moho::ResourceFactory_RScaResource::LoadFrom)
     */
    boost::shared_ptr<void> LoadFrom(
      const gpg::StrArg path, const gpg::RType*, const boost::shared_ptr<void> prefetchData, const gpg::RType*
    ) override
    {
      return LoadFromImpl(path, boost::static_pointer_cast<T>(prefetchData));
    }

    /** Slot 4, pure here; the concrete factory's loader. */
    virtual boost::shared_ptr<T> LoadImpl(gpg::StrArg path) = 0;

    /**
     * Address: 0x0044A360 (FUN_0044A360, Moho::ResourceFactory_SBatchTextureData::PreloadImpl)
     * Address: 0x00539730 (FUN_00539730, Moho::ResourceFactory_RScmResource::PreloadImpl)
     * Address: 0x0053AD40 (FUN_0053AD40, Moho::ResourceFactory_RScaResource::PreloadImpl)
     */
    virtual boost::shared_ptr<T> PreloadImpl(const gpg::StrArg path)
    {
      return LoadImpl(path);
    }

    /**
     * Address: 0x0044A390 (FUN_0044A390, Moho::ResourceFactory_SBatchTextureData::LoadFromImpl)
     * Address: 0x00539760 (FUN_00539760, Moho::ResourceFactory_RScmResource::LoadFromImpl)
     * Address: 0x0053AD70 (FUN_0053AD70, Moho::ResourceFactory_RScaResource::LoadFromImpl)
     */
    virtual boost::shared_ptr<T> LoadFromImpl(gpg::StrArg, const boost::shared_ptr<T> prefetchData)
    {
      return prefetchData;
    }
  };

  /**
   * A factory whose prefetch step produces a different object `P` (raw file
   * bytes, say) that `LoadFromImpl` turns into the resource. All three `*Impl`
   * slots are pure (vftable 0x00E02958 holds `_purecall` in slots 4-6).
   */
  template <class T, class P>
  class ResourceFactoryPreload : public ResourceFactoryBase
  {
  public:
    /**
     * Address: 0x0043E470 (FUN_0043E470, ??0ResourceFactoryPreload@Moho@@QAE@@Z)
     */
    ResourceFactoryPreload() = default;

    /**
     * Address: 0x004434E0 (FUN_004434E0, Moho::ResourceFactoryPreload_RD3DTextureResource::Init)
     */
    void Init() override
    {
      mPrefetchType = gpg::RTypeOf<P>();
      mResourceType = gpg::RTypeOf<T>();
    }

    /**
     * Address: 0x00443530 (FUN_00443530, Moho::ResourceFactoryPreload_RD3DTextureResource::Load)
     */
    boost::shared_ptr<void> Load(const gpg::StrArg path, const gpg::RType*) override
    {
      return LoadImpl(path);
    }

    /**
     * Address: 0x004435E0 (FUN_004435E0, Moho::ResourceFactoryPreload_RD3DTextureResource::Preload)
     */
    boost::shared_ptr<void> Preload(const gpg::StrArg path, const gpg::RType*) override
    {
      return PreloadImpl(path);
    }

    /**
     * Address: 0x00443690 (FUN_00443690, Moho::ResourceFactoryPreload_RD3DTextureResource::LoadFrom)
     */
    boost::shared_ptr<void> LoadFrom(
      const gpg::StrArg path, const gpg::RType*, const boost::shared_ptr<void> prefetchData, const gpg::RType*
    ) override
    {
      return LoadFromImpl(path, boost::static_pointer_cast<P>(prefetchData));
    }

    virtual boost::shared_ptr<T> LoadImpl(gpg::StrArg path) = 0;
    virtual boost::shared_ptr<P> PreloadImpl(gpg::StrArg path) = 0;
    virtual boost::shared_ptr<T> LoadFromImpl(gpg::StrArg path, boost::shared_ptr<P> prefetchData) = 0;
  };

  class CScmResourceFactory final : public ResourceFactory<RScmResource>
  {
  public:
    /**
     * Address: 0x005391A0 (FUN_005391A0, Moho::CScmResourceFactory::CScmResourceFactory)
     *
     * What it does:
     * Out-of-line copy of the constructor (`this` folded to the static
     * factory): the attaching template constructor, then this vftable
     * (0x00E163B0).
     */
    CScmResourceFactory() = default;

    /**
     * Address: 0x005391C0 (FUN_005391C0, Moho::CScmResourceFactory::~CScmResourceFactory)
     *
     * What it does:
     * Out-of-line copy of the destructor: restores the base vftable and
     * detaches from the resource manager.
     */
    ~CScmResourceFactory() = default;

    /**
     * Address: 0x00539290 (FUN_00539290)
     * Vtable slot 4 of ??_7CScmResourceFactory@Moho@@6B@ (0x00E163B0), the
     * only slot it overrides; slots 0..3 and 5..6 are the template's.
     *
     * What it does:
     * Reads one SCM file and wraps it in an `RScmResource`; files shorter than
     * the 0x30-byte header load as nothing.
     */
    boost::shared_ptr<RScmResource> LoadImpl(gpg::StrArg path) override;
  };

  static_assert(sizeof(CScmResourceFactory) == 0x0C, "CScmResourceFactory size must be 0x0C");
} // namespace moho
