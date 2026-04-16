#include "moho/resource/RScmResource.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/animation/CAniSkel.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/math/Vector3f.h"
#include "moho/resource/ResourceManager.h"
#include "moho/resource/SScmFile.h"
#include "moho/serialization/PrefetchHandleBase.h"

#pragma init_seg(lib)

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

  SerSaveLoadHelperNodeRuntime gRScmResourceSaveConstructHelper{};
  SerSaveLoadHelperNodeRuntime gRScmResourceConstructHelper{};

  [[nodiscard]] gpg::RType* ResolveRScmResourceTypeCached() noexcept
  {
    gpg::RType* resourceType = moho::RScmResource::sType;
    if (resourceType == nullptr) {
      resourceType = gpg::LookupRType(typeid(moho::RScmResource));
      moho::RScmResource::sType = resourceType;
    }
    return resourceType;
  }

  [[nodiscard]] boost::shared_ptr<moho::RScmResource> GetModelResourceByPath(
    const char* const path,
    moho::CResourceWatcher* const resourceWatcher
  )
  {
    boost::weak_ptr<moho::RScmResource> weakResource{};
    (void)moho::RES_GetResource(
      &weakResource,
      path,
      resourceWatcher,
      ResolveRScmResourceTypeCached()
    );
    return weakResource.lock();
  }

  void SetConstructResultSharedRScmResource(
    gpg::SerConstructResult* const result,
    const boost::shared_ptr<moho::RScmResource>& resource
  )
  {
    const boost::shared_ptr<void>& sharedAny =
      reinterpret_cast<const boost::shared_ptr<void>&>(resource);
    result->SetShared(sharedAny, ResolveRScmResourceTypeCached(), 1u);
  }

  struct RScmResourcePrefetchBootstrap
  {
    RScmResourcePrefetchBootstrap()
    {
      moho::register_RScmResourceModelPrefetchType();
    }
  };

  RScmResourcePrefetchBootstrap gRScmResourcePrefetchBootstrap;
} // namespace

namespace moho
{
  gpg::RType* RScmResource::sType = nullptr;

  /**
   * Address: 0x00538F10 (FUN_00538F10)
   *
   * What it does:
   * Unlinks `RScmResource` save-construct helper links and restores the node
   * to self-linked sentinel state.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupRScmResourceSaveConstructHelperPrimary() noexcept
  {
    return UnlinkSerSaveLoadHelperNode(gRScmResourceSaveConstructHelper);
  }

  /**
   * Address: 0x00538F40 (FUN_00538F40)
   *
   * What it does:
   * Secondary entrypoint for unlink/reset of the same
   * `RScmResource` save-construct helper lane.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupRScmResourceSaveConstructHelperSecondary() noexcept
  {
    return UnlinkSerSaveLoadHelperNode(gRScmResourceSaveConstructHelper);
  }

  /**
   * Address: 0x00539060 (FUN_00539060)
   *
   * What it does:
   * Unlinks `RScmResource` construct-helper links and restores the node to
   * self-linked sentinel state.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupRScmResourceConstructHelperPrimary() noexcept
  {
    return UnlinkSerSaveLoadHelperNode(gRScmResourceConstructHelper);
  }

  /**
   * Address: 0x00539090 (FUN_00539090)
   *
   * What it does:
   * Secondary entrypoint for unlink/reset of the same
   * `RScmResource` construct-helper lane.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupRScmResourceConstructHelperSecondary() noexcept
  {
    return UnlinkSerSaveLoadHelperNode(gRScmResourceConstructHelper);
  }

  /**
   * Address: 0x00538BF0 (FUN_00538BF0,
   * ??0RScmResource@Moho@@QAE@VStrArg@gpg@@ABV?$shared_ptr@$$CBUSScmFile@Moho@@@boost@@@Z)
   *
   * What it does:
   * Binds one SCM data-owner lane + resource path and computes cached
   * bounds/size from embedded bone-bounds samples.
   */
  RScmResource::RScmResource(const gpg::StrArg resourcePath, const boost::shared_ptr<const SScmFile>& scmFile) :
    mName(resourcePath),
    mFile(scmFile),
    mSkeleton(nullptr),
    mBounds(Empty<Wm3::AxisAlignedBox3f>()),
    mSize(0.0f)
  {
    const std::int32_t sampleCount = static_cast<std::int32_t>(mFile->mBoneBoundsSampleCount);
    const SScmBoneBoundsSample* const samples = scm_file::GetBoneBoundsSamples(*mFile);

    for (std::int32_t sampleIndex = 0; sampleIndex < sampleCount; ++sampleIndex) {
      const SScmBoneBoundsSample& sample = samples[sampleIndex];

      if (sample.mLocalPositionX < mBounds.Min.x) {
        mBounds.Min.x = sample.mLocalPositionX;
      }
      if (sample.mLocalPositionY < mBounds.Min.y) {
        mBounds.Min.y = sample.mLocalPositionY;
      }
      if (sample.mLocalPositionZ < mBounds.Min.z) {
        mBounds.Min.z = sample.mLocalPositionZ;
      }

      if (sample.mLocalPositionX > mBounds.Max.x) {
        mBounds.Max.x = sample.mLocalPositionX;
      }
      if (sample.mLocalPositionY > mBounds.Max.y) {
        mBounds.Max.y = sample.mLocalPositionY;
      }
      if (sample.mLocalPositionZ > mBounds.Max.z) {
        mBounds.Max.z = sample.mLocalPositionZ;
      }
    }

    Wm3::Vector3f axisExtents{};
    axisExtents.x = mBounds.Max.x - mBounds.Min.x;
    axisExtents.y = mBounds.Max.y - mBounds.Min.y;
    axisExtents.z = mBounds.Max.z - mBounds.Min.z;

    const int dominantAxis = VEC_LargestAxis(axisExtents);
    const float* const extentLanes = &axisExtents.x;
    mSize = extentLanes[dominantAxis] * 1.2f;
  }

  /**
   * Address: 0x00539FB0 (FUN_00539FB0)
   *
   * What it does:
   * Releases owned skeleton payload and tears down shared resource lanes.
   */
  RScmResource::~RScmResource()
  {
    delete mSkeleton;
    mSkeleton = nullptr;
  }

  /**
   * Address: 0x00538DB0 (FUN_00538DB0, ?GetSkeleton@RScmResource@Moho@@QAE?AV?$shared_ptr@$$CBVCAniSkel@Moho@@@boost@@XZ)
   *
   * What it does:
   * Returns one shared handle to the owned skeleton lane by aliasing this
   * resource's shared-control block.
   */
  boost::shared_ptr<const CAniSkel> RScmResource::GetSkeleton()
  {
    if (mSkeleton == nullptr) {
      return boost::shared_ptr<const CAniSkel>();
    }

    struct KeepOwnerAlive
    {
      boost::shared_ptr<RScmResource> owner;
      void operator()(const CAniSkel*) const {}
    };

    KeepOwnerAlive keepOwner{shared_from_this()};
    return boost::shared_ptr<const CAniSkel>(mSkeleton, keepOwner);
  }

  /**
   * Address: 0x00539EC0 (FUN_00539EC0)
   * Mangled: ??4shared_ptr_RScmResource@boost@@QAE@@Z
   *
   * What it does:
   * Constructs one `shared_ptr<RScmResource>` from one raw resource lane,
   * including `enable_shared_from_this` ownership binding.
   */
  boost::shared_ptr<RScmResource>* ConstructSharedRScmResourceFromRaw(
    boost::shared_ptr<RScmResource>* const outResource,
    RScmResource* const resource
  )
  {
    return ::new (outResource) boost::shared_ptr<RScmResource>(resource);
  }

  /**
   * Address: 0x00539D80 (FUN_00539D80)
   *
   * What it does:
   * Packages one shared `RScmResource` lane into construct-result shared
   * payload with resolved `RScmResource` runtime type metadata.
   */
  void SetConstructResultSharedModelResource(
    gpg::SerConstructResult* const result,
    const boost::shared_ptr<RScmResource>& resource
  )
  {
    SetConstructResultSharedRScmResource(result, resource);
  }

  /**
   * Address: 0x005390C0 (FUN_005390C0)
   *
   * What it does:
   * Reads one model path from archive, resolves/loads the referenced SCM
   * resource, and forwards it into construct-result shared ownership.
   */
  void Construct_RScmResource(
    gpg::ReadArchive* const archive,
    const int,
    const int,
    gpg::SerConstructResult* const result
  )
  {
    msvc8::string modelPath{};
    archive->ReadString(&modelPath);

    const boost::shared_ptr<RScmResource> modelResource =
      GetModelResourceByPath(modelPath.c_str(), nullptr);
    SetConstructResultSharedModelResource(result, modelResource);
  }

  /**
   * Address: 0x00538F70 (FUN_00538F70)
   *
   * What it does:
   * Writes one mounted-path string save-construct arg for one `RScmResource`
   * and marks the construct-result ownership lane as shared.
   */
  void SaveConstructArgs_RScmResource(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    const auto* const resource = reinterpret_cast<const RScmResource*>(static_cast<std::uintptr_t>(objectPtr));

    msvc8::string mountedPath{};
    (void)FILE_ToMountedPath(&mountedPath, resource->mName.c_str());
    archive->WriteString(&mountedPath);
    result->SetShared(1u);
  }

  /**
   * Address: 0x00538EF0 (FUN_00538EF0)
   *
   * What it does:
   * Thin callback thunk forwarding save-construct arg serialization for one
   * `RScmResource`.
   */
  void SaveConstructArgs_RScmResourceThunk(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    SaveConstructArgs_RScmResource(archive, objectPtr, version, ownerRef, result);
  }

  /**
   * Address: 0x00BC91A0 (FUN_00BC91A0)
   *
   * What it does:
   * Resolves `RScmResource` RTTI and registers the `"models"` prefetch lane.
   */
  void register_RScmResourceModelPrefetchType()
  {
    gpg::RType* resourceType = RScmResource::sType;
    if (resourceType == nullptr) {
      resourceType = gpg::LookupRType(typeid(RScmResource));
      RScmResource::sType = resourceType;
    }

    RES_RegisterPrefetchType("models", resourceType);
  }
} // namespace moho
