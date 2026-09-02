#include "moho/resource/RScmResource.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/animation/CAniSkel.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/resource/CAniResourceSkel.h"
#include "moho/math/Vector3f.h"
#include "moho/resource/ResourceManager.h"
#include "moho/resource/SScmFile.h"
#include "moho/serialization/PrefetchHandleBase.h"

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
  // Forward declarations: real definitions sit further down in this TU;
  // RScmResourceConstruct/RScmResourceSaveConstruct's ctors below only need
  // the signatures to bind their callback pointers.
  void Construct_RScmResource(gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result);
  void DeleteRScmResource(void* self);
  void SaveConstructArgs_RScmResourceThunk(
    gpg::WriteArchive* archive,
    int objectPtr,
    int version,
    gpg::RRef* ownerRef,
    gpg::SerSaveConstructArgsResult* result
  );
} // namespace moho

namespace
{
  // Forward declaration: real definition sits in the second anonymous
  // namespace further down in this TU, after CleanupRScmResourceConstructHelperPrimary
  // (namespace moho) is visible. Both anonymous-namespace blocks are the same
  // namespace for the whole translation unit.
  void CleanupRScmResourceConstructHelperAtExit();

  [[nodiscard]] gpg::RType* ResolveRScmResourceTypeCached() noexcept
  {
    gpg::RType* resourceType = moho::RScmResource::sType;
    if (resourceType == nullptr) {
      resourceType = gpg::LookupRType(typeid(moho::RScmResource));
      moho::RScmResource::sType = resourceType;
    }
    return resourceType;
  }

  /**
   * Demangled: gpg::SerSaveConstructHelper<class Moho::RScmResource>
   *
   * What it does:
   * Binds the save-construct-args callback used to serialize `RScmResource`
   * pointer lanes by mounted-path string. Base-class construction
   * (`gpg::SerHelperBase::SerHelperBase`) self-links this node and splices it
   * into the pending `sNewHelpers` list; `InitNewHelpers` later dispatches
   * `Init()` on it.
   */
  class RScmResourceSaveConstruct : public gpg::SerHelperBase
  {
  public:
    RScmResourceSaveConstruct();

    /**
     * Address: 0x00539620 (FUN_00539620, gpg::SerSaveConstructHelper<Moho::RScmResource>::Init)
     *
     * IDA signature:
     * gpg::RType *__thiscall sub_539620(SerSaveConstructHelperView *this);
     *
     * What it does:
     * Lazily resolves the `RScmResource` reflection descriptor, asserts the
     * save-construct-args callback slot is empty, and publishes this helper's
     * save-construct-args callback to the descriptor.
     */
    void Init() override;

  public:
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback;
  };
  static_assert(
    offsetof(RScmResourceSaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "RScmResourceSaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(sizeof(RScmResourceSaveConstruct) == 0x10, "RScmResourceSaveConstruct size must be 0x10");

  RScmResourceSaveConstruct::RScmResourceSaveConstruct()
    : mSaveConstructArgsCallback(
        reinterpret_cast<gpg::RType::save_construct_args_func_t>(&moho::SaveConstructArgs_RScmResourceThunk)
      )
  {}

  void RScmResourceSaveConstruct::Init()
  {
    constexpr const char* kSaveConstructAssertText = "!type->mSerSaveConstructArgsFunc";
    constexpr int kSerializationSaveConstructLine = 189;
    constexpr const char* kSerializationSourcePath =
      "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";

    gpg::RType* const type = ResolveRScmResourceTypeCached();
    if (type->serSaveConstructArgsFunc_ != nullptr) {
      gpg::HandleAssertFailure(
        kSaveConstructAssertText,
        kSerializationSaveConstructLine,
        kSerializationSourcePath
      );
    }
    type->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }

  RScmResourceSaveConstruct gRScmResourceSaveConstructHelper;

  /**
   * Demangled: gpg::SerConstructHelper<class Moho::RScmResource>
   *
   * What it does:
   * Binds the construct/delete callbacks used to materialize `RScmResource`
   * references during load. Base-class construction
   * (`gpg::SerHelperBase::SerHelperBase`) self-links this node and splices it
   * into the pending `sNewHelpers` list; `InitNewHelpers` later dispatches
   * `Init()` on it.
   */
  class RScmResourceConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC9140 (FUN_00BC9140, register_RScmResourceConstructHelper)
     *
     * What it does:
     * Binds `Construct_RScmResource` / `DeleteRScmResource` as this helper's
     * construct/delete callbacks (type-erased through
     * `gpg::RType::construct_func_t` / `delete_func_t`) and registers
     * process-exit cleanup. The published callbacks are later copied onto
     * `RScmResource`'s reflected `RType` by `Init()` (0x005396A0) when the
     * pending helper list is drained.
     */
    RScmResourceConstruct();

    /**
     * Address: 0x005396A0 (FUN_005396A0, gpg::SerConstructHelper<Moho::RScmResource>::Init)
     *
     * IDA signature:
     * void(__cdecl *) __thiscall sub_5396A0(SerConstructHelperView *this);
     *
     * What it does:
     * Lazily resolves the `RScmResource` reflection descriptor, asserts the
     * construct callback slot is empty, and publishes this helper's
     * construct/delete callbacks to the descriptor.
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };
  static_assert(
    offsetof(RScmResourceConstruct, mConstructCallback) == 0x0C,
    "RScmResourceConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(RScmResourceConstruct, mDeleteCallback) == 0x10,
    "RScmResourceConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(RScmResourceConstruct) == 0x14, "RScmResourceConstruct size must be 0x14");

  RScmResourceConstruct::RScmResourceConstruct()
    : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&moho::Construct_RScmResource))
    , mDeleteCallback(&moho::DeleteRScmResource)
  {
    (void)std::atexit(&CleanupRScmResourceConstructHelperAtExit);
  }

  void RScmResourceConstruct::Init()
  {
    constexpr const char* kConstructAssertText = "!type->mSerConstructFunc";
    constexpr int kSerializationConstructLine = 231;
    constexpr const char* kSerializationSourcePath =
      "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";

    gpg::RType* const type = ResolveRScmResourceTypeCached();
    if (type->serConstructFunc_ != nullptr) {
      gpg::HandleAssertFailure(kConstructAssertText, kSerializationConstructLine, kSerializationSourcePath);
    }
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }

  RScmResourceConstruct gRScmResourceConstructHelper;

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
  [[maybe_unused]] void CleanupRScmResourceSaveConstructHelperPrimary() noexcept
  {
    gRScmResourceSaveConstructHelper.ResetLinks();
  }

  /**
   * Address: 0x00538F40 (FUN_00538F40)
   *
   * What it does:
   * Secondary entrypoint for unlink/reset of the same
   * `RScmResource` save-construct helper lane.
   */
  [[maybe_unused]] void CleanupRScmResourceSaveConstructHelperSecondary() noexcept
  {
    gRScmResourceSaveConstructHelper.ResetLinks();
  }

  /**
   * Address: 0x00539060 (FUN_00539060)
   *
   * What it does:
   * Unlinks `RScmResource` construct-helper links and restores the node to
   * self-linked sentinel state. Reused as the body of the process-exit
   * cleanup registered by `RScmResourceConstruct`'s constructor (0x00BC9140,
   * atexit target 0x00BF3C70): the real 0x00BF3C70 thunk performs the
   * identical unlink sequence on the same global inline.
   */
  void CleanupRScmResourceConstructHelperPrimary() noexcept
  {
    gRScmResourceConstructHelper.ResetLinks();
  }

  /**
   * Address: 0x00539090 (FUN_00539090)
   *
   * What it does:
   * Secondary entrypoint for unlink/reset of the same
   * `RScmResource` construct-helper lane.
   */
  [[maybe_unused]] void CleanupRScmResourceConstructHelperSecondary() noexcept
  {
    gRScmResourceConstructHelper.ResetLinks();
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
   * Address: 0x00539D40 (FUN_00539D40, gpg::RType::delete_func_t callback for
   * Moho::RScmResourceConstruct)
   *
   * IDA signature:
   * void __cdecl sub_539D40(void *a1);
   *
   * What it does:
   * `gpg::RType::delete_func_t`-shaped callback installed alongside
   * `Construct_RScmResource` by `register_RScmResourceConstructHelper`
   * (0x00BC9140). Destroys one heap-allocated `RScmResource` in place
   * (destructor, then `operator delete`) when non-null -- the same shape as
   * `RType::deleteFunc_` uses to release constructed objects everywhere else
   * in the reflection system.
   */
  void DeleteRScmResource(void* const self)
  {
    if (self != nullptr) {
      static_cast<RScmResource*>(self)->~RScmResource();
      operator delete(self);
    }
  }

  /**
   * Address: 0x00538DB0 (FUN_00538DB0, ?GetSkeleton@RScmResource@Moho@@QAE?AV?$shared_ptr@$$CBVCAniSkel@Moho@@@boost@@XZ)
   *
   * What it does:
   * Lazily constructs the owned skeleton on first request by parsing this
   * resource's SCM file into a `CAniResourceSkel` (allocated with
   * `operator new(0x48)`), then returns one shared handle that aliases this
   * resource's own shared-control block so the skeleton stays alive for as long
   * as the returned handle does.
   */
  boost::shared_ptr<const CAniSkel> RScmResource::GetSkeleton()
  {
    if (mSkeleton == nullptr) {
      // The binary allocates a 0x48-byte CAniResourceSkel and constructs it
      // from this resource's name + SCM file, storing it through the CAniSkel*
      // base pointer lane.
      CAniSkel* const previousSkeleton = mSkeleton;
      mSkeleton = new CAniResourceSkel(mName, mFile);
      delete previousSkeleton;
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
   * Address: 0x0053A100 (FUN_0053A100, boost::detail::shared_count_RScmResource::shared_count_RScmResource)
   *
   * What it does:
   * Constructs one `shared_ptr<RScmResource>` from one raw resource lane,
   * including `enable_shared_from_this` ownership binding. The binary splits
   * the control-block allocation (0x0053A100, `shared_count(T*)`) from the
   * outer assignment/ownership-binding wrapper that calls it (0x00539EC0);
   * this single call to the real `boost::shared_ptr<RScmResource>` raw-pointer
   * constructor covers both.
   *
   * Wired from `CScmResourceFactory::Load` (ResourceFactory.cpp), whose
   * `outResource` is guaranteed null at this call site (explicitly reset at
   * function entry), matching the binary's fresh-construction shape.
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

    // 0x00539123: the same shared `GetModel` lane every other model consumer
    // goes through, not a second copy of the lookup.
    const boost::shared_ptr<RScmResource> modelResource = GetModel(modelPath.c_str(), nullptr);
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

namespace
{
  /**
   * Address: 0x00BF3C70 (FUN_00BF3C70, cleanup_RScmResourceConstructHelper)
   *
   * What it does:
   * Process-exit cleanup registered by `RScmResourceConstruct`'s constructor
   * via `atexit`. Unlinks the global `RScmResourceConstruct` helper node,
   * reusing the same unlink logic as `CleanupRScmResourceConstructHelperPrimary`
   * (0x00539060) -- the real binary duplicates this unlink sequence inline at
   * 0x00BF3C70 rather than calling 0x00539060 directly, but the effect is
   * identical.
   */
  void CleanupRScmResourceConstructHelperAtExit()
  {
    moho::CleanupRScmResourceConstructHelperPrimary();
  }
} // namespace
