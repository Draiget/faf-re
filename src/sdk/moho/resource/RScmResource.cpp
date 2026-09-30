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
#include "moho/resource/ResourceManager.h"

namespace moho
{
} // namespace moho

namespace
{
  [[nodiscard]] gpg::RType* ResolveRScmResourceTypeCached() noexcept
  {
    gpg::RType* resourceType = moho::RScmResource::sType;
    if (resourceType == nullptr) {
      resourceType = gpg::LookupRType(typeid(moho::RScmResource));
      moho::RScmResource::sType = resourceType;
    }
    return resourceType;
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
   * Address: 0x00538BF0 (FUN_00538BF0,
   * ??0RScmResource@Moho@@QAE@VStrArg@gpg@@ABV?$shared_ptr@$$CBUSScmFile@Moho@@@boost@@@Z)
   *
   * What it does:
   * Binds the SCM file and resource path, then caches the mesh's bounding
   * box (over every vertex position) and its size.
   */
  RScmResource::RScmResource(const gpg::StrArg resourcePath, const boost::shared_ptr<const SScmFile>& scmFile) :
    mName(resourcePath),
    mFile(scmFile),
    mSkeleton(nullptr),
    mBounds(Empty<Wm3::AxisAlignedBox3f>()),
    mSize(0.0f)
  {
    const std::int32_t vertexCount = static_cast<std::int32_t>(mFile->mVertexCount);
    const SScmVertex* const vertices = scm_file::GetVertices(*mFile);

    for (std::int32_t vertexIndex = 0; vertexIndex < vertexCount; ++vertexIndex) {
      const SScmVertex& vertex = vertices[vertexIndex];

      if (vertex.mLocalPositionX < mBounds.Min.x) {
        mBounds.Min.x = vertex.mLocalPositionX;
      }
      if (vertex.mLocalPositionY < mBounds.Min.y) {
        mBounds.Min.y = vertex.mLocalPositionY;
      }
      if (vertex.mLocalPositionZ < mBounds.Min.z) {
        mBounds.Min.z = vertex.mLocalPositionZ;
      }

      if (vertex.mLocalPositionX > mBounds.Max.x) {
        mBounds.Max.x = vertex.mLocalPositionX;
      }
      if (vertex.mLocalPositionY > mBounds.Max.y) {
        mBounds.Max.y = vertex.mLocalPositionY;
      }
      if (vertex.mLocalPositionZ > mBounds.Max.z) {
        mBounds.Max.z = vertex.mLocalPositionZ;
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

namespace moho
{
  void RScmResource::MemberConstruct(gpg::ReadArchive& archive, const int, const gpg::RRef&, gpg::SerConstructResult& result)
  {
    msvc8::string path;
    archive.ReadString(&path);
    result.SetShared(GetModel(path.c_str(), nullptr), 1u);
  }

  /**
   * Address: 0x00538F70 (FUN_00538F70)
   */
  void RScmResource::MemberSaveConstructArgs(
    gpg::WriteArchive& archive, const int, const gpg::RRef&, gpg::SerSaveConstructArgsResult& result
  )
  {
    msvc8::string mountedPath;
    (void)FILE_ToMountedPath(&mountedPath, mName.c_str());
    archive.WriteString(&mountedPath);
    result.SetShared(1u);
  }

  /**
   * `gpg::SerSaveConstructHelper<RScmResource>`, vtable 0x00E16390.
   *
   * Address: 0x00BC9110 (FUN_00BC9110 -- constructs the global and registers its destructor.)
   * Address: 0x00BF3C40 (FUN_00BF3C40 -- the global's destructor.)
   * Address: 0x00539620 (FUN_00539620 -- `Init`.)
   * Address: 0x00538EF0 (FUN_00538EF0 -- `SaveConstructArgs`, a forward to `MemberSaveConstructArgs`.)
   */
  struct RScmResourceSaveConstruct : gpg::SerSaveConstructHelper<RScmResource>
  {};

  /**
   * `gpg::SerConstructHelper<RScmResource>`, vtable 0x00E163A0.
   *
   * Address: 0x00BC9140 (FUN_00BC9140 -- constructs the global and registers its destructor.)
   * Address: 0x00BF3C70 (FUN_00BF3C70 -- the global's destructor.)
   * Address: 0x005396A0 (FUN_005396A0 -- `Init`.)
   * Address: 0x005390C0 (FUN_005390C0 -- `Construct`, `MemberConstruct` inlined.)
   * Address: 0x00539D40 (FUN_00539D40 -- `Delete`.)
   */
  struct RScmResourceConstruct : gpg::SerConstructHelper<RScmResource>
  {};
} // namespace moho

namespace
{
  // Address: 0x010ABB28 -- process-global `RScmResourceSaveConstruct` singleton.
  moho::RScmResourceSaveConstruct gRScmResourceSaveConstruct;

  // Address: 0x010ABB38 -- process-global `RScmResourceConstruct` singleton.
  moho::RScmResourceConstruct gRScmResourceConstruct;
} // namespace

namespace moho
{
  /**
   * Address: 0x00539BA0 (FUN_00539BA0, func_GetModel)
   *
   * IDA signature:
   * boost::shared_ptr<RScmResource> *__cdecl func_GetModel(
   *     boost::shared_ptr<RScmResource> *out, const char *path, int resWatcher);
   *
   * What it does:
   * Lazily resolves the `RScmResource` reflection descriptor (0x00539BC6
   * caches it in `RScmResource::sType`), dispatches one model path through
   * `RES_GetResource` (0x00539BF0), and retains the resolved object into the
   * caller's handle (0x00539BFC) before releasing the manager's temporary.
   * Yields an empty pointer when the lookup produced no live object -- the
   * empty-path case lands there too, via the manager's own
   * `GetResource: Invalid name` rejection.
   */
  boost::shared_ptr<RScmResource> GetModel(const gpg::StrArg path, CResourceWatcher* const resourceWatcher)
  {
    gpg::RType* resourceType = RScmResource::sType;
    if (resourceType == nullptr) {
      resourceType = gpg::LookupRType(typeid(RScmResource));
      RScmResource::sType = resourceType;
    }

    return boost::static_pointer_cast<RScmResource>(RES_GetResource(path, resourceWatcher, resourceType));
  }
} // namespace moho
