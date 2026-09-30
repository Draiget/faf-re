// RScaResource recovered implementation.

#include <cstdlib>
#include "moho/resource/RScaResource.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/resource/ResourceManager.h"
#include "moho/serialization/PrefetchHandleBase.h"

#include <cstddef>
#include <cstring>
#include <new>
#include <typeinfo>
#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/utils/Logging.h" // TEMPORARY PROBE (do not commit)

namespace moho
{

gpg::RType* RScaResource::sType = nullptr;

namespace
{
  [[nodiscard]] gpg::RType* ResolveRScaResourceTypeCached() noexcept
  {
    gpg::RType* type = moho::RScaResource::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::RScaResource));
      moho::RScaResource::sType = type;
    }
    return type;
  }

  class RScaResourceTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "RScaResource";
    }

    void Init() override
    {
      size_ = sizeof(RScaResource);
      gpg::RType::Init();
      Finish();
    }
  };

} // namespace

/**
 * Address: 0x0053A2D0 (FUN_0053A2D0, preregister_RScaResourceTypeInfo)
 *
 * What it does:
 * Constructs/preregisters reflection metadata for `RScaResource`.
 */
[[nodiscard]] gpg::RType* preregister_RScaResourceTypeInfo()
{
  static RScaResourceTypeInfo typeInfo;
  gpg::PreRegisterRType(typeid(RScaResource), &typeInfo);
  return &typeInfo;
}

/**
 * Address: 0x0053B2A0 (FUN_0053B2A0, boost::shared_ptr_RScaResource::shared_ptr_RScaResource)
 *
 * What it does:
 * Constructs one `shared_ptr<RScaResource>` from one raw resource pointer lane.
 */
boost::shared_ptr<RScaResource>* ConstructSharedRScaResourceFromRaw(
  boost::shared_ptr<RScaResource>* const outResource,
  RScaResource* const resource
)
{
  return ::new (outResource) boost::shared_ptr<RScaResource>(resource);
}

/**
 * Address: 0x0053B3B0 (FUN_0053B3B0)
 *
 * What it does:
 * Constructs one `boost::detail::sp_counted_impl_p<RScaResource>` control
 * block in caller-provided storage with both initial reference counters set to
 * `1` and payload pointer bound to `resource`.
 */
boost::detail::sp_counted_impl_p<RScaResource>* ConstructRScaSharedCountedImpl(
  boost::detail::sp_counted_impl_p<RScaResource>* const outControlBlock,
  RScaResource* const resource
)
{
  return ::new (outControlBlock) boost::detail::sp_counted_impl_p<RScaResource>(resource);
}

/**
 * Address: 0x0053A4D0 (FUN_0053A4D0)
 *
 * IDA signature:
 * char __userpurge Moho::RScaResource::LoadScaFile@<al>(
 *   Moho::RScaResource *res@<edi>, const char *filename);
 *
 * What it does:
 * Reads an SCA animation file from disk via DISK_ReadFile, copies the
 * buffer into the resource, and applies a quaternion rotation fixup for
 * files with version < 5. Returns true on success, false if the file
 * could not be loaded.
 */
bool RScaResource::LoadScaFile(const char* filename)
{
  gpg::MemBuffer<char> fileData = DISK_ReadFile(filename);

  if (!fileData.mBegin) {
    return false;
  }

  // Store filename and take ownership of the file data buffer.
  new (&mFilename) msvc8::string(filename, std::strlen(filename));
  mMem = fileData;

  // Parse header pointers.
  auto* header = reinterpret_cast<SScaHeader*>(fileData.mBegin);
  mStart = fileData.mBegin;
  mEnd = fileData.mBegin + header->animDataOffset;

  // Apply quaternion rotation fixup for version < 5 files.
  // Old versions stored quaternions as [w, x, y, z]; the fixup rotates
  // them to [x, w, y, z] by cycling the four components.
  if (header->version < 5u) {
    // Fix up the animation data section header quaternion.
    auto* animHeader = reinterpret_cast<SScaAnimDataHeader*>(mEnd);
    float w = animHeader->rotation[0];
    float x = animHeader->rotation[1];
    float y = animHeader->rotation[2];
    float z = animHeader->rotation[3];
    animHeader->rotation[0] = z;
    animHeader->rotation[1] = w;
    animHeader->rotation[2] = x;
    animHeader->rotation[3] = y;

    // Fix up each per-bone key quaternion.
    const std::uint32_t boneCount = header->boneCount;
    const std::uint32_t keysPerBone = header->keysPerBone;
    // Stride per bone: 8-byte bone header + keysPerBone * 28-byte keys.
    const std::uint32_t boneStride = 8u + keysPerBone * sizeof(SScaAnimKey);

    for (std::uint32_t bone = 0; bone < boneCount; ++bone) {
      char* boneBase = mEnd + sizeof(SScaAnimDataHeader) + bone * boneStride;

      for (std::uint32_t key = 0; key < keysPerBone; ++key) {
        auto* animKey = reinterpret_cast<SScaAnimKey*>(
          boneBase + 8u + key * sizeof(SScaAnimKey)
        );
        float kw = animKey->rotation[0];
        float kx = animKey->rotation[1];
        float ky = animKey->rotation[2];
        float kz = animKey->rotation[3];
        animKey->rotation[0] = kz;
        animKey->rotation[1] = kw;
        animKey->rotation[2] = kx;
        animKey->rotation[3] = ky;
      }
    }
  }

  return true;
}

/**
 * Address: 0x0053AAD0 (FUN_0053AAD0)
 *
 * What it does:
 * Allocates a fresh `RScaResource` straight into the returned handle, parses
 * the SCA file via `LoadScaFile`, and empties the handle when parsing fails.
 */
boost::shared_ptr<RScaResource> CScaResourceFactory::LoadImpl(const gpg::StrArg path)
{
  boost::shared_ptr<RScaResource> resource(new RScaResource());
  if (!resource->LoadScaFile(path)) {
    resource.reset();
  }
  return resource;
}

/**
 * Address: 0x0053B100 (FUN_0053B100)
 *
 * What it does:
 * Asks the resource manager for the animation at `path` and returns it as an
 * owning handle: `RES_GetResource`'s `shared_ptr<void>` is converted in place
 * (0x0053B2C0) and the temporary released.
 */
boost::shared_ptr<RScaResource> GetScaResource(const gpg::StrArg path)
{
  gpg::RType* resourceType = RScaResource::sType;
  if (resourceType == nullptr) {
    resourceType = gpg::LookupRType(typeid(RScaResource));
    RScaResource::sType = resourceType;
  }

  const boost::shared_ptr<RScaResource> resource =
    boost::static_pointer_cast<RScaResource>(RES_GetResource(path, nullptr, resourceType));
  { static int sScaBudget = 12; if (sScaBudget > 0) { --sScaBudget; gpg::Warnf("[SCADIAG] path='%s' useCount=%ld obj=%p", path != nullptr ? path : "", resource.use_count(), resource.get()); } } // TEMPORARY PROBE (do not commit)
  return resource;
}

/**
 * Address: 0x00BC9280 (FUN_00BC9280)
 *
 * IDA signature:
 * void __cdecl sub_BC9280();
 *
 * What it does:
 * Resolves `RScaResource`'s reflected type and publishes it under the `"anims"`
 * prefetch key.
 *
 * Without it `Prefetcher:Update` rejects the `anims` lane of the prefetch table
 * the in-game UI builds, and `CScrLuaInitFormSet`'s error raise unwinds
 * `CreateUI` at its first statement past the prefetch - so the border control,
 * the world view and every panel after it are never built. The help string the
 * binary attaches to the binder names all four keys:
 * `CPrefetchSet:Update({d3d_textures=..., batch_textures=..., models=...,
 * anims=...})`.
 */
void register_RScaResourceAnimPrefetchType()
{
  gpg::RType* resourceType = RScaResource::sType;
  if (resourceType == nullptr) {
    resourceType = gpg::LookupRType(typeid(RScaResource));
    RScaResource::sType = resourceType;
  }

  RES_RegisterPrefetchType("anims", resourceType);
}

namespace
{
  /**
   * Address: 0x00BC9260 (FUN_00BC9260, dynamic initializer for `sScaResourceFactory`)
   * Address: 0x00BF3DA0 (FUN_00BF3DA0, dynamic atexit destructor for `sScaResourceFactory`)
   *
   * What it does:
   * The process-lifetime `.sca` factory; constructing it attaches it to the
   * resource manager, which is what gives `RES_GetResource` a factory for
   * `RScaResource` (without it every PlayAnim gets an expired handle).
   * Defined ahead of the bootstrap below, as 0x00BC9260 precedes the "anims"
   * prefetch key's initializer 0x00BC9280.
   */
  CScaResourceFactory sScaResourceFactory;

  struct RScaResourcePrefetchBootstrap
  {
    RScaResourcePrefetchBootstrap()
    {
      moho::register_RScaResourceAnimPrefetchType();
    }
  };

  RScaResourcePrefetchBootstrap gRScaResourcePrefetchBootstrap;
} // namespace

} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_RScaResourceTypeInfo_ed4da3, moho::preregister_RScaResourceTypeInfo)

namespace moho
{
  void RScaResource::MemberConstruct(gpg::ReadArchive& archive, const int, const gpg::RRef&, gpg::SerConstructResult& result)
  {
    msvc8::string path;
    archive.ReadString(&path);
    result.SetShared(GetScaResource(path.c_str()), 1u);
  }

  /**
   * Address: 0x0053A770 (FUN_0053A770)
   */
  void RScaResource::MemberSaveConstructArgs(
    gpg::WriteArchive& archive, const int, const gpg::RRef&, gpg::SerSaveConstructArgsResult& result
  )
  {
    msvc8::string mountedPath;
    (void)FILE_ToMountedPath(&mountedPath, mFilename.c_str());
    archive.WriteString(&mountedPath);
    result.SetShared(1u);
  }

  /**
   * `gpg::SerSaveConstructHelper<RScaResource>`, vtable 0x00E1644C.
   *
   * Address: 0x00BC91F0 (FUN_00BC91F0 -- constructs the global and registers its destructor.)
   * Address: 0x00BF3D40 (FUN_00BF3D40 -- the global's destructor.)
   * Address: 0x0053ABD0 (FUN_0053ABD0 -- `Init`.)
   * Address: 0x0053A6F0 (FUN_0053A6F0 -- `SaveConstructArgs`, a forward to `MemberSaveConstructArgs`.)
   */
  struct RScaResourceSaveConstruct : gpg::SerSaveConstructHelper<RScaResource>
  {};

  /**
   * `gpg::SerConstructHelper<RScaResource>`, vtable 0x00E1645C.
   *
   * Address: 0x00BC9220 (FUN_00BC9220 -- constructs the global and registers its destructor.)
   * Address: 0x00BF3D70 (FUN_00BF3D70 -- the global's destructor.)
   * Address: 0x0053AC50 (FUN_0053AC50 -- `Init`.)
   * Address: 0x0053A8C0 (FUN_0053A8C0 -- `Construct`, `MemberConstruct` inlined.)
   * Address: 0x0053B0E0 (FUN_0053B0E0 -- `Delete`.)
   */
  struct RScaResourceConstruct : gpg::SerConstructHelper<RScaResource>
  {};
} // namespace moho

namespace
{
  // Address: 0x010ABC5C -- process-global `RScaResourceSaveConstruct` singleton.
  moho::RScaResourceSaveConstruct gRScaResourceSaveConstruct;

  // Address: 0x010ABCD4 -- process-global `RScaResourceConstruct` singleton.
  moho::RScaResourceConstruct gRScaResourceConstruct;
} // namespace
