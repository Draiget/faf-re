#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "boost/weak_ptr.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "legacy/containers/String.h"
#include "moho/resource/ResourceFactory.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  // ============================================================================
  // SCA file format header
  // ============================================================================
  // Binary evidence from LoadScaFile (0x0053A4D0):
  //   +0x00: magic              (uint32_t)
  //   +0x04: version            (uint32_t, checked < 5 for rotation fixup)
  //   +0x08: boneCount          (uint32_t)
  //   +0x10: keysPerBone        (uint32_t)
  //   +0x1C: animDataOffset     (uint32_t, byte offset from header start to anim data)

  struct SScaHeader
  {
    std::uint32_t magic;           // +0x00
    std::uint32_t version;         // +0x04
    std::uint32_t boneCount;       // +0x08
    std::uint32_t field_0C;        // +0x0C
    std::uint32_t keysPerBone;     // +0x10
    std::uint32_t field_14;        // +0x14
    std::uint32_t field_18;        // +0x18
    std::uint32_t animDataOffset;  // +0x1C
  };

  static_assert(offsetof(SScaHeader, version)        == 0x04);
  static_assert(offsetof(SScaHeader, boneCount)      == 0x08);
  static_assert(offsetof(SScaHeader, keysPerBone)    == 0x10);
  static_assert(offsetof(SScaHeader, animDataOffset) == 0x1C);
  static_assert(sizeof(SScaHeader)                   == 0x20);

  // ============================================================================
  // SCA animation key record (28 bytes per key)
  // ============================================================================
  // Each key stores position (3 floats) + rotation quaternion (4 floats).
  // In version < 5, the quaternion layout needs a rotation fixup:
  //   original: [w, x, y, z] -> fixed: [x, w, y, z]
  // (The fixup swaps the first component into position.)

  struct SScaAnimKey
  {
    float position[3];    // +0x00: x, y, z
    float rotation[4];    // +0x0C: quaternion components
  };

  static_assert(sizeof(SScaAnimKey) == 0x1C);

  // ============================================================================
  // SCA animation data section header
  // ============================================================================
  // Sits at the animDataOffset from the file start. Has a header with
  // at least 7 floats before the per-bone key data begins.

  struct SScaAnimDataHeader
  {
    float field_00[3];     // +0x00
    float rotation[4];     // +0x0C: quaternion subject to same fixup as keys
  };

  static_assert(sizeof(SScaAnimDataHeader) == 0x1C);

  // ============================================================================
  // RScaResource
  // ============================================================================

  /**
   * Holds one loaded SCA (SupCom Animation) file in memory.
   *
   * Binary evidence from LoadScaFile (0x0053A4D0):
   *   - mFilename at +0x00 (msvc8::string, ctor call at `ecx = edi`)
   *   - mMem at +0x1C (MemBuffer<char>, operator= call at `lea ecx, [edi+1Ch]`)
   *   - mStart at +0x2C (char*, raw pointer into loaded data)
   *   - mEnd at +0x30 (char*, pointer to animation data section)
   */
  class RScaResource
  {
  public:
    static gpg::RType* sType;

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
    bool LoadScaFile(const char* filename);

    /**
     * Default-constructs an empty resource (empty SSO filename, null mem
     * buffer, null start/end pointers). Matches the inline default-init
     * sequence emitted at 0x0053AAD0 (`Moho::CScaResourceFactory::Load`).
     */
    RScaResource() noexcept = default;

  public:
    msvc8::string mFilename{};          // +0x00
    gpg::MemBuffer<char> mMem{};        // +0x1C
    char* mStart = nullptr;             // +0x2C
    char* mEnd = nullptr;               // +0x30
  };

  static_assert(offsetof(RScaResource, mFilename) == 0x00);
  static_assert(offsetof(RScaResource, mMem)      == 0x1C);
  static_assert(offsetof(RScaResource, mStart)    == 0x2C);
  static_assert(offsetof(RScaResource, mEnd)      == 0x30);
  static_assert(sizeof(RScaResource)              == 0x34);

  /**
   * Resource-factory singleton that materializes one `RScaResource` per SCA path.
   * Pattern mirrors `CScmResourceFactory`.
   */
  class CScaResourceFactory final : public ResourceFactory<RScaResource>
  {
  public:
    using ResourceHandle = boost::shared_ptr<RScaResource>;

    /**
     * Address: 0x0053AD00 (FUN_0053AD00, Moho::ResourceFactory_RScaResource::Init)
     *
     * What it does:
     * Resolves cached `RScaResource` RTTI and updates the prefetch/resource
     * type lanes used by factory virtual dispatch.
     */
    void Init() override;

    /**
     * Address: 0x0053AAD0 (FUN_0053AAD0)
     * Mangled: ?Load@CScaResourceFactory@Moho@@UAEAAV?$shared_ptr@VRScaResource@Moho@@@boost@@AAV34@PBD@Z
     *
     * IDA signature:
     * boost::shared_ptr<Moho::RScaResource>* __thiscall
     * Moho::CScaResourceFactory::Load(
     *   Moho::CScaResourceFactory *this,
     *   boost::shared_ptr<Moho::RScaResource>* outResource,
     *   const char* path);
     *
     * What it does:
     * Default-constructs an `RScaResource`, parses the SCA file via
     * `LoadScaFile`, and resets the out handle on failure.
     */
    ResourceHandle& Load(ResourceHandle& outResource, const char* path) override;

    /**
     * Address: 0x0053AF60 (FUN_0053AF60, Moho::ResourceFactory_RScaResource::LoadFrom)
     *
     * What it does:
     * Clones prefetch handle lane, forwards into `LoadFromImpl`, and assigns
     * the loaded resource handle to `outResource`.
     */
    ResourceHandle& LoadFrom(ResourceHandle& outResource, const char* path, ResourceHandle prefetchData) override;

    /**
     * Forwarded by the base `LoadImpl` lane.
     */
    ResourceHandle& LoadImpl(ResourceHandle& outResource, const char* path) override
    {
      return Load(outResource, path);
    }
  };

  /**
   * Address: 0x0053AA40 (FUN_0053AA40)
   *
   * What it does:
   * Ensures the resource-manager singleton, attaches process-lifetime SCA
   * factory registration, and returns the attached factory object.
   */
  CScaResourceFactory* construct_CScaResourceFactoryPreload();

  /**
   * Address: 0x0053B100 (FUN_0053B100)
   *
   * IDA signature:
   * gpg::RRef* __cdecl Moho::func_GetScaResource(gpg::RRef* outRef, const char* path);
   *
   * What it does:
   * Looks up the cached reflection type for `RScaResource`, calls
   * `RES_GetResource` to fetch a weak handle to the resource, wraps it as a
   * typed `gpg::RRef`, and releases the temporary weak-pointer count.
   */
  gpg::RRef* GetScaResource(gpg::RRef* outRef, const char* path);
} // namespace moho
