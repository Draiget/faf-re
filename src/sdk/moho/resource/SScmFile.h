#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/Vector.h"

namespace moho
{
  /**
   * One SCM mesh vertex record (0x44 bytes).
   *
   * This is the on-disk `.scm` per-vertex structure. It doubles as the
   * "bone-bounds sample" the resource loader iterates to compute the mesh AABB
   * (`RScmResource::RScmResource`, 0x00538BF0) and the skeleton bounds
   * (`CAniSkel`, 0x00538... vein) — hence the historical name. It is also the
   * source record the hardware-batch fill path streams into the GPU vertex
   * buffer: `HardwareMeshBatch::Initialize` (0x007E7540) reads each vertex at
   * `SScmFile + mVertexDataOffset + i * 0x44` and scatters
   * `position / vec0C / vec18 / vec24 / uv0 / uv1 / boneIndices` into the
   * runtime source-vertex scratch consumed by the vertex formatter.
   *
   * All field offsets are byte-verified against the vertex-scatter loop in
   * `FUN_007E7540` (0x007E797D..0x007E7AD6).
   */
  struct SScmBoneBoundsSample
  {
    float mLocalPositionX;           // +0x00 (position.x)
    float mLocalPositionY;           // +0x04 (position.y)
    float mLocalPositionZ;           // +0x08 (position.z)
    float mVec0C[3];                 // +0x0C (streamed to source-vertex +0x7C)
    float mVec18[3];                 // +0x18 (streamed to source-vertex +0x88)
    float mVec24[3];                 // +0x24 (streamed to source-vertex +0x70)
    float mTexCoord0[2];             // +0x30 (streamed to source-vertex +0x94/+0x98)
    float mTexCoord1[2];             // +0x38 (streamed to source-vertex +0x9C/+0xA0)
    std::uint8_t mBoneIndex;         // +0x40 (bone index 0 / source-vertex +0x51)
    std::uint8_t mBoneIndex1;        // +0x41 (bone index 1 / source-vertex +0x52)
    std::uint8_t mBoneIndex2;        // +0x42 (bone index 2 / source-vertex +0x53)
    std::uint8_t mBoneIndex3;        // +0x43 (bone index 3 / source-vertex +0x54)
  };

  /// The SCM vertex record is the same 0x44-byte structure the loader also
  /// treats as a bone-bounds sample. Alias kept for mesh-fill call sites so the
  /// intent (vertex streaming) is explicit without duplicating the layout.
  using SScmVertex = SScmBoneBoundsSample;

  static_assert(
    offsetof(SScmBoneBoundsSample, mLocalPositionX) == 0x00,
    "SScmBoneBoundsSample::mLocalPositionX offset must be 0x00"
  );
  static_assert(
    offsetof(SScmBoneBoundsSample, mLocalPositionY) == 0x04,
    "SScmBoneBoundsSample::mLocalPositionY offset must be 0x04"
  );
  static_assert(
    offsetof(SScmBoneBoundsSample, mLocalPositionZ) == 0x08,
    "SScmBoneBoundsSample::mLocalPositionZ offset must be 0x08"
  );
  static_assert(offsetof(SScmBoneBoundsSample, mVec0C) == 0x0C, "SScmBoneBoundsSample::mVec0C offset must be 0x0C");
  static_assert(offsetof(SScmBoneBoundsSample, mVec18) == 0x18, "SScmBoneBoundsSample::mVec18 offset must be 0x18");
  static_assert(offsetof(SScmBoneBoundsSample, mVec24) == 0x24, "SScmBoneBoundsSample::mVec24 offset must be 0x24");
  static_assert(
    offsetof(SScmBoneBoundsSample, mTexCoord0) == 0x30, "SScmBoneBoundsSample::mTexCoord0 offset must be 0x30"
  );
  static_assert(
    offsetof(SScmBoneBoundsSample, mTexCoord1) == 0x38, "SScmBoneBoundsSample::mTexCoord1 offset must be 0x38"
  );
  static_assert(
    offsetof(SScmBoneBoundsSample, mBoneIndex) == 0x40,
    "SScmBoneBoundsSample::mBoneIndex offset must be 0x40"
  );
  static_assert(sizeof(SScmBoneBoundsSample) == 0x44, "SScmBoneBoundsSample size must be 0x44");
  static_assert(sizeof(SScmVertex) == 0x44, "SScmVertex size must be 0x44");

  /**
   * Header of an in-memory `.scm` model file.
   *
   * Field offsets follow the shipped SupCom SCM header layout and are
   * byte-verified against the hardware-batch fill path (`FUN_007E7540`):
   *   - `mBoneBoundsSampleOffset` (+0x10) is the vertex-data offset the fill
   *     loop reads from (`p + [p+0x10] + i*0x44`).
   *   - `mBoneBoundsSampleCount` (+0x18) is the vertex count.
   *   - `mIndexDataOffset` (+0x1C) is the byte offset of the 16-bit index
   *     buffer the fill path copies verbatim into the GPU index buffer.
   */
  struct SScmFile
  {
    std::uint8_t mUnknown00[0x08];
    std::uint32_t mBoneTableOffset;        // +0x08
    /// Skinned bone count - the number of bones a pose blends and the number of
    /// GPU skinning-palette slots one instance of this mesh occupies.
    /// `MeshBatch::Initialize` seeds `mBoneCount` from here (0x007E6FD8
    /// `mov ecx, [edi+0Ch]`), and `MeshInstance::UpdateInterpolatedFields`
    /// passes it to `CAniPose::InterpolatePose` (0x007DEDEF, same +0x0C).
    /// Distinct from `mBoneTotalCount` at +0x2C, which also counts attachment
    /// bones; their difference is `MeshBatch::mAttachCount`.
    std::uint32_t mSkinBoneCount;          // +0x0C
    std::uint32_t mBoneBoundsSampleOffset; // +0x10 (SCM vertex-data offset)
    std::uint8_t mUnknown14[0x04];
    std::uint32_t mBoneBoundsSampleCount;  // +0x18 (SCM vertex count)
    std::uint32_t mIndexDataOffset;        // +0x1C (SCM 16-bit index-data offset)
    /// 16-bit index count; the triangle count is this divided by three
    /// (0x007E6FC1 `mov ecx, [edi+20h]`, then the signed magic-divide by 3).
    std::uint32_t mIndexCount;             // +0x20
    std::uint8_t mUnknown24[0x08];
    /// Total bone-table entries, skinned bones plus attachment bones. Named
    /// `mBoneCount` before the +0x0C lane above was identified.
    std::uint32_t mBoneTotalCount;         // +0x2C
  };

  static_assert(offsetof(SScmFile, mBoneTableOffset) == 0x08, "SScmFile::mBoneTableOffset offset must be 0x08");
  static_assert(
    offsetof(SScmFile, mBoneBoundsSampleOffset) == 0x10,
    "SScmFile::mBoneBoundsSampleOffset offset must be 0x10"
  );
  static_assert(
    offsetof(SScmFile, mBoneBoundsSampleCount) == 0x18,
    "SScmFile::mBoneBoundsSampleCount offset must be 0x18"
  );
  static_assert(offsetof(SScmFile, mIndexDataOffset) == 0x1C, "SScmFile::mIndexDataOffset offset must be 0x1C");
  static_assert(offsetof(SScmFile, mSkinBoneCount) == 0x0C, "SScmFile::mSkinBoneCount offset must be 0x0C");
  static_assert(offsetof(SScmFile, mIndexCount) == 0x20, "SScmFile::mIndexCount offset must be 0x20");
  static_assert(offsetof(SScmFile, mBoneTotalCount) == 0x2C, "SScmFile::mBoneTotalCount offset must be 0x2C");

  namespace scm_file
  {
    /// SCM vertex-data byte offset (aliases the bone-bounds-sample offset).
    [[nodiscard]] inline std::uint32_t GetVertexDataOffset(const SScmFile& file) noexcept
    {
      return file.mBoneBoundsSampleOffset;
    }

    /// Base pointer of the packed SCM vertex records inside the file image.
    [[nodiscard]] inline const SScmVertex* GetVertices(const SScmFile& file) noexcept
    {
      const auto* const fileBase = reinterpret_cast<const std::uint8_t*>(&file);
      return reinterpret_cast<const SScmVertex*>(fileBase + file.mBoneBoundsSampleOffset);
    }

    /// Base pointer of the packed 16-bit SCM index buffer inside the file image.
    [[nodiscard]] inline const std::uint16_t* GetIndices(const SScmFile& file) noexcept
    {
      const auto* const fileBase = reinterpret_cast<const std::uint8_t*>(&file);
      return reinterpret_cast<const std::uint16_t*>(fileBase + file.mIndexDataOffset);
    }

    [[nodiscard]] const SScmBoneBoundsSample* GetBoneBoundsSamples(const SScmFile& file);

    /**
     * Address: 0x005379D0 (FUN_005379D0)
     *
     * Fills one scratch vector with a pointer per bone into the SCM bone-name
     * string block, which starts at file offset 0x40 and stores the names
     * back-to-back as null-terminated strings, so entry `i+1` begins one past
     * entry `i`'s terminator. Shared by `CAniSkel`'s skeleton build and
     * `MeshBatch::Initialize`'s bone-remap branch, which is why it lives here
     * next to the file layout it walks rather than in either caller.
     */
    void FillBoneNamePointers(const SScmFile& file, msvc8::vector<const char*>& outNamePointers);
  } // namespace scm_file
} // namespace moho
