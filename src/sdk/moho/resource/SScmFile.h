#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/Vector.h"

namespace moho
{
  /**
   * One `.scm` mesh vertex as stored in the file image (0x44 bytes).
   *
   * Three readers walk the vertex array: `RScmResource`'s constructor
   * (0x00538BF0) takes the mesh bounding box over the positions,
   * `CAniSkel::UpdateBoneBounds` (0x0054A540) grows each bone's box, and
   * `HardwareMeshBatch::Initialize` (0x007E7540) copies every vertex into a
   * `gpg::gal::MeshVertex` for the vertex formatter. The vector names come
   * from that last copy (0x007E79B2..0x007E7A43): +0x0C lands in the
   * formatter's NORMAL input, +0x18 in TANGENT, +0x24 in BINORMAL.
   */
  struct SScmVertex
  {
    float mLocalPositionX;           // +0x00
    float mLocalPositionY;           // +0x04
    float mLocalPositionZ;           // +0x08
    float mNormal[3];                // +0x0C
    float mTangent[3];               // +0x18
    float mBinormal[3];              // +0x24
    float mTexCoord0[2];             // +0x30
    float mTexCoord1[2];             // +0x38
    std::uint8_t mBoneIndex;         // +0x40 (the bone the vertex is rigidly bound to)
    std::uint8_t mBoneIndex1;        // +0x41
    std::uint8_t mBoneIndex2;        // +0x42
    std::uint8_t mBoneIndex3;        // +0x43
  };

  static_assert(offsetof(SScmVertex, mLocalPositionX) == 0x00, "SScmVertex::mLocalPositionX offset must be 0x00");
  static_assert(offsetof(SScmVertex, mLocalPositionY) == 0x04, "SScmVertex::mLocalPositionY offset must be 0x04");
  static_assert(offsetof(SScmVertex, mLocalPositionZ) == 0x08, "SScmVertex::mLocalPositionZ offset must be 0x08");
  static_assert(offsetof(SScmVertex, mNormal) == 0x0C, "SScmVertex::mNormal offset must be 0x0C");
  static_assert(offsetof(SScmVertex, mTangent) == 0x18, "SScmVertex::mTangent offset must be 0x18");
  static_assert(offsetof(SScmVertex, mBinormal) == 0x24, "SScmVertex::mBinormal offset must be 0x24");
  static_assert(offsetof(SScmVertex, mTexCoord0) == 0x30, "SScmVertex::mTexCoord0 offset must be 0x30");
  static_assert(offsetof(SScmVertex, mTexCoord1) == 0x38, "SScmVertex::mTexCoord1 offset must be 0x38");
  static_assert(offsetof(SScmVertex, mBoneIndex) == 0x40, "SScmVertex::mBoneIndex offset must be 0x40");
  static_assert(sizeof(SScmVertex) == 0x44, "SScmVertex size must be 0x44");

  /**
   * Header of an in-memory `.scm` model file.
   *
   * Field offsets follow the shipped SupCom SCM header layout and are
   * byte-verified against the hardware-batch fill path (`FUN_007E7540`):
   *   - `mVertexOffset` (+0x10) is the byte offset of the vertex array the
   *     fill loop reads from (`p + [p+0x10] + i*0x44`).
   *   - `mVertexCount` (+0x18) is the vertex count.
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
    std::uint32_t mVertexOffset;           // +0x10 (byte offset of the SScmVertex array)
    std::uint8_t mUnknown14[0x04];
    std::uint32_t mVertexCount;            // +0x18
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
  static_assert(offsetof(SScmFile, mVertexOffset) == 0x10, "SScmFile::mVertexOffset offset must be 0x10");
  static_assert(offsetof(SScmFile, mVertexCount) == 0x18, "SScmFile::mVertexCount offset must be 0x18");
  static_assert(offsetof(SScmFile, mIndexDataOffset) == 0x1C, "SScmFile::mIndexDataOffset offset must be 0x1C");
  static_assert(offsetof(SScmFile, mSkinBoneCount) == 0x0C, "SScmFile::mSkinBoneCount offset must be 0x0C");
  static_assert(offsetof(SScmFile, mIndexCount) == 0x20, "SScmFile::mIndexCount offset must be 0x20");
  static_assert(offsetof(SScmFile, mBoneTotalCount) == 0x2C, "SScmFile::mBoneTotalCount offset must be 0x2C");

  namespace scm_file
  {
    /// Base pointer of the packed SCM vertex records inside the file image.
    [[nodiscard]] inline const SScmVertex* GetVertices(const SScmFile& file) noexcept
    {
      const auto* const fileBase = reinterpret_cast<const std::uint8_t*>(&file);
      return reinterpret_cast<const SScmVertex*>(fileBase + file.mVertexOffset);
    }

    /// Base pointer of the packed 16-bit SCM index buffer inside the file image.
    [[nodiscard]] inline const std::uint16_t* GetIndices(const SScmFile& file) noexcept
    {
      const auto* const fileBase = reinterpret_cast<const std::uint8_t*>(&file);
      return reinterpret_cast<const std::uint16_t*>(fileBase + file.mIndexDataOffset);
    }

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
