#include "moho/resource/SScmFile.h"

#include <cstring>

namespace moho::scm_file
{
  const SScmBoneBoundsSample* GetBoneBoundsSamples(const SScmFile& file)
  {
    const auto* const fileBase = reinterpret_cast<const std::uint8_t*>(&file);
    return reinterpret_cast<const SScmBoneBoundsSample*>(fileBase + file.mBoneBoundsSampleOffset);
  }

  /**
   * Address: 0x005379D0 (FUN_005379D0)
   *
   * What it does:
   * Fills one scratch vector with a pointer per bone into the SCM bone-name
   * string block at file offset 0x40. The names sit back-to-back as
   * null-terminated strings, so each entry starts one past the previous
   * terminator.
   */
  void FillBoneNamePointers(const SScmFile& file, msvc8::vector<const char*>& outNamePointers)
  {
    const std::uint32_t boneCount = file.mBoneTotalCount;
    outNamePointers.resize(boneCount);

    const char* cursor = reinterpret_cast<const char*>(&file) + 0x40;
    for (std::uint32_t boneIndex = 0; boneIndex < boneCount; ++boneIndex) {
      outNamePointers.begin()[boneIndex] = cursor;
      cursor += std::strlen(cursor) + 1;
    }
  }
} // namespace moho::scm_file
