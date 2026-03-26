#include "moho/resource/SScmFile.h"

namespace moho::scm_file
{
  const SScmBoneBoundsSample* GetBoneBoundsSamples(const SScmFile& file)
  {
    const auto* const fileBase = reinterpret_cast<const std::uint8_t*>(&file);
    return reinterpret_cast<const SScmBoneBoundsSample*>(fileBase + file.mBoneBoundsSampleOffset);
  }
} // namespace moho::scm_file
