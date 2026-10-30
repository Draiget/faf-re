#include "gpg/core/diagnostics/BuildInfo.h"

// Written by the faf_build_info build step (cmake/FafBuildInfo.cmake). This is the
// only file that includes it, so a new commit recompiles this file alone.
#include "faf/BuildInfoGenerated.h"

namespace gpg::diag
{
  namespace
  {
#if FAF_BUILD_DIRTY
    constexpr char kCommitShort[] = FAF_BUILD_COMMIT_SHORT "-dirty";
#else
    constexpr char kCommitShort[] = FAF_BUILD_COMMIT_SHORT;
#endif
    constexpr char kIdentity[] =
      FAF_BUILD_COMMIT_SHORT
#if FAF_BUILD_DIRTY
      "-dirty"
#endif
      " " FAF_BUILD_ARCH " " FAF_BUILD_CONFIG " (" FAF_BUILD_BRANCH ", " FAF_BUILD_DESCRIBE ")";
    constexpr char kLabel[] =
      "FAF-RE by Draiget, build " FAF_BUILD_COMMIT_SHORT
#if FAF_BUILD_DIRTY
      "-dirty"
#endif
      " " FAF_BUILD_ARCH;
  } // namespace

  const char* BuildLabel() noexcept
  {
    return kLabel;
  }

  const char* BuildCommit() noexcept
  {
    return FAF_BUILD_COMMIT;
  }

  const char* BuildCommitShort() noexcept
  {
    return kCommitShort;
  }

  const char* BuildDescribe() noexcept
  {
    return FAF_BUILD_DESCRIBE;
  }

  const char* BuildBranch() noexcept
  {
    return FAF_BUILD_BRANCH;
  }

  const char* BuildArch() noexcept
  {
    return FAF_BUILD_ARCH;
  }

  bool BuildDirty() noexcept
  {
    return FAF_BUILD_DIRTY != 0;
  }

  const char* BuildIdentity() noexcept
  {
    return kIdentity;
  }
} // namespace gpg::diag
