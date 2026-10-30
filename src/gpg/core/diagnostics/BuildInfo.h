#pragma once

namespace gpg::diag
{
  /**
   * Engine addition (issue #215): the git commit this executable was built from, read
   * by the faf_build_info build step (cmake/FafBuildInfo.cmake). Each value is
   * "unknown" when the build had no git checkout.
   */

  /// Full commit hash.
  [[nodiscard]] const char* BuildCommit() noexcept;

  /// First 7 characters of the commit hash, with "-dirty" when tracked files had
  /// local edits, e.g. "a48d131-dirty".
  [[nodiscard]] const char* BuildCommitShort() noexcept;

  /// `git describe --tags --dirty` output, e.g. "v1.1.1-186-ga48d131-dirty".
  [[nodiscard]] const char* BuildDescribe() noexcept;

  /// Branch the commit was built on ("detached" without one).
  [[nodiscard]] const char* BuildBranch() noexcept;

  /// Target architecture: "x64", "x86" or "x64-linux".
  [[nodiscard]] const char* BuildArch() noexcept;

  /// Whether tracked files had local edits.
  [[nodiscard]] bool BuildDirty() noexcept;

  /// The line shown to players: "FAF-RE by Draiget, build a48d131-dirty x64" (the lobby
  /// label and the first line of the network-stats panel).
  [[nodiscard]] const char* BuildLabel() noexcept;

  /// One line for logs and reports: "a48d131-dirty x64 Release (master, v1.1.1-186-ga48d131-dirty)".
  [[nodiscard]] const char* BuildIdentity() noexcept;
} // namespace gpg::diag
