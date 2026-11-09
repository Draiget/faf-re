// Shared helpers for faf_core_tests: a temporary folder each test removes, and byte patterns tests build
// their inputs from. Nothing here reads files the test didn't write itself.
#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <system_error>

namespace faf_core_tests
{
  /** A folder under the system temp folder, created here and removed with everything in it on destruction. */
  class TempDir
  {
  public:
    TempDir();
    ~TempDir();
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;

    [[nodiscard]] const std::filesystem::path& Path() const noexcept { return mPath; }
    [[nodiscard]] std::string File(const char* name) const { return (mPath / name).string(); }

  private:
    std::filesystem::path mPath;
  };

  /** `size` bytes of a fixed, non-repeating-looking pattern (an LCG), so misplaced or dropped bytes show. */
  [[nodiscard]] std::string PatternBytes(std::size_t size, std::uint32_t seed = 1u);

  /** The whole content of a file, read with the C runtime (not the code under test). */
  [[nodiscard]] std::string ReadWholeFile(const std::string& path);

  /** Writes `bytes` to `path` with the C runtime, replacing what was there. */
  void WriteWholeFile(const std::string& path, const std::string& bytes);

  /** Lowercase hex of `size` bytes. */
  [[nodiscard]] std::string ToHex(const void* data, std::size_t size);
} // namespace faf_core_tests
