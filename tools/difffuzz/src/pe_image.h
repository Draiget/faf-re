#pragma once

#include <cstdint>
#include <string>

namespace difffuzz
{
  /**
   * Maps the retail ForgedAlliance.exe at its preferred base (0x00400000)
   * without running any of it: no entry point, no TLS callbacks, no import
   * resolution. Every IAT slot is pointed at a per-import trap stub that
   * prints "unresolved import DLL!name" and raises an SEH exception the
   * harness catches, so a target that accidentally reaches an import fails
   * loudly instead of jumping into garbage.
   */
  class RetailImage
  {
  public:
    bool Load(const std::string& path, std::string& error);

    [[nodiscard]] std::uint32_t Base() const noexcept { return mBase; }
    [[nodiscard]] std::uint32_t SizeOfImage() const noexcept { return mSizeOfImage; }
    [[nodiscard]] unsigned ImportCount() const noexcept { return mImportCount; }

    /// True when `va` lies inside a mapped executable section.
    [[nodiscard]] bool IsExecutable(std::uint32_t va) const noexcept;

    /// Writes one dword into the mapped image (used to seed CRT globals such
    /// as `global_mode_sse2`, which the never-run CRT init would have set).
    bool PokeDword(std::uint32_t va, std::uint32_t value) noexcept;

  private:
    std::uint32_t mBase = 0;
    std::uint32_t mSizeOfImage = 0;
    unsigned mImportCount = 0;
  };

  /// Reads ImageBase/SizeOfImage from the PE header without mapping anything.
  bool ReadImageExtent(const std::string& path, std::uint32_t& base, std::uint32_t& size);

  /// Re-runs this exe with the same command line as a suspended child,
  /// commits [base, base+size) in it before it initialises (process init
  /// otherwise puts NLS views and heaps at 0x00400000), resumes it and
  /// returns its exit code.
  int RelaunchWithPreclaimedImage(std::uint32_t base, std::uint32_t size);
} // namespace difffuzz
