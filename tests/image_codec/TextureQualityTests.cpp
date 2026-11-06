// Engine addition: the original's texture-quality mip skip applies to 2D DDS,
// not to cubes or volumes. This topology check needs no graphics device.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "gpg/gal/backends/common/TextureQuality.h"

namespace
{
  int gFailures = 0;

  void Check(const bool condition, const char* const what)
  {
    if (!condition) {
      std::printf("FAIL: %s\n", what);
      ++gFailures;
    }
  }

  void Put(std::uint8_t* const data, const std::size_t offset, const std::uint32_t value)
  {
    std::memcpy(data + offset, &value, sizeof(value));
  }

  void TestTopology(const std::uint32_t skip)
  {
    // Deliberately unaligned: DDS files need no word alignment.
    std::array<std::uint8_t, 150U> storage{};
    std::uint8_t* const data = storage.data() + 1U;
    Put(data, 0U, 0x20534444U);
    Put(data, 4U, 124U);
    Put(data, 76U, 32U);
    Put(data, 80U, 0x4U);
    Put(data, 84U, 0x31545844U);
    const auto effective = [&](const std::size_t bytes = 148U) {
      return gpg::gal::imaging::TextureQualityMipLevels(data, bytes, skip);
    };

    Check(gpg::gal::imaging::TextureQualityMipLevels(nullptr, 0U, skip) == skip, "null input");
    for (std::size_t bytes = 0U; bytes < 128U; ++bytes) {
      Check(effective(bytes) == skip, "short legacy header");
    }
    Check(effective() == skip, "ordinary 2D preserves quality");
    for (const std::uint32_t caps : {0x200U, 0xFE00U, 0x200000U, 0x200200U}) {
      Put(data, 112U, caps);
      Check(effective() == 0U, "legacy cube or volume retains top mip");
    }
    Put(data, 112U, 0U);
    Put(data, 84U, 0x30315844U);
    for (const std::uint32_t dimension : {3U, 4U}) {
      for (const std::uint32_t misc : {0U, 4U}) {
        for (const std::uint32_t legacyCaps : {0U, 0x200U, 0x200000U}) {
          Put(data, 112U, legacyCaps);
          Put(data, 132U, dimension);
          Put(data, 136U, misc);
          Put(data, 140U, 3U); // arrays do not themselves suppress 2D quality
          Check(effective() == (dimension == 4U || misc == 4U ? 0U : skip), "DX10 topology supersedes legacy caps");
        }
      }
    }
    Put(data, 112U, 0U);
    for (std::size_t bytes = 128U; bytes < 148U; ++bytes) {
      Check(effective(bytes) == skip, "short DX10 extension");
    }
    Put(data, 80U, 0x41U); // RGB: the unused FourCC slot must not enable DX10
    Check(effective() == skip, "RGB ignores unused FourCC slot");
    Put(data, 112U, 0x200U);
    Check(effective() == 0U, "RGB cube retains top mip");
    Put(data, 0U, 0U);
    Check(effective() == skip, "non-DDS input preserves quality");
  }
} // namespace

int main()
{
  for (std::uint32_t skip = 0U; skip < 32U; ++skip) {
    TestTopology(skip);
  }
  std::printf("%d failed\n", gFailures);
  return gFailures == 0 ? 0 : 1;
}
