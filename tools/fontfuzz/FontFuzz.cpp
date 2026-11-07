// Engine addition: fuzzes what a mod's font goes through (issue #305): the structure check, the cook, and the
// atlas that comes back. Run it built with FAF_FONTFUZZ_SANITIZE, so AddressSanitizer turns a bad read into a stop.
//
//   faf_fontfuzz <folder of fonts> [--seed N] [--seconds N] [--iterations N] [--save <folder>]
//
// Most inputs only change bytes inside tables, keeping the file's structure, because anything else stops at the
// structure check and never reaches a parser. Each input is written to <folder>/last.ttf first, so one that
// brings the process down is on disk. It uses no engine code, so the x64 small-block pool isn't in the way.

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <random>
#include <string>
#include <vector>

#include "moho/render/font/MsdfFontCheck.h"
#include "moho/render/font/MsdfFontCook.h"

namespace
{
  using Bytes = std::vector<std::uint8_t>;
  using Random = std::mt19937_64;

  struct TableSpan
  {
    std::size_t mOffset;
    std::size_t mLength;
  };

  std::uint32_t GetU32(const Bytes& bytes, const std::size_t at)
  {
    return (static_cast<std::uint32_t>(bytes[at]) << 24u) | (static_cast<std::uint32_t>(bytes[at + 1u]) << 16u)
      | (static_cast<std::uint32_t>(bytes[at + 2u]) << 8u) | bytes[at + 3u];
  }

  std::vector<TableSpan> ReadTables(const Bytes& font)
  {
    std::vector<TableSpan> tables;
    const std::size_t count = (static_cast<std::size_t>(font[4]) << 8u) | font[5];
    for (std::size_t i = 0; i < count; ++i) {
      const std::size_t entry = 12u + i * 16u;
      const TableSpan span{GetU32(font, entry + 8u), GetU32(font, entry + 12u)};
      if (span.mLength != 0u && span.mOffset + span.mLength <= font.size()) {
        tables.push_back(span);
      }
    }
    return tables;
  }

  std::uint8_t InterestingByte(Random& random)
  {
    static constexpr std::uint8_t values[] = {0x00u, 0x01u, 0x7Fu, 0x80u, 0xFEu, 0xFFu};
    return random() % 3u == 0u ? values[random() % std::size(values)] : static_cast<std::uint8_t>(random());
  }

  /** Bytes inside tables only: the structure check still passes, and the parsers get to see them. */
  void MutateTables(Bytes& font, Random& random)
  {
    const std::vector<TableSpan> tables = ReadTables(font);
    if (tables.empty()) {
      return;
    }
    const int edits = 1 + static_cast<int>(random() % 16u);
    for (int i = 0; i < edits; ++i) {
      const TableSpan& table = tables[random() % tables.size()];
      // Half the time near the start, where the headers and counts are.
      const std::size_t window = random() % 2u == 0u ? (std::min<std::size_t>)(table.mLength, 64u) : table.mLength;
      font[table.mOffset + random() % window] = InterestingByte(random);
    }
  }

  /** The file's shape: what the structure check is there to catch. */
  void MutateStructure(Bytes& font, Random& random)
  {
    const std::size_t count = (static_cast<std::size_t>(font[4]) << 8u) | font[5];
    switch (random() % 5u) {
      case 0u:
        font[12u + random() % (count * 16u)] = InterestingByte(random);
        break;
      case 1u:
        font.resize(random() % font.size());
        break;
      case 2u:
        font.resize(font.size() + 1u + random() % 64u, InterestingByte(random));
        break;
      case 3u:
        font[random() % 12u] = InterestingByte(random);
        break;
      default:
        for (int i = 0; i < 8 && !font.empty(); ++i) {
          font[random() % font.size()] = InterestingByte(random);
        }
        break;
    }
  }

  struct Counts
  {
    std::uint64_t mInputs = 0u;
    std::uint64_t mStructureRefused = 0u;
    std::uint64_t mCookRefused = 0u;
    std::uint64_t mCooked = 0u;
    std::uint64_t mAtlasRefused = 0u;
    int mSlowestMs = 0;
  };

  void RunOne(const Bytes& input, const moho::SMsdfCookOptions& options, Counts& counts, Random& random)
  {
    ++counts.mInputs;
    std::string reason;
    if (!moho::MSDF_CheckFontStructure(input.data(), input.size(), reason)) {
      ++counts.mStructureRefused;
      return;
    }

    (void)moho::MSDF_ReadFontNames(input.data(), input.size());

    moho::SMsdfFontAtlas atlas;
    const auto start = std::chrono::steady_clock::now();
    const bool cooked = moho::MSDF_CookFont(input.data(), input.size(), options, atlas, reason);
    counts.mSlowestMs = (std::max)(
      counts.mSlowestMs, static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count())
    );
    if (!cooked) {
      ++counts.mCookRefused;
      return;
    }
    ++counts.mCooked;

    // What comes back from a cache file is an input too.
    Bytes packed = moho::MSDF_SaveAtlas(atlas);
    if (packed.empty()) {
      return;
    }
    const int edits = static_cast<int>(random() % 4u);
    for (int i = 0; i < edits; ++i) {
      packed[random() % packed.size()] = InterestingByte(random);
    }
    moho::SMsdfFontAtlas loaded;
    if (!moho::MSDF_LoadAtlas(packed.data(), packed.size(), loaded) || !moho::MSDF_CheckCookedAtlas(loaded, options, reason)) {
      ++counts.mAtlasRefused;
    }
  }
} // namespace

int main(const int argc, char** const argv)
{
  if (argc < 2) {
    std::printf("usage: faf_fontfuzz <folder of fonts> [--seed N] [--seconds N] [--iterations N] [--save <folder>]\n");
    return 2;
  }
  std::uint64_t seed = 1u;
  long seconds = 60;
  std::uint64_t iterations = 0u;
  std::filesystem::path saveFolder = ".";
  for (int i = 2; i + 1 < argc; i += 2) {
    const std::string name = argv[i];
    if (name == "--seed") {
      seed = std::strtoull(argv[i + 1], nullptr, 10);
    } else if (name == "--seconds") {
      seconds = std::strtol(argv[i + 1], nullptr, 10);
    } else if (name == "--iterations") {
      iterations = std::strtoull(argv[i + 1], nullptr, 10);
    } else if (name == "--save") {
      saveFolder = argv[i + 1];
    }
  }

  std::vector<Bytes> fonts;
  for (const auto& entry : std::filesystem::directory_iterator(argv[1])) {
    std::ifstream in(entry.path(), std::ios::binary);
    Bytes bytes{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    std::string reason;
    if (moho::MSDF_CheckFontStructure(bytes.data(), bytes.size(), reason)) {
      fonts.push_back(std::move(bytes));
    } else {
      std::printf("skipped %s: %s\n", entry.path().string().c_str(), reason.c_str());
    }
  }
  if (fonts.empty()) {
    std::printf("no usable fonts in %s\n", argv[1]);
    return 2;
  }

  // A mod's limits, with few characters and small glyphs: the parsers are the target, and this gets
  // through far more inputs.
  moho::SMsdfCookOptions options = moho::MSDF_MakeModCookOptions(1);
  options.mEmPixels = 16.0;
  options.mDistanceRange = 4.0;
  options.mCodepoints = {' ', 'A', 'B', 'g', 'i', '&', '@', '0', 0xE9u, 0x416u, 0x2014u};
  options.mStrikeSizes = {10, 13};

  std::filesystem::create_directories(saveFolder);
  const std::filesystem::path lastPath = saveFolder / "last.ttf";
  Random random(seed);
  Counts counts;
  const auto start = std::chrono::steady_clock::now();
  for (;;) {
    if (iterations != 0u ? counts.mInputs >= iterations
                         : std::chrono::steady_clock::now() - start >= std::chrono::seconds(seconds)) {
      break;
    }
    Bytes input = fonts[random() % fonts.size()];
    if (random() % 8u == 0u) {
      MutateStructure(input, random);
    } else {
      MutateTables(input, random);
    }
    {
      std::ofstream out(lastPath, std::ios::binary | std::ios::trunc);
      out.write(reinterpret_cast<const char*>(input.data()), static_cast<std::streamsize>(input.size()));
    }
    RunOne(input, options, counts, random);
  }

  std::printf(
    "seed %llu: %llu inputs, %llu refused by structure, %llu refused by the cook, %llu cooked, %llu atlases refused, slowest cook %d ms\n",
    static_cast<unsigned long long>(seed), static_cast<unsigned long long>(counts.mInputs),
    static_cast<unsigned long long>(counts.mStructureRefused), static_cast<unsigned long long>(counts.mCookRefused),
    static_cast<unsigned long long>(counts.mCooked), static_cast<unsigned long long>(counts.mAtlasRefused), counts.mSlowestMs
  );
  return 0;
}
