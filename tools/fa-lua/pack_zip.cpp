// faf_pack_zip: writes faf-re-lua.nx2 (cmake/FafLuaArchive.cmake).
//
// The engine's zip reader, like the shipped game's, skips every entry whose local header leaves the
// sizes to a data descriptor (moho/misc/CZipFile.cpp), and that is what CMake's own zip writer
// (`cmake -E tar --format=zip`) makes. This writes stored entries with their sizes and CRC in the
// local header, in the order given, with one fixed time stamp, so the same files give the same
// archive.
//
// usage: faf_pack_zip <archive> <folder> <entry>...   (entries are '/'-separated paths in <folder>)

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace
{
  constexpr std::uint16_t kDosTime = 0u;      // 00:00:00
  constexpr std::uint16_t kDosDate = 0x5021u; // 2020-01-01

  void Put16(
    std::string& out,
    const std::uint16_t value
  )
  {
    out.push_back(static_cast<char>(value & 0xFFu));
    out.push_back(static_cast<char>(value >> 8));
  }

  void Put32(
    std::string& out,
    const std::uint32_t value
  )
  {
    Put16(out, static_cast<std::uint16_t>(value & 0xFFFFu));
    Put16(out, static_cast<std::uint16_t>(value >> 16));
  }

  [[nodiscard]] std::uint32_t Crc32(
    const std::string& bytes
  )
  {
    std::uint32_t crc = 0xFFFFFFFFu;
    for (const char byte : bytes) {
      crc ^= static_cast<unsigned char>(byte);
      for (int bit = 0; bit < 8; ++bit) {
        crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
      }
    }
    return ~crc;
  }

  /** The fields a local header and its central directory record share, from "version needed" on. */
  void PutCommon(
    std::string& out,
    const std::uint32_t crc,
    const std::uint32_t size,
    const std::string& name
  )
  {
    Put16(out, 10u); // version needed: 1.0, stored
    Put16(out, 0u);  // flags: no data descriptor
    Put16(out, 0u);  // method: stored
    Put16(out, kDosTime);
    Put16(out, kDosDate);
    Put32(out, crc);
    Put32(out, size);
    Put32(out, size);
    Put16(out, static_cast<std::uint16_t>(name.size()));
    Put16(out, 0u); // extra field length
  }
} // namespace

int main(
  int argc,
  char** argv
)
{
  if (argc < 4) {
    std::fprintf(stderr, "usage: faf_pack_zip <archive> <folder> <entry>...\n");
    return 2;
  }
  const std::filesystem::path folder = argv[2];
  std::string body;
  std::string directory;
  std::uint16_t count = 0;
  for (int index = 3; index < argc; ++index) {
    const std::string name = argv[index];
    std::ifstream in(folder / std::filesystem::path(name), std::ios::binary);
    if (!in) {
      std::fprintf(stderr, "faf_pack_zip: can't read %s\n", (folder / name).string().c_str());
      return 1;
    }
    const std::string payload((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (body.size() + payload.size() > 0x7FFFFFFFu || count == 0xFFFFu) {
      std::fprintf(stderr, "faf_pack_zip: too big for a zip without zip64\n");
      return 1;
    }
    const std::uint32_t crc = Crc32(payload);
    const auto size = static_cast<std::uint32_t>(payload.size());
    const auto offset = static_cast<std::uint32_t>(body.size());

    Put32(body, 0x04034B50u);
    PutCommon(body, crc, size, name);
    body += name;
    body += payload;

    Put32(directory, 0x02014B50u);
    Put16(directory, 20u); // made by: 2.0, MS-DOS attributes
    PutCommon(directory, crc, size, name);
    Put16(directory, 0u); // comment length
    Put16(directory, 0u); // disk number
    Put16(directory, 0u); // internal attributes
    Put32(directory, 0u); // external attributes
    Put32(directory, offset);
    directory += name;
    ++count;
  }

  std::string out = body + directory;
  Put32(out, 0x06054B50u);
  Put16(out, 0u);
  Put16(out, 0u);
  Put16(out, count);
  Put16(out, count);
  Put32(out, static_cast<std::uint32_t>(directory.size()));
  Put32(out, static_cast<std::uint32_t>(body.size()));
  Put16(out, 0u);

  std::ofstream file(argv[1], std::ios::binary | std::ios::trunc);
  file.write(out.data(), static_cast<std::streamsize>(out.size()));
  if (!file) {
    std::fprintf(stderr, "faf_pack_zip: can't write %s\n", argv[1]);
    return 1;
  }
  return 0;
}
