// Engine addition (in-game launcher plan, WP6): zip archives in memory (online/Zip.h), as the map editor read them.

#include "online/Zip.h"

#include <cstdint>
#include <cstring>

#include "zlib.h"

namespace faf::online
{
  namespace
  {
    /** No mod or map comes near this; a bigger archive is damaged or hostile. */
    constexpr std::uint64_t kMaxUnpacked = 1024ull * 1024ull * 1024ull;

    std::uint32_t Get32(
      const std::string& data,
      const std::size_t at
    )
    {
      std::uint32_t value = 0;
      std::memcpy(&value, data.data() + at, sizeof(value));
      return value;
    }

    std::uint16_t Get16(
      const std::string& data,
      const std::size_t at
    )
    {
      std::uint16_t value = 0;
      std::memcpy(&value, data.data() + at, sizeof(value));
      return value;
    }

  } // namespace

  std::expected<std::vector<ZipEntry>, std::string> ReadZip(
    const std::string& zip
  )
  {
    std::vector<ZipEntry> entries;
    std::uint64_t unpacked = 0;
    // The end of central directory record: its signature within the last 64 KB and 22 bytes.
    std::size_t end = std::string::npos;
    for (std::size_t at = zip.size() >= 22 ? zip.size() - 22 : std::string::npos;
         at != std::string::npos && zip.size() - at <= 65557;
         --at) {
      if (Get32(zip, at) == 0x06054B50u) {
        end = at;
        break;
      }
      if (at == 0) {
        break;
      }
    }
    if (end == std::string::npos) {
      return std::unexpected("not a zip archive");
    }
    const std::uint16_t count = Get16(zip, end + 10);
    std::size_t at = Get32(zip, end + 16);
    for (std::uint16_t i = 0; i < count; ++i) {
      if (at + 46 > zip.size() || Get32(zip, at) != 0x02014B50u) {
        return std::unexpected("the archive's directory is broken");
      }
      const std::uint16_t method = Get16(zip, at + 10);
      const std::uint32_t crc = Get32(zip, at + 16);
      const std::uint32_t packed = Get32(zip, at + 20);
      const std::uint32_t size = Get32(zip, at + 24);
      const std::uint16_t nameLength = Get16(zip, at + 28);
      const std::uint16_t extraLength = Get16(zip, at + 30);
      const std::uint16_t commentLength = Get16(zip, at + 32);
      const std::uint32_t local = Get32(zip, at + 42);
      if (at + 46 + nameLength > zip.size()) {
        return std::unexpected("the archive's directory is broken");
      }
      unpacked += size;
      if (unpacked > kMaxUnpacked) {
        return std::unexpected(std::string("the archive unpacks to more than 1 GB"));
      }
      ZipEntry entry;
      entry.name = zip.substr(at + 46, nameLength);
      at += 46 + static_cast<std::size_t>(nameLength) + extraLength + commentLength;
      // The data follows the local header (its name and extra field can differ in length from the directory's).
      if (local + 30 > zip.size() || Get32(zip, local) != 0x04034B50u) {
        return std::unexpected("the archive's entry " + entry.name + " is broken");
      }
      const std::size_t data = local + 30 + Get16(zip, local + 26) + Get16(zip, local + 28);
      if (data + packed > zip.size()) {
        return std::unexpected("the archive is cut short at " + entry.name);
      }
      if (method == 0) {
        entry.data = zip.substr(data, packed);
      } else if (method == 8) {
        entry.data.resize(size);
        z_stream stream{};
        stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(zip.data() + data));
        stream.avail_in = packed;
        stream.next_out = reinterpret_cast<Bytef*>(entry.data.data());
        stream.avail_out = size;
        const bool inflated = inflateInit2(&stream, -MAX_WBITS) == Z_OK && inflate(&stream, Z_FINISH) == Z_STREAM_END &&
          stream.total_out == size;
        inflateEnd(&stream);
        if (!inflated) {
          return std::unexpected("the archive's entry " + entry.name + " doesn't unpack");
        }
      } else {
        return std::unexpected(
          "the archive's entry " + entry.name + " is packed in a way this program can't read (method " +
          std::to_string(method) + ")"
        );
      }
      if (crc32(0, reinterpret_cast<const Bytef*>(entry.data.data()), static_cast<uInt>(entry.data.size())) != crc) {
        return std::unexpected("the archive's entry " + entry.name + " is damaged (its checksum differs)");
      }
      entries.push_back(std::move(entry));
    }
    return entries;
  }
} // namespace faf::online
