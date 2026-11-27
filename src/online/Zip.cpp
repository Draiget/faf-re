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

  namespace
  {
    void Put16(
      std::string& out,
      const std::uint32_t value
    )
    {
      out.push_back(static_cast<char>(value & 0xFF));
      out.push_back(static_cast<char>((value >> 8) & 0xFF));
    }

    void Put32(
      std::string& out,
      const std::uint32_t value
    )
    {
      Put16(out, value & 0xFFFF);
      Put16(out, value >> 16);
    }
  } // namespace

  std::expected<std::string, std::string> WriteZip(
    const std::vector<ZipEntry>& entries
  )
  {
    constexpr std::size_t kLimit = std::size_t{1} << 30;
    if (entries.size() > 0xFFFF) {
      return std::unexpected(std::string("too many files for a zip archive"));
    }
    std::string out;
    std::string central;
    for (const ZipEntry& entry : entries) {
      const bool folder = !entry.name.empty() && entry.name.back() == '/';
      const auto crc = static_cast<std::uint32_t>(
        crc32(0, reinterpret_cast<const Bytef*>(entry.data.data()), static_cast<uInt>(entry.data.size()))
      );
      std::string packed;
      std::uint32_t method = 0;
      if (!folder && !entry.data.empty()) {
        z_stream stream{};
        if (deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -MAX_WBITS, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
          return std::unexpected(std::string("can't compress"));
        }
        packed.resize(deflateBound(&stream, static_cast<uLong>(entry.data.size())));
        stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(entry.data.data()));
        stream.avail_in = static_cast<uInt>(entry.data.size());
        stream.next_out = reinterpret_cast<Bytef*>(packed.data());
        stream.avail_out = static_cast<uInt>(packed.size());
        const bool done = deflate(&stream, Z_FINISH) == Z_STREAM_END;
        packed.resize(stream.total_out);
        deflateEnd(&stream);
        if (done && packed.size() < entry.data.size()) {
          method = 8;
        } else {
          packed = entry.data;
        }
      }
      if (out.size() + packed.size() + entry.name.size() + 128 > kLimit) {
        return std::unexpected(std::string("the archive would pass 1 GB"));
      }
      const auto offset = static_cast<std::uint32_t>(out.size());
      // The local header: version 2.0, UTF-8 names (bit 11), the method, no time, CRC and sizes.
      Put32(out, 0x04034b50);
      Put16(out, 20);
      Put16(out, 0x0800);
      Put16(out, method);
      Put16(out, 0);
      Put16(out, 0x21); // 1980-01-01
      Put32(out, crc);
      Put32(out, static_cast<std::uint32_t>(packed.size()));
      Put32(out, static_cast<std::uint32_t>(entry.data.size()));
      Put16(out, static_cast<std::uint32_t>(entry.name.size()));
      Put16(out, 0);
      out += entry.name;
      out += packed;
      // Its central directory record.
      Put32(central, 0x02014b50);
      Put16(central, 20);
      Put16(central, 20);
      Put16(central, 0x0800);
      Put16(central, method);
      Put16(central, 0);
      Put16(central, 0x21);
      Put32(central, crc);
      Put32(central, static_cast<std::uint32_t>(packed.size()));
      Put32(central, static_cast<std::uint32_t>(entry.data.size()));
      Put16(central, static_cast<std::uint32_t>(entry.name.size()));
      Put16(central, 0);
      Put16(central, 0);
      Put16(central, 0);
      Put16(central, 0);
      Put32(central, folder ? 0x10 : 0); // the MS-DOS folder attribute
      Put32(central, offset);
      central += entry.name;
    }
    const auto centralOffset = static_cast<std::uint32_t>(out.size());
    out += central;
    Put32(out, 0x06054b50);
    Put16(out, 0);
    Put16(out, 0);
    Put16(out, static_cast<std::uint32_t>(entries.size()));
    Put16(out, static_cast<std::uint32_t>(entries.size()));
    Put32(out, static_cast<std::uint32_t>(central.size()));
    Put32(out, centralOffset);
    Put16(out, 0);
    return out;
  }
} // namespace faf::online
