#include "SfdMetadata.h"
#include <array>
#include <filesystem>
#include <fstream>
namespace moho::sfd
{
  bool ReadMetadata(
    const char* filename,
    Metadata& result,
    std::string& error
  )
  {
    result = {};
    if (!filename || !*filename) {
      error = "Empty movie path";
      return false;
    }
    const auto* utf8 = reinterpret_cast<const char8_t*>(filename);
    std::ifstream file(std::filesystem::path(std::u8string_view(utf8)), std::ios::binary);
    std::array<std::byte, 65536> bytes{};
    file.read(reinterpret_cast<char*>(bytes.data()), bytes.size());
    const std::span<const std::byte> data(bytes.data(), static_cast<std::size_t>(file.gcount()));
    if (!ParseSfdHeader(data, result.header)) {
      error = "Missing, malformed or unsupported FAF SFD header";
      return false;
    }
    // Diagnostic only: inspect bounded private_stream_2 packet candidates, never
    // demux media or interpret unconfirmed CRITAGS/AINF/subtitle layouts here.
    for (std::size_t i = 0; i + 6 <= data.size(); ++i) {
      if (data[i] != std::byte{0} || data[i + 1] != std::byte{0} || data[i + 2] != std::byte{1} ||
          data[i + 3] != std::byte{0xbf})
        continue;
      const auto length = static_cast<std::uint16_t>(
        (std::to_integer<unsigned>(data[i + 4]) << 8) | std::to_integer<unsigned>(data[i + 5])
      );
      if (length <= data.size() - i - 6) {
        result.privatePacketLengths.push_back(length);
        i += 5 + length;
      }
    }
    return true;
  }
} // namespace moho::sfd
