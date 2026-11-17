#pragma once
#include "SfdHeaderParser.h"
#include <expected>
#include <string>
#include <vector>
namespace moho::sfd
{
  struct Metadata
  {
    HeaderInfo header;
    std::vector<std::uint16_t> privatePacketLengths;
  };
  [[nodiscard]] std::expected<void, std::string> ReadMetadata(const char* filename, Metadata& result);
  // Unknown subtitle/user-data formats intentionally have no guessed decoder.
} // namespace moho::sfd
