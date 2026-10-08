#pragma once
#include "SfdHeaderParser.h"
#include <string>
#include <vector>
namespace moho::sfd
{
  struct Metadata
  {
    HeaderInfo header;
    std::vector<std::uint16_t> privatePacketLengths;
  };
  bool ReadMetadata(const char* filename, Metadata& result, std::string& error);
  // Unknown subtitle/user-data formats intentionally have no guessed decoder.
} // namespace moho::sfd
