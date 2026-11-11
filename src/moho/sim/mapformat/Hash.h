// CRC32 (IEEE 802.3, reflected, as zlib) and SHA-256 for the map container. Standard library only.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace moho::mapformat {

/// CRC32 of `size` bytes; pass the previous result as `crc` to continue a running value.
std::uint32_t Crc32(const std::uint8_t* data, std::size_t size, std::uint32_t crc = 0);

class Sha256 {
 public:
  Sha256();
  void Update(const std::uint8_t* data, std::size_t size);
  /// Finishes and writes the 32-byte digest. The object must not be used afterwards.
  void Final(std::uint8_t out[32]);

 private:
  void Block(const std::uint8_t* p);
  std::uint32_t h_[8];
  std::uint8_t buf_[64];
  std::uint64_t total_ = 0;
  std::size_t fill_ = 0;
};

/// SHA-256 as 64 lower-case hex characters.
std::string Sha256Hex(const std::uint8_t* data, std::size_t size);
std::string HexString(const std::uint8_t* data, std::size_t size);

} // namespace moho::mapformat
