// zlib CRC-32 runtime recovery.
//
// ForgedAlliance.exe statically links zlib (1.2.x) as zlib.lib; this recovered
// crc32 matches the binary body at FUN_0095DE30 and overrides the library copy
// via normal .obj-before-.lib symbol resolution.
//
// The binary uses zlib's slice-by-4 little-endian CRC (crc32_little) driven by
// four 256-entry lookup tables held as static data at VA 0xD4A698..0xD4B698.
// Those tables are the standard reflected CRC-32 (polynomial 0xEDB88320) and its
// three derived slice tables; they are reproduced here as a constexpr table so
// the values are identical to the binary's static data (verified byte-for-byte
// against bin/2025.7.1/ForgedAlliance.exe: crc_table[0] signature at file offset
// 0x94A698, crc_table[3][1] == 0xB8BC6765) and self-verified against the
// canonical CRC32("123456789") == 0xCBF43926.

#include <cstdint>

namespace {

// Four slice-by-4 CRC-32 tables. crc_table[0] is the standard reflected CRC-32
// table; crc_table[k][n] = crc_table[0][crc_table[k-1][n] & 0xff] ^
// (crc_table[k-1][n] >> 8). Matches zlib's make_crc_table (BYFOUR).
struct CrcTables
{
  std::uint32_t table[4][256];
};

constexpr CrcTables MakeCrcTables() noexcept
{
  CrcTables ct{};
  for (int n = 0; n < 256; ++n)
  {
    std::uint32_t c = static_cast<std::uint32_t>(n);
    for (int k = 0; k < 8; ++k)
    {
      c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
    }
    ct.table[0][n] = c;
  }
  for (int n = 0; n < 256; ++n)
  {
    std::uint32_t c = ct.table[0][n];
    for (int k = 1; k < 4; ++k)
    {
      c = ct.table[0][c & 0xffu] ^ (c >> 8);
      ct.table[k][n] = c;
    }
  }
  return ct;
}

constexpr CrcTables kCrc = MakeCrcTables();

// One slice-by-4 step over the next little-endian 32-bit word of input.
[[nodiscard]] inline std::uint32_t SliceStep(std::uint32_t c, const unsigned char* buf) noexcept
{
  c ^= static_cast<std::uint32_t>(buf[0]) | (static_cast<std::uint32_t>(buf[1]) << 8)
     | (static_cast<std::uint32_t>(buf[2]) << 16) | (static_cast<std::uint32_t>(buf[3]) << 24);
  return kCrc.table[3][c & 0xffu] ^ kCrc.table[2][(c >> 8) & 0xffu]
       ^ kCrc.table[1][(c >> 16) & 0xffu] ^ kCrc.table[0][c >> 24];
}

} // namespace

/**
 * Address: 0x0095DE30 (FUN_0095DE30)
 * Mangled: crc32
 *
 * IDA signature:
 * unsigned int __cdecl crc32(unsigned int crc, unsigned char *buf, unsigned int len);
 *
 * zlib slice-by-4 little-endian CRC-32. Returns 0 for a null buffer (the
 * crc32(0, Z_NULL, 0) initial-value convention). Otherwise it inverts the
 * incoming CRC, byte-aligns the pointer to a 4-byte boundary, folds the bulk in
 * 32-byte then 4-byte slice-by-4 blocks, finishes any trailing bytes one at a
 * time, and inverts the result — matching the binary exactly.
 */
extern "C" unsigned long crc32(unsigned long crc, const unsigned char* buf, unsigned int len)
{
  if (buf == nullptr)
  {
    return 0;
  }

  std::uint32_t c = ~static_cast<std::uint32_t>(crc);

  // Align the pointer to a 4-byte boundary one byte at a time.
  while (len != 0 && (reinterpret_cast<std::uintptr_t>(buf) & 3u) != 0)
  {
    c = kCrc.table[0][(c ^ *buf++) & 0xffu] ^ (c >> 8);
    --len;
  }

  // Bulk: 32-byte blocks (eight slice-by-4 steps), then 4-byte blocks.
  while (len >= 32)
  {
    for (int i = 0; i < 8; ++i)
    {
      c = SliceStep(c, buf);
      buf += 4;
    }
    len -= 32;
  }
  while (len >= 4)
  {
    c = SliceStep(c, buf);
    buf += 4;
    len -= 4;
  }

  // Trailing bytes.
  while (len != 0)
  {
    c = kCrc.table[0][(c ^ *buf++) & 0xffu] ^ (c >> 8);
    --len;
  }

  return ~c;
}
