// zlib Adler-32 runtime recovery (ForgedAlliance.exe statically links zlib 1.2.x
// as zlib.lib). Matches the binary body at FUN_0095D3B0 and overrides the
// library copy via .obj-before-.lib resolution; the TU is ExcludedFromBuild (a
// source-faithful record verified per-TU + standalone).

#include <cstdint>

namespace {

// Largest prime below 65536, and the largest run length before the sums must be
// reduced modulo BASE to avoid overflow.
constexpr std::uint32_t kAdlerBase = 65521u;
constexpr std::uint32_t kAdlerNmax = 5552u;

// One 16-byte Adler block: s1 += byte; s2 += s1 for sixteen bytes.
inline void DoBlock16(const unsigned char*& buf, std::uint32_t& s1, std::uint32_t& s2) noexcept
{
  for (int i = 0; i < 16; ++i)
  {
    s1 += *buf++;
    s2 += s1;
  }
}

} // namespace

/**
 * Address: 0x0095D3B0 (FUN_0095D3B0)
 * Mangled: adler32
 *
 * IDA signature:
 * unsigned int __cdecl adler32(unsigned int adler, unsigned char* buf, unsigned int len);
 *
 * zlib Adler-32 checksum. Splits the running value into s1 (low 16 bits) and s2
 * (high 16 bits); a single byte and buffers shorter than 16 bytes take dedicated
 * fast paths, while longer buffers are folded in NMAX-sized runs (with the sums
 * reduced modulo BASE between runs) then a 16-byte-unrolled tail. Returns 1 for a
 * null buffer (the adler32(0, Z_NULL, 0) initial-value convention). Verified 1:1
 * against FUN_0095D3B0.asm and self-checked against the canonical vectors.
 */
extern "C" unsigned long adler32(unsigned long adler, const unsigned char* buf, unsigned int len)
{
  std::uint32_t s2 = (adler >> 16) & 0xFFFFu;
  std::uint32_t s1 = adler & 0xFFFFu;

  // Single-byte fast path.
  if (len == 1)
  {
    s1 += buf[0];
    if (s1 >= kAdlerBase)
    {
      s1 -= kAdlerBase;
    }
    s2 += s1;
    if (s2 >= kAdlerBase)
    {
      s2 -= kAdlerBase;
    }
    return s1 | (s2 << 16);
  }

  if (buf == nullptr)
  {
    return 1;
  }

  // Short buffers: no NMAX chunking, a single reduction at the end.
  if (len < 16)
  {
    while (len-- != 0)
    {
      s1 += *buf++;
      s2 += s1;
    }
    if (s1 >= kAdlerBase)
    {
      s1 -= kAdlerBase;
    }
    // s2 is small here, so (s2 + 15*(s2/BASE)) truncated to 16 bits == s2 % BASE.
    return s1 | ((s2 + 15u * (s2 / kAdlerBase)) << 16);
  }

  // Long buffers: fold NMAX bytes at a time, reducing between runs.
  while (len >= kAdlerNmax)
  {
    len -= kAdlerNmax;
    unsigned int n = kAdlerNmax / 16;  // 347 sixteen-byte blocks
    do
    {
      DoBlock16(buf, s1, s2);
    } while (--n != 0);
    s1 %= kAdlerBase;
    s2 %= kAdlerBase;
  }

  // Remaining tail (< NMAX): 16-byte blocks, then leftover bytes.
  if (len != 0)
  {
    while (len >= 16)
    {
      len -= 16;
      DoBlock16(buf, s1, s2);
    }
    while (len-- != 0)
    {
      s1 += *buf++;
      s2 += s1;
    }
    s1 %= kAdlerBase;
    s2 %= kAdlerBase;
  }

  return s1 | (s2 << 16);
}
