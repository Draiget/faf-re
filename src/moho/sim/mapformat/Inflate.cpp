// Raw DEFLATE decoder (RFC 1951). Structure follows Mark Adler's puff.c (canonical Huffman decoding with count/symbol
// tables) with a 64-bit bit buffer and a 10-bit lookup table in front of the canonical decode for speed.
#include "moho/sim/mapformat/Inflate.h"

#include <cstring>

namespace moho::mapformat {
namespace {

constexpr int kMaxBits = 15;
constexpr int kFastBits = 10;
constexpr int kMaxLitCodes = 288;

struct Huffman
{
  std::uint16_t count[kMaxBits + 1];
  std::uint16_t symbol[kMaxLitCodes];
  // (length << 9) | symbol for codes of at most kFastBits bits, indexed by the next kFastBits stream bits; 0 = use the
  // slow canonical path (longer code, or a bit pattern that is no code at all).
  std::uint16_t fast[1 << kFastBits];
};

struct Bits
{
  const std::uint8_t* p = nullptr;
  const std::uint8_t* end = nullptr;
  std::uint64_t buf = 0;
  int cnt = 0;
};

inline void Refill(Bits& b)
{
  while (b.cnt <= 56 && b.p < b.end) {
    b.buf |= static_cast<std::uint64_t>(*b.p++) << b.cnt;
    b.cnt += 8;
  }
}

/// Reads n (0..16) bits, LSB first; -1 when the input ends.
inline int GetBits(Bits& b, int n)
{
  Refill(b);
  if (b.cnt < n) return -1;
  const int v = static_cast<int>(b.buf & ((1ULL << n) - 1));
  b.buf >>= n;
  b.cnt -= n;
  return v;
}

/// Builds the decoding tables for `n` code lengths. Returns <0 for an over-subscribed set, 0 for a complete set and >0
/// (the number of unused code slots) for an incomplete set.
int Build(Huffman& h, const std::uint8_t* lengths, int n)
{
  for (int len = 0; len <= kMaxBits; ++len) h.count[len] = 0;
  for (int s = 0; s < n; ++s) ++h.count[lengths[s]];
  std::memset(h.fast, 0, sizeof(h.fast));
  if (h.count[0] == n) return 0; // no codes: complete, but every decode fails

  int left = 1;
  for (int len = 1; len <= kMaxBits; ++len) {
    left <<= 1;
    left -= h.count[len];
    if (left < 0) return left;
  }

  std::uint16_t offs[kMaxBits + 2];
  offs[1] = 0;
  for (int len = 1; len < kMaxBits; ++len) offs[len + 1] = static_cast<std::uint16_t>(offs[len] + h.count[len]);
  for (int s = 0; s < n; ++s)
    if (lengths[s] != 0) h.symbol[offs[lengths[s]]++] = static_cast<std::uint16_t>(s);

  // Canonical first code per length (RFC 1951 3.2.2), used for the fast table.
  std::uint32_t next[kMaxBits + 1];
  std::uint32_t code = 0;
  next[0] = 0;
  for (int len = 1; len <= kMaxBits; ++len) {
    code = (code + (len > 1 ? h.count[len - 1] : 0U)) << 1;
    next[len] = code;
  }
  for (int s = 0; s < n; ++s) {
    const int len = lengths[s];
    if (len == 0) continue;
    const std::uint32_t c = next[len]++;
    if (len > kFastBits) continue;
    // Huffman codes are packed MSB first into an LSB-first bit stream, so the table is indexed by the reversed code.
    std::uint32_t rev = 0;
    for (int i = 0; i < len; ++i) rev |= ((c >> i) & 1U) << (len - 1 - i);
    for (std::uint32_t i = rev; i < (1U << kFastBits); i += 1U << len)
      h.fast[i] = static_cast<std::uint16_t>((len << 9) | s);
  }
  return left;
}

/// Decodes one symbol; -1 on an invalid code or when the input ends inside the code.
int Decode(Bits& b, const Huffman& h)
{
  Refill(b);
  const std::uint16_t e = h.fast[b.buf & ((1U << kFastBits) - 1)];
  if (e) {
    const int len = e >> 9;
    if (len > b.cnt) return -1; // the "bits" are zero padding past the end of the input
    b.buf >>= len;
    b.cnt -= len;
    return e & 511;
  }
  int code = 0, first = 0, index = 0;
  for (int len = 1; len <= kMaxBits; ++len) {
    if (len > b.cnt) return -1;
    code |= static_cast<int>((b.buf >> (len - 1)) & 1U);
    const int count = h.count[len];
    if (code - count < first) {
      b.buf >>= len;
      b.cnt -= len;
      return h.symbol[index + (code - first)];
    }
    index += count;
    first += count;
    first <<= 1;
    code <<= 1;
  }
  return -1;
}

const std::uint16_t kLenBase[29] = {3,  4,  5,  6,  7,  8,  9,  10, 11,  13,  15,  17,  19,  23, 27,
                                    31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
const std::uint8_t kLenExt[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
const std::uint16_t kDistBase[30] = {1,   2,   3,   4,   5,   7,    9,    13,   17,   25,   33,   49,   65,    97,    129,
                                     193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
const std::uint8_t kDistExt[30] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

struct FixedTables
{
  Huffman lit, dist;
  FixedTables()
  {
    std::uint8_t l[kMaxLitCodes];
    int s = 0;
    for (; s < 144; ++s) l[s] = 8;
    for (; s < 256; ++s) l[s] = 9;
    for (; s < 280; ++s) l[s] = 7;
    for (; s < 288; ++s) l[s] = 8;
    Build(lit, l, 288);
    std::uint8_t d[32];
    for (int i = 0; i < 32; ++i) d[i] = 5; // 30 and 31 only complete the code set; Codes() rejects them
    Build(dist, d, 32);
  }
};

bool Codes(Bits& b, const Huffman& lit, const Huffman& dist, std::uint8_t* out, std::size_t outSize, std::size_t& pos,
           const char*& err)
{
  for (;;) {
    int sym = Decode(b, lit);
    if (sym < 0) {
      err = "invalid literal/length code or truncated input";
      return false;
    }
    if (sym < 256) {
      if (pos >= outSize) {
        err = "stream produces more data than declared";
        return false;
      }
      out[pos++] = static_cast<std::uint8_t>(sym);
      continue;
    }
    if (sym == 256) return true;
    sym -= 257;
    if (sym >= 29) {
      err = "invalid length symbol";
      return false;
    }
    int ext = GetBits(b, kLenExt[sym]);
    if (ext < 0) {
      err = "truncated input";
      return false;
    }
    const std::size_t len = static_cast<std::size_t>(kLenBase[sym]) + static_cast<std::size_t>(ext);
    const int dsym = Decode(b, dist);
    if (dsym < 0 || dsym >= 30) {
      err = "invalid distance code or truncated input";
      return false;
    }
    ext = GetBits(b, kDistExt[dsym]);
    if (ext < 0) {
      err = "truncated input";
      return false;
    }
    const std::size_t d = static_cast<std::size_t>(kDistBase[dsym]) + static_cast<std::size_t>(ext);
    if (d > pos) {
      err = "match distance reaches before the start of the output";
      return false;
    }
    if (len > outSize - pos) {
      err = "stream produces more data than declared";
      return false;
    }
    // Byte by byte on purpose: source and destination overlap when d < len (run-length semantics).
    for (std::size_t i = 0; i < len; ++i, ++pos) out[pos] = out[pos - d];
  }
}

bool Stored(Bits& b, std::uint8_t* out, std::size_t outSize, std::size_t& pos, const char*& err)
{
  // Drop the partial byte, then give the whole buffered bytes back to the input pointer.
  b.cnt -= (b.cnt & 7);
  b.p -= b.cnt >> 3;
  b.buf = 0;
  b.cnt = 0;
  if (b.end - b.p < 4) {
    err = "truncated stored block header";
    return false;
  }
  const unsigned len = b.p[0] | (static_cast<unsigned>(b.p[1]) << 8);
  const unsigned nlen = b.p[2] | (static_cast<unsigned>(b.p[3]) << 8);
  b.p += 4;
  if (len != (~nlen & 0xFFFFU)) {
    err = "stored block length check failed";
    return false;
  }
  if (static_cast<std::size_t>(b.end - b.p) < len) {
    err = "truncated stored block";
    return false;
  }
  if (len > outSize - pos) {
    err = "stream produces more data than declared";
    return false;
  }
  if (len) std::memcpy(out + pos, b.p, len);
  b.p += len;
  pos += len;
  return true;
}

bool Dynamic(Bits& b, std::uint8_t* out, std::size_t outSize, std::size_t& pos, const char*& err)
{
  static const std::uint8_t order[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
  const int hlit = GetBits(b, 5), hdist = GetBits(b, 5), hclen = GetBits(b, 4);
  if (hlit < 0 || hdist < 0 || hclen < 0) {
    err = "truncated dynamic block header";
    return false;
  }
  const int nlen = hlit + 257, ndist = hdist + 1, ncode = hclen + 4;
  if (nlen > 286 || ndist > 30) {
    err = "too many length or distance codes";
    return false;
  }
  std::uint8_t lengths[286 + 30];
  std::memset(lengths, 0, sizeof(lengths));
  std::uint8_t clens[19] = {0};
  for (int i = 0; i < ncode; ++i) {
    const int v = GetBits(b, 3);
    if (v < 0) {
      err = "truncated code length code lengths";
      return false;
    }
    clens[order[i]] = static_cast<std::uint8_t>(v);
  }
  Huffman lencode;
  if (Build(lencode, clens, 19) != 0) {
    err = "code length code is not complete";
    return false;
  }
  int index = 0;
  while (index < nlen + ndist) {
    const int sym = Decode(b, lencode);
    if (sym < 0) {
      err = "invalid code length code or truncated input";
      return false;
    }
    if (sym < 16) {
      lengths[index++] = static_cast<std::uint8_t>(sym);
      continue;
    }
    int len = 0, rep;
    if (sym == 16) {
      if (index == 0) {
        err = "repeat of a previous length with none before";
        return false;
      }
      len = lengths[index - 1];
      rep = GetBits(b, 2);
      if (rep >= 0) rep += 3;
    } else if (sym == 17) {
      rep = GetBits(b, 3);
      if (rep >= 0) rep += 3;
    } else {
      rep = GetBits(b, 7);
      if (rep >= 0) rep += 11;
    }
    if (rep < 0) {
      err = "truncated input";
      return false;
    }
    if (index + rep > nlen + ndist) {
      err = "code lengths repeat past the end of the table";
      return false;
    }
    while (rep--) lengths[index++] = static_cast<std::uint8_t>(len);
  }
  if (lengths[256] == 0) {
    err = "no end-of-block code";
    return false;
  }
  Huffman lit, dist;
  int e = Build(lit, lengths, nlen);
  // An incomplete set is tolerated only for the single-code case (one symbol of length 1), as zlib does.
  if (e < 0 || (e > 0 && nlen != lit.count[0] + lit.count[1])) {
    err = "over-subscribed or incomplete literal/length code";
    return false;
  }
  e = Build(dist, lengths + nlen, ndist);
  if (e < 0 || (e > 0 && ndist != dist.count[0] + dist.count[1])) {
    err = "over-subscribed or incomplete distance code";
    return false;
  }
  return Codes(b, lit, dist, out, outSize, pos, err);
}

} // namespace

bool Inflate(const std::uint8_t* in, std::size_t inSize, std::uint8_t* out, std::size_t outSize, std::size_t* consumed,
             const char** error)
{
  const char* err = nullptr;
  bool ok = false;
  if (consumed) *consumed = 0;
  do {
    if ((!in && inSize) || (!out && outSize)) {
      err = "null buffer";
      break;
    }
    Bits b;
    b.p = in;
    b.end = in + inSize;
    std::size_t pos = 0;
    int last = 0;
    bool good = true;
    do {
      last = GetBits(b, 1);
      const int type = GetBits(b, 2);
      if (last < 0 || type < 0) {
        err = "truncated input";
        good = false;
        break;
      }
      if (type == 0) {
        good = Stored(b, out, outSize, pos, err);
      } else if (type == 1) {
        static const FixedTables fixed;
        good = Codes(b, fixed.lit, fixed.dist, out, outSize, pos, err);
      } else if (type == 2) {
        good = Dynamic(b, out, outSize, pos, err);
      } else {
        err = "invalid block type";
        good = false;
      }
    } while (good && !last);
    if (!good) break;
    if (pos != outSize) {
      err = "stream ends before the declared size";
      break;
    }
    if (consumed) *consumed = static_cast<std::size_t>(b.p - in) - static_cast<std::size_t>(b.cnt >> 3);
    ok = true;
  } while (false);
  if (error) *error = ok ? nullptr : err;
  return ok;
}

} // namespace moho::mapformat
