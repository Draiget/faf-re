#include "moho/sim/mapformat/Hash.h"

#include <cstring>

namespace moho::mapformat {

namespace {

const std::uint32_t* CrcTable()
{
  static std::uint32_t table[256];
  static bool built = false;
  if (!built) {
    for (std::uint32_t i = 0; i < 256; ++i) {
      std::uint32_t c = i;
      for (int k = 0; k < 8; ++k) {
        c = (c & 1U) ? (0xEDB88320U ^ (c >> 1)) : (c >> 1);
      }
      table[i] = c;
    }
    built = true;
  }
  return table;
}

constexpr std::uint32_t kK[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

inline std::uint32_t Rotr(std::uint32_t x, int n)
{
  return (x >> n) | (x << (32 - n));
}

} // namespace

std::uint32_t Crc32(const std::uint8_t* data, std::size_t size, std::uint32_t crc)
{
  const std::uint32_t* t = CrcTable();
  std::uint32_t c = ~crc;
  for (std::size_t i = 0; i < size; ++i) {
    c = t[(c ^ data[i]) & 0xFFU] ^ (c >> 8);
  }
  return ~c;
}

Sha256::Sha256()
{
  static const std::uint32_t init[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  std::memcpy(h_, init, sizeof(h_));
  std::memset(buf_, 0, sizeof(buf_));
}

void Sha256::Block(const std::uint8_t* p)
{
  std::uint32_t w[64];
  for (int i = 0; i < 16; ++i) {
    w[i] = (std::uint32_t(p[i * 4]) << 24) | (std::uint32_t(p[i * 4 + 1]) << 16) | (std::uint32_t(p[i * 4 + 2]) << 8) |
           std::uint32_t(p[i * 4 + 3]);
  }
  for (int i = 16; i < 64; ++i) {
    const std::uint32_t s0 = Rotr(w[i - 15], 7) ^ Rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
    const std::uint32_t s1 = Rotr(w[i - 2], 17) ^ Rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  std::uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4], f = h_[5], g = h_[6], h = h_[7];
  for (int i = 0; i < 64; ++i) {
    const std::uint32_t S1 = Rotr(e, 6) ^ Rotr(e, 11) ^ Rotr(e, 25);
    const std::uint32_t ch = (e & f) ^ (~e & g);
    const std::uint32_t t1 = h + S1 + ch + kK[i] + w[i];
    const std::uint32_t S0 = Rotr(a, 2) ^ Rotr(a, 13) ^ Rotr(a, 22);
    const std::uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t t2 = S0 + mj;
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  h_[0] += a;
  h_[1] += b;
  h_[2] += c;
  h_[3] += d;
  h_[4] += e;
  h_[5] += f;
  h_[6] += g;
  h_[7] += h;
}

void Sha256::Update(const std::uint8_t* data, std::size_t size)
{
  total_ += size;
  while (size > 0) {
    const std::size_t take = (64 - fill_) < size ? (64 - fill_) : size;
    std::memcpy(buf_ + fill_, data, take);
    fill_ += take;
    data += take;
    size -= take;
    if (fill_ == 64) {
      Block(buf_);
      fill_ = 0;
    }
  }
}

void Sha256::Final(std::uint8_t out[32])
{
  const std::uint64_t bits = total_ * 8U;
  const std::uint8_t one = 0x80;
  Update(&one, 1);
  const std::uint8_t zero = 0;
  while (fill_ != 56) {
    Update(&zero, 1);
  }
  std::uint8_t len[8];
  for (int i = 0; i < 8; ++i) {
    len[i] = static_cast<std::uint8_t>(bits >> (56 - 8 * i));
  }
  Update(len, 8);
  for (int i = 0; i < 8; ++i) {
    out[i * 4] = static_cast<std::uint8_t>(h_[i] >> 24);
    out[i * 4 + 1] = static_cast<std::uint8_t>(h_[i] >> 16);
    out[i * 4 + 2] = static_cast<std::uint8_t>(h_[i] >> 8);
    out[i * 4 + 3] = static_cast<std::uint8_t>(h_[i]);
  }
}

std::string HexString(const std::uint8_t* data, std::size_t size)
{
  static const char* digits = "0123456789abcdef";
  std::string s;
  s.reserve(size * 2);
  for (std::size_t i = 0; i < size; ++i) {
    s.push_back(digits[data[i] >> 4]);
    s.push_back(digits[data[i] & 15U]);
  }
  return s;
}

std::string Sha256Hex(const std::uint8_t* data, std::size_t size)
{
  Sha256 h;
  if (size > 0) {
    h.Update(data, size);
  }
  std::uint8_t out[32];
  h.Final(out);
  return HexString(out, 32);
}

} // namespace moho::mapformat
