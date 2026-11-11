// Shared building blocks of the map-format reader: a bounds-checked byte reader, a byte writer (tests, tools),
// plane predictors and the canonical text dump (docs/mapformat/CONTAINER.md section 8).
// Standard library only: the reader must stay engine-independent so tools and tests can link it alone.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "moho/sim/mapformat/Hash.h"

namespace moho::mapformat {

/// Result of a chunk-family entry point (`DumpChunk<Family>`): Ok = decoded and dumped, Error = malformed or
/// unsupported version (`err` says why), NotMine = the chunk id belongs to another family.
enum class DecodeStatus { Ok, Error, NotMine };

/// Context a chunk decoder may need: the grid size from GRID and the world cell count from WRLD (0 until decoded) and
/// the container.
struct ChunkCtx
{
  std::uint32_t cellsX = 0;
  std::uint32_t cellsZ = 0;
  std::uint64_t worldCells = 0; ///< cellsX * cellsY * cellsZ of WRLD (0 until WRLD is decoded; container 4)
  int container = 3;
  bool strict = true;
};

/// Length (1..4) of the UTF-8 sequence at `p` (`n` > 0 bytes available) and its code point in `*cp`. Strict like Python's
/// decoder: no overlong forms, no surrogates, nothing above U+10FFFF. An invalid byte returns length 1 and U+FFFD.
inline std::size_t Utf8Length(const char* p, std::size_t n, std::uint32_t* cp)
{
  const unsigned char c = static_cast<unsigned char>(p[0]);
  if (c < 0x80) {
    if (cp) *cp = c;
    return 1;
  }
  int need = 0;
  std::uint32_t v = 0, minCp = 0;
  if (c >= 0xC2 && c <= 0xDF) { need = 1; v = c & 0x1FU; minCp = 0x80; }
  else if (c >= 0xE0 && c <= 0xEF) { need = 2; v = c & 0x0FU; minCp = 0x800; }
  else if (c >= 0xF0 && c <= 0xF4) { need = 3; v = c & 0x07U; minCp = 0x10000; }
  if (need > 0 && n > static_cast<std::size_t>(need)) {
    bool good = true;
    for (int k = 1; k <= need; ++k) {
      const unsigned char cc = static_cast<unsigned char>(p[k]);
      if ((cc & 0xC0U) != 0x80U) { good = false; break; }
      v = (v << 6) | (cc & 0x3FU);
    }
    if (good && v >= minCp && v <= 0x10FFFF && !(v >= 0xD800 && v <= 0xDFFF)) {
      if (cp) *cp = v;
      return static_cast<std::size_t>(need) + 1;
    }
  }
  if (cp) *cp = 0xFFFD;
  return 1;
}

inline bool IsValidUtf8(const char* p, std::size_t n)
{
  for (std::size_t i = 0; i < n;) {
    std::uint32_t cp;
    const std::size_t len = Utf8Length(p + i, n - i, &cp);
    if (cp == 0xFFFD && len == 1 && static_cast<unsigned char>(p[i]) >= 0x80) return false;
    i += len;
  }
  return true;
}

/// `path` of the format: empty ("none") or a VFS path that starts with '/' and has no ASCII upper-case letter.
inline bool IsValidVfsPath(const std::string& s)
{
  if (s.empty()) return true;
  if (s[0] != '/') return false;
  for (char c : s)
    if (c >= 'A' && c <= 'Z') return false;
  return true;
}

/// Sticky-failure little-endian reader. After the first failed read every read returns zero and `ok()` stays false.
/// Nothing here allocates from file-supplied sizes: use Count() before reserving.
class ByteReader
{
public:
  ByteReader(const std::uint8_t* data, std::size_t size) : d_(data), n_(size) {}

  bool ok() const { return ok_; }
  std::size_t remaining() const { return n_ - o_; }
  std::size_t offset() const { return o_; }
  bool atEnd() const { return o_ == n_; }
  void fail() { ok_ = false; }

  std::uint8_t u8() { return static_cast<std::uint8_t>(read(1)); }
  std::uint16_t u16() { return static_cast<std::uint16_t>(read(2)); }
  std::uint32_t u32() { return static_cast<std::uint32_t>(read(4)); }
  std::uint64_t u64() { return read(8); }
  std::int8_t i8() { return static_cast<std::int8_t>(u8()); }
  std::int16_t i16() { return static_cast<std::int16_t>(u16()); }
  std::int32_t i32() { return static_cast<std::int32_t>(u32()); }
  std::int64_t i64() { return static_cast<std::int64_t>(u64()); }
  float f32()
  {
    const std::uint32_t b = u32();
    float f;
    std::memcpy(&f, &b, 4);
    return f;
  }
  double f64()
  {
    const std::uint64_t b = u64();
    double f;
    std::memcpy(&f, &b, 8);
    return f;
  }

  /// `u16 length` + UTF-8; fails above `maxLen` (default 4096) and on invalid UTF-8 (strict: no overlongs, surrogates, > U+10FFFF).
  std::string str(std::size_t maxLen = 4096)
  {
    const std::size_t len = u16();
    if (!ok_ || len > maxLen || len > remaining()) {
      ok_ = false;
      return std::string();
    }
    std::string s(reinterpret_cast<const char*>(d_ + o_), len);
    o_ += len;
    if (!IsValidUtf8(s.data(), s.size())) {
      ok_ = false;
      return std::string();
    }
    return s;
  }

  /// Reads a u32 element count. Fails (returns 0) when it exceeds `maxCount` or when `count * minElemBytes` cannot
  /// fit in the remaining bytes, so a caller may reserve `count` elements safely.
  std::uint32_t count(std::size_t minElemBytes, std::uint32_t maxCount)
  {
    const std::uint32_t c = u32();
    if (!ok_) return 0;
    if (c > maxCount || (minElemBytes > 0 && static_cast<std::uint64_t>(c) * minElemBytes > remaining())) {
      ok_ = false;
      return 0;
    }
    return c;
  }

  /// Returns a pointer to the next `n` bytes and skips them, or nullptr (and fails) when fewer remain.
  const std::uint8_t* bytes(std::uint64_t n)
  {
    if (!ok_ || n > remaining()) {
      ok_ = false;
      return nullptr;
    }
    const std::uint8_t* p = d_ + o_;
    o_ += static_cast<std::size_t>(n);
    return p;
  }

  /// Strict end check: a chunk must be consumed exactly.
  bool finish()
  {
    if (ok_ && o_ != n_) ok_ = false;
    return ok_;
  }

private:
  std::uint64_t read(int n)
  {
    if (!ok_ || static_cast<std::size_t>(n) > remaining()) {
      ok_ = false;
      return 0;
    }
    std::uint64_t v = 0;
    for (int i = 0; i < n; ++i) v |= static_cast<std::uint64_t>(d_[o_ + i]) << (8 * i);
    o_ += n;
    return v;
  }

  const std::uint8_t* d_;
  std::size_t n_;
  std::size_t o_ = 0;
  bool ok_ = true;
};

/// Little-endian writer (tests, golden generation in C++).
class ByteWriter
{
public:
  std::vector<std::uint8_t> buf;

  void u8(std::uint8_t v) { buf.push_back(v); }
  void u16(std::uint16_t v) { put(v, 2); }
  void u32(std::uint32_t v) { put(v, 4); }
  void u64(std::uint64_t v) { put(v, 8); }
  void i8(std::int8_t v) { u8(static_cast<std::uint8_t>(v)); }
  void i16(std::int16_t v) { u16(static_cast<std::uint16_t>(v)); }
  void i32(std::int32_t v) { u32(static_cast<std::uint32_t>(v)); }
  void f32(float f)
  {
    std::uint32_t b;
    std::memcpy(&b, &f, 4);
    u32(b);
  }
  void f64(double f)
  {
    std::uint64_t b;
    std::memcpy(&b, &f, 8);
    u64(b);
  }
  void str(const std::string& s)
  {
    u16(static_cast<std::uint16_t>(s.size()));
    buf.insert(buf.end(), s.begin(), s.end());
  }
  void bytes(const std::uint8_t* p, std::size_t n) { buf.insert(buf.end(), p, p + n); }
  void vec3(float x, float y, float z)
  {
    f32(x);
    f32(y);
    f32(z);
  }

private:
  void put(std::uint64_t v, int n)
  {
    for (int i = 0; i < n; ++i) buf.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
  }
};

/// Reverses a predictor in place (CONTAINER.md section 3). `data` holds `rows * cols * channels` elements of
/// `elemBytes` bytes (little-endian unsigned). predictor 0 = none, 1 = left, 2 = up, 3 = Paeth. Returns false for an
/// unknown predictor or elemBytes outside 1..8.
inline std::uint64_t PlaneGet(const std::uint8_t* p, std::uint32_t elemBytes)
{
  std::uint64_t v = 0;
  for (std::uint32_t i = 0; i < elemBytes; ++i) v |= static_cast<std::uint64_t>(p[i]) << (8 * i);
  return v;
}
inline void PlanePut(std::uint8_t* p, std::uint32_t elemBytes, std::uint64_t v)
{
  for (std::uint32_t i = 0; i < elemBytes; ++i) p[i] = static_cast<std::uint8_t>(v >> (8 * i));
}
inline std::uint64_t PlanePrediction(std::uint8_t predictor, std::uint64_t a, std::uint64_t b, std::uint64_t c)
{
  switch (predictor) {
  case 1: return a;
  case 2: return b;
  case 3: {
    const std::int64_t p = static_cast<std::int64_t>(a) + static_cast<std::int64_t>(b) - static_cast<std::int64_t>(c);
    const std::int64_t pa = p > static_cast<std::int64_t>(a) ? p - static_cast<std::int64_t>(a) : static_cast<std::int64_t>(a) - p;
    const std::int64_t pb = p > static_cast<std::int64_t>(b) ? p - static_cast<std::int64_t>(b) : static_cast<std::int64_t>(b) - p;
    const std::int64_t pc = p > static_cast<std::int64_t>(c) ? p - static_cast<std::int64_t>(c) : static_cast<std::int64_t>(c) - p;
    if (pa <= pb && pa <= pc) return a;
    return pb <= pc ? b : c;
  }
  default: return 0;
  }
}

inline bool UnpredictPlane(std::uint8_t* data, std::uint32_t rows, std::uint32_t cols, std::uint32_t channels,
                           std::uint32_t elemBytes, std::uint8_t predictor)
{
  if (elemBytes < 1 || elemBytes > 8 || predictor > 3 || channels < 1) return false;
  if (predictor == 0) return true;
  const std::uint64_t rowElems = static_cast<std::uint64_t>(cols) * channels;
  const std::uint64_t mask = elemBytes == 8 ? ~0ULL : ((1ULL << (8 * elemBytes)) - 1);
  for (std::uint32_t z = 0; z < rows; ++z) {
    std::uint8_t* row = data + static_cast<std::size_t>(z) * rowElems * elemBytes;
    const std::uint8_t* up = z ? row - rowElems * elemBytes : nullptr;
    for (std::uint64_t i = 0; i < rowElems; ++i) {
      const std::uint64_t a = i >= channels ? PlaneGet(row + (i - channels) * elemBytes, elemBytes) : 0;
      const std::uint64_t b = up ? PlaneGet(up + i * elemBytes, elemBytes) : 0;
      const std::uint64_t c = (up && i >= channels) ? PlaneGet(up + (i - channels) * elemBytes, elemBytes) : 0;
      const std::uint64_t v = (PlaneGet(row + i * elemBytes, elemBytes) + PlanePrediction(predictor, a, b, c)) & mask;
      PlanePut(row + i * elemBytes, elemBytes, v);
    }
  }
  return true;
}

/// Applies a predictor (encoder side; tests and tools). Reads `data` (unpredicted), writes the encoded plane to `out`.
inline bool PredictPlane(const std::uint8_t* data, std::uint8_t* out, std::uint32_t rows, std::uint32_t cols,
                         std::uint32_t channels, std::uint32_t elemBytes, std::uint8_t predictor)
{
  if (elemBytes < 1 || elemBytes > 8 || predictor > 3 || channels < 1) return false;
  const std::uint64_t rowElems = static_cast<std::uint64_t>(cols) * channels;
  const std::uint64_t mask = elemBytes == 8 ? ~0ULL : ((1ULL << (8 * elemBytes)) - 1);
  for (std::uint32_t z = 0; z < rows; ++z) {
    const std::uint8_t* row = data + static_cast<std::size_t>(z) * rowElems * elemBytes;
    const std::uint8_t* up = z ? row - rowElems * elemBytes : nullptr;
    std::uint8_t* orow = out + static_cast<std::size_t>(z) * rowElems * elemBytes;
    for (std::uint64_t i = 0; i < rowElems; ++i) {
      const std::uint64_t a = i >= channels ? PlaneGet(row + (i - channels) * elemBytes, elemBytes) : 0;
      const std::uint64_t b = up ? PlaneGet(up + i * elemBytes, elemBytes) : 0;
      const std::uint64_t c = (up && i >= channels) ? PlaneGet(up + (i - channels) * elemBytes, elemBytes) : 0;
      const std::uint64_t v = (PlaneGet(row + i * elemBytes, elemBytes) - PlanePrediction(predictor, a, b, c)) & mask;
      PlanePut(orow + i * elemBytes, elemBytes, v);
    }
  }
  return true;
}

/// Bytes of bitmask(W, H): `H * ceil(W / 8)`.
inline std::uint64_t BitmaskBytes(std::uint32_t w, std::uint32_t h)
{
  return static_cast<std::uint64_t>(h) * ((static_cast<std::uint64_t>(w) + 7) / 8);
}

/// Canonical text dump (CONTAINER.md section 8). Append-only; lines end in '\n'.
class TextDump
{
public:
  std::string out;

  static std::string Idx(const std::string& base, std::size_t i) { return base + "[" + std::to_string(i) + "]"; }

  void Raw(const std::string& path, const std::string& text) { out += path + " = " + text + "\n"; }
  void U(const std::string& path, std::uint64_t v) { Raw(path, std::to_string(v)); }
  void I(const std::string& path, std::int64_t v) { Raw(path, std::to_string(v)); }
  void F32(const std::string& path, float f) { Raw(path, F32Text(f)); }
  void F64(const std::string& path, double f) { Raw(path, F64Text(f)); }
  void Str(const std::string& path, const std::string& s) { Raw(path, Quote(s)); }
  void Count(const std::string& path, std::size_t n) { Raw(path + ".count", std::to_string(n)); }
  void Bytes(const std::string& path, const std::uint8_t* p, std::size_t n)
  {
    Raw(path, "bytes[" + std::to_string(n) + "] sha256:" + Sha256Hex(p, n));
  }
  void Plane(const std::string& path, std::uint64_t w, std::uint64_t h, const std::uint8_t* p, std::size_t n)
  {
    Raw(path, "plane[" + std::to_string(w) + "x" + std::to_string(h) + "] sha256:" + Sha256Hex(p, n));
  }
  void Vec(const std::string& path, const float* v, int n)
  {
    std::string s = "[";
    for (int i = 0; i < n; ++i) s += (i ? ", " : "") + F32Text(v[i]);
    Raw(path, s + "]");
  }

  static std::string F32Text(float f)
  {
    std::uint32_t b;
    std::memcpy(&b, &f, 4);
    return "f32:" + Hex(b, 8);
  }
  static std::string F64Text(double f)
  {
    std::uint64_t b;
    std::memcpy(&b, &f, 8);
    return "f64:" + Hex(b, 16);
  }
  static std::string Hex(std::uint64_t v, int digits)
  {
    static const char* d = "0123456789abcdef";
    std::string s(static_cast<std::size_t>(digits), '0');
    for (int i = digits - 1; i >= 0; --i, v >>= 4) s[static_cast<std::size_t>(i)] = d[v & 15U];
    return s;
  }
  /// Exactly Python's `json.dumps(s, ensure_ascii=True)` of the string decoded as UTF-8: `"` and `\` escaped, `\b \f \n \r \t`
  /// in their short forms, other controls below 0x20 as \u00xx, every code point from 0x80 up as \uxxxx (lower case hex,
  /// one escape per UTF-16 code unit, surrogate pairs above U+FFFF). 0x7f and `/` stay as they are. The reader refuses
  /// invalid UTF-8 in file strings; bytes that are not valid UTF-8 (error messages only) are dumped as U+FFFD.
  static std::string Quote(const std::string& s)
  {
    std::string r = "\"";
    const std::size_t n = s.size();
    for (std::size_t i = 0; i < n;) {
      const unsigned char c = static_cast<unsigned char>(s[i]);
      if (c >= 0x80) {
        std::uint32_t cp = 0xFFFD;
        const std::size_t len = Utf8Length(s.data() + i, n - i, &cp);
        i += len;
        if (cp >= 0x10000) {
          const std::uint32_t v = cp - 0x10000;
          r += "\\u" + Hex(0xD800 + (v >> 10), 4) + "\\u" + Hex(0xDC00 + (v & 0x3FFU), 4);
        } else {
          r += "\\u" + Hex(cp, 4);
        }
        continue;
      }
      ++i;
      switch (c) {
      case '"': r += "\\\""; break;
      case '\\': r += "\\\\"; break;
      case '\n': r += "\\n"; break;
      case '\r': r += "\\r"; break;
      case '\t': r += "\\t"; break;
      case '\b': r += "\\b"; break;
      case '\f': r += "\\f"; break;
      default:
        if (c < 0x20) r += "\\u" + Hex(c, 4);
        else r.push_back(static_cast<char>(c));
      }
    }
    return r + "\"";
  }
};

} // namespace moho::mapformat
