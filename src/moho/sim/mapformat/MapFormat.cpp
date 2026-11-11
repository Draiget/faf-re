#include "moho/sim/mapformat/MapFormat.h"

#include "moho/sim/mapformat/Hash.h"

namespace moho::mapformat {
namespace {

constexpr std::uint32_t kMagic = 0x1A70614DU;

std::uint32_t ReadU32(const std::uint8_t* p)
{
  return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) | (static_cast<std::uint32_t>(p[2]) << 16) |
         (static_cast<std::uint32_t>(p[3]) << 24);
}

std::string HexNoPad(std::uint64_t v)
{
  if (v == 0) return "0";
  std::string s;
  while (v) {
    s.insert(s.begin(), "0123456789abcdef"[v & 15U]);
    v >>= 4;
  }
  return s;
}

void SetReason(std::string* reason, const std::string& text)
{
  if (reason) *reason = text;
}

} // namespace

const char* MapFormatName(EMapFormat f)
{
  switch (f) {
  case EMapFormat::Classic: return "Classic";
  case EMapFormat::Legacy25D: return "Legacy25D";
  case EMapFormat::Extended: return "Extended";
  case EMapFormat::Full3D: return "Full3D";
  default: return "Unknown";
  }
}

EMapFormat DetectFromHeader(const std::uint8_t* first8, std::size_t n, bool scenarioSaysMesh, std::string* reason)
{
  SetReason(reason, std::string());
  if (!first8 || n < 8) {
    SetReason(reason, "NotAMap: file is shorter than the 8 byte magic + container header");
    return EMapFormat::Unknown;
  }
  if (ReadU32(first8) != kMagic) {
    SetReason(reason, "NotAMap: bad magic (expected 0x1A70614D)");
    return EMapFormat::Unknown;
  }
  const std::uint32_t container = ReadU32(first8 + 4);
  switch (container) {
  case 2: return scenarioSaysMesh ? EMapFormat::Legacy25D : EMapFormat::Classic;
  case 3: return EMapFormat::Extended;
  case 4: return EMapFormat::Full3D;
  default:
    SetReason(reason, "UnsupportedContainer: container version " + std::to_string(container) + " is not known (2, 3 and 4 are)");
    return EMapFormat::Unknown;
  }
}

std::string FeatureNamesText(std::uint64_t mask)
{
  std::string s;
  for (const std::string& name : FeatureNames(mask)) {
    if (!s.empty()) s += ", ";
    s += name;
  }
  return s;
}

std::string DescribeFormat(const SMapFormatInfo& info)
{
  std::string s = std::string("MapFormat: ") + MapFormatName(info.id);
  if (info.id == EMapFormat::Unknown) {
    if (!info.reason.empty()) s += " (" + info.reason + ")";
    return s;
  }
  if (!info.IsChunked()) return s;
  s += " rev " + std::to_string(info.revision);
  s += " features req=0x" + HexNoPad(info.requiredFeatures);
  s += " opt=0x" + HexNoPad(info.optionalFeatures);
  s += " simhash=" + HexString(info.simHash.data(), 8) + "...";
  return s;
}

} // namespace moho::mapformat
