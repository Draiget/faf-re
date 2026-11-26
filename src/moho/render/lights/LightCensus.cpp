#include "moho/render/lights/LightCensus.h"

#include <algorithm>
#include <cstdint>
#include <map>
#include <unordered_map>
#include <vector>

#include "gpg/core/utils/Logging.h"
#include "moho/console/CConCommand.h"

namespace moho::lights
{
  int ren_DynLightsCensus = 0;

  static TConVar<int> gTConVar_ren_DynLightsCensus(
    "ren_DynLightsCensus",
    "Census of what the dynamic light feeds see: every N rendered frames the log gets a table of every particle "
    "texture, beam, trail and unit "
    "mesh that reached a feed, how often, and whether it became a light (or why not). 0 (the default) does nothing. "
    "Needs ren_DynLights.",
    &ren_DynLightsCensus
  );

  namespace
  {
    struct Record
    {
      std::string kind;
      std::string key;
      std::string result;
      std::uint64_t count = 0;
      double sizeSum = 0.0;
      bool haveColour = false;
      TextureColour colour;
    };

    std::unordered_map<std::string, Record> gRecords;
    int gFrames = 0;
  } // namespace

  void CensusNote(
    const char* const kind,
    const std::string& key,
    const char* const result,
    const float size,
    const TextureColour* const colour
  )
  {
    if (!CensusEnabled()) {
      return;
    }
    const std::string id = std::string(kind) + "\n" + result + "\n" + key;
    Record& r = gRecords[id];
    if (r.count == 0) {
      r.kind = kind;
      r.key = key;
      r.result = result;
    }
    ++r.count;
    r.sizeSum += static_cast<double>(size);
    if (colour != nullptr && colour->valid && !r.haveColour) {
      r.colour = *colour;
      r.haveColour = true;
    }
  }

  void CensusDump()
  {
    std::vector<const Record*> sorted;
    sorted.reserve(gRecords.size());
    std::map<std::string, std::uint64_t> totals;
    for (const auto& item : gRecords) {
      sorted.push_back(&item.second);
      totals[item.second.kind + " " + item.second.result] += item.second.count;
    }
    std::sort(sorted.begin(), sorted.end(), [](const Record* a, const Record* b) {
      return a->count > b->count;
    });

    gpg::Logf("DynLights census: %u distinct entries, totals follow", static_cast<unsigned>(sorted.size()));
    for (const auto& t : totals) {
      gpg::Logf("DynLights census total: %s = %llu", t.first.c_str(), static_cast<unsigned long long>(t.second));
    }
    const std::size_t shown = std::min<std::size_t>(sorted.size(), 400);
    for (std::size_t i = 0; i < shown; ++i) {
      const Record& r = *sorted[i];
      if (r.haveColour) {
        gpg::Logf(
          "DynLights census: %s | %s | n=%llu size=%.2f | peak=%.2f bright=%.3f alpha=%.2f hue=(%.2f %.2f %.2f) | %s",
          r.kind.c_str(),
          r.result.c_str(),
          static_cast<unsigned long long>(r.count),
          r.sizeSum / static_cast<double>(r.count),
          r.colour.peak,
          r.colour.brightness,
          r.colour.alpha,
          r.colour.hue[0],
          r.colour.hue[1],
          r.colour.hue[2],
          r.key.c_str()
        );
      } else {
        gpg::Logf(
          "DynLights census: %s | %s | n=%llu size=%.2f | %s",
          r.kind.c_str(),
          r.result.c_str(),
          static_cast<unsigned long long>(r.count),
          r.sizeSum / static_cast<double>(r.count),
          r.key.c_str()
        );
      }
    }
    gpg::Logf("DynLights census: end of table");
  }

  void CensusFrame()
  {
    if (!CensusEnabled()) {
      return;
    }
    if (++gFrames >= ren_DynLightsCensus) {
      gFrames = 0;
      CensusDump();
    }
  }
} // namespace moho::lights
