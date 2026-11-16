#include "editor/tools/EdInterop.h"
#include "editor/doc/EdJsonTree.h"

#include <cctype>

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <filesystem>

namespace faf::editor
{
  HeightImage OrientHeights(
    const HeightImage& image,
    const bool flipX,
    const bool flipZ,
    int turns
  )
  {
    HeightImage out = image;
    if (image.width <= 0 || image.height <= 0) {
      return out;
    }
    const auto at = [](const HeightImage& img, const int x, const int z) {
      return img.words[static_cast<std::size_t>(z) * img.width + x];
    };
    if (flipX || flipZ) {
      for (int z = 0; z < image.height; ++z) {
        for (int x = 0; x < image.width; ++x) {
          out.words[static_cast<std::size_t>(z) * image.width + x] =
            at(image, flipX ? image.width - 1 - x : x, flipZ ? image.height - 1 - z : z);
        }
      }
    }
    turns = ((turns % 4) + 4) % 4;
    for (int t = 0; t < turns; ++t) {
      // A quarter turn clockwise: the new (x, z) is the old (z, width-1-x) seen from above with z down.
      HeightImage turned;
      turned.width = out.height;
      turned.height = out.width;
      turned.words.resize(out.words.size());
      for (int z = 0; z < turned.height; ++z) {
        for (int x = 0; x < turned.width; ++x) {
          turned.words[static_cast<std::size_t>(z) * turned.width + x] = at(out, z, out.height - 1 - x);
        }
      }
      out = std::move(turned);
    }
    return out;
  }

  void HeightImageRange(
    const HeightImage& image,
    std::uint16_t& darkest,
    std::uint16_t& brightest
  )
  {
    darkest = 65535;
    brightest = 0;
    for (const std::uint16_t w : image.words) {
      darkest = std::min(darkest, w);
      brightest = std::max(brightest, w);
    }
    if (image.words.empty()) {
      darkest = 0;
    }
  }

  std::vector<std::uint16_t> ImportedHeights(
    const HeightImage& image,
    const std::vector<std::uint16_t>& current,
    const int width,
    const int height,
    const ImportSettings& s
  )
  {
    std::vector<std::uint16_t> out = current;
    if (
      image.words.empty() || width <= 0 || height <= 0 || current.size() != static_cast<std::size_t>(width) * height
    ) {
      return out;
    }
    // The part that takes the import: the region (clipped to the map), else all of it.
    const int x0 = s.region ? std::clamp(std::min(s.regionX0, s.regionX1), 0, width - 1) : 0;
    const int x1 = s.region ? std::clamp(std::max(s.regionX0, s.regionX1), 0, width - 1) : width - 1;
    const int z0 = s.region ? std::clamp(std::min(s.regionZ0, s.regionZ1), 0, height - 1) : 0;
    const int z1 = s.region ? std::clamp(std::max(s.regionZ0, s.regionZ1), 0, height - 1) : height - 1;
    const int rw = x1 - x0 + 1;
    const int rh = z1 - z0 + 1;
    HeightImage fitted = ResampleHeights(OrientHeights(image, s.flipX, s.flipZ, s.turns), rw, rh, s.filter);
    if (s.invert) {
      for (std::uint16_t& w : fitted.words) {
        w = static_cast<std::uint16_t>(65535 - w);
      }
    }
    std::uint16_t darkest = 0, brightest = 0;
    HeightImageRange(fitted, darkest, brightest);
    if (!s.stretch) {
      darkest = 0;
      brightest = 65535;
    }
    const float span = std::max(1.0f, static_cast<float>(brightest - darkest));
    // The sea level in the image: the value seaValue lands on the map's water.
    float seaShift = 0.0f;
    if (s.seaPin) {
      const float seaWord = std::clamp(s.seaValue, 0.0f, 1.0f) * 65535.0f;
      const float at = s.mapping == ImportSettings::Mapping::Normalised
        ? s.low + (seaWord - static_cast<float>(darkest)) / span * (s.high - s.low)
        : seaWord * s.scale / 128.0f;
      seaShift = s.seaLevel - at;
    }
    const auto unitsAt = [&](const int x, const int z) {
      const float word = static_cast<float>(fitted.words[static_cast<std::size_t>(z - z0) * rw + (x - x0)]);
      return (s.mapping == ImportSettings::Mapping::Normalised
                ? s.low + (word - static_cast<float>(darkest)) / span * (s.high - s.low)
                : word * s.scale / 128.0f) +
        seaShift;
    };
    // Pads: the new ground's height at each spot (flatten), for the spots inside the region.
    std::vector<float> padHeights;
    for (const auto& p : s.padPoints) {
      const int px = std::clamp(static_cast<int>(std::lround(p[0])), x0, x1);
      const int pz = std::clamp(static_cast<int>(std::lround(p[1])), z0, z1);
      padHeights.push_back(unitsAt(px, pz));
    }
    const float strength = std::clamp(s.strength, 0.0f, 1.0f);
    for (int z = z0; z <= z1; ++z) {
      for (int x = x0; x <= x1; ++x) {
        const std::size_t k = static_cast<std::size_t>(z) * width + x;
        // The image's value as a height in map units.
        float units = unitsAt(x, z);
        const float now = static_cast<float>(current[k]) / 128.0f;
        // Pads: flatten the new ground round each spot to its height there.
        if (s.pads == 2) {
          for (std::size_t p = 0; p < s.padPoints.size(); ++p) {
            const float d =
              std::hypot(static_cast<float>(x) - s.padPoints[p][0], static_cast<float>(z) - s.padPoints[p][1]);
            const float t = std::clamp((d - s.padRadius) / std::max(4.0f, s.padRadius * 0.6f), 0.0f, 1.0f);
            units = padHeights[p] + (units - padHeights[p]) * (t * t * (3.0f - 2.0f * t));
          }
        }
        float result = units;
        switch (s.blend) {
        case ImportSettings::Blend::Add:
          // On top of the map's: the import's lowest point adds nothing.
          result = now + units - (s.mapping == ImportSettings::Mapping::Normalised ? s.low : 0.0f);
          break;
        case ImportSettings::Blend::Max:
          result = std::max(now, units);
          break;
        case ImportSettings::Blend::Min:
          result = std::min(now, units);
          break;
        default:
          break;
        }
        // The feather: in from the edge, a smooth fade from nothing to all.
        float weight = strength;
        if (!s.maskWeights.empty() && k < s.maskWeights.size()) {
          weight *= std::clamp(s.maskWeights[k], 0.0f, 1.0f);
        }
        if (s.pads == 1) {
          // Keep the old ground round each spot.
          for (const auto& p : s.padPoints) {
            const float d = std::hypot(static_cast<float>(x) - p[0], static_cast<float>(z) - p[1]);
            const float t = std::clamp((d - s.padRadius) / std::max(4.0f, s.padRadius * 0.6f), 0.0f, 1.0f);
            weight *= t * t * (3.0f - 2.0f * t);
          }
        }
        if (s.feather > 0.0f) {
          const float in = static_cast<float>(std::min({x - x0, x1 - x, z - z0, z1 - z}));
          const float t = std::clamp(in / s.feather, 0.0f, 1.0f);
          weight *= t * t * (3.0f - 2.0f * t);
        }
        result = now + (result - now) * weight;
        out[k] = static_cast<std::uint16_t>(std::clamp(std::lround(result * 128.0f), 0L, 65535L));
      }
    }
    return out;
  }

  MaskImportFile GuessMaskImport(
    const std::string& path,
    const std::array<std::string, 9>& layerKinds
  )
  {
    MaskImportFile f;
    f.path = path;
    std::string name = std::filesystem::path(path).stem().string();
    for (char& c : name) {
      c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    for (const char* const prefix : {"layer", "mask", "stratum"}) {
      const std::size_t at = name.find(prefix);
      if (at != std::string::npos) {
        const std::size_t digit = at + std::string(prefix).size();
        const std::size_t n = digit < name.size() && name[digit] == '_' ? digit + 1 : digit;
        if (n < name.size() && std::isdigit(static_cast<unsigned char>(name[n])) != 0) {
          f.target = MaskImportFile::Target::Layer;
          f.layer = std::clamp(name[n] - '0', 1, 8);
          return f;
        }
      }
    }
    if (name.contains("splat")) {
      f.target = MaskImportFile::Target::Splat;
      f.layer = 1;
      return f;
    }
    if (name.contains("type")) {
      f.target = MaskImportFile::Target::TerrainType;
      return f;
    }
    // A kind of ground: its words, then the layer whose texture is of that kind.
    // (The two-word kinds first: "rock_high" is the high rock layer when there is one.)
    static const std::vector<std::pair<const char*, const char*>> kWords = {
      {"high", "high rock"},
      {"dark", "dark rock"},
      {"grass", "grass"},
      {"rock", "rock"},
      {"cliff", "rock"},
      {"sand", "sand"},
      {"beach", "sand"},
      {"dirt", "dirt"},
      {"soil", "dirt"},
      {"wet", "wet ground"},
      {"mud", "wet ground"},
      {"snow", "snow"},
      {"ice", "snow"},
    };
    for (const auto& [word, kind] : kWords) {
      if (!name.contains(word)) {
        continue;
      }
      for (int layer = 1; layer <= 8; ++layer) {
        if (layerKinds[static_cast<std::size_t>(layer)] == kind) {
          f.target = MaskImportFile::Target::Layer;
          f.layer = layer;
          return f;
        }
      }
    }
    f.target = MaskImportFile::Target::Skip;
    return f;
  }

  std::expected<void, std::string> ImportFromSidecar(
    const std::string& json,
    ImportSettings& settings
  )
  {
    const auto parsed = ParseJsonTree(json);
    if (!parsed) {
      return std::unexpected(parsed.error());
    }
    const JsonTree& root = *parsed;
    const double perWord = root.Num("heightPerWord", 0.0);
    if (perWord <= 0.0) {
      return std::unexpected("it has no heightPerWord (not one of the editor's exports)");
    }
    settings.mapping = ImportSettings::Mapping::Absolute;
    settings.scale = static_cast<float>(perWord * 128.0);
    settings.invert = false;
    settings.seaPin = false;
    settings.low = static_cast<float>(root.Num("lowest", settings.low));
    settings.high = static_cast<float>(root.Num("highest", settings.high));
    return {};
  }

  std::string ExportSheet(
    const ExportFacts& f
  )
  {
    constexpr double kMetresPerUnit = 1000.0 / 51.2; // 20 km = 1024 units
    const double widthKm = f.mapWidth / 51.2;
    const double depthKm = f.mapHeight / 51.2;
    const double lowM = f.lowest * kMetresPerUnit;
    const double highM = f.highest * kMetresPerUnit;
    char text[2048];
    (void)std::snprintf(
      text,
      sizeof(text),
      "Heightmap of %s for Gaea / World Machine\n"
      "==========================================\n\n"
      "Map: %d x %d units = %.2f x %.2f km (a unit is %.2f m).\n"
      "Image: %d x %d samples, 16-bit, corners on the map's corners, the top row is the map's top (z = 0).\n"
      "Heights now: %.2f to %.2f units = %.0f to %.0f m; sea level %.2f units (%.0f m).\n"
      "The image's words are the heights times %.3f: word / %.1f = height in units.\n\n"
      "Gaea: Terrain > Scale %.2f km, Height %.0f m; export the heightmap as 16-bit PNG or .r32 at %d.\n"
      "World Machine: Extents %.2f x %.2f km, Elevation range %.0f m; export .r16 or 16-bit PNG at %d.\n"
      "Import back in the editor's Terrain > Import / Export with the same scale (Live link re-reads the file).\n",
      f.map.c_str(),
      f.mapWidth,
      f.mapHeight,
      widthKm,
      depthKm,
      kMetresPerUnit,
      f.imageWidth,
      f.imageHeight,
      static_cast<double>(f.lowest),
      static_cast<double>(f.highest),
      lowM,
      highM,
      static_cast<double>(f.sea),
      f.sea * kMetresPerUnit,
      static_cast<double>(f.scale),
      128.0 * f.scale,
      widthKm,
      std::max(1.0, highM),
      f.imageWidth,
      widthKm,
      depthKm,
      std::max(1.0, highM),
      f.imageWidth
    );
    return text;
  }

  const ReferenceMapStats& ReferenceStatsFor(
    const int size
  )
  {
    static const std::vector<ReferenceMapStats> stats = {
      {0,
       342,
       {14.13f, 26.5f, 37.25f, 49.51f, 86.83f},
       {4.95f, 12.43f, 19.8f, 29.0f, 62.73f},
       {2.89f, 6.21f, 9.02f, 12.1f, 17.84f},
       {0.01f, 0.05f, 0.09f, 0.14f, 0.23f}},
      {256,
       18,
       {7.48f, 15.01f, 19.03f, 21.87f, 26.83f},
       {3.0f, 8.75f, 11.46f, 12.6f, 16.15f},
       {2.76f, 6.21f, 8.48f, 10.18f, 14.4f},
       {0.03f, 0.05f, 0.1f, 0.13f, 0.2f}},
      {512,
       143,
       {15.22f, 23.59f, 30.8f, 40.0f, 53.64f},
       {5.68f, 12.23f, 18.06f, 24.16f, 33.42f},
       {4.37f, 7.87f, 10.0f, 12.7f, 17.78f},
       {0.03f, 0.08f, 0.11f, 0.14f, 0.22f}},
      {1024,
       161,
       {20.23f, 32.92f, 48.23f, 64.05f, 94.91f},
       {6.63f, 15.95f, 24.0f, 39.91f, 82.55f},
       {2.74f, 5.89f, 8.53f, 11.61f, 18.04f},
       {0.01f, 0.05f, 0.08f, 0.14f, 0.26f}},
      {2048,
       19,
       {0.0f, 30.52f, 49.34f, 49.84f, 159.96f},
       {0.0f, 8.77f, 22.33f, 23.46f, 54.26f},
       {0.0f, 3.61f, 5.56f, 6.1f, 8.94f},
       {0.0f, 0.02f, 0.02f, 0.03f, 0.13f}},
    };
    const ReferenceMapStats* best = nullptr;
    double bestDistance = 1e9;
    for (const ReferenceMapStats& s : stats) {
      if (s.size > 0 && s.n >= 8 && s.size <= 1024) {
        const double distance = std::fabs(std::log(static_cast<double>(std::max(size, 1)) / s.size));
        if (distance < bestDistance) {
          best = &s;
          bestDistance = distance;
        }
      }
    }
    return best != nullptr && bestDistance <= 0.75 ? *best : stats.front();
  }

  std::string ReferenceAdvice(
    const int size,
    const float relief,
    const float meanSlope
  )
  {
    const ReferenceMapStats& s = ReferenceStatsFor(size);
    char text[320];
    (void)std::snprintf(
      text,
      sizeof(text),
      "relief %.0f units, mean slope %.1f deg; %d reference maps%s: relief %.0f (%.0f to %.0f), slope %.1f deg (%.1f "
      "to "
      "%.1f)%s",
      static_cast<double>(relief),
      static_cast<double>(meanSlope),
      s.n,
      s.size == 0 ? "" : (" at " + std::to_string(static_cast<int>(std::lround(s.size / 51.2))) + " km").c_str(),
      static_cast<double>(s.relief[2]),
      static_cast<double>(s.relief[1]),
      static_cast<double>(s.relief[3]),
      static_cast<double>(s.slope[2]),
      static_cast<double>(s.slope[1]),
      static_cast<double>(s.slope[3]),
      relief > s.relief[4]       ? " -- taller than 95 % of them"
        : relief < s.relief[0]   ? " -- flatter than 95 % of them"
        : meanSlope > s.slope[4] ? " -- steeper than 95 % of them"
                                 : ""
    );
    return text;
  }

  std::vector<std::string> ImportedMaskFiles(
    const std::string& heightmap
  )
  {
    std::vector<std::string> files;
    if (heightmap.empty()) {
      return files;
    }
    const std::filesystem::path self(heightmap);
    std::error_code ignored;
    for (const auto& item : std::filesystem::directory_iterator(self.parent_path(), ignored)) {
      std::string extension = item.path().extension().string();
      for (char& c : extension) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      }
      if (
        (extension == ".png" || extension == ".tif" || extension == ".tiff" || extension == ".r16" ||
         extension == ".raw" || extension == ".r32" || extension == ".bmp") &&
        !std::filesystem::equivalent(item.path(), self, ignored)
      ) {
        files.push_back(item.path().string());
      }
    }
    std::sort(files.begin(), files.end());
    return files;
  }

  std::string FindNamedMask(
    const std::vector<std::string>& files,
    const std::string& name
  )
  {
    const auto lower = [](std::string text) {
      for (char& c : text) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      }
      return text;
    };
    const std::string wanted = lower(name);
    if (wanted.empty()) {
      return {};
    }
    for (const std::string& file : files) {
      const std::size_t slash = file.find_last_of("/\\");
      const std::string base = lower(slash == std::string::npos ? file : file.substr(slash + 1));
      const std::size_t dot = base.find_last_of('.');
      if (dot == std::string::npos) {
        continue;
      }
      const std::string stem = base.substr(0, dot);
      const std::string extension = base.substr(dot);
      if (
        extension != ".png" && extension != ".tif" && extension != ".tiff" && extension != ".r16" &&
        extension != ".raw" && extension != ".r32" && extension != ".bmp"
      ) {
        continue;
      }
      if (stem == wanted) {
        return file;
      }
      if (stem.size() > wanted.size() && stem.ends_with(wanted)) {
        const char before = stem[stem.size() - wanted.size() - 1];
        if (before == '_' || before == '-' || before == ' ' || before == '.') {
          return file;
        }
      }
    }
    return {};
  }

  std::string ExportSidecar(
    const ExportFacts& f
  )
  {
    // Hand written: a few fields, and the strings are map and symmetry names (no quotes or backslashes in them).
    const auto quoted = [](const std::string& text) {
      std::string out = "\"";
      for (const char c : text) {
        if (c == '"' || c == '\\') {
          out += '\\';
        }
        out += c;
      }
      return out + "\"";
    };
    char text[1024];
    (void)std::snprintf(
      text,
      sizeof(text),
      "{\n"
      "  \"map\": %s,\n"
      "  \"mapSize\": [%d, %d],\n"
      "  \"imageSize\": [%d, %d],\n"
      "  \"heightPerWord\": %.9g,\n"
      "  \"lowest\": %.3f,\n"
      "  \"highest\": %.3f,\n"
      "  \"seaLevel\": %.3f,\n"
      "  \"symmetry\": %s,\n"
      "  \"howToRead\": \"height in map units = word * heightPerWord; the image's top row is the map's top (z = 0)\"\n"
      "}\n",
      quoted(f.map).c_str(),
      f.mapWidth,
      f.mapHeight,
      f.imageWidth,
      f.imageHeight,
      static_cast<double>(1.0f / (128.0f * std::max(1e-6f, f.scale))),
      static_cast<double>(f.lowest),
      static_cast<double>(f.highest),
      static_cast<double>(f.sea),
      quoted(f.symmetry).c_str()
    );
    return text;
  }

  FileStamp StampOf(
    const std::string& file
  )
  {
    FileStamp stamp;
    std::error_code error;
    const std::filesystem::path path(file);
    if (file.empty() || !std::filesystem::is_regular_file(path, error)) {
      return stamp;
    }
    stamp.size = std::filesystem::file_size(path, error);
    stamp.written = static_cast<long long>(std::filesystem::last_write_time(path, error).time_since_epoch().count());
    return stamp;
  }

  bool LiveLink::Poll(
    const FileStamp& now,
    const double seconds,
    const double settle
  ) noexcept
  {
    if (now.written == 0) {
      return false; // gone (a tool saving by delete and write): wait for it
    }
    if (!(now == mSeen)) {
      mSeen = now;
      mSince = seconds;
      return false;
    }
    if (now == mApplied || mSince < 0.0 || seconds - mSince < settle) {
      return false;
    }
    mApplied = now;
    mSince = -1.0;
    return true;
  }
} // namespace faf::editor
