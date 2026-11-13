#include "editor/tools/EdInterop.h"

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
    const HeightImage fitted = ResampleHeights(OrientHeights(image, s.flipX, s.flipZ, s.turns), width, height);
    std::uint16_t darkest = 0, brightest = 0;
    HeightImageRange(fitted, darkest, brightest);
    const float span = std::max(1.0f, static_cast<float>(brightest - darkest));
    const float strength = std::clamp(s.strength, 0.0f, 1.0f);
    for (std::size_t k = 0; k < out.size(); ++k) {
      const float word = static_cast<float>(fitted.words[k]);
      // The image's value as a height in map units.
      const float units = s.mapping == ImportSettings::Mapping::Normalised
        ? s.low + (word - static_cast<float>(darkest)) / span * (s.high - s.low)
        : word * s.scale / 128.0f;
      const float now = static_cast<float>(current[k]) / 128.0f;
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
      result = now + (result - now) * strength;
      out[k] = static_cast<std::uint16_t>(std::clamp(std::lround(result * 128.0f), 0L, 65535L));
    }
    return out;
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
