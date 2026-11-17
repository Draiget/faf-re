#include "editor/tools/EdBrushLibrary.h"

#include "editor/tools/EdHeightFile.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <system_error>

namespace faf::editor
{
  ShapeGrid RasterizeShape(
    const BrushShape shape,
    const int n
  )
  {
    ShapeGrid grid;
    grid.n = std::max(2, n);
    grid.values.resize(static_cast<std::size_t>(grid.n) * static_cast<std::size_t>(grid.n));
    const float top = static_cast<float>(grid.n - 1);
    for (int z = 0; z < grid.n; ++z) {
      for (int x = 0; x < grid.n; ++x) {
        grid.values[static_cast<std::size_t>(z) * static_cast<std::size_t>(grid.n) + static_cast<std::size_t>(x)] =
          std::clamp(
            BrushShapeAt(shape, -1.0f + 2.0f * static_cast<float>(x) / top, -1.0f + 2.0f * static_cast<float>(z) / top),
            0.0f,
            1.0f
          );
      }
    }
    return grid;
  }

  std::vector<BrushImage> ListBrushImages(
    const std::filesystem::path& folder
  )
  {
    std::vector<BrushImage> images;
    std::error_code error;
    if (folder.empty() || !std::filesystem::is_directory(folder, error)) {
      return images;
    }
    for (const std::filesystem::directory_entry& entry : std::filesystem::directory_iterator(folder, error)) {
      if (!entry.is_regular_file(error)) {
        continue;
      }
      std::string extension = entry.path().extension().string();
      for (char& c : extension) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      }
      if (
        extension == ".png" || extension == ".tif" || extension == ".tiff" || extension == ".bmp" ||
        extension == ".r16" || extension == ".raw"
      ) {
        images.push_back({entry.path().stem().string(), entry.path()});
      }
    }
    std::sort(images.begin(), images.end(), [](const BrushImage& a, const BrushImage& b) {
      return a.name < b.name;
    });
    return images;
  }

  std::expected<ShapeGrid, std::string> LoadBrushImage(
    const std::filesystem::path& file,
    const int n
  )
  {
    const auto image = ReadHeightImage(file, 0, 0);
    if (!image) {
      return std::unexpected(image.error());
    }
    const HeightImage grid = ResampleHeights(*image, std::max(2, n), std::max(2, n));
    ShapeGrid out;
    out.n = grid.width;
    out.values.resize(grid.words.size());
    for (std::size_t i = 0; i < grid.words.size(); ++i) {
      out.values[i] = static_cast<float>(grid.words[i]) / 65535.0f;
    }
    return out;
  }

  namespace
  {
    // FAF Studio's gen_brush_masks.py, as it is.
    double Smooth(
      const double a,
      const double b,
      const double x
    )
    {
      const double t = std::clamp((x - a) / (b - a), 0.0, 1.0);
      return t * t * (3.0 - 2.0 * t);
    }

    double ValueNoise(
      const double x,
      const double z,
      const int seed
    )
    {
      const auto hash = [seed](const std::int64_t ix, const std::int64_t iz) {
        std::uint32_t n = static_cast<std::uint32_t>(ix * 374761393LL + iz * 668265263LL + seed * 1442695041LL);
        n = static_cast<std::uint32_t>((static_cast<std::uint64_t>(n ^ (n >> 13)) * 1274126177ULL) & 0xFFFFFFFFULL);
        return static_cast<double>(n & 0xFFFFU) / 65535.0;
      };
      const double fx0 = std::floor(x);
      const double fz0 = std::floor(z);
      const auto ix = static_cast<std::int64_t>(fx0);
      const auto iz = static_cast<std::int64_t>(fz0);
      double fx = x - fx0;
      double fz = z - fz0;
      fx = fx * fx * (3.0 - 2.0 * fx);
      fz = fz * fz * (3.0 - 2.0 * fz);
      const double a = hash(ix, iz);
      const double b = hash(ix + 1, iz);
      const double c = hash(ix, iz + 1);
      const double d = hash(ix + 1, iz + 1);
      return (a + (b - a) * fx) + ((c + (d - c) * fx) - (a + (b - a) * fx)) * fz;
    }

    double Fractal(
      const double x,
      const double z,
      const int seed = 0
    )
    {
      return 0.5 * ValueNoise(x * 2.0, z * 2.0, seed) + 0.3 * ValueNoise(x * 4.0, z * 4.0, seed + 1) +
        0.2 * ValueNoise(x * 8.0, z * 8.0, seed + 2);
    }

    double ShippedValue(
      const std::string& name,
      const double u,
      const double v
    )
    {
      const double d = std::hypot(u, v);
      if (name == "crater") {
        return std::min(1.0, Smooth(0.35, 0.72, d) * Smooth(1.0, 0.8, d) + 0.25 * Smooth(0.5, 0.0, d));
      }
      if (name == "volcano") {
        return Smooth(1.0, 0.15, d) * (1.0 - 0.45 * Smooth(0.18, 0.0, d)) *
          (0.85 + 0.3 * Fractal(u * 1.5 + 5.0, v * 1.5 + 5.0));
      }
      if (name == "canyon") {
        const double wobble = 0.18 * std::sin(u * 3.0) + 0.1 * std::sin(u * 7.0 + 1.0);
        return Smooth(0.45, 0.05, std::fabs(v - wobble)) * Smooth(1.0, 0.8, std::fabs(u));
      }
      if (name == "dunes") {
        return (0.5 + 0.5 * std::sin(u * 6.0 + 2.0 * Fractal(u, v) * 3.0)) * Smooth(1.0, 0.7, d);
      }
      // ridgeline
      const double r = 1.0 - std::fabs(2.0 * Fractal(u * 1.2 + 9.0, v * 1.2 + 4.0, 7) - 1.0);
      return std::clamp(r * r, 0.0, 1.0) * Smooth(1.0, 0.55, d);
    }
  } // namespace

  std::vector<std::pair<std::string, HeightImage>> ShippedBrushImages(
    const int n
  )
  {
    std::vector<std::pair<std::string, HeightImage>> out;
    for (const char* const name : {"canyon", "crater", "dunes", "ridgeline", "volcano"}) {
      HeightImage image;
      image.width = n;
      image.height = n;
      image.words.resize(static_cast<std::size_t>(n) * static_cast<std::size_t>(n));
      for (int j = 0; j < n; ++j) {
        const double v = (j + 0.5) / n * 2.0 - 1.0;
        for (int i = 0; i < n; ++i) {
          const double u = (i + 0.5) / n * 2.0 - 1.0;
          const double value = std::clamp(ShippedValue(name, u, v), 0.0, 1.0);
          image.words[static_cast<std::size_t>(j) * static_cast<std::size_t>(n) + static_cast<std::size_t>(i)] =
            static_cast<std::uint16_t>(std::lround(value * 65535.0));
        }
      }
      out.emplace_back(name, std::move(image));
    }
    return out;
  }

  int WriteShippedBrushImages(
    const std::filesystem::path& folder,
    std::string& error
  )
  {
    std::error_code ec;
    if (std::filesystem::exists(folder / ".shipped", ec)) {
      return 0;
    }
    std::filesystem::create_directories(folder, ec);
    int written = 0;
    for (const auto& [name, image] : ShippedBrushImages()) {
      const std::filesystem::path file = folder / (name + ".png");
      if (std::filesystem::exists(file, ec)) {
        continue;
      }
      if (const auto wrote = WriteHeightImage(file, image)) {
        ++written;
      } else {
        error = wrote.error();
      }
    }
    std::ofstream(folder / ".shipped", std::ios::binary | std::ios::trunc)
      << "canyon crater dunes ridgeline volcano: written once; delete one and it stays deleted\n";
    return written;
  }

  int ImportBrushImages(
    const std::vector<std::filesystem::path>& files,
    const std::filesystem::path& folder,
    std::string& error
  )
  {
    std::error_code made;
    std::filesystem::create_directories(folder, made);
    if (made) {
      error = "can't make " + folder.string() + ": " + made.message();
      return 0;
    }
    int copied = 0;
    for (const std::filesystem::path& file : files) {
      std::error_code failed;
      std::filesystem::copy_file(
        file, folder / file.filename(), std::filesystem::copy_options::overwrite_existing, failed
      );
      if (failed) {
        error += (error.empty() ? "" : "; ") + file.filename().string() + ": " + failed.message();
      } else {
        ++copied;
      }
    }
    return copied;
  }

  HeightStamp StampFromGrid(
    const ShapeGrid& grid
  )
  {
    HeightStamp stamp;
    stamp.width = grid.n;
    stamp.height = grid.n;
    stamp.words.resize(grid.values.size());
    for (std::size_t i = 0; i < grid.values.size(); ++i) {
      stamp.words[i] = static_cast<std::uint16_t>(std::lround(std::clamp(grid.values[i], 0.0f, 1.0f) * 65535.0f));
    }
    return stamp;
  }

  std::vector<StampDab> StampDabsAlong(
    const float x0,
    const float z0,
    const float x1,
    const float z1,
    const float spacing,
    float& travelled
  )
  {
    std::vector<StampDab> dabs;
    if (spacing <= 0.0f) {
      // One per click: the first point only.
      if (travelled > 0.0f) {
        dabs.push_back({x1, z1});
        travelled = 0.0f;
      }
      return dabs;
    }
    const float length = std::hypot(x1 - x0, z1 - z0);
    if (travelled >= spacing) {
      // The stroke's first point (or one owed from before the move).
      dabs.push_back({x0, z0});
      travelled = 0.0f;
    }
    // Every `spacing` along the segment, counting what was travelled before it.
    float along = spacing - travelled;
    while (along <= length) {
      const float t = length > 0.0f ? along / length : 0.0f;
      dabs.push_back({x0 + (x1 - x0) * t, z0 + (z1 - z0) * t});
      along += spacing;
    }
    travelled = length - (along - spacing);
    return dabs;
  }
} // namespace faf::editor
