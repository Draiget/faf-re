#include "editor/tools/EdBrushLibrary.h"

#include "editor/tools/EdHeightFile.h"

#include <algorithm>
#include <cctype>
#include <cmath>
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

  bool LoadBrushImage(
    const std::filesystem::path& file,
    const int n,
    ShapeGrid& out,
    std::string& error
  )
  {
    HeightImage image;
    if (!ReadHeightImage(file, 0, 0, image, error)) {
      return false;
    }
    const HeightImage grid = ResampleHeights(image, std::max(2, n), std::max(2, n));
    out.n = grid.width;
    out.values.resize(grid.words.size());
    for (std::size_t i = 0; i < grid.words.size(); ++i) {
      out.values[i] = static_cast<float>(grid.words[i]) / 65535.0f;
    }
    return true;
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
