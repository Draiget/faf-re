#pragma once

#include "editor/tools/EdHeightFile.h"

#include <array>
#include "editor/tools/EdHeightFile.h"
#include <cstdint>
#include <expected>
#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * Heightmaps in from and out to other tools (the consolidated design's Terrain > Import / Export; FAF Studio's
   * interop.lua): how an image's values become heights, turned and blended into the map's, the live link that
   * re-imports a file when another tool saves it, and the sidecar that tells that tool what the export is.
   */
  struct ImportSettings
  {
    enum class Mapping
    {
      Normalised, // the image's darkest .. brightest stretched over [low, high] map units
      Absolute,   // the image's words are heights (1/128 unit each) times `scale`
    } mapping = Mapping::Normalised;
    float low = 0.0f;
    float high = 128.0f;
    float scale = 1.0f;
    bool flipX = false;
    bool flipZ = false;
    int turns = 0; // quarter turns clockwise, 0..3 (a turn swaps the image's sides)
    enum class Blend
    {
      Replace,
      Add, // the import's height on top of the map's (its low end at nothing)
      Max,
      Min,
    } blend = Blend::Replace;
    float strength = 1.0f; // how far the map moves to the result, 0..1
    /**
     * Only part of the map takes the import (FAF Studio's import region): the image fitted onto this rectangle of
     * samples, x0..x1 by z0..z1 inclusive; the rest stays. Off: the whole map.
     */
    bool region = false;
    int regionX0 = 0;
    int regionZ0 = 0;
    int regionX1 = 256;
    int regionZ1 = 256;
    /** Samples in from the edge (of the region, or of the map) over which the import fades in; 0: a hard edge. */
    float feather = 0.0f;
    /** How the image is read between its samples when it isn't the map's size (FAF Studio's filters). */
    ResampleFilter filter = ResampleFilter::Bilinear;
    // FAF Studio's further import options.
    HeightReadOptions read; // the image's channel, a raw file's layout
    bool invert = false;    // bright is low
    bool stretch = true;    // Normalised: the image's own darkest .. brightest (off: the whole 0 .. 65535)
    bool seaPin = false;    // the image value `seaValue` (0..1) lands on `seaLevel` (the map's water)
    float seaValue = 0.3f;
    float seaLevel = 25.0f;
    int pads = 0; // 0 none, 1 keep the old ground round starts and resources, 2 flatten the new ground
    float padRadius = 16.0f;
    std::vector<std::array<float, 2>> padPoints; // the caller gives them (the markers)
    bool symmetric = false;                      // the caller makes the result symmetric
    std::string maskFile;                        // blend by a mask image (bright = the import, dark = the map stays)
    std::vector<float> maskWeights;              // the caller loads it onto the map's grid (0..1); empty: none
    bool regionPlayable = false;                 // the region is the playable area (the caller sets it)
  };
  /**
   * Reads back what an export wrote beside its image (`<file>.json`: heightPerWord, lowest, highest): the settings
   * that put it back at the same heights (Absolute with that scale). The error when the text isn't one.
   */
  [[nodiscard]] std::expected<void, std::string> ImportFromSidecar(const std::string& json, ImportSettings& settings);

  /** The image flipped and turned as the settings say. */
  [[nodiscard]] HeightImage OrientHeights(const HeightImage& image, bool flipX, bool flipZ, int turns);

  /** The darkest and brightest words of an image. */
  void HeightImageRange(const HeightImage& image, std::uint16_t& darkest, std::uint16_t& brightest);

  /**
   * The map's new height words: the image oriented, resampled onto `width` x `height`, its values mapped to heights
   * and blended with `current` by the settings. `current` holds the map's words.
   */
  [[nodiscard]] std::vector<std::uint16_t> ImportedHeights(
    const HeightImage& image,
    const std::vector<std::uint16_t>& current,
    int width,
    int height,
    const ImportSettings& settings
  );

  /** What an export is, for the tool that reads it: the map, the image's size and how its values are heights. */
  struct ExportFacts
  {
    std::string map;
    int mapWidth = 0; // map units
    int mapHeight = 0;
    int imageWidth = 0; // samples
    int imageHeight = 0;
    float scale = 1.0f;  // the export's words are heights times this
    float lowest = 0.0f; // map units
    float highest = 0.0f;
    float sea = 0.0f;     // the sea level (0 without a sea)
    std::string symmetry; // the toolbar's symmetry, by name
  };
  /** The sidecar `<file>.json`: the facts, and how to read the words back as heights. */
  [[nodiscard]] std::string ExportSidecar(const ExportFacts& facts);

  /**
   * The sheet `<file>.txt` for people setting up Gaea or World Machine (FAF Studio's interop README): the map's size
   * in kilometres and the height range in metres as those tools ask for them (a map unit is 1/51.2 km: 20 km maps are
   * 1024 units), and the export's size and range.
   */
  [[nodiscard]] std::string ExportSheet(const ExportFacts& facts);

  /**
   * A named mask another tool exported beside the heightmap (FAF Studio adopts them by name: flow, wear, deposit...):
   * the first of `files` whose name without its extension is `name` or ends in `_name` / `-name` / ` name`, case
   * ignored, with a height image's extension. Empty when none.
   */
  [[nodiscard]] std::string FindNamedMask(const std::vector<std::string>& files, const std::string& name);
  /**
   * The imported masks' slots (FAF Studio's interop Named, the mask generator's Imported mask): the height images
   * beside `heightmap`, the heightmap itself left out, sorted by name; slot 1 is the first.
   */
  [[nodiscard]] std::vector<std::string> ImportedMaskFiles(const std::string& heightmap);

  /** One file of Import / Export > Masks (FAF Studio's mask import): where it goes and how it is read. */
  struct MaskImportFile
  {
    std::string path;
    enum class Target
    {
      Layer,       // `layer`'s paint
      TerrainType, // `typeCode` where the mask is above `threshold`
      Splat,       // an RGBA splat: its R, G, B, A into `layer` .. `layer` + 3
      Skip,
    } target = Target::Layer;
    int layer = 1;
    int typeCode = 1;
    float threshold = 0.5f;
    int channel = 0; // 0 grey, 1..4 R G B A
    bool invert = false;
    bool stretch = false; // its own darkest .. brightest becomes 0 .. 1
  };
  /**
   * What a file is for by its name (FAF Studio's interop name rules): layer<n> / mask<n> / stratum<n> -> layer n;
   * "splat" -> the splat into layers 1-4; "type" -> a terrain type; a kind of ground in the name (grass, rock, sand,
   * dirt, wet, snow ...) -> the layer whose kind it is (`layerKinds[1..8]`, lower case names, "" for none); else Skip.
   */
  [[nodiscard]] MaskImportFile GuessMaskImport(const std::string& path, const std::array<std::string, 9>& layerKinds);

  /**
   * What the reference maps look like (FAF Studio's mapsets.lua Stats, 342 maps): for a map size (0 all), the 5th,
   * 25th, 50th, 75th and 95th percentiles of the relief (highest - lowest), the land's span, the mean slope (degrees)
   * and the share steeper than 30 degrees.
   */
  struct ReferenceMapStats
  {
    int size = 0;
    int n = 0;
    std::array<float, 5> relief{};
    std::array<float, 5> span{};
    std::array<float, 5> slope{};
    std::array<float, 5> steep{};
  };
  /** The numbers for a map `size` units across: the nearest size with 8 maps or more (up to 1024), else all maps. */
  [[nodiscard]] const ReferenceMapStats& ReferenceStatsFor(int size);
  /** A line comparing an import's relief and mean slope with the reference maps of its size (FAF Studio's Advice). */
  [[nodiscard]] std::string ReferenceAdvice(int size, float relief, float meanSlope);

  /** A file's stamp for the live link: its size and its last write (0 for none). */
  struct FileStamp
  {
    std::uintmax_t size = 0;
    long long written = 0;
    bool operator==(const FileStamp& other) const = default;
  };
  [[nodiscard]] FileStamp StampOf(const std::string& file);

  /**
   * The live link's watch: `Poll` is told the file's stamp and the time each frame, and says yes once a change has
   * held still for `settle` seconds (a tool writing a big file takes a while), once a change.
   */
  class LiveLink
  {
  public:
    void Start(
      const FileStamp& now
    ) noexcept
    {
      mApplied = now;
      mSeen = now;
      mSince = -1.0;
    }
    [[nodiscard]] bool Poll(const FileStamp& now, double seconds, double settle = 1.0) noexcept;

  private:
    FileStamp mApplied; // the stamp the map has
    FileStamp mSeen;    // the last one seen
    double mSince = -1.0;
  };
} // namespace faf::editor
