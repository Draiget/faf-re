#include "editor/tools/EdAssetCatalog.h"

#include "editor/doc/EdEmitter.h"
#include "editor/tools/EdDecals.h"
#include "editor/tools/EdMarkers.h"
#include "editor/tools/EdTextureLibrary.h"
#include "editor/ui/EdUnitCatalog.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <system_error>

namespace faf::editor
{
  namespace
  {
    std::string Lower(
      std::string s
    )
    {
      std::transform(s.begin(), s.end(), s.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      return s;
    }

    /** The search text: key, name, sub and the tag values, lower case. */
    void Finish(
      AssetEntry& e
    )
    {
      std::string text = e.key + " " + e.name + " " + e.sub;
      for (const auto& [facet, value] : e.tags) {
        text += " " + value;
      }
      e.search = Lower(text);
    }

    std::string FileName(
      const std::string& path
    )
    {
      const std::size_t slash = path.find_last_of("/\\");
      return slash == std::string::npos ? path : path.substr(slash + 1);
    }

    /** The folder after /env/ (`Evergreen`), or "" outside /env/. */
    std::string EnvFolder(
      const std::string& path
    )
    {
      const std::string lower = Lower(path);
      if (lower.rfind("/env/", 0) != 0) {
        return {};
      }
      const std::size_t end = path.find('/', 5);
      return path.substr(5, end == std::string::npos ? std::string::npos : end - 5);
    }

    std::string Capital(
      std::string s
    )
    {
      if (!s.empty()) {
        s[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(s[0])));
      }
      return s;
    }

    const char* const kMarkFavourite = "f ";
    const char* const kMarkRecent = "r ";
  } // namespace

  const char* AssetKindName(
    const AssetKind kind
  )
  {
    static const char* const kNames[kAssetKindCount] = {"Units", "Props", "Decals", "Markers", "Textures", "Effects"};
    return kNames[static_cast<int>(kind)];
  }

  const std::vector<AssetFacet>& AssetFacets(
    const AssetKind kind
  )
  {
    static const std::vector<AssetFacet> kUnits = {{"faction", "Faction"}, {"tech", "Tech"}, {"type", "Type"}};
    static const std::vector<AssetFacet> kGroupType = {{"group", "Environment"}, {"type", "Type"}};
    static const std::vector<AssetFacet> kType = {{"type", "Type"}};
    static const std::vector<AssetFacet> kEffects = {{"faction", "Faction"}, {"type", "For"}, {"file", "Kind"}};
    switch (kind) {
    case AssetKind::Units:
      return kUnits;
    case AssetKind::Markers:
      return kType;
    case AssetKind::Effects:
      return kEffects;
    default:
      return kGroupType;
    }
  }

  std::vector<std::string> AssetFacetValues(
    const std::vector<AssetEntry>& entries,
    const std::string& facet
  )
  {
    std::set<std::string> values;
    for (const AssetEntry& e : entries) {
      const auto it = e.tags.find(facet);
      if (it != e.tags.end() && !it->second.empty()) {
        values.insert(it->second);
      }
    }
    return {values.begin(), values.end()};
  }

  // ---- marks
  std::string AssetMarks::Id(
    const AssetEntry& entry
  )
  {
    return std::string(AssetKindName(entry.kind)) + ":" + entry.key;
  }

  bool AssetMarks::Favourite(
    const AssetEntry& entry
  ) const
  {
    return mFavourites.count(Id(entry)) != 0;
  }

  void AssetMarks::ToggleFavourite(
    const AssetEntry& entry
  )
  {
    const std::string id = Id(entry);
    if (mFavourites.erase(id) == 0) {
      mFavourites.insert(id);
    }
  }

  void AssetMarks::Used(
    const AssetEntry& entry
  )
  {
    const std::string id = Id(entry);
    mRecent.erase(std::remove(mRecent.begin(), mRecent.end(), id), mRecent.end());
    mRecent.push_front(id);
    while (mRecent.size() > kRecent) {
      mRecent.pop_back();
    }
  }

  int AssetMarks::RecentRank(
    const AssetEntry& entry
  ) const
  {
    const auto it = std::find(mRecent.begin(), mRecent.end(), Id(entry));
    return it == mRecent.end() ? -1 : static_cast<int>(it - mRecent.begin());
  }

  std::string AssetMarks::Save() const
  {
    std::string out;
    for (const std::string& id : mFavourites) {
      out += kMarkFavourite + id + "\n";
    }
    for (const std::string& id : mRecent) {
      out += kMarkRecent + id + "\n";
    }
    return out;
  }

  void AssetMarks::Load(
    const std::string& text
  )
  {
    mFavourites.clear();
    mRecent.clear();
    std::istringstream lines(text);
    std::string line;
    while (std::getline(lines, line)) {
      if (!line.empty() && line.back() == '\r') {
        line.pop_back();
      }
      if (line.size() < 3 || line.find(':') == std::string::npos) {
        continue;
      }
      if (line.rfind(kMarkFavourite, 0) == 0) {
        mFavourites.insert(line.substr(2));
      } else if (
        line.rfind(kMarkRecent, 0) == 0 && mRecent.size() < kRecent &&
        std::find(mRecent.begin(), mRecent.end(), line.substr(2)) == mRecent.end()
      ) {
        mRecent.push_back(line.substr(2));
      }
    }
  }

  std::vector<std::size_t> FindAssets(
    const std::vector<AssetEntry>& entries,
    const AssetQuery& query,
    const AssetMarks& marks
  )
  {
    std::vector<std::string> words;
    {
      std::istringstream in(Lower(query.text));
      std::string word;
      while (in >> word) {
        words.push_back(word);
      }
    }
    std::vector<std::size_t> out;
    for (std::size_t i = 0; i < entries.size(); ++i) {
      const AssetEntry& e = entries[i];
      if (query.onlyFavourites && !marks.Favourite(e)) {
        continue;
      }
      if (query.recent && marks.RecentRank(e) < 0) {
        continue;
      }
      bool pass = std::all_of(words.begin(), words.end(), [&](const std::string& w) {
        return e.search.find(w) != std::string::npos;
      });
      for (const auto& [facet, value] : query.filters) {
        if (!value.empty()) {
          const auto it = e.tags.find(facet);
          pass = pass && it != e.tags.end() && it->second == value;
        }
      }
      if (pass) {
        out.push_back(i);
      }
    }
    if (query.recent) {
      std::stable_sort(out.begin(), out.end(), [&](const std::size_t a, const std::size_t b) {
        return marks.RecentRank(entries[a]) < marks.RecentRank(entries[b]);
      });
    } else {
      std::stable_partition(out.begin(), out.end(), [&](const std::size_t i) {
        return marks.Favourite(entries[i]);
      });
    }
    return out;
  }

  // ---- entries
  AssetEntry UnitAsset(
    const EdUnitInfo& unit
  )
  {
    AssetEntry e;
    e.kind = AssetKind::Units;
    e.key = unit.id;
    e.name = unit.name.empty() ? unit.id : unit.name;
    e.sub = unit.id;
    e.tags["faction"] = kUnitFactions[static_cast<std::size_t>(std::clamp(unit.faction, 0, 4))];
    e.tags["tech"] = kUnitTechs[static_cast<std::size_t>(std::clamp(unit.tech, 0, 4))];
    e.tags["type"] = kUnitKinds[static_cast<std::size_t>(std::clamp(unit.kind, 0, 4))];
    Finish(e);
    return e;
  }

  AssetEntry PropAsset(
    const std::string& blueprint
  )
  {
    AssetEntry e;
    e.kind = AssetKind::Props;
    e.key = blueprint;
    std::string name = FileName(blueprint);
    if (const std::size_t suffix = Lower(name).find("_prop.bp"); suffix != std::string::npos) {
      name.resize(suffix);
    }
    e.name = name;
    const std::string env = EnvFolder(blueprint);
    e.tags["group"] = env.empty() ? std::string("Other") : Capital(env);
    e.sub = e.tags["group"];
    // The type by the words of its path, first match.
    static const std::pair<const char*, const char*> kTypes[] = {
      {"tree", "Trees"},
      {"pine", "Trees"},
      {"oak", "Trees"},
      {"bush", "Bushes"},
      {"shrub", "Bushes"},
      {"rock", "Rocks"},
      {"boulder", "Rocks"},
      {"stone", "Rocks"},
      {"crystal", "Crystals"},
      {"wreck", "Wrecks"},
      {"geothermal", "Geothermal"},
      {"hydro", "Geothermal"},
    };
    const std::string lower = Lower(blueprint);
    e.tags["type"] = "Other";
    for (const auto& [word, type] : kTypes) {
      if (lower.find(word) != std::string::npos) {
        e.tags["type"] = type;
        break;
      }
    }
    Finish(e);
    return e;
  }

  AssetEntry DecalAsset(
    const DecalTexture& texture
  )
  {
    AssetEntry e;
    e.kind = AssetKind::Decals;
    e.key = texture.path;
    e.name = texture.name;
    e.tags["group"] = texture.biome.empty() ? std::string("Other") : Capital(texture.biome);
    e.tags["type"] = texture.type == 2 ? "Normals" : texture.type == 6 ? "Glow" : "Albedo";
    e.sub = e.tags["group"] + " " + Lower(e.tags["type"]);
    Finish(e);
    return e;
  }

  AssetEntry MarkerAsset(
    const MarkerType& type
  )
  {
    AssetEntry e;
    e.kind = AssetKind::Markers;
    e.key = type.type;
    e.name = type.type;
    e.sub = type.group;
    e.tags["type"] = type.group;
    Finish(e);
    return e;
  }

  AssetEntry TextureAsset(
    const LayerTexture& texture
  )
  {
    AssetEntry e;
    e.kind = AssetKind::Textures;
    e.key = texture.path;
    e.name = texture.name;
    e.tags["group"] = texture.biome.empty() ? std::string("Other") : Capital(texture.biome);
    e.tags["type"] = texture.normals.empty() ? "Albedo" : "Albedo + normals";
    e.sub = e.tags["group"];
    Finish(e);
    return e;
  }

  AssetEntry EffectAsset(
    const std::string& path
  )
  {
    AssetEntry e;
    e.kind = AssetKind::Effects;
    e.key = path;
    std::string name = FileName(path);
    if (name.size() > 3 && Lower(name.substr(name.size() - 3)) == ".bp") {
      name.resize(name.size() - 3);
    }
    e.name = name;
    const int faction = EffectFaction(path);
    const int kind = EffectKind(path);
    e.tags["faction"] = faction > 0 ? kEffectFactions[faction] : "Other";
    e.tags["type"] = kind > 0 ? kEffectKinds[kind] : "Other";
    const std::string lower = Lower(name);
    e.tags["file"] = lower.find("_beam") != std::string::npos ? "Beam"
      : lower.find("_trail") != std::string::npos             ? "Trail"
                                                              : "Emitter";
    e.sub = e.tags["faction"] + " " + Lower(e.tags["type"]);
    Finish(e);
    return e;
  }

  // ---- the picture cache
  std::filesystem::path ThumbCacheFile(
    const std::filesystem::path& folder,
    const std::string& key
  )
  {
    // FNV-1a, 64 bits, of the key as given.
    std::uint64_t hash = 14695981039346656037ULL;
    for (const char c : key) {
      hash ^= static_cast<unsigned char>(c);
      hash *= 1099511628211ULL;
    }
    char name[32];
    std::snprintf(name, sizeof(name), "%016llx.thumb", static_cast<unsigned long long>(hash));
    return folder / name;
  }

  namespace
  {
    constexpr char kThumbMagic[8] = {'F', 'A', 'F', 'T', 'H', 'M', 'B', '1'};
  }

  bool WriteThumbFile(
    const std::filesystem::path& file,
    const int width,
    const int height,
    const std::uint32_t* pixels
  )
  {
    if (width <= 0 || height <= 0 || width > 1024 || height > 1024 || pixels == nullptr) {
      return false;
    }
    std::error_code ec;
    std::filesystem::create_directories(file.parent_path(), ec);
    const std::filesystem::path temporary = file.string() + ".writing";
    {
      std::ofstream out(temporary, std::ios::binary | std::ios::trunc);
      if (!out) {
        return false;
      }
      const std::int32_t size[2] = {width, height};
      out.write(kThumbMagic, sizeof(kThumbMagic));
      out.write(reinterpret_cast<const char*>(size), sizeof(size));
      out.write(
        reinterpret_cast<const char*>(pixels),
        static_cast<std::streamsize>(static_cast<std::size_t>(width) * static_cast<std::size_t>(height) * 4U)
      );
      if (!out.good()) {
        return false;
      }
    }
    std::filesystem::rename(temporary, file, ec);
    if (ec) {
      std::filesystem::remove(temporary, ec);
      return false;
    }
    return true;
  }

  bool ReadThumbFile(
    const std::filesystem::path& file,
    int& width,
    int& height,
    std::vector<std::uint32_t>& pixels
  )
  {
    std::ifstream in(file, std::ios::binary);
    char magic[sizeof(kThumbMagic)] = {};
    std::int32_t size[2] = {};
    if (
      !in.read(magic, sizeof(magic)) || std::memcmp(magic, kThumbMagic, sizeof(magic)) != 0 ||
      !in.read(reinterpret_cast<char*>(size), sizeof(size)) || size[0] <= 0 || size[1] <= 0 || size[0] > 1024 ||
      size[1] > 1024
    ) {
      return false;
    }
    std::vector<std::uint32_t> out(static_cast<std::size_t>(size[0]) * static_cast<std::size_t>(size[1]));
    if (!in.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size() * 4U))) {
      return false;
    }
    width = size[0];
    height = size[1];
    pixels = std::move(out);
    return true;
  }
} // namespace faf::editor
