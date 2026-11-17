#include "editor/tools/EdDetailPass.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <map>

namespace faf::editor
{
  namespace
  {
    struct Set
    {
      const char* id;
      const char* label;
      const char* group;
      std::vector<std::string> small, big, crack, ground, cliff;
      float smallScale[2] = {0.0f, 0.0f};
      float bigScale[2] = {0.0f, 0.0f};
    };

    const std::vector<Set>& Sets()
    {
      const std::string E = "/env/";
      static const std::vector<Set> kSets = [&E] {
        std::vector<Set> s;
        s.push_back(
          {"evergreen",
           "Evergreen (temperate, valley)",
           "evergreen",
           {"fieldstone01", "fieldstone02", "fieldstone03", "fieldstone04", "rock01", "rock02"},
           {"rock03", "rock04", "rock05", "rockpile01", "rockpile02"},
           {E + "Evergreen2/Decals/eg_scatterstones001_albedo.dds",
            E + "Evergreen2/Decals/eg_scatterstones002_albedo.dds",
            E + "Evergreen2/Decals/eg_scatterstones003_albedo.dds",
            E + "Evergreen2/Decals/eg_scatterstones004_albedo.dds",
            E + "Evergreen2/Decals/eg_patchdry001_albedo.dds",
            E + "Evergreen2/Decals/eg_patchwarm001_albedo.dds",
            E + "Evergreen2/Decals/eg_mudder01_albedo.dds",
            E + "Evergreen2/Decals/eg_mudder02_albedo.dds"},
           {E + "Evergreen2/Decals/eg_ground001_albedo.dds",
            E + "Evergreen2/Decals/eg_ground002_albedo.dds",
            E + "Evergreen2/Decals/eg_ground003_albedo.dds",
            E + "Evergreen2/Decals/eg_boulder002_albedo.dds",
            E + "Evergreen2/Decals/eg_boulder005_albedo.dds",
            E + "Evergreen2/Decals/eg_boulder007_albedo.dds"},
           {E + "Evergreen2/Decals/eg_cliff01_albedo.dds",
            E + "Evergreen2/Decals/eg_cliff02_albedo.dds",
            E + "Evergreen2/Decals/eg_cliff03_albedo.dds",
            E + "Evergreen2/Decals/eg_cliff04_albedo.dds"}}
        );
        s.push_back(
          {"desert",
           "Desert",
           "desert",
           {"des_boulder01", "des_boulder02", "des_boulder03"},
           {"des_boulder04", "des_boulder05", "des_boulder06"},
           {E + "Desert/Decals/des_swirl01_albedo.dds",
            E + "Desert/Decals/des_swirl02_albedo.dds",
            E + "Desert/Decals/des_swirl03_albedo.dds",
            E + "Desert/Decals/des_rock01_albedo.dds",
            E + "Desert/Decals/des_rock02_albedo.dds",
            E + "Desert/Decals/des_rock03_albedo.dds"},
           {E + "Desert/Decals/des_rockground_albedo.dds",
            E + "Desert/Decals/des_rockground2_albedo.dds",
            E + "Desert/Decals/des_rockground3_albedo.dds",
            E + "Desert/Decals/des_boulder005_albedo.dds",
            E + "Desert/Decals/des_boulder008_albedo.dds"},
           {E + "Desert/Decals/des_cliff01_albedo.dds",
            E + "Desert/Decals/des_cliff02_albedo.dds",
            E + "Desert/Decals/des_cliff03_albedo.dds"}}
        );
        s.push_back(
          {"tropical",
           "Tropical",
           "tropical",
           {"rock01", "rock02", "trrock01"},
           {"rock03", "rock04", "rock05", "rockpile01"},
           {E + "Tropical/Decals/trrawground01_albedo.dds",
            E + "Tropical/Decals/trrawground02_albedo.dds",
            E + "Tropical/Decals/trrawground03_albedo.dds",
            E + "Tropical/Decals/tr_mud004_albedo.dds"},
           {E + "Tropical/Decals/trrockage001_albedo.dds",
            E + "Tropical/Decals/trrockage002_albedo.dds",
            E + "Tropical/Decals/trrockage003_albedo.dds",
            E + "Tropical/Decals/trrockage004_albedo.dds"},
           {E + "Tropical/Decals/trrockage005_albedo.dds",
            E + "Tropical/Decals/trrockage006_albedo.dds",
            E + "Tropical/Decals/trrockage007_albedo.dds"}}
        );
        s.push_back(
          {"tundra",
           "Tundra",
           "tundra",
           {"icerocksm01", "icerocksm02", "icerocksm03", "icerocksm04"},
           {"tund_rock02", "tund_rock03", "tund_rock04", "tund_rock05"},
           {E + "Tundra/Decals/tund_crack001_albedo.dds",
            E + "Tundra/Decals/tund_crack002_albedo.dds",
            E + "Tundra/Decals/tund_crack003_albedo.dds",
            E + "Tundra/Decals/tund_crack004_albedo.dds"},
           {E + "Tundra/Decals/tund_rockground_albedo.dds",
            E + "Tundra/Decals/tund_rockground2_albedo.dds",
            E + "Tundra/Decals/tund_rockground3_albedo.dds",
            E + "Tundra/Decals/tund_rockground4_albedo.dds"},
           {E + "Tundra/Decals/tund_cliff002_albedo.dds",
            E + "Tundra/Decals/tund_cliff003_albedo.dds",
            E + "Tundra/Decals/tund_cliff004_albedo.dds"}}
        );
        s.push_back(
          {"lava",
           "Lava",
           "lava",
           {"lav_rock01", "lav_rock02", "lv_rock01"},
           {"lav_rock03", "lav_rock04", "lav_rock05", "lv_rock02"},
           {E + "Lava/Decals/lav_lavarock01_albedo.dds",
            E + "Lava/Decals/lav_lavarock02_albedo.dds",
            E + "Lava/Decals/lav_lavarock03_albedo.dds"},
           {E + "Lava/Decals/lav_lavarock04_albedo.dds",
            E + "Lava/Decals/lav_lavarock05_albedo.dds",
            E + "Lava/Decals/lav_lavarock06_albedo.dds"},
           {E + "Lava/Decals/lav_lavarock07_albedo.dds"}}
        );
        s.push_back(
          {"swamp",
           "Swamp",
           "swamp",
           {"boulder01", "boulder02"},
           {"boulder03", "outcrop01"},
           {E + "Swamp/Decals/muddetail01_albedo.dds",
            E + "Swamp/Decals/mudhole001_albedo.dds",
            E + "Swamp/Decals/mudhole002_albedo.dds",
            E + "Swamp/Decals/mudhole003_albedo.dds"},
           {E + "Swamp/Decals/sw_boulder002_albedo.dds",
            E + "Swamp/Decals/sw_boulder007_albedo.dds",
            E + "Swamp/Decals/sw_boulder008_albedo.dds"},
           {E + "Swamp/Decals/swcliff01_albedo.dds",
            E + "Swamp/Decals/swcliff02_albedo.dds",
            E + "Swamp/Decals/swcliff03_albedo.dds",
            E + "Swamp/Decals/cliffside001_albedo.dds"}}
        );
        Set red{
          "redbarrens",
          "Red Barrens",
          "redrocks",
          {"rock_sm01", "rock_sm02", "rock_sm03", "rock_sm04", "rock_sm05", "rock_sm06", "rock_sm07"},
          {"rock01", "rock02", "rock03", "boulder01", "boulder02", "boulder03", "boulder04"},
          {E + "Desert/Decals/des_rockground_albedo.dds",
           E + "Desert/Decals/des_rockground2_albedo.dds",
           E + "Desert/Decals/des_rockground3_albedo.dds",
           E + "Desert/Decals/des_swirl01_albedo.dds",
           E + "Desert/Decals/des_swirl02_albedo.dds"},
          {E + "Red Barrens/Decals/rb_rockground_albedo.dds", E + "Red Barrens/Decals/rb_rockground2_albedo.dds"},
          {E + "Red Barrens/Decals/rb_cliff01_albedo.dds",
           E + "Red Barrens/Decals/rb_cliff02_albedo.dds",
           E + "Red Barrens/Decals/rb_cliff03_albedo.dds"}
        };
        red.smallScale[0] = 3.2f;
        red.smallScale[1] = 5.6f;
        red.bigScale[0] = 1.6f;
        red.bigScale[1] = 2.8f;
        s.push_back(std::move(red));
        s.push_back(
          {"geothermal",
           "Geothermal",
           "geothermal",
           {"georock01", "georock04", "georock05"},
           {"georock02", "georock03", "georock06", "georock07"},
           {E + "Geothermal/Decals/mudsplats01_albedo.dds",
            E + "Geothermal/Decals/mudsplats02_albedo.dds",
            E + "Geothermal/Decals/mudsplats03_albedo.dds"},
           {E + "Geothermal/Decals/scum001_albedo.dds", E + "Geothermal/Decals/scum002_albedo.dds"},
           {}}
        );
        return s;
      }();
      return kSets;
    }

    /** Studio's Defs: slope window, per 1,000 square units (Citadel), spacing, scale, decal size, clustering. */
    std::vector<DetailClass> Defs()
    {
      std::vector<DetailClass> d(6);
      d[0] = {
        "small", "Small rocks (gentle ground, in clusters)", false, 0, 14, 9.8f, 6, 0.6f, 1.3f, 0, 70, 0.5f, 0, 0, {}
      };
      d[1] = {
        "stones",
        "Stones along the water (channels and banks)",
        false,
        0,
        25,
        3.5f,
        3,
        0.6f,
        1.5f,
        0,
        40,
        0.8f,
        0.42f,
        0.55f,
        {}
      };
      d[2] = {"big", "Big rocks (steep ground, cliffs)", false, 6, 55, 1.8f, 10, 0.9f, 1.5f, 0, 50, 0.85f, 0, 0, {}};
      d[3] = {
        "crack", "Crevice and patch decals (gentle ground)", true, 0, 12, 0.7f, 14, 0.6f, 1.6f, 25, 90, 0.6f, 0, 0, {}
      };
      d[4] = {
        "ground", "Rock ground decals (steeper ground)", true, 8, 35, 0.17f, 25, 0.7f, 1.4f, 36, 110, 0.6f, 0, 0, {}
      };
      d[5] = {"cliff", "Cliff face decals (steep ground)", true, 30, 85, 0.12f, 22, 0.6f, 1.1f, 26, 70, 0.8f, 0, 0, {}};
      return d;
    }

    std::string Lower(
      std::string s
    )
    {
      std::transform(s.begin(), s.end(), s.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      return s;
    }

    const Set& SetOf(
      const std::string& id
    )
    {
      for (const Set& s : Sets()) {
        if (id == s.id) {
          return s;
        }
      }
      return Sets().front();
    }

    const std::vector<std::string>& ListOf(
      const Set& set,
      const std::string& classId
    )
    {
      if (classId == "small" || classId == "stones") {
        return set.small;
      }
      if (classId == "big") {
        return set.big;
      }
      if (classId == "crack") {
        return set.crack;
      }
      if (classId == "ground") {
        return set.ground;
      }
      return set.cliff;
    }

    MaskGenRule Rule(
      const char* type,
      const std::map<std::string, float>& values,
      const MaskCombine op = MaskCombine::And
    )
    {
      MaskGenRule r = NewMaskRule(type);
      for (const auto& [k, v] : values) {
        r.v[k] = v;
      }
      r.op = op;
      r.invert = false;
      return r;
    }
  } // namespace

  const std::vector<DetailEnvironment>& DetailEnvironments()
  {
    static const std::vector<DetailEnvironment> kEnv = [] {
      std::vector<DetailEnvironment> out;
      for (const Set& s : Sets()) {
        out.push_back({s.id, s.label});
      }
      return out;
    }();
    return kEnv;
  }

  std::string GuessDetailEnvironment(
    const std::vector<std::string>& layerTextures
  )
  {
    // The /env/<folder>/ of the layers' textures, the most common one, by folder name.
    static const std::vector<std::pair<const char*, const char*>> kFolders = {
      {"evergreen", "evergreen"},
      {"desert", "desert"},
      {"tropical", "tropical"},
      {"tundra", "tundra"},
      {"lava", "lava"},
      {"swamp", "swamp"},
      {"red barrens", "redbarrens"},
      {"redrocks", "redbarrens"},
      {"geothermal", "geothermal"},
      {"crystalline", "tundra"},
      {"paradise", "tropical"},
      {"utility", "evergreen"},
    };
    std::map<std::string, int> votes;
    for (const std::string& texture : layerTextures) {
      const std::string t = Lower(texture);
      const std::size_t at = t.find("/env/");
      if (at == std::string::npos) {
        continue;
      }
      const std::size_t end = t.find('/', at + 5);
      const std::string folder = t.substr(at + 5, end == std::string::npos ? std::string::npos : end - at - 5);
      for (const auto& [name, id] : kFolders) {
        if (folder.contains(name)) {
          ++votes[id];
          break;
        }
      }
    }
    std::string best = "evergreen";
    int most = 0;
    for (const auto& [id, n] : votes) {
      if (n > most) {
        most = n;
        best = id;
      }
    }
    return best;
  }

  std::string FindEnvironmentProp(
    const std::vector<std::string>& blueprints,
    const std::string& group,
    const std::string& name
  )
  {
    const std::string g = "/env/" + Lower(group) + "/";
    const std::string file = "/" + Lower(name) + "_prop.bp";
    for (const std::string& bp : blueprints) {
      const std::string l = Lower(bp);
      if (l.contains(g) && l.size() >= file.size() && l.ends_with(file)) {
        return bp;
      }
    }
    return {};
  }

  std::vector<DetailClass> DetailClasses(
    const std::string& environment,
    const std::function<std::string(const std::string&, const std::string&)>& findProp,
    const std::function<bool(const std::string&)>& exists
  )
  {
    const Set& set = SetOf(environment);
    std::vector<DetailClass> out;
    for (DetailClass c : Defs()) {
      const bool smallList = c.id == "small" || c.id == "stones";
      if (smallList && set.smallScale[1] > 0.0f) {
        c.scaleMin = set.smallScale[0];
        c.scaleMax = set.smallScale[1];
      }
      if (c.id == "big" && set.bigScale[1] > 0.0f) {
        c.scaleMin = set.bigScale[0];
        c.scaleMax = set.bigScale[1];
      }
      for (const std::string& p : ListOf(set, c.id)) {
        if (!c.decals) {
          const std::string path = findProp ? findProp(set.group, p) : std::string();
          if (!path.empty()) {
            c.entries.push_back(path);
          }
        } else if (!exists || exists(p)) {
          c.entries.push_back(p);
        }
      }
      if (!c.entries.empty()) {
        out.push_back(std::move(c));
      }
    }
    return out;
  }

  int DetailCount(
    const DetailClass& c,
    const double area,
    const float density
  )
  {
    return std::max(1, static_cast<int>(std::floor(c.per1000 * area / 1000.0 * density + 0.5)));
  }

  std::expected<void, std::string> DetailDensity(
    MaskGenContext& context,
    const DetailClass& c,
    const int seed,
    field::Grid& out
  )
  {
    // The raw clustering noise first (0..1, monotone in the noise), then its top share kept: the value a share of the
    // map lies below read off the samples.
    std::vector<MaskGenRule> raw = {Rule(
      "noise",
      {{"kind", 5.0f},
       {"seed", static_cast<float>(seed)},
       {"size", c.clusterSize},
       {"octaves", 4.0f},
       {"from", 0.0f},
       {"to", 1.0f}}
    )};
    field::Grid noise;
    if (auto made = EvaluateMaskRules(context, raw, noise); !made) {
      return made;
    }
    std::vector<float> sorted = noise.v;
    std::sort(sorted.begin(), sorted.end());
    const auto quantile = [&sorted](const float p) {
      if (sorted.empty()) {
        return 0.5f;
      }
      const float x = std::clamp(p, 0.0f, 1.0f) * static_cast<float>(sorted.size() - 1);
      const std::size_t i = static_cast<std::size_t>(x);
      const std::size_t j = std::min(sorted.size() - 1, i + 1);
      return sorted[i] + (sorted[j] - sorted[i]) * (x - static_cast<float>(i));
    };
    const float lo = quantile(1.0f - c.clusterShare);
    float hi = quantile(std::min(0.98f, 1.0f - c.clusterShare + (c.flowTo > 0.0f ? 0.12f : 0.3f)));
    if (hi - lo < 0.02f) {
      hi = lo + 0.02f;
    }
    out = noise;
    for (float& v : out.v) {
      const float t = std::clamp((v - lo) / (hi - lo), 0.0f, 1.0f);
      v = t * t * (3.0f - 2.0f * t);
    }
    if (c.flowTo > 0.0f) {
      // Along the water: the drainage network, widened a little, thinned by the noise.
      std::vector<MaskGenRule> flow = {
        Rule("flow", {{"range", 600.0f}, {"from", c.flowFrom}, {"to", c.flowTo}}),
        Rule("grow", {{"distance", 2.0f}, {"soft", 2.0f}}),
      };
      field::Grid channels;
      if (auto made = EvaluateMaskRules(context, flow, channels); !made) {
        return made;
      }
      if (channels.v.size() == out.v.size()) {
        for (std::size_t k = 0; k < out.v.size(); ++k) {
          out.v[k] = std::min(out.v[k], channels.v[k]);
        }
      }
    }
    return {};
  }

  std::vector<DetailMeasure> MeasureDetail(
    const std::vector<DetailThing>& things,
    const double area,
    const std::function<float(float, float)>& slope
  )
  {
    // Every environment's names per class: a prop by its file name, a decal by its texture.
    std::map<std::string, std::string> classOf;
    for (const Set& s : Sets()) {
      for (const std::string& n : s.small) {
        classOf.emplace(Lower(n) + "_prop.bp", "small");
      }
      for (const std::string& n : s.big) {
        classOf.emplace(Lower(n) + "_prop.bp", "big");
      }
      for (const char* id : {"crack", "ground", "cliff"}) {
        for (const std::string& n : ListOf(s, id)) {
          classOf.emplace(Lower(n), id);
        }
      }
    }
    std::vector<DetailMeasure> out;
    for (const DetailClass& c : Defs()) {
      if (c.id == "stones") {
        continue; // the same props as the small rocks
      }
      DetailMeasure m;
      m.id = c.id;
      m.label = c.label;
      out.push_back(m);
    }
    std::vector<double> slopeSum(out.size(), 0.0);
    std::vector<double> sizeSum(out.size(), 0.0);
    for (const DetailThing& t : things) {
      std::string key = Lower(t.path);
      if (!t.decal) {
        const std::size_t slash = key.find_last_of('/');
        key = slash == std::string::npos ? key : key.substr(slash + 1);
      }
      const auto it = classOf.find(key);
      if (it == classOf.end()) {
        continue;
      }
      for (std::size_t i = 0; i < out.size(); ++i) {
        if (out[i].id == it->second) {
          ++out[i].count;
          slopeSum[i] += slope ? slope(t.x, t.z) : 0.0f;
          sizeSum[i] += t.size;
        }
      }
    }
    for (std::size_t i = 0; i < out.size(); ++i) {
      if (out[i].count > 0) {
        out[i].meanSlope = static_cast<float>(slopeSum[i] / out[i].count);
        out[i].meanSize = static_cast<float>(sizeSum[i] / out[i].count);
      }
      out[i].per1000 = area > 0.0 ? static_cast<float>(out[i].count * 1000.0 / area) : 0.0f;
    }
    return out;
  }
} // namespace faf::editor
