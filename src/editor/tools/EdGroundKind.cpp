#include "editor/tools/EdGroundKind.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <string>
#include <vector>

namespace faf::editor
{
  namespace
  {
    constexpr int kKinds = 9;
    constexpr float kMinConfidence = 0.25f; // below it a colour says nothing

    enum class Match : std::uint8_t
    {
      Inside, // anywhere in a word
      Word,   // the whole word
      Prefix, // the start of a word
    };

    struct Token
    {
      const char* text;
      GroundKind kind;
      float weight;
      Match match;
    };

    using enum GroundKind;
    constexpr Match S = Match::Inside;
    constexpr Match W = Match::Word;
    constexpr Match P = Match::Prefix;

    // FAF Studio's roledetect.lua TOKENS, in its order (the order breaks ties between tokens of one length).
    constexpr Token kTokens[] = {
      // compounds first
      {"sandwet", Wet, 1.2f, S},
      {"wetsand", Wet, 1.2f, S},
      {"drysand", Sand, 1.1f, S},
      {"sandstone", Rock, 1.0f, S},
      {"darkrock", DarkRock, 1.2f, S},
      {"highrock", HighRock, 1.2f, S},
      {"icerock", HighRock, 1.2f, S},
      {"snowrock", HighRock, 1.2f, S},
      {"lavarock", DarkRock, 1.1f, S},
      {"permafrost", Snow, 1.0f, S},
      // grass
      {"grass", Grass, 1.0f, S},
      {"gras", Grass, 1.0f, S},
      {"moss", Grass, 0.8f, S},
      {"hosta", Grass, 1.0f, S},
      {"jungle", Grass, 0.9f, S},
      {"jung", Grass, 0.8f, P},
      {"fern", Grass, 0.7f, S},
      {"meadow", Grass, 1.0f, S},
      {"lawn", Grass, 1.0f, S},
      {"turf", Grass, 1.0f, S},
      {"weed", Grass, 0.6f, S},
      {"shrub", Grass, 0.5f, S},
      {"bush", Grass, 0.5f, W},
      {"leaf", Grass, 0.5f, W},
      {"leaves", Grass, 0.6f, W},
      {"veget", Grass, 0.9f, P},
      {"bushy", Grass, 0.6f, S},
      {"creeper", Grass, 0.6f, S},
      {"foliage", Grass, 0.8f, S},
      {"sphagnum", Grass, 0.7f, S},
      {"clover", Grass, 1.0f, S},
      {"forest", Grass, 0.6f, W},
      {"pasture", Grass, 1.0f, S},
      {"green", Grass, 0.7f, W},
      {"heather", Grass, 0.8f, S},
      // sand
      {"sand", Sand, 1.0f, S},
      {"dune", Sand, 1.0f, S},
      {"desert", Sand, 0.9f, S},
      {"beach", Sand, 1.0f, S},
      {"dust", Sand, 0.6f, S},
      {"silt", Sand, 0.5f, S},
      {"arid", Sand, 0.7f, S},
      {"coast", Sand, 0.6f, S},
      // dirt
      {"dirt", Dirt, 1.0f, S},
      {"mud", Dirt, 1.0f, S},
      {"soil", Dirt, 1.0f, S},
      {"earth", Dirt, 0.6f, W},
      {"ground", Dirt, 0.8f, S},
      {"gravel", Dirt, 0.9f, S},
      {"gravil", Dirt, 0.9f, S},
      {"pebble", Dirt, 0.8f, S},
      {"clay", Dirt, 0.9f, S},
      {"path", Dirt, 0.6f, W},
      {"trail", Dirt, 0.6f, W},
      {"road", Dirt, 0.5f, W},
      {"loam", Dirt, 1.0f, S},
      {"rubble", Dirt, 0.7f, S},
      {"hardpan", Dirt, 0.9f, S},
      {"crack", Dirt, 0.4f, P},
      // rock
      {"rock", Rock, 1.0f, S},
      {"cliff", Rock, 1.0f, S},
      {"stone", Rock, 0.9f, S},
      {"granite", Rock, 1.0f, S},
      {"boulder", Rock, 1.0f, S},
      {"basalt", Rock, 0.9f, S},
      {"slate", Rock, 0.8f, S},
      {"crag", Rock, 0.9f, S},
      {"cobble", Rock, 0.7f, S},
      {"shale", Rock, 0.8f, S},
      {"limestone", Rock, 1.0f, S},
      {"strata", Rock, 0.5f, P},
      // wet ground
      {"wet", Wet, 0.9f, W},
      {"water", Wet, 0.9f, S},
      {"melt", Wet, 0.8f, S},
      {"lava", Wet, 0.8f, S},
      {"swamp", Wet, 0.7f, S},
      {"bog", Wet, 0.8f, W},
      {"marsh", Wet, 0.8f, S},
      {"puddle", Wet, 1.0f, S},
      {"river", Wet, 0.6f, S},
      {"damp", Wet, 0.9f, S},
      {"slime", Wet, 0.6f, S},
      {"algae", Wet, 0.6f, S},
      {"lake", Wet, 0.6f, W},
      {"ooze", Wet, 0.7f, S},
      // high rock
      {"peak", HighRock, 0.8f, W},
      {"alpine", HighRock, 0.7f, S},
      {"summit", HighRock, 0.8f, S},
      {"mountain", HighRock, 0.6f, S},
      {"mount", HighRock, 0.6f, W},
      // dark rock
      {"obsidian", DarkRock, 1.0f, S},
      {"ash", DarkRock, 0.8f, W},
      {"ashes", DarkRock, 0.8f, W},
      {"coal", DarkRock, 0.9f, S},
      {"soot", DarkRock, 0.9f, S},
      {"cinder", DarkRock, 0.9f, S},
      {"burnt", DarkRock, 0.8f, S},
      {"scorch", DarkRock, 0.8f, S},
      {"volcan", DarkRock, 0.8f, P},
      {"magma", DarkRock, 0.6f, S},
      // snow
      {"snow", Snow, 1.0f, S},
      {"ice", Snow, 1.0f, W},
      {"frost", Snow, 1.0f, S},
      {"glacier", Snow, 1.0f, S},
      {"frozen", Snow, 1.0f, S},
      {"white", Snow, 0.6f, W},
      {"arctic", Snow, 0.7f, S},
    };

    constexpr const char* kDarkWords[] = {"dark", "dk", "black", "blk", "dim", "shadow"};
    constexpr const char* kLightWords[] = {"light", "lt", "pale", "bright", "high", "top", "white"};

    /** The tokens, longest first (ties in the table's order). */
    const std::vector<const Token*>& SortedTokens()
    {
      static const std::vector<const Token*> sorted = [] {
        std::vector<const Token*> list;
        for (const Token& token : kTokens) {
          list.push_back(&token);
        }
        std::stable_sort(list.begin(), list.end(), [](const Token* a, const Token* b) {
          return std::char_traits<char>::length(a->text) > std::char_traits<char>::length(b->text);
        });
        return list;
      }();
      return sorted;
    }

    /** The words of a name, lower case: a change from lower to upper case, digits and punctuation split them. */
    std::vector<std::string> Words(
      const std::string_view name
    )
    {
      std::vector<std::string> words;
      std::string current;
      bool previousLower = false;
      for (const char c : name) {
        const bool upper = c >= 'A' && c <= 'Z';
        const bool lower = c >= 'a' && c <= 'z';
        if (upper || lower) {
          if (upper && previousLower && !current.empty()) {
            words.push_back(current);
            current.clear();
          }
          current.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
          previousLower = lower;
        } else {
          if (!current.empty()) {
            words.push_back(current);
          }
          current.clear();
          previousLower = false;
        }
      }
      if (!current.empty()) {
        words.push_back(current);
      }
      return words;
    }

    bool WordHas(
      const std::string& word,
      const Token& token
    )
    {
      switch (token.match) {
      case Match::Word:
        return word == token.text;
      case Match::Prefix:
        return word.rfind(token.text, 0) == 0;
      case Match::Inside:
        return word.find(token.text) != std::string::npos;
      }
      return false;
    }

    float Ramp(
      const float x,
      const float a,
      const float b
    )
    {
      if (x <= a) {
        return 0.0f;
      }
      if (x >= b) {
        return 1.0f;
      }
      return (x - a) / (b - a);
    }

    /** 0 below a, rising to 1 at b, 1 up to c, falling to 0 at d. */
    float Band(
      const float x,
      const float a,
      const float b,
      const float c,
      const float d
    )
    {
      return std::min(Ramp(x, a, b), 1.0f - Ramp(x, c, d));
    }

    /** The best kind of a score table (in the enum's order on ties) and the runner-up's score. */
    GroundKind Best(
      const std::array<float, kKinds>& scores,
      float& top,
      float& second
    )
    {
      top = 0.0f;
      second = 0.0f;
      GroundKind best = Unknown;
      for (int k = 1; k < kKinds; ++k) {
        const float s = scores[static_cast<std::size_t>(k)];
        if (s > top) {
          second = top;
          top = s;
          best = static_cast<GroundKind>(k);
        } else if (s > second) {
          second = s;
        }
      }
      return best;
    }

    float& Score(
      std::array<float, kKinds>& scores,
      const GroundKind kind
    )
    {
      return scores[static_cast<std::size_t>(kind)];
    }
  } // namespace

  const char* GroundKindName(
    const GroundKind kind
  ) noexcept
  {
    switch (kind) {
    case Grass:
      return "grass";
    case Rock:
      return "rock";
    case Sand:
      return "sand";
    case Dirt:
      return "dirt";
    case Wet:
      return "wet ground";
    case HighRock:
      return "high rock";
    case DarkRock:
      return "dark rock";
    case Snow:
      return "snow";
    case Unknown:
      break;
    }
    return "unknown";
  }

  bool IsRockKind(
    const GroundKind kind
  ) noexcept
  {
    return kind == Rock || kind == HighRock || kind == DarkRock;
  }

  GroundGuess GroundKindOfName(
    const std::string_view path
  )
  {
    // The file's name without its folder, its extension and an "_albedo" ending.
    std::string_view base = path;
    if (const std::size_t slash = base.find_last_of("/\\"); slash != std::string_view::npos) {
      base.remove_prefix(slash + 1);
    }
    if (const std::size_t dot = base.find_last_of('.'); dot != std::string_view::npos) {
      base = base.substr(0, dot);
    }
    if (base.size() >= 6) {
      std::string tail(base.substr(base.size() - 6));
      for (char& c : tail) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      }
      if (tail == "albedo") {
        base.remove_suffix(6);
        if (!base.empty() && base.back() == '_') {
          base.remove_suffix(1);
        }
      }
    }
    const std::vector<std::string> words = Words(base);
    const std::size_t count = words.size();
    std::array<float, kKinds> scores{};
    std::vector<bool> used(count, false);
    for (const Token* const token : SortedTokens()) {
      for (std::size_t i = 0; i < count; ++i) {
        if (used[i] || !WordHas(words[i], *token)) {
          continue;
        }
        float weight = token->weight;
        // The noun of a compound comes last.
        if (i + 1 == count || (i + 2 == count && words[count - 1].size() <= 3)) {
          weight += 0.15f;
        }
        Score(scores, token->kind) += weight;
        if (std::char_traits<char>::length(token->text) >= 4 || token->match == Match::Word) {
          used[i] = true;
        }
        break; // each token counts once
      }
    }
    bool dark = false;
    bool light = false;
    for (const std::string& word : words) {
      dark = dark || std::find(std::begin(kDarkWords), std::end(kDarkWords), word) != std::end(kDarkWords);
      light = light || std::find(std::begin(kLightWords), std::end(kLightWords), word) != std::end(kLightWords);
    }
    // Ice and rock together: a pale rock, not snow.
    if (Score(scores, Snow) >= 0.5f && Score(scores, Rock) >= 0.5f) {
      Score(scores, HighRock) += Score(scores, Snow) + Score(scores, Rock) - 0.3f;
      Score(scores, Snow) = 0.0f;
      Score(scores, Rock) = 0.0f;
    }
    GroundGuess guess;
    guess.grassScore = Score(scores, Grass);
    guess.sandScore = Score(scores, Sand);
    float top = 0.0f;
    float second = 0.0f;
    guess.kind = Best(scores, top, second);
    if (guess.kind == Unknown) {
      return guess;
    }
    bool modified = false;
    if (IsRockKind(guess.kind)) {
      if (dark && !light) {
        guess.kind = DarkRock;
        modified = true;
      } else if (light && !dark) {
        guess.kind = HighRock;
        modified = true;
      }
    }
    guess.confidence = std::min(0.95f, 0.45f + 0.5f * std::min(1.0f, top));
    if (second > 0.5f * top) {
      guess.confidence *= 0.6f;
    }
    guess.plainRock = guess.kind == Rock && !modified;
    return guess;
  }

  GroundGuess GroundKindOfColour(
    const float r,
    const float g,
    const float b
  )
  {
    const float high = std::max({r, g, b});
    const float low = std::min({r, g, b});
    const float spread = high - low;
    float hue = 0.0f;
    if (spread > 0.0001f) {
      if (high == r) {
        hue = 60.0f * (g - b) / spread;
      } else if (high == g) {
        hue = 60.0f * (2.0f + (b - r) / spread);
      } else {
        hue = 60.0f * (4.0f + (r - g) / spread);
      }
      if (hue < 0.0f) {
        hue += 360.0f;
      }
    }
    const float sat = high > 0.0001f ? spread / high : 0.0f;
    const float val = high;
    const float greenLead = g - std::max(r, b);
    const float warm = r - b;

    std::array<float, kKinds> s{};
    const float white = Ramp(val, 0.70f, 0.86f) * (1.0f - Ramp(sat, 0.10f, 0.26f));
    const float icy = Ramp(val, 0.60f, 0.78f) * Band(hue, 165, 190, 250, 275) * Ramp(sat, 0.05f, 0.12f) *
      (1.0f - Ramp(sat, 0.30f, 0.45f));
    Score(s, Snow) = std::max(white, icy * 0.85f);
    Score(s, Grass) = Ramp(greenLead, 0.0f, 0.05f) * Band(hue, 52, 64, 150, 175) * Ramp(sat, 0.12f, 0.28f);
    Score(s, Sand) = Band(hue, 18, 30, 56, 64) * Band(sat, 0.08f, 0.16f, 0.50f, 0.70f) * Ramp(val, 0.42f, 0.62f) *
      Ramp(warm, 0.0f, 0.06f);
    Score(s, Dirt) =
      Band(hue, 5, 14, 40, 52) * Band(sat, 0.14f, 0.24f, 0.70f, 0.85f) * Band(val, 0.16f, 0.26f, 0.50f, 0.66f);
    const float grey = 1.0f - Ramp(sat, 0.14f, 0.30f);
    Score(s, Rock) = grey * Band(val, 0.22f, 0.32f, 0.60f, 0.74f);
    Score(s, HighRock) = grey * Ramp(val, 0.56f, 0.70f) * (1.0f - Ramp(val, 0.80f, 0.90f));
    Score(s, DarkRock) = (1.0f - Ramp(sat, 0.40f, 0.60f)) * (1.0f - Ramp(val, 0.20f, 0.32f));
    Score(s, Wet) = std::max(
      {Band(hue, 165, 185, 265, 285) * Ramp(sat, 0.08f, 0.18f) * (1.0f - Ramp(val, 0.42f, 0.58f)),
       Band(hue, 10, 20, 50, 60) * Ramp(sat, 0.35f, 0.50f) * (1.0f - Ramp(val, 0.20f, 0.30f)) * 0.8f,
       // molten ground: saturated orange red
       Band(hue, -1, 0, 24, 36) * Ramp(sat, 0.65f, 0.82f) * Ramp(val, 0.45f, 0.60f) * 0.8f}
    );
    GroundGuess guess;
    float top = 0.0f;
    float second = 0.0f;
    const GroundKind best = Best(s, top, second);
    if (top < kMinConfidence) {
      return guess;
    }
    guess.kind = best;
    const float margin = (top - second) / std::max(top, 0.001f);
    guess.confidence = std::min(0.95f, top * (0.55f + 0.45f * margin));
    return guess;
  }

  GroundGuess GroundKindOf(
    const std::string_view path,
    const float* const averageRgb
  )
  {
    const GroundGuess name = GroundKindOfName(path);
    const GroundGuess colour =
      averageRgb != nullptr ? GroundKindOfColour(averageRgb[0], averageRgb[1], averageRgb[2]) : GroundGuess{};
    if (name.kind == Unknown) {
      GroundGuess out = colour;
      out.confidence *= 0.85f;
      return out;
    }
    GroundGuess out = name;
    // A rock by name: the colour says which rock (dark, ordinary, pale) unless the name already did.
    if (name.plainRock && IsRockKind(colour.kind)) {
      out.kind = colour.kind;
      out.confidence = std::min(name.confidence, 0.5f + 0.5f * colour.confidence);
    }
    // Sand and grass are the pair that mixes up: the colour decides when the name is weak, names both, or the colour is
    // sure.
    const auto grassOrSand = [](const GroundKind k) {
      return k == Grass || k == Sand;
    };
    if (grassOrSand(out.kind) && grassOrSand(colour.kind) && colour.kind != out.kind) {
      const bool both = name.grassScore > 0.0f && name.sandScore > 0.0f;
      if (name.confidence < 0.8f || both || (colour.confidence > 0.8f && name.confidence < 0.9f)) {
        out.kind = colour.kind;
        out.confidence = colour.confidence * 0.85f;
      } else {
        out.confidence *= 0.7f;
      }
    } else if (
      name.confidence < 0.6f && colour.kind != Unknown && colour.kind != out.kind && colour.confidence > name.confidence
    ) {
      out.kind = colour.kind;
      out.confidence = colour.confidence * 0.85f;
    }
    return out;
  }
} // namespace faf::editor
