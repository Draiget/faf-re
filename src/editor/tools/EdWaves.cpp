#include "editor/tools/EdWaves.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <unordered_map>

#include "editor/doc/EdJson.h"

namespace faf::editor
{
  namespace
  {
    constexpr float kPi = 3.14159265358979323846f;

    // The 17 floats in the file's order.
    void Floats(const WaveRecord& wave, float (&out)[17])
    {
      const float values[17] = {wave.position[0], wave.position[1], wave.position[2], wave.angle,       wave.velocity[0], wave.velocity[1],
                                wave.velocity[2], wave.lifetime[0], wave.lifetime[1], wave.period[0],   wave.period[1],   wave.scale[0],
                                wave.scale[1],    wave.frameCount,  wave.frameRate[0], wave.frameRate[1], wave.stripCount};
      std::memcpy(out, values, sizeof(values));
    }

    void FromFloats(const float (&in)[17], WaveRecord& wave)
    {
      float* const fields[17] = {&wave.position[0], &wave.position[1], &wave.position[2], &wave.angle,       &wave.velocity[0], &wave.velocity[1],
                                 &wave.velocity[2], &wave.lifetime[0], &wave.lifetime[1], &wave.period[0],   &wave.period[1],   &wave.scale[0],
                                 &wave.scale[1],    &wave.frameCount,  &wave.frameRate[0], &wave.frameRate[1], &wave.stripCount};
      for (int i = 0; i < 17; ++i) {
        *fields[i] = in[i];
      }
    }

    float Roll(std::uint32_t& seed)
    {
      seed = seed * 1664525U + 1013904223U;
      return static_cast<float>(seed >> 8) / 16777216.0f;
    }

    // A small reader of Lua table constructors: strings, numbers, booleans, nested tables, `--` comments.
    struct LuaValue
    {
      std::string text;
      double number = 0.0;
      bool isNumber = false;
      bool isTable = false;
      std::vector<std::pair<std::string, std::shared_ptr<LuaValue>>> fields;
      std::vector<std::shared_ptr<LuaValue>> items;

      [[nodiscard]] const LuaValue* Get(const std::string& key) const
      {
        for (const auto& [name, value] : fields) {
          if (name == key) {
            return value.get();
          }
        }
        return nullptr;
      }
      [[nodiscard]] float Number(const std::string& key, const float fallback) const
      {
        const LuaValue* const value = Get(key);
        return value != nullptr && value->isNumber ? static_cast<float>(value->number) : fallback;
      }
      [[nodiscard]] std::string Text(const std::string& key) const
      {
        const LuaValue* const value = Get(key);
        return value != nullptr && !value->isNumber && !value->isTable ? value->text : std::string();
      }
    };

    class LuaReader
    {
    public:
      explicit LuaReader(const std::string& text) : mText(text) {}

      bool Value(LuaValue& out)
      {
        Skip();
        if (mAt >= mText.size()) {
          return false;
        }
        const char c = mText[mAt];
        if (c == '{') {
          ++mAt;
          out.isTable = true;
          for (;;) {
            Skip();
            if (mAt >= mText.size()) {
              return false;
            }
            if (mText[mAt] == '}') {
              ++mAt;
              return true;
            }
            // `name = value`, `['name'] = value` or a list item.
            std::string key;
            const std::size_t save = mAt;
            if (std::isalpha(static_cast<unsigned char>(mText[mAt])) || mText[mAt] == '_') {
              std::size_t end = mAt;
              while (end < mText.size() && (std::isalnum(static_cast<unsigned char>(mText[end])) || mText[end] == '_')) {
                ++end;
              }
              key = mText.substr(mAt, end - mAt);
              mAt = end;
              Skip();
              if (mAt < mText.size() && mText[mAt] == '=' && (mAt + 1 >= mText.size() || mText[mAt + 1] != '=')) {
                ++mAt;
              } else {
                key.clear();
                mAt = save;
              }
            } else if (mText[mAt] == '[') {
              ++mAt;
              LuaValue name;
              if (!Value(name)) {
                return false;
              }
              Skip();
              if (mAt >= mText.size() || mText[mAt] != ']') {
                return false;
              }
              ++mAt;
              Skip();
              if (mAt >= mText.size() || mText[mAt] != '=') {
                return false;
              }
              ++mAt;
              key = name.isNumber ? std::to_string(static_cast<long long>(name.number)) : name.text;
            }
            auto value = std::make_shared<LuaValue>();
            if (!Value(*value)) {
              return false;
            }
            if (key.empty()) {
              out.items.push_back(value);
            } else {
              out.fields.emplace_back(key, value);
            }
            Skip();
            if (mAt < mText.size() && (mText[mAt] == ',' || mText[mAt] == ';')) {
              ++mAt;
            }
          }
        }
        if (c == '"' || c == '\'') {
          ++mAt;
          while (mAt < mText.size() && mText[mAt] != c) {
            if (mText[mAt] == '\\' && mAt + 1 < mText.size()) {
              ++mAt;
            }
            out.text += mText[mAt++];
          }
          ++mAt;
          return true;
        }
        if (c == '-' || c == '.' || std::isdigit(static_cast<unsigned char>(c))) {
          char* end = nullptr;
          out.number = std::strtod(mText.c_str() + mAt, &end);
          if (end == mText.c_str() + mAt) {
            return false;
          }
          out.isNumber = true;
          mAt = static_cast<std::size_t>(end - mText.c_str());
          return true;
        }
        // A word: true, false, nil.
        std::size_t end = mAt;
        while (end < mText.size() && std::isalpha(static_cast<unsigned char>(mText[end]))) {
          ++end;
        }
        if (end == mAt) {
          return false;
        }
        out.text = mText.substr(mAt, end - mAt);
        mAt = end;
        return true;
      }

      /** `name = value` at the top of the file. */
      bool Assignment(const std::string& name, LuaValue& out)
      {
        for (;;) {
          Skip();
          if (mAt >= mText.size()) {
            return false;
          }
          std::size_t end = mAt;
          while (end < mText.size() && (std::isalnum(static_cast<unsigned char>(mText[end])) || mText[end] == '_')) {
            ++end;
          }
          const std::string word = mText.substr(mAt, end - mAt);
          mAt = end == mAt ? mAt + 1 : end;
          Skip();
          if (word == name && mAt < mText.size() && mText[mAt] == '=') {
            ++mAt;
            return Value(out);
          }
        }
      }

    private:
      void Skip()
      {
        while (mAt < mText.size()) {
          if (std::isspace(static_cast<unsigned char>(mText[mAt]))) {
            ++mAt;
          } else if (mText.compare(mAt, 2, "--") == 0) {
            while (mAt < mText.size() && mText[mAt] != '\n') {
              ++mAt;
            }
          } else {
            break;
          }
        }
      }

      const std::string& mText;
      std::size_t mAt = 0;
    };
  } // namespace

  bool WaveRecord::operator==(const WaveRecord& other) const
  {
    float a[17], b[17];
    Floats(*this, a);
    Floats(other, b);
    return texture == other.texture && ramp == other.ramp && std::memcmp(a, b, sizeof(a)) == 0;
  }

  std::string WaveRecordsToBytes(const std::vector<WaveRecord>& waves)
  {
    std::string out;
    const std::int32_t count = static_cast<std::int32_t>(waves.size());
    out.append(reinterpret_cast<const char*>(&count), sizeof(count));
    for (const WaveRecord& wave : waves) {
      out += wave.texture;
      out += '\0';
      out += wave.ramp;
      out += '\0';
      float values[17];
      Floats(wave, values);
      out.append(reinterpret_cast<const char*>(values), sizeof(values));
    }
    return out;
  }

  bool WaveRecordsFromBytes(const std::string& bytes, std::vector<WaveRecord>& waves)
  {
    std::int32_t count = 0;
    if (bytes.size() < sizeof(count)) {
      return false;
    }
    std::memcpy(&count, bytes.data(), sizeof(count));
    std::size_t at = sizeof(count);
    std::vector<WaveRecord> read;
    for (std::int32_t i = 0; i < count; ++i) {
      WaveRecord wave;
      for (std::string* const text : {&wave.texture, &wave.ramp}) {
        const std::size_t end = bytes.find('\0', at);
        if (end == std::string::npos) {
          return false;
        }
        *text = bytes.substr(at, end - at);
        at = end + 1;
      }
      float values[17];
      if (bytes.size() < at + sizeof(values)) {
        return false;
      }
      std::memcpy(values, bytes.data() + at, sizeof(values));
      at += sizeof(values);
      FromFloats(values, wave);
      read.push_back(std::move(wave));
    }
    waves = std::move(read);
    return true;
  }

  std::string WavesToScmwaves(const std::vector<WaveRecord>& waves)
  {
    std::string out = "{\n    \"AllWaves\": [";
    const std::string in = "            ";
    for (std::size_t i = 0; i < waves.size(); ++i) {
      const WaveRecord& wave = waves[i];
      out += i == 0 ? "\n" : ",\n";
      out += "        {\n";
      out += in + "\"propertyID\": 0,\n";
      out += in + "\"Position\": " + JsonVectorText(wave.position, 3, in) + ",\n";
      out += in + "\"Rotation\": " + JsonNumber(wave.angle) + ",\n";
      out += in + "\"TextureName\": " + JsonQuoted(wave.texture) + ",\n";
      out += in + "\"RampName\": " + JsonQuoted(wave.ramp) + ",\n";
      out += in + "\"Velocity\": " + JsonVectorText(wave.velocity, 3, in) + ",\n";
      out += in + "\"LifetimeFirst\": " + JsonNumber(wave.lifetime[0]) + ",\n";
      out += in + "\"LifetimeSecond\": " + JsonNumber(wave.lifetime[1]) + ",\n";
      out += in + "\"PeriodFirst\": " + JsonNumber(wave.period[0]) + ",\n";
      out += in + "\"PeriodSecond\": " + JsonNumber(wave.period[1]) + ",\n";
      out += in + "\"ScaleFirst\": " + JsonNumber(wave.scale[0]) + ",\n";
      out += in + "\"ScaleSecond\": " + JsonNumber(wave.scale[1]) + ",\n";
      out += in + "\"FrameCount\": " + JsonNumber(wave.frameCount) + ",\n";
      out += in + "\"FrameRateFirst\": " + JsonNumber(wave.frameRate[0]) + ",\n";
      out += in + "\"FrameRateSecond\": " + JsonNumber(wave.frameRate[1]) + ",\n";
      out += in + "\"StripCount\": " + JsonNumber(wave.stripCount) + "\n";
      out += "        }";
    }
    return out + (waves.empty() ? "]\n}" : "\n    ]\n}");
  }

  bool WavesFromScmwaves(const std::string& text, std::vector<WaveRecord>& waves, std::string& error)
  {
    std::string array;
    if (!JsonValue(text, "AllWaves", array) || array.empty() || array.front() != '[') {
      error = "not a waves file (no AllWaves list)";
      return false;
    }
    std::vector<WaveRecord> read;
    for (const std::string& object : JsonObjects(array)) {
      WaveRecord wave;
      if (!JsonValue(object, "TextureName", wave.texture)) {
        continue;
      }
      (void)JsonValue(object, "RampName", wave.ramp);
      JsonVector(object, "Position", wave.position, 3);
      (void)JsonFloat(object, "Rotation", wave.angle);
      JsonVector(object, "Velocity", wave.velocity, 3);
      (void)JsonFloat(object, "LifetimeFirst", wave.lifetime[0]);
      (void)JsonFloat(object, "LifetimeSecond", wave.lifetime[1]);
      (void)JsonFloat(object, "PeriodFirst", wave.period[0]);
      (void)JsonFloat(object, "PeriodSecond", wave.period[1]);
      (void)JsonFloat(object, "ScaleFirst", wave.scale[0]);
      (void)JsonFloat(object, "ScaleSecond", wave.scale[1]);
      (void)JsonFloat(object, "FrameCount", wave.frameCount);
      (void)JsonFloat(object, "FrameRateFirst", wave.frameRate[0]);
      (void)JsonFloat(object, "FrameRateSecond", wave.frameRate[1]);
      (void)JsonFloat(object, "StripCount", wave.stripCount);
      read.push_back(std::move(wave));
    }
    waves = std::move(read);
    return true;
  }

  const std::vector<WavePattern>& BuiltInWavePatterns()
  {
    // SCMP_001's generators: each kind's fixed ranges, its speeds' middle and spread, its sizes' middle and spread.
    static const std::vector<WavePattern> patterns = [] {
      std::vector<WavePattern> list;
      WavePattern shore;
      shore.name = "Shore break";
      shore.texture = "/env/common/decals/shoreline/wave05_albedo.dds";
      shore.ramp = "/env/common/decals/shoreline/ramp_waves_01.dds";
      shore.speed = 0.04f;
      shore.speedVariance = 0.02f;
      shore.lifetime[0] = 15.0f;
      shore.lifetime[1] = 115.0f;
      shore.period[0] = 6.0f;
      shore.period[1] = 14.0f;
      shore.scale[0] = 0.8f;
      shore.scale[1] = 2.4f;
      shore.scaleVariance = 0.5f;
      shore.frameCount = 16.0f;
      shore.frameRate[0] = 0.423f;
      shore.frameRate[1] = 0.517f;
      shore.stripCount = 2.0f;
      list.push_back(shore);
      WavePattern swell;
      swell.name = "Long swell";
      swell.texture = "/env/common/decals/shoreline/wave06_albedo.dds";
      swell.ramp = "/env/common/decals/shoreline/ramp_waves_01.dds";
      swell.speed = 0.021f;
      swell.speedVariance = 0.007f;
      swell.lifetime[0] = 65.0f;
      swell.lifetime[1] = 265.0f;
      swell.period[0] = 10.0f;
      swell.period[1] = 50.0f;
      swell.scale[0] = 4.5f;
      swell.scale[1] = 6.0f;
      swell.scaleVariance = 0.4f;
      list.push_back(swell);
      WavePattern turbulence;
      turbulence.name = "Sea turbulence";
      turbulence.texture = "/env/common/decals/shoreline/turbulance02_albedo.dds";
      turbulence.ramp = "/env/common/decals/shoreline/waveramptest.dds";
      turbulence.speed = 0.007f;
      turbulence.speedVariance = 0.005f;
      turbulence.lifetime[0] = 30.0f;
      turbulence.lifetime[1] = 70.0f;
      turbulence.period[0] = 4.5f;
      turbulence.period[1] = 5.5f;
      turbulence.scale[0] = 0.8f;
      turbulence.scale[1] = 1.5f;
      turbulence.scaleVariance = 0.5f;
      list.push_back(turbulence);
      return list;
    }();
    return patterns;
  }

  bool ParseWavePatterns(const std::string& lua, std::vector<WavePattern>& patterns, std::string& error)
  {
    LuaReader reader(lua);
    LuaValue root;
    if (!reader.Assignment("patterns", root) || !root.isTable) {
      error = "no `patterns = { ... }` table";
      return false;
    }
    std::vector<WavePattern> read;
    for (const auto& item : root.items) {
      const LuaValue* const parameters = item->isTable ? item->Get("parameters") : nullptr;
      if (parameters == nullptr || !parameters->isTable || parameters->items.empty() || !parameters->items.front()->isTable) {
        continue;
      }
      const LuaValue& first = *parameters->items.front();
      WavePattern pattern;
      pattern.name = item->Text("name");
      pattern.texture = first.Text("texture");
      pattern.ramp = first.Text("ramp");
      const float period = first.Number("period", 5.0f);
      const float periodVariance = first.Number("periodVariance", 0.0f);
      pattern.period[0] = period - periodVariance;
      pattern.period[1] = period + periodVariance;
      const float lifetime = first.Number("lifetime", 30.0f);
      const float lifetimeVariance = first.Number("lifetimeVariance", 0.0f);
      pattern.lifetime[0] = lifetime - lifetimeVariance;
      pattern.lifetime[1] = lifetime + lifetimeVariance;
      pattern.speed = first.Number("speed", 0.01f);
      pattern.speedVariance = first.Number("speedVariance", 0.0f);
      if (const LuaValue* const scale = first.Get("scale"); scale != nullptr && scale->isTable && scale->items.size() >= 2) {
        pattern.scale[0] = static_cast<float>(scale->items[0]->number);
        pattern.scale[1] = static_cast<float>(scale->items[1]->number);
      }
      pattern.scaleVariance = first.Number("scaleVariance", 0.0f);
      pattern.frameCount = first.Number("frameCount", 1.0f);
      const float frameRate = first.Number("frameRate", 1.0f);
      const float frameRateVariance = first.Number("frameRateVariance", 0.0f);
      pattern.frameRate[0] = frameRate - frameRateVariance;
      pattern.frameRate[1] = frameRate + frameRateVariance;
      pattern.stripCount = first.Number("stripCount", 1.0f);
      if (!pattern.texture.empty()) {
        read.push_back(std::move(pattern));
      }
    }
    if (read.empty()) {
      error = "the patterns table has no pattern with a texture";
      return false;
    }
    patterns = std::move(read);
    return true;
  }

  std::vector<ShorePoint> FindShorePoints(const std::vector<float>& heights, const int width, const int height, const float waterLevel,
                                          const float depth, const float centreDegrees, const float rangeDegrees)
  {
    std::vector<ShorePoint> points;
    if (width <= 0 || height <= 0 || heights.size() < static_cast<std::size_t>(width + 1) * static_cast<std::size_t>(height + 1)) {
      return points;
    }
    const float level = waterLevel - depth;
    const auto at = [&](const int x, const int z) { return heights[static_cast<std::size_t>(z) * static_cast<std::size_t>(width + 1) + x]; };
    for (int z = 0; z < height; ++z) {
      for (int x = 0; x < width; ++x) {
        const float h00 = at(x, z), h10 = at(x + 1, z), h01 = at(x, z + 1), h11 = at(x + 1, z + 1);
        const bool above = h00 > level;
        if ((h10 > level) == above && (h01 > level) == above && (h11 > level) == above) {
          continue;
        }
        const float gx = (h10 + h11) - (h00 + h01);
        const float gz = (h01 + h11) - (h00 + h10);
        if (gx == 0.0f && gz == 0.0f) {
          continue;
        }
        const float heading = std::atan2(gz, gx);
        float off = heading * (180.0f / kPi) - centreDegrees;
        off = std::fmod(std::fmod(off, 360.0f) + 540.0f, 360.0f) - 180.0f;
        if (std::fabs(off) <= rangeDegrees) {
          points.push_back({static_cast<float>(x) + 0.5f, static_cast<float>(z) + 0.5f, heading});
        }
      }
    }
    return points;
  }

  std::vector<ShorePoint> PickShorePoints(std::vector<ShorePoint> points, const float density, const float spacing, std::uint32_t seed)
  {
    // Shuffled by the seed, then each taken unless one already taken is within the spacing (a grid of spacing-sized
    // cells finds the neighbours), until the density's share is reached.
    for (std::size_t i = points.size(); i > 1; --i) {
      std::swap(points[i - 1], points[static_cast<std::size_t>(Roll(seed) * static_cast<float>(i)) % i]);
    }
    const std::size_t target = static_cast<std::size_t>(std::lround(std::clamp(density, 0.0f, 1.0f) * static_cast<float>(points.size())));
    std::vector<ShorePoint> picked;
    const float cell = std::max(spacing, 0.001f);
    std::unordered_map<std::int64_t, std::vector<std::size_t>> grid;
    const auto key = [](const int cx, const int cz) { return (static_cast<std::int64_t>(cx) << 32) ^ static_cast<std::uint32_t>(cz); };
    for (const ShorePoint& point : points) {
      if (picked.size() >= target) {
        break;
      }
      const int cx = static_cast<int>(std::floor(point.x / cell));
      const int cz = static_cast<int>(std::floor(point.z / cell));
      bool near = false;
      for (int dz = -1; dz <= 1 && !near && spacing > 0.0f; ++dz) {
        for (int dx = -1; dx <= 1 && !near; ++dx) {
          if (const auto found = grid.find(key(cx + dx, cz + dz)); found != grid.end()) {
            for (const std::size_t other : found->second) {
              if (std::hypot(picked[other].x - point.x, picked[other].z - point.z) < spacing) {
                near = true;
                break;
              }
            }
          }
        }
      }
      if (near) {
        continue;
      }
      grid[key(cx, cz)].push_back(picked.size());
      picked.push_back(point);
    }
    return picked;
  }

  WaveRecord MakeShoreWave(const WavePattern& pattern, const ShorePoint& point, const float waterLevel, std::uint32_t& seed)
  {
    WaveRecord wave;
    wave.texture = pattern.texture;
    wave.ramp = pattern.ramp;
    wave.position[0] = point.x;
    wave.position[1] = waterLevel;
    wave.position[2] = point.z;
    // Travelling to the shore, the texture turned a quarter from it (every retail shore wave: angle = heading + 90).
    const float speed = std::max(0.0f, pattern.speed + (Roll(seed) * 2.0f - 1.0f) * pattern.speedVariance);
    wave.angle = point.heading + kPi * 0.5f;
    wave.velocity[0] = std::cos(point.heading) * speed;
    wave.velocity[2] = std::sin(point.heading) * speed;
    wave.lifetime[0] = pattern.lifetime[0];
    wave.lifetime[1] = pattern.lifetime[1];
    wave.period[0] = pattern.period[0];
    wave.period[1] = pattern.period[1];
    wave.scale[0] = std::max(0.05f, pattern.scale[0] + (Roll(seed) * 2.0f - 1.0f) * pattern.scaleVariance);
    wave.scale[1] = std::max(0.05f, pattern.scale[1] + (Roll(seed) * 2.0f - 1.0f) * pattern.scaleVariance);
    wave.frameCount = pattern.frameCount;
    wave.frameRate[0] = pattern.frameRate[0];
    wave.frameRate[1] = pattern.frameRate[1];
    wave.stripCount = pattern.stripCount;
    return wave;
  }
} // namespace faf::editor
