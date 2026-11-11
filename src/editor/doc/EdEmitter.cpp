#include "editor/doc/EdEmitter.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace faf::editor
{
  namespace
  {
    // Retail's kEmitterCurveEditors (src/moho/app/WEmitterWx.cpp), in the file's curve order.
    const EmitterCurveInfo kCurves[kEmitterCurveCount] = {
      {"XDirectionCurve", "Direction, Rate, Lifetime", "X Direction", -1.0f, 1.0f, 0.0f, 0.0f},
      {"YDirectionCurve", "", "Y Direction", -1.0f, 1.0f, 0.5f, 0.0f},
      {"ZDirectionCurve", "", "Z Direction", -1.0f, 1.0f, 0.0f, 0.0f},
      {"EmitRateCurve", "", "Emit Rate", -0.5f, 30.0f, 1.0f, 0.0f},
      {"LifetimeCurve", "", "Lifetime", 0.0f, 30.0f, 10.0f, 0.0f},
      {"VelocityCurve", "Forces", "Velocity", 0.0f, 5.0f, 1.0f, 0.0f},
      {"XAccelCurve", "", "X Acceleration", -0.5f, 0.5f, 0.0f, 0.0f},
      {"YAccelCurve", "", "Y Acceleration", -0.5f, 0.5f, 0.0f, 0.0f},
      {"ZAccelCurve", "", "Z Acceleration", -0.5f, 0.5f, 0.0f, 0.0f},
      {"ResistanceCurve", "", "Resistance", 0.0f, 1.0f, 0.0f, 0.0f},
      {"SizeCurve", "Spacial", "Emitter Size", 0.0f, 5.0f, 0.0f, 0.0f},
      {"XPosCurve", "", "X Position", -5.0f, 5.0f, 0.0f, 0.0f},
      {"YPosCurve", "", "Y Position", -5.0f, 5.0f, 0.0f, 0.0f},
      {"ZPosCurve", "", "Z Position", -5.0f, 5.0f, 0.0f, 0.0f},
      {"StartSizeCurve", "Size and Rotation", "Particle Start Size", 0.0f, 2.0f, 1.0f, 0.0f},
      {"EndSizeCurve", "", "Particle End Size", 0.0f, 2.0f, 1.0f, 0.1f},
      {"InitialRotationCurve", "", "Particle Rotation", 0.0f, 360.0f, 180.0f, 360.0f},
      {"RotationRateCurve", "", "Particle Rotation Rate", -90.0f, 90.0f, 0.0f, 10.0f},
      {"FrameRateCurve", "Animation and Selection", "Particle Frame Rate", 0.0f, 5.0f, 1.0f, 0.0f},
      {"TextureSelectionCurve", "", "Particle Texture Selection", 0.0f, 5.0f, 0.0f, 0.0f},
      {"RampSelectionCurve", "", "Color/Alpha Ramp Selection", 0.0f, 1.0f, 0.0f, 0.0f},
    };

    const char* const kFlags[kEmitterFlagCount] = {
      "LocalVelocity", "LocalAcceleration", "Gravity", "AlignRotation", "AlignToBone", "Flat", "EmitIfVisible",
      "CatchupEmit", "CreateIfVisible", "SnapToWaterline", "OnlyEmitOnWater", "ParticleResistance", "InterpolateEmission",
    };

    // ---- A Lua table literal, enough for blueprint files ----

    struct Value;
    struct Field
    {
      std::string key; // empty: a positional item
      std::vector<Value> value; // one
    };

    struct Value
    {
      enum class Kind
      {
        Nil,
        Number,
        String,
        Bool,
        Name,
        Table,
      } kind = Kind::Nil;
      double number = 0.0;
      std::string text;
      bool flag = false;
      std::vector<Field> fields;
      std::size_t begin = 0;
      std::size_t end = 0;

      [[nodiscard]] const Value* Find(const char* key) const
      {
        for (const Field& field : fields) {
          if (field.key == key) {
            return &field.value.front();
          }
        }
        return nullptr;
      }
    };

    class Reader
    {
    public:
      explicit Reader(const std::string& text) : mText(text) {}

      bool Parse(Value& out, std::string& error)
      {
        Skip();
        // `EmitterBlueprint { ... }` or `EmitterBlueprint({ ... })`.
        const std::size_t nameStart = mAt;
        while (mAt < mText.size() && (std::isalnum(static_cast<unsigned char>(mText[mAt])) != 0 || mText[mAt] == '_')) {
          ++mAt;
        }
        const std::string name = mText.substr(nameStart, mAt - nameStart);
        if (name != "EmitterBlueprint") {
          return Fail("not an EmitterBlueprint file", error);
        }
        Skip();
        const bool paren = Eat('(');
        Skip();
        if (!ParseValue(out) || out.kind != Value::Kind::Table) {
          return Fail(mError.empty() ? "expected a table" : mError, error);
        }
        Skip();
        if (paren && !Eat(')')) {
          return Fail("expected )", error);
        }
        return true;
      }

    private:
      bool Fail(const std::string& what, std::string& error)
      {
        int line = 1;
        for (std::size_t i = 0; i < mAt && i < mText.size(); ++i) {
          line += mText[i] == '\n' ? 1 : 0;
        }
        error = "line " + std::to_string(line) + ": " + what;
        return false;
      }

      bool Eat(const char c)
      {
        if (mAt < mText.size() && mText[mAt] == c) {
          ++mAt;
          return true;
        }
        return false;
      }

      /** Whitespace and comments (`-- line`, `--[[ block ]]`). */
      void Skip()
      {
        for (;;) {
          while (mAt < mText.size() && std::isspace(static_cast<unsigned char>(mText[mAt])) != 0) {
            ++mAt;
          }
          if (mText.compare(mAt, 4, "--[[") == 0) {
            const std::size_t close = mText.find("]]", mAt + 4);
            mAt = close == std::string::npos ? mText.size() : close + 2;
          } else if (mText.compare(mAt, 2, "--") == 0) {
            const std::size_t close = mText.find('\n', mAt);
            mAt = close == std::string::npos ? mText.size() : close + 1;
          } else {
            return;
          }
        }
      }

      bool ParseValue(Value& out)
      {
        Skip();
        out.begin = mAt;
        if (mAt >= mText.size()) {
          mError = "unexpected end of file";
          return false;
        }
        const char c = mText[mAt];
        if (c == '{') {
          ++mAt;
          out.kind = Value::Kind::Table;
          for (;;) {
            Skip();
            if (Eat('}')) {
              break;
            }
            Field field;
            // `name = value`, `[key] = value` or a positional value.
            const std::size_t save = mAt;
            if (std::isalpha(static_cast<unsigned char>(mText[mAt])) != 0 || mText[mAt] == '_') {
              std::size_t end = mAt;
              while (end < mText.size() && (std::isalnum(static_cast<unsigned char>(mText[end])) != 0 || mText[end] == '_')) {
                ++end;
              }
              std::size_t after = end;
              while (after < mText.size() && std::isspace(static_cast<unsigned char>(mText[after])) != 0) {
                ++after;
              }
              if (after < mText.size() && mText[after] == '=' && (after + 1 >= mText.size() || mText[after + 1] != '=')) {
                field.key = mText.substr(mAt, end - mAt);
                mAt = after + 1;
              } else {
                mAt = save;
              }
            } else if (mText[mAt] == '[' && mAt + 1 < mText.size() && mText[mAt + 1] != '[') {
              ++mAt;
              Value key;
              if (!ParseValue(key)) {
                return false;
              }
              Skip();
              if (!Eat(']')) {
                mError = "expected ]";
                return false;
              }
              Skip();
              if (!Eat('=')) {
                mError = "expected =";
                return false;
              }
              field.key = key.kind == Value::Kind::String ? key.text : mText.substr(key.begin, key.end - key.begin);
            }
            field.value.resize(1);
            if (!ParseValue(field.value.front())) {
              return false;
            }
            out.fields.push_back(std::move(field));
            Skip();
            if (!Eat(',') && !Eat(';')) {
              Skip();
              if (!Eat('}')) {
                mError = "expected , or }";
                return false;
              }
              break;
            }
          }
        } else if (c == '\'' || c == '"') {
          ++mAt;
          out.kind = Value::Kind::String;
          while (mAt < mText.size() && mText[mAt] != c) {
            if (mText[mAt] == '\\' && mAt + 1 < mText.size()) {
              ++mAt;
            }
            out.text += mText[mAt++];
          }
          if (!Eat(c)) {
            mError = "unfinished string";
            return false;
          }
        } else if (c == '[' && mAt + 1 < mText.size() && (mText[mAt + 1] == '[' || mText[mAt + 1] == '=')) {
          // [[long string]] (or [==[ ... ]==]).
          std::size_t level = 0;
          std::size_t at = mAt + 1;
          while (at < mText.size() && mText[at] == '=') {
            ++level;
            ++at;
          }
          if (at >= mText.size() || mText[at] != '[') {
            mError = "bad long string";
            return false;
          }
          const std::string close = "]" + std::string(level, '=') + "]";
          const std::size_t end = mText.find(close, at + 1);
          if (end == std::string::npos) {
            mError = "unfinished long string";
            return false;
          }
          out.kind = Value::Kind::String;
          out.text = mText.substr(at + 1, end - at - 1);
          mAt = end + close.size();
        } else if (c == '-' || c == '.' || std::isdigit(static_cast<unsigned char>(c)) != 0) {
          char* end = nullptr;
          out.number = std::strtod(mText.c_str() + mAt, &end);
          if (end == mText.c_str() + mAt) {
            mError = "bad number";
            return false;
          }
          out.kind = Value::Kind::Number;
          mAt = static_cast<std::size_t>(end - mText.c_str());
        } else if (std::isalpha(static_cast<unsigned char>(c)) != 0 || c == '_') {
          std::size_t end = mAt;
          while (end < mText.size() && (std::isalnum(static_cast<unsigned char>(mText[end])) != 0 || mText[end] == '_' || mText[end] == '.')) {
            ++end;
          }
          out.text = mText.substr(mAt, end - mAt);
          mAt = end;
          if (out.text == "true" || out.text == "false") {
            out.kind = Value::Kind::Bool;
            out.flag = out.text == "true";
          } else if (out.text == "nil") {
            out.kind = Value::Kind::Nil;
          } else {
            out.kind = Value::Kind::Name; // a name or a call like Sound { ... }: kept as text
            Skip();
            if (mAt < mText.size() && (mText[mAt] == '{' || mText[mAt] == '(')) {
              Value argument;
              const bool paren = Eat('(');
              if (!ParseValue(argument)) {
                return false;
              }
              Skip();
              if (paren && !Eat(')')) {
                mError = "expected )";
                return false;
              }
            }
          }
        } else {
          mError = std::string("unexpected '") + c + "'";
          return false;
        }
        out.end = mAt;
        return true;
      }

      const std::string& mText;
      std::size_t mAt = 0;
      std::string mError;
    };

    float NumberOf(const Value& value)
    {
      if (value.kind == Value::Kind::Number) {
        return static_cast<float>(value.number);
      }
      if (value.kind == Value::Kind::Bool) {
        return value.flag ? 1.0f : 0.0f;
      }
      return 0.0f;
    }

    bool FlagOf(const Value& value)
    {
      return value.kind == Value::Kind::Bool ? value.flag : value.kind == Value::Kind::Number && value.number != 0.0;
    }

    void Append(std::string& out, const char* format, ...)
    {
      char buffer[1024];
      va_list args;
      va_start(args, format);
      const int n = std::vsnprintf(buffer, sizeof(buffer), format, args);
      va_end(args);
      if (n > 0) {
        out.append(buffer, static_cast<std::size_t>(std::min(n, static_cast<int>(sizeof(buffer)) - 1)));
      }
    }
  } // namespace

  const EmitterCurveInfo& CurveInfo(const int curve)
  {
    return kCurves[curve < 0 || curve >= kEmitterCurveCount ? 0 : curve];
  }

  const char* FlagName(const int flag)
  {
    return kFlags[flag < 0 || flag >= kEmitterFlagCount ? 0 : flag];
  }

  EmitterBlueprint NewEmitter()
  {
    EmitterBlueprint emitter;
    emitter.blueprintId = "new_emitter";
    emitter.flags[kEmitIfVisible] = true;
    emitter.flags[kCatchupEmit] = true;
    emitter.flags[kInterpolateEmission] = true;
    emitter.texture = "/textures/particles/smoke_white_01.dds";
    emitter.rampTexture = "/textures/particles/ramp_white_01.dds";
    for (int c = 0; c < kEmitterCurveCount; ++c) {
      EmitterCurve& curve = emitter.curves[static_cast<std::size_t>(c)];
      curve.xRange = emitter.lifetime;
      curve.keys = {{emitter.lifetime * 0.5f, kCurves[c].initialValue, kCurves[c].initialSpread}};
    }
    return emitter;
  }

  bool ParseEmitter(const std::string& text, EmitterBlueprint& out, std::string& error)
  {
    Value root;
    Reader reader(text);
    if (!reader.Parse(root, error)) {
      return false;
    }
    EmitterBlueprint emitter;
    for (EmitterCurve& curve : emitter.curves) {
      curve = {};
    }
    for (const Field& field : root.fields) {
      const Value& value = field.value.front();
      const std::string& key = field.key;
      bool known = true;
      if (key == "BlueprintId") {
        emitter.blueprintId = value.text;
      } else if (key == "Lifetime") {
        emitter.lifetime = NumberOf(value);
      } else if (key == "Repeattime") {
        emitter.repeatTime = NumberOf(value);
      } else if (key == "TextureFramecount") {
        emitter.textureFrameCount = NumberOf(value);
      } else if (key == "Blendmode") {
        emitter.blendMode = NumberOf(value);
      } else if (key == "LODCutoff") {
        emitter.lodCutoff = NumberOf(value);
      } else if (key == "TextureStripcount") {
        emitter.textureStripCount = NumberOf(value);
      } else if (key == "SortOrder") {
        emitter.sortOrder = NumberOf(value);
      } else if (key == "LowFidelity") {
        emitter.lowFidelity = FlagOf(value);
      } else if (key == "MedFidelity") {
        emitter.medFidelity = FlagOf(value);
      } else if (key == "HighFidelity") {
        emitter.highFidelity = FlagOf(value);
      } else if (key == "Texture") {
        emitter.texture = value.text;
      } else if (key == "RampTexture") {
        emitter.rampTexture = value.text;
      } else {
        known = false;
        for (int f = 0; f < kEmitterFlagCount && !known; ++f) {
          if (key == kFlags[f]) {
            emitter.flags[static_cast<std::size_t>(f)] = FlagOf(value);
            known = true;
          }
        }
        for (int c = 0; c < kEmitterCurveCount && !known; ++c) {
          if (key != kCurves[c].name || value.kind != Value::Kind::Table) {
            continue;
          }
          EmitterCurve& curve = emitter.curves[static_cast<std::size_t>(c)];
          if (const Value* range = value.Find("XRange")) {
            curve.xRange = NumberOf(*range);
          }
          if (const Value* keys = value.Find("Keys"); keys != nullptr && keys->kind == Value::Kind::Table) {
            for (const Field& item : keys->fields) {
              const Value& k = item.value.front();
              EmitterKey made;
              const Value* x = k.Find("x");
              const Value* y = k.Find("y");
              const Value* z = k.Find("z");
              if (x == nullptr && k.fields.size() >= 2) {
                // { 1, 2, 3 }
                x = &k.fields[0].value.front();
                y = &k.fields[1].value.front();
                z = k.fields.size() >= 3 ? &k.fields[2].value.front() : nullptr;
              }
              made.x = x != nullptr ? NumberOf(*x) : 0.0f;
              made.y = y != nullptr ? NumberOf(*y) : 0.0f;
              made.z = z != nullptr ? NumberOf(*z) : 0.0f;
              curve.keys.push_back(made);
            }
          }
          known = true;
        }
      }
      if (!known && !key.empty()) {
        emitter.extra.emplace_back(key, text.substr(value.begin, value.end - value.begin));
      }
    }
    out = std::move(emitter);
    return true;
  }

  float EmitterCurveValue(const EmitterCurve& curve, const float t, const float random)
  {
    if (curve.keys.empty()) {
      return 0.0f;
    }
    // SEfxCurve keeps its keys sorted by x (BuildEmitterCurveFromBlueprint inserts them in order).
    std::vector<EmitterKey> keys = curve.keys;
    std::stable_sort(keys.begin(), keys.end(), [](const EmitterKey& a, const EmitterKey& b) { return a.x < b.x; });
    std::size_t at = 0;
    while (at < keys.size() && keys[at].x <= t) {
      ++at;
    }
    float y = 0.0f;
    float z = 0.0f;
    if (at == keys.size()) {
      y = keys.back().y;
      z = keys.back().z;
    } else if (at == 0) {
      y = keys.front().y;
      z = keys.front().z;
    } else {
      const EmitterKey& a = keys[at - 1];
      const EmitterKey& b = keys[at];
      const float f = (t - a.x) / (b.x - a.x);
      y = a.y + (b.y - a.y) * f;
      z = a.z + (b.z - a.z) * f;
    }
    return (random - 0.5f) * z + y;
  }

  std::string EmitterTypeTag(const EmitterBlueprint& e)
  {
    const bool align = e.flags[kAlignRotation];
    const bool bone = e.flags[kAlignToBone];
    const bool flat = e.flags[kFlat];
    if (e.textureFrameCount <= 1.0f && e.textureStripCount <= 1.0f) {
      if (align) {
        return "TRampAlign";
      }
      if (!bone) {
        return flat ? "TRampFlat" : "TRamp";
      }
      return flat ? "TRampFlat" : "TRampAlignToBone";
    }
    if (align) {
      return "TRampAnimateAlign";
    }
    if (!bone) {
      return flat ? "TRampAnimateFlat" : "TRampAnimate";
    }
    return flat ? "TRampAnimateFlat" : "TRampAnimateAlignToBone";
  }

  bool EmitterFinished(const EmitterBlueprint& e, const float tickCount)
  {
    // CEfxEmitter::OnTick: destroyed once TICKCOUNT reaches Lifetime, unless Lifetime is negative.
    return e.lifetime >= 0.0f && tickCount >= e.lifetime;
  }

  std::vector<EmittedParticle> EmitTick(const EmitterBlueprint& e, const float tickCount, float& carry, const std::function<float()>& random)
  {
    std::vector<EmittedParticle> out;
    const float repeat = e.repeatTime;
    const auto phaseOf = [repeat](const float t) {
      if (repeat == 0.0f) {
        return t;
      }
      float phase = std::fmod(t, repeat);
      if ((phase < 0.0f) != (repeat < 0.0f)) {
        phase += repeat;
      }
      return phase;
    };
    const auto curve = [&](const int c, const float phase) { return EmitterCurveValue(e.curves[static_cast<std::size_t>(c)], phase, random()); };
    carry += curve(kEmitRate, phaseOf(tickCount));
    const int count = static_cast<int>(std::floor(carry));
    carry -= static_cast<float>(count);
    if (count <= 0) {
      return out;
    }
    const bool interpolate = e.flags[kInterpolateEmission];
    const float step = interpolate ? 1.0f / static_cast<float>(count) : 0.0f;
    float cursor = 0.0f;
    out.reserve(static_cast<std::size_t>(count));
    for (int i = 0; i < count; ++i, cursor += step) {
      const float phase = phaseOf(tickCount + cursor);
      EmittedParticle p;
      const float ox = curve(kXPos, phase);
      const float oy = curve(kYPos, phase);
      const float oz = curve(kZPos, phase);
      // A random spot within the emitter's size, across the ground (CEfxEmitter::Tick's scatter).
      const float size = curve(kSize, phase);
      const float r0 = random();
      const float r1 = random();
      float sx = r1 - 0.5f;
      float sz = r0 - 0.5f;
      const float length = std::sqrt(sx * sx + sz * sz);
      if (length > 1e-6f) {
        sx /= length;
        sz /= length;
      }
      const float magnitude = (random() - 0.5f) * size;
      p.pos[0] = ox + magnitude * sx;
      p.pos[1] = oy;
      p.pos[2] = oz + magnitude * sz;
      p.accel[0] = curve(kXAccel, phase);
      p.accel[1] = curve(kYAccel, phase) - (e.flags[kGravity] ? 0.02f : 0.0f);
      p.accel[2] = curve(kZAccel, phase);
      const float vx = curve(kXDirection, phase);
      const float vy = curve(kYDirection, phase);
      const float vz = curve(kZDirection, phase);
      const float velocity = curve(kVelocity, phase);
      p.dir[0] = vx * velocity;
      p.dir[1] = vy * velocity;
      p.dir[2] = vz * velocity;
      p.resistance = curve(kResistance, phase);
      p.birth = cursor;
      p.lifetime = std::max(curve(kLifetime, phase), 0.0f);
      p.beginSize = curve(kStartSize, phase);
      p.endSize = curve(kEndSize, phase);
      p.rampSelection = curve(kRampSelection, phase);
      p.framerate = curve(kFrameRate, phase);
      // floor(selection) * (1 / TextureStripcount), for every particle (CEfxEmitter.cpp 0x0065CE00; a ramp-only tag ignores it).
      p.textureSelection = e.textureStripCount > 0.0f ? std::floor(curve(kTextureSelection, phase)) / e.textureStripCount : 0.0f;
      p.angle = curve(kInitialRotation, phase) * 0.017453292f;
      p.rotationRate = curve(kRotationRate, phase) * 0.017453292f;
      out.push_back(p);
    }
    return out;
  }

  std::string WriteEmitter(const EmitterBlueprint& e)
  {
    // WEmitterWx::WriteBlueprintScript's order and formats.
    std::string out = "EmitterBlueprint {\n";
    Append(out, "\tBlueprintId = '%s',\n", e.blueprintId.c_str());
    Append(out, "\tLifetime = %.2f,\n", static_cast<double>(e.lifetime));
    Append(out, "\tRepeattime = %.2f,\n", static_cast<double>(e.repeatTime));
    Append(out, "\tTextureFramecount = %.2f,\n", static_cast<double>(e.textureFrameCount));
    Append(out, "\tBlendmode = %.2f,\n", static_cast<double>(e.blendMode));
    const auto flag = [&](const int f) { return e.flags[static_cast<std::size_t>(f)] ? "true" : "false"; };
    for (const int f : {kLocalVelocity, kLocalAcceleration, kGravity, kAlignRotation, kAlignToBone, kFlat}) {
      Append(out, "\t%s = %s,\n", kFlags[f], flag(f));
    }
    Append(out, "\tLODCutoff = %.2f,\n", static_cast<double>(e.lodCutoff));
    for (const int f : {kEmitIfVisible, kCatchupEmit, kCreateIfVisible, kSnapToWaterline, kOnlyEmitOnWater, kParticleResistance, kInterpolateEmission}) {
      Append(out, "\t%s = %s,\n", kFlags[f], flag(f));
    }
    Append(out, "\tTextureStripcount = %.2f,\n", static_cast<double>(e.textureStripCount));
    Append(out, "\tSortOrder = %.2f,\n", static_cast<double>(e.sortOrder));
    Append(out, "\tLowFidelity = %s,\n", e.lowFidelity ? "true" : "false");
    Append(out, "\tMedFidelity = %s,\n", e.medFidelity ? "true" : "false");
    Append(out, "\tHighFidelity = %s,\n", e.highFidelity ? "true" : "false");
    Append(out, "\tTexture = [[%s]],\n", e.texture.c_str());
    Append(out, "\tRampTexture = [[%s]],\n", e.rampTexture.c_str());
    for (int c = 0; c < kEmitterCurveCount; ++c) {
      const EmitterCurve& curve = e.curves[static_cast<std::size_t>(c)];
      Append(out, "\t%s = {\n\t\tXRange = %.2f,\n\t\tKeys = {\n", kCurves[c].name, static_cast<double>(curve.xRange));
      for (const EmitterKey& key : curve.keys) {
        Append(out, "\t\t\t{ x=%.3f,y=%.3f,z=%.3f },\n", static_cast<double>(key.x), static_cast<double>(key.y), static_cast<double>(key.z));
      }
      out += "\t\t},\n\t},\n";
    }
    for (const auto& [key, value] : e.extra) {
      out += "\t" + key + " = " + value + ",\n";
    }
    out += "}\n\n";
    return out;
  }
} // namespace faf::editor
