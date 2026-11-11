#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

namespace faf::editor
{
  // An emitter blueprint file (`EmitterBlueprint { ... }`, the game's effects/emitters/*.bp) as the particle editor
  // edits it: its settings, textures and 21 curves, read from the Lua text and written back in the order and number
  // format of retail's own emitter editor (WEmitterWx::WriteBlueprintScript and WCurveEditor::WriteCurveScript),
  // so a file it wrote reads back byte for byte. Keys it doesn't know are kept and written back as they were.

  /** A curve key: x the time (0 to the curve's XRange), y the value, z a random spread around it. */
  struct EmitterKey
  {
    float x = 0.0f;
    float y = 0.0f;
    float z = 0.0f;
  };

  struct EmitterCurve
  {
    float xRange = 1.0f;
    std::vector<EmitterKey> keys;
  };

  /** The curves, in the file's order (REmitterBlueprint's EMITTER_*_CURVE order differs; see EmitterCurveInfo). */
  enum EmitterCurveId : int
  {
    kXDirection,
    kYDirection,
    kZDirection,
    kEmitRate,
    kLifetime,
    kVelocity,
    kXAccel,
    kYAccel,
    kZAccel,
    kResistance,
    kSize,
    kXPos,
    kYPos,
    kZPos,
    kStartSize,
    kEndSize,
    kInitialRotation,
    kRotationRate,
    kFrameRate,
    kTextureSelection,
    kRampSelection,
    kEmitterCurveCount,
  };

  /** What retail's emitter editor shows for a curve (its kEmitterCurveEditors table). */
  struct EmitterCurveInfo
  {
    const char* name;    // the file's key
    const char* group;   // the editor's tab the curve opens ("" continues the one above)
    const char* caption;
    float viewMin;
    float viewMax;
    float initialValue;
    float initialSpread;
  };
  const EmitterCurveInfo& CurveInfo(int curve);

  /** The on/off settings, in the file's order. */
  enum EmitterFlagId : int
  {
    kLocalVelocity,
    kLocalAcceleration,
    kGravity,
    kAlignRotation,
    kAlignToBone,
    kFlat,
    kEmitIfVisible,
    kCatchupEmit,
    kCreateIfVisible,
    kSnapToWaterline,
    kOnlyEmitOnWater,
    kParticleResistance,
    kInterpolateEmission,
    kEmitterFlagCount,
  };
  const char* FlagName(int flag);

  /** The blend modes by Blendmode value (BeamRenderHelpers.cpp: the technique's suffix). */
  inline constexpr const char* kEmitterBlendModes[6] = {"Alpha blend", "Modulate inverse", "Modulate 2x inverse", "Add", "Premultiplied alpha", "Refract"};

  struct EmitterBlueprint
  {
    std::string blueprintId;
    float lifetime = 10.0f;
    float repeatTime = 10.0f;
    float textureFrameCount = 1.0f;
    float blendMode = 0.0f;
    float lodCutoff = 100.0f;
    float textureStripCount = 1.0f;
    float sortOrder = 0.0f;
    std::array<bool, kEmitterFlagCount> flags{};
    bool lowFidelity = true;
    bool medFidelity = true;
    bool highFidelity = true;
    std::string texture;
    std::string rampTexture;
    std::array<EmitterCurve, kEmitterCurveCount> curves{};
    /** Keys this model doesn't know, with their value's text as the file had it. */
    std::vector<std::pair<std::string, std::string>> extra;
  };

  /** A new emitter as retail's editor starts one: every curve one key at its initial value, a white puff. */
  EmitterBlueprint NewEmitter();

  // ---- What the game makes of it (the particle editor's preview) ----

  /**
   * The curve at `t` as SEfxCurve::GetValue (0x00514E50) samples it: the keys sorted by x, y and z interpolated between
   * the keys around `t` (clamped to the first and last), then (random - 0.5) * z + y. No keys: 0.
   */
  float EmitterCurveValue(const EmitterCurve& curve, float t, float random);

  /** One particle as CEfxEmitter::Tick builds it, for an emitter at the origin, unattached, at scale 1. */
  struct EmittedParticle
  {
    float pos[3] = {};
    float dir[3] = {};   // game units a tick
    float accel[3] = {}; // game units a tick, squared
    float resistance = 0.0f;
    float birth = 0.0f; // in ticks after the tick's start (the emission cursor)
    float lifetime = 0.0f;
    float beginSize = 0.0f;
    float endSize = 0.0f;
    float rampSelection = 0.0f;
    float framerate = 0.0f;
    float textureSelection = 0.0f;
    float angle = 0.0f;        // radians
    float rotationRate = 0.0f; // radians a tick
  };

  /**
   * The particles the emitter makes in one tick, `tickCount` ticks after it started (CEfxEmitter::Tick 0x0065CE00 with
   * TICKCOUNT = tickCount): the emit rate at the tick's phase in the repeat time adds to `carry`, its whole part is
   * emitted (spread over the tick with InterpolateEmission), each particle's curves sampled at its own phase. `random`
   * returns 0-1. SnapToWaterline, OnlyEmitOnWater and the bone and local-space switches need a unit or the map: left out.
   */
  std::vector<EmittedParticle> EmitTick(const EmitterBlueprint& emitter, float tickCount, float& carry, const std::function<float()>& random);
  /** The particle technique's type tag (CEfxEmitter::UpdateCurve): TRamp, TRampFlat, TRampAlign, TRampAnimate... */
  std::string EmitterTypeTag(const EmitterBlueprint& emitter);
  /** The emitter's whole life is over at `tickCount` (a negative Lifetime: it never ends). */
  bool EmitterFinished(const EmitterBlueprint& emitter, float tickCount);

  /** Reads the file's text; false with `error` (and the line) when it isn't an emitter blueprint. */
  bool ParseEmitter(const std::string& text, EmitterBlueprint& out, std::string& error);
  /** The file's text, as retail's editor writes it. */
  std::string WriteEmitter(const EmitterBlueprint& emitter);

  // ---- Beams and trails: short flat tables, written by hand in the game's data ----

  /** One value of a beam's or trail's blueprint. */
  struct FlatValue
  {
    enum class Kind : std::uint8_t
    {
      Number,
      Bool,
      Text,
      Color, // {x=r, y=g, z=b, w=a}
      Raw,   // anything else, kept as the file had it
    } kind = Kind::Number;
    float number = 0.0f;
    bool flag = false;
    std::string text;
    std::array<float, 4> color{};
  };

  /** A BeamBlueprint or TrailEmitterBlueprint: its keys in the file's order (only those it has: a missing key keeps the engine's default). */
  struct FlatBlueprint
  {
    std::string kind; // "BeamBlueprint" or "TrailEmitterBlueprint"
    std::vector<std::pair<std::string, FlatValue>> fields;

    [[nodiscard]] const FlatValue* Find(const std::string& key) const;
    /** Sets the key's value, adding it at the end when the file didn't have it. */
    void Set(const std::string& key, const FlatValue& value);
    [[nodiscard]] float Number(const std::string& key, float fallback) const;
    [[nodiscard]] std::string Text(const std::string& key) const;
    [[nodiscard]] std::array<float, 4> Color(const std::string& key, const std::array<float, 4>& fallback) const;
  };

  /** What the editor shows for one key: its kind, the engine's default (RBeamBlueprint / RTrailBlueprint), and help. */
  struct FlatField
  {
    const char* key;
    FlatValue::Kind kind;
    float initial;
    std::array<float, 4> initialColor;
    const char* help;
    bool texture;
  };
  const std::vector<FlatField>& FlatFields(const std::string& kind);

  /** Reads a beam or trail file; false with `error` for anything else. */
  bool ParseFlatBlueprint(const std::string& text, FlatBlueprint& out, std::string& error);
  /** The file's text: `Kind {`, a key a line (four spaces, as the game's own), `}`. */
  std::string WriteFlatBlueprint(const FlatBlueprint& blueprint);
} // namespace faf::editor
