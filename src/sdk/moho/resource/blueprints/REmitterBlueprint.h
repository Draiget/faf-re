#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"
#include "moho/resource/blueprints/REffectBlueprint.h"

namespace gpg
{
  class RRef;
  class RType;
} // namespace gpg

namespace moho
{
  /**
   * Address: 0x00515620 (FUN_00515620)
   *
   * What it does:
   * Reflection type init for emitter-curve key samples (`sizeof = 0x10`).
   */
  class REmitterCurveKey : public gpg::RObject
  {
  public:
    float X{0.0f}; // +0x04
    float Y{0.0f}; // +0x08
    float Z{0.0f}; // +0x0C
    static gpg::RType* sType;

    /**
     * Address: 0x00514B30 (FUN_00514B30)
     * Mangled: ?GetClass@REmitterCurveKey@Moho@@UBEPAVRType@gpg@@XZ
     *
     * What it does:
     * Returns cached reflection descriptor for `REmitterCurveKey`.
     */
    [[nodiscard]] gpg::RType* GetClass() const override;

    /**
     * Address: 0x00514B50 (FUN_00514B50)
     * Mangled: ?GetDerivedObjectRef@REmitterCurveKey@Moho@@UAE?AVRRef@gpg@@XZ
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x00514B90 (FUN_00514B90, scalar deleting dtor thunk)
     *
     * What it does:
     * Runtime destructor for curve-key samples.
     */
    ~REmitterCurveKey() override;
  };

  /**
   * Legacy vector-like storage used by `REmitterBlueprintCurve::Keys`.
   *
   * Evidence:
   * - field registration at `REmitterBlueprintCurve + 0x08` uses
   *   `std::vector` RTTI (`FUN_00516F20`).
   * - ctor/dtor chains initialize/free begin/end/capacity at +0x0C/+0x10/+0x14.
   */
  struct REmitterCurveKeyListStorage
  {
    void* mAllocProxy{nullptr};              // +0x00
    REmitterCurveKey* mBegin{nullptr};       // +0x04
    REmitterCurveKey* mEnd{nullptr};         // +0x08
    REmitterCurveKey* mCapacityEnd{nullptr}; // +0x0C

    [[nodiscard]] std::size_t Count() const noexcept;
    [[nodiscard]] bool Empty() const noexcept;
  };

  /**
   * Address: 0x00515460 (FUN_00515460)
   *
   * What it does:
   * Reflection type init for `REmitterBlueprintCurve` (`sizeof = 0x18`) and fields:
   * `XRange` (+0x04), `Keys` (+0x08).
   */
  class REmitterBlueprintCurve : public gpg::RObject
  {
  public:
    float XRange{0.0f};               // +0x04
    REmitterCurveKeyListStorage Keys; // +0x08
    static gpg::RType* sType;

    /**
     * Address: 0x0050E4F0 (FUN_0050E4F0)
     * Mangled: ?GetClass@REmitterBlueprintCurve@Moho@@UBEPAVRType@gpg@@XZ
     *
     * What it does:
     * Returns cached reflection descriptor for `REmitterBlueprintCurve`.
     */
    [[nodiscard]] gpg::RType* GetClass() const override;

    /**
     * Address: 0x0050E510 (FUN_0050E510)
     * Mangled: ?GetDerivedObjectRef@REmitterBlueprintCurve@Moho@@UAE?AVRRef@gpg@@XZ
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x0050E580 (FUN_0050E580, scalar deleting dtor thunk)
     *
     * What it does:
     * Releases key-storage payload for this curve instance.
     */
    ~REmitterBlueprintCurve() override;
  };

  /**
   * Address: 0x0050F4C0 (FUN_0050F4C0)
   *
   * What it does:
   * Reflection type init for `REmitterBlueprint` (`sizeof = 0x284`) with
   * 21 curve blocks (`+0x28..+0x208`), emitter flags (`+0x220..+0x22C`),
   * timing/render scalars (`+0x230..+0x248`), and texture strings
   * (`TextureName` +0x24C, `RampTextureName` +0x268).
   */
  struct REmitterBlueprint : public REffectBlueprint
  {
    REmitterBlueprintCurve SizeCurve;             // +0x28
    REmitterBlueprintCurve XDirectionCurve;       // +0x40
    REmitterBlueprintCurve YDirectionCurve;       // +0x58
    REmitterBlueprintCurve ZDirectionCurve;       // +0x70
    REmitterBlueprintCurve EmitRateCurve;         // +0x88
    REmitterBlueprintCurve LifetimeCurve;         // +0xA0
    REmitterBlueprintCurve VelocityCurve;         // +0xB8
    REmitterBlueprintCurve XAccelCurve;           // +0xD0
    REmitterBlueprintCurve YAccelCurve;           // +0xE8
    REmitterBlueprintCurve ZAccelCurve;           // +0x100
    REmitterBlueprintCurve ResistanceCurve;       // +0x118
    REmitterBlueprintCurve StartSizeCurve;        // +0x130
    REmitterBlueprintCurve EndSizeCurve;          // +0x148
    REmitterBlueprintCurve InitialRotationCurve;  // +0x160
    REmitterBlueprintCurve RotationRateCurve;     // +0x178
    REmitterBlueprintCurve FrameRateCurve;        // +0x190
    REmitterBlueprintCurve TextureSelectionCurve; // +0x1A8
    REmitterBlueprintCurve XPosCurve;             // +0x1C0
    REmitterBlueprintCurve YPosCurve;             // +0x1D8
    REmitterBlueprintCurve ZPosCurve;             // +0x1F0
    REmitterBlueprintCurve RampSelectionCurve;    // +0x208
    std::uint8_t LocalVelocity{1};                // +0x220
    std::uint8_t LocalAcceleration{0};            // +0x221
    std::uint8_t Gravity{0};                      // +0x222
    std::uint8_t AlignRotation{0};                // +0x223
    std::uint8_t AlignToBone{0};                  // +0x224
    std::uint8_t EmitIfVisible{1};                // +0x225
    std::uint8_t CatchupEmit{1};                  // +0x226
    std::uint8_t CreateIfVisible{0};              // +0x227
    std::uint8_t ParticleResistance{0};           // +0x228
    std::uint8_t Flat{0};                         // +0x229
    std::uint8_t InterpolateEmission{1};          // +0x22A
    std::uint8_t SnapToWaterline{1};              // +0x22B
    std::uint8_t OnlyEmitOnWater{0};              // +0x22C
    std::uint8_t pad_022D_0230[0x03]{0, 0, 0};    // +0x22D
    float TextureStripCount{1.0f};                // +0x230
    float SortOrder{0.0f};                        // +0x234
    float LODCutoff{100.0f};                      // +0x238
    float Lifetime{0.0f};                         // +0x23C
    float RepeatTime{0.0f};                       // +0x240
    float TextureFrameCount{0.0f};                // +0x244
    std::int32_t BlendMode{0};                    // +0x248
    msvc8::string TextureName;                    // +0x24C
    msvc8::string RampTextureName;                // +0x268
    static gpg::RType* sType;

    /**
     * Address: 0x0050E710 (FUN_0050E710)
     * Mangled: ?GetClass@REmitterBlueprint@Moho@@UBEPAVRType@gpg@@XZ
     *
     * What it does:
     * Returns cached reflection descriptor for `REmitterBlueprint`.
     */
    [[nodiscard]] gpg::RType* GetClass() const;

    /**
     * Address: 0x0050E730 (FUN_0050E730)
     * Mangled: ?GetDerivedObjectRef@REmitterBlueprint@Moho@@UAE?AVRRef@gpg@@XZ
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef();

    /**
     * Address: 0x0050EAE0 (FUN_0050EAE0)
     *
     * What it does:
     * Emitter cast hook for effect-blueprint unions. Returns `this`.
     */
    [[nodiscard]] REmitterBlueprint* IsEmitter() override;
  };

  static_assert(sizeof(REmitterCurveKey) == 0x10, "REmitterCurveKey size must be 0x10");
  static_assert(sizeof(REmitterCurveKeyListStorage) == 0x10, "REmitterCurveKeyListStorage size must be 0x10");
  static_assert(sizeof(REmitterBlueprintCurve) == 0x18, "REmitterBlueprintCurve size must be 0x18");

  static_assert(offsetof(REmitterCurveKey, X) == 0x04, "REmitterCurveKey::X offset must be 0x04");
  static_assert(offsetof(REmitterCurveKey, Y) == 0x08, "REmitterCurveKey::Y offset must be 0x08");
  static_assert(offsetof(REmitterCurveKey, Z) == 0x0C, "REmitterCurveKey::Z offset must be 0x0C");
  static_assert(
    offsetof(REmitterCurveKeyListStorage, mBegin) == 0x04, "REmitterCurveKeyListStorage::mBegin offset must be 0x04"
  );
  static_assert(
    offsetof(REmitterCurveKeyListStorage, mEnd) == 0x08, "REmitterCurveKeyListStorage::mEnd offset must be 0x08"
  );
  static_assert(
    offsetof(REmitterCurveKeyListStorage, mCapacityEnd) == 0x0C,
    "REmitterCurveKeyListStorage::mCapacityEnd offset must be 0x0C"
  );
  static_assert(offsetof(REmitterBlueprintCurve, XRange) == 0x04, "REmitterBlueprintCurve::XRange offset must be 0x04");
  static_assert(offsetof(REmitterBlueprintCurve, Keys) == 0x08, "REmitterBlueprintCurve::Keys offset must be 0x08");

  static_assert(offsetof(REmitterBlueprint, SizeCurve) == 0x28, "REmitterBlueprint::SizeCurve offset must be 0x28");
  static_assert(
    offsetof(REmitterBlueprint, XDirectionCurve) == 0x40, "REmitterBlueprint::XDirectionCurve offset must be 0x40"
  );
  static_assert(
    offsetof(REmitterBlueprint, YDirectionCurve) == 0x58, "REmitterBlueprint::YDirectionCurve offset must be 0x58"
  );
  static_assert(
    offsetof(REmitterBlueprint, ZDirectionCurve) == 0x70, "REmitterBlueprint::ZDirectionCurve offset must be 0x70"
  );
  static_assert(
    offsetof(REmitterBlueprint, EmitRateCurve) == 0x88, "REmitterBlueprint::EmitRateCurve offset must be 0x88"
  );
  static_assert(
    offsetof(REmitterBlueprint, LifetimeCurve) == 0xA0, "REmitterBlueprint::LifetimeCurve offset must be 0xA0"
  );
  static_assert(
    offsetof(REmitterBlueprint, VelocityCurve) == 0xB8, "REmitterBlueprint::VelocityCurve offset must be 0xB8"
  );
  static_assert(offsetof(REmitterBlueprint, XAccelCurve) == 0xD0, "REmitterBlueprint::XAccelCurve offset must be 0xD0");
  static_assert(offsetof(REmitterBlueprint, YAccelCurve) == 0xE8, "REmitterBlueprint::YAccelCurve offset must be 0xE8");
  static_assert(
    offsetof(REmitterBlueprint, ZAccelCurve) == 0x100, "REmitterBlueprint::ZAccelCurve offset must be 0x100"
  );
  static_assert(
    offsetof(REmitterBlueprint, ResistanceCurve) == 0x118, "REmitterBlueprint::ResistanceCurve offset must be 0x118"
  );
  static_assert(
    offsetof(REmitterBlueprint, StartSizeCurve) == 0x130, "REmitterBlueprint::StartSizeCurve offset must be 0x130"
  );
  static_assert(
    offsetof(REmitterBlueprint, EndSizeCurve) == 0x148, "REmitterBlueprint::EndSizeCurve offset must be 0x148"
  );
  static_assert(
    offsetof(REmitterBlueprint, InitialRotationCurve) == 0x160,
    "REmitterBlueprint::InitialRotationCurve offset must be 0x160"
  );
  static_assert(
    offsetof(REmitterBlueprint, RotationRateCurve) == 0x178, "REmitterBlueprint::RotationRateCurve offset must be 0x178"
  );
  static_assert(
    offsetof(REmitterBlueprint, FrameRateCurve) == 0x190, "REmitterBlueprint::FrameRateCurve offset must be 0x190"
  );
  static_assert(
    offsetof(REmitterBlueprint, TextureSelectionCurve) == 0x1A8,
    "REmitterBlueprint::TextureSelectionCurve offset must be 0x1A8"
  );
  static_assert(offsetof(REmitterBlueprint, XPosCurve) == 0x1C0, "REmitterBlueprint::XPosCurve offset must be 0x1C0");
  static_assert(offsetof(REmitterBlueprint, YPosCurve) == 0x1D8, "REmitterBlueprint::YPosCurve offset must be 0x1D8");
  static_assert(offsetof(REmitterBlueprint, ZPosCurve) == 0x1F0, "REmitterBlueprint::ZPosCurve offset must be 0x1F0");
  static_assert(
    offsetof(REmitterBlueprint, RampSelectionCurve) == 0x208,
    "REmitterBlueprint::RampSelectionCurve offset must be 0x208"
  );
  static_assert(
    offsetof(REmitterBlueprint, LocalVelocity) == 0x220, "REmitterBlueprint::LocalVelocity offset must be 0x220"
  );
  static_assert(
    offsetof(REmitterBlueprint, LocalAcceleration) == 0x221, "REmitterBlueprint::LocalAcceleration offset must be 0x221"
  );
  static_assert(offsetof(REmitterBlueprint, Gravity) == 0x222, "REmitterBlueprint::Gravity offset must be 0x222");
  static_assert(
    offsetof(REmitterBlueprint, AlignRotation) == 0x223, "REmitterBlueprint::AlignRotation offset must be 0x223"
  );
  static_assert(
    offsetof(REmitterBlueprint, AlignToBone) == 0x224, "REmitterBlueprint::AlignToBone offset must be 0x224"
  );
  static_assert(
    offsetof(REmitterBlueprint, EmitIfVisible) == 0x225, "REmitterBlueprint::EmitIfVisible offset must be 0x225"
  );
  static_assert(
    offsetof(REmitterBlueprint, CatchupEmit) == 0x226, "REmitterBlueprint::CatchupEmit offset must be 0x226"
  );
  static_assert(
    offsetof(REmitterBlueprint, CreateIfVisible) == 0x227, "REmitterBlueprint::CreateIfVisible offset must be 0x227"
  );
  static_assert(
    offsetof(REmitterBlueprint, ParticleResistance) == 0x228,
    "REmitterBlueprint::ParticleResistance offset must be 0x228"
  );
  static_assert(offsetof(REmitterBlueprint, Flat) == 0x229, "REmitterBlueprint::Flat offset must be 0x229");
  static_assert(
    offsetof(REmitterBlueprint, InterpolateEmission) == 0x22A,
    "REmitterBlueprint::InterpolateEmission offset must be 0x22A"
  );
  static_assert(
    offsetof(REmitterBlueprint, SnapToWaterline) == 0x22B, "REmitterBlueprint::SnapToWaterline offset must be 0x22B"
  );
  static_assert(
    offsetof(REmitterBlueprint, OnlyEmitOnWater) == 0x22C, "REmitterBlueprint::OnlyEmitOnWater offset must be 0x22C"
  );
  static_assert(
    offsetof(REmitterBlueprint, TextureStripCount) == 0x230, "REmitterBlueprint::TextureStripCount offset must be 0x230"
  );
  static_assert(offsetof(REmitterBlueprint, SortOrder) == 0x234, "REmitterBlueprint::SortOrder offset must be 0x234");
  static_assert(offsetof(REmitterBlueprint, LODCutoff) == 0x238, "REmitterBlueprint::LODCutoff offset must be 0x238");
  static_assert(offsetof(REmitterBlueprint, Lifetime) == 0x23C, "REmitterBlueprint::Lifetime offset must be 0x23C");
  static_assert(offsetof(REmitterBlueprint, RepeatTime) == 0x240, "REmitterBlueprint::RepeatTime offset must be 0x240");
  static_assert(
    offsetof(REmitterBlueprint, TextureFrameCount) == 0x244, "REmitterBlueprint::TextureFrameCount offset must be 0x244"
  );
  static_assert(offsetof(REmitterBlueprint, BlendMode) == 0x248, "REmitterBlueprint::BlendMode offset must be 0x248");
  static_assert(
    offsetof(REmitterBlueprint, TextureName) == 0x24C, "REmitterBlueprint::TextureName offset must be 0x24C"
  );
  static_assert(
    offsetof(REmitterBlueprint, RampTextureName) == 0x268, "REmitterBlueprint::RampTextureName offset must be 0x268"
  );
  static_assert(sizeof(REmitterBlueprint) == 0x284, "REmitterBlueprint size must be 0x284");
} // namespace moho
