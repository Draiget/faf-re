#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"
#include "moho/math/Vector4f.h"
#include "moho/resource/blueprints/REffectBlueprint.h"

namespace gpg
{
  class RRef;
  class RType;
} // namespace gpg

namespace moho
{
  /**
   * Address: 0x0050FA90 (FUN_0050FA90)
   *
   * What it does:
   * Reflection type init for `RBeamBlueprint` (`sizeof = 0x84`) and fields:
   * `Length` (+0x28), `Lifetime` (+0x2C), `Thickness` (+0x30),
   * `UShift` (+0x34), `VShift` (+0x38), `TextureName` (+0x3C),
   * `StartColor` (+0x58), `EndColor` (+0x68), `LODCutoff` (+0x78),
   * `RepeatRate` (+0x7C), `BlendMode` (+0x80).
   */
  struct RBeamBlueprint : public REffectBlueprint
  {
    /**
     * Address: 0x0050EEF0 (FUN_0050EEF0, ??0RBeamBlueprint@Moho@@QAE@XZ)
     *
     * What it does:
     * Initializes base effect-blueprint ownership lanes and beam defaults:
     * length/lifetime/thickness, texture/color ramps, LOD cutoff, and blend mode.
     */
    RBeamBlueprint();

    float Length{10.0f};                         // +0x28
    float Lifetime{1.0f};                        // +0x2C
    float Thickness{1.0f};                       // +0x30
    float UShift{0.0f};                          // +0x34
    float VShift{0.0f};                          // +0x38
    msvc8::string TextureName;                   // +0x3C
    Vector4f StartColor{1.0f, 1.0f, 1.0f, 0.0f}; // +0x58
    Vector4f EndColor{1.0f, 1.0f, 1.0f, 0.0f};   // +0x68
    float LODCutoff{200.0f};                     // +0x78
    float RepeatRate{0.0f};                      // +0x7C
    std::int32_t BlendMode{3};                   // +0x80
    static gpg::RType* sType;

    /**
     * Address: 0x0050EEB0 (FUN_0050EEB0)
     * Mangled: ?GetClass@RBeamBlueprint@Moho@@UBEPAVRType@gpg@@XZ
     *
     * What it does:
     * Returns cached reflection descriptor for `RBeamBlueprint`.
     */
    [[nodiscard]] gpg::RType* GetClass() const override;

    /**
     * Address: 0x0050EED0 (FUN_0050EED0)
     * Mangled: ?GetDerivedObjectRef@RBeamBlueprint@Moho@@UAE?AVRRef@gpg@@XZ
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x0050EFA0 (FUN_0050EFA0)
     *
     * What it does:
     * Beam cast hook for effect-blueprint unions. Returns `this`.
     */
    [[nodiscard]] RBeamBlueprint* IsBeam() override;
  };

  static_assert(offsetof(RBeamBlueprint, Length) == 0x28, "RBeamBlueprint::Length offset must be 0x28");
  static_assert(offsetof(RBeamBlueprint, Lifetime) == 0x2C, "RBeamBlueprint::Lifetime offset must be 0x2C");
  static_assert(offsetof(RBeamBlueprint, Thickness) == 0x30, "RBeamBlueprint::Thickness offset must be 0x30");
  static_assert(offsetof(RBeamBlueprint, UShift) == 0x34, "RBeamBlueprint::UShift offset must be 0x34");
  static_assert(offsetof(RBeamBlueprint, VShift) == 0x38, "RBeamBlueprint::VShift offset must be 0x38");
  static_assert(offsetof(RBeamBlueprint, TextureName) == 0x3C, "RBeamBlueprint::TextureName offset must be 0x3C");
  static_assert(offsetof(RBeamBlueprint, StartColor) == 0x58, "RBeamBlueprint::StartColor offset must be 0x58");
  static_assert(offsetof(RBeamBlueprint, EndColor) == 0x68, "RBeamBlueprint::EndColor offset must be 0x68");
  static_assert(offsetof(RBeamBlueprint, LODCutoff) == 0x78, "RBeamBlueprint::LODCutoff offset must be 0x78");
  static_assert(offsetof(RBeamBlueprint, RepeatRate) == 0x7C, "RBeamBlueprint::RepeatRate offset must be 0x7C");
  static_assert(offsetof(RBeamBlueprint, BlendMode) == 0x80, "RBeamBlueprint::BlendMode offset must be 0x80");
  static_assert(sizeof(RBeamBlueprint) == 0x84, "RBeamBlueprint size must be 0x84");
} // namespace moho
