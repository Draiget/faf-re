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

namespace gpg
{
  class ReadArchive;
  class RRef;
  class SerConstructResult;
  class SerSaveConstructArgsResult;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  /**
   * Address: 0x0050F230 (FUN_0050F230)
   *
   * What it does:
   * Reflection type init for `RTrailBlueprint` (`sizeof = 0x80`) and fields:
   * `Lifetime` (+0x28), `TrailLength` (+0x2C), `StartSize` (+0x30),
   * `SortOrder` (+0x34), `BlendMode` (+0x38), `LODCutoff` (+0x3C),
   * `EmitIfVisible` (+0x40), `CatchupEmit` (+0x41),
   * `TextureRepeatRate` (+0x44), `RepeatTexture` (+0x48),
   * `RampTexture` (+0x64).
   */
  struct RTrailBlueprint : public REffectBlueprint
  {
    /**
     * What it does:
     * Reads the owning rules and the blueprint id and hands back the rules'
     * own `RTrailBlueprint` (owned by the rules, so the archive may not delete it).
     * Inlined into `SerConstructHelper<RTrailBlueprint>::Construct` 0x005100C0.
     */
    static void MemberConstruct(
      gpg::ReadArchive& archive, int version, const gpg::RRef& ownerRef, gpg::SerConstructResult& result
    );

    /**
     * Address: 0x0050FFE0 (FUN_0050FFE0)
     *
     * What it does:
     * Saves the owning rules (unowned) and the blueprint id for
     * `MemberConstruct` to look the blueprint up by.
     */
    void MemberSaveConstructArgs(
      gpg::WriteArchive& archive, int version, const gpg::RRef& ownerRef, gpg::SerSaveConstructArgsResult& result
    );

    float Lifetime;                   // +0x28
    float TrailLength;                // +0x2C
    float StartSize;                  // +0x30
    float SortOrder;                  // +0x34
    std::int32_t BlendMode;           // +0x38
    float LODCutoff;                  // +0x3C
    std::uint8_t EmitIfVisible;       // +0x40
    std::uint8_t CatchupEmit;         // +0x41
    std::uint8_t pad_0042_0044[0x02]; // +0x42
    float TextureRepeatRate;          // +0x44
    msvc8::string RepeatTexture;      // +0x48
    msvc8::string RampTexture;        // +0x64
    static gpg::RType* sType;

    /**
     * Address: 0x0050ED80 (FUN_0050ED80)
     *
     * What it does:
     * Initializes trail-blueprint defaults and empty texture string storage.
     */
    RTrailBlueprint();

    /**
     * Address: 0x0050EE20 (FUN_0050EE20, Moho::RTrailBlueprint::dtr core)
     *
     * What it does:
     * Releases trail texture string storage and resets base resource-id storage.
     */
    ~RTrailBlueprint() override;

    /**
     * Address: 0x0050ED40 (FUN_0050ED40)
     * Mangled: ?GetClass@RTrailBlueprint@Moho@@UBEPAVRType@gpg@@XZ
     *
     * What it does:
     * Returns cached reflection descriptor for `RTrailBlueprint`.
     */
    [[nodiscard]] gpg::RType* GetClass() const override;

    /**
     * Address: 0x0050ED60 (FUN_0050ED60)
     * Mangled: ?GetDerivedObjectRef@RTrailBlueprint@Moho@@UAE?AVRRef@gpg@@XZ
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x0050EDF0 (FUN_0050EDF0)
     *
     * What it does:
     * Trail cast hook for effect-blueprint unions. Returns `this`.
     */
    [[nodiscard]] RTrailBlueprint* IsTrail() override;
  };

  static_assert(offsetof(RTrailBlueprint, Lifetime) == 0x28, "RTrailBlueprint::Lifetime offset must be 0x28");
  static_assert(offsetof(RTrailBlueprint, TrailLength) == 0x2C, "RTrailBlueprint::TrailLength offset must be 0x2C");
  static_assert(offsetof(RTrailBlueprint, StartSize) == 0x30, "RTrailBlueprint::StartSize offset must be 0x30");
  static_assert(offsetof(RTrailBlueprint, SortOrder) == 0x34, "RTrailBlueprint::SortOrder offset must be 0x34");
  static_assert(offsetof(RTrailBlueprint, BlendMode) == 0x38, "RTrailBlueprint::BlendMode offset must be 0x38");
  static_assert(offsetof(RTrailBlueprint, LODCutoff) == 0x3C, "RTrailBlueprint::LODCutoff offset must be 0x3C");
  static_assert(offsetof(RTrailBlueprint, EmitIfVisible) == 0x40, "RTrailBlueprint::EmitIfVisible offset must be 0x40");
  static_assert(offsetof(RTrailBlueprint, CatchupEmit) == 0x41, "RTrailBlueprint::CatchupEmit offset must be 0x41");
  static_assert(
    offsetof(RTrailBlueprint, TextureRepeatRate) == 0x44, "RTrailBlueprint::TextureRepeatRate offset must be 0x44"
  );
  static_assert(offsetof(RTrailBlueprint, RepeatTexture) == 0x48, "RTrailBlueprint::RepeatTexture offset must be 0x48");
  static_assert(offsetof(RTrailBlueprint, RampTexture) == 0x64, "RTrailBlueprint::RampTexture offset must be 0x64");
  static_assert(sizeof(RTrailBlueprint) == 0x80, "RTrailBlueprint size must be 0x80");
} // namespace moho
