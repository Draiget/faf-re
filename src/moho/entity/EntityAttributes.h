#pragma once

#include <cstddef>
#include <cstdint>

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
  class RType;
} // namespace gpg

namespace moho
{
  struct RUnitBlueprint;

  /**
   * The world layers an entity can occupy. A bitmask: `SFootprint` and the
   * occupancy grid test several at once, while `Entity::mVarDat.mLayerMask`
   * holds exactly one.
   */
  enum ELayer : std::int32_t
  {
    LAYER_None = 0,
    LAYER_Land = 1,
    LAYER_Seabed = 2,
    LAYER_Sub = 4,
    LAYER_Water = 8,
    LAYER_Air = 16,
    LAYER_Orbit = 32,
  };

  enum EEntityAttribute : std::int32_t
  {
    ENTATTR_Vision = 0,
    ENTATTR_WaterVision = 1,
    ENTATTR_Radar = 2,
    ENTATTR_Sonar = 3,
    ENTATTR_Omni = 4,
    ENTATTR_RadarStealthField = 5,
    ENTATTR_SonarStealthField = 6,
    ENTATTR_CloakField = 7,
    ENTATTR_Jammer = 8,
    ENTATTR_Spoof = 9,
    ENTATTR_Cloak = 10,
    ENTATTR_RadarStealth = 11,
    ENTATTR_SonarStealth = 12,
  };

  static_assert(sizeof(EEntityAttribute) == 0x04, "EEntityAttribute size must be 0x04");

  /**
   * The eight intel lanes an entity publishes to the recon grid. Each word is a
   * radius in the low 31 bits and an enable flag in the sign bit, which is what
   * `GetRange` / `IsEnabled` split apart.
   */
  struct SSTIIntelAttributes
  {
    std::uint32_t vision;
    std::uint32_t waterVision;
    std::uint32_t radar;
    std::uint32_t sonar;
    std::uint32_t omni;
    std::uint32_t radarStealth;
    std::uint32_t sonarStealth;
    std::uint32_t cloak;
  };

  static_assert(sizeof(SSTIIntelAttributes) == 0x20, "SSTIIntelAttributes size must be 0x20");

  /**
   * Reflected payload wrapper for the engine's entity-intel attribute lanes.
   *
   * The binary exposes this shape through RTTI as `Moho::EntityAttributes`
   * while the project currently stores the fields in `SSTIIntelAttributes`.
   * The wrapper keeps the recovered behavior typed without reintroducing any
   * raw offset access.
   */
  struct EntityAttributes : SSTIIntelAttributes
  {
    inline static gpg::RType* sType = nullptr;

    /**
     * Address: 0x005BD530 (FUN_005BD530, Moho::EntityAttributes::GetRange)
     *
     * What it does:
     * Returns the masked intel range magnitude for a stored attribute lane,
     * or zero for the field/jammer/spoof lanes that do not carry a range.
     */
    [[nodiscard]] std::uint32_t GetRange(EEntityAttribute attribute) const noexcept;

    /**
     * Address: 0x005BD470 (FUN_005BD470, Moho::EntityAttributes::SetIntelRadius)
     *
     * What it does:
     * Stores a new intel radius magnitude in the selected lane while preserving
     * the lane's sign bit. The field/jammer/spoof lanes are ignored.
     */
    void SetIntelRadius(EEntityAttribute attribute, int radius) noexcept;

    /**
     * Address: 0x008B8330 (FUN_008B8330, Moho::EntityAttributes::IsEnabled)
     *
     * What it does:
     * Returns the sign-bit enable flag for intel-bearing attributes; field and
     * jammer/spoof lanes always report disabled.
     */
    [[nodiscard]] bool IsEnabled(EEntityAttribute attribute) const noexcept;

    /**
     * Address: 0x00689DC0 (FUN_00689DC0, Moho::EntityAttributes::SetEnabled)
     *
     * What it does:
     * Writes the sign-bit enable flag for one intel-bearing lane while
     * preserving the stored radius payload.
     */
    void SetEnabled(EEntityAttribute attribute, bool enabled) noexcept;

    /**
     * Address: 0x00559350 (FUN_00559350, Moho::EntityAttributes::MemberDeserialize)
     *
     * What it does:
     * Loads all eight intel payload lanes from archive storage in field order.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x005593D0 (FUN_005593D0, Moho::EntityAttributes::MemberSerialize)
     *
     * What it does:
     * Stores all eight intel payload lanes to archive storage in field order.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x006A46A0 (FUN_006A46A0, Moho::EntityAttributes::Initialize)
     *
     * What it does:
     * Seeds intel lanes from unit-blueprint intel radii, setting the enable
     * sign bit for non-zero ranges.
     */
    void Initialize(const RUnitBlueprint* blueprint);
  };

  static_assert(sizeof(EntityAttributes) == sizeof(SSTIIntelAttributes), "EntityAttributes size must match payload");
} // namespace moho
