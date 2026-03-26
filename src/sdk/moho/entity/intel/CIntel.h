#pragma once

#include <cstddef>
#include <cstdint>

#include "wm3/Vector3.h"

namespace gpg
{
  class RRef;
  class RType;
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class CAiReconDBImpl;
  class CIntelCounterHandle;
  class CIntelGrid;
  class CIntelPosHandle;
  struct RUnitBlueprintIntel;
  class Sim;

  struct CIntelToggleState
  {
    std::uint8_t present; // +0x00
    std::uint8_t enabled; // +0x01
  };

  static_assert(sizeof(CIntelToggleState) == 0x02, "CIntelToggleState size must be 0x02");
  static_assert(offsetof(CIntelToggleState, present) == 0x00, "CIntelToggleState::present offset must be 0x00");
  static_assert(offsetof(CIntelToggleState, enabled) == 0x01, "CIntelToggleState::enabled offset must be 0x01");

  /**
   * Runtime intel manager owned by Entity at +0x1D8.
   *
   * Layout evidence:
   * - CIntelTypeInfo::Init (0x0076E5B0) sets sizeof(CIntel)=0x30.
   * - CIntel::WriteArchive (0x0076EAE0) serializes 9 handle pointers then
   *   5 toggle-state pairs (present/enabled).
   */
  class CIntel
  {
  public:
    static constexpr std::size_t kHandleCount = 9u;

    [[nodiscard]] static gpg::RType* StaticGetClass();
    static gpg::RType* sType;

    /**
     * Address: 0x0076DED0 (FUN_0076DED0, Moho::CIntel::CIntel)
     *
     * What it does:
     * Initializes all intel handle slots to null and clears all
     * `{present,enabled}` toggle-state pairs.
     */
    CIntel();

    /**
     * Address: 0x0076DAE0 (FUN_0076DAE0, Moho::CIntel::CIntel)
     *
     * What it does:
     * Initializes intel handles and toggle presence flags from
     * `RUnitBlueprintIntel` radii/booleans and owning recon/sim pointers.
     */
    CIntel(const RUnitBlueprintIntel* blueprintIntel, Sim* sim, CAiReconDBImpl* reconDB);

    /**
     * Address: 0x0076E490 (FUN_0076E490, Moho::CIntel::ForceUpdate)
     *
     * Wm3::Vector3f *,int
     *
     * What it does:
     * Forces position refresh pass across all active intel handles.
     */
    void ForceUpdate(const Wm3::Vec3f& position, std::int32_t tick);

    /**
     * Address: 0x0076E4C0 (FUN_0076E4C0, Moho::CIntel::Update)
     *
     * Wm3::Vector3f *,int
     *
     * What it does:
     * Updates armed intel handles against new position and updates
     * per-handle tick stamps.
     */
    void Update(const Wm3::Vec3f& position, std::int32_t tick);

    /**
     * Address: 0x0076EA60 (FUN_0076EA60)
     *
     * What it does:
     * Reads all 9 intel-handle pointers and 5 toggle-state pairs from archive,
     * replacing any existing handle instances.
     */
    void ReadArchive(gpg::ReadArchive& archive, const gpg::RRef& ownerRef);

    /**
     * Address: 0x0076EAE0 (FUN_0076EAE0, Moho::CIntel::WriteArchive)
     *
     * What it does:
     * Writes all 9 intel-handle pointers as owned tracked pointers and then
     * serializes 5 toggle-state `{present,enabled}` pairs.
     */
    void WriteArchive(gpg::WriteArchive& archive, const gpg::RRef& ownerRef) const;

    /**
     * Address: 0x0076E9E0 (FUN_0076E9E0, thunk to 0x0076EA60)
     *
     * What it does:
     * Reflection serializer load callback wrapper for `ReadArchive`.
     */
    static void SerializeLoad(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0076E6C0 (FUN_0076E6C0, Moho::CIntelSerializer::Serialize)
     *
     * What it does:
     * Reflection serializer save callback wrapper for `WriteArchive`.
     */
    static void SerializeSave(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0076E010 (FUN_0076E010, Moho::CIntel::InitIntel)
     *
     * What it does:
     * Initializes or replaces one intel lane (vision/radar/sonar/omni/counter
     * fields/toggle lanes) against recon grids.
     */
    void InitIntel(std::int32_t intelType, std::uint32_t radius, CAiReconDBImpl* reconDB, Sim* sim);

    [[nodiscard]] bool HasActiveJamming() const noexcept;

  private:
    /**
     * Address: 0x0076D800 (FUN_0076D800, Moho::CIntel::BoolFieldInit)
     *
     * What it does:
     * Clears one `{present,enabled}` toggle pair.
     */
    static void BoolFieldInit(CIntelToggleState* toggleState);

  public:
    union
    {
      struct
      {
        CIntelPosHandle* mVisionGrid;   // +0x00
        CIntelPosHandle* mWaterGrid;    // +0x04
        CIntelPosHandle* mRadarGrid;    // +0x08
        CIntelPosHandle* mSonarGrid;    // +0x0C
        CIntelPosHandle* mOmniGrid;     // +0x10
        CIntelCounterHandle* mRCIGrid;  // +0x14
        CIntelCounterHandle* mSCIGrid;  // +0x18
        CIntelCounterHandle* mVCIGrid;  // +0x1C
        CIntelPosHandle* mReservedGrid; // +0x20 (unresolved handle slot in 9-entry handle array)
      };
      CIntelPosHandle* mIntelHandles[kHandleCount]; // +0x00
    };

    CIntelToggleState mJamming;      // +0x24
    CIntelToggleState mCloak;        // +0x26
    CIntelToggleState mSpoof;        // +0x28
    CIntelToggleState mSonarStealth; // +0x2A
    CIntelToggleState mRadarStealth; // +0x2C
  };

  static_assert(offsetof(CIntel, mVisionGrid) == 0x00, "CIntel::mVisionGrid offset must be 0x00");
  static_assert(offsetof(CIntel, mReservedGrid) == 0x20, "CIntel::mReservedGrid offset must be 0x20");
  static_assert(offsetof(CIntel, mJamming) == 0x24, "CIntel::mJamming offset must be 0x24");
  static_assert(offsetof(CIntel, mCloak) == 0x26, "CIntel::mCloak offset must be 0x26");
  static_assert(offsetof(CIntel, mSpoof) == 0x28, "CIntel::mSpoof offset must be 0x28");
  static_assert(offsetof(CIntel, mSonarStealth) == 0x2A, "CIntel::mSonarStealth offset must be 0x2A");
  static_assert(offsetof(CIntel, mRadarStealth) == 0x2C, "CIntel::mRadarStealth offset must be 0x2C");
  static_assert(sizeof(CIntel) == 0x30, "CIntel size must be 0x30");
} // namespace moho
