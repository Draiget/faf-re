#pragma once

#include <cstdint>

#include "Wm3Quaternion.h"
#include "Wm3Vector3.h"

namespace gpg
{
  class RType;
  class ReadArchive;
  class WriteArchive;
}

namespace moho
{
  enum class EUnitCommandType : std::int32_t;
  struct SCoordsVec2;
  struct SOCellPos;
  struct SOffsetInfo;
  class Unit;

  /**
   * Minimal formation-instance interface view used by transport/runtime callers.
   *
   * Address ownership:
   * - `CAiFormationInstance` slot-0 implementation: 0x0059BD60 (`FUN_0059BD60`)
   *
   * What it does:
   * Invokes instance destructor and optionally frees storage when bit0 of
   * `deleteFlags` is set.
   */
  class IFormationInstance
  {
  public:
    inline static gpg::RType* sType = nullptr;
    inline static gpg::RType* sPointerType = nullptr;

    /**
     * Address: 0x00569450 (FUN_00569450, Moho::IFormationInstance::IFormationInstance)
     *
     * What it does:
     * Initializes the base runtime lane and self-links the embedded
     * formation-status broadcaster node.
     */
    IFormationInstance();

    /**
     * Address: 0x00565C70 (FUN_00565C70, Moho::IFormationInstance::~IFormationInstance)
     *
     * What it does:
     * Unlinks the embedded formation-status broadcaster lane from its
     * intrusive listener list.
     */
    ~IFormationInstance();

    /**
     * Address: 0x0059D010 (FUN_0059D010, Moho::IFormationInstance::GetPointerType)
     *
     * What it does:
     * Lazily resolves and caches the reflection descriptor for
     * `IFormationInstance*`.
     */
    [[nodiscard]] static gpg::RType* GetPointerType();

    /**
     * Address: 0x00570D80 (FUN_00570D80, Moho::IFormationInstance::MemberDeserialize)
     *
     * What it does:
     * Loads reflected formation-status broadcaster payload for this instance.
     */
    static void MemberDeserialize(IFormationInstance* object, gpg::ReadArchive* archive);

    /**
     * Address: 0x00570DD0 (FUN_00570DD0, Moho::IFormationInstance::MemberSerialize)
     *
     * What it does:
     * Saves reflected formation-status broadcaster payload for this instance.
     */
    static void MemberSerialize(const IFormationInstance* object, gpg::WriteArchive* archive);

    virtual void operator_delete(std::int32_t deleteFlags) = 0;

    /**
     * Slots 1-24 of `??_7IFormationInstance@Moho@@6B@` (0x00E18D74) are all
     * `_purecall`; only the deleting destructor at slot 0 (0x00565CA0) has a
     * body. `CFormationInstance` (0x00E18E0C) fills every one of them and adds
     * slot 25 (`FindSlotFor`); `CAiFormationInstance` (0x00E1B47C) overrides
     * six and adds slot 26 (`Func27`). The order below is the binary slot
     * order and must not change.
     */
    virtual SCoordsVec2* Func2(SCoordsVec2* outCenter) const = 0;                                        // slot 1
    virtual void Func3(const SCoordsVec2& center) = 0;                                                    // slot 2
    virtual int UnitCount() const = 0;                                                                    // slot 3
    virtual std::int32_t GetLayer(Unit* unit) const = 0;                                                  // slot 4
    virtual SOffsetInfo* Func6(Unit* unit) = 0;                                                           // slot 5
    virtual SCoordsVec2* GetFormationPosition(SCoordsVec2* dest, Unit* unit, SOffsetInfo* laneEntry) = 0; // slot 6
    virtual SOCellPos* GetAdjustedFormationPosition(SOCellPos* dest, Unit* unit, SOffsetInfo* laneEntry) = 0; // slot 7
    virtual SCoordsVec2* Func9(SCoordsVec2* dest, Unit* unit, SOffsetInfo* laneEntry) = 0;               // slot 8
    virtual Wm3::Vec3f* Func10(Wm3::Vec3f* out, Unit* unit, SOffsetInfo* laneEntry) = 0;                 // slot 9
    virtual float Func11(Unit* unit, SOffsetInfo* laneEntry) = 0;                                         // slot 10
    virtual std::int32_t Func12(Unit* unit, SOffsetInfo* laneEntry) = 0;                                  // slot 11
    virtual float CalcFormationSpeed(Unit* unit, float* speedScaleOut, SOffsetInfo* laneEntry) = 0;       // slot 12
    virtual Unit* Func14(Unit* unit, SOffsetInfo* laneEntry) = 0;                                         // slot 13
    virtual void AddUnit(Unit* unit) = 0;                                                                 // slot 14
    virtual void RemoveUnit(Unit* unit) = 0;                                                              // slot 15
    virtual bool Func17(Unit* unit, bool checkAll) const = 0;                                             // slot 16
    virtual void Update() = 0;                                                                            // slot 17
    virtual Wm3::Vec3f* Func19(Wm3::Vec3f* out, Unit* unit) const = 0;                                    // slot 18
    virtual bool CommandIsForm() const = 0;                                                               // slot 19
    virtual bool Func21(Unit* unit) const = 0;                                                            // slot 20
    virtual void Func22(float scale) = 0;                                                                 // slot 21
    virtual void SetOrientation(const Wm3::Quatf& orientation) = 0;                                       // slot 22
    virtual Wm3::Quatf* GetOrientation(Wm3::Quatf* outOrientation) const = 0;                             // slot 23
    virtual EUnitCommandType GetCommandType() const = 0;                                                  // slot 24
  };

  static_assert(sizeof(IFormationInstance) == 0x04, "IFormationInstance size must be 0x04");
} // namespace moho
