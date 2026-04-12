#pragma once

#include <cstddef>
#include <cstdint>

#include "Entity.h"
#include "moho/lua/CScrLuaObjectFactory.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
  class RType;
} // namespace gpg

namespace moho
{
  struct RPropBlueprint;
  class Sim;
  class VTransform;

  struct SPropPriorityInfo
  {
    std::int32_t mPriority;    // +0x00
    std::int32_t mBoundedTick; // +0x04

    static gpg::RType* sType;
  };

  static_assert(sizeof(SPropPriorityInfo) == 0x08, "SPropPriorityInfo size must be 0x08");
  static_assert(offsetof(SPropPriorityInfo, mPriority) == 0x00, "SPropPriorityInfo::mPriority offset must be 0x00");
  static_assert(
    offsetof(SPropPriorityInfo, mBoundedTick) == 0x04, "SPropPriorityInfo::mBoundedTick offset must be 0x04"
  );

  /**
   * Address: 0x006F9D90 (FUN_006F9D90)
   *
   * What it does:
   * Prop concrete entity type (size 0x288) initialized by Prop constructor.
   * This layout currently captures fields touched by constructor/materialize paths.
   *
   * Additional recovered virtual bodies in retail binary:
   * - Slot 12 (`Entity::Sync` override): 0x006FA2A0
   *   Updates interface state and unlinks coord-list node when transform is unchanged.
   * - Slot 29 (`Entity::Materialize` override): 0x006FA180
   *   Applies reclaim delta, clamps reclaim-progress, and fires reclaim callbacks.
   * - Slot 31 override helper: 0x006FA150
   *   Marks reclaim terminal flag and dispatches kill/reclaim path.
   *
   * Notes:
   * - Parent/attach ownership is inherited from `Entity::mAttachInfo`
   *   (`SEntAttachInfo` + `WeakPtr<Entity>` intrusive owner chain).
   */
  class Prop : public Entity
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x006F9CD0 (FUN_006F9CD0)
     *
     * What it does:
     * Serialization constructor lane used by Prop construct callback paths.
     */
    explicit Prop(Sim* sim);

    /**
     * Address: 0x006F9D90 (FUN_006F9D90)
     *
     * What it does:
     * Constructs Prop from resolved blueprint/transform and performs initial
     * layer/mesh/reclaim setup.
     */
    Prop(Sim* sim, const RPropBlueprint* blueprint, const VTransform& transform);

    /**
     * Address: 0x006F9D70 (FUN_006F9D70)
     */
    ~Prop() override = default;

    /**
     * Address: 0x006FB3B0 (FUN_006FB3B0)
     *
     * IDA signature:
     * Moho::Prop * __cdecl Moho::PROP_Create(Moho::Sim *, Moho::VTransform const &, Moho::RPropBlueprint const *);
     *
     * What it does:
     * Allocates Prop and dispatches to Prop ctor path.
     */
    static Prop* CreateFromBlueprintResolved(Sim* sim, const RPropBlueprint* blueprint, const VTransform&);

    /**
     * Address: 0x006F9A30 (FUN_006F9A30, Moho::Prop::GetClass)
     *
     * What it does:
     * Returns cached reflection descriptor for Prop.
     */
    [[nodiscard]]
    gpg::RType* GetClass() const override;

    /**
     * Address: 0x006F9A50 (FUN_006F9A50, Moho::Prop::GetDerivedObjectRef)
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflected object reference.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x006F9A70 (FUN_006F9A70)
     */
    Prop* IsProp() override;

    /**
     * Address: 0x006FA2A0 (FUN_006FA2A0)
     */
    void Sync(SSyncData*) override;

    /**
     * Address: 0x006F9A80 (FUN_006F9A80)
     */
    float GetUniformScale() const override;

    /**
     * Address: 0x006F9A90 (FUN_006F9A90)
     */
    bool IsMobile() const override;

    /**
     * Address: 0x006FA180 (FUN_006FA180)
     */
    float Materialize(float) override;

    /**
     * Address: 0x006FA150 (FUN_006FA150)
     */
    void Kill(Entity*, gpg::StrArg, float) override;

    /**
     * Address: 0x006FB0F0 (FUN_006FB0F0, Moho::Prop::MemberDeserialize)
     *
     * What it does:
     * Loads Prop reclaim/priority state after deserializing Entity base lanes.
     */
    void MemberDeserialize(gpg::ReadArchive* archive, int version);

    /**
     * Address: 0x006FB1D0 (FUN_006FB1D0, Moho::Prop::MemberSerialize)
     *
     * What it does:
     * Saves Prop reclaim/priority state after serializing Entity base lanes.
     */
    void MemberSerialize(gpg::WriteArchive* archive, int version) const;

  public:
    float mReclaimMass;               // +0x270
    float mReclaimEnergy;             // +0x274
    bool mTracksReclaimArea;          // +0x278 (set when reclaim mass/energy > 0)
    bool mReclaimTerminated;          // +0x279 (set by 0x006FA150 / 0x006FA180 terminal path)
    std::uint8_t pad_027A[0x02];      // +0x27A
    SPropPriorityInfo mPriorityInfo;  // +0x27C
    std::int32_t mHandleIndex;        // +0x284
  };

  static_assert(offsetof(Prop, mReclaimMass) == 0x270, "Prop::mReclaimMass offset must be 0x270");
  static_assert(offsetof(Prop, mReclaimEnergy) == 0x274, "Prop::mReclaimEnergy offset must be 0x274");
  static_assert(offsetof(Prop, mTracksReclaimArea) == 0x278, "Prop::mTracksReclaimArea offset must be 0x278");
  static_assert(offsetof(Prop, mPriorityInfo) == 0x27C, "Prop::mPriorityInfo offset must be 0x27C");
  static_assert(offsetof(Prop, mHandleIndex) == 0x284, "Prop::mHandleIndex offset must be 0x284");
  static_assert(sizeof(Prop) == 0x288, "Prop size must be 0x288");

  template <>
  class CScrLuaMetatableFactory<Prop> final : public CScrLuaObjectFactory
  {
  public:
    [[nodiscard]]
    static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x00680010 (FUN_00680010, Moho::CScrLuaMetatableFactory<Moho::Prop>::Create)
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(sizeof(CScrLuaMetatableFactory<Prop>) == 0x08, "CScrLuaMetatableFactory<Prop> size must be 0x08");

  /**
   * Address: 0x00BD50F0 (FUN_00BD50F0, register_CScrLuaMetatableFactory_Prop_Index)
   *
   * What it does:
   * Assigns startup factory-object index for `CScrLuaMetatableFactory<Prop>::sInstance`.
   */
  int register_CScrLuaMetatableFactory_Prop_Index();
} // namespace moho
