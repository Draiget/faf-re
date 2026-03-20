#pragma once

#include <cstddef>
#include <cstdint>

#include "Entity.h"

namespace moho
{
  class RPropBlueprint;
  class Sim;
  class VTransform;

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

  public:
    float mReclaimMass;              // +0x270
    float mReclaimEnergy;            // +0x274
    std::uint8_t mTracksReclaimArea; // +0x278 (set when reclaim mass/energy > 0)
    std::uint8_t mReclaimTerminated; // +0x279 (set by 0x006FA150 / 0x006FA180 terminal path)
    std::uint8_t pad_027A[0x02];     // +0x27A
    std::int32_t mPriority;          // +0x27C
    std::int32_t mHandleIndex;       // +0x280
    std::int32_t mHandleLink;        // +0x284
  };

  static_assert(offsetof(Prop, mReclaimMass) == 0x270, "Prop::mReclaimMass offset must be 0x270");
  static_assert(offsetof(Prop, mReclaimEnergy) == 0x274, "Prop::mReclaimEnergy offset must be 0x274");
  static_assert(offsetof(Prop, mTracksReclaimArea) == 0x278, "Prop::mTracksReclaimArea offset must be 0x278");
  static_assert(offsetof(Prop, mPriority) == 0x27C, "Prop::mPriority offset must be 0x27C");
  static_assert(offsetof(Prop, mHandleIndex) == 0x280, "Prop::mHandleIndex offset must be 0x280");
  static_assert(offsetof(Prop, mHandleLink) == 0x284, "Prop::mHandleLink offset must be 0x284");
  static_assert(sizeof(Prop) == 0x288, "Prop size must be 0x288");
} // namespace moho
