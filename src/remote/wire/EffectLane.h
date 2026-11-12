#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "moho/effects/rendering/EffectOps.h"

// Engine addition, server mode (plan WP9.1 step 3): the effects lane, the seventh lane of a `View` message
// (remote/net/GameLinks.h), after the pose lane. It carries the beat's effect operations as the server's sim performed
// them (moho/effects/rendering/EffectOps.h), for a client that hosts the same emitter classes to draw the same effects.
// The server writes it (server/EffectOpEncoder.h); this reads it.
//
// An empty lane: no op this beat. Otherwise, all varints unsigned LEB128:
//
//   varint n, then n times: varint entry, varint length, that many bytes   blueprint names new to this client
//   varint m, then m times: the same                                       texture names new to this client
//   ops to the lane's end
//
// A name's entry never changes for the server's whole game, so a client keeps every name it was sent; one sent again
// (after a reconnect) has the same text. Each op: its `EEffectOp` byte, then (all but `CreateLightParticle`) the
// effect's id, then per op (int: varint of the value + 1, so -1 is 0; name: varint 0 for none or entry + 1; floats: 4
// bytes little-endian each, a variable count first as a varint):
//
//   CreateEmitter                                     blueprint, army, 3 floats (the position)
//   CreateAttachedEmitter, CreateEmitterAtBone,
//   CreateTrail                                       entity, bone, blueprint, army
//   CreateEmitterAtEntity, CreateEmitterOnEntity      entity, blueprint, army
//   CreateBeam                                        blueprint, then with one: army; without (a beam from create
//                                                     parameters): entity, bone, army, texture, blend mode, floats
//   CreateBeamEntityToEntity, AttachBeamEntityToEntity entity, bone, entity2, bone2, blueprint, army
//   CreateLightParticle                               army, texture, ramp texture, 5 floats (position, size, lifetime)
//   SetFloat                                          parameter, 1 float
//   SetVector, SetN, SetCurve                         parameter, floats (a curve: its bounds, then x y z per key)
//   SetEntity                                         entity
//   SetBone                                           entity, bone
//   DestroyByScript                                   nothing more
//
// Effect ids count up from 0 and are never reused. A client that never saw an effect's create (it joined, or came
// back, after it) drops the ops on it. `Destroy` never goes: a client derives it (the effect's lifetime, the entity's
// death). Entities are the server's ids, as the view's frames name them.
//
// Plan WP9.2: a view gets only the effects its client can place (server/EffectOpRouter.h): those on entities its
// frames hold, at points its army sees, and lights its army sees or detects. A client drops an effect when it drops the
// effect's entity, or when an attach names an entity it doesn't hold; when it holds the entity again the effect comes
// again whole, with the same id: its create, then its latest setters. A create for an id the client holds replaces
// that effect. A whole view (after a lost connection) is followed by every effect the client can place. An emitter
// placed once at an entity or a bone (`CreateEmitterAtEntity`, `CreateEmitterAtBone`) may name an entity the same
// view message removes (a projectile's impact): the client places it from that entity's last state, and keeps it when
// the entity goes, as it doesn't follow it.
//
// Open (for the client step): ops name entities by the sim's ids. A view's frames hold another army's unit as its
// recon blip, and other armies' projectiles and blips under ids of the view's own (remote/ViewIdMap.h), so such an
// effect goes to the views that draw that unit or projectile, but its entity id is not yet one the client holds.

namespace faf::remote::wire
{
  /** One op as the lane has it. Names are references: 0 none, else entry + 1 (`CEffectLaneReader::Name`). */
  struct SEffectLaneOp
  {
    moho::EEffectOp op = moho::EEffectOp::Count;
    std::uint32_t id = 0; // not for `CreateLightParticle`
    std::int32_t entity = -1;
    std::int32_t bone = -1;
    std::int32_t entity2 = -1;
    std::int32_t bone2 = -1;
    std::int32_t army = -1;
    std::int32_t param = -1;
    std::uint32_t blueprint = 0;
    std::uint32_t texture = 0;
    std::uint32_t texture2 = 0;
    std::vector<float> values;
  };

  /** A client's end of the effects lane: the names it holds, and each lane's ops. */
  class CEffectLaneReader
  {
  public:
    /**
     * Reads one lane: takes its names, then decodes its ops into `ops` (cleared first). False when it doesn't parse
     * (cut short, an op this build doesn't know, a count past the lane's end); `ops` then holds those before it.
     */
    [[nodiscard]] bool Read(std::span<const std::uint8_t> lane, std::vector<SEffectLaneOp>& ops);

    /** A blueprint (`textures` false) or texture name by reference; null for none or one this client wasn't sent. */
    [[nodiscard]] const std::string* Name(bool textures, std::uint32_t ref) const noexcept;

    /** References, over every lane read, to a name this client wasn't sent (a view from before a reconnect). */
    [[nodiscard]] std::uint64_t UnknownNames() const noexcept
    {
      return mUnknownNames;
    }
    [[nodiscard]] std::uint64_t NamesTaken() const noexcept
    {
      return mNamesTaken;
    }

  private:
    struct SName
    {
      std::string text;
      bool held = false;
    };
    std::vector<SName> mNames[2]; // blueprints, textures; by entry
    std::uint64_t mUnknownNames = 0;
    std::uint64_t mNamesTaken = 0;
  };
} // namespace faf::remote::wire
