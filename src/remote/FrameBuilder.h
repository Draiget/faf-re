#pragma once

#include <algorithm>
#include <atomic>
#include <bit>
#include <cstdint>
#include <map>
#include <memory>
#include <span>
#include <vector>

#include "boost/shared_ptr.h"
#include "gpg/core/containers/ChunkedVector.h"
#include "gpg/core/containers/FlatGenerationMap.h"

#include "moho/entity/SSTIEntityVariableData.h"
#include "remote/UnderlayPaths.h"
#include "remote/wire/EntityFrame.h"
#include "remote/wire/OrdinalTable.h"
#include "remote/wire/SessionTables.h"

// Engine addition, server mode: the server side of the entities lane. It follows the entity
// state a sim publishes in its sync packets (creations, entity and unit updates, erases and
// deletes, in `CWldSession::DoBeat`'s order) and turns it into one view frame per beat.
// Today it builds the full-vision frame of a canonical (focus -1) packet; the per-view filter
// (WP5.2, the oracle of WP4) sits on top of it later.
//
// Erase versus delete (WP7.7): a deleted entity leaves the frame. An erased one (a prop the
// sim is done with, `Prop::Sync`) stays as an orphaned record, flag `kEntityFlagOrphaned`,
// for `orphanBeats` beats, so a client decoding against any baseline from that window tells
// the two apart: a record that turns orphaned is erased (the client orphans its entity and
// deletes it once its view sees the spot, `UserEntity::OrphanUpdate`), a record that goes
// away while not orphaned is deleted. A client whose baseline is older than the window reads
// an erase as a delete; the server keeps its baselines inside it.

namespace moho
{
  class CHeightField;
  class Entity;
  class ReconBlip;
  class StatItem;
  class Unit;
  template <class T>
  class Stats;
  struct SSyncData;
  struct SSTIEntityVariableData;
  struct SSTIUnitVariableData;
}

namespace faf::remote
{
  /** Flag bit of an erased entity's record while the frame keeps it (see above). */
  inline constexpr std::uint16_t kEntityFlagOrphaned = 1u << 12;

  /** How long an erased record stays in the frame: 5 seconds of beats. */
  inline constexpr std::uint32_t kDefaultOrphanBeats = 50;

  /** Being built, dead, the visibility mode and the layer, as the record's 16 flag bits. */
  [[nodiscard]] std::uint16_t PackEntityFlags(const moho::SSTIEntityVariableData& data) noexcept;

  /** The reverse of `PackEntityFlags`, into `data` (the orphan bit is not entity data). */
  void UnpackEntityFlags(std::uint16_t flags, moho::SSTIEntityVariableData& data) noexcept;

  /** Hidden, alt footprint, alt footprint 2, destroyed by a kill, refresh UI: `SAppearance::visualFlags`. */
  [[nodiscard]] std::uint8_t PackVisualFlags(const moho::SSTIEntityVariableData& data) noexcept;

  /**
   * A frame's appearance block, written into entity data: everything but the mesh (the caller
   * resolves the ordinal), the sounds and the underlay texture.
   */
  void UnpackAppearance(const wire::SAppearance& look, moho::SSTIEntityVariableData& data);

  /**
   * A unit's stats tree as `SUnitFields::stats`: every item's path and value interned in the
   * session's name table, sorted by name id.
   */
  void ReadUnitStats(
    moho::Stats<moho::StatItem>& stats, wire::CSessionTableWriters& session, std::vector<wire::SUnitStat>& out
  );

  /** A frame's unit block, written into a unit update's data. */
  void UnpackUnitFields(const wire::SUnitFields& unit, moho::SSTIUnitVariableData& data) noexcept;

  struct SChangedEntity;

  /**
   * Plan WPR.35: this beat's records of one changed plain entity or prop, one per visibility mode
   * a view shows it in. Which modes is written by the views' workers, the records are read by them
   * once `CSharedEntityRecords::Build` has made them.
   */
  struct SSharedUpdate
  {
    static constexpr std::size_t kModes = 3;

    /** `EUserEntityVisibilityMode` is one bit per mode. */
    [[nodiscard]] static std::size_t ModeIndex(const moho::EUserEntityVisibilityMode mode) noexcept
    {
      return static_cast<std::size_t>(std::countr_zero(static_cast<std::uint32_t>(mode)));
    }
    /** A view shows the entity in `mode`. Only the first view of a mode writes. */
    void UseMode(const moho::EUserEntityVisibilityMode mode) noexcept
    {
      const auto bit = static_cast<std::uint8_t>(mode);
      if ((modes.load(std::memory_order_relaxed) & bit) == 0u) {
        modes.fetch_or(bit, std::memory_order_relaxed);
      }
    }

    std::atomic<std::uint8_t> modes{0};
    wire::SEntityRecord* records[kModes]{}; // valid for the modes used
  };

  /**
   * Plan WPR.35: what one blip's update writes for the views that show it the same way and share
   * its recon data, worked out once a beat. Each view copies it into its own record, so nothing here
   * is counted by more than one thread, and it lasts one beat.
   */
  struct SBlipRecord
  {
    wire::SEntityRecord record;
    wire::SUnitDetail detail;
    std::uint64_t hash = 0; // `wire::HashBlipUpdate`: a view holding this one already skips it
  };

  /**
   * Plan WPR.35: the records of plain entities and props, held once for all views. A published
   * entity gets every change in every view and an unpublished one leaves the view, so a view's
   * record is a function of the entity and the mode the view showed it in at its last change: the
   * views need not store it, nor count their references. A record's last change replaces it for
   * every view in one beat (a view that orphans it copies it), so the old one stays readable for
   * that beat, as the record before the change, and is reused after it.
   *
   * What depends on a client's session tables (a sound, an underlay) stays in the view's own record.
   */
  class CSharedEntityRecords
  {
  public:
    CSharedEntityRecords(const wire::SContentTables& tables, const wire::SFrameCodec& codec);
    ~CSharedEntityRecords();

    /** Whether `entity`'s record can be shared now: it names nothing in a session table. */
    [[nodiscard]] static bool Shareable(const moho::Entity& entity) noexcept;

    /** A new beat with `changedCount` changed entities; what the last beat replaced is free again. */
    void BeginBeat(std::size_t changedCount);
    /** The update of the change set's `index`th entity. */
    [[nodiscard]] SSharedUpdate& Update(const std::size_t index) noexcept { return mUpdates[index]; }
    /** Makes the records the views asked for (`UseMode`), on the sim's workers with `parallel`. */
    void Build(const std::vector<SChangedEntity>& changed, bool parallel);

    /** `count` blip records for this beat; none moves until the next call. */
    void ReserveBlipRecords(std::size_t count);
    [[nodiscard]] SBlipRecord& BlipRecord(const std::size_t index) noexcept { return mBlipRecords[index]; }
    /** One `army`'s update of `blip`; `block` is scratch. Reads only the sim. The blip must be `Shareable`. */
    void FillBlipRecord(
      SBlipRecord& out, moho::SSTIEntityVariableData& block, moho::ReconBlip& blip, bool requestRefreshUI, std::size_t army,
      moho::EUserEntityVisibilityMode mode, std::uint32_t vision, bool hasVision
    ) const;

  private:
    static constexpr std::uint32_t kNoRecord = 0xFFFFFFFFu;

    /** An entity some view holds. */
    struct SEntry
    {
      const moho::Entity* entity = nullptr;
      std::uint32_t blueprint = 0;
      std::uint32_t tickCreated = 0;
      std::uint32_t records[SSharedUpdate::kModes]{kNoRecord, kNoRecord, kNoRecord};
    };

    const wire::SContentTables& mTables;
    wire::SFrameCodec mCodec;
    CUnderlayPathReader mNoUnderlays;
    gpg::core::ChunkedVector<wire::SEntityRecord> mRecords;
    gpg::core::ChunkedVector<SBlipRecord> mBlipRecords;
    std::vector<std::uint32_t> mFree;
    std::vector<std::uint32_t> mReplaced; // this beat's old records, free from the next beat on
    gpg::core::FlatGenerationMap<SEntry> mEntries; // by entity id
    std::unique_ptr<SSharedUpdate[]> mUpdates;
    std::size_t mUpdateCapacity = 0;
    std::size_t mUpdateCount = 0;
  };

  /**
   * Plan WPR.35: one entity's update for one view, as what to read from the sim: the sim is
   * stopped until the views are built, so nothing is copied into a packet first.
   */
  struct SDirectUpdate
  {
    /** What every view reads of the entity, once a beat. */
    struct STarget
    {
      SSharedUpdate* shared = nullptr;  // a plain entity or prop: its records for all views
      moho::Entity* entity = nullptr;
      moho::Unit* unit = nullptr;       // the entity as a unit, or
      moho::ReconBlip* blip = nullptr;  // as a blip
      bool requestRefreshUI = false;    // `mRequestRefreshUI` as the sync walk found it
    };

    const STarget* target = nullptr;
    const SBlipRecord* blipRecord = nullptr; // a blip: its update for this view, if it could be shared
    std::uint32_t vision = 0; // a blip: the vision range the view last copied from its creator
    std::uint8_t mode = 0;    // `EUserEntityVisibilityMode`
    std::uint8_t army = 0;    // the view's army (a blip's recon record)
    bool hasVision = false;   // whether it ever did
    bool created = false;     // with `shared`: the view creates it now (`CreateInterface`)

    [[nodiscard]] moho::EUserEntityVisibilityMode Mode() const noexcept
    {
      return static_cast<moho::EUserEntityVisibilityMode>(mode);
    }
  };

  /**
   * What `Entity::SyncInterface` (0x0067A290) writes over its copy for a view: the attach parent
   * and children from the live attach info, the view's visibility mode and flag, the refresh flag.
   */
  void WriteEntityBlockForView(
    moho::SSTIEntityVariableData& data, moho::Entity& entity, moho::EUserEntityVisibilityMode mode, bool requestRefreshUI
  );

  class CViewFrameBuilder
  {
  public:
    CViewFrameBuilder(
      const wire::SContentTables& tables, const wire::SFrameCodec& codec, std::uint32_t orphanBeats = kDefaultOrphanBeats
    );

    /**
     * The session tables sounds and underlay names are interned into (WP7.2); without them the
     * frames name no sounds and no underlays.
     */
    void SetSessionTables(wire::CSessionTableWriters* session) noexcept { mSession = session; }

    /**
     * Applies one packet's entity lanes to the world the frames are built from. The sim's unit
     * stats trees it lets go of are kept until `ReleaseDropped`: a builder running on a sim
     * worker must not drop the last reference of a sim object (.plans/sim-threading/PLAN.md §2).
     * `direct` are this beat's updates the packet does not carry (`SDirectUpdate`).
     */
    void Apply(const moho::SSyncData& packet, std::span<const SDirectUpdate> direct = {});
    /** Drops the stats trees `Apply` let go of; on the sim thread. */
    void ReleaseDropped();

    /** The frame of the world as it stands, stamped with `beat` and the next frame id. */
    [[nodiscard]] wire::SViewFrame Build(std::uint32_t beat)
    {
      return Build(beat, [](const wire::SEntityRecord&) { return true; });
    }
    /**
     * `Build`, less the records `keep` refuses; it is asked in ascending id order, and a refused
     * record is never copied (plan WPR.35).
     */
    template <class Keep>
    [[nodiscard]] wire::SViewFrame Build(const std::uint32_t beat, Keep&& keep)
    {
      wire::SViewFrame frame = StartFrame(beat);
      FillFrame(frame, keep);
      return frame;
    }

    /** An empty frame stamped with `beat` and the next frame id, after the units' stats are read. */
    [[nodiscard]] wire::SViewFrame StartFrame(std::uint32_t beat);
    /** Adds the world's records `keep` accepts to `frame`. */
    template <class Keep>
    void FillFrame(wire::SViewFrame& frame, Keep&& keep) const
    {
      frame.entities.reserve(mWorldIndex.size());
      for (const SWorldEntry& entry : mWorldIndex) {
        const wire::SEntityRecord& record = *mWorldSlots[entry.slot];
        if (keep(record)) {
          frame.entities.push_back(record);
        }
      }
    }

    /** A record that left the world: its id and the slot it had. */
    struct SErasedRecord
    {
      std::uint32_t id;
      std::uint32_t slot;
    };
    /**
     * Plan WPR.35: from now on `TouchedIds` and `ErasedRecords` say which records changed since
     * `ClearChanges`, for a caller that keeps its frame between beats.
     */
    void TrackChanges() noexcept { mTrackChanges = true; }
    /** Ids of the records created or changed; an id can be listed more than once. */
    [[nodiscard]] const std::vector<std::uint32_t>& TouchedIds() const noexcept { return mTouchedIds; }
    [[nodiscard]] const std::vector<SErasedRecord>& ErasedRecords() const noexcept { return mErasedRecords; }
    /** Ids that got a record in a new slot; it may have left again (`ErasedRecords`). */
    [[nodiscard]] const std::vector<std::uint32_t>& NewRecordIds() const noexcept { return mNewRecordIds; }
    void ClearChanges() noexcept
    {
      mTouchedIds.clear();
      mErasedRecords.clear();
      mNewRecordIds.clear();
    }
    /**
     * Plan WPR.35: for a caller that holds no copy of `slot`'s record because its own would be
     * equal. The first change of a beat to a watched slot first saves the record (`RecordBefore`).
     */
    void WatchRecord(const std::uint32_t slot)
    {
      if (mWatched.size() <= slot) {
        mWatched.resize(mWorldSlots.size(), 0u);
        mBeforeRecords.resize(mWorldSlots.size(), nullptr);
      }
      mWatched[slot] = 1u;
    }
    void UnwatchRecord(const std::uint32_t slot) noexcept
    {
      if (slot < mWatched.size()) {
        mWatched[slot] = 0u;
      }
    }
    /** What a watched `slot` held before this beat's changes; null if it was not changed. */
    [[nodiscard]] const wire::SEntityRecord* RecordBefore(const std::uint32_t slot) const noexcept
    {
      return slot < mBeforeRecords.size() ? mBeforeRecords[slot] : nullptr;
    }
    /** Lets go of last beat's saved records; before this beat's changes. */
    void ClearBefore() noexcept;
    /** How many slots records can lie in (a slot is below this). */
    [[nodiscard]] std::size_t SlotCount() const noexcept { return mWorldSlots.size(); }
    /** `visit(id, slot)` for every record, in ascending id order, without reading the records. */
    template <class Visit>
    void ForEachRecord(Visit&& visit) const
    {
      for (const SWorldEntry& entry : mWorldIndex) {
        visit(entry.id, entry.slot);
      }
    }
    /** The slot of `id`'s record, if the world has one. */
    [[nodiscard]] bool FindSlot(const std::uint32_t id, std::uint32_t& slot) const
    {
      const auto found = LowerBound(id);
      if (found == mWorldIndex.end() || found->id != id) {
        return false;
      }
      slot = found->slot;
      return true;
    }
    /** `FindSlot` for ids in ascending order: `cursor` starts at 0 and stays between calls. */
    [[nodiscard]] bool FindSlotFrom(std::size_t& cursor, const std::uint32_t id, std::uint32_t& slot) const
    {
      cursor = SeekWorld(cursor, id);
      if (cursor == mWorldIndex.size() || mWorldIndex[cursor].id != id) {
        return false;
      }
      slot = mWorldIndex[cursor].slot;
      return true;
    }
    [[nodiscard]] const wire::SEntityRecord& RecordAt(const std::uint32_t slot) const { return *mWorldSlots[slot]; }

    [[nodiscard]] const wire::SFrameCodec& Codec() const noexcept { return mCodec; }
    [[nodiscard]] std::size_t EntityCount() const noexcept { return mWorldIndex.size(); }
    /** Whether the client still holds a record of `id` (orphans included). */
    [[nodiscard]] bool Holds(const std::uint32_t id) const
    {
      const auto found = LowerBound(id);
      return found != mWorldIndex.end() && found->id == id;
    }
    /** Creations whose blueprint is missing from the content tables (should stay 0). */
    [[nodiscard]] std::uint64_t UnknownBlueprints() const noexcept { return mUnknownBlueprints; }
    /** Underlay textures that are not plain file textures (should stay 0). */
    [[nodiscard]] std::uint64_t UnknownUnderlays() const noexcept { return mUnknownUnderlays; }
    /** Beats with more resource deposits than the session record may carry (should stay 0). */
    [[nodiscard]] std::uint64_t DepositOverflows() const noexcept { return mDepositOverflows; }
    /**
     * The heights as the client holds them after this beat's edits: the server's terrain for
     * predictions the client makes on its own copy (ground following). The sim's own field may
     * be ahead of the frames when the sim runs ahead of them (loopback, replays).
     */
    [[nodiscard]] const moho::CHeightField* SentTerrain() const noexcept { return mSentTerrain.get(); }
    /** Terrain edits the session record could not carry (should stay 0). */
    [[nodiscard]] std::uint64_t TerrainEditOverflows() const noexcept { return mTerrainEditOverflows; }

  private:
    /** One record of the world: its id and where it lies in `mWorldSlots`. */
    struct SWorldEntry
    {
      std::uint32_t id;
      std::uint32_t slot;
    };

    [[nodiscard]] std::vector<SWorldEntry>::const_iterator LowerBound(const std::uint32_t id) const
    {
      return std::lower_bound(mWorldIndex.begin(), mWorldIndex.end(), id, [](const SWorldEntry& entry, const std::uint32_t value) {
        return entry.id < value;
      });
    }
    static constexpr std::uint32_t kNoLocal = 0xFFFFFFFFu;

    /**
     * Where `id` is or belongs in the index, looking forward from `from`: a beat's updates come in
     * ascending id order and lie close together. An id before `from` searches from the start.
     */
    [[nodiscard]] std::size_t SeekWorld(std::size_t from, const std::uint32_t id) const
    {
      const std::size_t size = mWorldIndex.size();
      if (from > size || (from > 0u && mWorldIndex[from - 1u].id >= id)) {
        from = 0u;
      }
      std::size_t step = 1u;
      while (from + step < size && mWorldIndex[from + step].id < id) {
        from += step;
        step *= 2u;
      }
      const std::size_t end = from + step < size ? from + step + 1u : size;
      const auto first = mWorldIndex.begin() + static_cast<std::ptrdiff_t>(from);
      const auto last = mWorldIndex.begin() + static_cast<std::ptrdiff_t>(end);
      return static_cast<std::size_t>(
        std::lower_bound(first, last, id, [](const SWorldEntry& entry, const std::uint32_t value) { return entry.id < value; }) - mWorldIndex.begin()
      );
    }

    /** A watched slot's record is about to change. */
    void SaveBefore(std::uint32_t slot);
    /** `slot`'s record as this view's own, to change it. */
    [[nodiscard]] wire::SEntityRecord& LocalRecord(std::uint32_t slot);
    /** `slot` no longer has a record of this view's own. */
    void ReleaseLocal(std::uint32_t slot);
    /** The slot for a new record of `id`, which goes in the index at `found`. */
    [[nodiscard]] std::uint32_t NewSlot(std::uint32_t id, std::vector<SWorldEntry>::const_iterator found);
    /** `id`'s record, to change it, or null. */
    [[nodiscard]] wire::SEntityRecord* FindRecord(std::uint32_t id);
    /** Stores `record` under its id, over any record that id has, and returns it in place. */
    wire::SEntityRecord& PutRecord(const wire::SEntityRecord& record);
    /** A shared update: the view's record is now the one all views share. `cursor`: `SeekWorld`'s. */
    void ApplySharedUpdate(const SDirectUpdate& update, std::size_t& cursor);
    void EraseRecord(std::uint32_t id);

    const wire::SContentTables& mTables;
    wire::SFrameCodec mCodec;
    std::uint32_t mOrphanBeats;
    // The world in ascending id order, as frames list it. Plan WPR.35: one flat index over stable
    // slots, so each beat's thousands of lookups and the frame's walk stay within a few arrays.
    std::vector<SWorldEntry> mWorldIndex;
    gpg::core::ChunkedVector<const wire::SEntityRecord*> mWorldSlots; // a shared record or a local one
    std::vector<std::uint32_t> mFreeSlots;
    gpg::core::ChunkedVector<wire::SEntityRecord> mLocalRecords;      // this view's own records
    std::vector<std::uint32_t> mLocalSlots;                           // per slot: index into them, or `kNoLocal`
    std::vector<std::uint64_t> mBlipHashes;                           // per slot: the blip update its record is, or 0
    std::vector<std::uint32_t> mFreeLocal;
    bool mTrackChanges = false;
    std::vector<std::uint32_t> mTouchedIds;
    std::vector<SErasedRecord> mErasedRecords;
    std::vector<std::uint32_t> mNewRecordIds;
    std::vector<std::uint8_t> mWatched;                  // per slot
    std::vector<const wire::SEntityRecord*> mBeforeRecords; // per slot: before this beat's changes, or null
    std::vector<std::uint32_t> mBeforeSlots;             // the slots with one
    gpg::core::ChunkedVector<wire::SEntityRecord> mBefore; // the local ones among them, which change in place
    std::map<std::uint32_t, std::uint32_t> mOrphanedAt; // id -> beat of its erase
    std::map<std::uint32_t, boost::shared_ptr<moho::Stats<moho::StatItem>>> mUnitStats; // the sim's live trees
    std::vector<boost::shared_ptr<moho::Stats<moho::StatItem>>> mDroppedStats;          // until `ReleaseDropped`
    std::uint32_t mNextFrameId = 1;
    std::uint64_t mUnknownBlueprints = 0;
    std::uint64_t mUnknownUnderlays = 0;
    std::uint64_t mDepositOverflows = 0;
    std::uint64_t mTerrainEditOverflows = 0;
    boost::shared_ptr<moho::CHeightField> mSentTerrain; // the client's heights, as the edits sent leave them
    moho::SSTIEntityVariableData mBlockScratch;  // a direct update's entity block
    CUnderlayPathReader mUnderlays;              // the entities' underlay paths, as of this beat
    wire::SUnitDetail mDetailScratch;            // a unit update's detail, before it is compared
    std::vector<wire::SUnitStat> mStatsScratch;  // a unit's stats, likewise
    wire::CSessionTableWriters* mSession = nullptr;

    void DropStats(std::uint32_t id);
  };

  /** A height field as the terrain ground-following records stand on (WP7.8). */
  class CHeightFieldGround final : public wire::IGroundHeight
  {
  public:
    void SetField(const moho::CHeightField* field) noexcept { mField = field; }
    [[nodiscard]] float HeightAt(float x, float z) const noexcept override;

  private:
    const moho::CHeightField* mField = nullptr;
  };

  /**
   * Dead reckoning for one view (WP7.5, WP7.8): rewrites each record of a built frame so it
   * keeps the anchor the view holds while the view's prediction stays within the scheme's
   * tolerance of the sim's position, and re-anchors it, with the motion the scheme fits to the
   * last beats' positions, otherwise. Frames go through it in beat order.
   */
  class CDeadReckoner
  {
  public:
    explicit CDeadReckoner(const wire::SReckoningScheme& scheme) noexcept
      : mScheme(scheme)
    {}

    /** `codec.deadReckoning` must be on; orientations are reckoned with `codec.orientationReckoning`. */
    void Apply(wire::SViewFrame& frame, const wire::SFrameCodec& codec);

    [[nodiscard]] const wire::SReckoningScheme& Scheme() const noexcept { return mScheme; }
    [[nodiscard]] std::uint32_t Tolerance() const noexcept { return mScheme.tolerance; }
    [[nodiscard]] std::uint64_t Reanchors() const noexcept { return mReanchors; }
    [[nodiscard]] std::uint64_t OrientationReanchors() const noexcept { return mOrientationReanchors; }
    /** Re-anchors that made the position follow the terrain. */
    [[nodiscard]] std::uint64_t GroundAnchors() const noexcept { return mGroundAnchors; }

    /** What the re-anchors were (to tune the schemes, WP7.8). */
    struct SReanchorCauses
    {
      std::uint64_t horizontalOnly = 0; // only x or z beyond the tolerance
      std::uint64_t verticalOnly = 0;
      std::uint64_t both = 0;
      std::uint64_t units = 0;
      std::uint64_t stopped = 0;          // the position did not move on the last beat
      std::uint64_t afterBeats[4]{};      // beats since the anchor: 1, 2-3, 4-9, 10 or more
    };
    [[nodiscard]] const SReanchorCauses& Causes() const noexcept { return mCauses; }

  private:
    struct SSent
    {
      wire::SEntityRecord anchor; // the motion fields as the view holds them; the rest unused
      std::array<wire::QuantizedPosition, wire::kReckoningHistory> history{}; // the sim's, oldest first
      std::uint32_t historyCount = 0;
      std::array<std::uint32_t, wire::kReckoningHistory> yawHistory{}; // while yaw-only, oldest first
      std::uint32_t yawCount = 0;
      std::uint32_t lastBeat = 0;
    };

    wire::SReckoningScheme mScheme;
    std::map<std::uint32_t, SSent> mSent;
    std::uint64_t mReanchors = 0;
    std::uint64_t mOrientationReanchors = 0;
    std::uint64_t mGroundAnchors = 0;
    SReanchorCauses mCauses;
  };
} // namespace faf::remote
