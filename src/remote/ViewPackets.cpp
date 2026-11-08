#include "remote/ViewPackets.h"

#include <algorithm>
#include <bit>
#include <utility>

#include "moho/entity/Entity.h"
#include "moho/entity/EntityId.h"
#include "moho/entity/Prop.h"
#include "moho/sim/ReconBlip.h"
#include "gpg/core/utils/Logging.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/sim/SSTIArmyVariableData.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/SimWorkerPool.h"
#include "moho/unit/core/Unit.h"
#include "remote/wire/ArmyLane.h"

// Engine addition, server mode: see ViewPackets.h. Each step names the function it replays.

namespace faf::remote
{
  namespace
  {
    constexpr std::int32_t kUnitReconFlags = 28; // `Unit::SyncInterface`, 0x006AC4DC..0x006AC500
    constexpr std::size_t kMaxViews = wire::kMaxArmyRecords; // no frame names more armies; `SEntityViews` has a bit per view
    static_assert(kMaxViews <= 32u);
    constexpr std::size_t kChangedGrain = 64; // blips, the costly part, sit together by id: small chunks spread them
    constexpr std::size_t kBlipGrain = 8;

    /** What makes one view's update of a blip differ from another's; floats by their bits. */
    struct SBlipKey
    {
      std::int32_t mode;
      std::uint32_t flags;
      const void* mesh;
      std::uint32_t health;
      std::uint32_t maxHealth;
      std::uint32_t fraction;
      std::uint32_t dead;
      std::uint32_t vision;
      bool hasVision;

      [[nodiscard]] bool operator==(const SBlipKey&) const = default;
    };

    /** The block `Entity::SyncInterface` (0x0067A290) copies, for one view. */
    [[nodiscard]] moho::SSTIEntityVariableData EntityBlockForView(
      moho::Entity& entity, const SViewVisibility& visibility, const bool requestRefreshUI
    )
    {
      moho::SSTIEntityVariableData data = entity.mVarDat;
      WriteEntityBlockForView(data, entity, visibility.mode, requestRefreshUI);
      return data;
    }
  } // namespace

  /**
   * Plan WP5.4: army `index`'s record as view `viewArmy` gets it. Every army's public fields go to
   * every view; the fields the client reads for the focus army alone go to their own view only,
   * zeroed for the others: economy totals (`GetEconomyTotals`, UserLuaFunctions.cpp:3954),
   * resource sharing (:4093), use-whole-map (the focus army's camera bounds and command checks, CameraImpl.cpp:1286/1487, UserCommandIssue.cpp:418/746), the path-preview
   * scratch (CWldSession.cpp:4734), start position and no-rush ring (RangeRenderer.cpp:1934-1954,
   * CWldSession.cpp:9164, UserCommandIssue.cpp:422/750). `mIsAlly` is the one focus-dependent field
   * the sim writes (`CArmyImpl::SetCanSee` 0x006FDEE0): 1 with no focus, else whether the army lists
   * the view's army among its allies.
   */
  moho::SSTIArmyVariableData ArmyRecordForView(
    const moho::SSTIArmyVariableData& source, const std::size_t index, const std::int32_t viewArmy,
    const bool beforeFirstTick
  )
  {
    moho::SSTIArmyVariableData record = source;
    if (beforeFirstTick) {
      // The constructor's value, until the army's first tick runs `SetCanSee`: the army the sim
      // was focused on when it was built (`Sim.cpp` 6350, `CArmyImpl.cpp` 1141).
      record.mIsAlly = static_cast<std::int32_t>(index) == viewArmy ? 1u : 0u;
    } else {
      record.mIsAlly = viewArmy < 0 || source.mAllies.Contains(static_cast<std::uint32_t>(viewArmy)) ? 1u : 0u;
    }
    if (viewArmy >= 0 && index != static_cast<std::size_t>(viewArmy)) {
      record.mEconomyTotals = moho::SEconTotals{};
      record.mIsResourceSharingEnabled = 0u;
      record.mUseWholeMap = 0u;
      record.mWordVectorWithMeta = moho::SArmyVectorWithMeta{};
      record.mArmyStart = Wm3::Vector2f{0.0f, 0.0f};
      record.mNoRushTimer = 0;
      record.mNoRushRadius = 0.0f;
      record.mNoRushOffset = Wm3::Vector2f{0.0f, 0.0f};
    }
    return record;
  }

  CViewPackets::CViewPackets() = default;
  CViewPackets::~CViewPackets() = default;

  void CViewPackets::OnBeatChanges(moho::Sim& sim, const moho::SSyncData& packet)
  {
    OnBeatStarting();
    mSyncPacket = &packet;
    mBuildStart = std::chrono::steady_clock::now();
    const std::size_t armyCount = sim.mArmiesList.size();
    mArmySlots = static_cast<std::int32_t>(armyCount);
    if (mWantTeams && !mTeamsOn) {
      mWantTeams = false;
      BuildTeams(sim);
    }
    if (mTeamsOn) {
      CheckTeams(sim);
    }
    const std::size_t slots = armyCount + mTeams.size();
    if (mPhaseTimesOn) {
      mPhaseMark = mBuildStart;
      mViewSeconds.assign(slots, 0.0);
    }
    while (mPackets.size() < slots) {
      mPackets.push_back(std::make_unique<moho::SSyncData>());
      mHasView.push_back(1u);
      mDirect.emplace_back();
    }

    // Last beat's records go on the sim thread: they hold references to sim objects (poses,
    // stats trees), whose last one a sim worker must not drop (.plans/sim-threading/PLAN.md §2).
    for (std::size_t army = 0; army < slots; ++army) {
      moho::SSyncData& out = *mPackets[army];
      out.mNewEntities.clear();
      out.mNewUnits.clear();
      out.mEntityUpdates.clear();
      out.mUnitUpdates.clear();
      out.mDeleteIds.clear();
      out.mEraseIds.clear();
      out.mArmyUpdates.clear();
      out.mCurBeat = static_cast<std::int32_t>(sim.mCurBeat);
      out.mCurTick = static_cast<std::int32_t>(sim.mCurTick);
      out.mFocusArmy = static_cast<std::int32_t>(army);
      mDirect[army].clear();
      if (army >= armyCount) {
        // A team's view, while any of its players has one.
        mHasView[army] = (mTeams[army - armyCount].mask & mViewArmies) != 0u ? 1u : 0u;
        continue;
      }
      const moho::CArmyImpl* const owner = sim.mArmiesList[army];
      mHasView[army] = army >= kMaxViews || (mSkipCivilians && owner != nullptr && owner->IsCivilian()) || (mViewArmies & (std::uint32_t{1} << army)) == 0u ? 0u : 1u;
    }

    if (mSharedRecords != nullptr) {
      mSharedRecords->BeginBeat(Entities().size());
    }
    ReadChangedEntities(sim);
    MarkPhase(EViewPhase::ReadBlips);

    // Each view reads the sim and the change set and writes its own packet and view state only
    // (plan I3), so the views can be built on the sim's workers (plan WP5.7).
    const auto build = [&](const std::size_t army) {
      if (mHasView[army] == 0u) {
        return;
      }
      moho::SSyncData& out = *mPackets[army];
      const std::uint32_t bit = std::uint32_t{1} << army;
      for (std::size_t i = 0; i < Entities().size(); ++i) {
        if ((mChanged[i].mayAct & bit) != 0u) {
          SyncForView(sim, static_cast<std::int32_t>(army), mChanged[i], out);
        }
      }

      if (army >= static_cast<std::size_t>(mArmySlots)) {
        return; // a team's view has no army lane: each player's goes with their own
      }
      // Plan WP5.4: the army lane, positionally as `Sim::Sync` fills it.
      for (std::size_t index = 0; index < packet.mArmyUpdates.size(); ++index) {
        out.mArmyUpdates.push_back(
          ArmyRecordForView(packet.mArmyUpdates[index], index, static_cast<std::int32_t>(army), packet.mCurBeat == 0)
        );
      }
    };
    if (mParallel && slots > 1u) {
      // The team views first: each holds what its whole team sees, the longest jobs.
      const std::size_t teams = slots - armyCount;
      moho::CSimWorkerPool::Get().ParallelFor(slots, 1u, [this, &build, teams, armyCount](const std::size_t begin, const std::size_t end) {
        for (std::size_t job = begin; job < end; ++job) {
          const std::size_t army = job < teams ? armyCount + job : job - teams;
          this->TimeView(army, [&] { build(army); });
        }
      });
    } else {
      for (std::size_t army = 0; army < slots; ++army) {
        TimeView(army, [&] { build(army); });
      }
    }
    MarkPhase(EViewPhase::Build);
    WriteChangedEntities();
    MarkPhase(EViewPhase::Write);
    if (mSharedRecords != nullptr) {
      mSharedRecords->Build(Entities(), mParallel);
    }
    MarkPhase(EViewPhase::Shared);
    OnViewPackets(sim);
  }

  void CViewPackets::MarkPhase(const EViewPhase phase) noexcept
  {
    if (!mPhaseTimesOn) {
      return;
    }
    const auto now = std::chrono::steady_clock::now();
    SPhaseTime& time = mPhaseTimes[static_cast<std::size_t>(phase)];
    time.wall += std::chrono::duration<double>(now - mPhaseMark).count();
    mPhaseMark = now;
    double slowest = 0.0;
    for (std::size_t slot = 0; slot < mViewSeconds.size(); ++slot) {
      const double seconds = std::exchange(mViewSeconds[slot], 0.0);
      time.viewSum += seconds;
      time.teamViews += slot >= static_cast<std::size_t>(mArmySlots) ? seconds : 0.0;
      slowest = std::max(slowest, seconds);
    }
    time.viewMax += slowest;
  }

  void CViewPackets::BuildTeams(const moho::Sim& sim)
  {
    const std::size_t armies = sim.mArmiesList.size();
    mTeams.clear();
    mTeamOfArmy.assign(armies, -1);
    const auto hasView = [&](const std::size_t army) {
      const moho::CArmyImpl* const owner = sim.mArmiesList[army];
      return owner != nullptr && army < kMaxViews && !(mSkipCivilians && owner->IsCivilian()) && (mViewArmies & (std::uint32_t{1} << army)) != 0u;
    };
    const auto mutual = [&](const std::size_t a, const std::size_t b) {
      return sim.mArmiesList[a]->mVarDat.mAllies.Contains(static_cast<unsigned int>(b)) && sim.mArmiesList[b]->mVarDat.mAllies.Contains(static_cast<unsigned int>(a));
    };
    for (std::size_t army = 0; army < armies; ++army) {
      if (!hasView(army) || mTeamOfArmy[army] >= 0) {
        continue;
      }
      STeam team;
      team.members.push_back(static_cast<std::int32_t>(army));
      team.mask = std::uint32_t{1} << army;
      for (std::size_t other = army + 1u; other < armies; ++other) {
        if (!hasView(other) || mTeamOfArmy[other] >= 0) {
          continue;
        }
        const bool fits = std::all_of(team.members.begin(), team.members.end(), [&](const std::int32_t member) {
          return mutual(static_cast<std::size_t>(member), other);
        });
        if (fits) {
          team.members.push_back(static_cast<std::int32_t>(other));
          team.mask |= std::uint32_t{1} << other;
        }
      }
      for (const std::int32_t member : team.members) {
        mTeamOfArmy[static_cast<std::size_t>(member)] = static_cast<std::int32_t>(mTeams.size());
      }
      mTeams.push_back(std::move(team));
    }
    if (armies + mTeams.size() > kMaxViews) {
      gpg::Warnf("views: %zu armies and %zu teams don't fit %zu views; each player gets a view of their own", armies, mTeams.size(), kMaxViews);
      mTeams.clear();
      mTeamOfArmy.clear();
      return;
    }
    mTeamBits = 0u;
    for (std::size_t team = 0; team < mTeams.size(); ++team) {
      mTeamBits |= std::uint32_t{1} << (armies + team);
    }
    mTeamsOn = true;
  }

  void CViewPackets::CheckTeams(const moho::Sim& sim)
  {
    const auto mutual = [&sim](const std::size_t a, const std::size_t b) {
      return sim.mArmiesList[a] != nullptr && sim.mArmiesList[b] != nullptr && sim.mArmiesList[a]->mVarDat.mAllies.Contains(static_cast<unsigned int>(b))
        && sim.mArmiesList[b]->mVarDat.mAllies.Contains(static_cast<unsigned int>(a));
    };
    for (STeam& team : mTeams) {
      // While two of those still in the team aren't mutual allies, the one with fewer allies left in it goes.
      for (;;) {
        std::int32_t leaving = -1;
        int leavingAllies = 0;
        for (const std::int32_t a : team.members) {
          if (((team.mask >> a) & 1u) == 0u) {
            continue;
          }
          bool broken = false;
          int allies = 0;
          for (const std::int32_t b : team.members) {
            if (b != a && ((team.mask >> b) & 1u) != 0u) {
              const bool ally = mutual(static_cast<std::size_t>(a), static_cast<std::size_t>(b));
              broken = broken || !ally;
              allies += ally ? 1 : 0;
            }
          }
          if (broken && (leaving < 0 || allies <= leavingAllies)) {
            leaving = a;
            leavingAllies = allies;
          }
        }
        if (leaving < 0) {
          break;
        }
        team.mask &= ~(std::uint32_t{1} << leaving);
        mCutArmies |= std::uint32_t{1} << leaving;
        gpg::Warnf("views: army index %d is no longer allied with the rest of its team; from now on its player gets only a view of their own units", leaving);
      }
    }
    if (mTeamsJoined) {
      return;
    }
    for (std::size_t a = 0; a < mTeamOfArmy.size(); ++a) {
      for (std::size_t b = a + 1u; b < mTeamOfArmy.size(); ++b) {
        if (mTeamOfArmy[a] >= 0 && mTeamOfArmy[b] >= 0 && mTeamOfArmy[a] != mTeamOfArmy[b] && !CutFromTeam(a) && !CutFromTeam(b) && mutual(a, b)) {
          mTeamsJoined = true;
          gpg::Warnf("views: army indices %zu and %zu became allies across teams; their teams' views stay apart, so neither sees what the other does", a, b);
          return;
        }
      }
    }
  }

  std::int32_t CViewPackets::TeamLead(const STeam& team) const noexcept
  {
    return team.mask != 0u ? std::countr_zero(team.mask) : team.members.front();
  }

  std::int32_t CViewPackets::ReconArmyFor(const std::int32_t view, const SEntityFacts& facts) const noexcept
  {
    if (!mTeamsOn || view < mArmySlots) {
      return view;
    }
    const STeam& team = mTeams[static_cast<std::size_t>(view - mArmySlots)];
    const std::uint32_t holders = team.mask & static_cast<std::uint32_t>(facts.blipNeedsFlush);
    return holders != 0u ? std::countr_zero(holders) : TeamLead(team);
  }

  SViewVisibility CViewPackets::VisibilityFor(const moho::Sim& sim, const std::int32_t view, const SEntityFacts& facts) const
  {
    if (!mTeamsOn) {
      return ResolveViewVisibility(sim, view, facts);
    }
    if (view < mArmySlots) {
      // An army's own view: its real units.
      return facts.kind == SEntityFacts::EKind::Unit ? ResolveViewVisibility(sim, view, facts) : SViewVisibility{};
    }
    if (facts.kind == SEntityFacts::EKind::Unit) {
      return SViewVisibility{};
    }
    const STeam& team = mTeams[static_cast<std::size_t>(view - mArmySlots)];
    if (facts.kind == SEntityFacts::EKind::Blip) {
      return ResolveViewVisibility(sim, ReconArmyFor(view, facts), facts);
    }
    // An entity of the team's shows as to its owner, which all of the team may see.
    const bool owned = facts.armyIndex >= 0 && facts.armyIndex < 32 && ((team.mask >> facts.armyIndex) & 1u) != 0u;
    return ResolveViewVisibility(sim, owned ? facts.armyIndex : TeamLead(team), facts);
  }

  std::uint32_t CViewPackets::ViewsKeeping(const moho::Sim& sim, const SEntityFacts& facts) const
  {
    if (!mTeamsOn) {
      return ViewsThatSee(sim, mPackets.size(), facts);
    }
    if (facts.destroyed) {
      return 0u;
    }
    if (facts.kind == SEntityFacts::EKind::Unit) {
      return facts.armyIndex >= 0 && facts.armyIndex < mArmySlots ? std::uint32_t{1} << facts.armyIndex : 0u;
    }
    std::uint32_t views = 0u;
    for (std::size_t index = 0; index < mTeams.size(); ++index) {
      const STeam& team = mTeams[index];
      const auto slot = std::uint32_t{1} << (static_cast<std::size_t>(mArmySlots) + index);
      if (facts.kind == SEntityFacts::EKind::Blip) {
        views |= (team.mask & static_cast<std::uint32_t>(facts.blipNeedsFlush)) != 0u ? slot : 0u;
        continue;
      }
      const bool owned = facts.armyIndex >= 0 && facts.armyIndex < 32 && ((team.mask >> facts.armyIndex) & 1u) != 0u;
      views |= CanViewSee(sim, owned ? facts.armyIndex : TeamLead(team), facts) ? slot : 0u;
    }
    return views;
  }

  bool CViewPackets::ViewVision(const SChangedView& changed, const std::size_t army, std::uint32_t& vision) const
  {
    if (changed.hasCreator) {
      vision = changed.creatorVision;
      return true;
    }
    if ((changed.before.hasVision & (std::uint32_t{1} << army)) != 0u) {
      vision = mVisions[changed.before.visions + army];
      return true;
    }
    vision = 0;
    return false;
  }

  void CViewPackets::MatchBlipViews(moho::Sim& sim, SChangedView& changed)
  {
    SBlipKey keys[kBlipViews];
    int count = 0;
    const std::size_t armies = std::min(mPackets.size(), kBlipViews);
    for (std::size_t army = 0; army < armies; ++army) {
      if (mHasView[army] == 0u) {
        continue;
      }
      const SViewVisibility visibility = VisibilityFor(sim, static_cast<std::int32_t>(army), changed.facts);
      if (!visibility.published) {
        continue;
      }
      const moho::SPerArmyReconInfo& recon = changed.target.blip->mReconDat[static_cast<std::size_t>(ReconArmyFor(static_cast<std::int32_t>(army), changed.facts))];
      std::uint32_t vision = 0;
      const bool hasVision = ViewVision(changed, army, vision);
      const SBlipKey key{
        static_cast<std::int32_t>(visibility.mode), static_cast<std::uint32_t>(recon.mReconFlags), recon.mStiMesh,
        std::bit_cast<std::uint32_t>(recon.mHealth), std::bit_cast<std::uint32_t>(recon.mMaxHealth),
        std::bit_cast<std::uint32_t>(recon.mFractionComplete), static_cast<std::uint32_t>(recon.mMaybeDead), vision, hasVision
      };
      int match = 0;
      while (match < count && !(keys[match] == key)) {
        ++match;
      }
      if (match == count) {
        keys[count] = key;
        changed.blipRecordView[count] = static_cast<std::uint8_t>(army);
        ++count;
      }
      changed.blipRecordOf[army] = static_cast<std::uint8_t>(match);
    }
    changed.blipRecordCount = static_cast<std::uint8_t>(count);
  }

  void CViewPackets::ReadChangedEntities(moho::Sim& sim)
  {
    static_assert(kBlipViews == kMaxViews);
    const std::vector<SChangedEntity>& entities = Entities();
    if (entities.size() > mChangedCapacity) {
      mChangedCapacity = entities.size() + entities.size() / 2u;
      mChanged = std::make_unique<SChangedView[]>(mChangedCapacity);
    }
    const auto read = [&](const std::size_t begin, const std::size_t end) {
      for (std::size_t i = begin; i < end; ++i) {
        SChangedView& changed = mChanged[i];
        moho::Entity& entity = *entities[i].entity;
        SDirectUpdate::STarget& target = changed.target;
        target.entity = &entity;
        target.requestRefreshUI = entities[i].requestRefreshUI;
        changed.prop = entity.IsProp();
        target.unit = changed.prop == nullptr ? entity.IsUnit() : nullptr;
        target.blip = changed.prop == nullptr && target.unit == nullptr ? entity.IsReconBlip() : nullptr;
        target.shared = nullptr;
        changed.facts = ReadEntityFacts(entity);
        const SEntityViews* const found = mEntityViews.Find(static_cast<std::uint32_t>(entity.id_));
        changed.before = found != nullptr ? *found : SEntityViews{};
        changed.created.store(changed.before.created, std::memory_order_relaxed);
        changed.hasVision.store(changed.before.hasVision, std::memory_order_relaxed);
        changed.hasCreator = false;
        // Plan WPR.35: the creation goes with the update, as the record both make is shared.
        if (mSharedRecords != nullptr && target.unit == nullptr && target.blip == nullptr && CSharedEntityRecords::Shareable(entity)) {
          target.shared = &mSharedRecords->Update(i);
        }
        if (target.unit != nullptr) {
          // `ResolveViewVisibility`: a unit is published to its own army alone.
          const std::int32_t own = changed.facts.armyIndex;
          changed.mayAct = changed.before.created | (own >= 0 && static_cast<std::size_t>(own) < kMaxViews ? std::uint32_t{1} << own : 0u);
        } else if (target.blip != nullptr) {
          // A blip: to the armies whose recon record needs a flush.
          changed.mayAct = changed.before.created;
          if (mTeamsOn) {
            for (std::size_t team = 0; team < mTeams.size(); ++team) {
              if ((mTeams[team].mask & static_cast<std::uint32_t>(changed.facts.blipNeedsFlush)) != 0u) {
                changed.mayAct |= std::uint32_t{1} << (static_cast<std::size_t>(mArmySlots) + team);
              }
            }
          } else {
            changed.mayAct |= static_cast<std::uint32_t>(changed.facts.blipNeedsFlush);
          }
          if (moho::Unit* const creator = target.blip->mCreator.GetObjectPtr(); creator != nullptr) {
            // 0x005BF00A..0x005BF027: the creator's vision range, written into the blip itself.
            changed.creatorVision = static_cast<moho::Entity*>(creator)->mVarDat.mIntelAttributes.GetRange(moho::ENTATTR_Vision);
            changed.hasCreator = true;
          }
          changed.blipRecordCount = 0;
          if (mDirectUpdates && mSharedRecords != nullptr && CSharedEntityRecords::Shareable(entity)) {
            MatchBlipViews(sim, changed);
          }
        } else {
          changed.mayAct = mTeamsOn ? mTeamBits | changed.before.created : ~std::uint32_t{0};
        }
      }
    };
    if (mParallel && entities.size() > kChangedGrain) {
      moho::CSimWorkerPool::Get().ParallelFor(entities.size(), kChangedGrain, read);
    } else {
      read(0u, entities.size());
    }
    MarkPhase(EViewPhase::Read);

    // The blocks of vision ranges and blip hashes stay in place while the views fill them.
    for (std::size_t i = 0; i < entities.size(); ++i) {
      SChangedView& changed = mChanged[i];
      const bool needsVisions = changed.hasCreator && changed.before.visions == kNoVisions;
      const bool needsHashes = changed.target.blip != nullptr && changed.blipRecordCount != 0u && changed.before.blipHashes == kNoVisions;
      if (!needsVisions && !needsHashes) {
        continue;
      }
      if (needsVisions) {
        if (!mFreeVisions.empty()) {
          changed.before.visions = mFreeVisions.back();
          mFreeVisions.pop_back();
        } else {
          changed.before.visions = static_cast<std::uint32_t>(mVisions.size());
          mVisions.grow_to(mVisions.size() + kMaxViews);
        }
      }
      if (needsHashes) {
        if (!mFreeBlipHashes.empty()) {
          changed.before.blipHashes = mFreeBlipHashes.back();
          mFreeBlipHashes.pop_back();
        } else {
          changed.before.blipHashes = static_cast<std::uint32_t>(mBlipHashes.size());
          mBlipHashes.grow_to(mBlipHashes.size() + kMaxViews);
        }
        for (std::size_t view = 0; view < kMaxViews; ++view) {
          mBlipHashes[changed.before.blipHashes + view] = 0u;
        }
      }
      const auto id = static_cast<std::uint32_t>(changed.target.entity->id_);
      if (SEntityViews* const found = mEntityViews.Find(id); found != nullptr) {
        found->visions = changed.before.visions;
        found->blipHashes = changed.before.blipHashes;
      } else {
        (void)mEntityViews.Insert(id, changed.before);
      }
    }
    MarkPhase(EViewPhase::ReadBlocks);

    // One update for each group of views a blip shows the same to.
    if (mSharedRecords != nullptr) {
      std::size_t blipRecords = 0;
      mBlipIndices.clear();
      for (std::size_t i = 0; i < entities.size(); ++i) {
        SChangedView& changed = mChanged[i];
        if (changed.target.blip != nullptr) {
          changed.firstBlipRecord = static_cast<std::uint32_t>(blipRecords);
          blipRecords += changed.blipRecordCount;
          if (changed.blipRecordCount != 0u) {
            mBlipIndices.push_back(static_cast<std::uint32_t>(i));
          }
        }
      }
      mSharedRecords->ReserveBlipRecords(blipRecords);
      // Over the blips alone, in small chunks: their ids keep them together in the change set, so
      // chunks of all its entities left a few workers with every blip.
      const auto fill = [&](const std::size_t begin, const std::size_t end) {
        moho::SSTIEntityVariableData block;
        for (std::size_t at = begin; at < end; ++at) {
          const SChangedView& changed = mChanged[mBlipIndices[at]];
          for (std::size_t k = 0; k < changed.blipRecordCount; ++k) {
            const std::size_t view = changed.blipRecordView[k];
            std::uint32_t vision = 0;
            const bool hasVision = ViewVision(changed, view, vision);
            mSharedRecords->FillBlipRecord(
              mSharedRecords->BlipRecord(changed.firstBlipRecord + k), block, *changed.target.blip, changed.target.requestRefreshUI,
              static_cast<std::size_t>(ReconArmyFor(static_cast<std::int32_t>(view), changed.facts)), VisibilityFor(sim, static_cast<std::int32_t>(view), changed.facts).mode, vision, hasVision
            );
          }
        }
      };
      if (mParallel && mBlipIndices.size() > kBlipGrain) {
        moho::CSimWorkerPool::Get().ParallelFor(mBlipIndices.size(), kBlipGrain, fill);
      } else {
        fill(0u, mBlipIndices.size());
      }
    }
  }

  void CViewPackets::WriteChangedEntities()
  {
    for (std::size_t i = 0; i < Entities().size(); ++i) {
      const SChangedView& changed = mChanged[i];
      const auto id = static_cast<std::uint32_t>(changed.target.entity->id_);
      // Every view unpublishes an entity in its destroy pass: a later entity with this id is a new one.
      if (changed.facts.destroyed) {
        if (changed.before.visions != kNoVisions) {
          mFreeVisions.push_back(changed.before.visions);
        }
        if (changed.before.blipHashes != kNoVisions) {
          mFreeBlipHashes.push_back(changed.before.blipHashes);
        }
        mEntityViews.Erase(id);
        continue;
      }
      const std::uint32_t created = changed.created.load(std::memory_order_relaxed);
      const std::uint32_t hasVision = changed.hasVision.load(std::memory_order_relaxed);
      if (created == changed.before.created && hasVision == changed.before.hasVision) {
        continue;
      }
      SEntityViews* const found = mEntityViews.Find(id);
      SEntityViews& views = found != nullptr ? *found : mEntityViews.Insert(id, changed.before);
      views.created = created;
      views.hasVision = hasVision;
    }
  }

  void CViewPackets::SyncForView(moho::Sim& sim, const std::int32_t army, SChangedView& changed, moho::SSyncData& out)
  {
    moho::Entity& entity = *changed.target.entity;
    const SViewVisibility visibility = VisibilityFor(sim, army, changed.facts);
    moho::Prop* const prop = changed.prop;
    moho::Unit* const unit = changed.target.unit;
    moho::ReconBlip* const blip = changed.target.blip;
    const std::uint32_t bit = std::uint32_t{1} << army;
    const bool wasCreated = (changed.before.created & bit) != 0u;

    if (!visibility.published) {
      // `Entity::Sync` 0x0067A0EA..0x0067A102 / `Prop::Sync` 0x006FA2B8..0x006FA2F1.
      if (wasCreated) {
        if (prop != nullptr && prop->mReclaimTerminated) {
          out.mEraseIds.push_back(entity.id_);
        } else {
          out.mDeleteIds.push_back(entity.id_);
        }
        changed.created.fetch_and(~bit, std::memory_order_relaxed);
      }
      return;
    }

    if (!wasCreated) {
      changed.created.fetch_or(bit, std::memory_order_relaxed);
    }
    const bool shared = changed.target.shared != nullptr;
    if (!wasCreated && !shared) {
      if (unit != nullptr || blip != nullptr) {
        // `Unit::CreateInterface` 0x006AC2C0 / `ReconBlip::CreateInterface` 0x005BEE90.
        moho::SCreateUnitParams params{};
        params.mEntityId = entity.id_;
        params.mBlueprint = entity.BluePrint;
        params.mTickCreated = static_cast<std::uint32_t>(entity.mTickCreated);
        if (unit != nullptr) {
          params.mConstDat.mBuildStateTag = unit->mConstDat.mBuildStateTag;
          params.mConstDat.mStatsRoot = unit->mConstDat.mStatsRoot;
          params.mConstDat.mFake = unit->mConstDat.mFake;
        } else {
          params.mConstDat.mBuildStateTag = blip->mUnitConstDat.mBuildStateTag;
          params.mConstDat.mStatsRoot = blip->mUnitConstDat.mStatsRoot;
          params.mConstDat.mFake = blip->mUnitConstDat.mFake;
        }
        out.mNewUnits.push_back(params);
      } else {
        // `Entity::CreateInterface` 0x0067A220.
        moho::SCreateEntityParams params{};
        params.mEntityId = entity.id_;
        params.mBlueprint = entity.BluePrint;
        params.mTickCreated = static_cast<std::uint32_t>(entity.mTickCreated);
        out.mNewEntities.push_back(params);
      }
    }

    // The vision range this view last copied from the blip's creator.
    std::uint32_t vision = 0;
    bool hasVision = false;
    if (blip != nullptr) {
      if (changed.hasCreator) {
        mVisions[changed.before.visions + static_cast<std::size_t>(army)] = changed.creatorVision;
        if ((changed.before.hasVision & bit) == 0u) {
          changed.hasVision.fetch_or(bit, std::memory_order_relaxed);
        }
        vision = changed.creatorVision;
        hasVision = true;
      } else if ((changed.before.hasVision & bit) != 0u) {
        vision = mVisions[changed.before.visions + static_cast<std::size_t>(army)];
        hasVision = true;
      }
    }

    if (mDirectUpdates) {
      // Most of a late game's blip updates are what the view's client holds already: nothing to do.
      // An update the view takes the long way (a blip with a sound, say) leaves no hash to match.
      const SBlipRecord* blipRecord = nullptr;
      if (blip != nullptr && changed.blipRecordCount != 0u) {
        blipRecord = &mSharedRecords->BlipRecord(changed.firstBlipRecord + changed.blipRecordOf[static_cast<std::size_t>(army)]);
        std::uint64_t& held = mBlipHashes[changed.before.blipHashes + static_cast<std::size_t>(army)];
        if (wasCreated && held == blipRecord->hash) {
          return;
        }
        held = blipRecord->hash;
      } else if (blip != nullptr && changed.before.blipHashes != kNoVisions) {
        mBlipHashes[changed.before.blipHashes + static_cast<std::size_t>(army)] = 0u;
      }
      // Plan WPR.35: the builder reads the sim directly, while it is stopped for this beat.
      SDirectUpdate& direct = mDirect[static_cast<std::size_t>(army)].emplace_back();
      if (shared) {
        changed.target.shared->UseMode(visibility.mode);
        direct.created = !wasCreated;
      }
      direct.target = &changed.target;
      direct.blipRecord = blipRecord;
      direct.army = static_cast<std::uint8_t>(ReconArmyFor(army, changed.facts));
      direct.mode = static_cast<std::uint8_t>(visibility.mode);
      direct.vision = vision;
      direct.hasVision = hasVision;
      return;
    }

    moho::SSTIEntityVariableData block = EntityBlockForView(entity, visibility, changed.target.requestRefreshUI);

    if (unit != nullptr) {
      moho::SUnitVariableUpdateEntry& update = out.mUnitUpdates.emplace_back();
      update.mEntityId = entity.id_;
      update.mVariableData = unit->VarDat();
      update.mReconFlags = kUnitReconFlags;
    } else if (blip != nullptr) {
      const moho::SPerArmyReconInfo& recon = blip->mReconDat[static_cast<std::size_t>(army)];
      moho::Unit* const creator = blip->mCreator.GetObjectPtr();
      if (hasVision) {
        block.mIntelAttributes.SetIntelRadius(moho::ENTATTR_Vision, static_cast<int>(vision));
      }

      moho::SUnitVariableUpdateEntry& update = out.mUnitUpdates.emplace_back();
      update.mEntityId = entity.id_;
      update.mVariableData = blip->mUnitVarDat;
      update.mVariableData.mSharedPose = recon.mPose;
      update.mVariableData.mPriorSharedPose = recon.mPriorPose;
      if (creator != nullptr) {
        update.mVariableData.mStunTicks = creator->mUnitVarDat.mStunTicks != 0 ? 1 : 0;
      }
      update.mReconFlags = static_cast<std::int32_t>(recon.mReconFlags);

      // 0x005BF168..0x005BF1C4: the entity block from the recon record.
      block.mMeshBlueprint = recon.mStiMesh;
      block.mScmResource = recon.mMesh;
      block.mHealth = recon.mHealth;
      block.mMaxHealth = recon.mMaxHealth;
      block.mFractionComplete = recon.mFractionComplete;
      block.mIsDead = recon.mMaybeDead;

      // `ReconBlip::SyncInterface`: only an active real contact in current line of sight
      // publishes its creator's scroll.
      if (!blip->IsFake() && creator != nullptr && recon.mNeedsFlush != 0u && recon.mMaybeDead == 0u &&
          (recon.mReconFlags & static_cast<std::uint32_t>(moho::RECON_LOSNow)) != 0u) {
        const moho::SSTIEntityVariableData& creatorData = static_cast<moho::Entity*>(creator)->mVarDat;
        block.mScrollBeatStart = creatorData.mScrollBeatStart;
        block.mScrollBeatEnd = creatorData.mScrollBeatEnd;
      }
    }

    moho::SEntityVariableUpdateEntry& update = out.mEntityUpdates.emplace_back();
    update.mEntityId = entity.id_;
    update.mVariableData = std::move(block);
  }
} // namespace faf::remote
