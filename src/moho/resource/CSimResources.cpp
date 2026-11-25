#include "CSimResources.h"

#include "legacy/math/X87Math.h"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <limits>
#include <new>
#include <vector>
#include "legacy/thread/Mutex.h"
#include "moho/console/CConCommand.h"

namespace
{
  /**
   * Shared inlined corner conversion of 0x00545E80 / 0x00545FD0 / 0x005465C0:
   * `fld` + `fistp` (round-to-nearest under the caller's x87 control word, not
   * truncation) into a 16-bit cell lane (`movsx reg, word ptr`). A Mass marker
   * at x = 875.4999 lands its 1x1 deposit on cell 875, which truncation put on
   * cell 874 -- and an extractor on cell 875 then failed DepositIsInArea.
   */
  [[nodiscard]] std::int16_t DepositCornerCell(
    const float centre,
    const int extent
  ) noexcept
  {
    return static_cast<std::int16_t>(fa::RoundToInt(centre - static_cast<float>(extent) * 0.5f));
  }

  [[nodiscard]] gpg::Rect2i BuildRectFromPointAndSize(
    const Wm3::Vec3f& point,
    const Wm3::Vec2i& size
  ) noexcept
  {
    const int x0 = DepositCornerCell(point.x, size.x);
    const int z0 = DepositCornerCell(point.z, size.y);
    return {x0, z0, x0 + size.x, z0 + size.y};
  }

  [[nodiscard]] bool HasPositiveArea(
    const gpg::Rect2i& rect
  ) noexcept
  {
    return rect.x0 < rect.x1 && rect.z0 < rect.z1;
  }

  [[nodiscard]] bool HasPositiveArea(
    const gpg::Rect2f& rect
  ) noexcept
  {
    return rect.x0 < rect.x1 && rect.z0 < rect.z1;
  }

  [[nodiscard]] bool RectsOverlapStrict(
    const gpg::Rect2i& lhs,
    const gpg::Rect2i& rhs
  ) noexcept
  {
    return lhs.x0 < rhs.x1 && rhs.x0 < lhs.x1 && lhs.z0 < rhs.z1 && rhs.z0 < lhs.z1 && HasPositiveArea(lhs) &&
      HasPositiveArea(rhs);
  }

  /**
   * DepositIsInArea's test of one deposit, as the binary orders it (see that function's comment).
   */
  [[nodiscard]] bool DepositContainsOrIsContained(
    const gpg::Rect2i& rect,
    const gpg::Rect2i& area
  ) noexcept
  {
    if (area.x0 <= rect.x0) {
      if (area.x1 >= rect.x1 && rect.z0 >= area.z0 && area.z1 >= rect.z1) {
        return true;
      }
      if (area.x0 < rect.x0) {
        return false;
      }
    }
    return rect.x1 >= area.x1 && area.z0 >= rect.z0 && rect.z1 >= area.z1;
  }

  /**
   * AreaHasDeposit's test of one deposit of `type`.
   */
  [[nodiscard]] bool DepositOverlapsArea(
    const moho::ResourceDeposit& deposit,
    const moho::EDepositType type,
    const gpg::Rect2f& area
  ) noexcept
  {
    float minX = 0.0f;
    float minZ = 0.0f;
    float maxX = 0.0f;
    float maxZ = 0.0f;
    if (type == moho::kMass) {
      minX = static_cast<float>(deposit.footprintRect.x0) - 0.5f;
      minZ = static_cast<float>(deposit.footprintRect.z0) - 0.5f;
      maxX = static_cast<float>(deposit.footprintRect.x1) + 0.5f;
      maxZ = static_cast<float>(deposit.footprintRect.z1) + 0.5f;
    } else if (type == moho::kHydrocarbon) {
      minX = static_cast<float>(deposit.footprintRect.x0) - 1.5f;
      minZ = static_cast<float>(deposit.footprintRect.z0) - 1.5f;
      maxX = static_cast<float>(deposit.footprintRect.x1) + 1.5f;
      maxZ = static_cast<float>(deposit.footprintRect.z1) + 1.5f;
    }

    const bool overlaps = maxX > area.x0 && area.x1 > minX && maxZ > area.z0 && area.z1 > minZ;
    return overlaps && HasPositiveArea(area) && maxX > minX && minZ < maxZ;
  }

  /**
   * Engine addition (sim_DepositIndex): each thread's index of one deposit list, the deposits of
   * each type sorted by `x0`. Both queries only ask whether any deposit passes their test, so testing
   * every deposit whose `x0` could pass, in any order, gives the scan's answer. Rebuilt when the
   * list's owner, buffer or length differs, or `gDepositEpoch` moved (a deposit added, a resources
   * object made or freed).
   */
  std::atomic<std::uint32_t> gDepositEpoch{1u};

  struct DepositTypeIndex
  {
    std::vector<std::uint32_t> byX0; // indices into the list, ordered by footprintRect.x0
    std::vector<int> x0;             // the same order's x0, for the binary search
    std::int64_t minWidth = 0;
    std::int64_t maxWidth = 0;
  };

  struct DepositIndex
  {
    const void* owner = nullptr;
    const moho::ResourceDeposit* data = nullptr;
    std::size_t size = 0;
    std::uint32_t epoch = 0;
    DepositTypeIndex types[2]; // kMass, kHydrocarbon
  };

  thread_local DepositIndex tDepositIndex;

  [[nodiscard]] const DepositTypeIndex* FindDepositTypeIndex(
    const void* const owner,
    const fa::vector<moho::ResourceDeposit>& deposits,
    const moho::EDepositType type
  )
  {
    if (type != moho::kMass && type != moho::kHydrocarbon) {
      return nullptr;
    }
    DepositIndex& index = tDepositIndex;
    const std::uint32_t epoch = gDepositEpoch.load(std::memory_order_acquire);
    if (
      index.owner != owner || index.data != deposits.data() || index.size != deposits.size() || index.epoch != epoch
    ) {
      index.owner = owner;
      index.data = deposits.data();
      index.size = deposits.size();
      index.epoch = epoch;
      for (int slot = 0; slot < 2; ++slot) {
        DepositTypeIndex& typeIndex = index.types[slot];
        const moho::EDepositType slotType = slot == 0 ? moho::kMass : moho::kHydrocarbon;
        typeIndex.byX0.clear();
        typeIndex.x0.clear();
        typeIndex.minWidth = 0;
        typeIndex.maxWidth = 0;
        bool first = true;
        for (std::size_t i = 0; i < deposits.size(); ++i) {
          const moho::ResourceDeposit& deposit = deposits.data()[i];
          if (deposit.depositType != slotType) {
            continue;
          }
          typeIndex.byX0.push_back(static_cast<std::uint32_t>(i));
          const std::int64_t width =
            static_cast<std::int64_t>(deposit.footprintRect.x1) - static_cast<std::int64_t>(deposit.footprintRect.x0);
          typeIndex.minWidth = first ? width : (std::min)(typeIndex.minWidth, width);
          typeIndex.maxWidth = first ? width : (std::max)(typeIndex.maxWidth, width);
          first = false;
        }
        const moho::ResourceDeposit* const base = deposits.data();
        std::stable_sort(
          typeIndex.byX0.begin(), typeIndex.byX0.end(), [base](const std::uint32_t a, const std::uint32_t b) {
          return base[a].footprintRect.x0 < base[b].footprintRect.x0;
        }
        );
        typeIndex.x0.reserve(typeIndex.byX0.size());
        for (const std::uint32_t i : typeIndex.byX0) {
          typeIndex.x0.push_back(base[i].footprintRect.x0);
        }
      }
    }
    return &index.types[type == moho::kMass ? 0 : 1];
  }

  /// Calls `test(deposit)` for each indexed deposit whose x0 lies in [lo, hi]; true at the first pass.
  template <typename Test>
  [[nodiscard]] bool AnyIndexedDepositInX0Range(
    const DepositTypeIndex& typeIndex,
    const moho::ResourceDeposit* const deposits,
    const std::int64_t lo,
    const std::int64_t hi,
    Test test
  )
  {
    if (lo > hi) {
      return false;
    }
    const auto begin =
      std::lower_bound(typeIndex.x0.begin(), typeIndex.x0.end(), lo, [](const int value, const std::int64_t bound) {
      return static_cast<std::int64_t>(value) < bound;
    });
    for (auto it = begin; it != typeIndex.x0.end() && static_cast<std::int64_t>(*it) <= hi; ++it) {
      if (test(deposits[typeIndex.byX0[static_cast<std::size_t>(it - typeIndex.x0.begin())]])) {
        return true;
      }
    }
    return false;
  }
} // namespace

namespace moho
{
  gpg::RType* CSimResources::sType = nullptr;

  void RES_NoteDepositsChanged() noexcept
  {
    gDepositEpoch.fetch_add(1u, std::memory_order_acq_rel);
  }

  /**
   * Engine addition: `DepositIsInArea` and `AreaHasDeposit` test only the deposits whose position
   * could pass, found in a per-thread index sorted by x (see `FindDepositTypeIndex`). Live; both
   * answer whether any deposit passes, so the answer is the full scan's.
   */
  bool sim_DepositIndex = true;
  TConVar<bool> gTConVar_sim_DepositIndex(
    "sim_DepositIndex",
    "Find the deposits a build-site check can touch through an index instead of testing every deposit (same results).",
    &sim_DepositIndex
  );

  /**
   * Address: 0x00545DC0 (FUN_00545DC0, ??0CSimResources@Moho@@QAE@@Z)
   *
   * What it does:
   * Constructs mutex/vector members for resource deposit bookkeeping.
   */
  CSimResources::CSimResources()
  {
    gDepositEpoch.fetch_add(1u, std::memory_order_acq_rel); // sim_DepositIndex
  }

  /**
   * Address: 0x00546E90 (FUN_00546E90, Moho::CSimResources::operator new)
   *
   * What it does:
   * Allocates and constructs one `CSimResources` instance.
   */
  CSimResources* CSimResources::Create()
  {
    void* const storage = ::operator new(sizeof(CSimResources), std::nothrow);
    if (storage == nullptr) {
      return nullptr;
    }

    try {
      return ::new (storage) CSimResources();
    } catch (...) {
      ::operator delete(storage);
      throw;
    }
  }

  /**
   * Address: 0x00545E10 (FUN_00545E10, core dtor body)
   * Address: 0x00546A00 (FUN_00546A00, Moho::CSimResources::dtr)
   *
   * What it does:
   * Destructs mutex/vector members (deleting-thunk behavior is compiler
   * generated).
   */
  CSimResources::~CSimResources()
  {
    gDepositEpoch.fetch_add(1u, std::memory_order_acq_rel); // sim_DepositIndex
  }

  /**
   * Address: 0x00545F10 (FUN_00545F10, Moho::CSimResources::AddDeposit)
   *
   * What it does:
   * Adds one deposit rectangle and type under the resource lock.
   */
  void CSimResources::AddDeposit(
    const EDepositType type,
    gpg::Rect2i* const pos
  )
  {
    fa::mutex::scoped_lock lock(lock_);

    ResourceDeposit deposit{};
    deposit.footprintRect = *pos;
    deposit.depositType = type;
    deposits_.push_back(deposit);
    gDepositEpoch.fetch_add(1u, std::memory_order_acq_rel); // sim_DepositIndex
  }

  /**
   * Address: 0x00545E80 (FUN_00545E80, Moho::CSimResources::AddDepositPoint)
   *
   * What it does:
   * Converts center+size to grid rect and forwards to AddDeposit.
   */
  void CSimResources::AddDepositPoint(
    EDepositType type,
    Wm3::Vec3f* pos,
    Wm3::Vec2i* size
  )
  {
    gpg::Rect2i rect = BuildRectFromPointAndSize(*pos, *size);
    AddDeposit(type, &rect);
  }

  /**
   * Address: 0x00545FC0 (FUN_00545FC0, Moho::CSimResources::GetDeposits1)
   */
  const fa::vector<ResourceDeposit>& CSimResources::GetDeposits() const
  {
    return deposits_;
  }

  /**
   * Address: 0x00545FB0 (FUN_00545FB0, Moho::CSimResources::GetDeposits2)
   */
  fa::vector<ResourceDeposit>& CSimResources::GetDeposits()
  {
    return deposits_;
  }

  /**
   * Address: 0x00546060 (FUN_00546060, Moho::CSimResources::IsDepositAt)
   *
   * What it does:
   * Tests strict rectangle overlap against deposits of the requested type.
   */
  bool CSimResources::IsDepositAt(
    gpg::Rect2i* pos,
    EDepositType type
  )
  {
    fa::mutex::scoped_lock lock(lock_);
    for (const ResourceDeposit& deposit : deposits_) {
      if (deposit.depositType == type && RectsOverlapStrict(*pos, deposit.footprintRect)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Address: 0x00545FD0 (FUN_00545FD0, Moho::CSimResources::IsDepositAtPoint)
   *
   * What it does:
   * Converts center+size to grid rect and reuses IsDepositAt.
   */
  bool CSimResources::IsDepositAtPoint(
    Wm3::Vec3f* pos,
    Wm3::Vec2i* size,
    EDepositType type
  )
  {
    gpg::Rect2i rect = BuildRectFromPointAndSize(*pos, *size);
    return IsDepositAt(&rect, type);
  }

  /**
   * Address: 0x00546470 (FUN_00546470, Moho::CSimResources::DepositCollides)
   *
   * What it does:
   * Emits deposits whose terrain AABB intersects the provided solid, optionally
   * filtering by deposit type.
   */
  void CSimResources::DepositCollides(
    CGeomSolid3* solid,
    CHeightField* field,
    gpg::fastvector<ResourceDeposit>* outDeposits,
    EDepositType type
  )
  {
    for (const ResourceDeposit& deposit : deposits_) {
      if (type != kNone && deposit.depositType != type) {
        continue;
      }
      if (deposit.Intersects(*solid, *field)) {
        outDeposits->PushBack(deposit);
      }
    }
  }

  /**
   * Address: 0x00546650 (FUN_00546650, Moho::CSimResources::DepositIsInArea)
   *
   * What it does:
   * Returns true when the query area and one deposit of the requested type
   * are in a containment relation - either the area encloses the deposit or
   * the deposit encloses the area. This is the gate `OCCUPY_Check` runs for
   * `RULEUBR_OnMassDeposit` / `RULEUBR_OnHydrocarbonDeposit`, i.e. the only
   * thing that keeps a mass extractor on its mass point.
   *
   * The shipped body picks which way round to test from the two `x0`s
   * (0x005466BC `cmp esi, edx` / `jg`), and the two arms are exact mirrors of
   * each other:
   *
   *   area.x0 <= deposit.x0  ->  area encloses deposit
   *       0x005466C0  area.x1 >= deposit.x1
   *       0x005466C8  deposit.z0 >= area.z0
   *       0x005466D0  area.z1 >= deposit.z1
   *   area.x0 >= deposit.x0  ->  deposit encloses area
   *       0x005466DC  deposit.x1 >= area.x1
   *       0x005466E4  area.z0 >= deposit.z0
   *       0x005466EC  deposit.z1 >= area.z1
   *
   * When the first arm fails, 0x005466D8 re-tests `area.x0 < deposit.x0` and
   * only advances to the next deposit on a *strict* less-than; equal `x0`s
   * fall through into the second arm, so a deposit is given both tests.
   *
   * Both arms had previously been recovered with the *same* comparison - the
   * enclosing arm carried the enclosed arm's three tests. For the 1x1 rects
   * this function is actually called with (a mass point and a mass
   * extractor's footprint), that degenerates to "area.x0 <= deposit.x0 &&
   * area.z0 == deposit.z0", i.e. a mass extractor could be placed on any cell
   * in the same Z row at or west of any mass point on the map.
   */
  bool CSimResources::DepositIsInArea(
    EDepositType type,
    gpg::Rect2i* area
  )
  {
    fa::mutex::scoped_lock lock(lock_);
    if (sim_DepositIndex) {
      if (const DepositTypeIndex* const index = FindDepositTypeIndex(this, deposits_, type)) {
        // A pass needs x0 in [area.x0, area.x1 - width] (the area encloses the deposit) or
        // [area.x1 - width, area.x0] (the deposit encloses the area), for the deposit's own width.
        const std::int64_t ax0 = area->x0;
        const std::int64_t ax1 = area->x1;
        const std::int64_t lo = (std::min)(ax0, ax1 - index->maxWidth);
        const std::int64_t hi = (std::max)(ax1 - index->minWidth, ax0);
        const gpg::Rect2i query = *area;
        return AnyIndexedDepositInX0Range(*index, deposits_.data(), lo, hi, [&query](const ResourceDeposit& deposit) {
          return DepositContainsOrIsContained(deposit.footprintRect, query);
        });
      }
    }
    for (const ResourceDeposit& deposit : deposits_) {
      if (deposit.depositType != type) {
        continue;
      }
      if (DepositContainsOrIsContained(deposit.footprintRect, *area)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Address: 0x005465C0 (FUN_005465C0, Moho::CSimResources::DepositIsInAreaPoint)
   *
   * What it does:
   * Converts center+size to grid rect and reuses DepositIsInArea.
   */
  bool CSimResources::DepositIsInAreaPoint(
    EDepositType type,
    Wm3::Vec3f* pos,
    Wm3::Vec2i* size
  )
  {
    gpg::Rect2i rect = BuildRectFromPointAndSize(*pos, *size);
    return DepositIsInArea(type, &rect);
  }

  /**
   * Address: 0x00546760 (FUN_00546760, Moho::CSimResources::FindClosestDespoit)
   *
   * What it does:
   * Finds the closest deposit center of matching type within radius.
   */
  bool CSimResources::FindClosestDeposit(
    GridPos* from,
    GridPos* outPos,
    float radius,
    EDepositType type
  )
  {
    float closestDistance = (std::numeric_limits<float>::max)();
    int closestX = 0;
    int closestZ = 0;
    bool found = false;

    for (const ResourceDeposit& deposit : deposits_) {
      if (deposit.depositType != type) {
        continue;
      }

      const int centerX = deposit.footprintRect.x0 + ((deposit.footprintRect.x1 - deposit.footprintRect.x0) >> 1);
      const int centerZ = deposit.footprintRect.z0 + (deposit.footprintRect.z1 - deposit.footprintRect.z0) / 2;

      const float dx = static_cast<float>(from->x - centerX);
      const float dz = static_cast<float>(from->z - centerZ);
      const float distance = std::sqrt(dx * dx + dz * dz);

      if (distance < closestDistance && distance <= radius) {
        closestDistance = distance;
        closestX = centerX;
        closestZ = centerZ;
        found = true;
      }
    }

    if (found) {
      outPos->x = closestX;
      outPos->z = closestZ;
    }
    return found;
  }

  /**
   * Address: 0x00546860 (FUN_00546860, Moho::CSimResources::AreaHasDeposit)
   *
   * What it does:
   * Checks area/deposit overlap with type-specific footprint expansion.
   */
  bool CSimResources::AreaHasDeposit(
    EDepositType type,
    gpg::Rect2f* area
  )
  {
    fa::mutex::scoped_lock lock(lock_);
    // NaN and huge coordinates take the scan: the bounds below need them as 64-bit integers.
    if (sim_DepositIndex && area->x0 > -1.0e9f && area->x0 < 1.0e9f && area->x1 > -1.0e9f && area->x1 < 1.0e9f) {
      if (const DepositTypeIndex* const index = FindDepositTypeIndex(this, deposits_, type)) {
        // A pass needs x1 + margin > area.x0 and area.x1 > x0 - margin (margin 0.5 or 1.5), so x0 lies
        // within these bounds, widened by a cell against float rounding.
        const double margin = type == kMass ? 0.5 : 1.5;
        const std::int64_t lo =
          static_cast<std::int64_t>(std::floor(static_cast<double>(area->x0) - margin)) - index->maxWidth - 1;
        const std::int64_t hi = static_cast<std::int64_t>(std::floor(static_cast<double>(area->x1) + margin)) + 1;
        const gpg::Rect2f query = *area;
        return AnyIndexedDepositInX0Range(
          *index, deposits_.data(), lo, hi, [&query, type](const ResourceDeposit& deposit) {
          return DepositOverlapsArea(deposit, type, query);
        }
        );
      }
    }
    for (const ResourceDeposit& deposit : deposits_) {
      if (deposit.depositType != type) {
        continue;
      }
      if (DepositOverlapsArea(deposit, type, *area)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Source parity: FAF binary patch helper `SimGetDepositsAroundPoint`.
   *
   * What it does:
   * Enumerates deposit centers around a query point and emits matching deposits
   * with Euclidean center distance.
   */
  void CSimResources::GetDepositsAroundPoint(
    const float x,
    const float z,
    float radius,
    const EDepositType type,
    gpg::fastvector<ResourceDepositDistance>* const outDeposits
  ) const
  {
    if (!outDeposits) {
      return;
    }

    outDeposits->Clear();

    // FAF patch parity (`SimGetDepositsAroundPoint`): early-out only for NaN.
    const float nanGuard = x + z + radius;
    if (nanGuard != nanGuard) {
      return;
    }

    radius *= radius;

    for (const ResourceDeposit& deposit : deposits_) {
      if (type != kNone && type != deposit.depositType) {
        continue;
      }

      const float centerX =
        (static_cast<float>(deposit.footprintRect.x0) + static_cast<float>(deposit.footprintRect.x1)) * 0.5f;
      const float centerZ =
        (static_cast<float>(deposit.footprintRect.z0) + static_cast<float>(deposit.footprintRect.z1)) * 0.5f;
      const float dx = centerX - x;
      const float dz = centerZ - z;
      const float distanceSquared = dx * dx + dz * dz;
      if (distanceSquared > radius) {
        continue;
      }

      ResourceDepositDistance hit{};
      hit.deposit = deposit;
      hit.centerDistance = std::sqrt(distanceSquared);
      outDeposits->PushBack(hit);
    }
  }
} // namespace moho
