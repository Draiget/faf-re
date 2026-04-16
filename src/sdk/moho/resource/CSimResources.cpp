#include "CSimResources.h"

#include <cmath>
#include <limits>
#include <new>

namespace
{
  [[nodiscard]] gpg::Rect2i BuildRectFromPointAndSize(const Wm3::Vec3f& point, const Wm3::Vec2i& size) noexcept
  {
    const int x0 = static_cast<int>(point.x - static_cast<float>(size.x) * 0.5f);
    const int z0 = static_cast<int>(point.z - static_cast<float>(size.y) * 0.5f);
    return {x0, z0, x0 + size.x, z0 + size.y};
  }

  [[nodiscard]] bool HasPositiveArea(const gpg::Rect2i& rect) noexcept
  {
    return rect.x0 < rect.x1 && rect.z0 < rect.z1;
  }

  [[nodiscard]] bool HasPositiveArea(const gpg::Rect2f& rect) noexcept
  {
    return rect.x0 < rect.x1 && rect.z0 < rect.z1;
  }

  [[nodiscard]] bool RectsOverlapStrict(const gpg::Rect2i& lhs, const gpg::Rect2i& rhs) noexcept
  {
    return lhs.x0 < rhs.x1 && rhs.x0 < lhs.x1 && lhs.z0 < rhs.z1 && rhs.z0 < lhs.z1 && HasPositiveArea(lhs) &&
      HasPositiveArea(rhs);
  }
} // namespace

namespace moho
{
  gpg::RType* CSimResources::sType = nullptr;

  /**
   * Address: 0x00545DC0 (??0CSimResources@Moho@@QAE@@Z)
   *
   * What it does:
   * Constructs mutex/vector members for resource deposit bookkeeping.
   */
  CSimResources::CSimResources() = default;

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
   * Address: 0x00546A00 (Moho::CSimResources::dtr)
   *
   * What it does:
   * Destructs mutex/vector members (deleting-thunk behavior is compiler
   * generated).
   */
  CSimResources::~CSimResources() = default;

  /**
   * Address: 0x00545F10 (Moho::CSimResources::AddDeposit)
   *
   * What it does:
   * Adds one deposit rectangle and type under the resource lock.
   */
  void CSimResources::AddDeposit(const EDepositType type, gpg::Rect2i* const pos)
  {
    boost::mutex::scoped_lock lock(lock_);

    ResourceDeposit deposit{};
    deposit.footprintRect = *pos;
    deposit.depositType = type;
    deposits_.push_back(deposit);
  }

  /**
   * Address: 0x00545E80 (Moho::CSimResources::AddDepositPoint)
   *
   * What it does:
   * Converts center+size to grid rect and forwards to AddDeposit.
   */
  void CSimResources::AddDepositPoint(EDepositType type, Wm3::Vec3f* pos, Wm3::Vec2i* size)
  {
    gpg::Rect2i rect = BuildRectFromPointAndSize(*pos, *size);
    AddDeposit(type, &rect);
  }

  /**
   * Address: 0x00545FC0 (Moho::CSimResources::GetDeposits1)
   */
  const msvc8::vector<ResourceDeposit>& CSimResources::GetDeposits() const
  {
    return deposits_;
  }

  /**
   * Address: 0x00545FB0 (Moho::CSimResources::GetDeposits2)
   */
  msvc8::vector<ResourceDeposit>& CSimResources::GetDeposits()
  {
    return deposits_;
  }

  /**
   * Address: 0x00546060 (Moho::CSimResources::IsDepositAt)
   *
   * What it does:
   * Tests strict rectangle overlap against deposits of the requested type.
   */
  bool CSimResources::IsDepositAt(gpg::Rect2i* pos, EDepositType type)
  {
    boost::mutex::scoped_lock lock(lock_);
    for (const ResourceDeposit& deposit : deposits_) {
      if (deposit.depositType == type && RectsOverlapStrict(*pos, deposit.footprintRect)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Address: 0x00545FD0 (Moho::CSimResources::IsDepositAtPoint)
   *
   * What it does:
   * Converts center+size to grid rect and reuses IsDepositAt.
   */
  bool CSimResources::IsDepositAtPoint(Wm3::Vec3f* pos, Wm3::Vec2i* size, EDepositType type)
  {
    gpg::Rect2i rect = BuildRectFromPointAndSize(*pos, *size);
    return IsDepositAt(&rect, type);
  }

  /**
   * Address: 0x00546470 (Moho::CSimResources::DepositCollides)
   *
   * What it does:
   * Emits deposits whose terrain AABB intersects the provided solid, optionally
   * filtering by deposit type.
   */
  void CSimResources::DepositCollides(
    CGeomSolid3* solid, CHeightField* field, gpg::fastvector<ResourceDeposit>* outDeposits, EDepositType type
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
   * Address: 0x00546650 (Moho::CSimResources::DepositIsInArea)
   *
   * What it does:
   * Tests containment relation used by original placement logic for typed
   * deposits.
   */
  bool CSimResources::DepositIsInArea(EDepositType type, gpg::Rect2i* area)
  {
    boost::mutex::scoped_lock lock(lock_);
    for (const ResourceDeposit& deposit : deposits_) {
      if (deposit.depositType != type) {
        continue;
      }

      const gpg::Rect2i& rect = deposit.footprintRect;
      if (area->x0 <= rect.x0) {
        if (rect.x1 >= area->x1 && area->z0 >= rect.z0 && rect.z1 >= area->z1) {
          return true;
        }
        continue;
      }

      if (area->x1 < rect.x1 || rect.z0 < area->z0 || area->z1 < rect.z1) {
        if (area->x0 < rect.x0) {
          continue;
        }
      }

      if (rect.x1 >= area->x1 && area->z0 >= rect.z0 && rect.z1 >= area->z1) {
        return true;
      }
    }

    return false;
  }

  /**
   * Address: 0x005465C0 (Moho::CSimResources::DepositIsInAreaPoint)
   *
   * What it does:
   * Converts center+size to grid rect and reuses DepositIsInArea.
   */
  bool CSimResources::DepositIsInAreaPoint(EDepositType type, Wm3::Vec3f* pos, Wm3::Vec2i* size)
  {
    gpg::Rect2i rect = BuildRectFromPointAndSize(*pos, *size);
    return DepositIsInArea(type, &rect);
  }

  /**
   * Address: 0x00546760 (Moho::CSimResources::FindClosestDespoit)
   *
   * What it does:
   * Finds the closest deposit center of matching type within radius.
   */
  bool CSimResources::FindClosestDeposit(GridPos* from, GridPos* outPos, float radius, EDepositType type)
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
   * Address: 0x00546860 (Moho::CSimResources::AreaHasDeposit)
   *
   * What it does:
   * Checks area/deposit overlap with type-specific footprint expansion.
   */
  bool CSimResources::AreaHasDeposit(EDepositType type, gpg::Rect2f* area)
  {
    boost::mutex::scoped_lock lock(lock_);
    for (const ResourceDeposit& deposit : deposits_) {
      if (deposit.depositType != type) {
        continue;
      }

      float minX = 0.0f;
      float minZ = 0.0f;
      float maxX = 0.0f;
      float maxZ = 0.0f;
      if (type == kMass) {
        minX = static_cast<float>(deposit.footprintRect.x0) - 0.5f;
        minZ = static_cast<float>(deposit.footprintRect.z0) - 0.5f;
        maxX = static_cast<float>(deposit.footprintRect.x1) + 0.5f;
        maxZ = static_cast<float>(deposit.footprintRect.z1) + 0.5f;
      } else if (type == kHydrocarbon) {
        minX = static_cast<float>(deposit.footprintRect.x0) - 1.5f;
        minZ = static_cast<float>(deposit.footprintRect.z0) - 1.5f;
        maxX = static_cast<float>(deposit.footprintRect.x1) + 1.5f;
        maxZ = static_cast<float>(deposit.footprintRect.z1) + 1.5f;
      }

      const bool overlaps = maxX > area->x0 && area->x1 > minX && maxZ > area->z0 && area->z1 > minZ;
      if (overlaps && HasPositiveArea(*area) && maxX > minX && minZ < maxZ) {
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
