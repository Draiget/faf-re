#pragma once

#include <cstddef>
#include <type_traits>

#include "boost/mutex.h"
#include "gpg/core/containers/FastVector.h"
#include "IResources.h"
#include "ISimResources.h"
#include "legacy/containers/Vector.h"
#include "ResourceDeposit.h"
#include "util/Build.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  class CSimResources : public ISimResources
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x00545DC0 (FUN_00545DC0, ??0CSimResources@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes the resource mutex and clears the deposit vector.
     */
    CSimResources();

    /**
     * Address: 0x00546E90 (FUN_00546E90, Moho::CSimResources::operator new)
     *
     * What it does:
     * Allocates one `CSimResources` object and runs in-place construction,
     * returning `nullptr` on allocation failure.
     */
    [[nodiscard]] static CSimResources* Create();

    /**
     * Address: 0x00545E10 (FUN_00545E10, core dtor body)
     * Address: 0x00546A00 (FUN_00546A00, Moho::CSimResources::dtr)
     *
     * What it does:
     * Releases mutex/vector storage and optionally deletes `this` via deleting
     * destructor thunk.
     */
    ~CSimResources() override;

    /**
     * Address: 0x00545F10 (FUN_00545F10, Moho::CSimResources::AddDeposit)
     */
    void AddDeposit(EDepositType type, gpg::Rect2i* pos) override;

    /**
     * Address: 0x00545E80 (FUN_00545E80, Moho::CSimResources::AddDepositPoint)
     */
    void AddDepositPoint(EDepositType type, Wm3::Vec3f* pos, Wm3::Vec2i* size) override;

    /**
     * Address: 0x00545FC0 (FUN_00545FC0, Moho::CSimResources::GetDeposits1)
     */
    const msvc8::vector<ResourceDeposit>& GetDeposits() const override;

    /**
     * Address: 0x00545FB0 (FUN_00545FB0, Moho::CSimResources::GetDeposits2)
     */
    msvc8::vector<ResourceDeposit>& GetDeposits() override;

    /**
     * Address: 0x00546060 (FUN_00546060, Moho::CSimResources::IsDepositAt)
     */
    bool IsDepositAt(gpg::Rect2i* pos, EDepositType type) override;

    /**
     * Address: 0x00545FD0 (FUN_00545FD0, Moho::CSimResources::IsDepositAtPoint)
     */
    bool IsDepositAtPoint(Wm3::Vec3f* pos, Wm3::Vec2i* size, EDepositType type) override;

    /**
     * Address: 0x00546470 (FUN_00546470, Moho::CSimResources::DepositCollides)
     */
    void DepositCollides(
      CGeomSolid3* solid, CHeightField* field, gpg::fastvector<ResourceDeposit>* outDeposits, EDepositType type
    ) override;

    /**
     * Address: 0x00546650 (FUN_00546650, Moho::CSimResources::DepositIsInArea)
     */
    bool DepositIsInArea(EDepositType type, gpg::Rect2i* area) override;

    /**
     * Address: 0x005465C0 (FUN_005465C0, Moho::CSimResources::DepositIsInAreaPoint)
     */
    bool DepositIsInAreaPoint(EDepositType type, Wm3::Vec3f* pos, Wm3::Vec2i* size) override;

    /**
     * Address: 0x00546760 (FUN_00546760, Moho::CSimResources::FindClosestDespoit)
     */
    bool FindClosestDeposit(GridPos* from, GridPos* outPos, float radius, EDepositType type) override;

    /**
     * Address: 0x00546860 (FUN_00546860, Moho::CSimResources::AreaHasDeposit)
     */
    bool AreaHasDeposit(EDepositType type, gpg::Rect2f* area) override;

    /**
     * Source parity: FAF binary patch helper `SimGetDepositsAroundPoint`.
     *
     * What it does:
     * Collects deposits whose centers are within `radius` from (`x`, `z`),
     * optionally filtered by `type` (`kNone` means any type), and records
     * distance as `sqrt(dx*dx + dz*dz)`.
     */
    void GetDepositsAroundPoint(
      float x, float z, float radius, EDepositType type, gpg::fastvector<ResourceDepositDistance>* outDeposits
    ) const;

  public:
    boost::mutex lock_;                       // +0x04
    msvc8::vector<ResourceDeposit> deposits_; // +0x0C
  };

  static_assert(std::is_polymorphic<ISimResources>::value, "ISimResources must remain polymorphic");
  static_assert(offsetof(CSimResources, deposits_) == 0x0C, "CSimResources::deposits_ offset must be 0x0C");
  // The sim constructor (FUN_00744060) allocates this with `operator new(0x1Cu)`
  // and inlines the body: vftable, then `boost::mutex::mutex(&mLock)`, then the
  // three deposit-vector pointers.
  static_assert(sizeof(CSimResources) == 0x1C, "CSimResources size must be 0x1C");
  ABI_SIZE_MUST_BE(CSimResources, 0x1C);
} // namespace moho
