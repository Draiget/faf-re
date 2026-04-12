#pragma once

#include <type_traits>

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/Rect2.h"
#include "gpg/core/utils/BoostUtils.h"
#include "legacy/containers/Vector.h"
#include "moho/math/GridPos.h"
#include "ResourceDeposit.h"
#include "Wm3Vector2.h"
#include "Wm3Vector3.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  class CGeomSolid3;
  class CHeightField;

  class IResources : public boost::noncopyable_::noncopyable
  {
    // ==== Primary vftable (12 entries) ====
  public:
    static gpg::RType* sType;

  protected:
    /**
     * Address: 0x00546E80 (loc_00546E80, shared constructor/destructor helper chunk)
     *
     * What it does:
     * Initializes this interface subobject's vtable pointer.
     */
    IResources() noexcept;

  public:
    /**
     * Address: 0x00546E80 (loc_00546E80, shared constructor/destructor helper chunk)
     *
     * What it does:
     * Finalizes this interface subobject by restoring the base vtable state.
     */
    virtual ~IResources() noexcept;

    virtual void AddDeposit(EDepositType type, gpg::Rect2i* pos) = 0;
    virtual void AddDepositPoint(EDepositType type, Wm3::Vec3f* pos, Wm3::Vec2i* size) = 0;
    virtual const msvc8::vector<ResourceDeposit>& GetDeposits() const = 0;
    virtual msvc8::vector<ResourceDeposit>& GetDeposits() = 0;
    virtual bool IsDepositAt(gpg::Rect2i* pos, EDepositType type) = 0;
    virtual bool IsDepositAtPoint(Wm3::Vec3f* pos, Wm3::Vec2i* size, EDepositType type) = 0;
    virtual void DepositCollides(
      CGeomSolid3* solid, CHeightField* field, gpg::fastvector<ResourceDeposit>* outDeposits, EDepositType type
    ) = 0;
    virtual bool DepositIsInArea(EDepositType type, gpg::Rect2i* area) = 0;
    virtual bool DepositIsInAreaPoint(EDepositType type, Wm3::Vec3f* pos, Wm3::Vec2i* size) = 0;
    virtual bool FindClosestDeposit(GridPos* from, GridPos* outPos, float radius, EDepositType type) = 0;
    virtual bool AreaHasDeposit(EDepositType type, gpg::Rect2f* area) = 0;
  };

  static_assert(sizeof(IResources) == 0x4, "IResources size must be 0x4");
  static_assert(std::is_polymorphic<IResources>::value, "IResources must remain polymorphic");
  static_assert(std::is_abstract<IResources>::value, "IResources must remain abstract");
} // namespace moho
