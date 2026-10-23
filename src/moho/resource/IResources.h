#pragma once

#include <type_traits>

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/Rect2.h"
#include "gpg/core/utils/BoostUtils.h"
#include "legacy/containers/String.h"
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
     * Address: 0x00546CB0 (FUN_00546CB0, ??0IResources@Moho@@IAE@XZ)
     * Shared helper: 0x00546E80 (loc_00546E80)
     *
     * What it does:
     * Initializes this interface subobject's base vtable pointer.
     */
    IResources() noexcept;

  public:
    /**
     * Address: 0x00546CC0 (FUN_00546CC0, ??1IResources@Moho@@UAE@XZ)
     * Shared helper: 0x00546E80 (loc_00546E80)
     *
     * What it does:
     * Restores the base vtable lane for this interface during teardown.
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

    /**
     * Address: 0x00546CD0 (FUN_00546CD0, ?Translate@IResources@Moho@@SA?AW4EResourceType@2@ABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z)
     *
     * What it does:
     * Maps one deposit-type string to its `EDepositType` enum lane (`""`,
     * `"Mass"`, `"Hydrocarbon"`), returning `kNone` when unmatched.
     */
    [[nodiscard]] static EDepositType Translate(const msvc8::string& depositTypeName);

    /**
     * Address: 0x00546D10 (FUN_00546D10)
     *
     * What it does:
     * Returns one deposit-type string table entry by enum index.
     */
    [[nodiscard]] static const msvc8::string* Translate(EDepositType depositType);
  };

  /**
   * Address: 0x005491C0 (FUN_005491C0, func_SearchStringArrayFor)
   *
   * What it does:
   * Scans one contiguous string array range for an exact match and returns the
   * first matching element or `end` when no match is found.
   */
  msvc8::string* SearchStringArrayFor(msvc8::string* begin, msvc8::string* end, const msvc8::string* value);

  static_assert(sizeof(IResources) == 0x4, "IResources size must be 0x4");
  static_assert(std::is_polymorphic<IResources>::value, "IResources must remain polymorphic");
  static_assert(std::is_abstract<IResources>::value, "IResources must remain abstract");
} // namespace moho
