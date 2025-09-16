#pragma once

#include "ResourceDeposit.h"
#include "gpg/core/containers/Rect2.h"
#include "gpg/core/utils/BoostUtils.h"
#include "legacy/containers/Vector.h"
#include "moho/math/GridPos.h"
#include "wm3/Vector2.h"
#include "wm3/Vector3.h"

namespace moho
{
    enum EDepositType
    {
        kNone = 0x0,
        kMass = 0x1,
        kHydrocarbon = 0x2,
    };

	class IResources : public boost::noncopyable_::noncopyable
	{
        // ==== Primary vftable (12 entries) ====
	public:
        virtual ~IResources() noexcept = default;
        virtual void AddDeposit(EDepositType type, Rect2i* pos) = 0;
        virtual void AddDepositPoint(EDepositType type, Wm3::Vec3f* pos, Wm3::Vec2i* size) = 0;
        virtual const msvc8::vector<ResourceDeposit>& GetDeposits() const = 0;
		virtual msvc8::vector<ResourceDeposit>& GetDeposits() = 0;
        virtual bool IsDepositAt(Rect2i* pos, EDepositType type) = 0;
        virtual bool IsDepositAtPoint(Wm3::Vec3f* pos, Wm3::Vec2i* size, EDepositType type) = 0;
        //virtual void DepositCollides(CGeomSolid3* solid, CHeightField* field, gpg::core::FastVector<ResourceDeposit*>* dest, Moho::EDepositType type) = 0;
        virtual bool DepositIsInArea(EDepositType type, Rect2i* area) = 0;
        virtual bool DepositIsInAreaPoint(EDepositType type, Wm3::Vec3f* pos, Wm3::Vec2i* size) = 0;
        virtual bool FindClosestDeposit(GridPos* from, GridPos* outPos, float radius, EDepositType type) = 0;
        virtual bool AreaHasDeposit(EDepositType type, Rect2f* area) = 0;
	};
}
