#pragma once

#include "ISimResources.h"
#include "IResources.h"
#include "ResourceDeposit.h"
#include "util/Build.h"
#include "legacy/containers/Vector.h"
#include "gpg/core/utils/Sync.h"

namespace moho
{
	class CSimResources : public ISimResources, public IResources
	{
	public:
        virtual void sub_546A00(); // 0x546A00 (slot 0)
        virtual void sub_545F10(); // 0x545F10 (slot 1)
        virtual void sub_545E80(); // 0x545E80 (slot 2)
        virtual void sub_545FC0(); // 0x545FC0 (slot 3)
        virtual void sub_545FB0(); // 0x545FB0 (slot 4)
        virtual void sub_546060(); // 0x546060 (slot 5)
        virtual void sub_545FD0(); // 0x545FD0 (slot 6)
        virtual void sub_546470(); // 0x546470 (slot 7)
        virtual void sub_546650(); // 0x546650 (slot 8)
        virtual void sub_5465C0(); // 0x5465C0 (slot 9)
        virtual void sub_546760(); // 0x546760 (slot 10)
        virtual void sub_546860(); // 0x546860 (slot 11)

	public:
        gpg::core::Mutex lock_;
        msvc8::vector<ResourceDeposit> deposits_; // at 0x0C
	};

	static_assert(!std::is_polymorphic<ISimResources>::value, "ISimResources must be non-polymorphic");
    ABI_SIZE_MUST_BE(CSimResources, 0x1C);
}
