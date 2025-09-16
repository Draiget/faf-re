#pragma once

#include "ISimResources.h"
#include "../../gpg/core/utils/BoostWrappers.h"

namespace moho
{
	class ISimResources;
	using SimResourcesHandle = boost::BorrowedSharedPtr<ISimResources>;

	class ISimResources
	{
	protected:
		~ISimResources() = default;
	};

	static_assert(!std::is_polymorphic<ISimResources>::value, "ISimResources must be non-polymorphic");
}
