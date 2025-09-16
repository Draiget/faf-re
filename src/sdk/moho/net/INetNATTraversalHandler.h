#pragma once

namespace moho
{
	class INetNATTraversalHandler
	{
		// Primary vftable (2 entries)
	public:
		virtual void sub_A82547() = 0; // 0xA82547 (slot 0)
		virtual void sub_A82547_1() = 0; // 0xA82547 (slot 1)
	};
}