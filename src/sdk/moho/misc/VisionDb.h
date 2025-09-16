#pragma once

namespace moho
{
	class VisionDb
	{
		// Primary vftable (1 entries)
	public:
		virtual ~VisionDb() = default; // 0x81AEB0 (slot 0)

		class Pool
		{
			// Primary vftable (1 entries)
		public:
			virtual ~Pool() = default; // 0x81AD00 (slot 0)

			char pad_0004[24];
		} pool; //0x0004

		char pad_0020[4]; //0x0020
	};
}
