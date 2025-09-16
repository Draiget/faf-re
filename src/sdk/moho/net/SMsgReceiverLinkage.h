#pragma once
#include "IMessageReceiver.h"
#include "moho/misc/TDatListItem.h"

namespace moho
{
	struct struct_filler4 { int filler; };

	class SMsgReceiverLinkage : public
		TDatListItem<SMsgReceiverLinkage>,
		struct_filler4,
		TDatListItem<IMessageReceiver>
	{
		
	};
}
