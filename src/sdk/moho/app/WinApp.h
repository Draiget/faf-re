#pragma once
#include "moho/task/CTaskThread.h"

namespace moho
{
	class CWaitHandleSet;

	/**
	 * Address: 0x004F2480
	 */
	CTaskStage* WIN_GetBeforeEventsStage();

	/**
	 * Address: 0x004F24F0
	 */
	CTaskStage* WIN_GetBeforeWaitStage();

	/**
	 * Address: 0x004F2420
	 *
	 * @return 
	 */
	CWaitHandleSet* WIN_GetWaitHandleSet();
}
