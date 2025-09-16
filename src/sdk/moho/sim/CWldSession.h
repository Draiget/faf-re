#pragma once
#include <cstdint>

#include "CArmyImpl.h"
#include "legacy/containers/Vector.h"
#include "legacy/containers/String.h"
#include "moho/math/Vector3f.h"
#include "moho/misc/VisionDb.h"
#include "gpg/core/containers/IntrusiveLink.h"

namespace moho
{
	class UserArmy;

	class CWldSession
	{
	public:
		gpg::core::IntrusiveLink<CWldSession*> head0;
		gpg::core::IntrusiveLink<CWldSession*> head1;

		void* luaState; //0x0010
		char pad_0014[4]; //0x0014
		class RRuleGameRulesImpl* rules; //0x0018
		char pad_001C[4]; //0x001C
		uint32_t CanRestart; //0x0020
		char pad_0024[4]; //0x0024
		msvc8::string mapName; //0x0028
		char pad_0044[8]; //0x0044
		int32_t LeftReclaim; //0x004C
		char pad_0050[160]; //0x0050
		void* vecFirst; //0x00F0
		void* vecLast; //0x00F4
		void* vecEnd; //0x00F8
		void* vecInlineBase; //0x00FC
		char vecInlineData[176][4]; //0x0100
		char pad_03C0[8]; //0x03C0
		VisionDb visionDb; //0x03C8
		msvc8::vector<UserArmy*> userArmies; //0x03EC
		char pad_03FC[40]; //0x03FC
		CSimResources* deposits; //0x0424
		char pad_0428[28]; //0x0428
		void* ScenarioInfoLuaTable; //0x0444
		char pad_0448[16]; //0x0448
		int32_t GameTimeSeconds; //0x0458
		int32_t IsRunning; //0x045C
		float GameTimeMilliSeconds; //0x0460
		uint8_t IsPaused; //0x0464
		uint8_t N00001903; //0x0465
		uint8_t IsPausedB; //0x0466
		char pad_0467[5]; //0x0467
		uint8_t N0000315B; //0x046C
		char pad_046D[3]; //0x046D
		msvc8::vector<SSTICommandSource*> cmdSources; //0x0470
		int32_t ourCmdSource; //0x0480
		bool IsReplay; //0x0484
		bool IsBeingRecorded; //0x0485
		bool IsMultiplayer; //0x0486
		bool IsObservingAllowed; //0x0487
		uint32_t FocusArmy; //0x0488
		uint8_t IsGameOver; //0x048C
		char pad_048D[19]; //0x048D
		void* selectedUnitUnknownPtr1; //0x04A0
		void* selectedUnitListPtr; //0x04A4
		int32_t selectedUnitCount1; //0x04A8
		int32_t selectedUnitCount2; //0x04AC
		char pad_04B0[4]; //0x04B0
		Vector3f CursorWorldPos; //0x04B4
		char pad_04C0[8]; //0x04C0
		int32_t HighlightCommandId; //0x04C8
		Vector2f CursorScreenPos; //0x04CC
		bool IsCheatsEnabled; //0x04D4
		char pad_04D5[19]; //0x04D5
		bool DisplayEconomyOverlay; //0x04E8
		bool RelationsArmyColors; //0x04E9
		char pad_04EA[30]; //0x04EA
	};
}
