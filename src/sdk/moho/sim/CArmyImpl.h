#pragma once
#include <cstdint>

#include "Sim.h"
#include "SimArmy.h"
#include "STIMap.h"
#include "../../legacy/containers/String.h"
#include "../../gpg/core/containers/Set.h"
#include "../../legacy/containers/Vector.h"
#include "../math/Vector2f.h"

namespace moho
{
	class Sim;
	class CAiBrain;
	class CAiReconDBImpl;
	class CSimArmyEconomyInfo;
	class CArmyStats;
	class CPlatoon;

	struct ArmyPool
	{
		std::uint32_t meta0;
		std::uint32_t meta1;
		msvc8::inline_vector<CPlatoon*, 8> armies;
		std::int32_t padding;
	};

	class CArmyImpl : public SimArmy
	{
		// Primary vftable (55 entries)
	public:
		/**
		 * In binary: Destructor.
		 *
		 * PDB name: sub_6FE670
		 * Address: 0x6FE670
		 * VFTable SLOT: 0
		 */
		virtual ~CArmyImpl() = default;

		/**
		 * In binary: GetSimulation
		 *
		 * PDB name: sub_6FDC10
		 * Address: 0x6FDC10
		 * VFTable SLOT: 1
		 */
		virtual Sim* GetSimulation() {
			return Simulation;
		}

		/**
		 * In binary: IsHuman
		 *
		 * PDB name: sub_6FFC90
		 * Address: 0x6FFC90
		 * VFTable SLOT: 2
		 */
		virtual bool IsHuman() {
			return _stricmp(ControllerKind.raw_data_unsafe(), "Human") == 0;
		}

		/**
		 * In binary: GetControllerKind
		 *
		 * PDB name: sub_6FDC20
		 * Address: 0x6FDC20
		 * VFTable SLOT: 3
		 */
		virtual const char* GetControllerKind() {
			return ControllerKind.raw_data_unsafe();
		}

		/**
		 * In binary: ???
		 * Note: Doing something close to `std::string::erase(0, npos)`.
		 * Uses `sub_4056B0` as std::string (assign/replace/erase).
		 *
		 * PDB name: sub_6FDC40
		 * Address: 0x6FDC40
		 * VFTable SLOT: 4
		 */
		virtual void sub_6FDC40() = 0;

		/**
		 * In binary: ???
		 * Note: Getting string at 0x1F8 position.
		 *
		 * PDB name: sub_6FDC60
		 * Address: 0x6FDC60
		 * VFTable SLOT: 5
		 */
		virtual const char* sub_6FDC60() {
			return UnknownName.raw_data_unsafe();
		}

		/**
		 * In binary: ???
		 * Note: 32-bit field right after string at 0x1F8.
		 *
		 * PDB name: sub_6FDC80
		 * Address: 0x6FDC80
		 * VFTable SLOT: 6
		 */
		virtual int32_t sub_6FDC80() {
			return reinterpret_cast<int32_t*>(this)[134]; // 0x218
		}

        /**
         * In binary: GetArmyBrain
         *
         * PDB name: sub_6FDC90
         * Address: 0x6FDC90
         * VFTable SLOT: 7
         */
		virtual CAiBrain* GetArmyBrain() {
			return AiBrain;
		}

		/**
		 * In binary: GetAiReconDb
		 *
		 * PDB name: sub_6FDCA0
		 * Address: 0x6FDCA0
		 * VFTable SLOT: 8
		 */
		virtual CAiReconDBImpl* GetAiReconDb() {
			return AiReconDb;
		}

		/**
		 * In binary: GetEconomyInfo
		 *
		 * PDB name: sub_6FDCB0
		 * Address: 0x6FDCB0
		 * VFTable SLOT: 9
		 */
		virtual CSimArmyEconomyInfo* GetEconomyInfo() {
			return EconomyInfo;
		}

		/**
		 * In binary: Randomize starting position
		 *
		 * PDB name: sub_6FFCB0
		 * Address: 0x6FFCB0
		 * VFTable SLOT: 10
		 */
		virtual void RandomizeStartingPosition() {
			const auto w = Simulation->stiMap->HeightField->width;
			const auto h = Simulation->stiMap->HeightField->height;

			gpg::core::Mt19937State& rng = Simulation->rng->core;

			// Two draws (note: owner passed as in the binary: 1st = army, 2nd = sim)
			const float rx = gpg::core::mt_unitf_from_u32(mt_next_u32_game_exact(this, rng)) + 0.1f;
			const float ry = gpg::core::mt_unitf_from_u32(mt_next_u32_game_exact(Simulation, rng)) + 0.1f;

			// Scale to [0, w-1] / [0, h-1]
			StartPosition.x = (w > 0 ? static_cast<float>(w - 1) * rx : 0.0f);
			StartPosition.y = (h > 0 ? static_cast<float>(h - 1) * ry : 0.0f);
		}

		/**
		 * In binary: SetStartPosition
		 *
		 * PDB name: sub_6FDCC0
		 * Address: 0x6FDCC0
		 * VFTable SLOT: 11
		 */
		virtual void SetStartPosition(Vector2f* pos) {
			StartPosition.x = pos->x;
			StartPosition.y = pos->y;
		}

		/**
		 * In binary: SetStartPosition
		 *
		 * PDB name: sub_6FDCE0
		 * Address: 0x6FDCE0
		 * VFTable SLOT: 12
		 */
		virtual Vector2f* SetStartPosition() {
			return &StartPosition;
		}

		/**
		 * In binary: SetRelationBitUnique
		 *
		 * PDB name: sub_6FDF30
		 * Address: 0x6FDF30
		 * VFTable SLOT: 13
		 */
		virtual void SetRelationBitUnique(uint32_t id, int which) {
			Set* sets[3] = { &Neutrals, &Allies, &Enemies };

			const uint32_t word = id >> 5;
			const uint32_t bit = 1u << (id & 31);
			for (int i = 0;i < 3;i++) {
				auto& s = *sets[i];
				const uint32_t rel = word - s.baseWordIndex;
				const uint32_t words = (
					reinterpret_cast<uint8_t*>(s.items_end) - 
					reinterpret_cast<uint8_t*>(s.items_begin)
				) >> 2;

				if (rel < words) {
					if (i == which) s.items_begin[rel] |= bit;
					else            s.items_begin[rel] &= ~bit;
				}
				// sub_401980 / sub_4018A0 looks like "ensure capacity/trim"; skip.
			}

			// NOTE: sub_6FDF30 also moving nodes in (Sim+0x984).
		}

		/**
		 * In binary: ???
		 * Note: Probably smth like GetAbandonedByPlayerToken
		 *
		 * PDB name: sub_700FC0
		 * Address: 0x700FC0
		 * VFTable SLOT: 14
		 */
		virtual int sub_700FC0() {
			// sub_403650(a2) side-effects elided
			int tok = *reinterpret_cast<int*>(reinterpret_cast<uint8_t*>(this) + 0x138);
			const int sentinel = *reinterpret_cast<int*>(reinterpret_cast<uint8_t*>(this) + 0x13C);
			if (tok == sentinel) {
				// sub_581AA0("AbandonedByPlayer")
				// Here just return a placeholder; in practice call the real game func.
			}
			return tok;
		}

		/**
		 * In binary: Tick
		 *
		 * PDB name: sub_6FFD70
		 * Address: 0x6FFD70
		 * VFTable SLOT: 15
		 */
		virtual void sub_6FFD70() = 0;

		/**
		 * In binary: ???
		 *
		 * PDB name: sub_700080
		 * Address: 0x700080
		 * VFTable SLOT: 16
		 */
		virtual void sub_700080() = 0;

		/**
		 * In binary: Export army economy snapshot/info?
		 *
		 * PDB name: sub_700240
		 * Address: 0x700240
		 * VFTable SLOT: 17
		 */
		virtual int32_t sub_700240(void* outBuffer) {
			// // EconomyInfo*
			// int eco = *(int32_t*)(this + 0x1F4);
			// // copy eco floats/caps
			// memcpy((void*)(this + 0x88), (const void*)(eco + 0x18), 0x38);
			// // IsResourceSharingEnabled
			// *(int8_t*)(this + 0xC0) = *(int8_t*)(eco + 0x54);
			// // export ArmyInfoBlock -> outBuf
			// return sub_700280(outBuffer, this + 0x88);        
			return 0;
		}

		/**
		 * In binary: GetStats
		 *
		 * PDB name: sub_6FDD50
		 * Address: 0x6FDD50
		 * VFTable SLOT: 18
		 */
		virtual CArmyStats* GetStats() = 0;

		/**
		 * In binary: Sum of one of the field of all units
		 *
		 * PDB name: sub_6FDD60
		 * Address: 0x6FDD60
		 * VFTable SLOT: 19
		 */
		virtual void sub_6FDD60() = 0;

		virtual void sub_6FDDE0() = 0; // 0x6FDDE0 (slot 20)
		virtual void sub_6FDDF0() = 0; // 0x6FDDF0 (slot 21)
		virtual void sub_6FDE40() = 0; // 0x6FDE40 (slot 22)
		virtual void sub_6FDE70() = 0; // 0x6FDE70 (slot 23)
		virtual void sub_6FDE90() = 0; // 0x6FDE90 (slot 24)
		virtual void sub_700410() = 0; // 0x700410 (slot 25)
		virtual void sub_700470() = 0; // 0x700470 (slot 26)
		virtual void sub_7004E0() = 0; // 0x7004E0 (slot 27)
		virtual void sub_7005F0() = 0; // 0x7005F0 (slot 28)

		/**
		 * In binary: GetUnitCap
		 *
		 * PDB name: sub_700540
		 * Address: 0x700540
		 * VFTable SLOT: 29
		 */
		virtual void sub_700540() = 0;

		/**
		 * In binary: SetUnitCap
		 *
		 * PDB name: sub_7006C0
		 * Address: 0x7006C0
		 * VFTable SLOT: 30
		 */
		virtual void sub_7006C0() = 0;

		virtual void sub_700700() = 0; // 0x700700 (slot 31)
		virtual void sub_700730() = 0; // 0x700730 (slot 32)
		virtual void sub_700770() = 0; // 0x700770 (slot 33)
		virtual void sub_7007C0() = 0; // 0x7007C0 (slot 34)
		virtual void sub_700A00() = 0; // 0x700A00 (slot 35)
		virtual void sub_700A70() = 0; // 0x700A70 (slot 36)
		virtual void sub_700E20() = 0; // 0x700E20 (slot 37)
		virtual void sub_700E70() = 0; // 0x700E70 (slot 38)
		virtual void sub_700EB0() = 0; // 0x700EB0 (slot 39)
		virtual void sub_6FE090() = 0; // 0x6FE090 (slot 40)
		virtual void sub_6FDD00() = 0; // 0x6FDD00 (slot 41)
		virtual void sub_6FDD10() = 0; // 0x6FDD10 (slot 42)
		virtual void sub_6FDD30() = 0; // 0x6FDD30 (slot 43)
		virtual void sub_6FDD40() = 0; // 0x6FDD40 (slot 44)
		virtual void sub_6FDEC0() = 0; // 0x6FDEC0 (slot 45)
		virtual void sub_6FDED0() = 0; // 0x6FDED0 (slot 46)
		virtual void sub_6FE1B0() = 0; // 0x6FE1B0 (slot 47)
		virtual void sub_6FE220() = 0; // 0x6FE220 (slot 48)
		virtual void sub_6FE290() = 0; // 0x6FE290 (slot 49)
		virtual void sub_6FE2B0() = 0; // 0x6FE2B0 (slot 50)
		virtual void sub_6FE2D0() = 0; // 0x6FE2D0 (slot 51)
		virtual void sub_6FE2F0() = 0; // 0x6FE2F0 (slot 52)
		virtual void sub_6FE300() = 0; // 0x6FE300 (slot 53)
		virtual void sub_6FE310() = 0; // 0x6FE310 (slot 54)

	public:
		void* N000006B2; //0x0004
		int32_t ArmyId; //0x0008
		msvc8::string ArmyTextId; //0x000C
		msvc8::string Name; //0x0028
		uint8_t IsCivilian; //0x0044
		char pad_0045[67]; //0x0045
		float EnergyCurrent; //0x0088
		float MassCurrent; //0x008C
		float IncomeEnergy10x; //0x0090
		float IncomeMass10x; //0x0094
		float ReclaimedEnergy10x; //0x0098
		float ReclaimedMass10x; //0x009C
		float RequestedEnergy10x; //0x00A0
		float RequestedMass10x; //0x00A4
		float ExpenseEnergy10x; //0x00A8
		float ExpenseMass10x; //0x00AC
		uint32_t EnergyCapacity; //0x00B0
		char pad_00B4[4]; //0x00B4
		uint32_t MassCapacity; //0x00B8
		char pad_00BC[4]; //0x00BC
		uint8_t IsResourceSharingEnabled; //0x00C0
		char pad_00C1[7]; //0x00C1
		Set Neutrals; //0x00C8
		Set Allies; //0x00E8
		Set Enemies; //0x0108
		char pad_0128[8]; //0x0128
		Set MohoSetValidCommandSources; //0x0130
		uint8_t ColorB; //0x0150
		uint8_t ColorG; //0x0151
		uint8_t ColorR; //0x0152
		uint8_t ColorA; //0x0153
		uint8_t IconColorB; //0x0154
		uint8_t IconColorG; //0x0155
		uint8_t IconColorR; //0x0156
		uint8_t IconColorA; //0x0157
		msvc8::string ControllerKind; //0x0158
		int32_t FactionIndex; //0x0174
		char pad_0178[64]; //0x0178
		void* isOutOfGamePtr; //0x01B8
		char pad_01BC[4]; //0x01BC
		uint8_t IsOutOfGame; //0x01C0
		char pad_01C1[3]; //0x01C1
		Vector2f StartPosition; //0x01C4
		char pad_01CC[4]; //0x01CC
		float NoRushRadius; //0x01D0
		float NoRushOffsetX; //0x01D4
		float NoRushOffsetY; //0x01D8
		char pad_01DC[12]; //0x01DC
		Sim* Simulation; //0x01E8
		CAiBrain* AiBrain; //0x01EC
		CAiReconDBImpl* AiReconDb; //0x01F0
		CSimArmyEconomyInfo* EconomyInfo; //0x01F4
		msvc8::string UnknownName; //0x01F8
		CArmyStats* Stats; //0x0214
		char pad_0218[16]; //0x0218
		ArmyPool platoons; //0x0228
		char pad_0260[16]; //0x0260
		float UnitCapacity; //0x0270
		char pad_0274[4]; //0x0274
		int32_t PathCapacityLand; //0x0278
		int32_t PathCapacitySea; //0x027C
		int32_t PathCapacityBoth; //0x0280
		char pad_0284[4]; //0x0284
	};
}
