#pragma once

#define GPG_ERROR(msg) gpg::HandleAssertFailure(msg, __LINE__, __FILE__);
#define GPG_UNREACHABLE(...) GPG_ERROR("Reached the supposably unreachable.");
#define GPG_ASSERT(x) do {\
    if (! (x)) { GPG_ERROR(#x); }\
} while (false)

#include <cstddef>
#include <cstdint>

namespace gpg
{
	using die_handler_t = void (*)(const char*);
	using mem_hook_t = void (*)(int, int, ...);

	struct HeapStats
	{
		std::uint32_t reserved;      // +0x00
		std::uint32_t committed;     // +0x04
		std::uint32_t total;         // +0x08
		std::uint32_t inSmallBlocks; // +0x0C
		std::uint32_t inUse;         // +0x10
	};
	static_assert(offsetof(HeapStats, reserved) == 0x00, "gpg::HeapStats::reserved offset must be 0x00");
	static_assert(offsetof(HeapStats, committed) == 0x04, "gpg::HeapStats::committed offset must be 0x04");
	static_assert(offsetof(HeapStats, total) == 0x08, "gpg::HeapStats::total offset must be 0x08");
	static_assert(offsetof(HeapStats, inSmallBlocks) == 0x0C, "gpg::HeapStats::inSmallBlocks offset must be 0x0C");
	static_assert(offsetof(HeapStats, inUse) == 0x10, "gpg::HeapStats::inUse offset must be 0x10");
	static_assert(sizeof(HeapStats) == 0x14, "gpg::HeapStats size must be 0x14");

	void HandleAssertFailure(const char* msg, int lineNum, const char* file); // 0x0093EDE0
	die_handler_t SetDieHandler(die_handler_t handler); // 0x00938FE0
	void InvokeDieHandler(const char*); // 0x00938FF0
	void Die(const char* args, ...); // 0x00939000

	/**
	 * Address: 0x00957EF0 (FUN_00957EF0, func_SetMemHook)
	 *
	 * What it does:
	 * Installs or clears the process-wide memory hook callback pointer.
	 */
	void SetMemHook(mem_hook_t hook);

	mem_hook_t GetMemHook();

	/**
	 * Address: 0x00958D60 (FUN_00958D60, func_GetHeapInfo)
	 *
	 * What it does:
	 * Copies allocator heap counters into `outStats` under allocator lock.
	 */
	void GetHeapInfo(HeapStats* outStats);

	/**
	 * Parse integer in [start,end) with base auto-detection:
	 *  - optional leading '-'
	 *  - if starts with '0x'/'0X' => base 16
	 *  - else if starts with '0'  => base 8
	 *  - else => base 10
	 *  Returns true on success and stores into *dest.
	 *  Accepts only ASCII digits/letters; requires that the entire span is valid.
	 */
	bool ParseNum(const char* start, const char* end, int* dest) noexcept;

	void SetThreadName(unsigned int id, const char* name); // 0x009071D0
}

static gpg::die_handler_t dieHandler; // 0x00F8EBDC
