#pragma once

#define GPG_ERROR(msg) gpg::HandleAssertFailure(msg, __LINE__, __FILE__);
#define GPG_UNREACHABLE(x) GPG_ERROR("Reached the supposably unreachable.");
#define GPG_ASSERT(x) do {\
    if (! (x)) { GPG_ERROR(#x); }\
} while (false)

namespace gpg
{
	using die_handler_t = void (*)(const char*);

	void HandleAssertFailure(const char* msg, int lineNum, const char* file); // 0x0093EDE0
	die_handler_t SetDieHandler(die_handler_t handler); // 0x00938FE0
	void InvokeDieHandler(const char*); // 0x00938FF0
	void Die(const char* args, ...); // 0x00939000

	/**
	 * Parse integer in [start,end) with base auto-detection:
	 *  - optional leading '-'
	 *  - if starts with '0x'/'0X' => base 16
	 *  - else if starts with '0'  => base 8
	 *  - else => base 10
	 *  Returns true on success and stores into *dest.
	 *  Accepts only ASCII digits/letters; requires that the entire span is valid.
	 */
	bool func_ParseNum(const char* start, const char* end, int* dest) noexcept;
}

static gpg::die_handler_t dieHandler; // 0x00F8EBDC
