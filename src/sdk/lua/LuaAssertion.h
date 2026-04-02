#pragma once

#include <stdexcept>

namespace LuaPlus
{
	/**
	 * VFTABLE: 0x00D44C28
	 * COL: 0x00E5FF5C
	 */
	class LuaAssertion : public std::logic_error
	{
	public:
		using std::logic_error::logic_error;

		/**
		 * Address: 0x00457880 (FUN_00457880, ??0LuaAssertion@LuaPlus@@QAE@PBD@Z)
		 *
		 * What it does:
		 * Builds one Lua assertion exception object from the provided message.
		 */
		explicit LuaAssertion(const char* message);

		/**
		 * Address: 0x00457920
		 * Slot: 0
		 * Demangled: LuaPlus::LuaAssertion scalar deleting destructor
		 */
		~LuaAssertion() noexcept override;

		/**
		 * Address: 0x00408580
		 * Slot: 1
		 * Demangled: std::logic_error::what / c_str accessor path
		 */
		[[nodiscard]]
		const char* what() const noexcept override;
	};
}
