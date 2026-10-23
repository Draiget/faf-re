#include "lua/LuaAssertion.h"

using namespace LuaPlus;

/**
 * Address: 0x00457880
 */
LuaAssertion::LuaAssertion(const char* const message)
	: std::logic_error(message != nullptr ? message : "")
{
}

/**
 * Address: 0x00457920
 */
LuaAssertion::~LuaAssertion() noexcept = default;

/**
 * Address: 0x00408580
 */
const char* LuaAssertion::what() const noexcept
{
	return std::logic_error::what();
}
