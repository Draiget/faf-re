#include "Localization.h"
using namespace moho;

msvc8::string moho::Loc([[maybe_unused]] LuaPlus::LuaState* state, [[maybe_unused]] const char* key) {
    // TODO: Work on LuaPlus files
    //LuaPlus::LuaFunction fn{ state->GetGlobal("LOC") };
    //return std::string{ fn(key) };
    return msvc8::string{};
}
