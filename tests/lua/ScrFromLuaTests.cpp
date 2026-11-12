// The Lua-to-engine-object converters (src/moho/script/CScriptEvent.cpp, SCR_FromLua_*): what each one does with a
// value that is no game object. Every converter reads the value's `_c_object` (a table's field, or the value itself)
// through SCR_ScriptObjectSlot and, when that is no CScriptObject userdata, raises retail's "Expected a game object.
// (Did you call with '.' instead of ':'?)" (the text at the converters' first luaL_error, for example
// SCR_FromLua_Unit 0x005936C0 and SCR_FromLua_CScriptEvent 0x004CBA60). Game runs only ever hand them real
// objects, so these branches ran in no test or game before. Windows only: the list includes the UI types, which the
// Linux build doesn't compile (cmake/FafLinux.cmake builds tests/lua/Lua*.cpp only).

#include <string>
#include <type_traits>
#include <vector>
#include <gtest/gtest.h>

#include "LuaTestSupport.h"
#include "moho/script/CScriptEvent.h"

namespace
{
  using faf_lua_tests::Contains;
  using faf_lua_tests::LuaFixture;

  // Calls one converter with the object at stack index 1, whichever of the two signatures it has.
  template <auto Converter>
  void Call(
    lua_State* const L
  )
  {
    LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(L);
    const LuaPlus::LuaObject object(state, 1);
    if constexpr (std::is_invocable_v<decltype(Converter), const LuaPlus::LuaObject&, LuaPlus::LuaState*>) {
      (void)Converter(object, state);
    } else {
      (void)Converter(object);
    }
  }

  struct Converter
  {
    const char* name;
    void (*call)(lua_State*);
  };

  const std::vector<Converter> kConverters = {
    {"CAiAttackerImpl", &Call<&moho::SCR_FromLua_CAiAttackerImpl>},
    {"CAiBrain", &Call<&moho::SCR_FromLua_CAiBrain>},
    {"CAiNavigatorImpl", &Call<&moho::SCR_FromLua_CAiNavigatorImpl>},
    {"CAiPersonality", &Call<&moho::SCR_FromLua_CAiPersonality>},
    {"CAimManipulator", &Call<&moho::SCR_FromLua_CAimManipulator>},
    {"CAnimationManipulator", &Call<&moho::SCR_FromLua_CAnimationManipulator>},
    {"CCollisionManipulator", &Call<&moho::SCR_FromLua_CCollisionManipulator>},
    {"CDamage", &Call<&moho::SCR_FromLua_CDamage>},
    {"CDecalHandleOpt", &Call<&moho::SCR_FromLua_CDecalHandleOpt>},
    {"CDiscoveryService", &Call<&moho::SCR_FromLua_CDiscoveryService>},
    {"CDiscoveryServiceOpt", &Call<&moho::SCR_FromLua_CDiscoveryServiceOpt>},
    {"CLobby", &Call<&moho::SCR_FromLua_CLobby>},
    {"CLobbyOpt", &Call<&moho::SCR_FromLua_CLobbyOpt>},
    {"CMauiBitmap", &Call<&moho::SCR_FromLua_CMauiBitmap>},
    {"CMauiBorder", &Call<&moho::SCR_FromLua_CMauiBorder>},
    {"CMauiControl", &Call<&moho::SCR_FromLua_CMauiControl>},
    {"CMauiCursor", &Call<&moho::SCR_FromLua_CMauiCursor>},
    {"CMauiEdit", &Call<&moho::SCR_FromLua_CMauiEdit>},
    {"CMauiFrame", &Call<&moho::SCR_FromLua_CMauiFrame>},
    {"CMauiHistogram", &Call<&moho::SCR_FromLua_CMauiHistogram>},
    {"CMauiItemList", &Call<&moho::SCR_FromLua_CMauiItemList>},
    {"CMauiLuaDragger", &Call<&moho::SCR_FromLua_CMauiLuaDragger>},
    {"CMauiMesh", &Call<&moho::SCR_FromLua_CMauiMesh>},
    {"CMauiMovie", &Call<&moho::SCR_FromLua_CMauiMovie>},
    {"CMauiScrollbar", &Call<&moho::SCR_FromLua_CMauiScrollbar>},
    {"CMauiText", &Call<&moho::SCR_FromLua_CMauiText>},
    {"CPathDebugger", &Call<&moho::SCR_FromLua_CPathDebugger>},
    {"CPlatoon", &Call<&moho::SCR_FromLua_CPlatoon>},
    {"CPlatoonOpt", &Call<&moho::SCR_FromLua_CPlatoonOpt>},
    {"CScriptEvent", &Call<&moho::SCR_FromLua_CScriptEvent>},
    {"CSlaveManipulator", &Call<&moho::SCR_FromLua_CSlaveManipulator>},
    {"CSlideManipulator", &Call<&moho::SCR_FromLua_CSlideManipulator>},
    {"CThrustManipulator", &Call<&moho::SCR_FromLua_CThrustManipulator>},
    {"CUIMapPreview", &Call<&moho::SCR_FromLua_CUIMapPreview>},
    {"CUIWorldMesh", &Call<&moho::SCR_FromLua_CUIWorldMesh>},
    {"CUIWorldView", &Call<&moho::SCR_FromLua_CUIWorldView>},
    {"CUnitCommand", &Call<&moho::SCR_FromLua_CUnitCommand>},
    {"CUnitScriptTask", &Call<&moho::SCR_FromLua_CUnitScriptTask>},
    {"CameraImpl", &Call<&moho::SCR_FromLua_CameraImpl>},
    {"CollisionBeamEntity", &Call<&moho::SCR_FromLua_CollisionBeamEntity>},
    {"Entity", &Call<&moho::SCR_FromLua_Entity>},
    {"EntityOpt", &Call<&moho::SCR_FromLua_EntityOpt>},
    {"HSound", &Call<&moho::SCR_FromLua_HSound>},
    {"HSoundOpt", &Call<&moho::SCR_FromLua_HSoundOpt>},
    {"IAniManipulator", &Call<&moho::SCR_FromLua_IAniManipulator>},
    {"IAniManipulatorOpt", &Call<&moho::SCR_FromLua_IAniManipulatorOpt>},
    {"IEffect", &Call<&moho::SCR_FromLua_IEffect>},
    {"IEffectOpt", &Call<&moho::SCR_FromLua_IEffectOpt>},
    {"MotorFallDown", &Call<&moho::SCR_FromLua_MotorFallDown>},
    {"Projectile", &Call<&moho::SCR_FromLua_Projectile>},
    {"ProjectileOpt", &Call<&moho::SCR_FromLua_ProjectileOpt>},
    {"Prop", &Call<&moho::SCR_FromLua_Prop>},
    {"ReconBlip", &Call<&moho::SCR_FromLua_ReconBlip>},
    {"ScriptedDecal", &Call<&moho::SCR_FromLua_ScriptedDecal>},
    {"Unit", &Call<&moho::SCR_FromLua_Unit>},
    {"UnitWeapon", &Call<&moho::SCR_FromLua_UnitWeapon>},
    {"UnitWeaponOpt", &Call<&moho::SCR_FromLua_UnitWeaponOpt>},
    {"UserEntity", &Call<&moho::SCR_FromLua_UserEntity>},
    {"UserUnit", &Call<&moho::SCR_FromLua_UserUnit>}
  };

  const Converter* gCurrent = nullptr;

  int CallCurrent(
    lua_State* const L
  )
  {
    gCurrent->call(L);
    lua_pushboolean(L, 1);
    return 1;
  }

  class ScrFromLua : public LuaFixture
  {
  protected:
    void SetUp() override
    {
      lua_pushcclosure(L(), &CallCurrent, 0);
      lua_setglobal(L(), "convert");
    }
  };
} // namespace

TEST_F(
  ScrFromLua,
  EveryConverterRejectsValuesThatAreNoGameObject
)
{
  ASSERT_GE(kConverters.size(), 50u);
  for (const Converter& converter : kConverters) {
    gCurrent = &converter;
    for (const char* value : {"1", "'text'", "{}", "{ _c_object = 5 }", "{ _c_object = {} }", "true"}) {
      const std::string message = ErrorOf(std::string("convert(") + value + ")");
      EXPECT_TRUE(Contains(message, "Expected a game object. (Did you call with '.' instead of ':'?)"))
        << converter.name << "(" << value << "): " << message;
    }
  }
  gCurrent = nullptr;
}

TEST_F(
  ScrFromLua,
  NilIsNoGameObjectEither
)
{
  for (const Converter& converter : kConverters) {
    gCurrent = &converter;
    const std::string message = ErrorOf("convert(nil)");
    EXPECT_TRUE(Contains(message, "Expected a game object.")) << converter.name << ": " << message;
  }
  gCurrent = nullptr;
}
