// SCR_ImportLuaModule and SCR_GetLuaTableField (src/moho/lua/CScrLuaObjectFactory.cpp) when the
// import or the lookup fails, and the formation lookups that call them.
//
// Issue #379: the Nomads featured mod's formations hook reads `LightAttackNaval` as a global, FAF's
// strict-globals check raises, and the import of /lua/formations.lua fails. The failed import came
// back as a LuaObject with no state. FORMATION_GetNumScripts guards with IsNil(), which is false for
// such an object, so the GetByName after it threw LuaAssertion("m_state") through the mouse handler
// and ended the game. Retail's SCR_Import (0x004D3250) answers a nil object bound to the state
// (0x00908970), FORMATION_GetNumScripts (0x00575A30) sees IsNil() and answers 0.

#include <gtest/gtest.h>

#include "LuaTestSupport.h"
#include "moho/ai/IAiFormationDB.h"
#include "moho/lua/CScrLuaObjectFactory.h"

namespace
{
  using moho::EFormationType;

  class ScrImport : public faf_lua_tests::LuaFixture
  {};

  TEST_F(
    ScrImport,
    FailedImportIsNil
  )
  {
    Run("import = function(path) error('access to nonexistent global variable \"LightAttackNaval\"') end");
    const LuaPlus::LuaObject module = moho::SCR_ImportLuaModule(&state, "/lua/formations.lua");
    EXPECT_TRUE(module.IsNil());
    EXPECT_FALSE(module.IsTable());
    EXPECT_FALSE(static_cast<bool>(module));
  }

  TEST_F(
    ScrImport,
    MissingImportFunctionIsNil
  )
  {
    Run("import = nil");
    EXPECT_TRUE(moho::SCR_ImportLuaModule(&state, "/lua/formations.lua").IsNil());
  }

  TEST_F(
    ScrImport,
    FieldOfNonTableIsNil
  )
  {
    const LuaPlus::LuaObject number = Run("return 5");
    EXPECT_TRUE(moho::SCR_GetLuaTableField(&state, number, "SurfaceFormations").IsNil());
  }

  TEST_F(
    ScrImport,
    FormationsAnswerNothingWhenTheModuleFails
  )
  {
    Run("import = function(path) error('access to nonexistent global variable \"LightAttackNaval\"') end");
    unsigned int count = 99;
    EXPECT_NO_THROW(count = moho::FORMATION_GetNumScripts(&state, EFormationType::Surface));
    EXPECT_EQ(count, 0u);
    const char* name = "unset";
    EXPECT_NO_THROW(name = moho::FORMATION_GetScriptName(&state, 0, EFormationType::Surface));
    EXPECT_EQ(name, nullptr);
    int index = 99;
    EXPECT_NO_THROW(index = moho::FORMATION_GetScriptIndex(&state, "GrowthFormation", EFormationType::Surface));
    EXPECT_EQ(index, 0);
  }

  TEST_F(
    ScrImport,
    FormationsReadAWorkingModule
  )
  {
    Run(
      "local m = { SurfaceFormations = { 'AttackFormation', 'GrowthFormation' }, AirFormations = { 'AttackFormation' } "
      "}\n"
      "import = function(path) return m end"
    );
    EXPECT_EQ(moho::FORMATION_GetNumScripts(&state, EFormationType::Surface), 2u);
    EXPECT_EQ(moho::FORMATION_GetNumScripts(&state, EFormationType::Air), 1u);
    EXPECT_STREQ(moho::FORMATION_GetScriptName(&state, 1, EFormationType::Surface), "GrowthFormation");
  }
} // namespace
