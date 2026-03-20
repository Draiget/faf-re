#include "moho/ai/CAiFormationDBImpl.h"

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "lua/LuaObject.h"
#include "moho/ai/CAiFormationInstance.h"
#include "moho/sim/Sim.h"

using namespace moho;

namespace
{
  constexpr const char* kFormationModulePath = "/lua/formations.lua";
  constexpr const char* kFormationBuckets[] = {
    "SurfaceFormations",
    "AirFormations",
  };
  constexpr int kFormationBucketCount = static_cast<int>(sizeof(kFormationBuckets) / sizeof(kFormationBuckets[0]));

  [[nodiscard]] int ToFormationBucketIndex(const EFormationType type)
  {
    const int bucket = static_cast<int>(type);
    if (bucket < 0 || bucket >= kFormationBucketCount) {
      return 0;
    }
    return bucket;
  }

  [[nodiscard]] LuaPlus::LuaObject
  GetLuaTableField(LuaPlus::LuaState* state, const LuaPlus::LuaObject& tableObj, const char* fieldName)
  {
    if (!state || !tableObj || !fieldName || !*fieldName) {
      return {};
    }

    lua_State* const luaState = state->GetCState();
    if (!luaState) {
      return {};
    }

    const int oldTop = lua_gettop(luaState);
    const_cast<LuaPlus::LuaObject&>(tableObj).PushStack(luaState);
    lua_pushstring(luaState, fieldName);
    lua_gettable(luaState, -2);
    LuaPlus::LuaObject fieldObj{LuaPlus::LuaStackObject(state, -1)};
    lua_settop(luaState, oldTop);
    return fieldObj;
  }

  [[nodiscard]] LuaPlus::LuaObject ImportLuaModule(LuaPlus::LuaState* state, const char* modulePath)
  {
    if (!state || !modulePath || !*modulePath) {
      return {};
    }

    lua_State* const luaState = state->GetCState();
    if (!luaState) {
      return {};
    }

    const int oldTop = lua_gettop(luaState);
    lua_getglobal(luaState, "import");
    if (!lua_isfunction(luaState, -1)) {
      lua_settop(luaState, oldTop);
      return {};
    }

    lua_pushstring(luaState, modulePath);
    if (lua_pcall(luaState, 1, 1, 0) != 0) {
      lua_settop(luaState, oldTop);
      return {};
    }

    LuaPlus::LuaObject moduleObj{LuaPlus::LuaStackObject(state, -1)};
    lua_settop(luaState, oldTop);
    return moduleObj;
  }

  [[nodiscard]] LuaPlus::LuaObject ResolveFormationBucket(LuaPlus::LuaState* state, const EFormationType formationType)
  {
    LuaPlus::LuaObject module = ImportLuaModule(state, kFormationModulePath);
    if (!module || !module.IsTable()) {
      return {};
    }

    const char* const bucketName = kFormationBuckets[ToFormationBucketIndex(formationType)];
    LuaPlus::LuaObject bucket = GetLuaTableField(state, module, bucketName);
    if (!bucket || !bucket.IsTable()) {
      return {};
    }

    return bucket;
  }

  [[nodiscard]] bool EqualsIgnoreCaseAscii(const char* lhs, const char* rhs)
  {
    if (!lhs || !rhs) {
      return false;
    }

    for (; *lhs && *rhs; ++lhs, ++rhs) {
      const unsigned char l = static_cast<unsigned char>(*lhs);
      const unsigned char r = static_cast<unsigned char>(*rhs);
      if (std::tolower(l) != std::tolower(r)) {
        return false;
      }
    }

    return *lhs == '\0' && *rhs == '\0';
  }
} // namespace

/**
 * Address: 0x0059C340 (FUN_0059C340)
 */
CAiFormationDBImpl::~CAiFormationDBImpl()
{
  // Mirrors FUN_0059BFE0 storage teardown semantics before base destruction.
  mFormInstances.ResetStorageToInline();
}

/**
 * Address: 0x0059C030 (FUN_0059C030)
 */
void CAiFormationDBImpl::Update()
{
  for (CAiFormationInstance** it = mFormInstances.begin(); it != mFormInstances.end(); ++it) {
    (*it)->Update();
  }
}

/**
 * Address: 0x0059C060 (FUN_0059C060)
 */
void CAiFormationDBImpl::RemoveFormation(CAiFormationInstance* const formation)
{
  CAiFormationInstance** begin = mFormInstances.begin();
  CAiFormationInstance** end = mFormInstances.end();
  for (CAiFormationInstance** it = begin; it != end; ++it) {
    if (*it != formation) {
      continue;
    }

    for (CAiFormationInstance **src = it + 1, **dst = it; src != end; ++src, ++dst) {
      *dst = *src;
    }

    const std::size_t newSize = static_cast<std::size_t>((end - begin) - 1);
    mFormInstances.SetSizeUnchecked(newSize);
    return;
  }
}

/**
 * Address: 0x0059C0C0 (FUN_0059C0C0)
 */
const char* CAiFormationDBImpl::GetScriptName(const int scriptIndex, const EFormationType formationType)
{
  if (!mSim || !mSim->GetLuaState()) {
    return nullptr;
  }

  LuaPlus::LuaObject scripts = ResolveFormationBucket(mSim->GetLuaState(), formationType);
  if (!scripts || !scripts.IsTable()) {
    return nullptr;
  }

  const int scriptCount = scripts.GetN();
  if (scriptCount <= 0) {
    return nullptr;
  }

  const int clampedIndex = (scriptIndex >= 0 && scriptIndex < scriptCount) ? (scriptIndex + 1) : 1;
  LuaPlus::LuaObject scriptObj = scripts.GetByIndex(clampedIndex);
  if (!scriptObj.IsString()) {
    return nullptr;
  }

  return scriptObj.GetString();
}

/**
 * Address: 0x0059C0F0 (FUN_0059C0F0)
 */
int CAiFormationDBImpl::GetScriptIndex(const gpg::StrArg scriptName, const EFormationType formationType)
{
  if (!mSim || !mSim->GetLuaState()) {
    return 0;
  }

  LuaPlus::LuaObject scripts = ResolveFormationBucket(mSim->GetLuaState(), formationType);
  if (!scripts || !scripts.IsTable()) {
    return 0;
  }

  if (!scriptName || !*scriptName) {
    return -1;
  }

  const int scriptCount = scripts.GetN();
  for (int luaIndex = 1; luaIndex <= scriptCount; ++luaIndex) {
    LuaPlus::LuaObject scriptObj = scripts.GetByIndex(luaIndex);
    if (!scriptObj.IsString()) {
      continue;
    }

    const char* const candidate = scriptObj.GetString();
    if (EqualsIgnoreCaseAscii(candidate, scriptName)) {
      return luaIndex - 1;
    }
  }

  return -1;
}

/**
 * Address: 0x0059C120 (FUN_0059C120)
 */
CAiFormationInstance* CAiFormationDBImpl::NewFormation(
  [[maybe_unused]] int scriptIndex,
  [[maybe_unused]] const char* scriptName,
  [[maybe_unused]] void* unitWeakSet,
  [[maybe_unused]] int arg4,
  [[maybe_unused]] int arg5,
  [[maybe_unused]] int arg6,
  [[maybe_unused]] int arg7,
  [[maybe_unused]] int arg8
)
{
  // Full lift depends on unrecovered CAiFormationInstance ctor body (FUN_005694B0)
  // and its 0x330-byte runtime layout.
  return nullptr;
}
