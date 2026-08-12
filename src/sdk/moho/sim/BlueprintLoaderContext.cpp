#include "moho/sim/BlueprintLoaderContext.h"

namespace
{
  // Constant-initialized, so this costs a TLS slot and nothing else - no
  // dynamic initializer runs when a thread first touches it.
  thread_local moho::SBlueprintLoaderContext gBlueprintLoaderContext{};
} // namespace

moho::SBlueprintLoaderContext& moho::BlueprintLoaderContext() noexcept
{
  return gBlueprintLoaderContext;
}

moho::BlueprintLoaderContextScope::BlueprintLoaderContextScope(
  RRuleGameRulesImpl* const rules, CBackgroundTaskControl* const initHandler
) noexcept
{
  SBlueprintLoaderContext& context = BlueprintLoaderContext();
  context.mRules = rules;
  context.mInitHandler = initHandler;
}

moho::BlueprintLoaderContextScope::~BlueprintLoaderContextScope()
{
  SBlueprintLoaderContext& context = BlueprintLoaderContext();
  context.mRules = nullptr;
  context.mInitHandler = nullptr;
}
