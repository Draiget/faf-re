#pragma once

namespace moho
{
  class RRuleGameRulesImpl;
  struct CBackgroundTaskControl;

  /**
   * Address context:
   * - seeded at 0x00529472, inside 0x00529120 (RRuleGameRulesImpl ctor), and by
   *   the standalone seeder 0x005290E0
   * - cleared by 0x00529100
   * - read by 0x00529030 (cfunc_BlueprintLoaderUpdateProgress), 0x005290C0, and
   *   the RegisterXxxBlueprint callbacks at 0x00528DF0 / 0x00528EB0 /
   *   0x00528F60 / 0x00529010
   *
   * What it does:
   * Holds, per thread, the context the blueprint Lua scripts run under: the
   * rules object they register into and the background-task control they report
   * progress to. The binary keeps this in a `__declspec(thread)` record and
   * reaches it through `fs:[0x2C]`; blueprint loading runs on the session
   * loader's own worker thread, so a plain global would be wrong.
   *
   * Field comments give the offsets of the corresponding words in the binary's
   * TLS record. There is no size assert: the record is a linker-built block
   * shared with every other thread-local in the image, not a standalone type.
   */
  struct SBlueprintLoaderContext
  {
    RRuleGameRulesImpl* mRules = nullptr;           // TLS record +0x04
    CBackgroundTaskControl* mInitHandler = nullptr; // TLS record +0x08
  };

  /**
   * What it does:
   * Returns the calling thread's blueprint-loader context. Threads that are not
   * loading blueprints see a zeroed one.
   */
  [[nodiscard]] SBlueprintLoaderContext& BlueprintLoaderContext() noexcept;

  /**
   * Address: 0x005290E0 (seed) / 0x00529100 (clear)
   *
   * What it does:
   * Publishes a blueprint-loader context for the calling thread and withdraws it
   * again when the load leaves scope, so an error thrown out of a blueprint
   * script cannot leave a dangling rules pointer behind for the next load.
   */
  class BlueprintLoaderContextScope
  {
  public:
    BlueprintLoaderContextScope(RRuleGameRulesImpl* rules, CBackgroundTaskControl* initHandler) noexcept;
    ~BlueprintLoaderContextScope();

    BlueprintLoaderContextScope(const BlueprintLoaderContextScope&) = delete;
    BlueprintLoaderContextScope& operator=(const BlueprintLoaderContextScope&) = delete;
  };
} // namespace moho
