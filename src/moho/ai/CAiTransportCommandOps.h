#pragma once

#include "moho/ai/IAiBuilder.h"

namespace moho
{
  /**
   * Legacy compatibility alias.
   *
   * Address: 0x00749970 (FUN_00749970)
   *
   * What it does:
   * Earlier recovery passes modeled this as a transport command-vtable, but
   * callsite evidence maps slot +0x2C/+0x34 at Unit+0x554 to IAiBuilder
   * (`BuilderContainsCommand` / `BuilderRemoveFactoryCommand`).
   *
   * Keep this alias for include/source compatibility while using the
   * engine-native IAiBuilder interface.
   */
  using CAiTransportCommandOps = IAiBuilder;
} // namespace moho
