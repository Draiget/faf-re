#pragma once

// Engine addition, server mode (plan WP11): which lockstep driver a session runs on.

namespace moho
{
  class ISTIDriver;
}

namespace faf::remote::client
{
  /**
   * `driver` itself, or the lockstep driver a loopback remote driver stands in for the server
   * with: for engine code that reaches into `CSimDriver` itself (cfunc_SetFocusArmySim), which
   * under /loopback means the stand-in.
   */
  [[nodiscard]] moho::ISTIDriver* LockstepDriverOf(moho::ISTIDriver* driver) noexcept;
} // namespace faf::remote::client
