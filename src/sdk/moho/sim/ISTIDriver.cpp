#include "ISTIDriver.h"

#include <cstdint>

using namespace moho;

namespace
{
  struct ISTIDriverRuntimeView
  {
    void* vtable;
  };

  /**
   * Address: 0x0073B930 (FUN_0073B930)
   *
   * What it does:
   * Rebinds one runtime payload to the base `ISTIDriver` vtable lane.
   */
  [[maybe_unused]] [[nodiscard]] ISTIDriverRuntimeView* ResetISTIDriverBaseVtableLane(
    ISTIDriverRuntimeView* const runtime
  ) noexcept
  {
    static std::uint8_t sISTIDriverRuntimeVTableTag = 0;
    if (runtime != nullptr) {
      runtime->vtable = &sISTIDriverRuntimeVTableTag;
    }
    return runtime;
  }
} // namespace

/**
 * Address: 0x0073B0C0 (FUN_0073B0C0, ??0ISTIDriver@Moho@@QAE@XZ)
 *
 * What it does:
 * Initializes one simulation-driver base interface object.
 */
ISTIDriver::ISTIDriver() = default;

/**
 * Address: 0x0073B0D0 (FUN_0073B0D0)
 *
 * What it does:
 * Base scalar-deleting destructor body for ISTIDriver.
 */
ISTIDriver::~ISTIDriver() = default;
