#include "ICommandSink.h"

#include <cstdint>
#include <new>

using namespace moho;

namespace
{
  struct ICommandSinkRuntimeView
  {
    void* vtable;
  };

  /**
   * Address: 0x006E5A70 (FUN_006E5A70)
   *
   * What it does:
   * Rebinds one runtime payload to the base `ICommandSink` vtable lane.
   */
  [[maybe_unused]] [[nodiscard]] ICommandSinkRuntimeView* ResetICommandSinkBaseVtableLaneA(
    ICommandSinkRuntimeView* const runtime
  ) noexcept
  {
    static std::uint8_t sICommandSinkRuntimeVTableTag = 0;
    if (runtime != nullptr) {
      runtime->vtable = &sICommandSinkRuntimeVTableTag;
    }
    return runtime;
  }

  /**
   * Address: 0x006E5A80 (FUN_006E5A80)
   *
   * What it does:
   * Secondary alias lane that rebinds one runtime payload to the base
   * `ICommandSink` vtable.
   */
  [[maybe_unused]] [[nodiscard]] ICommandSinkRuntimeView* ResetICommandSinkBaseVtableLaneB(
    ICommandSinkRuntimeView* const runtime
  ) noexcept
  {
    return ResetICommandSinkBaseVtableLaneA(runtime);
  }
} // namespace

/**
 * Address: 0x006E59F0 (FUN_006E59F0, ??0ICommandSink@Moho@@QAE@XZ)
 *
 * What it does:
 * Initializes one command-sink base interface object.
 */
ICommandSink::ICommandSink() = default;

/**
 * Address: 0x007418D0 (FUN_007418D0)
 *
 * What it does:
 * Releases one owned command-sink storage lane with raw `operator delete`.
 */
void moho::DeleteOwnedCommandSinkStorage(ICommandSink* const sink) noexcept
{
  if (sink == nullptr) {
    return;
  }

  ::operator delete(static_cast<void*>(sink));
}

/**
 * Address: 0x0073F8A0 (FUN_0073F8A0)
 *
 * What it does:
 * Replaces one owned command-sink storage pointer and releases the previous
 * storage lane with raw `operator delete` when present.
 */
void moho::ReplaceOwnedCommandSinkStorage(ICommandSink*& slot, ICommandSink* const replacement) noexcept
{
  ICommandSink* const previous = slot;
  slot = replacement;
  DeleteOwnedCommandSinkStorage(previous);
}
