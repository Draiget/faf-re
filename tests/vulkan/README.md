# Vulkan host tests

Both executables build with the normal repository preset and run under the `Vulkan` label:

```powershell
cmake --build --preset clang-x64-release --target faf_vulkan_allocator_tests faf_vulkan_attachment_tests
ctest --test-dir build/clang-x64-release -L Vulkan --output-on-failure
```

## Limits

`faf_vulkan_limits_tests` checks `src/gpg/gal/backends/vulkan/VulkanLimits.h`, what `DeviceVulkan` checks against a device's limits before it makes its pipeline layouts and GPU programs, with limits of its own: Vulkan 1.3's required minimums, which a phone's GPU may report, and a desktop GPU's. It counts the descriptors a stage sees and a layout holds as the limits count them, and checks hand-made copies of the layouts' sets (the GPU programs' and the effects' pipeline layouts, the ray-traced scene's set included), a compute work group's size, the last fragment input location and the depth bias clamp without its feature. It needs only the pinned Vulkan headers.

## Attachment barriers

`faf_vulkan_attachment_tests` checks `AttachmentWriteBarrier` (`src/gpg/gal/backends/vulkan/VulkanAttachmentBarrier.h`), the barrier `DeviceVulkan::BeginRendering` records when a color or depth target starts a new dynamic-rendering instance in the layout it already has. Six tests cover color, depth and depth/stencil: stages, access masks, kept layout, image and the mip 0 / layer 0 range that render-target views use. It needs only the pinned Vulkan headers; no driver, device or engine.

## Allocator

This GoogleTest executable compiles the same `VulkanMemoryAllocator.cpp` that `faf_engine` uses. It does not link the engine, load a Vulkan driver, or need a GPU. Vulkan types and callback signatures come from the repository's pinned Vulkan headers. Five callbacks supply fixed-capacity handle accounting; `CheckVk` and `backend::ThrowError` use test exception transport.

The 42 tests cover four split shapes, persistent host-allocation failures, repeated recovery, driver allocation/map errors, error-transport failure, free-map insertion, empty/nonempty block-vector growth, published-block protection, idle-block retention, oversized release, and empty-slot reuse. Free-map and vector-publication fault positions are calibrated from actual allocation counts on the active standard library, with and without pre-reserved vector capacity, including map sentinel/proxy allocations before the native allocation, rather than assuming fixed allocation ordinals.

Standard `new`/`delete` replacements are confined to this executable. Failure injection is disarmed before GoogleTest assertions and before cleanup by the test allocator. `Free()` is never called with injection enabled: its pre-existing potentially allocating `noexcept` behavior is outside this fix.

Native memory sizes are accounting values. Successful maps share one host buffer for address checks, not independent resource payloads. Logging, production error formatting, real driver behavior, GPU execution, rendered output, and performance are not validated by these tests.
