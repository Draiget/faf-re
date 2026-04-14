/**
 * Link anchor for the `main` executable.
 *
 * Why this exists:
 * The project otherwise has zero local object files, which causes MSVC link to
 * skip CRT startup/object defaults and fail before resolving SDK `WinMain`.
 *
 * Entry point still comes from SDK:
 * `src/sdk/moho/app/WinMain.cpp` (`int WINAPI WinMain(...)`).
 */
namespace
{
  [[maybe_unused]] constexpr int kSdkWinMainLinkAnchor = 0;
}

