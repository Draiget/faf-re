#pragma once

// Engine addition (issue #255): the Linux client's DXC, behind plain C++ types. DXC's Linux headers
// bring their own Win32 types (dxc/WinAdapter.h), which clash with the POSIX <Windows.h> every
// other client file is compiled with, so DxcGlue.cpp is the one file that includes them and is
// compiled without that header (cmake/FafLinuxClient.cmake). libdxcompiler.so is loaded at run time,
// as dxcompiler.dll is on Windows (gpg/gal/effects/ShaderCompiler.cpp).

#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace platform::posix::dxc
{
  struct Output
  {
    bool succeeded = false;
    std::vector<unsigned char> object; // the compiled code
    std::string text;                  // preprocessed source (Preprocess)
    std::string messages;              // errors, or warnings on success
  };

  /**
   * Loads libdxcompiler.so (and libdxil.so beside it, the DXIL signer) from the first of
   * `directories` that has it, then the system's library path. Returns "" or why it failed;
   * `version` gets "dxc <major>.<minor>".
   */
  std::string Load(const std::vector<std::string>& directories, std::string& version);

  /** DXC is loaded. */
  bool Loaded();

  /** IDxcCompiler3::Compile of UTF-8 `source` with `arguments` (DXC takes wchar_t on Linux too). */
  Output Compile(std::string_view source, const std::vector<std::wstring>& arguments);

  /**
   * Runs only DXC's preprocessor (-P) over `source`, with `defines` (name, value), as
   * D3DPreprocess does for the Windows renderers. `sourceName` names the source in messages.
   */
  Output Preprocess(
    std::string_view source,
    std::string_view sourceName,
    const std::vector<std::pair<std::string, std::string>>& defines
  );
} // namespace platform::posix::dxc
