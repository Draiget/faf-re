#pragma once

// Engine addition, not in the shipped binary (issue #315): files the game needs beside it, carried
// inside the executable as resources. FAF Develop delivers one file, ForgedAlliance.exe, and its
// upload removes every other file of that version, so nothing else can travel with the exe.
//
// Each resource is written once to %LOCALAPPDATA%\FAForever\faf-re\<name>-<hash>, where the hash
// is the resource's own bytes, so a new build writes a new copy and older copies are never
// changed while another game has them open. Loose files next to the exe win over these.

#include <string>

namespace gpg
{
  /**
   * The folder holding dxcompiler.dll and dxil.dll, unpacked from the executable's FAF_DXC
   * resource (a zstd-compressed tar), with a trailing backslash; empty without the resource or
   * when they can't be written.
   */
  [[nodiscard]] std::wstring EmbeddedDxcDirectory();

  /**
   * The engine's own Lua (data/fafengine), unpacked from the executable's FAF_ENGINE_LUA resource
   * (a zstd-compressed tar), to mount at /fafengine; with a trailing backslash, empty without the
   * resource or when it can't be written. A folder, not a zip: the VFS reads only zips without
   * data descriptors, which `cmake -E tar` writes.
   */
  [[nodiscard]] std::wstring EmbeddedEngineLuaDirectory();
} // namespace gpg
