#pragma once

// Engine addition, not in the shipped binary (issue #315): DLLs the game needs beside it, carried
// inside the executable as resources. FAF Develop delivers one file, ForgedAlliance.exe, and its
// upload removes every other file of that version, so nothing else can travel with the exe. The
// engine's own Lua is not carried here: it goes to FAF's Lua (FAForever/fa, issue #327).
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
} // namespace gpg
